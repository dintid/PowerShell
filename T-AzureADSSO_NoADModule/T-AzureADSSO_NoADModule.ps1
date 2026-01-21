<#
MODNI 20260112
PingCastle ID: T-AzureADSSO

ISE-safe Azure AD Seamless SSO key rollover WITHOUT RSAT/ActiveDirectory module.
- Detects local AAD Connect (ADSync service or AzureADSSO.psd1).
- Imports AzureADSSO module.
- Connects to Azure using New-AzureADSSOAuthenticationContext.
- Reads status (Get-AzureADSSOStatus).
- Prompts for on-prem creds and validates LDAP bind using .NET (no Get-ADDomain).
- Detects which domain hosts AZUREADSSOACC by LDAP scan across forest domains.
- Performs rollover (Update-AzureADSSOForest).
- Optionally shows AZUREADSSOACC pwdLastSet via LDAP attribute (no Get-ADComputer).
- Logs to C:\ITM8\T-AzureADSSO\Detection.log

Reference:
https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq#how-can-i-roll-over-the-kerberos-decryption-key-of-the--azureadsso--computer-account-
#>

#region ---------- logging ----------
$LogRoot = "C:\ITM8\T-AzureADSSO"
$null = New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$LogFile = Join-Path $LogRoot "Detection.log"

function Write-Log {
    param([string]$Line)
    try {
        $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $LogFile -Value "[$stamp] $Line"
    } catch { }
}
#endregion ---------- logging ----------

#region ---------- helpers (no RSAT) ----------
function Resolve-AzureAdSsoModulePath {
    $roots = @(
        (Join-Path $env:ProgramFiles "Microsoft Azure AD Connect"),
        (Join-Path $env:ProgramFiles "Microsoft Azure Active Directory Connect")
    )
    foreach ($root in $roots) {
        $candidate = Join-Path $root "AzureADSSO.psd1"
        if (Test-Path $candidate) { return $candidate }
    }

    # best-effort search (bounded)
    try {
        $hit = Get-ChildItem -Path $env:ProgramFiles -Filter "AzureADSSO.psd1" -Recurse -Depth 3 -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    } catch { }

    return $null
}

function Get-ForestDomainsViaLDAP {
    param(
        [Parameter(Mandatory=$true)][string]$AnyDomainDnsName,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
    )

    # Query CN=Partitions for crossRef objects (domain partitions) and read their dnsRoot
    $domains = New-Object System.Collections.Generic.List[string]
    try {
        $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
            "Domain",
            $AnyDomainDnsName,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
        $domObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        $forest = $domObj.Forest
        $rootDom = $forest.RootDomain.Name

        # Bind to RootDSE of root domain to get configurationNamingContext
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$rootDom/RootDSE",
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
        $configNC = $rootDse.Properties["configurationNamingContext"].Value
        if (-not $configNC) { throw "configurationNamingContext not found" }

        $partitionsDn = "CN=Partitions,$configNC"
        $de = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$rootDom/$partitionsDn",
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )

        $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
        $ds.PageSize = 500
        $ds.Filter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2)(dnsRoot=*))"
        $null = $ds.PropertiesToLoad.Add("dnsRoot")
        $results = $ds.FindAll()

        foreach ($r in $results) {
            if ($r.Properties["dnsroot"] -and $r.Properties["dnsroot"].Count -gt 0) {
                $dns = [string]$r.Properties["dnsroot"][0]
                if ($dns -and -not $domains.Contains($dns)) { $domains.Add($dns) }
            }
        }

        if (-not $domains.Contains($rootDom)) { $domains.Add($rootDom) }
    } catch {
        Write-Log "Get-ForestDomainsViaLDAP failed: $($_.Exception.Message)"
    }

    return $domains.ToArray()
}

function Get-PdcNameNoRSAT {
    param(
        [Parameter(Mandatory=$true)][string]$DomainDnsName,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
    )
    $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
        "Domain",
        $DomainDnsName,
        $Credential.UserName,
        $Credential.GetNetworkCredential().Password
    )
    $domObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
    return $domObj.PdcRoleOwner.Name
}

function Test-LdapBindNoRSAT {
    param(
        [Parameter(Mandatory=$true)][string]$DomainDnsName,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
    )
    $pdc = Get-PdcNameNoRSAT -DomainDnsName $DomainDnsName -Credential $Credential
    $bind = New-Object System.DirectoryServices.DirectoryEntry(
        "LDAP://$pdc/RootDSE",
        $Credential.UserName,
        $Credential.GetNetworkCredential().Password
    )
    $null = $bind.NativeObject
    return $pdc
}

function Find-AzureAdSsoAccDomainNoRSAT {
    param(
        [Parameter(Mandatory=$true)][string[]]$Domains,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
    )

    # Search for computer account with sAMAccountName = AZUREADSSOACC$
    foreach ($d in $Domains) {
        try {
            $pdc = Get-PdcNameNoRSAT -DomainDnsName $d -Credential $Credential

            $rootDse = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$pdc/RootDSE",
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
            $defaultNC = $rootDse.Properties["defaultNamingContext"].Value
            if (-not $defaultNC) { continue }

            $base = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$pdc/$defaultNC",
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )

            $ds = New-Object System.DirectoryServices.DirectorySearcher($base)
            $ds.PageSize = 200
            $ds.Filter = "(&(objectCategory=computer)(sAMAccountName=AZUREADSSOACC$))"
            $null = $ds.PropertiesToLoad.Add("distinguishedName")
            $null = $ds.PropertiesToLoad.Add("pwdLastSet")
            $res = $ds.FindOne()

            if ($res) {
                return [pscustomobject]@{
                    DomainDnsName = $d
                    PdcName       = $pdc
                    Dn            = [string]$res.Properties["distinguishedname"][0]
                    PwdLastSet    = if ($res.Properties["pwdlastset"]) { [Int64]$res.Properties["pwdlastset"][0] } else { $null }
                }
            }
        } catch {
            Write-Log "Find-AzureAdSsoAccDomainNoRSAT error on $d : $($_.Exception.Message)"
        }
    }
    return $null
}

function Convert-PwdLastSetFileTime {
    param([Nullable[Int64]]$FileTime)
    if (-not $FileTime) { return $null }
    try { return [DateTime]::FromFileTimeUtc($FileTime.Value) } catch { return $null }
}
#endregion ---------- helpers ----------

Write-Host "`n🔎 Checking for Azure AD Connect installation..." -ForegroundColor Cyan
Write-Log  "Begin detection"

#region ---------- detect AD Connect host locally ----------
$localAdSyncSvc = Get-Service -Name "ADSync" -ErrorAction SilentlyContinue
$localModule    = Resolve-AzureAdSsoModulePath

if ($localAdSyncSvc -or $localModule) {
    Write-Host "`n✅ Azure AD Connect installation detected on this server." -ForegroundColor Green
    Write-Host "   Proceeding with Azure AD SSO module initialization...`n" -ForegroundColor Gray
    Write-Log  "Local ADSync: $([bool]$localAdSyncSvc); Module: $localModule"
} else {
    Write-Host "`n❌ Azure AD Connect not detected locally." -ForegroundColor Red
    Write-Host "   Run this script on the server hosting Azure AD Connect (ADSync)." -ForegroundColor Yellow
    Write-Log  "No local ADSync/module; abort"
    return
}
#endregion ---------- detect AD Connect host locally ----------

#region ---------- module import & status ----------
Write-Host "   Resolving AzureADSSO module path..." -ForegroundColor Gray
if (-not $localModule) { $localModule = Resolve-AzureAdSsoModulePath }
if (-not $localModule) {
    Write-Host "❌ Could not locate AzureADSSO.psd1 under Program Files." -ForegroundColor Red
    Write-Host "   Ensure Azure AD Connect is fully installed." -ForegroundColor Yellow
    Write-Log  "AzureADSSO.psd1 not found; abort"
    return
}

try {
    $moduleDir = Split-Path -Path $localModule -Parent
    Set-Location -Path $moduleDir -ErrorAction SilentlyContinue
} catch { }

try {
    Import-Module -Name $localModule -ErrorAction Stop
    Write-Host "✔ AzureADSSO module imported from: $localModule`n" -ForegroundColor Green
    Write-Log  "Module imported: $localModule"
} catch {
    $errMsg = $_.Exception.Message
    Write-Host "❌ Failed to import AzureADSSO module:`n   $errMsg" -ForegroundColor Red
    Write-Log  "Module import failed: $errMsg"
    return
}

# Enforce TLS 1.2
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

Write-Host "🔐 Please authenticate with a Microsoft 365 account that has Hybrid Identity Administrator rights..." -ForegroundColor Yellow
try {
    New-AzureADSSOAuthenticationContext
    Write-Log "New-AzureADSSOAuthenticationContext OK"
} catch {
    $errMsg = $_.Exception.Message
    Write-Host "❌ Azure authentication context failed:`n   $errMsg" -ForegroundColor Red
    Write-Log  "New-AzureADSSOAuthenticationContext failed: $errMsg"
    return
}

Write-Host "`n📊 Current Azure AD SSO configuration:" -ForegroundColor Cyan
try {
    $statusRaw = Get-AzureADSSOStatus
    $statusObj = $statusRaw | ConvertFrom-Json
    $statusObj | Format-Table -AutoSize
    Write-Log "Get-AzureADSSOStatus OK"
} catch {
    $errMsg = $_.Exception.Message
    Write-Host "⚠️  Could not retrieve SSO status: $errMsg" -ForegroundColor Yellow
    Write-Log  "Get-AzureADSSOStatus failed: $errMsg"
}
#endregion ---------- module import & status ----------

#region ---------- on-prem creds + domain discovery (no RSAT) ----------
$defaultDomain = $env:USERDNSDOMAIN
if (-not $defaultDomain) { $defaultDomain = $env:USERDOMAIN }

Write-Host "`nEnter on-prem credentials that can reset AZUREADSSOACC (typically Domain Admin or delegated rights)." -ForegroundColor Yellow
Write-Host "Tip: Use domain\user. If unsure, start with: $defaultDomain\$env:USERNAME" -ForegroundColor Yellow

$creds = Get-Credential -UserName "$defaultDomain\$env:USERNAME" -Message "On-prem credentials (domain\user)"

# Validate LDAP bind to current domain (no RSAT)
try {
    $pdc0 = Test-LdapBindNoRSAT -DomainDnsName $defaultDomain -Credential $creds
    Write-Host "✅ LDAP bind succeeded for $($creds.UserName) (PDC: $pdc0)" -ForegroundColor Green
    Write-Log  "LDAP bind OK: $($creds.UserName) -> $defaultDomain ($pdc0)"
} catch {
    $errMsg = $_.Exception.Message
    Write-Host "❌ LDAP bind failed for $($creds.UserName): $errMsg" -ForegroundColor Red
    Write-Log  "LDAP bind failed: $($creds.UserName) -> $defaultDomain : $errMsg"
    return
}

# Discover forest domains via LDAP (Partitions) and find AZUREADSSOACC
Write-Host "`n🔎 Discovering forest domains (LDAP) and locating AZUREADSSOACC..." -ForegroundColor Cyan
$domains = Get-ForestDomainsViaLDAP -AnyDomainDnsName $defaultDomain -Credential $creds
if (-not $domains -or $domains.Count -eq 0) {
    Write-Host "⚠️  Could not enumerate forest domains via LDAP. Will attempt current domain only: $defaultDomain" -ForegroundColor Yellow
    Write-Log  "Forest domain enumeration failed; fallback to current domain"
    $domains = @($defaultDomain)
} else {
    Write-Host "   Domains found: $($domains -join ', ')" -ForegroundColor Gray
    Write-Log  "Domains found: $($domains -join ', ')"
}

$ssoInfo = Find-AzureAdSsoAccDomainNoRSAT -Domains $domains -Credential $creds
if ($ssoInfo) {
    Write-Host "`nℹ️  AZUREADSSOACC located in domain: $($ssoInfo.DomainDnsName) (PDC: $($ssoInfo.PdcName))" -ForegroundColor Gray
    Write-Log  "AZUREADSSOACC in domain: $($ssoInfo.DomainDnsName); PDC=$($ssoInfo.PdcName); DN=$($ssoInfo.Dn)"
} else {
    Write-Host "`n⚠️  Could not locate AZUREADSSOACC in the forest via LDAP." -ForegroundColor Yellow
    Write-Host "   Update-AzureADSSOForest may still work if the current context is correct." -ForegroundColor Yellow
    Write-Log  "AZUREADSSOACC not found via LDAP"
}
#endregion ---------- on-prem creds + domain discovery ----------

#region ---------- rollover ----------
Write-Host "`n🧩 Updating AZUREADSSOACC Kerberos decryption key..." -ForegroundColor Yellow
try {
    Update-AzureADSSOForest -OnPremCredentials $creds
    Write-Host "✔ Key rollover completed (Update-AzureADSSOForest)." -ForegroundColor Green
    Write-Log  "Update-AzureADSSOForest completed"
} catch {
    $errMsg = $_.Exception.Message
    Write-Host "❌ Update-AzureADSSOForest failed:`n   $errMsg" -ForegroundColor Red
    Write-Log  "Update-AzureADSSOForest failed: $errMsg"
    return
}
#endregion ---------- rollover ----------

#region ---------- optional: show pwdLastSet (no RSAT) ----------
$pwdRaw = if ($res.Properties["pwdlastset"]) { $res.Properties["pwdlastset"][0] } else { $null }

$pwdFt = $null
if ($pwdRaw -is [int64]) {
    $pwdFt = $pwdRaw
} elseif ($pwdRaw -and $pwdRaw.GetType().FullName -like "*LargeInteger*") {
    $pwdFt = ([int64]$pwdRaw.HighPart -shl 32) -bor ($pwdRaw.LowPart -band 0xffffffff)
}

PwdLastSet = $pwdFt

#endregion ---------- optional pwdLastSet ----------

Write-Host "Done. Log: $LogFile" -ForegroundColor Gray
Write-Log "Done"
