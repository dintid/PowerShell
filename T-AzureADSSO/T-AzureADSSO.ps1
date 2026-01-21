<#
MODNI 20251022
PingCastle ID: T-AzureADSSO

🔎 Script Description:
Performs a secure and ISE-safe rollover of the Azure AD Seamless SSO (AZUREADSSOACC) Kerberos decryption key.

Key Features:
• Automatically detects whether Azure AD Connect (ADSync) is installed locally.
• If not, searches the domain for the server hosting AD Connect and warns the user.
• Detects which domain hosts the AZUREADSSOACC computer account.
• Suggests correct SAM-format credential prefixes (NetBIOS and DNS) for the target domain.
• Validates LDAP bind before attempting the rollover — preventing “invalid credentials” errors.
• Imports the AzureADSSO module safely (handles both common install paths).
• Authenticates with a Microsoft 365 Hybrid Identity Administrator for Azure connection.
• Displays current Azure AD SSO status (Get-AzureADSSOStatus).
• Prompts for on-prem Domain Admin credentials and securely updates the Kerberos decryption key (Update-AzureADSSOForest).
• Optionally displays when the AZUREADSSOACC password was last changed.
• Fully compatible with PowerShell ISE (uses `return`, never `exit`).
• Writes detection and action logs to: C:\ITM8\T-AzureADSSO\Detection.log

Intended Use:
To resolve PingCastle finding **T-AzureADSSO**, ensuring Azure AD Seamless SSO remains secure by rotating its Kerberos key.
Run **only** on the server hosting Azure AD Connect, using an account with:
   • Local admin rights on that server (recommended)
   • Domain Admin (or delegated “Reset Password” permission) in the on-prem AD forest
   • Hybrid Identity Administrator (or higher) in Microsoft 365

Reference:
https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq#how-can-i-roll-over-the-kerberos-decryption-key-of-the--azureadsso--computer-account-
#>


#region ---------- helpers ----------
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

function Resolve-AzureAdSsoModulePath {
    $roots = @(
        (Join-Path $env:ProgramFiles "Microsoft Azure AD Connect"),
        (Join-Path $env:ProgramFiles "Microsoft Azure Active Directory Connect")
    )
    foreach ($root in $roots) {
        $candidate = Join-Path $root "AzureADSSO.psd1"
        if (Test-Path $candidate) { return $candidate }
    }
    try {
        $hit = Get-ChildItem -Path $env:ProgramFiles -Filter "AzureADSSO.psd1" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    } catch { }
    return $null
}

function Find-AdConnectServer {
    param(
        [int]$MaxCandidates = 60,
        [System.Management.Automation.PSCredential]$Credential
    )
    $queryParams = @{
        Filter      = "Enabled -eq 'true' -and OperatingSystem -like '*Server*'"
        Properties  = 'Name','lastLogonTimestamp','OperatingSystem'
        ErrorAction = 'Stop'
    }
    if ($Credential) { $queryParams.Credential = $Credential }

    $candidates = @()
    try {
        $candidates = Get-ADComputer @queryParams |
            Sort-Object lastLogonTimestamp -Descending |
            Select-Object -First $MaxCandidates
    } catch { return $null }

    $opt = New-CimSessionOption -Protocol DCOM
    foreach ($c in $candidates) {
        $name = $c.Name
        try {
            $cimParams = @{ ComputerName = $name; SessionOption = $opt; ErrorAction = 'Stop' }
            if ($Credential) { $cimParams.Credential = $Credential }
            $cim = New-CimSession @cimParams
            try {
                $adSync = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
                if ($adSync) { return $name }
                $h1 = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='AzureADConnectHealthSyncMonitor'" -ErrorAction SilentlyContinue
                $h2 = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='AzureADConnectHealthSyncInsights'" -ErrorAction SilentlyContinue
                if ($h1 -or $h2) { return $name }
            } finally {
                if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }
            }
        } catch { }
    }
    return $null
}

function Get-AzureAdSsoAccDomain {
    # Try to find which domain hosts AZUREADSSOACC
    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
        $forest = Get-ADForest -ErrorAction Stop
        foreach ($d in $forest.Domains) {
            try {
                $obj = Get-ADComputer -Identity "AZUREADSSOACC" -Server $d -ErrorAction Stop
                if ($obj) { return $d }
            } catch { }
        }
    } catch { }
    # Fallback: current domain DNS root
    try {
        $dom = Get-ADDomain -ErrorAction Stop
        return $dom.DNSRoot
    } catch {
        return $null
    }
}
#endregion ---------- helpers ----------

#region ---------- detect AD Connect host ----------
Write-Host "`n🔎 Checking for Azure AD Connect installation..." -ForegroundColor Cyan
Write-Log  "Begin detection"

$localAdSyncSvc = Get-Service -Name "ADSync" -ErrorAction SilentlyContinue
$localModule    = Resolve-AzureAdSsoModulePath

if ($localAdSyncSvc -or $localModule) {
    Write-Host "`n✅ Azure AD Connect installation detected on this server." -ForegroundColor Green
    Write-Host "   Proceeding with Azure AD SSO module initialization...`n" -ForegroundColor Gray
    Write-Log  "Local ADSync: $([bool]$localAdSyncSvc); Module: $localModule"
} else {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDomainJoined = $false
    $isDC = $false
    if ($cs) {
        $isDomainJoined = [bool]$cs.PartOfDomain
        $isDC = ($cs.DomainRole -ge 4) # 4/5 = DC
    }
    Write-Log "DomainJoined=$isDomainJoined; IsDC=$isDC"

    if (-not $isDomainJoined) {
        Write-Host "`n⚠️  This computer is not domain-joined. Skipping domain scan for AD Connect host." -ForegroundColor Yellow
        Write-Host "   Run on a domain-joined admin box or on the suspected AD Connect server." -ForegroundColor Yellow
        Write-Log  "Not domain-joined; abort"
        return
    }

    if (-not (Get-Module ActiveDirectory -ListAvailable)) {
        Write-Host "`n⚠️  RSAT ActiveDirectory module not available; cannot query AD." -ForegroundColor Yellow
        Write-Host "   Run on a DC/management server with RSAT or on the AD Connect server." -ForegroundColor Yellow
        Write-Log  "AD module missing; abort"
        return
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null

    Write-Host "   Not detected locally. Searching domain for AD Connect host(s)..." -ForegroundColor Gray
    Write-Log  "Discovery scan start"
    $hostFound = $null
    try { $hostFound = Find-AdConnectServer } catch { $hostFound = $null }
    if (-not $hostFound) {
        Write-Host "   Attempting credentialed lookup (you may be prompted)..." -ForegroundColor Gray
        Write-Log  "Credentialed retry"
        try {
            $adCred = Get-Credential -Message "Enter domain credentials for directory discovery (e.g., CONTOSO\jdoe)"
            if ($adCred) { $hostFound = Find-AdConnectServer -Credential $adCred }
        } catch { $hostFound = $null }
    }

    if ($hostFound) {
        Write-Host "`n⚠️  Azure AD Connect detected on server: $hostFound" -ForegroundColor Yellow
        Write-Host "   Please run this script on that server to perform the T-AzureADSSO key rollover.`n" -ForegroundColor Yellow
        Write-Log  "AD Connect host: $hostFound"
        return
    } else {
        Write-Host "`n⚠️  Could not remotely detect any AD Connect host." -ForegroundColor Yellow
        Write-Host "   Likely causes: AD query limits, remote Service/WMI firewall, WinRM/WMI/DCOM restrictions, or insufficient rights." -ForegroundColor Yellow
        Write-Host "   Tip: Run on the suspected AD Connect server, or enable 'Remote Service Management' & 'Windows Management Instrumentation' firewall rules." -ForegroundColor Yellow
        Write-Log  "Discovery failed; none found"
        return
    }
}
#endregion ---------- detect host ----------

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
    Set-Location -Path $moduleDir -ErrorAction Stop
} catch { }

try {
    Import-Module -Name $localModule -ErrorAction Stop
    Write-Host "✔ AzureADSSO module imported from: $localModule`n" -ForegroundColor Green
    Write-Log  "Module imported: $localModule"
} catch {
    $err = $_.Exception.Message
    Write-Host "❌ Failed to import AzureADSSO module:`n   $err" -ForegroundColor Red
    Write-Log  "Module import failed: $err"
    return
}

# Enforce TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Connect to Azure AD (Hybrid Identity Admin)
Write-Host "🔐 Please authenticate with a Microsoft 365 account that has Hybrid Identity Administrator rights..." -ForegroundColor Yellow
New-AzureADSSOAuthenticationContext

# Show status
Write-Host "`n📊 Current Azure AD SSO configuration:" -ForegroundColor Cyan
try {
    $statusRaw = Get-AzureADSSOStatus
    $statusObj = $statusRaw | ConvertFrom-Json
    $statusObj | Format-Table -AutoSize
} catch {
    $err = $_.Exception.Message
    Write-Host "⚠️  Could not retrieve SSO status: $err" -ForegroundColor Yellow
    Write-Log  "Get-AzureADSSOStatus failed: $err"
}
#endregion ---------- module & status ----------

#region ---------- credentials (with good prefix) + bind test + rollover ----------
# Determine domain that hosts AZUREADSSOACC (best-effort)
$targetDomain = Get-AzureAdSsoAccDomain
if ($targetDomain) {
    Write-Host "`nℹ️  Detected AZUREADSSOACC in domain: $targetDomain" -ForegroundColor Gray
    Write-Log  "AZUREADSSOACC domain: $targetDomain"
} else {
    Write-Host "`n⚠️  Could not determine AZUREADSSOACC domain. Using current domain context." -ForegroundColor Yellow
    Write-Log  "AZUREADSSOACC domain unknown"
}

# Suggest SAM prefixes
Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
$dom = $null
try { $dom = if ($targetDomain) { Get-ADDomain -Server $targetDomain -ErrorAction Stop } else { Get-ADDomain -ErrorAction Stop } } catch { }
$nb  = if ($dom) { $dom.NetBIOSName } else { $env:USERDOMAIN }
$dns = if ($dom) { $dom.DNSRoot }    else { "$($env:USERDOMAIN).local" }

$suggest1 = "$nb\$env:USERNAME"
$suggest2 = "$dns\$env:USERNAME"

Write-Host "`nEnter Domain Admin for the target forest (SAM format: domain\user)." -ForegroundColor Yellow
Write-Host "Examples: $suggest1  or  $suggest2" -ForegroundColor Yellow

# Prompt with DNS-form suggestion (resolves best in multi-domain/trust setups)
$creds = Get-Credential -UserName $suggest2 -Message "On-prem Domain Admin (SAM format: domain\user)"

# Pre-validate LDAP bind to the target domain’s PDC
try {
    $bindDomain = if ($targetDomain) { $targetDomain } else { $dns }
    $pdc = (Get-ADDomain -Server $bindDomain).PDCEmulator
    $bind = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$pdc/RootDSE",$creds.UserName,$creds.GetNetworkCredential().Password)
    $null = $bind.NativeObject
    Write-Host "✅ LDAP bind succeeded for $($creds.UserName) against $bindDomain (PDC: $pdc)" -ForegroundColor Green
    Write-Log  "LDAP bind OK: $($creds.UserName) -> $bindDomain ($pdc)"
} catch {
    Write-Host "❌ LDAP bind failed for $($creds.UserName): $($_.Exception.Message)" -ForegroundColor Red
    Write-Log  "LDAP bind failed: $($creds.UserName) -> $bindDomain : $($_.Exception.Message)"
    return
}

# Rollover
Write-Host "`n🧩 Updating AzureADSSOACC Kerberos decryption key..." -ForegroundColor Yellow
try {
    Update-AzureADSSOForest -OnPremCredentials $creds
    Write-Host "✔ Key rollover completed (Update-AzureADSSOForest)." -ForegroundColor Green
    Write-Log  "Update-AzureADSSOForest completed"
} catch {
    $err = $_.Exception.Message
    Write-Host "❌ Update-AzureADSSOForest failed:`n   $err" -ForegroundColor Red
    Write-Log  "Update-AzureADSSOForest failed: $err"
    return
}

# Optional: show when AZUREADSSOACC password last set
try {
    $aadComp = if ($targetDomain) {
        Get-ADComputer -Identity "AZUREADSSOACC" -Server $targetDomain -Properties PasswordLastSet -ErrorAction Stop
    } else {
        Get-ADComputer -Identity "AZUREADSSOACC" -Properties PasswordLastSet -ErrorAction Stop
    }
    $lastSet = $aadComp.PasswordLastSet
    Write-Host "`n📅 AZUREADSSOACC password last set: $lastSet`n" -ForegroundColor Cyan
    Write-Log  "AZUREADSSOACC PasswordLastSet: $lastSet"
} catch {
    $err = $_.Exception.Message
    Write-Host "`n⚠️ Could not retrieve PasswordLastSet for AZUREADSSOACC.`n   $err`n" -ForegroundColor Yellow
    Write-Log  "Get-ADComputer AZUREADSSOACC failed: $err"
}
#endregion ---------- credentials + rollover ----------
