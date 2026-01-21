<#
MODNI 20260108
PingCastle ID: A-DCLdapsChannelBinding

READ-ONLY — This script does not change any settings.

Fixes in this version
---------------------
- Supports explicit -Credential for WinRM (avoids “username/password incorrect” when implicit auth fails)
- Automatically detects the currently logged-on DC and NEVER remotes to itself (runs locally instead)
- Centralized Invoke-DC wrapper used everywhere (preflight + collectors)
- Reports CBT registry value correctly:
    * Missing value = "Not configured (missing)"
    * 0/1/2 mapped to Disabled/Compatibility/Require

Outputs to:
  C:\ITM8\A-DCLdapsChannelBinding
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 7,
    [System.Management.Automation.PSCredential]$Credential
)

Import-Module ActiveDirectory -ErrorAction Stop

$logFolder = "C:\ITM8\A-DCLdapsChannelBinding"
if (-not (Test-Path -LiteralPath $logFolder)) { New-Item -ItemType Directory -Path $logFolder | Out-Null }

# --- identify local machine / FQDNs so we can avoid remoting-to-self ---
$localHostShort = $env:COMPUTERNAME
$localDnsDomain = $env:USERDNSDOMAIN
$localFqdn = if ($localDnsDomain) { "{0}.{1}" -f $localHostShort, $localDnsDomain } else { $null }

function Test-IsLocalComputerName {
    param([Parameter(Mandatory)][string]$ComputerName)

    $cn = $ComputerName.Trim().ToLowerInvariant()

    $candidates = @()
    if ($localHostShort) { $candidates += $localHostShort.ToLowerInvariant() }
    if ($localFqdn)      { $candidates += $localFqdn.ToLowerInvariant() }
    $candidates += 'localhost'
    $candidates = $candidates | Select-Object -Unique

    return ($candidates -contains $cn)
}

function Invoke-DC {
    <#
      Runs scriptblock locally if ComputerName refers to the local machine.
      Otherwise runs via WinRM (Invoke-Command), optionally with -Credential.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    if (Test-IsLocalComputerName -ComputerName $ComputerName) {
        & $ScriptBlock @ArgumentList
    } else {
        if ($Credential) {
            Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        } else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
    }
}

function Test-WSManSmart {
    param([Parameter(Mandatory)][string]$ComputerName)

    if (Test-IsLocalComputerName -ComputerName $ComputerName) {
        return $true
    }

    try {
        if ($Credential) {
            Test-WSMan -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop | Out-Null
        } else {
            Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        }
        return $true
    } catch {
        return $false
    }
}

# Get all DCs (FQDN/HostName)
$domainControllers = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
$dcCount = $domainControllers.Count

Write-Host ""
Write-Host ("Local host detected as: {0}{1}" -f $localHostShort, $(if ($localFqdn) { " ($localFqdn)" } else { "" })) -ForegroundColor DarkGray
Write-Host "Domain Controllers found: $dcCount" -ForegroundColor DarkGray
Write-Host ""

# Recommended size by DC count
$recommendedSizeMB = if ($dcCount -le 5) { 64 } elseif ($dcCount -le 20) { 128 } else { 256 }
$minBytes = $recommendedSizeMB * 1MB

Write-Host "Checking Directory Service log size on all Domain Controllers..." -ForegroundColor Cyan

# ---- Log size check (local for self; WinRM for others) ----
$logSizeResults = @()
$logInfoBlock = { Get-WinEvent -ListLog 'Directory Service' }

foreach ($dc in $domainControllers) {
    try {
        $logInfo = Invoke-DC -ComputerName $dc -ScriptBlock $logInfoBlock
        $sizeMB = [math]::Round(($logInfo.MaximumSizeInBytes / 1MB), 1)
        $statusMsg = if ($logInfo.MaximumSizeInBytes -lt $minBytes) { "Too Small (<${recommendedSizeMB} MB)" } else { "OK" }

        $logSizeResults += [PSCustomObject]@{
            'Domain Controller' = $dc
            'Log Size (MB)'     = $sizeMB
            'Status'            = $statusMsg
        }
    } catch {
        $msg = $_.Exception.Message
        $logSizeResults += [PSCustomObject]@{
            'Domain Controller' = $dc
            'Log Size (MB)'     = 'N/A'
            'Status'            = ("Query error: " + $msg)
        }
    }
}

$logSizeResults | Sort-Object 'Domain Controller' | Format-Table -AutoSize
Write-Host ("`nRecommended Directory Service log size for {0} DCs: {1} MB`n" -f $dcCount, $recommendedSizeMB) -ForegroundColor DarkGray

# ---------- Pre-flight checks (local for self; WinRM for others) ----------
function Test-DcPreflight {
    param([Parameter(Mandatory)][string]$ComputerName)

    $result = [ordered]@{
        ComputerName   = $ComputerName
        IsLocal        = (Test-IsLocalComputerName -ComputerName $ComputerName)
        WinRM          = $false
        RegistryAccess = $false
        EventLogAccess = $false
        Note           = ""
    }

    # 1) WinRM (skip requirement for local)
    if ($result.IsLocal) {
        $result.WinRM = $true
    } else {
        if (Test-WSManSmart -ComputerName $ComputerName) {
            $result.WinRM = $true
        } else {
            $result.Note = "Remoting failed (WinRM): Test-WSMan failed"
            return [PSCustomObject]$result
        }
    }

    # 2) Registry read (NTDS\Parameters + NTDS\Diagnostics)
    try {
        $regOK = Invoke-DC -ComputerName $ComputerName -ScriptBlock {
            try {
                $null = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction Stop
                $null = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -ErrorAction Stop
                $true
            } catch { $false }
        }
        if ($regOK) {
            $result.RegistryAccess = $true
        } else {
            $result.Note = "Registry read failed (NTDS)"
            return [PSCustomObject]$result
        }
    } catch {
        $result.Note = "Registry access error: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    # 3) Event Log access (Directory Service)
    try {
        $ok = Invoke-DC -ComputerName $ComputerName -ScriptBlock {
            try { Get-WinEvent -LogName 'Directory Service' -MaxEvents 1 -ErrorAction Stop | Out-Null; $true } catch { $false }
        }
        if ($ok) {
            $result.EventLogAccess = $true
        } else {
            $result.Note = "Event Log access failed (Directory Service)"
            return [PSCustomObject]$result
        }
    } catch {
        $result.Note = "Event Log test error: $($_.Exception.Message)"
        return [PSCustomObject]$result
    }

    $result.Note = "OK"
    [PSCustomObject]$result
}

Write-Host "Running pre-flight checks (WinRM, Registry, Event Log)..." -ForegroundColor Cyan
$preflight = foreach ($dc in $domainControllers) { Test-DcPreflight -ComputerName $dc }
$preflight | Sort-Object ComputerName | Format-Table ComputerName, IsLocal, WinRM, RegistryAccess, EventLogAccess, Note -AutoSize

# ---------- Remote/local collector (read-only) ----------
$collectorBlock = {
    param($startTimeString, $endTimeString)

    function Get-DiagLevel {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $name = "16 LDAP Interface Events"
        try { (Get-ItemProperty -Path $reg -Name $name -ErrorAction Stop).$name } catch { 0 }
    }

    function Get-CBTValueRaw {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $name = "LdapEnforceChannelBinding"
        try {
            # return $null if missing
            $item = Get-ItemProperty -Path $reg -ErrorAction Stop
            if ($item.PSObject.Properties.Name -contains $name) {
                $v = $item.$name
                if ($null -eq $v -or "$v" -eq "") { return $null }
                return [int]$v
            }
            return $null
        } catch {
            return $null
        }
    }

    function Get-CBTText {
        param($raw)
        if ($null -eq $raw) { return "Not configured (missing)" }
        switch ([int]$raw) {
            0 { "0 - Disabled" }
            1 { "1 - Compatibility (When Supported)" }
            2 { "2 - Require (Always)" }
            default { "$raw - Unknown" }
        }
    }

    $startTime = [datetime]::Parse($startTimeString)
    $endTime   = [datetime]::Parse($endTimeString)

    $logName  = "Directory Service"
    $eventIDs = 3039, 3074, 3075, 3040, 3041

    $diag   = Get-DiagLevel
    $cbtRaw = Get-CBTValueRaw

    $o = [ordered]@{
        DiagLevel   = $diag
        CBTRaw      = $cbtRaw
        CBTModeText = (Get-CBTText $cbtRaw)
        Events      = @()
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName=$logName; ID=$eventIDs; StartTime=$startTime; EndTime=$endTime} -ErrorAction Stop
    } catch { $events = @() }

    foreach ($e in $events) {
        $msg = $e.Message

        $ip = "Unknown"
        try {
            $m = [regex]::Match($msg, 'Client IP address:\s*(?:\r?\n\s*)?([0-9\.\:\[\]a-fA-F]+)', 'Singleline')
            if ($m.Success) { $ip = $m.Groups[1].Value }
        } catch { }

        $acct = "Unknown"
        try {
            $m1 = [regex]::Match($msg, 'Account Name:\s*(.+)$', 'Singleline')
            if ($m1.Success) { $acct = $m1.Groups[1].Value.Trim() }
            if ($acct -eq "Unknown") {
                $m2 = [regex]::Match($msg, 'Identity the client attempted to authenticate as:\s*(.+)$', 'Singleline')
                if ($m2.Success) { $acct = $m2.Groups[1].Value.Trim() }
            }
        } catch { }

        $ClientHost = "No PTR"
        if ($ip -ne "Unknown" -and $ip -notmatch ':') {
            try {
                $ptr = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop | Select-Object -First 1 -ExpandProperty NameHost
                if ($ptr) { $ClientHost = $ptr }
            } catch { }
        }

        $severity = switch ($e.Id) {
            3039 { "Failure" }
            3074 { "Audit (What-If)" }
            3075 { "Audit (What-If)" }
            3040 { "Advisory" }
            3041 { "Advisory" }
            default { "Info" }
        }

        $o.Events += [PSCustomObject]@{
            TimeStamp    = $e.TimeCreated
            EventID      = $e.Id
            Severity     = $severity
            'Client IP'  = $ip
            ClientHost   = $ClientHost
            Account      = $acct
        }
    }

    $o
}

$startTime = (Get-Date).AddDays(-[math]::Abs($DaysBack))
$endTime   = Get-Date

$summary = @()
$details = @()
$state   = @()

Write-Host ""
Write-Host "Checking LDAP Channel Binding events on all Domain Controllers..." -ForegroundColor Cyan
Write-Host ("Time window: {0} to {1}" -f $startTime.ToString('dd-MM-yyyy'), $endTime.ToString('dd-MM-yyyy')) -ForegroundColor DarkGray
Write-Host ("-" * 60)

foreach ($dc in $domainControllers) {
    $pf = $preflight | Where-Object { $_.ComputerName -eq $dc }

    if (-not $pf) {
        Write-Warning ("Failed to query {0}: No preflight result." -f $dc)
        continue
    }
    if (-not $pf.WinRM) {
        Write-Warning ("Failed to query {0}: Remoting failed (WinRM). {1}" -f $dc, $pf.Note)
        continue
    }
    if (-not $pf.RegistryAccess) {
        Write-Warning ("Failed to query {0}: Registry access failed. {1}" -f $dc, $pf.Note)
        continue
    }
    if (-not $pf.EventLogAccess) {
        Write-Warning ("Failed to query {0}: Event Log access failed. {1}" -f $dc, $pf.Note)
        continue
    }

    Write-Host ("Querying {0} ..." -f $dc) -ForegroundColor Cyan

    try {
        $r = Invoke-DC -ComputerName $dc -ScriptBlock $collectorBlock -ArgumentList @($startTime.ToString("o"), $endTime.ToString("o"))
        if (-not $r) { throw "Collector returned no data." }
    } catch {
        Write-Warning ("Failed to query {0}: {1}" -f $dc, $_.Exception.Message)
        continue
    }

    # State row
    $state += [PSCustomObject]@{
        'Domain Controller'           = $dc
        'LDAP Interface Events Level' = $r.DiagLevel
        'CBT Mode'                    = $r.CBTModeText
        'CBT Value'                   = $(if ($null -eq $r.CBTRaw) { "" } else { [string]$r.CBTRaw })
    }

    # Events summary
    $fail = 0; $audit = 0; $adv = 0
    if ($r.Events -and $r.Events.Count -gt 0) {
        foreach ($ev in $r.Events) {
            $details += [PSCustomObject]@{
                TimeStamp           = $ev.TimeStamp
                EventID             = $ev.EventID
                Severity            = $ev.Severity
                'Client IP'         = $ev.'Client IP'
                ClientHost          = $ev.ClientHost
                Account             = $ev.Account
                'Domain Controller' = $dc
            }
        }
        $fail  = ($r.Events | Where-Object { $_.EventID -eq 3039 }).Count
        $audit = ($r.Events | Where-Object { $_.EventID -in 3074,3075 }).Count
        $adv   = ($r.Events | Where-Object { $_.EventID -in 3040,3041 }).Count
    } else {
        Write-Warning ("No CBT-related events found on {0} in the selected window." -f $dc)
    }

    # Risk heuristic (informational)
    $risk = "Low"
    if ($fail -gt 0) {
        $risk = "High (Failures present)"
    } elseif ($audit -gt 0) {
        $risk = "Medium (Audit hits)"
    } elseif ($r.CBTModeText -notlike "2 -*") {
        $risk = "Medium (CBT not enforced)"
    }

    $summary += [PSCustomObject]@{
        'Domain Controller'  = $dc
        'CBT Mode'           = $r.CBTModeText
        'Failures 3039'      = $fail
        'Audit 3074/3075'    = $audit
        'Advisory 3040/3041' = $adv
        'Risk'               = $risk
    }
}

# Console views
Write-Host ""
Write-Host "CBT State per Domain Controller:" -ForegroundColor Yellow
$state | Sort-Object 'Domain Controller' | Format-Table -AutoSize

Write-Host ""
Write-Host "CBT Event Summary (last $DaysBack days):" -ForegroundColor Magenta
if ($summary.Count -gt 0) {
    $summary | Sort-Object 'Domain Controller' | Format-Table 'Domain Controller','CBT Mode','Failures 3039','Audit 3074/3075','Advisory 3040/3041','Risk' -AutoSize
    # =========================
# INSERT THIS BLOCK
# =========================

# --- Explicit note: why clients show as Unknown + GPO requirement ---
$needVerbose = $false
$diagTable = @()

try {
    $diagTable = $state | ForEach-Object {
        [pscustomobject]@{
            'Domain Controller' = $_.'Domain Controller'
            'LDAP Interface Events Level' = [int]($_.'LDAP Interface Events Level')
        }
    }
    $needVerbose = ($diagTable | Where-Object { $_.'LDAP Interface Events Level' -lt 2 }).Count -gt 0
} catch {
    # If something unexpected happens, do not break script output
    $needVerbose = $true
}

if ($needVerbose) {
    Write-Host ""
    Write-Host "IMPORTANT NOTE - LDAP client visibility (CBT audit)" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------" -ForegroundColor Yellow
    Write-Host "LDAP Interface Events are not logged at a sufficient level on one or more Domain Controllers."
    Write-Host ""
    Write-Host "Registry value:"
    Write-Host '  HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
    Write-Host '  "16 LDAP Interface Events"'
    Write-Host ""
    Write-Host "Current levels per DC (need >= 2 to identify clients):"
    $diagTable | Sort-Object 'Domain Controller' | Format-Table -AutoSize

    Write-Host ""
    Write-Host "Impact:"
    Write-Host "  With level 0/1, Windows typically logs only advisory events (e.g. 3040/3041)"
    Write-Host "  which do NOT include client IP address or account information."
    Write-Host "  Therefore, 'Client IP' and 'Account' may show as 'Unknown' in this report."
    Write-Host ""
    Write-Host "Required action (must be via GPO for consistency):"
    Write-Host "  Configure ALL Domain Controllers using Group Policy Preferences (Registry):"
    Write-Host '    Key      : HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
    Write-Host '    Value    : 16 LDAP Interface Events'
    Write-Host '    Type     : REG_DWORD'
    Write-Host '    Data     : 2'
    Write-Host ""
    Write-Host "Next step:"
    Write-Host "  After the GPO is applied and LDAPS traffic has occurred, rerun this audit."
    Write-Host "  This will allow identifying LDAPS clients (IP/account/PTR) before enforcing CBT."
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "LDAP Interface Events Level is >= 2 on all DCs - client identification should be available when 3039/3074/3075 events occur." -ForegroundColor DarkGray
}

# =========================
# END INSERT
# =========================

} else {
    Write-Host "No CBT-related events found for any DC in the selected window." -ForegroundColor DarkGray
}

if ($details.Count -gt 0) {
    Write-Host ""
    Write-Host "CBT Event Details (last $DaysBack days):" -ForegroundColor Magenta
    $details | Sort-Object TimeStamp -Descending | Format-Table TimeStamp,EventID,Severity,'Client IP',ClientHost,Account,'Domain Controller' -AutoSize
}

# Exports
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvState   = Join-Path $logFolder ("CBT_State_{0}.csv" -f $ts)
$csvSummary = Join-Path $logFolder ("CBT_Summary_{0}.csv" -f $ts)
$csvDetails = Join-Path $logFolder ("CBT_Details_{0}.csv" -f $ts)
$txtReport  = Join-Path $logFolder ("CBT_Report_{0}.txt" -f $ts)

$state   | Export-Csv -Path $csvState   -NoTypeInformation -Encoding UTF8
$summary | Export-Csv -Path $csvSummary -NoTypeInformation -Encoding UTF8
if ($details.Count -gt 0) { $details | Export-Csv -Path $csvDetails -NoTypeInformation -Encoding UTF8 }

# Human-readable TXT
$lines = @()
$lines += "LDAPS Channel Binding (CBT) Audit Report"
$lines += ("Generated on: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$lines += ("Days back: {0}" -f $DaysBack)
$lines += ("=" * 60)
$lines += ""
$lines += "Pre-flight results:"
$lines += ($preflight | Sort-Object ComputerName | Format-Table ComputerName,IsLocal,WinRM,RegistryAccess,EventLogAccess,Note -AutoSize | Out-String)
$lines += ""
$lines += "CBT Mode and LDAP Interface Events Level per Domain Controller:"
foreach ($row in ($state | Sort-Object 'Domain Controller')) {
    $lines += (" - {0} : CBT {1} (Value {2}), LDAP Interface Events Level {3}" -f `
        $row.'Domain Controller', $row.'CBT Mode', $(if ($row.'CBT Value') { $row.'CBT Value' } else { "missing" }), $row.'LDAP Interface Events Level')
}
$lines += ""
$lines += ("-" * 60)
$lines += ""
$lines += "CBT Events Summary:"
if ($summary.Count -gt 0) {
    $lines += ($summary | Sort-Object 'Domain Controller' |
        Format-Table 'Domain Controller','CBT Mode','Failures 3039','Audit 3074/3075','Advisory 3040/3041','Risk' -AutoSize | Out-String)
} else {
    $lines += "No CBT-related events found."
}
$lines += ""
$lines += ("-" * 60)
$lines += ""
$lines += "CBT Event Details:"
if ($details.Count -gt 0) {
    $lines += ($details | Sort-Object TimeStamp -Descending |
        Format-Table TimeStamp,EventID,Severity,'Client IP',ClientHost,Account,'Domain Controller' -AutoSize | Out-String)
} else {
    $lines += "No details to show."
}
$lines += ""
$lines += ("=" * 60)

$lines | Out-File -FilePath $txtReport -Encoding UTF8 -Force

Write-Host ("`nCSV exported:`n - {0}`n - {1}{2}`nReport: {3}" -f `
    $csvState, $csvSummary, ($(if ($details.Count -gt 0) { "`n - $csvDetails" } else { "" })), $txtReport) -ForegroundColor Green
