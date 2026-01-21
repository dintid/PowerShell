<#  
MODNI 20250627
S-KerberosArmoring
• Checks that all DCs have Kerberos Armoring (FAST) enabled  
• If OK, scans Kerberos AS-REQs to identify clients using or not using FAST  
• Checks each domain controller to see if Kerberos Armoring (FAST) is enabled
• Warns and exits if any DC is not properly configured
• Asks how many days of Kerberos events to scan (default: 3 days)
• Asks how many unique clients to show (default: 10)
• Scans security logs (Event ID 4768) for Kerberos authentication requests
• Detects if each client used FAST (PreAuthType = 138) or not
• Adds each client’s operating system from Active Directory (best effort)
• Displays newest event per unique client in a table
• Shows total number of unique clients detected
• Warns (in yellow) if any client is still not using FAST, indicating a deployment risk

#>

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# ──────────────── SECTION 1 – CHECK DC KDC FAST SETTING ────────────────
$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
$regName = 'EnableCbacAndArmor'
$meaning = @{
    0 = 'Not configured / Not supported'
    1 = 'Supported'
    2 = 'Always provide claims'
    3 = 'Fail unarmored auth requests'
}

Write-Host "`nChecking every domain controller for KDC FAST support …`n" -ForegroundColor Cyan

$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

$kdcResults = foreach ($dc in $dcs) {
    try {
        $val = Invoke-Command -ComputerName $dc -ErrorAction Stop -ScriptBlock {
            $p = Get-ItemProperty -Path $using:regPath -Name $using:regName -ErrorAction SilentlyContinue
            if ($null -eq $p) { return $null } else { return [int]$p.$using:regName }
        }

        [pscustomobject]@{
            DomainController = $dc
            RawValue         = $val
            Setting          = if ($null -eq $val) { 'Not configured' } else { $meaning[$val] }
            Configured       = if ($val -and $val -ge 1) { $true } else { $false }
        }
    }
    catch {
        [pscustomobject]@{
            DomainController = $dc
            RawValue         = '—'
            Setting          = 'Unavailable (RPC/WinRM failed)'
            Configured       = $false
        }
    }
}

# Display per-DC status
$kdcResults | Sort-Object DomainController | ForEach-Object {
    $fg = if ($_.Configured) { 'Green' } else { 'Yellow' }
    Write-Host ("{0,-30}  {1}" -f $_.DomainController, $_.Setting) -ForegroundColor $fg
}

if ($kdcResults.Configured -contains $false) {
    Write-Host "`nAt least one KDC does NOT have FAST/armoring enabled." -ForegroundColor Yellow
    Write-Host "Please configure the GPO: `"KDC support for claims, compound authentication and Kerberos armoring`" and rerun the script.`n" -ForegroundColor Yellow
    return
} else {
    Write-Host "`nAll KDCs are correctly configured for Kerberos FAST – continuing …`n" -ForegroundColor Green
}

# ──────────────── SECTION 2 – CLIENT FAST USAGE SCAN ────────────────

$logName  = 'Security'
$eventId  = 4768  # Kerberos AS-REQ

$inputDays = Read-Host 'How many days back to scan? (Enter = 3)'
if ([string]::IsNullOrWhiteSpace($inputDays))      { $daysBack = 3 }
elseif ($inputDays -as [int] -gt 0)                { $daysBack = [int]$inputDays }
else  { Write-Warning 'Invalid number given – defaulting to 3.'; $daysBack = 3 }

$inputCount = Read-Host 'How many unique clients to display? (Enter = 10)'
if ([string]::IsNullOrWhiteSpace($inputCount))     { $maxRows = 10 }
elseif ($inputCount -as [int] -gt 0)                { $maxRows = [int]$inputCount }
else  { Write-Warning 'Invalid number given – defaulting to 10.'; $maxRows = 10 }

Write-Host "Scanning the last $daysBack day(s) – will show up to $maxRows unique clients…" -ForegroundColor Cyan

$statusDescriptions = @{
    '0x0'          = 'Success (TGT issued)'
    '0x6'          = 'Incorrect function'
    '0x7'          = 'The data is invalid'
    '0xc'          = 'Access denied'
    '0x6f'         = 'Pre-authentication failed'
    '0xc000018b'   = 'KDC_ERR_PREAUTH_FAILED'
    '0xc000018c'   = 'KDC_ERR_PREAUTH_REQUIRED'
    '0xc000018d'   = 'KDC_ERR_PREAUTH_EXPIRED'
    '0xc0000193'   = 'KDC_ERR_S_PRINCIPAL_UNKNOWN'
    '0xc0000194'   = 'KDC_ERR_NOT_UNIQUE'
    '0xc0000195'   = 'KDC_ERR_NULL_KEY'
    '0xc0000196'   = 'KDC_ERR_CANT_POSTDATE'
    '0xc0000197'   = 'KDC_ERR_CANT_VALIDATE'
    '0xc0000198'   = 'KDC_ERR_KEY_EXPIRED'
    '0xc0000199'   = 'KDC_ERR_PREAUTH_NOT_OK'
    '0xc000019a'   = 'KDC_ERR_WRONG_REALM'
    '0xc000019b'   = 'KDC_ERR_NULL_KEY'
}

$startTime = (Get-Date).AddDays(-$daysBack)
$events = Get-WinEvent -FilterHashtable @{
    LogName   = $logName
    Id        = $eventId
    StartTime = $startTime
}

$parsed = foreach ($ev in $events) {
    $xml = [xml]$ev.ToXml()

    $ip = ($xml.Event.EventData.Data | Where {$_.Name -eq 'IpAddress'}).'#text'
    if ($ip -eq '::1')           { continue }
    if ($ip -like '::ffff:*')    { $ip = $ip.Substring(7) }

    $preAuthType = ($xml.Event.EventData.Data | Where {$_.Name -eq 'PreAuthType'}).'#text'
    $armoring    = if ($preAuthType -eq '138') { 'Kerberos Armoring used' } else { 'Armoring Not Used' }

    $status = ($xml.Event.EventData.Data | Where {$_.Name -eq 'Status'}).'#text'
    $statusDesc = if ($statusDescriptions.ContainsKey($status)) { $statusDescriptions[$status] } else { 'Unknown status code' }

    $clientName   = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetUserName'}).'#text'
    $targetDomain = ($xml.Event.EventData.Data | Where {$_.Name -eq 'TargetDomainName'}).'#text'

    [pscustomobject]@{
        TimeGenerated     = $ev.TimeCreated
        ClientIP          = $ip
        ClientName        = $clientName
        TargetDomain      = $targetDomain
        Armoring          = $armoring
        StatusDescription = $statusDesc
    }
}

# Add ClientOS from AD
foreach ($item in $parsed) {
    try {
        $comp = Get-ADComputer -Identity $item.ClientName -Properties OperatingSystem -ErrorAction SilentlyContinue
        if ($comp -and $comp.OperatingSystem) {
            $item | Add-Member -NotePropertyName ClientOS -NotePropertyValue $comp.OperatingSystem
        } else {
            $item | Add-Member -NotePropertyName ClientOS -NotePropertyValue 'Unknown'
        }
    } catch {
        $item | Add-Member -NotePropertyName ClientOS -NotePropertyValue 'Unknown'
    }
}

$latestPerClient = $parsed |
    Sort-Object TimeGenerated -Descending |
    Group-Object ClientName |
    ForEach-Object { $_.Group[0] } |
    Sort-Object TimeGenerated -Descending

$latestPerClient |
    Select-Object -First $maxRows -Property TimeGenerated, ClientIP, ClientName, TargetDomain, Armoring, StatusDescription, ClientOS |
    Format-Table -AutoSize

Write-Host "`nTotal unique clients found: $($latestPerClient.Count)" -ForegroundColor Cyan

if ($latestPerClient.Armoring -contains 'Armoring Not Used') {
    Write-Host "Armoring must not be enabled unless all clients can be manually updated." -ForegroundColor Yellow
}
