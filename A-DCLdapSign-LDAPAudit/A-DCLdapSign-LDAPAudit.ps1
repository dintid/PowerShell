<#
MODNI 20250804
PingCastle ID: A-DCLdapSign

🔎 Script Description:
- Retrieves all Domain Controllers in the current domain.
- Checks the configured maximum size of the Directory Service log on each DC.
- Recommends appropriate log size based on the number of DCs.
- Audits LDAP Interface Events (2887, 2889) for the past 7 days.
- Collects and parses:
    • Simple binds without SSL/TLS (Event ID 2887)
    • SASL binds without signing (Event ID 2887)
    • Insecure LDAP bind attempts with client IPs and identities (Event ID 2889)
- Displays LDAP logging level per DC (based on registry key 16).
- Outputs results to:
    • Human-readable console tables
    • CSV files for summary and details
    • Combined .txt report in C:\itm8\A-DCLdapSign

Intended for LDAP signing audit and diagnostic review before enforcing stricter LDAP settings.
#>

Import-Module ActiveDirectory

$logFolder = "C:\itm8\A-DCLdapSign"
if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder | Out-Null
}

# Get all Domain Controllers in the current domain
$domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

Write-Host "`n📦 Checking Directory Service log size on all Domain Controllers..." -ForegroundColor Cyan

# Dynamically recommend log size based on number of DCs
$dcCount = $domainControllers.Count
$recommendedSizeMB = switch ($dcCount) {
    { $_ -le 5 }      { 64; break }
    { $_ -le 20 }     { 128; break }
    default           { 256 }
}
$minRecommendedSizeBytes = $recommendedSizeMB * 1MB

$logSizeResults = @()

foreach ($dc in $domainControllers) {
    try {
        $sizeBytes = Invoke-Command -ComputerName $dc -ScriptBlock {
            $size = 0
            $output = wevtutil get-log "Directory Service"
            foreach ($line in $output) {
                if ($line -match "maxSize:\s*(\d+)") {
                    $size = [int]$matches[1]
                    break
                }
            }
            return $size
        }

        $sizeMB = [math]::Round($sizeBytes / 1MB, 1)
        $status = if ($sizeBytes -lt $minRecommendedSizeBytes) {
            "❌ Too Small (<${recommendedSizeMB} MB)"
        } else {
            "✅ OK"
        }

        $logSizeResults += [PSCustomObject]@{
            'Domain Controller' = $dc
            'Log Size (MB)'      = $sizeMB
            'Status'             = $status
        }

    } catch {
        $logSizeResults += [PSCustomObject]@{
            'Domain Controller' = $dc
            'Log Size (MB)'      = "N/A"
            'Status'             = "⚠️ Error: $_"
        }
    }
}

$logSizeResults | Format-Table -AutoSize
Write-Host "`n📌 Recommended log size based on your environment ($dcCount DCs): $recommendedSizeMB MB`n" -ForegroundColor DarkGray

# Script block to run remotely on each DC
$remoteScript = {
    param($startTimeString, $endTimeString)

    function Get-LdapInterfaceEventsLevel {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
        $valueName = "16 LDAP Interface Events"
        try {
            $value = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop | Select-Object -ExpandProperty $valueName
            return $value
        } catch {
            return 0
        }
    }

    function Get-BindTypeDescription {
        param($bindType)
        switch ($bindType) {
            '1' { return "Simple Bind (unencrypted)" }
            '2' { return "SASL Bind (Negotiate/Kerberos/NTLM/Digest) unsigned" }
            default { return "Unknown Bind Type ($bindType)" }
        }
    }

    $startTime = [datetime]::Parse($startTimeString)
    $endTime = [datetime]::Parse($endTimeString)

    $logName = "Directory Service"
    $eventIDs = 2887, 2889

    $loggingLevel = Get-LdapInterfaceEventsLevel

    $results = [PSCustomObject]@{
        LoggingLevel = $loggingLevel
        BindSummary  = @()
        BindDetails  = @()
    }

    try {
        try {
            $allEvents = Get-WinEvent -FilterHashtable @{LogName=$logName; ID=$eventIDs; StartTime=$startTime; EndTime=$endTime} -ErrorAction Stop
        }
        catch {
            # No events found, return empty arrays to avoid terminating error
            $allEvents = @()
        }
    } catch {
        $results.Error = $_.Exception.Message
        return $results
    }

    foreach ($id in $eventIDs) {
        $filtered = $allEvents | Where-Object { $_.Id -eq $id }
        if ($filtered) {
            if ($id -eq 2887) {
                foreach ($event in $filtered) {
                    $simpleBindMatch = [regex]::Match($event.Message, 'Number of simple binds performed without SSL/TLS:\s*(\d+)')
                    $saslBindMatch = [regex]::Match($event.Message, 'Number of Negotiate/Kerberos/NTLM/Digest binds performed without signing:\s*(\d+)')

                    $entry = [PSCustomObject]@{
                        Time                       = $event.TimeCreated
                        'Simple binds without SSL' = if ($simpleBindMatch.Success) { [int]$simpleBindMatch.Groups[1].Value } else { 0 }
                        'SASL binds without signing' = if ($saslBindMatch.Success) { [int]$saslBindMatch.Groups[1].Value } else { 0 }
                    }
                    $results.BindSummary += $entry
                }
            }
            elseif ($id -eq 2889) {
                foreach ($event in $filtered) {
                    $message = $event.Message
                    $timestamp = $event.TimeCreated

                    $ipMatch = [regex]::Match($message, 'Client IP address:\s*(?:\r?\n\s*)?([\d\.]+)')
                    $ip = if ($ipMatch.Success) { $ipMatch.Groups[1].Value } else { "Unknown" }

                    $identityMatch = [regex]::Match($message, 'Identity the client attempted to authenticate as:\s*(.+)')
                    $identity = if ($identityMatch.Success) { $identityMatch.Groups[1].Value.Trim() } else { "Unknown" }

                    $bindTypeMatch = [regex]::Match($message, 'Binding Type:\s*(.+)')
                    $bindTypeRaw = if ($bindTypeMatch.Success) { $bindTypeMatch.Groups[1].Value.Trim() } else { "Unknown" }

                    $bindType = Get-BindTypeDescription $bindTypeRaw

                    try {
                        $hostname = (Resolve-DnsName -ErrorAction Stop -Name $ip -Type PTR | Select-Object -First 1 -ExpandProperty NameHost)
                    } catch {
                        $hostname = "No PTR record"
                    }

                    $entry = [PSCustomObject]@{
                        TimeStamp   = $timestamp
                        'Client IP' = $ip
                        Hostname    = $hostname
                        Identity    = $identity
                        'Bind Type' = $bindType
                    }

                    $results.BindDetails += $entry
                }
            }
        }
    }

    return $results
}

$startTime = (Get-Date).AddDays(-7)
$endTime = Get-Date
$startTimeString = $startTime.ToString()
$endTimeString = $endTime.ToString()

$allBindSummary = @()
$allBindDetails = @()
$dcLoggingLevels = @{}

Write-Host "🔍 Checking LDAP Interface Events on all Domain Controllers..." -ForegroundColor Cyan
Write-Host "🕒 Time window: $($startTime.ToString('dd-MM-yyyy')) to $($endTime.ToString('dd-MM-yyyy'))" -ForegroundColor DarkGray
Write-Host ("-" * 60)

foreach ($dc in $domainControllers) {
    Write-Host "🌐 Querying $dc ..." -ForegroundColor Cyan
    try {
        $result = Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ArgumentList $startTimeString, $endTimeString -ErrorAction Stop

        if ($null -ne $result.Error) {
            Write-Warning "Error on ${dc}: $($result.Error)"
            continue
        }

        $dcLoggingLevels[$dc] = $result.LoggingLevel

        foreach ($item in $result.BindSummary) {
            $simple = $item.'Simple binds without SSL'
            $sasl = $item.'SASL binds without signing'

            $simpleStatus = if ($simple -eq 0) { "None" }
                            elseif ($simple -lt 5) { "Low" }
                            else { "High" }

            $saslStatus = if ($sasl -eq 0) { "None" }
                          elseif ($sasl -lt 5) { "Low" }
                          else { "High" }

            $status = if ($simple -eq 0 -and $sasl -eq 0) { "None" }
                      elseif ($simple -ge 5 -or $sasl -ge 5) { "High" }
                      else { "Low" }

            $obj = [PSCustomObject]@{
                Time                       = $item.Time
                'Simple binds without SSL' = "$simpleStatus ($simple)"
                'SASL binds without signing' = "$saslStatus ($sasl)"
                Status                     = $status
                'Domain Controller'        = $dc
            }
            $allBindSummary += $obj
        }

        foreach ($item in $result.BindDetails) {
            $status = if ($item.'Bind Type' -match 'unencrypted') { "Insecure" } else { "Secure" }

            $obj = [PSCustomObject]@{
                TimeStamp          = $item.TimeStamp
                'Client IP'        = $item.'Client IP'
                Hostname           = $item.Hostname
                Identity           = $item.Identity
                'Bind Type'        = $item.'Bind Type'
                'Domain Controller' = $dc
                Status             = $status
            }
            $allBindDetails += $obj
        }
    } catch {
        Write-Warning "Failed to query ${dc}: $_"
    }
}

Write-Host "`n📌 LDAP Signing Status and Logging Level Summary (based on registry):" -ForegroundColor Yellow
foreach ($dc in $domainControllers) {
    $level = $dcLoggingLevels[$dc]
    if ($level -ge 2) {
        Write-Host "ℹ️ ${dc}: Logging enabled at level $level" -ForegroundColor Green
    } else {
        Write-Host "⚠️ ${dc}: Logging NOT enabled or below recommended level ($level)" -ForegroundColor Red
    }
}
Write-Host ("-" * 60)

# Export CSV files
if ($allBindSummary.Count -gt 0) {
    Write-Host "`n📊 Combined LDAP Bind Summary (Event ID 2887) from all DCs:" -ForegroundColor Magenta
    $allBindSummary | Sort-Object Time -Descending | Format-Table Time,'Simple binds without SSL','SASL binds without signing','Status','Domain Controller' -AutoSize
    $csvSummaryPath = "$logFolder\LDAPBindSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $allBindSummary | Export-Csv -Path $csvSummaryPath -NoTypeInformation
    Write-Host "✅ LDAP Bind Summary exported to $csvSummaryPath" -ForegroundColor Green
} else {
    Write-Host "❌ No Event ID 2887 entries found on any DC." -ForegroundColor DarkGray
}

if ($allBindDetails.Count -gt 0) {
    Write-Host "`n📊 Combined Insecure Bind Activity (Event ID 2889) from all DCs:" -ForegroundColor Magenta
    $allBindDetails | Sort-Object TimeStamp -Descending | Format-Table TimeStamp,'Client IP',Hostname,Identity,'Bind Type','Domain Controller','Status' -AutoSize
    $csvDetailsPath = "$logFolder\InsecureBindDetails_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $allBindDetails | Export-Csv -Path $csvDetailsPath -NoTypeInformation
    Write-Host "✅ Insecure Bind Details exported to $csvDetailsPath" -ForegroundColor Green
} else {
    Write-Host "❌ No Event ID 2889 entries found on any DC." -ForegroundColor DarkGray
}

# Create combined human-readable text report
$txtReportPath = "$logFolder\LDAP_Insecure_Bind_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

$reportContent = @()
$reportContent += "LDAP Interface Events Audit Report"
$reportContent += "Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$reportContent += ("=" * 60)
$reportContent += ""
$reportContent += "LDAP Interface Events Logging Levels per Domain Controller:"
foreach ($dc in $domainControllers) {
    $level = $dcLoggingLevels[$dc]
    if ($null -eq $level) { $level = "N/A" }
    $reportContent += " - $dc : $level"
}
$reportContent += ""
$reportContent += ("-" * 60)
$reportContent += ""
$reportContent += "Event ID 2887 - Summary of Insecure LDAP Binds (Last 7 Days):"
if ($allBindSummary.Count -gt 0) {
    $summaryTable = $allBindSummary | Sort-Object Time -Descending | Format-Table Time,'Simple binds without SSL','SASL binds without signing','Status','Domain Controller' -AutoSize | Out-String
    $reportContent += $summaryTable
} else {
    $reportContent += "No Event ID 2887 entries found."
}
$reportContent += ""
$reportContent += ("-" * 60)
$reportContent += ""
$reportContent += "Event ID 2889 - Detailed Insecure Bind Activity (Last 7 Days):"
if ($allBindDetails.Count -gt 0) {
    $detailsTable = $allBindDetails | Sort-Object TimeStamp -Descending | Format-Table TimeStamp,'Client IP',Hostname,Identity,'Bind Type','Domain Controller','Status' -AutoSize | Out-String
    $reportContent += $detailsTable
} else {
    $reportContent += "No Event ID 2889 entries found."
}
$reportContent += ""
$reportContent += ("=" * 60)

$reportContent | Out-File -FilePath $txtReportPath -Encoding UTF8

Write-Host "📝 Combined human-readable report saved to $txtReportPath" -ForegroundColor Green
