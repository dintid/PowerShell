<#
MODNI 20250708
S-C-INACTIVE
#>

param(
    [int]$InactiveDays = 180
)

Import-Module ActiveDirectory -ErrorAction Stop

# ---- Export setup ----------------------------------------------------------------
$ExportFolder = 'C:\itm8\S-C-Inactive'
if (-not (Test-Path $ExportFolder)) {
    New-Item -ItemType Directory -Path $ExportFolder -Force | Out-Null
}
$TimeStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$CsvPath   = Join-Path $ExportFolder "S-C-Inactive_$TimeStamp.csv"

# ---- Obsolete OS patterns --------------------------------------------------------
$ObsoleteOsPatterns = @(
    'Windows XP',
    'Windows Vista',
    'Windows 7',
    'Windows 8(?:\.1)?',
    'Windows 10 (1507|1511|16\d\d|1703|1709|1803|1809|19\d\d|2004|20H2)',
    'Windows Server 2003',
    'Windows Server 2008(?: R2)?',
    'Windows Server 2012(?: R2)?'
)

$CutoffDate = (Get-Date).AddDays(-$InactiveDays)

# ---- Collect data ----------------------------------------------------------------
$results = Get-ADComputer -Filter * -Properties LastLogonTimestamp,OperatingSystem,OperatingSystemVersion,Enabled |
ForEach-Object {
    $lastLogon = if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime($_.LastLogonTimestamp) } else { $null }
    $daysSince = if ($lastLogon) { (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days } else { 'N/A' }

    $inactive  = (-not $lastLogon) -or ($lastLogon -lt $CutoffDate)

    $obsolete  = $false
    foreach ($pattern in $ObsoleteOsPatterns) {
        if ($_.OperatingSystem -match $pattern) { $obsolete = $true; break }
    }

    if ($inactive -or $obsolete) {
        [PSCustomObject]@{
            ComputerName    = $_.Name
            Enabled         = $_.Enabled
            OperatingSystem = $_.OperatingSystem
            OSVersion       = $_.OperatingSystemVersion
            LastLogon       = $lastLogon
            Inactive        = if ($inactive) { "Inactive ($daysSince days)" } else { "Active" }
            ObsoleteOS      = $obsolete
            ADPath          = ($_.DistinguishedName -replace '^CN=[^,]+,', '')  # <-- NEW COLUMN
            InactiveFlag    = $inactive
        }
    }
}

if (-not $results) {
    Write-Host 'No inactive or obsolete-OS computer accounts found.' -ForegroundColor Cyan
    return
}

# ---- Display table with yellow header -------------------------------------------
$display = $results | Select-Object ComputerName,ADPath,ObsoleteOS,Inactive,Enabled,OperatingSystem,OSVersion,LastLogon
$table   = $display | Format-Table -AutoSize | Out-String
$lines   = $table -split "`r?`n"

Write-Host $lines[0] -ForegroundColor Yellow
$lines[1..($lines.Count-1)] | ForEach-Object { Write-Host $_ }

# ---- Summary counts -------------------------------------------------------------
$totalFound            = $results.Count
$totalInactive         = ($results | Where-Object { $_.InactiveFlag }).Count
$totalObsoleteInactive = ($results | Where-Object { $_.ObsoleteOS -and $_.InactiveFlag }).Count
$totalObsoleteActive   = ($results | Where-Object { $_.ObsoleteOS -and -not $_.InactiveFlag }).Count

Write-Host ''
Write-Host 'Totals:' -ForegroundColor Cyan
Write-Host ("Total found               : {0}" -f $totalFound)
Write-Host ("Total inactive            : {0}" -f $totalInactive)
Write-Host ("Total ObsoleteOS inactive : {0}" -f $totalObsoleteInactive)
Write-Host ("Total ObsoleteOS active   : {0}" -f $totalObsoleteActive)

# ---- Export CSV ------------------------------------------------------------------
$display | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "CSV exported to $CsvPath" -ForegroundColor Green
