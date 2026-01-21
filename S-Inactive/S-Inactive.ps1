<#
MODNI 20251022
PingCastle mapping: S-Inactive (user accounts)

Description:
    This script lists all *enabled Active Directory user accounts* that have been inactive
    for more than the number of days specified by -InactiveDays (default: 180).

    It mirrors the logic used by PingCastle’s “S-Inactive” indicator, which reports
    enabled user accounts whose last logon is older than the chosen threshold.

Technical details:
    • The script uses the 'LastLogonDate' property, which is a replicated, computed value
      derived from the attribute 'lastLogonTimestamp'.
    • 'lastLogonTimestamp' was introduced in Windows Server 2003.  Older accounts created
      before that attribute existed—or accounts that have *never* authenticated since
      its introduction—will have a null value here.
    • Therefore, if 'LastLogonDate' is blank, it means:
         ? The user has never logged on since creation, OR
         ? The account was created prior to Server 2003 and has never logged on since then.
      PingCastle considers such accounts *inactive*.
    • This report is intended for identifying dormant or stale enabled accounts.

Output:
    - Console table with summary counts
    - CSV file: C:\ITM8\S-Inactive\S-Inactive_<timestamp>.csv
#>

[CmdletBinding()]
param(
    [int]$InactiveDays = 180
)

Import-Module ActiveDirectory -ErrorAction Stop

# --- Export setup ---------------------------------------------------------------
$ExportFolder = 'C:\ITM8\S-Inactive'
if (-not (Test-Path -LiteralPath $ExportFolder)) {
    New-Item -ItemType Directory -Path $ExportFolder -Force | Out-Null
}
$TimeStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$CsvPath   = Join-Path $ExportFolder ("S-Inactive_{0}.csv" -f $TimeStamp)

$CutoffDate = (Get-Date).AddDays(-$InactiveDays)

Write-Host ""
Write-Host ("Detecting enabled user accounts inactive for more than {0} days..." -f $InactiveDays) -ForegroundColor Cyan
Write-Host "Accounts with an empty 'LastLogonDate' have never logged on since their creation" -ForegroundColor DarkYellow
Write-Host "or were created before Windows Server 2003 introduced the 'lastLogonTimestamp' attribute." -ForegroundColor DarkYellow
Write-Host "Such accounts are treated as inactive by PingCastle." -ForegroundColor DarkYellow
Write-Host ""

# --- Collect data (PingCastle logic) --------------------------------------------
$results = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan (New-TimeSpan -Days $InactiveDays) -ResultPageSize 2000 -ResultSetSize $null |
    Where-Object { $_.Enabled -eq $true } |
    Select-Object Name, SamAccountName, DistinguishedName, Enabled, LastLogonDate

if (-not $results) {
    Write-Host "No enabled user accounts inactive for more than $InactiveDays days were found." -ForegroundColor Cyan
    @() | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ("CSV exported to {0}" -f $CsvPath) -ForegroundColor Green
    return
}

# --- Enrich results with inactivity age -----------------------------------------
$now = Get-Date
$report = foreach ($r in $results) {
    $lastLogon = $r.LastLogonDate
    $daysSince = if ($lastLogon) { (New-TimeSpan -Start $lastLogon -End $now).Days } else { 'N/A' }

    [PSCustomObject]@{
        Name              = $r.Name
        SamAccountName    = $r.SamAccountName
        DistinguishedName = $r.DistinguishedName
        Enabled           = $r.Enabled
        LastLogonDate     = $lastLogon
        DaysSinceLogon    = $daysSince
    }
}

# --- Display results ------------------------------------------------------------
$display = $report | Select-Object Name,SamAccountName,DaysSinceLogon,Enabled,LastLogonDate
$table = $display | Format-Table -AutoSize | Out-String
$lines = $table -split "`r?`n"

if ($lines.Count -gt 0) {
    Write-Host $lines[0] -ForegroundColor Yellow
    if ($lines.Count -gt 1) {
        $lines[1..($lines.Count-1)] | ForEach-Object { Write-Host $_ }
    }
}

# --- Summary --------------------------------------------------------------------
$total = $report.Count
$emptyDates = ($report | Where-Object { -not $_.LastLogonDate }).Count
Write-Host ""
Write-Host ("Total enabled user accounts inactive > {0} days : {1}" -f $InactiveDays,$total) -ForegroundColor Cyan
if ($emptyDates -gt 0) {
    Write-Host ("(of which {0} have no LastLogonDate — meaning they have never logged on" -f $emptyDates) -ForegroundColor DarkYellow
    Write-Host "  or were created prior to Windows Server 2003 tracking lastLogonTimestamp)" -ForegroundColor DarkYellow
}

# --- Export CSV -----------------------------------------------------------------
$report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host ("CSV exported to {0}" -f $CsvPath) -ForegroundColor Green
