<#
Script Name:    A-DsHeuristicsLDAPSecurity
Author:         MODNI
Date:           2025-12-03
PingCastle Rule: A-DsHeuristicsLDAPSecurity

Purpose:
    This script connects to every domain controller in the current forest
    and reads the dSHeuristics attribute from that DC's view of:

        CN=Directory Service,CN=Windows NT,CN=Services,<Configuration NC>

    It verifies:
        - Whether all domain controllers report the same value
        - Whether dSHeuristics is unset or misconfigured

    Logs are written to:
        C:\ITM8\A-DsHeuristicsLDAPSecurity\

    The script is read-only and makes no changes to AD.
#>

# ----------------------------
#   Logging Setup
# ----------------------------
$LogFolder = "C:\ITM8\A-DsHeuristicsLDAPSecurity"

if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory | Out-Null
}

$timestamp = (Get-Date -Format "yyyy-MM-dd_HH-mm-ss")
$csvPath   = Join-Path $LogFolder ("A-DsHeuristicsLDAPSecurity_{0}.csv" -f $timestamp)
$txtPath   = Join-Path $LogFolder ("A-DsHeuristicsLDAPSecurity_{0}.txt" -f $timestamp)


# ----------------------------
#   Get all DCs in the forest
# ----------------------------
try {
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}
catch {
    Write-Host "Unable to get current forest" -ForegroundColor Red
    throw
}

$dcList = @()
foreach ($domain in $forest.Domains) {
    foreach ($dc in $domain.DomainControllers) {
        $dcList += $dc
    }
}

if (-not $dcList -or $dcList.Count -eq 0) {
    Write-Host "No domain controllers found in the forest" -ForegroundColor Red
    return
}

Write-Host ("Found {0} domain controllers in the forest" -f $dcList.Count) -ForegroundColor Yellow
Write-Host ""


# ----------------------------
#   Read dSHeuristics per DC
# ----------------------------
$results = @()

foreach ($dc in $dcList) {
    $dcName = $dc.Name
    $site   = $dc.SiteName

    $value        = $null
    $errorText    = $null
    $configNCStr  = $null

    try {
        # Use this DC's RootDSE to get its Configuration NC as a string
        $rootDse     = [ADSI]("LDAP://{0}/RootDSE" -f $dcName)
        $configNCStr = [string]$rootDse.configurationNamingContext

        # Target server explicitly using its own Config NC
        $path = "LDAP://{0}/CN=Directory Service,CN=Windows NT,CN=Services,{1}" -f $dcName, $configNCStr

        $ds = [ADSI]$path
        $value = $ds.dSHeuristics

        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = "<not set>"
        }
    }
    catch {
        $errorText = $_.Exception.Message
        if (-not $errorText) {
            $errorText = "Unknown error"
        }
    }

    $results += [PSCustomObject]@{
        DomainController = $dcName
        Site             = $site
        ConfigurationNC  = $configNCStr
        DsHeuristics     = $value
        Error            = $errorText
    }
}


# ----------------------------
#   Display Table
# ----------------------------
Write-Host "dSHeuristics value per domain controller" -ForegroundColor Cyan
$results | Sort-Object DomainController | Format-Table -AutoSize
Write-Host ""


# ----------------------------
#   Check for mismatched values
# ----------------------------
$distinctValues = $results |
    Where-Object { -not $_.Error } |
    Select-Object -ExpandProperty DsHeuristics -Unique

$summary = @()

if ($distinctValues.Count -gt 1) {
    Write-Host "Warning  not all domain controllers have the same dSHeuristics value" -ForegroundColor Red
    Write-Host "Distinct values found" -ForegroundColor Red
    $distinctValues | ForEach-Object { Write-Host ("  {0}" -f $_) -ForegroundColor Red }

    $summary += "WARNING: Domain controllers report inconsistent dSHeuristics values:"
    $summary += $distinctValues
}
elseif ($distinctValues.Count -eq 1) {
    Write-Host ("All domain controllers report the same dSHeuristics value  {0}" -f $distinctValues[0]) -ForegroundColor Green
    $summary += "All domain controllers report consistent dSHeuristics value:"
    $summary += $distinctValues[0]
}
else {
    Write-Host "No successful dSHeuristics reads were recorded. Check connectivity and permissions" -ForegroundColor Red
    $summary += "No successful reads of dSHeuristics."
}


# ----------------------------
#   Save Logs (CSV + TXT)
# ----------------------------
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Add-Content -Path $txtPath -Value "MODNI A-DsHeuristicsLDAPSecurity Check - $(Get-Date)"
Add-Content -Path $txtPath -Value ""
Add-Content -Path $txtPath -Value "Per-DC Configuration NC and dSHeuristics:"
$results | ForEach-Object {
    Add-Content -Path $txtPath -Value ("  DC= {0}  Site= {1}  ConfigNC= {2}  dSHeuristics= {3}  Error= {4}" -f `
        $_.DomainController, $_.Site, $_.ConfigurationNC, $_.DsHeuristics, $_.Error)
}
Add-Content -Path $txtPath -Value ""
Add-Content -Path $txtPath -Value "Summary:"
$summary | ForEach-Object { Add-Content -Path $txtPath -Value ("  " + $_) }

Write-Host ""
Write-Host "Logs written to:" -ForegroundColor Yellow
Write-Host "  $csvPath"
Write-Host "  $txtPath"
Write-Host ""
Write-Host "Reminder: for A-DsHeuristicsLDAPSecurity, PingCastle expects the CVE-2021-42291 mitigation value (e.g. 00000000010000000002000000011 when starting from a blank attribute)." -ForegroundColor Yellow
