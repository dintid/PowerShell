<#
.SYNOPSIS
    MODNI 20250708
    Checks adminCount attribute and email address configured for these.
    Detect PingCastle rule P-AdminEmailOn:
      "Administrator accounts must NOT be mail‑enabled."
    Automatically exports the result to C:\ITM8\P-AdminEmailOn\<timestamped>.csv
#>

Import-Module ActiveDirectory -ErrorAction Stop

# --- Export setup ---------------------------------------------------------------
$ExportFolder = 'C:\ITM8\P-AdminEmailOn'
if (-not (Test-Path $ExportFolder)) {
    New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
}
$TimeStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$CsvPath   = Join-Path $ExportFolder "P-AdminEmailOn_$TimeStamp.csv"

# --- Find all adminCount = 1 users ---------------------------------------------
$adminUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' `
                         -Properties mail, proxyAddresses, Enabled

if (-not $adminUsers) {
    Write-Host "No accounts with adminCount=1 found." -ForegroundColor Cyan
    return
}

# --- Determine mail-enabled status ---------------------------------------------
$report = foreach ($user in $adminUsers) {
    $mailAttr  = $user.mail
    $proxySMTP = ($user.proxyAddresses | Where-Object { $_ -match '^SMTP:' }) -replace '^SMTP:'

    if ($mailAttr) {
        $mailAddress = $mailAttr
    } elseif ($proxySMTP) {
        $mailAddress = $proxySMTP[0]
    } else {
        $mailAddress = $null
    }

    $violatesRule = [bool]$mailAddress   # TRUE = PingCastle would flag

    [PSCustomObject]@{
        Name         = $user.SamAccountName
        Enabled      = $user.Enabled
        MailAddress  = $mailAddress
        ViolatesRule = $violatesRule
    }
}

# --- Screen output --------------------------------------------------------------
$report | Sort-Object ViolatesRule, Name | Format-Table -AutoSize

# --- Export CSV -----------------------------------------------------------------
$report | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV exported to $CsvPath" -ForegroundColor Green
