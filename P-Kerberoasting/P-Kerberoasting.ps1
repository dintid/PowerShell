# MODNI 2025.06.17
# PingCastle P-Kerberoasting
# Checks specific administrator users for ServicePrincipalNames

$users = @("MCHSQLADMIN", "sysbackup", "Administrator")
$results = @()
$warnings = @()

foreach ($user in $users) {
    try {
        $adUser = Get-ADUser -Identity $user -Properties ServicePrincipalNames
        $results += [PSCustomObject]@{
            User                  = $user
            DistinguishedName     = $adUser.DistinguishedName
            ServicePrincipalNames = $adUser.ServicePrincipalNames -join "`n"
        }
    } catch {
        $warnings += "⚠️  Warning: User '$user' not found or error retrieving properties."
    }
}

# Display table
$results | Format-Table -AutoSize

# Display warnings
if ($warnings.Count -gt 0) {
    Write-Host "`nWarnings:" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host $_ -ForegroundColor DarkYellow }
}
