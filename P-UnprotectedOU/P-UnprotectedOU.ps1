<#
MODNI 20252207

Rule ID: P-UnprotectedOU
Check if OUs are protected from accidental deletion.
Logs before and after changes to: C:\ITM8\P-UnprotectedOU

#>

# Set up log folder and timestamp
$logFolder = 'C:\ITM8\P-UnprotectedOU'
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$beforeLog = Join-Path $logFolder "UnprotectedOUs_before_$timestamp.csv"
$afterLog  = Join-Path $logFolder "UnprotectedOUs_after_$timestamp.csv"
$changeLog = Join-Path $logFolder "Changes_$timestamp.txt"

# Step 1 – Find all OUs without protection
$unprotectedOUs = Get-ADObject -LDAPFilter '(objectClass=organizationalUnit)' `
    -Properties ProtectedFromAccidentalDeletion | Where-Object {
        $_.ProtectedFromAccidentalDeletion -ne $true
    } | Sort-Object DistinguishedName

# Save "before" log
$unprotectedOUs | Select-Object Name, DistinguishedName | Export-Csv -Path $beforeLog -NoTypeInformation -Encoding UTF8

if ($unprotectedOUs.Count -eq 0) {
    Write-Host "? All OUs are protected from accidental deletion." -ForegroundColor Green
    return
}

# Display found OUs in a table
Write-Host "`n??  The following OUs are not protected from accidental deletion:`n" -ForegroundColor Yellow
$unprotectedOUs | Select-Object Name, DistinguishedName | Format-Table -AutoSize



# Prompt
$choice = Read-Host "`nDo you want to enable protection on these OUs now? (Y/N, default is N)"
if ($choice -ne 'Y' -and $choice -ne 'y') {
    Write-Host "`n? No changes were made." -ForegroundColor Red
    return
}

# Step 2 – Apply protection and log what was changed
$changesMade = @()

foreach ($ou in $unprotectedOUs) {
    try {
        Set-ADObject -Identity $ou.DistinguishedName -ProtectedFromAccidentalDeletion $true
        $changesMade += "[$(Get-Date -Format 'u')] Enabled protection on: $($ou.DistinguishedName)"
    } catch {
        $changesMade += "[$(Get-Date -Format 'u')] ? Failed to update: $($ou.DistinguishedName) - $_"
    }
}

# Save change log
$changesMade | Out-File -FilePath $changeLog -Encoding UTF8

# Step 3 – Save "after" state
$stillUnprotected = Get-ADObject -LDAPFilter '(objectClass=organizationalUnit)' `
    -Properties ProtectedFromAccidentalDeletion | Where-Object {
        $_.ProtectedFromAccidentalDeletion -ne $true
    } | Sort-Object DistinguishedName

$stillUnprotected | Select-Object Name, DistinguishedName | Export-Csv -Path $afterLog -NoTypeInformation -Encoding UTF8

# Final output
Write-Host "`n? Protection update completed. Logs saved to:`n" -ForegroundColor Green
Write-Host " - $beforeLog"
Write-Host " - $changeLog"
Write-Host " - $afterLog"
