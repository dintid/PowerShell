<#

MODNI 2025.12.08
PingCastle: S-AesNotEnabled

.SYNOPSIS
    Audits and optionally enables AES Kerberos encryption (AES128 + AES256 + RC4)
    on computer accounts matching PingCastle finding S-AesNotEnabled.

.DESCRIPTION
    This script safely identifies computer accounts that lack AES Kerberos
    encryption support, using the same logical criteria as PingCastle
    (S-AesNotEnabled). It performs the following actions:

      1. Scans Active Directory for computers that:
           - Have servicePrincipalNames (SPNs), AND
           - Do NOT have AES128 or AES256 enabled, OR
           - Have passwords older than the first Windows Server 2008 DC
        These objects are listed as at-risk Kerberos principals.

      2. Produces table output on screen, and logs results to:
           C:\ITM8\S-AesNotEnabled\
           - S-AesNotEnabled_Computers.csv
           - S-AesNotEnabled_Computers.txt

      3. Prompts the user with **two safe options**:
           TEST  – Simulates which computers *would* be modified. 
                   Nothing is changed. A simulation CSV is created.
           YES   – Actually enables AES128 + AES256 + RC4 on the listed computers.
                   A detailed change log is stored under the same folder.

      4. ANY other input cancels the script with no changes.

.SAFETY
    - No changes are ever performed automatically.
    - You must explicitly choose YES for any modification to occur.
    - TEST mode shows exactly which accounts would be changed, allowing
      verification before enabling AES.
    - Only computers identified by the scan are ever modified.
    - Service accounts and users are untouched.
    - RC4 is retained for compatibility; AES128 and AES256 are added.

.OUTPUT
    Results and logs are stored in:
        C:\ITM8\S-AesNotEnabled\

.REQUIREMENTS
    - ActiveDirectory PowerShell module
    - Domain admin or delegated rights to modify computer account attributes
    - Run in a context with access to a writable domain controller

.NOTES
    This script is designed to be ISE-safe, non-destructive by default, and
    suitable for compliance evidence and PingCastle remediation follow-up.
#>

<#

MODNI 2025.12.08
PingCastle: S-AesNotEnabled

.SYNOPSIS
    Audits and optionally enables AES Kerberos encryption (AES128 + AES256 + RC4)
    on computer accounts matching PingCastle finding S-AesNotEnabled.

.DESCRIPTION
    This script safely identifies computer accounts that lack AES Kerberos
    encryption support, using the same logical criteria as PingCastle
    (S-AesNotEnabled). It performs the following actions:

      1. Scans Active Directory for computers that:
           - Have servicePrincipalNames (SPNs), AND
           - Do NOT have AES128 or AES256 enabled, OR
           - Have passwords older than the first Windows Server 2008+ DC
        These objects are listed as at-risk Kerberos principals.

      2. Produces table output on screen, and logs results to:
           C:\ITM8\S-AesNotEnabled\
           - S-AesNotEnabled_Computers.csv
           - S-AesNotEnabled_Computers.txt

      3. Prompts the user with two safe options:
           TEST  – Simulates which computers *would* be modified. 
                   Nothing is changed. A simulation CSV is created.
           YES   – Actually enables AES128 + AES256 + RC4 on the listed computers.
                   A detailed change log is stored under the same folder.

      4. ANY other input cancels the script with no changes.

.SAFETY
    - No changes are ever performed automatically.
    - You must explicitly choose YES for any modification to occur.
    - TEST mode shows exactly which accounts would be changed, allowing
      verification before enabling AES.
    - Only computers identified by the scan are ever modified.
    - Service accounts and users are untouched.
    - RC4 is retained for compatibility; AES128 and AES256 are added.

.OUTPUT
    Results and logs are stored in:
        C:\ITM8\S-AesNotEnabled\

.REQUIREMENTS
    - ActiveDirectory PowerShell module
    - Domain admin or delegated rights to modify computer account attributes
    - Run in a context with access to a writable domain controller

.NOTES
    This script is designed to be ISE-safe, non-destructive by default, and
    suitable for compliance evidence and PingCastle remediation follow-up.
#>

Import-Module ActiveDirectory

########################################
# Output paths
########################################

$OutputFolder = "C:\ITM8\S-AesNotEnabled"
$CsvFile      = Join-Path $OutputFolder "S-AesNotEnabled_Computers.csv"
$TxtFile      = Join-Path $OutputFolder "S-AesNotEnabled_Computers.txt"
$ChangeLog    = Join-Path $OutputFolder ("S-AesNotEnabled_Changes_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

########################################
# Detect date of first 2008+ DC (best effort, environment-agnostic)
########################################

# Default: no pre-2008 logic if we can't detect anything
$first2008dcInstall = [DateTime]::MinValue

try {
    $domainDN = (Get-ADDomain).DistinguishedName

    # Domain controllers (UAC bit 0x2000) with OS 2008 or newer
    $dcFilter = "(&(userAccountControl:1.2.840.113556.1.4.803:=8192)(|(operatingSystem=*2008*)(operatingSystem=*2012*)(operatingSystem=*2016*)(operatingSystem=*2019*)(operatingSystem=*2022*)(operatingSystem=*2025*)))"

    $firstNewerDC = Get-ADComputer -LDAPFilter $dcFilter -SearchBase $domainDN -Properties whenCreated |
                    Sort-Object whenCreated |
                    Select-Object -First 1

    if ($firstNewerDC -and $firstNewerDC.whenCreated) {
        $first2008dcInstall = $firstNewerDC.whenCreated
    }
}
catch {
    # If detection fails, $first2008dcInstall stays at MinValue and we effectively skip pre-2008 logic
}

########################################
# Ensure output folder exists
########################################

if (-not (Test-Path $OutputFolder)) { 
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null 
}

########################################
# Scan computers matching S-AesNotEnabled logic
########################################

$results = Get-ADComputer -LDAPFilter "(servicePrincipalName=*)" `
    -Properties servicePrincipalName,
                msDS-SupportedEncryptionTypes,
                pwdLastSet,
                DistinguishedName,
                OperatingSystem,
                LastLogonDate,
                Enabled |
    Where-Object {
        $enc = $_."msDS-SupportedEncryptionTypes"

        # AES checks (bit values: 0x10, 0x20 in this environment)
        $hasAes128 = ($enc -band 0x10) -ne 0
        $hasAes256 = ($enc -band 0x20) -ne 0
        $hasAnyAes = $hasAes128 -or $hasAes256

        # password date
        $pwdDate = if ($_.pwdLastSet -and $_.pwdLastSet -ne 0) {
            [DateTime]::FromFileTime($_.pwdLastSet)
        } else { $null }

        # very old secrets (only if we actually detected a 2008+ DC date)
        $pre2008Pwd = ($first2008dcInstall -ne [DateTime]::MinValue) -and $pwdDate -and ($pwdDate -lt $first2008dcInstall)

        # match PingCastle-style logic: no AES OR pre-2008 password
        -not $hasAnyAes -or $pre2008Pwd
    } |
    Select-Object `
        Name,
        DistinguishedName,
        OperatingSystem,
        LastLogonDate,
        Enabled,
        @{Name="HasSPN"; Expression={ if ($_.servicePrincipalName) { "Yes" } else { "No" }}},
        @{Name="AES128"; Expression={ ( $_."msDS-SupportedEncryptionTypes" -band 0x10 ) -ne 0 }},
        @{Name="AES256"; Expression={ ( $_."msDS-SupportedEncryptionTypes" -band 0x20 ) -ne 0 }},
        @{Name="EncryptionRaw"; Expression={ $_."msDS-SupportedEncryptionTypes" }},
        @{Name="PasswordLastSet"; Expression={ if ($_.pwdLastSet) { [DateTime]::FromFileTime($_.pwdLastSet) } else { $null } }}

########################################
# Output + logging (always safe)
########################################

if (-not $results) {
    Write-Host "`nNo computers found matching S-AesNotEnabled criteria." -ForegroundColor Green
    return
}

Write-Host "`nComputers matching S-AesNotEnabled criteria:`n" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$results | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
$results | Format-Table -AutoSize | Out-File $TxtFile -Encoding UTF8

Write-Host "`nFindings saved to:" -ForegroundColor Cyan
Write-Host "  $CsvFile" -ForegroundColor Yellow
Write-Host "  $TxtFile" -ForegroundColor Yellow

########################################
# Prompt user: TEST / YES / cancel
########################################

Write-Host "`nNo changes have been made yet." -ForegroundColor Yellow
Write-Host "Options:" -ForegroundColor Cyan
Write-Host "  TEST  - Simulate which computers WOULD be modified (no changes)" -ForegroundColor White
Write-Host "  YES   - Apply AES128 + AES256 + RC4 to the listed computers" -ForegroundColor White

$choice = Read-Host "`nSelect an option (TEST / YES):"
$choiceUpper = $choice.ToUpper()

if ($choiceUpper -ne "TEST" -and $choiceUpper -ne "YES") {
    Write-Host "`nAborted. No changes made." -ForegroundColor Yellow
    return
}

#########################
# TEST option (safe)
#########################
if ($choiceUpper -eq "TEST") {
    Write-Host "`n*** SIMULATION ONLY – NO CHANGES WILL BE MADE ***" -ForegroundColor Magenta
    Write-Host "The following computers WOULD have AES128+AES256+RC4 enabled:`n" -ForegroundColor Magenta

    $results |
        Select-Object Name, DistinguishedName, OperatingSystem, LastLogonDate, Enabled |
        Format-Table -AutoSize

    $simCsv = Join-Path $OutputFolder ("S-AesNotEnabled_Simulation_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $results | Export-Csv -Path $simCsv -NoTypeInformation -Encoding UTF8

    Write-Host "`nSimulation list saved to: $simCsv" -ForegroundColor Cyan

    # Final confirmation after TEST
    $confirm = Read-Host "`nIf you want to ENABLE AES now, type YES. Anything else cancels."

    if ($confirm.ToUpper() -ne "YES") {
        Write-Host "`nAborted after simulation. No changes made." -ForegroundColor Yellow
        return
    }
}

########################################
# Apply AES (only if final answer == YES)
########################################

Write-Host "`nEnabling AES128 + AES256 + RC4 on the listed computers..." -ForegroundColor Cyan

$changeLogEntries = @()

foreach ($comp in $results) {
    $before = $comp.EncryptionRaw

    try {
        # Keep RC4 for compatibility, just add AES
        Set-ADComputer -Identity $comp.DistinguishedName -KerberosEncryptionType AES128,AES256,RC4

        $afterObj = Get-ADComputer -Identity $comp.DistinguishedName -Properties msDS-SupportedEncryptionTypes

        $entry = [PSCustomObject]@{
            Name               = $comp.Name
            DistinguishedName  = $comp.DistinguishedName
            BeforeEncTypes     = $before
            AfterEncTypes      = $afterObj."msDS-SupportedEncryptionTypes"
            Timestamp          = (Get-Date)
            Status             = "Success"
            Error              = $null
        }

        Write-Host "Updated: $($comp.Name)" -ForegroundColor Green
    }
    catch {
        $entry = [PSCustomObject]@{
            Name               = $comp.Name
            DistinguishedName  = $comp.DistinguishedName
            BeforeEncTypes     = $before
            AfterEncTypes      = $null
            Timestamp          = (Get-Date)
            Status             = "Failed"
            Error              = $_.Exception.Message
        }

        Write-Host "FAILED: $($comp.Name) - $($_.Exception.Message)" -ForegroundColor Red
    }

    $changeLogEntries += $entry
}

$changeLogEntries | Export-Csv -Path $ChangeLog -NoTypeInformation -Encoding UTF8

Write-Host "`nAES enablement completed. Change log saved to:" -ForegroundColor Cyan
Write-Host "  $ChangeLog" -ForegroundColor Yellow
