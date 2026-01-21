# MODNI 20250108
# A-DnsZoneUpdate2 - Check DNS zones that allow Nonsecure updates,
# list records with OS info, AD-join status, and export to CSV.
# If a machine is not AD-joined it will fail once the zone is set to Secure-only.

<#
.SYNOPSIS
    Audit DNS zones that allow Nonsecure updates, show dynamically registered
    records, export to CSV, and optionally secure the zone.

.NOTES
    • Run elevated on a DC or RSAT workstation.
    • Requires DnsServer and ActiveDirectory modules.
#>

Import-Module DnsServer       -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# ---------- export setup ----------
$exportFolder = 'C:\itm8\A-DnsZoneUpdate2'
if (-not (Test-Path $exportFolder)) {
    New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
}
$timeStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$exportFile = Join-Path $exportFolder "A-DnsZoneUpdate2_$timeStamp.csv"

$allZoneData = @()

# ---------- find insecure zones ----------
$insecureZones = Get-DnsServerZone |
                 Where-Object { $_.DynamicUpdate -eq 'NonsecureAndSecure' }

if (-not $insecureZones) {
    Write-Host 'No zones allow Nonsecure updates – nothing to do.' -ForegroundColor Green
    return
}

foreach ($zone in $insecureZones) {

    Write-Host "`n[+] Insecure zone found: $($zone.ZoneName)" -ForegroundColor Yellow

    $recordTypeWanted = if ($zone.IsReverseLookupZone) { 'PTR' } else { 'A' }

    $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName |
               Where-Object { $_.RecordType -eq $recordTypeWanted -and $_.TimeStamp -ne 0 }

    if (-not $records) {
        Write-Host "    No dynamic $recordTypeWanted records found in this zone." -ForegroundColor DarkGray
        continue
    }

    # ---------- build objects ----------
    $tableData = foreach ($rec in $records) {

        if ($recordTypeWanted -eq 'A') {
            # forward zone
            $ownerFqdn    = "$($rec.HostName).$($zone.ZoneName)"
            $target       = $rec.RecordData.IPv4Address
            $adLookupFqdn = $ownerFqdn.TrimEnd('.')
        }
        else {
            # reverse zone (PTR)
            # zone name part → "170.16.172"  → split → reverse → 172.16.170
            $revOctets = ($zone.ZoneName -replace '\.in-addr\.arpa$','').Split('.')
            [array]::Reverse($revOctets)
            $ownerFqdn    = ($revOctets -join '.') + ".$($rec.HostName)"   # full IP
            $target       = $rec.RecordData.PtrDomainName
            $adLookupFqdn = $target.TrimEnd('.')
        }

        # --- OS categorisation & AD status ---
        $osCategory = 'Unknown'
        $status     = 'No AD Computer Found'

        try {
            $computer = Get-ADComputer -Filter "DNSHostName -eq '$adLookupFqdn'" `
                        -Properties OperatingSystem,Enabled -ErrorAction SilentlyContinue

            if (-not $computer) {
                # case-insensitive fallback
                $computer = Get-ADComputer -Filter * `
                           -Properties DNSHostName,OperatingSystem,Enabled |
                           Where-Object { $_.DNSHostName -and $_.DNSHostName.Equals($adLookupFqdn, 'InvariantCultureIgnoreCase') }
            }

            if ($computer) {
                $status = if ($computer.Enabled) { 'AD Joined Enabled' } else { 'AD Joined Disabled' }
                $osRaw  = $computer.OperatingSystem

                if ($osRaw -match 'Windows Server') {
                    $osCategory = $osRaw
                }
                elseif ($osRaw -match 'Windows') {
                    switch -Regex ($osRaw) {
                        'Windows 11' { $osCategory = 'Windows 11' ; break }
                        'Windows 10' { $osCategory = 'Windows 10' ; break }
                        'Windows 8'  { $osCategory = 'Windows 8'  ; break }
                        'Windows 7'  { $osCategory = 'Windows 7'  ; break }
                        default      { $osCategory = 'Windows Client' }
                    }
                }
                elseif ($osRaw -match 'Linux|Ubuntu|Debian|CentOS|Red Hat|Fedora|SUSE|Unix') {
                    $osCategory = 'Linux'
                }
                elseif ($osRaw -match 'Mac|OS X|macOS|Apple') {
                    $osCategory = 'Apple'
                }
            }
        } catch {
            Write-Host "DEBUG: AD lookup error for '$adLookupFqdn': $($_.Exception.Message)" -ForegroundColor Red
        }

        [pscustomobject]@{
            Zone                       = $zone.ZoneName
            Type                       = $recordTypeWanted
            Owner                      = $ownerFqdn
            Target                     = $target
            Registered                 = $rec.TimeStamp
            OS                         = $osCategory
            ADLookupFQDN               = $adLookupFqdn
            'ADJoined dis- or enabled' = $status
        }
    }

    $allZoneData += $tableData

    # ---------- display ----------
    $tableData | Format-Table Owner,Type,Target,OS,'ADJoined dis- or enabled',Registered -AutoSize

    # ---------- prompt to secure ----------
    do {
        $ans = Read-Host "Set '$($zone.ZoneName)' to Secure-only updates? (Y/N)"
    } until ($ans -match '^[YyNn]$')

    if ($ans -match '^[Yy]$') {
        try {
            Set-DnsServerZone -Name $zone.ZoneName -DynamicUpdate Secure
            Write-Host "    [$($zone.ZoneName)] set to Secure updates." -ForegroundColor Green
        } catch {
            Write-Host "    ERROR securing zone: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "    Skipped securing this zone." -ForegroundColor Cyan
    }
}

# ---------- export ----------
if ($allZoneData) {
    try {
        $allZoneData | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8
        Write-Host "`nReport exported to: $exportFile" -ForegroundColor Green
    } catch {
        Write-Host "ERROR exporting CSV: $_" -ForegroundColor Red
    }
}
