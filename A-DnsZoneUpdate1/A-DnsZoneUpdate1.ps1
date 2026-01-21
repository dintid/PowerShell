<#
MODNI 20251027
PingCastle A-DnsZoneUpdate1 – universal audit (ISE-safe, full output, summary + explanations)

Nyheder i denne version
-----------------------
- Viser AKTIVE (≤30 dage) ikke-AD-dynamiske poster med forklaring pr. post
- Finder og forklarer "forkert oprettede" poster (DomainDnsZones.*, ForestDnsZones.*, gc._msdcs.* i _msdcs, apex @.<zone>)
- Gemmer begge sæt i separate TXT-filer og tilføjer dem til Summary

Hvad scriptet gør (uændret + forbedringer)
------------------------------------------
1) Auditerer lokale AD DNS-zoner (<domain> og _msdcs.<domain>) for dynamiske opdateringer (NonsecureAndSecure = FAIL).
2) Finder kun dynamiske A/AAAA (+ valgfrit PTR) poster, som IKKE matcher nogen AD-computer (dNSHostName).
3) Kategoriserer sandsynlige enhedstyper (Printer, NAS, VoIP, AP) + keywords: sql, terminal, alarm, pso, laser, mail.
4) Konsol: 
   - Failing zones
   - CSV-stier
   - Non-domain per-zone counts
   - Top-10 preview (af TOTAL)
   - Category counts
   - Keyword/category top-10
   - Impact forecast (Active ≤30d / Stale ≥365d)
   - NYT: Aktive med forklaring (tabel)
   - NYT: Forkert oprettede poster med forklaring (tabel)
5) Eksporter:
   • Zones overview -> C:\ITM8\A-DnsZoneUpdate1\A-DnsZoneUpdate1_Zones_<timestamp>.csv
   • Non-domain dynamics -> C:\ITM8\A-DnsZoneUpdate1\A-DnsZoneUpdate1_NonDomainDynamics_<timestamp>.csv
   • Summary one-pager -> C:\ITM8\A-DnsZoneUpdate1\A-DnsZoneUpdate1_Summary_<timestamp>.txt
   • Transcript          -> C:\ITM8\A-DnsZoneUpdate1\transcript_<timestamp>.txt
   • NYT: Active details -> C:\ITM8\A-DnsZoneUpdate1\A-DnsZoneUpdate1_ActiveDetails_<timestamp>.txt
   • NYT: Misconfig list -> C:\ITM8\A-DnsZoneUpdate1\A-DnsZoneUpdate1_Misconfigured_<timestamp>.txt
#>

[CmdletBinding()]
param(
    [switch]$IncludeReverse
)

Import-Module DnsServer       -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Quiet defaults for transcript cleanliness
$PSDefaultParameterValues['Get-ADComputer:ErrorAction'] = 'SilentlyContinue'
$PSDefaultParameterValues['Get-ADDomainController:ErrorAction'] = 'SilentlyContinue'

# ---------- output setup ----------
$ExportFolder = 'C:\ITM8\A-DnsZoneUpdate1'
if (-not (Test-Path -LiteralPath $ExportFolder)) {
    New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
}
$TimeStamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$CsvZones       = Join-Path $ExportFolder ("A-DnsZoneUpdate1_Zones_{0}.csv" -f $TimeStamp)
$CsvNonAD       = Join-Path $ExportFolder ("A-DnsZoneUpdate1_NonDomainDynamics_{0}.csv" -f $TimeStamp)
$TranscriptPath = Join-Path $ExportFolder ("transcript_{0}.txt" -f $TimeStamp)
$SummaryPath    = Join-Path $ExportFolder ("A-DnsZoneUpdate1_Summary_{0}.txt" -f $TimeStamp)
$ActiveTxtPath  = Join-Path $ExportFolder ("A-DnsZoneUpdate1_ActiveDetails_{0}.txt" -f $TimeStamp)
$MisconfTxtPath = Join-Path $ExportFolder ("A-DnsZoneUpdate1_Misconfigured_{0}.txt" -f $TimeStamp)

Start-Transcript -Path $TranscriptPath -Force

# ---------- helpers ----------
function Convert-DnsTimestampToDate {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [double]) {
        if ([double]$Value -eq 0) { return $null }
        return ([datetime]'1601-01-01Z').AddHours([double]$Value)
    }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        $dt = $null
        if ([datetime]::TryParse($s, [ref]$dt)) { return $dt }
        $num = $null
        if ([double]::TryParse($s, [ref]$num)) {
            if ($num -eq 0) { return $null }
            return ([datetime]'1601-01-01Z').AddHours($num)
        }
    }
    return $null
}

function Get-AdComputerByDns {
    param([Parameter(Mandatory)][string]$DnsFqdn,
          [Parameter(Mandatory)][string]$RootDomain)
    try {
        $dc = (Get-ADDomainController -Discover -Service ADWS -ErrorAction Stop |
               Select-Object -First 1 -ExpandProperty HostName)
        if (-not $dc) { return $null }
    } catch { return $null }

    try {
        return Get-ADComputer -Server $dc -LDAPFilter ("(dNSHostName={0})" -f $DnsFqdn) `
               -Properties OperatingSystem,Enabled -ErrorAction SilentlyContinue
    } catch { return $null }
}

function Get-CategoryByName {
    param([string]$NameLower)
    if ([string]::IsNullOrWhiteSpace($NameLower)) { return 'Other' }

    # Custom keywords
    if ($NameLower -match '\b(sql)\b')         { return 'SQL' }
    if ($NameLower -match '\b(terminal)\b')    { return 'Terminal' }
    if ($NameLower -match '\b(alarm)\b')       { return 'Alarm' }
    if ($NameLower -match '\b(pso)\b')         { return 'PSO' }
    if ($NameLower -match '\b(laser)\b')       { return 'Laser' }
    if ($NameLower -match '\b(mail|smtp|mx)\b'){ return 'Mail' }

    # Devices/vendors
    if ($NameLower -match 'hp|hewlett|laserjet|deskjet|pagewide|lexmark|brother|epson|canon|ricoh|kyocera|xerox|oki|konica|minolta') { return 'Printer' }
    if ($NameLower -match 'synology|qnap|readynas|thecus|buffalo|truenas|freenas|wd|drobo') { return 'NAS' }
    if ($NameLower -match 'yealink|cisco|poly|polycom|grandstream|avaya|snom') { return 'VoIP' }
    if ($NameLower -match 'ap-|ap[0-9]|accesspoint|aruba|unifi|ruckus|meraki') { return 'AP' }

    return 'Other'
}

try {
    # ---------- determine local domain ----------
    $LocalDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    Write-Host "Local domain: $LocalDomain"

    # ---------- gather zones (domain + _msdcs) ----------
    $AllZones = Get-DnsServerZone
    $TargetZones = $AllZones | Where-Object {
        $_.ZoneName -ieq $LocalDomain -or $_.ZoneName -ieq ("_msdcs.{0}" -f $LocalDomain)
    }

    if (-not $TargetZones) {
        Write-Host "No relevant zones found for $LocalDomain" -ForegroundColor Yellow
        @() | Export-Csv -Path $CsvZones -NoTypeInformation -Encoding UTF8
        @() | Export-Csv -Path $CsvNonAD -NoTypeInformation -Encoding UTF8
        Stop-Transcript
        return
    }

    # ---------- build zone overview ----------
    $ZoneRows = New-Object System.Collections.Generic.List[object]
    foreach ($Z in $TargetZones) {
        $Mode     = $Z.DynamicUpdate
        $FailFlag = ($Mode -eq 'NonsecureAndSecure')
        $A_DnsZoneUpdate1 = if ($FailFlag) { 'FAIL' } else { 'OK' }

        $ZoneRows.Add([pscustomobject]@{
            ZoneName         = $Z.ZoneName
            DynamicUpdate    = $Mode
            A_DnsZoneUpdate1 = $A_DnsZoneUpdate1
        })
    }

    $BadZones = $ZoneRows | Where-Object { $_.A_DnsZoneUpdate1 -eq 'FAIL' }
    if ($BadZones) {
        Write-Host "Zones allowing INSECURE dynamic updates:" -ForegroundColor Yellow
        foreach ($b in $BadZones) { Write-Host ("  {0} (DynamicUpdate={1})" -f $b.ZoneName, $b.DynamicUpdate) }
    }

    # ---------- enumerate only non-AD dynamic records ----------
    $NonAdRows = New-Object System.Collections.Generic.List[object]
    foreach ($Z in $TargetZones | Where-Object { -not $_.IsReverseLookupZone }) {
        $ZName = $Z.ZoneName
        foreach ($RR in @('A','AAAA')) {
            $Recs = Get-DnsServerResourceRecord -ZoneName $ZName -RRType $RR -ErrorAction SilentlyContinue |
                    Where-Object { $_.TimeStamp -ne 0 }

            foreach ($R in $Recs) {
                $OwnerFqdn = ("{0}.{1}" -f $R.HostName.TrimEnd('.'), $ZName).TrimEnd('.')
                $OwnerLower = $OwnerFqdn.ToLowerInvariant()
                $TargetObj = if ($RR -eq 'A') { $R.RecordData.IPv4Address } else { $R.RecordData.IPv6Address }
                $TargetStr = if ($TargetObj) { $TargetObj.ToString() } else { '' }
                $RegDate   = Convert-DnsTimestampToDate $R.TimeStamp

                $ADobj = Get-AdComputerByDns -DnsFqdn $OwnerFqdn -RootDomain $LocalDomain
                if (-not $ADobj) {
                    $Category = Get-CategoryByName -NameLower $OwnerLower
                    $NonAdRows.Add([pscustomobject]@{
                        ZoneName          = $ZName
                        OwnerFqdn         = $OwnerFqdn
                        Target            = $TargetStr
                        DynamicRegistered = $RegDate
                        Category          = $Category
                    })
                }
            }
        }
    }

    if ($IncludeReverse) {
        foreach ($RZ in Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -and $_.IsDsIntegrated }) {
            $rzname = $RZ.ZoneName
            $ptrs = Get-DnsServerResourceRecord -ZoneName $rzname -RRType PTR -ErrorAction SilentlyContinue |
                    Where-Object { $_.TimeStamp -ne 0 }
            foreach ($p in $ptrs) {
                $ptrHost = $p.RecordData.PtrDomainName.TrimEnd('.')
                $ptrLower= $ptrHost.ToLowerInvariant()
                $regDate = Convert-DnsTimestampToDate $p.TimeStamp
                $ad = Get-AdComputerByDns -DnsFqdn $ptrHost -RootDomain $LocalDomain
                if (-not $ad) {
                    $category = Get-CategoryByName -NameLower $ptrLower
                    $NonAdRows.Add([pscustomobject]@{
                        ZoneName          = $rzname
                        OwnerFqdn         = $ptrHost
                        Target            = $p.RecordData.PtrDomainName
                        DynamicRegistered = $regDate
                        Category          = $category
                    })
                }
            }
        }
    }

    # ---------- exports ----------
    $ZoneRows  | Export-Csv -Path $CsvZones -NoTypeInformation -Encoding UTF8
    $NonAdRows | Export-Csv -Path $CsvNonAD -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host ("CSV (zones overview)      : {0}" -f $CsvZones)
    Write-Host ("CSV (non-domain dynamics) : {0}" -f $CsvNonAD)
    Write-Host ""

    # ---------- on-screen summaries ----------
    $TotalNonDomain = $NonAdRows.Count
    if ($TotalNonDomain -gt 0) {
        $PerZone = $NonAdRows | Group-Object ZoneName | Sort-Object Name
        Write-Host "Non-domain dynamic records per zone:"
        foreach ($g in $PerZone) {
            Write-Host ("  {0} : {1}" -f $g.Name, $g.Count)
        }

        $PreviewCount = 10
        Write-Host ("`nTop {0} non-domain dynamic records (preview of {1} total):" -f $PreviewCount, $TotalNonDomain)
        $NonAdRows | Select-Object -First $PreviewCount ZoneName,OwnerFqdn,Target,DynamicRegistered,Category |
            Format-Table -AutoSize

        # Category breakdown
        $CatGroups = $NonAdRows | Group-Object Category | Sort-Object Count -Descending
        Write-Host ("`nCounts per Category (total {0} records):" -f $TotalNonDomain)
        foreach ($c in $CatGroups) {
            Write-Host ("  {0,-12} : {1}" -f $c.Name, $c.Count)
        }

        # Keyword/category matches (your keywords + device groups)
        $KeyCats = @('SQL','Terminal','Alarm','PSO','Laser','Mail','Printer','NAS','VoIP','AP')
        $KeyMatches = $NonAdRows | Where-Object { $_.Category -in $KeyCats }
        $TotalKey = ($KeyMatches | Measure-Object).Count
        $ShowKey  = [math]::Min($PreviewCount, $TotalKey)

        Write-Host ("`nTop {0} keyword/category matches (of {1} total matches across {2} records):" -f $ShowKey, $TotalKey, $TotalNonDomain)
        if ($TotalKey -gt 0) {
            $KeyMatches | Select-Object -First $PreviewCount ZoneName,OwnerFqdn,Target,DynamicRegistered,Category |
                Format-Table -AutoSize
        } else {
            Write-Host "  (no keyword or category matches found)"
        }

        # ---------- impact forecast ----------
        $Now = Get-Date
        $WithAge = $NonAdRows | ForEach-Object {
            $ageDays = $null
            if ($_.DynamicRegistered) {
                $ageDays = (New-TimeSpan -Start $_.DynamicRegistered -End $Now).Days
            }
            [pscustomobject]@{
                ZoneName          = $_.ZoneName
                OwnerFqdn         = $_.OwnerFqdn
                Target            = $_.Target
                Category          = $_.Category
                DynamicRegistered = $_.DynamicRegistered
                AgeDays           = $ageDays
            }
        }

        $Active = $WithAge | Where-Object { $_.AgeDays -ne $null -and $_.AgeDays -le 30 }
        $Stale  = $WithAge | Where-Object { $_.AgeDays -ge 365 }

        $ActiveCount = ($Active | Measure-Object).Count
        $StaleCount  = ($Stale  | Measure-Object).Count

        $ShowActive = [math]::Min($PreviewCount, $ActiveCount)
        $ShowStale  = [math]::Min($PreviewCount, $StaleCount)

        Write-Host ("`nImpact forecast (across {0} total non-domain records):" -f $TotalNonDomain)
        Write-Host ("  Active (<= 30 days): showing top {0} of {1}" -f $ShowActive, $ActiveCount)
        $Active | Sort-Object AgeDays | Select-Object -First $PreviewCount ZoneName,OwnerFqdn,Target,Category,DynamicRegistered,AgeDays |
            Format-Table -AutoSize

        Write-Host ("`n  Stale (>= 365 days): showing top {0} of {1}" -f $ShowStale, $StaleCount)
        $Stale | Sort-Object AgeDays -Descending | Select-Object -First $PreviewCount ZoneName,OwnerFqdn,Target,Category,DynamicRegistered,AgeDays |
            Format-Table -AutoSize

        # ---------- EXPLANATIONS: Active (<=30d) ----------
        # Collect DC IPs for apex explanations
        $DCIPs = @()
        try {
            $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
            foreach ($dc in $dcs) {
                try {
                    $a = Resolve-DnsName -Name $dc.HostName -Type A -ErrorAction SilentlyContinue
                    $DCIPs += ($a | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
                } catch { }
            }
        } catch { }

        $DCIPSet = [System.Collections.Generic.HashSet[string]]::new()
        $DCIPs | ForEach-Object { [void]$DCIPSet.Add($_) }

        function Get-ActiveExplanation {
            param([string]$ZoneName, [string]$OwnerFqdn, [string]$Target)

            $owner = ($OwnerFqdn   | ForEach-Object { $_.ToLowerInvariant() })
            $zone  = ($ZoneName    | ForEach-Object { $_.ToLowerInvariant() })
            $t     = ($Target      | ForEach-Object { $_.ToString() })

            if ($owner -like 'domaindnszones.*') {
                return 'Fejl: "DomainDnsZones" er en applikationspartition, ikke en host. Slet A-posten.'
            }
            if ($owner -like 'forestdnszones.*') {
                return 'Fejl: "ForestDnsZones" er en applikationspartition, ikke en host. Slet A-posten.'
            }
            if ($zone -like '_msdcs.*' -and $owner -like 'gc._msdcs.*') {
                return 'Fejl: "gc" under _msdcs skal være SRV/CNAME, ikke A/AAAA. Slet posten.'
            }
            if ($owner -like '@.*') {
                if ($t -and $DCIPSet.Contains($t)) {
                    return 'Zone-apex A-post der peger på en DC. Normalt unødvendig – fjern medmindre det er bevidst.'
                } else {
                    return 'Zone-apex A-post. Kun nødvendig i særlige scenarier – ellers fjern.'
                }
            }
            return 'Ikke-AD enhed. Anbefal: DHCP med sikre opdateringer (Option 81 + konto) eller statisk DNS.'
        }

        $ActiveDetailed = $WithAge | Where-Object { $_.AgeDays -ne $null -and $_.AgeDays -le 30 } |
            Sort-Object DynamicRegistered -Descending | ForEach-Object {
                [pscustomobject]@{
                    OwnerFqdn         = $_.OwnerFqdn
                    Target            = $_.Target
                    ZoneName          = $_.ZoneName
                    DynamicRegistered = $_.DynamicRegistered
                    Explanation       = Get-ActiveExplanation -ZoneName $_.ZoneName -OwnerFqdn $_.OwnerFqdn -Target $_.Target
                }
            }

        if ($ActiveDetailed.Count -gt 0) {
            Write-Host "`nAktive ikke-AD poster (<= 30 dage) – kort liste:" -ForegroundColor Cyan
            $ActiveDetailed | Select-Object OwnerFqdn, Target, DynamicRegistered, Explanation |
                Format-Table -AutoSize
        } else {
            Write-Host "`nIngen aktive (<= 30 dage) ikke-AD poster fundet."
        }

        # Gem Active-detaljer
        $ActiveTxt = @()
        $ActiveTxt += "Aktive ikke-AD poster (<= 30 dage) – detaljer"
        $ActiveTxt += "Genereret: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $ActiveTxt += ""
        foreach ($r in $ActiveDetailed) {
            $ActiveTxt += ("- {0} -> {1}  |  {2:yyyy-MM-dd HH:mm}  |  {3}" -f $r.OwnerFqdn, $r.Target, $r.DynamicRegistered, $r.Explanation)
        }
        $ActiveTxt | Out-File -FilePath $ActiveTxtPath -Encoding UTF8 -Force
        Write-Host ("Active-detaljer skrevet til: {0}" -f $ActiveTxtPath)

        # ---------- EXPLANATIONS: Misconfigured (pattern-based) ----------
        function Test-IsMisconfigured {
            param([string]$ZoneName, [string]$OwnerFqdn)
            $owner = $OwnerFqdn.ToLowerInvariant()
            $zone  = $ZoneName.ToLowerInvariant()
            if ($owner -like 'domaindnszones.*') { return $true }
            if ($owner -like 'forestdnszones.*') { return $true }
            if ($zone -like '_msdcs.*' -and $owner -like 'gc._msdcs.*') { return $true }
            if ($owner -like '@.*') { return $true }
            return $false
        }
        function Get-MisconfExplanation {
            param([string]$ZoneName, [string]$OwnerFqdn, [string]$Target)
            $owner = $OwnerFqdn.ToLowerInvariant()
            $zone  = $ZoneName.ToLowerInvariant()
            if ($owner -like 'domaindnszones.*') {
                return 'Forkert: "DomainDnsZones" er applikationspartition (ikke host). Slet A/AAAA-posten.'
            }
            if ($owner -like 'forestdnszones.*') {
                return 'Forkert: "ForestDnsZones" er applikationspartition (ikke host). Slet A/AAAA-posten.'
            }
            if ($zone -like '_msdcs.*' -and $owner -like 'gc._msdcs.*') {
                return 'Forkert: "gc" i _msdcs skal være SRV/CNAME – ikke A/AAAA. Slet posten.'
            }
            if ($owner -like '@.*') {
                if ($Target -and $DCIPSet.Contains($Target)) {
                    return 'Zone-apex A-post peger på DC. Normalt unødvendig – fjern hvis ikke bevidst.'
                } else {
                    return 'Zone-apex A-post. Kun ved særlige behov – ellers fjern.'
                }
            }
            return '—'
        }

        $Misconfigured = $NonAdRows | Where-Object { Test-IsMisconfigured -ZoneName $_.ZoneName -OwnerFqdn $_.OwnerFqdn } |
            Sort-Object ZoneName, OwnerFqdn |
            ForEach-Object {
                [pscustomobject]@{
                    ZoneName    = $_.ZoneName
                    OwnerFqdn   = $_.OwnerFqdn
                    Target      = $_.Target
                    Registered  = $_.DynamicRegistered
                    Explanation = Get-MisconfExplanation -ZoneName $_.ZoneName -OwnerFqdn $_.OwnerFqdn -Target $_.Target
                }
            }

        if ($Misconfigured.Count -gt 0) {
            Write-Host "`nForkert oprettede poster – kort liste:" -ForegroundColor Magenta
            $Misconfigured | Select-Object ZoneName, OwnerFqdn, Target, Registered, Explanation |
                Format-Table -AutoSize
        } else {
            Write-Host "`nIngen forkert oprettede poster fundet."
        }

        # Gem Misconfigured-detaljer
        $MisTxt = @()
        $MisTxt += "Forkert oprettede poster – detaljer"
        $MisTxt += "Genereret: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $MisTxt += ""
        foreach ($r in $Misconfigured) {
            $MisTxt += ("- [{0}] {1} -> {2} | {3:yyyy-MM-dd HH:mm} | {4}" -f $r.ZoneName, $r.OwnerFqdn, $r.Target, $r.Registered, $r.Explanation)
        }
        $MisTxt | Out-File -FilePath $MisconfTxtPath -Encoding UTF8 -Force
        Write-Host ("Misconfigured-detaljer skrevet til: {0}" -f $MisconfTxtPath)

        # ---------- summary file ----------
        $ZonesFailText = if ($BadZones) {
            ($BadZones | ForEach-Object { " - {0} (DynamicUpdate={1})" -f $_.ZoneName, $_.DynamicUpdate }) -join "`r`n"
        } else { " - (none)" }

        $NonAdByZoneText = if ($PerZone) {
            ($PerZone | ForEach-Object { " - {0}: {1}" -f $_.Name, $_.Count }) -join "`r`n"
        } else { " - (none)" }

        $CatBreakdownText = if ($CatGroups) {
            ($CatGroups | ForEach-Object { " - {0}: {1}" -f $_.Name, $_.Count }) -join "`r`n"
        } else { " - (none)" }

        $SummaryText = @"
A-DnsZoneUpdate1 Summary  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Domain: $LocalDomain

Zones allowing INSECURE dynamic updates:
$ZonesFailText

Non-domain dynamic records per zone:
$NonAdByZoneText

Totals:
 - Non-domain records: $TotalNonDomain
 - Active (<= 30 days): $ActiveCount
 - Stale (>= 365 days): $StaleCount

Category breakdown:
$CatBreakdownText

Aktive ikke-AD poster (<= 30 dage) – kort liste:
"@

        if ($ActiveDetailed.Count -gt 0) {
            foreach ($r in $ActiveDetailed) {
                $SummaryText += (" - {0} -> {1} | {2:yyyy-MM-dd HH:mm} | {3}`r`n" -f $r.OwnerFqdn, $r.Target, $r.DynamicRegistered, $r.Explanation)
            }
        } else {
            $SummaryText += " - (ingen)`r`n"
        }

        $SummaryText += "`r`nForkert oprettede poster – kort liste:`r`n"
        if ($Misconfigured.Count -gt 0) {
            foreach ($r in $Misconfigured) {
                $SummaryText += (" - [{0}] {1} -> {2} | {3:yyyy-MM-dd HH:mm} | {4}`r`n" -f $r.ZoneName, $r.OwnerFqdn, $r.Target, $r.Registered, $r.Explanation)
            }
        } else {
            $SummaryText += " - (ingen)`r`n"
        }

        Write-Host "`n===== Summary (also written to file) ====="
        $SummaryText
        $SummaryText | Out-File -FilePath $SummaryPath -Encoding UTF8 -Force
        Write-Host ("Summary written to: {0}" -f $SummaryPath)

    } else {
        Write-Host "No dynamic records were found that are outside AD."
        # Empty summary if nothing found
        $SummaryText = @"
A-DnsZoneUpdate1 Summary  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Domain: $LocalDomain

Result:
 - No non-domain dynamic records found.

CSV (zones)      : $CsvZones
CSV (non-domain) : $CsvNonAD
"@
        $SummaryText | Out-File -FilePath $SummaryPath -Encoding UTF8 -Force
        Write-Host ("Summary written to: {0}" -f $SummaryPath)
    }

} finally {
    Stop-Transcript | Out-Null
}
