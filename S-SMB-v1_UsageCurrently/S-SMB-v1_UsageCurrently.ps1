<#
S-SMB-v1_UsageCurrently.ps1
MODNI 2026-01-14

Purpose (PingCastle Rule: S-SMB-v1)
Read-only verification across all DCs in current domain:
Phase 1 (always):
- SMBv1 posture per DC (feature state + Get-SmbServerConfiguration EnableSMB1Protocol)
- Verdict per DC: PingCastle_S-SMB-v1 = OK/FAIL

Phase 2 (prompted):
- Live SMB sessions per DC (Get-SmbSession)
- This provides "usage currently" evidence; SMBv1 would show Dialect = 1.5

Notes
- Only shows items relevant to S-SMB-v1.
- Logs + CSVs to C:\ITM\S-SMB-v1
- Local-first: if the DC is the machine you run on, it queries locally (no WinRM).
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ---- Logging / output folder ----
$OutDir = 'C:\ITM\S-SMB-v1'
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Phase1Csv = Join-Path $OutDir ("S-SMB-v1_Phase1_{0}.csv" -f $stamp)
$Phase2Csv = Join-Path $OutDir ("S-SMB-v1_Phase2_SmbSessions_{0}.csv" -f $stamp)
$TranscriptPath = Join-Path $OutDir ("S-SMB-v1_UsageCurrently_{0}.log" -f $stamp)

try { Start-Transcript -Path $TranscriptPath -ErrorAction Stop | Out-Null } catch { }

function Get-LocalNameVariants {
    $set = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $cn = $env:COMPUTERNAME
    if ($cn) { [void]$set.Add($cn) }

    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($cn).HostName
        if ($fqdn) { [void]$set.Add($fqdn) }
    } catch { }

    try {
        $dnsDomain = $env:USERDNSDOMAIN
        if ($cn -and $dnsDomain) { [void]$set.Add(("{0}.{1}" -f $cn, $dnsDomain)) }
    } catch { }

    return $set
}

function Get-DomainControllerNames {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        return ($domain.DomainControllers | ForEach-Object { $_.Name } | Sort-Object -Unique)
    } catch {
        Write-Host "ERROR: Unable to enumerate domain controllers. Are you domain-joined and on the domain network?" -ForegroundColor Red
        throw
    }
}

function Invoke-OnDC {
    param(
        [Parameter(Mandatory)][string]$DC,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    if ($script:LocalNames.Contains($DC)) {
        return & $ScriptBlock
    }
    return Invoke-Command -ComputerName $DC -ScriptBlock $ScriptBlock -ErrorAction Stop
}

function Get-FeatureStateSafe {
    param([Parameter(Mandatory)][string]$FeatureName)
    try {
        (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop).State.ToString()
    } catch {
        'NotPresent'
    }
}

function Is-FeatureEnabledState {
    param([string]$State)
    if (-not $State) { return $false }
    return ($State -match 'Enabled')
}

Write-Host ""
Write-Host "PingCastle S-SMB-v1 - Usage Currently (DC fleet)" -ForegroundColor Cyan
Write-Host ("Output folder: {0}" -f $OutDir) -ForegroundColor Gray
Write-Host ("Log          : {0}" -f $TranscriptPath) -ForegroundColor Gray

$script:LocalNames = Get-LocalNameVariants
$dcs = Get-DomainControllerNames

Write-Host ("Found {0} domain controller(s)." -f $dcs.Count) -ForegroundColor Cyan

# -------------------------
# Phase 1 - posture per DC
# -------------------------
$phase1 = @()

foreach ($dc in $dcs) {
    Write-Host ("Processing DC: {0}" -f $dc) -ForegroundColor White

    $isLocal = $script:LocalNames.Contains($dc)

    if (-not $isLocal) {
        try {
            Test-WSMan -ComputerName $dc -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning ("Remote query failed for {0} - WinRM unavailable" -f $dc)
            $phase1 += [pscustomobject]@{
                DC                 = $dc
                SMB1Protocol       = 'Unknown'
                SMB1ProtocolServer = 'Unknown'
                SMB1ProtocolClient = 'Unknown'
                EnableSMB1Protocol = 'Unknown'
                PingCastle_S_SMB_v1 = 'Unknown (WinRM unavailable)'
            }
            continue
        }
    }

    try {
        $data = Invoke-OnDC -DC $dc -ScriptBlock {
            $smb1Root   = $null
            $smb1Server = $null
            $smb1Client = $null

            try { $smb1Root   = (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol'        -ErrorAction Stop).State.ToString() } catch { $smb1Root = 'NotPresent' }
            try { $smb1Server = (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Server' -ErrorAction Stop).State.ToString() } catch { $smb1Server = 'NotPresent' }
            try { $smb1Client = (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Client' -ErrorAction Stop).State.ToString() } catch { $smb1Client = 'NotPresent' }

            $cfg = Get-SmbServerConfiguration -ErrorAction Stop

            [pscustomobject]@{
                SMB1ProtocolRoot   = $smb1Root
                SMB1ProtocolServer = $smb1Server
                SMB1ProtocolClient = $smb1Client
                EnableSMB1Protocol = [bool]$cfg.EnableSMB1Protocol
            }
        }

        $smb1FeatureEnabled =
            (Is-FeatureEnabledState $data.SMB1ProtocolRoot) -or
            (Is-FeatureEnabledState $data.SMB1ProtocolServer) -or
            (Is-FeatureEnabledState $data.SMB1ProtocolClient)

        $smb1Available = $false
        if ($data.EnableSMB1Protocol -eq $true) { $smb1Available = $true }
        if ($smb1FeatureEnabled)                { $smb1Available = $true }

        $verdict = if ($smb1Available) { 'FAIL (SMBv1 available)' } else { 'OK (SMBv1 not available)' }

        $phase1 += [pscustomobject]@{
            DC                 = $dc
            SMB1Protocol       = $data.SMB1ProtocolRoot
            SMB1ProtocolServer = $data.SMB1ProtocolServer
            SMB1ProtocolClient = $data.SMB1ProtocolClient
            EnableSMB1Protocol = $data.EnableSMB1Protocol
            PingCastle_S_SMB_v1 = $verdict
        }

    } catch {
        $msg = $_.Exception.Message
        Write-Warning ("Remote query failed for {0} - {1}" -f $dc, $msg)

        $phase1 += [pscustomobject]@{
            DC                 = $dc
            SMB1Protocol       = 'Unknown'
            SMB1ProtocolServer = 'Unknown'
            SMB1ProtocolClient = 'Unknown'
            EnableSMB1Protocol = 'Unknown'
            PingCastle_S_SMB_v1 = 'Unknown (error)'
        }
    }
}

Write-Host ""
Write-Host "Summary (Phase 1 - S-SMB-v1 posture):" -ForegroundColor White
$phase1 | Sort-Object DC | Format-Table -AutoSize

$phase1 | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Phase1Csv
Write-Host ("Phase 1 CSV saved to: {0}" -f $Phase1Csv) -ForegroundColor Green

# -------------------------
# Phase 2 - live sessions
# -------------------------
Write-Host ""
Write-Host "Optional Phase 2: Collect live SMB sessions from each DC (Get-SmbSession)." -ForegroundColor Yellow
Write-Host "This is relevant to S-SMB-v1 because SMBv1 usage would appear as Dialect = 1.5." -ForegroundColor DarkYellow
$choice = Read-Host "Collect SMB sessions from all DCs now? (Y/N)"

if ($choice -match '^(Y|y)$') {
    Write-Host ""
    Write-Host "Collecting SMB sessions (Phase 2)..." -ForegroundColor Cyan

    $sessions = @()

    foreach ($dc in $dcs) {

        # Only attempt Phase2 on DCs we could query in Phase1 (WinRM ok or local)
        $p1 = $phase1 | Where-Object { $_.DC -eq $dc } | Select-Object -First 1
        if (-not $p1 -or ($p1.PingCastle_S_SMB_v1 -like 'Unknown*')) {
            Write-Host ("Skipping {0} (no remote access for session query)." -f $dc) -ForegroundColor Yellow
            continue
        }

        Write-Host ("Sessions from DC: {0}" -f $dc) -ForegroundColor White

        try {
            $dcSessions = Invoke-OnDC -DC $dc -ScriptBlock {
                Get-SmbSession | Select-Object ClientComputerName, ClientUserName, Dialect, Signed
            }

            if ($dcSessions) {
                foreach ($s in $dcSessions) {
                    $sessions += [pscustomobject]@{
                        DC                 = $dc
                        ClientComputerName = $s.ClientComputerName
                        ClientUserName     = $s.ClientUserName
                        Dialect            = $s.Dialect
                        Signed             = $s.Signed
                    }
                }
                Write-Host ("  Found {0} session(s)." -f $dcSessions.Count) -ForegroundColor Green
            } else {
                Write-Host "  No sessions returned (may be normal if idle)." -ForegroundColor DarkYellow
            }

        } catch {
            $msg2 = $_.Exception.Message
            Write-Warning ("Session query failed for {0} - {1}" -f $dc, $msg2)
        }
    }

    Write-Host ""
    Write-Host "Summary (Phase 2 - SMB Sessions):" -ForegroundColor White

    if ($sessions -and ($sessions | Measure-Object).Count -gt 0) {
        $sessions | Sort-Object DC, ClientComputerName | Format-Table -AutoSize

        $dialects = $sessions |
            Where-Object { $_.Dialect -and $_.Dialect.ToString().Trim() -ne '' } |
            Select-Object -ExpandProperty Dialect -Unique |
            Sort-Object

        if ($dialects -and $dialects.Count -gt 0) {
            Write-Host ""
            Write-Host "Dialect meanings observed (only what was found):" -ForegroundColor Yellow
            foreach ($d in $dialects) {
                $meaning = switch ($d) {
                    '1.5'   { 'SMBv1 (legacy/insecure) - S-SMB-v1 concern' }
                    '2.0'   { 'SMBv2.0' }
                    '2.1'   { 'SMBv2.1' }
                    '3.0'   { 'SMBv3.0' }
                    '3.0.2' { 'SMBv3.0.2' }
                    '3.1.1' { 'SMBv3.1.1' }
                    default { 'Unknown/other' }
                }
                Write-Host ("  {0} : {1}" -f $d, $meaning) -ForegroundColor White
            }
        }

        $sessions | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Phase2Csv
        Write-Host ("Phase 2 CSV saved to: {0}" -f $Phase2Csv) -ForegroundColor Green
    }
    else {
        Write-Host "No session data collected." -ForegroundColor Yellow
    }
}
else {
    Write-Host "Skipped Phase 2." -ForegroundColor Yellow
}

try { Stop-Transcript | Out-Null } catch { }
Write-Host ("Log saved to: {0}" -f $TranscriptPath) -ForegroundColor Green
