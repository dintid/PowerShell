<#
  MODNI - PingCastle - A-SMB2SignatureNotRequired (DC SMB signing readiness + optional live sessions)
  Date: 2026-01-09

  Phase 1 (always):
    - SMB1 posture (for compatibility sanity check):
        * Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        * Get-SmbServerConfiguration: AuditSmb1Access / EnableSMB1Protocol / EnableSMB2Protocol
    - Logging readiness checks (GPO-driven):
        * Event channel enabled: Microsoft-Windows-SMBServer/Operational
        * Event channel enabled: Microsoft-Windows-SMBServer/Audit
        * Advanced Audit Policy: Audit Logon (Failure) enabled

  Phase 2 (prompted):
    - Get-SmbSession snapshot from each DC:
        * ClientComputerName / ClientUserName / Dialect / Signed
    - Prints Dialect meaning ONLY for Dialects observed.

  Notes:
    - If you are logged onto a DC, the script runs locally for that DC (no remoting to self).
    - For other DCs it uses WinRM (Invoke-Command).
    - Output logs + CSVs go to: C:\ITM8\A-SMB2SignatureNotRequired (created if missing).
#>

$ErrorActionPreference = 'Stop'

# --- Output folder ---
$OutDir = 'C:\ITM8\A-SMB2SignatureNotRequired'
if (-not (Test-Path -Path $OutDir)) {
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
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
        if ($cn -and $dnsDomain) {
            [void]$set.Add(("{0}.{1}" -f $cn, $dnsDomain))
        }
    } catch { }

    return $set
}

function Parse-WevtutilEnabled {
    param([string[]]$Lines)
    $enabledLine = $Lines | Where-Object { $_ -match '^\s*enabled\s*:\s*' } | Select-Object -First 1
    if (-not $enabledLine) { return 'Unknown' }
    if ($enabledLine -match ':\s*true\s*$')  { return $true }
    if ($enabledLine -match ':\s*false\s*$') { return $false }
    return 'Unknown'
}

function Parse-AuditpolLogonFailure {
    param([string[]]$Lines)
    # auditpol /get output contains a row starting with "Logon" and indicates Success and/or Failure / No Auditing
    $logonLine = $Lines | Where-Object { $_ -match '^\s*Logon\s{2,}' } | Select-Object -First 1
    if (-not $logonLine) { return 'Unknown' }

    if ($logonLine -match 'Failure')     { return $true }
    if ($logonLine -match 'No Auditing') { return $false }
    return 'Unknown'
}

function Get-DialectMeaning {
    param([string]$Dialect)

    switch ($Dialect) {
        '3.1.1' { return 'SMBv3.1.1 (modern; supports signing/encryption)' }
        '3.0.2' { return 'SMBv3.0.2 (modern; supports signing/encryption)' }
        '3.0'   { return 'SMBv3.0 (modern; supports signing/encryption)' }
        '2.1'   { return 'SMBv2.1 (ok; supports signing)' }
        '2.0'   { return 'SMBv2.0 (older but ok; supports signing)' }
        '1.5'   { return 'SMBv1 (legacy/insecure; should not be used)' }
        default { return 'Unknown/other SMB dialect (verify client/server versions)' }
    }
}

function Invoke-OnDC {
    param(
        [Parameter(Mandatory=$true)][string]$DC,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )

    if ($script:LocalNames.Contains($DC)) {
        return & $ScriptBlock
    }

    return Invoke-Command -ComputerName $DC -ScriptBlock $ScriptBlock -ErrorAction Stop
}

# --- Main ---
$script:LocalNames = Get-LocalNameVariants
$dcs = Get-DomainControllerNames

if (-not $dcs -or $dcs.Count -eq 0) {
    Write-Host "No domain controllers were found." -ForegroundColor Yellow
    return
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Phase1Csv = Join-Path $OutDir ("DC_A-SMB2SignatureNotRequired_Phase1_{0}.csv" -f $stamp)
$Phase2Csv = Join-Path $OutDir ("DC_A-SMB2SignatureNotRequired_Phase2_SmbSessions_{0}.csv" -f $stamp)
$TranscriptPath = Join-Path $OutDir ("DC_A-SMB2SignatureNotRequired_Run_{0}.log" -f $stamp)

try { Start-Transcript -Path $TranscriptPath -ErrorAction Stop | Out-Null } catch { }

Write-Host ("PingCastle - A-SMB2SignatureNotRequired") -ForegroundColor Cyan
Write-Host ("Output folder: {0}" -f $OutDir) -ForegroundColor Cyan
Write-Host ("Found {0} domain controller(s)." -f $dcs.Count) -ForegroundColor Cyan

$phase1 = @()

foreach ($dc in $dcs) {
    Write-Host ("Processing DC: {0}" -f $dc) -ForegroundColor White

    $isLocal = $script:LocalNames.Contains($dc)
    $ok = $false

    if ($isLocal) {
        Write-Host ("  Local DC detected ({0}) - running locally (no WinRM)." -f $dc) -ForegroundColor Green
        $ok = $true
    } else {
        try {
            Test-WSMan -ComputerName $dc -ErrorAction Stop | Out-Null
            Write-Host ("  WinRM OK on {0}" -f $dc) -ForegroundColor Green
            $ok = $true
        } catch {
            Write-Host ("  WinRM NOT available on {0}. Skipping." -f $dc) -ForegroundColor Yellow
        }
    }

    if (-not $ok) {
        $phase1 += [pscustomobject]@{
            DC                          = $dc
            SMB1OptionalFeature         = 'Unknown'
            EnableSMB1Protocol          = 'Unknown'
            EnableSMB2Protocol          = 'Unknown'
            AuditSmb1Access             = 'Unknown'
            SMBServerOperationalEnabled = 'Unknown'
            SMBServerAuditEnabled       = 'Unknown'
            AuditLogonFailureEnabled    = 'Unknown'
            Recommendation              = 'WinRM unavailable'
            Error                       = 'WinRM unavailable'
        }
        continue
    }

    try {
        $data = Invoke-OnDC -DC $dc -ScriptBlock {
            $opt = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
            $cfg = Get-SmbServerConfiguration -ErrorAction Stop

            $operOut  = & wevtutil get-log 'Microsoft-Windows-SMBServer/Operational' 2>&1
            $auditOut = & wevtutil get-log 'Microsoft-Windows-SMBServer/Audit' 2>&1
            $auditpolOut = & auditpol /get /subcategory:"Logon" 2>&1

            [pscustomobject]@{
                SMB1OptionalFeature = $opt.State.ToString()
                AuditSmb1Access     = [bool]$cfg.AuditSmb1Access
                EnableSMB1Protocol  = [bool]$cfg.EnableSMB1Protocol
                EnableSMB2Protocol  = [bool]$cfg.EnableSMB2Protocol
                OperLines           = @($operOut)
                AuditLines          = @($auditOut)
                AuditpolLines       = @($auditpolOut)
            }
        }

        $operEnabled  = Parse-WevtutilEnabled -Lines $data.OperLines
        $auditEnabled = Parse-WevtutilEnabled -Lines $data.AuditLines
        $logonFail    = Parse-AuditpolLogonFailure -Lines $data.AuditpolLines

        $recs = New-Object System.Collections.Generic.List[string]

        # SMB1 auditing advice only if SMB1 is enabled
        if ($data.EnableSMB1Protocol -eq $true -or $data.SMB1OptionalFeature -match 'Enabled') {
            if ($data.AuditSmb1Access -ne $true) {
                $recs.Add('SMB1 enabled: consider enabling SMB1 auditing (not required for SMB signing change)')
            }
        }

        # Logging readiness (GPO-driven)
        if ($operEnabled -ne $true)  { $recs.Add('GPO: Enable SMBServer Operational channel') }
        if ($auditEnabled -ne $true) { $recs.Add('GPO: Enable SMBServer Audit channel (optional)') }
        if ($logonFail -ne $true)    { $recs.Add('GPO: Enable Advanced Audit Policy Audit Logon (Failure)') }

$recText = 'OK – required SMB logging already enabled; no additional logging needed'
if ($recs.Count -gt 0) { $recText = ($recs -join ' | ') }


        $phase1 += [pscustomobject]@{
            DC                          = $dc
            SMB1OptionalFeature         = $data.SMB1OptionalFeature
            EnableSMB1Protocol          = $data.EnableSMB1Protocol
            EnableSMB2Protocol          = $data.EnableSMB2Protocol
            AuditSmb1Access             = $data.AuditSmb1Access
            SMBServerOperationalEnabled = $operEnabled
            SMBServerAuditEnabled       = $auditEnabled
            AuditLogonFailureEnabled    = $logonFail
            Recommendation              = $recText
            Error                       = ''
        }

        Write-Host ("  SMB1 Optional Feature         : {0}" -f $data.SMB1OptionalFeature) -ForegroundColor Cyan
        Write-Host ("  EnableSMB1Protocol            : {0}" -f $data.EnableSMB1Protocol) -ForegroundColor Cyan
        Write-Host ("  EnableSMB2Protocol            : {0}" -f $data.EnableSMB2Protocol) -ForegroundColor Cyan
        Write-Host ("  AuditSmb1Access               : {0}" -f $data.AuditSmb1Access) -ForegroundColor Cyan
        Write-Host ("  SMBServer Operational enabled : {0}" -f $operEnabled) -ForegroundColor Cyan
        Write-Host ("  SMBServer Audit enabled       : {0}" -f $auditEnabled) -ForegroundColor Cyan
        Write-Host ("  Audit Logon Failure enabled   : {0}" -f $logonFail) -ForegroundColor Cyan
        Write-Host ("  Recommendation                : {0}" -f $recText) -ForegroundColor White

    } catch {
        $msg = $_.Exception.Message
        Write-Host ("  ERROR on {0}. {1}" -f $dc, $msg) -ForegroundColor Red

        $phase1 += [pscustomobject]@{
            DC                          = $dc
            SMB1OptionalFeature         = 'Unknown'
            EnableSMB1Protocol          = 'Unknown'
            EnableSMB2Protocol          = 'Unknown'
            AuditSmb1Access             = 'Unknown'
            SMBServerOperationalEnabled = 'Unknown'
            SMBServerAuditEnabled       = 'Unknown'
            AuditLogonFailureEnabled    = 'Unknown'
            Recommendation              = 'Check manually'
            Error                       = $msg
        }
    }
}

Write-Host ""
Write-Host "Summary (Phase 1):" -ForegroundColor White
$phase1 | Sort-Object DC | Format-Table -AutoSize

$phase1 | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Phase1Csv
Write-Host ("Phase 1 CSV saved to: {0}" -f $Phase1Csv) -ForegroundColor Green

# ---- Phase 2 prompt ----
Write-Host ""
Write-Host "Optional Phase 2: Collect live SMB sessions from each DC (Get-SmbSession)." -ForegroundColor Yellow
Write-Host "Note: This is a point-in-time snapshot and may be empty on quiet DCs." -ForegroundColor DarkYellow
$choice = Read-Host "Collect SMB sessions from all DCs now? (Y/N)"

if ($choice -match '^(Y|y)$') {

    Write-Host ""
    Write-Host "Collecting SMB sessions (Phase 2)..." -ForegroundColor Cyan

    $sessions = @()

    foreach ($dc in $dcs) {

        $row = $phase1 | Where-Object { $_.DC -eq $dc } | Select-Object -First 1
        if (-not $row -or ($row.Error -and $row.Error.ToString().Trim() -ne '')) {
            Write-Host ("Skipping {0} (Phase 1 error or WinRM unavailable)." -f $dc) -ForegroundColor Yellow
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
            Write-Host ("  ERROR collecting sessions from {0}. {1}" -f $dc, $msg2) -ForegroundColor Red

            $sessions += [pscustomobject]@{
                DC                 = $dc
                ClientComputerName = ''
                ClientUserName     = ''
                Dialect            = ''
                Signed             = ''
                Error              = $msg2
            }
        }
    }

    Write-Host ""
    Write-Host "Summary (Phase 2 - SMB Sessions):" -ForegroundColor White

    if ($sessions -and ($sessions | Measure-Object).Count -gt 0) {

        $sessions | Sort-Object DC, ClientComputerName | Format-Table -AutoSize

        # Dialect explanation (ONLY observed dialects)
        $observedDialects = $sessions |
            Where-Object { $_.Dialect -and $_.Dialect.ToString().Trim() -ne '' } |
            Select-Object -ExpandProperty Dialect -Unique |
            Sort-Object

        if ($observedDialects -and $observedDialects.Count -gt 0) {
            Write-Host ""
            Write-Host "Dialect meanings observed (only what was found):" -ForegroundColor Yellow

            foreach ($d in $observedDialects) {
                $meaning = Get-DialectMeaning -Dialect $d
                Write-Host ("  {0} : {1}" -f $d, $meaning) -ForegroundColor White
            }
        }

        $sessions | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Phase2Csv
        Write-Host ("Phase 2 CSV saved to: {0}" -f $Phase2Csv) -ForegroundColor Green

    } else {
        Write-Host "No session data collected." -ForegroundColor Yellow
    }

} else {
    Write-Host "Skipped Phase 2." -ForegroundColor Yellow
}

try { Stop-Transcript | Out-Null } catch { }
Write-Host ("Log saved to: {0}" -f $TranscriptPath) -ForegroundColor Green
