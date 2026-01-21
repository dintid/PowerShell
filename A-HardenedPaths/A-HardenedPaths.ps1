<#
MODNI – SYSVOL/NETLOGON Impact Audit (fast, PS 5.1) — 2025-08-27
PingCastle ID: A-HardenedPaths

What this script does
---------------------
Audits client access to the domain SYSVOL and NETLOGON shares and assesses
impact before enabling Hardened UNC Paths (e.g., RequireMutualAuthentication).
It:
  • Collects Security Event Log entries on each reachable DC:
      - 4624  (logons) for correlation
      - 4776  (NTLM validation) as a heuristic hint
      - 5140  (share access) filtered to SYSVOL/NETLOGON only
  • Correlates each 5140 access to its likely auth method (Kerberos vs NTLM)
    using LogonId (primary) or Account+SourceIP within a time skew, and
    falls back to nearby 4776 to label likely NTLM.
  • Shows first N rows PER DC, plus a summary table and an NTLM impact list.
  • Uses a real **Event Log RPC** probe (short timeout) to mark DCs reachable
    (or show the exact failure reason).

How to use / tune
-----------------
  • Set the time window here:
        $TimeWindow = New-TimeSpan -Hours 4
    (use -Minutes / -Days as you prefer). $StartTime is derived automatically.
  • Optional speed knobs:
        $FetchMaxEvents         # reduce for speed; increase to catch more
        $EnableReverseDns = $false   # skip PTR lookups for speed
  • Output is written to console and to:
        C:\itm8\A-HardenedPaths

Interpreting results
--------------------
  • The per-DC table shows OK / No events / Error (with reason).
  • “AuthMethod = NTLM” on SYSVOL/NETLOGON indicates accesses likely to BREAK
    if RequireMutualAuthentication=1 is enforced for those shares.

Requirements
------------
  • Run with rights to read Security logs on DCs.
  • Windows PowerShell 5.1 (kept PS5.1-safe).
#>

# ===== Tunables =====
$TimeWindow               = New-TimeSpan -Hours 4        # << change window (e.g. -Hours 4, -Minutes 90, -Days 1)
$StartTime                = (Get-Date) - $TimeWindow
$FetchMaxEvents           = 300                          # lower = faster, higher = more coverage
$ShowTopPerDC             = 10
$CorrelationSkewMinutes   = 5                            # 4624/4776 within ±N minutes of 5140
$EnableReverseDns         = $true                        # set $false for speed if PTR is slow
$PerPhaseJobTimeoutSec    = 45                           # job cap per phase (4624/4776/5140)
$ProbeTimeoutSec          = 8                            # reachability probe timeout (Event Log RPC)

# ===== Logging =====
$LogFolder = 'C:\itm8\A-HardenedPaths'
if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
$LogFile = Join-Path $LogFolder ("A-HardenedPaths_SYSVOL_NETLOGON_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
function Write-Log { param($text) Add-Content -Path $LogFile -Value $text }

# ===== DC discovery =====
try { $AllDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName }
catch { $AllDCs = @($env:COMPUTERNAME) }

# Normalize local names (avoid false negatives)
$LocalNames = @($env:COMPUTERNAME)
if ($env:USERDNSDOMAIN) { $LocalNames += "$($env:COMPUTERNAME).$($env:USERDNSDOMAIN)" }

# ===== Event Log RPC reachability probe (authoritative) =====
function Invoke-EventLogProbe {
  param([string]$Computer,[int]$TimeoutSec=8)
  $sb = {
    param($Computer)
    try {
      Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='Security'; StartTime=(Get-Date).AddMinutes(-1) } -MaxEvents 1 -ErrorAction Stop | Out-Null
      'OK'
    } catch {
      $_.Exception.Message
    }
  }
  $job = Start-Job -ScriptBlock $sb -ArgumentList @($Computer)
  if (-not (Wait-Job $job -Timeout $TimeoutSec)) {
    Try { Stop-Job $job -Force -ErrorAction SilentlyContinue } Catch {}
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return 'probe timeout'
  }
  $res = Receive-Job $job -ErrorAction SilentlyContinue
  Remove-Job $job -Force -ErrorAction SilentlyContinue
  if ([string]::IsNullOrWhiteSpace($res)) { 'unknown error' } else { [string]$res }
}

$DCStates = @()
foreach ($dc in $AllDCs) {
  $probe = if ($LocalNames -contains $dc) { 'OK' } else { Invoke-EventLogProbe -Computer $dc -TimeoutSec $ProbeTimeoutSec }
  $DCStates += [pscustomobject]@{
    DC        = $dc
    Reachable = ($probe -eq 'OK')
    Reason    = if ($probe -eq 'OK') { '' } else { "unreachable: $probe" }
  }
}

$Reachable   = $DCStates | Where-Object { $_.Reachable }   | Select-Object -ExpandProperty DC
$Unreachable = $DCStates | Where-Object { -not $_.Reachable }

# ----- Print DC lists with a clear separator -----
$dcList = "Target DCs (reachable): {0}" -f (($Reachable | Sort-Object) -join ', ')
Write-Host $dcList -ForegroundColor Cyan
Write-Log  $dcList

Write-Host "----------------------------------------" -ForegroundColor DarkGray
Write-Log  "----------------------------------------"

if ($Unreachable) {
  Write-Host "Skipped (unreachable):" -ForegroundColor Yellow
  ($Unreachable | Select-Object @{n='DC';e={$_.DC}}, @{n='Reason';e={$_.Reason}} | Sort-Object DC) | Format-Table -AutoSize
  Write-Log (($Unreachable | Select-Object DC,Reason | Sort-Object DC | Out-String))
} else {
  Write-Host "Skipped (unreachable): none" -ForegroundColor Yellow
  Write-Log  "Skipped (unreachable): none"
}
if (-not $Reachable) { Write-Host "No reachable DCs. Exiting." -ForegroundColor Red; return }

# ===== Helpers =====
function Get-JobHelperBlock {
@'
function Field { param($msg,$label) if ($msg -match ("{0}:\s+([^\r\n]+)" -f [regex]::Escape($label))) { $Matches[1].Trim() } else { '-' } }
function Get-From-AnyLabel { param($msg,[string[]]$labels) foreach ($l in $labels) { $v = Field $msg $l; if ($v -ne '-') { return $v } } '-' }
# DNS helpers (per-job cache)
$dnsCache = @{}
function Resolve-Name { param([string]$ip,[string]$fallback,[bool]$DoPtr=$true)
  if (-not $DoPtr) { if ($fallback -and $fallback -ne '-') { return $fallback } else { return $ip } }
  if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') {
    if ($fallback -and $fallback -ne '-') { return $fallback } else { return $ip }
  }
  if ($dnsCache.ContainsKey($ip)) { return $dnsCache[$ip] }
  try {
    $fqdn = [System.Net.Dns]::GetHostEntry($ip).HostName
    if ([string]::IsNullOrWhiteSpace($fqdn)) { $fqdn = $ip }
  } catch {
    if ($fallback -and $fallback -ne '-') { $fqdn = $fallback } else { $fqdn = $ip }
  }
  $dnsCache[$ip] = $fqdn
  return $fqdn
}
function Compose-ResolvedIP { param([string]$ip,[string]$name)
  if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-') { return '-' }
  if ($name -and $name -ne $ip) { return ("{0} ({1})" -f $ip, $name) }
  $ip
}
'@
}

function Run-PhaseJobs {
  param(
    [string]$Title,
    [ScriptBlock]$ScriptBlock,
    [object[]]$ArgListPerDC,
    [int]$TimeoutSec = 45
  )
  Write-Host "`n$Title" -ForegroundColor Cyan; Write-Log "`n$Title"
  $jobs = @()
  for ($i=0; $i -lt $ArgListPerDC.Count; $i++) {
    $args = $ArgListPerDC[$i]
    $jobs += Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args
  }

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $done = @()
  do {
    $completed = $jobs | Where-Object { $_.State -ne 'Running' -and $_.State -ne 'NotStarted' }
    foreach ($j in $completed) { if ($done -notcontains $j.Id) { $done += $j.Id } }
    if ($done.Count -eq $jobs.Count) { break }
    Start-Sleep -Milliseconds 300
  } while ((Get-Date) -lt $deadline)

  $stragglers = $jobs | Where-Object { $_.State -eq 'Running' -or $_.State -eq 'NotStarted' }
  foreach ($j in $stragglers) { Try { Stop-Job $j -Force -ErrorAction SilentlyContinue } Catch {} }

  $results = @()
  foreach ($j in $jobs) {
    try {
      $out = Receive-Job -Job $j -ErrorAction SilentlyContinue
      if ($null -ne $out) { $results += $out } else {
        $comp = ($j.ChildJobs[0].JobParameters.Values | Select-Object -First 1)
        $results += [pscustomobject]@{ Server=$comp; _Error='timeout' }
      }
    } catch {
      $comp = ($j.ChildJobs[0].JobParameters.Values | Select-Object -First 1)
      $results += [pscustomobject]@{ Server=$comp; _Error=$_.Exception.Message }
    } finally {
      Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
    }
  }
  return ,$results
}

# Add explicit “unreachable” errors to each phase’s results so they show up in counts and final table
function Add-UnreachablePhaseErrors {
  param([array]$Results,[array]$DCStates,[int]$Id)
  $errs = foreach ($s in $DCStates) {
    if (-not $s.Reachable) {
      [pscustomobject]@{ Server=$s.DC; Id=$Id; _Error=$s.Reason }
    }
  }
  return @($Results + $errs)
}

# ===== Jobs (helpers inlined) =====
$HelperBlock = Get-JobHelperBlock

$Job4624 = [ScriptBlock]::Create($HelperBlock + @'
param($Computer,$StartTime,$FetchMaxEvents,$DoPtr)
try {
  $ev = Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='Security'; Id=4624; StartTime=$StartTime } -MaxEvents $FetchMaxEvents -ErrorAction Stop |
       Sort-Object TimeCreated -Descending
} catch { return ,([pscustomobject]@{ Server=$Computer; _Error=$_.Exception.Message }) }
$rows = New-Object System.Collections.Generic.List[object]
foreach ($e in $ev) {
  $m   = $e.Message
  $lp  = Field $m 'Logon Process'
  $acc = Get-From-AnyLabel -msg $m -labels @('Account Name','Account','Target Account')
  $ws  = Get-From-AnyLabel -msg $m -labels @('Workstation Name','Workstation','Client Name','ClientName','Source Workstation')
  $ip  = Get-From-AnyLabel -msg $m -labels @('Source Network Address','Source Address','Client Address','ClientAddress')
  $lid = Get-From-AnyLabel -msg $m -labels @('Logon ID','LogonId','Logon-ID')
  $client = Resolve-Name -ip $ip -fallback $ws -DoPtr:$DoPtr
  $src    = Compose-ResolvedIP -ip $ip -name $client
  $rows.Add([pscustomobject]@{
    Server=$Computer; TimeCreated=$e.TimeCreated; Id=4624; LogonProcess=$lp;
    Account=$acc; Client=$client; Workstation=$ws; SourceIP=$src; SourceIPRaw=$ip; LogonId=$lid
  })
}
$rows
'@)

$Job4776 = [ScriptBlock]::Create($HelperBlock + @'
param($Computer,$StartTime,$FetchMaxEvents,$DoPtr)
try {
  $ev = Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='Security'; Id=4776; StartTime=$StartTime } -MaxEvents $FetchMaxEvents -ErrorAction Stop |
       Sort-Object TimeCreated -Descending
} catch { return ,([pscustomobject]@{ Server=$Computer; _Error=$_.Exception.Message }) }
$rows = New-Object System.Collections.Generic.List[object]
foreach ($e in $ev) {
  $m = $e.Message
  $acc = Get-From-AnyLabel -msg $m -labels @('Logon Account','Account Name','Account')
  $ws  = Get-From-AnyLabel -msg $m -labels @('Source Workstation','Workstation Name','Workstation','Client Name','ClientName')
  $ip  = Get-From-AnyLabel -msg $m -labels @('Source Network Address','Source Address','Client Address','ClientAddress')
  $client = Resolve-Name -ip $ip -fallback $ws -DoPtr:$DoPtr
  $src    = Compose-ResolvedIP -ip $ip -name $client
  $rows.Add([pscustomobject]@{
    Server=$Computer; TimeCreated=$e.TimeCreated; Id=4776; Account=$acc;
    Client=$client; Workstation=$ws; SourceIP=$src; SourceIPRaw=$ip
  })
}
$rows
'@)

$Job5140 = [ScriptBlock]::Create($HelperBlock + @'
param($Computer,$StartTime,$FetchMaxEvents,$DoPtr)
try {
  $ev = Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='Security'; Id=5140; StartTime=$StartTime } -MaxEvents $FetchMaxEvents -ErrorAction Stop |
       Sort-Object TimeCreated -Descending
} catch { return ,([pscustomobject]@{ Server=$Computer; _Error=$_.Exception.Message }) }
$rows = New-Object System.Collections.Generic.List[object]
foreach ($e in $ev) {
  $m = $e.Message
  $share = Get-From-AnyLabel -msg $m -labels @('Share Name','ShareName')
  if ($share -eq '-' -or ($share -notmatch 'SYSVOL' -and $share -notmatch 'NETLOGON')) { continue }
  $acc = Get-From-AnyLabel -msg $m -labels @('Account Name','Account','Subject:')
  $ip  = Get-From-AnyLabel -msg $m -labels @('Source Network Address','Source Address','Client Address','ClientAddress')
  $ws  = Get-From-AnyLabel -msg $m -labels @('Workstation Name','Workstation','Client Name','ClientName')
  $lid = Get-From-AnyLabel -msg $m -labels @('Logon ID','LogonId','Logon-ID')
  $client = Resolve-Name -ip $ip -fallback $ws -DoPtr:$DoPtr
  $src    = Compose-ResolvedIP -ip $ip -name $client
  $rows.Add([pscustomobject]@{
    Server=$Computer; TimeCreated=$e.TimeCreated; Share=($share -replace '^\\\\[^\\]+\\','');
    Account=$acc; Client=$client; SourceIP=$src; SourceIPRaw=$ip; LogonId=$lid; AuthMethod='-'
  })
}
$rows
'@)

# ===== PHASE 1: Collect 4624 logons (for correlation later) =====
$argList = @(); foreach ($dc in $Reachable) { $argList += ,@($dc,$StartTime,$FetchMaxEvents,$EnableReverseDns) }
$All4624 = Run-PhaseJobs -Title 'Phase 1: Collect 4624 logons (for correlation later)' -ScriptBlock $Job4624 -ArgListPerDC $argList -TimeoutSec $PerPhaseJobTimeoutSec
$All4624 = Add-UnreachablePhaseErrors -Results $All4624 -DCStates $DCStates -Id 4624
foreach ($dc in ($DCStates.DC | Sort-Object)) {
  $rows = $All4624 | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count }
  $count = ($rows | Measure-Object).Count
  $err   = $All4624 | Where-Object { $_.Server -eq $dc -and $_.PSObject.Properties.Match('_Error').Count }
  if ($err) {
    $msg = ($err | Select-Object -First 1 -ExpandProperty _Error)
    $line = ("  {0}: error ({1})" -f $dc,$msg)
  } else {
    $line = ("  {0}: {1}" -f $dc,$count)
  }
  Write-Host $line; Write-Log  $line
}

# ===== PHASE 2: Collect 4776 (NTLM hints for correlation later) =====
$argList = @(); foreach ($dc in $Reachable) { $argList += ,@($dc,$StartTime,$FetchMaxEvents,$EnableReverseDns) }
$All4776 = Run-PhaseJobs -Title 'Phase 2: Collect 4776 (NTLM hints for correlation later)' -ScriptBlock $Job4776 -ArgListPerDC $argList -TimeoutSec $PerPhaseJobTimeoutSec
$All4776 = Add-UnreachablePhaseErrors -Results $All4776 -DCStates $DCStates -Id 4776
foreach ($dc in ($DCStates.DC | Sort-Object)) {
  $rows = $All4776 | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count }
  $count = ($rows | Measure-Object).Count
  $err   = $All4776 | Where-Object { $_.Server -eq $dc -and $_.PSObject.Properties.Match('_Error').Count }
  if ($err) {
    $msg = ($err | Select-Object -First 1 -ExpandProperty _Error)
    $line = ("  {0}: error ({1})" -f $dc,$msg)
  } else {
    $line = ("  {0}: {1}" -f $dc,$count)
  }
  Write-Host $line; Write-Log  $line
}

# ===== PHASE 3: Collect 5140 (SYSVOL/NETLOGON accesses to analyze) =====
$argList = @(); foreach ($dc in $Reachable) { $argList += ,@($dc,$StartTime,$FetchMaxEvents,$EnableReverseDns) }
$All5140 = Run-PhaseJobs -Title 'Phase 3: Collect 5140 (SYSVOL/NETLOGON accesses to analyze)' -ScriptBlock $Job5140 -ArgListPerDC $argList -TimeoutSec $PerPhaseJobTimeoutSec
$All5140 = Add-UnreachablePhaseErrors -Results $All5140 -DCStates $DCStates -Id 5140
foreach ($dc in ($DCStates.DC | Sort-Object)) {
  $rows = $All5140 | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count }
  $count = ($rows | Measure-Object).Count
  $err   = $All5140 | Where-Object { $_.Server -eq $dc -and $_.PSObject.Properties.Match('_Error').Count }
  if ($err) {
    $msg = ($err | Select-Object -First 1 -ExpandProperty _Error)
    $line = ("  {0}: error ({1})" -f $dc,$msg)
  } else {
    $line = ("  {0}: {1}" -f $dc,$count)
  }
  Write-Host $line; Write-Log  $line
}

# ===== PHASE 4: Correlate 5140 with 4624/4776 and output =====
Write-Host "`nPhase 4: Correlate 5140 with 4624/4776 and output" -ForegroundColor Cyan
Write-Log "Phase 4: Correlate 5140 with 4624/4776 and output"

# Build 4624 index per DC
$ByDC4624 = @{}
foreach ($dc in $Reachable) { $ByDC4624[$dc] = $All4624 | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count } }

# Correlate
foreach ($dc in $Reachable) {
  $dc5140 = $All5140 | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count }
  if (-not $dc5140) { continue }

  $idxByLogon = @{}
  $list4624   = $ByDC4624[$dc]
  foreach ($r in $list4624) {
    $lid = $r.LogonId
    if ($lid -and $lid -ne '-' -and -not $idxByLogon.ContainsKey($lid)) { $idxByLogon[$lid] = $r }
  }

  foreach ($row in $dc5140) {
    $auth = '-'
    $match = $null

    if ($row.LogonId -and $row.LogonId -ne '-' -and $idxByLogon.ContainsKey($row.LogonId)) { $match = $idxByLogon[$row.LogonId] }

    if (-not $match -and $list4624) {
      $from = $row.TimeCreated.AddMinutes(-$CorrelationSkewMinutes)
      $to   = $row.TimeCreated.AddMinutes($CorrelationSkewMinutes)
      $cand = $list4624 | Where-Object {
        $_.Account -eq $row.Account -and $_.SourceIPRaw -eq $row.SourceIPRaw -and $_.TimeCreated -ge $from -and $_.TimeCreated -le $to
      } | Sort-Object { [math]::Abs( (New-TimeSpan -Start $_.TimeCreated -End $row.TimeCreated).TotalSeconds ) } | Select-Object -First 1
      if ($cand) { $match = $cand }
    }

    if ($match) {
      if     ($match.LogonProcess -eq 'Kerberos') { $auth = 'Kerberos' }
      elseif ($match.LogonProcess -eq 'NtLmSsp')  { $auth = 'NTLM' }
      elseif ($match.LogonProcess)                { $auth = $match.LogonProcess }
    } else {
      $from = $row.TimeCreated.AddMinutes(-$CorrelationSkewMinutes)
      $to   = $row.TimeCreated.AddMinutes($CorrelationSkewMinutes)
      $sawNTLM = $All4776 | Where-Object {
        $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count -and
        $_.Account -eq $row.Account -and $_.SourceIPRaw -eq $row.SourceIPRaw -and
        $_.TimeCreated -ge $from -and $_.TimeCreated -le $to
      } | Select-Object -First 1
      if ($sawNTLM) { $auth = 'NTLM' }
    }

    $row.AuthMethod = $auth
  }
}

# ===== Output =====
function Show-DCStatusTable {
  param([string]$Title,[string[]]$DCs,[array]$Results,[int]$Top=10)
  Write-Host "`n$Title" -ForegroundColor Cyan; Write-Log "`n$Title"
  $status = foreach ($dc in $DCs) {
    $err = $Results | Where-Object { $_.Server -eq $dc -and $_.PSObject.Properties.Match('_Error').Count }
    $rows= $Results | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count }
    if ($err) {
      $msg = ($err | Select-Object -First 1 -ExpandProperty _Error)
      if ($msg -eq 'timeout' -or $msg -match 'No events were found') { [pscustomobject]@{ DC=$dc; Status=($msg); Count=0 } }
      else { [pscustomobject]@{ DC=$dc; Status=("Error: {0}" -f $msg); Count=0 } }
    } elseif ($rows) { [pscustomobject]@{ DC=$dc; Status='OK'; Count=$rows.Count } }
      else { [pscustomobject]@{ DC=$dc; Status='No events found'; Count=0 } }
  }
  $status | Sort-Object DC | Format-Table -AutoSize
  Write-Log ($status | Sort-Object DC | Out-String)

  $grand=0; $withData=0
  foreach ($dc in $DCs) {
    $rows = $Results | Where-Object { $_.Server -eq $dc -and -not $_.PSObject.Properties.Match('_Error').Count }
    if (-not $rows) { continue }
    $withData++; $grand += $rows.Count
    $hdr = "[{0}] first {1}" -f $dc,$Top
    Write-Host $hdr -ForegroundColor DarkCyan; Write-Log $hdr
    $topRows = $rows | Sort-Object TimeCreated -Descending | Select-Object -First $Top |
      Select-Object Server,TimeCreated,Account,Share,Client,SourceIP,AuthMethod,LogonId
    $topRows | Format-Table -AutoSize
    Write-Log ($topRows | Out-String)
    if ($rows.Count -gt $Top) {
      $note = "(showing first {0} of {1} on {2})" -f $Top,$rows.Count,$dc
      Write-Host $note -ForegroundColor Yellow; Write-Log $note
    }
  }
  $sum = "Summary: {0} total accesses across {1} DCs with results" -f $grand,$withData
  Write-Host $sum -ForegroundColor Cyan; Write-Log $sum
}

Show-DCStatusTable -Title 'Event 5140 — SYSVOL/NETLOGON access (auth correlation)' -DCs $Reachable -Results $All5140 -Top $ShowTopPerDC

# ===== Impact summary (NTLM) with dynamic window text =====
$ntlmHits = $All5140 | Where-Object { -not $_.PSObject.Properties.Match('_Error').Count -and $_.AuthMethod -eq 'NTLM' }

# Human-friendly window description
$windowDesc = if ($TimeWindow.Days -ge 1) {
  "{0} day(s)" -f $TimeWindow.Days
} elseif ($TimeWindow.Hours -ge 1) {
  "{0} hour(s)" -f $TimeWindow.Hours
} else {
  "{0} minute(s)" -f $TimeWindow.Minutes
}

if ($ntlmHits) {
  $summary = $ntlmHits | Group-Object SourceIP | Sort-Object Count -Descending |
    Select-Object @{n='SourceIP';e={$_.Name}}, @{n='Hits';e={$_.Count}}
  Write-Host "`nLikely to BREAK under Hardened UNC Paths (RequireMutualAuthentication=1):" -ForegroundColor Red
  $summary | Format-Table -AutoSize
  Write-Log ("`r`nNTLM to SYSVOL/NETLOGON:`r`n" + ($summary | Out-String))
} else {
  $msg1 = "No NTLM access to SYSVOL/NETLOGON observed in the defined $windowDesc window."
  $msg2 = "It is safe to run Hardening on SYSVOL and NETLOGON folders, since no clients logged onto these using NTLM."
  Write-Host "`n$msg1" -ForegroundColor Green
  Write-Host $msg2 -ForegroundColor Green
  Write-Log ("`r`n$msg1`r`n$msg2")
}
