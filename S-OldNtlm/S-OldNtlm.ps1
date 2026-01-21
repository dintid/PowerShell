<#
MODNI – 8004/8005-first NTLM Impact Audit (ISE-safe) — 2025-09-03
PingCastle ID: S-OldNTLM

WHAT THIS SCRIPT DOES
---------------------
Audits NTLM activity observed by Domain Controllers (DCs) and estimates impact if you enforce "NTLMv2 only (deny LM/NTLMv1)".

PHASE 1  — NTLM/Operational (Events 8004/8005), per DC
  • 8004 = “Blocked (Audit-only)” -> would be denied if “Restrict NTLM: Incoming NTLM traffic” = Deny.
  • 8005 = “Allowed (Audit-only)” -> would be allowed.
  • In Audit mode NOTHING is actually blocked; DC logs what *would* happen.
  • Shows a combined view (one row per (DC, Client)) with first/last seen and counts.

PHASE 2  — Targets (group per client per DC)
  • Summarizes Phase-1 into a clean target list (per (DC, Client)), flags if any 8004 were seen, and which protocol was hinted.

PHASE 3  — Follow-ups in Security log (fast & bounded)
  • 4776 “NTLM validation” -> PackageName field confirms NTLM V1 vs V2.
  • 4624 “Logon” with LogonProcessName = NtLmSsp -> NTLM logon completed.
  • Uses tight time windows around Phase-1 sightings, window clamp, event caps, and XML parsing to stay fast.
  • Optionally looks across *other DCs* to find the 4776 that confirmed v1/v2 (common in multi-DC sites).
  • Produces a single combined status table (one line per (DC, Client)), plus a “Focus” subset:
      - Confirmed NTLMv1
      - NTLM logons (version unknown)

OUTPUT FILES  (default folder: C:\itm8\S-OldNTLM)
--------------------------------------------------
- S-OldNTLM_8004First_<MODE>_<ts>.log
- S-OldNTLM_Transcript_<MODE>_<ts>.txt                 (if transcript enabled)
- S-OldNTLM_Targets_<MODE>_<ts>.csv                    (Phase 2)
- S-OldNTLM_ClientStatus_<MODE>_<ts>.csv               (Phase 3 combined status)
- S-OldNTLM_Focus_NTLMv1_Unknown_<MODE>_<ts>.csv       (Focus subset; path logged, not echoed to console)

HOW TO USE
----------
- For quick development on the current DC only: set $CurrentDCOnly = $true.
- For full domain scan: $CurrentDCOnly = $false.
- If Phase 3 feels slow, reduce caps, shorten the clamp window, disable cross-DC lookups.

KNOWN ISE BEHAVIOR
------------------
- PowerShell ISE locks transcript files while a transcript is active. This script uses a safe toggle and try/finally
  so the transcript is stopped cleanly and the file handle released.
#>

# ======================
# ====== TUNABLES ======
# ======================
# (Each tunable has a short explanation)

# Time window for Phase 1 (NTLM/Operational 8004/8005) and base for Phase 3 windows
$TimeWindow               = New-TimeSpan -Hours 24         # look back this long across DCs
$StartTime                = (Get-Date) - $TimeWindow       # Phase 1 start
$Now                      = Get-Date                       # Phase 1 end

# Phase 1: per-DC event cap
$MaxDCNTLM                = 2000                           # max 8004/8005 to fetch per DC (keeps Phase 1 bounded)

# Phase 3: per-DC local fetch caps (Security log)
$FollowUpMax_4776         = 400                            # cap 4776 (NTLM validation) per DC
$FollowUpMax_4624         = 800                            # cap 4624 (NTLM logons) per DC
$SkewMinutes              = 5                              # +/- minutes around each client’s first/last seen

# Phase 1 console presentation
$Phase1AggregateSamples   = $true                          # show aggregated Phase 1 (one row per DC,Client)
$Phase1CombinedView       = $true                          # combine all DCs into one table (DC is a column)
$ShowTopCombinedPhase1    = 30                             # only show this many rows in console (full data still used)
$ShowTopPerDC             = 10                             # unused when combined; left for fallback

# Scope / UX
$CurrentDCOnly            = $false                         # true = only the current DC; false = all DCs in domain
$ShowAuditModeNote        = $true                          # print the “this is Audit-only” note before tables
$QuietConsole             = $false                         # reduce console tables (export still happens)

# Phase 3 performance & presentation
$Phase3FastMode           = $true                          # fast path (prefetch, XML parsing, summarized)
$MaxPhase3Targets         = 300                            # limit per DC number of clients processed in Phase 3
$Phase3CombinedView       = $true                          # show one combined Phase 3 table for all DCs
$ShowTopPhase3Combined    = 200                            # cap console rows for Phase 3
$Phase3PerDCConsole       = $false                         # if true, also print per-DC tables (verbose)

# Phase 3 fetch visibility & guard rails
$Phase3FetchProgress      = $true                          # show small “Fetching …” lines per DC
$LimitPhase3WindowMinutes = 75                             # clamp per-DC Phase 3 window to this size (prevents big scans)

# Optional short-circuits
$ShortCircuitSilentDCs    = $true                          # skip Phase 3 per-target work if DC returned 0 of 4776+4624
$ShortCircuitNoisyDCs     = $false                         # skip overly noisy DCs (sum of 4776+4624 > threshold)
$NoisyDCMaxTotalEvents    = 2000                           # threshold for “noisy DC” if enabled

# Cross-DC 4776 lookup (useful when 4624 is on DC A but 4776 validation happens on DC B)
$CrossDC4776Lookup        = $true                          # enable/disable cross-DC 4776 correlation
$CrossDCMaxEventsPerDC    = 400                            # cap fetched 4776 per other-DC
$CrossDCMaxDCs            = 20                             # cap number of other DCs scanned

# 4624 filtering & 4776 indexing
$UseFilterXmlFor4624      = $true                          # fetch only 4624 where LogonProcessName = NtLmSsp/NTLM
$Use4776Indexing          = $true                          # index 4776 by Workstation & User for fast lookups

# Resolve “NULL/UNKNOWN” clients (best-effort)
$ResolveNullClients       = $true                          # try to guess likely workstation from 4776 correlation
$GuessMinCount            = 4                              # minimum hits to consider a guess
$GuessMinRatio            = 0.40                           # minimum share of hits to accept a guess
$DoReverseDnsForGuesses   = $false                         # placeholder; DNS lookups are off for speed/ISE

# Focus table options
$ShowFocusConsole         = $true                          # show Focus table on screen (kept as you wanted)
$UseReasonCodes           = $true                          # add compact reason codes to Focus
$ShowReasonLegend         = $true                          # show legend below the Focus table

# Transcript control (safer for ISE)
$EnableTranscript         = $true                          # start/stop transcript safely (locked until stopped)

# ========================
# ====== FILE PATHS ======
# ========================
$LogFolder = 'C:\itm8\S-OldNTLM'
if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }

$ModeString = if ($CurrentDCOnly) { "CurrentDC_$env:COMPUTERNAME" } else { "AllDCs" }
$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'

$LogFile    = Join-Path $LogFolder ("S-OldNTLM_8004First_{0}_{1}.log" -f $ModeString, $Timestamp)
$CsvTargets = Join-Path $LogFolder ("S-OldNTLM_Targets_{0}_{1}.csv"   -f $ModeString, $Timestamp)
$CsvStatus  = Join-Path $LogFolder ("S-OldNTLM_ClientStatus_{0}_{1}.csv" -f $ModeString, $Timestamp)
$CsvFocus   = Join-Path $LogFolder ("S-OldNTLM_Focus_NTLMv1_Unknown_{0}_{1}.csv" -f $ModeString, $Timestamp)
$Transcript = Join-Path $LogFolder ("S-OldNTLM_Transcript_{0}_{1}.txt" -f $ModeString, $Timestamp)

function Write-Log { param($text) Add-Content -Path $LogFile -Value $text }
function Note   { param($text) Write-Host $text -ForegroundColor Yellow; Write-Log $text }
function Info   { param($text) Write-Host $text -ForegroundColor Cyan;   Write-Log $text }
function Emph   { param($text) Write-Host $text -ForegroundColor Green;  Write-Log $text }
function Warn   { param($text) Write-Host $text -ForegroundColor Yellow; Write-Log $text }
function ErrL   { param($text) Write-Host $text -ForegroundColor Red;    Write-Log $text }

# ============================
# ===== Transcript (safe) =====
# ============================
$TranscriptStarted = $false
if ($EnableTranscript) {
  try {
    Start-Transcript -Path $Transcript -Force | Out-Null
    $TranscriptStarted = $true
    Note ("Transcript started: {0}" -f $Transcript)
  } catch {
    Warn ("WARNING: Could not start transcript ({0})" -f $_.Exception.Message)
  }
}

try {
  # ===============================
  # ===== DC discovery/reach =====
  # ===============================
  try { Import-Module ActiveDirectory -ErrorAction Stop } catch {}
  if ($CurrentDCOnly) {
    $AllDCs = @($env:COMPUTERNAME); Note ("Mode: Current DC only ({0})" -f $env:COMPUTERNAME)
  } else {
    try { $AllDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName; Note "Mode: All DCs in domain" }
    catch { $AllDCs = @($env:COMPUTERNAME); Note ("Mode: Fallback to current DC only ({0})" -f $env:COMPUTERNAME) }
  }

  function Probe-DC { param([string]$Computer)
    try {
      Get-WinEvent -ComputerName $Computer -FilterHashtable @{ LogName='Security'; StartTime=(Get-Date).AddMinutes(-1); EndTime=(Get-Date) } -MaxEvents 1 -ErrorAction Stop | Out-Null
      'OK'
    } catch { $_.Exception.Message }
  }
  $DCStates = foreach ($dc in $AllDCs) { $res = Probe-DC $dc; [pscustomobject]@{ DC=$dc; Reachable=($res -eq 'OK'); Reason= if ($res -eq 'OK') { '' } else { "unreachable: $res" } } }
  $Reachable   = $DCStates | Where-Object { $_.Reachable }   | Select-Object -ExpandProperty DC
  $Unreachable = $DCStates | Where-Object { -not $_.Reachable }

  Info ("Target DCs (reachable): {0}" -f ($Reachable -join ', '))
  Write-Host "----------------------------------------" -ForegroundColor DarkGray
  Write-Log  "----------------------------------------"
  if ($Unreachable) { Warn "Skipped (unreachable):"; ($Unreachable | Select-Object DC,Reason | Sort-Object DC) | Format-Table -AutoSize; Write-Log (($Unreachable | Select-Object DC,Reason | Sort-Object DC | Out-String)) }
  if (-not $Reachable) { ErrL "No reachable DCs. Exiting."; return }

  # ===================
  # ===== Helpers =====
  # ===================
  function Field { param($msg,$label) if ($msg -match ("{0}:\s+([^\r\n]+)" -f [regex]::Escape($label))) { $Matches[1].Trim() } else { "-" } }
  function Get-From-AnyLabel { param($msg,[string[]]$labels) foreach ($l in $labels) { $v = Field $msg $l; if ($v -ne "-") { return $v } } "-" }

  function Get-XmlDataValue { param($event, [string]$name)
    try { $x = [xml]$event.ToXml(); ($x.Event.EventData.Data | Where-Object { $_.Name -eq $name } | Select-Object -First 1).'#text' } catch { $null }
  }

  # Prefer workstation, else IP, else account
  function Get-ClientKey { param($ws,$ip,$acct)
    if ($ws -and $ws -ne '-') { return $ws.ToUpper() }
    if ($ip -and $ip -ne '-') { return $ip.ToUpper() }
    if ($acct)                { return $acct.ToUpper() }
    'UNKNOWN'
  }

  function Show-AuditModeNote { param([string]$Phase='Phase 2/3 tables')
    $note = @(
      "NOTE about 'Blocked' (Audit mode) — applies to $Phase",
      "• 'Blocked' below means: the DC flagged the NTLM attempt as one that WOULD be denied if",
      "  'Restrict NTLM: Incoming NTLM traffic' were set to Deny. In Audit mode, nothing is actually blocked.",
      "• Protocol labels from 8004/8005 are approximate. Phase 3 uses Event 4776 to confirm 'NTLM V1' vs 'NTLM V2'.",
      "• If there are 8004/8005 events but NO matching 4776/4624, the NTLM attempt likely didn’t complete (often the client fell back to Kerberos)."
    ) -join [Environment]::NewLine
    Write-Host $note -ForegroundColor Yellow
    Write-Log  $note
  }

  $ReasonLegendMap = @{
    1 = "4624 NTLM on this DC, but no 4776 here — validation likely on another DC or outside caps/window"
    2 = "Unattributed client in 8004/8005 (NULL/UNKNOWN); see LikelyClient guess if present"
    3 = "NTLM attempt (8004/8005) but no NTLM logon completed — likely Kerberos fallback"
  }
  function Compute-ReasonCode {
    param(
      [string]$ProtocolSeen,
      [int]   $NTLM4624,
      [int]   $NTLM4776,
      [string]$Client
    )
    if ($ProtocolSeen -eq 'NTLM (unknown ver)' -and $NTLM4624 -gt 0 -and $NTLM4776 -eq 0) { return 1 }
    if ($Client -in @('UNKNOWN','NULL'))                                            { return 2 }
    if ($ProtocolSeen -eq 'NTLMv2/Kerberos (uncertain)' -and $NTLM4624 -eq 0)       { return 3 }
    return $null
  }

  function Get-ConfidenceLabel {
    param([int]$count,[double]$ratio)
    if ($count -ge 10 -and $ratio -ge 0.70) { return 'High' }
    if ($count -ge 5  -and $ratio -ge 0.55) { return 'Medium' }
    if ($count -ge $GuessMinCount -and $ratio -ge $GuessMinRatio) { return 'Low' }
    return $null
  }
  function Guess-LikelyClient {
    param(
      [object[]]$E4776Slim,   # PSCustomObjects {Time, WS, User, Pkg, DC}
      [datetime]$from,
      [datetime]$to
    )
    $cands = $E4776Slim | Where-Object { $_.Time -ge $from -and $_.Time -le $to } |
             ForEach-Object {
               $ws = $_.WS
               if ([string]::IsNullOrWhiteSpace($ws) -or $ws -eq '-' -or $ws -eq 'NULL') {
                 if ($_.User -and $_.User.EndsWith('$')) { $ws = $_.User.TrimEnd('$') } else { $ws = $null }
               }
               if ($ws) { $ws.ToUpper() }
             } | Where-Object { $_ }

    if (-not $cands -or $cands.Count -lt $GuessMinCount) { return $null }

    $grp   = $cands | Group-Object | Sort-Object Count -Descending
    $top   = $grp | Select-Object -First 1
    $total = ($grp | Measure-Object -Property Count -Sum).Sum
    if (-not $top -or $total -le 0) { return $null }

    $ratio = [double]$top.Count / [double]$total
    $conf  = Get-ConfidenceLabel -count $top.Count -ratio $ratio
    if (-not $conf) { return $null }

    [pscustomobject]@{
      Name       = $top.Name
      Count      = $top.Count
      Total      = $total
      Ratio      = $ratio
      Confidence = $conf
    }
  }

  function New-4624NtlmFilterXml {
    param([datetime]$From,[datetime]$To)
    $fromUtc = $From.ToUniversalTime().ToString("o")
    $toUtc   = $To.ToUniversalTime().ToString("o")
@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)
        and TimeCreated[@SystemTime &gt;= '$fromUtc' and @SystemTime &lt;= '$toUtc']]]
      and
      *[EventData[Data[@Name='LogonProcessName']='NtLmSsp' or Data[@Name='LogonProcessName']='NTLM']]
    </Select>
  </Query>
</QueryList>
"@
  }

  # ============================
  # ===== Phase 1: 8004/8005 ===
  # ============================
  Info "`nPhase 1: Collect 8004/8005 (NTLM/Operational) — 8004=Blocked (audit), 8005=Allowed (audit). Detect NTLM attempts."
  $AllDCNTLM = @()

  foreach ($dc in $Reachable) {
    $r = try {
      Get-WinEvent -ComputerName $dc -FilterHashtable @{
        LogName='Microsoft-Windows-NTLM/Operational'; Id=8004,8005; StartTime=$StartTime; EndTime=$Now
      } -MaxEvents $MaxDCNTLM -ErrorAction Stop
    } catch { $null }
    if (-not $r) { ErrL ("  {0}: error or no access to NTLM/Operational" -f $dc); continue }

    $rows = foreach ($e in $r) {
      $m        = $e.Message
      $acct     = Get-From-AnyLabel -msg $m -labels @('Account Name','Account','Target Account','User')
      $clientIP = Get-From-AnyLabel -msg $m -labels @('Client Address','Source Network Address','Source Address','ClientAddress')
      $ws       = Get-From-AnyLabel -msg $m -labels @('Workstation Name','Client Name','Workstation','ClientName')
      $protoRaw = Get-From-AnyLabel -msg $m -labels @('NTLM Protocol','NTLM Version','NTLM protocol name')
      if ($protoRaw -eq '-') { $protoRaw = $m }

      $isLM     = ($protoRaw -match '(?i)\bLM\b(?!\w)')
      $isV1     = ($protoRaw -match '(?i)NTLM\s*v?1\b')
      $isV2     = ($protoRaw -match '(?i)NTLM\s*v?2\b')
      $blocked  = ($m -match '(?i)\bBlocked\b')
      $proto    = if     ($isLM) { 'LM' } elseif ($isV1) { 'NTLMv1' } elseif ($isV2) { 'NTLMv2' } else { 'Unknown' }

      [pscustomobject]@{
        Server=$dc; TimeCreated=$e.TimeCreated; Id=$e.Id;
        Account=$acct; Workstation=$ws; ClientAddress=$clientIP;
        Protocol=$proto; Blocked=$blocked; Message=($m.Split("`n")[0])
      }
    }

    Write-Log ("  {0}: {1}" -f $dc, ($rows | Measure-Object).Count)
    $AllDCNTLM += $rows
  }

  Write-Host ("  Total events collected: {0}" -f ($AllDCNTLM.Count)) -ForegroundColor Cyan
  Write-Log  ("  Total events collected: {0}" -f ($AllDCNTLM.Count))

  if (-not $AllDCNTLM) {
    Warn "`nNo 8004/8005 events found in the window. Ensure NTLM Operational channel is enabled and policies applied."
    return
  }

  if ($Phase1AggregateSamples) {
    if ($ShowAuditModeNote -and -not $QuietConsole) {
      Write-Host "NOTE: 'Blocked (Audit-only)' = would be denied if 'Restrict NTLM' were set to Deny. In Audit mode, nothing is actually blocked." -ForegroundColor Yellow
      Write-Log  "NOTE: Blocked (Audit-only) explanation shown."
    }

    # Build (DC,Client) aggregates
    $PreAgg = foreach ($r in $AllDCNTLM) {
      $clientKey = Get-ClientKey -ws $r.Workstation -ip $r.ClientAddress -acct $r.Account
      [pscustomobject]@{
        Server     = $r.Server
        Client     = $clientKey
        Id         = $r.Id
        TimeCreated= $r.TimeCreated
      }
    }

    $AggCombined = $PreAgg | Group-Object -Property Server, Client | ForEach-Object {
      $items = $_.Group
      $server = $items[0].Server
      $client = $items[0].Client
      [pscustomobject]@{
        Server     = $server
        Client     = $client
        AuditHits  = $items.Count
        Events8004 = ($items | Where-Object { $_.Id -eq 8004 }).Count
        Events8005 = ($items | Where-Object { $_.Id -eq 8005 }).Count
        Blocked    = if (($items | Where-Object { $_.Id -eq 8004 }).Count -gt 0) { 'Blocked (Audit-only)' } else { 'Allowed (Audit-only)' }
        FirstSeen  = ($items | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        LastSeen   = ($items | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
      }
    }

    if (-not $QuietConsole) {
      Write-Host "`nPhase 1 Combined sample (aggregated) — one line per (DC, Client)" -ForegroundColor DarkCyan
      $AggCombined |
        Sort-Object -Property @{Expression='Events8004';Descending=$true}, @{Expression='AuditHits';Descending=$true}, @{Expression='Server';Descending=$false}, @{Expression='Client';Descending=$false} |
        Select-Object -First $ShowTopCombinedPhase1 |
        Format-Table -AutoSize Server, Client, Blocked, AuditHits, Events8004, Events8005, FirstSeen, LastSeen

      if ($AggCombined.Count -gt $ShowTopCombinedPhase1) {
        Warn ("(showing top {0} of {1} (DC,Client) aggregates by 8004 count)" -f $ShowTopCombinedPhase1, $AggCombined.Count)
      }
    }
  }

  # ============================
  # ===== Phase 2: Targets =====
  # ============================
  Info "`nPhase 2: Build targets (LM/NTLMv1/Blocked) — Summarises per client per DC for clarity."
  if ($ShowAuditModeNote -and -not $QuietConsole) { Show-AuditModeNote -Phase 'Phase 2 (Targets)' }

  $Targets = @()
  $grouped = $AllDCNTLM | Group-Object -Property @{Expression={ Get-ClientKey -ws $_.Workstation -ip $_.ClientAddress -acct $_.Account }}, 'Server'

  foreach ($g in $grouped) {
    $clientKey = $g.Group[0] | ForEach-Object { Get-ClientKey -ws $_.Workstation -ip $_.ClientAddress -acct $_.Account } | Select-Object -First 1
    $server    = $g.Group[0].Server
    $first     = ($g.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    $last      = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated

    $anyLM      = ($g.Group | Where-Object { $_.Protocol -eq 'LM' }).Count -gt 0
    $anyV1      = ($g.Group | Where-Object { $_.Protocol -eq 'NTLMv1' }).Count -gt 0
    $anyBlocked = ($g.Group | Where-Object { $_.Blocked }).Count -gt 0
    $cnt8004    = ($g.Group | Where-Object { $_.Id -eq 8004 }).Count
    $cnt8005    = ($g.Group | Where-Object { $_.Id -eq 8005 }).Count

    $proto = if ($anyLM) { 'LM' } elseif ($anyV1) { 'NTLMv1' } else { 'NTLMv2/Unknown' }

    $Targets += [pscustomobject]@{
      Server       = $server
      Client       = $clientKey
      Protocol     = $proto
      Blocked      = $anyBlocked
      BlockedAudit = if ($anyBlocked) { 'Blocked (Audit-only; not actually denied)' } else { 'Not blocked' }
      FirstSeen    = $first
      LastSeen     = $last
      Count8004    = $cnt8004
      Count8005    = $cnt8005
      Accounts     = ($g.Group.Account | Where-Object { $_ -and $_ -ne '-' } | Select-Object -Unique) -join '; '
    }
  }

  if (-not $QuietConsole) {
    Write-Host "Targets (per client, per DC):" -ForegroundColor Cyan
    $Targets |
      Select-Object Server, Client, Blocked, BlockedAudit, @{n='Protocol (from 8004/8005)';e={$_.Protocol}}, FirstSeen, LastSeen, Count8004, Count8005, Accounts |
      Sort-Object -Property @{Expression='Blocked';Descending=$true}, @{Expression='Client';Descending=$false} |
      Format-Table -AutoSize
  }

  # ===========================================
  # ===== Phase 3: Follow-ups (fast/combined) ==
  # ===========================================
  Info "`nPhase 3: Follow-ups (4776/4624, tight window) — 4776=NTLM validation (Package Name shows NTLMv1/v2); 4624 NtLmSsp=NTLM logon."
  if ($ShowAuditModeNote -and -not $QuietConsole) { Show-AuditModeNote -Phase 'Phase 3 (Follow-ups)' }

  $FollowUpTargets = $Targets | Where-Object { $_.Blocked -or $_.Protocol -in @('LM','NTLMv1','NTLMv2/Unknown') }
  if (-not $FollowUpTargets) {
    Emph "`nNo follow-up targets found."
  } else {
    $AllStatusRows = @()

    foreach ($dc in ($FollowUpTargets.Server | Select-Object -Unique)) {
      $dcTargets = $FollowUpTargets | Where-Object { $_.Server -eq $dc } | Select-Object -First $MaxPhase3Targets
      if (-not $dcTargets) { continue }

      Write-Log ("--- DC: {0} (summarized) ---" -f $dc)
      # Per-DC time window with clamp
      $dcFrom = ($dcTargets | Measure-Object -Property FirstSeen -Minimum).Minimum.AddMinutes(-$SkewMinutes)
      $dcTo   = ($dcTargets | Measure-Object -Property LastSeen  -Maximum).Maximum.AddMinutes($SkewMinutes)
      $maxSpan = [TimeSpan]::FromMinutes($LimitPhase3WindowMinutes)
      if (($dcTo - $dcFrom) -gt $maxSpan) { $dcFrom = $dcTo - $maxSpan }

      # Prefetch local 4776 / 4624 with caps
      if ($Phase3FetchProgress -and -not $QuietConsole) { Write-Host ("  [{0}] Fetching 4776..." -f $dc) -ForegroundColor DarkGray }
      $r4776 = try {
        Get-WinEvent -ComputerName $dc -FilterHashtable @{
          LogName='Security'; Id=4776; StartTime=$dcFrom; EndTime=$dcTo
        } -MaxEvents $FollowUpMax_4776 -ErrorAction Stop
      } catch { $null }

      if ($UseFilterXmlFor4624) {
        $xml4624 = New-4624NtlmFilterXml -From $dcFrom -To $dcTo
        if ($Phase3FetchProgress -and -not $QuietConsole) { Write-Host ("  [{0}] Fetching 4624 NtLmSsp (FilterXml, max {1})..." -f $dc,$FollowUpMax_4624) -ForegroundColor DarkGray }
        $r4624   = try { Get-WinEvent -ComputerName $dc -FilterXml $xml4624 -MaxEvents $FollowUpMax_4624 -ErrorAction Stop } catch { $null }
      } else {
        if ($Phase3FetchProgress -and -not $QuietConsole) { Write-Host ("  [{0}] Fetching 4624 (Hashtable, max {1})..." -f $dc,$FollowUpMax_4624) -ForegroundColor DarkGray }
        $r4624   = try {
          Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName='Security'; Id=4624; StartTime=$dcFrom; EndTime=$dcTo
          } -MaxEvents $FollowUpMax_4624 -ErrorAction Stop
        } catch { $null }
      }

      # Short circuit “silent” DCs
      if ($ShortCircuitSilentDCs) {
        $cLocal = (($r4776 | Measure-Object).Count) + (($r4624 | Measure-Object).Count)
        if ($cLocal -eq 0) {
          if ($Phase3FetchProgress -and -not $QuietConsole) { Write-Host ("  [{0}] No 4776/4624 in window; skipping Phase 3 details." -f $dc) -ForegroundColor DarkGray }
          continue
        }
      }
      # Short circuit very noisy DCs (optional)
      if ($ShortCircuitNoisyDCs) {
        $evtCount = (($r4776 | Measure-Object).Count) + (($r4624 | Measure-Object).Count)
        if ($evtCount -gt $NoisyDCMaxTotalEvents) {
          if ($Phase3FetchProgress -and -not $QuietConsole) { Write-Host ("  [{0}] Too many events ({1}); skipping Phase 3 details for performance." -f $dc, $evtCount) -ForegroundColor DarkGray }
          continue
        }
      }

      $E4776 = @(); if ($r4776) { $E4776 = $r4776 }
      $E4624 = @()
      if ($r4624) {
        if ($UseFilterXmlFor4624) {
          $E4624 = $r4624
        } else {
          $E4624 = $r4624 | Where-Object { (Get-XmlDataValue $_ 'LogonProcessName') -match 'NTLM|NtLmSsp' }
        }
      }

      # Slim projections (local DC)
      $E4776Slim = foreach ($e in $E4776) {
        [pscustomobject]@{
          Time = $e.TimeCreated
          WS   = (Get-XmlDataValue $e 'Workstation')
          User = (Get-XmlDataValue $e 'TargetUserName')
          Pkg  = (Get-XmlDataValue $e 'PackageName')  # "NTLM V1" / "NTLM V2"
          DC   = $dc
        }
      }
      $E4624Times = $E4624 | Select-Object -ExpandProperty TimeCreated

      # Optional indexing (local)
      $Idx4776ByWS   = @{}
      $Idx4776ByUser = @{}
      if ($Use4776Indexing -and $E4776Slim.Count -gt 0) {
        foreach ($e in $E4776Slim) {
          $wsU = if ($e.WS) { $e.WS.ToUpper() } else { $null }
          $usU = if ($e.User) { $e.User.ToUpper() } else { $null }
          if ($wsU) { if (-not $Idx4776ByWS.ContainsKey($wsU)) { $Idx4776ByWS[$wsU] = New-Object 'System.Collections.Generic.List[object]' }; $Idx4776ByWS[$wsU].Add($e) }
          if ($usU) { if (-not $Idx4776ByUser.ContainsKey($usU)) { $Idx4776ByUser[$usU] = New-Object 'System.Collections.Generic.List[object]' }; $Idx4776ByUser[$usU].Add($e) }
        }
      }

      # Optional: Cross-DC 4776 prefetch within same time window
      $CrossE4776ByDC = @{}
      if ($CrossDC4776Lookup -and ($Reachable.Count -gt 1)) {
        $OtherDCs = ($Reachable | Where-Object { $_ -ne $dc }) | Select-Object -First $CrossDCMaxDCs
        foreach ($odc in $OtherDCs) {
          $r = try {
            Get-WinEvent -ComputerName $odc -FilterHashtable @{
              LogName='Security'; Id=4776; StartTime=$dcFrom; EndTime=$dcTo
            } -MaxEvents $CrossDCMaxEventsPerDC -ErrorAction Stop
          } catch { $null }
          if ($r) {
            $CrossE4776ByDC[$odc] = ($r | ForEach-Object {
              [pscustomobject]@{
                Time = $_.TimeCreated
                WS   = (Get-XmlDataValue $_ 'Workstation')
                User = (Get-XmlDataValue $_ 'TargetUserName')
                Pkg  = (Get-XmlDataValue $_ 'PackageName')
                DC   = $odc
              }
            })
          }
        }
      }

      # Optional: Cross-DC indexing
      $CrossIdxByWS   = @{}
      $CrossIdxByUser = @{}
      if ($Use4776Indexing -and $CrossE4776ByDC.Keys.Count -gt 0) {
        foreach ($kv in $CrossE4776ByDC.GetEnumerator()) {
          foreach ($e in $kv.Value) {
            $wsU = if ($e.WS) { $e.WS.ToUpper() } else { $null }
            $usU = if ($e.User) { $e.User.ToUpper() } else { $null }
            if ($wsU) { if (-not $CrossIdxByWS.ContainsKey($wsU))   { $CrossIdxByWS[$wsU]   = New-Object 'System.Collections.Generic.List[object]' }; $CrossIdxByWS[$wsU].Add($e) }
            if ($usU) { if (-not $CrossIdxByUser.ContainsKey($usU)) { $CrossIdxByUser[$usU] = New-Object 'System.Collections.Generic.List[object]' }; $CrossIdxByUser[$usU].Add($e) }
          }
        }
      }

      # Build status rows for each client on this DC
      $StatusRows = foreach ($t in $dcTargets) {
        $from = $t.FirstSeen.AddMinutes(-$SkewMinutes)
        $to   = $t.LastSeen.AddMinutes($SkewMinutes)

        # 4776 bucket for this client (local DC)
        $bucketLocal = @()
        if ($Use4776Indexing -and $t.Client -and $t.Client -notin @('UNKNOWN','NULL')) {
          $key = $t.Client
          if ($Idx4776ByWS.ContainsKey($key))   { $bucketLocal += $Idx4776ByWS[$key] }
          if ($Idx4776ByUser.ContainsKey($key)) { $bucketLocal += $Idx4776ByUser[$key] }
        } else { $bucketLocal = $E4776Slim }

        $bucketLocal = $bucketLocal | Where-Object { $_.Time -ge $from -and $_.Time -le $to }

        $c4776 = 0; $pAcc = @(); $VersionSource = $null; $CrossDCValidatingDCs = $null
        foreach ($e in $bucketLocal) {
          $wsU = if ($e.WS) { $e.WS.ToUpper() } else { '' }
          $acU = if ($e.User) { $e.User.ToUpper() } else { '' }
          $match = $true
          if ($t.Client -and $t.Client -notin @('UNKNOWN','NULL')) {
            $match = ($t.Client -eq $wsU) -or ($t.Client -eq $acU)
          }
          if ($match) {
            $c4776++
            if     ($e.Pkg -match '(?i)V\s*1') { $pAcc += 'NTLMv1' }
            elseif ($e.Pkg -match '(?i)V\s*2') { $pAcc += 'NTLMv2' }
            elseif ($e.Pkg) { $pAcc += $e.Pkg }
          }
        }
        if ($c4776 -gt 0) { $VersionSource = 'Local DC (4776)' }

        # 4624 counts (already filtered if FilterXml used)
        $c4624 = ($E4624Times | Where-Object { $_ -ge $from -and $_ -le $to }).Count

        # Cross-DC 4776 if 4624 seen here but no local 4776
        if ($CrossDC4776Lookup -and $c4624 -gt 0 -and $c4776 -eq 0 -and $CrossE4776ByDC.Keys.Count -gt 0) {
          $bucketCross = @()
          if ($Use4776Indexing -and $t.Client -and $t.Client -notin @('UNKNOWN','NULL')) {
            $key = $t.Client
            if ($CrossIdxByWS.ContainsKey($key))   { $bucketCross += $CrossIdxByWS[$key] }
            if ($CrossIdxByUser.ContainsKey($key)) { $bucketCross += $CrossIdxByUser[$key] }
          } else {
            foreach ($v in $CrossE4776ByDC.Values) { $bucketCross += $v }
          }
          $bucketCross = $bucketCross | Where-Object { $_.Time -ge $from -and $_.Time -le $to }

          $crossMatches = @()
          foreach ($e in $bucketCross) {
            $wsU = if ($e.WS) { $e.WS.ToUpper() } else { '' }
            $acU = if ($e.User) { $e.User.ToUpper() } else { '' }
            $match = $true
            if ($t.Client -and $t.Client -notin @('UNKNOWN','NULL')) {
              $match = ($t.Client -eq $wsU) -or ($t.Client -eq $acU)
            }
            if ($match) { $crossMatches += $e }
          }
          if ($crossMatches) {
            $c4776 += $crossMatches.Count
            foreach ($e in $crossMatches) {
              if     ($e.Pkg -match '(?i)V\s*1') { $pAcc += 'NTLMv1' }
              elseif ($e.Pkg -match '(?i)V\s*2') { $pAcc += 'NTLMv2' }
              elseif ($e.Pkg) { $pAcc += $e.Pkg }
            }
            $VersionSource = 'Other DC (4776)'
            $CrossDCValidatingDCs = ($crossMatches | Select-Object -ExpandProperty DC -Unique) -join '; '
          }
        }

        # Protocol seen label
        $protSeen =
          if ($pAcc | Where-Object { $_ -eq 'NTLMv2' }) { 'NTLMv2' }
          elseif ($pAcc | Where-Object { $_ -eq 'NTLMv1' }) { 'NTLMv1' }
          elseif ($c4624 -gt 0 -and $c4776 -eq 0) { 'NTLM (unknown ver)' }
          else { 'NTLMv2/Kerberos (uncertain)' }

        # Assessment & bucket
        $assessment, $category =
          if ($protSeen -eq 'NTLMv2') { 'Confirmed NTLMv2', 'Confirmed NTLMv2' }
          elseif ($protSeen -eq 'NTLMv1') { 'Uses NTLMv1 (risk)', 'Confirmed NTLMv1' }
          elseif ($protSeen -eq 'NTLM (unknown ver)') { 'NTLM logons seen; version unconfirmed', 'NTLM logons (version unknown)' }
          else { 'No NTLM logon completed; likely Kerberos fallback', 'No NTLM logon (Kerberos fallback)' }

        $blockedAudit = if ($t.Blocked) { 'Blocked (Audit-only; not actually denied)' } else { 'Not blocked' }

        # Likely client guess for NULL/UNKNOWN
        $LikelyClient = $null; $GuessConfidence = $null; $GuessBasis = $null
        if ($ResolveNullClients -and ($t.Client -eq 'UNKNOWN' -or $t.Client -eq 'NULL')) {
          $Combined4776 = @($E4776Slim)
          if ($CrossE4776ByDC.Keys.Count -gt 0) {
            foreach ($v in $CrossE4776ByDC.Values) { $Combined4776 += $v }
          }
          $g = Guess-LikelyClient -E4776Slim $Combined4776 -from $from -to $to
          if ($g) {
            $LikelyClient    = $g.Name
            $GuessConfidence = $g.Confidence
            $pct = [math]::Round($g.Ratio * 100)
            $GuessBasis      = "{0}/{1} events ({2}%)" -f $g.Count, $g.Total, $pct
          }
        }

        $ReasonCode = if ($UseReasonCodes) { Compute-ReasonCode -ProtocolSeen $protSeen -NTLM4624 $c4624 -NTLM4776 $c4776 -Client $t.Client } else { $null }
        $ReasonText = if ($ReasonCode) { $ReasonLegendMap[$ReasonCode] } else { $null }

        [pscustomobject]@{
          Server        = $t.Server
          Client        = $t.Client
          Blocked       = $t.Blocked
          BlockedAudit  = $blockedAudit
          AuditHits     = $t.Count8004 + $t.Count8005
          Events8004    = $t.Count8004
          Events8005    = $t.Count8005
          NTLM4776      = $c4776
          NTLM4624      = $c4624
          ProtocolSeen  = $protSeen
          Assessment    = $assessment
          Category      = $category
          VersionSource = $VersionSource
          CrossDCValidatingDCs = $CrossDCValidatingDCs
          FirstSeen     = $t.FirstSeen
          LastSeen      = $t.LastSeen
          LikelyClient  = $LikelyClient
          GuessConfidence = $GuessConfidence
          GuessBasis    = $GuessBasis
          ReasonCode    = $ReasonCode
          Reason        = $ReasonText
        }
      }

      $AllStatusRows += $StatusRows
    }

    # Phase 3 combined console table
    if (-not $QuietConsole -and $Phase3CombinedView -and $AllStatusRows) {
      Write-Host "`nPhase 3 Combined (one line per DC, Client)" -ForegroundColor DarkCyan
      $AllStatusRows |
        Sort-Object -Property @{Expression='Blocked';Descending=$true}, @{Expression='Server';Descending=$false}, @{Expression='Client';Descending=$false} |
        Select-Object -First $ShowTopPhase3Combined |
        Select-Object Server, Client, Blocked,
                      @{n='AuditHits';e={$_.AuditHits}},
                      @{n='NTLM Validations (4776)';e={$_.NTLM4776}},
                      @{n='NTLM Logons (4624)';e={$_.NTLM4624}},
                      ProtocolSeen,
                      Assessment,
                      VersionSource |
        Format-Table -AutoSize

      if (($AllStatusRows | Measure-Object).Count -gt $ShowTopPhase3Combined) {
        Write-Host ("(showing top {0} of {1} rows)" -f $ShowTopPhase3Combined, ($AllStatusRows | Measure-Object).Count) -ForegroundColor Yellow
      }
    }

    # Export full status CSV
    $AllStatusRows | Sort-Object Server, Client | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvStatus
    Emph ("Saved client status: {0}" -f $CsvStatus)

    # Build & export Focus (Confirmed NTLMv1 + NTLM (version unknown))
    $Focus = $AllStatusRows | Where-Object { $_.Category -in @('Confirmed NTLMv1','NTLM logons (version unknown)') } |
             Sort-Object Server, Client

    if ($Focus) {
      # Console: Focus (kept)
      if ($ShowFocusConsole -and -not $QuietConsole) {
        Write-Host "`nFocus: NTLMv1 & NTLM (unknown version)" -ForegroundColor Cyan
        $Focus |
          Select-Object Server, Client, BlockedAudit, AuditHits,
                        @{n='NTLM Validations (4776)';e={$_.NTLM4776}},
                        @{n='NTLM Logons (4624)';e={$_.NTLM4624}},
                        ProtocolSeen, Assessment,
                        @{n='Reason#';e={$_.ReasonCode}},
                        LikelyClient, GuessConfidence |
          Format-Table -AutoSize

        if ($UseReasonCodes -and $ShowReasonLegend) {
          $usedCodes = $Focus | Where-Object { $_.ReasonCode } | Select-Object -ExpandProperty ReasonCode -Unique | Sort-Object
          if ($usedCodes) {
            Write-Host "`nReason codes:" -ForegroundColor DarkCyan
            foreach ($code in $usedCodes) {
              Write-Host ("  {0}: {1}" -f $code, $ReasonLegendMap[$code]) -ForegroundColor Yellow
            }
          }
        }
      }

      # Export Focus CSV (do not echo path to console; log only)
      $Focus |
        Select-Object Server, Client, BlockedAudit, AuditHits,
                      @{n='NTLM Validations (4776)';e={$_.NTLM4776}},
                      @{n='NTLM Logons (4624)';e={$_.NTLM4624}},
                      ProtocolSeen, Assessment,
                      VersionSource, CrossDCValidatingDCs,
                      ReasonCode, Reason,
                      LikelyClient, GuessConfidence, GuessBasis |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvFocus
      Write-Log ("Saved focus list (NTLMv1 + Unknown version): {0}" -f $CsvFocus)
    } else {
      Emph "Focus list empty (no Confirmed NTLMv1 or Unknown-version NTLM logons found)."
    }
  }

  # =======================
  # ====== Summary ========
  # =======================
  Info "`nSummary: Totals by outcome (management view)."
  $SummaryNote = @(
    "How to read this summary:",
    "• Confirmed NTLMv2 — Clients that validated using NTLMv2 (from 4776, local or cross-DC).",
    "• Confirmed NTLMv1 — Clients that validated using NTLMv1 during the audit. They may still support NTLMv2,",
    "  but MUST be reviewed and tested before blocking NTLMv1.",
    "• NTLM logons (version unknown) — NTLM logons were seen (4624 NtLmSsp), but no 4776 version confirmation",
    "  on any DC in scope. Investigate before enforcing NTLMv2-only.",
    "• No NTLM logon (Kerberos fallback) — 8004/8005 showed an NTLM attempt, but no NTLM logon completed in the window,",
    "  often indicating the client fell back to Kerberos. Typically low risk when enforcing NTLMv2-only."
  ) -join [Environment]::NewLine
  if (-not $QuietConsole) { Write-Host $SummaryNote -ForegroundColor Yellow }
  Write-Log  $SummaryNote

  $OutcomeSummary =
    $AllStatusRows |
      Group-Object Category |
      ForEach-Object { [pscustomobject]@{ Bucket=$_.Name; Clients=$_.Count } } |
      Sort-Object Bucket

  if ($OutcomeSummary) {
    if (-not $QuietConsole) { $OutcomeSummary | Format-Table -AutoSize }
  } else {
    if (-not $QuietConsole) {
      $Targets | Group-Object { if ($_.Blocked) { 'Blocked (Audit-only)' } else { $_.Protocol } } |
        ForEach-Object { [pscustomobject]@{ Bucket=$_.Name; Clients=$_.Count } } |
        Sort-Object Bucket | Format-Table -AutoSize
    }
  }

  # ==============================
  # ===== Export & announce ======
  # ==============================
  $Targets |
    Sort-Object -Property @{Expression='Blocked';Descending=$true}, @{Expression='Client';Descending=$false} |
    Select-Object Server, Client, Blocked, BlockedAudit, @{n='Protocol (from 8004/8005)';e={$_.Protocol}}, FirstSeen, LastSeen, Count8004, Count8005, Accounts |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvTargets

  Emph ("Saved targets list: {0}" -f $CsvTargets)
  Emph ("Saved client status: {0}" -f $CsvStatus)
  Emph ("Saved log file:     {0}" -f $LogFile)
  if ($TranscriptStarted) { Emph ("Saved transcript:   {0}" -f $Transcript) }

}
finally {
  if ($TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
  }
}
