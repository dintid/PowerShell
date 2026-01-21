<# ==================================================================================================
S-OldNTLM_CheckSettings.ps1
====================================================================================================
SYNOPSIS
  Local, read-only check of NTLM-related configuration on a Domain Controller.

WHAT IT DOES (checks)
  - STEP 0: Script context (computer, user, timestamp, PowerShell version)
  - STEP 1: Reference (informational) - LmCompatibilityLevel meanings
  - STEP 2: NTLM auditing knobs (registry)
    - Restrict NTLM: Audit Incoming NTLM Traffic
    - Restrict NTLM: Audit NTLM authentication in the domain
  - STEP 3: END GOAL (informational only)
    - LmCompatibilityLevel compared to target value 5 (no remediation exported)
  - STEP 4: Advanced Audit Policy (auditpol + force override)
    - Credential Validation (4776)
    - Logon (4624)
    - Force subcategory override (SCENoApplyLegacyAuditPolicy)
  - STEP 5: Event log channels (wevtutil)
    - Security log enabled and max size
    - Microsoft-Windows-NTLM/Operational enabled and max size
    - NOTE: If wevtutil maxSize is not yet updated, a policy registry fallback check is used
            and a reboot or Event Log service reload may be required for the change to reflect.

OUTPUTS
  - Console report (non-compliant items shown in red)
  - Text report (.txt)
  - CSV report (.csv)
  - Transcript (.transcript.txt) unless -NoTranscript
  - Remediation guidance (.txt) generated only if enforced checks are non-compliant

NOTES
  - No settings are modified by this script
  - No Winning GPO parsing
  - PowerShell 5.1 compatible (PowerShell ISE-safe)
  - ASCII-only output
  - Remediation guidance is GPO-only (no local command options)
  - Remediation section ends with a one-time reminder to run: gpupdate /force

MODNI 2026-01-20
================================================================================================= #>

[CmdletBinding()]
param(
  [switch]$NoTranscript
)

$ErrorActionPreference = 'Stop'

# -----------------------------
# Output paths
# -----------------------------
$baseRoot = 'C:\ITM8\S-OldNTLM\CheckSettings'
$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Join-Path $baseRoot $stamp
New-Item -Path $outDir -ItemType Directory -Force | Out-Null

$txtPath         = Join-Path $outDir 'S-OldNTLM_CheckSettings.txt'
$csvPath         = Join-Path $outDir 'S-OldNTLM_CheckSettings.csv'
$transcriptPath  = Join-Path $outDir 'S-OldNTLM_CheckSettings.transcript.txt'
$remediationPath = Join-Path $outDir 'S-OldNTLM_Remediation.txt'

# Collect remediation only for failing items
$script:Remediation = New-Object System.Collections.Generic.List[object]

# =================================================================================================
# ISE-safety: kill any stale function definition from the current session and define it ONCE
# =================================================================================================
Remove-Item -Path Function:\Add-RemediationItem -Force -ErrorAction SilentlyContinue

function Add-RemediationItem {
  param(
    [Parameter(Mandatory)][string]$Step,
    [Parameter(Mandatory)][string]$Title,

    # Accept scalar, array, empty string, empty array, or $null
    [Parameter(Mandatory=$false)]
    [AllowNull()]
    $Lines
  )

  # Normalize to string[]
  $norm = @()
  if ($null -eq $Lines) {
    # ok
  }
  elseif ($Lines -is [System.Array]) {
    foreach ($l in $Lines) { $norm += [string]$l }
  }
  else {
    $norm += [string]$Lines
  }

  $script:Remediation.Add([pscustomobject]@{
    Step  = $Step
    Title = $Title
    Lines = $norm
  }) | Out-Null
}

# -----------------------------
# Helpers
# -----------------------------
function Set-ConsoleWidth {
  param([int]$Width = 240)
  try {
    if ($Host -and $Host.UI -and $Host.UI.RawUI) {
      $buf = $Host.UI.RawUI.BufferSize
      if ($buf.Width -lt $Width) {
        $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size($Width, $buf.Height)
      }
      $win = $Host.UI.RawUI.WindowSize
      if ($win.Width -lt [Math]::Min($Width, 240)) {
        $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size([Math]::Min($Width, 240), $win.Height)
      }
    }
  } catch { }
}

function Write-Section {
  param([string]$Title)
  $line = '=' * 92
  Write-Host ''
  Write-Host $line
  Write-Host $Title
  Write-Host $line
}

function Out-TableWide {
  param(
    [Parameter(Mandatory)] $InputObject,
    [int]$Width = 5000
  )
  ($InputObject | Format-Table -AutoSize | Out-String -Width $Width).TrimEnd()
}

function Add-TextFile {
  param([string]$Text)
  $Text | Out-File -FilePath $txtPath -Encoding UTF8 -Append
}

function Write-ColoredRow {
  param(
    [Parameter(Mandatory)][string]$Line,
    [Parameter(Mandatory)][ValidateSet('Yes','No','N/A','Info')][string]$State
  )
  switch ($State) {
    'Yes' { Write-Host $Line -ForegroundColor Green }
    'No'  { Write-Host $Line -ForegroundColor Red }
    'N/A' { Write-Host $Line -ForegroundColor Yellow }
    default { Write-Host $Line }
  }
}

function Pad {
  param([string]$s, [int]$w)
  if ($null -eq $s) { $s = '' }
  $s = [string]$s
  if ($s.Length -gt $w) {
    if ($w -le 3) { return $s.Substring(0, $w) }
    return $s.Substring(0, $w-3) + '...'
  }
  return $s.PadRight($w)
}

function Get-RegistryValueSafe {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name
  )
  try {
    $item = Get-ItemProperty -Path $Path -ErrorAction Stop
    if ($null -ne $item.$Name) { return $item.$Name }
    return $null
  } catch {
    return $null
  }
}

function Get-FirstRegistryValueOfNames {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string[]]$Names
  )
  foreach ($n in $Names) {
    $v = Get-RegistryValueSafe -Path $Path -Name $n
    if ($null -ne $v) {
      return [pscustomobject]@{ Configured='Yes'; FoundName=$n; FoundValue=$v }
    }
  }
  return [pscustomobject]@{ Configured='No'; FoundName='<not found>'; FoundValue=$null }
}

function Get-LmCompatMeaning {
  param([int]$Value)
  switch ($Value) {
    0 { 'Send LM and NTLM responses (least secure).' }
    1 { 'Send LM and NTLM; use NTLMv2 session security if negotiated.' }
    2 { 'Send NTLM response only (no LM).' }
    3 { 'Send NTLMv2 response only.' }
    4 { 'Send NTLMv2 response only; refuse LM.' }
    5 { 'Send NTLMv2 response only; refuse LM and NTLM.' }
    default { 'Unknown / not set.' }
  }
}

function Get-AuditPolSubcategoryState {
  param([Parameter(Mandatory)][string]$Subcategory)

  try { $out = & auditpol.exe /get /subcategory:"$Subcategory" 2>&1 }
  catch { return '' }

  # Match the subcategory row, not the category header row
  $line = ($out | Where-Object {
      $_ -and
      ($_.TrimStart() -like "$Subcategory*") -and
      ($_.TrimStart() -notlike "$Subcategory/*")
    } | Select-Object -First 1)

  if (-not $line) { return '' }

  $t = ($line -replace '\s+',' ').Trim()

  if ($t -match '(Success and Failure)\s*$') { return 'Success and Failure' }
  if ($t -match '(No Auditing)\s*$')         { return 'No Auditing' }
  if ($t -match '(Success)\s*$')             { return 'Success' }
  if ($t -match '(Failure)\s*$')             { return 'Failure' }

  return $t
}

function Get-WevtutilChannel {
  param([Parameter(Mandatory)][string]$ChannelName)
  $h = @{}
  try {
    $out = & wevtutil.exe gl $ChannelName 2>&1
    foreach ($line in $out) {
      if ($line -match '^\s*enabled:\s*(.+)\s*$')     { $h.enabled    = $Matches[1].Trim() }
      if ($line -match '^\s*maxSize:\s*(\d+)\s*$')    { $h.maxSize    = [int64]$Matches[1].Trim() }
      if ($line -match '^\s*retention:\s*(.+)\s*$')   { $h.retention  = $Matches[1].Trim() }
      if ($line -match '^\s*autoBackup:\s*(.+)\s*$')  { $h.autoBackup = $Matches[1].Trim() }
    }
  } catch { }
  return $h
}

function Format-Bytes {
  param([int64]$Bytes)
  if ($Bytes -ge 1GB) { return ("{0:N2} GB" -f ($Bytes / 1GB)) }
  if ($Bytes -ge 1MB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
  if ($Bytes -ge 1KB) { return ("{0:N2} KB" -f ($Bytes / 1KB)) }
  return ("{0} B" -f $Bytes)
}

# STEP 5 fallback check (policy registry) for NTLM/Operational maxSize (KB)
function Get-PolicyNtlmOperationalMaxSizeKB {
  $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-NTLM/Operational'
  $v = Get-RegistryValueSafe -Path $regPath -Name 'MaxSize'
  if ($null -eq $v) {
    return [pscustomobject]@{
      Configured = 'No'
      MaxSizeKB  = $null
      RegPath    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-NTLM/Operational'
    }
  }

  $kb = $null
  try { $kb = [int64]$v } catch { $kb = $null }

  return [pscustomobject]@{
    Configured = 'Yes'
    MaxSizeKB  = $kb
    RegPath    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-NTLM/Operational'
  }
}

# STEP 5 fallback check (policy registry) for Security maxSize (KB)
function Get-PolicySecurityMaxSizeKB {
  $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
  $v = Get-RegistryValueSafe -Path $regPath -Name 'MaxSize'
  if ($null -eq $v) {
    return [pscustomobject]@{
      Configured = 'No'
      MaxSizeKB  = $null
      RegPath    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
    }
  }

  $kb = $null
  try { $kb = [int64]$v } catch { $kb = $null }

  return [pscustomobject]@{
    Configured = 'Yes'
    MaxSizeKB  = $kb
    RegPath    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
  }
}

function Write-ColorTable {
  param(
    [Parameter(Mandatory)][object[]]$Rows,
    [Parameter(Mandatory)][string[]]$Columns,
    [Parameter(Mandatory)][hashtable]$Widths,
    [string]$ComplianceColumn = 'Compliant'
  )

  $hdr = ''
  foreach ($c in $Columns) { $hdr += (Pad $c $Widths[$c]) + ' ' }
  $hdr = $hdr.TrimEnd()

  $sep = '-' * ([Math]::Min(220, [Math]::Max(80, $hdr.Length)))

  Write-Host $hdr
  Write-Host $sep

  $plainLines = New-Object System.Collections.Generic.List[string]
  $plainLines.Add($hdr) | Out-Null
  $plainLines.Add($sep) | Out-Null

  foreach ($r in $Rows) {
    $line = ''
    foreach ($c in $Columns) { $line += (Pad ($r.$c) $Widths[$c]) + ' ' }
    $line = $line.TrimEnd()

    $state = 'Info'
    if ($ComplianceColumn -and ($Columns -contains $ComplianceColumn)) {
      $state = $(if ($r.$ComplianceColumn) { [string]$r.$ComplianceColumn } else { 'Info' })
      if ($state -ne 'Yes' -and $state -ne 'No' -and $state -ne 'N/A') { $state = 'Info' }
    }

    if ($state -eq 'Info') { Write-Host $line } else { Write-ColoredRow -Line $line -State $state }
    $plainLines.Add($line) | Out-Null
  }

  return ($plainLines -join [Environment]::NewLine)
}

Set-ConsoleWidth -Width 240
if (-not $NoTranscript) {
  try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch { }
}

# --------------------------------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------------------------------
Write-Section ("S-OldNTLM - CheckSettings (timestamp: {0})" -f $stamp)

# --------------------------------------------------------------------------------------------------
# STEP 0
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 0 - Script info (read-only)"

$step0 = @(
  [pscustomobject]@{ Setting='Computer';         Value=$env:COMPUTERNAME }
  [pscustomobject]@{ Setting='User';             Value=$env:USERNAME }
  [pscustomobject]@{ Setting='DateTime (local)'; Value=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
  [pscustomobject]@{ Setting='PowerShell';       Value=$PSVersionTable.PSVersion.ToString() }
)
$step0Text = Out-TableWide -InputObject $step0
Write-Host $step0Text
Add-TextFile $step0Text

# --------------------------------------------------------------------------------------------------
# STEP 1
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 1 - Reference: LmCompatibilityLevel meanings"

$lmMeanings = @(
  [pscustomobject]@{ Value=0; Meaning='Send LM and NTLM responses.'; Notes='Least secure.' }
  [pscustomobject]@{ Value=1; Meaning='Send LM and NTLM; use NTLMv2 session security if negotiated.'; Notes='' }
  [pscustomobject]@{ Value=2; Meaning='Send NTLM response only.'; Notes='No LM.' }
  [pscustomobject]@{ Value=3; Meaning='Send NTLMv2 response only.'; Notes='Common baseline.' }
  [pscustomobject]@{ Value=4; Meaning='Send NTLMv2 response only; refuse LM.'; Notes='' }
  [pscustomobject]@{ Value=5; Meaning='Send NTLMv2 response only; refuse LM and NTLM.'; Notes='Hardening target; may break legacy.' }
)
$step1Text = Out-TableWide -InputObject $lmMeanings
Write-Host $step1Text
Add-TextFile $step1Text

# --------------------------------------------------------------------------------------------------
# STEP 2
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 2 - NTLM auditing knobs (registry)"

$msvPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$inCandidates = @('AuditReceivingNTLMTraffic','AuditIncomingNTLMTraffic')

$netlogonPath     = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$domainCandidates = @('AuditNTLMInDomain')

$rIncoming = Get-FirstRegistryValueOfNames -Path $msvPath -Names $inCandidates
$rDomain   = Get-FirstRegistryValueOfNames -Path $netlogonPath -Names $domainCandidates

$incomingOk = $false
if ($rIncoming.Configured -eq 'Yes') { try { $incomingOk = ([int]$rIncoming.FoundValue -eq 2) } catch { $incomingOk = $false } }

$domainOk = $false
if ($rDomain.Configured -eq 'Yes') { try { $domainOk = ([int]$rDomain.FoundValue -eq 7) } catch { $domainOk = $false } }

$step2Rows = @(
  [pscustomobject]@{
    Setting='Restrict NTLM: Audit Incoming NTLM Traffic'
    Configured=$rIncoming.Configured
    Value=$rIncoming.FoundValue
    Expected=2
    Compliant=$(if ($incomingOk) { 'Yes' } else { 'No' })
    Notes=("2 = Audit all incoming NTLM (8004/8005 evidence). Found value name: {0}" -f $rIncoming.FoundName)
  }
  [pscustomobject]@{
    Setting='Restrict NTLM: Audit NTLM authentication in the domain'
    Configured=$rDomain.Configured
    Value=$rDomain.FoundValue
    Expected=7
    Compliant=$(if ($domainOk) { 'Yes' } else { 'No' })
    Notes=("7 = Enable all domain NTLM auditing. Found value name: {0} (Path: Netlogon\Parameters)" -f $rDomain.FoundName)
  }
)

$plain2 = Write-ColorTable -Rows $step2Rows -Columns @('Setting','Configured','Value','Expected','Compliant','Notes') -Widths @{
  Setting=52; Configured=10; Value=8; Expected=8; Compliant=10; Notes=90
}
Add-TextFile $plain2

if (-not $incomingOk) {
  $cur = $(if ($rIncoming.Configured -ne 'Yes') { 'Not Set (value missing)' } else { [string]$rIncoming.FoundValue })
  Add-RemediationItem -Step 'STEP 2' -Title 'Restrict NTLM: Audit Incoming NTLM Traffic' -Lines @(
    ("Current state: {0} (value name: {1})" -f $cur, $rIncoming.FoundName),
    "Required state: 2 (Audit all)",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Windows Settings",
    "     - Security Settings",
    "       - Local Policies",
    "         - Security Options",
    "           - Network security: Restrict NTLM: Audit Incoming NTLM Traffic",
    "             Enable auditing for all accounts (Audit all)",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

if (-not $domainOk) {
  $cur = $(if ($rDomain.Configured -ne 'Yes') { 'Not Set (value missing)' } else { [string]$rDomain.FoundValue })
  Add-RemediationItem -Step 'STEP 2' -Title 'Restrict NTLM: Audit NTLM authentication in the domain' -Lines @(
    ("Current state: {0} (value name: {1})" -f $cur, $rDomain.FoundName),
    "Required state: 7 (Enable all - audit)",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Windows Settings",
    "     - Security Settings",
    "       - Local Policies",
    "         - Security Options",
    "           - Network security: Restrict NTLM: Audit NTLM authentication in this domain",
    "             Enable all (audit)",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

# --------------------------------------------------------------------------------------------------
# STEP 3 (informational only)
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 3 - Enforce NTLMv2 and deny LM (END GOAL - informational only)"

$lmVal        = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
$lmConfigured = $(if ($null -ne $lmVal) { 'Yes' } else { 'No' })
$lmExpected   = 5

$lmOk = $false
if ($null -ne $lmVal) { try { $lmOk = ([int]$lmVal -eq $lmExpected) } catch { $lmOk = $false } }

$lmMeaning = $(if ($null -ne $lmVal) { try { Get-LmCompatMeaning -Value ([int]$lmVal) } catch { '' } } else { '' })

$step3Rows = @(
  [pscustomobject]@{
    Setting='LAN Manager authentication level (LmCompatibilityLevel)'
    Configured=$lmConfigured
    Value=$lmVal
    Expected=$lmExpected
    Compliant=$(if ($lmOk) { 'Yes' } else { 'No' })
    Meaning=$lmMeaning
    Notes='Target is Value 5 (NTLMv2 only; refuse LM and NTLMv1). Do not change blindly.'
  }
)

$plain3 = Write-ColorTable -Rows $step3Rows -Columns @('Setting','Configured','Value','Expected','Compliant','Meaning','Notes') -Widths @{
  Setting=54; Configured=10; Value=8; Expected=8; Compliant=10; Meaning=34; Notes=80
}
Add-TextFile $plain3

# --------------------------------------------------------------------------------------------------
# STEP 4
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 4 - Advanced Audit Policy (auditpol + force override)"

$credState  = Get-AuditPolSubcategoryState -Subcategory 'Credential Validation'
$logonState = Get-AuditPolSubcategoryState -Subcategory 'Logon'

$credOk  = ($credState  -eq 'Success and Failure')
$logonOk = ($logonState -eq 'Success and Failure')

$forceVal        = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy'
$forceConfigured = $(if ($null -ne $forceVal) { 'Yes' } else { 'No' })
$forceOk         = ($forceVal -eq 1)

$step4Rows = @(
  [pscustomobject]@{
    Setting='Audit Credential Validation (4776)'
    Configured='Yes'
    Value=$credState
    Expected='Success and Failure'
    Compliant=$(if ($credOk) { 'Yes' } else { 'No' })
    Notes='Required for Event 4776 (NTLM confirmation).'
  }
  [pscustomobject]@{
    Setting='Audit Logon (4624)'
    Configured='Yes'
    Value=$logonState
    Expected='Success and Failure'
    Compliant=$(if ($logonOk) { 'Yes' } else { 'No' })
    Notes='Helps confirm NTLM logons via 4624 (NtlmSsp).'
  }
  [pscustomobject]@{
    Setting='Audit: Force subcategory override (SCENoApplyLegacyAuditPolicy)'
    Configured=$forceConfigured
    Value=$(if ($null -eq $forceVal) { 'Not Set' } else { $forceVal })
    Expected='1'
    Compliant=$(if ($forceOk) { 'Yes' } else { 'No' })
    Notes='Ensures Advanced Audit subcategories apply.'
  }
)

$plain4 = Write-ColorTable -Rows $step4Rows -Columns @('Setting','Configured','Value','Expected','Compliant','Notes') -Widths @{
  Setting=62; Configured=10; Value=22; Expected=20; Compliant=10; Notes=70
}
Add-TextFile $plain4

if (-not $credOk) {
  $cur = $(if ([string]::IsNullOrWhiteSpace($credState)) { 'Unknown (auditpol did not return a row)' } else { $credState })
  Add-RemediationItem -Step 'STEP 4' -Title 'Advanced Audit: Credential Validation (4776)' -Lines @(
    ("Current state: {0}" -f $cur),
    "Required state: Success and Failure",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Windows Settings",
    "     - Security Settings",
    "       - Advanced Audit Policy Configuration",
    "         - Audit Policies",
    "           - Account Logon",
    "             - Audit Credential Validation",
    "               Success and Failure",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

if (-not $logonOk) {
  $cur = $(if ([string]::IsNullOrWhiteSpace($logonState)) { 'Unknown (auditpol did not return a row)' } else { $logonState })
  Add-RemediationItem -Step 'STEP 4' -Title 'Advanced Audit: Audit Logon (4624)' -Lines @(
    ("Current state: {0}" -f $cur),
    "Required state: Success and Failure",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Windows Settings",
    "     - Security Settings",
    "       - Advanced Audit Policy Configuration",
    "         - Audit Policies",
    "           - Logon/Logoff",
    "             - Audit Logon",
    "               Success and Failure",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

if (-not $forceOk) {
  $cur = $(if ($null -eq $forceVal) { 'Not Set (value missing)' } else { [string]$forceVal })
  Add-RemediationItem -Step 'STEP 4' -Title 'Force subcategory override (SCENoApplyLegacyAuditPolicy)' -Lines @(
    ("Current state: {0}" -f $cur),
    "Required state: 1 (Enabled)",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Windows Settings",
    "     - Security Settings",
    "       - Local Policies",
    "         - Security Options",
    "           - Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings",
    "             Enabled",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

# --------------------------------------------------------------------------------------------------
# STEP 5
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 5 - Event log channel health (wevtutil)"

$sec  = Get-WevtutilChannel -ChannelName 'Security'
$ntlm = Get-WevtutilChannel -ChannelName 'Microsoft-Windows-NTLM/Operational'

$secEnabled  = ($sec.enabled  -match 'true')
$ntlmEnabled = ($ntlm.enabled -match 'true')

$secExpectedBytes  = 1GB
$secExpectedKB     = 1048576

# NTLM/Operational minimum = 200MB
$ntlmExpectedBytes = 200MB
$ntlmExpectedKB    = 204800

$secMax  = $(if ($sec.ContainsKey('maxSize'))  { [int64]$sec.maxSize }  else { 0 })
$ntlmMax = $(if ($ntlm.ContainsKey('maxSize')) { [int64]$ntlm.maxSize } else { 0 })

$secSizeOk   = ($secMax  -ge $secExpectedBytes)
$ntlmSizeOk  = ($ntlmMax -ge $ntlmExpectedBytes)

# Policy fallback: Security
$secPolicy = $null
$secPolicyOk = $false
if (-not $secSizeOk) {
  $secPolicy = Get-PolicySecurityMaxSizeKB
  if ($secPolicy.Configured -eq 'Yes' -and $null -ne $secPolicy.MaxSizeKB) {
    $secPolicyOk = ($secPolicy.MaxSizeKB -ge $secExpectedKB)
  }
}
$secSizeFinalOk = ($secSizeOk -or $secPolicyOk)

$secSizeNotes = ("Raw bytes: {0}" -f $secMax)
if (-not $secSizeOk -and $secPolicyOk) {
  $secSizeNotes = ("Raw bytes: {0}. Policy MaxSize is set to {1} KB at {2}. A reboot or Event Log service reload may be required before wevtutil reflects the new size. Verify: reg query ""HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"" /v MaxSize" -f $secMax, $secPolicy.MaxSizeKB, $secPolicy.RegPath)
}

# Policy fallback: NTLM/Operational
$ntlmPolicy = $null
$ntlmPolicyOk = $false
if (-not $ntlmSizeOk) {
  $ntlmPolicy = Get-PolicyNtlmOperationalMaxSizeKB
  if ($ntlmPolicy.Configured -eq 'Yes' -and $null -ne $ntlmPolicy.MaxSizeKB) {
    $ntlmPolicyOk = ($ntlmPolicy.MaxSizeKB -ge $ntlmExpectedKB)
  }
}
$ntlmSizeFinalOk = ($ntlmSizeOk -or $ntlmPolicyOk)

$ntlmSizeNotes = ("Raw bytes: {0}" -f $ntlmMax)
if (-not $ntlmSizeOk -and $ntlmPolicyOk) {
  $ntlmSizeNotes = ("Raw bytes: {0}. Policy MaxSize is set to {1} KB at {2}. A reboot or Event Log service reload may be required before wevtutil reflects the new size. Verify: reg query ""HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-NTLM/Operational"" /v MaxSize" -f $ntlmMax, $ntlmPolicy.MaxSizeKB, $ntlmPolicy.RegPath)
}

$step5Rows = @(
  [pscustomobject]@{
    Setting='Security log enabled'
    Configured='Yes'
    Value=$sec.enabled
    Expected='true'
    Compliant=$(if ($secEnabled) { 'Yes' } else { 'No' })
    Notes='4776/4624 require Security log.'
  }
  [pscustomobject]@{
    Setting='Security log maxSize'
    Configured='Yes'
    Value=(Format-Bytes $secMax)
    Expected='>= 1 GB recommended on DCs'
    Compliant=$(if ($secSizeFinalOk) { 'Yes' } else { 'No' })
    Notes=$secSizeNotes
  }
  [pscustomobject]@{
    Setting='Security log retention'
    Configured='Yes'
    Value=$sec.retention
    Expected='false (overwrite) or planned retention'
    Compliant='N/A'
    Notes='If too small/strict retention, events may roll quickly.'
  }
  [pscustomobject]@{
    Setting='Security log autoBackup'
    Configured='Yes'
    Value=$sec.autoBackup
    Expected='Any'
    Compliant='N/A'
    Notes='If enabled, may create .evtx backups when full.'
  }
  [pscustomobject]@{
    Setting='NTLM/Operational enabled'
    Configured='Yes'
    Value=$ntlm.enabled
    Expected='true'
    Compliant=$(if ($ntlmEnabled) { 'Yes' } else { 'No' })
    Notes='Required for 8004/8005.'
  }
  [pscustomobject]@{
    Setting='NTLM/Operational maxSize'
    Configured='Yes'
    Value=(Format-Bytes $ntlmMax)
    Expected='>= 200 MB recommended'
    Compliant=$(if ($ntlmSizeFinalOk) { 'Yes' } else { 'No' })
    Notes=$ntlmSizeNotes
  }
)

$plain5 = Write-ColorTable -Rows $step5Rows -Columns @('Setting','Configured','Value','Expected','Compliant','Notes') -Widths @{
  Setting=28; Configured=10; Value=14; Expected=32; Compliant=10; Notes=60
}
Add-TextFile $plain5

# Explicit notes if policy is ok but runtime still old
if (-not $secSizeOk -and $secPolicyOk) {
  Write-Host ""
  Write-Host "NOTE: Security log size policy is configured, but wevtutil maxSize may not update until after a reboot or Event Log service reload." -ForegroundColor Yellow
  Add-TextFile "NOTE: Security log size policy is configured, but wevtutil maxSize may not update until after a reboot or Event Log service reload."
}

if (-not $ntlmSizeOk -and $ntlmPolicyOk) {
  Write-Host ""
  Write-Host "NOTE: NTLM/Operational log size policy is configured, but wevtutil maxSize may not update until after a reboot or Event Log service reload." -ForegroundColor Yellow
  Add-TextFile "NOTE: NTLM/Operational log size policy is configured, but wevtutil maxSize may not update until after a reboot or Event Log service reload."
}

if (-not $secEnabled) {
  Add-RemediationItem -Step 'STEP 5' -Title 'Enable Security event log' -Lines @(
    ("Current state: enabled = {0}" -f $sec.enabled),
    "Required state: enabled = true",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Administrative Templates",
    "     - Windows Components",
    "       - Event Log Service",
    "         - Security",
    "           - Enable logging",
    "             Enabled",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

# Remediation only if both runtime and policy are not ok
if (-not $secSizeFinalOk) {
  $cur = ("{0} (raw bytes: {1})" -f (Format-Bytes $secMax), $secMax)
  Add-RemediationItem -Step 'STEP 5' -Title 'Increase Security log max size' -Lines @(
    ("Current state (runtime): {0}" -f $cur),
    ("Policy state: {0}" -f $(if ($secPolicy -and $secPolicy.Configured -eq 'Yes') { "MaxSize=" + $secPolicy.MaxSizeKB + " KB at " + $secPolicy.RegPath } else { "Not Set (policy value missing)" })),
    "Required state: >= 1 GB recommended on DCs",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Administrative Templates",
    "     - Windows Components",
    "       - Event Log Service",
    "         - Security",
    "           - Specify the maximum log file size (KB)",
    "             Set to: 1048576 KB (1 GB) or higher",
    "",
    "Note: A reboot or Event Log service reload may be required before wevtutil reflects the new size.",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

if (-not $ntlmEnabled) {
  Add-RemediationItem -Step 'STEP 5' -Title 'Enable Microsoft-Windows-NTLM/Operational log' -Lines @(
    ("Current state: enabled = {0}" -f $ntlm.enabled),
    "Required state: enabled = true",
    "",
    "Apply via GPO:",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Policies",
    "   - Administrative Templates",
    "     - Windows Components",
    "       - Event Log Service",
    "         - Microsoft-Windows-NTLM/Operational",
    "           - Enable logging",
    "             Enabled",
    "",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

# Remediation only if both runtime and policy are not ok
if (-not $ntlmSizeFinalOk) {
  $cur = ("{0} (raw bytes: {1})" -f (Format-Bytes $ntlmMax), $ntlmMax)
  Add-RemediationItem -Step 'STEP 5' -Title 'Increase NTLM/Operational log max size' -Lines @(
    ("Current state (runtime): {0}" -f $cur),
    ("Policy state: {0}" -f $(if ($ntlmPolicy -and $ntlmPolicy.Configured -eq 'Yes') { "MaxSize=" + $ntlmPolicy.MaxSizeKB + " KB at " + $ntlmPolicy.RegPath } else { "Not Set (policy value missing)" })),
    "Required state: >= 200 MB recommended",
    "",
    "Apply via GPO (recommended method): GPP Registry (policy path)",
    "Placement: Domain Controllers OU",
    "GPO: Default Domain Controllers Policy (edit existing; do not create a new GPO)",
    "",
    "Computer Configuration",
    " - Preferences",
    "   - Windows Settings",
    "     - Registry",
    "       - New -> Registry Item (Update)",
    "",
    "Hive: HKEY_LOCAL_MACHINE",
    "Key Path: SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-NTLM/Operational",
    "Value name: MaxSize",
    "Value type: REG_DWORD",
    "Value data: 204800 (Decimal) (KB = 200 MB)",
    "",
    "Verify policy is present:",
    "  reg query ""HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Microsoft-Windows-NTLM/Operational"" /v MaxSize",
    "",
    "Important: A reboot or Event Log service reload may be required before wevtutil reflects the new size.",
    "Note: If another GPO defines this differently, ensure this GPO has higher precedence (link order) so it wins."
  )
}

# --------------------------------------------------------------------------------------------------
# STEP 6 - Export results (CSV + paths) + remediation TXT (only if needed)
# --------------------------------------------------------------------------------------------------
Write-Section "STEP 6 - Export results (CSV + paths)"

try {
  $csvAll = New-Object System.Collections.Generic.List[object]
  foreach ($r in $step2Rows) { $csvAll.Add([pscustomobject]@{ Section='Step2'; Setting=$r.Setting; Value=$r.Value; Expected=$r.Expected; Compliant=$r.Compliant; Notes=$r.Notes }) | Out-Null }
  foreach ($r in $step3Rows) { $csvAll.Add([pscustomobject]@{ Section='Step3'; Setting=$r.Setting; Value=$r.Value; Expected=$r.Expected; Compliant=$r.Compliant; Notes=$r.Notes }) | Out-Null }
  foreach ($r in $step4Rows) { $csvAll.Add([pscustomobject]@{ Section='Step4'; Setting=$r.Setting; Value=$r.Value; Expected=$r.Expected; Compliant=$r.Compliant; Notes=$r.Notes }) | Out-Null }
  foreach ($r in $step5Rows) { $csvAll.Add([pscustomobject]@{ Section='Step5'; Setting=$r.Setting; Value=$r.Value; Expected=$r.Expected; Compliant=$r.Compliant; Notes=$r.Notes }) | Out-Null }

  $csvAll | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
  Write-Host "CSV exported."
  Add-TextFile ("CSV exported: {0}" -f $csvPath)
} catch {
  $errMsg = $_.Exception.Message
  Write-Host "WARNING: Failed to export CSV."
  Write-Host ("Details: {0}" -f $errMsg)
  Add-TextFile ("WARNING: Failed to export CSV. Details: {0}" -f $errMsg)
}

# Write remediation TXT ONLY if there are failing items anywhere
if ($script:Remediation.Count -gt 0) {
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add(("S-OldNTLM - Remediation guidance (generated: {0})" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))) | Out-Null
  $lines.Add("") | Out-Null
  $lines.Add("Only non-compliant findings are included below.") | Out-Null
  $lines.Add("") | Out-Null

  $grouped = $script:Remediation | Group-Object Step
  foreach ($g in $grouped) {
    $lines.Add(("=" * 92)) | Out-Null
    $lines.Add($g.Name) | Out-Null
    $lines.Add(("=" * 92)) | Out-Null
    $lines.Add("") | Out-Null

    foreach ($item in $g.Group) {
      $lines.Add($item.Title) | Out-Null
      $lines.Add(('-' * 60)) | Out-Null
      foreach ($l in $item.Lines) { $lines.Add([string]$l) | Out-Null }
      $lines.Add("") | Out-Null
    }
  }

  # One-time reminder at end
  $lines.Add(("=" * 92)) | Out-Null
  $lines.Add("Post-change action (run once)") | Out-Null
  $lines.Add(("=" * 92)) | Out-Null
  $lines.Add("") | Out-Null
  $lines.Add("After implementing the GPO changes and allowing replication, run on each DC:") | Out-Null
  $lines.Add("  gpupdate /force") | Out-Null
  $lines.Add("") | Out-Null

  $lines | Out-File -FilePath $remediationPath -Encoding UTF8 -Force

  Write-Host ""
  Write-Host "Remediation guidance written to:" -ForegroundColor Yellow
  Write-Host ("  {0}" -f $remediationPath)
  Add-TextFile ("Remediation guidance: {0}" -f $remediationPath)

  Write-Host ""
  Write-Host "After implementing the GPO changes, run on each DC:" -ForegroundColor Yellow
  Write-Host "  gpupdate /force"
}

$pathsBlock = @()
$pathsBlock += ""
$pathsBlock += "Full paths (not truncated):"
$pathsBlock += ("  Output folder  : {0}" -f $outDir)
$pathsBlock += ("  Transcript     : {0}" -f $transcriptPath)
$pathsBlock += ("  Text report    : {0}" -f $txtPath)
$pathsBlock += ("  CSV report     : {0}" -f $csvPath)
if ($script:Remediation.Count -gt 0) { $pathsBlock += ("  Remediation    : {0}" -f $remediationPath) }
$pathsText = ($pathsBlock -join [Environment]::NewLine)

Write-Host $pathsText
Add-TextFile $pathsText

# --------------------------------------------------------------------------------------------------
# DONE
# --------------------------------------------------------------------------------------------------
Write-Section "DONE"
Write-Host "Completed."
Write-Host ("Output folder: {0}" -f $outDir)

if (-not $NoTranscript) {
  try { Stop-Transcript | Out-Null } catch { }
}
