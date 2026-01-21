<#
S-SMB-v1_ViewActualSettings.ps1
MODNI 2026-01-14

Purpose (PingCastle Rule: S-SMB-v1)
Read-only, local machine view:
- SMBv1 feature state (SMB1Protocol + Server/Client subfeatures if present)
- SMB server runtime configuration (EnableSMB1Protocol, EnableSMB2Protocol, AuditSmb1Access)
- Verdict: whether SMBv1 is available on THIS machine (DC)

Notes
- Only shows items relevant to S-SMB-v1.
- No SMB signing / GPO parsing (not relevant for S-SMB-v1).
- Logs to C:\ITM\S-SMB-v1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ---- Logging / output folder ----
$OutDir = 'C:\ITM\S-SMB-v1'
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$TranscriptPath = Join-Path $OutDir ("S-SMB-v1_ViewActualSettings_{0}.log" -f $stamp)

try { Start-Transcript -Path $TranscriptPath -ErrorAction Stop | Out-Null } catch { }

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
Write-Host "PingCastle S-SMB-v1 - View Actual Settings (local)" -ForegroundColor Cyan
Write-Host ("Computer: {0}" -f $env:COMPUTERNAME) -ForegroundColor Gray
Write-Host ("Log     : {0}" -f $TranscriptPath) -ForegroundColor Gray

# --- Feature states ---
$smb1Root   = Get-FeatureStateSafe -FeatureName 'SMB1Protocol'
$smb1Server = Get-FeatureStateSafe -FeatureName 'SMB1Protocol-Server'
$smb1Client = Get-FeatureStateSafe -FeatureName 'SMB1Protocol-Client'

$smb1FeatureEnabled =
    (Is-FeatureEnabledState $smb1Root) -or
    (Is-FeatureEnabledState $smb1Server) -or
    (Is-FeatureEnabledState $smb1Client)

# --- Runtime server config ---
$cfg = $null
try { $cfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $cfg = $null }

$enableSmb1 = if ($cfg) { [bool]$cfg.EnableSMB1Protocol } else { $null }
$enableSmb2 = if ($cfg) { [bool]$cfg.EnableSMB2Protocol } else { $null }
$auditSmb1  = if ($cfg) { [bool]$cfg.AuditSmb1Access } else { $null }

# --- Verdict ---
# SMBv1 is "available" if either:
# - Server runtime says EnableSMB1Protocol=True
# - OR feature indicates SMB1 is enabled (root/server/client). (Conservative posture check)
$smb1Available = $false
if ($enableSmb1 -eq $true) { $smb1Available = $true }
if ($smb1FeatureEnabled)   { $smb1Available = $true }

$verdict = if ($smb1Available) { 'FAIL (SMBv1 available)' } else { 'OK (SMBv1 not available)' }

# --- Display (only relevant items) ---
Write-Host ""
Write-Host "SMBv1 posture (local):" -ForegroundColor Yellow
$rows = @(
    [pscustomobject]@{ Item='Feature: SMB1Protocol';        Value=$smb1Root }
    [pscustomobject]@{ Item='Feature: SMB1Protocol-Server'; Value=$smb1Server }
    [pscustomobject]@{ Item='Feature: SMB1Protocol-Client'; Value=$smb1Client }
    [pscustomobject]@{ Item='Server: EnableSMB1Protocol';   Value=$(if($enableSmb1 -eq $null){'Unknown'}else{$enableSmb1}) }
    [pscustomobject]@{ Item='Server: EnableSMB2Protocol';   Value=$(if($enableSmb2 -eq $null){'Unknown'}else{$enableSmb2}) }
    [pscustomobject]@{ Item='Server: AuditSmb1Access';      Value=$(if($auditSmb1 -eq $null){'Unknown'}else{$auditSmb1}) }
    [pscustomobject]@{ Item='PingCastle S-SMB-v1 verdict';  Value=$verdict }
)
$rows | Format-Table -AutoSize

Write-Host ""
Write-Host "Practical next step (if FAIL):" -ForegroundColor Yellow
Write-Host " - Disable/remove SMB1 on this DC, then re-run this script and S-SMB-v1_UsageCurrently to confirm no SMBv1 remains."
Write-Host " - If you want evidence of clients before removal: run S-SMB-v1_UsageCurrently Phase 2 (Get-SmbSession) and verify no Dialect=1.5."

try { Stop-Transcript | Out-Null } catch { }
