<#
MODNI 20250708
PingCastle S‑PrimaryGroup helper   (PowerShell 5.1)
───────────────────────────────────────────────────────────────────────────────
 • Lists all enabled users whose PrimaryGroupID ≠ 513
 • Backs them up to CSV
 • Separate files per run under  C:\ITM8\S-PrimaryGroup
      • *.backup.csv      – snapshot before changes
      • *.transcript.log  – full console (Start‑Transcript)
      • *.actions.log     – only restore / fix operations
 • Menu
      [R]estore from old backup
      [F]ix Primary Group. Remediate now
      [N]o action (default ENTER)
───────────────────────────────────────────────────────────────────────────────
#>

[CmdletBinding()]
param([switch]$ListAll)

Import-Module ActiveDirectory -ErrorAction Stop

#──────── Paths ───────
$root = 'C:\ITM8\S-PrimaryGroup'
if (-not (Test-Path $root)) { New-Item -Path $root -ItemType Directory -Force | Out-Null }

$stamp       = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvBackup   = Join-Path $root "S-PrimaryGroup_backup_${stamp}.csv"
$transcript  = Join-Path $root "S-PrimaryGroup_${stamp}.transcript.log"
$actionLog   = Join-Path $root "S-PrimaryGroup_${stamp}.actions.log"

#──────── Helpers ─────
function Write-ActionLog { param([string]$Msg) Add-Content -Path $actionLog -Value $Msg }

function Ensure-Membership {
    param(
        [string]$GroupDN,
        [string]$UserSam
    )
    $already = Get-ADGroupMember -Identity $GroupDN -Recursive |
               Where-Object { $_.SamAccountName -eq $UserSam }
    if (-not $already) {
        Add-ADGroupMember -Identity $GroupDN -Members $UserSam -ErrorAction Stop
        return $true  # added
    }
    return $false     # already member
}

#──────── Start transcript ─────
Start-Transcript -Path $transcript | Out-Null

try { $domainSid = (Get-ADDomain).DomainSID.Value }
catch { Stop-Transcript; throw "Unable to obtain domain SID. $_" }

$domainUsersDN = (Get-ADGroup -Identity ("$domainSid-513")).DistinguishedName

Write-Host "Checking for hidden group memberships (PingCastle rule S‑PrimaryGroup)..." -ForegroundColor Yellow
Write-Host ("{0,-20} : {1,-25} -> {2}" -f 'User','Primary Group','Status') -ForegroundColor Yellow
Write-Host ("{0,-20} : {1,-25} -> {2}" -f '----','-------------','------')   -ForegroundColor Yellow

$report = @()

Get-ADUser -Filter * -Properties Enabled,PrimaryGroupID,SamAccountName |
Where-Object { $_.Enabled } |
ForEach-Object {
    $u    = $_
    $pgid = $u.PrimaryGroupID
    if (-not $ListAll.IsPresent -and $pgid -eq 513) { return }

    $groupSid = "$domainSid-$pgid"
    $group    = Get-ADGroup -Identity $groupSid -ErrorAction SilentlyContinue
    if (-not $group) {
        Write-Warning "Cannot resolve RID $pgid for $($u.SamAccountName)"
        return
    }

    $explicit = Get-ADPrincipalGroupMembership -Identity $u |
                Where-Object { $_.DistinguishedName -eq $group.DistinguishedName }

    if ($hidden = (-not $explicit)) {
        $stat  = 'HIDDEN'
        $color = 'Red'
    } else {
        $stat  = 'explicit'
        $color = 'DarkGray'
    }

    Write-Host ("{0,-20} : {1,-25} -> {2}" -f $u.SamAccountName,$group.Name,$stat) -ForegroundColor $color

    $report += [PSCustomObject]@{
        SamAccountName  = $u.SamAccountName
        PrimaryGroupDN  = $group.DistinguishedName
        PrimaryGroupRID = $pgid
        Hidden          = $hidden
    }
}

Write-Host "`n'HIDDEN' = user inherits rights via PrimaryGroupID but is NOT listed in the group's member attribute." -ForegroundColor Yellow
Write-Host "'explicit' = user already appears in the group's member list."                                        -ForegroundColor Yellow

if ($report.Count) {
    $report | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvBackup
    Write-Host "`nBackup report saved to $csvBackup" -ForegroundColor Cyan
} else {
    Write-Host "`nNo accounts with PrimaryGroupID <> 513 found." -ForegroundColor Green
    Stop-Transcript; return
}

#──────── Menu ────────
Write-Host ""
Write-Host "[R]estore from old backup"
Write-Host "[F]ix Primary Group. Remediate now"
Write-Host "[N]o action (default - ENTER)"
Write-Host ""
$choice = Read-Host "Select action"
if (-not $choice) { $choice = 'N' }

switch ($choice.ToUpper()) {

    #──── Restore ────────────────────────────────────────────────────────────
    'R' {
        $backups = Get-ChildItem -Path $root -Filter 'S-PrimaryGroup_backup_*.csv' |
                   Sort-Object Name -Descending
        if (-not $backups) { Write-Host "No backup files found." -ForegroundColor Red; break }

        Write-Host "`nAvailable backups:" -ForegroundColor Cyan
        for ($i=0; $i -lt $backups.Count; $i++) { Write-Host "[$i] $($backups[$i].Name)" }

        $sel = Read-Host "Enter number to restore (ENTER = 0 / latest)"
        if (-not $sel) { $sel = 0 }
        if (($sel -as [int]) -ge $backups.Count) { Write-Host "Invalid selection." -ForegroundColor Red; break }

        $csvPath = $backups[$sel].FullName
        Write-Host "Restoring from $csvPath ..." -ForegroundColor Yellow

        Import-Csv $csvPath | ForEach-Object {
            $user      = $_.SamAccountName
            $rid       = [int]$_.PrimaryGroupRID
            $groupDN   = $_.PrimaryGroupDN
            $wasHidden = $_.Hidden -eq 'True'

            try {
                # Ensure membership in target group before changing PGID
                if (Ensure-Membership -GroupDN $groupDN -UserSam $user) {
                    Write-ActionLog "[$(Get-Date)] Added $user to $groupDN (required for restore)"
                }
                Set-ADUser -Identity $user -Replace @{PrimaryGroupID = $rid} -ErrorAction Stop
                Write-ActionLog "[$(Get-Date)] Restored PrimaryGroupID $rid for $user"

                if ($wasHidden) {
                    Remove-ADGroupMember -Identity $groupDN -Members $user -Confirm:$false -ErrorAction Stop
                    Write-ActionLog "[$(Get-Date)] Removed $user from $groupDN (was hidden)"
                }
            }
            catch {
                Write-ActionLog "[$(Get-Date)] ERROR restoring $user : $_"
                Write-Warning   "Restore failed for $user : $_"
            }
        }
        Write-Host "`nRestore complete.`nTranscript : $transcript`nAction log: $actionLog" -ForegroundColor Green
    }

    #──── Fix / Remediate ────────────────────────────────────────────────────
    'F' {
        foreach ($item in $report) {
            try {
                # 1. Make sure user is in Domain Users
                if (Ensure-Membership -GroupDN $domainUsersDN -UserSam $item.SamAccountName) {
                    Write-ActionLog "[$(Get-Date)] Added $($item.SamAccountName) to Domain Users"
                }

                # 2. If hidden, add user to their current primary group first
                if ($item.Hidden) {
                    Add-ADGroupMember -Identity $item.PrimaryGroupDN -Members $item.SamAccountName -ErrorAction Stop
                    Write-ActionLog "[$(Get-Date)] Added $($item.SamAccountName) explicitly to $($item.PrimaryGroupDN)"
                }

                # 3. Switch PrimaryGroupID to 513
                Set-ADUser -Identity $item.SamAccountName -Replace @{PrimaryGroupID = 513} -ErrorAction Stop
                Write-ActionLog "[$(Get-Date)] Set PrimaryGroupID 513 for $($item.SamAccountName)"
            }
            catch {
                Write-ActionLog "[$(Get-Date)] ERROR remediating $($item.SamAccountName) : $_"
                Write-Warning   "Failed on $($item.SamAccountName) : $_"
            }
        }
        Write-Host "`nRemediation complete.`nTranscript : $transcript`nAction log: $actionLog" -ForegroundColor Green
    }

    #──── No action ──────────────────────────────────────────────────────────
    Default { Write-Host "No changes made." -ForegroundColor Green }
}

Stop-Transcript
