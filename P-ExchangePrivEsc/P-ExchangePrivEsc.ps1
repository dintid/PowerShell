<#
.SYNOPSIS
    Detect, back up, fix, or restore the two “Exchange Windows Permissions”
    ACEs on the domain-root DACL (priv-escalation mitigation).

.VERSION
    MODNI 20250702-AutoCheck-PS51-BackupPrefix
    Original Source: https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/Fix-DomainObjectDACL.ps1
.NOTES
    • Auto-checks first; prompts only if vulnerable.
    • “Fix” or “Restore” require Domain Admin rights.
    • Transcript log:      C:\ITM8\P-ExchangePrivEsc
    • All DACL backups:    C:\ITM8\P-ExchangePrivEsc\backup
    Tested on Windows PowerShell 5.1 and PowerShell 7+.
    USE AT YOUR OWN RISK!
#>

#region ----- Initial setup ----------------------------------------------------
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$LogDir    = 'C:\ITM8\P-ExchangePrivEsc'
$BackupDir = Join-Path $LogDir 'backup'

foreach ($dir in @($LogDir, $BackupDir)) {
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

$NowUTC     = [DateTime]::UtcNow
$DateString = $NowUTC.ToString('yyyyMMddTHHmmssZ')

$Transcript = Join-Path $LogDir "ExchangePrivEsc_$DateString.log"
Start-Transcript -Path $Transcript
#endregion

try {
    $DC        = Get-ADDomainController
    $PrimaryDN = $DC.DefaultPartition
    $DomainACL = Get-Acl "ad:$PrimaryDN"

    $FaultyACE = $DomainACL.Access | Where-Object {
        $_.IdentityReference -match '\\Exchange Windows Permissions' -and
        $_.ActiveDirectoryRights -match 'WriteDacl'                  -and
        $_.ObjectType           -match '00000000-0000-0000-0000-000000000000' -and
        $_.PropagationFlags     -eq   'None'
    }
    $FixedACE = $DomainACL.Access | Where-Object {
        $_.IdentityReference -match '\\Exchange Windows Permissions' -and
        $_.ActiveDirectoryRights -match 'WriteDacl'                  -and
        $_.ObjectType           -match '00000000-0000-0000-0000-000000000000' -and
        $_.PropagationFlags     -eq   'InheritOnly'
    }
    $Vulnerable = ($FaultyACE.Count -eq 2)
    $AlreadyFix = ($FixedACE.Count  -eq 2)

    if (-not $Vulnerable) {
        if ($AlreadyFix) { Write-Host "SAFE – ACEs already fixed." }
        else { Write-Host "Status unknown – Expected ACEs not found." }
        return
    }

    # --- UPDATED: Technical warning (ONLY output change; fix logic unchanged) ---
    Write-Warning "VULNERABLE – Unsafe ACEs detected on domain root: $PrimaryDN"
    Write-Host "Faulty ACEs found on the domain-root DACL:`n" -ForegroundColor Yellow

    $FaultyACE |
        Select-Object `
            IdentityReference,
            AccessControlType,
            ActiveDirectoryRights,
            ObjectType,
            InheritanceFlags,
            PropagationFlags,
            IsInherited |
        Format-Table -AutoSize

    Write-Host ""
    Write-Host "Issue:" -ForegroundColor Cyan
    Write-Host "These ACEs are NOT InheritOnly (PropagationFlags=None) and therefore apply directly to the domain root (WriteDACL)." -ForegroundColor Gray
    Write-Host "The fix sets inheritance so the permissions apply only to child objects." -ForegroundColor Gray
    # --- end updated warning ---

    $restoreAvailable = Get-ChildItem -Path $BackupDir -Filter 'backup_domainObjectDACL_*_Fix.txt' -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1

    Write-Host ""
    Write-Host "Choose operation:" -ForegroundColor Cyan
    Write-Host "  [B] Backup only (no changes)"                 -ForegroundColor Gray
    Write-Host "  [F] Fix – set InheritOnly (creates backup)" -ForegroundColor Yellow
    if ($restoreAvailable) {
        Write-Host "  [R] Restore using latest backup"         -ForegroundColor Red
    }
    Write-Host "  [Q] Quit (default)"                          -ForegroundColor Gray
    Write-Host ""

    $choice = Read-Host "Enter your choice"

    if ([string]::IsNullOrWhiteSpace($choice) -or $choice.ToUpper() -eq 'Q') {
        Write-Host "No action taken."
        return
    }

    if ($choice.ToUpper() -eq 'B') {
        $Backup = Join-Path $BackupDir "backup_domainObjectDACL_${DateString}_Manual.txt"
        $DomainACL.Sddl | Out-File $Backup
        Write-Host "Backup saved to: $Backup"
        return
    }

    if ($choice.ToUpper() -eq 'F') {
        $Backup = Join-Path $BackupDir "backup_domainObjectDACL_${DateString}_Fix.txt"
        $DomainACL.Sddl | Out-File $Backup
        Write-Host "Backup saved to: $Backup"

        $inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
        $ace0 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $FaultyACE[0].IdentityReference,$FaultyACE[0].ActiveDirectoryRights,`
                $FaultyACE[0].AccessControlType,$FaultyACE[0].ObjectType,`
                $inherit,$FaultyACE[0].InheritedObjectType
        $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $FaultyACE[1].IdentityReference,$FaultyACE[1].ActiveDirectoryRights,`
                $FaultyACE[1].AccessControlType,$FaultyACE[1].ObjectType,`
                $inherit,$FaultyACE[1].InheritedObjectType

        $DomainACL.RemoveAccessRule($FaultyACE[0])
        $DomainACL.RemoveAccessRule($FaultyACE[1])
        $DomainACL.AddAccessRule($ace0)
        $DomainACL.AddAccessRule($ace1)

        try {
            Set-Acl -AclObject $DomainACL "ad:$PrimaryDN"
            Write-Host "FIX applied successfully." -ForegroundColor Green
        } catch { Write-Error "Failed to apply fix: $_" }
        return
    }

    if ($choice.ToUpper() -eq 'R') {
        if (-not $restoreAvailable) {
            Write-Warning "No backup found – cannot restore."
            return
        }

        $latest = $restoreAvailable.FullName
        Write-Host ""
        Write-Host "Latest backup: $latest"
        $confirm = Read-Host "Type YES to restore from this backup"
        if ($confirm -ne 'YES') {
            Write-Host "Restore aborted."
            return
        }

        $CurrBackup = Join-Path $BackupDir "backup_domainObjectDACL_${DateString}_Restore.txt"
        $DomainACL.Sddl | Out-File $CurrBackup
        Write-Host "Current DACL backed up to: $CurrBackup"

        try {
            $sddl = Get-Content -Path $latest -Raw
            $DomainACL.SetSecurityDescriptorSddlForm($sddl)
            Set-Acl -AclObject $DomainACL "ad:$PrimaryDN"
            Write-Host "Restore completed – domain ACL rolled back." -ForegroundColor Yellow
        } catch { Write-Error "Restore failed: $_" }
        return
    }
}
finally {
    Stop-Transcript
    Write-Host "`nLog saved to: $Transcript"
}
