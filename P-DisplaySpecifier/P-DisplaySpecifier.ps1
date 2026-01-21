<#
MODNI 20250701
PingCastle P-DisplaySpecifier

Loads Active Directory module and sets variables for computer name, target file, and DisplaySpecifier DN.

Step 1: Searches all Domain Controllers for the specified script file in common shares.
Step 2: Searches AD for computer objects matching the computer name (partial match).
Step 3: Retrieves the adminContextMenu attribute from the specified DisplaySpecifier object.

Based on findings, prompts you to fix (update path), clear (remove), or skip modifying the adminContextMenu.
Backs up the current value before applying any changes.
Includes Undo function to restore from backup file.

Why it does this:
Ensures DisplaySpecifier scripts point to existing files and servers.
Helps clean up stale or insecure references in AD.
Lets you safely review and fix issues interactively before applying changes.
#>

Import-Module ActiveDirectory

# === Configurable variables ===
$ComputerName = "cc-ad01"
$TargetFile = "user_logon_info.vbs"
$DN = "CN=user-Display,CN=409,CN=DisplaySpecifiers,CN=Configuration,DC=creativcompany,DC=local"
$BackupFolder = "C:\ITM8\P-DisplaySpecifier"
# =============================

# Ensure backup folder exists
if (-not (Test-Path $BackupFolder)) {
    New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
}

function Backup-AdminContextMenu {
    param(
        [string]$valueToBackup
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $BackupFolder "adminContextMenu_backup_$timestamp.txt"
    $valueToBackup | Out-File -FilePath $backupFile -Encoding UTF8
    Write-Host "Backup of current adminContextMenu saved to $backupFile" -ForegroundColor Yellow
    return $backupFile
}

function Undo-AdminContextMenuChange {
    param(
        [string]$DN,
        [string]$BackupFolder
    )
    $backupFiles = Get-ChildItem -Path $BackupFolder -Filter "adminContextMenu_backup_*.txt" | Sort-Object LastWriteTime -Descending
    if ($backupFiles.Count -eq 0) {
        Write-Host "No backup files found in $BackupFolder to restore from." -ForegroundColor Red
        return
    }
    Write-Host "Available backup files:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backupFiles.Count; $i++) {
        Write-Host "[$i] $($backupFiles[$i].Name) (Last modified: $($backupFiles[$i].LastWriteTime))"
    }
    $selection = Read-Host "Enter the number of the backup file to restore (or press Enter to cancel)"
    if ($selection -eq '') {
        Write-Host "Undo cancelled." -ForegroundColor Yellow
        return
    }
    if (-not ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $backupFiles.Count)) {
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }
    $chosenBackupFile = $backupFiles[[int]$selection].FullName
    $backupValue = Get-Content -Path $chosenBackupFile -Raw
    try {
        Set-ADObject -Identity $DN -Replace @{adminContextMenu = $backupValue}
        Write-Host "adminContextMenu restored from backup file '$chosenBackupFile'." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to restore adminContextMenu: $_" -ForegroundColor Red
    }
}

function PromptChoice($message, $choices, $explanations) {
    Write-Host $message -ForegroundColor Cyan
    for ($i = 0; $i -lt $choices.Length; $i++) {
        Write-Host "[$i] $($choices[$i])"
        Write-Host "    -> $($explanations[$i])"
    }
    Write-Host "[Enter] Skip Changes"
    do {
        $input = Read-Host "Enter choice number (or press Enter to skip)"
        if ($input -eq '') {
            return -1  # indicate skip
        }
    } while (-not ($input -match '^\d+$' -and [int]$input -ge 0 -and [int]$input -lt $choices.Length))
    return [int]$input
}

# --- Step 1: Search file on DC shares ---
Write-Host "Step 1: Searching all Domain Controllers for the file '$TargetFile'..." -ForegroundColor Cyan

$domainControllers = Get-ADDomainController -Filter *
$foundFile = $false

foreach ($dc in $domainControllers) {
    Write-Host " Searching on DC: $($dc.Name)" -ForegroundColor Cyan

    $sysvolScriptsPath = "\\$($dc.Name)\SYSVOL\$($dc.Domain)\scripts"
    $pathsToSearch = @("\\$($dc.Name)\NETLOGON", "\\$($dc.Name)\SYSVOL", $sysvolScriptsPath) | Where-Object { Test-Path $_ }

    foreach ($path in $pathsToSearch) {
        try {
            $items = Get-ChildItem -Path $path -Filter $TargetFile -Recurse -ErrorAction SilentlyContinue
            if ($items) {
                foreach ($item in $items) {
                    Write-Host "  Found '$TargetFile' on DC '$($dc.Name)': $($item.FullName)" -ForegroundColor Green
                    $foundFile = $true
                }
            }
        }
        catch {
            # ignore access denied etc.
        }
    }
}

if (-not $foundFile) {
    Write-Host " The file '$TargetFile' was NOT found on any domain controller in the searched shares." -ForegroundColor Yellow
}

# --- Step 2: Search AD computer objects ---
Write-Host "`nStep 2: Searching Active Directory for computer objects with names containing '$ComputerName'..." -ForegroundColor Cyan

$results = Get-ADComputer -Filter "Name -like '*'" -Properties Name, DNSHostName, whenChanged, DistinguishedName |
    Where-Object { $_.Name -like "*$ComputerName*" -or ($_.DNSHostName -and $_.DNSHostName -like "*$ComputerName*") }

if ($results) {
    Write-Host " Found the following computer objects matching '$ComputerName':" -ForegroundColor Green
    $results | Select-Object Name, DNSHostName, whenChanged, DistinguishedName | Format-Table -AutoSize
    $foundComputer = $true
} else {
    Write-Host " No computer objects with names containing '$ComputerName' found in Active Directory." -ForegroundColor Yellow
    $foundComputer = $false
}

# --- Step 3: Check DisplaySpecifier adminContextMenu ---
Write-Host "`nStep 3: Checking DisplaySpecifier object '$DN' for adminContextMenu attribute..." -ForegroundColor Cyan

try {
    $adminContextMenu = Get-ADObject -Identity $DN -Properties adminContextMenu | Select-Object -ExpandProperty adminContextMenu
    if ($adminContextMenu) {
        Write-Host " adminContextMenu value:" -ForegroundColor Green
        Write-Host $adminContextMenu
        $hasAdminContextMenu = $true
    } else {
        Write-Host " adminContextMenu attribute is empty or not set." -ForegroundColor Yellow
        $hasAdminContextMenu = $false
    }
}
catch {
    Write-Host " ERROR: Could not retrieve the object at '$DN'. Check if the DN is correct and you have sufficient permissions." -ForegroundColor Red
    exit 1
}

if (-not $hasAdminContextMenu) {
    Write-Host "`nNo adminContextMenu attribute found, nothing to fix or clear." -ForegroundColor Yellow
    exit 0
}

# --- Extract UNC path from adminContextMenu ---
$uncPath = $null
# Match UNC paths (\\server\share...) possibly containing file name
$matches = [regex]::Matches($adminContextMenu, '\\\\[^\s,]+')

# Find any UNC path containing the target file name (case-insensitive)
$matchingPaths = $matches | Where-Object { $_.Value -like "*$TargetFile*" }
if ($matchingPaths.Count -gt 0) {
    $uncPath = $matchingPaths[0].Value
    Write-Host "`nDetected UNC path in adminContextMenu: $uncPath" -ForegroundColor Green
} else {
    Write-Host "`nNo UNC path containing '$TargetFile' found in adminContextMenu." -ForegroundColor Yellow
}

# --- Verification of script file accessibility on all DCs ---
if ($uncPath) {
    Write-Host " Verifying script file accessibility at $uncPath on all Domain Controllers..." -ForegroundColor Cyan

    foreach ($dc in $domainControllers) {
        # Replace server name in UNC path with current DC name
        $testPath = $uncPath -replace '^\\\\[^\\]+', "\\$($dc.Name)"
        $fileExists = Test-Path $testPath

        if ($fileExists) {
            Write-Host "  File found on $($dc.Name): $testPath" -ForegroundColor Green
        }
        else {
            Write-Host "  File NOT found on $($dc.Name): $testPath" -ForegroundColor Yellow
        }

        # Check NETLOGON and SYSVOL shares accessibility
        $netlogon = "\\$($dc.Name)\NETLOGON"
        $sysvol = "\\$($dc.Name)\SYSVOL"

        $netlogonAccess = Test-Path $netlogon
        $sysvolAccessible = Test-Path $sysvol

        $netlogonMsg = if ($netlogonAccess) { "NETLOGON share accessible" } else { "NETLOGON share NOT accessible" }
        $sysvolMsg = if ($sysvolAccessible) { "SYSVOL share accessible" } else { "SYSVOL share NOT accessible" }

        Write-Host "  $netlogonMsg on $($dc.Name)"
        Write-Host "  $sysvolMsg on $($dc.Name)"
    }
}

# --- Step 4: Prompt user for action ---

# Backup current adminContextMenu before any changes
$backupFilePath = $null
function BackupIfNeeded() {
    if ($backupFilePath -eq $null) {
        $backupFilePath = Backup-AdminContextMenu -valueToBackup $adminContextMenu
    }
}

if ($foundFile -and $foundComputer) {
    $choices = @("Fix adminContextMenu (update path)", "Skip changes")
    $explanations = @(
        "Update the adminContextMenu attribute to point to a new valid script path.",
        "Do not modify the adminContextMenu attribute."
    )
    $choice = PromptChoice "`nBoth file and computer exist. What do you want to do?" $choices $explanations

    if ($choice -eq 0) {
        BackupIfNeeded
        $newPath = Read-Host "Enter the new UNC path for the script (e.g. \\new-dc\netlogon\user_logon_info.vbs)"
        $newValue = "&Show Logon Info,$newPath"
        Set-ADObject -Identity $DN -Replace @{adminContextMenu = $newValue}
        Write-Host "adminContextMenu updated." -ForegroundColor Green
    }
    elseif ($choice -eq -1) {
        Write-Host "No changes made." -ForegroundColor Yellow
    }
}
elseif ($foundFile -or $foundComputer) {
    $choices = @("Clear adminContextMenu", "Fix adminContextMenu (update path)", "Skip changes")
    $explanations = @(
        "Remove the adminContextMenu attribute entirely, cleaning up obsolete references.",
        "Update the adminContextMenu attribute to point to a new valid script path.",
        "Do not modify the adminContextMenu attribute."
    )
    $choice = PromptChoice "`nEither the file or the computer is missing. What do you want to do?" $choices $explanations

    switch ($choice) {
        0 {
            BackupIfNeeded
            Set-ADObject -Identity $DN -Clear adminContextMenu
            Write-Host "adminContextMenu cleared." -ForegroundColor Green
        }
        1 {
            BackupIfNeeded
            $newPath = Read-Host "Enter the new UNC path for the script (e.g. \\new-dc\netlogon\user_logon_info.vbs)"
            $newValue = "&Show Logon Info,$newPath"
            Set-ADObject -Identity $DN -Replace @{adminContextMenu = $newValue}
            Write-Host "adminContextMenu updated." -ForegroundColor Green
        }
        -1 {
            Write-Host "No changes made." -ForegroundColor Yellow
        }
    }
}
else {
    $choices = @("Clear adminContextMenu", "Skip changes")
    $explanations = @(
        "Remove the adminContextMenu attribute entirely, cleaning up obsolete references.",
        "Do not modify the adminContextMenu attribute."
    )
    $choice = PromptChoice "`nBoth the file and computer were NOT found. What do you want to do?" $choices $explanations

    if ($choice -eq 0) {
        BackupIfNeeded
        Set-ADObject -Identity $DN -Clear adminContextMenu
        Write-Host "adminContextMenu cleared." -ForegroundColor Green
    }
    elseif ($choice -eq -1) {
        Write-Host "No changes made." -ForegroundColor Yellow
    }
}

# --- Optional: Ask user if they want to undo from backup ---
$undoChoice = Read-Host "`nDo you want to undo (restore) adminContextMenu from a backup file? (Y/N)"
if ($undoChoice -match '^[Yy]$') {
    Undo-AdminContextMenuChange -DN $DN -BackupFolder $BackupFolder
}

# --- End of Script ---
