# MODNI 20250622
# S-ADRegistrationSchema - Vulnerable Schema Class check

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Remove-PossSuperiorsComputer {
    param (
        [Parameter(Mandatory=$true)][string]$SchemaObjectDN,
        [Parameter(Mandatory=$true)][string[]]$CurrentValues,
        [Parameter(Mandatory=$true)][string]$SchemaMasterDC,
        [switch]$Simulate
    )

    $valueToRemove = $CurrentValues | Where-Object {
        ($_ -ieq "computer") -or ($_ -match "^CN=Computer,")
    }

    if ($Simulate) {
        Write-Host "SIMULATION: Would remove the following from possSuperiors of $SchemaObjectDN" -ForegroundColor Cyan
        foreach ($val in $CurrentValues) {
            if ($valueToRemove -contains $val) {
                Write-Host " - $val  <-- (to be REMOVED)" -ForegroundColor Yellow
            } else {
                Write-Host " - $val"
            }
        }
        $newValues = $CurrentValues | Where-Object { $valueToRemove -notcontains $_ }
        Write-Host "Resulting possSuperiors values after removal:"
        if ($newValues.Count -eq 0) {
            Write-Host " (none)" -ForegroundColor Green
        } else {
            $newValues | ForEach-Object { Write-Host " - $_" }
        }
    } else {
        try {
            Set-ADObject -Identity $SchemaObjectDN -Remove @{possSuperiors = $valueToRemove} -Server $SchemaMasterDC
            Write-Host "✅ Successfully removed 'computer' entries from possSuperiors." -ForegroundColor Green
        } catch {
            Write-Host ("❌ Failed to remove 'computer': {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }
}

function Restore-PossSuperiorsComputer {
    param (
        [Parameter(Mandatory=$true)][string]$SchemaObjectDN,
        [Parameter(Mandatory=$true)][string]$StoredType,
        [Parameter(Mandatory=$true)][string]$SchemaMasterDC
    )

    $valueToAdd = if ($StoredType -eq "DistinguishedName") {
        "CN=Computer,CN=Schema,CN=Configuration," + ((Get-ADRootDSE -Server $SchemaMasterDC).rootDomainNamingContext)
    } else {
        "computer"
    }

    try {
        Set-ADObject -Identity $SchemaObjectDN -Add @{possSuperiors = $valueToAdd} -Server $SchemaMasterDC
        Write-Host "✅ Restored 'computer' to possSuperiors as [$StoredType]" -ForegroundColor Green
    } catch {
        Write-Host ("❌ Failed to restore 'computer': {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
}

# === Main ===

try {
    # Detect Schema Master DC
    $SchemaMasterDC = (Get-ADForest).SchemaMaster
    Write-Host ("Schema Master DC: {0}" -f $SchemaMasterDC) -ForegroundColor Cyan

    # Schema naming context from Schema Master DC
    $schemaDN = (Get-ADRootDSE -Server $SchemaMasterDC).schemaNamingContext
} catch {
    Write-Host ("❌ Failed to get schema naming context from {0}: {1}" -f $SchemaMasterDC, $_.Exception.Message) -ForegroundColor Red
    return
}

try {
    # Read the msExchStorageGroup object from Schema Master DC
    $entry = Get-ADObject -LDAPFilter "(lDAPDisplayName=msExchStorageGroup)" -SearchBase $schemaDN -Properties possSuperiors -Server $SchemaMasterDC
    if (-not $entry) {
        Write-Host "❌ msExchStorageGroup object not found in schema." -ForegroundColor Red
        return
    }
    $schemaObjectDN = $entry.DistinguishedName
    Write-Host ("Found Schema Object: {0}" -f $schemaObjectDN)
    Write-Host "`npossSuperiors:"
} catch {
    Write-Host ("❌ Failed to read msExchStorageGroup from Schema Master DC {0}: {1}" -f $SchemaMasterDC, $_.Exception.Message) -ForegroundColor Red
    return
}

$hasComputer = $false
$computerFormat = $null

foreach ($val in $entry.possSuperiors) {
    try {
        $resolved = Get-ADObject -Identity $val -Server $SchemaMasterDC -ErrorAction Stop
        $name = $resolved.Name
        Write-Host (" - {0} → Resolved as: {1}" -f $val, $name)
        if ($name -ieq "computer") {
            $hasComputer = $true
            $computerFormat = "DistinguishedName"
        }
    } catch {
        if ($val -ieq "computer") {
            $hasComputer = $true
            $computerFormat = "PlainText"
        }
        Write-Host (" - {0} → ❗ Invalid or shorthand entry" -f $val) -ForegroundColor Red
    }
}

Write-Host "`n'computer' in possSuperiors:"
if ($hasComputer) {
    Write-Host "❗ PRESENT (to be fixed)" -ForegroundColor Yellow
} else {
    Write-Host "✅ NOT PRESENT (no action needed)" -ForegroundColor Green
}

# Ensure backup folder exists
$backupDir = "C:\itm8\S-ADRegistrationSchema"
if (-not (Test-Path $backupDir)) {
    try {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        Write-Host ("📁 Created folder: {0}" -f $backupDir) -ForegroundColor Cyan
    } catch {
        Write-Host ("❌ Failed to create folder {0}: {1}" -f $backupDir, $_.Exception.Message) -ForegroundColor Red
        return
    }
}

# Current user info
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserName = $currentUser.Name
$currentUserSam = $currentUserName.Split('\')[-1]

# Get Schema Admins group
try {
    $schemaAdminsGroup = Get-ADGroup -Identity "Schema Admins"
} catch {
    Write-Host ("❌ Could not find 'Schema Admins' group: {0}" -f $_.Exception.Message) -ForegroundColor Red
    return
}

try {
    $members = Get-ADGroupMember -Identity $schemaAdminsGroup -Recursive
    $isMember = $members | Where-Object { $_.SamAccountName -eq $currentUserSam } | ForEach-Object { $true }
} catch {
    Write-Host ("❌ Failed to check membership in Schema Admins: {0}" -f $_.Exception.Message) -ForegroundColor Red
    return
}

$addedSelfToSchemaAdmins = $false

if (-not $isMember) {
    Write-Host "`n❌ You are NOT a member of Schema Admins" -ForegroundColor Red
    $add = Read-Host "Add yourself to Schema Admins? (Y/N)"
    if ($add.ToUpper() -eq "Y") {
        try {
            Add-ADGroupMember -Identity $schemaAdminsGroup -Members $currentUserSam -ErrorAction Stop
            Write-Host "✅ Added to Schema Admins" -ForegroundColor Green
            $isMember = $true
            $addedSelfToSchemaAdmins = $true
        } catch {
            Write-Host ("❌ Failed to add user: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-Host ""
            Write-Host "👉 To add yourself manually to Schema Admins:" -ForegroundColor Yellow
            Write-Host "  1. Open 'Active Directory Users and Computers' (ADUC) with an account that has permission."
            Write-Host "  2. Click 'View' and enable 'Advanced Features'."
            Write-Host "  3. Navigate to the 'Schema Admins' group (usually under Builtin or Users container)."
            Write-Host "  4. Right-click 'Schema Admins' and choose 'Properties'."
            Write-Host "  5. Go to the 'Members' tab and click 'Add...'."
            Write-Host ("  6. Add your user '{0}' to the group and confirm." -f $currentUserSam)
            Write-Host ""
            Write-Host "⚠️ After manual addition, please rerun this script." -ForegroundColor Cyan
            return
        }
    } else {
        Write-Host "Operation canceled — no membership, no fix needed or is not possible"
        return
    }
} else {
    Write-Host "✅ You ARE a member of Schema Admins" -ForegroundColor Green
}

# Find latest backup file, if any
$latestBackup = Get-ChildItem -Path $backupDir -Filter "possSuperiors_computer_format_*.txt" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Show menu choices
Write-Host "`nChoose action:"

if ($hasComputer) {
    Write-Host "  [S] Simulate fix"
    Write-Host "  [R] Remove 'computer'"
}

if ($latestBackup) {
    Write-Host ("  [A] Add 'computer' back from latest backup: {0}" -f $latestBackup.Name)
}

Write-Host "  [N] No action"

$choice = Read-Host "Enter your choice (S/R/A/N)"

# Function to save backup
function Save-Backup {
    param($format)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = Join-Path $backupDir ("possSuperiors_computer_format_{0}.txt" -f $timestamp)
    try {
        Set-Content -Path $backupPath -Value $format -Force
        Write-Host ("🔸 Backup saved to: {0}" -f $backupPath) -ForegroundColor Cyan
        return $backupPath
    } catch {
        Write-Host ("❌ Could not save backup: {0}" -f $_.Exception.Message) -ForegroundColor Red
        return $null
    }
}

$backupPath = $null
$changesMade = $false

switch ($choice.ToUpper()) {
    "S" {
        if (-not $hasComputer) {
            Write-Host "No 'computer' entry found — cannot simulate fix." -ForegroundColor Yellow
            break
        }
        $backupPath = Save-Backup $computerFormat
        Remove-PossSuperiorsComputer -SchemaObjectDN $schemaObjectDN -CurrentValues $entry.possSuperiors -SchemaMasterDC $SchemaMasterDC -Simulate
    }
    "R" {
        if (-not $hasComputer) {
            Write-Host "No 'computer' entry found — nothing to remove." -ForegroundColor Yellow
            break
        }
        $backupPath = Save-Backup $computerFormat
        Remove-PossSuperiorsComputer -SchemaObjectDN $schemaObjectDN -CurrentValues $entry.possSuperiors -SchemaMasterDC $SchemaMasterDC
        $changesMade = $true
    }
    "A" {
        if ($latestBackup) {
            try {
                $storedType = Get-Content $latestBackup.FullName -ErrorAction Stop
                Restore-PossSuperiorsComputer -SchemaObjectDN $schemaObjectDN -StoredType $storedType -SchemaMasterDC $SchemaMasterDC
                $changesMade = $true
            } catch {
                Write-Host ("❌ Failed to read backup file: {0}" -f $_.Exception.Message) -ForegroundColor Red
            }
        } else {
            Write-Host "❌ No backup available to restore from." -ForegroundColor Red
        }
    }
    default {
        Write-Host "No action taken."
    }
}

# Remove current user from Schema Admins at the very end regardless of changes or membership

try {
    Write-Host "`nRemoving your user from Schema Admins group..."
    Remove-ADGroupMember -Identity $schemaAdminsGroup -Members $currentUserSam -Confirm:$false -ErrorAction Stop
    Write-Host ("✅ Successfully removed your user '{0}' from Schema Admins." -f $currentUserSam) -ForegroundColor Green
} catch {
    Write-Host ("❌ Could not remove your user '{0}' from Schema Admins: {1}" -f $currentUserSam, $_.Exception.Message) -ForegroundColor Red
    Write-Host "⚠️ You may need to remove yourself manually via ADUC or ask an administrator to do so."
}

# Summary
if ($hasComputer) {
    Write-Host "`nFormat summary:"
    switch ($computerFormat) {
        "PlainText"         { Write-Host "⚠️ Format was plain text ('computer')" -ForegroundColor Yellow }
        "DistinguishedName" { Write-Host "✅ Format was full DN" -ForegroundColor Green }
        default             { Write-Host "❓ Format could not be determined" -ForegroundColor DarkYellow }
    }
    if ($backupPath) {
        Write-Host ("   ➤ Backup: {0}" -f $backupPath)
    }
}
