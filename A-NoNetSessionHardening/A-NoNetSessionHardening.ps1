<#
MODNI 2025-08-19
 Script Purpose
  • Downloads and imports the NetCease module (from PowerShell Gallery) into C:\ITM8
  • Prompts user to choose an action for Net Session Enumeration permissions:
      – View current permissions
      – Harden permissions
      – Restore default permissions
      – Stop script without changes
  • Logs all actions and outputs to C:\ITM8\NetCease-YYYYMMDD-HHMMSS.log
  • Displays table-formatted permission results in console and log
  • Restarts Server (LanmanServer) service after Harden/Restore to apply changes
  • Handles PSGallery/NuGet/TLS bootstrap automatically

 Usage
  • Run in an elevated PowerShell session (Run as Administrator)
  • Follow the on-screen prompt to select desired action [1–4]
  • Review results in console and in the log file created under C:\ITM8
  • No changes are made unless option [2] Harden or [3] Restore is selected
#>


$folder = "C:\ITM8"
$moduleName = "NetCease"

if (-not (Test-Path -Path $folder)) { New-Item -Path $folder -ItemType Directory | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logPath = Join-Path $folder "NetCease-$timestamp.log"

function Write-Log { param($msg)
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  "$ts - $msg" | Tee-Object -FilePath $logPath -Append
}
function Write-RawLog { param($msg) $msg | Out-File -FilePath $logPath -Append -Encoding utf8 }

Write-Log "=== Starting NetCease management ==="

# --- Bootstrap PSGallery/NuGet/TLS safely ---
try {
  # Ensure TLS 1.2 for older hosts
  if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12 -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Write-Log "Enabled TLS 1.2 for PowerShell Gallery connectivity."
  }

  if (-not (Get-PSRepository -ErrorAction SilentlyContinue | Where-Object Name -eq 'PSGallery')) {
    Write-Log "Registering PSGallery..."
    Register-PSRepository -Default -ErrorAction Stop
  }

  if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
    Write-Log "Installing NuGet package provider..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
  }
}
catch {
  Write-Log "ERROR: Package provider / PSGallery bootstrap failed: $_"
  exit 1
}

# --- Locate / Download / Import module ---
try {
  $moduleInfo = Find-Module -Name $moduleName -Repository PSGallery -ErrorAction Stop
  $version = $moduleInfo.Version.ToString()
  $modulePath = Join-Path -Path $folder -ChildPath "$moduleName\$version\$moduleName.psd1"

  if (-not (Test-Path $modulePath)) {
    Write-Log "Module $moduleName v$version not found locally. Downloading to $folder..."
    Save-Module -Name $moduleName -Path $folder -RequiredVersion $version -Force -ErrorAction Stop
  } else {
    Write-Log "Module $moduleName v$version already exists. Skipping download."
  }

  if (Test-Path $modulePath) {
    Write-Log "Importing module from $modulePath..."
    Import-Module $modulePath -Force -Verbose 4>&1 | ForEach-Object { Write-Log "$_" }
  } else {
    Write-Log "ERROR: Module file not found at expected path: $modulePath"
    exit 1
  }
}
catch {
  Write-Log ("ERROR: Could not find/download/import {0}: {1}" -f $moduleName, $_)
  exit 1
}

function Show-CurrentPermissions {
  try {
    $result = Get-NetSessionEnumPermission
    if ($result) {
      $tableString = $result | Format-Table TranslatedSID, SecurityIdentifier, AccessMask, AceType -AutoSize | Out-String
      Write-Host $tableString
      $tableString -split "`n" | ForEach-Object { Write-RawLog $_.TrimEnd() }
    } else {
      Write-Log "No entries returned by Get-NetSessionEnumPermission."
      Write-Host "No permissions found."
    }
  } catch {
    Write-Log "ERROR during Get-NetSessionEnumPermission: $_"
  }
}

function Restart-LanmanServer {
  try {
    Write-Log "Restarting 'Server (LanmanServer)' service to apply changes..."
    Restart-Service -Name LanmanServer -Force -Verbose 4>&1 | ForEach-Object { Write-Log "$_" }
  } catch {
    Write-Log "ERROR restarting LanmanServer: $_"
  }
}

function Prompt-NetSessionEnumAction {
  Write-Host ""
  Write-Host "Choose an action for Net Session Enumeration permissions:"
  Write-Host "[1] View current permissions (Get-NetSessionEnumPermission)"
  Write-Host "[2] Harden (Set-NetSessionEnumPermission)"
  Write-Host "[3] Restore default (Restore-NetSessionEnumPermission)"
  Write-Host "[4] Stop script"
  Write-Host ""

  $choice = Read-Host "Enter your choice [1/2/3/4]"

  switch ($choice) {
    '1' {
      Write-Log "User selected: View current permissions"
      Write-Log "Running Get-NetSessionEnumPermission..."
      Show-CurrentPermissions
    }
    '2' {
      Write-Log "User selected: Harden"
      Write-Log "Running Set-NetSessionEnumPermission..."
      try {
        Set-NetSessionEnumPermission -Confirm:$false -Verbose 4>&1 | ForEach-Object { Write-Log "$_" }
        Restart-LanmanServer
        Write-Log "Post-change: current permissions:"
        Show-CurrentPermissions
      } catch {
        Write-Log "ERROR during Set-NetSessionEnumPermission: $_"
      }
    }
    '3' {
      Write-Log "User selected: Restore to default"
      Write-Log "Running Restore-NetSessionEnumPermission..."
      try {
        Restore-NetSessionEnumPermission -Confirm:$false -Verbose 4>&1 | ForEach-Object { Write-Log "$_" }
        Restart-LanmanServer
        Write-Log "Post-change: current permissions:"
        Show-CurrentPermissions
      } catch {
        Write-Log "ERROR during Restore-NetSessionEnumPermission: $_"
      }
    }
    '4' {
      Write-Log "User chose to stop script."
      Write-Host "Script stopped. No changes were made."
      return
    }
    default {
      Write-Log "Invalid selection. User entered: $choice"
      Write-Warning "Invalid selection. Please run the script again and choose a valid option."
    }
  }
}

Prompt-NetSessionEnumAction
Write-Log "=== Script completed ==="
