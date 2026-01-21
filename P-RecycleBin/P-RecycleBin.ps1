# MODNI 20250624
# PingCastle P-RecycleBin
# Script to verify functional levels and offer to enable AD Recycle Bin

# Define log folder and file
$logFolder = "C:\itm8"
$logFile = Join-Path $logFolder "ad_recyclebin.log"

# Create log folder if it doesn't exist
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

# Logging function (logs timestamp only to file, not screen)
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
}

# Console display function (clean output)
function Show-Message {
    param (
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    $originalColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Message
    $Host.UI.RawUI.ForegroundColor = $originalColor
}

# Map functional level numbers to version names
$levelMap = @{
    0 = "Windows 2000"
    1 = "Windows Server 2003"
    2 = "Windows Server 2008"
    3 = "Windows Server 2008 R2"
    4 = "Windows Server 2012"
    5 = "Windows Server 2012 R2"
    6 = "Windows Server 2016"
    7 = "Windows Server 2019"
    8 = "Windows Server 2022"
}

# Get domain and forest info
$domain = Get-ADDomain
$forest = Get-ADForest
$domainLevel = [int]$domain.DomainMode
$forestLevel = [int]$forest.ForestMode

# Log current levels (to file only)
Write-Log "Domain Functional Level: $($levelMap[$domainLevel]) ($domainLevel)"
Write-Log "Forest Functional Level: $($levelMap[$forestLevel]) ($forestLevel)"

# Check if levels meet minimum requirement (level 5 = 2012 R2)
if ($domainLevel -lt 5 -or $forestLevel -lt 5) {
    Show-Message "AD Recycle Bin requires Domain and Forest functional levels to be at least Windows Server 2012 R2 (level 5)." Yellow
    Show-Message "Current Domain Level: $($levelMap[$domainLevel])"
    Show-Message "Current Forest Level: $($levelMap[$forestLevel])"
    Show-Message "`nPlease raise the functional levels before enabling AD Recycle Bin." Yellow
    Write-Log "Functional level requirement not met. Script terminated." "WARN"
    return
}

Show-Message "Functional levels are sufficient. Continuing..." Green
Write-Log "Functional level requirement met."

# Check AD Recycle Bin status
$recycleBinFeature = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"}
$enabledScopes = $recycleBinFeature.EnabledScopes

if ($enabledScopes) {
    Show-Message "AD Recycle Bin is already enabled." Cyan
    Write-Log "AD Recycle Bin is already enabled."
} else {
    Show-Message "AD Recycle Bin is NOT currently enabled." Yellow
    Write-Log "AD Recycle Bin is not enabled."

    # Prompt user
    $answer = Read-Host "Do you want to enable AD Recycle Bin now? (Y/N)"
    if ($answer -match '^[Yy]$') {
        try {
            Enable-ADOptionalFeature `
                -Identity "Recycle Bin Feature" `
                -Scope ForestOrConfigurationSet `
                -Target $forest.Name `
                -Confirm:$false

            Show-Message "AD Recycle Bin has been successfully enabled." Green
            Write-Log "AD Recycle Bin successfully enabled."
        }
        catch {
            $errorMsg = $_.Exception.Message
            Show-Message "Failed to enable AD Recycle Bin: $errorMsg" Red
            Write-Log "Failed to enable AD Recycle Bin: $errorMsg" "ERROR"
        }
    } else {
        Show-Message "AD Recycle Bin enable operation was canceled by the user." Gray
        Write-Log "User chose not to enable AD Recycle Bin." "INFO"
    }
}
