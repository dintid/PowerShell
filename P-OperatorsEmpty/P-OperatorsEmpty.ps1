# MODNI 20250624
# Must run as administrator
# Check and prompt to clean protected operator groups (P-OperatorsEmpty fix)
# Logfile in C:\itm8

# Define log folder
$logFolder = "C:\itm8"

# Create folder if not exists
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

# Create logfile with datetime in the filename
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $logFolder "p_operators_empty_$timestamp.log"

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestampLog = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestampLog [$Level] $Message"
}

# Console output function (string param, validate color)
function Show-Message {
    param (
        [string]$Message,
        [string]$Color = $null
    )
    $validColors = @(
        "Black","DarkBlue","DarkGreen","DarkCyan","DarkRed","DarkMagenta",
        "DarkYellow","Gray","DarkGray","Blue","Green","Cyan","Red","Magenta",
        "Yellow","White"
    )
    if ($Color -and ($validColors -contains $Color)) {
        Write-Host $Message -ForegroundColor $Color
    }
    else {
        Write-Host $Message
    }
}

# Protected operator groups to check
$operatorGroups = @(
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators"
)

Show-Message "Checking protected operator groups for non-empty membership..." "Cyan"
Write-Log "Started scan for P-OperatorsEmpty cleanup."

foreach ($groupName in $operatorGroups) {
    try {
        $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue

        if ($members.Count -gt 0) {
            Show-Message "`nGroup '$groupName' has the following members:" "Red"
            foreach ($member in $members) {
                Show-Message "  - $($member.Name) [$($member.SamAccountName)]"  # default color, no param
            }

            $memberList = $members | ForEach-Object { $_.SamAccountName } | Sort-Object
            $memberListString = $memberList -join ', '
            Write-Log "Group '$groupName' has $($members.Count) member(s): $memberListString"

            # Green prompt line for input
            $promptText = "Do you want to remove all members from '$groupName'? (Y/N): "
            Write-Host $promptText -NoNewline -ForegroundColor Green
            $prompt = Read-Host

            if ($prompt -match '^[Yy]$') {
                try {
                    Remove-ADGroupMember -Identity $group -Members $members -Confirm:$false -ErrorAction Stop
                    Show-Message "Removed all members from '$groupName'." "Green"
                    Write-Log "Removed all members from '$groupName'."
                }
                catch {
                    $err = $_.Exception.Message
                    Show-Message "Failed to remove members from '$groupName': $err" "Red"
                    Write-Log "Error removing members from '$groupName': $err" "ERROR"
                }
            }
            else {
                Show-Message "Skipped removing members from '$groupName'." "Gray"
                Write-Log "User skipped removing members from '$groupName'." "INFO"
            }
        }
        else {
            Show-Message "Group '$groupName' is already empty." "Green"
            Write-Log "Group '$groupName' is empty."
        }
    }
    catch {
        $err = $_.Exception.Message
        Show-Message "Error checking group '$groupName': $err" "Red"
        Write-Log "Error checking group '$groupName': $err" "ERROR"
    }
}

Show-Message "`nDone. Review the log file at $logFile" "Cyan"
Write-Log "Completed P-OperatorsEmpty scan."
