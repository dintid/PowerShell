<#
MODNI 20250708
PingCastle A-AuditDC

1. **Audit Policy Compliance Check:**

   * The script compares current audit policy settings on domain controllers against Microsoft’s best practice baseline for both **simple** and **advanced** audit categories.
   * It identifies audit categories and subcategories that are missing or misconfigured.
   * It outputs detailed tables listing these missing or incorrect audit policies, including the current and recommended settings.
   * It exports these findings to CSV files for record-keeping or further review.
   * It provides an explanation why current audit policy values might not immediately reflect recent changes (e.g., policy refresh delays, caching, reboot requirements).
   * It suggests using `auditpol /get /category:*` locally on a domain controller to verify effective policy settings directly.

2. **User Prompt to Refresh Group Policy:**

   * After displaying the audit compliance report, the script prompts the user if they want to **run `gpupdate /force` remotely on all domain controllers**.
   * The user can respond with **Y** to proceed or **N** (default) to skip.

3. **Remote gpupdate Execution (if user agrees):**

   * The script retrieves the list of all domain controllers in Active Directory.
   * For each domain controller:

     * It tests if PowerShell Remoting (WinRM) is available.
     * If available, it runs `gpupdate /force` remotely on the domain controller.
     * Logs success messages and gpupdate output to a timestamped log file under `C:\ITM8\gpupdate`.
     * If remoting is unavailable or running gpupdate fails, it logs and displays the error but continues with other DCs.
   * After processing all DCs, it informs the user where the log file is saved.

---

This script helps **audit your domain controllers’ security event policy compliance** and offers an **automated way to refresh group policy across all DCs**, with detailed logging and error handling.
#>

# ----------- Audit Settings Compliance Section -----------

# Define Microsoft best practice correct settings for simple audit categories
$bestPracticeSettings = @{
    "Account Logon"      = "Success and Failure"
    "Account Management" = "Success and Failure"
    "DS Access"          = "Success and Failure"
    "Logon/Logoff"       = "Success and Failure"
    "Object Access"      = "Success and Failure"
    "Policy Change"      = "Success and Failure"
    "Privilege Use"      = "Success and Failure"
    "System"             = "Success and Failure"
}

# Define Microsoft best practice correct settings for advanced audit subcategories
# Key format: "Category|Subcategory"
$bestPracticeAdvancedSettings = @{
    "Account Logon|Credential Validation"              = "Success and Failure"
    "Account Logon|Kerberos Service Ticket Operations" = "Success and Failure"
    "Account Management|User Account Management"       = "Success and Failure"
    "DS Access|Directory Service Changes"              = "Success and Failure"
    "DS Access|Directory Service Replication"          = "Success and Failure"
    "Logon/Logoff|Logon"                                = "Success and Failure"
    "Logon/Logoff|Logoff"                               = "Success and Failure"
    "Object Access|File System"                          = "Success and Failure"
    "Policy Change|Audit Policy Change"                 = "Success and Failure"
    "Privilege Use|Sensitive Privilege Use"             = "Success and Failure"
    "System|Security System Extension"                   = "Success and Failure"
    "Detailed Tracking|Process Creation"                 = "Success and Failure"
}

# Mapping for display names of simple categories with "Audit " prefix
$categoryDisplayNamesSimple = @{
    "Account Logon"      = "Audit Account Logon Events"
    "DS Access"          = "Audit Directory Service Access"
    "System"             = "Audit System Events"
    "Logon/Logoff"       = "Audit Logon Events"
    "Account Management" = "Audit Account Management"
    "Object Access"      = "Audit Object Access"
    "Policy Change"      = "Audit Policy Change"
    "Privilege Use"      = "Audit Privilege Use"
}

# Mapping for display names of advanced categories
$categoryDisplayNamesAdvanced = @{
    "Account Logon"      = "Account Logon"
    "Account Management" = "Account Management"
    "DS Access"          = "DS Access"
    "Logon/Logoff"       = "Logon/Logoff"
    "Object Access"      = "Object Access"
    "Policy Change"      = "Policy Change"
    "Privilege Use"      = "Privilege Use"
    "System"             = "System"
    "Detailed Tracking"  = "Detailed Tracking"
}

# Aggregate unique missing simple categories with current settings
$uniqueMissingSimple = $MissingSimpleResults | 
    Select-Object Category, 
                  @{Name='CurrentSetting';Expression={ if ([string]::IsNullOrEmpty($_.CurrentSetting)) { "Not defined or set" } else { $_.CurrentSetting } }},
                  @{Name='CorrectSetting';Expression={ 
                      if ($bestPracticeSettings.ContainsKey($_.Category)) { $bestPracticeSettings[$_.Category] } 
                      else { "Success and Failure" }
                  }} |
    Sort-Object Category -Unique

# Aggregate unique missing advanced subcategories with current and correct settings
$uniqueMissingAdvanced = $MissingAdvancedResults | 
    Select-Object Category, Subcategory,
                  @{Name='CurrentSetting';Expression={ if ([string]::IsNullOrEmpty($_.CurrentSetting)) { "Not defined or set" } else { $_.CurrentSetting } }},
                  @{Name='CorrectSetting';Expression={
                      $key = "$($_.Category)|$($_.Subcategory)"
                      if ($bestPracticeAdvancedSettings.ContainsKey($key)) { $bestPracticeAdvancedSettings[$key] }
                      else { "Success and Failure" }
                  }} |
    Sort-Object Category, Subcategory -Unique

Write-Host "`n================= GPO AUDIT SETTINGS STILL NOT DEFINED =================`n"

if ($uniqueMissingSimple.Count) {
    Write-Host "Missing or misconfigured SIMPLE audit categories:`n"
    Write-Host "  (Find these settings under: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy)`n"

    # Print simple audit table header with wider Category column
    $headerFormatSimple = "{0,-35} {1,-30} {2,-25}"
    Write-Host ($headerFormatSimple -f "Category", "Current Setting", "Correct Setting") -ForegroundColor Yellow
    Write-Host ($headerFormatSimple -f "--------", "---------------", "---------------") -ForegroundColor Yellow

    # Print each simple category row with display name mapping
    foreach ($item in $uniqueMissingSimple) {
        $displayName = if ($categoryDisplayNamesSimple.ContainsKey($item.Category)) { $categoryDisplayNamesSimple[$item.Category] } else { $item.Category }
        Write-Host ($headerFormatSimple -f $displayName, $item.CurrentSetting, $item.CorrectSetting)
    }
    Write-Host ""
}
else {
    Write-Host "All SIMPLE audit categories are already compliant.`n"
}

if ($uniqueMissingAdvanced.Count) {
    Write-Host "--- ADVANCED audit sub‑categories NOT SET CORRECTLY ---`n"
    Write-Host "  (Find these settings under: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies)`n"

    # Print advanced audit table header
    $headerFormatAdvanced = "{0,-25} {1,-35} {2,-25} {3,-25}"
    Write-Host ($headerFormatAdvanced -f "Category", "Subcategory", "Current Setting", "Correct Setting") -ForegroundColor Yellow
    Write-Host ($headerFormatAdvanced -f "--------", "-----------", "---------------", "---------------") -ForegroundColor Yellow

    # Print each advanced audit row with display name mapping for category
    foreach ($item in $uniqueMissingAdvanced) {
        $displayName = if ($categoryDisplayNamesAdvanced.ContainsKey($item.Category)) { $categoryDisplayNamesAdvanced[$item.Category] } else { $item.Category }
        Write-Host ($headerFormatAdvanced -f $displayName, $item.Subcategory, $item.CurrentSetting, $item.CorrectSetting)
    }
    Write-Host ""
}
else {
    Write-Host "All ADVANCED audit subcategories are already compliant.`n"
}

# Export the unique lists to CSV files
if ($uniqueMissingSimple.Count) {
    $uniqueMissingSimple | 
        Export-Csv -Path $MissingSimpleCSV -NoTypeInformation -Encoding UTF8
    Write-Host "Simple list saved to $MissingSimpleCSV"
}

if ($uniqueMissingAdvanced.Count) {
    $uniqueMissingAdvanced | Export-Csv -Path $MissingAdvancedCSV -NoTypeInformation -Encoding UTF8
    Write-Host "Advanced list saved to $MissingAdvancedCSV"
}

# Show explanation to user about why current settings might not immediately show changes
Write-Host "`n--- NOTE ---`n" -ForegroundColor Yellow
Write-Host "The 'Current Setting' values shown above represent the audit policy as retrieved live from each Domain Controller at runtime."
Write-Host "If you have recently applied new Group Policy settings and run 'gpupdate', these current settings might still show as 'Not defined or set' or outdated."
Write-Host "This can happen because:"
Write-Host " - Audit policy changes sometimes require a reboot or a security policy refresh on the DC to take effect."
Write-Host " - There can be delays due to replication, caching, or policy refresh intervals."
Write-Host " - The script queries the effective policy on each DC, which might lag behind recent changes."
Write-Host ""
Write-Host "To verify the actual current audit policy directly on a Domain Controller, run the following command locally on that DC:" -ForegroundColor Yellow
Write-Host ""
Write-Host "    auditpol /get /category:*" -ForegroundColor Cyan
Write-Host ""
Write-Host "This will display the effective audit policy for all categories and subcategories, allowing you to confirm whether the DC has applied the new settings correctly."
Write-Host ""

# ----------- Prompt to Run gpupdate /force on all DCs -----------

# Ask user
$runGpupdate = Read-Host "Run 'gpupdate /force' on all domain controllers now? (Y/N)"

if ($runGpupdate -match '^(Y|y)$') {

    Import-Module ActiveDirectory

    # Prepare log folder and file
    $logDir = "C:\ITM8\gpupdate"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    $logFile = Join-Path $logDir ("gpupdate_log_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")

    # Get all Domain Controllers
    $domainControllers = Get-ADDomainController -Filter *

    foreach ($dc in $domainControllers) {
        $dcName = $dc.Name

        Write-Host "`nProcessing domain controller: $dcName" -ForegroundColor Cyan
        Add-Content -Path $logFile -Value ("`nProcessing domain controller: " + $dcName)

        # Test PowerShell remoting availability
        try {
            $session = New-PSSession -ComputerName $dcName -ErrorAction Stop
            Remove-PSSession $session
            $msg = "PowerShell remoting is available on " + $dcName + "."
            Write-Host $msg -ForegroundColor Green
            Add-Content -Path $logFile -Value $msg
        }
        catch {
            $errorText = $_.ToString()
            $msg = "PowerShell remoting not available on " + $dcName + ": " + $errorText
            Write-Host $msg -ForegroundColor Yellow
            Add-Content -Path $logFile -Value $msg
            continue
        }

        # Run gpupdate /force remotely
        try {
            $invokeResult = Invoke-Command -ComputerName $dcName -ScriptBlock { gpupdate /force } -ErrorAction Stop
            $msg = "Successfully ran gpupdate /force on " + $dcName + "."
            Write-Host $msg -ForegroundColor Green
            Add-Content -Path $logFile -Value $msg
            if ($invokeResult) {
                $output = $invokeResult | Out-String
                Add-Content -Path $logFile -Value ("gpupdate output on " + $dcName + ":`n" + $output)
            }
        }
        catch {
            $errorText = $_.ToString()
            $errMsg = "Failed to run gpupdate on " + $dcName + ": " + $errorText
            Write-Host $errMsg -ForegroundColor Red
            Add-Content -Path $logFile -Value $errMsg
        }
    }

    Write-Host "`nAll domain controllers processed. Log saved to $logFile" -ForegroundColor Cyan
}
else {
    Write-Host "Skipping gpupdate on domain controllers." -ForegroundColor Yellow
}
