<#
MODNI 20250720

Creates outbound Windows Firewall rules to restrict internet access for common script engines
(wscript.exe, cscript.exe, mshta.exe, conhost.exe, runScriptHelper.exe).

- Allows these programs to communicate only with internal IP ranges (10/8, 172.16/12, 192.168/16).
- Blocks all other outbound internet traffic for these programs.
- Checks if rules exist before creating to avoid duplicates.
- Lists all created rules with details after creation.

NOTE: Any further changes to these firewall rules must be done manually.
#>


# ---------------- 1. Check for and create new Firewall Rules
$executables = @(
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "conhost.exe",
    "runScriptHelper.exe"
)

# Paths to check: System32 and SysWOW64
$basePaths = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64"
)

# Internal IP ranges to allow
$internalRanges = "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"

foreach ($exe in $executables) {
    foreach ($path in $basePaths) {
        $fullPath = Join-Path $path $exe

        if (Test-Path $fullPath) {
            # Rule names with PingCastle prefix
            $allowRuleName = "S-FirewallScript - Allow Internal - $exe ($path)"
            $blockRuleName = "S-FirewallScript - Block Internet - $exe ($path)"

            # Create allow rule for internal access
            if (-not (Get-NetFirewallRule -DisplayName $allowRuleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule `
                    -DisplayName $allowRuleName `
                    -Direction Outbound `
                    -Action Allow `
                    -Program $fullPath `
                    -RemoteAddress $internalRanges `
                    -Profile Domain,Private `
                    -Description "PingCastle S-FirewallScript: Allow internal network access for $exe in $path" `
                    -Enabled True
            }

            # Create block rule for external access (IPv4 only)
            if (-not (Get-NetFirewallRule -DisplayName $blockRuleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule `
                    -DisplayName $blockRuleName `
                    -Direction Outbound `
                    -Action Block `
                    -Program $fullPath `
                    -RemoteAddress "0.0.0.0/0" `
                    -Profile Domain,Private,Public `
                    -Description "PingCastle S-FirewallScript: Block internet access for $exe in $path" `
                    -Enabled True
            }
        }
    }
}


# ---------------- 2. Show Firewall rules with names like S-FirewallScript 
$rules = Get-NetFirewallRule | Where-Object DisplayName -like "S-FirewallScript*"
$appFilters = Get-NetFirewallApplicationFilter | Where-Object InstanceID -in $rules.InstanceID

$results = foreach ($rule in $rules) {
    $appFilter = $appFilters | Where-Object InstanceID -eq $rule.InstanceID
    $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule

    [PSCustomObject]@{
        DisplayName   = $rule.DisplayName
        Program       = if ($appFilter) { $appFilter.Program } else { "<none>" }
        Enabled       = $rule.Enabled
        Direction     = $rule.Direction
        Action        = $rule.Action
        RemoteAddress = $filter.RemoteAddress -join ", "
    }
}

$results | Format-Table -AutoSize
write-host "NOTE: Any further changes to these firewall rules must be done manually." -ForegroundColor yellow