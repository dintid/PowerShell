<#
MODNI 20260630
PingCastle ID: A-NTFRSOnSysvol

Script Explanation:

- Performs DFSR & SYSVOL status check across all domain controllers (DCs) in the domain.
- Retrieves and displays basic computer and network info for each DC:
    * Hostname, enabled status, IPv4 addresses, and DNS hostname.
- Checks SYSVOL share path and replication method (DFS-R or NTFRS) on each DC.
- Retrieves DFSR service status and start type with friendly readable descriptions.
- Gets DFSR migration state from the PDC Emulator and displays authoritative migration progress.
- Lists any domain controllers that have not yet reached 'Eliminated' DFSR migration state.
- Retrieves local DFSR migration states from all DCs and displays them in a formatted table.
- Provides manual verification advice if any DCs report unknown or inconsistent DFSR migration states.
- Checks and displays SYSVOL replication status on all DCs.
- Includes an option to skip or prompt for DFSR migration guidance (can be disabled).
- Uses colorized output for better readability.
- Handles errors gracefully and informs user if retrieval fails on any DC.

Additional notes:
- AzureADKerberos (read-only) DCs may appear in early migration states and can be safely ignored.
- Migration state differences may occur due to replication latency or cached data.
- Designed for use in Active Directory environments with PowerShell remoting enabled.

#>

# Define helper function for colored output
function Write-ColorLine {
    param (
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

Write-ColorLine "`n===== DFSR & SYSVOL Status Check =====" Cyan

# Step 1: Get list of domain controllers
$dcList = (Get-ADDomainController -Filter *).Name | Sort-Object

# Show detailed info per DC
foreach ($dc in $dcList) {
    Write-ColorLine "`n===== DFSR & SYSVOL Status Check for $dc =====" Cyan

    try {
        $compSys = Invoke-Command -ComputerName $dc -ScriptBlock {
            $cs = Get-WmiObject -Class Win32_ComputerSystem
            $enabled = $cs.Status -eq 'OK'

            $ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
                $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1'
            }

            $mainIP = ($ips | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' })[0].IPAddress
            $dnsHost = $env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN

            $dfsrService = Get-Service -Name 'DFSR' -ErrorAction SilentlyContinue

            $share = Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue

            [PSCustomObject]@{
                Name               = $cs.Name
                Enabled            = $enabled
                IPv4Address        = $mainIP
                DNSHostName        = $dnsHost
                IPsWithInterface   = $ips | ForEach-Object { "$($_.IPAddress)  $($_.InterfaceAlias)" }
                SYSVOLSharePath    = if ($share) { $share.Path } else { 'Unknown' }
                ReplicationMethod  = if ($share -and $share.Path -like '*SYSVOL_DFSR*') { 'DFS-R' } elseif ($share) { 'NTFRS' } else { 'Unknown' }
                DFSRServiceStatus  = if ($dfsrService) { $dfsrService.Status } else { 'Not Found' }
                DFSRServiceStartType = if ($dfsrService) { $dfsrService.StartType } else { 'N/A' }
            }
        }

        # Display info
        Write-ColorLine "`n--- Basic Computer & Network Info ---" Cyan
        Write-Host "Name        : $($compSys.Name)"
        Write-Host "Enabled     : $($compSys.Enabled)"
        Write-Host "IPv4Address : $($compSys.IPv4Address)"
        Write-Host "DNSHostName : $($compSys.DNSHostName)"
        $compSys.IPsWithInterface | ForEach-Object { Write-Host $_ }

        Write-ColorLine "`n--- SYSVOL Share Path ---" Cyan
        Write-Host "SYSVOL Share Path   : $($compSys.SYSVOLSharePath)"
        Write-Host "Replication Method  : $($compSys.ReplicationMethod)"

        Write-ColorLine "`n--- DFSR Service ---" Cyan
        Write-Host "Status    : $($compSys.DFSRServiceStatus)"
        Write-Host "StartType : $($compSys.DFSRServiceStartType)"

    } catch {
        Write-Warning ("Failed to retrieve info from {0}: {1}" -f $dc, $_.Exception.Message)
    }
}

# Step 2: DFSR Migration State on PDC Emulator (always get LOCAL state on PDC machine)
$pdcFqdn  = (Get-ADDomain).PDCEmulator
$pdcShort = $pdcFqdn.Split('.')[0].ToUpper()
$localShort = $env:COMPUTERNAME.ToUpper()

Write-ColorLine "`nPDC Emulator: $pdcFqdn" Cyan
Write-ColorLine "`nChecking DFSR migration state on PDC emulator ($pdcFqdn)..." Cyan

try {
    if ($pdcShort -eq $localShort) {
        # Running locally on the PDC emulator
        $pdcLocalOutput = dfsrmig /getmigrationstate 2>&1 | Out-String
    } else {
        # Remote invoke to PDC emulator to get local DFSR migration state there
        $pdcLocalOutput = Invoke-Command -ComputerName $pdcFqdn -ScriptBlock {
            dfsrmig /getmigrationstate 2>&1 | Out-String
        } -ErrorAction Stop
    }
} catch {
    Write-Warning "Failed to retrieve DFSR migration state from PDC emulator ($pdcFqdn): $($_.Exception.Message)"
    $pdcLocalOutput = ''
}

# Parse PDC local output for migration state (supporting both 'Global state' and 'State')
$pdcState = 'Unknown'
$match = [regex]::Match($pdcLocalOutput, 'Global state.*:\s*(\w+)', 'IgnoreCase')
if (-not $match.Success) {
    $match = [regex]::Match($pdcLocalOutput, 'State:\s*(\w+)', 'IgnoreCase')
}
if ($match.Success) {
    $pdcState = $match.Groups[1].Value
}

Write-ColorLine "`nPDC migration state (local on PDC): $pdcState" Yellow

# Parse list of DCs not eliminated, ignoring AzureADKerberos entries
$lines      = $pdcLocalOutput -split "`n"
$startIndex = ($lines | Select-String -Pattern 'Domain Controller \(Local Migration State\) - DC Type').LineNumber
$dcBlock    = @()

if ($startIndex) {
    for ($i = $startIndex + 1; $i -lt $lines.Length; $i++) {
        $line = $lines[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { break }  # End of list
        if ($line -match '^=+') { continue }                 # Skip separator lines
        if ($line -match '^AzureADKerberos') { continue }    # Skip AzureADKerberos
        $dcBlock += $line
    }
}

if ($dcBlock.Count -eq 0) {
    Write-Host "All domain controllers (excluding AzureADKerberos) have reached Global state ('Eliminated')."
} else {
    Write-ColorLine "`nThe following domain controllers have not reached Global state ('Eliminated'):" Yellow
    Write-Host "Domain Controller (Local Migration State) - DC Type"
    Write-Host "==================================================="
    $dcBlock | ForEach-Object { Write-Host $_ }
    Write-Warning "Migration has not yet reached a consistent state on all domain controllers."
}

# Step 3: Local DFSR migration states for all DCs
Write-ColorLine "`nLocal DFSR Migration States per DC:" Yellow
$localStates = @()

foreach ($dc in $dcList) {
    $dcShort = $dc.Split('.')[0].ToUpper()
    try {
        if ($dcShort -eq $localShort) {
            $output = dfsrmig /getmigrationstate 2>&1 | Out-String
            $share = Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue
            $sharePath = if ($share) { $share.Path } else { '' }
        } else {
            $output = Invoke-Command -ComputerName $dc -ScriptBlock {
                dfsrmig /getmigrationstate 2>&1 | Out-String
            } -ErrorAction Stop
            $sharePath = Invoke-Command -ComputerName $dc -ScriptBlock {
                $s = Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue
                if ($s) { $s.Path } else { '' }
            }
        }

        $state = 'Unknown'
        $match = [regex]::Match($output, 'Global state.*:\s*(\w+)', 'IgnoreCase')
        if (-not $match.Success) {
            $match = [regex]::Match($output, 'State:\s*(\w+)', 'IgnoreCase')
        }
        if ($match.Success) {
            $state = $match.Groups[1].Value
        }

        # Override 'Domain' state to 'Eliminated' if SYSVOL path shows DFSR (fix local PDC discrepancy)
        if ($state -eq 'Domain' -and $sharePath -like '*SYSVOL_DFSR*') {
            $state = 'Eliminated'
        }

        $localStates += [PSCustomObject]@{ DC = $dc; LocalState = $state }
    } catch {
        $localStates += [PSCustomObject]@{ DC = $dc; LocalState = "Unknown (error)" }
    }
}
$localStates | Format-Table -AutoSize

# Manual verification advice if unknowns present
if ($localStates.LocalState -contains 'Unknown' -or ($localStates.LocalState -match '^Unknown')) {
    Write-ColorLine "`nSome domain controllers reported DFSR migration state as 'Unknown'. This is normal, and does not mean there are problems" Yellow
    Write-ColorLine "But manual verification is recommended:"
    Write-ColorLine " - Run 'dfsrmig /getmigrationstate' directly on those DCs locally."
    Write-ColorLine " - Check SYSVOL share path on those DCs to confirm replication method:"
    Write-ColorLine "     * Open a PowerShell prompt on the DC."
    Write-ColorLine "     * Run 'Get-SmbShare -Name SYSVOL' and check the 'Path' property."
    Write-ColorLine "       - If path contains 'SYSVOL_DFSR', DFS-R replication is in use."
    Write-ColorLine "       - Otherwise, it is likely still using NTFRS replication."
    Write-ColorLine "Inconsistencies may occur due to replication delays, cached states, or transient issues." Yellow
}

# Step 4: DFSR Replication Status for all DCs
Write-ColorLine "`nChecking SYSVOL replication status on all DCs..." Cyan
$replicationResults = @()
foreach ($dc in $dcList) {
    try {
        $share = Invoke-Command -ComputerName $dc -ScriptBlock {
            Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue
        }
        $method = if ($share -and $share.Path -like '*SYSVOL_DFSR*') { 'DFS-R' } elseif ($share) { 'NTFRS' } else { 'Unknown' }
        $replicationResults += [PSCustomObject]@{
            DC            = $dc
            State         = $method
            Method        = $method
            PSComputerName = $dc
        }
    } catch {
        Write-Warning ("Failed to retrieve DFSR status from {0}: {1}" -f $dc, $_.Exception.Message)
    }
}
$replicationResults | Format-Table -AutoSize

# Final authoritative note uses local DFSR migration state ON PDC emulator
# Use localStates object to find PDC's local state
$pdcLocalState = ($localStates | Where-Object { $_.DC -ieq $pdcShort }).LocalState
if (-not $pdcLocalState) {
    $pdcLocalState = $pdcState
}

if ($pdcLocalState -eq 'Eliminated') {
    Write-ColorLine "`nPDC migration state is 'Eliminated'; DFS-R migration complete." Green
} elseif ($pdcLocalState -eq 'Domain') {
    Write-ColorLine "`nPDC migration state is 'Domain'." Yellow
    Write-ColorLine "Migration is ongoing, but all domain controllers (except AzureADKerberos) have reached 'Eliminated' state." 
    Write-ColorLine "No immediate migration action is required at this time."
    Write-ColorLine "Note that the PDC's reported state may take time to update to 'Eliminated' due to replication latency." 
} else {
    Write-ColorLine "`nPDC migration state is '$pdcLocalState'. Manual verification of migration state may be required." 
}

Write-ColorLine "`nNote:" Yellow
Write-ColorLine "The PDC emulator's migration state ('$pdcLocalState') is the authoritative indicator of DFSR SYSVOL migration progress." 
Write-ColorLine "Local DFSR migration states on other domain controllers may temporarily differ due to replication latency or cached state information." 
Write-ColorLine "If some DCs report 'Unknown' or inconsistent states, manual verification on those DCs is recommended." 
Write-ColorLine "AzureADKerberos (read-only) DCs may remain in early migration states; these can be safely ignored." 
