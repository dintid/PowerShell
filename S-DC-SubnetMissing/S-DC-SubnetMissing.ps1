<#
MODNI 20260114
S-DC-SubnetMissing - PingCastle (ISE-safe)
- Local-first NIC query for local DC (no WinRM needed to self)
- Remote WinRM query for other DCs
- Verification fallback: DNS, ping, TCP 5985/5986, Test-WSMan
- Short warning line per failed DC
- CurrentSubnetBy is cleaned (no "RemoteUnavailable:" prefix)
- VerifyPorts shows ports to verify (what to check), not their open/closed state
- Adds short "what to do" guidance below output if remote failures exist
#>

[CmdletBinding()]
param()

Add-Type -AssemblyName System.Net

# -----------------------------
# AD Subnets (Sites and Services)
# -----------------------------
$subnetBase = "CN=Subnets,CN=Sites," + (Get-ADRootDSE).configurationNamingContext

$adSubnets = Get-ADObject -Filter * -SearchBase $subnetBase -Properties Name, siteObject |
Where-Object { $_.Name -match '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$' } |
ForEach-Object {
    $split = $_.Name -split '/'
    [PSCustomObject]@{
        Subnet     = $_.Name
        Network    = $split[0]
        MaskLength = [int]$split[1]
        Site       = ($_.siteObject -split ',')[0] -replace '^CN='
    }
}

# -----------------------------
# Helpers
# -----------------------------
function Test-IPInSubnet {
    param (
        [string]$ip,
        [string]$network,
        [int]$maskLength
    )
    try {
        $ipAddr  = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
        $netAddr = [System.Net.IPAddress]::Parse($network).GetAddressBytes()
    } catch {
        return $false
    }

    $bytesToCheck  = [math]::Floor($maskLength / 8)
    $remainingBits = $maskLength % 8

    for ($i = 0; $i -lt $bytesToCheck; $i++) {
        if ($ipAddr[$i] -ne $netAddr[$i]) { return $false }
    }

    if ($remainingBits -gt 0) {
        $mask = 0xFF -shl (8 - $remainingBits)
        if (($ipAddr[$bytesToCheck] -band $mask) -ne ($netAddr[$bytesToCheck] -band $mask)) { return $false }
    }

    return $true
}

function Convert-MaskToCIDR {
    param([string]$mask)
    if (-not $mask) { return 0 }
    $binary = ($mask -split '\.') | ForEach-Object { [Convert]::ToString([int]$_,2).PadLeft(8,'0') }
    $joined = $binary -join ''
    return ($joined.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

function Get-PrimaryIPv4AndMaskLocal {
    try {
        $nic = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" |
               Where-Object { $_.IPAddress -ne $null } |
               Select-Object -First 1

        if ($nic -and $nic.IPAddress -and $nic.IPSubnet) {
            $ipv4 = ($nic.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
            $mask = ($nic.IPSubnet  | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
            if ($ipv4) {
                return [pscustomobject]@{ IPv4=$ipv4; SubnetMask=$mask }
            }
        }
    } catch { }
    return $null
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 800
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.Close()
            return $false
        }
        $client.EndConnect($iar) | Out-Null
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

function Get-RemoteVerify {
    param([Parameter(Mandatory)][string]$ComputerName)

    $dnsOk   = $false
    $pingOk  = $false
    $p5985   = $false
    $p5986   = $false
    $wsmanOk = $false

    try {
        $null = Resolve-DnsName -Name $ComputerName -Type A -ErrorAction Stop
        $dnsOk = $true
    } catch { $dnsOk = $false }

    try {
        $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    } catch { $pingOk = $false }

    $p5985 = Test-TcpPort -ComputerName $ComputerName -Port 5985
    $p5986 = Test-TcpPort -ComputerName $ComputerName -Port 5986

    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        $wsmanOk = $true
    } catch { $wsmanOk = $false }

    $reason = 'Unknown'
    $hint   = ''

    if (-not $dnsOk) {
        $reason = 'DNSFail'
        $hint   = 'DNS kan ikke resolve navnet.'
    }
    elseif (-not $pingOk) {
        $reason = 'NoPing'
        $hint   = 'Ingen ping-svar (netværk/firewall).'
    }
    elseif (-not $p5985 -and -not $p5986) {
        $reason = 'WinRMPortClosed'
        $hint   = 'WinRM porte er ikke tilgængelige.'
    }
    elseif ($p5985 -or $p5986) {
        if (-not $wsmanOk) {
            $reason = 'WSManPolicyOrAuth'
            $hint   = 'WinRM port åben, men WSMan fejler (policy/auth/cert).'
        } else {
            $reason = 'WSManOKButInvokeFailed'
            $hint   = 'WSMan OK, men Invoke fejler (rettigheder/PSRemoting).'
        }
    }

    [pscustomobject]@{
        DnsOk    = $dnsOk
        PingOk   = $pingOk
        Port5985 = $p5985
        Port5986 = $p5986
        WSManOk  = $wsmanOk
        Reason   = $reason
        Hint     = $hint
    }
}

function Get-PrimaryIPv4AndMaskRemote {
    param([Parameter(Mandatory)][string]$ComputerName)

    return Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $nic = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" |
               Where-Object { $_.IPAddress -ne $null } |
               Select-Object -First 1

        $ipv4 = $null
        $mask = $null

        if ($nic -and $nic.IPAddress) {
            $ipv4 = ($nic.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
        }
        if ($nic -and $nic.IPSubnet) {
            $mask = ($nic.IPSubnet  | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
        }

        [pscustomobject]@{
            IPv4       = $ipv4
            SubnetMask = $mask
        }
    } -ErrorAction Stop
}

function Get-NetworkPrefixFromIpAndMask {
    param(
        [Parameter(Mandatory)][string]$IPv4,
        [Parameter(Mandatory)][string]$SubnetMask
    )
    $cidr = Convert-MaskToCIDR $SubnetMask
    $ipBytes   = [System.Net.IPAddress]::Parse($IPv4).GetAddressBytes()
    $maskBytes = [System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes()
    for ($i=0; $i -lt 4; $i++) { $ipBytes[$i] = $ipBytes[$i] -band $maskBytes[$i] }
    $networkAddr = [System.Net.IPAddress]::new($ipBytes)
    return ("{0}/{1}" -f $networkAddr, $cidr)
}

function Normalize-CurrentSubnetBy {
    param([string]$Source)
    if (-not $Source) { return 'Unknown' }
    if ($Source -like 'RemoteUnavailable:*') {
        return ($Source -replace '^RemoteUnavailable:', '')
    }
    return $Source
}

# -----------------------------
# Local host identity (avoid remote to self)
# -----------------------------
$LocalComputerName = $env:COMPUTERNAME
$LocalFqdn = $null
try { $LocalFqdn = ([System.Net.Dns]::GetHostByName($LocalComputerName)).HostName } catch { $LocalFqdn = $null }

# Get DC list
$dcs = Get-ADDomainController -Filter * | Sort-Object Name

# Track remote failures for the "what to do" section
$RemoteFailures = New-Object System.Collections.Generic.List[object]

$results = foreach ($dc in $dcs) {

    $dcHost = $dc.HostName
    $dcIPv4FromAD = $dc.IPv4Address

    $isLocal = $false
    if ($dc.Name -ieq $LocalComputerName) { $isLocal = $true }
    elseif ($dcHost -and $LocalFqdn -and ($dcHost -ieq $LocalFqdn)) { $isLocal = $true }
    elseif ($dcHost -and ($dcHost -split '\.')[0] -ieq $LocalComputerName) { $isLocal = $true }

    # Match AD subnet for the DC IPv4Address (PingCastle-relevant)
    $matchedSubnet = $null
    if ($dcIPv4FromAD) {
        foreach ($subnet in $adSubnets) {
            if (Test-IPInSubnet -ip $dcIPv4FromAD -network $subnet.Network -maskLength $subnet.MaskLength) {
                $matchedSubnet = $subnet
                break
            }
        }
    }

    # NIC query (local first, then remote). If remote fails, verify and keep minimal warning.
    $netInfo = $null
    $netInfoSource = $null
    $verifyReason = ''
    $verifyPorts  = ''

    if ($isLocal) {
        $netInfo = Get-PrimaryIPv4AndMaskLocal
        $netInfoSource = if ($netInfo) { 'Local' } else { 'LocalFailed' }
    } else {
        try {
            $netInfo = Get-PrimaryIPv4AndMaskRemote -ComputerName $dcHost
            $netInfoSource = 'RemoteWinRM'
        } catch {
            $verify = Get-RemoteVerify -ComputerName $dcHost

            # Minimal warning (single line)
            Write-Warning ("Remote query failed for {0} - {1}" -f $dcHost, $verify.Reason)

            $netInfo = $null
            $netInfoSource = ("RemoteUnavailable:{0}" -f $verify.Reason)

            $verifyReason = $verify.Reason

            # "VerifyPorts" should show what ports to verify
            $verifyPorts = 'Verify TCP 5985 (WinRM HTTP) and 5986 (WinRM HTTPS)'

            # collect for guidance below
            $RemoteFailures.Add([pscustomobject]@{
                DCName = $dc.Name
                Host   = $dcHost
                Reason = $verify.Reason
                Hint   = $verify.Hint
            }) | Out-Null
        }
    }

    # Compute CurrentSubnet
    $currentSubnetPrefix = 'Unknown'
    $currentSubnetBy     = 'Unknown'

    if ($netInfo -and $netInfo.IPv4 -and $netInfo.SubnetMask) {
        try {
            $currentSubnetPrefix = Get-NetworkPrefixFromIpAndMask -IPv4 $netInfo.IPv4 -SubnetMask $netInfo.SubnetMask
            $currentSubnetBy = $netInfoSource
        } catch {
            $currentSubnetPrefix = 'Unknown'
            $currentSubnetBy = $netInfoSource
        }
    }
    elseif ($matchedSubnet) {
        # Fallback: show the AD subnet that the DC IP matches (useful when remote is unavailable)
        $currentSubnetPrefix = $matchedSubnet.Subnet
        $currentSubnetBy = 'FromADSubnet'
    }
    else {
        $currentSubnetPrefix = 'Unknown'
        $currentSubnetBy = if ($netInfoSource) { $netInfoSource } else { 'Unknown' }
    }

    # Clean CurrentSubnetBy (remove RemoteUnavailable prefix)
    $currentSubnetBy = Normalize-CurrentSubnetBy -Source $currentSubnetBy

    # Prefer locally discovered IPv4 for display; otherwise use AD IPv4
    $displayIPv4 = if ($netInfo -and $netInfo.IPv4) { $netInfo.IPv4 } else { $dcIPv4FromAD }

    [PSCustomObject]@{
        DCName          = $dc.Name
        IPv4            = $displayIPv4
        CurrentSubnet   = $currentSubnetPrefix
        CurrentSubnetBy = $currentSubnetBy
        Verify          = $verifyReason
        VerifyPorts     = $verifyPorts
        ADSite          = $dc.Site
        ADSubnetPrefix  = if ($matchedSubnet) { $matchedSubnet.Subnet } else { 'Not Found' }
        SubnetSite      = if ($matchedSubnet) { $matchedSubnet.Site } else { 'Unknown' }
    }
}

# Output
$results | Format-Table DCName, IPv4, CurrentSubnet, CurrentSubnetBy, Verify, VerifyPorts, ADSite, ADSubnetPrefix, SubnetSite -AutoSize

# PingCastle issue check (subnet mapping)
$hasIssues = $results | Where-Object {
    $_.ADSubnetPrefix -eq 'Not Found' -or $_.SubnetSite -eq 'Unknown'
}

if ($hasIssues) {
    Write-Host "`nQuick Guide to Add Subnets in AD Sites and Services:`n" -ForegroundColor Yellow
    Write-Host "1. Open 'Active Directory Sites and Services' (run 'dssite.msc')."
    Write-Host "2. Expand 'Subnets', right-click and select 'New Subnet...'."
    Write-Host "3. Enter subnet prefix (e.g. 10.212.60.0/24), assign correct site, and click OK."
    Write-Host "4. Repeat for all relevant subnets to ensure proper site mapping.`n"
}
else {
    Write-Host "`nAll domain controllers appear properly configured with matching subnets and sites." -ForegroundColor Green
}

# -----------------------------
# What to do (remote verification guidance)
# -----------------------------
if ($RemoteFailures.Count -gt 0) {
    Write-Host "`nRemote verification summary (only for DCs where remote NIC query failed):" -ForegroundColor Yellow
    foreach ($f in $RemoteFailures) {
        $hint = $f.Hint
        if (-not $hint) { $hint = 'Tjek connectivity og WinRM policy/firewall.' }
        Write-Host (" - {0} ({1}): {2}. {3}" -f $f.DCName, $f.Host, $f.Reason, $hint)
    }

    Write-Host "`nWhat to do (kort):" -ForegroundColor Yellow
    Write-Host " - Verify at TCP 5985/5986 (WinRM) er tilladt mellem denne server og den pågældende DC, hvis du vil hente SubnetMask remote."
    Write-Host " - Alternativt: WinRM er ikke påkrævet for PingCastle-fix; opret de manglende AD subnets i Sites and Services."
}
