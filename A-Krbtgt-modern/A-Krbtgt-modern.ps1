<#
A-Krbtgt 
MODNI 2025-08-25

What this script does

- Analyzes domain state: PDC, domain mode, Kerberos policy (TGT lifetime, clock skew).
- Computes and displays:
  • N-1 ticket expiry time
  • “Next safe Mode 3” time (enforces a policy-defined window; default 48h).
- Enumerates writable DCs and verifies “replication-capable reachability”:
  • LDAP (prefers LDAPS/StartTLS; signed SASL fallback if allowed)
  • AD Web Services (ADWS) availability.
- Mode 1 (Informational): runs all checks; no changes made.
- Mode 2 (Simulation): triggers single-object replication of krbtgt to estimate impact time; no key changes.
- Mode 3 (Reset): resets krbtgt on the PDC, replicates to all reachable DCs, then validates PasswordLastSet sync.
- Re-queries the PDC immediately before the reset and again before the replication loop.
- Hard-blocks Mode 3 when unsafe (N-1 not expired or policy window not met); no prompt shown.
- Logs to C:\ITM8\A-Krbtgt\ (UTF-8) with timestamped filenames and header lines (Next safe Mode 3 / N-1 expiry).
- ISE-safe control flow (uses `return`, never exits the host) with clear, operator-friendly prompts.

---------------------------------------------------------------------------------------------------------

How to use

1) Prereqs
   - Run as Domain Admin (or equivalent) on a host with RSAT ActiveDirectory + GroupPolicy.
   - Network to DCs: 389/636 (LDAP/LDAPS), 9389 (ADWS).
   - Domain functional level: Windows 2008+.

2) Policy window (optional)
   - Default wait between krbtgt resets is 48h. To change:
       $PolicyHoursBetweenResets = 48 (you can define this below)

3) Run the script (ISE or console)
   - A menu appears: Mode 1 / 2 / 3.

4) Modes
   - Mode 1 (Informational): No changes. Shows PDC, policy, N-1 expiry, and “Next safe Mode 3”.
   - Mode 2 (Simulation): No key changes. Triggers single-object replication to measure impact time.
       * SAFE to run even if N-1 expired check FAILED.
   - Mode 3 (Reset): Resets krbtgt on PDC + replicates.
       * HARD-BLOCKED until N-1 tickets have expired AND the policy window has elapsed.

5) Read the header lines
   - “N-1 tickets fully expire by: …”
   - “Next safe Mode 3 (per policy: Xh): …”
   - Only run Mode 3 at/after the “Next safe Mode 3” time.

6) Logs
   - All output/status written to: C:\ITM8\A-Krbtgt\New-CtmADKrbtgtKeys_*.log (UTF-8)
   - Header lines are also written at the top of each log.

7) Re-runs
   - You can run Mode 1 and Mode 2 anytime.
   - Do NOT run Mode 3 again until the policy window (Xh) has passed since the last reset.

Troubleshooting
   - If reachability fails: verify LDAPS/StartTLS/certs (389/636), ADWS (9389), DNS, and DC health.
   - If domain functional level < 2008: use the legacy (repadmin/rpcping) method.

---------------------------------------------------------------------------------------------------------

Why this modernized script (vs. the legacy Microsoft one)

The original “New-CtmADKrbtgtKeys.ps1” relied on external tools (rpcping.exe and repadmin.exe)
and parsed their English console output to decide success/failure. In many customer
environments those assumptions no longer hold. We built this version to be safer, more
portable, and compliant with hardened configurations.

Key reasons for change
1) No external utilities or locale parsing
   - Replaces rpcping.exe with an LDAP signed bind + RootDSE read (and LDAPS/StartTLS support).
   - Replaces repadmin.exe with Sync-ADObject (ADWS), avoiding brittle text parsing and the
     requirement for English output.
2) Works in hardened/STIG environments
   - Handles LDAP signing requirements correctly (won’t “pass” on an unsigned bind).
   - Prefers LDAPS 636, then StartTLS on 389; can optionally require TLS.
   - Checks AD Web Services (TCP 9389) so “reachability == replication capability.”
3) Safer operator experience
   - Clear guardrails: explains N-1 ticket expiry and enforces a policy-defined window (default 48h) between resets.
   - Hard-blocks Mode 3 when it’s unsafe (no prompt to proceed when N-1 not expired or the policy window not met).
   - Re-queries the PDC immediately before reset and again before the replication loop.
4) Better UX and logging
   - ISE-safe (uses `return`, never closes ISE).
   - Fixed log path (C:\ITM8\A-Krbtgt) with UTF-8 logs and header lines:
     * “Next safe Mode 3 (per policy: Xh)”
     * “N-1 tickets fully expire by”
   - Mode 2 prompt clarifies it’s safe to run even if N-1 hasn’t expired (no key changes).

What this doesn’t change
- You still need RSAT’s ActiveDirectory and GroupPolicy modules.
- Domain functional level must be Windows 2008 or higher (for ADWS/Sync-ADObject).
- Operational best practice: run Mode 1 → Mode 2 → Mode 3, and wait the policy-defined number of hours between resets.

Bottom line
This version removes fragile dependencies, aligns with modern security baselines, and adds
built-in safety checks so krbtgt rotations are predictable, auditable, and low-risk.
#>

# =========================
# region Rotation policy (hours between krbtgt resets)
# =========================
$PolicyHoursBetweenResets = 48   # <-- set to 50 if you want a 50-hour window (48 is default)
# =========================
# endregion Rotation policy
# =========================

# =========================
# region LDAP TLS preferences (tweak if needed)
# =========================
$RequireTLS         = $false   # Only pass LDAP test on LDAPS/StartTLS if $true
$PreferLDAPS        = $true    # Try LDAPS first, then StartTLS, then signed SASL (if RequireTLS=$false)
$SkipCertValidation = $false   # NOT recommended; use only in labs
# =========================
# endregion LDAP TLS preferences
# =========================

# =========================
# region Helpers / Utilities
# =========================

function Confirm-CtmADPasswordIsComplex {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Pw)
    process {
        $criteria = 0
        if ($Pw -cmatch '[A-Z]') { $criteria++ }
        if ($Pw -cmatch '[a-z]') { $criteria++ }
        if ($Pw -match '\d')     { $criteria++ }
        if ($Pw -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') { $criteria++ }
        if ($criteria -lt 3) { return $false }
        if ($Pw.Length -lt 6) { return $false }
        return $true
    }
}

function New-CtmADComplexPassword {
    [CmdletBinding()]
    param([ValidateRange(6,127)][int]$PwLength = 24)
    process {
        $iterations = 0
        do {
            if ($iterations -ge 20) {
                Write-Host "Password generation failed to meet complexity after $iterations attempts, exiting."
                return $null
            }
            $iterations++
            $pwBytes = New-Object 'System.Collections.Generic.List[byte]'
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try {
                while ($pwBytes.Count -lt $PwLength) {
                    $b = New-Object byte[] 1
                    $rng.GetBytes($b)
                    if ($b[0] -ge 33 -and $b[0] -le 126) { $pwBytes.Add($b[0]) }
                }
            } finally { $rng.Dispose() }
            $pw = ([char[]]$pwBytes.ToArray()) -join ''
        } until (Confirm-CtmADPasswordIsComplex $pw)
        return $pw
    }
}

function New-CtmADKrbtgtAccountPassword {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Server)
    try {
        $krb = Get-ADUser -Identity 'krbtgt' -Server $Server -ErrorAction Stop
        $new = New-CtmADComplexPassword -PwLength 32
        if (-not $new) {
            return [pscustomobject]@{ Success = $false; Message = 'Password generator failed complexity.' }
        }
        $sec = ConvertTo-SecureString $new -AsPlainText -Force
        Set-ADAccountPassword -Identity $krb.DistinguishedName -Server $Server -Reset -NewPassword $sec -ErrorAction Stop
        return [pscustomobject]@{ Success = $true; Message = 'Krbtgt key reset successfully.' }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'ActiveDirectoryCmdlet:System.UnauthorizedAccessException*' -or
            $_.CategoryInfo.Category -eq 'PermissionDenied') {
            return [pscustomobject]@{ Success = $false; Message = 'Krbtgt key reset failed due to insufficient permissions.' }
        }
        return [pscustomobject]@{ Success = $false; Message = "Krbtgt key reset failed: $($_.Exception.Message)" }
    }
}

function Test-LdapConnectivity {
    <#
      Reachability test that prefers LDAPS:636, then StartTLS on 389, then signed SASL (Negotiate).
      Returns Success, Mode (LDAPS|StartTLS|SignedOnly|None), and Message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [int]$TimeoutSeconds = 3,
        [switch]$RequireTLS,
        [switch]$PreferLDAPS,
        [switch]$SkipCertValidation
    )
    function Invoke-RootDseRead([System.DirectoryServices.Protocols.LdapConnection]$c) {
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)",
            [System.DirectoryServices.Protocols.SearchScope]::Base, @("defaultNamingContext"))
        $resp = $c.SendRequest($req)
        return ($resp.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success)
    }

    if ($PreferLDAPS) {
        try {
            $c = New-Object System.DirectoryServices.Protocols.LdapConnection($Server)
            $c.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $c.SessionOptions.ProtocolVersion = 3
            $c.SessionOptions.SecureSocketLayer = $true
            if ($SkipCertValidation) { $c.SessionOptions.VerifyServerCertificate = { param($conn,$cert) return $true } }
            $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
            $c.Bind()
            if (Invoke-RootDseRead $c) {
                return [pscustomobject]@{ Success=$true; Mode='LDAPS'; Message="$Server - LDAPS bind + RootDSE OK." }
            }
        } catch {} finally { if ($c) { $c.Dispose() } }
    }

    try {
        $c = New-Object System.DirectoryServices.Protocols.LdapConnection($Server)
        $c.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $c.SessionOptions.ProtocolVersion = 3
        if ($SkipCertValidation) { $c.SessionOptions.VerifyServerCertificate = { param($conn,$cert) return $true } }
        try { $c.SessionOptions.StartTransportLayerSecurity($null) } catch { throw }
        $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $c.Bind()
        if (Invoke-RootDseRead $c) {
            return [pscustomobject]@{ Success=$true; Mode='StartTLS'; Message="$Server - StartTLS bind + RootDSE OK." }
        }
    } catch {} finally { if ($c) { $c.Dispose() } }

    try {
        $c = New-Object System.DirectoryServices.Protocols.LdapConnection($Server)
        $c.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $c.SessionOptions.ProtocolVersion = 3
        $c.SessionOptions.Signing = $true
        $c.SessionOptions.Sealing = $true
        $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
        $c.Bind()
        if (Invoke-RootDseRead $c) {
            if ($RequireTLS) {
                return [pscustomobject]@{ Success=$false; Mode='SignedOnly'; Message="$Server - Signed bind OK, but TLS is required." }
            }
            return [pscustomobject]@{ Success=$true; Mode='SignedOnly'; Message="$Server - Signed (no TLS) bind + RootDSE OK." }
        }
    } catch {
        return [pscustomobject]@{ Success=$false; Mode='None'; Message="$Server - LDAP connectivity failed: $($_.Exception.Message)" }
    } finally { if ($c) { $c.Dispose() } }
}

function Test-ADWS {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Server)
    try {
        Get-ADDomain -Server $Server -ErrorAction Stop | Out-Null
        return [pscustomobject]@{ Success = $true; Message = "$Server - ADWS reachable." }
    } catch {
        return [pscustomobject]@{ Success = $false; Message = "$Server - ADWS check failed: $($_.Exception.Message)" }
    }
}

function Invoke-SingleObjectReplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetDC,
        [Parameter(Mandatory)][string]$SourceDC,
        [Parameter(Mandatory)][string]$ObjectDN
    )
    try {
        Sync-ADObject -Object $ObjectDN -Source $SourceDC -Destination $TargetDC -ErrorAction Stop | Out-Null
        return [pscustomobject]@{ Success = $true; Message = "$ObjectDN - Replicated from $SourceDC to $TargetDC." }
    } catch {
        $msg = $_.Exception.Message
        return [pscustomobject]@{ Success = $false; Message = "$ObjectDN - Replication $SourceDC -> $TargetDC failed: $msg" }
    }
}

# =========================
# endregion Helpers
# =========================


# =========================
# region Initialize / Logging / Menu
# =========================

$LogFolder   = 'C:\ITM8\A-Krbtgt'
$LogEncoding = 'utf8'
if (-not (Test-Path -LiteralPath $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}
$TimeStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile   = Join-Path $LogFolder "New-CtmADKrbtgtKeys_$TimeStamp.log"

# Safe working directory (no crash in ISE/paste)
$here = $PSScriptRoot
if (-not $here) {
    try { $here = Split-Path -Path $PSCommandPath -ErrorAction Stop } catch {}
    if (-not $here -and $MyInvocation.MyCommand.Path) { $here = Split-Path -Path $MyInvocation.MyCommand.Path }
}
if ($here) { Set-Location -LiteralPath $here }

$Status  = [pscustomobject]@{}
$timeFmt = 'yyyy-MM-dd HH:mm'

Write-Host 'Checking domain functional level (early)...'
Import-Module ActiveDirectory -ErrorAction Stop
try {
    $dom = Get-ADDomain
    $dfl = $dom.DomainMode
} catch {
    Write-Host -ForegroundColor Red "Failed to read domain info: $($_.Exception.Message)"
    $Status | Add-Member NoteProperty EarlyError $_.Exception.Message
    $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
    return
}
if ($dfl -in 'Windows2000Domain','Windows2003InterimDomain','Windows2003Domain') {
    Write-Host -ForegroundColor Red "Domain functional level is $dfl. This modern method requires Windows 2008 or higher."
    Write-Host -ForegroundColor Yellow "Please use the legacy script method that relies on repadmin.exe / rpcping.exe."
    $Status | Add-Member NoteProperty DomainMode $dfl
    $Status | Add-Member NoteProperty EarlyExit 'Domain functional level too low for ADWS-based method.'
    $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
    return
}

Import-Module GroupPolicy -ErrorAction Stop

$ScriptDescription = @'
This script performs a single reset of the shared krbtgt key for all writable DCs in the current domain.

It has 3 modes:
'@
$Mode1Description = @'
  - Mode 1: Informational (no changes, no replication). Safe to run anytime.
'@
$Mode2Description = @'
  - Mode 2: Simulation (no changes, but single-object replication of krbtgt is triggered to estimate impact time).
'@
$Mode3Description = @'
  - Mode 3: Reset (resets krbtgt once on the PDC; then replicates krbtgt to all reachable writable DCs).
    During the impact window, some Kerberos validations may fail until all DCs have the new key.
'@
$Mode3Impact1 = @'
    - Potential PAC validation/TGS request failures across sites until replication completes.
'@
$Mode3Impact2 = @'
    - Some clients/apps may need a restart if they don’t recover automatically after replication finishes.
'@
$ScriptRecommendation = "Recommended order: Mode 1 -> Mode 2 -> Mode 3."
$Menu = @'
Choose mode:

  1 — Informational
  2 — Simulation (triggers replication only)
  3 — Reset (changes krbtgt and triggers replication)
  0 — Exit
'@
$MenuPrompt = '(Enter 1-3, or 0 to exit)'

Write-Host ''
Write-Host $ScriptDescription
Write-Host -ForegroundColor Green  $Mode1Description
Write-Host -ForegroundColor Yellow $Mode2Description
Write-Host -ForegroundColor Red    $Mode3Description
Write-Host -ForegroundColor Cyan   $Mode3Impact1
Write-Host -ForegroundColor Cyan   $Mode3Impact2
Write-Host ''
Write-Host $ScriptRecommendation
Write-Host ''
Write-Host $Menu
Write-Host ''

$Status | Add-Member NoteProperty ScriptMode (Read-Host $MenuPrompt)
if (($Status.ScriptMode -lt 1) -or ($Status.ScriptMode -gt 3)) { Write-Host 'Invalid selection.'; $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding; return }

# =========================
# endregion Initialize / Logging / Menu
# =========================


# =========================
# region Pre-flight
# =========================
Write-Host 'Checking pre-requisites...'
$Status | Add-Member NoteProperty PreFlightPassed $true
Write-Host ''

Write-Host '   Checking for ActiveDirectory module.....' -NoNewline
if (Get-Module -ListAvailable ActiveDirectory) { Write-Host -ForegroundColor Green 'PASSED' } else { $Status.PreFlightPassed = $false; Write-Host -ForegroundColor Red 'FAILED' }

Write-Host '   Checking for GroupPolicy module.....' -NoNewline
if (Get-Module -ListAvailable GroupPolicy) { Write-Host -ForegroundColor Green 'PASSED' } else { $Status.PreFlightPassed = $false; Write-Host -ForegroundColor Red 'FAILED' }

Write-Host ''
if (-not $Status.PreFlightPassed) { Write-Host -ForegroundColor Red "Pre-flight checks failed."; $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding; return }

# =========================
# endregion Pre-flight
# =========================


# =========================
# region Domain + Kerberos Policy (with Header Summary)
# =========================
Write-Host 'Gathering domain information...'
$TargetDomain = Get-ADDomain | Select-Object Name, DNSRoot, NetBIOSName, DomainMode, PDCEmulator

Write-Host ''
Write-Host '   Domain NetBIOS name: ' -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.NetBIOSName
Write-Host '   Domain DNS name: '    -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.DNSRoot 
Write-Host '   PDC emulator (current read): ' -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.PDCEmulator
Write-Host '   DomainMode: '         -NoNewline; Write-Host -ForegroundColor Cyan $TargetDomain.DomainMode
Write-Host '   Checking domain functional mode is ''Windows2008Domain'' or higher.....' -NoNewline
$Status | Add-Member NoteProperty DomainModePassed $true
Write-Host -ForegroundColor Green 'PASSED'
Write-Host ''

Write-Host 'Gathering krbtgt + Kerberos policy...'
Write-Host ''

$Krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet,DistinguishedName -Server $TargetDomain.PDCEmulator

try {
    [xml]$gpo = Get-GPOReport -Guid '{31B2F340-016D-11D2-945F-00C04FB984F9}' -ReportType Xml
    $sec = ($gpo.gpo.Computer.ExtensionData | Where-Object { $_.name -eq 'Security' }).Extension.ChildNodes
    $MaxTgtLifetimeHrs = ($sec | Where-Object { $_.Name -eq 'MaxTicketAge' }).SettingNumber
    $MaxClockSkewMins  = ($sec | Where-Object { $_.Name -eq 'MaxClockSkew' }).SettingNumber
} catch {
    Write-Warning 'Could not read MaxTicketAge/MaxClockSkew from Default Domain Policy; using defaults 10h / 5m.'
    $MaxTgtLifetimeHrs = 10
    $MaxClockSkewMins  = 5
}

$NMinusOneExpire     = $Krbtgt.PasswordLastSet.AddHours($MaxTgtLifetimeHrs).AddMinutes($MaxClockSkewMins * 2)
$SecondResetEarliest = $Krbtgt.PasswordLastSet.AddHours($PolicyHoursBetweenResets)

$Status | Add-Member NoteProperty SecondResetEarliest $SecondResetEarliest
$Status | Add-Member NoteProperty NMinusOneTicketExpirationPassed ($NMinusOneExpire -lt (Get-Date))

# Header summary (also write to log header)
$headerLine1 = ('Next safe Mode 3 (per policy: {0}h): {1}' -f $PolicyHoursBetweenResets, $SecondResetEarliest.ToString($timeFmt))
$headerLine2 = ('N-1 tickets fully expire by: {0}' -f $NMinusOneExpire.ToString($timeFmt))
Write-Host ''
Write-Host ('===== {0} =====' -f $headerLine1) -ForegroundColor Magenta
Write-Host ('===== {0} =====' -f $headerLine2) -ForegroundColor Magenta
Write-Host ''
Add-Content -Path $LogFile -Value $headerLine1 -Encoding $LogEncoding
Add-Content -Path $LogFile -Value $headerLine2 -Encoding $LogEncoding

Write-Host ('   Krbtgt account: {0}' -f $Krbtgt.DistinguishedName)
Write-Host ('   Krbtgt pwd last set on PDC: {0}' -f $Krbtgt.PasswordLastSet.ToString($timeFmt))
Write-Host '   Kerberos MaxTicketAge: ' -NoNewline; Write-Host -ForegroundColor Cyan $MaxTgtLifetimeHrs 'hours'
Write-Host '   Kerberos MaxClockSkew: ' -NoNewline; Write-Host -ForegroundColor Cyan $MaxClockSkewMins 'minutes'
Write-Host '   All N-1 tickets expired check.....' -NoNewline
if ($Status.NMinusOneTicketExpirationPassed) {
    Write-Host -ForegroundColor Green 'PASSED'
    Write-Host -ForegroundColor Yellow ("      Note: Operational policy still requires {0} hours after last reset." -f $PolicyHoursBetweenResets)
    Write-Host -ForegroundColor Yellow ("      Earliest safe time for NEXT Mode 3 (per policy: {0}h): {1}" -f $PolicyHoursBetweenResets, $SecondResetEarliest.ToString($timeFmt))
} else {
    Write-Host -ForegroundColor Red 'FAILED'
    Write-Host -ForegroundColor Yellow ("      Explanation: Some tickets issued with the previous (N-1) krbtgt key may still be valid.")
    Write-Host -ForegroundColor Yellow ("      N-1 tickets estimated to fully expire by: {0}" -f $NMinusOneExpire.ToString($timeFmt))
    Write-Host -ForegroundColor Yellow ("      Operational policy: Wait {0} hours after the last reset." -f $PolicyHoursBetweenResets)
    Write-Host -ForegroundColor Yellow ("      Earliest safe time for NEXT Mode 3 (per policy: {0}h): {1}" -f $PolicyHoursBetweenResets, $SecondResetEarliest.ToString($timeFmt))
}
Write-Host ''

# =========================
# endregion Domain + Kerberos Policy
# =========================


# =========================
# region DC inventory + reachability (LDAP TLS + ADWS)
# =========================
Write-Host 'Enumerating writable DCs and testing reachability (LDAP TLS + ADWS)...'
Write-Host ''

$RwDcs = Get-ADDomainController -Filter { IsReadOnly -eq $false } -Server $TargetDomain.PDCEmulator |
         Select-Object Name, Hostname, Domain, Site

$Status | Add-Member NoteProperty ReachabilityPassed $true
Write-Host '   Reachability to DCs (LDAP + ADWS must pass):'
foreach ($dc in $RwDcs) {
    $isPdc = ($dc.Hostname -eq $TargetDomain.PDCEmulator)
    $dc | Add-Member NoteProperty IsPdcEmulator $isPdc

    Write-Host ("      LDAP to {0} ....." -f $dc.Hostname) -NoNewline
    $ldap = Test-LdapConnectivity -Server $dc.Hostname -TimeoutSeconds 3 `
                -RequireTLS:$RequireTLS -PreferLDAPS:$PreferLDAPS -SkipCertValidation:$SkipCertValidation
    $dc | Add-Member NoteProperty LdapMode ($ldap.Mode)
    $dc | Add-Member NoteProperty LdapOK ($ldap.Success)
    if ($ldap.Success) { Write-Host -ForegroundColor Green ("PASSED ({0})" -f $ldap.Mode) }
    else { Write-Host -ForegroundColor Red 'FAILED'; Write-Host "         $($ldap.Message)" }

    Write-Host "      ADWS to $($dc.Hostname) ....." -NoNewline
    $adws = Test-ADWS -Server $dc.Hostname
    $dc | Add-Member NoteProperty AdwsOK $adws.Success
    if ($adws.Success) { Write-Host -ForegroundColor Green 'PASSED' } else { Write-Host -ForegroundColor Red 'FAILED'; Write-Host "         $($adws.Message)" }

    $both = $ldap.Success -and $adws.Success
    $dc | Add-Member NoteProperty IsReachable $both
    if (-not $both) { $Status.ReachabilityPassed = $false }
}

if ($Status.ReachabilityPassed) {
    Write-Host -ForegroundColor Green '   All writable DCs passed LDAP (per policy) AND ADWS checks.'
} else {
    Write-Host -ForegroundColor Red '   One or more writable DCs failed LDAP and/or ADWS checks.'
    if ($RequireTLS) {
        Write-Host -ForegroundColor Yellow '   Hint: TLS required. Check DC certificates, trust chain, and LDAPS/StartTLS reachability (636/389).'
    } else {
        Write-Host -ForegroundColor Yellow '   Hint: Check LDAP signing policy, certificates (if using TLS), firewall (389/LDAP & 636/LDAPS & 9389/ADWS), name resolution, and DC health.'
    }
}
Write-Host ''

# =========================
# endregion DC inventory + reachability
# =========================


# =========================
# region Modes 2 and 3 — replicate krbtgt to estimate impact
# =========================
if ($Status.ScriptMode -gt 1 -and $Status.PreFlightPassed -and $Status.ReachabilityPassed) {
    Write-Host 'Replicating krbtgt (single object) to reachable writable DCs to estimate impact...'
    if ($Status.ScriptMode -eq 2) {
        Write-Host -ForegroundColor Yellow '   Replication WILL BE triggered if you proceed (non-destructive; no key change).'
        if (-not $Status.NMinusOneTicketExpirationPassed) {
            Write-Host -ForegroundColor Yellow ("   NOTE: N-1 tickets have NOT fully expired (est. {0})." -f $NMinusOneExpire.ToString($timeFmt))
            Write-Host -ForegroundColor Yellow ("   It is SAFE to proceed with Mode 2 now to measure replication time.")
            Write-Host -ForegroundColor Yellow ("   Do NOT run Mode 3 until the Earliest safe Mode 3 time (per policy: {0}h): {1}" -f $PolicyHoursBetweenResets, $SecondResetEarliest.ToString($timeFmt))
        }
        if ( (Read-Host "   Enter 'Y' to proceed with Mode 2 or any other key to cancel").ToUpper() -ne 'Y') {
            Write-Host -ForegroundColor Yellow "   Replication skipped at user's request."
            $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
            return
        }
    }

    # Re-read the PDC immediately before replication
    $currentPdc = (Get-ADDomain).PDCEmulator
    Write-Host "   Current PDC (fresh read): $currentPdc"
    $Krbtgt = Get-ADUser krbtgt -Properties DistinguishedName -Server $currentPdc

    $ImpactStartTime = (Get-Date).ToUniversalTime()
    $Status | Add-Member NoteProperty ReplicationCheckSucceeded $true

    foreach ($dc in $RwDcs) {
        if (-not $dc.IsPdcEmulator) {
            Write-Host "      Replication $currentPdc -> $($dc.Hostname) ..." -NoNewline
            if ($dc.IsReachable) {
                $start = (Get-Date).ToUniversalTime()
                $res = Invoke-SingleObjectReplication -TargetDC $dc.Hostname -SourceDC $currentPdc -ObjectDN $Krbtgt.DistinguishedName
                if ($res.Success) { Write-Host -ForegroundColor Green 'SUCCEEDED' -NoNewline }
                else { $Status.ReplicationCheckSucceeded = $false; Write-Host -ForegroundColor Red 'FAILED' -NoNewline }
                $elapsed = ((Get-Date).ToUniversalTime() - $start)
                Write-Host -ForegroundColor Cyan "  Time: $elapsed"
            } else {
                Write-Host -ForegroundColor Yellow 'SKIPPED (reachability failed)'
            }
        }
    }

    $TotalImpactTime = (Get-Date).ToUniversalTime() - $ImpactStartTime
    $Status | Add-Member NoteProperty ImpactDurationEstimate $TotalImpactTime
    Write-Host ''
    if ($Status.ReplicationCheckSucceeded) {
        Write-Host -ForegroundColor Cyan 'Estimated Mode 3 impact duration:' $TotalImpactTime
    } else {
        Write-Host -ForegroundColor Red 'Single-object replication failed to one or more DCs. Remediate before Mode 3.'
    }
}
# =========================
# endregion Modes 2 and 3
# =========================


# =========================
# region Mode 3 — reset and replicate (hard block before any prompt)
# =========================
if ($Status.ScriptMode -eq 3 -and $Status.PreFlightPassed -and $Status.ReachabilityPassed -and $Status.ReplicationCheckSucceeded) {
    Write-Host 'Preparing to reset krbtgt and replicate to reachable DCs...'
    Write-Host ''

    # ---- HARD BLOCKS (NO PROMPTS) ----
    if ((Get-Date) -lt $Status.SecondResetEarliest) {
        Write-Host -ForegroundColor Red   ("BLOCKED: {0}-hour policy not met." -f $PolicyHoursBetweenResets)
        Write-Host -ForegroundColor Yellow ("Earliest safe time for Mode 3 (per policy: {0}h): {1}" -f $PolicyHoursBetweenResets, $Status.SecondResetEarliest.ToString($timeFmt))
        Write-Host -ForegroundColor Yellow ("Reason: Avoid invalidating still-valid tickets from the previous reset.")
        $Status | Add-Member NoteProperty SecondResetPolicyBlocked $true
        $Status | Add-Member NoteProperty HardBlockReason 'SecondResetWindow'
        $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
        return
    }

    if (-not $Status.NMinusOneTicketExpirationPassed) {
        Write-Host -ForegroundColor Red   "BLOCKED: N-1 tickets have not fully expired."
        Write-Host -ForegroundColor Yellow ("N-1 tickets estimated to fully expire by: {0}" -f $NMinusOneExpire.ToString($timeFmt))
        Write-Host -ForegroundColor Yellow ("Earliest safe time for Mode 3 (per policy: {0}h): {1}" -f $PolicyHoursBetweenResets, $SecondResetEarliest.ToString($timeFmt))
        $Status | Add-Member NoteProperty NMinusOneBlock $true
        $Status | Add-Member NoteProperty HardBlockReason 'NMinusOneNotExpired'
        $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
        return
    }
    # ---- END HARD BLOCKS ----

    # Safe to proceed; now warn and prompt
    Write-Host -ForegroundColor Red '   WARNING: This will reset the krbtgt key and trigger replication.'
    Write-Host -ForegroundColor Red '   The impact window begins immediately and lasts until all DCs have the new key.'
    if ( (Read-Host "   Enter 'Y' to proceed or any other key to cancel").ToUpper() -ne 'Y') {
        Write-Host -ForegroundColor Yellow "   Reset/replication skipped at user's request."
        $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
        return
    }
    Write-Host ''

    # Re-read the PDC immediately before RESET
    $currentPdc = (Get-ADDomain).PDCEmulator
    Write-Host "   Current PDC (fresh read): $currentPdc"
    $Krbtgt = Get-ADUser krbtgt -Properties DistinguishedName,PasswordLastSet -Server $currentPdc

    # Extra guard: enforce policy window again using the freshest PDC read
    if (-not $Status.SecondResetEarliest) { $Status.SecondResetEarliest = $Krbtgt.PasswordLastSet.AddHours($PolicyHoursBetweenResets) }
    if ((Get-Date) -lt $Status.SecondResetEarliest) {
        Write-Host -ForegroundColor Red   ("   BLOCKED (re-check): {0}-hour policy not met." -f $PolicyHoursBetweenResets)
        Write-Host -ForegroundColor Yellow("   Earliest safe time for Mode 3 (per policy: {0}h): {1}" -f $PolicyHoursBetweenResets, $Status.SecondResetEarliest.ToString($timeFmt))
        $Status | Add-Member NoteProperty SecondResetPolicyBlocked $true
        $Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
        return
    }

    $ImpactStartTime = (Get-Date).ToUniversalTime()

    # Reset on current PDC
    Write-Host -ForegroundColor Cyan '   Resetting krbtgt key.....' -NoNewline
    $Status | Add-Member NoteProperty ResetSucceeded (New-CtmADKrbtgtAccountPassword -Server $currentPdc).Success
    if ($Status.ResetSucceeded) { Write-Host -ForegroundColor Green 'SUCCEEDED' } else { Write-Host -ForegroundColor Red 'FAILED'; Write-Host -ForegroundColor Red '   Reset failed; skipping replication.' }

    Write-Host ''
    if ($Status.ResetSucceeded) {
        $Status | Add-Member NoteProperty PostResetReplicationSucceeded $true

        # Re-read the PDC again right before the replication loop
        $currentPdc = (Get-ADDomain).PDCEmulator
        Write-Host "   Current PDC (pre-replication read): $currentPdc"

        foreach ($dc in $RwDcs) {
            if (-not $dc.IsPdcEmulator) {
                Write-Host "      Replication $currentPdc -> $($dc.Hostname) ..." -NoNewline
                if ($dc.IsReachable) {
                    $start = (Get-Date).ToUniversalTime()
                    $res = Invoke-SingleObjectReplication -TargetDC $dc.Hostname -SourceDC $currentPdc -ObjectDN $Krbtgt.DistinguishedName
                    if ($res.Success) { Write-Host -ForegroundColor Green 'SUCCEEDED' -NoNewline }
                    else { $Status.PostResetReplicationSucceeded = $false; Write-Host -ForegroundColor Red 'FAILED' -NoNewline }
                    $elapsed = ((Get-Date).ToUniversalTime() - $start)
                    Write-Host -ForegroundColor Cyan "  Time: $elapsed"
                } else {
                    Write-Host -ForegroundColor Yellow 'SKIPPED (reachability failed)'
                }
            }
        }

        $TotalImpactTime = (Get-Date).ToUniversalTime() - $ImpactStartTime
        $Status | Add-Member NoteProperty ImpactDuration $TotalImpactTime
        if ($Status.PostResetReplicationSucceeded) {
            Write-Host -ForegroundColor Cyan 'Mode 3 total impact duration:' $TotalImpactTime
        } else {
            Write-Host -ForegroundColor Red 'Single-object replication failed to one or more DCs.'
        }

        # Validate "password last set" sync
        Write-Host ''
        Write-Host '   Validating krbtgt "password last set" vs PDC...'
        $Status | Add-Member NoteProperty NewKrbtgtKeyReplValidationPassed $true
        $PdcLastSet = (Get-ADUser krbtgt -Properties PasswordLastSet -Server $currentPdc).PasswordLastSet
        Write-Host '      PDC: last set ..... ' -NoNewline; Write-Host -ForegroundColor Cyan $PdcLastSet.ToString($timeFmt)

        foreach ($dc in $RwDcs) {
            if (-not $dc.IsPdcEmulator) {
                Write-Host "      $($dc.Hostname): checking ..... " -NoNewline
                if (-not $dc.IsReachable) { Write-Host -ForegroundColor Yellow "SKIPPED (unreachable for this method)"; continue }
                try {
                    $val = (Get-ADUser krbtgt -Properties PasswordLastSet -Server $dc.Hostname -ErrorAction Stop).PasswordLastSet
                    if ($val -ne $PdcLastSet) {
                        Write-Host -ForegroundColor Red 'FAILED' -NoNewline
                        $Status.NewKrbtgtKeyReplValidationPassed = $false
                        Write-Host -ForegroundColor Cyan "  Last set: $($val.ToString($timeFmt))"
                    } else {
                        Write-Host -ForegroundColor Green 'PASSED' -NoNewline
                        Write-Host -ForegroundColor Cyan "  Last set: $($val.ToString($timeFmt))"
                    }
                } catch {
                    Write-Host -ForegroundColor Yellow "SKIPPED (could not connect: $($_.Exception.Message))"
                }
            }
        }
        Write-Host ''
        if (-not $Status.NewKrbtgtKeyReplValidationPassed) {
            Write-Host -ForegroundColor Red '   One or more reachable DCs were out of sync with the PDC.'
        } else {
            Write-Host -ForegroundColor Green '   All reachable DCs are in sync with the PDC.'
        }
    }
}

if ( (-not $Status.PreFlightPassed) -or (-not $Status.ReachabilityPassed) -or
     ($Status.ScriptMode -gt 1 -and -not $Status.ReplicationCheckSucceeded) ) {
    Write-Host -ForegroundColor Red 'One or more items failed. Resolve failures and retry.'
}

# Log status data
$Status | Out-File -FilePath $LogFile -Append -Encoding $LogEncoding
Write-Host "Logged to file: $LogFile"
# =========================
# endregion Mode 3
# =========================
