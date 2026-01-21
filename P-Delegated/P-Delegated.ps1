<#
MODNI 20251029
Title: P-Delegated + Usage Audit – single-account pre-hardening check (read-only)

What it does
-------------
A) Account configuration:
   - Delegation flags (TrustedForDelegation / TrustedToAuthForDelegation / msDS-AllowedToDelegateTo)
   - SPNs
   - UPN presence
   - AdminSDHolder / privileged group membership
   - Protected Users membership
B) Usage:
   - Exact LastLogon on every DC
   - Optional Security log scan (4624/4776) for Kerberos vs NTLM, auto-skipped if dormant
   - Optional remote scan for services, scheduled tasks, or active sessions

Notes
-----
- Read-only, no Set-ADUser or modifications.
- ISE-friendly, no $using: or $_ interpolation.
#>

[CmdletBinding()]
param(
  [string]$User = 'svc_sec_admin',     				# Define user - sAM / UPN / mail
  [int]$Days = 14,                     				# lookback window for Security logs
  [switch]$ScanServers = $true,        				# optionally scan for services/tasks/sessions
  [string]$ComputerSearchBase = "",    # Example: [string]$ComputerSearchBase = "auff.local/Domain Controllers" # optional OU DN to limit scope
  [string]$ComputerFilter = '(operatingSystem -like "*Server*")' # AD computer filter
)

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Write-Info([string]$m){ Write-Host $m -ForegroundColor Cyan }
function Write-Good([string]$m){ Write-Host $m -ForegroundColor Green }
function Write-Warn([string]$m){ Write-Host $m -ForegroundColor Yellow }
function Write-Bad ([string]$m){ Write-Host $m -ForegroundColor Red }

# ---------- Resolve the user ----------
Write-Info ("Resolving user '{0}' ..." -f $User)
$resolved = $null
try {
  $resolved = Get-ADUser -Identity $User -Properties * -ErrorAction Stop
} catch {
  $flt = ("SamAccountName -eq '{0}' -or UserPrincipalName -eq '{0}' -or mail -eq '{0}'" -f $User)
  $cand = Get-ADUser -Filter $flt -Properties * -ErrorAction SilentlyContinue
  if ($cand -and $cand.Count -gt 1) {
    $resolved = ($cand | Where-Object { $_.SamAccountName -eq $User } | Select-Object -First 1)
    if (-not $resolved) { $resolved = ($cand | Where-Object { $_.UserPrincipalName -eq $User } | Select-Object -First 1) }
    if (-not $resolved) { $resolved = ($cand | Where-Object { $_.mail -eq $User } | Select-Object -First 1) }
    if (-not $resolved) { $resolved = $cand | Select-Object -First 1 }
  } else {
    $resolved = $cand
  }
}
if (-not $resolved) { Write-Bad ("User '{0}' not found." -f $User); return }

# Re-read with needed props
$u = Get-ADUser $resolved.DistinguishedName -Properties `
  msDS-AllowedToDelegateTo,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,AccountNotDelegated, `
  adminCount,Enabled,WhenCreated,UserPrincipalName,MemberOf,SamAccountName,DistinguishedName

# ---------- Identity safety ----------
$groups = @()
try { $groups = Get-ADPrincipalGroupMembership -Identity $u.DistinguishedName | Select-Object -ExpandProperty Name } catch {}
$protectedUsers = $false
try { $protectedUsers = ($groups -contains (Get-ADGroup -Identity 'Protected Users' -ErrorAction Stop).Name) } catch {}
$privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Server Operators','Backup Operators','Print Operators','DNSAdmins')
$inPriv = @($groups | Where-Object { $privGroups -contains $_ })
$unconstrained = ($u.TrustedForDelegation -eq $true)
$protTransition = ($u.TrustedToAuthForDelegation -eq $true)
$allowedToDel = @(); if ($u.'msDS-AllowedToDelegateTo') { $allowedToDel = @($u.'msDS-AllowedToDelegateTo') }
$spns = @(); if ($u.ServicePrincipalName) { $spns = @($u.ServicePrincipalName) }
$hasUPN = ([string]::IsNullOrWhiteSpace($u.UserPrincipalName) -eq $false)
$adminSD = ($u.adminCount -eq 1)

$delegationType = 'None'
if     ($unconstrained) { $delegationType = 'Unconstrained' }
elseif ($allowedToDel.Count -gt 0 -and $protTransition) { $delegationType = 'Constrained (with Protocol Transition)' }
elseif ($allowedToDel.Count -gt 0) { $delegationType = 'Constrained' }

Write-Host ""
Write-Host ("Account: {0}" -f $u.SamAccountName) -ForegroundColor White
Write-Host ("DN     : {0}" -f $u.DistinguishedName) -ForegroundColor DarkGray
Write-Host ("Enabled: {0}" -f $u.Enabled) -ForegroundColor DarkGray
Write-Host ("Created: {0}" -f $u.WhenCreated) -ForegroundColor DarkGray
Write-Host ""
if ($hasUPN) { Write-Good ("UPN    : {0}" -f $u.UserPrincipalName) } else { Write-Warn "UPN    : (missing) – consider setting a UPN" }

switch ($delegationType) {
  'Unconstrained' { Write-Bad "Delegation: UNCONSTRAINED (highest risk)" }
  'Constrained (with Protocol Transition)' { Write-Warn "Delegation: Constrained WITH Protocol Transition (S4U2Self)" }
  'Constrained' { Write-Warn "Delegation: Constrained" }
  default { Write-Good "Delegation: None" }
}
Write-Host (" - TrustedForDelegation           : {0}" -f $u.TrustedForDelegation) -ForegroundColor DarkGray
Write-Host (" - TrustedToAuthForDelegation     : {0}" -f $u.TrustedToAuthForDelegation) -ForegroundColor DarkGray
Write-Host (" - msDS-AllowedToDelegateTo count : {0}" -f $allowedToDel.Count) -ForegroundColor DarkGray
if ($u.AccountNotDelegated) { Write-Good "AccountNotDelegated: True (cannot be delegated by others)" } else { Write-Warn "AccountNotDelegated: False (consider setting True)" }
if ($protectedUsers) { Write-Good "Protected Users   : Member" } else { Write-Info "Protected Users   : Not a member" }
if ($adminSD) { Write-Info "AdminSDHolder     : adminCount=1 (protected)" } else { Write-Info "AdminSDHolder     : adminCount=0" }
if ($inPriv.Count -gt 0) { Write-Warn ("Privileged groups : {0}" -f ($inPriv -join ', ')) } else { Write-Good "Privileged groups : None of the high-privilege sets" }

Write-Host ""
if ($spns.Count -gt 0) { Write-Info "SPNs:"; $spns | ForEach-Object { Write-Host ("  - {0}" -f $_) -ForegroundColor Gray } }
else { Write-Info "SPNs: (none)" }
if ($allowedToDel.Count -gt 0) { Write-Host ""; Write-Info "Constrained delegation targets:"; $allowedToDel | ForEach-Object { Write-Host ("  - {0}" -f $_) -ForegroundColor Gray } }

# ---------- LastLogon ----------
Write-Host ""; Write-Host "Activity (LastLogon per DC)" -ForegroundColor Yellow
$lastLogonPerDC = @()
$dcList = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
foreach ($dc in $dcList) {
  try {
    $ll = (Get-ADUser $u.SamAccountName -Server $dc -Properties LastLogon -ErrorAction Stop).LastLogon
    if ($ll -and $ll -gt 0) {
      $dt = [DateTime]::FromFileTime($ll)
      $lastLogonPerDC += [PSCustomObject]@{ DC = $dc; LastLogon = $dt }
    }
  } catch {}
}
if ($lastLogonPerDC.Count -gt 0) {
  $lastLogonPerDC | Sort-Object LastLogon -Descending | Format-Table -AutoSize
} else {
  Write-Host "No LastLogon recorded across DCs." -ForegroundColor DarkGray
}

# ---------- Decide whether to scan logs ----------
$cutoff = (Get-Date).AddDays(-1 * $Days)
$mostRecent = $null
if ($lastLogonPerDC.Count -gt 0) { $mostRecent = ($lastLogonPerDC | Sort-Object LastLogon -Descending | Select-Object -First 1).LastLogon }
$shouldScanAuth = $true
if (-not $mostRecent -or $mostRecent -lt $cutoff) {
    Write-Host ""
    $logonDisplay = if ($mostRecent) { $mostRecent } else { 'None' }
    Write-Host ("Skipping Security log scan: most recent logon ({0}) is older than lookback window ({1} days)." -f $logonDisplay, $Days) -ForegroundColor DarkGray
    $shouldScanAuth = $false
}


# ---------- Authentication activity ----------
$authRows = @()
$ntlmRows = @()
if ($shouldScanAuth) {
  $msWindow = [int]($Days * 24 * 60 * 60 * 1000)
  $userName = $u.SamAccountName
  foreach ($dc in $dcList) {
    try {
      $xpath4624 = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $msWindow]]] and *[EventData[Data[@Name='TargetUserName']='$userName']]"
      $ev4624 = Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath4624 -MaxEvents 400 -ErrorAction Stop
      foreach ($e in $ev4624) {
        $xml = [xml]$e.ToXml()
        $authRows += [pscustomobject]@{
          DC          = $dc
          Time        = $e.TimeCreated
          AuthPackage = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'AuthenticationPackageName'}).'#text'
          LogonType   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
          Workstation = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'WorkstationName'}).'#text'
          SourceIP    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        }
      }

      $xpath4776 = "*[System[(EventID=4776) and TimeCreated[timediff(@SystemTime) <= $msWindow]]] and *[EventData[Data[@Name='Account Name']='$userName']]"
      $ev4776 = Get-WinEvent -ComputerName $dc -LogName Security -FilterXPath $xpath4776 -MaxEvents 400 -ErrorAction Stop
      foreach ($e in $ev4776) {
        $xml = [xml]$e.ToXml()
        $ntlmRows += [pscustomobject]@{
          DC          = $dc
          Time        = $e.TimeCreated
          Workstation = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Workstation Name'}).'#text'
          Status      = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Status'}).'#text'
          Package     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Authentication Package'}).'#text'
        }
      }
    } catch {}
  }

  if ($authRows.Count -gt 0) {
    Write-Host ""; Write-Host "4624 successful logons:" -ForegroundColor Cyan
    $authRows | Sort-Object Time -Descending | Select-Object -First 30 |
      Format-Table Time,DC,AuthPackage,LogonType,Workstation,SourceIP -AutoSize
    if ($authRows.Where({ $_.AuthPackage -eq 'NTLM' }).Count -gt 0 -or $ntlmRows.Count -gt 0) {
      Write-Warn "NTLM usage detected in the lookback window."
    } else {
      Write-Good "Kerberos-only authentication observed."
    }
  } else {
    Write-Host "No 4624 logons found in the lookback window." -ForegroundColor DarkGray
  }

  if ($ntlmRows.Count -gt 0) {
    Write-Host ""; Write-Host "4776 NTLM validations:" -ForegroundColor Cyan
    $ntlmRows | Sort-Object Time -Descending | Select-Object -First 30 |
      Format-Table Time,DC,Package,Status,Workstation -AutoSize
  }
}

# ---------- Optional server scan ----------
if ($ScanServers) {
  Write-Host ""; Write-Host "Server-side usage scan (services / scheduled tasks / sessions)" -ForegroundColor Yellow
  $compParams = @{ Filter = $ComputerFilter; Properties = @('Name') }
  if ($ComputerSearchBase) { $compParams['SearchBase'] = $ComputerSearchBase }
  $targets = @(); try { $targets = Get-ADComputer @compParams | Select-Object -ExpandProperty Name } catch {}
  if ($targets.Count -eq 0) { Write-Warn "No servers found; skipping remote scan." }
  else {
    $sb = {
      param($Acct)
      $out = [ordered]@{ Computer=$env:COMPUTERNAME; Services=@(); Tasks=@(); Sessions=@() }
      try {
        $svcs = Get-WmiObject Win32_Service -ErrorAction Stop | Where-Object { $_.StartName -match ('(?i)^{0}$' -f [regex]::Escape($Acct)) }
        foreach ($s in $svcs) { $out.Services += ("{0} (StartMode={1},State={2})" -f $s.Name,$s.StartMode,$s.State) }
      } catch {}
      try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.Principal.UserId -match ('(?i)^{0}$' -f [regex]::Escape($Acct)) }
        foreach ($t in $tasks) { $out.Tasks += ("{0}{1}" -f $t.TaskPath,$t.TaskName) }
      } catch {}
      try {
        $q = (quser 2>$null)
        if ($q) { foreach ($l in $q) { if ($l -match ('(?i)\b{0}\b' -f [regex]::Escape($Acct))) { $out.Sessions += $l.Trim() } } }
      } catch {}
      return $out
    }
    $results = @(); foreach ($c in $targets) { try { $r=Invoke-Command -ComputerName $c -ScriptBlock $sb -ArgumentList $u.SamAccountName -ErrorAction Stop; $results+=$r } catch {} }
    if ($results.Count -gt 0) {
      $hits=$false
      foreach ($r in $results) {
        $any=(($r.Services.Count -gt 0)-or($r.Tasks.Count -gt 0)-or($r.Sessions.Count -gt 0))
        if ($any) {
          $hits=$true; Write-Info $r.Computer
          if ($r.Services.Count -gt 0){Write-Host "  Services:"-ForegroundColor Gray; $r.Services|%{Write-Host ("    - {0}"-f $_)-ForegroundColor Gray}}
          if ($r.Tasks.Count -gt 0){Write-Host "  Tasks:"-ForegroundColor Gray; $r.Tasks|%{Write-Host ("    - {0}"-f $_)-ForegroundColor Gray}}
          if ($r.Sessions.Count -gt 0){Write-Host "  Sessions:"-ForegroundColor Gray; $r.Sessions|%{Write-Host ("    - {0}"-f $_)-ForegroundColor Gray}}
        }
      }
      if (-not $hits){Write-Good "No services, tasks, or sessions using this account on scanned computers."}
    } else { Write-Host "No remote scan results." -ForegroundColor DarkGray }
  }
}

# ---------- Summary ----------
Write-Host ""; Write-Host "Summary Recommendations" -ForegroundColor Yellow
Write-Host "-------------------------" -ForegroundColor Yellow
if ($delegationType -eq 'None') { Write-Good "• No delegation detected – ideal." }
elseif ($delegationType -eq 'Unconstrained') { Write-Bad "• Unconstrained delegation – eliminate immediately." }
else { Write-Warn "• Constrained delegation present – verify necessity and scope." }
if (-not $u.AccountNotDelegated) { Write-Warn "• AccountNotDelegated is False – consider enabling for defense-in-depth." }
if ($inPriv.Count -gt 0) { Write-Warn "• High-privilege account – use only for elevated tasks; rotate or disable if unused." }
if (-not $protectedUsers) { Write-Info "• Consider Protected Users if Kerberos-only." }
if ($mostRecent -and $mostRecent -lt (Get-Date).AddMonths(-6)) { Write-Info ("• Last logon {0:yyyy-MM-dd} – account appears dormant; verify need or disable." -f $mostRecent) }

Write-Host ""; Write-Host "Done." -ForegroundColor Green
