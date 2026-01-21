<#
MODNI 20251103
Scan AD for direct delegations with orphaned SIDs.

Behavior:
- If -SIDs is provided: report direct delegations for those SIDs (mark if orphaned).
- If -SIDs is empty: report all direct delegations where the SID is orphaned (unresolvable).
- Shows only "interesting" rights by default (GenericAll, WriteDacl, etc.) like PingCastle.
- Excludes any path that contains ",CN=Policies," by default (use -ExcludePolicies:$false to include).
- Outputs: on-screen summary (one line per SID+object) and detailed CSV (one row per ACE).

ISE-safe (Windows PowerShell 5.1). Native methods only.
#>

[CmdletBinding()]
param(
  [string[]]$SIDs = @(),                 # Empty = find ALL orphaned SIDs; Non-empty = restrict to these SIDs
  [string]$SearchBase = $null,           # Default = domain DN
  [switch]$IncludeContainers = $true,    # Include CN=Users, CN=Computers, and other 'container' objects
  [switch]$IncludeDomainRoot = $false,   # Also scan the domain root object
  [switch]$InterestingOnly = $true,      # Keep only "interesting" rights like PingCastle
  [switch]$ExcludePolicies = $true       # Default: exclude any DN containing ",CN=Policies,"
)

# ---------- Setup ----------
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

if (-not $SearchBase) {
  try { $domainDN = (Get-ADDomain).DistinguishedName }
  catch { throw "Cannot resolve domain DN. RSAT AD PowerShell required." }
  $SearchBase = $domainDN
} else {
  try { $domainDN = (Get-ADDomain).DistinguishedName } catch { $domainDN = $null }
}

$OutDir = 'C:\ITM8\P-UnknownDelegation'
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
$csv = Join-Path $OutDir "AD_OrphanedSID_DirectDelegations_${ts}.csv"

Write-Host "Mode:" -ForegroundColor Yellow
if ($SIDs.Count -gt 0) { Write-Host "  Scan for specific SIDs (and mark if orphaned)" -ForegroundColor Yellow }
else { Write-Host "  Scan for ALL orphaned SIDs" -ForegroundColor Yellow }
Write-Host "SearchBase = $SearchBase"
if ($IncludeContainers) { Write-Host "IncludeContainers = True" }
if ($IncludeDomainRoot) { Write-Host "IncludeDomainRoot = True" }
if ($InterestingOnly)  { Write-Host "Filter = Interesting rights only" }
if ($ExcludePolicies)  { Write-Host "Exclude CN=Policies = True" }

# ---------- Helpers ----------
$InterestingRights = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','CreateChild','DeleteChild','ExtendedRight','WriteProperty')

function Get-RIDTypeHint {
  param([string]$Sid)
  if ($Sid -like 'S-1-5-32-*') { return 'Builtin (local)' }
  if ($Sid -notmatch '^S-1-5-21-(\d+-){2}\d+-(\d+)$') { return 'Not domain SID' }
  $rid = [int]$Matches[2]
  switch ($rid) {
    500 { 'Built-in: Administrator' }
    501 { 'Built-in: Guest' }
    502 { 'Built-in: KRBTGT' }
    512 { 'Built-in: Domain Admins' }
    513 { 'Built-in: Domain Users' }
    514 { 'Built-in: Domain Guests' }
    515 { 'Built-in: Domain Computers' }
    516 { 'Built-in: Domain Controllers' }
    517 { 'Built-in: Cert Publishers' }
    518 { 'Built-in: Schema Admins' }
    519 { 'Built-in: Enterprise Admins' }
    520 { 'Built-in: GPO Creator Owners' }
    521 { 'Built-in: RODC Group' }
    default { 'Regular domain principal (class unknown)' }
  }
}

# IdentityReference -> SID translator with cache
$IdToSidCache = @{}
function Get-SID-FromIdentity {
  param([System.Security.Principal.IdentityReference]$IdRef)
  if (-not $IdRef) { return $null }
  $key = $IdRef.Value
  if ($IdToSidCache.ContainsKey($key)) { return $IdToSidCache[$key] }
  if ($key -and $key.StartsWith('S-')) { $IdToSidCache[$key] = $key; return $key }
  try {
    $sidVal = $IdRef.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $IdToSidCache[$key] = $sidVal
    return $sidVal
  } catch { $IdToSidCache[$key] = $null; return $null }
}

function Test-OrphanedSID {
  param([string]$SidString)
  try {
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SidString)
    $null   = $sidObj.Translate([System.Security.Principal.NTAccount])
    return $false
  } catch { return $true }
}

# ---------- Target discovery ----------
$targets = New-Object System.Collections.Generic.List[object]
try {
  $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -SearchScope Subtree -Properties objectClass -EA SilentlyContinue
  foreach ($ou in $ous) { $targets.Add([pscustomobject]@{ DN = $ou.DistinguishedName; Type = 'OU' }) }
} catch {}

if ($IncludeContainers) {
  try {
    $cons = Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $SearchBase -SearchScope Subtree -Properties objectClass -EA SilentlyContinue
    foreach ($c in $cons) { $targets.Add([pscustomobject]@{ DN = $c.DistinguishedName; Type = 'Container' }) }
  } catch {}
}

if ($IncludeDomainRoot -and $domainDN) { $targets.Add([pscustomobject]@{ DN = $domainDN; Type = 'Domain' }) }

# Filter out *any* DN that contains ",CN=Policies," when switch is enabled (case-insensitive)
if ($ExcludePolicies) {
  $targets = $targets | Where-Object { $_.DN -notmatch '(?i),CN=Policies,' }
}

$targets = $targets | Sort-Object DN -Unique
$targetCount = ($targets | Measure-Object).Count
Write-Host ("Targets to scan = {0}" -f $targetCount)

# For specific-SID mode, prep a fast lookup set
$SidSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($s in $SIDs) { [void]$SidSet.Add($s) }

# ---------- Scan ----------
$rows = New-Object System.Collections.Generic.List[object]
$idx = 0
$lastTick = [Environment]::TickCount

foreach ($t in $targets) {
  $idx++
  $pct = [int](($idx / [math]::Max($targetCount,1)) * 100)
  if (([Environment]::TickCount - $lastTick) -ge 120) {
    Write-Progress -Activity "Scanning direct ACEs" -Status "$idx / $targetCount" -PercentComplete $pct
    $lastTick = [Environment]::TickCount
  }

  try { $acl = Get-Acl -Path ("AD:{0}" -f $t.DN) } catch { continue }
  if (-not $acl -or -not $acl.Access) { continue }

  foreach ($ace in $acl.Access) {
    # Only direct (non-inherited)
    $isInherited = $false
    try { if ($ace.IsInherited) { $isInherited = $true } } catch {}
    if ($isInherited) { continue }

    # Optional "interesting rights" filter early
    if ($InterestingOnly) {
      $r = $ace.ActiveDirectoryRights.ToString()
      $interestingHit = $false
      foreach ($ir in $InterestingRights) { if ($r -like "*$ir*") { $interestingHit = $true; break } }
      if (-not $interestingHit) { continue }
    }

    $aceSid = Get-SID-FromIdentity -IdRef $ace.IdentityReference
    if (-not $aceSid) { continue }

    # Mode selection
    $keep = $false
    $isOrphan = $true

    if ($SIDs.Count -gt 0) {
      if ($SidSet.Contains($aceSid)) {
        $isOrphan = Test-OrphanedSID -SidString $aceSid
        $keep = $true
      }
    } else {
      # Orphan-scan mode
      $isOrphan = Test-OrphanedSID -SidString $aceSid
      if ($isOrphan) { $keep = $true }
    }

    if (-not $keep) { continue }

    # Best-effort resolved name (only if not orphaned)
    $resolved = '(not resolvable)'
    if (-not $isOrphan) {
      try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($aceSid)
        $nt     = $sidObj.Translate([System.Security.Principal.NTAccount])
        $resolved = $nt.Value
      } catch { $resolved = '(not resolvable)' }
    }

    # Skip any Policy container result at the row level too (belt-and-suspenders)
    if ($ExcludePolicies -and ($t.DN -match '(?i),CN=Policies,')) { continue }

    $rows.Add([pscustomobject]@{
      SID          = $aceSid
      Orphaned     = $isOrphan
      ResolvedTo   = $resolved
      RIDTypeHint  = (Get-RIDTypeHint $aceSid)
      TargetDN     = $t.DN
      TargetType   = $t.Type
      Rights       = $ace.ActiveDirectoryRights.ToString()
      AccessType   = $ace.AccessControlType.ToString()
      Inherited    = $false
    })
  }
}

# Ensure we remove any leftover CN=Policies rows if switch is enabled (post-scan safety)
if ($ExcludePolicies) {
  $rows = $rows | Where-Object { $_.TargetDN -notmatch '(?i),CN=Policies,' }
}

try { Write-Progress -Activity "Scanning direct ACEs" -Completed } catch {}

# ---------- Output ----------
if ($rows.Count -eq 0) {
  if ($SIDs.Count -gt 0) {
    Write-Host "✅ No DIRECT delegations found for the specified SID(s) under the scanned scope."
  } else {
    Write-Host "✅ No DIRECT delegations with orphaned SIDs found under the scanned scope."
  }
  return
}

$sortedRows = $rows | Sort-Object SID, TargetDN, Rights
$sortedRows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host ("CSV saved => {0}" -f $csv) -ForegroundColor Yellow

# On-screen summary: one line per SID+TargetDN with union of rights
$summary = $sortedRows | Group-Object SID, TargetDN | ForEach-Object {
  $any = $_.Group | Select-Object -First 1
  $rightsUnion = ($_.Group.Rights | Sort-Object -Unique) -join ', '
  [pscustomobject]@{
    SID         = $any.SID
    Orphaned    = $any.Orphaned
    ResolvedTo  = $any.ResolvedTo
    RIDTypeHint = $any.RIDTypeHint
    TargetDN    = $any.TargetDN
    TargetType  = $any.TargetType
    Rights      = $rightsUnion
  }
}

$summary = $summary | Sort-Object -Property @{Expression='Orphaned';Descending=$true}, SID, TargetDN

Write-Host ""
Write-Host "=== Summary (direct delegations)" -ForegroundColor Yellow
$summary | Format-Table -AutoSize -Wrap
