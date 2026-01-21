<#
MODNI 20251105
Title: A-DnsZoneAUCreateChild – AUDIT ONLY + grouped remediation tables + step-by-step plan (ISE-safe, null-proof)

What it does
------------
• Audits AD-integrated DNS zones for risky ACLs:
  - Principals: "NT AUTHORITY\Authenticated Users", "Everyone"
  - Rights: CreateChild (incl. Create dnsNode) or GenericAll
  - Non-inherited ACEs on dnsZone (dnsNode/AnyChildClass)
• Writes CSV + transcript under C:\ITM8\A-DnsZoneAUCreateChild\<timestamp>\
• Writes RemediationPlan_<timestamp>.txt with:
  - Step-by-step ADSI Edit fix instructions
  - How to back up zone ACLs first (two methods)
  - Grouped recommendations with neat tables
  - Exact ADSI DNs per group
  - Safe follow-ups (Secure-only, DHCP creds, tests, rollback snippet)

No changes are made.
#>

[CmdletBinding()]
param(
  [string]$OutRoot = 'C:\ITM8\A-DnsZoneAUCreateChild'
)

# --- helpers ---
function Resolve-SchemaGuidName {
  param([Guid]$Guid)
  try {
    $rootDse  = [ADSI]"LDAP://RootDSE"
    $schemaNC = $rootDse.schemaNamingContext
    $ds = New-Object System.DirectoryServices.DirectorySearcher
    $ds.SearchRoot = [ADSI]("LDAP://$schemaNC")
    $ds.Filter = "(objectClass=classSchema)"
    $ds.PageSize = 1000
    foreach ($r in $ds.FindAll()) {
      $de = $r.GetDirectoryEntry()
      if ($de.Properties['schemaIDGUID'].Count -gt 0) {
        $bytes = $de.Properties['schemaIDGUID'][0].ToByteArray()
        $g = New-Object Guid ($bytes)
        if ($g -eq $Guid) { return ($de.Properties['lDAPDisplayName'][0]) }
      }
    }
  } catch { }
  return $Guid.ToString()
}

function Get-DnsNodeGuid {
  try {
    $rootDse  = [ADSI]"LDAP://RootDSE"
    $schemaNC = $rootDse.schemaNamingContext
    $ds = New-Object System.DirectoryServices.DirectorySearcher
    $ds.SearchRoot = [ADSI]("LDAP://$schemaNC")
    $ds.Filter = "(lDAPDisplayName=dnsNode)"
    $ds.PropertiesToLoad.Add("schemaIDGUID") | Out-Null
    $one = $ds.FindOne()
    if ($one -and $one.Properties['schemaidguid']) {
      return (New-Object Guid ($one.Properties['schemaidguid'][0]))
    }
  } catch { }
  return [Guid]::Empty
}

function Get-ZoneNameFromDN { param([string]$dn)
  if ($dn -match '^CN=([^,]+),') { return ($matches[1] -replace '\\,', ',') }
  return $dn
}

# --- output prep ---
$ts     = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path $OutRoot $ts
if (!(Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }
$csv    = Join-Path $OutDir "A-DnsZoneAUCreateChild_${ts}.csv"
$log    = Join-Path $OutDir "transcript_${ts}.txt"
$plan   = Join-Path $OutDir "RemediationPlan_${ts}.txt"
Start-Transcript -Path $log -Force | Out-Null

Write-Host "A-DnsZoneAUCreateChild – audit starting..." -ForegroundColor Yellow
Write-Host "Output folder: $OutDir"
if ($PSVersionTable -and $PSVersionTable.PSVersion) {
  Write-Host ("PowerShell version: {0}" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray
}

Write-Host "Running with these settings:" -ForegroundColor Yellow
Write-Host ("  OutRoot               : {0}" -f $OutRoot)
Write-Host "  Mode                  : Audit only (no changes)" -ForegroundColor DarkGray
Write-Host ""

# --- contexts ---
$root         = [ADSI]"LDAP://RootDSE"
$domainNC     = $root.defaultNamingContext
$forestRootDN = ($root.configurationNamingContext -replace '^CN=Configuration,','')
$searchBases  = @(
  "CN=MicrosoftDNS,DC=DomainDnsZones,$domainNC",
  "CN=MicrosoftDNS,DC=ForestDnsZones,$forestRootDN",
  "CN=MicrosoftDNS,CN=System,$domainNC"
)

$dnsNodeGuid  = Get-DnsNodeGuid
$riskAccounts = @('NT AUTHORITY\Authenticated Users','Everyone')

# --- audit (pipeline, null-proof; no +=, no .Add()) ---
$findings = foreach ($base in $searchBases) {
  $zones = $null
  try {
    $sr = New-Object System.DirectoryServices.DirectorySearcher
    $sr.SearchRoot = [ADSI]("LDAP://$base")
    $sr.Filter   = "(objectClass=dnsZone)"
    $sr.PageSize = 1000
    $zones = $sr.FindAll()
  } catch {
    Write-Host "Warning: cannot enumerate zones under $base. $_" -ForegroundColor DarkYellow
    continue
  }

  foreach ($z in $zones) {
    $dn       = $z.Path -replace '^LDAP://',''
    $zoneDE   = $z.GetDirectoryEntry()
    $zoneName = Get-ZoneNameFromDN -dn $dn

    $acl = $null
    try { $acl = $zoneDE.ObjectSecurity } catch {
      Write-Host "Failed to read ACL for $zoneName ($dn). $_" -ForegroundColor Red
      continue
    }

    $rules = $acl.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])

    foreach ($r in $rules) {
      if ($r -eq $null) { continue }
      if ($r.IsInherited) { continue }

      $id = $null
      try { $id = $r.IdentityReference.Value } catch { $id = $null }
      if (-not $id) { continue }
      if ($riskAccounts -notcontains $id) { continue }

      # rights and checks (null-safe)
      $rights = $null
      try { $rights = $r.ActiveDirectoryRights } catch { $rights = $null }
      $isCreateChild = $false
      $isGenericAll  = $false
      if ($rights -ne $null) {
        $isCreateChild = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0)
        $isGenericAll  = (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)  -ne 0)
      }
      if (-not ($isCreateChild -or $isGenericAll)) { continue }

      # ObjectType GUID (null-safe)
      $objTypeGuid = [Guid]::Empty
      try {
        if ($r.ObjectType -ne $null) {
          $objTypeGuid = [Guid]$r.ObjectType
        }
      } catch { $objTypeGuid = [Guid]::Empty }

      $isDnsNodeOrAny = ($objTypeGuid -eq [Guid]::Empty) -or ($objTypeGuid -eq $dnsNodeGuid)
      if (-not $isDnsNodeOrAny -and -not $isGenericAll) { continue }

      # Strings (null-safe, no .ToString() calls)
      $rightsStr = if ($rights -ne $null) { "$rights" } else { "" }
      $ruleType  = ""
      try { if ($r.AceType -ne $null) { $ruleType = "$($r.AceType)" } } catch { $ruleType = "" }
      $objectTypeName = if ($objTypeGuid -eq [Guid]::Empty) { 'AnyChildClass' } else { Resolve-SchemaGuidName $objTypeGuid }

      try {
        New-Object -TypeName PSObject -Property @{
          ZoneName       = $zoneName
          ZoneDN         = $dn
          PartitionBase  = $base
          Identity       = $id
          Rights         = $rightsStr
          ObjectTypeGuid = $objTypeGuid
          ObjectTypeName = $objectTypeName
          Inherited      = $r.IsInherited
          RuleType       = $ruleType
        }
      } catch {
        Write-Host "Skipping one ACE on $zoneName due to emit error: $($_.Exception.Message)" -ForegroundColor DarkYellow
        continue
      }
    }
  }
}

# --- export CSV ---
if (-not $findings -or $findings.Count -eq 0) {
  Write-Host "No risky ACEs found (Authenticated Users/Everyone with CreateChild/GenericAll on dnsZone)." -ForegroundColor Green
  Stop-Transcript | Out-Null
  return
} else {
  $findings | Sort-Object ZoneName, Identity |
    Export-Csv -NoTypeInformation -Path $csv -Encoding UTF8
  Write-Host "Findings exported to: $csv" -ForegroundColor Yellow
}

# === Grouped remediation view ===
# Normalize into “fix groups” keyed by Identity + RightCategory + ObjectTypeGroup
$fixRows = foreach ($f in $findings) {
  $rightCategory = if ($f.Rights -match 'GenericAll') { 'GenericAll' }
                   elseif ($f.Rights -match 'CreateChild') { 'CreateChild' }
                   else { $null }
  if (-not $rightCategory) { continue }

  $objGroup = if ($f.ObjectTypeName -eq 'AnyChildClass' -or $f.ObjectTypeGuid -eq [Guid]::Empty) { 'dnsNode/AnyChildClass' }
              elseif ($f.ObjectTypeName -match '^dnsNode$') { 'dnsNode/AnyChildClass' }
              else { $f.ObjectTypeName }

  New-Object -TypeName PSObject -Property @{
    ZoneName        = $f.ZoneName
    ZoneDN          = $f.ZoneDN
    PartitionBase   = $f.PartitionBase
    Identity        = $f.Identity
    RightCategory   = $rightCategory
    ObjectTypeGroup = $objGroup
  }
}

# Build groups
$groups = $fixRows | Group-Object Identity, RightCategory, ObjectTypeGroup | Sort-Object Count -Descending

# --- Write step-by-step guidance header in plan file ---
@"
Remediation plan generated: $(Get-Date)
============================================================
Rule: A-DnsZoneAUCreateChild – Remove risky ACEs (Authenticated Users/Everyone with CreateChild or GenericAll)

BEFORE YOU CHANGE ANYTHING – BACK UP THE ZONE ACLs
--------------------------------------------------
Option A (quick screenshots):
  1) DNS Manager (dnsmgmt.msc) → Zone → Properties → Security → Advanced → View.
  2) Take screenshots of the permission entries (store them alongside this plan).

Option B (PowerShell SDDL export – recommended):
  # Paste this in an elevated PS on a DC/member server with RSAT/PowerShell:
  `$zoneDNs = @(
$( ($fixRows.ZoneDN | Sort-Object -Unique | ForEach-Object { '    "' + $_ + '"' }) -join ",`n")
  )
  `$out = '$($OutDir -replace "\\\\","\\")\\SDDL_Backups_${ts}.csv'
  "ZoneDN,SDDL" | Out-File -FilePath `$out -Encoding UTF8
  foreach (`$dn in `$zoneDNs) {
    try {
      `$de  = [ADSI]("LDAP://`$dn")
      `$sd  = `$de.ObjectSecurity
      `$sddl= `$sd.GetSecurityDescriptorSddlForm('All')
      "`$dn,`"$sddl`"" | Out-File -FilePath `$out -Append -Encoding UTF8
    } catch {
      "`$dn,""ERROR: `$($_.Exception.Message)""" | Out-File -FilePath `$out -Append -Encoding UTF8
    }
  }
  Write-Host "Saved SDDL backups to: `$out"

HOW TO FIX THE ACEs IN ADSI EDIT (GUI)
--------------------------------------
1) Open ADSI Edit (adsiedit.msc).
2) Connect to each of the following naming contexts when needed:
   • DomainDnsZones: CN=MicrosoftDNS,DC=DomainDnsZones,<your domain DN>
   • ForestDnsZones: CN=MicrosoftDNS,DC=ForestDnsZones,<your forest root DN>
   • Legacy:        CN=MicrosoftDNS,CN=System,<your domain DN>
3) Under CN=MicrosoftDNS in the relevant context, locate the zone object:
   • Example: CN=_msdcs.example.com, CN=MicrosoftDNS, DC=ForestDnsZones, <forest root>
   • Example: CN=example.com,       CN=MicrosoftDNS, DC=DomainDnsZones, <domain DN>
4) Right-click the zone → Properties → Security → Advanced.
5) Identify and remove ONLY explicit (non-inherited) ACEs where:
   • Principal = “NT AUTHORITY\\Authenticated Users” or “Everyone”
   • Permission shows “Create all child objects” or “Create dnsNode objects”, or “Full control”
   • Scope typically “This object only” or “This object and child objects”
   • DO NOT remove read/visibility permissions (GenericRead), and DO NOT remove inherited entries.
6) Apply and OK.

AFTER FIXING – HARDEN DYNAMIC UPDATES & DHCP
--------------------------------------------
• DNS Manager → Zone → Properties → General → Dynamic updates: set to “Secure only”.
• DHCP (if used) → Server/IPv4 → Properties → DNS tab → Credentials:
  - Configure a dedicated low-priv domain user (e.g., svc_dhcp_dnsupdate) for dynamic updates.

TEST & VERIFY
-------------
• As a normal domain user (non-admin), try adding a new A record in the zone → should FAIL.
• Renew a DHCP client lease → host/PTR should still update (via DHCP credentials).
• Re-run this audit → groups for the fixed ACEs should be gone.

ROLLBACK (if needed)
--------------------
• If you exported SDDL (Option B), you can restore it for a given zone DN:
  `$dn = "<Zone DN from the CSV>"; `$sddl = "<Saved SDDL string>"
  `$de = [ADSI]("LDAP://`$dn")
  `$sd = `$de.ObjectSecurity
  `$sd.SetSecurityDescriptorSddlForm(`$sddl)
  `$de.ObjectSecurity = `$sd
  `$de.CommitChanges()
============================================================

"@ | Out-File -FilePath $plan -Encoding UTF8

# --- Grouped remediation output (screen + file) ---
Write-Host ""
Write-Host "=== Grouped remediation (one recommendation per ACE-type) ===" -ForegroundColor Yellow

foreach ($g in $groups) {
  $sample = $g.Group | Select-Object -First 1
  $identity = $sample.Identity
  $rightCat = $sample.RightCategory
  $objGroup = $sample.ObjectTypeGroup

  $severity = if ($rightCat -eq 'GenericAll') { '[SEVERE]' } else { '[HIGH]' }
  $sevColor = if ($rightCat -eq 'GenericAll') { 'Red' } else { 'Yellow' }

  $recommendation =
    if ($rightCat -eq 'GenericAll') {
      "Remove explicit ACE: $identity has GenericAll on dnsZone ($objGroup). Keep read rights if needed."
    } else {
      "Remove explicit ACE: $identity has CreateChild on dnsZone ($objGroup). Keep read rights if needed."
    }

  # Table rows: distinct zones under this group
  $rows = $g.Group | Sort-Object ZoneName, PartitionBase |
          Select-Object @{n='Zone';e={$_.ZoneName}},
                        @{n='Partition';e={
                          if ($_.PartitionBase -like 'CN=MicrosoftDNS,DC=DomainDnsZones*') {'DomainDnsZones'}
                          elseif ($_.PartitionBase -like 'CN=MicrosoftDNS,DC=ForestDnsZones*') {'ForestDnsZones'}
                          else {'CN=System'}
                        }}

  # Also prepare ADSI DNs list for the plan file
  $dnRows = $g.Group | Sort-Object ZoneDN -Unique | Select-Object -ExpandProperty ZoneDN

  # Screen output
  Write-Host ""
  Write-Host ("{0}  {1}" -f $severity, $recommendation) -ForegroundColor $sevColor
  $rows | Format-Table -AutoSize | Out-Host

  # Append to plan file (plain text)
  Add-Content -Path $plan -Value ""
  Add-Content -Path $plan -Value ("{0}  {1}" -f $severity, $recommendation)
  $rows | Out-String | Add-Content -Path $plan
  Add-Content -Path $plan -Value "ADSI paths for this group:"
  foreach ($dn in $dnRows) { Add-Content -Path $plan -Value ("  - {0}" -f $dn) }
}

# --- Global follow-up summary (also append to plan) ---
$global = @"
============================================================
GLOBAL FOLLOW-UP (manual, safe)
• Remove only the explicit, non-inherited ACEs listed in each group above.
• Ensure Dynamic updates = Secure only on all AD-integrated zones.
• Configure DHCP dynamic update credentials (dedicated low-priv domain user).
• Re-run this audit and verify the groups are gone.
============================================================
"@
Write-Host ""
Write-Host "=== Global follow-up (manual, safe) ===" -ForegroundColor Yellow
Write-Host "  • Remove explicit, non-inherited ACEs per group recommendation." -ForegroundColor Yellow
Write-Host "  • DNS zones: set Dynamic updates = Secure only." -ForegroundColor Yellow
Write-Host "  • DHCP: configure DNS update credentials (dedicated low-priv domain user)." -ForegroundColor Yellow
Write-Host "  • Re-run this audit and verify groups disappear." -ForegroundColor Yellow
Add-Content -Path $plan -Value $global

Write-Host ""
Write-Host ("Saved remediation plan: {0}" -f $plan) -ForegroundColor Yellow
Write-Host "Audit complete." -ForegroundColor Yellow
Stop-Transcript | Out-Null
