<# 
MODNI 2025-08-21 — PingCastle S-Duplicate Helper

Summary
 • Detects duplicate sAMAccountName (NTLM logon names)
 • Detects duplicate userPrincipalName (UPN / modern logon names)
 • Detects conflict objects (CNF \0ACNF: entries)
    - CNF = "Conflict" objects created by AD when two objects share the same CN/DN
    - AD appends "\0ACNF:<GUID>" to the duplicate copy
    - Often due to replication collisions or restores; review and clean if unintended
 • Prints results in clear tables
 • Exports summary + per-object CSVs to C:\itm8\S-Duplicate
 • Generates a commented cleanup draft (Remove-DuplicateIdentities.ps1)
 • Uses only native AD cmdlets (no external modules)
 • Makes no changes by default — all cleanup lines are commented

 Important Notes:
 • If the CNF objects correspond to PAM (Privileged Access Management) accounts that you actively use.
 • That’s not abnormal — it’s expected when Microsoft Identity Manager (MIM) / PAM / JIT is deployed.
#>

[CmdletBinding()]
param(
  # Output directory (fixed per your request)
  [string]$OutDir = "C:\itm8\S-Duplicate",

  # If a DN contains this substring, we consider it part of the PAM/JIT area
  [string]$PamOuSubstring = "OU=JustInTimeAccess"
)

# --- Setup --------------------------------------------------------------------
$null = New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction SilentlyContinue

function Write-Header { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Yellow }

Write-Host "Collecting identity attributes from AD..." -ForegroundColor Cyan

# Pull objects that have either sAMAccountName or UPN
$props = 'sAMAccountName','userPrincipalName','objectClass','distinguishedName','whenCreated','cn'
$all = Get-ADObject -LDAPFilter '(|(sAMAccountName=*)(userPrincipalName=*))' -Properties $props

if (-not $all) {
  Write-Warning "No objects with sAMAccountName or userPrincipalName were found."
  return
}

# --- Helpers ------------------------------------------------------------------
function Normalize-ToLower {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value.ToLowerInvariant()
}

function Get-CnfBaseNameFromCN {
  param([string]$CnValue)
  if ([string]::IsNullOrWhiteSpace($CnValue)) { return $null }
  # CN looks like "Name\0ACNF:GUID" when in conflict
  $parts = $CnValue -split '\\0ACNF:'
  return $parts[0]
}

# --- Build rows ---------------------------------------------------------------
$rows = foreach ($o in $all) {
  [pscustomobject]@{
    SAM               = $o.sAMAccountName
    SAM_Norm          = Normalize-ToLower $o.sAMAccountName
    UPN               = $o.userPrincipalName
    UPN_Norm          = Normalize-ToLower $o.userPrincipalName
    CN                = $o.cn
    IsCNF             = ($o.cn -like '*\0ACNF:*')
    CNF_Base          = if ($o.cn -like '*\0ACNF:*') { Get-CnfBaseNameFromCN -CnValue $o.cn } else { $null }
    ObjectClass       = $o.objectClass
    DistinguishedName = $o.distinguishedName
    WhenCreated       = $o.whenCreated
  }
}

# --- Duplicate SAM ------------------------------------------------------------
$samDupGroups = $rows |
  Where-Object { $_.SAM_Norm } |
  Group-Object SAM_Norm |
  Where-Object { $_.Count -gt 1 }

if ($samDupGroups) {
  Write-Header "=== Duplicate sAMAccountName detected ==="
  $samSummary = foreach ($g in $samDupGroups) {
    $sorted  = $g.Group | Sort-Object -Property WhenCreated
    $keeper  = $sorted[0]
    $acctList = $g.Group | ForEach-Object { if ($_.SAM) { $_.SAM } else { $_.DistinguishedName } } | Sort-Object -Unique
    [pscustomobject]@{
      sAMAccountName = $g.Group[0].SAM
      Count          = $g.Count
      SuggestedKeep  = $keeper.DistinguishedName
      Accounts       = ($acctList -join ', ')
    }
  }
  $samSummary | Sort-Object -Property Count,sAMAccountName -Descending | Format-Table -AutoSize
} else {
  Write-Host "No duplicate sAMAccountName found. ✅" -ForegroundColor Green
}

# --- Duplicate UPN ------------------------------------------------------------
$upnDupGroups = $rows |
  Where-Object { $_.UPN_Norm } |
  Group-Object UPN_Norm |
  Where-Object { $_.Count -gt 1 }

$printedImportantNotesAfterUPN = $false

if ($upnDupGroups) {
  Write-Header "=== Duplicate userPrincipalName detected ==="
  $upnSummary = foreach ($g in $upnDupGroups) {
    $sorted  = $g.Group | Sort-Object -Property WhenCreated
    $keeper  = $sorted[0]
    $acctList = $g.Group | ForEach-Object { if ($_.SAM) { $_.SAM } else { $_.DistinguishedName } } | Sort-Object -Unique
    [pscustomobject]@{
      userPrincipalName = $g.Group[0].UPN
      Count             = $g.Count
      SuggestedKeep     = $keeper.DistinguishedName
      Accounts          = ($acctList -join ', ')
    }
  }

  $upnSummary | Sort-Object -Property Count,userPrincipalName -Descending | Format-Table -AutoSize

  # --- Conditional "Important Notes" directly after the UPN table -------------
  # Show only if any duplicate UPN group has members under the PAM OU path
  $hasPamUPNDuplicates = $false
  foreach ($g in $upnDupGroups) {
    if ($g.Group | Where-Object { $_.DistinguishedName -like "*$PamOuSubstring*" }) { $hasPamUPNDuplicates = $true; break }
  }

  if ($hasPamUPNDuplicates) {
    Write-Host "Important Notes:" -ForegroundColor Cyan
    Write-Host " • If the CNF objects correspond to PAM (Privileged Access Management) accounts that you actively use." -ForegroundColor Gray
    Write-Host " • That’s not abnormal — it’s expected when Microsoft Identity Manager (MIM) / PAM / JIT is deployed." -ForegroundColor Gray
    Write-Host ""
    $printedImportantNotesAfterUPN = $true
  }
} else {
  Write-Host "No duplicate userPrincipalName found. ✅" -ForegroundColor Green
}

# --- CNF conflicts ------------------------------------------------------------
$cnfObjects = $rows | Where-Object { $_.IsCNF }

if ($cnfObjects) {
  Write-Header "=== Conflict objects (\\0ACNF:) detected ==="
  $cnfSummary = $cnfObjects |
    Group-Object CNF_Base |
    ForEach-Object {
      $acctList = $_.Group | ForEach-Object { if ($_.SAM) { $_.SAM } else { $_.DistinguishedName } } | Sort-Object -Unique
      [pscustomobject]@{
        BaseName     = $_.Name
        Count        = $_.Count
        Accounts     = ($acctList -join ', ')
        ExampleCN    = ($_.Group | Select-Object -First 1).CN
      }
    }
  $cnfSummary | Sort-Object -Property Count,BaseName -Descending | Format-Table -AutoSize

  # If you also want the notes here (only when not shown after UPN), uncomment:
  # if (-not $printedImportantNotesAfterUPN) {
  #   Write-Host ""
  #   Write-Host "Important Notes:" -ForegroundColor Cyan
  #   Write-Host " • If the CNF objects correspond to PAM (Privileged Access Management) accounts that you actively use." -ForegroundColor Gray
  #   Write-Host " • That’s not abnormal — it’s expected when Microsoft Identity Manager (MIM) / PAM / JIT is deployed." -ForegroundColor Gray
  # }
} else {
  Write-Host "No CNF conflict objects found. ✅" -ForegroundColor Green
}

# --- Exports ------------------------------------------------------------------
$csvSamSummary = Join-Path $OutDir 'DuplicateSAM.csv'
$csvSamDetail  = Join-Path $OutDir 'DuplicateSAM-PerObject.csv'
$csvUpnSummary = Join-Path $OutDir 'DuplicateUPN.csv'
$csvUpnDetail  = Join-Path $OutDir 'DuplicateUPN-PerObject.csv'
$csvCnfSummary = Join-Path $OutDir 'CNFConflicts.csv'
$csvCnfDetail  = Join-Path $OutDir 'CNFConflicts-PerObject.csv'

if ($samDupGroups) {
  $samSummary | Sort-Object -Property Count,sAMAccountName -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvSamSummary
  $samPerObj = foreach ($g in $samDupGroups) {
    foreach ($r in $g.Group) {
      [pscustomobject]@{
        sAMAccountName    = $r.SAM
        ObjectClass       = $r.ObjectClass
        DistinguishedName = $r.DistinguishedName
        WhenCreated       = $r.WhenCreated
        CN                = $r.CN
        IsCNF             = $r.IsCNF
      }
    }
  }
  $samPerObj | Sort-Object -Property sAMAccountName,WhenCreated | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvSamDetail
}

if ($upnDupGroups) {
  $upnSummary | Sort-Object -Property Count,userPrincipalName -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvUpnSummary
  $upnPerObj = foreach ($g in $upnDupGroups) {
    foreach ($r in $g.Group) {
      [pscustomobject]@{
        userPrincipalName  = $r.UPN
        sAMAccountName     = $r.SAM
        ObjectClass        = $r.ObjectClass
        DistinguishedName  = $r.DistinguishedName
        WhenCreated        = $r.WhenCreated
        CN                 = $r.CN
        IsCNF              = $r.IsCNF
      }
    }
  }
  $upnPerObj | Sort-Object -Property userPrincipalName,WhenCreated | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvUpnDetail
}

if ($cnfObjects) {
  $cnfSummary | Sort-Object -Property Count,BaseName -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCnfSummary
  $cnfObjects |
    Select-Object CN,CNF_Base,SAM,UPN,ObjectClass,WhenCreated,DistinguishedName |
    Sort-Object -Property CNF_Base,WhenCreated |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvCnfDetail
}

Write-Host ""
Write-Host "Saved CSVs to:" -ForegroundColor Cyan
Get-ChildItem -Path $OutDir -Filter *.csv | ForEach-Object { Write-Host "  $($_.FullName)" }

# --- Cleanup draft (commented) ------------------------------------------------
$draft = Join-Path $OutDir 'Remove-DuplicateIdentities.ps1'
$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('# Review carefully before executing! Draft actions for duplicate identities / CNF conflicts')
$null = $sb.AppendLine('# Nothing runs by default. Uncomment the lines you decide to execute.')
$null = $sb.AppendLine()

if ($samDupGroups) {
  foreach ($g in ($samDupGroups | Sort-Object -Property Count -Descending)) {
    $null = $sb.AppendLine("# Duplicate sAMAccountName: '$($g.Group[0].SAM)'  (Count: $($g.Count))")
    $sorted = $g.Group | Sort-Object -Property WhenCreated
    $keeper = $sorted[0]
    $null = $sb.AppendLine("# Suggested keeper (oldest): $($keeper.DistinguishedName)")
    foreach ($r in $sorted) {
      $dn = $r.DistinguishedName
      $null = $sb.AppendLine("# Review: $dn")
      $null = $sb.AppendLine("# Remove-ADObject -Identity '$dn' -Confirm")
    }
    $null = $sb.AppendLine()
  }
}

if ($upnDupGroups) {
  foreach ($g in ($upnDupGroups | Sort-Object -Property Count -Descending)) {
    $null = $sb.AppendLine("# Duplicate UPN: '$($g.Group[0].UPN)'  (Count: $($g.Count))")
    $sorted = $g.Group | Sort-Object -Property WhenCreated
    $keeper = $sorted[0]
    $null = $sb.AppendLine("# Suggested keeper (oldest): $($keeper.DistinguishedName)")
    foreach ($r in $sorted) {
      $dn = $r.DistinguishedName
      $newUpn = ("{0}+dedupe@{1}" -f ($r.SAM), ($r.UPN -split '@')[-1])
      $null = $sb.AppendLine("# Review: $dn")
      $null = $sb.AppendLine("# Set-ADUser -Identity '$dn' -UserPrincipalName '$newUpn' -WhatIf")
    }
    $null = $sb.AppendLine()
  }
}

if ($cnfObjects) {
  $null = $sb.AppendLine("# CNF conflict objects:")
  foreach ($g in ($cnfObjects | Group-Object CNF_Base | Sort-Object -Property Count -Descending)) {
    $null = $sb.AppendLine("# BaseName: $($g.Name)  (Count: $($g.Count))")
    $sorted = $g.Group | Sort-Object -Property WhenCreated
    $keeper = $sorted[0]
    $null = $sb.AppendLine("# Suggested keeper (oldest): $($keeper.DistinguishedName)")
    foreach ($r in $sorted) {
      $dn = $r.DistinguishedName
      $null = $sb.AppendLine("# Review: $dn")
      $null = $sb.AppendLine("# Remove-ADObject -Identity '$dn' -Confirm")
    }
    $null = $sb.AppendLine()
  }
}

[IO.File]::WriteAllText($draft, $sb.ToString(), [Text.UTF8Encoding]::new($false))

Write-Host "Draft cleanup script: $draft" -ForegroundColor Cyan
Write-Host "NOTE: All lines are commented. Decide keeper object(s) and carefully test before making changes." -ForegroundColor Yellow
