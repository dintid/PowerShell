<#
MODNI 20251104
Title: P-ControlPathIndirectMany – sIDHistory + SYSVOL content scan for foreign domain SID

What it does
------------
- Finds any AD objects with sIDHistory entries from the foreign domain SID prefix
- Greps SYSVOL GPO *contents* (Preferences XML, GptTmpl.inf, etc.) for the bare domain SID string
- Keeps outputs ISE-safe; writes CSVs to C:\ITM8\P-ControlPathIndirectMany\

Why
---
If ACLs/owners don’t reference the SID, the remaining common places are:
- sIDHistory (objects migrated from that domain)
- GPO data files (Restricted Groups, User Rights Assignment, GPP LUG), which may hold SIDs in file contents

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$ForeignDomainSid = 'S-1-5-21-901647220-347810192-996637233',

  [Parameter(Mandatory=$false)]
  [string]$OutDir = 'C:\ITM8\P-ControlPathIndirectMany',

  [Parameter(Mandatory=$false)]
  [string]$SysvolDC = $env:COMPUTERNAME
)

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvSIDHist = Join-Path $OutDir "ForeignDomainSID_sIDHistory_${ts}.csv"
$csvSYSVOL  = Join-Path $OutDir "ForeignDomainSID_SYSVOLContent_${ts}.csv"
$log = Join-Path $OutDir "transcript_${ts}.txt"
Start-Transcript -Path $log -Force | Out-Null

Write-Host "=== Deep check: sIDHistory + SYSVOL content scan ===" -ForegroundColor Cyan
Write-Host ("Foreign domain SID prefix : {0}" -f $ForeignDomainSid)
Write-Host ("Your domain SID           : {0}" -f (Get-ADDomain).DomainSID.Value)
Write-Host ""

# ---------- 1) sIDHistory scan ----------
Write-Host "Scanning AD for sIDHistory entries from the foreign domain..." -ForegroundColor Cyan
$foundSIDHist = New-Object System.Collections.Generic.List[object]

try {
  # Pull all objects with sIDHistory (users/groups/computers)
  $objs = Get-ADObject -LDAPFilter '(sIDHistory=*)' -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree `
          -Properties sIDHistory, objectClass, name, distinguishedName -ResultSetSize $null

  foreach ($o in $objs) {
    foreach ($sidBytes in ($o.sIDHistory)) {
      try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
        $domainSidPart = $sid.AccountDomainSid.Value
        if ($domainSidPart -eq $ForeignDomainSid) {
          $foundSIDHist.Add([pscustomobject]@{
            ObjectClass     = $o.objectClass
            Name            = $o.name
            DistinguishedName = $o.distinguishedName
            SIDHistory      = $sid.Value
            SIDHistoryDomain= $domainSidPart
          }) | Out-Null
        }
      } catch { }
    }
  }
} catch {
  Write-Host ("Warning: sIDHistory enumeration failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

if ($foundSIDHist.Count -gt 0) {
  Write-Host "✅ sIDHistory hits found:" -ForegroundColor Green
  $foundSIDHist | Format-Table ObjectClass, Name, SIDHistory -AutoSize
  $foundSIDHist | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvSIDHist
  Write-Host ("sIDHistory CSV saved: {0}" -f $csvSIDHist) -ForegroundColor Cyan
} else {
  Write-Host "No sIDHistory entries from that domain were found." -ForegroundColor Yellow
}

# ---------- 2) SYSVOL GPO content grep ----------
Write-Host ""
Write-Host "Scanning SYSVOL GPO *contents* for the foreign SID string..." -ForegroundColor Cyan

$domainName = (Get-ADDomain).DNSRoot
$polRoot = "\\$SysvolDC\SYSVOL\$domainName\Policies"
$foundSYSVOL = New-Object System.Collections.Generic.List[object]

if (Test-Path $polRoot) {
  # Target typical text files; also light binary sweep up to 5 MB
  $patterns = @("*.xml","*.inf","*.ini","*.txt","GptTmpl.inf","GPT.ini","*.pol","*.json","*.cfg")
  $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
  foreach ($pat in $patterns) {
    try {
      (Get-ChildItem -Path $polRoot -Recurse -File -Filter $pat -ErrorAction SilentlyContinue) | ForEach-Object { $files.Add($_) | Out-Null }
    } catch {}
  }

  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  $files = $files | Sort-Object FullName -Unique

  foreach ($f in $files) {
    if ($seen.Contains($f.FullName)) { continue } else { $seen.Add($f.FullName) | Out-Null }
    $hit = $false
    try {
      # Attempt text read first
      $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
      if ($content -like "*$ForeignDomainSid*") { $hit = $true }
    } catch {
      # If text read fails or file is binary, do a light byte scan (<= 5 MB)
      try {
        if ($f.Length -le 5MB) {
          $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
          $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
          if ($ascii -like "*$ForeignDomainSid*") { $hit = $true }
        }
      } catch {}
    }

    if ($hit) {
      $foundSYSVOL.Add([pscustomobject]@{
        FilePath   = $f.FullName
        SizeKB     = [math]::Round($f.Length/1KB,1)
        MatchedSid = $ForeignDomainSid
      }) | Out-Null
    }
  }
} else {
  Write-Host ("SYSVOL not reachable: {0}" -f $polRoot) -ForegroundColor Yellow
}

if ($foundSYSVOL.Count -gt 0) {
  Write-Host "✅ SYSVOL content hits found:" -ForegroundColor Green
  $foundSYSVOL | Format-Table -AutoSize
  $foundSYSVOL | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvSYSVOL
  Write-Host ("SYSVOL content CSV saved: {0}" -f $csvSYSVOL) -ForegroundColor Cyan
} else {
  Write-Host "No SYSVOL file contents contain the bare foreign domain SID string." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done (sIDHistory + SYSVOL content) ===" -ForegroundColor Cyan
Stop-Transcript | Out-Null
