<#
MODNI 20260112
PingCastle ID: A-SMB2SignatureNotRequired

Goal:
- Clearly list ALL relevant GPOs that define SMB signing values, even if only one of the two settings is defined.
- Security Options live in SYSVOL GptTmpl.inf, not Registry.pol.

Outputs:
A) Local effective summary (registry + runtime + winning GPO via gpresult)
B) One-row-per-GPO list from SYSVOL GptTmpl.inf:
   - ServerRequire (Always) / ServerEnable (IfAgree)
   - WorkstationRequire / WorkstationEnable
   - Shows NotDefined where missing
   - Includes GPOs that define ANY of these keys

Logs:
C:\ITM8\A-SMB2SignatureNotRequired\Verify.log
#>

$LogRoot = "C:\ITM8\A-SMB2SignatureNotRequired"
$null = New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction SilentlyContinue
$LogFile = Join-Path $LogRoot "Verify.log"

$GpDir = Join-Path $LogRoot "gpresult"
$null  = New-Item -Path $GpDir -ItemType Directory -Force -ErrorAction SilentlyContinue

$Computer = $env:COMPUTERNAME
$TxtPath  = Join-Path $GpDir ("gpresult_{0}.txt"  -f $Computer)
$HtmlPath = Join-Path $GpDir ("gpresult_{0}.html" -f $Computer)

function Write-Log {
    param([string]$Line)
    try {
        $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $LogFile -Value "[$stamp] $Line"
    } catch { }
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try {
        $p = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -ne $p.$Name) { return $p.$Name }
        return $null
    } catch { return $null }
}

function As-SettingText {
    param([Nullable[int]]$v)
    if ($v -eq $null) { return "NotPresent" }
    if ($v -eq 1) { return "Enabled" }
    return "Disabled"
}

function Get-ModeText {
    param([Nullable[int]]$Require, [Nullable[int]]$Enable)
    if ($Require -eq 1) { return "Signing REQUIRED" }
    if ($Enable -eq 1 -and ($Require -eq 0 -or $Require -eq $null)) { return "Signing ENABLED (not required)" }
    if (($Enable -eq 0 -or $Enable -eq $null) -and ($Require -eq 0 -or $Require -eq $null)) { return "Signing NOT enabled" }
    return "Unknown"
}

function Parse-GpresultWinners {
    param([string]$GpresultTxtPath)

    $map = @{}
    $currentGpo = $null
    $lines = Get-Content -Path $GpresultTxtPath -ErrorAction SilentlyContinue

    foreach ($line in $lines) {
        if ($line -match "^\s*GPO:\s*(.+?)\s*$") {
            $currentGpo = $matches[1].Trim()
            continue
        }
        if ($line -match "^\s*ValueName:\s*(.+?)\s*$") {
            $vn = $matches[1].Trim()
            if ($currentGpo -and $vn) { $map[$vn] = $currentGpo }
            continue
        }
    }
    return $map
}

function Get-DomainDnsName {
    if ($env:USERDNSDOMAIN) { return $env:USERDNSDOMAIN }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.Domain) { return $cs.Domain }
    } catch { }
    return $null
}

function Get-GpoGuidsFromSysvol {
    param([string]$DomainDns)

    $polPath = "\\$DomainDns\SYSVOL\$DomainDns\Policies"
    if (-not (Test-Path $polPath)) { return @() }

    $guids = @()
    try {
        Get-ChildItem -Path $polPath -Directory -ErrorAction Stop |
            Where-Object { $_.Name -match "^\{[0-9A-Fa-f\-]+\}$" } |
            ForEach-Object { $guids += $_.Name }
    } catch { }
    return $guids
}

function Try-ResolveGpoName {
    param([string]$GuidWithBraces)

    $guid = $GuidWithBraces.Trim("{}")
    try {
        Import-Module GroupPolicy -ErrorAction Stop | Out-Null
        $g = Get-GPO -Guid $guid -ErrorAction Stop
        return $g.DisplayName
    } catch {
        return $GuidWithBraces
    }
}

function Get-GptTmplPath {
    param([string]$DomainDns, [string]$GuidWithBraces)
    return "\\$DomainDns\SYSVOL\$DomainDns\Policies\$GuidWithBraces\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
}

function Parse-GptTmplRegistryValues {
    param([string]$InfPath)

    if (-not (Test-Path $InfPath)) { return @{} }

    $lines = @()
    try { $lines = Get-Content -Path $InfPath -ErrorAction Stop } catch { return @{} }

    $inRegSection = $false
    $map = @{} # key -> int value (or $null if unparsed)

    foreach ($ln in $lines) {
        $t = $ln.Trim()

        if ($t -match "^\[Registry Values\]$") { $inRegSection = $true; continue }
        if ($t -match "^\[.+\]$" -and $t -notmatch "^\[Registry Values\]$") { $inRegSection = $false; continue }
        if (-not $inRegSection) { continue }
        if (-not $t -or $t.StartsWith(";")) { continue }

        # Typical format:
        # MACHINE\...\Key\ValueName=4,1   (REG_DWORD, value 1)
        if ($t -match "^(MACHINE\\.+?)\s*=\s*(.+)$") {
            $k = $matches[1].Trim()
            $rhs = $matches[2].Trim()

            if ($rhs -match "^\s*4\s*,\s*(\d+)\s*$") {
                $map[$k] = [int]$matches[1]
            } else {
                # present but not parsed as REG_DWORD
                $map[$k] = $null
            }
        }
    }

    return $map
}

function As-GpoCell {
    param($v)
    if ($v -eq $null) { return "NotDefined" }
    if ($v -is [int]) { return $v }
    return "<Unparsed>"
}

# -------- Targets we want to list (even if missing) --------
$Keys = [ordered]@{
    ServerRequire      = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature"
    ServerEnable       = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature"
    WorkstationRequire = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature"
    WorkstationEnable  = "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature"
}

# ---------------- Run ----------------
Write-Host ""
Write-Host "Logging to: $LogRoot" -ForegroundColor Gray
Write-Log  "---- Verify run start on $Computer ----"

# A) Local effective summary
Write-Host "Generating gpresult reports..." -ForegroundColor Cyan
try {
    gpresult /SCOPE COMPUTER /V > $TxtPath
    gpresult /SCOPE COMPUTER /H $HtmlPath /F | Out-Null
} catch {
    $m = $_.Exception.Message
    Write-Host "❌ gpresult failed: $m" -ForegroundColor Red
    Write-Log  "gpresult failed: $m"
    return
}

$winnerMap = Parse-GpresultWinners -GpresultTxtPath $TxtPath

$serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$req = Get-RegistryValueSafe -Path $serverRegPath -Name "RequireSecuritySignature"
$ena = Get-RegistryValueSafe -Path $serverRegPath -Name "EnableSecuritySignature"

$reqText = As-SettingText $req
$enaText = As-SettingText $ena
$mode    = Get-ModeText -Require $req -Enable $ena

$vnReq = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature"
$vnEna = "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature"

$gpoReq = if ($winnerMap.ContainsKey($vnReq)) { $winnerMap[$vnReq] } else { "<Not Identified>" }
$gpoEna = if ($winnerMap.ContainsKey($vnEna)) { $winnerMap[$vnEna] } else { "<Not Identified>" }

$live = $null
try { $live = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature } catch { }

$status = "OK"
$statusColor = "Green"
if ($req -ne 1) { $status = "NOT ENFORCED"; $statusColor = "Yellow" }
if ($reqText -eq "Disabled") { $status = "CONFLICT / DISABLED"; $statusColor = "Red" }

Write-Host ""
Write-Host "SMB Signing Summary (easy view):" -ForegroundColor Cyan
Write-Host ("  Status                  : {0}" -f $status) -ForegroundColor $statusColor
Write-Host ("  Policy (Always/Require) : {0} (Reg={1})" -f $reqText, $(if($req -eq $null){"<null>"}else{$req})) -ForegroundColor Gray
Write-Host ("  Policy (If agree/Enable): {0} (Reg={1})" -f $enaText, $(if($ena -eq $null){"<null>"}else{$ena})) -ForegroundColor Gray
Write-Host ("  Effective mode          : {0}" -f $mode) -ForegroundColor Gray
Write-Host ("  Winning GPO (Require)   : {0}" -f $gpoReq) -ForegroundColor Gray
Write-Host ("  Winning GPO (Enable)    : {0}" -f $gpoEna) -ForegroundColor Gray
if ($live) {
    Write-Host ("  Runtime state           : Require={0} Enable={1}" -f $live.RequireSecuritySignature, $live.EnableSecuritySignature) -ForegroundColor Gray
}

Write-Log ("Summary: Status={0}; Require={1}; Enable={2}; Mode={3}; WinGPO_Require={4}; WinGPO_Enable={5}" -f `
    $status, $(if($req -eq $null){"null"}else{$req}), $(if($ena -eq $null){"null"}else{$ena}), $mode, $gpoReq, $gpoEna)

# B) Enumerate SYSVOL GptTmpl.inf and list relevant GPOs even if partial
Write-Host ""
Write-Host "Enumerating GPO Security Options via SYSVOL (GptTmpl.inf)..." -ForegroundColor Cyan

$domainDns = Get-DomainDnsName
if (-not $domainDns) {
    Write-Host "❌ Could not determine domain DNS name." -ForegroundColor Red
    Write-Log  "Domain DNS not found; abort GPO enumeration"
} else {
    $guids = Get-GpoGuidsFromSysvol -DomainDns $domainDns
    if (-not $guids -or $guids.Count -eq 0) {
        Write-Host "⚠️  No GPO GUIDs found in SYSVOL (or SYSVOL not accessible)." -ForegroundColor Yellow
        Write-Log  "No SYSVOL GPO folders found"
    } else {
        $rows = @()

        foreach ($g in $guids) {
            $name = Try-ResolveGpoName -GuidWithBraces $g
            $inf  = Get-GptTmplPath -DomainDns $domainDns -GuidWithBraces $g

            $kv = Parse-GptTmplRegistryValues -InfPath $inf

            # Pull each key (or NotDefined if absent)
            $sr = $null; $se = $null; $wr = $null; $we = $null

            if ($kv.ContainsKey($Keys.ServerRequire))      { $sr = $kv[$Keys.ServerRequire] }
            if ($kv.ContainsKey($Keys.ServerEnable))       { $se = $kv[$Keys.ServerEnable] }
            if ($kv.ContainsKey($Keys.WorkstationRequire)) { $wr = $kv[$Keys.WorkstationRequire] }
            if ($kv.ContainsKey($Keys.WorkstationEnable))  { $we = $kv[$Keys.WorkstationEnable] }

            # Only include if ANY of the 4 values is defined (this is the key change you requested)
            $anyDefined = $false
            if ($kv.ContainsKey($Keys.ServerRequire) -or
                $kv.ContainsKey($Keys.ServerEnable) -or
                $kv.ContainsKey($Keys.WorkstationRequire) -or
                $kv.ContainsKey($Keys.WorkstationEnable)) {
                $anyDefined = $true
            }

            if ($anyDefined) {
                $rows += [pscustomobject]@{
                    GPOName             = $name
                    GPOGuid             = $g
                    ServerRequire_Always = As-GpoCell $sr
                    ServerEnable_IfAgree = As-GpoCell $se
                    WorkstationRequire   = As-GpoCell $wr
                    WorkstationEnable    = As-GpoCell $we
                    InfPath              = $inf
                }
            }
        }

        if ($rows.Count -gt 0) {
            Write-Host ""
            Write-Host "GPOs defining SMB signing (partial definitions included):" -ForegroundColor Cyan
            $rows | Sort-Object GPOName | Format-Table -AutoSize

            foreach ($r in $rows) {
                Write-Log ("GptTmplRow: {0} {1} SR={2} SE={3} WR={4} WE={5}" -f `
                    $r.GPOName, $r.GPOGuid, $r.ServerRequire_Always, $r.ServerEnable_IfAgree, $r.WorkstationRequire, $r.WorkstationEnable)
            }
        } else {
            Write-Host "No SMB signing definitions found in any GptTmpl.inf." -ForegroundColor Yellow
            Write-Log  "No GptTmpl SMB matches found"
        }
    }
}

Write-Host ""
Write-Host "Artifacts:" -ForegroundColor Cyan
Write-Host "  gpresult (txt) : $TxtPath" -ForegroundColor Gray
Write-Host "  gpresult (html): $HtmlPath" -ForegroundColor Gray
Write-Host "  log           : $LogFile" -ForegroundColor Gray

Write-Log "---- Verify run end ----"
