<# 
S-OS-W10 (AD-only)
MODNI 20251006
- Lists ALL obsolete Windows 10 machines (pre-19045) regardless of activity
- Adds an "Inactive" column (LastLogonDate older than window or missing)
- AD-only: uses OperatingSystem / OperatingSystemVersion / LastLogonDate
- Always exports ONE CSV: Obsolete list with the Inactive column

Config tips:
- If some 17763/19044 devices are LTSC in your estate, add them to $LtscHostAllowList.
- Set $IncludeDisabled = $true if you also want disabled AD objects included.
#>

# ====== CONFIG ======
[int]   $DaysActiveWindow  = 90        # "Active" = LastLogonDate within this many days
[bool]  $IncludeDisabled   = $false     # include disabled AD computer objects
[string]$ExportDirectory   = 'C:\ITM8\S-OS-W10'
[string[]]$LtscHostAllowList = @()      # e.g. @('KIOSK-LTSC-01','PLANT-LTSC-02')

# Win10 builds considered obsolete for non-LTSC line (pre-19045 / 22H2)
[int[]] $ObsoleteBuilds = 10240,10586,14393,15063,16299,17134,17763,18362,18363,19041,19042,19043,19044
# ====================

$cutoff = (Get-Date).AddDays(-$DaysActiveWindow)

function Get-AdWinBuild {
    param([string]$osver)
    if ([string]::IsNullOrWhiteSpace($osver)) { return $null }
    $m = [regex]::Match($osver, '\((\d{3,6})\)')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    $m2 = [regex]::Matches($osver, '\d{3,6}')
    if ($m2.Count -gt 0) { return [int]$m2[$m2.Count-1].Value }
    $null
}

# --- 1) Pull Windows 10 computers from AD ---
$props = 'Name','OperatingSystem','OperatingSystemVersion','LastLogonDate','Enabled'
$filter = if ($IncludeDisabled) {
    '(OperatingSystem -like "Windows 10*")'
} else {
    '(Enabled -eq $true) -and (OperatingSystem -like "Windows 10*")'
}

$adWin10 = Get-ADComputer -Filter $filter -Property $props

if (-not $adWin10) {
    Write-Host "No Windows 10 computers found in AD with current filter." -ForegroundColor Yellow
    return
}

# --- 2) Compute build/obsolete/active flags (AD-only logic) ---
$results = foreach ($c in $adWin10) {
    $build = Get-AdWinBuild $c.OperatingSystemVersion
    $isObsolete = $false
    $reason = $null

    if ($build) {
        if ($ObsoleteBuilds -contains $build) {
            $isObsolete = $true
            $reason = "Build $build"
        } else {
            $reason = "Build $build (>=19045)"
        }
    } else {
        $reason = "Missing build in AD"
    }

    # Exclude known LTSC hosts (AD can’t reliably detect LTSC)
    if ($isObsolete -and ($LtscHostAllowList -contains $c.Name)) {
        $isObsolete = $false
        $reason = "$reason; excluded by LTSC allow-list"
    }

    # Active flag based on LastLogonDate vs window
    $isActive = $false
    if ($c.LastLogonDate) { $isActive = ($c.LastLogonDate -gt $cutoff) }

    [pscustomobject]@{
        Name              = $c.Name
        Enabled           = $c.Enabled
        OS                = $c.OperatingSystem
        OSVer             = $c.OperatingSystemVersion
        Build             = $build
        LastLogonDate     = $c.LastLogonDate
        ActiveWithinDays  = $isActive
        Inactive          = -not $isActive   # <-- requested column
        ObsoleteWin10     = $isObsolete
        Reason            = $reason
    }
}

# --- 3) Views + Summary ---
$allObsolete      = $results | Where-Object { $_.ObsoleteWin10 -eq $true }
$activeObsolete   = $allObsolete | Where-Object { $_.ActiveWithinDays -eq $true }
$inactiveObsolete = $allObsolete | Where-Object { $_.ActiveWithinDays -eq $false }
$unknownBuild     = $results | Where-Object { -not $_.Build }

Write-Host "=== Summary (AD-only) ===" -ForegroundColor Yellow
[pscustomobject]@{
    AD_Win10_Total                         = $results.Count
    AD_Win10_Obsolete_All                  = $allObsolete.Count
    AD_Win10_Obsolete_ActiveWithinDays     = $activeObsolete.Count
    AD_Win10_Obsolete_InactiveOrNoLogon    = $inactiveObsolete.Count
    MissingBuildInAD_FYI                   = $unknownBuild.Count
    ActiveWindow_Days                      = $DaysActiveWindow
    IncludeDisabledObjects                 = $IncludeDisabled
} | Format-List

Write-Host "`n=== Obsolete Win10 (ALL) ===" -ForegroundColor Yellow
$allObsolete | Sort-Object Name |
    Select-Object Name,Enabled,Build,OS,OSVer,LastLogonDate,Inactive,Reason |
    Format-Table -AutoSize

# --- 4) Export ONE CSV (ONLY the ALL obsolete list, with Inactive column) ---
$null = New-Item -ItemType Directory -Force -Path $ExportDirectory -ErrorAction SilentlyContinue
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$export = Join-Path $ExportDirectory ("S-OS-W10_ADonly_Obsolete_{0}.csv" -f $stamp)

$allObsolete |
    Select-Object Name,Enabled,Build,OS,OSVer,LastLogonDate,Inactive,Reason |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $export

Write-Host "`nCSV exported: $export" -ForegroundColor Green
