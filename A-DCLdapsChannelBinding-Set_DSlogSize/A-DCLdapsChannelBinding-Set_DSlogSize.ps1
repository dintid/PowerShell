<#
MODNI 20251107
Title: Set 'Directory Service' log size on selected DCs (before/after audit)

What it does
------------
- Reads current max size of "Directory Service" log on each target DC
- Sets new max size using 'wevtutil sl "Directory Service" /ms:<bytes>' via WinRM
- Re-reads to verify
- Exports CSV + Transcript

Notes
-----
- Uses WinRM (Invoke-Command). No RPC/dynamic ports required.
- Safe guard: -OnlyIfSmaller will skip DCs already >= target size.
- Increasing size takes effect immediately. Decreasing below current file size would require clearing the log first (not done here).
#>

[CmdletBinding()]
param(
    # Pass one or more DCs. If omitted, all DCs in the domain are targeted.
    [string[]]$ComputerName,

    # Target size in MB
    [int]$TargetMB = 64,

    # Skip setting if current size is already >= TargetMB
    [switch]$OnlyIfSmaller,

    # Output folder
    [string]$OutputPath = "C:\ITM8\A-DCLdapsChannelBinding"
)

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

if (-not $ComputerName) {
    $ComputerName = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
}

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvPath = Join-Path $OutputPath ("Set-DSLogSize_{0}.csv" -f $ts)
$transcriptPath = Join-Path $OutputPath ("Transcript_Set-DSLogSize_{0}.txt" -f $ts)

try { Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Null } catch { }

Write-Host ("Target size: {0} MB" -f $TargetMB) -ForegroundColor DarkGray
$bytesTarget = [int64]$TargetMB * 1MB

$results = New-Object System.Collections.Generic.List[object]

foreach ($dc in $ComputerName) {
    Write-Host ("Processing {0}..." -f $dc) -ForegroundColor Cyan

    $beforeBytes = $null
    $afterBytes  = $null
    $status = "OK"
    $action = "None"
    $errorMsg = ""

    # Read BEFORE (via WinRM)
    try {
        $beforeBytes = Invoke-Command -ComputerName $dc -ErrorAction Stop -ScriptBlock {
            (Get-WinEvent -ListLog 'Directory Service').MaximumSizeInBytes
        }
    } catch {
        $status = "ReadBeforeError"
        $errorMsg = $_.Exception.Message
    }

    # Decide whether to set
    $shouldSet = $true
    if ($OnlyIfSmaller -and $beforeBytes -ne $null) {
        if ($beforeBytes -ge $bytesTarget) { $shouldSet = $false }
    }

    if ($status -eq "OK" -and $shouldSet) {
        try {
            # Set on DC (local) via WinRM
            Invoke-Command -ComputerName $dc -ScriptBlock {
                param($bytesTarget)
                wevtutil sl "Directory Service" /ms:$bytesTarget | Out-Null
            } -ArgumentList $bytesTarget -ErrorAction Stop
            $action = "Set"
        } catch {
            $status = "SetError"
            $errorMsg = $_.Exception.Message
        }
    } elseif ($status -eq "OK" -and -not $shouldSet) {
        $action = "Skipped (Already >= Target)"
    }

    # Read AFTER (via WinRM)
    if ($status -eq "OK") {
        try {
            $afterBytes = Invoke-Command -ComputerName $dc -ErrorAction Stop -ScriptBlock {
                (Get-WinEvent -ListLog 'Directory Service').MaximumSizeInBytes
            }
        } catch {
            $status = "ReadAfterError"
            $errorMsg = $_.Exception.Message
        }
    }

    $beforeMB = if ($beforeBytes -ne $null) { [math]::Round(($beforeBytes / 1MB), 1) } else { $null }
    $afterMB  = if ($afterBytes  -ne $null) { [math]::Round(($afterBytes  / 1MB), 1) } else { $null }

    $results.Add([PSCustomObject]@{
        DomainController = $dc
        BeforeBytes      = $beforeBytes
        BeforeMB         = $beforeMB
        AfterBytes       = $afterBytes
        AfterMB          = $afterMB
        TargetMB         = $TargetMB
        Action           = $action
        Status           = $status
        Error            = $errorMsg
    })

    Write-Host (" - Before: {0} MB ; After: {1} MB ; Action: {2} ; Status: {3}" -f `
        ($(if ($beforeMB -ne $null) { $beforeMB } else { "N/A" }), `
         $(if ($afterMB  -ne $null) { $afterMB  } else { "N/A" }), `
         $action, $status)) -ForegroundColor DarkGray
}

$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ("CSV       : {0}" -f $csvPath) -ForegroundColor Green
Write-Host ("Transcript: {0}" -f $transcriptPath) -ForegroundColor Green

try { Stop-Transcript | Out-Null } catch { }
