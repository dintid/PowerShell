# MODNI 20250625 – Security & SMB audit (PS 5.1) with Logon-Type names, NTLM info & Source-IP, plus logging
$StartTime = (Get-Date).AddMinutes(-20)

$SecurityEventDescriptions = @{
    4624 = 'Successful login'
    4625 = 'Failed login (Kerberos/NTLM issues)'
    4776 = 'NTLM authentication attempt'
    2889 = 'NTLM relay attack detection'
}

$SMBEventGroups = @(
    @{ Name='SMB connection events';      Ids=3000..3010 },
    @{ Name='Failed SMB authentication'; Ids=@(3100)    },
    @{ Name='SMB signing failure';       Ids=@(3200)    }
)

$LogFolder = 'C:\itm8\A-HardenedPaths'
if (-not (Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
}
$LogFile = Join-Path $LogFolder ("A-HardenedPaths_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# Helper function to append to log file
function Write-Log {
    param($text)
    Add-Content -Path $LogFile -Value $text
}

function Clean-AuthPackage { param($p) if(!$p){'-'}else{ $p -replace '\s*\(Microsoft package\)'} }

function Field {
    param($msg,$label)
    if ($msg -match "${label}:\s+([^\r\n]+)") { $Matches[1].Trim() } else { '-' }
}

function Guess-NtlmVersion {
    param($msg)
    if ($msg -match 'NTLM V2') { 'NTLM V2' }
    elseif ($msg -match 'NTLM V1') { 'NTLM V1' }
    elseif ($msg -match 'Package Name \(NTLM only\):\s*(NTLM V[12])') { $Matches[1] }
    else { 'NTLM (unspecified)' }
}

function SourceIP-4776 {
    param($msg)
    foreach ($tag in 'Source Network Address','Source Address','Client Address') {
        $val = Field $msg $tag
        if ($val -ne '-') { return $val }
    }
    '-'
}

# Clear or create log file at start
Set-Content -Path $LogFile -Value "A-HardenedPaths Audit Log - Started: $(Get-Date)" -Encoding UTF8

foreach ($eventId in $SecurityEventDescriptions.Keys) {

    $header = "`nEvent ID $eventId — $($SecurityEventDescriptions[$eventId])"
    Write-Host $header -Foreground Cyan
    Write-Log $header

    $evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eventId; StartTime=$StartTime} -EA SilentlyContinue
    if (!$evts) {
        $noEventsText = 'No events found.'
        Write-Host $noEventsText -Foreground Yellow
        Write-Log $noEventsText
        continue
    }

    $rows = foreach ($e in $evts) {
        $msg = $e.Message
        $lp='N/A'; $ap='-'; $lt='-'; $acc='-'; $ws='-'; $ip='-'; $ver='-'

        if ($eventId -in 4624,4625) {
            $lp  = Field $msg 'Logon Process'
            $ap  = Clean-AuthPackage (Field $msg 'Authentication Package')

            $raw = Field $msg 'Logon Type'
            if ($LogonTypeDescriptions.ContainsKey($raw)) { $lt = $LogonTypeDescriptions[$raw] } else { $lt = $raw }

            $acc = Field $msg 'Account Name'
            $ws  = Field $msg 'Workstation Name'
            $ip  = Field $msg 'Source Network Address'

            if ($lp -eq 'NtLmSsp') { $ver = Guess-NtlmVersion $msg }

            if ($eventId -eq 4624 -and $lp -eq 'Kerberos') { continue }
        }
        elseif ($eventId -eq 4776) {
            $lp = '-'
            $lpRaw = Field $msg 'Authentication Package'

            if ($lpRaw -match 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0') {
                $ap = 'NTLM'
            } else {
                $ap = Clean-AuthPackage $lpRaw
            }

            $acc = Field $msg 'Logon Account'
            $ws  = Field $msg 'Source Workstation'
            $lt  = 'Network (NTLM validation)'
            $ip  = SourceIP-4776 $msg
            $ver = 'NTLM (unspecified)'
        }

        [pscustomobject]@{
            TimeCreated = $e.TimeCreated
            Id          = $e.Id
            LogonProcess= $lp
            AuthPackage = $ap
            LogonType   = $lt
            Account     = $acc
            Workstation = $ws
            SourceIP    = $ip
            NTLMVersion = $ver
        }
    }

    if ($rows) {
        $outRows = $rows | Select-Object -First 10
        $outRows | Format-Table -AutoSize
        Write-Log ($outRows | Out-String)
        if ($rows.Count -gt 10) {
            $msg = "(showing first 10 of $($rows.Count))"
            Write-Host $msg -Foreground Yellow
            Write-Log $msg
        }
        if ($eventId -eq 4624) {
            $msg = "(after filtering out Kerberos)"
            Write-Host $msg -Foreground Yellow
            Write-Log $msg
        }
    } else {
        $noMoreEvents = 'No events after filters.'
        Write-Host $noMoreEvents -Foreground Yellow
        Write-Log $noMoreEvents
    }
}

foreach ($g in $SMBEventGroups) {
    $groupHeader = "`nSMB Group: $($g.Name)  IDs: $($g.Ids -join ',')"
    Write-Host $groupHeader -Foreground Cyan
    Write-Log $groupHeader

    $ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-SMBServer/Operational'; Id=$g.Ids; StartTime=$StartTime} -EA SilentlyContinue
    if (!$ev) {
        $noEvText = 'No events found.'
        Write-Host $noEvText -Foreground Yellow
        Write-Log $noEvText
        continue
    }

    $evOut = $ev | Select-Object -First 10 | ForEach-Object {
        [pscustomobject]@{
            Time        = $_.TimeCreated
            Id          = $_.Id
            MessageLine1= ($_.Message.Split("`n")[0]).Trim()
        }
    }

    $evOut | Format-Table -AutoSize
    Write-Log ($evOut | Out-String)
}
