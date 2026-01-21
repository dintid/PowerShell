<#
.SYNOPSIS

    MODNI 20250703
    PingCastle ID: A‑DCLdapsProtocol

    Creates or re‑uses a GPO named “A‑DCLdapsProtocol‑Audit”, links it to the
    Domain Controllers OU, and enables verbose SCHANNEL logging.
    Ensures:
      • EventLogging = 7 (Verbose)
      • DisableEventLogging = 0 (Enabled)
    Offers to run gpupdate /force on all DCs afterwards.

.NOTES
    • Requires RSAT ActiveDirectory & Group Policy Management tools
    • Run from an elevated PowerShell session with domain‑level privileges
    • Remote gpupdate uses WinRM – must be enabled on DCs
#>

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy    -ErrorAction Stop

# ─── SETTINGS ────────────────────────────────────────────────────────────────
$GpoName         = 'A-DCLdapsProtocol-Audit'
$RegistryKeyPath = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
$DesiredEnforced = 'Yes'

$RegistrySettings = @(
    @{ Name = 'EventLogging';        DesiredValue = 7 }
    @{ Name = 'DisableEventLogging'; DesiredValue = 0 }
)
# ─────────────────────────────────────────────────────────────────────────────

function Prompt-YesNo {
    param([string]$Message, [switch]$DefaultYes)
    $defChar = if ($DefaultYes) { 'Y' } else { 'N' }
    while ($true) {
        Write-Host ""
        Write-Host $Message -ForegroundColor Yellow
        Write-Host "  Y = Yes (default)"
        Write-Host "  N = No"
        $resp = Read-Host "[Y/N] (default $defChar)"
        if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $defChar }
        switch ($resp.ToLower()) {
            'y' { return $true }
            'n' { return $false }
            default { Write-Host "Please enter Y or N." -ForegroundColor Yellow }
        }
    }
}

function Explain-Val {
    param ($name, $val)
    switch ($name) {
        'EventLogging' {
            switch ($val) {
                0 { '0 = Logging disabled' }
                1 { '1 = Fatal errors only' }
                2 { '2 = Fatal + Error' }
                3 { '3 = Fatal + Error + Warning' }
                4 { '4 = Fatal + Error + Warning + Info' }
                7 { '7 = Fatal + Error + Warning + Success (Verbose)' }
                default { "$val = Custom/Unknown" }
            }
        }
        'DisableEventLogging' {
            switch ($val) {
                0 { '0 = SCHANNEL logging is enabled' }
                1 { '1 = SCHANNEL logging is disabled' }
                default { "$val = Custom/Unknown" }
            }
        }
        default { "$val = Unknown meaning" }
    }
}

function Get-OuGpLinks {
    param([string]$ouDn)
    $ou = Get-ADOrganizationalUnit -Identity $ouDn -Properties gpLink
    if (-not $ou.gpLink) { return @() }
    $links = @()
    foreach ($entry in $ou.gpLink -split '\]\[') {
        $entry = $entry.Trim('[', ']')
        $parts = $entry -split ';'
        if ($parts.Count -ge 2 -and $parts[0] -match '\{([0-9a-fA-F-]+)\}') {
            $guid = $matches[1]
            $enforced = if ($parts[1] -eq '1') { 'Yes' } else { 'No' }
            $links += [PSCustomObject]@{
                Guid     = $guid
                Enforced = $enforced
            }
        }
    }
    return $links
}

function Invoke-DCGpupdate {
    $dcs = Get-ADDomainController -Filter * | Sort-Object HostName
    Write-Host "`n📋 Domain Controllers detected:" -ForegroundColor Cyan
    foreach ($dc in $dcs) {
        Write-Host "  • $($dc.HostName)" -ForegroundColor Cyan
    }

    Write-Host ""
    if (-not (Prompt-YesNo "Run gpupdate /force on all Domain Controllers now?" -DefaultYes)) {
        Write-Host "ℹ️  Skipping gpupdate." -ForegroundColor Yellow
        return
    }

    Write-Host "`n🚀 Running gpupdate /force remotely..." -ForegroundColor Cyan
    foreach ($dc in $dcs) {
        Write-Host "➡️  $($dc.HostName)..." -NoNewline
        try {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock { gpupdate /force /wait:0 | Out-Null } -ErrorAction Stop
            Write-Host " success" -ForegroundColor Green
        } catch {
            Write-Host " failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ─── MAIN ────────────────────────────────────────────────────────────────────
try {
    $domainDN = (Get-ADDomain).DistinguishedName
    $dcOuDN   = "OU=Domain Controllers,$domainDN"

    # GPO creation
    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        Write-Host "GPO '$GpoName' not found." -ForegroundColor Yellow
        if (Prompt-YesNo "Create GPO now?" -DefaultYes) {
            $gpo = New-GPO -Name $GpoName
            Write-Host "✔️  GPO created." -ForegroundColor Green
        } else {
            Write-Warning "Aborted."
            return
        }
    } else {
        Write-Host "ℹ️  Using existing GPO '$GpoName'" -ForegroundColor Yellow
    }

    # Link check
    $link = Get-OuGpLinks -ouDn $dcOuDN | Where-Object { $_.Guid -eq $gpo.Id.Guid }
    if (-not $link) {
        if (Prompt-YesNo "Link GPO to Domain Controllers OU?" -DefaultYes) {
            New-GPLink -Guid $gpo.Id -Target $dcOuDN -Enforced $DesiredEnforced
            Write-Host "✔️  GPO linked (Enforced=$DesiredEnforced)." -ForegroundColor Green
        }
    } elseif ($link.Enforced -ne $DesiredEnforced) {
        if (Prompt-YesNo "Update link to Enforced=$DesiredEnforced?" -DefaultYes) {
            Set-GPLink -Guid $gpo.Id -Target $dcOuDN -Enforced $DesiredEnforced
            Write-Host "✔️  Link enforcement updated." -ForegroundColor Green
        }
    } else {
        Write-Host "✔️  GPO is linked (Enforced=$($link.Enforced))." -ForegroundColor Green
    }

    # Registry settings
    foreach ($reg in $RegistrySettings) {
        $current = Get-GPPrefRegistryValue -Name $GpoName -Context Computer -Key $RegistryKeyPath -ValueName $reg.Name -ErrorAction SilentlyContinue
        $desired = $reg.DesiredValue
        $explanation = Explain-Val $reg.Name $desired

        if (-not $current) {
            Write-Host "$($reg.Name) not set. Desired: $desired ($explanation)" -ForegroundColor Yellow
            if (Prompt-YesNo "Create this registry setting?" -DefaultYes) {
                Set-GPPrefRegistryValue -Name $GpoName -Context Computer -Key $RegistryKeyPath `
                    -ValueName $reg.Name -Type DWord -Action Create -Value $desired
                Write-Host "✔️  $($reg.Name) created with value $desired." -ForegroundColor Green
            }
        } elseif ($current.Value[0] -ne $desired) {
            $currVal = $current.Value[0]
            $currExplanation = Explain-Val $reg.Name $currVal
            Write-Host "$($reg.Name) is $currVal ($currExplanation); expected $desired ($explanation)" -ForegroundColor Yellow
            if (Prompt-YesNo "Update to $desired?" -DefaultYes) {
                Set-GPPrefRegistryValue -Name $GpoName -Context Computer -Key $RegistryKeyPath `
                    -ValueName $reg.Name -Type DWord -Action Update -Value $desired
                Write-Host "✔️  $($reg.Name) updated to $desired." -ForegroundColor Green
            }
        } else {
            Write-Host "✔️  $($reg.Name) already $desired ($explanation)." -ForegroundColor Green
        }
    }

    Write-Host "`n✅ Configuration complete." -ForegroundColor Cyan
    Invoke-DCGpupdate

} catch {
    Write-Error "❌ Error: $_"
}
