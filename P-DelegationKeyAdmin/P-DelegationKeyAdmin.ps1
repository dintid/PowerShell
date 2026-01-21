<#
Script Name:    P-DelegationKeyAdmin
Author:         MODNI
Date:           2025-12-03
PingCastle Rule: P-DelegationKeyAdmin

Purpose:
    This script detects whether the group "Enterprise Key Admins"
    (or another group specified by -GroupName) has explicit ACEs
    on the domain root object (the domain naming context).

    If such ACEs exist, PingCastle flags rule P-DelegationKeyAdmin,
    because permissions such as GenericAll, WriteDacl, WriteOwner or
    WriteProperty on the domain root allow privilege escalation to
    full domain compromise.

    The script:
        - Automatically resolves the domain naming context DN
        - Checks ACLs on that DN for the specified group
        - Displays any ACEs found in a readable table
        - Prints clear manual "how to fix" steps, customized for
          the domain it discovered

    This script does NOT modify any permissions. It is read-only.
#>

param(
    [string]$GroupName  = "Enterprise Key Admins",
    [string]$DomainName # optional, e.g. "LeasingFyn.local"
)

function Get-DomainRootDn {
    param(
        [string]$DomainName
    )

    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        # Current logon domain
        $rootDse = [ADSI]"LDAP://RootDSE"
    }
    else {
        # Target explicit domain, e.g. LeasingFyn.local
        $rootDse = [ADSI]("LDAP://{0}/RootDSE" -f $DomainName)
    }

    return $rootDse.defaultNamingContext
}

function Get-DnsNameFromDn {
    param(
        [string]$DistinguishedName
    )

    # Convert DN "DC=LeasingFyn,DC=local" -> "LeasingFyn.local"
    $parts = $DistinguishedName -split ',' |
             Where-Object { $_ -like "DC=*" } |
             ForEach-Object { $_ -replace "^DC=" }

    return ($parts -join ".")
}

# 1) Resolve domain root DN and DNS name
$dn = Get-DomainRootDn -DomainName $DomainName
$dnsName = Get-DnsNameFromDn -DistinguishedName $dn

Write-Host "Using domain naming context  $dn" -ForegroundColor Cyan

# 2) Read the ACL
$root = [ADSI]("LDAP://{0}" -f $dn)
$acl  = $root.psbase.ObjectSecurity.Access

# 3) Detect ACEs for the target group using IdentityReference.ToString()
$results = $acl | Where-Object {
    $_.IdentityReference -like ("*{0}*" -f $GroupName)
}

if (-not $results) {
    Write-Host "No ACEs for group  $GroupName  found on  $dn" -ForegroundColor Green
    return
}

Write-Host "Found ACEs for group  $GroupName  on  $dn" -ForegroundColor Yellow

$results |
    Select-Object `
        @{n="DistinguishedName";e={$dn}},
        IdentityReference,
        ActiveDirectoryRights,
        AccessControlType,
        IsInherited |
    Format-Table -AutoSize

# Example ID string for fix instructions
$exampleId = ($results | Select-Object -First 1).IdentityReference.ToString()

Write-Host ""
Write-Host "How to fix this manually" -ForegroundColor Cyan
Write-Host ""

Write-Host "  1) Open Active Directory Users and Computers" -ForegroundColor Yellow
Write-Host "     Click View then enable  Advanced Features"
Write-Host ""

Write-Host ("  2) In the left pane, right-click the domain root  {0}  and choose Properties" -f $dnsName) -ForegroundColor Yellow
Write-Host "     Go to the Security tab and click the Advanced button"
Write-Host ""

Write-Host ("  3) Locate the ACE entries for  {0}" -f $exampleId) -ForegroundColor Yellow
Write-Host ("     These correspond to the PingCastle flagged group  {0}" -f $GroupName)
Write-Host ""

Write-Host "  4) Remove the explicit ACE entries for this group ONLY on the domain root" -ForegroundColor Yellow
Write-Host "     Important"
Write-Host "       Do NOT check  Replace all child object permissions"
Write-Host "       Only remove the ACEs directly on the root DN"
Write-Host ""

Write-Host "  5) Apply changes and close all dialogs" -ForegroundColor Yellow
Write-Host ""

Write-Host ("  6) Re-run this script to confirm that no ACEs remain for  {0}" -f $GroupName) -ForegroundColor Yellow
