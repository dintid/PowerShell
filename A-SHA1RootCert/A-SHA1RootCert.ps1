Get-ChildItem -Path Cert:\LocalMachine\My | 
    Where-Object { $_.SignatureAlgorithm.FriendlyName -match "sha1" } |
    Select-Object Subject, @{Name='SignatureAlgorithm';Expression={$_.SignatureAlgorithm.FriendlyName}}, NotBefore, NotAfter
