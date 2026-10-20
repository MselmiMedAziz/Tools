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
```


Check BitLocker
```
(New-Object -ComObject Shell.Application).NameSpace("C:\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
```
