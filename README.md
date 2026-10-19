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
```
