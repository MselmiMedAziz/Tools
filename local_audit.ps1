<#
.SYNOPSIS
  Local network discovery + laptop security-configuration audit using only built-in Windows
  PowerShell / cmd tools. No administrator rights and nothing to install.
  AUTHORIZED USE ONLY.

.DESCRIPTION
  Network mode
    For each connected adapter: reads the neighbor (ARP) cache, optionally ping-sweeps the local
    subnet to populate it, resolves host names and lists every IP + MAC address on the same
    network. Flags missing client isolation on Wi-Fi, randomized MACs and IPs sharing a MAC.
    -PortCheck adds a quick TCP check of common ports on the hosts found.
    -PassiveOnly reads the existing neighbor cache only (sends nothing).

  Host mode (read-only)
    OS support / patch age / Insider builds, local admins, built-in accounts, autologon, LAPS,
    UAC, LSA protection, Credential Guard, WDigest, NTLM level, antivirus & Defender, firewall,
    BitLocker, Secure Boot, LLMNR / NetBIOS / mDNS / WPAD, SMBv1 / SMB signing / guest auth,
    RDP / NLA, WinRM, Remote Registry, listening ports, shares, saved Wi-Fi profiles,
    mobile hotspot policy, stored credentials (count only), PowerShell v2 / logging / language
    mode, AppLocker, AlwaysInstallElevated, unquoted service paths, service binaries and PATH
    folders writable by the current user, screen lock, USB storage, local password policy.

  Output: <OutDir>\report.html, neighbors.csv, listening.csv, findings.json

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\local_audit.ps1
  powershell -ExecutionPolicy Bypass -File .\local_audit.ps1 -Mode Network -PortCheck
  powershell -ExecutionPolicy Bypass -File .\local_audit.ps1 -Mode Network -PassiveOnly
  powershell -ExecutionPolicy Bypass -File .\local_audit.ps1 -Mode Host
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Network', 'Host')][string]$Mode = 'All',
    [string]$OutDir = ".\local-audit-$env:COMPUTERNAME",
    [string[]]$InterfaceAlias,      # limit discovery to these adapters (Get-NetAdapter names)
    [switch]$IncludeVirtual,        # also scan VMware / Hyper-V / VPN adapters
    [switch]$FullSubnet,            # sweep the whole subnet even if larger than /24 (max 4096 hosts)
    [switch]$PassiveOnly,           # do not ping: only read the neighbor cache
    [switch]$PortCheck,             # TCP check of common ports on discovered hosts
    [int]$TimeoutMs = 400
)

$ErrorActionPreference = 'Continue'
$OutFull = (New-Item -ItemType Directory -Force -Path $OutDir).FullName
$Findings = New-Object System.Collections.ArrayList
$Facts = [ordered]@{}
$Neighbors = New-Object System.Collections.ArrayList
$Listening = New-Object System.Collections.ArrayList
$FullLang = $ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage'
$PortList = 21, 22, 23, 80, 135, 139, 443, 445, 515, 631, 3389, 5900, 5985, 8080, 9100

# ------------------------------------------------------------------ helpers
function Add-Finding([string]$Severity, [string]$Area, [string]$Title, [string]$Target, [string]$Detail, [string]$Fix = '') {
    [void]$Findings.Add([pscustomobject]@{ severity = $Severity; area = $Area; title = $Title; target = $Target; detail = $Detail; fix = $Fix })
    $color = @{ critical = 'Red'; high = 'Red'; medium = 'Yellow'; low = 'Cyan'; info = 'Gray' }[$Severity]
    Write-Host ("  [{0,-8}] {1} - {2}" -f $Severity.ToUpper(), $Title, $Target) -ForegroundColor $color
}

function Get-Reg([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Invoke-Safe([string]$Name, [scriptblock]$Block) {
    try { & $Block } catch { Write-Host "  [!] $Name check failed: $($_.Exception.Message)" -ForegroundColor DarkGray }
}

function ConvertTo-UInt32([string]$Ip) {
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0)
}
function ConvertFrom-UInt32([uint32]$N) {
    $b = [BitConverter]::GetBytes($N); [Array]::Reverse($b); ($b | ForEach-Object { $_ }) -join '.'
}

function Get-SubnetRange([string]$Ip, [int]$Prefix) {
    if ($Prefix -lt 24 -and -not $FullSubnet) { $Prefix = 24 }
    if ($Prefix -lt 20) { $Prefix = 20 }                                   # hard cap: 4096 addresses
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Prefix))
    $net = [uint32]((ConvertTo-UInt32 $Ip) -band $mask)
    $count = [uint32][math]::Pow(2, 32 - $Prefix)
    [pscustomobject]@{ Network = $net; Broadcast = [uint32]($net + $count - 1); Prefix = $Prefix }
}

function Test-InRange([string]$Ip, $Range) {
    try { $n = ConvertTo-UInt32 $Ip; ($n -ge $Range.Network) -and ($n -le $Range.Broadcast) } catch { $false }
}

function Encode([string]$s) { ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;') }

# ------------------------------------------------------------------ network discovery
function Invoke-PingSweep([string[]]$Ips) {
    $alive = @{}
    if ($FullLang) {
        for ($i = 0; $i -lt $Ips.Count; $i += 128) {
            $batch = @($Ips[$i..([math]::Min($i + 127, $Ips.Count - 1))])
            $tasks = @(foreach ($ip in $batch) { (New-Object System.Net.NetworkInformation.Ping).SendPingAsync($ip, $TimeoutMs) })
            try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks, $TimeoutMs + 4000) } catch {}
            for ($k = 0; $k -lt $batch.Count; $k++) {
                $t = $tasks[$k]
                if ($t.Status -eq 'RanToCompletion' -and $t.Result.Status -eq 'Success') { $alive[$batch[$k]] = $true }
            }
            Write-Progress -Activity 'Ping sweep' -PercentComplete ([math]::Min(100, 100 * ($i + 128) / $Ips.Count))
        }
    } else {
        # Constrained Language Mode: fall back to ping.exe (slower, sequential)
        $n = 0
        foreach ($ip in $Ips) {
            if ((& ping.exe -n 1 -w $TimeoutMs $ip) -match 'TTL=') { $alive[$ip] = $true }
            $n++; Write-Progress -Activity 'Ping sweep (ping.exe)' -PercentComplete (100 * $n / $Ips.Count)
        }
    }
    Write-Progress -Activity 'Ping sweep' -Completed
    $alive
}

function Get-NeighborCache([int]$Index) {
    $res = @()
    try {
        $res = @(Get-NetNeighbor -InterfaceIndex $Index -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe', 'Permanent' } |
            ForEach-Object { [pscustomobject]@{ Ip = $_.IPAddress; Mac = $_.LinkLayerAddress; State = [string]$_.State } })
    } catch {
        # fallback: arp -a (all interfaces; filtered by range by the caller)
        foreach ($line in (& arp.exe -a)) {
            if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})\s+(\S+)') {
                $res += [pscustomobject]@{ Ip = $Matches[1]; Mac = $Matches[2].ToUpper(); State = $Matches[4] }
            }
        }
    }
    $res | Where-Object { $_.Mac -and $_.Mac -notin '00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF' -and $_.Ip -notmatch '^(22[4-9]|23\d|24\d|25[0-5])\.' }
}

function Resolve-Names([string[]]$Ips) {
    $names = @{}
    if (-not $FullLang -or -not $Ips) { return $names }
    $tasks = @{}
    foreach ($ip in $Ips) { try { $tasks[$ip] = [System.Net.Dns]::GetHostEntryAsync($ip) } catch {} }
    try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks.Values), 4000) } catch {}
    foreach ($ip in $tasks.Keys) {
        $t = $tasks[$ip]
        if ($t.Status -eq 'RanToCompletion' -and $t.Result.HostName -ne $ip) { $names[$ip] = $t.Result.HostName }
    }
    $names
}

function Test-Ports([string[]]$Ips) {
    $open = @{}
    if (-not $FullLang) { Write-Host '  [!] Port check needs FullLanguage mode - skipped'; return $open }
    $targets = @(foreach ($ip in $Ips) { foreach ($p in $PortList) { [pscustomobject]@{ Ip = $ip; Port = $p } } })
    for ($i = 0; $i -lt $targets.Count; $i += 300) {
        $slice = @($targets[$i..([math]::Min($i + 299, $targets.Count - 1))])
        $conns = @(foreach ($t in $slice) {
                $c = New-Object System.Net.Sockets.TcpClient
                [pscustomobject]@{ Ip = $t.Ip; Port = $t.Port; Client = $c; Task = $c.ConnectAsync($t.Ip, $t.Port) }
            })
        try { [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($conns | ForEach-Object { $_.Task }), 1500) } catch {}
        foreach ($x in $conns) {
            if ($x.Task.Status -eq 'RanToCompletion') { $open[$x.Ip] = @($open[$x.Ip]) + $x.Port | Where-Object { $_ } }
            try { $x.Client.Close() } catch {}
        }
    }
    $open
}

function Invoke-NetworkDiscovery {
    Write-Host "`n=== Local network discovery ===" -ForegroundColor White
    $ifaces = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object {
            $ad = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
            if ($ad -and $ad.Status -eq 'Up') {
                [pscustomobject]@{
                    Alias = $ad.Name; Index = $_.InterfaceIndex; Ip = $_.IPAddress; Prefix = [int]$_.PrefixLength
                    Mac = $ad.MacAddress; Desc = $ad.InterfaceDescription; Media = [string]$ad.PhysicalMediaType
                    Virtual = [bool]($ad.InterfaceDescription -match 'VMware|Virtual|Hyper-V|VirtualBox|TAP-|WireGuard|Wintun|Loopback|VPN')
                }
            }
        })
    if ($InterfaceAlias) { $ifaces = @($ifaces | Where-Object { $_.Alias -in $InterfaceAlias }) }
    elseif (-not $IncludeVirtual) { $ifaces = @($ifaces | Where-Object { -not $_.Virtual }) }
    if (-not $ifaces) { Write-Host '  [!] No connected adapter to scan.'; return }

    foreach ($if in $ifaces) {
        $range = Get-SubnetRange $if.Ip $if.Prefix
        $gw = (Get-NetRoute -InterfaceIndex $if.Index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1).NextHop
        $isWifi = $if.Media -match '802\.11'
        Write-Host ("[*] {0} ({1}) {2}/{3}  gateway {4}  -> scanning {5}/{6}" -f $if.Alias, $if.Desc, $if.Ip, $if.Prefix, $gw,
            (ConvertFrom-UInt32 $range.Network), $range.Prefix)
        $Facts["adapter: $($if.Alias)"] = "$($if.Desc) | $($if.Ip)/$($if.Prefix) | MAC $($if.Mac) | gateway $gw"

        $cached = @{}
        foreach ($n in (Get-NeighborCache $if.Index)) { if (Test-InRange $n.Ip $range) { $cached[$n.Ip] = $true } }

        $alive = @{}
        if (-not $PassiveOnly) {
            $ips = @(for ($n = $range.Network + 1; $n -lt $range.Broadcast; $n++) { ConvertFrom-UInt32 ([uint32]$n) })
            $alive = Invoke-PingSweep $ips
            Start-Sleep -Seconds 2   # let late ARP replies land in the cache
        }

        $hosts = @{}
        foreach ($n in (Get-NeighborCache $if.Index)) {
            if (Test-InRange $n.Ip $range) { $hosts[$n.Ip] = $n }
        }
        foreach ($ip in $alive.Keys) { if (-not $hosts[$ip]) { $hosts[$ip] = [pscustomobject]@{ Ip = $ip; Mac = '?'; State = 'ping only' } } }
        $hosts.Remove($if.Ip)

        $names = Resolve-Names @($hosts.Keys)
        $ports = @{}
        if ($PortCheck -and $hosts.Count) { Write-Host "  [*] Checking $($PortList.Count) TCP ports on $($hosts.Count) hosts ..."; $ports = Test-Ports @($hosts.Keys) }

        $gwMac = if ($gw -and $hosts[$gw]) { $hosts[$gw].Mac } else { $null }
        foreach ($ip in ($hosts.Keys | Sort-Object { ConvertTo-UInt32 $_ })) {
            $h = $hosts[$ip]
            $randomized = $h.Mac -match '^.[26AEae]-'
            $role = if ($ip -eq $gw) { 'gateway' } elseif ($gwMac -and $h.Mac -eq $gwMac) { 'proxy-ARP (gateway MAC)' } else { 'host' }
            [void]$Neighbors.Add([pscustomobject]@{
                    Interface = $if.Alias; IP = $ip; MAC = $h.Mac; Hostname = [string]$names[$ip]; Role = $role
                    PingReply = [bool]$alive[$ip]; InCacheBefore = [bool]$cached[$ip]; ArpState = $h.State
                    RandomizedMAC = $randomized; OpenPorts = (@($ports[$ip]) -join ',')
                })
        }

        $rows = @($Neighbors | Where-Object { $_.Interface -eq $if.Alias })
        $peers = @($rows | Where-Object { $_.Role -eq 'host' })
        $proxied = @($rows | Where-Object { $_.Role -like 'proxy*' })
        Write-Host ("  {0} hosts found ({1} peers, gateway {2})" -f $rows.Count, $peers.Count, $(if ($gwMac) { $gwMac } else { '?' }))

        if ($proxied.Count -gt 5) {
            Add-Finding 'info' 'network' 'Gateway answers ARP for other clients (proxy-ARP)' $if.Alias `
                "$($proxied.Count) IPs resolve to the gateway MAC $gwMac - typical of controllers enforcing client isolation."
        }
        if ($isWifi -and $peers.Count) {
            Add-Finding 'medium' 'network' 'Other Wi-Fi clients reachable (no client isolation)' "$($if.Alias) $($if.Ip)/$($if.Prefix)" `
                ("{0} hosts answered on the wireless subnet, e.g. {1}" -f $peers.Count, (($peers | Select-Object -First 10 | ForEach-Object { "$($_.IP) [$($_.MAC)]" }) -join ', ')) `
                'Enable client/peer-to-peer isolation on the WLAN.'
        } elseif ($peers.Count) {
            Add-Finding 'info' 'network' 'Hosts on the same local network' "$($if.Alias) $($if.Ip)/$($if.Prefix)" "$($peers.Count) peers found (see neighbors.csv)."
        }
        $dups = @($rows | Where-Object { $_.MAC -ne '?' -and $_.Role -eq 'host' } | Group-Object MAC | Where-Object { $_.Count -gt 1 })
        foreach ($d in $dups) {
            Add-Finding 'low' 'network' 'Several IPs share one MAC address' "$($if.Alias) $($d.Name)" `
                ("IPs: {0}. Usually a router/NAT/multi-homed device; otherwise it can indicate ARP spoofing." -f (($d.Group | ForEach-Object { $_.IP }) -join ', '))
        }
        foreach ($r in @($peers | Where-Object { $_.OpenPorts -match '\b(23|445|3389|5900)\b' })) {
            Add-Finding 'low' 'network' 'Peer exposes remote-access / file-sharing ports' "$($r.IP) [$($r.MAC)]" "Open: $($r.OpenPorts)" `
                'Host firewall should block inbound on untrusted/Wi-Fi networks.'
        }
    }
    $Neighbors | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutFull 'neighbors.csv')
}

# ------------------------------------------------------------------ host audit
function Invoke-HostAudit {
    Write-Host "`n=== Laptop configuration audit ===" -ForegroundColor White
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Facts['user'] = $me.Name
    $Facts['language mode'] = [string]$ExecutionContext.SessionState.LanguageMode

    Invoke-Safe 'OS' {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $build = [int]$os.BuildNumber
        $ubr = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
        $disp = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
        $Facts['os'] = "$($os.Caption) $disp build $build.$ubr"
        $Facts['domain'] = if ($cs.PartOfDomain) { $cs.Domain } else { "WORKGROUP ($($cs.Domain))" }
        if ($build -lt 22000) {
            Add-Finding 'high' 'os' 'Windows 10 is out of mainstream support' $os.Caption `
                'Windows 10 support ended on 14 Oct 2025; the device only gets security fixes if enrolled in ESU.' 'Upgrade to a supported Windows 11 release or confirm ESU enrolment.'
        } elseif ($build -lt 26100) {
            Add-Finding 'medium' 'os' 'Older Windows 11 release' "$($os.Caption) $disp ($build)" `
                'Windows 11 21H2/22H2 are out of support and 23H2 Home/Pro ended Nov 2025 (Enterprise/Education: Nov 2026).' 'Move to 24H2 or later.'
        }
        if (Get-Reg 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability' 'BranchName') {
            Add-Finding 'low' 'os' 'Windows Insider Preview build on a corporate device' "build $build.$ubr" `
                "Insider channel: $(Get-Reg 'HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability' 'BranchName'). Pre-release builds are not supported for production use." 'Leave the Insider program and install a GA release.'
        }
        $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        if ($hf) {
            $age = ((Get-Date) - $hf[0].InstalledOn).Days
            $Facts['last update'] = "$($hf[0].HotFixID) on $($hf[0].InstalledOn.ToString('yyyy-MM-dd')) ($age days ago)"
            if ($age -gt 45) { Add-Finding 'medium' 'os' 'No Windows update installed recently' $env:COMPUTERNAME "Last update $age days ago ($($hf[0].HotFixID))." 'Check Windows Update / WSUS / Intune compliance.' }
        }
    }

    Invoke-Safe 'Accounts' {
        # whoami also lists the group when UAC has filtered it out of the current (non-elevated) token
        if (((& whoami.exe /groups /fo csv) -match 'S-1-5-32-544') -or ($me.Groups.Value -contains 'S-1-5-32-544')) {
            Add-Finding 'medium' 'accounts' 'Current user is a local administrator' $me.Name 'Day-to-day accounts with admin rights let malware take over the device.' 'Use a standard account; elevate with a separate admin account / LAPS.'
        }
        $adm = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        $members = @(Get-LocalGroupMember -Group $adm -ErrorAction Stop | ForEach-Object { $_.Name })
        $Facts['local administrators'] = $members -join ', '
        $broad = @($members | Where-Object { $_ -match '\\(Domain Users|Utilisateurs du domaine|Everyone|Tout le monde|Authenticated Users|Utilisateurs authentifi)' })
        if ($broad) { Add-Finding 'high' 'accounts' 'Broad group in local Administrators' ($broad -join ', ') 'Every member of these groups is admin on this laptop.' 'Remove broad groups from local Administrators.' }
        foreach ($u in @(Get-LocalUser -ErrorAction Stop)) {
            if ($u.SID.Value -like '*-500' -and $u.Enabled) { Add-Finding 'medium' 'accounts' 'Built-in Administrator account enabled' $u.Name 'A well-known account name is a brute-force and lateral-movement target.' 'Disable it, or manage its password with LAPS.' }
            if ($u.SID.Value -like '*-501' -and $u.Enabled) { Add-Finding 'medium' 'accounts' 'Guest account enabled' $u.Name '' 'Disable the Guest account.' }
        }
    }
    Invoke-Safe 'Autologon/LAPS' {
        $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if ((Get-Reg $wl 'AutoAdminLogon') -eq '1') { Add-Finding 'medium' 'accounts' 'Automatic logon enabled' (Get-Reg $wl 'DefaultUserName') 'The device logs on without a password.' 'Disable AutoAdminLogon.' }
        if ($null -ne (Get-Reg $wl 'DefaultPassword')) { Add-Finding 'high' 'accounts' 'Logon password stored in the registry' 'Winlogon\DefaultPassword' 'A clear-text password is stored in a registry value readable on this device (value not displayed).' 'Remove DefaultPassword and change that password.' }
        $laps = (Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory') -or
                (Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled') -or
                (Test-Path 'C:\Program Files\LAPS\CSE\AdmPwd.dll')
        if (-not $laps) { Add-Finding 'low' 'accounts' 'No LAPS policy detected' $env:COMPUTERNAME 'Local admin passwords may be identical across laptops (one compromise = all).' 'Deploy Windows LAPS.' }
    }

    Invoke-Safe 'UAC' {
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if ((Get-Reg $p 'EnableLUA') -eq 0) { Add-Finding 'high' 'uac' 'UAC disabled' 'EnableLUA=0' 'All admin processes run fully elevated.' 'Enable UAC.' }
        if ((Get-Reg $p 'ConsentPromptBehaviorAdmin') -eq 0) { Add-Finding 'medium' 'uac' 'UAC elevates admins without prompting' 'ConsentPromptBehaviorAdmin=0' '' 'Set to prompt for consent on the secure desktop.' }
        if ((Get-Reg $p 'PromptOnSecureDesktop') -eq 0) { Add-Finding 'low' 'uac' 'UAC prompt not on the secure desktop' 'PromptOnSecureDesktop=0' '' 'Enable the secure desktop.' }
        if ((Get-Reg $p 'LocalAccountTokenFilterPolicy') -eq 1) { Add-Finding 'medium' 'uac' 'Remote UAC filtering disabled' 'LocalAccountTokenFilterPolicy=1' 'Local admin accounts get full admin rights over the network (pass-the-hash).' 'Remove the value / set to 0.' }
        $lock = Get-Reg $p 'InactivityTimeoutSecs'
        if (-not $lock -or $lock -gt 900) { Add-Finding 'low' 'uac' 'No machine inactivity lock policy (or > 15 min)' "InactivityTimeoutSecs=$lock" '' 'Set the screen to lock after 15 minutes or less.' }
    }

    Invoke-Safe 'Credential protection' {
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if ((Get-Reg $lsa 'RunAsPPL') -notin 1, 2) { Add-Finding 'medium' 'credentials' 'LSA protection (RunAsPPL) not enabled' 'Lsa\RunAsPPL' 'Credential-dumping tools can read LSASS memory.' 'Enable LSA protection.' }
        if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1) { Add-Finding 'high' 'credentials' 'WDigest stores clear-text passwords' 'UseLogonCredential=1' '' 'Set UseLogonCredential to 0.' }
        $lm = Get-Reg $lsa 'LmCompatibilityLevel'
        if ($null -ne $lm -and $lm -lt 3) { Add-Finding 'medium' 'credentials' 'LM / NTLMv1 authentication allowed' "LmCompatibilityLevel=$lm" 'NTLMv1 responses can be cracked or relayed easily.' 'Set LmCompatibilityLevel to 5.' }
        if ((Get-Reg $lsa 'NoLMHash') -eq 0) { Add-Finding 'medium' 'credentials' 'LM hashes stored' 'NoLMHash=0' '' 'Set NoLMHash to 1.' }
        try {
            $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
            $Facts['credential guard'] = if (@($dg.SecurityServicesRunning) -contains 1) { 'running' } else { 'not running' }
            if (@($dg.SecurityServicesRunning) -notcontains 1) { Add-Finding 'low' 'credentials' 'Credential Guard not running' $env:COMPUTERNAME '' 'Enable Credential Guard (VBS) where hardware allows.' }
        } catch {}
        $n = ((& cmdkey.exe /list) -match 'target=').Count
        $Facts['stored credentials (cmdkey)'] = $n
        if ($n -gt 0) { Add-Finding 'info' 'credentials' 'Saved credentials in Credential Manager' "$n entries" 'Saved credentials can be reused by malware running as this user (targets listed by: cmdkey /list).' 'Avoid saving passwords for servers/RDP.' }
    }

    Invoke-Safe 'Antivirus' {
        $avs = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
        $Facts['antivirus'] = ($avs | ForEach-Object { $_.displayName }) -join ', '
        $active = @($avs | Where-Object { (($_.productState -shr 12) -band 0xF) -in 1, 3 })
        if (-not $active) { Add-Finding 'high' 'antivirus' 'No active antivirus reported' ($Facts['antivirus']) 'Windows Security Center reports no enabled antivirus.' 'Enable/repair the endpoint protection agent.' }
        foreach ($av in $active) {
            if ((($av.productState -shr 4) -band 0xF) -ne 0) { Add-Finding 'medium' 'antivirus' 'Antivirus signatures out of date' $av.displayName '' 'Update signatures; check agent connectivity.' }
        }
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            if ($mp.AMRunningMode -eq 'Normal') {
                if (-not $mp.RealTimeProtectionEnabled) { Add-Finding 'high' 'antivirus' 'Defender real-time protection off' $env:COMPUTERNAME '' 'Enable real-time protection.' }
                if (-not $mp.IsTamperProtected) { Add-Finding 'low' 'antivirus' 'Defender tamper protection off' $env:COMPUTERNAME '' 'Enable tamper protection (Intune / Defender portal).' }
            }
            $pref = Get-MpPreference -ErrorAction Stop
            $ex = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ -and $_ -notmatch 'Must be an administrator|N/A' }
            if ($ex) { Add-Finding 'medium' 'antivirus' 'Defender exclusions visible to standard users' ($ex -join '; ') 'Excluded paths are places where malware is not scanned, and users can see them.' 'Review exclusions; hide them from non-admins (HideExclusionsFromLocalUsers).' }
        } catch {}
    }

    Invoke-Safe 'Firewall' {
        foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            if (-not $p.Enabled) { Add-Finding 'high' 'firewall' "Firewall disabled ($($p.Name) profile)" $p.Name '' 'Enable Windows Firewall on all profiles.' }
            elseif ($p.DefaultInboundAction -eq 'Allow') { Add-Finding 'high' 'firewall' "Firewall allows all inbound ($($p.Name) profile)" $p.Name '' 'Set default inbound action to Block.' }
        }
        $Facts['network category'] = (@(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias)=$($_.NetworkCategory)" }) -join ', ')
    }

    Invoke-Safe 'Disk encryption' {
        if ($FullLang) {
            $v = (New-Object -ComObject Shell.Application).NameSpace("$env:SystemDrive\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
            $Facts['bitlocker (system drive)'] = $v
            if ($v -eq 2) { Add-Finding 'high' 'encryption' 'System drive not encrypted (BitLocker off)' $env:SystemDrive 'A lost or stolen laptop exposes all data and cached credentials.' 'Enable BitLocker with TPM (+PIN).' }
        }
        if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled') -eq 0) { Add-Finding 'medium' 'encryption' 'Secure Boot disabled' $env:COMPUTERNAME '' 'Enable Secure Boot in UEFI.' }
    }

    Invoke-Safe 'Name resolution' {
        if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -ne 0) { Add-Finding 'medium' 'network-hardening' 'LLMNR enabled' $env:COMPUTERNAME 'Anyone on the same network can answer LLMNR queries and capture NTLM hashes.' 'GPO: Turn off multicast name resolution.' }
        foreach ($c in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')) {
            if ($c.TcpipNetbiosOptions -ne 2) { Add-Finding 'medium' 'network-hardening' 'NetBIOS over TCP/IP enabled' $c.Description 'NBT-NS can be poisoned the same way as LLMNR.' 'Disable NetBIOS over TCP/IP (DHCP option or adapter setting).' }
        }
        if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS') -ne 0) { Add-Finding 'low' 'network-hardening' 'mDNS enabled' $env:COMPUTERNAME 'The laptop answers and sends multicast DNS on every network.' 'Disable mDNS if not needed (EnableMDNS=0).' }
        if ((Get-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoDetect') -ne 0) { Add-Finding 'low' 'network-hardening' 'WPAD proxy auto-detection enabled' $me.Name 'A rogue WPAD answer can redirect web traffic through an attacker proxy.' 'Disable "Automatically detect settings" unless WPAD is used.' }
    }

    Invoke-Safe 'SMB' {
        $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $smb1 = Get-Service mrxsmb10 -ErrorAction SilentlyContinue
        if ($smb1 -and $smb1.StartType -ne 'Disabled') { Add-Finding 'medium' 'smb' 'SMBv1 client installed' 'mrxsmb10' 'SMBv1 is obsolete and was used by WannaCry/NotPetya.' 'Remove the SMB 1.0/CIFS feature.' }
        if ((Get-Reg $srv 'SMB1') -eq 1) { Add-Finding 'high' 'smb' 'SMBv1 server enabled' 'LanmanServer\SMB1=1' '' 'Disable SMBv1.' }
        if ((Get-Reg $srv 'RequireSecuritySignature') -ne 1) { Add-Finding 'medium' 'smb' 'SMB server signing not required' $env:COMPUTERNAME 'SMB relay attacks against this laptop are possible.' 'GPO: Microsoft network server: Digitally sign communications (always).' }
        if ((Get-Reg $wks 'RequireSecuritySignature') -ne 1) { Add-Finding 'low' 'smb' 'SMB client signing not required' $env:COMPUTERNAME '' 'GPO: Microsoft network client: Digitally sign communications (always).' }
        if ((Get-Reg $wks 'AllowInsecureGuestAuth') -eq 1) { Add-Finding 'medium' 'smb' 'Insecure SMB guest logons allowed' 'AllowInsecureGuestAuth=1' 'The laptop will connect to unauthenticated (possibly rogue) SMB servers.' 'Set AllowInsecureGuestAuth to 0.' }
        try {
            $shares = @(Get-CimInstance Win32_Share -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$$' })
            foreach ($s in $shares) {
                if ($s.Type -eq 0) { Add-Finding 'medium' 'smb' 'Folder shared from the laptop' "\\$env:COMPUTERNAME\$($s.Name)" "Path: $($s.Path)" 'Remove user shares from laptops.' }
                elseif ($s.Type -eq 1) { Add-Finding 'low' 'smb' 'Printer shared from the laptop' "\\$env:COMPUTERNAME\$($s.Name)" 'The laptop acts as a print server (Print Spooler reachable over SMB).' 'Unshare printers on laptops.' }
            }
        } catch {}
    }

    Invoke-Safe 'Remote access' {
        $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if ((Get-Reg $ts 'fDenyTSConnections') -eq 0) {
            $nla = Get-Reg "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
            if ($nla -eq 0) { Add-Finding 'high' 'remote-access' 'RDP enabled without Network Level Authentication' $env:COMPUTERNAME '' 'Require NLA, or disable RDP on laptops.' }
            else { Add-Finding 'low' 'remote-access' 'RDP enabled' $env:COMPUTERNAME 'Remote Desktop is listening on this laptop.' 'Disable RDP on laptops unless required; restrict with firewall.' }
        }
        foreach ($svc in 'WinRM', 'RemoteRegistry', 'SSHD', 'TlntSvr', 'SNMP') {
            $s = Get-Service $svc -ErrorAction SilentlyContinue
            if ($s -and $s.Status -eq 'Running') { Add-Finding 'low' 'remote-access' "Remote management service running: $($s.DisplayName)" $svc '' 'Stop/disable it on laptops unless required.' }
        }
    }

    Invoke-Safe 'Listening ports' {
        $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
        foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' })) {
            [void]$Listening.Add([pscustomobject]@{ Proto = 'TCP'; Address = $c.LocalAddress; Port = $c.LocalPort; PID = $c.OwningProcess; Process = [string]$procs[[int]$c.OwningProcess] })
        }
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' })) {
            [void]$Listening.Add([pscustomobject]@{ Proto = 'UDP'; Address = $u.LocalAddress; Port = $u.LocalPort; PID = $u.OwningProcess; Process = [string]$procs[[int]$u.OwningProcess] })
        }
        $Listening | Sort-Object Proto, Port -Unique | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutFull 'listening.csv')
        $odd = @($Listening | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -notin 135, 139, 445, 5040, 7680 -and $_.Port -lt 49152 })
        if ($odd) {
            Add-Finding 'info' 'listening' 'Services listening on the network' $env:COMPUTERNAME `
                (($odd | Sort-Object Port -Unique | ForEach-Object { "$($_.Port)/$($_.Process)" }) -join ', ') 'Check each one is needed and firewalled.'
        }
    }

    Invoke-Safe 'Wi-Fi profiles' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wlanprof-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            & netsh.exe wlan export profile "folder=$tmp" | Out-Null      # no key=clear: passwords are not exported
            foreach ($f in @(Get-ChildItem $tmp -Filter *.xml)) {
                [xml]$x = Get-Content -LiteralPath $f.FullName -Raw
                $val = { param($n) $node = $x.SelectSingleNode("//*[local-name()='$n']"); if ($node) { $node.InnerText } }
                $name = & $val 'name'; $auth = & $val 'authentication'; $enc = & $val 'encryption'
                $mode = & $val 'connectionMode'; $hidden = & $val 'nonBroadcast'; $onex = & $val 'useOneX'
                if ($auth -eq 'open' -and $enc -eq 'none' -and $mode -eq 'auto') { Add-Finding 'medium' 'wifi' 'Auto-connects to an open Wi-Fi network' $name 'A fake access point with this name will be joined automatically.' 'Set open networks to manual connect or remove the profile.' }
                if ($enc -in 'WEP', 'TKIP') { Add-Finding 'medium' 'wifi' "Saved Wi-Fi profile uses $enc" $name '' 'Remove or upgrade the network to WPA2/WPA3-AES.' }
                if ($hidden -eq 'true') { Add-Finding 'low' 'wifi' 'Profile for a hidden network' $name 'The laptop broadcasts this network name everywhere while looking for it.' 'Avoid hidden SSIDs.' }
                if ($onex -eq 'true') {
                    $prompt = & $val 'DisableUserPromptForServerValidation'
                    $ca = $x.SelectNodes("//*[local-name()='TrustedRootCA']").Count
                    $names = & $val 'ServerNames'
                    if ($prompt -ne 'true' -or $ca -eq 0 -or -not $names) {
                        Add-Finding 'medium' 'wifi' '802.1X profile with weak server-certificate validation' $name `
                            "Pinned CA: $ca, server names: '$names', user can accept unknown certs: $($prompt -ne 'true'). A rogue AP could collect domain credentials." `
                            'Pin the RADIUS CA and server name; disable the user prompt (GPO/Intune).'
                    }
                }
            }
        } finally { Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue }
        if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' 'NC_ShowSharedAccessUI') -ne 0) {
            Add-Finding 'low' 'wifi' 'Mobile hotspot / connection sharing not blocked by policy' $env:COMPUTERNAME 'Users can share the corporate connection with unmanaged devices.' 'GPO: Prohibit use of Internet Connection Sharing.'
        }
    }

    Invoke-Safe 'PowerShell / app control' {
        if ($FullLang) { Add-Finding 'low' 'app-control' 'PowerShell runs in FullLanguage mode for standard users' $me.Name 'No application control (WDAC/AppLocker) restricts scripts.' 'Deploy WDAC or AppLocker with script enforcement.' }
        if ((Get-Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion') -like '2.*') { Add-Finding 'medium' 'app-control' 'PowerShell 2.0 engine installed' $env:COMPUTERNAME 'PowerShell 2.0 bypasses script-block logging and AMSI.' 'Remove the Windows PowerShell 2.0 feature.' }
        if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -ne 1) { Add-Finding 'low' 'app-control' 'PowerShell script-block logging not enabled' $env:COMPUTERNAME '' 'Enable script-block logging via GPO.' }
        try {
            [xml]$al = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            if ($al.SelectNodes('//*[local-name()="FilePathRule" or local-name()="FilePublisherRule" or local-name()="FileHashRule"]').Count -eq 0) {
                Add-Finding 'info' 'app-control' 'No AppLocker rules in effect' $env:COMPUTERNAME '' 'Consider WDAC/AppLocker.'
            }
        } catch {}
        if ((Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') -eq 1 -and
            (Get-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') -eq 1) {
            Add-Finding 'high' 'privilege' 'AlwaysInstallElevated enabled' $env:COMPUTERNAME 'Any user can install MSI packages with SYSTEM rights.' 'Disable AlwaysInstallElevated (HKLM and HKCU).'
        }
    }

    Invoke-Safe 'Services and PATH permissions' {
        $mySids = @($me.User.Value) + @($me.Groups | ForEach-Object { $_.Value }) | Where-Object { $_ -ne 'S-1-5-32-544' }
        $writeMask = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000   # WriteData, AppendData, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL
        $writable = {
            param($path)
            try { $acl = Get-Acl -LiteralPath $path -ErrorAction Stop } catch { return $false }
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow' -or ($ace.PropagationFlags -band 2)) { continue }   # skip deny / inherit-only
                try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
                if ($sid -in $mySids -and ([int]$ace.FileSystemRights -band $writeMask)) { return $true }
            }
            $false
        }
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName })) {
            $pn = $s.PathName.Trim()
            $exe = if ($pn.StartsWith('"')) { $pn.Split('"')[1] } elseif ($pn -match '^(.+?\.exe)') { $Matches[1] } else { $pn.Split(' ')[0] }
            if (-not $pn.StartsWith('"') -and $exe -match ' ' -and $exe -notmatch '^[A-Za-z]:\\Windows\\') {
                Add-Finding 'medium' 'privilege' 'Unquoted service path with spaces' $s.Name "$pn (runs as $($s.StartName))" 'Quote the service ImagePath.'
            }
            if ((Test-Path -LiteralPath $exe) -and (& $writable $exe)) {
                Add-Finding 'high' 'privilege' 'Service binary writable by the current user' $s.Name "$exe (runs as $($s.StartName))" 'Fix the file permissions.'
            }
        }
        foreach ($d in ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object { $_ } | Select-Object -Unique)) {
            $d = [Environment]::ExpandEnvironmentVariables($d)
            if ((Test-Path -LiteralPath $d) -and (& $writable $d)) {
                Add-Finding 'high' 'privilege' 'System PATH folder writable by the current user' $d 'Programs running as SYSTEM may load DLLs/EXEs planted here.' 'Remove write access for users.'
            }
        }
    }

    Invoke-Safe 'Device policy' {
        if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start') -eq 3) { Add-Finding 'info' 'device' 'USB mass storage allowed' $env:COMPUTERNAME '' 'Restrict removable storage if your policy requires it.' }
        $lines = @(& net.exe accounts | Where-Object { $_ -match ':' })
        if ($lines.Count -ge 6) {
            $minLen = ($lines[3] -split '\s{2,}|:\s*')[-1].Trim()
            $lockout = ($lines[5] -split '\s{2,}|:\s*')[-1].Trim()
            $Facts['local password policy'] = "min length $minLen, lockout threshold $lockout"
            if ($minLen -match '^\d+$' -and [int]$minLen -lt 12) { Add-Finding 'low' 'device' 'Short minimum password length (local policy)' "min length $minLen" 'Applies to local accounts; domain accounts use the domain policy.' 'Require 12+ characters.' }
            if ($lockout -notmatch '^\d+$' -or [int]$lockout -eq 0) { Add-Finding 'low' 'device' 'No account lockout (local policy)' "threshold: $lockout" 'Local accounts can be brute-forced.' 'Set a lockout threshold.' }
        }
    }
}

# ------------------------------------------------------------------ report
function Write-Report {
    $sev = 'critical', 'high', 'medium', 'low', 'info'
    $sorted = @($Findings | Sort-Object { [array]::IndexOf($sev, $_.severity) }, area)
    $counts = ($sev | ForEach-Object { $s = $_; "<div class='count'><span class='sev $s'>$s</span><b>$(@($sorted | Where-Object { $_.severity -eq $s }).Count)</b></div>" }) -join ''
    $rows = ($sorted | ForEach-Object {
            $fix = if ($_.fix) { "<div class='fix'>Fix: $(Encode $_.fix)</div>" } else { '' }
            "<tr><td><span class='sev $($_.severity)'>$($_.severity)</span></td><td>$(Encode $_.area)</td><td><b>$(Encode $_.title)</b><div>$(Encode $_.detail)</div>$fix</td><td><code>$(Encode $_.target)</code></td></tr>"
        }) -join "`n"
    $nrows = ($Neighbors | ForEach-Object {
            "<tr><td>$(Encode $_.Interface)</td><td><code>$($_.IP)</code></td><td><code>$($_.MAC)</code></td><td>$(Encode $_.Hostname)</td><td>$($_.Role)</td><td>$(if ($_.PingReply) {'yes'})</td><td>$(if ($_.RandomizedMAC) {'yes'})</td><td>$($_.OpenPorts)</td></tr>"
        }) -join "`n"
    $frows = ($Facts.Keys | ForEach-Object { "<tr><td>$(Encode $_)</td><td><code>$(Encode ([string]$Facts[$_]))</code></td></tr>" }) -join "`n"
    $lrows = ($Listening | Sort-Object Proto, Port -Unique | ForEach-Object { "<tr><td>$($_.Proto)</td><td><code>$($_.Address)</code></td><td>$($_.Port)</td><td>$(Encode $_.Process)</td></tr>" }) -join "`n"
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Audit Report</title><style>
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e3e0;--critical:#b42318;--high:#d4500f;--medium:#b7791f;--low:#2f6fb3;--info:#6b6b70}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--fg:#ececee;--muted:#9a9aa2;--line:#2e2e33;--critical:#f97066;--high:#fb8c4f;--medium:#f0b44c;--low:#6aa7ec;--info:#9a9aa2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1150px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}.muted{color:var(--muted)}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.count{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:110px}.count b{display:block;font-size:22px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted)}tr:last-child td{border-bottom:0}
.sev{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:var(--c);border:1px solid var(--c)}
.critical{--c:var(--critical)}.high{--c:var(--high)}.medium{--c:var(--medium)}.low{--c:var(--low)}.info{--c:var(--info)}
.fix{color:var(--muted);margin-top:4px}code{font:12px ui-monospace,Consolas,monospace}
</style></head><body><main>
<h1>Local network &amp; laptop audit</h1>
<div class="muted">$env:COMPUTERNAME &middot; $(Encode $me_name) &middot; generated $(Get-Date -Format 's') &middot; no admin rights used</div>
<div class="counts">$counts</div>
<h2>Findings</h2><div class="wrap"><table><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Target</th></tr>$rows</table></div>
<h2>Hosts on the local network ($($Neighbors.Count))</h2><div class="wrap"><table><tr><th>Interface</th><th>IP</th><th>MAC</th><th>Hostname</th><th>Role</th><th>Ping</th><th>Random MAC</th><th>Open ports</th></tr>$nrows</table></div>
<h2>Listening ports on this laptop</h2><div class="wrap"><table><tr><th>Proto</th><th>Address</th><th>Port</th><th>Process</th></tr>$lrows</table></div>
<h2>Facts</h2><div class="wrap"><table>$frows</table></div>
</main></body></html>
"@
    Set-Content -LiteralPath (Join-Path $OutFull 'report.html') -Value $html -Encoding UTF8
    $Findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutFull 'findings.json') -Encoding UTF8
}

# ------------------------------------------------------------------ main
$me_name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Local audit on $env:COMPUTERNAME as $me_name (language mode: $($ExecutionContext.SessionState.LanguageMode))"
if (-not $FullLang) { Write-Host '[!] Constrained Language Mode: some checks fall back to slower methods or are skipped.' -ForegroundColor Yellow }
if ($Mode -in 'All', 'Network') { Invoke-NetworkDiscovery }
if ($Mode -in 'All', 'Host') { Invoke-HostAudit }
Write-Report
Write-Host "`n[+] Report: $(Join-Path $OutFull 'report.html')" -ForegroundColor Green
if ($Neighbors.Count) { Write-Host "[+] Hosts:  $(Join-Path $OutFull 'neighbors.csv')" -ForegroundColor Green }
