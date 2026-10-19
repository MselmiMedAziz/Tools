<#
.SYNOPSIS
  Lightweight TCP connect port scanner - native PowerShell only (5.1 / 7), no admin rights.
  AUTHORIZED USE ONLY: scan only hosts and networks in your written scope.

.DESCRIPTION
  Full TCP connect (no raw packets), many connections in parallel via .NET async sockets.
  Optional ping-first host discovery, banner grabbing (incl. HTTP Server header and
  TLS certificate subject/issuer/expiry) and CSV export.

  Targets: single IP, host name, CIDR (10.0.0.0/24), range (10.0.0.10-50 or
           10.0.0.10-10.0.0.50), comma list, or -TargetFile (one per line).
  Ports:   "top" (default, 95 common ports), "all" (1-65535), or a list/ranges "22,80,443,8000-8100".

.EXAMPLE
  .\portscan.ps1 -Target 192.168.1.1
  .\portscan.ps1 -Target 192.168.1.0/24 -Ports 22,80,443,445,3389 -PingFirst
  .\portscan.ps1 -Target 10.0.0.5 -Ports all -Banner -OutCsv .\gw.csv
  .\portscan.ps1 -TargetFile .\hosts.txt -Ports 1-1024 -Timeout 500 -Parallel 500
#>
[CmdletBinding()]
param(
    [string[]]$Target,
    [string]$TargetFile,
    [string[]]$Ports = @('top'),
    [int]$Timeout = 800,         # ms per connection attempt
    [int]$Parallel = 300,        # simultaneous connection attempts
    [switch]$PingFirst,          # skip hosts that don't answer ping (faster, may miss hosts blocking ICMP)
    [switch]$Banner,             # grab banners / HTTP Server header / TLS certificate on open ports
    [string]$OutCsv
)

$TopPorts = 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 443, 445, 465,
    500, 514, 515, 548, 554, 587, 631, 636, 873, 902, 990, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 1900,
    2000, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4343, 4443, 4786, 5000, 5060, 5432,
    5555, 5601, 5800, 5900, 5985, 5986, 6000, 6379, 6443, 7001, 7547, 8000, 8008, 8009, 8043, 8080, 8081, 8088, 8443,
    8880, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 10443, 11211, 27017, 49152, 50000
$TlsPorts = 443, 465, 636, 990, 993, 995, 3269, 4343, 4443, 5986, 6443, 8043, 8443, 9443, 10443
$HttpPorts = 80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8880, 8888, 9000, 9090, 9200

# ------------------------------------------------------------------ parsing
function ConvertTo-UInt32([string]$Ip) { $b = ([Net.IPAddress]::Parse($Ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function ConvertFrom-UInt32([uint32]$N) { $b = [BitConverter]::GetBytes($N); [Array]::Reverse($b); $b -join '.' }

function Expand-Target([string]$t) {
    $t = $t.Trim()
    if (-not $t -or $t.StartsWith('#')) { return }
    if ($t -match '^(\d+\.\d+\.\d+\.\d+)/(\d{1,2})$') {
        $prefix = [int]$Matches[2]
        if ($prefix -lt 16) { throw "CIDR $t is too large (max /16)." }
        $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
        $net = [uint32]((ConvertTo-UInt32 $Matches[1]) -band $mask)
        $size = [uint32][math]::Pow(2, 32 - $prefix)
        if ($prefix -ge 31) { 0..($size - 1) | ForEach-Object { ConvertFrom-UInt32 ([uint32]($net + $_)) } }
        else { 1..($size - 2) | ForEach-Object { ConvertFrom-UInt32 ([uint32]($net + $_)) } }
    } elseif ($t -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$') {
        $a = ConvertTo-UInt32 $Matches[1]; $b = ConvertTo-UInt32 $Matches[2]
        if ($b - $a -gt 65535) { throw "Range $t is too large." }
        for ($n = $a; $n -le $b; $n++) { ConvertFrom-UInt32 ([uint32]$n) }
    } elseif ($t -match '^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$') {
        [int]$Matches[2]..[int]$Matches[3] | ForEach-Object { "$($Matches[1])$_" }
    } else { $t }
}

function Expand-Ports([string[]]$spec) {
    $list = foreach ($s in ($spec -join ',').Split(',')) {
        $s = $s.Trim().ToLower()
        if ($s -eq 'top') { $TopPorts }
        elseif ($s -eq 'all') { 1..65535 }
        elseif ($s -match '^(\d+)-(\d+)$') { [int]$Matches[1]..[int]$Matches[2] }
        elseif ($s -match '^\d+$') { [int]$s }
    }
    @($list | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object -Unique)
}

# ------------------------------------------------------------------ scanning
function Invoke-PingFilter([string[]]$Ips) {
    $alive = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Ips.Count; $i += 128) {
        $batch = @($Ips[$i..([math]::Min($i + 127, $Ips.Count - 1))])
        $tasks = @(foreach ($ip in $batch) { (New-Object Net.NetworkInformation.Ping).SendPingAsync($ip, 500) })
        try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, 5000) } catch {}
        for ($k = 0; $k -lt $batch.Count; $k++) {
            if ($tasks[$k].Status -eq 'RanToCompletion' -and $tasks[$k].Result.Status -eq 'Success') { [void]$alive.Add($batch[$k]) }
        }
    }
    , $alive.ToArray()
}

function Get-Banner([string]$Ip, [int]$Port) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        if (-not $c.ConnectAsync($Ip, $Port).Wait(2000)) { return '' }
        $stream = $c.GetStream(); $stream.ReadTimeout = 2500; $stream.WriteTimeout = 2000
        $info = ''
        if ($Port -in $TlsPorts) {
            $ssl = New-Object Net.Security.SslStream($stream, $false, ([Net.Security.RemoteCertificateValidationCallback] { $true }))
            $ssl.AuthenticateAsClient($Ip, $null, [Security.Authentication.SslProtocols]'Tls12, Tls11, Tls', $false)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $info = "TLS cert: $($cert.Subject) | issuer: $($cert.Issuer) | expires $($cert.NotAfter.ToString('yyyy-MM-dd'))"
            if ($cert.NotAfter -lt (Get-Date)) { $info += ' [EXPIRED]' }
            if ($cert.Subject -eq $cert.Issuer) { $info += ' [self-signed]' }
            $stream = $ssl
        }
        if ($Port -in $HttpPorts -or $Port -in $TlsPorts) {
            $req = [Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.0`r`nHost: $Ip`r`nUser-Agent: portscan`r`n`r`n")
            try { $stream.Write($req, 0, $req.Length) } catch {}
        }
        $buf = New-Object byte[] 2048
        $n = 0
        try { $n = $stream.Read($buf, 0, $buf.Length) } catch {}
        if ($n -gt 0) {
            $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
            $parts = @()
            if ($txt -match '^(HTTP/\S+ \d{3}[^\r\n]*)') { $parts += $Matches[1] }
            if ($txt -match '(?im)^Server:\s*([^\r\n]+)') { $parts += "Server: $($Matches[1])" }
            if (-not $parts) { $parts += (($txt -replace '[^\x20-\x7e]', ' ') -replace '\s+', ' ').Trim() }
            $info = (@($info) + $parts | Where-Object { $_ }) -join ' | '
        }
        if ($info.Length -gt 200) { $info = $info.Substring(0, 200) }
        $info
    } catch { '' } finally { $c.Close() }
}

# ------------------------------------------------------------------ main
$hosts = @()
if ($Target) { $hosts += foreach ($t in ($Target -join ',').Split(',')) { Expand-Target $t } }
if ($TargetFile) { $hosts += foreach ($t in (Get-Content -LiteralPath $TargetFile)) { Expand-Target $t } }
$hosts = @($hosts | Where-Object { $_ } | Select-Object -Unique)
$portList = Expand-Ports $Ports
if (-not $hosts) { Write-Host 'Usage: .\portscan.ps1 -Target <ip|cidr|range|name>[,...] [-Ports top|all|22,80,8000-8100] [-PingFirst] [-Banner] [-OutCsv file]'; return }

if ($PingFirst) {
    Write-Host "[*] Ping discovery on $($hosts.Count) hosts ..."
    $hosts = Invoke-PingFilter $hosts
    Write-Host "[*] $($hosts.Count) hosts answered ping"
    if (-not $hosts) { return }
}

$total = [int64]$hosts.Count * $portList.Count
Write-Host ("[*] Scanning {0} host(s) x {1} port(s) = {2} connections (timeout {3} ms, {4} in parallel)" -f $hosts.Count, $portList.Count, $total, $Timeout, $Parallel)
$start = Get-Date
$results = New-Object System.Collections.ArrayList
$done = 0

$batch = New-Object System.Collections.ArrayList
$flush = {
    $conns = @(foreach ($x in $batch) {
            $c = New-Object Net.Sockets.TcpClient
            try { $task = $c.ConnectAsync($x[0], [int]$x[1]) } catch { $task = $null }
            [pscustomobject]@{ Host = $x[0]; Port = [int]$x[1]; Client = $c; Task = $task }
        })
    $tasks = @($conns | Where-Object { $_.Task } | ForEach-Object { $_.Task })
    if ($tasks) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $Timeout) } catch {} }
    foreach ($x in $conns) {
        if ($x.Task -and $x.Task.Status -eq 'RanToCompletion') {
            [void]$results.Add([pscustomobject]@{ Host = $x.Host; Port = $x.Port; State = 'open'; Banner = '' })
            Write-Host ("  {0,-16} {1,5}/tcp open" -f $x.Host, $x.Port) -ForegroundColor Green
        }
        try { $x.Client.Close() } catch {}
    }
    $script:done += $batch.Count
    Write-Progress -Activity 'TCP scan' -Status "$($script:done) / $total" -PercentComplete ([math]::Min(100, 100 * $script:done / [math]::Max(1, $total)))
    $batch.Clear()
}
# fill batches host by host, so "all ports" on many hosts never builds a huge list in memory
foreach ($h in $hosts) {
    foreach ($p in $portList) {
        [void]$batch.Add(@($h, $p))
        if ($batch.Count -ge $Parallel) { & $flush }
    }
}
if ($batch.Count) { & $flush }
Write-Progress -Activity 'TCP scan' -Completed

if ($Banner -and $results.Count) {
    Write-Host "[*] Grabbing banners on $($results.Count) open port(s) ..."
    foreach ($r in $results) { $r.Banner = Get-Banner $r.Host $r.Port }
}

$elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
Write-Host "`n[+] $($results.Count) open port(s) on $(@($results | Select-Object -ExpandProperty Host -Unique).Count) host(s) in $elapsed s"
$results | Sort-Object { try { ConvertTo-UInt32 $_.Host } catch { 0 } }, Host, Port | Format-Table Host, Port, State, Banner -AutoSize -Wrap
if ($OutCsv) { $results | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutCsv; Write-Host "[+] Saved $OutCsv" }
