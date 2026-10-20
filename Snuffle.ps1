<#
.SYNOPSIS
    Snuffle - a flexible, native PowerShell alternative to Snaffler.

.DESCRIPTION
    Finds potentially sensitive information in files on the local disk or on
    network shares.  Snuffle is dependency-free (works on stock Windows
    PowerShell 5.1 and PowerShell 7), and lets you tune what it looks for:
    file extensions, literal keywords, interesting file names, and named regex
    rules (secret-format signatures).

    Run with no parameters to search the current directory immediately with a
    broad, high-yield default set of extensions and keywords (txt, csv, pdf,
    html, office docs, configs, scripts, keys, backups, ...).  Pass -Interactive
    to open the configuration menu instead, where you can add/remove extensions
    and keywords before launching the search.

.PARAMETER Path
    One or more filesystem roots to search (folders or UNC shares).  Defaults to
    the current directory when neither -Path nor a config SearchPaths is set.

.PARAMETER Config
    Path to a JSON config file to load instead of the built-in defaults.

.PARAMETER Interactive
    Open the interactive configuration menu before searching.

.PARAMETER NonInteractive
    Do not open the menu (this is the default; kept for compatibility).

.PARAMETER Discover
    Enumerate domain computers via LDAP, then enumerate and search their SMB
    shares.  Requires domain connectivity (current user's AD context).

.PARAMETER Computer
    Enumerate and search shares on these specific hosts (names or IPs).  Skips
    the LDAP query.

.PARAMETER Share
    Explicit share/UNC paths to search (e.g. \\server\share).  Added directly
    without enumeration.

.PARAMETER IncludeAdminShares
    Also enumerate admin shares (C$, ADMIN$, ...).  Off by default.

.PARAMETER MaxComputers
    Cap the number of computers to enumerate when -Discover is used (0 = all).

.PARAMETER Throttle
    How many hosts to enumerate shares on in parallel (default 20).  Raise it to
    scan a large fleet faster; lower it if hosts are flaky or the network is slow.

.PARAMETER OutputFile
    Write all findings to a file.  The extension is derived from -Format.

.PARAMETER Format
    Output file format when -OutputFile is used: 'csv', 'json' or 'both'.

.PARAMETER AddExtension
    Add one or more file extensions to the search list (e.g. ".ini", "bak").

.PARAMETER AddKeyword
    Add one or more literal keywords to the content search.

.PARAMETER AddRule
    Add a named regex rule, as "Name|pattern" (e.g. "MyToken|tok_[a-f0-9]{20}").

.PARAMETER ReportExtensionHits
    Also list every file whose extension matches, even if its content had no hit.

.PARAMETER ScanAllTextFiles
    Content-scan every text file regardless of extension (slower, thorough).

.PARAMETER MaxFileSizeMB
    Skip content scanning of files larger than this size (default 50).

.PARAMETER MaxFindings
    Stop after this many findings (0 = unlimited).

.PARAMETER ExportConfig
    Write the effective configuration to Snuffle.config.json and exit.

.PARAMETER ListDefaults
    Print the default extensions/keywords/rules and exit.

.PARAMETER Quiet
    Suppress console output (findings still go to -OutputFile if given).

.EXAMPLE
    .\Snuffle.ps1
    # Search the current directory with the default broad ruleset.

.EXAMPLE
    .\Snuffle.ps1 -Path C:\Users\Public
    # Search a specific root.

.EXAMPLE
    .\Snuffle.ps1 -Interactive
    # Open the menu to add/remove extensions and keywords, then search.

.EXAMPLE
    .\Snuffle.ps1 -Path \\server\share -AddExtension .bak -AddKeyword "db_pass" -OutputFile out.csv

.EXAMPLE
    .\Snuffle.ps1 -Discover -OutputFile domain_shares.csv
    # LDAP-enumerate domain computers, enumerate their shares, search them all.

.EXAMPLE
    .\Snuffle.ps1 -Computer SRV-01,SRV-02 -MaxFindings 100
    # Enumerate and search shares on specific hosts.

.EXAMPLE
    .\Snuffle.ps1 -Share \\files\dept,\\files\finance
    # Search explicit shares only.

.NOTES
    List parameters (-Path, -Computer, -Share, -AddExtension, -AddKeyword,
    -AddRule) take comma-separated values, e.g. -Computer a,b,c.  Bare
    space-separated values are not accepted (PowerShell binds them positionally).
#>

[CmdletBinding()]
param(
    [Alias('SearchPath')]
    [string[]]$Path,

    [string]$Config,

    [Alias('Menu')]
    [switch]$Interactive,

    [switch]$NonInteractive,

    [switch]$Discover,

    [Alias('Computers')]
    [string[]]$Computer,

    [Alias('Shares')]
    [string[]]$Share,

    [switch]$IncludeAdminShares,

    [int]$MaxComputers = 0,

    [int]$Throttle = 20,

    [string]$OutputFile,

    [ValidateSet('csv', 'json', 'both')]
    [string]$Format = 'csv',

    [string[]]$AddExtension,

    [string[]]$AddKeyword,

    [string[]]$AddRule,

    [switch]$ReportExtensionHits,

    [switch]$ScanAllTextFiles,

    [int]$MaxFileSizeMB = 0,

    [int]$MaxFindings = 0,

    [switch]$ExportConfig,

    [switch]$ListDefaults,

    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
function Get-DefaultConfig {
    $rules = @(
        [PSCustomObject]@{ Name = 'Private Key (generic PEM)';  Pattern = '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' }
        [PSCustomObject]@{ Name = 'OpenSSH Private Key';        Pattern = '-----BEGIN OPENSSH PRIVATE KEY-----' }
        [PSCustomObject]@{ Name = 'RSA Private Key';            Pattern = '-----BEGIN RSA PRIVATE KEY-----' }
        [PSCustomObject]@{ Name = 'PuTTY Private Key';          Pattern = '(?i)PuTTY-User-Key-File' }
        [PSCustomObject]@{ Name = 'AWS Access Key ID';          Pattern = '\bAKIA[0-9A-Z]{16}\b' }
        [PSCustomObject]@{ Name = 'AWS Secret Access Key';      Pattern = '(?i)(aws_secret_access_key|secret_access_key|secretKey)["'']?\s*[:=]\s*["'']?[A-Za-z0-9/+=]{40}' }
        [PSCustomObject]@{ Name = 'Google API Key';             Pattern = '\bAIza[0-9A-Za-z_\-]{35}\b' }
        [PSCustomObject]@{ Name = 'GitHub Token';               Pattern = '\bgh[pousr]_[A-Za-z0-9]{20,}\b' }
        [PSCustomObject]@{ Name = 'GitLab Token';               Pattern = '\bglpat-[A-Za-z0-9_\-]{20,}\b' }
        [PSCustomObject]@{ Name = 'Slack Token';                Pattern = '\bxox[baprs]-[0-9A-Za-z\-]{10,}\b' }
        [PSCustomObject]@{ Name = 'Stripe Secret Key';          Pattern = '\bsk_live_[0-9a-zA-Z]{16,}\b' }
        [PSCustomObject]@{ Name = 'Azure Storage Account Key';  Pattern = '(?i)AccountKey["'']?\s*[:=]\s*["'']?[A-Za-z0-9+/=]{40,}' }
        [PSCustomObject]@{ Name = 'Azure Storage Conn String';  Pattern = '(?i)DefaultEndpointsProtocol\s*=' }
        [PSCustomObject]@{ Name = 'MongoDB URI';                Pattern = '(?i)mongodb(\+srv)?://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'PostgreSQL URI';             Pattern = '(?i)postgres(ql)?://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'MySQL URI';                  Pattern = '(?i)mysql://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'Redis URI';                  Pattern = '(?i)redis://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'AMQP URI';                   Pattern = '(?i)amqps?://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'JDBC URL';                   Pattern = '(?i)jdbc:[a-z0-9]+://[^\s;"'']+' }
        [PSCustomObject]@{ Name = 'S3 URI';                     Pattern = '(?i)s3://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'SFTP/SSH URI';               Pattern = '(?i)(sftp|ssh)://[^\s"'']+' }
        [PSCustomObject]@{ Name = 'Basic Auth Header';          Pattern = '(?i)authorization\s*:\s*basic\s+[A-Za-z0-9+/=]{10,}' }
        [PSCustomObject]@{ Name = 'Bearer/Token Assignment';    Pattern = '(?i)(access[_-]?token|refresh[_-]?token|bearer)["'']?\s*[:=]\s*["'']?[A-Za-z0-9._\-]{16,}' }
        [PSCustomObject]@{ Name = 'API Key Assignment';         Pattern = '(?i)(api[_-]?key|apikey|client[_-]?secret)["'']?\s*[:=]\s*["'']?[A-Za-z0-9._\-]{16,}' }
        [PSCustomObject]@{ Name = 'Password Assignment';        Pattern = '(?i)(password|passwd|pwd|passphrase)["'']?\s*[:=]\s*["'']?[^\s"'',;]{1,}' }
        [PSCustomObject]@{ Name = 'Connection String';          Pattern = '(?i)(server|data source|host)\s*=\s*[^;\r\n]+;[^\r\n]{0,80}(password|pwd|user id)\s*=' }
        [PSCustomObject]@{ Name = 'Docker Registry Auth';       Pattern = '(?i)["'']auth["'']\s*:\s*["''][A-Za-z0-9+/=]{20,}["'']' }
        [PSCustomObject]@{ Name = '.netrc Password';            Pattern = '(?i)machine\s+\S+(\s+login\s+\S+)?\s+password\s+\S+' }
    )

    [PSCustomObject]@{
        SearchPaths        = @()
        Extensions         = @(
            # documents / data exports (high-yield for credentials)
            '.txt', '.csv', '.tsv', '.pdf', '.html', '.htm', '.xhtml', '.svg', '.md', '.markdown',
            '.rst', '.adoc', '.tex', '.eml', '.url', '.rtf', '.log',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp',
            # config / settings / structured data
            '.config', '.conf', '.cfg', '.ini', '.xml', '.json', '.jsonc', '.yaml', '.yml',
            '.toml', '.env', '.properties', '.prefs', '.settings', '.lock', '.plist', '.clixml',
            '.resx', '.nuspec', '.ps1xml', '.sitemap', '.pubxml', '.user',
            # data sources / connection files (connection strings)
            '.dsn', '.odc', '.udl', '.sql', '.sdf',
            # scripts / web
            '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.js', '.ts', '.jsx', '.tsx',
            '.py', '.sh', '.pl', '.rb', '.php', '.go', '.java', '.cs', '.cpp', '.h', '.vb',
            '.wsf', '.ws', '.wsc', '.aspx', '.ascx', '.asax', '.cshtml', '.vbhtml', '.master',
            # projects / build
            '.sln', '.csproj', '.vbproj', '.fsproj', '.xproj',
            # credentials / keys / certs / remote-access
            '.rdp', '.key', '.pem', '.ppk', '.crt', '.cer', '.p12', '.pfx', '.p7b', '.der',
            '.kdbx', '.kdb', '.ovpn', '.reg', '.inf', '.pol', '.mstsc',
            # backups / archives of the above
            '.bak', '.backup', '.old', '.orig', '.sav', '.dump', '.export', '.bkp'
        )
        Keywords           = @(
            'password', 'passwd', 'pwd', 'pass', 'passphrase', 'passcode', 'pin', 'otp',
            'secret', 'secret_key', 'secretkey', 'api key', 'apikey', 'api_key', 'api token',
            'api_token', 'access key', 'accesskey', 'access key id', 'secret access key',
            'access_token', 'refresh_token', 'auth_token', 'secret_token', 'private_key',
            'private key', 'BEGIN PRIVATE KEY', 'BEGIN RSA', 'BEGIN OPENSSH',
            'authorization: basic', 'bearer', 'oauth', 'client_id', 'client id', 'client_secret',
            'clientsecret', 'connection string', 'connectionstring', 'data source', 'server=',
            'uid=', 'user id=', 'db_pass', 'db_password', 'db_user', 'database password',
            'master key', 'masterkey', 'encryption key', 'decrypt', 'salt=', 'hash=',
            'smtp', 'smtp password', 'ldap password', 'ftp password', 'ssh password',
            'vnc', 'rdp password', 'vpn', 'wifi', 'wireless', 'ssid', 'wpa', 'wep', 'psk',
            'credential', 'credentials', 'token', 'authentication', 'DefaultEndpointsProtocol',
            'AccountKey', 'AccountName', 'sa password', 'root password', 'user password',
            'admin password', 'default password', 'database username', 'session', 'cookie'
        )
        FileNames          = @(
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa.*', 'id_ed25519.*',
            'authorized_keys', 'authorized_keys2', 'known_hosts', '.htpasswd', '.htaccess',
            '.npmrc', '.gitconfig', '.git-credentials', '.netrc', '.pgpass', '.env', '.env.*',
            'web.config', 'app.config', 'wp-config.php', 'docker-compose*', 'credentials*',
            'secrets*', '*password*', '*secret*', '*.ovpn', '*.rdp'
        )
        Rules              = $rules
        MaxFileSizeMB      = 50
        ScanAllTextFiles   = $false
        ReportExtensionHits = $false
    }
}

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
function ConvertTo-Array([object]$Value) {
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value) }
    return @($Value)
}

function Normalize-Extension([string]$Ext) {
    $e = $Ext.Trim().ToLowerInvariant()
    if ($e -eq '') { return $null }
    if (-not $e.StartsWith('.')) { $e = '.' + $e }
    return $e
}

function Get-Config {
    if ($Config) {
        if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
            throw "Config file not found: '$Config'. If you meant to pass a list of targets, separate them with commas (e.g. -Computer a,b,c or -Share \\srv1,\\srv2) - bare space-separated values are not accepted."
        }
        $raw = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
    }
    else {
        $raw = Get-DefaultConfig
    }

    # Overlay CLI additions / switches
    if ($Path)            { $raw.SearchPaths = @($Path) }
    if ($AddExtension)    { $raw.Extensions = @($raw.Extensions) + @($AddExtension) }
    if ($AddKeyword)      { $raw.Keywords   = @($raw.Keywords)   + @($AddKeyword) }
    if ($ReportExtensionHits) { $raw.ReportExtensionHits = $true }
    if ($ScanAllTextFiles)    { $raw.ScanAllTextFiles = $true }
    if ($MaxFileSizeMB -gt 0) { $raw.MaxFileSizeMB = $MaxFileSizeMB }
    foreach ($r in $AddRule) {
        $parts = $r -split '\|', 2
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
            Write-Warning "Ignoring malformed -AddRule value (expected 'Name|pattern'): $r"
            continue
        }
        $raw.Rules = @($raw.Rules) + [PSCustomObject]@{ Name = $parts[0].Trim(); Pattern = $parts[1].Trim() }
    }

    $cfg = [PSCustomObject]@{
        SearchPaths         = ConvertTo-Array $raw.SearchPaths
        Extensions          = @(ConvertTo-Array $raw.Extensions | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ -ne $null } | Select-Object -Unique)
        Keywords            = @(ConvertTo-Array $raw.Keywords | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' } | Select-Object -Unique)
        FileNames           = @(ConvertTo-Array $raw.FileNames | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' } | Select-Object -Unique)
        Rules               = @(ConvertTo-Array $raw.Rules | ForEach-Object {
                                    [PSCustomObject]@{ Name = [string]$_.Name; Pattern = [string]$_.Pattern }
                               } | Where-Object { $_.Pattern -ne '' })
        MaxFileSizeMB       = [int]$raw.MaxFileSizeMB
        ScanAllTextFiles    = [bool]$raw.ScanAllTextFiles
        ReportExtensionHits = [bool]$raw.ReportExtensionHits
    }
    if ($cfg.MaxFileSizeMB -le 0) { $cfg.MaxFileSizeMB = 50 }

    $cfg.SearchPaths = @($cfg.SearchPaths | ForEach-Object { $_.Trim().TrimEnd('\') } | Where-Object { $_ -ne '' } | Select-Object -Unique)
    return $cfg
}

function Save-Config([object]$Cfg, [string]$File) {
    $Cfg | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $File -Encoding UTF8
    Write-Host "Config saved to $File" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host ''
    Write-Host '   ____  _   _ _   _ __     __    _      _____ ' -ForegroundColor Cyan
    Write-Host '  / ___|| \ | | | | |\ \   / /_ _| | ___| ____|' -ForegroundColor Cyan
    Write-Host '  \___ \|  \| | | | | \ \ / / _` | |/ _ \  _|  ' -ForegroundColor Cyan
    Write-Host '   ___) | |\  | |_| |  \ V / (_| | |  __/ |___ ' -ForegroundColor Cyan
    Write-Host '  |____/|_| \_|\___/    \_/ \__,_|_|\___|_____|' -ForegroundColor Cyan
    Write-Host '        flexible native-PowerShell Snaffler' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-Config([object]$Cfg) {
    Write-Host 'Current configuration' -ForegroundColor White
    Write-Host ('  Search paths : ' + ($(if ($Cfg.SearchPaths.Count) { $Cfg.SearchPaths -join '; ' } else { '(none set)' }))) -ForegroundColor Gray
    Write-Host ('  Extensions   : ' + $Cfg.Extensions.Count + '  (add more to widen the net)') -ForegroundColor Gray
    Write-Host ('  Keywords     : ' + $Cfg.Keywords.Count + '  (literal content search terms)') -ForegroundColor Gray
    Write-Host ('  File names   : ' + $Cfg.FileNames.Count + '  (interesting file names)') -ForegroundColor Gray
    Write-Host ('  Regex rules  : ' + $Cfg.Rules.Count + '  (secret-format signatures)') -ForegroundColor Gray
    Write-Host ('  Max file size: ' + $Cfg.MaxFileSizeMB + ' MB') -ForegroundColor Gray
    Write-Host ''
}

function Show-Lists([object]$Cfg) {
    Write-Host "Extensions ($($Cfg.Extensions.Count)):" -ForegroundColor White
    Write-Host ('  ' + ($Cfg.Extensions -join ' ')) -ForegroundColor Gray
    Write-Host ''
    Write-Host "Keywords ($($Cfg.Keywords.Count)):" -ForegroundColor White
    Write-Host ('  ' + ($Cfg.Keywords -join ', ')) -ForegroundColor Gray
    Write-Host ''
    Write-Host "File names ($($Cfg.FileNames.Count)):" -ForegroundColor White
    Write-Host ('  ' + ($Cfg.FileNames -join ' ')) -ForegroundColor Gray
    Write-Host ''
    Write-Host "Rules ($($Cfg.Rules.Count)):" -ForegroundColor White
    foreach ($r in $Cfg.Rules) { Write-Host ('  ' + $r.Name + '  ->  ' + $r.Pattern) -ForegroundColor Gray }
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Search engine
# ---------------------------------------------------------------------------
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:Stats      = @{ Files = 0; Scanned = 0; Findings = 0; Errors = 0; SkippedBinary = 0; TooLarge = 0 }
$script:KwRegex    = $null
$script:Rules      = @()
$script:Cfg        = $null
$script:OptQuiet      = $false
$script:MaxPerFile = 100
$script:OptMaxFindings = 0
$script:Stop        = $false
$script:HostName    = $env:COMPUTERNAME

function New-Finding {
    param([string]$RuleName, [string]$Match, [int]$LineNo, [string]$Line, [string]$FullPath, [long]$Size)
    if ($Line.Length -gt 400) { $Line = $Line.Substring(0, 400) + '...' }
    if ($Match.Length -gt 200) { $Match = $Match.Substring(0, 200) + '...' }
    $f = [PSCustomObject]@{
        Time       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Host       = $script:HostName
        Path       = $FullPath
        File       = [System.IO.Path]::GetFileName($FullPath)
        Rule       = $RuleName
        Match      = $Match
        LineNumber = $LineNo
        Line       = $Line
        Size       = $Size
    }
    $script:Findings.Add($f)
    $script:Stats.Findings++

    if (-not $script:OptQuiet) {
        $color = switch -Regex ($RuleName) {
            '^(FileName|Extension)$' { 'Green'; break }
            '^Keyword$'              { 'Yellow'; break }
            default                  { 'Cyan' }
        }
        Write-Host ("[{0}]" -f $RuleName) -NoNewline -ForegroundColor $color
        Write-Host (" {0}" -f $FullPath) -NoNewline -ForegroundColor White
        if ($LineNo -gt 0) { Write-Host (":{0}" -f $LineNo) -NoNewline -ForegroundColor DarkGray }
        Write-Host ("  {0}" -f $Match) -ForegroundColor Gray
        if ($Line -and $Line -ne $Match) {
            Write-Host ("        {0}" -f $Line) -ForegroundColor DarkGray
        }
    }

    if ($script:OptMaxFindings -gt 0 -and $script:Stats.Findings -ge $script:OptMaxFindings) {
        $script:Stop = $true
    }
    return $f
}

function Test-IsTextFile {
    param([string]$Path, [int]$SampleSize = 8192)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $buf = New-Object byte[] $SampleSize
            $n = $fs.Read($buf, 0, $SampleSize)
            for ($i = 0; $i -lt $n; $i++) {
                if ($buf[$i] -eq 0) { return $false }
            }
            return $true
        }
        finally { $fs.Dispose() }
    }
    catch { return $false }
}

function Get-OfficeText {
    param([string]$Path)
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
            $matchAll = $false
            $prefix = $null
            $exact = $null
            if ($ext -eq '.docx') { $exact = 'word/document.xml' }
            elseif ($ext -eq '.xlsx') { $exact = 'xl/sharedStrings.xml' }
            elseif ($ext -eq '.pptx') { $matchAll = $true; $prefix = 'ppt/slides/' }
            elseif ($ext -in @('.odt', '.ods', '.odp')) { $exact = 'content.xml' }
            else { return $null }

            $sb = New-Object System.Text.StringBuilder
            foreach ($entry in $zip.Entries) {
                $full = $entry.FullName
                $want = $false
                if ($matchAll) { if ($full.StartsWith($prefix) -and $full.EndsWith('.xml')) { $want = $true } }
                elseif ($full -eq $exact) { $want = $true }
                if ($want) {
                    $s = $entry.Open()
                    try {
                        $r = New-Object System.IO.StreamReader($s)
                        [void]$sb.Append($r.ReadToEnd())
                        $r.Dispose()
                    }
                    finally { $s.Dispose() }
                }
            }
            $text = $sb.ToString()
            $text = $text -replace '<[^>]+>', ' '
            $text = [System.Net.WebUtility]::HtmlDecode($text)
            return $text
        }
        finally { $zip.Dispose() }
    }
    catch { return $null }
}

# --- Best-effort PDF text extraction (no external libraries) ----------------
# Maps each byte 0..255 to a char so we can regex over raw PDF syntax.
function ConvertTo-Latin1String([byte[]]$Bytes) {
    $sb = New-Object System.Text.StringBuilder($Bytes.Length)
    foreach ($b in $Bytes) { [void]$sb.Append([char]$b) }
    return $sb.ToString()
}

function Get-PdfStrings {
    param([string]$S)
    $sb = New-Object System.Text.StringBuilder
    # PDF draws text as parenthesized strings: (Hello) Tj   -> extract "Hello"
    foreach ($m in [regex]::Matches($S, '\(([^)]*)\)')) {
        $v = $m.Groups[1].Value
        if ($v -and $v.Trim().Length -gt 0) { [void]$sb.Append($v).Append(' ') }
    }
    return $sb.ToString()
}

function Get-PdfText {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 16) { return $null }
        $text = ConvertTo-Latin1String $bytes
        $sb = New-Object System.Text.StringBuilder

        # Walk each stream...endstream block; inflate FlateDecode streams, then
        # pull the drawn-text strings out.  Falls back to raw text when a stream
        # cannot be decompressed (e.g. encrypted/unsupported filter).
        $streamRegex = [regex]'(?s)stream\r?\n(.*?)endstream'
        foreach ($m in $streamRegex.Matches($text)) {
            $raw = $m.Groups[1].Value
            $chunk = $null
            try {
                $rawBytes = [byte[]][char[]]$raw
                if ($rawBytes.Length -gt 2 -and $rawBytes[0] -eq 0x78) {
                    $ms = [System.IO.MemoryStream]::new($rawBytes, 2, $rawBytes.Length - 2)
                }
                else {
                    $ms = [System.IO.MemoryStream]::new($rawBytes)
                }
                try {
                    $ds = [System.IO.Compression.DeflateStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress)
                    try {
                        $out = New-Object System.IO.MemoryStream
                        $ds.CopyTo($out)
                        $chunk = ConvertTo-Latin1String $out.ToArray()
                        $out.Dispose()
                    }
                    finally { $ds.Dispose() }
                }
                finally { $ms.Dispose() }
            }
            catch { $chunk = $null }

            if (-not $chunk) { $chunk = $raw }
            $strs = Get-PdfStrings $chunk
            if ($strs) { [void]$sb.Append($strs).Append(' ') }
        }

        # Also scan strings that live outside streams (uncompressed / metadata).
        $strs = Get-PdfStrings $text
        if ($strs) { [void]$sb.Append($strs) }

        if ($sb.Length -eq 0) { return $null }
        return $sb.ToString()
    }
    catch { return $null }
}

function Invoke-TextScan {
    param([System.IO.TextReader]$Reader, [string]$FullPath, [long]$Size)
    $added = 0
    $lineNo = 0
    while (($line = $Reader.ReadLine()) -ne $null) {
        if ($script:Stop) { return $added }
        $lineNo++
        if ($line.Length -eq 0) { continue }

        foreach ($r in $script:Rules) {
            try {
                $m = $r.Regex.Match($line)
                if ($m.Success) {
                    [void](New-Finding -RuleName $r.Name -Match $m.Value -LineNo $lineNo -Line $line -FullPath $FullPath -Size $Size)
                    $added++
                }
            }
            catch { $script:Stats.Errors++ }
        }

        if ($script:KwRegex) {
            foreach ($m in $script:KwRegex.Matches($line)) {
                if ($m.Value -eq '') { continue }
                [void](New-Finding -RuleName 'Keyword' -Match $m.Value -LineNo $lineNo -Line $line -FullPath $FullPath -Size $Size)
                $added++
            }
        }

        if ($added -ge $script:MaxPerFile) { return $added }
    }
    return $added
}

function Search-File {
    param([string]$FullPath)

    $script:Stats.Files++
    if ($script:Stop) { return }

    $fileName = [System.IO.Path]::GetFileName($FullPath)
    $ext = [System.IO.Path]::GetExtension($FullPath).ToLowerInvariant()
    $nameLower = $fileName.ToLowerInvariant()

    $nameMatch = $false
    foreach ($p in $script:Cfg.FileNames) {
        if ($nameLower -like $p) { $nameMatch = $true; break }
    }
    $extMatch = $script:Cfg.Extensions -contains $ext
    $shouldScan = $extMatch -or $nameMatch -or $script:Cfg.ScanAllTextFiles

    if ($nameMatch) {
        [void](New-Finding -RuleName 'FileName' -Match $fileName -LineNo 0 -Line '' -FullPath $FullPath -Size 0)
    }

    if (-not $shouldScan) { return }

    $fi = $null
    try { $fi = [System.IO.FileInfo]::new($FullPath) } catch { }

    if ($null -ne $fi) {
        $maxBytes = [long]$script:Cfg.MaxFileSizeMB * 1MB
        if ($fi.Length -gt $maxBytes) {
            $script:Stats.TooLarge++
            return
        }
        $size = $fi.Length
    }
    else { $size = 0 }

    $officeExts = @('.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp')
    $isOffice = $officeExts -contains $ext

    if ($isOffice) {
        $text = Get-OfficeText -Path $FullPath
        if ($text) {
            $script:Stats.Scanned++
            $sr = New-Object System.IO.StringReader($text)
            try { [void](Invoke-TextScan -Reader $sr -FullPath $FullPath -Size $size) }
            finally { $sr.Dispose() }
            return
        }
        # Not a readable archive -> fall through and treat as a plain text file.
    }

    if ($ext -eq '.pdf') {
        $text = Get-PdfText -Path $FullPath
        if ($text) {
            $script:Stats.Scanned++
            $sr = New-Object System.IO.StringReader($text)
            try { [void](Invoke-TextScan -Reader $sr -FullPath $FullPath -Size $size) }
            finally { $sr.Dispose() }
            return
        }
        # Not extractable -> fall through (binary check will skip it).
    }

    if (-not (Test-IsTextFile -Path $FullPath)) {
        $script:Stats.SkippedBinary++
        if ($extMatch -and $script:Cfg.ReportExtensionHits -and -not $nameMatch) {
            [void](New-Finding -RuleName 'Extension' -Match $ext -LineNo 0 -Line '(binary)' -FullPath $FullPath -Size $size)
        }
        return
    }

    try {
        $reader = New-Object System.IO.StreamReader($FullPath)
        try {
            $script:Stats.Scanned++
            [void](Invoke-TextScan -Reader $reader -FullPath $FullPath -Size $size)
        }
        finally { $reader.Dispose() }
    }
    catch { $script:Stats.Errors++ }
}

function Search-Directory {
    param([string]$Root)
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)

    while ($stack.Count -gt 0) {
        if ($script:Stop) { return }
        $dir = $stack.Pop()

        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                Search-File -FullPath $f
                if ($script:Stop) { return }
            }
        }
        catch { $script:Stats.Errors++ }

        try {
            foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) {
                try {
                    $attr = [System.IO.File]::GetAttributes($d)
                    if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                    $stack.Push($d)
                }
                catch { }
            }
        }
        catch { $script:Stats.Errors++ }

        if (-not $script:OptQuiet -and ($script:Stats.Files % 2000) -eq 0) {
            Write-Progress -Activity 'Snuffle' -Status ("Scanning $dir") -CurrentOperation ("files: {0}  findings: {1}" -f $script:Stats.Files, $script:Stats.Findings)
        }
    }
}

# ---------------------------------------------------------------------------
# Network discovery: AD computers -> SMB shares (like Snaffler's finder)
# ---------------------------------------------------------------------------
function Get-DomainComputers {
    # Enumerate enabled domain-joined computers via LDAP (System.DirectoryServices,
    # built into .NET Framework).  Uses the current user's domain context.
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        $searcher.PageSize = 1000
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        [void]$searcher.PropertiesToLoad.Add('dnsHostName')
        [void]$searcher.PropertiesToLoad.Add('name')
        $computers = New-Object System.Collections.Generic.List[string]
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $dns = $r.Properties['dnsHostName']
            if ($dns -and $dns.Count) { $computers.Add([string]$dns[0]) }
            else {
                $name = $r.Properties['name']
                if ($name -and $name.Count) { $computers.Add([string]$name[0]) }
            }
        }
        $results.Dispose()
        return @($computers | Select-Object -Unique)
    }
    catch {
        Write-Warning "LDAP computer enumeration failed: $($_.Exception.Message)"
        return @()
    }
}

function Invoke-NetView {
    param([string]$Computer, [int]$TimeoutMs = 8000)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'net.exe'
        $psi.Arguments = "view \\$Computer"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        if (-not $p.WaitForExit($TimeoutMs)) {
            try { $p.Kill() } catch { }
            return @()
        }
        return @($p.StandardOutput.ReadToEnd() -split "`r?`n")
    }
    catch { return @() }
}

function Get-ComputerShares {
    param([string]$Computer, [switch]$IncludeAdminShares)
    $Computer = $Computer.Trim().TrimEnd('\')
    $names = New-Object System.Collections.Generic.List[string]

    # net view: SMB share listing, no modules, bounded by a per-host timeout.
    # Parsing is localization-independent: skip everything before the dashed
    # separator line, then the share name is the column before 2+ spaces.
    $inData = $false
    foreach ($line in (Invoke-NetView -Computer $Computer)) {
        $t = $line.Trim()
        if ($t -eq '') { continue }
        if ($t -match '^-{3,}') { $inData = $true; continue }
        if (-not $inData) { continue }

        $parts = $t -split '\s{2,}'
        if ($parts.Count -lt 2) { continue }          # footer/blank rows lack a Type column
        $name = $parts[0].Trim()
        if (-not $name -or $name -match '^[^A-Za-z0-9_.\-]') { continue }
        $names.Add($name)
    }

    $shares = New-Object System.Collections.Generic.List[string]
    foreach ($n in ($names | Select-Object -Unique)) {
        if ($n -eq 'IPC$') { continue }
        if ($n.EndsWith('$') -and -not $IncludeAdminShares) { continue }
        $shares.Add("\\$Computer\$n")
    }
    return @($shares)
}

function Discover-Shares {
    param(
        [string[]]$Computers,
        [switch]$IncludeAdminShares,
        [int]$MaxComputers = 0,
        [int]$Throttle = 20
    )
    if (-not $Computers) { $Computers = Get-DomainComputers }
    if (-not $Computers -or $Computers.Count -eq 0) {
        Write-Warning 'No computers found to enumerate (check domain connectivity, or pass -Computer/-Share).'
        return @()
    }
    if ($MaxComputers -gt 0 -and $Computers.Count -gt $MaxComputers) {
        Write-Warning "Limiting enumeration to the first $MaxComputers of $($Computers.Count) computers."
        $Computers = @($Computers | Select-Object -First $MaxComputers)
    }
    $Computers = @($Computers | Where-Object { $_ } | Select-Object -Unique)
    if ($Throttle -lt 1) { $Throttle = 20 }

    # Self-contained worker (runs in a separate runspace): enumerate one host's
    # shares via net view and emit the "\\host\share" UNC paths.
    $worker = {
        param([string]$Computer, [bool]$IncludeAdmin)
        $Computer = $Computer.Trim().TrimEnd('\')
        $found = New-Object System.Collections.Generic.List[string]
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'net.exe'
            $psi.Arguments = "view \\$Computer"
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $psi
            [void]$p.Start()
            if (-not $p.WaitForExit(8000)) { try { $p.Kill() } catch { } return }
            $lines = @($p.StandardOutput.ReadToEnd() -split "`r?`n")
        }
        catch { return }

        $inData = $false
        foreach ($line in $lines) {
            $t = $line.Trim()
            if ($t -eq '') { continue }
            if ($t -match '^-{3,}') { $inData = $true; continue }
            if (-not $inData) { continue }
            $parts = $t -split '\s{2,}'
            if ($parts.Count -lt 2) { continue }
            $name = $parts[0].Trim()
            if (-not $name -or $name -match '^[^A-Za-z0-9_.\-]') { continue }
            if ($name -eq 'IPC$') { continue }
            if ($name.EndsWith('$') -and -not $IncludeAdmin) { continue }
            $found.Add("\\$Computer\$name")
        }
        foreach ($s in ($found | Select-Object -Unique)) { $s }
    }

    $shares = New-Object System.Collections.Generic.List[string]
    $total = $Computers.Count
    $completed = 0

    $pool = $null
    try {
        $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
        $pool.Open()
    }
    catch { $pool = $null }

    if ($pool) {
        # Parallel enumeration across hosts.
        $jobs = New-Object System.Collections.Generic.List[object]
        foreach ($c in $Computers) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($worker).AddArgument([string]$c).AddArgument([bool]$IncludeAdminShares)
            $jobs.Add([pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() })
        }
        foreach ($j in $jobs) {
            try {
                $out = $j.PS.EndInvoke($j.Handle)
                if ($out) { $out | ForEach-Object { if ($_) { $shares.Add([string]$_) } } }
            }
            catch { }
            $j.PS.Dispose()
            $completed++
            if (-not $script:OptQuiet) {
                Write-Progress -Activity 'Discovering network shares' -Status ("{0}/{1} hosts done" -f $completed, $total) -PercentComplete (($completed / $total) * 100)
            }
        }
        $pool.Close()
        $pool.Dispose()
    }
    else {
        # Sequential fallback.
        foreach ($c in $Computers) {
            foreach ($s in (Get-ComputerShares -Computer $c -IncludeAdminShares:$IncludeAdminShares)) { $shares.Add($s) }
            $completed++
            if (-not $script:OptQuiet) {
                Write-Progress -Activity 'Discovering network shares' -Status ("{0}/{1} hosts done" -f $completed, $total) -PercentComplete (($completed / $total) * 100)
            }
        }
    }

    if (-not $script:OptQuiet) {
        Write-Progress -Activity 'Discovering network shares' -Completed
        foreach ($s in ($shares | Select-Object -Unique)) { Write-Host ("[share] {0}" -f $s) -ForegroundColor DarkCyan }
    }
    return @($shares | Select-Object -Unique)
}

function Export-Findings([string]$File, [string]$Fmt) {
    if ($script:Findings.Count -eq 0) {
        if (-not $script:OptQuiet) { Write-Host 'No findings to export.' -ForegroundColor DarkGray }
        return
    }
    # Strip an existing .csv/.json extension so we always write the right one.
    $base = $File -replace '\.(csv|json)$', ''
    $arr = $script:Findings.ToArray()
    switch ($Fmt) {
        'csv' {
            $csv = "$base.csv"
            $arr | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
            if (-not $script:OptQuiet) { Write-Host "Wrote $($script:Findings.Count) findings to $csv" -ForegroundColor Green }
        }
        'json' {
            $json = "$base.json"
            $arr | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $json -Encoding UTF8
            if (-not $script:OptQuiet) { Write-Host "Wrote $($script:Findings.Count) findings to $json" -ForegroundColor Green }
        }
        'both' {
            $csv = "$base.csv"
            $json = "$base.json"
            $arr | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
            $arr | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $json -Encoding UTF8
            if (-not $script:OptQuiet) { Write-Host "Wrote findings to $csv and $json" -ForegroundColor Green }
        }
    }
}

# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------
function Read-Choice {
    param([string]$Prompt, [string[]]$Options)
    Write-Host ''
    Write-Host $Prompt -ForegroundColor White
    foreach ($o in $Options) { Write-Host $o -ForegroundColor Gray }
    $in = Read-Host 'Choice'
    return $in
}

function Show-Menu {
    $cfg = $script:Cfg
    while ($true) {
        Write-Host ''
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host ' SNUFFLE MENU' -ForegroundColor Cyan
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host '  Search paths : ' -NoNewline -ForegroundColor White
        if ($cfg.SearchPaths.Count) { Write-Host ($cfg.SearchPaths -join ' ; ') -ForegroundColor Gray } else { Write-Host '(none)' -ForegroundColor DarkYellow }
        Write-Host ('  Extensions   : {0}   Keywords: {1}   Rules: {2}   Filenames: {3}' -f $cfg.Extensions.Count, $cfg.Keywords.Count, $cfg.Rules.Count, $cfg.FileNames.Count) -ForegroundColor White
        Write-Host ('  Max size     : {0} MB   ScanAllText: {1}   ReportByExt: {2}' -f $cfg.MaxFileSizeMB, $cfg.ScanAllTextFiles, $cfg.ReportExtensionHits) -ForegroundColor White
        Write-Host '------------------------------------------------------------' -ForegroundColor Cyan
        Write-Host '   1. Add search path(s)'            -ForegroundColor Gray
        Write-Host '   2. Add file extension(s)'         -ForegroundColor Gray
        Write-Host '   3. Remove file extension(s)'      -ForegroundColor Gray
        Write-Host '   4. Add keyword(s)'                -ForegroundColor Gray
        Write-Host '   5. Remove keyword(s)'             -ForegroundColor Gray
        Write-Host '   6. Add regex rule (Name|pattern)' -ForegroundColor Gray
        Write-Host '   7. Toggle Scan-All-Text-Files'    -ForegroundColor Gray
        Write-Host '   8. Toggle Report-Extension-Hits'  -ForegroundColor Gray
        Write-Host '   9. Set max file size (MB)'        -ForegroundColor Gray
        Write-Host '   L. List all extensions/keywords/rules' -ForegroundColor Gray
        Write-Host '   S. Save config to JSON'           -ForegroundColor Gray
        Write-Host '   G. GO  -> start the search'       -ForegroundColor Green
        Write-Host '   Q. Quit'                          -ForegroundColor Gray
        Write-Host '------------------------------------------------------------' -ForegroundColor Cyan

        $c = (Read-Host 'Select').Trim().ToLowerInvariant()
        switch ($c) {
            '1' {
                $p = Read-Host 'Enter path(s), separated by ; or comma'
                foreach ($x in ($p -split '[;,]')) {
                    $x = $x.Trim().TrimEnd('\')
                    if ($x -and (Test-Path -LiteralPath $x)) { $cfg.SearchPaths += $x }
                    elseif ($x -like '\\*') { $cfg.SearchPaths += $x }
                    elseif ($x) { Write-Warning "Path not found, skipped: $x" }
                }
                $cfg.SearchPaths = @($cfg.SearchPaths | Select-Object -Unique)
            }
            '2' {
                $e = Read-Host 'Enter extension(s) to ADD, separated by space or comma (e.g. .bak .db or bak,db)'
                foreach ($x in ($e -split '[,\s]+')) {
                    $n = Normalize-Extension $x
                    if ($n -and $cfg.Extensions -notcontains $n) { $cfg.Extensions += $n }
                }
                Write-Host ('Extensions now: ' + ($cfg.Extensions -join ' ')) -ForegroundColor Green
            }
            '3' {
                $e = Read-Host 'Enter extension(s) to REMOVE (exact, e.g. .bak)'
                foreach ($x in ($e -split '[,\s]+')) {
                    $n = Normalize-Extension $x
                    if ($n) { $cfg.Extensions = @($cfg.Extensions | Where-Object { $_ -ne $n }) }
                }
                Write-Host ('Extensions now: ' + ($cfg.Extensions -join ' ')) -ForegroundColor Green
            }
            '4' {
                $k = Read-Host 'Enter keyword(s) to ADD, separated by comma (e.g. db_pass, "my secret")'
                foreach ($x in ($k -split ',')) {
                    $x = $x.Trim().ToLowerInvariant()
                    if ($x -and $cfg.Keywords -notcontains $x) { $cfg.Keywords += $x }
                }
                Write-Host ('Keywords now: ' + ($cfg.Keywords -join ', ')) -ForegroundColor Green
            }
            '5' {
                $k = Read-Host 'Enter keyword(s) to REMOVE, separated by comma'
                foreach ($x in ($k -split ',')) {
                    $x = $x.Trim().ToLowerInvariant()
                    $cfg.Keywords = @($cfg.Keywords | Where-Object { $_ -ne $x })
                }
                Write-Host ('Keywords now: ' + ($cfg.Keywords -join ', ')) -ForegroundColor Green
            }
            '6' {
                $r = Read-Host 'Enter rule as  Name|pattern  (e.g. MyToken|tok_[a-f0-9]{20})'
                $parts = $r -split '\|', 2
                if ($parts.Count -eq 2 -and $parts[0].Trim() -and $parts[1].Trim()) {
                    $cfg.Rules += [PSCustomObject]@{ Name = $parts[0].Trim(); Pattern = $parts[1].Trim() }
                    Write-Host ('Rule added. Total rules: ' + $cfg.Rules.Count) -ForegroundColor Green
                }
                else { Write-Warning 'Expected format: Name|pattern' }
            }
            '7' {
                $cfg.ScanAllTextFiles = -not $cfg.ScanAllTextFiles
                Write-Host ('Scan-All-Text-Files = ' + $cfg.ScanAllTextFiles) -ForegroundColor Green
            }
            '8' {
                $cfg.ReportExtensionHits = -not $cfg.ReportExtensionHits
                Write-Host ('Report-Extension-Hits = ' + $cfg.ReportExtensionHits) -ForegroundColor Green
            }
            '9' {
                $m = Read-Host 'Max file size in MB (content-scan limit)'
                $val = 0
                if ([int]::TryParse($m, [ref]$val) -and $val -gt 0) { $cfg.MaxFileSizeMB = $val; Write-Host ('Max size set to ' + $val + ' MB') -ForegroundColor Green }
                else { Write-Warning 'Invalid number.' }
            }
            'l' { Show-Lists $cfg }
            's' {
                $f = Read-Host 'Save config to (default Snuffle.config.json)'
                if (-not $f) { $f = 'Snuffle.config.json' }
                Save-Config $cfg $f
            }
            'g' { return 'go' }
            'q' { return 'quit' }
            default { Write-Warning 'Unknown choice.' }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Main {
    # Load the compression assembly (needed for office-file text extraction on PS 5.1)
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch { }
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue } catch { }

    if (-not $Quiet) { Show-Banner }

    # Catch the common "space-separated list" mistake: -Computer a b c (or
    # -Share x y) leaves the extra tokens to bind positionally onto -Path.
    # If -Path received something that is neither an existing path nor looks
    # like a path (no '\' or ':'), tell the user to use commas.
    if (($Computer -or $Share -or $Discover) -and $Path) {
        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p) -and $p -notmatch '[\\:]') {
                Write-Error "List values must be comma-separated. '$p' was read as a -Path value but is not a valid path - if you were passing a list to -Computer/-Share, use commas (e.g. -Computer a,b,c)."
                exit 1
            }
        }
    }

    try { $cfg = Get-Config } catch { Write-Error $_; exit 1 }

    if ($ListDefaults) {
        Show-Lists $cfg
        return
    }

    $script:Cfg = $cfg
    $script:OptQuiet = $Quiet
    $script:OptMaxFindings = $MaxFindings

    if ($ExportConfig) {
        Save-Config $cfg 'Snuffle.config.json'
        return
    }

    # Interactive mode (opt-in)
    if ($Interactive -and -not $NonInteractive) {
        $action = Show-Menu
        if ($action -eq 'quit') { return }
        # after menu, CLI -OutputFile / -Format still apply
    }

    # Resolve output file
    $outFile = $OutputFile

    # Assemble the list of paths to search: explicit paths + explicit shares +
    # per-computer share enumeration + optional full-domain discovery.
    $explicitDiscovery = [bool]($Share -or $Computer -or $Discover)
    $hadConfiguredPaths = [bool]($cfg.SearchPaths -and $cfg.SearchPaths.Count -gt 0)

    $searchPaths = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($cfg.SearchPaths)) { if ($p) { $searchPaths.Add($p) } }
    foreach ($s in @($Share)) { if ($s) { $searchPaths.Add($s.Trim().TrimEnd('\')) } }

    if ($Computer) {
        foreach ($s in (Discover-Shares -Computers $Computer -IncludeAdminShares:$IncludeAdminShares -Throttle $Throttle)) { $searchPaths.Add($s) }
    }
    if ($Discover) {
        foreach ($s in (Discover-Shares -IncludeAdminShares:$IncludeAdminShares -MaxComputers $MaxComputers -Throttle $Throttle)) { $searchPaths.Add($s) }
    }

    if ($searchPaths.Count -eq 0) {
        if ($explicitDiscovery -or $hadConfiguredPaths) {
            Write-Warning 'No shares or paths were resolved to search. Check connectivity, credentials, or the given targets.'
            return
        }
        $cwd = (Get-Location).Path
        $searchPaths.Add($cwd)
        if (-not $Quiet) { Write-Host "No search path given; scanning current directory: $cwd" -ForegroundColor DarkYellow }
    }

    $cfg.SearchPaths = @($searchPaths | Where-Object { $_ } | Select-Object -Unique)

    # Build compiled regexes once
    $script:Rules = @()
    foreach ($r in $cfg.Rules) {
        try {
            $re = New-Object System.Text.RegularExpressions.Regex($r.Pattern, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled), [TimeSpan]::FromSeconds(3))
            $script:Rules += [PSCustomObject]@{ Name = $r.Name; Regex = $re }
        }
        catch { Write-Warning "Skipping invalid rule '$($r.Name)': $($_.Exception.Message)" }
    }

    if ($cfg.Keywords.Count -gt 0) {
        $escaped = @($cfg.Keywords | ForEach-Object { [System.Text.RegularExpressions.Regex]::Escape($_) })
        $kwPattern = '(' + ($escaped -join '|') + ')'
        try { $script:KwRegex = New-Object System.Text.RegularExpressions.Regex($kwPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) }
        catch { $script:KwRegex = $null }
    }

    if (-not $Quiet) {
        Write-Host ''
        Write-Host ('Searching {0} path(s)...' -f $cfg.SearchPaths.Count) -ForegroundColor White
        Write-Host ('Extensions: {0} | Keywords: {1} | Rules: {2} | Filenames: {3}' -f $cfg.Extensions.Count, $cfg.Keywords.Count, $script:Rules.Count, $cfg.FileNames.Count) -ForegroundColor Gray
        Write-Host ''
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($root in $cfg.SearchPaths) {
        if ($script:Stop) { break }
        if (-not $Quiet) { Write-Host ("[+] {0}" -f $root) -ForegroundColor DarkCyan }
        Search-Directory -Root $root
    }
    $sw.Stop()
    if (-not $Quiet) { Write-Progress -Activity 'Snuffle' -Completed }

    if ($outFile) {
        Export-Findings -File $outFile -Fmt $Format
    }

    if (-not $Quiet) {
        Write-Host ''
        Write-Host '----------------- Summary -----------------' -ForegroundColor Cyan
        Write-Host ('  Files enumerated : {0}' -f $script:Stats.Files) -ForegroundColor White
        Write-Host ('  Files scanned    : {0}' -f $script:Stats.Scanned) -ForegroundColor White
        Write-Host ('  Skipped (binary) : {0}' -f $script:Stats.SkippedBinary) -ForegroundColor DarkGray
        Write-Host ('  Skipped (size)   : {0}' -f $script:Stats.TooLarge) -ForegroundColor DarkGray
        Write-Host ('  Errors           : {0}' -f $script:Stats.Errors) -ForegroundColor DarkYellow
        Write-Host ('  FINDINGS         : {0}' -f $script:Stats.Findings) -ForegroundColor Green
        Write-Host ('  Elapsed          : {0:hh\:mm\:ss}' -f $sw.Elapsed) -ForegroundColor Gray
        if ($script:Stop) { Write-Host '  (stopped early: -MaxFindings reached)' -ForegroundColor DarkYellow }
        Write-Host '--------------------------------------------' -ForegroundColor Cyan
    }
}

Main
