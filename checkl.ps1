# ============================================================================
#  win-privesc-check.ps1
#  Lightweight Windows privilege-escalation enumeration — native only.
#  Read-only. No third-party modules. Locale-independent (uses SIDs, not names).
#
#  Usage (as the unprivileged user you are testing):
#     powershell -ExecutionPolicy Bypass -File .\win-privesc-check.ps1
#     .\win-privesc-check.ps1 | Tee-Object -FilePath results.txt
#
#  Legend:  [+] good/notable   [i] info   [!] likely escalation lead
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'

function Banner($t) { Write-Output ("`n" + ('=' * 72) + "`n  " + $t + "`n" + ('=' * 72)) }
function Info($t)  { Write-Output ("  [i] " + $t) }
function Good($t)  { Write-Output ("  [+] " + $t) }
function Bad($t)   { Write-Output ("  [!] " + $t) }

# True if the current user (or Everyone / Users / Auth Users) can write here.
function Test-Writable($path) {
    if (-not (Test-Path $path)) { return $false }
    try {
        $acl  = Get-Acl $path
        $me   = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $want = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value }
        $everyoneSids = @($me, 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11') + $want
        $w = [System.Security.AccessControl.FileSystemRights]::Write
        $m = [System.Security.AccessControl.FileSystemRights]::Modify
        $f = [System.Security.AccessControl.FileSystemRights]::FullControl
        $need = $w -bor $m -bor $f
        foreach ($acc in $acl.Access) {
            if ($acc.AccessControlType -ne 'Allow') { continue }
            $sid = $null
            try { $sid = $acc.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { $sid = $acc.IdentityReference.Value }
            if ($everyoneSids -contains $sid -and (($acc.FileSystemRights -band $need) -ne 0)) { return $true }
        }
        return $false
    } catch { return $false }
}
function RegVal($path, $name) { (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name }

# ============================================================================
Banner "1. SYSTEM & USER"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Info "User        : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Info "Hostname    : $env:COMPUTERNAME"
Info "OS          : $($os.Caption)  build $($os.BuildNumber)  $($os.OSArchitecture)"
Info "Uptime      : $(((Get-Date) - $os.LastBootUpTime).ToString('dd\.hh\:mm\:ss'))"
Info "Domain/Work : $($cs.Domain)"
Info "Is Admin?   : $admin"
Info "LanguageMode: $($ExecutionContext.SessionState.LanguageMode)"
Info "Hotfixes    : $((Get-HotFix | Measure-Object).Count)"

# ============================================================================
Banner "2. TOKEN PRIVILEGES  (presence = the key signal; Potato/Backup attacks work even 'disabled')"
$privRaw = (whoami /priv) -join "`n"
$found   = [regex]::Matches($privRaw, 'Se[A-Za-z]+Privilege') | ForEach-Object { $_.Value } | Sort-Object -Unique
$interesting = @{
  'SeImpersonatePrivilege'           = '-> Potato-family EoP (Juicy/Rotten/GodPotato)'
  'SeAssignPrimaryTokenPrivilege'    = '-> Potato-family EoP'
  'SeBackupPrivilege'                = '-> read any file (dump SAM/SYSTEM)'
  'SeRestorePrivilege'               = '-> write any file (service DLL/binary hijack)'
  'SeTakeOwnershipPrivilege'         = '-> take ownership of files'
  'SeDebugPrivilege'                 = '-> inject into processes'
  'SeLoadDriverPrivilege'            = '-> load kernel driver'
  'SeTcbPrivilege'                   = '-> act as part of OS (dangerous)'
  'SeCreateTokenPrivilege'           = '-> create tokens'
  'SeManageVolumePrivilege'          = '-> volume manipulation'
  'SeDelegateSessionUserImpersonatePrivilege' = '-> impersonate (session)'
}
foreach ($p in $interesting.Keys) { if ($found -contains $p) { Bad ("$p  " + $interesting[$p]) } }

# ============================================================================
Banner "3. GROUP MEMBERSHIP  (by SID)"
$grpSids = @{
  'S-1-5-32-544' = 'Administrators'
  'S-1-5-32-551' = 'Backup Operators'
  'S-1-5-32-547' = 'Power Users'
  'S-1-5-32-548' = 'Account Operators'
  'S-1-5-32-549' = 'Server Operators'
  'S-1-5-32-550' = 'Print Operators'
  'S-1-5-32-555' = 'Remote Desktop Users'
  'S-1-5-32-556' = 'Network Configuration Operators'
  'S-1-5-32-562' = 'Distributed COM Users'
  'S-1-5-32-573' = 'Event Log Readers'
  'S-1-5-32-578' = 'Hyper-V Administrators'
  'S-1-5-32-580' = 'Remote Management Users'
}
$myGroups = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value }
foreach ($g in $myGroups) {
    if ($grpSids.ContainsKey($g)) { Good ("Member of " + $grpSids[$g]) }
    elseif ($g -match '-512$')  { Good "Member of DOMAIN ADMINS (RID 512)" }
    elseif ($g -match '-519$')  { Good "Member of ENTERPRISE ADMINS (RID 519)" }
    elseif ($g -match '-518$')  { Good "Member of SCHEMA ADMINS (RID 518)" }
    elseif ($g -match '-1101$') { Good "Member of DNSADMINS (RID 1101)" }
}

# ============================================================================
Banner "4. ALWAYSINSTALLELEVATED (MSI runs as SYSTEM)"
$hk = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
$hc = RegVal 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
if ($hk -eq 1 -and $hc -eq 1) { Bad "AlwaysInstallElevated = 1 on HKLM + HKCU" }
else { Info "Not enabled (HKLM=$hk HKCU=$hc)" }

# ============================================================================
Banner "5. AUTOLOGON / CREDENTIALS IN REGISTRY"
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ((RegVal $wl 'AutoAdminLogon') -eq '1') {
    Bad ("AutoAdminLogon ON -> " + (RegVal $wl 'DefaultUserName') + " : " + (RegVal $wl 'DefaultPassword'))
} else { Info "AutoAdminLogon off" }
foreach ($rk in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
    $p = Get-ItemProperty $rk -ErrorAction SilentlyContinue
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Info ("AUTORUN " + $rk + " : " + $_.Name + " = " + $_.Value) } }
}

# ============================================================================
Banner "6. UAC"
Info ("EnableLUA                    = " + (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'))
Info ("ConsentPromptBehaviorAdmin   = " + (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'))
Info ("LocalAccountTokenFilterPolicy= " + (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'))
if ((RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -eq 0) { Bad "UAC disabled (EnableLUA=0)" }

# ============================================================================
Banner "7. SERVICES — UNQUOTED PATH / WRITABLE BINARY"
foreach ($s in Get-CimInstance Win32_Service) {
    $p = ($s.PathName -replace '^\s+','').Trim()
    if (-not $p -or $p -notmatch '\.exe') { continue }
    $isSystem = ($s.StartName -eq 'LocalSystem' -or $s.StartName -match 'SYSTEM' -or $s.StartName -match 'Autorité')
    if (($p -match ' ') -and ($p -notmatch '^"') -and ($p -notmatch '(?i)\\system32\\|\\syswow64\\')) {
        Bad ("Unquoted path: $($s.Name) -> $p   (runs as $($s.StartName))")
    }
    $exe = ($p -replace '^"?([^"]+?\.exe).*$','$1')
    $dir = Split-Path $exe -Parent
    if ($dir -and $isSystem -and (Test-Writable $dir)) {
        Bad ("Writable SYSTEM service dir: $($s.Name) -> $dir")
    }
}

# ============================================================================
Banner "8. SCHEDULED TASKS — SYSTEM + WRITABLE ACTION"
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_
    if ($t.Principal.UserId -match 'SYSTEM|Autorit') {
        foreach ($a in $t.Actions) {
            if ($a.Execute) {
                $ad = Split-Path $a.Execute -Parent
                if ($ad -and (Test-Writable $ad)) { Bad ("SYSTEM task, writable action: $($t.TaskName) -> $($a.Execute)") }
            }
        }
    }
}

# ============================================================================
Banner "9. WRITABLE DIRECTORIES / PATH"
foreach ($d in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\', 'C:\ProgramData', 'C:\Windows\Temp', 'C:\Temp')) {
    if ($d -and (Test-Writable $d)) { Bad "Writable: $d" }
}
foreach ($p in ($env:PATH -split ';')) {
    if ($p -and (Test-Path $p) -and (Test-Writable $p)) {
        $owner = (Get-Acl $p).Owner
        if ($owner -and $owner -notmatch [regex]::Escape($env:USERNAME)) { Bad ("Writable PATH entry (not owned by you): $p  (owner $owner)") }
    }
}

# ============================================================================
Banner "10. STARTUP FOLDERS"
foreach ($s in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
    if (Test-Path $s) {
        Info ("$s  (writable=" + (Test-Writable $s) + ")")
        Get-ChildItem $s -ErrorAction SilentlyContinue | ForEach-Object { Info ("   -> " + $_.Name) }
    }
}

# ============================================================================
Banner "11. INSTALLED SOFTWARE"
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | ForEach-Object {
    Get-ItemProperty $_ -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        Info ("{0}   v{1}" -f $_.DisplayName, $_.DisplayVersion)
    }
}

# ============================================================================
Banner "12. LISTENING PORTS"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique | ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Info ("{0}:{1}   ({2} / PID {3})" -f $_.LocalAddress, $_.LocalPort, $proc, $_.OwningProcess)
}

# ============================================================================
Banner "13. STORED CREDENTIALS (cmdkey /list)"
cmdkey /list | ForEach-Object { if ($_ -match 'Target|Cible|Type|Nom') { Info $_.Trim() } }

# ============================================================================
Banner "14. CREDENTIAL / UNATTENDED FILES"
$creds = @(
  'C:\Windows\Panther\Unattend.xml','C:\Windows\Panther\Unattend\Unattend.xml',
  'C:\Windows\System32\sysprep\sysprep.xml','C:\Windows\System32\sysprep\Panther\unattend.xml',
  'C:\Windows\System32\sysprep\unattend.xml','C:\unattend.xml',
  'C:\Windows\System32\GroupPolicy\Machine\Preferences\Groups\Groups.xml'
)
foreach ($f in $creds) { if (Test-Path $f) { Bad "Present: $f" } }
Get-ChildItem 'C:\Windows\System32\GroupPolicy' -Recurse -Filter 'Groups.xml' -ErrorAction SilentlyContinue | ForEach-Object {
    if (Select-String -Path $_.FullName -Pattern 'cpassword' -Quiet) { Bad ("GPP cpassword in: " + $_.FullName) }
}
Get-ChildItem 'C:\' -Include 'sysprep.xml','sysprep.inf','unattend.xml','unattended.xml' -Recurse -Depth 3 -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'sysprep|unattend|Panther' } | ForEach-Object { Bad ("Found: " + $_.FullName) }

# ============================================================================
Banner "15. POWERSHELL HISTORY"
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $hist) {
    Info "PSReadLine history: $hist"
    Get-Content $hist -ErrorAction SilentlyContinue | Select-String -Pattern '(?i)password|passwd|pwd|secret|token|api.?key|credential|connect-' | ForEach-Object { Bad ("  " + $_.Line) }
} else { Info "No PSReadLine history" }

# ============================================================================
Banner "16. DPAPI / CREDENTIAL STORES"
Info ("Credential Manager : " + "$env:APPDATA\Microsoft\Credentials")
Info ("Vault             : " + "$env:APPDATA\Microsoft\Vault")
Info ("DPAPI master keys : " + "$env:APPDATA\Microsoft\Protect")
if (Test-Path "$env:APPDATA\Microsoft\Credentials") { Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force | ForEach-Object { Info ("   -> " + $_.Name) } }

# ============================================================================
Banner "17. NAMED PIPES"
try { Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | ForEach-Object { Info $_.Name } } catch {}

# ============================================================================
Banner "18. AV / EDR / APPLOCKER / WDAC"
Get-Service -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -match '(?i)antivirus|endpoint|defender|sentinel|crowdstrike|carbon|sophos|trend|eset|kaspersky|symantec|mcafee|norton'
} | ForEach-Object { Info ("Security product: " + $_.DisplayName + " [" + $_.Status + "]") }
Info ("AppLocker (SrpV2)     : " + [bool](Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'))
Info ("WDAC (CodeIntegrity)  : " + [bool](Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CodeIntegrity'))

# ============================================================================
Banner "19. OS BUILD — manual kernel-exploit cross-check"
$b = [int]$os.BuildNumber
Info "Build $b  (verify against a current CVE list; hints below are illustrative)"
if ($b -lt 9600)  { Info "  <= 8.1 / 2012 R2 era -> many legacy EoPs may apply" }
elseif ($b -ge 10240 -and $b -le 17763) { Info "  1507..1809 -> PrintNightmare / HiveNightmare era" }
elseif ($b -ge 18362 -and $b -le 19043) { Info "  1903..21H1 -> HiveNightmare (SAM readable), PrintNightmare" }
else { Info "  modern build -> cross-check current CVEs manually" }

Write-Output "`n[+] Enumeration complete. Review [!] items."
