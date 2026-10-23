<#
.SYNOPSIS
    Enumerate directory objects and emit JSON graphs for offline review.
    Pure .NET LDAP only - no modules, no binaries, no downloads.

.DESCRIPTION
    Emits node/relationship JSON (users, computers, groups, domains, OUs,
    containers, GPOs, membership, links, trusts, and object access-control
    entries) and packages it into a single archive for import into a graph
    analysis tool. Runs as a normal domain user - no local admin required.

    Switches to lower the footprint:
      -NoACL      skip access-control (DACL) collection entirely - much faster
                  and far quieter, at the cost of the permission edges.
      -DelayMs    throttle between collection passes (spreads out the volume).
      -Quiet      minimal console output.
      -Test       bind, verify read access, and exit (quick sanity check).

.PARAMETER Domain
    DNS domain name. Defaults to the current machine's domain.

.PARAMETER Server
    Optional directory server to bind to (e.g. dc01.corp.local).

.PARAMETER Credential
    Optional directory credentials (Get-Credential). Defaults to current context.

.PARAMETER OutputDir
    Where to write the JSON + archive. Defaults to the current directory.

.EXAMPLE
    .\ad-healthcheck.ps1 -Domain corp.local
    .\ad-healthcheck.ps1 -Domain corp.local -Credential (Get-Credential)
    .\ad-healthcheck.ps1 -Domain corp.local -Server dc01.corp.local -NoACL -DelayMs 500
#>

[CmdletBinding()]
param(
    [string]$Domain = $env:USERDNSDOMAIN,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputDir = '.',
    [switch]$NoACL,
    [int]$DelayMs = 0,
    [switch]$Quiet,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$Version = 4

# Standard directory rights identifiers (used as labels in the emitted graph).
$GUID_AllExt          = '00000000-0000-0000-0000-000000000000'
$GUID_ForcePwd        = '00299570-246d-11d0-a768-00aa006e0529'
$GUID_GetChanges      = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GetChangesAll   = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GetChangesFilt  = '89e95b76-444d-4c62-991a-0facbeda640c'
$GUID_SelfMembership  = 'bf9679c0-0de6-11d0-a285-00aa003049e2'

# RID ranges used to classify principals that are not resolved by enumeration.
$GroupRids = @(498,512,513,514,515,516,517,518,519,520,521,522,526,527,544,548,549,550,551,552,553,554,555,571,572)

# Well-known privileged group names (uppercased).
$HighValueGroups = @(
    'DOMAIN ADMINS','ENTERPRISE ADMINS','SCHEMA ADMINS','ADMINISTRATORS','DOMAIN CONTROLLERS',
    'READ-ONLY DOMAIN CONTROLLERS','ACCOUNT OPERATORS','BACKUP OPERATORS','SERVER OPERATORS',
    'PRINT OPERATORS','GROUP POLICY CREATOR OWNERS','DNSADMINS','KEY ADMINS','ENTERPRISE KEY ADMINS'
)

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------
$script:SidType  = @{}   # SID  -> 'User'|'Group'|'Computer'|'Domain'
$script:DNToSid  = @{}   # DN   -> SID
$script:DNToType = @{}   # DN   -> type

function Wait-Throttle {
    param([int]$Base)
    if ($Base -le 0) { return }
    $jitter = Get-Random -Minimum 0 -Maximum ([math]::Max(1, [int]($Base * 0.4)))
    Start-Sleep -Milliseconds ($Base + $jitter)
}

function New-Searcher {
    param([string]$Filter, [string[]]$Props, [string]$SearchBase = '')
    $s = New-Object System.DirectoryServices.DirectorySearcher
    if ($SearchBase) {
        $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
    } else {
        $s.SearchRoot = $script:RootEntry
    }
    $s.Filter = $Filter
    $s.PageSize = 1000
    $s.SizeLimit = 0
    if (-not $NoACL) { $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl }
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    $s
}

function Get-AllResults {
    param($Searcher)
    $out = @()
    try {
        $res = $Searcher.FindAll()
        foreach ($r in $res) { $out += $r }
        $res.Dispose()
    } catch {
        Write-Warning "Search failed: $($_.Exception.Message)"
    }
    $out
}

function Get-Prop {
    param($Result, [string]$Name, $Default = $null)
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return $Result.Properties[$Name][0]
    }
    return $Default
}

function Get-Props {
    param($Result, [string]$Name)
    if ($Result.Properties.Contains($Name)) { return @($Result.Properties[$Name]) }
    return @()
}

function To-Unix {
    param($v)
    if ($null -eq $v) { return 0 }
    try {
        $ft = [long]$v
        if ($ft -eq 0) { return 0 }
        return [long]([DateTime]::FromFileTime($ft) - (Get-Date '1970-01-01')).TotalSeconds
    } catch { return 0 }
}

function Get-Sid {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Bytes, 0)).Value }
    catch { return $null }
}

function Get-Guid {
    param($Bytes)
    if ($null -eq $Bytes) { return $null }
    try { return (New-Object Guid (,$Bytes)).ToString() } catch { return $null }
}

function Get-PrincipalType {
    param([string]$Sid)
    if ($script:SidType.ContainsKey($Sid)) { return $script:SidType[$Sid] }
    if ($Sid -match '^S-1-5-21-.*-(\d+)$') {
        $rid = [int]$Matches[1]
        if ($GroupRids -contains $rid) { return 'Group' }
        if ($rid -eq 500) { return 'User' }
        if ($rid -lt 1000) { return 'Group' }
    }
    return 'Unknown'
}

function Get-RightName {
    param($Ace)
    $r  = $Ace.ActiveDirectoryRights
    $ot = $null
    if ($Ace.ObjectType) { $ot = $Ace.ObjectType.ToString() }

    if ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)    { return 'GenericAll' }
    if ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  { return 'GenericWrite' }
    if ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)     { return 'WriteDacl' }
    if ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)    { return 'WriteOwner' }
    if ($r -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
        switch ($ot) {
            $GUID_AllExt         { return 'AllExtendedRights' }
            $GUID_ForcePwd       { return 'ForceChangePassword' }
            $GUID_GetChanges     { return 'GetChanges' }
            $GUID_GetChangesAll  { return 'GetChangesAll' }
            $GUID_GetChangesFilt { return 'GetChangesInFilteredSet' }
            $GUID_SelfMembership { return 'AddSelf' }
        }
    }
    if ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
        if ($ot -eq $GUID_SelfMembership) { return 'AddMember' }
    }
    return $null
}

function Get-Aces {
    param($Result)
    $aces = @()
    try {
        if (-not $Result.Properties.Contains('ntSecurityDescriptor')) { return $aces }
        $bytes = $Result.Properties['ntSecurityDescriptor'][0]
        if ($null -eq $bytes) { return $aces }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$bytes)
        foreach ($ace in $sd.Access) {
            $right = Get-RightName $ace
            if (-not $right) { continue }
            $sid = $null
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
            catch { continue }
            $aces += [pscustomobject]@{
                PrincipalSID  = $sid
                PrincipalType = (Get-PrincipalType $sid)
                RightName     = $right
                IsInherited   = $ace.IsInherited
            }
        }
    } catch {}
    $aces
}

function Get-Uac {
    param($Result)
    $uac = Get-Prop $Result 'userAccountControl' 0
    try { return [int]$uac } catch { return 0 }
}

# ---------------------------------------------------------------------------
# Bind
# ---------------------------------------------------------------------------
if (-not $Domain) { throw "No domain specified and none detected. Use -Domain." }

$bindPath = "LDAP://$Domain"
if ($Server) { $bindPath = "LDAP://$Server/$Domain" }

if ($Credential) {
    $pw = $Credential.GetNetworkCredential().Password
    $script:RootEntry = New-Object System.DirectoryServices.DirectoryEntry($bindPath, $Credential.UserName, $pw)
} else {
    $script:RootEntry = New-Object System.DirectoryServices.DirectoryEntry($bindPath)
}

if ($Credential) {
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry("$bindPath/rootDSE", $Credential.UserName, $Credential.GetNetworkCredential().Password)
} else {
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry("$bindPath/rootDSE")
}
$defaultNC = $null
if ($rootDse.Properties.Contains('defaultNamingContext')) {
    $defaultNC = $rootDse.Properties['defaultNamingContext'][0].ToString()
}
if (-not $defaultNC) {
    throw "Cannot read the directory naming context - check -Domain/-Server and supply -Credential (domain account)."
}

$domainSid = $null
if ($rootDse.Properties.Contains('objectSid')) {
    $domainSid = Get-Sid $rootDse.Properties['objectSid'][0]
}
$domainUp  = $Domain.ToUpper()

if (-not $Quiet) { Write-Host "[*] Target: $Domain  (SID $domainSid)" -ForegroundColor Cyan }

if ($domainSid) { $script:SidType[$domainSid] = 'Domain' }

# Quick validation mode
if ($Test) {
    Write-Host "[*] Bind OK: $Domain  (SID $domainSid)" -ForegroundColor Green
    $checks = [ordered]@{
        'users'     = '(&(objectClass=user)(objectCategory=person))'
        'computers' = '(objectClass=computer)'
        'groups'    = '(objectClass=group)'
        'ous'       = '(objectClass=organizationalUnit)'
        'gpos'      = '(objectClass=groupPolicyContainer)'
    }
    foreach ($k in $checks.Keys) {
        $s = New-Searcher -Filter $checks[$k] -Props @('objectSid') -SearchBase $defaultNC
        $s.SizeLimit = 1
        $r = $s.FindOne()
        Write-Host ("    {0,-10} {1}" -f $k, $(if ($r) {'readable'} else {'no access / empty'}))
    }
    return
}

# ---------------------------------------------------------------------------
# Domain node
# ---------------------------------------------------------------------------
$domainNodes = @()
$domSearcher = New-Searcher -Filter "(objectClass=domainDNS)" -Props @('name','distinguishedName','objectSid','msDS-Behavior-Version') -SearchBase $defaultNC
$domRes = Get-AllResults $domSearcher
$domLinks = @()
$domProps = @{}
if ($domRes.Count -gt 0) {
    $d = $domRes[0]
    if (-not $domainSid) { $domainSid = Get-Sid (Get-Prop $d 'objectSid') }
    if (-not $domainSid) { throw "Could not determine the domain SID. Supply -Credential (domain account)." }
    $fn = Get-Prop $d 'msDS-Behavior-Version' '0'
    $fl = switch ([int]$fn) {
        0 {'2000'} 1 {'2003'} 2 {'2003'} 3 {'2008'} 4 {'2008 R2'} 5 {'2012'} 6 {'2012 R2'} 7 {'2016'} 8 {'2019'} default {'2019+'}
    }
    $domProps = @{
        name = $domainUp
        domainsid = $domainSid
        distinguishedname = (Get-Prop $d 'distinguishedName')
        functionallevel = $fl
        highvalue = $true
    }
    $domLinks = Get-Props $d 'gPLink' | ForEach-Object {
        [pscustomobject]@{ Guid = $_; IsEnforced = $false }
    }
    $domNode = [ordered]@{
        Label = 'Domain'
        ObjectIdentifier = $domainSid
        Properties = $domProps
        Aces = @(Get-Aces $d)
        IsDeleted = $false
        IsACLProtected = $false
        Links = $domLinks
    }
    $domainNodes += $domNode
}
Wait-Throttle $DelayMs

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
$userNodes = @()
$uProps = @('name','sAMAccountName','distinguishedName','objectSid','userAccountControl','description','adminCount',
    'lastLogon','lastLogonTimestamp','pwdLastSet','servicePrincipalName','sIDHistory','title','department','msDS-AllowedToDelegateTo')
if (-not $NoACL) { $uProps += 'ntSecurityDescriptor' }
$uSearcher = New-Searcher -Filter "(&(objectClass=user)(objectCategory=person))" -Props $uProps -SearchBase $defaultNC
foreach ($r in Get-AllResults $uSearcher) {
    $sid = Get-Sid (Get-Prop $r 'objectSid')
    if (-not $sid) { continue }
    $sam = (Get-Prop $r 'sAMAccountName' '')
    $dn  = (Get-Prop $r 'distinguishedName' '')
    $script:SidType[$sid] = 'User'
    $script:DNToSid[$dn]  = $sid
    $script:DNToType[$dn] = 'User'

    $uac = Get-Uac $r
    $adminCount = ([int](Get-Prop $r 'adminCount' 0)) -eq 1
    $enabled    = ($uac -band 0x2) -eq 0
    $dontReq    = ($uac -band 0x400000) -ne 0
    $unconstr   = ($uac -band 0x80000) -ne 0

    $spns = @(Get-Props $r 'servicePrincipalName')
    $sidHist = @(Get-Props $r 'sIDHistory') | ForEach-Object { Get-Sid $_ } | Where-Object { $_ }

    $allowedToDelegate = @(Get-Props $r 'msDS-AllowedToDelegateTo')

    $props = @{
        domain = $domainUp
        name = "$sam@$domainUp"
        distinguishedname = $dn
        domainsid = $domainSid
        highvalue = $adminCount
        admincount = $adminCount
        description = (Get-Prop $r 'description' '')
        title = (Get-Prop $r 'title' '')
        department = (Get-Prop $r 'department' '')
        dontreqpreauth = $dontReq
        enabled = $enabled
        lastlogon = (To-Unix (Get-Prop $r 'lastLogon' 0))
        lastlogontimestamp = (To-Unix (Get-Prop $r 'lastLogonTimestamp' 0))
        passwordlastset = (To-Unix (Get-Prop $r 'pwdLastSet' 0))
        pwdneverexpires = ($uac -band 0x10000) -ne 0
        unconstraineddelegation = $unconstr
        sidhistory = $sidHist
        sensitive = $false
    }
    if ($spns.Count) { $props['serviceprincipalnames'] = $spns; $props['hasspn'] = $true }

    $node = [ordered]@{
        Label = 'User'
        ObjectIdentifier = $sid
        Properties = $props
        Aces = @(Get-Aces $r)
        IsDeleted = $false
        IsACLProtected = $false
    }
    if ($allowedToDelegate.Count) { $node['AllowedToDelegate'] = $allowedToDelegate }
    if ($sidHist.Count) { $node['HasSIDHistory'] = $sidHist }
    $userNodes += $node
}
Wait-Throttle $DelayMs

# ---------------------------------------------------------------------------
# Computers
# ---------------------------------------------------------------------------
$compNodes = @()
$cProps = @('name','sAMAccountName','distinguishedName','objectSid','userAccountControl','description','operatingSystem',
    'lastLogon','lastLogonTimestamp','pwdLastSet','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity')
if (-not $NoACL) { $cProps += 'ntSecurityDescriptor' }
$cSearcher = New-Searcher -Filter "(objectClass=computer)" -Props $cProps -SearchBase $defaultNC
foreach ($r in Get-AllResults $cSearcher) {
    $sid = Get-Sid (Get-Prop $r 'objectSid')
    if (-not $sid) { continue }
    $sam = (Get-Prop $r 'sAMAccountName' '')
    $dn  = (Get-Prop $r 'distinguishedName' '')
    $script:SidType[$sid] = 'Computer'
    $script:DNToSid[$dn]  = $sid
    $script:DNToType[$dn] = 'Computer'

    $uac = Get-Uac $r
    $enabled  = ($uac -band 0x2) -eq 0
    $unconstr = ($uac -band 0x80000) -ne 0

    $allowedToDelegate = @(Get-Props $r 'msDS-AllowedToDelegateTo')

    $allowedToAct = @()
    if ($r.Properties.Contains('msDS-AllowedToActOnBehalfOfOtherIdentity')) {
        try {
            $sdBytes = $r.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'][0]
            if ($sdBytes) {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm([byte[]]$sdBytes)
                foreach ($ace in $sd.Access) {
                    try { $allowedToAct += $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
                }
            }
        } catch {}
    }

    $props = @{
        domain = $domainUp
        name = "$sam@$domainUp"
        distinguishedname = $dn
        domainsid = $domainSid
        operatingsystem = (Get-Prop $r 'operatingSystem' '')
        enabled = $enabled
        unconstraineddelegation = $unconstr
        lastlogon = (To-Unix (Get-Prop $r 'lastLogon' 0))
        lastlogontimestamp = (To-Unix (Get-Prop $r 'lastLogonTimestamp' 0))
        pwdlastset = (To-Unix (Get-Prop $r 'pwdLastSet' 0))
        description = (Get-Prop $r 'description' '')
    }

    $node = [ordered]@{
        Label = 'Computer'
        ObjectIdentifier = $sid
        Properties = $props
        Aces = @(Get-Aces $r)
        IsDeleted = $false
        IsACLProtected = $false
    }
    if ($allowedToDelegate.Count) { $node['AllowedToDelegate'] = $allowedToDelegate }
    if ($allowedToAct.Count)     { $node['AllowedToAct'] = $allowedToAct }
    $compNodes += $node
}
Wait-Throttle $DelayMs

# ---------------------------------------------------------------------------
# Groups (+ membership)
# ---------------------------------------------------------------------------
$groupNodes = @()
$gProps = @('name','sAMAccountName','distinguishedName','objectSid','description','adminCount','member')
if (-not $NoACL) { $gProps += 'ntSecurityDescriptor' }
$gSearcher = New-Searcher -Filter "(objectClass=group)" -Props $gProps -SearchBase $defaultNC
foreach ($r in Get-AllResults $gSearcher) {
    $sid = Get-Sid (Get-Prop $r 'objectSid')
    if (-not $sid) { continue }
    $sam = (Get-Prop $r 'sAMAccountName' '')
    $dn  = (Get-Prop $r 'distinguishedName' '')
    $script:SidType[$sid] = 'Group'
    $script:DNToSid[$dn]  = $sid
    $script:DNToType[$dn] = 'Group'

    $adminCount = ([int](Get-Prop $r 'adminCount' 0)) -eq 1
    $highvalue = $adminCount -or ($HighValueGroups -contains $sam.ToUpper())

    $members = @()
    foreach ($m in (Get-Props $r 'member')) {
        $mSid = $null; $mType = 'Unknown'
        if ($script:DNToSid.ContainsKey($m)) {
            $mSid  = $script:DNToSid[$m]
            $mType = $script:DNToType[$m]
        } elseif ($m -match '^CN=(S-1-5-[^,]+),') {
            $mSid = $Matches[1]
        }
        if ($mSid) { $members += [ordered]@{ MemberId = $mSid; MemberType = $mType } }
    }

    $props = @{
        domain = $domainUp
        name = "$sam@$domainUp"
        distinguishedname = $dn
        domainsid = $domainSid
        admincount = $adminCount
        highvalue = $highvalue
        description = (Get-Prop $r 'description' '')
    }

    $node = [ordered]@{
        Label = 'Group'
        ObjectIdentifier = $sid
        Properties = $props
        Members = $members
        Aces = @(Get-Aces $r)
        IsDeleted = $false
        IsACLProtected = $false
    }
    $groupNodes += $node
}
Wait-Throttle $DelayMs

# ---------------------------------------------------------------------------
# OUs, Containers, GPOs (+ GPO links)
# ---------------------------------------------------------------------------
$ouNodes = @(); $containerNodes = @(); $gpoNodes = @()

$ouSearcher = New-Searcher -Filter "(objectClass=organizationalUnit)" -Props @('name','distinguishedName','objectGUID','description','gPLink','objectSid') -SearchBase $defaultNC
foreach ($r in Get-AllResults $ouSearcher) {
    $guid = Get-Guid $r.Properties['objectGUID'][0]
    if (-not $guid) { continue }
    $dn   = (Get-Prop $r 'distinguishedName' '')
    $name = (Get-Prop $r 'name' '')
    $script:DNToSid[$dn]  = $guid
    $script:DNToType[$dn] = 'OU'
    $links = Get-Props $r 'gPLink' | ForEach-Object { [ordered]@{ Guid = $_; IsEnforced = $false } }
    $node = [ordered]@{
        Label = 'OU'
        ObjectIdentifier = $guid
        Properties = @{ domain = $domainUp; name = $name; distinguishedname = $dn; blocksinheritance = $false; description = (Get-Prop $r 'description' '') }
        Aces = @(Get-Aces $r)
        IsDeleted = $false
        IsACLProtected = $false
        Links = $links
    }
    $ouNodes += $node
}
Wait-Throttle $DelayMs

$conSearcher = New-Searcher -Filter "(&(objectClass=container)(!(objectClass=organizationalUnit)))" -Props @('name','distinguishedName','objectGUID','description') -SearchBase $defaultNC
foreach ($r in Get-AllResults $conSearcher) {
    $guid = Get-Guid $r.Properties['objectGUID'][0]
    if (-not $guid) { continue }
    $dn   = (Get-Prop $r 'distinguishedName' '')
    $name = (Get-Prop $r 'name' '')
    $script:DNToSid[$dn]  = $guid
    $script:DNToType[$dn] = 'Container'
    $node = [ordered]@{
        Label = 'Container'
        ObjectIdentifier = $guid
        Properties = @{ domain = $domainUp; name = $name; distinguishedname = $dn }
        Aces = @(Get-Aces $r)
        IsDeleted = $false
        IsACLProtected = $false
    }
    $containerNodes += $node
}
Wait-Throttle $DelayMs

$gpoSearcher = New-Searcher -Filter "(objectClass=groupPolicyContainer)" -Props @('name','distinguishedName','objectGUID','description','gPCFileSysPath') -SearchBase $defaultNC
foreach ($r in Get-AllResults $gpoSearcher) {
    $guid = Get-Guid $r.Properties['objectGUID'][0]
    if (-not $guid) { continue }
    $dn   = (Get-Prop $r 'distinguishedName' '')
    $name = (Get-Prop $r 'name' '')
    $node = [ordered]@{
        Label = 'GPO'
        ObjectIdentifier = $guid
        Properties = @{ domain = $domainUp; name = $name; distinguishedname = $dn; description = (Get-Prop $r 'description' ''); gpcpath = (Get-Prop $r 'gPCFileSysPath' '') }
        Aces = @(Get-Aces $r)
        IsDeleted = $false
        IsACLProtected = $false
    }
    $gpoNodes += $node
}
Wait-Throttle $DelayMs

# ---------------------------------------------------------------------------
# Trusts
# ---------------------------------------------------------------------------
$trustEdges = @()
$tSearcher = New-Searcher -Filter "(objectClass=trustedDomain)" -Props @('trustPartner','securityIdentifier','trustDirection','trustType') -SearchBase "CN=System,$defaultNC"
foreach ($r in Get-AllResults $tSearcher) {
    $partnerSid = $null
    if ($r.Properties.Contains('securityIdentifier')) {
        $partnerSid = Get-Sid $r.Properties['securityIdentifier'][0]
    }
    if (-not $partnerSid) { continue }
    $trustEdges += [ordered]@{
        Label = 'TrustedBy'
        From  = $partnerSid
        To    = $domainSid
        Properties = @{
            trustdirection = (Get-Prop $r 'trustDirection' '')
            trusttype      = (Get-Prop $r 'trustType' '')
            isacl = $false
        }
    }
    $script:SidType[$partnerSid] = 'Domain'
}

# ---------------------------------------------------------------------------
# Write output
# ---------------------------------------------------------------------------
$ts = Get-Date -Format 'yyyyMMddHHmmss'
$out = Join-Path $OutputDir "${ts}_ad"
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Write-DataFile {
    param([string]$Name, [string]$Type, $Items)
    $obj = [ordered]@{
        data = $Items
        meta = [ordered]@{
            count   = $Items.Count
            type    = $Type
            version = $Version
            methods = 0
        }
    }
    $json = $obj | ConvertTo-Json -Depth 8 -Compress
    Set-Content -Path (Join-Path $out "$Name.json") -Value $json -Encoding UTF8
    if (-not $Quiet) { Write-Host ("[+] {0,-14} {1} items" -f "$Name.json", $Items.Count) -ForegroundColor Green }
}

Write-DataFile 'users'      'users'      $userNodes
Write-DataFile 'computers'  'computers'  $compNodes
Write-DataFile 'groups'     'groups'     $groupNodes
Write-DataFile 'domains'    'domains'    ($domainNodes + $trustEdges)
Write-DataFile 'ous'        'ous'        $ouNodes
Write-DataFile 'gpos'       'gpos'       $gpoNodes
Write-DataFile 'containers' 'containers' $containerNodes

$zip = "$out.zip"
Compress-Archive -Path (Join-Path $out '*.json') -DestinationPath $zip -Force
if (-not $Quiet) {
    Write-Host ""
    Write-Host "[*] Done. Archive ready for import:" -ForegroundColor Cyan
    Write-Host "    $zip" -ForegroundColor Yellow
}
