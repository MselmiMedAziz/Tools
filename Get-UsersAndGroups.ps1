<#
.SYNOPSIS
    Lists users, their group memberships and description using native ADSI only
    (no ActiveDirectory module / RSAT required).

.PARAMETER Local
    List local accounts on this machine (WinNT provider) instead of domain users (LDAP).

.PARAMETER SearchRoot
    Optional LDAP path to limit the search, e.g. "LDAP://OU=Staff,DC=contoso,DC=com".
    Defaults to the current domain.

.PARAMETER CsvPath
    Optional path to export results as CSV.

.EXAMPLE
    .\Get-UsersAndGroups.ps1
    .\Get-UsersAndGroups.ps1 -CsvPath .\users.csv
    .\Get-UsersAndGroups.ps1 -Local | Format-Table -AutoSize
#>
[CmdletBinding()]
param(
    [switch]$Local,
    [string]$SearchRoot,
    [string]$CsvPath
)

function Get-DomainUsers {
    param([string]$SearchRoot)

    $searcher = [adsisearcher]'(&(objectCategory=person)(objectClass=user))'
    if ($SearchRoot) { $searcher.SearchRoot = [adsi]$SearchRoot }
    $searcher.PageSize = 1000          # required to get past the 1000-result limit
    $searcher.SearchScope = 'Subtree'
    'samaccountname','displayname','description','memberof',
    'primarygroupid','objectsid','useraccountcontrol','distinguishedname' |
        ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }

    # Cache primary-group lookups (usually just "Domain Users")
    $primaryGroupCache = @{}

    foreach ($r in $searcher.FindAll()) {
        $p = $r.Properties

        # memberOf holds DNs -> extract the CN
        $groups = @($p['memberof'] | ForEach-Object {
            if ($_ -match '^CN=((?:[^,\\]|\\.)+),') { $Matches[1] -replace '\\(.)', '$1' }
        })

        # memberOf does NOT include the primary group, so resolve it from primaryGroupID
        if ($p['primarygroupid'].Count -and $p['objectsid'].Count) {
            $userSid   = New-Object System.Security.Principal.SecurityIdentifier($p['objectsid'][0], 0)
            $groupSid  = "$($userSid.AccountDomainSid)-$($p['primarygroupid'][0])"
            if (-not $primaryGroupCache.ContainsKey($groupSid)) {
                try   { $primaryGroupCache[$groupSid] = ([adsi]"LDAP://<SID=$groupSid>").cn[0] }
                catch { $primaryGroupCache[$groupSid] = $groupSid }
            }
            $groups = @($primaryGroupCache[$groupSid]) + $groups
        }

        $uac = [int]($p['useraccountcontrol'][0])

        [pscustomobject]@{
            SamAccountName = $p['samaccountname'][0]
            DisplayName    = $p['displayname'][0]
            Description    = $p['description'][0]
            Enabled        = -not ($uac -band 2)     # ACCOUNTDISABLE flag
            Groups         = ($groups | Sort-Object) -join '; '
            DN             = $p['distinguishedname'][0]
        }
    }
}

function Get-LocalUsersAdsi {
    $computer = [adsi]"WinNT://$env:COMPUTERNAME,computer"

    foreach ($user in $computer.Children | Where-Object { $_.SchemaClassName -eq 'user' }) {
        $groups = @($user.Groups() | ForEach-Object {
            $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
        })

        [pscustomobject]@{
            SamAccountName = $user.Name[0]
            DisplayName    = $user.FullName[0]
            Description    = $user.Description[0]
            Enabled        = -not ($user.UserFlags[0] -band 2)
            Groups         = ($groups | Sort-Object) -join '; '
        }
    }
}

$results = if ($Local) { Get-LocalUsersAdsi } else { Get-DomainUsers -SearchRoot $SearchRoot }
$results = $results | Sort-Object SamAccountName

if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $(@($results).Count) users to $CsvPath"
}
else {
    $results
}
