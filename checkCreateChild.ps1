#!/usr/bin/env powershell
<#
.SYNOPSIS
    Check whether a given user has the Create-Child right on any OU in an Active Directory domain.

.DESCRIPTION
    This script enumerates all Organizational Units in the specified domain and checks
    if the given user has Create-Child permissions on each OU using .NET DirectoryServices.

.PARAMETER Username
    sAMAccountName (e.g. alice)

.PARAMETER Password
    Password for the user

.PARAMETER Domain
    Domain FQDN (e.g. corp.example.com)

.PARAMETER DcIp
    Domain Controller hostname or IP (optional - will autodiscover if not specified)

.PARAMETER UseSSL
    Use LDAPS (TCP/636) instead of LDAP (TCP/389)

.PARAMETER ShowDebug
    Enable verbose debug output

.PARAMETER EnumerateUsers
    Instead of checking a specific user, enumerate all users/groups with CreateChild permissions by reading OU ACLs

.EXAMPLE
    .\createChildCheck.ps1 -u alice -p password123 -d corp.example.com

.EXAMPLE
    .\createChildCheck.ps1 -u alice -p password123 -d corp.example.com -DcIp 192.168.1.10 -ShowDebug

.EXAMPLE
    .\createChildCheck.ps1 -u alice -p password123 -d corp.example.com -EnumerateUsers

.NOTES
    Uses .NET DirectoryServices - no RSAT installation required
    
    Enumeration mode reads security descriptors from OUs to discover who has been granted 
    CreateChild permissions. This is more efficient than checking individual user accounts
    and provides a complete view of all granted permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="sAMAccountName (e.g. alice)")]
    [Alias("u")]
    [string]$Username,
    
    [Parameter(Mandatory=$true, HelpMessage="Password")]
    [Alias("p")]
    [string]$Password,
    
    [Parameter(Mandatory=$true, HelpMessage="Domain FQDN (e.g. corp.example.com)")]
    [Alias("d")]
    [string]$Domain,
    
    [Parameter(Mandatory=$false, HelpMessage="Domain Controller hostname or IP")]
    [string]$DcIp,
    
    [Parameter(Mandatory=$false, HelpMessage="Use LDAPS (TCP/636)")]
    [switch]$UseSSL,
    
    [Parameter(Mandatory=$false, HelpMessage="Enable verbose debug output")]
    [switch]$ShowDebug,
    
    [Parameter(Mandatory=$false, HelpMessage="Instead of checking a specific user, enumerate all users/groups with CreateChild permissions by reading OU ACLs")]
    [switch]$EnumerateUsers
)

# Load required .NET assemblies
Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# Debug function
function Write-DebugInfo {
    param([string]$Message)
    if ($ShowDebug) {
        Write-Host "[DEBUG] $Message" -ForegroundColor Yellow
    }
}

# Function to convert domain to DN
function Convert-DomainToDN {
    param([string]$Domain)
    $DN = "DC=" + ($Domain -split "\." -join ",DC=")
    Write-DebugInfo "Converted domain $Domain to DN: $DN"
    return $DN
}

# Function to get user and group SIDs
function Get-UserSids {
    param(
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry,
        [string]$Username
    )
    
    Write-DebugInfo "Collecting SIDs for user: $Username"
    
    try {
        # Test directory entry connection first
        Write-DebugInfo "Testing directory entry connection..."
        $TestPath = $DirectoryEntry.Path
        Write-DebugInfo "Directory entry path: $TestPath"
        
        # Get the base DN from the directory entry
        $BaseDN = $DirectoryEntry.DistinguishedName
        Write-DebugInfo "Base DN from directory entry: $BaseDN"
        
        # Try to construct user DN and bind directly (common approach)
        Write-DebugInfo "Attempting direct user binding approach..."
        $CommonUserContainers = @(
            "CN=Users,$BaseDN",
            "OU=Users,$BaseDN", 
            "CN=$Username,CN=Users,$BaseDN",
            "CN=$Username,OU=Users,$BaseDN"
        )
        
        $UserSid = $null
        $UserDN = $null
        
        # Try direct binding to common user locations
        foreach ($Container in $CommonUserContainers) {
            try {
                Write-DebugInfo "Trying direct bind to: $Container"
                $UserPath = $DirectoryEntry.Path.Replace($DirectoryEntry.Name.Substring(7), $Container)
                $UserEntry = New-Object System.DirectoryServices.DirectoryEntry($UserPath, $DirectoryEntry.Username, $DirectoryEntry.Password)
                
                # Test if this is our user
                $TestName = $UserEntry.Properties["sAMAccountName"].Value
                if ($TestName -eq $Username) {
                    Write-DebugInfo "Found user via direct binding: $Container"
                    $UserDN = $Container
                    $UserSidBytes = $UserEntry.Properties["objectSid"].Value
                    $UserSid = New-Object System.Security.Principal.SecurityIdentifier($UserSidBytes, 0)
                    Write-DebugInfo "User SID: $UserSid"
                    break
                }
            } catch {
                Write-DebugInfo "Direct bind to $Container failed: $($_.Exception.Message)"
            }
        }
        
        # If direct binding failed, try a very simple search with FindAll instead of FindOne
        if (-not $UserSid) {
            Write-DebugInfo "Direct binding failed, trying simple FindAll search..."
            
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry)
            $Searcher.Filter = "(sAMAccountName=$Username)"
            $Searcher.SearchScope = "OneLevel"  # Try OneLevel first instead of Subtree
            $Searcher.SizeLimit = 10
            $Searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $Searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
            $Searcher.PropertiesToLoad.Add("objectSid") | Out-Null
            
            Write-DebugInfo "Executing FindAll search with OneLevel scope..."
            $Results = $Searcher.FindAll()
            
            if ($Results.Count -eq 0) {
                Write-DebugInfo "OneLevel search returned no results, trying Subtree..."
                $Searcher.SearchScope = "Subtree"
                $Results = $Searcher.FindAll()
            }
            
            Write-DebugInfo "Search returned $($Results.Count) results"
            
            foreach ($Result in $Results) {
                $FoundUser = $Result.Properties["sAMAccountName"][0]
                Write-DebugInfo "Found user: $FoundUser"
                
                if ($FoundUser -eq $Username) {
                    $UserDN = $Result.Properties["distinguishedName"][0]
                    $UserSidBytes = $Result.Properties["objectSid"][0]
                    $UserSid = New-Object System.Security.Principal.SecurityIdentifier($UserSidBytes, 0)
                    Write-DebugInfo "User SID: $UserSid"
                    break
                }
            }
        }
        
        if (-not $UserSid) {
            throw "Could not find user $Username using any method"
        }
        
        # Start with just the user SID
        $UserSids = @($UserSid)
        
        # Try to get group SIDs if possible, but don't fail if we can't
        try {
            Write-DebugInfo "Attempting to get group memberships..."
            $UserPath = $DirectoryEntry.Path.Replace($DirectoryEntry.Name.Substring(7), $UserDN)
            $UserEntry = New-Object System.DirectoryServices.DirectoryEntry($UserPath, $DirectoryEntry.Username, $DirectoryEntry.Password)
            
            if ($UserEntry.Properties["tokenGroups"].Count -gt 0) {
                Write-DebugInfo "Processing $($UserEntry.Properties['tokenGroups'].Count) group SIDs..."
                $GroupCount = 0
                foreach ($GroupSidBytes in $UserEntry.Properties["tokenGroups"]) {
                    try {
                        $GroupSid = New-Object System.Security.Principal.SecurityIdentifier($GroupSidBytes, 0)
                        $UserSids += $GroupSid
                        $GroupCount++
                        Write-DebugInfo "Group SID $GroupCount`: $GroupSid"
                    } catch {
                        Write-DebugInfo "Skipping invalid group SID: $($_.Exception.Message)"
                    }
                }
            } else {
                Write-DebugInfo "No tokenGroups available"
            }
        } catch {
            Write-DebugInfo "Could not retrieve group memberships: $($_.Exception.Message)"
            Write-DebugInfo "Continuing with user SID only"
        }
        
        Write-DebugInfo "Total SIDs collected: $($UserSids.Count)"
        return $UserSids
        
    } catch {
        Write-DebugInfo "Error in Get-UserSids: $($_.Exception.Message)"
        Write-DebugInfo "Inner exception: $($_.Exception.InnerException.Message)"
        Write-DebugInfo "Stack trace: $($_.Exception.StackTrace)"
        throw "Failed to collect user SIDs: $($_.Exception.Message)"
    }
}

# Function to check if user has Create-Child permission on an OU
function Test-CreateChildPermission {
    param(
        [string]$OuDistinguishedName,
        [System.Security.Principal.SecurityIdentifier[]]$UserSids,
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry
    )
    
    Write-DebugInfo "Checking permissions on: $OuDistinguishedName"
    
    try {
        # Get the OU object
        $OuPath = "LDAP://$($DirectoryEntry.Name.Substring(7))/$OuDistinguishedName"
        $OU = New-Object System.DirectoryServices.DirectoryEntry($OuPath, $DirectoryEntry.Username, $DirectoryEntry.Password)
        
        # Test if we can actually read the security descriptor
        try {
            $TestAccess = $OU.psbase.ObjectSecurity
        } catch {
            Write-DebugInfo "WARNING: Cannot read security descriptor for $OuDistinguishedName - access denied"
            return $false
        }
        
        # Get security descriptor with both explicit and inherited permissions
        $SecurityDescriptor = $OU.psbase.ObjectSecurity
        $AccessRules = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        
        Write-DebugInfo "Retrieved $($AccessRules.Count) access rules (including inherited)"
        
        # First pass: Check for DENY rules that would block access
        $DenyRules = @()
        foreach ($Rule in $AccessRules) {
            if ($Rule.AccessControlType -eq "Deny" -and ($UserSids -contains $Rule.IdentityReference)) {
                $HasCreateChildDeny = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0
                $HasGenericAllDeny = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0
                $HasFullControlDeny = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::FullControl) -ne 0
                
                if ($HasCreateChildDeny -or $HasGenericAllDeny -or $HasFullControlDeny) {
                    Write-DebugInfo "DENY rule found for user - CreateChild access explicitly denied"
                    return $false
                }
            }
        }
        
        # Second pass: Check for ALLOW rules
        foreach ($Rule in $AccessRules) {
            Write-DebugInfo "Examining rule: $($Rule.IdentityReference) - $($Rule.AccessControlType) - $($Rule.ActiveDirectoryRights) - Inherited: $($Rule.IsInherited)"
            
            # Check for Allow rules with permissions that grant CreateChild capability
            if ($Rule.AccessControlType -eq "Allow") {
                $HasCreateChild = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0
                $HasGenericAll = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0
                $HasFullControl = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::FullControl) -ne 0
                $HasGenericWrite = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -ne 0
                
                # Check for permission modification rights (can grant themselves CreateChild)
                $HasWriteDacl = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0
                $HasWriteOwner = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0
                
                if ($HasCreateChild -or $HasGenericAll -or $HasFullControl -or $HasGenericWrite -or ($HasWriteDacl -and $HasWriteOwner)) {
                    $PermissionType = ""
                    if ($HasGenericAll) { $PermissionType = "GenericAll" }
                    elseif ($HasFullControl) { $PermissionType = "FullControl" }
                    elseif ($HasCreateChild) { $PermissionType = "CreateChild" }
                    elseif ($HasGenericWrite) { $PermissionType = "GenericWrite" }
                    elseif ($HasWriteDacl -and $HasWriteOwner) { $PermissionType = "WriteDacl+WriteOwner" }
                    
                    Write-DebugInfo "Rule grants $PermissionType permission"
                    
                    # Check if this rule applies to our user
                    if ($UserSids -contains $Rule.IdentityReference) {
                        Write-DebugInfo "MATCH: User has CreateChild capability via $PermissionType on $($Rule.IdentityReference)"
                        return $true
                    }
                }
                
                # Check for object-specific CreateChild extended rights
                if ($Rule -is [System.Security.AccessControl.ObjectAccessRule]) {
                    $ObjectRule = [System.Security.AccessControl.ObjectAccessRule]$Rule
                    if ($ObjectRule.ObjectType -ne [System.Guid]::Empty) {
                        $ObjectTypeGuid = $ObjectRule.ObjectType.ToString().ToLower()
                        if ($ADObjectTypes.ContainsKey($ObjectTypeGuid)) {
                            $HasObjectCreateChild = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0
                            if ($HasObjectCreateChild -and ($UserSids -contains $Rule.IdentityReference)) {
                                $ObjectTypeName = $ADObjectTypes[$ObjectTypeGuid]
                                Write-DebugInfo "MATCH: User has CreateChild permission for $ObjectTypeName objects via $($Rule.IdentityReference)"
                                return $true
                            }
                        }
                    }
                }
            }
        }
        
        Write-DebugInfo "No matching permissions found"
        return $false
        
    } catch {
        Write-DebugInfo "Error checking permissions on $OuDistinguishedName`: $_"
        return $false
    }
}

# Function to enumerate all users/groups with CreateChild permission on OU
function Get-CreateChildUsers {
    param(
        [string]$OuDistinguishedName,
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry
    )
    
    Write-DebugInfo "Enumerating all users/groups with CreateChild on: $OuDistinguishedName"
    
    $CreateChildUsers = @()
    
    try {
        # Get the OU object
        $OuPath = "LDAP://$($DirectoryEntry.Name.Substring(7))/$OuDistinguishedName"
        $OU = New-Object System.DirectoryServices.DirectoryEntry($OuPath, $DirectoryEntry.Username, $DirectoryEntry.Password)
        
        # Test if we can actually read the security descriptor
        try {
            $TestAccess = $OU.psbase.ObjectSecurity
        } catch {
            Write-DebugInfo "WARNING: Cannot read security descriptor for $OuDistinguishedName - access denied"
            return @()
        }
        
        # Get security descriptor with both explicit and inherited permissions
        $SecurityDescriptor = $OU.psbase.ObjectSecurity
        $AccessRules = $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        
        Write-DebugInfo "Retrieved $($AccessRules.Count) access rules (including inherited)"
        
        # Collect DENY rules to check against later
        $DenyRules = @()
        foreach ($Rule in $AccessRules) {
            if ($Rule.AccessControlType -eq "Deny") {
                $HasCreateChildDeny = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0
                $HasGenericAllDeny = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0
                $HasFullControlDeny = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::FullControl) -ne 0
                
                if ($HasCreateChildDeny -or $HasGenericAllDeny -or $HasFullControlDeny) {
                    $DenyRules += $Rule
                    Write-DebugInfo "Found DENY rule for $($Rule.IdentityReference)"
                }
            }
        }
        
        foreach ($Rule in $AccessRules) {
            # Check for Allow rules with permissions that grant CreateChild capability
            if ($Rule.AccessControlType -eq "Allow") {
                $HasCreateChild = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0
                $HasGenericAll = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0
                $HasFullControl = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::FullControl) -ne 0
                $HasGenericWrite = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -ne 0
                
                # Check for permission modification rights (can grant themselves CreateChild)
                $HasWriteDacl = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0
                $HasWriteOwner = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0
                
                if ($HasCreateChild -or $HasGenericAll -or $HasFullControl -or $HasGenericWrite -or ($HasWriteDacl -and $HasWriteOwner)) {
                    # Determine the most specific permission type
                    $PermissionType = ""
                    if ($HasGenericAll) { $PermissionType = "GenericAll" }
                    elseif ($HasFullControl) { $PermissionType = "FullControl" }
                    elseif ($HasCreateChild) { $PermissionType = "CreateChild" }
                    elseif ($HasGenericWrite) { $PermissionType = "GenericWrite" }
                    elseif ($HasWriteDacl -and $HasWriteOwner) { $PermissionType = "WriteDacl+WriteOwner" }
                    
                    Write-DebugInfo "Found $PermissionType permission for SID: $($Rule.IdentityReference)"
                    
                    # Check if this permission is overridden by a DENY rule
                    $IsDenied = $false
                    foreach ($DenyRule in $DenyRules) {
                        if ($DenyRule.IdentityReference -eq $Rule.IdentityReference) {
                            Write-DebugInfo "Permission overridden by DENY rule for $($Rule.IdentityReference)"
                            $IsDenied = $true
                            break
                        }
                    }
                    
                    if (-not $IsDenied) {
                        # Try to resolve SID to name
                        $ResolvedName = "Unknown"
                        try {
                            $ResolvedName = $Rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                            Write-DebugInfo "Resolved to: $ResolvedName"
                        } catch {
                            Write-DebugInfo "Could not resolve SID $($Rule.IdentityReference) to name"
                            $ResolvedName = $Rule.IdentityReference.Value
                        }
                        
                        $CreateChildUsers += [PSCustomObject]@{
                            Identity = $ResolvedName
                            SID = $Rule.IdentityReference.Value
                            Permission = $PermissionType
                            OU = $OuDistinguishedName
                            IsInherited = $Rule.IsInherited
                        }
                    }
                }
                
                # Check for object-specific CreateChild extended rights
                if ($Rule -is [System.Security.AccessControl.ObjectAccessRule]) {
                    $ObjectRule = [System.Security.AccessControl.ObjectAccessRule]$Rule
                    if ($ObjectRule.ObjectType -ne [System.Guid]::Empty) {
                        $ObjectTypeGuid = $ObjectRule.ObjectType.ToString().ToLower()
                        if ($ADObjectTypes.ContainsKey($ObjectTypeGuid)) {
                            $HasObjectCreateChild = ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::CreateChild) -ne 0
                            if ($HasObjectCreateChild) {
                                $ObjectTypeName = $ADObjectTypes[$ObjectTypeGuid]
                                Write-DebugInfo "Found CreateChild permission for $ObjectTypeName objects: $($Rule.IdentityReference)"
                                
                                # Check if this permission is overridden by a DENY rule
                                $IsDenied = $false
                                foreach ($DenyRule in $DenyRules) {
                                    if ($DenyRule.IdentityReference -eq $Rule.IdentityReference) {
                                        Write-DebugInfo "Permission overridden by DENY rule for $($Rule.IdentityReference)"
                                        $IsDenied = $true
                                        break
                                    }
                                }
                                
                                if (-not $IsDenied) {
                                    # Try to resolve SID to name
                                    $ResolvedName = "Unknown"
                                    try {
                                        $ResolvedName = $Rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                                        Write-DebugInfo "Resolved to: $ResolvedName"
                                    } catch {
                                        Write-DebugInfo "Could not resolve SID $($Rule.IdentityReference) to name"
                                        $ResolvedName = $Rule.IdentityReference.Value
                                    }
                                    
                                    $CreateChildUsers += [PSCustomObject]@{
                                        Identity = $ResolvedName
                                        SID = $Rule.IdentityReference.Value
                                        Permission = "CreateChild-$ObjectTypeName"
                                        OU = $OuDistinguishedName
                                        IsInherited = $Rule.IsInherited
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Write-DebugInfo "Found $($CreateChildUsers.Count) users/groups with CreateChild permissions"
        return $CreateChildUsers
        
    } catch {
        Write-DebugInfo "Error enumerating users on $OuDistinguishedName`: $_"
        return @()
    }
}

# Common AD object type GUIDs for CreateChild extended rights
$ADObjectTypes = @{
    "bf967aba-0de6-11d0-a285-00aa003049e2" = "User"
    "bf967a86-0de6-11d0-a285-00aa003049e2" = "Computer" 
    "bf967a9c-0de6-11d0-a285-00aa003049e2" = "Group"
    "bf967aa5-0de6-11d0-a285-00aa003049e2" = "Organization"
    "bf967aad-0de6-11d0-a285-00aa003049e2" = "Organizational-Unit"
    "5cb41ed0-0e4c-11d0-a286-00aa003049e2" = "Contact"
    "bf967aa8-0de6-11d0-a285-00aa003049e2" = "Organizational-Person"
}

# Main execution
try {
    Write-DebugInfo "Target domain: $Domain"
    Write-DebugInfo "Username: $Username"
    Write-DebugInfo "DC override: $(if ($DcIp) { $DcIp } else { 'None (auto-discover)' })"
    Write-DebugInfo "SSL enabled: $UseSSL"
    
    # Build LDAP connection string
    $BaseDN = Convert-DomainToDN -Domain $Domain
    $Server = if ($DcIp) { $DcIp } else { $Domain }
    $Protocol = if ($UseSSL) { "LDAPS" } else { "LDAP" }
    $Port = if ($UseSSL) { "636" } else { "389" }
    $LdapPath = "$Protocol`://$Server`:$Port/$BaseDN"
    
    Write-DebugInfo "LDAP connection string: $LdapPath"
    Write-DebugInfo "Base DN: $BaseDN"
    
    # Create directory entry with credentials
    Write-DebugInfo "Creating directory entry with credentials..."
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LdapPath, "$Domain\$Username", $Password)
    
    # Set authentication type explicitly
    $DirectoryEntry.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure
    
    # Test authentication by accessing properties
    Write-DebugInfo "Testing authentication..."
    try {
        $TestName = $DirectoryEntry.Name
        $TestGuid = $DirectoryEntry.Guid
        Write-DebugInfo "Connection test successful - Name: $TestName, GUID: $TestGuid"
        Write-Host "[+] Successfully authenticated as $Domain\$Username" -ForegroundColor Green
    } catch {
        Write-DebugInfo "Authentication test failed: $($_.Exception.Message)"
        
        # Try without SSL if SSL failed
        if ($UseSSL) {
            Write-DebugInfo "SSL connection failed, trying without SSL..."
            $LdapPath = "LDAP://$Server`:389/$BaseDN"
            Write-DebugInfo "Fallback LDAP connection string: $LdapPath"
            
            $DirectoryEntry.Dispose()
            $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($LdapPath, "$Domain\$Username", $Password)
            $DirectoryEntry.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure
            
            $TestName = $DirectoryEntry.Name
            $TestGuid = $DirectoryEntry.Guid
            Write-DebugInfo "Fallback connection successful - Name: $TestName, GUID: $TestGuid"
            Write-Host "[+] Successfully authenticated as $Domain\$Username (using fallback LDAP)" -ForegroundColor Green
        } else {
            throw "Authentication failed: $($_.Exception.Message)"
        }
    }
    
    # Get user SIDs (only needed for specific user check)
    $UserSids = $null
    if (-not $EnumerateUsers) {
        $UserSids = Get-UserSids -DirectoryEntry $DirectoryEntry -Username $Username
    }
    
    # Search for all OUs
    Write-DebugInfo "Enumerating OUs in domain..."
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry)
    $Searcher.Filter = "(objectClass=organizationalUnit)"
    $Searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $Searcher.SearchScope = "Subtree"
    
    $OuResults = $Searcher.FindAll()
    Write-DebugInfo "Found $($OuResults.Count) OUs"
    
    if ($EnumerateUsers) {
        # Enumeration mode - find all users/groups with CreateChild permissions
        Write-DebugInfo "Running in enumeration mode - reading ACLs to find all users/groups with CreateChild permissions"
        Write-Host "`n[*] Enumerating CreateChild permissions by reading OU security descriptors..." -ForegroundColor Cyan
        Write-Host "[*] Note: This reads ACLs from OUs to find who has been granted permissions (not checking individual users)" -ForegroundColor Yellow
        
        $AllCreateChildUsers = @()
        $OuCount = 0
        
        foreach ($OuResult in $OuResults) {
            $OuDN = $OuResult.Properties['distinguishedname'][0]
            $OuCount++
            
            Write-Host "  [$OuCount/$($OuResults.Count)] Checking: $OuDN" -ForegroundColor Gray
            Write-DebugInfo "`n=== Enumerating users on OU: $OuDN ==="
            
            $OuUsers = Get-CreateChildUsers -OuDistinguishedName $OuDN -DirectoryEntry $DirectoryEntry
            if ($OuUsers.Count -gt 0) {
                Write-Host "    Found $($OuUsers.Count) permission(s)" -ForegroundColor Green
            }
            $AllCreateChildUsers += $OuUsers
        }
        
        # Display enumeration results
        Write-Host "`n[*] Completed enumeration of $($OuResults.Count) OU(s) in $Domain" -ForegroundColor Cyan
        Write-Host "[!] Note: Results limited to OUs where security descriptors are readable by current user" -ForegroundColor Yellow
        
        if ($AllCreateChildUsers.Count -gt 0) {
            Write-Host "`n[+] Found $($AllCreateChildUsers.Count) CreateChild permission(s) across all OUs:" -ForegroundColor Green
            
            # Group by OU for better readability
            $GroupedByOU = $AllCreateChildUsers | Group-Object -Property OU
            
            foreach ($Group in $GroupedByOU | Sort-Object Name) {
                Write-Host "`n  OU: $($Group.Name)" -ForegroundColor Yellow
                foreach ($User in $Group.Group | Sort-Object Identity) {
                    $ColorCode = if ($User.Permission -eq "GenericAll") { "Red" } else { "Green" }
                    Write-Host "    $($User.Identity) ($($User.Permission))" -ForegroundColor $ColorCode
                    Write-DebugInfo "      SID: $($User.SID)"
                }
            }
            
            # Summary by user/group
            Write-Host "`n[*] Summary by Identity:" -ForegroundColor Cyan
            $GroupedByIdentity = $AllCreateChildUsers | Group-Object -Property Identity
            foreach ($Group in $GroupedByIdentity | Sort-Object Name) {
                $OuCount = $Group.Group.Count
                $HasGenericAll = ($Group.Group | Where-Object { $_.Permission -eq "GenericAll" }).Count -gt 0
                $ColorCode = if ($HasGenericAll) { "Red" } else { "Green" }
                Write-Host "  $($Group.Name): $OuCount OU(s)" -ForegroundColor $ColorCode
            }
        } else {
            Write-Host "`n[-] No users or groups found with CreateChild permissions on any OUs in $Domain" -ForegroundColor Red
        }
        
    } else {
        # Specific user check mode (original functionality)
        $CheckedOUs = @()
        $CreatableOUs = @()
        
        foreach ($OuResult in $OuResults) {
            $OuDN = $OuResult.Properties['distinguishedname'][0]
            $CheckedOUs += $OuDN
            
            Write-DebugInfo "`n=== Processing OU: $OuDN ==="
            
            if (Test-CreateChildPermission -OuDistinguishedName $OuDN -UserSids $UserSids -DirectoryEntry $DirectoryEntry) {
                Write-DebugInfo "RESULT: Create-Child permission GRANTED on $OuDN"
                $CreatableOUs += $OuDN
            } else {
                Write-DebugInfo "RESULT: Create-Child permission DENIED on $OuDN"
            }
        }
        
        # Display results for specific user
        Write-Host "`n[*] Checked $($CheckedOUs.Count) OU(s) in $Domain`:" -ForegroundColor Cyan
        foreach ($OU in $CheckedOUs | Sort-Object) {
            Write-Host "    $OU"
        }
        
        if ($CreatableOUs.Count -gt 0) {
            Write-Host "`n[+] User '$Username' has Create-Child permission on $($CreatableOUs.Count) OU(s):" -ForegroundColor Green
            foreach ($OU in $CreatableOUs | Sort-Object) {
                Write-Host "    $OU" -ForegroundColor Green
            }
        } else {
            Write-Host "`n[-] User '$Username' does NOT have Create-Child permission on any OUs in $Domain" -ForegroundColor Red
        }
    }
    
    # Cleanup
    $DirectoryEntry.Dispose()
    $OuResults.Dispose()
    
} catch {
    Write-Error "[!] Script execution failed: $_"
    exit 1
} 
