#!/usr/bin/env python3
"""
check_createchild.py
Determine whether a given user has the Create‑Child right on any OU in an Active Directory domain.

Requirements (tested):
    pip install -U ldap3>=2.6 impacket>=0.11
"""

import argparse
import sys
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ldap3 import Connection

# -----------------------------------------------------------------------------
# Active Directory Rights Constants
# -----------------------------------------------------------------------------
ADS_RIGHT_DS_CREATE_CHILD = 0x00000001  # Create‑Child Objects right
ADS_RIGHT_GENERIC_ALL = 0x10000000      # Generic All
ADS_RIGHT_GENERIC_WRITE = 0x40000000    # Generic Write  
ADS_RIGHT_WRITE_DAC = 0x00040000        # Write DACL
ADS_RIGHT_WRITE_OWNER = 0x00080000      # Write Owner
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100 # Control Access (for extended rights)

# Common AD object type GUIDs for CreateChild extended rights
AD_OBJECT_TYPES = {
    "bf967aba-0de6-11d0-a285-00aa003049e2": "User",
    "bf967a86-0de6-11d0-a285-00aa003049e2": "Computer", 
    "bf967a9c-0de6-11d0-a285-00aa003049e2": "Group",
    "bf967aa5-0de6-11d0-a285-00aa003049e2": "Organization",
    "bf967aad-0de6-11d0-a285-00aa003049e2": "Organizational-Unit",
    "5cb41ed0-0e4c-11d0-a286-00aa003049e2": "Contact",
    "bf967aa8-0de6-11d0-a285-00aa003049e2": "Organizational-Person",
}

# -----------------------------------------------------------------------------
# Attempt to obtain helper utilities that moved between releases.
# -----------------------------------------------------------------------------
# --- ldap3 Security‑Descriptor control ---------------------------------------
def build_sd_control_factory():
    """Factory function to create the appropriate SD control builder"""
    try:
        # ldap3 ≥ 2.7
        from ldap3.protocol.controls.security_descriptor import SDFlagsControl  # type: ignore

        def build_sd_control(flags: int = 0x04):  # DACL_SECURITY_INFORMATION
            print(f"[DEBUG] Selected SDFlagsControl from ldap3.protocol.controls.security_descriptor")
            return SDFlagsControl(sdflags=flags)
        return build_sd_control

    except ModuleNotFoundError:  # fallback for ldap3 ≤ 2.6
        try:
            from ldap3.protocol.microsoft import security_descriptor_control  # type: ignore
            import struct

            def build_sd_control(flags: int = 0x04):
                print(f"[DEBUG] Selected security_descriptor_control from ldap3.protocol.microsoft")
                # Create the control value manually - SD_FLAGS is a 4-byte little-endian integer
                control_value = struct.pack('<I', flags)
                # Return in the format ldap3 expects: (controlType, criticality, controlValue)
                return ('1.2.840.113556.1.4.801', False, control_value)
            return build_sd_control

        except ModuleNotFoundError:
            def build_sd_control(*_, **__):  # noqa: D401
                raise ImportError(
                    "Unable to import SDFlagsControl or security_descriptor_control — "
                    "please upgrade the 'ldap3' package to version ≥ 2.6."
                )
            return build_sd_control

# --- Local formatSid implementation ------------------------------------------
def formatSid(sid_bytes):  # type: ignore  # pylint: disable=invalid-name
    """Best‑effort conversion of binary SID → S‑1‑… string (slow)."""
    if not sid_bytes:
        return "S‑0‑0"
    rev = sid_bytes[0]
    subauth_cnt = sid_bytes[1]
    auth = int.from_bytes(sid_bytes[2:8], "big")
    subs = struct.unpack("<" + "I" * subauth_cnt, sid_bytes[8 : 8 + 4 * subauth_cnt])
    return "S-%d-%d%s" % (rev, auth, "".join("-%d" % sa for sa in subs))

# -----------------------------------------------------------------------------

DEBUG = False  # toggled by --debug flag


def debug(msg: str):
    """Lightweight debug helper – prints only when --debug is set."""
    if DEBUG:
        print(f"[DEBUG] {msg}")


def domain_to_basedn(domain: str) -> str:
    """Convert contoso.com -> DC=contoso,DC=com"""
    basedn = ",".join(f"DC={part}" for part in domain.split("."))
    debug(f"Calculated BaseDN: {basedn}")
    return basedn


def collect_user_sids(conn: "Connection", basedn: str, sam_account: str):
    """Return a set of SIDs (user + tokenGroups) for *sam_account*."""
    from ldap3 import SUBTREE, BASE
    
    debug(f"Searching for user DN of {sam_account} …")
    conn.search(
        search_base=basedn,
        search_filter=f"(&(objectClass=user)(sAMAccountName={sam_account}))",
        search_scope=SUBTREE,
        attributes=["distinguishedName"],
    )
    if not conn.entries:
        raise RuntimeError(f"Unable to locate user {sam_account} in {basedn}")

    user_dn = conn.entries[0].entry_dn
    debug(f"User DN found: {user_dn}")

    debug("Pulling objectSid and tokenGroups …")
    conn.search(
        search_base=user_dn,
        search_filter="(objectClass=*)",
        search_scope=BASE,  # Use BASE scope when searching a specific DN
        attributes=["objectSid", "tokenGroups"],
    )
    
    if not conn.entries:
        raise RuntimeError(f"Unable to retrieve objectSid and tokenGroups for {user_dn}")
    
    entry = conn.entries[0]
    sids = {formatSid(entry.objectSid.raw_values[0])}
    for sid in entry.tokenGroups.raw_values:
        sids.add(formatSid(sid))
    debug(f"Caller SIDs collected: {len(sids)} total")
    return sids


def ace_grants_create_child(ace, principal_sids):
    """Return True if this ACE grants Create‑Child to the caller."""
    ace_mask = ace["Ace"]["Mask"]["Mask"]
    debug(f"Examining ACE with mask: 0x{ace_mask:08x}")
    
    # Check for various permissions that grant CreateChild capability
    has_create_child = (ace_mask & ADS_RIGHT_DS_CREATE_CHILD) != 0
    has_generic_all = (ace_mask & ADS_RIGHT_GENERIC_ALL) != 0
    has_generic_write = (ace_mask & ADS_RIGHT_GENERIC_WRITE) != 0
    has_write_dac = (ace_mask & ADS_RIGHT_WRITE_DAC) != 0
    has_write_owner = (ace_mask & ADS_RIGHT_WRITE_OWNER) != 0
    
    # Check if any of these permissions are present
    if not (has_create_child or has_generic_all or has_generic_write or (has_write_dac and has_write_owner)):
        debug("ACE does not grant CreateChild-capable permissions")
        return False
        
    ace_sid = formatSid(ace["Ace"]["Sid"].getData())
    debug(f"ACE applies to SID: {ace_sid}")
    
    # Determine permission type for debugging
    permission_type = ""
    if has_generic_all:
        permission_type = "GenericAll"
    elif has_create_child:
        permission_type = "CreateChild"
    elif has_generic_write:
        permission_type = "GenericWrite"
    elif has_write_dac and has_write_owner:
        permission_type = "WriteDacl+WriteOwner"
    
    if ace_sid in principal_sids:
        debug(f"MATCH: ACE SID {ace_sid} matches one of our principal SIDs via {permission_type}")
        return True
    else:
        debug(f"No match: ACE SID not in our principal SIDs")
        return False


def enumerate_createchild_users(sd_bytes: bytes):
    """Return a list of all users/groups with CreateChild permissions on this OU."""
    from impacket.ldap.ldaptypes import (
        SR_SECURITY_DESCRIPTOR,
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE,
        ACCESS_DENIED_OBJECT_ACE,
    )
    
    debug(f"Enumerating users with CreateChild permissions from security descriptor ({len(sd_bytes)} bytes)")
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    
    users_with_permissions = []

    # Empty (None) DACL means full access to everyone.
    if sd["Dacl"] is None:
        debug("DACL is None - everyone has full access")
        return [{"identity": "Everyone", "sid": "S-1-1-0", "permission": "Full (No DACL)", "is_inherited": False}]

    ace_count = len(sd["Dacl"].aces)
    debug(f"DACL contains {ace_count} ACE(s)")
    
    # Collect DENY rules to check against later
    deny_rules = {}
    for i, ace in enumerate(sd["Dacl"].aces):
        if ace["AceType"] in (ACCESS_DENIED_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE):
            ace_mask = ace["Ace"]["Mask"]["Mask"]
            blocks_create_child = (ace_mask & ADS_RIGHT_DS_CREATE_CHILD) != 0
            blocks_generic_all = (ace_mask & ADS_RIGHT_GENERIC_ALL) != 0
            
            if blocks_create_child or blocks_generic_all:
                ace_sid = formatSid(ace["Ace"]["Sid"].getData())
                deny_rules[ace_sid] = True
                debug(f"Found DENY rule for {ace_sid}")
    
    # Check ALLOW rules
    for i, ace in enumerate(sd["Dacl"].aces):
        debug(f"Processing ACE {i+1}/{ace_count}, type: {ace['AceType']}")
        
        if ace["AceType"] in (ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            ace_mask = ace["Ace"]["Mask"]["Mask"]
            ace_sid = formatSid(ace["Ace"]["Sid"].getData())
            
            # Check if this permission is overridden by a DENY rule
            if ace_sid in deny_rules:
                debug(f"Permission for {ace_sid} overridden by DENY rule")
                continue
            
            # Check for various permissions that grant CreateChild capability
            has_create_child = (ace_mask & ADS_RIGHT_DS_CREATE_CHILD) != 0
            has_generic_all = (ace_mask & ADS_RIGHT_GENERIC_ALL) != 0
            has_generic_write = (ace_mask & ADS_RIGHT_GENERIC_WRITE) != 0
            has_write_dac = (ace_mask & ADS_RIGHT_WRITE_DAC) != 0
            has_write_owner = (ace_mask & ADS_RIGHT_WRITE_OWNER) != 0
            
            if has_create_child or has_generic_all or has_generic_write or (has_write_dac and has_write_owner):
                # Determine the most specific permission type
                permission_type = ""
                if has_generic_all:
                    permission_type = "GenericAll"
                elif has_create_child:
                    permission_type = "CreateChild"
                elif has_generic_write:
                    permission_type = "GenericWrite"
                elif has_write_dac and has_write_owner:
                    permission_type = "WriteDacl+WriteOwner"
                
                debug(f"Found {permission_type} permission for SID: {ace_sid}")
                
                users_with_permissions.append({
                    "identity": ace_sid,  # Will try to resolve to name later
                    "sid": ace_sid,
                    "permission": permission_type,
                    "is_inherited": False  # TODO: Could be enhanced to detect inheritance
                })
            
            # Check for object-specific CreateChild rights (extended rights)
            if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                try:
                    object_type = ace["Ace"].get("ObjectType")
                    if object_type:
                        object_guid = str(object_type).lower()
                        if object_guid in AD_OBJECT_TYPES and (ace_mask & ADS_RIGHT_DS_CREATE_CHILD) != 0:
                            if ace_sid not in deny_rules:
                                object_name = AD_OBJECT_TYPES[object_guid]
                                debug(f"Found CreateChild permission for {object_name} objects: {ace_sid}")
                                
                                users_with_permissions.append({
                                    "identity": ace_sid,
                                    "sid": ace_sid, 
                                    "permission": f"CreateChild-{object_name}",
                                    "is_inherited": False
                                })
                except (KeyError, AttributeError):
                    debug(f"Could not parse object type for ACE {i+1}")
    
    debug(f"Found {len(users_with_permissions)} users/groups with CreateChild permissions")
    return users_with_permissions


def ou_allows_create_child(sd_bytes: bytes, principal_sids):
    """Examine a raw security descriptor and decide if Create‑Child applies."""
    from impacket.ldap.ldaptypes import (
        SR_SECURITY_DESCRIPTOR,
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE,
        ACCESS_DENIED_OBJECT_ACE,
    )
    
    debug(f"Parsing security descriptor ({len(sd_bytes)} bytes)")
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)

    # Empty (None) DACL means full access to everyone.
    if sd["Dacl"] is None:
        debug("DACL is None - full access granted to everyone")
        return True

    ace_count = len(sd["Dacl"].aces)
    debug(f"DACL contains {ace_count} ACE(s)")
    
    # First pass: Check for DENY rules that would block access
    for i, ace in enumerate(sd["Dacl"].aces):
        debug(f"Processing ACE {i+1}/{ace_count}, type: {ace['AceType']}")
        
        if ace["AceType"] in (ACCESS_DENIED_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE):
            debug(f"ACE {i+1} is a DENY ACE - checking if it blocks our access")
            ace_mask = ace["Ace"]["Mask"]["Mask"]
            
            # Check if this DENY ACE blocks CreateChild-related permissions
            blocks_create_child = (ace_mask & ADS_RIGHT_DS_CREATE_CHILD) != 0
            blocks_generic_all = (ace_mask & ADS_RIGHT_GENERIC_ALL) != 0
            
            if blocks_create_child or blocks_generic_all:
                ace_sid = formatSid(ace["Ace"]["Sid"].getData())
                if ace_sid in principal_sids:
                    debug(f"DENY rule blocks CreateChild access for our principal: {ace_sid}")
                    return False
    
    # Second pass: Check for ALLOW rules
    for i, ace in enumerate(sd["Dacl"].aces):
        if ace["AceType"] in (
            ACCESS_ALLOWED_ACE.ACE_TYPE,
            ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
        ):
            debug(f"ACE {i+1} is an ALLOW ACE - checking permissions")
            if ace_grants_create_child(ace, principal_sids):
                debug(f"ACE {i+1} grants CreateChild permission!")
                return True
                
            # Check for object-specific CreateChild rights (extended rights)
            if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                try:
                    object_type = ace["Ace"].get("ObjectType")
                    if object_type:
                        object_guid = str(object_type).lower()
                        if object_guid in AD_OBJECT_TYPES:
                            ace_mask = ace["Ace"]["Mask"]["Mask"]
                            if (ace_mask & ADS_RIGHT_DS_CREATE_CHILD) != 0:
                                ace_sid = formatSid(ace["Ace"]["Sid"].getData())
                                if ace_sid in principal_sids:
                                    object_name = AD_OBJECT_TYPES[object_guid]
                                    debug(f"ACE {i+1} grants CreateChild permission for {object_name} objects!")
                                    return True
                except (KeyError, AttributeError):
                    debug(f"Could not parse object type for ACE {i+1}")
        else:
            debug(f"ACE {i+1} is not an ALLOW ACE (type {ace['AceType']}) - skipping")
    
    debug("No ACEs grant Create-Child permission")
    return False


def main():
    global DEBUG  # pylint: disable=global-statement
    
    # Import dependencies inside main() to allow help to work without dependencies
    from ldap3 import Server, Connection, NTLM, SUBTREE, ALL
    from ldap3.core.exceptions import LDAPBindError, LDAPException

    parser = argparse.ArgumentParser(
        description="Check whether a user has Create‑Child permission on any OU.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python createChildCheck.py -u alice -p password123 -d corp.example.com
  python createChildCheck.py -u alice -p password123 -d corp.example.com --dc-ip 192.168.1.10
  python createChildCheck.py -u alice -p password123 -d corp.example.com --ssl --debug
  python createChildCheck.py -u alice -p password123 -d corp.example.com --enumerate-users

Note:
  Enumeration mode reads security descriptors from OUs to discover who has been granted 
  CreateChild permissions. This includes standard permissions, extended rights (object-specific), 
  and inherited permissions. Results are limited to OUs readable by the authenticated user.
""")
    parser.add_argument("-u", "--username", required=True, help="sAMAccountName (e.g. alice)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-d", "--domain", required=True, help="Domain FQDN (e.g. corp.example.com)")
    parser.add_argument(
        "--dc-ip",
        help="Domain Controller hostname or IP (default: autodiscover via DNS)",
    )
    parser.add_argument("--ssl", action="store_true", help="Use LDAPS (TCP/636)")
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")
    parser.add_argument("--enumerate-users", action="store_true", 
                       help="Instead of checking a specific user, enumerate all users/groups with CreateChild permissions by reading OU ACLs")
    args = parser.parse_args()

    DEBUG = args.debug

    basedn = domain_to_basedn(args.domain)

    debug("Initialising LDAP server object …")
    server = Server(
        args.dc_ip or args.domain,
        port=636 if args.ssl else 389,
        use_ssl=args.ssl,
        get_info=ALL,
    )

    debug("Attempting LDAP bind …")
    try:
        conn = Connection(
            server,
            user=f"{args.domain}\\{args.username}",
            password=args.password,
            authentication=NTLM,
            auto_bind=True,
        )
    except LDAPBindError as e:
        sys.exit(f"[!] LDAP bind failed: {e}")

    print(f"[+] Successfully authenticated as {args.domain}\\{args.username}")
    debug("LDAP bind successful.")

    # Get user SIDs (only needed for specific user check)
    principal_sids = None
    if not args.enumerate_users:
        try:
            principal_sids = collect_user_sids(conn, basedn, args.username)
        except LDAPException as e:
            sys.exit(f"[!] Failed to collect SIDs: {e}")

    debug("Building Security‑Descriptor control …")
    try:
        sd_control = build_sd_control_factory()(0x04)  # DACL_SECURITY_INFORMATION
        debug(f"SD control created: {sd_control}")
    except ImportError as e:
        sys.exit(f"[!] {e}")

    debug("Enumerating OUs …")
    try:
        conn.search(
            search_base=basedn,
            search_filter="(objectClass=organizationalUnit)",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "nTSecurityDescriptor"],
            controls=[sd_control],
        )
        debug(f"Search controls used: {[sd_control]}")
        debug(f"Search returned {len(conn.entries)} entries")
        if conn.entries:
            debug(f"First entry attributes: {list(conn.entries[0].entry_attributes_as_dict.keys())}")
    except LDAPException as e:
        sys.exit(f"[!] Failed to enumerate OUs: {e}")

    if args.enumerate_users:
        # Enumeration mode - find all users/groups with CreateChild permissions
        debug("Running in enumeration mode - reading ACLs to find all users/groups with CreateChild permissions")
        print("\n[*] Enumerating CreateChild permissions by reading OU security descriptors...")
        print("[*] Note: This reads ACLs from OUs to find who has been granted permissions (not checking individual users)")
        
        all_createchild_users = []
        ou_count = 0
        
        for entry in conn.entries:
            ou_dn = str(entry.distinguishedName)
            ou_count += 1
            
            print(f"  [{ou_count}/{len(conn.entries)}] Checking: {ou_dn}")
            debug(f"\n=== Enumerating users on OU: {ou_dn} ===")
            
            # Check if nTSecurityDescriptor is present and has data
            if "nTSecurityDescriptor" not in entry or not entry["nTSecurityDescriptor"].raw_values:
                debug(f"WARNING: No security descriptor available for {ou_dn} - skipping")
                continue
                
            sd_bytes = entry["nTSecurityDescriptor"].raw_values[0]
            debug(f"Security descriptor length: {len(sd_bytes)} bytes")
            
            ou_users = enumerate_createchild_users(sd_bytes)
            if ou_users:
                print(f"    Found {len(ou_users)} permission(s)")
                for user in ou_users:
                    user["ou"] = ou_dn
                all_createchild_users.extend(ou_users)
        
        # Display enumeration results
        print(f"\n[*] Completed enumeration of {len(conn.entries)} OU(s) in {args.domain}")
        print("[!] Note: Results limited to OUs where security descriptors are readable by current user")
        
        if all_createchild_users:
            print(f"\n[+] Found {len(all_createchild_users)} CreateChild permission(s) across all OUs:")
            
            # Group by OU for better readability
            ous_with_perms = {}
            for user in all_createchild_users:
                ou = user["ou"]
                if ou not in ous_with_perms:
                    ous_with_perms[ou] = []
                ous_with_perms[ou].append(user)
            
            for ou in sorted(ous_with_perms.keys()):
                print(f"\n  OU: {ou}")
                for user in sorted(ous_with_perms[ou], key=lambda x: x["identity"]):
                    print(f"    {user['identity']} ({user['permission']})")
            
            # Summary by user/group
            print(f"\n[*] Summary by Identity:")
            identity_summary = {}
            for user in all_createchild_users:
                identity = user["identity"]
                if identity not in identity_summary:
                    identity_summary[identity] = {"count": 0, "has_generic_all": False}
                identity_summary[identity]["count"] += 1
                if user["permission"] == "GenericAll":
                    identity_summary[identity]["has_generic_all"] = True
            
            for identity in sorted(identity_summary.keys()):
                count = identity_summary[identity]["count"]
                has_generic_all = identity_summary[identity]["has_generic_all"]
                marker = " (GenericAll)" if has_generic_all else ""
                print(f"  {identity}: {count} OU(s){marker}")
        else:
            print(f"\n[-] No users or groups found with CreateChild permissions on any OUs in {args.domain}")
    
    else:
        # Specific user check mode (original functionality)
        print(f"\n[*] Checking CreateChild permissions for {args.username} on {len(conn.entries)} OU(s)...")
        
        creatable_ous = []
        checked_ous = []
        ou_count = 0
        
        for entry in conn.entries:
            ou_dn = str(entry.distinguishedName)
            checked_ous.append(ou_dn)
            ou_count += 1
            
            print(f"  [{ou_count}/{len(conn.entries)}] Checking: {ou_dn}")
            debug(f"Processing OU: {ou_dn}")
            
            # Check if nTSecurityDescriptor is present and has data
            if "nTSecurityDescriptor" not in entry or not entry["nTSecurityDescriptor"].raw_values:
                debug(f"WARNING: No security descriptor available for {ou_dn} - skipping")
                continue
                
            sd_bytes = entry["nTSecurityDescriptor"].raw_values[0]
            debug(f"Security descriptor length: {len(sd_bytes)} bytes")
            
            if ou_allows_create_child(sd_bytes, principal_sids):
                debug(f"Create‑Child allowed on {ou_dn}")
                print(f"    Access GRANTED")
                creatable_ous.append(ou_dn)

        # Print results for specific user
        print(f"\n[*] Completed checking {len(checked_ous)} OU(s) in {args.domain}")
        
        if creatable_ous:
            print(f"\n[+] User '{args.username}' has Create-Child permission on {len(creatable_ous)} OU(s):")
            for ou in sorted(creatable_ous):
                print(f"    {ou}")
        else:
            print(f"\n[-] User '{args.username}' does NOT have Create-Child permission on any OUs in {args.domain}")

    conn.unbind()


if __name__ == "__main__":
    main()
