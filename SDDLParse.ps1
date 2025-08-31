using namespace System.Security.AccessControl
using namespace System.Security.Principal
using namespace System.DirectoryServices
using namespace System.Collections.Generic

class SDDLPermission {
    [string]$Code
    [int]$Value
    [string]$Name
    [string]$Description

    SDDLPermission([string]$code, [int]$value, [string]$name, [string]$description) {
        $this.Code = $code
        $this.Value = $value
        $this.Name = $name
        $this.Description = $description
    }
}

class SDDLRights {
    static [hashtable] $Permissions = @{
        # Generic Rights
        'GA' = [SDDLPermission]::new('GA', 0x10000000, 'Generic All', 'Full control over the object')
        'GR' = [SDDLPermission]::new('GR', 0x20000000, 'Generic Read', 'Read access to the object')
        'GW' = [SDDLPermission]::new('GW', 0x40000000, 'Generic Write', 'Write access to the object')
        'GX' = [SDDLPermission]::new('GX', 0x80000000, 'Generic Execute', 'Execute access to the object')
        # Standard Rights
        'RC' = [SDDLPermission]::new('RC', 0x00020000, 'Read Control', 'Read security descriptor and ownership')
        'SD' = [SDDLPermission]::new('SD', 0x00040000, 'Delete', 'Delete the object')
        'WD' = [SDDLPermission]::new('WD', 0x00080000, 'Write DAC', 'Modify the security descriptor')
        'WO' = [SDDLPermission]::new('WO', 0x00100000, 'Write Owner', 'Take ownership of the object')
        # Directory Service Rights
        'RP' = [SDDLPermission]::new('RP', 0x00000010, 'Read Property', 'Read property values')
        'WP' = [SDDLPermission]::new('WP', 0x00000020, 'Write Property', 'Modify property values')
        'CC' = [SDDLPermission]::new('CC', 0x00000001, 'Create Child', 'Create child objects')
        'DC' = [SDDLPermission]::new('DC', 0x00000002, 'Delete Child', 'Delete child objects')
        'LC' = [SDDLPermission]::new('LC', 0x00000004, 'List Children', 'List child objects')
        'SW' = [SDDLPermission]::new('SW', 0x00000008, 'Self Write', 'Modify own properties')
        'LO' = [SDDLPermission]::new('LO', 0x00000080, 'List Object', 'List object in directory')
        'DT' = [SDDLPermission]::new('DT', 0x00000040, 'Delete Tree', 'Delete a tree of objects')
        'CR' = [SDDLPermission]::new('CR', 0x00000100, 'Control Access', 'Extended access right')
        # Special Rights
        'FA' = [SDDLPermission]::new('FA', 0x1f01ff, 'File All Access', 'Full control over files/folders')
        'FX' = [SDDLPermission]::new('FX', 0x1200a0, 'File Execute', 'Execute access to files')
        'FW' = [SDDLPermission]::new('FW', 0x1301bf, 'File Write', 'Write access to files')
        'FR' = [SDDLPermission]::new('FR', 0x120089, 'File Read', 'Read access to files')
        'KA' = [SDDLPermission]::new('KA', 0x1f0000, 'Key All Access', 'Full control over registry keys')
        'KR' = [SDDLPermission]::new('KR', 0x20019, 'Key Read', 'Read access to registry keys')
        'KW' = [SDDLPermission]::new('KW', 0x20006, 'Key Write', 'Write access to registry keys')
        'KX' = [SDDLPermission]::new('KX', 0x20019, 'Key Execute', 'Execute access to registry keys')
    }

    static [int] ResolveRights([string]$rightString) {
        if ($rightString -match '^0x') {
            return [Convert]::ToInt32($rightString.Substring(2), 16)
        }
        if ($rightString -match '^\d+$') {
            return [Convert]::ToInt32($rightString)
        }
        
        # Handle composite rights strings by breaking them into individual codes
        $totalRights = 0
        if ($rightString.Length % 2 -eq 0) {
            for ($i = 0; $i -lt $rightString.Length; $i += 2) {
                $code = $rightString.Substring($i, 2)
                if ([SDDLRights]::Permissions.ContainsKey($code)) {
                    $totalRights = $totalRights -bor [SDDLRights]::Permissions[$code].Value
                }
            }
            if ($totalRights -ne 0) {
                return $totalRights
            }
        }
        
        # Single right code
        if ([SDDLRights]::Permissions.ContainsKey($rightString)) {
            return [SDDLRights]::Permissions[$rightString].Value
        }
        
        return 0
    }

    static [string[]] GetRightsFromMask([int]$mask) {
        $rights = @()
        foreach ($permission in [SDDLRights]::Permissions.Values) {
            if (($mask -band $permission.Value) -eq $permission.Value) {
                $rights += $permission.Name
            }
        }
        return $rights.Count -gt 0 ? $rights : @('None')
    }
}

$script:ADGuidMap = [ordered]@{
    # Account and User rights
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    '280f369c-67c7-438e-ae98-1d46f3c6f541' = 'User-Change-Password'
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' = 'Enable-Per-User-Reversibly-Encrypted-Password'

    # Certificate Rights
    '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Certificate-AutoEnrollment'
    
    # FSMO Role Rights
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' = 'Change-PDC'
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Infrastructure-Master'
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' = 'Change-Rid-Master'
    'bae50096-4752-11d1-9052-00c04fc2d4cf' = 'Change-Domain-Master'
    'ee914b82-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Schema-Master'
    
    # Schema Rights
    '5fd42471-1262-11d0-a060-00aa006c33ed' = 'Update-Schema'
    '9b026da6-0d3c-465c-8bee-5199d7165cba' = 'Validate-Schema'
    
    # Schema Attributes
    'bf967a68-0de6-11d0-a285-00aa003049e2' = 'Account-Name'
    'bf967953-0de6-11d0-a285-00aa003049e2' = 'Object-Class'
    'bf967954-0de6-11d0-a285-00aa003049e2' = 'Object-Category'
    'bf967961-0de6-11d0-a285-00aa003049e2' = 'Account-Expires'
    'bf967a7a-0de6-11d0-a285-00aa003049e2' = 'Search-Flags'
    'bf967991-0de6-11d0-a285-00aa003049e2' = 'Display-Name'
    'bf967a06-0de6-11d0-a285-00aa003049e2' = 'Common-Name'
    'bf967950-0de6-11d0-a285-00aa003049e2' = 'Sam-Account-Name'
    'bf967a0a-0de6-11d0-a285-00aa003049e2' = 'Description'
    'bf967a7f-0de6-11d0-a285-00aa003049e2' = 'User-Account-Control'
    'bf967a9a-0de6-11d0-a285-00aa003049e2' = 'Security-Descriptor'
    'bf967aa5-0de6-11d0-a285-00aa003049e2' = 'Object-Category'
    'bf96799f-0de6-11d0-a285-00aa003049e2' = 'Member'
    'bf967959-0de6-11d0-a285-00aa003049e2' = 'Primary-Group-ID'
    'bf967a6d-0de6-11d0-a285-00aa003049e2' = 'Password-Last-Set'
    'bf967aba-0de6-11d0-a285-00aa003049e2' = 'User-Object'
    'bf967a9c-0de6-11d0-a285-00aa003049e2' = 'Group-Object'
    'bf967a86-0de6-11d0-a285-00aa003049e2' = 'Computer-Object'

    # Replication Rights
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'DS-Replication-Get-Changes'
    'ab721a54-1e2f-11d0-9819-00aa0040529b' = 'DS-Replication-Synchronize'
    'ab721a56-1e2f-11d0-9819-00aa0040529b' = 'DS-Replication-Get-Changes-All'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All-In-Filtered-Set'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Monitor-Topology'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Check-Topology'
    '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
    '62dd28a8-7f46-11d2-b9ad-00c04f79f805' = 'DS-Query-Self-Quota'
    'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96' = 'DS-Replication-Synchronize-All'
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' = 'DS-Replication-Get-Changes-In-Filtered-Set-Extension'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set-Extension'
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f' = 'DS-Replication-Manage-Topology-Extension'

    # Additional Rights
    '4828cc14-1437-45bc-9b07-ad6f015e5f28' = 'msDS-PasswordSettings'
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' = 'SAM-Enumerate-Entire-Domain'
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Planning'
    'f0f8ffac-1191-11d0-a060-00aa006c33ed' = 'Read-Only-Replication-Secret-Synchronization'
    'f0f8ff9a-1191-11d0-a060-00aa006c33ed' = 'Token-Groups'
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Validated-DNS-Host-Name'
    'c7407360-20bf-11d0-a768-00aa006e0529' = 'Domain-Password-And-Lockout-Policies'
    '00fbf30c-91fe-11d1-aebc-0000f80367c1' = 'DNS-Host-Name'
    '018849b0-a981-11d2-a9ff-00c04f8eedd8' = 'ms-DS-Non-Security-Group-Extra-Classes'
    '0296c120-40da-11d1-a9c0-0000f80367c1' = 'ms-DS-Machine-Account-Quota'
    '037088f8-0ae1-11d2-b422-00a0c968f939' = 'Last-Logon'
    '19195a5b-6da0-11d0-afd3-00c04fd930c9' = 'Domain-DNS'
    '1f298a89-de98-47b8-b5cd-572ad53d267e' = 'Extended-Attributes'
    '2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e' = 'ms-DS-Property-Settings'
    '275b2f54-982d-4dcd-b0ad-e53501445efb' = 'DS-Core-Propagation-Data'
    '28630ebc-41d5-11d1-a9c1-0000f80367c1' = 'Attribute-Syntax'
    '28630ebf-41d5-11d1-a9c1-0000f80367c1' = 'Attribute-ID'
    '2cc06e9d-6f7e-426a-8825-0215de176e11' = 'ms-DS-Object-Reference-BL'
    '3263e3b8-fd6b-4c60-87f2-34bdaa9d69eb' = 'ms-DS-Integer-Settings'
    '3e0abfd0-126a-11d0-a060-00aa006c33ed' = 'USN-Changed'
    '3e74f60e-3e73-11d1-a9c0-0000f80367c1' = 'Description-Extended'
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'ms-DS-Resource-Properties'
    '46a9b11d-60ae-405a-b7e8-ff8a58d456d2' = 'Token-Groups-No-GC-Acceptable'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'Group-Membership'
    '5430e777-c3ea-4024-902e-dde192204669' = 'ms-DS-Security-Group-Extra-Classes'
    '5805bc62-bdc9-4428-a5e2-856a0f4c185e' = 'Terminal-Server-License-Server'
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf' = 'General-Information'
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'System-Only'
    '5cb41ed0-0e4c-11d0-a286-00aa003049e2' = 'Organizational-Unit'
    '5df2b673-6d41-4774-b3e8-d52e8ee9ff99' = 'ms-DS-Security-Settings'
    '5e353847-f36c-48be-a7f7-49685402503c' = 'Runtime-Connection-Settings'
    '5f202010-79a5-11d0-9020-00c04fc2d4cf' = 'Lockout-Time'
    '5fd424a1-1262-11d0-a060-00aa006c33ed' = 'Password-Last-Changed'
    '614aea82-abc6-4dd0-a148-d67a59c72816' = 'ms-DS-Auxiliary-Classes'
    '66437984-c3c5-498f-b269-987819ef484b' = 'Schema-Flags-Ex'
    '6db69a1c-9422-11d1-aebd-0000f80367c1' = 'Terminal-Server-License'
    '6f606079-3a82-4c1b-8efb-dcc8c91d26fe' = 'Attribute-Security-GUID'
    '72e39547-7b18-11d1-adef-00c04fd8d5cd' = 'DNS-Host-Name-Attributes'
    '77b5b886-944a-11d1-aebd-0000f80367c1' = 'Service-Principal-Name'
    '7cb4c7d3-8787-42b0-b438-3c5d479ad31e' = 'ms-DS-Schema-Extensions'
    '8d3bca50-1d7e-11d0-a081-00aa006c33ed' = 'System-Flags'
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8' = 'ms-DS-Resource-Property-List'
    '934de926-b09e-11d2-aa06-00c04f8eedd8' = 'Schema-ID-GUID'
    '9a7ad945-ca53-11d1-bbd0-0080c76670c0' = 'Friendly-Names' 
    '9a9a021e-4a5b-11d1-a9c3-0000f80367c1' = 'RDN-Reference-Update'
    'a1990816-4298-11d1-ade2-00c04fd8d5cd' = 'Open-Address-Book'
    'a673a21e-e65e-43a6-ac59-7e4bfdeb9fb8' = 'ACL-Revision'
    'a8df7489-c5ea-11d1-bbcb-0080c76670c0' = 'Domain-Component'
    'b1b3a417-ec55-4191-b327-b72e33e38af2' = 'Country-Code'
    'b7c69e6d-2cc7-11d2-854e-00a0c983f608' = 'Directory-Service-Reference'
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Bad-Password-Time'
    'bf96791a-0de6-11d0-a285-00aa003049e2' = 'Additional-Information'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Managed-By'
    'c975c901-6cea-4b6f-8319-d67f45449506' = 'ms-DS-Schema-Extensions-GUID'
    'e45795b2-9455-11d1-aebd-0000f80367c1' = 'Phone-Number'
    'e45795b3-9455-11d1-aebd-0000f80367c1' = 'Other-Parameters'
    'e48d0154-bcf8-11d1-8702-00c04fb96050' = 'Public-Information'
    'e8b2aff2-59a7-4eac-9a70-819adef701dd' = 'ms-DS-Members-Of-Resource-Properties-BL'
    'ea1b7b93-5e48-46d5-bc6c-4df4fda78a35' = 'ms-DS-Filtered-Attributes'
    'f30e3bc2-9ff0-11d1-b603-0000f80367c1' = 'Group-Policy-Container'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'ms-DS-Supported-Encryption-Types'
}
 
$script:WellKnownPrincipals = [ordered]@{

    # Domain SIDs (S-1-5-21-domain-) endings
    '498'         = 'Enterprise Read-only Domain Controllers'
    '500'         = 'Administrator'
    '501'         = 'Guest'
    '502'         = 'KRBTGT'
    '512'         = 'Domain Admins'
    '513'         = 'Domain Users'
    '514'         = 'Domain Guests'
    '515'         = 'Domain Computers'
    '516'         = 'Domain Controllers'
    '517'         = 'Cert Publishers'
    '518'         = 'Schema Admins'
    '519'         = 'Enterprise Admins'
    '520'         = 'Group Policy Creator Owners'
    '521'         = 'Read-only Domain Controllers'
    '522'         = 'Cloneable Domain Controllers'
    '525'         = 'Protected Users'
    '526'         = 'Key Admins'
    '527'         = 'Enterprise Key Admins'
    '553'         = 'RAS and IAS Servers'
    '571'         = 'Allowed RODC Password Replication Group'
    '572'         = 'Denied RODC Password Replication Group'
    
    # Well Known SIDs
    'S-1-0'        = 'Null Authority'
    'S-1-0-0'      = 'Nobody'
    'S-1-1'        = 'World Authority'
    'S-1-1-0'      = 'Everyone'
    'S-1-2'        = 'Local Authority'
    'S-1-2-0'      = 'Local'
    'S-1-2-1'      = 'Console Logon'
    'S-1-3'        = 'Creator Authority'
    'S-1-3-0'      = 'Creator Owner'
    'S-1-3-1'      = 'Creator Group'
    'S-1-3-2'      = 'Creator Owner Server'
    'S-1-3-3'      = 'Creator Group Server'
    'S-1-3-4'      = 'Owner Rights'
    'S-1-4'        = 'Non-unique Authority'
    'S-1-5'        = 'NT Authority'
    'S-1-5-1'      = 'Dialup'
    'S-1-5-2'      = 'Network'
    'S-1-5-3'      = 'Batch'
    'S-1-5-4'      = 'Interactive'
    'S-1-5-6'      = 'Service'
    'S-1-5-7'      = 'Anonymous'
    'S-1-5-8'      = 'Proxy'
    'S-1-5-9'      = 'Enterprise Domain Controllers'
    'S-1-5-10'     = 'Principal Self'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-12'     = 'Restricted Code'
    'S-1-5-13'     = 'Terminal Server Users'
    'S-1-5-14'     = 'Remote Interactive Logon'
    'S-1-5-15'     = 'This Organization'
    'S-1-5-17'     = 'IUSR'
    'S-1-5-18'     = 'Local System'
    'S-1-5-19'     = 'NT Authority\Local Service'
    'S-1-5-20'     = 'NT Authority\Network Service'
    
    # Built-in Groups
    'S-1-5-32-544' = 'Builtin\Administrators'
    'S-1-5-32-545' = 'Builtin\Users'
    'S-1-5-32-546' = 'Builtin\Guests'
    'S-1-5-32-547' = 'Builtin\Power Users'
    'S-1-5-32-548' = 'Builtin\Account Operators'
    'S-1-5-32-549' = 'Builtin\Server Operators'
    'S-1-5-32-550' = 'Builtin\Print Operators'
    'S-1-5-32-551' = 'Builtin\Backup Operators'
    'S-1-5-32-552' = 'Builtin\Replicators'
    'S-1-5-32-554' = 'Builtin\Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'Builtin\Remote Desktop Users'
    'S-1-5-32-556' = 'Builtin\Network Configuration Operators'
    'S-1-5-32-557' = 'Builtin\Incoming Forest Trust Builders'
    'S-1-5-32-558' = 'Builtin\Performance Monitor Users'
    'S-1-5-32-559' = 'Builtin\Performance Log Users'
    'S-1-5-32-560' = 'Builtin\Windows Authorization Access Group'
    'S-1-5-32-561' = 'Builtin\Terminal Server License Servers'
    'S-1-5-32-562' = 'Builtin\Distributed COM Users'
    'S-1-5-32-568' = 'Builtin\IIS_IUSRS'
    'S-1-5-32-569' = 'Builtin\Cryptographic Operators'
    'S-1-5-32-573' = 'Builtin\Event Log Readers'
    'S-1-5-32-574' = 'Builtin\Certificate Service DCOM Access'
    'S-1-5-32-575' = 'Builtin\RDS Remote Access Servers'
    'S-1-5-32-576' = 'Builtin\RDS Endpoint Servers'
    'S-1-5-32-577' = 'Builtin\RDS Management Servers'
    'S-1-5-32-578' = 'Builtin\Hyper-V Administrators'
    'S-1-5-32-579' = 'Builtin\Access Control Assistance Operators'
    'S-1-5-32-580' = 'Builtin\Remote Management Users'
        
    # Service SIDs
    'S-1-5-64-10'  = 'NTLM Authentication'
    'S-1-5-64-14'  = 'SChannel Authentication'
    'S-1-5-64-21'  = 'Digest Authentication'
    'S-1-5-80'     = 'NT Service'
    'S-1-5-80-0'   = 'All Services'
    'S-1-5-83-0'   = 'NT VIRTUAL MACHINE\Virtual Machines'
    
    # Integrity Levels
    'S-1-16-0'     = 'Untrusted Mandatory Level'
    'S-1-16-4096'  = 'Low Mandatory Level'
    'S-1-16-8192'  = 'Medium Mandatory Level'
    'S-1-16-8448'  = 'Medium Plus Mandatory Level'
    'S-1-16-12288' = 'High Mandatory Level'
    'S-1-16-16384' = 'System Mandatory Level'
    'S-1-16-20480' = 'Protected Process Mandatory Level'
    'S-1-16-28672' = 'Secure Process Mandatory Level'

    # Two letter codes
    'AN'           = 'Anonymous'
    'AO'           = 'Account Operators'
    'AU'           = 'Authenticated Users'
    'BA'           = 'Built-in Administrators'
    'BG'           = 'Built-in Guests'
    'BO'           = 'Backup Operators'
    'BU'           = 'Built-in Users'
    'CA'           = 'Certificate Publishers'
    'CD'           = 'Users/Computers with Certificates'
    'CG'           = 'Creator Group'
    'CO'           = 'Creator Owner'
    'DA'           = 'Domain Admins'
    'DC'           = 'Domain Controllers'
    'DD'           = 'Domain Computers'
    'DG'           = 'Domain Guests'
    'DU'           = 'Domain Users'
    'EA'           = 'Enterprise Admins'
    'ED'           = 'Enterprise Domain Controllers'
    'HI'           = 'High Integrity Level'
    'IU'           = 'Interactively Logged-on User'
    'LA'           = 'Local Administrator'
    'LG'           = 'Local Guest'
    'LS'           = 'Local Service'
    'LW'           = 'Low Integrity Level'
    'ME'           = 'Medium Integrity Level'
    'MU'           = 'Performance Monitor Users'
    'NO'           = 'Network Configuration Operators'
    'NS'           = 'Network Service'
    'NU'           = 'Network Logon User'
    'PA'           = 'Group Policy Administrators'
    'PO'           = 'Printer Operators'
    'PS'           = 'Principal Self'
    'PU'           = 'Power Users'
    'RC'           = 'Restricted Code'
    'RD'           = 'Remote Desktop Users'
    'RE'           = 'Replicator'
    'RO'           = 'Enterprise Read-only Domain Controllers'
    'RS'           = 'RAS and IAS Servers'
    'RU'           = 'Pre-Windows 2000 Compatible Access'
    'SA'           = 'Schema Administrators'
    'SI'           = 'System Integrity Level'
    'SO'           = 'Server Operators'
    'SU'           = 'Service Logon User'
    'SY'           = 'Local System'
    'WD'           = 'Everyone'
}

class ACEParser {
    static [hashtable] ParseACE([string]$ace) {
        $ace = $ace.Trim('(', ')')
        $parts = $ace.Split(';')
        
        return @{
            AceType             = $parts[0]
            AceFlags            = $parts[1]
            Rights              = [SDDLRights]::ResolveRights($parts[2])
            ObjectType          = $parts[3]
            InheritedObjectType = $parts[4]
            Sid                 = $parts[5]
        }
    }
 
    static [string] ParseRights([int]$accessMask) {
        $rights = @()
        foreach ($permission in [SDDLRights]::Permissions.Values) {
            if (($accessMask -band $permission.Value) -eq $permission.Value) {
                $rights += $permission.Name
            }
        }
        return $rights.Count -gt 0 ? ($rights -join ', ') : 'None'
    }
 
    static [string] ResolvePrincipal([string]$identifier) {
        # For two letter codes, match exact
        if ($script:WellKnownPrincipals.Keys -contains $identifier) {
            return $script:WellKnownPrincipals[$identifier]
        }
     
        # For SIDs
        if ($identifier -match '^S-\d+-') {
            
            # Match exact full SID 
            $exactMatch = $script:WellKnownPrincipals.Keys.Where({$_ -eq $identifier}, 'First')
            if ($exactMatch) {
                return $script:WellKnownPrincipals[$exactMatch[0]]
            }
     
            # Match domain SID ending
            if ($identifier -match '^S-1-5-21-[\d-]+-(\d+)$') {
                $rid = $matches[1]
                
                # Just match RID number
                $matchingRid = $script:WellKnownPrincipals.Keys.Where({$_ -eq $rid}, 'First')
                if ($matchingRid) {
                    return "Domain $($script:WellKnownPrincipals[$matchingRid[0]])"
                }
            }
     
            try {
                $sid = [SecurityIdentifier]::new($identifier)
                return $sid.Translate([NTAccount]).Value
            }
            catch {
                return $identifier
            }
        }
     
        return $identifier
     }
 
    static [string] ResolveGuid([string]$guid) {
        if ([string]::IsNullOrEmpty($guid)) { return 'All' }
        return ($script:ADGuidMap.Keys -contains $guid) ? $script:ADGuidMap[$guid] : $guid
    }
}

class SDDLAccessEntry {
    [string]$Identity
    [string]$AccessType
    [string]$Rights
    [string]$ObjectType
    [string]$InheritedObjectType
    [string]$PropertyGuid
    [string]$InheritanceFlags
    [bool]$IsInherited

    SDDLAccessEntry([hashtable]$aceData) {
        $this.Identity = [ACEParser]::ResolvePrincipal($aceData.Sid)
        $this.AccessType = ($aceData.AceType -match '^(A|OA)$') ? 'Allow' : 'Deny'
        $this.Rights = [ACEParser]::ParseRights($aceData.Rights)
        $this.ObjectType = [ACEParser]::ResolveGuid($aceData.ObjectType)
        $this.InheritedObjectType = [ACEParser]::ResolveGuid($aceData.InheritedObjectType)
        
        if ($aceData.Rights -band 0x30) {
            $this.PropertyGuid = "Property($($this.ObjectType))"
        }
        
        $this.InheritanceFlags = $this.ParseInheritanceFlags($aceData.AceFlags)
        $this.IsInherited = $aceData.AceFlags -match 'ID'
    }

    hidden [string] ParseInheritanceFlags([string]$flagString) {
        $inheritFlags = @()
        if ($flagString -match 'CI') { $inheritFlags += 'ContainerInherit' }
        if ($flagString -match 'OI') { $inheritFlags += 'ObjectInherit' }
        if ($flagString -match 'NP') { $inheritFlags += 'NoPropagateInherit' }
        if ($flagString -match 'IO') { $inheritFlags += 'InheritOnly' }
        return $inheritFlags.Count -gt 0 ? ($inheritFlags -join ', ') : 'None'
    }

    [string] ToString() {
        $output = [System.Text.StringBuilder]::new()
        $output.AppendLine("Identity: $($this.Identity)")
        $output.AppendLine("Access Type: $($this.AccessType)")
        $output.AppendLine("Rights: $($this.Rights)")
        $output.AppendLine("Object Type: $($this.ObjectType)")
        if ($this.PropertyGuid) { $output.AppendLine("Property GUID: $($this.PropertyGuid)") }
        $output.AppendLine("Inherited Object Type: $($this.InheritedObjectType)")
        $output.AppendLine("Inheritance Flags: $($this.InheritanceFlags)")
        $output.AppendLine("Is Inherited: $($this.IsInherited)")
        return $output.ToString()
    }
}

class SDDLDescriptor {
    [string]$Owner
    [string]$Group
    [SDDLAccessEntry[]]$AccessRules
    [string]$RawSDDL

    SDDLDescriptor([string]$sddl) {
        $this.RawSDDL = $sddl
        $sd = [RawSecurityDescriptor]::new($sddl)
        
        $this.Owner = [ACEParser]::ResolvePrincipal($sd.Owner.Value)
        $this.Group = [ACEParser]::ResolvePrincipal($sd.Group.Value)
        
        $aceRegex = '\([^\)]+\)'
        $this.AccessRules = @([regex]::Matches($sddl, $aceRegex).ForEach{
                [SDDLAccessEntry]::new([ACEParser]::ParseACE($_.Value))
            })
    }

    [string] ToString() {
        $output = [System.Text.StringBuilder]::new()
        $output.AppendLine("Owner: $($this.Owner)")
        $output.AppendLine("Group: $($this.Group)")
        $output.AppendLine('Access Rules:')
        foreach ($rule in $this.AccessRules) {
            $output.AppendLine($rule.ToString())
            $output.AppendLine()
        }
        return $output.ToString()
    }
}

function Convert-SDDLToFriendlyAccess {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$SDDL
    )
    
    process {
        try {
            [SDDLDescriptor]::new($SDDL)
        }
        catch {
            Write-Error "Failed to parse SDDL: $_"
        }
    }
}
