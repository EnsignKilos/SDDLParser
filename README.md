# SDDL Parser for Active Directory

PowerShell module for parsing and interpreting Security Descriptor Definition Language (SDDL) strings into human-readable security information.

## 📋 Prerequisites

- PowerShell 5.1 or PowerShell Core 7+
- Windows environment (uses .NET Security classes)
- Read access to Active Directory (for SID resolution)

## 🚀 Installation

```powershell
# Import the module
Import-Module .\SDDLParser.psm1

# Or dot-source the script
. .\SDDLParser.ps1
```

## 📖 Usage

### Basic SDDL Parsing

```powershell
# Parse an SDDL string
$sddl = "O:BAG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)"
$descriptor = Convert-SDDLToFriendlyAccess -SDDL $sddl

# Display the parsed output
$descriptor
```

### Active Directory SDDL

```powershell
# Get SDDL from AD object
$adObject = Get-ADObject "CN=AdminSDHolder,CN=System,DC=contoso,DC=local" -Properties nTSecurityDescriptor
$sddl = $adObject.nTSecurityDescriptor.GetSecurityDescriptorSddlForm('All')

# Parse the SDDL
$parsed = Convert-SDDLToFriendlyAccess -SDDL $sddl
$parsed.AccessRules | Format-Table
```

### Pipeline Processing

```powershell
# Process multiple SDDL strings
$sddlStrings | Convert-SDDLToFriendlyAccess | Format-List
```

## 🔧 Components

### Primary Function
- `Convert-SDDLToFriendlyAccess` - Main function to parse SDDL strings

### Classes

**SDDLDescriptor**
- Represents complete security descriptor
- Properties: Owner, Group, AccessRules, RawSDDL

**SDDLAccessEntry**
- Individual access control entry
- Properties: Identity, AccessType, Rights, ObjectType, InheritanceFlags

**ACEParser**
- Static methods for parsing ACE components
- Resolves SIDs, GUIDs, and access masks

**SDDLRights**
- Maps permission codes to friendly names
- Resolves composite rights strings

## 🔐 Supported Elements

### Access Rights
| Code | Permission | Description |
|------|------------|-------------|
| GA | Generic All | Full control |
| GR | Generic Read | Read access |
| GW | Generic Write | Write access |
| GX | Generic Execute | Execute access |
| RC | Read Control | Read security descriptor |
| SD | Delete | Delete the object |
| WD | Write DAC | Modify security descriptor |
| WO | Write Owner | Take ownership |

### AD-Specific Rights
| Code | Permission | Description |
|------|------------|-------------|
| RP | Read Property | Read property values |
| WP | Write Property | Modify property values |
| CC | Create Child | Create child objects |
| DC | Delete Child | Delete child objects |
| CR | Control Access | Extended access right |

### Well-Known Principals
- **BA** - Built-in Administrators
- **SY** - Local System
- **AU** - Authenticated Users
- **DA** - Domain Admins
- **EA** - Enterprise Admins
- **DC** - Domain Controllers
- **DU** - Domain Users

## 📊 Examples

### Parse AdminSDHolder SDDL

```powershell
# Typical AdminSDHolder SDDL
$adminSDHolderSDDL = "O:DAG:DAD:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPLOCRSDRCWDWO;;;SY)"

$result = Convert-SDDLToFriendlyAccess -SDDL $adminSDHolderSDDL

# View specific access rules
$result.AccessRules | Where-Object { $_.Identity -eq 'Built-in Administrators' }
```

### Parse GPO Permissions

```powershell
# Get GPO security descriptor
$gpo = Get-GPO -Name "Default Domain Policy"
$sddl = $gpo.GetSecurityInfo().GetSecurityDescriptorSddlForm('All')

# Parse and filter
$parsed = Convert-SDDLToFriendlyAccess -SDDL $sddl
$parsed.AccessRules | Where-Object { $_.AccessType -eq 'Allow' } | 
    Select-Object Identity, Rights, ObjectType
```

### Extract Replication Rights

```powershell
# Parse domain object SDDL for DCSync rights
$domainSDDL = (Get-ADObject -Identity "DC=contoso,DC=local" -Properties nTSecurityDescriptor).nTSecurityDescriptor.GetSecurityDescriptorSddlForm('All')

$parsed = Convert-SDDLToFriendlyAccess -SDDL $domainSDDL
$parsed.AccessRules | Where-Object { 
    $_.Rights -match 'DS-Replication-Get-Changes'
} | Format-Table Identity, Rights, ObjectType
```

## 🗺️ GUID Mappings

The parser includes mappings for common AD GUIDs:

### Replication Rights
- `ab721a53-1e2f-11d0-9819-00aa0040529b` - DS-Replication-Get-Changes
- `ab721a56-1e2f-11d0-9819-00aa0040529b` - DS-Replication-Get-Changes-All
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` - DS-Replication-Get-Changes-In-Filtered-Set

### User Rights
- `00299570-246d-11d0-a768-00aa006e0529` - User-Force-Change-Password
- `280f369c-67c7-438e-ae98-1d46f3c6f541` - User-Change-Password

### Certificate Rights
- `0e10c968-78fb-11d2-90d4-00c04f79dc55` - Certificate-Enrollment
- `a05b8cc2-17bc-4802-a710-e7c15ab866a2` - Certificate-AutoEnrollment

## 🛠️ Advanced Usage

### Custom GUID Resolution

```powershell
# Add custom GUID mappings
$script:ADGuidMap['your-guid-here'] = 'Custom-Permission-Name'

# Parse with custom mapping
Convert-SDDLToFriendlyAccess -SDDL $sddl
```

### Filtering Inherited Rights

```powershell
$parsed = Convert-SDDLToFriendlyAccess -SDDL $sddl

# Show only explicit (non-inherited) permissions
$parsed.AccessRules | Where-Object { -not $_.IsInherited }

# Show only inherited permissions
$parsed.AccessRules | Where-Object { $_.IsInherited }
```

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Failed to parse SDDL" | Verify SDDL string format is valid |
| Unknown SIDs displayed | Ensure running with AD access for SID resolution |
| Missing GUID names | GUID may not be in mapping table - shows raw GUID |
| Access denied errors | Need read access to AD for SID translation |

## 🔒 Security Considerations

- **Read-Only Tool**: This parser only reads and interprets, doesn't modify permissions
- **Sensitive Information**: SDDL reveals security configurations - handle output carefully
- **Audit Usage**: Log analysis activities for compliance
- **Access Control**: Limit who can view security descriptors in production

## ⚖️ Legal Disclaimer

This tool is for authorised security auditing and administration only. Users must comply with all applicable laws and organisational policies.

## 📧 Contact

**GitHub:** [EnsignKilos](https://github.com/EnsignKilos)

---

*Parse responsibly. Audit ethically.*
