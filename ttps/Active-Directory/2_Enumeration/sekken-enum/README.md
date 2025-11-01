# SekkenEnum - Active Directory Enumeration via ADWS

A Beacon Object File (BOF) for Active Directory enumeration through Active Directory Web Services (ADWS) compatible with BOFHound

## Features

- Query AD objects using LDAP filters via ADWS protocol (TCP 9389)
- Automatic DC discovery or specify target DC
- Custom base DN support for querying Configuration, Schema, or other partitions
- Retrieve specific attributes or all attributes
- Automatic pagination for large result sets
- Support for all AD object types (users, computers, groups, PKI objects, trustedDomain, etc.)


## Usage

```
sekken-enum [target] [filter] [attributes] [-b basedn]
```

### Parameters

- `target`: Target domain controller (optional, auto-discovers if omitted)
- `filter`: LDAP filter (default: `(objectClass=*)`)
- `attributes`: Comma-separated list of attributes (default: all attributes)
- `-b basedn`: Custom base DN (optional)

### Examples

```bash
# Auto-discover DC and query users starting with 'admin'
sekken-enum "(samaccountname=admin*)"

# Get specific attributes for all users
sekken-enum dc01.domain.local "(objectclass=user)" "samaccountname,distinguishedname,memberof"

# Get all computer objects
sekken-enum dc01.domain.local "(objectclass=computer)"

# Query ADCS Certificate Templates in Configuration partition
sekken-enum dc01.domain.local "(objectClass=pKICertificateTemplate)" "cn,displayname" -b "CN=Configuration,DC=domain,DC=local"

# Get all trusted domains
sekken-enum dc01.domain.local "(objectclass=trustedDomain)"
```

## Acknowledgments

This BOF was heavily built upon resources and research from [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) and [SoaPy](https://github.com/xforcered/SoaPy).
