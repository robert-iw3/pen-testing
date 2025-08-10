# RECON-1

## Description
Enumerate SCCM site information via LDAP

## MITRE ATT&CK TTPs
- [TA0007](https://attack.mitre.org/tactics/TA0007/) - Discovery

## Requirements
- Valid Active Directory domain credentials

## Summary
When designing a SCCM hierarchy, an optional, however very common, configuration step is to configure Active Directory for publishing SCCM information. This process involves [extending](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/network/schema-extensions) the Active Directory (AD) schema to include new attributes and classes. The `System Management` container is added within the `System` container and is used to house all data published to the domain. SCCM publishes information for clients such as providing a record to query for the client's default management point for DNS resolution.

The following attributes and classes are added to the schema:

| Attributes | Classes |
|----------|-------------|
|cn=mS-SMS-Assignment-Site-Code| cn=MS-SMS-Management-Point|
|cn=mS-SMS-Capabilities| cn=MS-SMS-Roaming-Boundary-Range
|cn=MS-SMS-Default-MP|cn=MS-SMS-Server-Locator-Point
|cn=mS-SMS-Device-Management-Point|cn=MS-SMS-Site
|cn=mS-SMS-Health-State|
|cn=MS-SMS-MP-Address|
|cn=MS-SMS-MP-Name|
|cn=MS-SMS-Ranged-IP-High|
|cn=MS-SMS-Ranged-IP-Low|
|cn=MS-SMS-Roaming-Boundaries|
|cn=MS-SMS-Site-Boundaries|
|cn=MS-SMS-Site-Code|
|cn=mS-SMS-Source-Forest|
|cn=mS-SMS-Version

While not every site system role is published to AD, there is still plenty of information to be gathered to identify infrastructure.

### System Management Container
First, the existence of the manually created `System Management` container indicates SCCM is, or was, installed in the domain. Second, to allow SCCM to publish site data to the  container,  all site servers in the domain are required to have Full Control permissions for the container. Querying for the container itself and then resolving the principals granted Full Control permissions can identify potential site servers.

### cn=MS-SMS-Site
For each individual site published to AD, an `mSSMSSite` class is published. This class provides the opportunity to identify how many individual sites may be published to a domain using the following attributes:

|Attribute| Notes|
|---------|------|
|mSSMSSiteCode|Each site's unique three character site code|
|mSSMSSourceForest| The originating forest for the site|


### cn=MS-SMS-Management-Point
The `mSMSManagementPoint` class is used by SCCM to publish details for SCCM clients to identify their respective default management point (MP) `(cn=MS-SMS-Management-Point)`. This class provides the opportunity to identify potential attack paths using the following attributes:

|Attribute|Notes|
|---------|-----|
|dNSHostName|The DNS hostanme for the MP's host operating system|
|msSMSSiteCode|The site the MP is a member of|


### Predictable Naming Conventions
At SpecterOps, we frequently observe predictable naming conventions in use to help system administrators identify and organize SCCM-related assets. We've observed security groups, organizational units, usernames, and group policy objects using strings such as "SCCM" or "MECM" to identify their purpose. Consequently, a broader, recursive search for principals that contain these strings can help identify site system roles that are not published to AD via extension of the schema. In some cases, we have observed the specific role for the user group or site system included in the hostname. For example:

- "sccmadmins" for a security group that contained all SCCM administrative users
- "sccm site servers" for a security group that contained all SCCM site systems in the domain
- "SCCMDP1" for a SCCM site system configured with the distribution point role

## Examples

### Management Points
Use `pyldapsearch` to query for published `mSMSManagementPoint` class objects


```
└─# poetry run pyldapsearch internal.lab/administrator:"<password>" "(objectclass=mssmsmanagementpoint)"  -attributes dnshostname,msSMSSiteCode
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] pyldapsearch v0.1.2 - @Tw1sm

[*] Binding to internal.lab
[*] Distinguished name: DC=internal,DC=lab
[*] Filter: (objectclass=mssmsmanagementpoint)
[*] Returning specific attributes(s): dnshostname,msSMSSiteCode
--------------------
dNSHostName: mp2.internal.lab
mSSMSSiteCode: ABC
--------------------
dNSHostName: mp.internal.lab
mSSMSSiteCode: LAB
--------------------
dNSHostName: sccm.internal.lab
mSSMSSiteCode: LAB
--------------------
dNSHostName: sccm2.internal.lab
mSSMSSiteCode: ABC
--------------------
dNSHostName: active.internal.lab
mSSMSSiteCode: ACT

[*] Retrieved 5 results total

```

## Impact
1. Identifying the presence of site servers and site systems is typically the first step in building potential attack paths
2. A resolved MP site system role can be abused to spoof SCCM client enrollment and potentially recover credentials ([CRED-2](../../CRED/CRED-2/cred-2_description.md))
3. A resolved MP site system role can be used to elevate privileges via credential relay attacks ([ELEVATE-1](../../ELEVATE/ELEVATE-1/ELEVATE-1_description.md))
4. All SCCM sites require at least one MP role except for central administration sites (CAS), which [do not](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/design-a-hierarchy-of-sites#BKMK_ChooseCAS) support roles that interact with clients. However, the CAS site code is still published via the `mSSMSSite` class. Additionally, the CAS primary site server requires Full Control for the `System Management` container for publishing purposes. Therefore, a query for all published site codes in a domain can be used to identify the CAS primary site server by elimintating site codes that have a published MP. Knowlege of the CAS can be used to perform credential relay attacks to elevate privileges in the domain or SCCM hierarchy (see TAKEOVERs 1-8).
5. Predictble naming conventions help identify high value targets associated with the SCCM hierarchy.

## Defensive IDs
- [DETECT-2: Monitor read access to the `System Management` Active Directory container](../../../defense-techniques/DETECT/DETECT-2/detect-2_description.md)

## Examples


## References
Garrett Foster, [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)

Matt Creel, [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)
