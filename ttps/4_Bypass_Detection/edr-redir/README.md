### EDR-Redir

EDR-Redir uses a **Bind Filter (mini filter bindflt.sys)** to redirect the Endpoint Detection and Response (EDR) 's working folder to a folder of the attacker's choice.
Alternatively, it can make the folder appear corrupt to prevent the EDR's process services from functioning.

### Command Line Syntax

**EDR-Redir.exe bind `<VirtualPath`> `<BackingPath`>**

_To create bind link from VirtualPath to BackingPath_

**EDR-Redir.exe bind `<VirtualPath`> `<BackingPath`> `<ExceptionPath`>**

_Powerfull mode to create bind link from VirtualPath to BackingPath. Exclude ExceptionPath_

_ExceptionPath often is Antivirus/EDR path. Use this mode when you want to redirect folder like **Program Files, Program Files (x86),...**_

**EDR-Redir.exe bind `<VirtualPath`>**

_To remove a link that was previously created_


### Some EDR/Antivirus have been successfully tested

- Microsoft Windows Defender
- Elastic Defend
- Sophos Intercept X
- ...