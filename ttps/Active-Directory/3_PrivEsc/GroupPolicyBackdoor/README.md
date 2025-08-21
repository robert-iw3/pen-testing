# GroupPolicyBackdoor

**GroupPolicyBackdoor** is a python utility for Group Policy Objects (GPOs) manipulation and exploitation. GPO attack vectors can very often lead to impactful privilege escalation scenarios in Active Directory environments. And yet, offensive security professionals may be reluctant to leverage them, partly due to the perceived risks associated with GPO manipulation.

GroupPolicyBackdoor aims at providing a modular, stable and stealthy exploitation framework for GPO attack vectors, all in python. The tool was presented at [DEFCON 33](https://www.synacktiv.com/sites/default/files/2025-08/roland_becard_turning-your-active-directory-into-the-attackers-c2_slides.pdf).

## Documentation

Usage instructions (quick or detailed) are provided in the repository's **wiki**, which also contains a cheatsheet of copy-paste ready commands:

[![Wiki](https://img.shields.io/badge/📖-Wiki-blue?style=for-the-badge)](https://github.com/synacktiv/GroupPolicyBackdoor/wiki).

## Main features

Here is an overview of GroupPolicyBackdoor main features:

- Python implementation using `ldap3` and `smbprotocol` (no impacket)
- GPO creation, deletion, backup and injections
- Various injectable configurations, with, for each, customizable options (see list in the wiki)
- Possibility to only apply injected configurations to specific objects with **filters** that can be combined (hostname, security group, WMI query - see wiki)
- Possibility to remove injected configurations from the target GPO
- Possibility to revert the actions performed on client devices
- GPO links manipulation
- GPO enumeration / user privileges enumeration on GPOs

## Main subcommands

```
 Usage: gpb.py [OPTIONS] COMMAND [ARGS]...                                                                                                                                                                         
                                                                                                                                                                                                                   
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                                                                                                                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ gpo       All subcommands related to GPO manipulation                                                                                                                                                           │
│ links     All subcommands related to GPO links                                                                                                                                                                  │
│ enum      All subcommands related to GPO and containers enumeration                                                                                                                                             │
│ restore   All subcommands related to exploit safety, allowing to restore the target environment in case anything goes wrong                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Contributing

If you find a bug or if you want to implement additional injectable configurations to extend GroupPolicyBackdoor capabilities, pull requests are welcome!