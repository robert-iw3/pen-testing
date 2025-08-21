from ldap3                      import LEVEL
from rich.console               import Console
from rich.table                 import Table

from gpb.protocols.ldap         import get_entries

from config                     import logger


class GPOLister:

    def __init__(self,
                domain,
                dc,
                ldap_session):

        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.ldap_session = ldap_session
    
    def run(self) -> None:
        attributes = [
            'cn',
            'displayName',
            'whenCreated',
            'whenChanged',
            'versionNumber',
            'gPCMachineExtensionNames',
            'gPCUserExtensionNames'
        ]

        entries = get_entries(
            self.ldap_session,
            f"CN=Policies,CN=System,{self.domain_dn}",
            "(objectclass=groupPolicyContainer)",
            LEVEL,
            attributes)

        table = Table()
        table.add_column("GPO name", justify="left", style="cyan")
        table.add_column("GPO GUID")
        table.add_column("Creation date")
        table.add_column("Last changed")
        table.add_column("Version\n(computer)", justify="right")
        table.add_column("Version\n(user)", justify="right")

        rows = []

        for entry in entries:
            gpo_guid = entry['attributes']['cn'][1:-1]
            display_name = entry['attributes']['displayName']
            when_created = entry['attributes']['whenCreated'].strftime("%m/%d/%Y %H:%M:%S")
            when_changed = entry['attributes']['whenChanged'].strftime("%m/%d/%Y %H:%M:%S")
            version_computer = entry['attributes']['versionNumber'] & 0xFFFF
            version_user = entry['attributes']['versionNumber'] >> 16 & 0xFFFF

            rows.append((display_name, gpo_guid, when_created, when_changed, str(version_computer), str(version_user)))


        rows.sort(key=lambda tup: tup[0])
        for row in rows:
            table.add_row(*row)

        logger.warning("\n")
        console = Console()
        console.print(table)
        logger.warning("\n")
