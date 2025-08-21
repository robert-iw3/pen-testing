import re

from ldap3                      import LEVEL
from rich.panel                 import Panel
from rich.console               import Console, Group, Style
from rich.table                 import Table
from rich.text                  import Text
from rich.tree                  import Tree
from rich.rule                  import Rule

from gpb.protocols.ldap         import get_entry, get_entries, modify_attribute

from config                     import logger, CSE_LIST, LinkOptions, GPBLDAPNoResultsError


class GPODetails:

    def __init__(self,
                domain,
                dc,
                ldap_session,
                gpo_guid,
                check_write):

        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.ldap_session = ldap_session
        self.check_write = check_write
        self.max_recursion = 10
    
    def run(self) -> None:
        attributes = [
            'cn',
            'displayName',
            'description',
            'whenCreated',
            'whenChanged',
            'versionNumber',
            'gPCMachineExtensionNames',
            'gPCUserExtensionNames',
            "gPCFileSysPath",
        ]

        gpo = get_entry(self.ldap_session, self.gpo_dn, attributes=attributes)
        
        generic_infos = Table(show_header=False, box=None)
        generic_infos.add_column("Key", style="bold cyan", justify="left")
        generic_infos.add_column("Value", style="white", justify="left")
        if self.check_write is True:
            write_permissions = self.check_write_permissions(gpo)
            permissions = "[bold italic green]True[/bold italic green]" if write_permissions is True else "[bold italic red]False[/bold italic red]"
            generic_infos.add_row("Write permissions", permissions)
        generic_infos.add_row("cn", gpo['attributes']['cn'])
        generic_infos.add_row("displayName", gpo['attributes']['displayName'])
        generic_infos.add_row("description", 
                                'N/A' if not gpo['attributes']['description']
                                else ' ; '.join(gpo['attributes']['description']))
        generic_infos.add_row("whenCreated", gpo['attributes']['whenCreated'].strftime("%m/%d/%Y, %H:%M:%S"))
        generic_infos.add_row("whenChanged", gpo['attributes']['whenChanged'].strftime("%m/%d/%Y, %H:%M:%S"))
        generic_infos.add_row("version (computer)", Text(str(gpo['attributes']['versionNumber'] & 0xFFFF), style="bold"))
        generic_infos.add_row("version (user)", Text(str(gpo['attributes']['versionNumber'] >> 16 & 0xFFFF), style="bold"))
        generic_infos.add_row("gPCFileSysPath", gpo['attributes']['gPCFileSysPath'])

        extensions_computer_header = Text("Machine extensions", style="cyan")
        if len(gpo['attributes']['gPCMachineExtensionNames']) > 0:
            extensions_computer = Table(box=None)
            extensions_computer.add_column("CSE")
            extensions_computer.add_column("Administrative")
            machine_guid_pairs = re.findall(r'\[([^\]]+)\]', gpo['attributes']['gPCMachineExtensionNames'])
            found_extensions = [re.findall(r'\{([0-9A-Fa-f\-]{36})\}', pair) for pair in machine_guid_pairs]
            for extension in found_extensions:
                extensions_computer.add_row(CSE_LIST[extension[0]] if extension[0] in CSE_LIST.keys() else extension[0],
                                            '\n'.join(CSE_LIST[adm_extension] if adm_extension in CSE_LIST.keys() else adm_extension for adm_extension in extension[1:]))
                extensions_computer.add_row(Rule(style="cyan"), Rule(style="cyan"))
        else:
            extensions_computer = "None"

        extensions_user_header = Text("\nUser extensions", style="cyan")
        if len(gpo['attributes']['gPCUserExtensionNames']) > 0:
            extensions_user = Table(box=None)
            extensions_user.add_column("CSE")
            extensions_user.add_column("Administrative")
            user_guid_pairs = re.findall(r'\[([^\]]+)\]', gpo['attributes']['gPCUserExtensionNames'])
            found_extensions = [re.findall(r'\{([0-9A-Fa-f\-]{36})\}', pair) for pair in user_guid_pairs]
            for extension in found_extensions:
                extensions_user.add_row(CSE_LIST[extension[0]] if extension[0] in CSE_LIST.keys() else extension[0],
                                            '\n'.join(CSE_LIST[adm_extension] if adm_extension in CSE_LIST.keys() else adm_extension for adm_extension in extension[1:]))
                extensions_user.add_row(Rule(style="cyan"), Rule(style="cyan"))
        else:
            extensions_user = "None"
        
        directly_linked_containers = []
        normal_link_style = Style(color="cyan")
        disabled_link_style = Style(color="cyan", dim=True)
        ous_tree = Tree("Organizational Units", hide_root=True)
        try:
            entries = get_entries(self.ldap_session, self.domain_dn, f'(gPLink=*{self.gpo_dn}*)', attributes=['distinguishedName', 'gPLink'])
        except GPBLDAPNoResultsError:
            entries = []
        for entry in entries:
            directly_linked_containers.append({
                'DN': entry['attributes']['distinguishedName'],
                'link': entry['attributes']['gPLink'],
            })

        for directly_linked_container in directly_linked_containers:
            escaped_gpo_dn = re.escape(self.gpo_dn)
            gplink_pattern = fr'\[(LDAP://{escaped_gpo_dn};[0-3])\]'
            gpo_link = re.search(gplink_pattern, directly_linked_container['link'], re.IGNORECASE)
            link_options = int(gpo_link.group(1)[-1])

            if link_options == LinkOptions.NORMAL.value:
                prefix = "[🔗] "
                style = normal_link_style
            elif link_options == LinkOptions.ENFORCED.value:
                prefix = "[👊] "
                style = normal_link_style
            else:
                prefix = "[🚫] "
                style = disabled_link_style
            root_branch = ous_tree.add(Text("\n"+prefix+directly_linked_container['DN'], style=style))

            if link_options != LinkOptions.DISABLED.value and link_options != LinkOptions.DISABLED_ENFORCED.value:
                if directly_linked_container['DN'].lower() == self.domain_dn.lower():
                    root_branch.add("GPO is linked to domain and will propagate to all OUs that did not disable inheritance")
                else:
                    self.recursive_OU_search(directly_linked_container['DN'], root_branch)

        generic_info_panel = Panel.fit(generic_infos, title="Generic information", title_align="left")
        extensions_group = Group(extensions_computer_header, extensions_computer, extensions_user_header, extensions_user)
        extensions_panel = Panel.fit(extensions_group, title="GPO extensions", title_align="left")
        ous_group = (ous_tree)
        ous_panel = Panel.fit(ous_group, title="Linked Containers - [🔗] Enabled [👊] Enforced [🚫] Disabled [❌] Inheritance disabled", title_align="left")

        logger.warning("\n")
        console = Console()
        console.print(generic_info_panel)
        console.print(extensions_panel)
        console.print(ous_panel)
        logger.warning("\n")



    def recursive_OU_search(self, ou_dn, tree, depth=0):
        try:
            direct_sub_ous = get_entries(self.ldap_session, ou_dn, '(objectClass=organizationalUnit)', search_scope=LEVEL, attributes=['distinguishedName', 'gPOptions'])
            depth += 1
        except GPBLDAPNoResultsError:
            direct_sub_ous = []
        for direct_sub_ou in direct_sub_ous:
            if direct_sub_ou['attributes']['gPOptions'] == 1:
                branch = tree.add(f"[❌] {direct_sub_ou['attributes']['distinguishedName']}", style=Style(dim=True))
            else:
                branch = tree.add(f"{direct_sub_ou['attributes']['distinguishedName']}")
                if depth > self.max_recursion:
                    branch.add(f"[... More OUs ...]")
                else:
                    self.recursive_OU_search(direct_sub_ou['attributes']['distinguishedName'], branch, depth)


    def check_write_permissions(self, gpo):
        try:
            modify_attribute(self.ldap_session, self.gpo_dn, "versionNumber", gpo["attributes"]["versionNumber"])
            return True
        except Exception as e:
            return False
