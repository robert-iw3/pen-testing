import re
import typer

from gpb.protocols.ldap                 import get_entry_attribute, modify_attribute
from gpb.utils.clean                    import clean_save_action

from config                             import bcolors, logger, LinkOptions

class GPOLinker():

    def __init__(self,
                domain,
                dc,
                ldap_session,
                gpo_guid,
                ou_dn_list,
                state_folder):

        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.ou_dn_list = ou_dn_list
        self.ldap_session = ldap_session
        self.state_folder = state_folder


    def run(self) -> None:
        logger.warning(f"\n{bcolors.OKCYAN}[#] Creating link for {len(self.ou_dn_list)} containers{bcolors.ENDC}")
        for ou_dn in self.ou_dn_list:
            logger.warning(f"[*] Creating link for '{ou_dn}'")
            try:
                self.create_link(ou_dn)
                logger.warning(f"{bcolors.OKGREEN}[+] Successfully created link on '{ou_dn}'")
            except Exception as e:
                logger.error(f"{bcolors.FAIL}[!] Link creation failed for {ou_dn}{bcolors.ENDC}", exc_info=True)
                continue


    def create_link(self, ou_dn):
        current_gplink = get_entry_attribute(self.ldap_session, ou_dn, "gPLink")
        logger.info(f"[INFO] Current gPLink is {current_gplink}")
        gplink_pattern = r'\[(.*?;[0-3])\]'
        link_exists = False
        current_links = re.findall(gplink_pattern, current_gplink)
        for i, current_link in enumerate(current_links):
            if self.gpo_dn.lower() in current_link.lower():
                link_exists = True
                logger.warning(f"[*] Link for GPO {self.gpo_guid} already exists on container {ou_dn}")
                link_options = int(current_link[-1])

                if link_options == LinkOptions.DISABLED.value or link_options == LinkOptions.DISABLED_ENFORCED.value:
                    confirmation = typer.confirm("[?] Link is currently disabled. Do you want to enable it ?")
                    if not confirmation:
                        return
                    current_links[i] = current_links[i][:-1] + str(LinkOptions.NORMAL.value) if link_options == LinkOptions.DISABLED.value \
                                       else current_links[i][:-1] + str(LinkOptions.ENFORCED.value)
                else:
                    return

        if link_exists is False:
            current_links.append(f"LDAP://cn={{{self.gpo_guid}}},cn=Policies,cn=System,{self.domain_dn};{LinkOptions.NORMAL.value}")
        updated_links = ''.join(f"[{link}]" for link in current_links)
        logger.info(f"[INFO] Updated gPLink is {updated_links}")
        modify_attribute(self.ldap_session, ou_dn, "gPLink", updated_links)
        clean_save_action(self.state_folder, "ldap_modify_attribute", ou_dn, attribute="gPLink", old_value=current_gplink, new_value=updated_links)


            

        