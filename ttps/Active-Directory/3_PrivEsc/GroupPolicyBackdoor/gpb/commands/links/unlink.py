import re

from gpb.protocols.ldap                 import get_entry_attribute, modify_attribute
from gpb.utils.clean                    import clean_save_action

from config                             import bcolors, logger

class GPOUnlinker():

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

        self.link_exists = False


    def run(self) -> None:
        logger.warning(f"\n{bcolors.OKCYAN}[#] Removing link on {len(self.ou_dn_list)} containers{bcolors.ENDC}")
        for ou_dn in self.ou_dn_list:
            logger.warning(f"[*] Removing link on '{ou_dn}'")
            try:
                if self.remove_link(ou_dn) is True:
                    logger.warning(f"{bcolors.OKGREEN}[+] Successfully deleted link from '{ou_dn}'")
                else:
                    logger.error(f"{bcolors.FAIL}[!] Link for GPO {self.gpo_guid} not found on container {ou_dn}{bcolors.ENDC}")
            except Exception as e:
                logger.error(f"{bcolors.FAIL}[!] Link deletion failed for {ou_dn}{bcolors.ENDC}", exc_info=True)
                continue


    def remove_link(self, ou_dn):
        current_gplink = get_entry_attribute(self.ldap_session, ou_dn, "gPLink")
        logger.info(f"[INFO] Current gPLink is {current_gplink}")
        gplink_pattern = r'\[(.*?;[0-3])\]'
        current_links = re.findall(gplink_pattern, current_gplink)

        updated_links = [link for link in current_links if self.gpo_dn.lower() not in link.lower()]
        if len(current_links) == len(updated_links):
            return False
        
        if len(updated_links) > 0:
            updated_links = ''.join(f"[{link}]" for link in updated_links)
        else:
            updated_links = ' '
        logger.info(f"[INFO] Updated gPLink is {updated_links}")
        modify_attribute(self.ldap_session, ou_dn, "gPLink", updated_links)
        clean_save_action(self.state_folder, "ldap_modify_attribute", ou_dn, attribute="gPLink", old_value=current_gplink, new_value=updated_links)
        return True


