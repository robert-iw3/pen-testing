import re

from gpb.protocols.ldap                 import get_entry_attribute, modify_attribute
from gpb.utils.clean                    import clean_save_action

from config                             import bcolors, logger, LinkOptions

class GPOLinkConfigure():

    def __init__(self,
                domain,
                dc,
                ldap_session,
                gpo_guid,
                ou_dn,
                action,
                state_folder):

        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.ou_dn = ou_dn
        self.action = action
        self.ldap_session = ldap_session
        self.state_folder = state_folder


    def run(self) -> None:
        logger.warning(f"\n{bcolors.OKCYAN}[#] Configuring link ({self.action}) of GPO {self.gpo_guid} for container {self.ou_dn}{bcolors.ENDC}")
        if self.configure_link() is True:
            logger.warning(f"{bcolors.OKGREEN}[+] Successfully configured link on '{self.ou_dn}'")
        else:
            logger.error(f"{bcolors.FAIL}[!] Link for GPO {self.gpo_guid} not found on container {self.ou_dn}{bcolors.ENDC}")

    def configure_link(self):
        current_gplink = get_entry_attribute(self.ldap_session, self.ou_dn, "gPLink")
        logger.info(f"[INFO] Current gPLink is {current_gplink}")
        gplink_pattern = r'\[(.*?;[0-3])\]'
        link_exists = False
        current_links = re.findall(gplink_pattern, current_gplink)

        for i, current_link in enumerate(current_links):
            if self.gpo_dn.lower() in current_link.lower():
                link_exists = True
                logger.info(f"[INFO] Found link on target OU")
                link_options = int(current_link[-1])

                if self.action == "enforce":
                    if link_options == LinkOptions.ENFORCED.value or link_options == LinkOptions.DISABLED_ENFORCED.value:
                        logger.warning(f"[?] Link is already in the 'enforced' state ({'ENFORCED' if link_options == LinkOptions.ENFORCED.value else 'DISABLED_ENFORCED'})")
                    elif link_options == LinkOptions.NORMAL.value:
                        logger.warning("[*] Link was in NORMAL state. New state: ENFORCED")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.ENFORCED.value)
                    elif link_options == LinkOptions.DISABLED.value:
                        logger.warning("[*] Link was in DISABLED state. New state: DISABLED_ENFORCED")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.DISABLED_ENFORCED.value)
                
                elif self.action == "unenforce":
                    if link_options == LinkOptions.NORMAL.value or link_options == LinkOptions.DISABLED.value:
                        logger.warning(f"[?] Link is not in the 'enforced' state ({'NORMAL' if link_options == LinkOptions.NORMAL.value else 'DISABLED'})")
                    elif link_options == LinkOptions.ENFORCED.value:
                        logger.warning("[*] Link was in ENFORCED state. New state: NORMAL")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.NORMAL.value)
                    elif link_options == LinkOptions.DISABLED_ENFORCED.value:
                        logger.warning("[*] Link was in DISABLED_ENFORCED state. New state: DISABLED")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.DISABLED.value)

                elif self.action == "enable":
                    if link_options == LinkOptions.NORMAL.value or link_options == LinkOptions.ENFORCED.value:
                        logger.warning(f"[?] Link is already is already enabled ({'NORMAL' if link_options == LinkOptions.NORMAL.value else 'ENFORCED'})")
                    elif link_options == LinkOptions.DISABLED.value:
                        logger.warning("[*] Link was in DISABLED state. New state: NORMAL")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.NORMAL.value)
                    elif link_options == LinkOptions.DISABLED_ENFORCED.value:
                        logger.warning("[*] Link was in DISABLED_ENFORCED state. New state: ENFORCED")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.ENFORCED.value)

                elif self.action == "disable":
                    if link_options == LinkOptions.DISABLED.value or link_options == LinkOptions.DISABLED_ENFORCED.value:
                        logger.warning(f"[?] Link is already is already disabled ({'DISABLED' if link_options == LinkOptions.DISABLED.value else 'DISABLED_ENFORCED'})")
                    elif link_options == LinkOptions.NORMAL.value:
                        logger.warning("[*] Link was in NORMAL state. New state: DISABLED")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.DISABLED.value)
                    elif link_options == LinkOptions.ENFORCED.value:
                        logger.warning("[*] Link was in ENFORCED state. New state: DISABLED_ENFORCED")
                        current_links[i] = current_links[i][:-1] + str(LinkOptions.DISABLED_ENFORCED.value)

        if link_exists is False:
            return False

        updated_links = ''.join(f"[{link}]" for link in current_links)
        logger.info(f"[INFO] Updated gPLink is {updated_links}")
        modify_attribute(self.ldap_session, self.ou_dn, "gPLink", updated_links)
        clean_save_action(self.state_folder, "ldap_modify_attribute", self.ou_dn, attribute="gPLink", old_value=current_gplink, new_value=updated_links)
        return True


            

        