import re
import base64
import smbclient

from gpb.utils.clean                import clean_save_action
from gpb.protocols.ldap             import delete_entry, get_entries, modify_attribute, serialize_ldap_entry_to_json
from gpb.protocols.smb              import delete_file, delete_directory, read_file_binary

from config                         import bcolors, logger, GPBLDAPNoResultsError


class GPODeleter:

    def __init__(self,
                domain,
                dc,
                ldap_session,
                gpo_guid,
                state_folder):

        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.gpo_guid = gpo_guid.upper()
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.ldap_session = ldap_session
        self.state_folder = state_folder
        self.max_bytes_save_action = 2 * 1024 * 1024

    def recursive_directory_delete(self, smb_path):
        for file_info in smbclient.scandir(smb_path):
            if file_info.is_dir():
                self.recursive_directory_delete(smb_path + fr"\{file_info.name}")
            elif file_info.is_file():
                # This should not happen as GPT files are typically rather small - but just in case someone put an installer or equivalent in the GPT folder
                if file_info.smb_info.end_of_file > self.max_bytes_save_action:
                    original_contents = "!TOOBIG!"
                    logger.warning(f"{bcolors.FAIL}[!] Can't save original content for deleted file {smb_path}\{file_info.name}', file is too big ({file_info.smb_info.end_of_file}){bcolors.ENDC}")
                else:
                    original_contents = base64.b64encode(read_file_binary(smb_path + fr"\{file_info.name}")).decode()
                delete_file(smb_path + fr"\{file_info.name}")
                clean_save_action(self.state_folder, "smb_delete_file", smb_path + fr"\{file_info.name}", old_value=original_contents)
                logger.warning(f"[*] Deleting SMB file {smb_path}\{file_info.name}")

        delete_directory(smb_path)
        clean_save_action(self.state_folder, "smb_delete_directory", smb_path)
        logger.warning(f"[*] Deleting SMB directory {smb_path}")

    def run(self):
        logger.warning(f"\n{bcolors.OKCYAN}[#] Removing all links associated with the GPO{bcolors.ENDC}")
        try:
            results = get_entries(self.ldap_session, self.domain_dn, f"(gPLink=*{{{self.gpo_guid}}}*)", attributes=["distinguishedName", "gpLink"])
            linked_containers = [(result['attributes']['distinguishedName'], result['attributes']['gpLink']) for result in results]
        except GPBLDAPNoResultsError:
            linked_containers = []
        logger.warning(f"[*] Total of {len(linked_containers)} GPO links discovered")

        for ou_dn, current_gplink in linked_containers:
            logger.info(f"[INFO] Removing link from container {ou_dn}")
            logger.info(f"[INFO] Current container gPLink is {current_gplink}")
            gplink_pattern = r'\[(.*?;[0-3])\]'
            current_links = re.findall(gplink_pattern, current_gplink)
            updated_links = [link for link in current_links if self.gpo_dn.lower() not in link.lower()]
            if len(current_links) == len(updated_links):
                logger.error(f"[!] Link for GPO {self.gpo_guid} not found on container {ou_dn}")
                break
            if len(updated_links) > 0:
                updated_links = ''.join(f"[{link}]" for link in updated_links)
            else:
                updated_links = ' '
            logger.info(f"[INFO] Updated container gPLink is {updated_links}")
            modify_attribute(self.ldap_session, ou_dn, "gPLink", updated_links)
            clean_save_action(self.state_folder, "ldap_modify_attribute", ou_dn, attribute="gPLink", old_value=current_gplink, new_value=updated_links)
            logger.warning(f"{bcolors.OKGREEN}[+] Removed link from container '{ou_dn}'{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Group Policy Container deletion{bcolors.ENDC}")
        self.delete_GPC()
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully deleted Group Policy Container for {self.gpo_dn}{bcolors.ENDC}")
        logger.warning(f"\n{bcolors.OKCYAN}[#] Group Policy Template deletion{bcolors.ENDC}")
        self.delete_GPT()
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully deleted Group Policy Template for {self.gpo_dn}{bcolors.ENDC}")


    def delete_GPC(self):
        gpc_entries = get_entries(self.ldap_session, self.gpo_dn, '(objectClass=*)')
        for gpc_entry in sorted(gpc_entries, key=lambda e: len(e['attributes']['distinguishedName'].split(',')), reverse=True):
            delete_entry(self.ldap_session, gpc_entry['attributes']['distinguishedName'])
            clean_save_action(self.state_folder, "ldap_delete_entry", gpc_entry['attributes']['distinguishedName'], old_value=serialize_ldap_entry_to_json(gpc_entry))
            logger.info(f"[INFO] Deleted {gpc_entry['attributes']['distinguishedName']}")
    
    def delete_GPT(self):
        self.recursive_directory_delete(fr"\\{self.dc}\SYSVOL\{self.domain}\Policies\{{{self.gpo_guid}}}")


