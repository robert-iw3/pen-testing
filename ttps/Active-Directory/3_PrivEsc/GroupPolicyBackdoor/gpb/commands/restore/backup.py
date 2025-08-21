import os
import json
import smbclient

from gpb.protocols.ldap             import get_entries, serialize_ldap_entry_to_json

from smbprotocol.exceptions         import SMBException
from config                         import logger, bcolors

class GPOBackup():
    
    def __init__(self,
                domain,
                dc,
                gpo_guid,
                output_dir,
                ldap_session):
        
        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.ldap_session = ldap_session
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.gpo_sysvol_path = fr"\\{self.dc}\SYSVOL\{self.domain}\Policies\{{{self.gpo_guid}}}"
        self.output_dir = output_dir


    def run(self):
        logger.warning(f"\n{bcolors.OKCYAN}[#] Output folder creation ({self.output_dir}){bcolors.ENDC}")
        self.initialize_backup_folder()

        logger.warning(f"\n{bcolors.OKCYAN}[#] Backuping the Group Policy Container via LDAP{bcolors.ENDC}")
        self.backup_GPC()
        logger.warning(f"{bcolors.OKGREEN}[+] Successful backup of the Group Policy Container for {self.gpo_dn}{bcolors.ENDC}")
        logger.warning(f"\n{bcolors.OKCYAN}[#] Backuping the Group Policy Template via SMB{bcolors.ENDC}")
        self.backup_GPT()
        logger.warning(f"{bcolors.OKGREEN}[+] Successful backup of the Group Policy Template for {self.gpo_dn}{bcolors.ENDC}")


    def backup_GPC(self):
        serialized_GPC = {}
        gpc_entries = get_entries(self.ldap_session, self.gpo_dn, '(objectClass=*)')

        for gpc_entry in sorted(gpc_entries, key=lambda e: len(e['attributes']['distinguishedName'].split(',')), reverse=True):
            logger.warning(f"[*] Backuping '{gpc_entry['attributes']['distinguishedName']}'")
            serialized_GPC[gpc_entry['attributes']['distinguishedName']] = serialize_ldap_entry_to_json(gpc_entry)
            
        with open(os.path.join(self.output_dir, "GroupPolicyContainer", "entries.json"), 'w') as f:
            json.dump(serialized_GPC, f)


    def recursive_smb_download(self, current_remote_dir, current_local_dir):
        logger.warning(f"[*] Processing remote directory '{current_remote_dir}'")
        try:
            entries = smbclient.scandir(current_remote_dir)
        except SMBException as e:
            logger.error(f"{bcolors.FAIL}[!] Error listing directory {current_remote_dir}: {e}{bcolors.ENDC}")
            return

        for entry in entries:
            remote_entry_path = os.path.join(current_remote_dir, entry.name)
            local_entry_path = os.path.join(current_local_dir, entry.name)
    
            try:
                if entry.is_dir():
                    os.makedirs(local_entry_path, exist_ok=True)
                    self.recursive_smb_download(remote_entry_path, local_entry_path)
                elif entry.is_file():
                    logger.warning(f"[*] Downloading file '{remote_entry_path}' to '{local_entry_path}'")
                    with smbclient.open_file(remote_entry_path, mode='rb') as r_file:
                        with open(local_entry_path, 'wb') as l_file:
                            while True:
                                chunk = r_file.read(8192)
                                if not chunk:
                                    break
                                l_file.write(chunk)
                else:
                    logger.warning(f"[?] Skipping unknown entry type '{remote_entry_path}'")
            except SMBException as e:
                logger.error(f"{bcolors.FAIL}[!] Error processing {remote_entry_path}: {e}{bcolors.ENDC}")
            except IOError as e:
                logger.error(f"{bcolors.FAIL}Local file system error for {local_entry_path}: {e}{bcolors.ENDC}")


    def backup_GPT(self):
        self.recursive_smb_download(self.gpo_sysvol_path, os.path.join(self.output_dir, "GroupPolicyTemplate"))


    def initialize_backup_folder(self):
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "GroupPolicyTemplate"), exist_ok=False)
        os.makedirs(os.path.join(self.output_dir, "GroupPolicyContainer"), exist_ok=False)
        with open(os.path.join(self.output_dir, "GroupPolicyContainer", "entries.json"), 'w+') as f:
            f.write("{}")



