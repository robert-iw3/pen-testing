import re
import os
import json
import base64
import smbclient
import traceback

from lxml                               import etree

from gpb.protocols.smb                  import delete_file, write_file_binary
from gpb.protocols.ldap                 import get_entry_attribute, modify_attribute
from gpb.utils.encodings                import get_xml_declared_encoding
from gpb.utils.clean                    import clean_save_action

from config                             import logger, bcolors, MODULES_CONFIG

class GPOCleaner():
    
    def __init__(self,
                domain,
                dc,
                clean_state_folder,
                state_folder,
                gpo_guid,
                ldap_session):
        
        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.ldap_session = ldap_session
        self.state_folder = state_folder

        
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.gpo_sysvol_path = fr"\\{self.dc}\SYSVOL\{self.domain}\Policies\{{{self.gpo_guid}}}"
        with open(os.path.join(clean_state_folder, "clean.json"), "r") as f:
            self.configurations_to_clean = json.load(f)


    def remove_extension_names(self, configuration_name, extensions_attribute, current_extension_names):
        extension_names_to_remove = [MODULES_CONFIG[configuration_name]["cse_guid"], MODULES_CONFIG[configuration_name]["admin_guid"]]

        if current_extension_names is None:
            current_extension_names = get_entry_attribute(self.ldap_session, self.gpo_dn, extensions_attribute)
            self.initial_extension_names = current_extension_names
            guid_pairs = re.findall(r'\[([^\]]+)\]', current_extension_names)
            current_extension_names = [re.findall(r'\{([0-9A-Fa-f\-]{36})\}', pair) for pair in guid_pairs]
        
        logger.info(f"[INFO] Current extension names: '{current_extension_names}'")
        updated_extension_names = [guid_pair for guid_pair in current_extension_names if guid_pair != extension_names_to_remove]
        if len(updated_extension_names) == len(current_extension_names):
            logger.error("[!] Could not find extension GUID pair in extension names, which is not expected")

        for guid_pair in updated_extension_names:
            if guid_pair[0] == '00000000-0000-0000-0000-000000000000':
                try:
                    guid_pair.remove(MODULES_CONFIG[configuration_name]["admin_guid"])
                except ValueError:
                    logger.error("[!] Could not find admin extension GUID in the GPO Core element, which is not expected")
                # If we only have the GPO Core GUID left, remove it
                if len(guid_pair) == 1:
                    updated_extension_names.remove(guid_pair)
                break

        logger.info(f"[INFO] Updated extension names: '{updated_extension_names}'")
        return updated_extension_names


    def run(self):
        
        cleaning_wrapper = {
            "computer": {},
            "user": {}
        }
        for configuration in self.configurations_to_clean:
            cleaning_wrapper[configuration['configuration_type']].setdefault(configuration['configuration_name'], [])
            cleaning_wrapper[configuration['configuration_type']][configuration["configuration_name"]].append(configuration["configuration_identifier"])
        
        for configuration_type in cleaning_wrapper.keys():
            extension_names = None
            extensions_attribute = "gPCMachineExtensionNames" if configuration_type == "computer" else "gPCUserExtensionNames"

            for configuration_name, identifiers in cleaning_wrapper[configuration_type].items():
                try:
                    logger.warning(f"\n{bcolors.OKCYAN}[#] Cleaning configuration of type {configuration_name} ({configuration_type}){bcolors.ENDC}")
                    gpt_base_path = fr"{self.gpo_sysvol_path}\User" if configuration_type == "user" else fr"{self.gpo_sysvol_path}\Machine"
                    gpt_path = gpt_base_path + '\\' + MODULES_CONFIG[configuration_name]["gpt_path"]
                    
                    # Read the XML for the configuration
                    with smbclient.open_file(gpt_path, mode="rb") as fd:
                        current_xml = fd.read()
                        encoding = get_xml_declared_encoding(current_xml)
                        logger.info(f"[INFO] Read current XML and picked encoding {encoding}")
                    root = etree.XML(current_xml)
                    tree = etree.ElementTree(root)

                    # For each identifier to remove
                    for identifier in identifiers:
                        try:
                            logger.warning(f"[*] Cleaning configuration with identifier {identifier}")
                            found = False
                            # Traverse all first-level elements
                            for node in root:
                                # If the element has the identifier, remove it
                                if identifier in node.attrib.values():
                                    logger.warning(f"[*] Found the XML node to remove")
                                    logger.info(etree.tostring(node).decode())
                                    root.remove(node)
                                    found = True
                            if found is False:
                                logger.warning(f"{bcolors.BOLD}[?] Did not find identifier {identifier} in module XML{bcolors.ENDC}")
                        except Exception as e:
                            logger.error(f"{bcolors.FAIL}[!] Encountered an error while removing identifier {identifier}{bcolors.ENDC}")
                            traceback.print_exc()
                            continue

                    # If there are no more elements in the configuration file, we just remove the file and we also update extension names. Otherwise, we write what's left
                    if len(root) == 0:
                        logger.warning(f"[*] Deleting empty file {gpt_path}")
                        delete_file(gpt_path)
                        clean_save_action(self.state_folder, "smb_delete_file", gpt_path, old_value=base64.b64encode(current_xml).decode())
                        logger.warning(f"[*] Extension names should be updated")
                        extension_names = self.remove_extension_names(configuration_name, extensions_attribute, extension_names)
                    else:
                        logger.warning(f"[*] Re-writing remaining configuration items to file '{gpt_path}'")
                        write_file_binary(gpt_path, etree.tostring(root, xml_declaration=True, encoding=encoding))
                        clean_save_action(self.state_folder, "smb_modify_file", gpt_path, old_value=base64.b64encode(current_xml).decode(), new_value=base64.b64encode(etree.tostring(root, xml_declaration=True, encoding=encoding)).decode())
                except Exception as e:
                    logger.error(f"{bcolors.FAIL}[!] Encountered an error while cleaning module {configuration_name} ({configuration_type}){bcolors.ENDC}")
                    traceback.print_exc()
                    continue                
                logger.warning(f"{bcolors.OKGREEN}[+] Successfully cleaned configuration {configuration_name} ({configuration_type})")

            # If we have to update the extension names, do it. Should not have to re-sort extension names since we are only removing elements
            if extension_names is not None:
                extension_names = [''.join(f"{{{guid}}}" for guid in guid_pair) for guid_pair in extension_names]
                extension_names = ''.join(f"[{item}]" for item in extension_names)
                if len(extension_names) == 0:
                    extension_names = " "
                modify_attribute(self.ldap_session, self.gpo_dn, extensions_attribute, extension_names)
                clean_save_action(self.state_folder, "ldap_modify_attribute", self.gpo_dn, attribute=extensions_attribute, old_value=self.initial_extension_names, new_value=extension_names)
                logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated extension names ('{extensions_attribute}')")
                