from smbprotocol.create_contexts import (
    CreateContextName,
    SMB2CreateContextRequest,
)
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    ShareAccess,
)
from smbprotocol.security_descriptor import (
    AccessAllowedAce,
    AccessMask,
    AclPacket,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
    AceFlags
)
from smbprotocol.tree                   import TreeConnect
from typer                              import confirm

from gpb.protocols.ldap                 import get_entry_attribute, add_entry
from gpb.utils.clean                    import clean_save_action

from config                             import bcolors, logger

class GPOCreator:

    def __init__(self,
                domain: str,
                dc: str,
                ldap_session,
                smb_session_lowlevel,
                display_name: str,
                gpo_guid,
                state_folder: str) -> None:

        self.domain = domain
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dc = dc
        self.display_name = display_name
        self.gpo_guid = gpo_guid
        self.gpo_dn = f"CN={{{self.gpo_guid}}},CN=Policies,CN=System,{self.domain_dn}"
        self.ldap_session = ldap_session
        self.smb_connection = smb_session_lowlevel[0]
        self.smb_session = smb_session_lowlevel[1]
        self.state_folder = state_folder
        
        try:
            self.domain_sid = get_entry_attribute(self.ldap_session, self.domain_dn, 'objectSid')
            logger.info(f"[INFO] Retrieved domain SID '{self.domain_sid}'")
            self.root_domain_dn = self.ldap_session.server.info.other['rootDomainNamingContext'][3]
            if self.root_domain_dn == self.domain_dn:
                self.root_domain_sid = self.domain_sid
            else:
                self.root_domain_sid = get_entry_attribute(self.ldap_session, self.root_domain_dn, 'objectSid')
            logger.info(f"[INFO] Retrieved forest root domain SID '{self.root_domain_sid}'")
        except Exception as e:
            logger.error(f"{bcolors.FAIL}[-] Could not retrieve the domain SID or the forest root domain SID.{bcolors.ENDC}")
            logger.debug("[DEBUG] Stacktrace:", exc_info=True)
            self.domain_sid = None
            self.root_domain_sid = None
            proceed = confirm("GPO creation can proceed, although the GPT folder permissions will not be exactly as expected by Windows. The only consequence is that a popup might appear if an administrator clicks on the created GPO in the Group Policy Management Console. Proceed ?")
            if not proceed:
                exit(0)


    def run(self) -> None:
        logger.warning(f"\n{bcolors.OKCYAN}[#] Group Policy Container creation{bcolors.ENDC}")
        self.create_GPC()
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully created Group Policy Container for {self.gpo_dn}{bcolors.ENDC}")
        logger.warning(f"\n{bcolors.OKCYAN}[#] Group Policy Template creation{bcolors.ENDC}")
        self.create_GPT()
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully created Group Policy Template for {self.gpo_dn}{bcolors.ENDC}")

    def create_GPC(self) -> None:
        gpc_attributes = {
            "objectClass": ['top', 'container', 'groupPolicyContainer'],
            "cn": f"{{{self.gpo_guid}}}",
            "displayName": self.display_name,
            "flags": 0,
            "gPCFileSysPath": f"\\\\{self.dc}\\SysVol\\{self.domain}\\Policies\\{{{self.gpo_guid}}}",
            "gPCFunctionalityVersion": 2,
            "name": f"{{{self.gpo_guid}}}",
            "versionNumber": 0,
        }

        add_entry(self.ldap_session, self.gpo_dn, gpc_attributes)
        clean_save_action(self.state_folder, "ldap_create_entry", self.gpo_dn)
        logger.info(f"[INFO] Created LDAP entry '{self.gpo_dn}'")

        for child_entry in ["Machine", "User"]:
            try:
                entry_attributes = {
                    "objectClass": ['top', 'container'],
                    "cn": child_entry
                }
                add_entry(self.ldap_session, f"CN={child_entry},{self.gpo_dn}", entry_attributes)
                clean_save_action(self.state_folder, "ldap_create_entry", f"CN={child_entry},{self.gpo_dn}")
                logger.info(f"[INFO] Created LDAP entry 'CN={child_entry},{self.gpo_dn}'")
            except Exception as e:
                logger.error(f"{bcolors.FAIL}[-] Non-fatal LDAP error encountered when creating LDAP entry CN={child_entry},{self.gpo_dn} ('{self.ldap_session.last_error}'){bcolors.ENDC}")
                logger.debug("[DEBUG] Stacktrace:", exc_info=True)
                continue


    def create_GPT(self):
        share = fr"\\{self.dc}\SYSVOL"
        dir_name = fr"{self.domain}\Policies\{{{self.gpo_guid}}}"

        try:
            tree = TreeConnect(self.smb_session, share)
            tree.connect()

            if self.root_domain_sid is not None:
                # CREATOR_OWNER - Full control - Subfolders and files only
                creator_owner_sid = SIDPacket()
                creator_owner_sid.from_string("S-1-3-0")
                ace = AccessAllowedAce()
                ace["mask"] = 0x1F01FF          # For whatever reason, for CREATOR_OWNER Windows uses FileSystemRights.FullControl Access right instead of FileSystemRights.GenericAll
                ace["sid"] = creator_owner_sid
                ace["ace_flags"] = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE | AceFlags.INHERIT_ONLY_ACE

                # Authenticated Users - Read & Execute + list folder contents - This folder, subfolders and files
                auth_users = SIDPacket()
                auth_users.from_string("S-1-5-11")
                ace2 = AccessAllowedAce()
                ace2["mask"] = AccessMask.GENERIC_READ | AccessMask.GENERIC_EXECUTE | DirectoryAccessMask.FILE_LIST_DIRECTORY
                ace2["sid"] = auth_users
                ace2["ace_flags"] = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE

                # SYSTEM - Full control - This folder, subfolders and files
                system_sid = SIDPacket()
                system_sid.from_string("S-1-5-18")
                ace3 = AccessAllowedAce()
                ace3["mask"] = AccessMask.GENERIC_ALL
                ace3["sid"] = system_sid
                ace3["ace_flags"] = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE

                # Domain administrators - Full control - This folder, subfolders and files
                da_sid = SIDPacket()
                da_sid.from_string(f"{self.domain_sid}-512")
                ace4 = AccessAllowedAce()
                ace4["mask"] = AccessMask.GENERIC_ALL
                ace4["sid"] = da_sid
                ace4["ace_flags"] = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE

                # Enterprise admins - Full control - This folder, subfolders and files
                ea_sid = SIDPacket()
                ea_sid.from_string(f"{self.root_domain_sid}-519")
                ace5 = AccessAllowedAce()
                ace5["mask"] = AccessMask.GENERIC_ALL
                ace5["sid"] = ea_sid
                ace5["ace_flags"] = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE
                

                # Enterprise domain controllers - Read & Execute + list folder contents - This folder, subfolders and files
                edc_sid = SIDPacket()
                edc_sid.from_string("S-1-5-9")
                ace6 = AccessAllowedAce()
                ace6["mask"] = AccessMask.GENERIC_READ | AccessMask.GENERIC_EXECUTE | DirectoryAccessMask.FILE_LIST_DIRECTORY
                ace6["sid"] = edc_sid
                ace6["ace_flags"] = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE

                acl = AclPacket()
                acl["aces"] = [ace, ace2, ace3, ace4, ace5, ace6]

                sec_desc = SMB2CreateSDBuffer()
                sec_desc["control"].set_flag(SDControl.SELF_RELATIVE)
                sec_desc.set_dacl(acl)
                sd_buffer = SMB2CreateContextRequest()
                sd_buffer["buffer_name"] = CreateContextName.SMB2_CREATE_SD_BUFFER
                sd_buffer["buffer_data"] = sec_desc

                create_contexts = [sd_buffer]
            else:
                create_contexts = []

            # Create the root GPT directory
            dir_open = Open(tree, dir_name)
            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.GENERIC_READ | DirectoryAccessMask.GENERIC_WRITE,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE,
                create_contexts
            )
            clean_save_action(self.state_folder, "smb_create_directory", fr"{share}\{dir_name}")
            logger.info(f"[INFO] Created the '{share}\{dir_name}' directory")

            # Create the 'Machine' and 'User' subfolders
            dir_open = Open(tree, fr"{dir_name}\User")
            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.GENERIC_READ | DirectoryAccessMask.GENERIC_WRITE,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE
            )
            clean_save_action(self.state_folder, "smb_create_directory", fr"{share}\{dir_name}\User")
            logger.info(fr"[INFO] Created the '{share}\{dir_name}\User' directory")

            dir_open = Open(tree, fr"{dir_name}\Machine")
            dir_open.create(
                ImpersonationLevel.Impersonation,
                DirectoryAccessMask.GENERIC_READ | DirectoryAccessMask.GENERIC_WRITE,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN_IF,
                CreateOptions.FILE_DIRECTORY_FILE
            )
            clean_save_action(self.state_folder, "smb_create_directory", fr"{share}\{dir_name}\Machine")
            logger.info(fr"[INFO] Created the '{share}\{dir_name}\Machine' directory")
            
            # Create the GPT.INI file
            gpt_ini_contents = b"[General]\r\nVersion=0\r\ndisplayName=New Group Policy Object"

            gpt_ini_file = Open(tree, fr"{dir_name}\GPT.INI")
            gpt_ini_file.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_WRITE | FilePipePrinterAccessMask.DELETE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE
            )
            clean_save_action(self.state_folder, "smb_create_file", fr"{share}\{dir_name}\GPT.INI")
            logger.info(fr"[INFO] Created the '{share}\{dir_name}\GPT.INI' file")

            compound_messages = [
                gpt_ini_file.write(gpt_ini_contents, 0, send=False),
                gpt_ini_file.close(False, send=False)
            ]
            self.smb_connection.send_compound([x[0] for x in compound_messages], self.smb_session.session_id, tree.tree_connect_id)
            logger.info(f"[INFO] Initialized the '{share}\{dir_name}\GPT.INI' file")
        except Exception as e:
            raise e
        finally:
            self.smb_connection.disconnect(True)
            
        