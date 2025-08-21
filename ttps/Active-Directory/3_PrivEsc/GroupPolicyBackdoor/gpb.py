import uuid
import typer
import logging
import traceback

from datetime                      import datetime
from typing_extensions             import Annotated, List

from gpb.utils.clean               import clean_create_folder, get_gpo_guid_from_state
from gpb.commands.gpo.create       import GPOCreator
from gpb.commands.gpo.inject       import GPOInjecter
from gpb.commands.gpo.delete       import GPODeleter
from gpb.commands.gpo.clean        import GPOCleaner
from gpb.commands.links.link       import GPOLinker
from gpb.commands.links.unlink     import GPOUnlinker
from gpb.commands.links.configure  import GPOLinkConfigure
from gpb.commands.enum.gpo_list    import GPOLister
from gpb.commands.enum.gpo_details import GPODetails
from gpb.commands.restore.undo     import GPOUndo
from gpb.commands.restore.backup   import GPOBackup
from gpb.modules.parsing.validate  import validate_modules

from gpb.protocols.ldap            import get_ldap_session
from gpb.protocols.smb             import initialize_smb_connection
from gpb.utils.gpo                 import get_gpo_by_name, gpo_exists

from config                        import logger, bcolors

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, add_completion=False, pretty_exceptions_enable=False, pretty_exceptions_short=True)
gpo_app = typer.Typer()
links_app = typer.Typer()
enumeration_app = typer.Typer()
restore_app = typer.Typer()

app.add_typer(gpo_app, name="gpo", help="All subcommands related to GPO manipulation")
app.add_typer(links_app, name="links", help="All subcommands related to GPO links")
app.add_typer(enumeration_app, name="enum", help="All subcommands related to GPO and containers enumeration")
app.add_typer(restore_app, name="restore", help="All subcommands related to exploit safety, allowing to restore the target environment in case anything goes wrong")

def set_verbosity(value):
    if value == 0:
        logger.setLevel(logging.WARN)
    elif value == 1:
        logger.setLevel(logging.INFO)
    elif value >= 2:
        logger.setLevel(logging.DEBUG)


@gpo_app.command(help="Create a new empty Group Policy Object")
def create(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain FQDN")],
    display_name: Annotated[str, typer.Option("--display-name", "-n", help="The display name of the created GPO")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - CREATE command - {datetime.now()}{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos, all_info=True)
        smb_session_lowlevel = initialize_smb_connection(dc, username, password, kerberos, low_level=True)
        gpo_guid = str(uuid.uuid4()).upper()
        logger.info(f"[INFO] GPO GUID will be {gpo_guid}")
        state_folder = clean_create_folder("create", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")

        gpo_creator = GPOCreator(domain,
                        dc,
                        ldap_session,
                        smb_session_lowlevel,
                        display_name,
                        gpo_guid,
                        state_folder)
        gpo_creator.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB CREATE command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running create command{bcolors.ENDC}")
        traceback.print_exc()


@gpo_app.command(help="Delete an existing Group Policy Object (use with caution)")
def delete(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - DELETE command - {datetime.now()}{bcolors.ENDC}")
        
        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")
        state_folder = clean_create_folder("delete", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")

        gpo_deleter = GPODeleter(domain,
                                dc,
                                ldap_session,
                                gpo_guid,
                                state_folder)
        gpo_deleter.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB DELETE command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running delete command{bcolors.ENDC}")
        traceback.print_exc()


@gpo_app.command(help="Inject one or several configuration(s) into an existing Group Policy Object")
def inject(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the target GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    modules: Annotated[List[str], typer.Option("--module", "-m", help="Specify a module (a configuration) to add to the GPO. Must be a path to a .ini file (see templates in 'modules_templates/'). This option can be specified multiple times")] = [],
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain
        
        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - INJECT command - {datetime.now()}{bcolors.ENDC}")
        
        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        modules = validate_modules(modules)
        logger.warning(f"{bcolors.OKGREEN}[+] All modules validated{bcolors.ENDC}")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")
        state_folder = clean_create_folder("inject", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")


        if len(modules) > 0:
            gpo_injecter = GPOInjecter(domain,
                                        dc,
                                        ldap_session,
                                        gpo_guid,
                                        modules,
                                        state_folder)
            gpo_injecter.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB INJECT command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running inject command{bcolors.ENDC}")
        traceback.print_exc()


@gpo_app.command(help="Clean a GPO by removing the configuration(s) injected through an 'inject' command. Provide the state folder generated by said 'inject' command.")
def clean(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    clean_state_folder: Annotated[str, typer.Option("--state-folder", "-sf", help="The path to a state folder (a subfolder of the state_folders directory, containing 'gpo_guid.json' and 'clean.json' files)")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - CLEAN command - {datetime.now()}{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        gpo_guid = get_gpo_guid_from_state(clean_state_folder)
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)
        gpo_guid = gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")
        state_folder = clean_create_folder("clean", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")

        gpo_cleaner = GPOCleaner(domain,
                                dc,
                                clean_state_folder,
                                state_folder,
                                gpo_guid,
                                ldap_session)
        gpo_cleaner.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB CLEAN command success{bcolors.ENDC}")
    
    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running clean command{bcolors.ENDC}")
        traceback.print_exc()


@links_app.command(help="Link a GPO to a container")
def link(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    ou_dn_list: Annotated[List[str], typer.Option("--ou-dn", "-o", help="The distinguished name of the container to which the GPO should be linked. This option can be specified multiple times to link to multiple OUs")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - LINK command - {datetime.now()}{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")
        state_folder = clean_create_folder("link", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")

        gpo_linker = GPOLinker(domain,
                            dc,
                            ldap_session,
                            gpo_guid,
                            ou_dn_list,
                            state_folder)
        gpo_linker.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB LINK command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running link command{bcolors.ENDC}")
        traceback.print_exc()


@links_app.command(help="Unlink a GPO from a container")
def unlink(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    ou_dn_list: Annotated[List[str], typer.Option("--ou-dn", "-o", help="The distinguished name of the container from which the GPO should be unlinked. This option can be specified multiple times to unlink multiple OUs")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - UNLINK command - {datetime.now()}{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")
        state_folder = clean_create_folder("unlink", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")

        gpo_unlinker = GPOUnlinker(domain,
                                dc,
                                ldap_session,
                                gpo_guid,
                                ou_dn_list,
                                state_folder)
        gpo_unlinker.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB UNLINK command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running unlink command{bcolors.ENDC}")
        traceback.print_exc()


@links_app.command(help="Configure a GPO link (enforce, unenforce, enable, disable)")
def configure(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    ou_dn: Annotated[str, typer.Option("--ou-dn", "-o", help="The distinguished name of the container on which the link is positioned")],
    action: Annotated[str, typer.Option("--action", "-a", help="The configuration to apply to the link ('enforce', 'unenforce', 'enable', 'disable')")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        action = action.lower()
        if action not in ["enforce", "unenforce", "enable", "disable"]:
            logger.error(f"{bcolors.FAIL}[!] Unknown action {action}{bcolors.ENDC}")
            return
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain
        
        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - CONFIGURE (link) command - {datetime.now()}{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")


        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")
        state_folder = clean_create_folder("unlink", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")

        gpo_linkconfigure = GPOLinkConfigure(domain,
                            dc,
                            ldap_session,
                            gpo_guid,
                            ou_dn,
                            action,
                            state_folder)
        gpo_linkconfigure.run()
        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB CONFIGURE (link) command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running configure (link) command{bcolors.ENDC}")
        traceback.print_exc()
    



@enumeration_app.command(help="List domain Group Policy Objects")
def list_gpos(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain
        
        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - LIST-GPOS command - {datetime.now()}{bcolors.ENDC}")

        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)

        gpo_lister = GPOLister(domain,
                            dc,
                            ldap_session)
        gpo_lister.run()

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running list_gpos command{bcolors.ENDC}")
        traceback.print_exc()


@enumeration_app.command(help="Get details on a particular Group Policy Object")
def gpo_details(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    check_write: Annotated[bool, typer.Option("--check-write", "-c", help="Check if the current user has write privileges over the GPC (reads the GPO version and attempt to write it back)")] = False,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if gpo_guid is None and gpo_name is None:
            logger.error(f"{bcolors.FAIL}[!] You should provide either a GPO GUID or a GPO name{bcolors.ENDC}")
            return
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - GPO-DETAILS command - {datetime.now()}{bcolors.ENDC}")

        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")

        gpo_details = GPODetails(domain,
                                dc,
                                ldap_session,
                                gpo_guid,
                                check_write)
        gpo_details.run()

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running gpo_details command{bcolors.ENDC}")
        traceback.print_exc()


@restore_app.command(help="Undo any changes performed by a previous GPB command")
def undo(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    undo_state_folder: Annotated[str, typer.Option("--state-folder", "-sf", help="The path to a state folder (a subfolder of the state_folders directory, containing 'gpo_guid.json' and 'actions.json' files)")],
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - UNDO command - {datetime.now()}{bcolors.ENDC}")

        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        gpo_guid = get_gpo_guid_from_state(undo_state_folder)
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)
        logger.info(f"[INFO] Target GPO GUID {gpo_guid}")
        state_folder = clean_create_folder("undo", gpo_guid)
        logger.warning(f"[*] State folder is {bcolors.BOLD}{state_folder}{bcolors.ENDC}")
      

        gpo_undo = GPOUndo(domain,
                            dc,
                            undo_state_folder,
                            state_folder,
                            gpo_guid,
                            ldap_session)
        gpo_undo.run()

        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB UNDO command success{bcolors.ENDC}")


    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running undo command{bcolors.ENDC}")
        traceback.print_exc()


@restore_app.command(help="Backup the Group Policy Container and Group Policy Template of a GPO")
def backup(
    domain: Annotated[str, typer.Option("--domain", "-d", help="The domain name")],
    output_dir: Annotated[str, typer.Option("--output", "-o", help="Path to the directory in which the GPO backup will be stored")],
    gpo_guid: Annotated[str, typer.Option("--gpo-guid", "-g", help="The GUID of the GPO (without enclosing brackets)")] = None,
    gpo_name: Annotated[str, typer.Option("--gpo-name", "-n", help="Alternatively to the GPO GUID, you can provide the GPO name")] = None,
    dc: Annotated[str, typer.Option("--dc", help="The target domain controller (IP or FQDN). Any writable DC is suitable, although the PDC is preferred for GPO operations. If omitted, defaults to the domain FQDN")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="The username")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    kerberos: Annotated[bool, typer.Option("-k", help="Use Kerberos authentication. Ticket file location should be stored in the $KRB5CCNAME environment variable")] = False,
    ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS (port 636)")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):
    try:
        if gpo_guid is None and gpo_name is None:
            logger.error(f"{bcolors.FAIL}[!] You should provide either a GPO GUID or a GPO name{bcolors.ENDC}")
            return
        if username is not None and (password is None and hash is None):
            logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
            return
        if hash is not None and len(hash) != 32:
            logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
            return
        if password is None and hash is not None:
            password = '0' * 32 + ':' + hash
        if dc is None:
            dc = domain

        logger.warning(f"{bcolors.HEADER}{bcolors.BOLD}GPB - BACKUP command - {datetime.now()}{bcolors.ENDC}")
        
        logger.warning(f"\n{bcolors.OKCYAN}[#] Command execution setup{bcolors.ENDC}")
        ldap_session = get_ldap_session(domain, dc, ldaps, username, password, kerberos)
        initialize_smb_connection(dc, username, password, kerberos)

        gpo_guid = get_gpo_by_name(ldap_session, domain, gpo_name) if gpo_name is not None else gpo_exists(ldap_session, domain, gpo_guid)
        if gpo_guid is None:
            return
        logger.info(f"[INFO] GPO has GUID {gpo_guid} and exists")

        gpo_backup = GPOBackup( domain,
                                dc,
                                gpo_guid,
                                output_dir,
                                ldap_session)
        gpo_backup.run()

        logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}\n[+] GPB BACKUP command success{bcolors.ENDC}")

    except Exception as e:
        logger.error(f"{bcolors.FAIL}[!] Error encountered while running backup command{bcolors.ENDC}")
        traceback.print_exc()



if __name__ == "__main__":
    app()