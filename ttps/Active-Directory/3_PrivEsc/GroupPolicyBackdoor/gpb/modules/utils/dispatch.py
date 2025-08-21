import smbclient

from smbprotocol.exceptions     import SMBOSError
from gpb.utils.clean            import clean_save_module

from config                     import logger, MODULES_CONFIG

        
def dispatch(modules, state_folder, gpo_sysvol_path):
    output = {
        "computer": {},
        "user": {}
    }
    existing_xml = {
        "computer": {},
        "user": {}
    }

    for module in modules:
        output[module.MODULECONFIG.type].setdefault(module.MODULECONFIG.name, b"")
        existing_xml[module.MODULECONFIG.type].setdefault(module.MODULECONFIG.name, None)
    for module_type, module_list in output.items():
        gpt_path_prefix = "Machine" if module_type == "computer" else "User"
        for module_name in module_list.keys():
            try:
                with smbclient.open_file(fr"{gpo_sysvol_path}\{gpt_path_prefix}\{MODULES_CONFIG[module_name]['gpt_path']}", mode="rb") as fd:
                    existing = fd.read()
                    module_list[module_name] = existing
                    existing_xml[module_type][module_name] = existing
                    logger.info(f"[INFO] There are existing GPO configurations for {module_name} ({module_type})")
            except SMBOSError as e:
                if (e.ntstatus == 0xC0000034 or e.ntstatus == 0xC000003A) and e.errno == 2:
                    logger.info(f"[INFO] No existing GPO configuration found for {module_name} ({module_type})")
                    continue
                else:
                    raise e

    for module in modules:
        logger.info(f"[INFO] Generating XML for module '{module.MODULECONFIG.name}' ({module.MODULECONFIG.type})")
        module_instance = MODULES_CONFIG[module.MODULECONFIG.name]["class"](module.MODULECONFIG, module.MODULEOPTIONS, module.MODULEFILTERS, output[module.MODULECONFIG.type][module.MODULECONFIG.name], state_folder)
        module_xml = module_instance.get_xml()
        clean_save_module(state_folder, module.MODULECONFIG.type, module.MODULECONFIG.name, f"{{{module_instance.identifier}}}")
        output[module.MODULECONFIG.type][module.MODULECONFIG.name] = module_xml

    return output, existing_xml
