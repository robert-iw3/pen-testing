import os
import importlib.util

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

MODULE_DIR = os.path.join(os.path.dirname(__file__), "modules")

def discover_module_files(base_dir):
    modules = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                rel_path = os.path.relpath(os.path.join(root, file), MODULE_DIR)
                modules.append(rel_path.replace(os.sep, "/")[:-3])  # Strip .py
    return modules

def search_modules(searchterm):
    try:
        keyword = searchterm.lower()

    except Exception as e:
        print(brightred + f"[-] ERROR failed to search modules: {e}")

    all_modules = discover_module_files(MODULE_DIR)
    if searchterm in ("all", "ALL"):
        return all_modules

    if keyword and searchterm not in ("all", "ALL"):
        try:
            result = [m for m in all_modules if keyword in m.lower()]

        except Exception as e:
            print(brightred + f"[-] ERROR failed to fetch modules: {e}")

        if not result:
            return None

        elif result:
            return result

        else:
            return None

    else:
        return None

def load_module(slash_path):  # e.g., windows/x64/post_exploitation/hashdump
    try:
        parts = slash_path.split("/")
        module_path = os.path.join(MODULE_DIR, *parts) + ".py"

        if not os.path.isfile(module_path):
            print(brightred + f"[-] Module file not found: {module_path}")
            return None

        spec = importlib.util.spec_from_file_location(slash_path.replace("/", "_"), module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class_name = [i for i in dir(module) if i.lower().endswith("module")][0]
        instance = getattr(module, class_name)()

        print(brightyellow + f"[*] Using module: {instance.name}\n")
        return instance

    except IndexError:
        print(brightred + f"[!] Failed: No class ending in 'module' found in {slash_path}.py")
    except Exception as e:
        print(brightred + f"[!] Error loading module: {e}")
    return None