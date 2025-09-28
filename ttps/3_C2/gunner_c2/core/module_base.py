import os
import importlib
import sys

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

class ModuleBase:
    """
    Base class for all C2 modules. Each module should subclass this and define:
      - name: str
      - description: str
      - options: dict mapping option name to dict {"value": default, "required": bool, "description": str}
      - run(self): the action when module is executed
    """
    name = None
    description = None
    options = {}

    def validate(self):
        missing = [k for k, v in self.options.items() if v.get("required") and not v.get("value")]
        if missing:
            return missing

        return True

    def show_options(self):
        print(brightyellow + f"\nOptions for module {self.name}:\n")
        for opt, meta in self.options.items():
            val = meta.get('value', '')
            req = 'yes' if meta.get('required') else 'no'
            desc = meta.get('description', '')
            print(brightgreen + f"  {opt:<15} {val:<10} Required: {req:<3}  {desc}")

    def set_option(self, key, value):
        if key in self.options:
            self.options[key]['value'] = value
        else:
            print(brightred + f"Unknown option '{key}' for module {self.name}")

    def run(self):
        raise NotImplementedError("Module must implement run().")


typedef = ModuleBase

class ModuleManager:
    def __init__(self, modules_path='core/modules'):
        self.modules_path = modules_path
        self.modules = {}  # name -> class
        self.load_modules()
        self.current_module = None

    def load_modules(self):
        sys.path.insert(0, os.getcwd())
        for filename in os.listdir(self.modules_path):
            if filename.endswith('.py') and not filename.startswith('_'):
                mod_name = filename[:-3]
                module = importlib.import_module(f"core.modules.{mod_name}")
                for attr in dir(module):
                    cls = getattr(module, attr)
                    if isinstance(cls, type) and issubclass(cls, ModuleBase) and cls is not ModuleBase:
                        self.modules[cls.name] = cls

    def search(self, term):
        results = [m for m in self.modules if term.lower() in m.lower()]
        return results

    def use(self, name):
        if name in self.modules:
            self.current_module = self.modules[name]()
        else:
            print(brightred + f"No module named '{name}'")

    def show_current(self):
        if self.current_module:
            print(brightyellow + f"Using module: {self.current_module.name}\n  {self.current_module.description}\n")
        else:
            print(brightred + "No module selected.")

    def run_current(self):
        if self.current_module:
            self.current_module.run()
        else:
            print(brightred + "No module selected.")