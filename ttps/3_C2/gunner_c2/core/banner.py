from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def print_banner():
    """
    Print a red ASCII-art banner saying 'GUNNER'.
    """
    # Initialize colorama
    init(autoreset=True)

    banner = r"""
   ______   __  __    _   __    _   __    ______    ____ 
  / ____/  / / / /   / | / /   / | / /   / ____/   / __ \
 / / __   / / / /   /  |/ /   /  |/ /   / __/     / /_/ /
/ /_/ /  / /_/ /   / /|  /   / /|  /   / /___    / _, _/ 
\____/   \____/   /_/ |_/   /_/ |_/   /_____/   /_/ |_|
"""

    print(brightred + banner)
    print("\n")
    #print("\n")