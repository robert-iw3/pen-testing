from functools import wraps
from core.teamserver import operator_manager as op_manage
from colorama import Fore, Style

brightred = Fore.RED + Style.BRIGHT
reset     = Style.RESET_ALL

# which top‑level commands only admins may run
ADMIN_ONLY = {
    "addop",    # create operators
    "delop",    # delete operators
    "operators",# list persistent operator accounts
    "kick",     # kick other operators
    "alert",    # message other operators
    # (alias -o could go here too; you'll special‑case that below)
}

def requires_admin(f):
    @wraps(f)
    def wrapper(user, *args, to_console=True, to_op=None, **kwargs):
        # only check if this is an operator invocation
        if to_op:
            op = op_manage.operators.get(to_op)
            if not op or op.role != "admin":
                # reject!
                print(brightred + "[!] Admin privileges required." + reset)
                return
        return f(user, *args, to_console=to_console, to_op=to_op, **kwargs)
    return wrapper