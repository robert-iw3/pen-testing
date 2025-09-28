from core.gunnershell.commands.base import register, Command, QuietParser
from core.session_handlers import session_manager
from colorama import Style, Fore
import shlex

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred   = "\001" + Style.BRIGHT + Fore.RED   + "\002"

from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec


def _run(sid, cmd, op_id="console"):
    display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
    sess = session_manager.sessions.get(sid)
    if not sess:
        print(brightred + f"[!] No such session: {display}")
        return ""
    transport = (sess.transport or "").lower()
    if transport in ("http","https"):
        return http_exec.run_command_http(sid, cmd, op_id=op_id)
    if transport in ("tcp","tls"):
        return tcp_exec.run_command_tcp(sid, cmd, timeout=1.2, portscan_active=False, op_id=op_id)
    print(brightred + f"[!] Unsupported shell type: {transport}")
    return ""


@register("cp")
class CpCommand(Command):
    """Copy files/dirs"""

    @property
    def help(self):
        return "cp [-r] <src> <dst>    Copy file(s) or directory tree"

    def execute(self, args):
        out = self.logic(self.gs.sid, args, op_id=self.op_id)
        if out: print(brightgreen + out)
        else:   print(brightyellow + "[*] No output or error")

    def logic(self, sid, argv, op_id="console"):
        p = QuietParser(prog="cp", add_help=False)
        p.add_argument("-r", action="store_true")
        p.add_argument("src")
        p.add_argument("dst")
        try:
            ns = p.parse_args(argv)
        except SystemExit:
            return ""
        rflag = "-r " if ns.r else ""
        return _run(
            sid,
            f"cp {rflag}{shlex.quote(ns.src)} {shlex.quote(ns.dst)} && echo 'OK'",
            op_id=op_id,
        )
