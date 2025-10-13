from __future__ import annotations
import logging
logger = logging.getLogger(__name__)

import os
import re
import fnmatch
import shutil
import time
import math
from datetime import timedelta
import itertools
from typing import Optional, Tuple, Dict, Any, List
from .manager import TransferManager, TransferOpts
from .state import StateStore
from .chunker import human_bytes
from core.session_handlers import session_manager
from core.utils import echo, print_help

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

def _emit(msg: str, to_console: bool = True, to_op: Optional[str] = None, color: Optional[str]=None, override_quiet: bool=False) -> None:
	"""
	Console/operator-aware print (matches your output conventions).
	"""
	if not override_quiet:
			if color:
				logger.debug(color + f"{msg}" + reset)

			else:
				logger.debug(f"{msg}")

	else:
		if color:
			echo(msg, to_console=to_console, to_op=to_op, world_wide=False, color=color)

		else:
			echo(msg, to_console=to_console, to_op=to_op, world_wide=False)


def _resolve_sid_or_none(raw: Optional[str]) -> Optional[str]:
	"""
	Resolve a session id or alias (supports wildcards). If None/empty, returns None.
	Returns a concrete sid string or None. Raises ValueError on bad alias.
	"""
	if not raw:
		return None
	return session_manager.resolve_sid(raw)


def _find_by_tid(tm: TransferManager, tid_or_prefix: str, sid_hint: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
	"""
	Search for a transfer by TID prefix.
	If sid_hint is provided, restrict search to that SID. Returns (sid, state_dict) on success or (None, None).
	"""
	tid_or_prefix = (tid_or_prefix or "").strip()
	if not tid_or_prefix:
		return None, None

	# Prefer scoped search if SID is provided
	if sid_hint:
		rows = tm.list(sid_hint).get("transfers", [])
	else:
		rows = tm.list().get("transfers", [])

	matches = [st for st in rows if _matches_tid(st.get("tid") or "", tid_or_prefix)]
	if not matches:
		return None, None
	if len(matches) == 1:
		st = matches[0]
		return st.get("sid"), st

	# Ambiguous: if a sid_hint was provided, try to narrow further (shouldn’t happen, but just in case)
	if sid_hint:
		scoped = [st for st in matches if st.get("sid") == sid_hint]
		if len(scoped) == 1:
			st = scoped[0]
			return st.get("sid"), st

	# Still ambiguous
	return None, None

def _find_tid_anywhere(tm: TransferManager, tid_or_prefix: str) -> list[Dict[str, Any]]:
	"""
	Return all transfer rows whose TID starts with tid_or_prefix across all SIDs.
	"""
	tid_or_prefix = (tid_or_prefix or "").strip()
	if not tid_or_prefix:
		return []
	rows = tm.list().get("transfers", [])
	return [st for st in rows if _matches_tid(st.get("tid") or "", tid_or_prefix)]

def _first_match_or_ambiguous(matches: list[Dict[str, Any]]) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
	"""
	If exactly one match, return it and None error.
	If zero, (None, 'notfound'); if >1, (None, 'ambiguous').
	"""
	if not matches:
		return None, "notfound"
	if len(matches) > 1:
		return None, "ambiguous"
	return matches[0], None

def _rebind_transfer(tid: str, old_sid: str, new_sid: str) -> Optional[Dict[str, Any]]:
	"""
	Move the on-disk transfer from old_sid -> new_sid and update state
	so it can resume on the new live session. Returns the updated state dict.
	"""
	store = StateStore()
	base = store.base
	old_dir = os.path.join(base, old_sid, tid)
	new_sid_dir = os.path.join(base, new_sid)
	new_dir = os.path.join(new_sid_dir, tid)

	if not os.path.isdir(old_dir):
		return None

	os.makedirs(new_sid_dir, exist_ok=True)

	# Move entire transfer folder (keeps .part and any other files intact)
	shutil.move(old_dir, new_dir)

	# Load, update, save with new session metadata
	st = store.load(new_sid, tid)
	st.sid = new_sid
	sess = session_manager.sessions.get(new_sid)
	if sess:
		st.os_type = sess.metadata.get("os", "").lower()
		st.transport = getattr(sess, "transport", "").lower()

	# Re-pin tmp path to the new sid/tid (belt-and-suspenders; load() already did it)
	st.tmp_local_path = store._tmp_path(new_sid, tid)
	store.save(st)
	return st.to_dict()


def _fmt_progress(st: Dict[str, Any]) -> str:
	"""
	Consistent progress line like your TransferManager emits.
	"""
	done = int(st.get("bytes_done") or 0)
	total = int(st.get("total_bytes") or 0)
	pct = (done / total * 100.0) if total else 0.0
	return f"[{st.get('tid')}] {pct:5.1f}%  {human_bytes(done)}/{human_bytes(total)}"

def _matches_tid(tid: str, pattern: str) -> bool:
	"""
	Support both glob wildcards and prefix matching:
	  - If pattern contains *, ?, or [] → fnmatch
	  - Else → prefix match (startswith)
	"""
	pattern = (pattern or "").strip()
	if not pattern:
		return False

	if any(ch in pattern for ch in "*?[]"):
		return fnmatch.fnmatch(tid, pattern)

	return tid.startswith(pattern)

# ------------------------------ Transfer Status Visual Helpers ---------------------------

def _human_rate(bps: float) -> str:
	if bps <= 0:
		return "—"
	units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
	x = float(bps)
	for u in units:
		if x < 1024 or u == units[-1]:
			return f"{x:.1f} {u}"
		x /= 1024.0

def _fmt_eta(remaining_bytes: int, bps: float) -> str:
	if bps <= 0:
		return "—"
	secs = int(max(0, remaining_bytes / bps))
	return str(timedelta(seconds=secs))

def _color_status_value(s: str) -> str:
	s = (s or "?").lower()
	if s == "done":
		return brightgreen + s + reset

	if s in ("paused", "cancelled"):
		return brightyellow + s + reset

	if s == "error":
		return brightred + s + reset

	return s

def _render_status_kv(st: Dict[str, Any]) -> str:
	tid     = st.get("tid","?")
	sid     = st.get("sid","?")
	status  = (st.get("status") or "?").lower()
	dirn    = st.get("direction","?")
	folder  = "true" if bool(st.get("is_folder")) else "false"
	chunks  = int(st.get("total_chunks") or 0)
	nexti   = int(st.get("next_index") or 0)
	done    = int(st.get("bytes_done") or 0)
	total   = int(st.get("total_bytes") or 0)
	remote  = st.get("remote_path","")
	local   = st.get("local_path","")
	created = float(st.get("created_at") or 0.0)
	updated = float(st.get("updated_at") or created)

	# progress: %  done/total  rate
	pct = (done/total*100.0) if total else 0.0
	elapsed = max(1e-6, updated - created)
	bps = done / elapsed
	progress_val = f"{pct:6.2f}%  {human_bytes(done)}/{human_bytes(total)}"
	if total > 0 and bps > 0:
		progress_val += f"  {_human_rate(bps)}"

	# Desired order exactly as you showed
	rows = [
		("TID", tid),
		("SID", sid),
		("status", _color_status_value(status)),
		("progress", progress_val),
		("type", dirn),
		("folder", folder),
		("chunks", str(chunks)),
		("next", str(nexti)),
		("remote", remote),
		("local", local),
	]

	# Align keys to the same column
	key_w = max(len(k) for k, _ in rows)
	def kfmt(k: str) -> str:
		return f"{brightblue}{k:<{key_w}}{reset}"

	lines = [f"{kfmt(k)}: {v}" for k, v in rows]
	if st.get("error"):
		lines.append(f"{brightred}error{reset}: {st.get('error')}")
	return "\n".join(lines)

# ------------------------ Transfer Listing Visual Helpers ---------------------------

_STATUS_ORDER = {"error": 0, "paused": 1, "running": 2, "init": 3, "done": 4, "cancelled": 5}

def _status_color(s: str) -> str:
	s = (s or "?").lower()
	if s == "done":
		return brightgreen + s + reset

	if s in ("paused", "cancelled"):
		return brightyellow + s + reset

	if s == "error":
		return brightred + s + reset

	return brightblue + s + reset  # running/init/unknown

def _human_rate(bps: float) -> str:
	x = float(bps)
	units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
	for u in units:
		if x < 1024 or u == units[-1]:
			return f"{x:,.1f} {u}"
		x /= 1024.0

def _truncate_middle(s: str, max_len: int) -> str:
	if max_len <= 0 or len(s) <= max_len:
		return s
	if max_len <= 3:
		return s[:max_len]
	keep = max_len - 1
	left = keep // 2
	right = keep - left
	return s[:left] + "…" + s[-right:]

def _render_list_table(rows: list[dict]) -> str:
	# Column layout (fixed widths); PATH uses the remainder of the terminal width.
	SID_W, TID_W, DIR_W, TYPE_W, STAT_W, PROG_W, RATE_W = 18, 12, 8, 6, 9, 24, 10
	PADDING = 1  # single space between columns
	fixed_w = SID_W + TID_W + DIR_W + TYPE_W + STAT_W + PROG_W + RATE_W + (PADDING * 7)  # + PATH later
	term_w = shutil.get_terminal_size((120, 20)).columns
	PATH_W = max(20, term_w - fixed_w)

	# Header
	hdr = (
		f"{brightblue}{'SID':<{SID_W}}{reset} "
		f"{brightblue}{'TID':<{TID_W}}{reset} "
		f"{brightblue}{'dir':<{DIR_W}}{reset} "
		f"{brightblue}{'type':<{TYPE_W}}{reset} "
		f"{brightblue}{'status':<{STAT_W}}{reset} "
		f"{brightblue}{'progress':<{PROG_W}}{reset} "
		f"{brightblue}{'rate':<{RATE_W}}{reset} "
		f"{brightblue}{'path':<{PATH_W}}{reset}"
	)
	underline = "-" * min(term_w, len(hdr))

	lines = [hdr, underline]

	for st in rows:
		sid     = st.get("sid","?")
		tid     = st.get("tid","?")
		dirn    = (st.get("direction") or "?").lower()
		ttype   = "FOLDER" if st.get("is_folder") else "FILE"
		status  = (st.get("status") or "?").lower()
		done    = int(st.get("bytes_done") or 0)
		total   = int(st.get("total_bytes") or 0)
		created = float(st.get("created_at") or 0.0)
		updated = float(st.get("updated_at") or created)
		elapsed = max(1e-6, updated - created)
		bps     = (done / elapsed) if elapsed > 0 else 0.0

		pct = (done/total*100.0) if total else 0.0
		prog = f"{pct:5.1f}% {human_bytes(done)}/{human_bytes(total)}"
		rate = _human_rate(bps) if done > 0 else ""

		# src → dst
		if dirn == "upload":
			src, dst = st.get("local_path",""), st.get("remote_path","")
		else:
			src, dst = st.get("remote_path",""), st.get("local_path","")
		path = _truncate_middle(f"{src} \u2192 {dst}", PATH_W)  # → arrow

		# Colorize a few bits
		sid_s = sid[:SID_W]
		tid_s = tid[:TID_W]
		dir_s = "upload" if dirn == "upload" else "download"
		stat_s = _status_color(status)

		line = (
			f"{sid_s:<{SID_W}} "
			f"{tid_s:<{TID_W}} "
			f"{dir_s:<{DIR_W}} "
			f"{ttype:<{TYPE_W}} "
			f"{stat_s:<{STAT_W}} "
			f"{prog:<{PROG_W}} "
			f"{rate:<{RATE_W}} "
			f"{path:<{PATH_W}}"
		)
		lines.append(line)

	return "\n".join(lines)

# ---------------- Public command functions (called from main.py) ----------------

def cmd_list(raw_sid: Optional[str] = None, *, to_console: bool = True, to_op: Optional[str] = None) -> bool:
	"""
	xfer list [-i SID]
	"""
	tm = TransferManager()
	sid: Optional[str] = None
	try:
		sid = _resolve_sid_or_none(raw_sid) if raw_sid else None
	except Exception:
		_emit(f"[!] Invalid session or alias: {raw_sid}", to_console, to_op, color=brightred, override_quiet=True)
		return False

	data = tm.list(sid).get("transfers", [])
	if not data:
		_emit("[*] No transfers.", to_console, to_op, color=brightyellow, override_quiet=True)
		return True

	# sort: interesting first (error/paused/running), then recency
	def _k(st):
		so = _STATUS_ORDER.get((st.get("status") or "").lower(), 9)
		# negative timestamp to get DESC while using ascending sort
		return (so, -(st.get("updated_at") or 0))
	data.sort(key=_k)

	table = _render_list_table(data)
	_emit(table, to_console, to_op, override_quiet=True)
	return True

	"""# Sorted stable list
	data.sort(key=lambda x: (x.get("sid", ""), x.get("tid", "")))

	for st in data:
		direction = (st.get("direction") or "?").lower()
		ftype     = "FOLDER" if st.get("is_folder") else "FILE"
		status    = st.get("status", "?")
		progress  = _fmt_progress(st)
		remote    = st.get("remote_path")
		local     = st.get("local_path")

		# Show the actual transfer direction:
		# - download: remote → local
		# - upload:   local  → remote
		if direction == "upload":
			src, dst = local, remote
		else:
			src, dst = remote, local

		_emit(f"{st.get('sid')} {st.get('tid')} {direction:<8} {ftype:<6} {status:<10} {progress}  {src} -> {dst}", to_console, to_op, override_quiet=True)
	return True"""


def cmd_status(tid_or_prefix: str, raw_sid: Optional[str] = None, *, to_console: bool = True, to_op: Optional[str] = None) -> bool:
	"""
	xfer status -t <tid|prefix> [-i SID]
	"""
	tm = TransferManager()
	sid_hint: Optional[str] = None
	try:
		sid_hint = _resolve_sid_or_none(raw_sid) if raw_sid else None
	except Exception:
		_emit(f"[!] Invalid session or alias: {raw_sid}", to_console, to_op, override_quiet=True)
		return False

	sid, st0 = _find_by_tid(tm, tid_or_prefix, sid_hint)
	if not sid or not st0:
		_emit(f"[!] Transfer not found for TID/prefix: {tid_or_prefix}", to_console, to_op, override_quiet=True)
		return False

	st = tm.status(sid, st0["tid"])
	if not st:
		_emit(f"[!] Unable to load status for {sid}:{st0['tid']}", to_console, to_op, override_quiet=True)
		return False

	"""_emit(_fmt_progress(st), to_console, to_op)
	_emit(
		f"  sid={st.get('sid')}  tid={st.get('tid')}  status={st.get('status')}\n"
		f"  dir={st.get('direction')}  folder={st.get('is_folder')}  chunks={st.get('total_chunks')}  "
		f"next={st.get('next_index')}  size={human_bytes(int(st.get('total_bytes') or 0))}\n"
		f"  remote={st.get('remote_path')}\n"
		f"  local={st.get('local_path')}",
		to_console, to_op
	)
	if st.get("error"):
		_emit(f"  error={st.get('error')}", to_console, to_op)"""

	_emit(_render_status_kv(st), to_console, to_op, override_quiet=True)
	return True


def cmd_resume(tid_or_prefix: str, raw_sid: Optional[str] = None, *, to_console: bool = True, to_op: Optional[str] = None, timeout: float = None) -> bool:
	"""
	xfer resume -t <tid|prefix> [-i SID]
	"""
	tm = TransferManager()
	sid_hint: Optional[str] = None
	try:
		sid_hint = _resolve_sid_or_none(raw_sid) if raw_sid else None
	except Exception:
		_emit(f"[!] Invalid session or alias: {raw_sid}", to_console, to_op, override_quiet=True)
		return False

	if sid_hint:
		session = session_manager.sessions[sid_hint]
		if session.transport.lower() in ("http", "https") and not timeout:
			_emit(f"You must specify a timeout for HTTP/HTTPS transfers (Use 2x your interval, 3x if jitter is big)", to_console, to_op, color=brightyellow, override_quiet=True)
			return False

	# 1) Does this TID/prefix exist anywhere?
	any_matches = _find_tid_anywhere(tm, tid_or_prefix)
	only, err = _first_match_or_ambiguous(any_matches)
	if err == "notfound":
		_emit(f"[!] Transfer not found for TID/prefix: {tid_or_prefix}", to_console, to_op, color=brightred, override_quiet=True)
		return False
	if err == "ambiguous":
		# Be explicit so the operator can pick the exact TID
		s = ", ".join(f"{m.get('sid')}:{m.get('tid')}" for m in any_matches)
		_emit(f"[!] Ambiguous TID/prefix. Matches: {s}", to_console, to_op, color=brightred, override_quiet=True)
		return False

	# 2) If user provided a SID, try to use it directly.
	sid, st0 = _find_by_tid(tm, tid_or_prefix, sid_hint)
	sid = _resolve_sid_or_none(sid) if sid else None
	if sid and st0:
		try:
			st = tm.store.load(sid, st0["tid"])
			tm._backfill_is_folder(st)
			tm.store.save(st)
		except Exception:
			pass
		ok = tm.resume(sid, st0["tid"], opts=TransferOpts(to_console=to_console, to_op=to_op), timeout=timeout)
		if ok:
			_emit(f"[*] Resuming TID={st0['tid']} for session {sid}", to_console, to_op, color=brightgreen, override_quiet=True)
			return True
		_emit(f"[!] Unable to resume TID={st0['tid']} (status may be final)", to_console, to_op, color=brightred, override_quiet=True)
		return False

	# 3) TID exists, but not under the provided SID (or no SID provided).
	current_sid = only.get("sid")
	real_tid    = only.get("tid")
	if not sid_hint:
		# Operator didn't specify -i → instruct to use -i to rebind
		_emit(f"[!] TID {real_tid} exists under session {current_sid}. "
			  f"Use -i <live_session_id> to rebind before resuming.", to_console, to_op, color=brightyellow, override_quiet=True)
		return False

	# 4) Rebind to the requested SID, then resume.
	#    We already validated sid_hint above; it's a concrete SID here.
	if current_sid != sid_hint:
		updated = _rebind_transfer(real_tid, current_sid, sid_hint)
		if not updated:
			_emit(f"[!] Failed to rebind {real_tid} from {current_sid} -> {sid_hint}", to_console, to_op, color=brightred, override_quiet=True)
			return False
		# Backfill FILE/FOLDER flag on the rebound state
		try:
			st = tm.store.load(sid_hint, real_tid)
			tm._backfill_is_folder(st)
			tm.store.save(st)
		except Exception:
			pass

		ok = tm.resume(sid_hint, real_tid, opts=TransferOpts(to_console=to_console, to_op=to_op), timeout=timeout)
		if ok:
			_emit(f"[*] Rebound and resuming TID={real_tid} for session {sid_hint}", to_console, to_op)
			return True
		_emit(f"[!] Unable to resume TID={real_tid} after rebind (status may be final)", to_console, to_op, override_quiet=True)
		return False

	# Safety fallback (shouldn’t reach here)
	_emit(f"[!] Internal error while resolving resume for {tid_or_prefix}", to_console, to_op, override_quiet=True)
	return False


def cmd_cancel(tid_or_prefix: str, raw_sid: Optional[str] = None, *, to_console: bool = True, to_op: Optional[str] = None) -> bool:
	"""
	xfer cancel -t <tid|prefix> [-i SID]
	"""
	tm = TransferManager()
	sid_hint: Optional[str] = None
	try:
		sid_hint = _resolve_sid_or_none(raw_sid) if raw_sid else None
	except Exception:
		_emit(f"[!] Invalid session or alias: {raw_sid}", to_console, to_op, override_quiet=True)
		return False

	sid, st0 = _find_by_tid(tm, tid_or_prefix, sid_hint)
	if not sid or not st0:
		_emit(f"[!] Transfer not found for TID/prefix: {tid_or_prefix}", to_console, to_op, override_quiet=True)
		return False

	ok = tm.cancel(sid, st0["tid"])
	if ok:
		_emit(f"[*] Cancelled TID={st0['tid']}", to_console, to_op, override_quiet=True)
		return True
	_emit(f"[!] Unable to cancel TID={st0['tid']}", to_console, to_op, override_quiet=True)
	return False

# --------------------- Xfer clear logic --------------------------------------------

def _store() -> StateStore:
	return StateStore()

def _tm() -> TransferManager:
	return TransferManager()

def _is_subpath(root: str, target: str) -> bool:
	root = os.path.abspath(root)
	target = os.path.abspath(target)
	return target == root or target.startswith(root + os.sep)

def _list_sids(base_dir: str):
	try:
		for name in os.listdir(base_dir):
			p = os.path.join(base_dir, name)
			if os.path.isdir(p):
				yield name
	except FileNotFoundError:
		return

def _list_tids(sid_dir: str):
	try:
		for name in os.listdir(sid_dir):
			p = os.path.join(sid_dir, name)
			if os.path.isdir(p):
				yield name
	except FileNotFoundError:
		return

def _expand_tid_prefixes(base_dir: str, prefixes: list[str]) -> list[tuple[str, str]]:
	"""
	Return (sid, tid) tuples for all tids that start with any prefix across all sids.
	"""
	matches: list[tuple[str, str]] = []
	seen = set()
	for sid in _list_sids(base_dir):
		sid_dir = os.path.join(base_dir, sid)
		for tid in _list_tids(sid_dir):
			for pref in prefixes:
				if tid.startswith(pref):
					key = (sid, tid)
					if key not in seen:
						matches.append(key)
						seen.add(key)
					break
	return matches

def _expand_sid_glob(base_dir: str, sid_pattern: str) -> list[str]:
	"""
	Match sessions by simple wildcard pattern against the on-disk store.
	"""
	out = []
	for sid in _list_sids(base_dir):
		if fnmatch.fnmatch(sid, sid_pattern):
			out.append(sid)
	return out

def _read_tids_file(path: str) -> list[str]:
	out = []
	try:
		with open(path, "r", encoding="utf-8", errors="ignore") as f:
			for line in f:
				line = line.strip()
				if not line or line.startswith("#"):
					continue
				# allow "sid tid" or just "tid"
				parts = line.split()
				out.append(parts[-1])
	except Exception:
		pass
	return out

def _cancel_if_running(sid: str, tid: str):
	"""
	If the transfer is still running, attempt to cancel it.
	"""
	store = _store()
	try:
		st = store.load(sid, tid)
	except Exception:
		return
	if getattr(st, "status", "").lower() == "running":
		try:
			_tm().cancel(sid, tid)
			# tiny wait to let the runner persist paused/cancelled state
			time.sleep(0.1)
		except Exception:
			pass

def clear_all(to_console=True, to_op=None) -> int:
	store = _store()
	base = store.base

	# 1) Collect all (sid, tid) targets up front so we don't race
	targets: list[tuple[str, str]] = []
	for sid in list(_list_sids(base)):
		sid_dir = os.path.join(base, sid)
		for tid in list(_list_tids(sid_dir)):
			targets.append((sid, tid))

	if not targets:
		echo("[+] Cleared 0 transfer(s).", to_console=to_console, to_op=to_op, world_wide=False)
		return 0

	# 2) Cancel any running transfers and remove their dirs
	removed = 0
	for sid, tid in targets:
		_cancel_if_running(sid, tid)
		tdir = os.path.join(base, sid, tid)
		# Only touch paths inside the store
		if _is_subpath(base, tdir) and os.path.isdir(tdir):
			try:
				shutil.rmtree(tdir)
			except Exception as e:
				echo(f"[!] Failed to remove {sid}/{tid}: {e}", to_console=to_console, to_op=to_op, world_wide=False)
		# Count as removed if it's gone now (handles races or pre-deleted dirs)
		if not os.path.exists(tdir):
			removed += 1

	# 3) Clean up any empty SID dirs
	for sid in list(_list_sids(base)):
		sid_dir = os.path.join(base, sid)
		try:
			if os.path.isdir(sid_dir) and not os.listdir(sid_dir):
				os.rmdir(sid_dir)
		except Exception:
			pass

	echo(f"[+] Cleared {removed} transfer(s).", to_console=to_console, to_op=to_op, world_wide=False)
	return removed

def clear_by_tids(tid_inputs: str, to_console=True, to_op=None) -> int:
	"""
	tid_inputs: comma-separated TIDs (full or unique prefixes).
	"""
	store = _store()
	base = store.base
	prefixes = [t.strip() for t in tid_inputs.split(",") if t.strip()]
	targets = _expand_tid_prefixes(base, prefixes)
	if not targets:
		echo("[*] No matching transfers for given TID(s)/prefix(es).", to_console=to_console, to_op=to_op, world_wide=False)
		return 0
	removed = 0
	for sid, tid in targets:
		_cancel_if_running(sid, tid)
		tdir = os.path.join(base, sid, tid)
		if _is_subpath(base, tdir) and os.path.isdir(tdir):
			try:
				shutil.rmtree(tdir)
				removed += 1
				echo(f"[-] Removed {sid}/{tid}", to_console=to_console, to_op=to_op, world_wide=False)
			except Exception as e:
				echo(f"[!] Failed to remove {sid}/{tid}: {e}", to_console=to_console, to_op=to_op, world_wide=False)
		# cleanup empty sid dir
		sdir = os.path.join(base, sid)
		try:
			if os.path.isdir(sdir) and not os.listdir(sdir):
				os.rmdir(sdir)
		except Exception:
			pass
	echo(f"[+] Cleared {removed} transfer(s).", to_console=to_console, to_op=to_op, world_wide=False)
	return removed

def clear_by_sid_pattern(sid_pattern: str, to_console=True, to_op=None) -> int:
	store = _store()
	base = store.base
	sids = _expand_sid_glob(base, sid_pattern)
	if not sids:
		echo("[*] No sessions matched that pattern in the local store.", to_console=to_console, to_op=to_op, world_wide=False)
		return 0
	removed = 0
	for sid in sids:
		sid_dir = os.path.join(base, sid)
		for tid in list(_list_tids(sid_dir)):
			_cancel_if_running(sid, tid)
			tdir = os.path.join(sid_dir, tid)
			if _is_subpath(base, tdir) and os.path.isdir(tdir):
				try:
					shutil.rmtree(tdir)
					removed += 1
					echo(f"[-] Removed {sid}/{tid}", to_console=to_console, to_op=to_op, world_wide=False)
				except Exception as e:
					echo(f"[!] Failed to remove {sid}/{tid}: {e}", to_console=to_console, to_op=to_op, world_wide=False)
		# cleanup empty sid dir
		try:
			if os.path.isdir(sid_dir) and not os.listdir(sid_dir):
				os.rmdir(sid_dir)
		except Exception:
			pass
	echo(f"[+] Cleared {removed} transfer(s) across {len(sids)} session(s).", to_console=to_console, to_op=to_op, world_wide=False)
	return removed

def clear_by_file(path: str, to_console=True, to_op=None) -> int:
	tids = _read_tids_file(path)
	if not tids:
		echo(f"[!] No TIDs found in file: {path}", to_console=to_console, to_op=to_op, world_wide=False)
		return 0
	# Reuse the comma-separated path to the same resolver
	return clear_by_tids(",".join(tids), to_console=to_console, to_op=to_op)

# ---- CLI entry used by main.py ----
def handle_clear(args, to_console=True, to_op=None):
	"""
	args supports: args.all (bool), args.t (str or None), args.i (str or None), args.f (str or None)
	Exactly one selector should be provided.
	"""
	selectors = sum([
		1 if getattr(args, "all", False) else 0,
		1 if getattr(args, "t", None) else 0,
		1 if getattr(args, "i", None) else 0,
		1 if getattr(args, "f", None) else 0,
	])
	if selectors != 1:
		print_help("xfer clear")
		return

	if getattr(args, "all", False):
		clear_all(to_console=to_console, to_op=to_op)
		return

	if getattr(args, "t", None):
		clear_by_tids(args.t, to_console=to_console, to_op=to_op)
		return

	if getattr(args, "i", None):
		clear_by_sid_pattern(args.i, to_console=to_console, to_op=to_op)
		return

	if getattr(args, "f", None):
		clear_by_file(args.f, to_console=to_console, to_op=to_op)
		return
