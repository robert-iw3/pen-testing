# gui/gunnershell_console.py
import os, html, re, time
from pathlib import Path
from html import escape as _esc

from PyQt5.QtWidgets import (
	QWidget, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout, QShortcut,
	QLabel, QFrame, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import QUrl, Qt, QPoint, QTimer, QRectF
from PyQt5.QtGui import (
	QKeySequence, QFont, QFontDatabase, QTextOption, QTextCursor, QColor, QPainter,
	QPen, QLinearGradient, QPainterPath, QIcon, QPixmap
)
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket

# Optional theme hook (safe fallback)
try:
	from theme_center import theme_color  # type: ignore
except Exception:
	def theme_color(_k, d): return d

# ─────────────────────────── Tiny icon helpers ───────────────────────────
def _make_play_icon(sz=16, col="#eaf2ff"):
	pm = QPixmap(sz, sz); pm.fill(Qt.transparent)
	p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)
	p.setBrush(QColor(col)); p.setPen(Qt.NoPen)
	path = QPainterPath(); path.moveTo(int(sz*0.30), int(sz*0.20))
	path.lineTo(int(sz*0.30), int(sz*0.80)); path.lineTo(int(sz*0.80), int(sz*0.50)); path.closeSubpath()
	p.drawPath(path); p.end(); return QIcon(pm)

def _make_dot_icon(sz=10, col="#22c55e"):
	pm = QPixmap(sz, sz); pm.fill(Qt.transparent)
	p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)
	p.setPen(Qt.NoPen); p.setBrush(QColor(col)); p.drawEllipse(0, 0, sz-1, sz-1); p.end()
	return QIcon(pm)

# ─────────────────────────── Fancy glass card ───────────────────────────
class _GlassCard(QFrame):
	def __init__(self, radius=14, parent=None):
		super().__init__(parent)
		self._r = radius
		self.setAttribute(Qt.WA_StyledBackground, True)
		self.setAutoFillBackground(False)
		sh = QGraphicsDropShadowEffect(self); sh.setBlurRadius(32); sh.setOffset(0, 14)
		sh.setColor(QColor(0, 0, 0, 160)); self.setGraphicsEffect(sh)

	def paintEvent(self, _):
		r = self.rect().adjusted(1, 1, -1, -1)
		rf = QRectF(r)
		p = QPainter(self); p.setRenderHint(QPainter.Antialiasing, True)

		# gradient glass
		g = QLinearGradient(rf.topLeft(), rf.bottomRight())
		g.setColorAt(0.0, QColor(theme_color("panel_grad_hi", "#121821")))
		g.setColorAt(1.0, QColor(theme_color("panel_grad_lo", "#0b0f14")))
		path = QPainterPath(); path.addRoundedRect(rf, float(self._r), float(self._r))
		p.fillPath(path, g)

		# faint top sheen
		top = QLinearGradient(rf.topLeft(), rf.topRight())
		top.setColorAt(0.0, QColor(255, 255, 255, 18)); top.setColorAt(1.0, QColor(255, 255, 255, 0))
		p.fillPath(path, top)

		# micro-grid (subtle)
		p.save(); p.setClipPath(path); p.setPen(QPen(QColor(255,255,255,10), 1))
		step = 24
		for x in range(r.left(), r.right(), step): p.drawLine(x, r.top(), x, r.bottom())
		for y in range(r.top(),  r.bottom(), step): p.drawLine(r.left(), y, r.right(), y)
		p.restore()

		# border
		p.setPen(QPen(QColor(theme_color("panel_border", "#243044")), 1)); p.drawPath(path); p.end()

# ─────────────────────────── ANSI → HTML (your mapper) ───────────────────────────
_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
_FG_NORMAL = {
	30:"#000000", 31:"#cc0000", 32:"#00a000", 33:"#c7a41c",
	34:"#1f6feb", 35:"#a000a0", 36:"#008b8b", 37:"#e6e6e6",
}
_FG_BRIGHT = {
	30:"#7f7f7f", 31:"#ff4d4d", 32:"#00ff44", 33:"#ffd75f",
	34:"#66b0ff", 35:"#ff7ad9", 36:"#00e5ff", 37:"#ffffff",
}
_FG_EXPLICIT = {
	90:"#9e9e9e", 91:"#ff5c5c", 92:"#00ff66", 93:"#ffe66d",
	94:"#66b0ff", 95:"#ff7ad9", 96:"#66f0ff", 97:"#ffffff",
}
_BG = {
	40:"#000000", 41:"#330000", 42:"#002b00", 43:"#332b00",
	44:"#001a33", 45:"#2b0033", 46:"#003333", 47:"#2b2b2b",
	100:"#4d4d4d",101:"#662222",102:"#226622",103:"#666622",
	104:"#224d66",105:"#662266",106:"#226666",107:"#aaaaaa",
}
def _xterm256(n: int) -> str:
	table = [
		"#000000","#800000","#008000","#808000","#000080","#800080","#008080","#c0c0c0",
		"#808080","#ff0000","#00ff00","#ffff00","#0000ff","#ff00ff","#00ffff","#ffffff"
	]
	if 0 <= n <= 15: return table[n]
	if 16 <= n <= 231:
		n -= 16; r = (n // 36) % 6; g = (n // 6) % 6; b = n % 6
		v = lambda x: 0 if x == 0 else 55 + x*40
		return f"#{v(r):02x}{v(g):02x}{v(b):02x}"
	if 232 <= n <= 255:
		v = 8 + (n - 232) * 10
		return f"#{v:02x}{v:02x}{v:02x}"
	return "#ffffff"

def _rgb(r,g,b):
	r = max(0, min(255, int(r))); g = max(0, min(255, int(g))); b = max(0, min(255, int(b)))
	return f"#{r:02x}{g:02x}{b:02x}"

def _style_from_state(state):
	parts = ["white-space: pre-wrap"]
	if state.get("fg"): parts.append(f"color:{state['fg']}")
	if state.get("bg"): parts.append(f"background:{state['bg']}")
	if state.get("bold"): parts += ["font-weight:700", "text-shadow:0 0 6px currentColor"]
	if state.get("underline"): parts.append("text-decoration: underline")
	return "; ".join(parts)

def ansi_to_html(s: str) -> str:
	s = s.replace("\x01","").replace("\x02","").replace("\r","")
	out, i, open_span = [], 0, False
	state = {"fg":None,"bg":None,"bold":False,"underline":False}
	for m in _ANSI_RE.finditer(s):
		if m.start() > i: out.append(html.escape(s[i:m.start()]).replace("\n","<br/>"))
		i = m.end()
		params = m.group(1)
		if params == "" or params == "0":
			if open_span: out.append("</span>"); open_span = False
			state = {"fg":None,"bg":None,"bold":False,"underline":False}; continue
		toks = [int(p) for p in params.split(";") if p != ""]
		j = 0
		while j < len(toks):
			code = toks[j]
			if code == 38 and j+4 < len(toks) and toks[j+1] == 2:
				state["fg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
			if code == 48 and j+4 < len(toks) and toks[j+1] == 2:
				state["bg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
			if code == 38 and j+2 < len(toks) and toks[j+1] == 5:
				state["fg"] = _xterm256(toks[j+2]); j += 3; continue
			if code == 48 and j+2 < len(toks) and toks[j+1] == 5:
				state["bg"] = _xterm256(toks[j+2]); j += 3; continue
			if code == 1: state["bold"] = True
			elif code == 22: state["bold"] = False
			elif code == 4:  state["underline"] = True
			elif code == 24: state["underline"] = False
			elif 30 <= code <= 37: state["fg"] = _FG_BRIGHT[code] if state["bold"] else _FG_NORMAL[code]
			elif 90 <= code <= 97: state["fg"] = _FG_EXPLICIT[code]
			elif code in _BG: state["bg"] = _BG[code]
			elif code == 39: state["fg"] = None
			elif code == 49: state["bg"] = None
			j += 1
		if open_span: out.append("</span>")
		out.append(f'<span style="{_style_from_state(state)}">'); open_span = True
	if i < len(s): out.append(html.escape(s[i:]).replace("\n","<br/>"))
	if open_span: out.append("</span>")
	return "".join(out)

def _ansi_default_state():
	return {"fg": None, "bg": None, "bold": False, "underline": False}

def ansi_to_html_stateful(s: str, state=None):
	"""
	Like ansi_to_html but takes a starting state and returns (html, new_state).
	It automatically opens a span for the incoming state so styles persist across lines.
	"""
	import copy, html as _html
	state = copy.deepcopy(state or _ansi_default_state())
	out, i, open_span = [], 0, False

	# if we already have style active, open it before any text
	if any((state.get("fg"), state.get("bg"), state.get("bold"), state.get("underline"))):
		out.append(f'<span style="{_style_from_state(state)}">')
		open_span = True

	for m in _ANSI_RE.finditer(s):
		if m.start() > i:
			out.append(_html.escape(s[i:m.start()]).replace("\n", "<br/>"))
		i = m.end()
		params = m.group(1)
		if params == "" or params == "0":
			if open_span:
				out.append("</span>"); open_span = False
			state = _ansi_default_state()
			continue

		toks = [int(p) for p in params.split(";") if p != ""]
		j = 0
		while j < len(toks):
			code = toks[j]
			if code == 38 and j+4 < len(toks) and toks[j+1] == 2:
				state["fg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
			if code == 48 and j+4 < len(toks) and toks[j+1] == 2:
				state["bg"] = _rgb(toks[j+2], toks[j+3], toks[j+4]); j += 5; continue
			if code == 38 and j+2 < len(toks) and toks[j+1] == 5:
				state["fg"] = _xterm256(toks[j+2]); j += 3; continue
			if code == 48 and j+2 < len(toks) and toks[j+1] == 5:
				state["bg"] = _xterm256(toks[j+2]); j += 3; continue

			if code == 1:  state["bold"] = True
			elif code == 22: state["bold"] = False
			elif code == 4:  state["underline"] = True
			elif code == 24: state["underline"] = False
			elif 30 <= code <= 37: state["fg"] = _FG_BRIGHT[code] if state["bold"] else _FG_NORMAL[code]
			elif 90 <= code <= 97: state["fg"] = _FG_EXPLICIT[code]
			elif code in _BG: state["bg"] = _BG[code]
			elif code == 39: state["fg"] = None
			elif code == 49: state["bg"] = None
			j += 1

		# close any open span and reopen with the new style
		if open_span:
			out.append("</span>")
		out.append(f'<span style="{_style_from_state(state)}">')
		open_span = True

	if i < len(s):
		out.append(_html.escape(s[i:]).replace("\n", "<br/>"))
	if open_span:
		out.append("</span>")
	return "".join(out), state

def _strip_non_sgr_escapes(s: str) -> str:
	"""Remove ANSI escapes that aren't SGR ('...m'), plus stray control chars."""
	out = []
	i, n = 0, len(s)
	while i < n:
		ch = s[i]
		if ch == "\x1b" and i + 1 < n:
			nxt = s[i + 1]
			if nxt == "[":  # CSI
				j = i + 2
				# scan to final byte 0x40–0x7E
				while j < n and not (0x40 <= ord(s[j]) <= 0x7E):
					j += 1
				if j < n:
					final = s[j]
					seq = s[i:j + 1]
					if final == "m":        # keep color/style sequences
						out.append(seq)
					# else: drop (K, H, G, etc.)
					i = j + 1
					continue
			elif nxt == "]":  # OSC: ESC ] ... BEL (or ST ESC \)
				j = i + 2
				while j < n and s[j] != "\x07":
					if s[j] == "\x1b" and j + 1 < n and s[j + 1] == "\\":
						j += 2
						break
					j += 1
				i = j + 1
				continue
		# drop other control chars except newline/carriage-return/tab
		if ord(ch) < 0x20 and ch not in ("\n", "\r", "\t"):
			i += 1
			continue
		out.append(ch)
		i += 1
	return "".join(out)

# ─────────────────────────── Command sets ───────────────────────────
COMMANDS = {
	"help","exit","list","gunnerid","banner","sessions","switch","shell","modhelp","run","search","bofexec",
	"ls","cat","type","cd","pwd","cp","mv","rmdir","checksum","upload","download","del","rm","mkdir","md",
	"touch","drives","edit",
	"netstat","ifconfig","portscan","portfwd","arp","hostname","socks","resolve","nslookup","route","getproxy","ipconfig",
	"sysinfo","ps","getuid","whoami","getprivs","groups","getav","defenderoff","amsioff","getpid","getenv","exec","kill",
	"getsid","clearev","localtime","reboot","pgrep","pkill","suspend","resume","shutdown","reg","services",
	"netusers","netgroups","steal_token",
	"screenshot",
	"winrm","netexec","nxc","rpcexec","wmiexec",
	"getusers","getgroups","getcomputers","getdomaincontrollers","getous","getdcs","getgpos","getdomain","gettrusts",
	"getforests","getfsmo","getpwpolicy","getdelegation","getadmins","getspns","kerbrute",
	"enumacls","dcsyncenum","enumrbcd","enumgmsa",
	"klist","asktgt","asreproast",
	"getintegrity","getuac","tokenprivs",
	"adduser","enablerdp",
	"getexclusions","getsecurity","driversigs","getsysmon","dumpsysmonconfig","killsysmon","checkdebuggers",
}
BOF_NAMES = {
	"dir","env","getpwpolicy","useridletime","getsessinfo","listmods","netlocalgroup","netloggedon","nettime","netuptime",
	"netuser","netuserenum","whoami","tasklist","cacls","enumdrives","enumdotnet","sc_enum","schtasksenum","schtasksquery",
	"getrecentfiles","enumlocalsessions","winver","locale","dotnetversion","listinstalled","getkernaldrivers","hotfixenum",
	"resources","getgpu","getcpu","getbios","arp","ipconfig","probe","listfwrules","listdns","netstat","openports",
	"routeprint","netview","netshares","noquotesvc","checkautoruns","hijackpath","enumcreds","enumautologons",
	"checkelevated","hivesave","hashdump","nanodump","credman","wifidump","dumpclip","dumpntlm","notepad","autologon",
	"ldapsearch","domaininfo","adadmins","adusers","adgroups","adcomputers","adtrusts","adous","adgpos","adspns","addns",
	"addelegations","adpasswords","adstaleusers","adcs_enum","adcs_enum_com","adcs_enum_com2","enumacls","dcsyncenum",
	"enumrbcd","enumgmsa","klist","asktgt","asreproast","getintegrity","getuac","tokenprivs","adduser","enablerdp",
	"getexclusions","getsecurity","driversigs","getsysmon","dumpsysmonconfig","killsysmon","checkdebuggers",
}

# ─────────────────────────── History line edit (premium UX) ───────────────────────────
class HistoryLineEdit(QLineEdit):
	"""Fast history: frozen-prefix browse, reverse-i-search, readline keys."""
	def __init__(self, history_path: str = None, parent=None):
		super().__init__(parent)
		self._hist: list[str] = []; self._idx: int = 0
		self._history_path = history_path
		self._complete_cb = None; self._cycle_state = None
		self.setFocusPolicy(Qt.StrongFocus); self._load()

		# browse state
		self._browsing = False; self._browse_origin_text = ""; self._browse_origin_cursor = 0

		# kill ring
		self._kill_buf = ""; self._last_cmd_was_kill = False

		# reverse-i-search
		self._ris_active = False; self._ris_query = ""; self._ris_idx = -1; self._ris_saved_text = ""
		self._ris_popup = QFrame(self.window(), Qt.ToolTip | Qt.FramelessWindowHint)
		self._ris_popup.setAttribute(Qt.WA_ShowWithoutActivating)
		self._ris_popup.setStyleSheet("QFrame{background:#1f232b;color:#e6e6e6;border:1px solid #3b404a;border-radius:6px;} QLabel{padding:4px 6px;}")
		self._ris_label = QLabel("", self._ris_popup); self._ris_popup.hide()
		self._sc_r_prev = QShortcut(QKeySequence("Ctrl+R"), self); self._sc_r_prev.setContext(Qt.WidgetShortcut)
		self._sc_r_prev.activated.connect(lambda: (self._ris_start() if not self._ris_active else self._ris_step(-1)))
		self._sc_r_next = QShortcut(QKeySequence("Ctrl+S"), self); self._sc_r_next.setContext(Qt.WidgetShortcut)
		self._sc_r_next.activated.connect(lambda: (self._ris_start() if not self._ris_active else self._ris_step(+1)))

		# typing exits browse
		self.textEdited.connect(lambda *_: self._exit_browse())

	def focusNextPrevChild(self, next: bool) -> bool:
		# keep Tab/Shift+Tab inside the line edit for completion
		return False

	# persistence
	def _load(self):
		try:
			if self._history_path and os.path.exists(self._history_path):
				with open(self._history_path, "r", encoding="utf-8", errors="ignore") as f:
					self._hist = [ln.rstrip("\n") for ln in f if ln.strip()]
			self._idx = len(self._hist)
		except Exception:
			pass
	def _flush(self):
		try:
			if not self._history_path: return
			Path(self._history_path).parent.mkdir(parents=True, exist_ok=True)
			with open(self._history_path, "w", encoding="utf-8") as f:
				f.write("\n".join(self._hist) + ("\n" if self._hist else ""))
		except Exception:
			pass
	def remember(self, cmd: str):
		if not cmd: return
		if self._hist and self._hist[-1] == cmd:
			self._idx = len(self._hist); return
		self._hist.append(cmd)
		if len(self._hist) > 2000: self._hist = self._hist[-2000:]
		self._idx = len(self._hist); self._flush()
	def set_complete_callback(self, fn): self._complete_cb = fn

	# helpers
	def _kill_range(self, a, b):
		if a > b: a, b = b, a
		s = self.text(); killed = s[a:b]
		if not killed: self._last_cmd_was_kill = False; return
		self._kill_buf = (self._kill_buf + killed) if self._last_cmd_was_kill else killed
		self.setText(s[:a] + s[b:]); self.setCursorPosition(a); self._last_cmd_was_kill = True
	def _word_left(self, pos):
		s = self.text(); i = max(0, pos)
		while i > 0 and s[i-1].isspace(): i -= 1
		while i > 0 and not s[i-1].isspace(): i -= 1
		return i
	def _word_right(self, pos):
		s = self.text(); n = len(s); i = min(n, pos)
		while i < n and s[i].isspace(): i += 1
		while i < n and not s[i].isspace(): i += 1
		return i
	def _hist_seek_prev_with_prefix(self, prefix, start_idx):
		for i in range(min(start_idx, len(self._hist)) - 1, -1, -1):
			if self._hist[i].startswith(prefix): return i
		return -1
	def _hist_seek_next_with_prefix(self, prefix, start_idx):
		for i in range(max(0, start_idx + 1), len(self._hist)):
			if self._hist[i].startswith(prefix): return i
		return -1

	# reverse-i-search
	@staticmethod
	def _subseq_score(q, s):
		q = q.lower(); t = s.lower()
		if not q: return 1
		if q in t: return 1000 - t.index(q) - (len(t) - len(q))
		it = iter(t); ok = all(ch in it for ch in q)
		return 100 if ok else -1
	def _ris_recompute(self, direction=-1):
		if not self._hist: self._ris_idx = -1; self._ris_update_popup(); return
		i = self._ris_idx if self._ris_idx >= 0 else len(self._hist)
		best = (-1, -1)
		rng = range(i - 1, -1, -1) if direction < 0 else range(i + 1, len(self._hist), 1)
		for k in rng:
			sc = self._subseq_score(self._ris_query, self._hist[k])
			if sc > best[0]:
				best = (sc, k)
				if sc >= 900: break
		self._ris_idx = best[1]; self._ris_update_popup()
	def _ris_update_popup(self):
		if not self._ris_active: self._ris_popup.hide(); return
		idx_ok = 0 <= self._ris_idx < len(self._hist)
		match_txt = (self._hist[self._ris_idx] if idx_ok else ("no history" if not self._hist else "no match"))
		self._ris_label.setText(f"reverse-i-search: “{_esc(self._ris_query)}” → {_esc(match_txt)}")
		self._ris_label.adjustSize()
		w = self._ris_label.sizeHint().width() + 12; h = self._ris_label.sizeHint().height() + 8
		self._ris_popup.resize(w, h)
		base = self.mapToGlobal(QPoint(0, self.height())); self._ris_popup.move(base + QPoint(6, 6)); self._ris_popup.show()
	def _ris_start(self):
		self._ris_active = True; self._ris_saved_text = self.text(); self._ris_query = ""; self._ris_idx = -1; self._ris_update_popup()
	def _ris_accept(self):
		if self._ris_idx >= 0:
			self.setText(self._hist[self._ris_idx]); self.setCursorPosition(len(self.text()))
		self._ris_cancel(hide_only=True)
	def _ris_step(self, delta):
		if not self._ris_active: return
		self._ris_recompute(+1 if delta > 0 else -1)
	def _ris_cancel(self, hide_only=False):
		if not hide_only:
			self.setText(self._ris_saved_text); self.setCursorPosition(len(self.text()))
		self._ris_active = False; self._ris_popup.hide()
	def resizeEvent(self, ev):
		super().resizeEvent(ev)
		if self._ris_active: self._ris_update_popup()

	# browse helpers
	def _exit_browse(self):
		if self._browsing and not self._ris_active:
			self._browsing = False; self._idx = len(self._hist)
	def _orig_prefix(self):
		return (self._browse_origin_text[:self._browse_origin_cursor]
				if self._browsing else self.text()[:self.cursorPosition()])

	# keys
	def keyPressEvent(self, e):
		# completion first (Tab / Shift+Tab)
		if e.key() in (Qt.Key_Tab, Qt.Key_Backtab):
			if self._complete_cb:
				reverse = (e.key() == Qt.Key_Backtab)
				new_text, new_pos, self._cycle_state = self._complete_cb(
					self.text(), self.cursorPosition(), reverse, self._cycle_state
				)
				if new_text is not None:
					self.setText(new_text);
					if new_pos is not None: self.setCursorPosition(new_pos)
			e.accept(); return
		else:
			self._cycle_state = None

		# ris quick actions
		if self._ris_active and e.key() == Qt.Key_Escape: self._ris_cancel(); e.accept(); return
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R: self._ris_start(); e.accept(); return

		if self._ris_active:
			if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R: self._ris_recompute(-1); e.accept(); return
			if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_S: self._ris_recompute(+1); e.accept(); return
			if e.key() in (Qt.Key_Return, Qt.Key_Enter): self._ris_accept(); e.accept(); return
			if e.key() == Qt.Key_Backspace:
				self._ris_query = self._ris_query[:-1]; self._ris_idx = len(self._hist); self._ris_recompute(-1); e.accept(); return
			txt = e.text()
			if txt and not (e.modifiers() & (Qt.ControlModifier | Qt.AltModifier | Qt.MetaModifier)):
				self._ris_query += txt; self._ris_idx = len(self._hist); self._ris_recompute(-1); e.accept(); return
			e.accept(); return

		# readline
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_A: self.setCursorPosition(0); e.accept(); return
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_K:
			cp = self.cursorPosition(); self._kill_range(cp, len(self.text())); e.accept(); return
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_U:
			cp = self.cursorPosition(); self._kill_range(0, cp); e.accept(); return
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_W:
			cp = self.cursorPosition(); self._kill_range(self._word_left(cp), cp); e.accept(); return
		if (e.modifiers() & Qt.AltModifier) and e.key() == Qt.Key_D:
			cp = self.cursorPosition(); self._kill_range(cp, self._word_right(cp)); e.accept(); return
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_Y:
			if self._kill_buf:
				cp = self.cursorPosition(); s = self.text()
				self.setText(s[:cp] + self._kill_buf + s[cp:]); self.setCursorPosition(cp + len(self._kill_buf))
			self._last_cmd_was_kill = False; e.accept(); return
		self._last_cmd_was_kill = False

		# history Up/Down with frozen prefix + fallback
		if e.key() == Qt.Key_Up:
			if not self._hist: e.accept(); return
			if not self._browsing:
				self._browsing = True; self._browse_origin_text = self.text(); self._browse_origin_cursor = self.cursorPosition()
				self._idx = len(self._hist)
			pfx = self._orig_prefix()
			if pfx:
				j = self._hist_seek_prev_with_prefix(pfx, self._idx)
				if j >= 0:
					self._idx = j; self.setText(self._hist[self._idx]); self.setCursorPosition(len(self.text())); e.accept(); return
			if self._idx > 0:
				self._idx -= 1; self.setText(self._hist[self._idx]); self.setCursorPosition(len(self.text()))
			e.accept(); return

		if e.key() == Qt.Key_Down:
			if not self._browsing: e.accept(); return
			pfx = self._orig_prefix()
			if pfx:
				j = self._hist_seek_next_with_prefix(pfx, self._idx if self._idx < len(self._hist) else len(self._hist)-1)
				if j >= 0:
					self._idx = j; self.setText(self._hist[self._idx]); self.setCursorPosition(len(self.text())); e.accept(); return
			if self._idx < len(self._hist) - 1:
				self._idx += 1; self.setText(self._hist[self._idx]); self.setCursorPosition(len(self.text())); e.accept(); return
			# end → restore original and exit
			self._browsing = False; self._idx = len(self._hist)
			self.setText(self._browse_origin_text); self.setCursorPosition(len(self.text())); e.accept(); return

		super().keyPressEvent(e)

# ─────────────────────────── Premium Gunnershell console ───────────────────────────
class GunnershellConsole(QWidget):
	def __init__(self, api, sid: str, hostname: str):
		super().__init__()
		self.api = api; self.sid = sid; self.hostname = hostname

		# state
		self._show_time = True
		self._autoscroll = True
		self._at_line_start = True  # <— NEW: are we at the start of a terminal line?
		self._ansi_state = _ansi_default_state()

		# outer card
		card = _GlassCard(radius=14, parent=self)
		lay = QVBoxLayout(card); lay.setContentsMargins(14,14,14,14); lay.setSpacing(10)

		# header
		self.title = QLabel(f"GS — {hostname}")
		self.title.setObjectName("GSTitle")
		self.title.setStyleSheet("QLabel#GSTitle{font-size:16.5pt;font-weight:600;color:#eaf2ff;letter-spacing:0.3px;}")
		self.badge = QLabel(f"SID: {sid}")
		self.badge.setObjectName("Badge")
		self.badge.setStyleSheet("QLabel#Badge{color:#cfe3ff;background:rgba(63,134,255,0.11);border:1px solid #2b3c5c;border-radius:9px;padding:2px 8px;font-size:9.5pt;}")

		self.status = QPushButton(); self.status.setEnabled(False); self.status.setFlat(True)
		self.status.setObjectName("StatusBtn")
		self.status.setIcon(_make_dot_icon(10, "#f59e0b")); self.status.setText(" Connecting…")
		self.status.setStyleSheet("QPushButton#StatusBtn{color:#cbd5e1;border:none;padding:0 4px;font-size:9.5pt;}")

		# toolbar buttons
		self.btn_wrap  = QPushButton("Wrap");        self._style_pill(self.btn_wrap,  checkable=True, checked=False)
		self.btn_time  = QPushButton("Timestamps");  self._style_pill(self.btn_time,  checkable=True, checked=True)
		self.btn_lock  = QPushButton("Scroll-lock"); self._style_pill(self.btn_lock,  checkable=True, checked=False)
		self.btn_copy  = QPushButton("Copy all");    self._style_pill(self.btn_copy)
		self.btn_clear = QPushButton("Clear");       self._style_pill(self.btn_clear)

		hdrL = QHBoxLayout(); hdrL.setSpacing(10)
		hdrL.addWidget(self.title); hdrL.addWidget(self.badge); hdrL.addSpacing(6); hdrL.addWidget(self.status); hdrL.addStretch(1)
		hdrR = QHBoxLayout(); hdrR.setSpacing(8)
		for b in (self.btn_wrap, self.btn_time, self.btn_lock, self.btn_copy, self.btn_clear): hdrR.addWidget(b)
		hdr = QHBoxLayout(); hdr.addLayout(hdrL, 1); hdr.addLayout(hdrR, 0)
		lay.addLayout(hdr)

		# output (HTML)
		self.out = QTextEdit(); self.out.setReadOnly(True); self.out.setLineWrapMode(QTextEdit.NoWrap)
		self.out.document().setMaximumBlockCount(4000)
		mono = QFont("JetBrains Mono"); mono.setStyleHint(QFont.Monospace); mono.setPointSize(10)
		try: mono.setStyleStrategy(QFont.NoFontMerging)
		except Exception: pass
		self.out.setFont(mono); self.out.setWordWrapMode(QTextOption.NoWrap)
		self.out.setStyleSheet("QTextEdit{background:transparent;color:#dce3ea;selection-background-color:#314e86;selection-color:#eaf2ff;border:none;}")
		lay.addWidget(self.out, 1)

		self._at_line_start = True  # are we currently at column 0?

		# compact “smart hints” strip (chips shown while typing)
		self.hints = QLabel(""); self.hints.setObjectName("HintChips")
		self.hints.setStyleSheet(
			"QLabel#HintChips{border:none;color:#a9b6c8;}"
		)
		lay.addWidget(self.hints)

		# command bar
		bar = QHBoxLayout(); bar.setSpacing(8)
		self.prompt = QLabel("❯"); self.prompt.setObjectName("PromptGlyph"); self.prompt.setAlignment(Qt.AlignCenter)
		self.prompt.setFixedWidth(26)
		self.prompt.setStyleSheet("QLabel#PromptGlyph{font:12pt 'JetBrains Mono','Fira Code','Consolas','Menlo';color:#cfe3ff;background:rgba(63,134,255,0.18);border:1px solid #2b3c5c;border-radius:9px;}")
		hist_path = str(Path.home() / f".gunnerc2_gs_{sid}_history")
		self.inp = HistoryLineEdit(history_path=hist_path)
		self._style_input(self.inp)
		self.btn_send = QPushButton(" Send"); self.btn_send.setIcon(_make_play_icon(16, "#eaf2ff"))
		self.btn_send.setObjectName("SendBtn"); self.btn_send.setCursor(Qt.PointingHandCursor); self.btn_send.setMinimumHeight(38)
		self.btn_send.setStyleSheet(
			"QPushButton#SendBtn{background:#2b6af1;border:1px solid #3c78f5;color:white;border-radius:10px;padding:8px 14px;font-weight:600;}"
			"QPushButton#SendBtn:hover{background:#3b7bff;border-color:#4b86ff;}"
			"QPushButton#SendBtn:pressed{background:#2a62db;}"
		)
		bar.addWidget(self.prompt, 0); bar.addWidget(self.inp, 1); bar.addWidget(self.btn_send, 0)
		lay.addLayout(bar)

		root = QVBoxLayout(self); root.setContentsMargins(10,10,10,10); root.addWidget(card)

		# wiring
		self.btn_send.clicked.connect(self._send)
		self.inp.returnPressed.connect(self._send)
		self.btn_clear.clicked.connect(self._clear_screen)
		self.btn_copy.clicked.connect(self._copy_all)
		self.btn_wrap.toggled.connect(lambda on: self.out.setLineWrapMode(QTextEdit.WidgetWidth if on else QTextEdit.NoWrap))
		self.btn_time.toggled.connect(lambda on: setattr(self, "_show_time", on))
		self.btn_lock.toggled.connect(lambda on: setattr(self, "_autoscroll", not on))
		self.inp.textEdited.connect(self._update_hints)

		# Ctrl+L clear
		self._sc_clear = QShortcut(QKeySequence("Ctrl+L"), self)
		self._sc_clear.setContext(Qt.WidgetWithChildrenShortcut); self._sc_clear.activated.connect(self._clear_screen)

		# completion
		self._cmd_set = set(COMMANDS); self._bof_set = set(BOF_NAMES)
		self.inp.set_complete_callback(self._tab_complete)

		# websocket
		ws_url = self.api.base_url.replace("http", "ws", 1) + f"/ws/gunnershell/{sid}?token={self.api.token}"
		self.ws = QWebSocket()

		def _on_ws_error(*args):
			try:
				enum = args[0] if args else None
				name = (QAbstractSocket.SocketError(enum).name if isinstance(enum, int) else str(enum))
				self._append_html(f'<span style="color:#ff5f5f"><b>[websocket error]</b> {html.escape(name)}</span>', add_br=True)
			except Exception:
				self._append_html(f'<span style="color:#ff5f5f"><b>[websocket error]</b></span>', add_br=True)
			self._set_connected(False)

		if hasattr(self.ws, "errorOccurred"): self.ws.errorOccurred.connect(_on_ws_error)
		elif hasattr(self.ws, "error"):       self.ws.error.connect(_on_ws_error)

		self.ws.connected.connect(lambda: self._set_connected(True))
		self.ws.disconnected.connect(lambda: self._set_connected(False))
		self.ws.textMessageReceived.connect(self._on_msg)
		self.ws.open(QUrl(ws_url))

	# ─────────────── Styling helpers
	def _style_pill(self, btn: QPushButton, *, checkable=False, checked=False):
		btn.setObjectName("Pill"); btn.setCheckable(checkable)
		if checkable: btn.setChecked(checked)
		btn.setCursor(Qt.PointingHandCursor); btn.setMinimumHeight(30)
		btn.setStyleSheet(
			"QPushButton#Pill{color:#cfd8e3;background:rgba(14,20,28,0.6);border:1px solid #2a3446;border-radius:10px;padding:6px 10px;}"
			"QPushButton#Pill:hover{border-color:#3b82f6;}"
			"QPushButton#Pill:checked{background:rgba(40,76,140,0.35);border-color:#3b82f6;color:#eaf2ff;}"
		)
	def _style_input(self, le: QLineEdit):
		f = QFont("JetBrains Mono"); f.setStyleHint(QFont.Monospace); f.setPointSize(10); le.setFont(f)
		le.setMinimumHeight(38)
		le.setStyleSheet(
			"QLineEdit{color:#eaf2ff;background:rgba(10,14,20,0.65);border:1px solid #2b3c5c;border-radius:10px;padding:8px 10px;"
			"selection-background-color:#3b82f6;selection-color:white;}"
			"QLineEdit:focus{border-color:#4b86ff;background:rgba(14,20,28,0.75);}"
		)

	# ─────────────── Connection state
	def _set_connected(self, ok: bool):
		self.inp.setEnabled(ok); self.btn_send.setEnabled(ok)
		self.status.setIcon(_make_dot_icon(10, "#22c55e" if ok else "#ef4444"))
		self.status.setText(" Connected" if ok else " Disconnected")

	# ─────────────── Output helpers
	def _with_scroll_guard(self, write_callable):
		vsb = self.out.verticalScrollBar(); hsb = self.out.horizontalScrollBar()
		v, h = vsb.value(), hsb.value()
		write_callable()
		if self._autoscroll:
			vsb.setValue(vsb.maximum())
		else:
			vsb.setValue(v); hsb.setValue(h)

	def _append_html(self, html_str: str, *, add_br: bool = False, ensure_newline_before: bool = False):
		def _write():
			cur = self.out.textCursor()
			cur.movePosition(QTextCursor.End)

			# if previous output didn't end with a newline, force one
			if ensure_newline_before and not self._at_line_start:
				cur.insertHtml("<br/>")
				self._at_line_start = True

			cur.insertHtml(html_str)

			if add_br:
				cur.insertHtml("<br/>")
				self._at_line_start = True
			else:
				self._at_line_start = False

			self.out.setTextCursor(cur)
			self.out.ensureCursorVisible()
		self._with_scroll_guard(_write)

	def _append_ansi(self, s: str):
		s = s.replace("\r\n", "\n")
		parts = re.split("(\n|\r)", s)  # keep delimiters

		out = []
		for tok in parts:
			if tok == "\n":
				out.append("<br/>"); self._at_line_start = True; continue
			if tok == "\r":
				out.append("<br/>"); self._at_line_start = True; continue
			if not tok:
				continue

			# timestamp only at real line starts with some content
			if self._show_time and self._at_line_start and tok.strip():
				out.append(f'<span style="color:#7aa2ff">{html.escape(time.strftime("[%H:%M:%S] "))}</span>')

			seg = tok.replace("\n", "").replace("\r", "")
			seg = _strip_non_sgr_escapes(seg)
			html_seg, self._ansi_state = ansi_to_html_stateful(seg, self._ansi_state)
			out.append(html_seg)
			self._at_line_start = False  # we just wrote content

		self._append_html("".join(out), add_br=False)

	def _clear_screen(self):
		self.out.clear()
		self._at_line_start = True
		self._ansi_state = _ansi_default_state()   # ← reset colors/styles

	def _copy_all(self):
		self.out.selectAll(); self.out.copy()
		txt = self.status.text(); self.status.setText(" Copied ✔"); QTimer.singleShot(750, lambda: self.status.setText(txt))

	# ─────────────── WS + input
	def _on_msg(self, msg: str):
		if msg == "\x00CLEAR\x00": self._clear_screen(); return
		self._append_ansi(msg)

	# suggestions (chips below the output)
	def _update_hints(self, _txt: str):
		text = self.inp.text()
		start, end = self._token_bounds(text, self.inp.cursorPosition())
		prefix = text[start:self.inp.cursorPosition()]
		head = text[:start].lstrip()
		matches = []
		if not head:
			matches = [c for c in self._cmd_set if c.lower().startswith(prefix.lower())][:8]
		elif head.startswith("bofexec ") and len(head.split()) == 1:
			matches = [b for b in self._bof_set if b.lower().startswith(prefix.lower())][:8]
		chips = " ".join(f'<span style="border:1px solid #2a3b5a;background:rgba(63,134,255,0.10);'
						 f'border-radius:8px;padding:2px 8px;margin-right:4px;color:#cfe3ff">{_esc(m)}</span>'
						 for m in matches)
		self.hints.setText(chips)

	# Tab completion core (kept from your original, slightly tucked in)
	@staticmethod
	def _lcp(strings):
		if not strings: return ""
		s1, s2 = min(strings), max(strings); i = 0
		for a, b in zip(s1, s2):
			if a.lower() != b.lower(): break
			i += 1
		return s1[:i]
	def _token_bounds(self, text: str, cursor: int):
		seps = " \t;|&"; start = cursor
		while start > 0 and text[start-1] not in seps: start -= 1
		end = cursor
		while end < len(text) and text[end] not in seps: end += 1
		return start, end
	def _suggest(self, head: str, prefix: str):
		hs = head.lstrip()
		if hs.startswith("bofexec "):
			parts = hs.split()
			if len(parts) == 1:
				return sorted([b for b in BOF_NAMES if b.lower().startswith(prefix.lower())], key=str.lower)
			return []
		if len(hs) == 0:
			return sorted([c for c in COMMANDS if c.lower().startswith(prefix.lower())], key=str.lower)
		return []
	def _tab_complete(self, text: str, cursor_pos: int, reverse: bool, cycle_state):
		start, end = self._token_bounds(text, cursor_pos)
		prefix = text[start:cursor_pos]; head = text[:start]; tail = text[end:]
		state = cycle_state or {}; recompute = (not state) or state.get("prefix") != prefix or state.get("start") != start
		if recompute:
			matches = self._suggest(head, prefix)
			if not matches: return (None, None, None)
			lcp = self._lcp(matches)
			if lcp and lcp.lower() != prefix.lower():
				new = head + lcp + tail; pos = start + len(lcp)
				return (new, pos, {"prefix": lcp, "matches": matches, "i": 0, "start": start})
			idx = -1
		else:
			matches = state.get("matches", []); idx = state.get("i", -1)
		if not matches: return (None, None, None)
		step = -1 if reverse else 1; idx = (idx + step) % len(matches); choice = matches[idx]
		new_text = head + choice + tail; new_pos = start + len(choice)
		return (new_text, new_pos, {"prefix": choice, "matches": matches, "i": idx, "start": start})

	def _send(self):
		text = self.inp.text().strip()
		if not text: return
		if self.ws.state() != QAbstractSocket.ConnectedState:
			self._append_html('<span style="color:#ffb4b4">[not connected]</span>'); return

		self.inp.remember(text)
		self._append_html(
			f'<span style="color:#62a0ea;font-weight:600">&gt;&gt;&gt;</span> '
			f'<span style="color:#cfcfcf">{html.escape(text)}</span>',
			add_br=True,
			ensure_newline_before=True,   # ← key line
		)
		try:
			self.ws.sendTextMessage(text)
		except Exception:
			self._append_html('<span style="color:#ff5f5f">[send failed]</span>')
		self.inp.clear()
