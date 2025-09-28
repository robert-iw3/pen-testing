# gui/session_console.py
import os
import time
from pathlib import Path
from html import escape as _esc

from PyQt5.QtWidgets import (
	QWidget, QPlainTextEdit, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout,
	QShortcut, QLabel, QFrame, QGraphicsDropShadowEffect, QSizePolicy
)
from PyQt5.QtCore import QUrl, Qt, pyqtSignal, QPoint, QTimer, QSize, QRect, QRectF
from PyQt5.QtGui import QKeySequence, QFont, QColor, QPainter, QPen, QLinearGradient, QPainterPath, QTextCursor, QIcon, QPixmap, QTextFormat
from PyQt5.QtNetwork import QAbstractSocket
from PyQt5.QtWebSockets import QWebSocket

# Optional theme hook (falls back gracefully)
try:
	from theme_center import theme_color, ThemeManager   # type: ignore
except Exception:
	def theme_color(_k, d): return d
	class ThemeManager:
		@staticmethod
		def instance(): return ThemeManager()
		def themeChanged(self, *a, **k): pass

# ---------- tiny icon helpers (vector-ish, no external assets) ----------
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

# ===================== console line edit with history (unchanged, polished) ============================
class _ConsoleHistoryLineEdit(QLineEdit):
	"""Snappy history with prefix browse, reverse-i-search, and debounced persistence."""
	def __init__(self, history_path: str = None, parent=None):
		super().__init__(parent)
		self._hist: list[str] = []
		self._idx: int = 0                 # points *between* items; len(_hist) == “after last”
		self._history_path = history_path
		self.setFocusPolicy(Qt.StrongFocus)
		self._load()

		# ---- browsing state (Up/Down) ----
		self._browsing: bool = False
		self._browse_origin_text: str = ""
		self._browse_origin_cursor: int = 0

		# ---- Kill ring ----
		self._kill_buf: str = ""
		self._last_cmd_was_kill: bool = False

		# ---- reverse-i-search UI/state ----
		self._ris_active = False
		self._ris_query = ""
		self._ris_idx = -1
		self._ris_saved_text = ""
		self._ris_popup = QFrame(self, Qt.ToolTip | Qt.FramelessWindowHint)
		self._ris_popup.setAttribute(Qt.WA_ShowWithoutActivating)
		self._ris_popup.setStyleSheet(
			"QFrame{background:#1f232b;color:#e6e6e6;border:1px solid #3b404a;border-radius:6px;}"
			"QLabel{padding:4px 6px;}"
		)
		self._ris_label = QLabel("", self._ris_popup)
		self._ris_popup.hide()

		# Debounced disk flush
		self._flush_timer = QTimer(self)
		self._flush_timer.setSingleShot(True)
		self._flush_timer.setInterval(600)
		self._flush_timer.timeout.connect(self._flush)
		self.textEdited.connect(self._exit_browse_if_typing)
		self.destroyed.connect(lambda *_: self._flush_immediate())

	def focusNextPrevChild(self, next: bool) -> bool:  # keep Tab in the line edit
		return False

	# ---------- persistence ----------
	def _load(self):
		try:
			if self._history_path and os.path.exists(self._history_path):
				with open(self._history_path, "r", encoding="utf-8", errors="ignore") as f:
					self._hist = [ln.rstrip("\n") for ln in f if ln.strip()]
			self._idx = len(self._hist)
		except Exception:
			self._hist = []; self._idx = 0

	def _flush_immediate(self):
		try:
			if not self._history_path:
				return
			Path(self._history_path).parent.mkdir(parents=True, exist_ok=True)
			with open(self._history_path, "w", encoding="utf-8") as f:
				f.write("\n".join(self._hist) + ("\n" if self._hist else ""))
		except Exception:
			pass

	def _flush(self):
		# timer targets this; keep it small and fast
		self._flush_immediate()

	def _schedule_flush(self):
		self._flush_timer.start()

	def remember(self, cmd: str):
		"""Append a command to history (dedup adjacent, cap length, debounce flush)."""
		if not cmd:
			return
		if self._hist and self._hist[-1] == cmd:
			self._idx = len(self._hist)
			return
		self._hist.append(cmd)
		MAX = 2000
		if len(self._hist) > MAX:
			self._hist = self._hist[-MAX:]
		self._idx = len(self._hist)
		self._schedule_flush()

	# ---------- helpers: kill ring ----------
	def _kill_range(self, a: int, b: int):
		if a > b: a, b = b, a
		s = self.text(); killed = s[a:b]
		if not killed:
			self._last_cmd_was_kill = False; return
		if self._last_cmd_was_kill: self._kill_buf += killed
		else: self._kill_buf = killed
		self.setText(s[:a] + s[b:]); self.setCursorPosition(a); self._last_cmd_was_kill = True

	def _word_left(self, pos: int) -> int:
		s = self.text(); i = max(0, pos)
		while i > 0 and s[i-1].isspace(): i -= 1
		while i > 0 and not s[i-1].isspace(): i -= 1
		return i

	def _word_right(self, pos: int) -> int:
		s = self.text(); n = len(s); i = min(n, pos)
		while i < n and s[i].isspace(): i += 1
		while i < n and not s[i].isspace(): i += 1
		return i

	# ---------- prefix navigation ----------
	def _hist_seek_prev_with_prefix(self, prefix: str, start_idx: int) -> int:
		for i in range(min(start_idx, len(self._hist)) - 1, -1, -1):
			if self._hist[i].startswith(prefix): return i
		return -1

	def _hist_seek_next_with_prefix(self, prefix: str, start_idx: int) -> int:
		for i in range(max(0, start_idx + 1), len(self._hist)):
			if self._hist[i].startswith(prefix): return i
		return -1

	def _orig_prefix(self) -> str:
		# While browsing, keep the prefix frozen to what the user had typed
		# at the moment browsing started. Otherwise, use what's before the cursor.
		if self._browsing:
			return self._browse_origin_text[:self._browse_origin_cursor]
		return self.text()[:self.cursorPosition()]

	# ---------- reverse-i-search ----------
	@staticmethod
	def _subseq_score(query: str, s: str) -> int:
		q = query.lower(); t = s.lower()
		if not q: return 1
		if q in t: return 1000 - t.index(q) - (len(t) - len(q))
		it = iter(t); ok = all(ch in it for ch in q)
		return 100 if ok else -1

	def _ris_recompute(self, direction: int = -1):
		if not self._hist:
			self._ris_idx = -1; self._ris_update_popup(); return
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
		match_txt = (self._hist[self._ris_idx] if idx_ok
					 else ("no history" if not self._hist else "no match"))
		self._ris_label.setText(f"reverse-i-search: “{_esc(self._ris_query)}”  →  {_esc(match_txt)}")
		self._ris_label.adjustSize()
		w = self._ris_label.sizeHint().width() + 12; h = self._ris_label.sizeHint().height() + 8
		self._ris_popup.resize(w, h)
		base = self.mapToGlobal(QPoint(0, self.height()))
		self._ris_popup.move(base + QPoint(6, 6))
		self._ris_popup.show()

	def _ris_start(self):
		self._ris_active = True
		self._ris_saved_text = self.text()
		self._ris_query = ""; self._ris_idx = -1
		self._ris_update_popup()

	def _ris_accept(self):
		if 0 <= self._ris_idx < len(self._hist):
			self.setText(self._hist[self._ris_idx]); self.setCursorPosition(len(self.text()))
		self._ris_cancel(hide_only=True)

	def _ris_step(self, delta: int):
		if not self._ris_active: return
		self._ris_recompute(+1 if delta > 0 else -1)

	def _ris_cancel(self, hide_only: bool = False):
		if not hide_only:
			self.setText(self._ris_saved_text); self.setCursorPosition(len(self.text()))
		self._ris_active = False; self._ris_popup.hide()

	# ---------- browsing lifecycle ----------
	def _exit_browse_if_typing(self, _txt: str):
		if self._browsing and not self._ris_active:
			self._browsing = False
			self._idx = len(self._hist)

	# ---------- keys ----------
	def keyPressEvent(self, e):
		# keep Tab in field
		if e.key() in (Qt.Key_Tab, Qt.Key_Backtab): e.accept(); return

		# reverse-i-search quick cancel
		if self._ris_active and e.key() == Qt.Key_Escape:
			self._ris_cancel(); e.accept(); return

		# ===== reverse-i-search active =====
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

		# start reverse-i-search
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_R:
			self._ris_start(); e.accept(); return
		if (e.modifiers() & Qt.ControlModifier) and e.key() == Qt.Key_S:
			# allow forward stepping even when starting with S
			self._ris_start(); self._ris_step(+1); e.accept(); return

		# readline keys
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

		# ===== history browse (Up/Down), prefix-aware =====
		if e.key() == Qt.Key_Up:
			if not self._hist:
				e.accept(); return
			if not self._browsing:
				self._browsing = True
				self._browse_origin_text = self.text()
				self._browse_origin_cursor = self.cursorPosition()
				self._idx = len(self._hist)

			pfx = self._orig_prefix()
			if pfx:
				j = self._hist_seek_prev_with_prefix(pfx, self._idx)
				if j >= 0:
					self._idx = j
					self.setText(self._hist[self._idx])
					self.setCursorPosition(len(self.text()))
					e.accept(); return
				# No prefix match → fall back to classic step

			# classic (no/failed prefix)
			if self._idx > 0:
				self._idx -= 1
				self.setText(self._hist[self._idx])
				self.setCursorPosition(len(self.text()))
			e.accept(); return

		if e.key() == Qt.Key_Down:
			if not self._browsing:
				e.accept(); return  # nothing to do if not browsing

			pfx = self._orig_prefix()
			if pfx:
				j = self._hist_seek_next_with_prefix(pfx, self._idx if self._idx < len(self._hist) else len(self._hist) - 1)
				if j >= 0:
					self._idx = j
					self.setText(self._hist[self._idx])
					self.setCursorPosition(len(self.text()))
					e.accept(); return
				# No prefix match → fall through to classic

			# classic step forward
			if self._idx < len(self._hist) - 1:
				self._idx += 1
				self.setText(self._hist[self._idx])
				self.setCursorPosition(len(self.text()))
				e.accept(); return

			# reached end → exit browsing and restore original typed text
			self._browsing = False
			self._idx = len(self._hist)
			self.setText(self._browse_origin_text)
			self.setCursorPosition(len(self.text()))
			e.accept(); return

		# default
		super().keyPressEvent(e)

# ===================== polished “glass card” container ============================
class _GlassCard(QFrame):
	def __init__(self, radius=14, parent=None):
		super().__init__(parent)
		self._r = radius
		self.setAttribute(Qt.WA_StyledBackground, True)
		self.setAutoFillBackground(False)
		shadow = QGraphicsDropShadowEffect(self)
		shadow.setBlurRadius(32); shadow.setOffset(0, 14)
		shadow.setColor(QColor(0, 0, 0, 160))
		self.setGraphicsEffect(shadow)

	def paintEvent(self, _):
		r_int = self.rect().adjusted(1, 1, -1, -1)   # QRect (ints) for loops
		rf = QRectF(r_int)                            # QRectF for rounded path/gradients

		p = QPainter(self); p.setRenderHint(QPainter.Antialiasing, True)

		# gradient glass panel
		g = QLinearGradient(rf.topLeft(), rf.bottomRight())
		g.setColorAt(0.0, QColor(theme_color("panel_grad_hi", "#151a22")))
		g.setColorAt(1.0, QColor(theme_color("panel_grad_lo", "#0e131a")))

		path = QPainterPath()
		path.addRoundedRect(rf, float(self._r), float(self._r))
		p.fillPath(path, g)

		# subtle sheen
		top = QLinearGradient(rf.topLeft(), rf.topRight())
		top.setColorAt(0.0, QColor(255, 255, 255, 16))
		top.setColorAt(1.0, QColor(255, 255, 255, 0))
		p.fillPath(path, top)

		# decorative micro-grid (very faint)
		p.save(); p.setClipPath(path)
		grid = QColor(255, 255, 255, 10)
		p.setPen(QPen(grid, 1))
		step = 24
		for x in range(r_int.left(), r_int.right(), step):
			p.drawLine(x, r_int.top(), x, r_int.bottom())
		for y in range(r_int.top(), r_int.bottom(), step):
			p.drawLine(r_int.left(), y, r_int.right(), y)
		p.restore()

		# border
		p.setPen(QPen(QColor(theme_color("panel_border", "#2a3343")), 1))
		p.drawPath(path)
		p.end()

# ===================== main console ============================
class SessionConsole(QWidget):
	files_requested = pyqtSignal(str, str)  # sid, hostname

	def __init__(self, api, sid: str, hostname: str):
		super().__init__()
		self.api = api; self.sid = sid
		self.hostname = hostname

		# --- state ---
		self._show_time = True
		self._autoscroll = True

		# repeat-collapse state
		self._rep_key_last = None
		self._rep_count = 1
		self._rep_last_ts = 0.0
		self._rep_window = 6.0   # seconds within which identical lines are collapsed
		self._rep_last_render_prefix = ""
		self._rep_last_base = ""
		self._snf_seen = False   # “session not found” guard

		# ================= HEADER =================
		card = _GlassCard(radius=14, parent=self)
		self._card = card
		card_lay = QVBoxLayout(card)
		card_lay.setContentsMargins(14, 14, 14, 14)
		card_lay.setSpacing(10)

		self.title = QLabel(hostname)
		self.title.setObjectName("ConsoleTitle")
		self.title.setStyleSheet("QLabel#ConsoleTitle{font-size:16.5pt;font-weight:600;color:#eaf2ff;letter-spacing:0.3px;}")

		self.sid_badge = QLabel(f"SID: {sid}")
		self.sid_badge.setObjectName("Badge")
		self.sid_badge.setStyleSheet(
			"QLabel#Badge{color:#cfe3ff;background:rgba(63,134,255,0.11);"
			"border:1px solid #2b3c5c;border-radius:9px;padding:2px 8px;font-size:9.5pt;}"
		)

		self.status = QPushButton()   # dot icon + text
		self.status.setObjectName("StatusBtn")
		self.status.setEnabled(False)
		self.status.setFlat(True)
		self.status.setIcon(_make_dot_icon(10, "#f59e0b")) # pending
		self.status.setText(" Connecting…")
		self.status.setStyleSheet("QPushButton#StatusBtn{color:#cbd5e1; border:none; padding:0 4px; font-size:9.5pt;}")

		self.btn_files = QPushButton("Files"); self._style_pill(self.btn_files)
		self.btn_wrap  = QPushButton("Wrap");  self._style_pill(self.btn_wrap, checkable=True)
		self.btn_time  = QPushButton("Timestamps"); self._style_pill(self.btn_time, checkable=True, checked=True)
		self.btn_lock  = QPushButton("Scroll-lock"); self._style_pill(self.btn_lock, checkable=True, checked=False)
		self.btn_copy  = QPushButton("Copy all"); self._style_pill(self.btn_copy)
		self.btn_clear = QPushButton("Clear"); self._style_pill(self.btn_clear)

		hdr = QHBoxLayout(); hdr.setSpacing(10)
		left = QHBoxLayout(); left.setSpacing(10)
		left.addWidget(self.title); left.addWidget(self.sid_badge); left.addSpacing(6); left.addWidget(self.status)
		left.addStretch(1)
		right = QHBoxLayout(); right.setSpacing(8)
		for b in (self.btn_files, self.btn_wrap, self.btn_time, self.btn_lock, self.btn_copy, self.btn_clear):
			right.addWidget(b)
		hdr.addLayout(left, 1); hdr.addLayout(right, 0)
		card_lay.addLayout(hdr)

		# ================= OUTPUT =================
		self.out = QPlainTextEdit(); self.out.setReadOnly(True)
		self._style_output()
		card_lay.addWidget(self.out, 1)

		# ================= COMMAND BAR =================
		h_cmd = QHBoxLayout(); h_cmd.setSpacing(8)

		self.prompt = QLabel("❯")
		self.prompt.setObjectName("PromptGlyph")
		self.prompt.setAlignment(Qt.AlignCenter)
		self.prompt.setFixedWidth(26)
		self.prompt.setStyleSheet(
			"QLabel#PromptGlyph{font: 12pt 'JetBrains Mono','Fira Code','Consolas','Menlo';"
			"color:#cfe3ff;background:rgba(63,134,255,0.18);border:1px solid #2b3c5c;border-radius:9px;}"
		)

		# history-enabled input
		hist_path = str(Path.home() / f".gunnerc2_sc_{sid}_history")
		self.inp = _ConsoleHistoryLineEdit(history_path=hist_path)
		self._style_input(self.inp)

		self.btn_send = QPushButton(" Send")
		self.btn_send.setIcon(_make_play_icon(16, "#eaf2ff"))
		self.btn_send.setCursor(Qt.PointingHandCursor)
		self.btn_send.setObjectName("SendBtn")
		self.btn_send.setMinimumHeight(38)
		self.btn_send.setStyleSheet(
			"QPushButton#SendBtn{background:#2b6af1;border:1px solid #3c78f5;color:white;"
			"border-radius:10px;padding:8px 14px;font-weight:600;}"
			"QPushButton#SendBtn:hover{background:#3b7bff;border-color:#4b86ff;}"
			"QPushButton#SendBtn:pressed{background:#2a62db;}"
		)

		h_cmd.addWidget(self.prompt, 0)
		h_cmd.addWidget(self.inp, 1)
		h_cmd.addWidget(self.btn_send, 0)
		card_lay.addLayout(h_cmd)

		# mount everything
		root = QVBoxLayout(self)
		root.setContentsMargins(10, 10, 10, 10)
		root.addWidget(card)

		# wiring
		self.btn_send.clicked.connect(self._send)
		self.inp.returnPressed.connect(self._send)
		self.btn_files.clicked.connect(self._on_files_clicked)
		self.btn_clear.clicked.connect(self._clear_screen)
		self.btn_copy.clicked.connect(self._copy_all)
		self.btn_wrap.toggled.connect(self._toggle_wrap)
		self.btn_time.toggled.connect(self._toggle_time)
		self.btn_lock.toggled.connect(self._toggle_lock)

		# Ctrl+L clear
		self._sc_clear = QShortcut(QKeySequence("Ctrl+L"), self)
		self._sc_clear.setContext(Qt.WidgetWithChildrenShortcut)
		self._sc_clear.activated.connect(self._clear_screen)

		# Websocket
		ws_url = self.api.base_url.replace("http", "ws", 1) + f"/ws/sessions/{sid}?token={self.api.token}"
		self.ws = QWebSocket()

		def _on_ws_error(*args):
			try:
				err_enum = args[0] if args else None
				err_name = QAbstractSocket.SocketError(err_enum).name if isinstance(err_enum, int) else str(err_enum)
				self._append_text(f"[websocket error] {err_name}", key="ws_error")
			except Exception:
				self._append_text("[websocket error]", key="ws_error")
			self._set_connected(False)

		"""self.ws.textMessageReceived.connect(self._on_msg)
		self.ws.connected.connect(lambda: (self.status.setIcon(_make_dot_icon(10, "#22c55e")), self.status.setText(" Connected")))
		self.ws.disconnected.connect(lambda: (self.status.setIcon(_make_dot_icon(10, "#ef4444")), self.status.setText(" Disconnected")))"""

		self.ws.textMessageReceived.connect(self._on_msg)
		self.ws.connected.connect(lambda: self._set_connected(True))
		self.ws.disconnected.connect(lambda: self._set_connected(False))
		self.ws.open(QUrl(ws_url))

	# ----- Websocket Helpers -----
	def _set_connected(self, ok: bool):
		self.inp.setEnabled(ok)
		self.btn_send.setEnabled(ok)
		self.status.setIcon(_make_dot_icon(10, "#22c55e" if ok else "#ef4444"))
		self.status.setText(" Connected" if ok else " Disconnected")

	# ---------- styling helpers ----------
	def _style_pill(self, btn: QPushButton, *, checkable=False, checked=False):
		btn.setObjectName("Pill")
		btn.setCheckable(checkable)
		if checkable: btn.setChecked(checked)
		btn.setCursor(Qt.PointingHandCursor)
		btn.setMinimumHeight(30)
		btn.setStyleSheet(
			"QPushButton#Pill{color:#cfd8e3;background:rgba(14,20,28,0.6);"
			"border:1px solid #2a3446;border-radius:10px;padding:6px 10px;}"
			"QPushButton#Pill:hover{border-color:#3b82f6;}"
			"QPushButton#Pill:checked{background:rgba(40,76,140,0.35);border-color:#3b82f6;color:#eaf2ff;}"
		)

	def _style_output(self):
		self.out.setFrameStyle(QFrame.NoFrame)
		self.out.setLineWrapMode(QPlainTextEdit.NoWrap)
		f = QFont("JetBrains Mono"); f.setStyleHint(QFont.Monospace); f.setPointSize(10)
		self.out.setFont(f)
		self.out.setStyleSheet(
			"QPlainTextEdit{background:transparent;color:#e6edf3;selection-background-color:#314e86;"
			"selection-color:#eaf2ff;border:none;}"
		)

	def _style_input(self, le: QLineEdit):
		f = QFont("JetBrains Mono"); f.setStyleHint(QFont.Monospace); f.setPointSize(10)
		le.setFont(f)
		le.setMinimumHeight(38)
		le.setStyleSheet(
			"QLineEdit{color:#eaf2ff;background:rgba(10,14,20,0.65);border:1px solid #2b3c5c;"
			"border-radius:10px;padding:8px 10px;selection-background-color:#3b82f6;selection-color:white;}"
			"QLineEdit:focus{border-color:#4b86ff;background:rgba(14,20,28,0.75);}"
		)

	# ---------- behavior ----------
	def _toggle_wrap(self, on: bool):
		self.out.setLineWrapMode(QPlainTextEdit.WidgetWidth if on else QPlainTextEdit.NoWrap)

	def _toggle_time(self, on: bool):
		self._show_time = on

	def _toggle_lock(self, on: bool):
		self._autoscroll = (not on)

	def _with_scroll_guard(self, write_callable):
		"""Run writes without jumping the view when scroll-lock is ON."""
		vsb = self.out.verticalScrollBar()
		hsb = self.out.horizontalScrollBar()
		v, h = vsb.value(), hsb.value()

		write_callable()  # perform the text insertion/update

		if self._autoscroll:
			vsb.setValue(vsb.maximum())  # follow output
		else:
			vsb.setValue(v)              # keep the view exactly where it was
			hsb.setValue(h)

	def _flash_last_line(self):
		# Build a selection covering the last line and flash it briefly
		cur = self.out.textCursor()
		cur.movePosition(QTextCursor.End)
		cur.select(QTextCursor.LineUnderCursor)

		sel = QTextEdit.ExtraSelection()   # <- was QPlainTextEdit.ExtraSelection()
		sel.cursor = cur
		sel.format.setBackground(QColor(102, 176, 255, 40))  # soft blue wash
		sel.format.setProperty(QTextFormat.FullWidthSelection, True)

		self.out.setExtraSelections([sel])
		QTimer.singleShot(170, lambda: self.out.setExtraSelections([]))

	def _append_text(self, text: str, *, key: str = None):
		import time as _t

		# honor CLEAR control
		if text == "\x00CLEAR\x00":
			self._clear_screen()
			return

		base_key = (key if key is not None else text.strip())
		now = _t.time()

		# Build visible text (with optional timestamp)
		if self._show_time:
			ts = time.strftime("[%H:%M:%S] ")
		else:
			ts = ""
		visible = []
		for ln in text.splitlines() or [""]:
			visible.append((ts + ln) if (self._show_time and ln.strip()) else ln)
		render = "\n".join(visible)

		# Repeat collapse: if same key within window, update the last line instead of appending
		if self._rep_key_last == base_key and (now - self._rep_last_ts) <= self._rep_window:
			self._rep_count += 1
			self._rep_last_ts = now
			self._update_last_line_repetition()
			self._flash_last_line()
			return

		# New line
		self._with_scroll_guard(lambda: self.out.appendPlainText(render))
		self._flash_last_line()

		# capture last line pieces for future updates
		self._rep_key_last = base_key
		self._rep_last_ts = now
		self._rep_count = 1
		# store only the final line’s base text (without “(xN)”)
		last_line = render.splitlines()[-1] if render.splitlines() else render
		if self._show_time and last_line.startswith(ts):
			self._rep_last_render_prefix = ts
			self._rep_last_base = last_line[len(ts):]
		else:
			self._rep_last_render_prefix = ""
			self._rep_last_base = last_line

		if self._autoscroll:
			cur = self.out.textCursor()
			cur.movePosition(QTextCursor.End)
			self.out.setTextCursor(cur)
			self.out.ensureCursorVisible()
			
	def _update_last_line_repetition(self):
		def _write():
			cur = self.out.textCursor()
			cur.movePosition(QTextCursor.End)
			cur.select(QTextCursor.LineUnderCursor)
			new_text = f"{self._rep_last_render_prefix}{self._rep_last_base}  (x{self._rep_count})"
			cur.insertText(new_text)
		self._with_scroll_guard(_write)

	def _send(self):
		cmd = self.inp.text().strip()
		if not cmd:
			return
		if self.ws.state() != QAbstractSocket.ConnectedState:
			self._append_text("[not connected]", key="not_connected")
			return
		self._append_text(f">>> {cmd}", key="prompt_cmd")
		self.inp.remember(cmd)
		try:
			self.ws.sendTextMessage(cmd)
		except Exception:
			self._append_text("[send failed]", key="send_failed")
		self.inp.clear()

	def _clear_screen(self):
		self.out.clear()

	def _copy_all(self):
		self.out.selectAll(); self.out.copy()
		# brief visual tick in the status
		txt = self.status.text()
		self.status.setText(" Copied ✔"); QTimer.singleShot(800, lambda: self.status.setText(txt))

	def _on_msg(self, m: str):
		low = m.strip().lower()
		# Collapse and permanently mute "session not found" floods
		if ("session not found" in low or "no such session" in low) and not self._snf_seen:
			self._snf_seen = True
			self._append_text("** Session not found — closing this console. **", key="snf_banner")
			try:
				self.ws.close()
			except Exception:
				pass
			self._set_connected(False)
			return
		# If we've already handled it, silently drop further ones
		if self._snf_seen and ("session not found" in low or "no such session" in low):
			return

		self._append_text(m)   # normal path

	# Files now handled by Dashboard (opens a tab)
	def _on_files_clicked(self):
		self.files_requested.emit(self.sid, self.hostname)
