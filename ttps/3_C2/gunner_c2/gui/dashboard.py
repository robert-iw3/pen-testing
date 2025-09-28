# gui/dashboard.py
from PyQt5.QtCore import Qt, QSettings, QByteArray, QTimer, QPoint, QRect, QEvent, QObject

from PyQt5.QtWidgets import (
	QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTabWidget, QSplitter, QMessageBox, QApplication, QSizePolicy,
	QMenu, QAction, QTabBar
)

from PyQt5.QtGui import QFont, QIcon, QPixmap, QPainter, QPen, QBrush

from session_graph import SessionGraph
from sessions_tab import SessionsTab
from listeners_tab import ListenersTab
from payloads_tab import PayloadsTab
from operators_tab import OperatorsTab
from file_browser import FileBrowser
from ldap_browser import LdapBrowser
from session_console import SessionConsole
from gunnershell_console import GunnershellConsole

from theme_center import ThemeManager, ThemePanel

try:
	# same import pattern you used elsewhere
	from .websocket_client import SessionsWSClient
	from .file_browser import FileBrowser
except Exception:
	from websocket_client import SessionsWSClient
	from file_browser import FileBrowser

# ----------- Helpers ------------
def _strip_host_prefix(username: str, hostname: str) -> str:
	"""Turn 'HOST\\user' into 'user' when HOST matches the hostname (case-insensitive)."""
	u = str(username or "")
	h = str(hostname or "")
	if u.lower().startswith(h.lower() + "\\"):
		return u[len(h) + 1 :]
	return u


class Dashboard(QWidget):
	"""
	Main landing page:
	  ┌───────────────────────────────────────────────┐
	  │  Top Button Bar (Graph • Sessions • …)       │
	  ├───────────────────────────────────────────────┤
	  │  Graph (SessionGraph)                         │
	  ├───────────────────────────────────────────────┤
	  │  Bottom Tab Browser (QTabWidget, closable)    │
	  └───────────────────────────────────────────────┘
	"""
	def __init__(self, api, parent=None):
		super().__init__(parent)
		self.api = api

		# ---------- Top button bar ----------
		self.btn_sessions = QPushButton("Sessions")
		self.btn_listeners = QPushButton("Listeners")
		self.btn_payloads = QPushButton("Payloads")
		self.btn_operators = QPushButton("Operators")

		for b in (self.btn_sessions, self.btn_listeners, self.btn_payloads, self.btn_operators):
			b.setCursor(Qt.PointingHandCursor)
			b.setMinimumHeight(34)
			b.setStyleSheet(
				"QPushButton {"
				"  background:#2c313a; color:#e9eaec; border:1px solid #3b404a;"
				"  border-radius:6px; padding:6px 14px;"
				"  font-family:'Segoe UI';"        
				"  font-size:13px; font-weight:600;" 
				"}"
				"QPushButton:hover { border-color:#5a6270; }"
				"QPushButton:pressed { background:#23272e; }"
			)

		buttons = QHBoxLayout()
		buttons.setContentsMargins(8, 8, 8, 4)
		buttons.setSpacing(8)
		buttons.addWidget(self.btn_sessions)
		buttons.addWidget(self.btn_listeners)
		buttons.addWidget(self.btn_payloads)
		buttons.addWidget(self.btn_operators)
		buttons.addStretch()

		# ---------- Graph (top) ----------
		self.graph = SessionGraph(self.api)
		self.graph.open_console_requested.connect(self._open_console_tab)
		self.graph.open_gunnershell_requested.connect(self._open_gunnershell_tab)
		self.graph.kill_session_requested.connect(self._kill_session)
		self.graph.open_file_browser_requested.connect(self._open_files_tab)
		self.graph.open_ldap_browser_requested.connect(self._open_ldap_tab)

		# ---------- Sessions WS (shared, for lookups) ----------
		self.sessions_ws = SessionsWSClient(self.api)
		self.sessions_ws.error.connect(lambda e: print("[ws] sessions:", e))
		self.sessions_ws.open()
		# (client maintains its own cache via snapshots)

		# ---------- Bottom tab browser ----------
		self.tabs = QTabWidget()
		self.tabs.setTabsClosable(True)
		self.tabs.setMovable(True)
		self.tabs.tabCloseRequested.connect(self._close_tab)

		# --- Per-tab metadata (for console/GS tabs only) ---
		self._tab_meta = {}  # widget -> {"kind": "console"|"gunnershell", "sid":..., "hostname":..., "username":..., "arch":...}

		# --- Right-click menu on the tab bar ---
		bar = self.tabs.tabBar()
		bar.setContextMenuPolicy(Qt.CustomContextMenu)
		bar.customContextMenuRequested.connect(self._on_tabbar_menu)

		# Use a vertical splitter so users can resize graph vs. tabs freely
		self.split = QSplitter(Qt.Vertical)
		self.split.setHandleWidth(8)
		self.split.setOpaqueResize(True)
		current = self.tabs.currentWidget()
		is_heavy = self._is_heavy_tab(current)

		if is_heavy:
			self.split.setChildrenCollapsible(False)
			# Let both panes shrink to 0 but still respect child minimums
			for w in (self.graph, self.tabs):
				w.setMinimumHeight(0)
				sp = w.sizePolicy()
				sp.setHorizontalPolicy(QSizePolicy.Expanding)
				# DO NOT use Ignored here for Payloads pages; keep MinimumExpanding
				sp.setVerticalPolicy(QSizePolicy.MinimumExpanding)
				w.setSizePolicy(sp)
		else:
			self.split.setChildrenCollapsible(True)

			# Let both panes shrink to 0 to avoid minimum-size blocking
			for w in (self.graph, self.tabs):
				w.setMinimumSize(0, 0)
				w.setMinimumHeight(0)
				sp = w.sizePolicy()
				# IMPORTANT: ignore vertical size hints so splitter can move freely
				sp.setVerticalPolicy(QSizePolicy.Ignored)
				w.setSizePolicy(sp)


		self.split.addWidget(self.graph)
		self.split.addWidget(self.tabs)

		# Track pre-payload sizes and pause-saving flag
		self._pre_payload_sizes = None
		self._suspend_split_save = False
		self._split_locked = False
		self._last_nonheavy_sizes = None  # remember a good 'normal' layout
		self._was_heavy = False

		# Now that splitter exists, hook the signal and apply mode
		self.tabs.currentChanged.connect(self._apply_splitter_mode)
		self._apply_splitter_mode()

		# Make panes explicitly collapsible
		try:
			self.split.setCollapsible(0, True)
			self.split.setCollapsible(1, True)
		except Exception:
			pass

		# Persist splitter position
		self._settings = QSettings("GunnerC2", "Console")
		state = self._settings.value("dashboard/splitter_state", None)
		if state is not None:
			try:
				ba = state if isinstance(state, QByteArray) else QByteArray(state)
				self.split.restoreState(ba)
			except Exception:
				# fallback if stored state is incompatible
				self.split.setSizes([600, 260])
		else:
			self.split.setSizes([600, 260])

		# Ensure we do not start collapsed at the top/bottom
		QTimer.singleShot(0, self._remember_nonheavy_sizes)
		QTimer.singleShot(0, self._normalize_initial_splitter)

		# Debounced save on move (prevents stutter while dragging)
		self._split_save_timer = QTimer(self)
		self._split_save_timer.setSingleShot(True)
		self._split_save_timer.setInterval(350)
		self._split_save_timer.timeout.connect(self._save_splitter_state)
		self.split.splitterMoved.connect(lambda *_: self._split_save_timer.start())

		# ---------- Layout ----------
		root = QVBoxLayout(self)
		root.setContentsMargins(0, 0, 0, 0)
		root.addLayout(buttons)
		root.addWidget(self.split)

		# ---------- Button wiring ----------
		self.btn_sessions.clicked.connect(self._open_sessions_tab)
		self.btn_listeners.clicked.connect(self._open_listeners_tab)
		self.btn_payloads.clicked.connect(self._open_payloads_tab)
		self.btn_operators.clicked.connect(self._open_operators_tab)

		# Lazy-singletons for the admin tabs
		self._tab_sessions = None
		self._tab_listeners = None
		self._tab_payloads = None
		self._tab_operators = None

		# watch geometry changes to keep overlay visibility correct
		self.installEventFilter(self)
		self.split.installEventFilter(self)
		self.tabs.installEventFilter(self)
		self.tabs.tabBar().installEventFilter(self)
		self.graph.view.installEventFilter(self)
		self.graph.view.viewport().installEventFilter(self)

		# first run after layout settles
		QTimer.singleShot(0, self._update_zoom_overlay_visibility)
		self.split.splitterMoved.connect(lambda *_: (self._split_save_timer.start(), self._update_zoom_overlay_visibility()))

		host = self._host_tabwidget()
		if host:
			host.currentChanged.connect(self._on_host_tab_changed)

		# Open Sessions by default in the bottom browser to mirror classic UX
		self._open_sessions_tab()

	def _is_heavy_tab(self, w):
		# Treat both Payloads and Files as “heavy” (maximize bottom pane)
		return isinstance(w, (PayloadsTab, FileBrowser, LdapBrowser))

	def _on_host_tab_changed(self, idx: int):
		host = self._host_tabwidget()
		if not host:
			return
		w = host.widget(idx)
		if not self._is_heavy_tab(w):
			self._exit_heavy_mode()
		else:
			# ensure we stay collapsed if we hopped heavy→heavy
			self._enforce_heavy_layout()

	def _update_zoom_overlay_visibility(self):
		"""Hide zoom overlay if the tab bar (or its near area) is close to it."""
		try:
			view = self.graph.view
			if not hasattr(view, "zoom_overlay_rect_global"):
				return
			ov_rect = view.zoom_overlay_rect_global()
			if ov_rect.isNull():
				return

			# rectangles to test: the tab BAR and the full tabs widget (for safety)
			bar  = self.tabs.tabBar()
			tabs = self.tabs
			bar_rect  = QRect(bar.mapToGlobal(QPoint(0, 0)),  bar.size())
			tabs_rect = QRect(tabs.mapToGlobal(QPoint(0, 0)), tabs.size())

			# treat “nearby” as overlap using an inflated margin
			MARGIN = 28  # <- tune here (px)
			r_overlay = ov_rect.adjusted(-MARGIN, -MARGIN, MARGIN, MARGIN)
			r_bar     = bar_rect.adjusted(-MARGIN, -MARGIN, MARGIN, MARGIN)
			r_tabs    = tabs_rect.adjusted(-MARGIN, -MARGIN, MARGIN, MARGIN)

			overlap = r_overlay.intersects(r_bar) or r_overlay.intersects(r_tabs)
			if hasattr(view, "set_zoom_overlay_visible"):
				view.set_zoom_overlay_visible(not overlap)
		except Exception:
			pass

	def eventFilter(self, obj, ev):
		if ev.type() in (QEvent.Resize, QEvent.Move, QEvent.Show, QEvent.Hide, QEvent.LayoutRequest):
			self._update_zoom_overlay_visibility()
		return super().eventFilter(obj, ev)

	def _toggle_handle_appearance(self, hidden: bool):
		"""Hide/show the splitter grip dots and handle width."""
		try:
			if hidden:
				# remember the previous width once
				if not hasattr(self, "_prev_handle_width"):
					self._prev_handle_width = self.split.handleWidth()
				# fully hide grip dots & bar visuals
				self.split.setHandleWidth(0)
				self.split.setStyleSheet("QSplitter::handle { image: none; background: transparent; }")
			else:
				# restore visuals
				self.split.setStyleSheet("")
				self.split.setHandleWidth(getattr(self, "_prev_handle_width", 8))
		except Exception:
			pass


	def _normalize_initial_splitter(self):
		"""
		After the window shows, ensure we start with a reasonable split.
		If either pane is ~collapsed, restore to a 70/30 layout.
		"""
		try:
			sizes = self.split.sizes()
			if not sizes:
				return	
			if min(sizes) < 80:  # effectively collapsed
				h = max(self.height(), 600)
				self.split.setSizes([int(h * 0.70), int(h * 0.30)])
		except Exception:
			pass

	
	def _remember_nonheavy_sizes(self):
		try:
			sz = self.split.sizes()
			# treat <80px as 'collapsed'; only store healthy layouts
			if sz and min(sz) >= 80:
				self._last_nonheavy_sizes = list(sz)
		except Exception:
			pass

	# lock/unlock the vertical splitter (prevents user dragging)
	def _set_splitter_locked(self, locked: bool):
		self._split_locked = bool(locked)
		try:
			# For a vertical QSplitter, there is one handle between its two widgets (index 1)
			for i in range(1, self.split.count()):
				h = self.split.handle(i)
				if h:
					h.setDisabled(locked)  # blocks mouse events & double-click collapse
					# nice cursor feedback
					h.setCursor(Qt.ArrowCursor if locked
								else (Qt.SplitVCursor if self.split.orientation() == Qt.Vertical
									  else Qt.SplitHCursor))
			self._toggle_handle_appearance(locked)

		except Exception:
			pass


	def _save_splitter_state(self):
		"""Don’t persist the temporary ‘payloads maximized’ layout."""
		if self._suspend_split_save:
			return
		self._settings.setValue("dashboard/splitter_state", self.split.saveState())

	class _HandleEater(QObject):
		def eventFilter(self, obj, ev):
			if ev.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease, QEvent.MouseMove, QEvent.HoverMove, QEvent.HoverEnter):
				return True
			return False

	def _host_tabwidget(self) -> QTabWidget | None:
		w = self.parent()
		while w is not None and not isinstance(w, QTabWidget):
			w = w.parent()
		return w if isinstance(w, QTabWidget) else None

	def _find_workspace_splitter(self) -> QSplitter | None:
		w = self.parent()
		while w is not None:
			if isinstance(w, QSplitter) and w.orientation() == Qt.Vertical:
				return w
			w = w.parent()
		return None

	def _find_workspace_splitter_and_child(self):
		child = self
		p = self.parent()
		while p is not None and not isinstance(p, QSplitter):
			child = p
			p = p.parent()
		return (p, child) if isinstance(p, QSplitter) else (None, None)

	def _collapse_workspace_header(self, on: bool):
		sp = getattr(self, "_ws_split", None) or self._find_workspace_splitter()
		if not isinstance(sp, QSplitter):
			return
		if on:
			self._ws_split = sp
			if getattr(self, "_ws_old_sizes", None) is None:
				sizes = list(sp.sizes() or [])
				if len(sizes) >= 2 and min(sizes) > 2:
					self._ws_old_sizes = sizes
			if getattr(self, "_ws_old_handle_w", None) is None:
				self._ws_old_handle_w = sp.handleWidth()
			if getattr(self, "_ws_old_css", None) is None:
				self._ws_old_css = sp.styleSheet()

			total = max(1, sum(sp.sizes()) or 1)
			sp.setSizes([0, total])
			try: sp.setHandleWidth(0)
			except Exception: pass
			try:
				sp.setStyleSheet((self._ws_old_css or "") + " QSplitter::handle { image: none; background: transparent; height: 0px; }")
			except Exception: pass
		else:
			try:
				if getattr(self, "_ws_old_sizes", None):
					sp.setSizes(self._ws_old_sizes)
				if getattr(self, "_ws_old_handle_w", None) is not None:
					sp.setHandleWidth(self._ws_old_handle_w)
				if getattr(self, "_ws_old_css", None) is not None:
					sp.setStyleSheet(self._ws_old_css)
			except Exception: pass

	def _ws(self):
		# Find the outer vertical workspace splitter (header above, content below)
		w = self.parent()
		while w is not None:
			if isinstance(w, QSplitter) and w.orientation() == Qt.Vertical:
				return w
			w = w.parent()
		return None

	def _cache_normal_ws_sizes(self):
		sp = self._ws()
		if not sp:
			return
		sizes = list(sp.sizes() or [])
		if len(sizes) >= 2 and sum(sizes) > 0:
			# Save both on the splitter (shared) and on self (local fallback)
			sp.setProperty("heavyNormalSizes", sizes)
			self._ws_normal_sizes = sizes
			# Also remember a sane handle width and css (once)
			if getattr(self, "_ws_restore_handle", None) is None:
				try:
					self._ws_restore_handle = sp.handleWidth()
				except Exception:
					self._ws_restore_handle = 6
			if getattr(self, "_ws_restore_css", None) is None:
				self._ws_restore_css = sp.styleSheet() or ""

	def _restore_workspace_from_cache(self):
		sp = self._ws()
		if not sp:
			return

		normal = sp.property("heavyNormalSizes") or getattr(self, "_ws_normal_sizes", None)
		if not (isinstance(normal, list) and len(normal) >= 2 and sum(normal) > 0):
			# fallback: ~22% header / 78% content
			total = max(1, sum(sp.sizes()) or 1)
			normal = [int(total * 0.22), total - int(total * 0.22)]

		# restore sizes + handle visuals
		sp.setSizes([int(normal[0]), int(normal[1])])
		try:
			if getattr(self, "_ws_restore_handle", None) is not None:
				sp.setHandleWidth(int(self._ws_restore_handle))
		except Exception:
			pass
		try:
			sp.setStyleSheet(getattr(self, "_ws_restore_css", ""))
		except Exception:
			pass

		# fight late relayouts with a couple of delayed re-applies
		QTimer.singleShot(0,  lambda: sp.setSizes([int(normal[0]), int(normal[1])]))
		QTimer.singleShot(50, lambda: sp.setSizes([int(normal[0]), int(normal[1])]))
		QTimer.singleShot(120, lambda: sp.setSizes([int(normal[0]), int(normal[1])]))

	def _lock_workspace_splitter(self):
		if getattr(self, "_locked_ws_splitter", None):
			return
		sp, child = self._find_workspace_splitter_and_child()
		if not sp:
			return
		# eat mouse on all handles
		self._locked_handle_blockers = []
		for i in range(1, sp.count()):
			h = sp.handle(i)
			if h:
				blocker = self._HandleEater(h)
				h.installEventFilter(blocker)
				try: h.setCursor(Qt.ArrowCursor)
				except Exception: pass
				self._locked_handle_blockers.append((h, blocker))

		self._locked_ws_old_css = sp.styleSheet()
		sp.setStyleSheet("QSplitter::handle { image: none; background: transparent; }")

		# give our pane almost everything so it sits flush under the app header
		try:
			idx = sp.indexOf(child)
			if idx != -1:
				sizes = sp.sizes()
				total = max(1, sum(sizes) or 1)
				new = [1] * len(sizes)
				new[idx] = max(total - (len(sizes) - 1), 1)
				sp.setSizes(new)
		except Exception:
			pass

		self._locked_ws_splitter = sp

	def _unlock_workspace_splitter(self):
		sp = getattr(self, "_locked_ws_splitter", None)
		if not sp:
			return
		for h, blocker in getattr(self, "_locked_handle_blockers", []):
			try: h.removeEventFilter(blocker)
			except Exception: pass
		self._locked_handle_blockers = []
		try:
			sp.setStyleSheet(self._locked_ws_old_css or "")
		except Exception: pass
		self._locked_ws_splitter = None
		self._locked_ws_old_css = None

	def _lock_host_tabbar(self):
		host = self._host_tabwidget()
		if not host:
			return
		tb = host.tabBar()
		if isinstance(tb, QTabBar):
			self._host_tabbar = tb
			self._host_tabbar_was_movable = tb.isMovable()
			tb.setMovable(False)
			tb.setDocumentMode(True)
			tb.setFocusPolicy(Qt.NoFocus)

	def _unlock_host_tabbar(self):
		tb = getattr(self, "_host_tabbar", None)
		if isinstance(tb, QTabBar):
			try: tb.setMovable(bool(getattr(self, "_host_tabbar_was_movable", True)))
			except Exception: pass
		self._host_tabbar = None
		self._host_tabbar_was_movable = None

	def _enforce_heavy_layout(self):
		# collapse Dashboard’s own graph→tabs splitter
		self._collapse_tabs_fullscreen()
		# fight late relayouts caused by tab insertions
		QTimer.singleShot(0, self._collapse_tabs_fullscreen)
		QTimer.singleShot(50, self._collapse_tabs_fullscreen)

	def _enter_heavy_mode(self):
		if getattr(self, "_heavy_mode_active", False):
			# heavy→heavy hop: just re-enforce
			self._enforce_heavy_layout()
			return
		self._heavy_mode_active = True
		# collapse & lock the OUTER header splitter (like FileBrowser does)
		self._collapse_workspace_header(True)
		self._lock_host_tabbar()
		self._lock_workspace_splitter()
		# and collapse our inner splitter hard
		self._enforce_heavy_layout()

	def _exit_heavy_mode(self):
		if not getattr(self, "_heavy_mode_active", False):
			return
		self._heavy_mode_active = False
		# restore outer splitter + tabbar
		self._unlock_workspace_splitter()
		self._unlock_host_tabbar()
		self._collapse_workspace_header(False)
		# existing logic will restore self.split sizes when switching to non-heavy

	"""def _apply_splitter_mode(self, *_):
		w = self.tabs.currentWidget()
		is_heavy = self._is_heavy_tab(w)
		was_heavy = getattr(self, "_was_heavy", False)

		# smoother dragging elsewhere
		self.split.setOpaqueResize(not is_heavy)

		if is_heavy:
			# entering heavy from non-heavy → save a GOOD baseline & collapse
			if not was_heavy:
				if self._pre_payload_sizes is None:
					# Prefer last healthy non-heavy layout, else current if not collapsed, else 70/30
					baseline = None
					if getattr(self, "_last_nonheavy_sizes", None) and min(self._last_nonheavy_sizes) >= 80:
						baseline = list(self._last_nonheavy_sizes)
					else:
						cur = self.split.sizes()
						if cur and min(cur) >= 80:
							baseline = list(cur)
						else:
							h = max(self.height(), 600)
							baseline = [int(h * 0.70), int(h * 0.30)]
					self._pre_payload_sizes = baseline

				# collapse to give everything to the bottom (tabs area)
				total = sum(self.split.sizes()) or max(1, self.split.height())
				self._suspend_split_save = True
				self.split.setSizes([0, max(1, total)])   # tabs fill window
				QTimer.singleShot(0, lambda: setattr(self, "_suspend_split_save", False))

			# heavy→heavy: stay collapsed; just ensure locked
			self._set_splitter_locked(True)

		else:
			# leaving heavy → restore once (after hidden heavy tab runs its hideEvent)
			if was_heavy and self._pre_payload_sizes:
				def _restore():
					self._suspend_split_save = True
					try:
						self.split.setSizes(self._pre_payload_sizes)
					finally:
						self._pre_payload_sizes = None
						QTimer.singleShot(0, lambda: setattr(self, "_suspend_split_save", False))
						# Update baseline now that we're back to normal
						self._remember_nonheavy_sizes()
				QTimer.singleShot(0, _restore)
			else:
				# staying non-heavy → refresh baseline
				self._remember_nonheavy_sizes()

			self._set_splitter_locked(False)

		self._was_heavy = is_heavy
		self._update_zoom_overlay_visibility()"""

	def _collapse_tabs_fullscreen(self):
		"""Give all vertical space to the bottom tabs area."""
		sizes = self.split.sizes()
		total = sum(sizes) or max(1, self.split.height())
		self._suspend_split_save = True
		try:
			self.split.setSizes([0, max(1, total)])
		finally:
			QTimer.singleShot(0, lambda: setattr(self, "_suspend_split_save", False))

	"""def _apply_splitter_mode(self, *_):
		w = self.tabs.currentWidget()
		is_heavy = self._is_heavy_tab(w)
		was_heavy = getattr(self, "_was_heavy", False)

		self.split.setOpaqueResize(not is_heavy)

		if is_heavy:
			# entering heavy from non-heavy → save baseline & collapse
			if not was_heavy:
				if self._pre_payload_sizes is None:
					baseline = None
					if getattr(self, "_last_nonheavy_sizes", None) and min(self._last_nonheavy_sizes) >= 80:
						baseline = list(self._last_nonheavy_sizes)
					else:
						cur = self.split.sizes()
						if cur and min(cur) >= 80:
							baseline = list(cur)
						else:
							h = max(self.height(), 600)
							baseline = [int(h * 0.70), int(h * 0.30)]
					self._pre_payload_sizes = baseline

				self._collapse_tabs_fullscreen()

			else:
				# heavy → heavy: if the graph re-expanded for any reason, re-collapse
				sizes = self.split.sizes()
				if sizes and sizes[0] > 8:          # tolerance so "almost 0" is OK
					self._collapse_tabs_fullscreen()

			self._set_splitter_locked(True)

		else:
			if was_heavy and self._pre_payload_sizes:
				def _restore():
					self._suspend_split_save = True
					try:
						self.split.setSizes(self._pre_payload_sizes)
					finally:
						self._pre_payload_sizes = None
						QTimer.singleShot(0, lambda: setattr(self, "_suspend_split_save", False))
						self._remember_nonheavy_sizes()
				QTimer.singleShot(0, _restore)
			else:
				self._remember_nonheavy_sizes()

			self._set_splitter_locked(False)

		self._was_heavy = is_heavy
		self._update_zoom_overlay_visibility()"""

	def _apply_splitter_mode(self, *_):
		w = self.tabs.currentWidget()
		is_heavy = self._is_heavy_tab(w)
		was_heavy = getattr(self, "_was_heavy", False)

		self.split.setOpaqueResize(not is_heavy)

		if is_heavy:
			self._enter_heavy_mode()
			self._set_splitter_locked(True)
		else:
			self._exit_heavy_mode()
			# restore the OUTER workspace split back to normal
			self._restore_workspace_from_cache()
			# after things settle, remember this as the new “normal”
			QTimer.singleShot(0, self._cache_normal_ws_sizes)
			self._set_splitter_locked(False)

		self._was_heavy = is_heavy
		self._update_zoom_overlay_visibility()

	def _lookup_from_cache(self, sid: str) -> dict:
		"""Return the best-effort cached session dict (merged with metadata)."""
		ws = getattr(self, "sessions_ws", None)
		sess = ws.get_cached(sid) if ws else {}  # may be {}
		meta = (sess.get("metadata") or {})
		# flatten a bit so callers can do .get(...) consistently
		merged = {}
		merged.update(sess or {})
		merged.update(meta or {})
		return merged

	def _set_tab_meta(self, w: QWidget, kind: str, sid: str, hostname: str, username: str = "", arch: str = ""):
		self._tab_meta[w] = {
			"kind": kind, "sid": sid, "hostname": hostname,
			"username": username or "", "arch": arch or ""
		}

	def _update_tab_meta_username(self, w: QWidget, username: str):
		m = self._tab_meta.get(w)
		if m is not None:
			m["username"] = username or ""

	def _update_tab_meta_arch(self, w: QWidget, arch: str):
		m = self._tab_meta.get(w)
		if m is not None and arch:
			m["arch"] = arch

	def _unique_tab_title(self, base: str) -> str:
		"""Return base or base (2)/(3)/... to avoid collisions."""
		titles = {self.tabs.tabText(i) for i in range(self.tabs.count())}
		if base not in titles:
			return base
		n = 2
		while True:
			cand = f"{base} ({n})"
			if cand not in titles:
				return cand
			n += 1

	def _duplicate_tab_from_index(self, idx: int):
		"""Duplicate the tab at index if it's a console/GS tab."""
		w = self.tabs.widget(idx)
		meta = self._tab_meta.get(w)
		if not meta:
			return  # not a console/GS tab

		kind = meta.get("kind")
		sid = meta.get("sid")
		host = meta.get("hostname") or ""
		user = meta.get("username") or ""
		arch = meta.get("arch") or ""

		# refresh anything we can from cache
		cached = self._lookup_from_cache(sid)
		if not user:
			user = cached.get("user") or cached.get("username") or user
		if not arch:
			arch = cached.get("arch") or arch

		if kind == "console":
			# Build title just like _open_console_tab, but force a unique copy
			title = f"{_strip_host_prefix(user, host)}@{host}" if user else host
			title = self._unique_tab_title(title)
			w2 = SessionConsole(self.api, sid, host)
			new_idx = self.tabs.addTab(w2, title)
			self.tabs.setTabIcon(new_idx, QApplication.windowIcon())
			self.tabs.setCurrentIndex(new_idx)
			self._set_tab_meta(w2, "console", sid, host, user, arch)

		elif kind == "gunnershell":
			base = (f"GS — {_strip_host_prefix(user, host)}@{host}" if user else f"GS — {host}")
			title = self._unique_tab_title(base)
			w2 = GunnershellConsole(self.api, sid, host)
			new_idx = self.tabs.addTab(w2, title)
			self.tabs.setTabIcon(new_idx, QApplication.windowIcon())
			self.tabs.setCurrentIndex(new_idx)
			self._set_tab_meta(w2, "gunnershell", sid, host, user, arch)

	def _copy_to_clipboard(self, text: str):
		QApplication.clipboard().setText(text or "")

	def _on_tabbar_menu(self, pos):
		bar = self.tabs.tabBar()
		idx = bar.tabAt(pos)
		if idx < 0:
			return

		w = self.tabs.widget(idx)
		meta = self._tab_meta.get(w) or {}

		m = QMenu(self)

		# Match Sessions tab: non-bold app font + dark menu stylesheet
		mf = QFont(self.font()); mf.setBold(False)
		m.setFont(mf)
		m.setStyleSheet(self._menu_stylesheet_dark())  # <<<< apply identical style

		# Optional actions for console/GS
		is_cs = meta.get("kind") in ("console", "gunnershell")
		if is_cs:
			m.addAction("Duplicate Tab", lambda: self._duplicate_tab_from_index(idx))
			m.addSeparator()
			m.addAction("Copy SID",      lambda: self._copy_to_clipboard(meta.get("sid", "")))
			m.addAction("Copy Username", lambda: self._copy_to_clipboard(meta.get("username", "")))
			m.addAction("Copy Hostname", lambda: self._copy_to_clipboard(meta.get("hostname", "")))
			if meta.get("sid") and not meta.get("username"):
				cached = self._lookup_from_cache(meta["sid"])
				u = cached.get("user") or cached.get("username") or ""
				if u:
					self._update_tab_meta_username(w, u)

		# --- ALWAYS LAST: Close submenu ---
		if m.actions():
			m.addSeparator()

		close_menu = m.addMenu("Close")

		# Ensure the submenu renders EXACTLY the same (stylesheet doesn’t always cascade across menus)
		close_menu.setFont(mf)
		close_menu.setStyleSheet(self._menu_stylesheet_dark())  # <<<< force same style

		act_close_this   = close_menu.addAction("Close Tab")
		act_close_right  = close_menu.addAction("Close tabs to the right")
		act_close_left   = close_menu.addAction("Close tabs to the left")
		act_close_others = close_menu.addAction("Close Others")

		act_close_right.setEnabled(idx < self.tabs.count() - 1)
		act_close_left.setEnabled(idx > 0)
		act_close_others.setEnabled(self.tabs.count() > 1)

		chosen = m.exec_(bar.mapToGlobal(pos))
		if not chosen:
			return

		if chosen == act_close_this:      
			self._close_tab(idx)
		elif chosen == act_close_right:
			self._close_tabs_to_right(idx)
		elif chosen == act_close_left:
			self._close_tabs_to_left(idx)
		elif chosen == act_close_others:
			self._close_other_tabs(idx)

	# ---------- Helpers: open/focus singleton tabs ----------
	def _ensure_tab(self, attr_name: str, widget_factory, title: str):
		w = getattr(self, attr_name)
		if w is None:
			w = widget_factory()
			idx = self.tabs.addTab(w, title)
			# Give every admin tab the app icon for a polished look
			self.tabs.setTabIcon(idx, QApplication.windowIcon())
			self.tabs.setCurrentIndex(idx)
			setattr(self, attr_name, w)
		else:
			idx = self.tabs.indexOf(w)
			if idx >= 0:
				self.tabs.setCurrentIndex(idx)
		return w

	def _open_sessions_tab(self):
		def _make():
			t = SessionsTab(self.api)
			t.session_double_clicked.connect(self._open_console_tab)
			t.gunnershell_requested.connect(self._open_gunnershell_tab)
			return t
		self._ensure_tab("_tab_sessions", _make, "Sessions")

	def _open_listeners_tab(self):
		self._ensure_tab("_tab_listeners", lambda: ListenersTab(self.api), "Listeners")

	def _open_payloads_tab(self):
		self._ensure_tab("_tab_payloads", lambda: PayloadsTab(self.api), "Payloads")

	def _open_operators_tab(self):
		self._ensure_tab("_tab_operators", lambda: OperatorsTab(self.api), "Operators")

	# ---------- Graph actions wiring ----------
	"""def _focus_graph(self):
		try:
			self.graph.view.centerOn(self.graph.c2)
			self.graph.view.raise_()
			# Give a gentle refresh
			self.graph.reload()
		except Exception:
			pass"""

	def _kill_session(self, sid: str, _hostname: str):
		"""
		Kill a session using the realtime WS API only.
		"""
		# Find/reuse the SessionsWSClient from the graph
		ws = getattr(self, "sessions_ws", None)
		if ws is None:
			ws = getattr(self.graph, "sessions_ws", None)
			if ws is not None:
				self.sessions_ws = ws  # cache for next time

		if not ws:
			print("[dashboard] kill_session: sessions WS not ready")
			return

		def _done(msg: dict):
			t = str(msg.get("type", "")).lower()
			if t == "killed":
				# Only refresh after a confirmed kill
				try:
					if self._tab_sessions:
						self._tab_sessions.reload()
				except Exception:
					pass
				try:
					self.graph.reload()
				except Exception:
					pass
			else:
				err = msg.get("error") or "unknown error"
				print(f"[dashboard] kill_session failed: {err}")

		try:
			ws.kill(sid, _done)
		except Exception as e:
			print(f"[dashboard] kill_session send failed: {e}")

	# ---------- Console tabs ----------
	def _open_console_tab(self, sid: str, hostname: str):
		# Build "username@hostname" using WS cache only (no REST)
		ws = getattr(self, "sessions_ws", None)
		s = ws.get_cached(sid) if ws else {}
		username = (s.get("user") or s.get("username")
					or (s.get("metadata") or {}).get("user") or "")

		if username:
			username = _strip_host_prefix(username, hostname)
			title = f"{username}@{hostname}"
		else:
			# fallback if user not available
			title = hostname

		# Reuse if open
		for i in range(self.tabs.count()):
			if self.tabs.tabText(i) == title:
				self.tabs.setCurrentIndex(i)
				return

		w = SessionConsole(self.api, sid, hostname)
		idx = self.tabs.addTab(w, title)
		self.tabs.setTabIcon(idx, QApplication.windowIcon())
		self.tabs.setCurrentIndex(idx)
		# When user clicks "Files" in the console, open a Files tab
		w.files_requested.connect(self._open_files_tab)

		# Store meta for tab-bar actions
		arch = ""
		try:
			s_cache = self.sessions_ws.get_cached(sid) if hasattr(self, "sessions_ws") else {}
			arch = (s_cache.get("metadata") or {}).get("arch") or s_cache.get("arch") or ""
		except Exception:
			pass
		self._set_tab_meta(w, "console", sid, hostname, username, arch)

		# If we didn’t have username yet, fetch it via WS and rename the tab once received
		if not username and ws:
			def _cb(msg):
				s2 = msg.get("session") or {}
				u2 = (s2.get("user") or s2.get("username")
					  or (s2.get("metadata") or {}).get("user") or "")
				if not u2:
					return
				new_title = f"{_strip_host_prefix(u2, hostname)}@{hostname}"
				j = self.tabs.indexOf(w)
				if j >= 0:
					self.tabs.setTabText(j, new_title)
					self._update_tab_meta_username(w, u2)
			ws.get(sid, cb=_cb)

	def _open_files_tab(self, sid: str, hostname: str):
		# avoid duplicates by title
		title = f"Files — {hostname}"
		for i in range(self.tabs.count()):
			if self.tabs.tabText(i) == title:
				self.tabs.setCurrentIndex(i)
				return

		s = self._lookup_from_cache(sid)
		meta = s.get("metadata") or {}
		os_type   = (meta.get("os") or s.get("os") or "").lower()
		transport = (s.get("transport") or meta.get("transport") or "").lower()
		interval  = meta.get("interval") or s.get("interval") or None
		jitter    = meta.get("jitter") or s.get("jitter") or None

		start_path = "C:\\" if os_type == "windows" else "/"

		w = FileBrowser(
			self.api, sid,
			start_path=start_path,
			os_type=os_type,
			transport=transport,
			beacon_interval=interval,
			beacon_jitter_pct=int(jitter or 0),
		)
		idx = self.tabs.addTab(w, title)
		self.tabs.setTabIcon(idx, QApplication.windowIcon())
		self.tabs.setCurrentIndex(idx)

	def _open_ldap_tab(self, sid: str, hostname: str):
		title = f"LDAP — {hostname}"

		# If it's already open: move it to index 0 and focus it
		for i in range(self.tabs.count()):
			if self.tabs.tabText(i) == title:
				if i != 0:
					w   = self.tabs.widget(i)
					ico = self.tabs.tabIcon(i)
					self.tabs.removeTab(i)
					self.tabs.insertTab(0, w, ico, title)
				self.tabs.setCurrentIndex(0)
				self._apply_splitter_mode()  # keep "heavy" behavior active
				return


		# Create and insert at index 0
		w = LdapBrowser(self.api, sid, hostname)
		idx = self.tabs.insertTab(0, w, title)
		self.tabs.setTabIcon(idx, QApplication.windowIcon())
		self.tabs.setCurrentIndex(idx)
		self._apply_splitter_mode()

	def _open_gunnershell_tab(self, sid: str, hostname: str):
		# Prefer cached WS snapshot; if missing, ask WS 'get' and open on reply
		sess = self.sessions_ws.get_cached(sid) or {}

		if not sess:
			# one-shot fetch; open once we have it
			def _cb(msg):
				s = msg.get("session") or {}
				self._try_open_gs_from_session(sid, hostname, s)
			self.sessions_ws.get(sid, cb=_cb)
			return
		# have it already
		self._try_open_gs_from_session(sid, hostname, sess)

	
	def _try_open_gs_from_session(self, sid: str, hostname: str, sess: dict):
		# Block until metadata is present
		if not self._is_meta_ready(sess):
			QMessageBox.information(self, "Please wait",
									"You must wait for metadata to complete before launching GunnerShell.\n"
									"Try again in a few seconds.")
			return
		# Optional: also require command mode like the CLI does
		mode = str(sess.get("mode") or (sess.get("metadata") or {}).get("mode") or "")
		if mode and mode.lower() != "cmd":
			QMessageBox.information(self, "Agent not ready",
									"The agent hasn't switched to command mode yet. Try again shortly.")
			return

		# Build tab title and open
		username = (sess.get("user") or sess.get("username") or (sess.get("metadata") or {}).get("user") or "")
		title = f"GS — { _strip_host_prefix(username, hostname) }@{hostname}" if username else f"GS — {hostname}"

		for i in range(self.tabs.count()):
			if self.tabs.tabText(i) == title:
				self.tabs.setCurrentIndex(i)
				return

		w = GunnershellConsole(self.api, sid, hostname)
		idx = self.tabs.addTab(w, title)
		self.tabs.setTabIcon(idx, QApplication.windowIcon())
		self.tabs.setCurrentIndex(idx)

		arch = (sess.get("arch") or (sess.get("metadata") or {}).get("arch") or "")
		user_for_meta = (sess.get("user") or sess.get("username") or (sess.get("metadata") or {}).get("user") or "")
		self._set_tab_meta(w, "gunnershell", sid, hostname, user_for_meta, arch)

	# In-Class Helpers

	def _is_meta_ready(self, sess: dict) -> bool:
		# Accept both top-level or nested "metadata" layouts
		meta = (sess.get("metadata") or sess) if isinstance(sess, dict) else {}
		os_str = str(meta.get("os") or "").lower()
		hostname = meta.get("hostname") or sess.get("hostname")
		user = meta.get("user") or sess.get("user") or sess.get("username")
		return bool(hostname and user and os_str in ("windows", "linux"))

	def _menu_stylesheet_dark(self) -> str:
		return """
			QMenu {
				background:#1a1f29;
				color:#e6e6e6;
				border:1px solid #3b404a;
			}
			QMenu::separator {
				height:1px;
				background:#3b404a;
				margin:6px 8px;
			}
			QMenu::item {
				padding:6px 14px;
				background:transparent;
				font-weight:400;       
				color:#e6e6e6;          
			}
			QMenu::item:selected {
				background:#2f3540;
				color:#ffffff;
			}
			QMenu::item:disabled {
				color:#9aa3ad;          
				font-weight:400;        
			}
		"""
	
	# ---- Bulk close helpers (relative to a given index) ----
	def _close_tabs_to_right(self, idx: int):
		# close from rightmost down to the one just after idx
		for j in range(self.tabs.count() - 1, idx, -1):
			self._close_tab(j)

	def _close_tabs_to_left(self, idx: int):
		# close from the one just before idx down to 0
		for j in range(idx - 1, -1, -1):
			self._close_tab(j)

	def _close_other_tabs(self, idx: int):
		# close everything except idx; iterate in reverse to avoid index shifts
		for j in range(self.tabs.count() - 1, -1, -1):
			if j != idx:
				self._close_tab(j)

	def _close_tab(self, index: int):
		w = self.tabs.widget(index)
		# Clear singleton handle if one of the admin tabs is closed
		if w is self._tab_sessions:
			self._tab_sessions = None

		elif w is self._tab_listeners:
			self._tab_listeners = None

		elif w is self._tab_payloads:
			self._tab_payloads = None

		elif w is self._tab_operators:
			self._tab_operators = None

		# drop tab meta if present
		try:
			if w in self._tab_meta:
				del self._tab_meta[w]
		except Exception:
			pass

		self.tabs.removeTab(index)
