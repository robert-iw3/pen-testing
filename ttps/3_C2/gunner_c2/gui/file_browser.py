# gui/file_browser.py
from __future__ import annotations

############################################################################
# SECTION: MODULE OVERVIEW & SPLIT PLAN                                    #
# This file is intentionally annotated with BIG SECTION BANNERS so you can #
# cut/paste each section into its own module (or Mixin) later. Each banner #
# lists a suggested filename, dependencies, and what it provides.          #
# Suggested split (filenames/classes):                                     #
#   • gui/file_browser_logging.py         => logger 'log' (setup)          #
#   • gui/file_items.py                   => NameItem, SizeItem            #
#   • gui/busy_overlay.py                 => BusyOverlay                   #
#   • gui/file_browser_init.py            => FileBrowser.__init__ (UI)     #
#   • gui/file_browser_theme.py           => _apply_theme()                #
#   • gui/file_browser_workspace.py       => header collapse/locks, host   #
#   • gui/file_browser_nav.py             => tabs, path bar, breadcrumbs   #
#   • gui/file_browser_live.py            => timers, refresh(), _on_list() #
#   • gui/file_browser_sidebar.py         => drives/quick handlers & views #
#   • gui/file_browser_pathutils.py       => _norm_path(), _join_path(),   #
#                                            fmt helpers                   #
#   • gui/file_transfers.py               => download/upload + handlers    #
#   • gui/archive_safe_extract.py         => _safe_extract_* helpers       #
#   • gui/file_browser_errors.py          => error handling, resize events #
# Extraction approach: turn each block into a `*Mixin` class OR functions  #
# that accept a FileBrowser instance (self). Then make FileBrowser inherit #
# the mixins.                                                              #
############################################################################

import logging, logging.handlers, traceback
import random, os, time, posixpath, ntpath, re, mimetypes
import datetime, zipfile, tarfile, tempfile, shutil, hashlib, binascii

from PyQt5.QtWidgets import (
	QWidget, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QLabel,
	QHBoxLayout, QVBoxLayout, QFileDialog, QMessageBox, QHeaderView, QToolButton,
	QApplication, QStyle, QFrame, QProgressBar, QShortcut, QMenu, QAbstractItemView,
	QSplitter, QTreeWidget, QTreeWidgetItem, QTabBar, QStackedWidget, QSizePolicy,
	QTabWidget
)

from PyQt5.QtCore import Qt, QTimer, QSortFilterProxyModel, QEvent, QObject, QSize
from PyQt5.QtGui import QKeySequence, QIcon

from files_ws_client import FilesWSClient
from gunner_text_editor import GunnerEditorWindow

############################################################################
# SECTION [LOGGING]: Logger initialization                                 #
# Suggested file: gui/file_browser_logging.py                              #
# Depends on: logging, logging.handlers, tempfile, os                      #
# Provides: 'log' configured RotatingFileHandler                           #
############################################################################


log = logging.getLogger("gui.file_browser")
if not log.handlers:
	try_paths = []
	try:
		try_paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui_filebrowser.log"))
	except Exception:
		pass
	try_paths.append(os.path.join(os.getcwd(), "gui_filebrowser.log"))
	try_paths.append(os.path.join(tempfile.gettempdir(), "gui_filebrowser.log"))
	_handler = None
	for _p in try_paths:
		try:
			_handler = logging.handlers.RotatingFileHandler(_p, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
			break
		except Exception:
			continue
	if _handler is None:
		_handler = logging.StreamHandler()
	_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
	_handler.setFormatter(_formatter)
	log.addHandler(_handler)
	log.setLevel(logging.DEBUG)
	log.propagate = False

############################################################################
# SECTION [HELPERS]: Small path/label helpers                              #
# Suggested file: gui/file_browser_pathutils.py (part 1)                   #
# Depends on: os.path                                                      #
# Provides: _sep_for(), _basename_for_label()                              #
############################################################################


# ---------- Small helpers ----------
def _sep_for(path: str, os_type: str) -> str:
	return "\\" if os_type.lower() == "windows" else "/"

def _basename_for_label(p: str) -> str:
	p = (p or "").rstrip("/\\")
	if not p: return p
	if "\\" in p and ("/" not in p): return p.split("\\")[-1]
	return p.split("/")[-1]

############################################################################
# SECTION [ITEM MODELS]: Table item classes                                #
# Suggested file: gui/file_items.py                                        #
# Depends on: PyQt5.QtWidgets (QTableWidgetItem), PyQt5.QtCore.Qt          #
# Provides: NameItem (dir-first sorting), SizeItem (numeric sort)          #
############################################################################


class NameItem(QTableWidgetItem):
	def __init__(self, text: str, is_dir: bool, icon: QIcon = None):
		super().__init__(text); self.is_dir = bool(is_dir)
		if icon: self.setIcon(icon)
	def __lt__(self, other):
		if isinstance(other, NameItem):
			if self.is_dir != other.is_dir:
				return self.is_dir and not other.is_dir
			return self.text().lower() < other.text().lower()
		return super().__lt__(other)


class SizeItem(QTableWidgetItem):
	def __init__(self, size_display: str, raw_size: int | None):
		super().__init__(size_display); self.raw_size = int(raw_size or 0)
		self.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
	def __lt__(self, other):
		if isinstance(other, SizeItem): return self.raw_size < other.raw_size
		return super().__lt__(other)

############################################################################
# SECTION [WIDGET]: BusyOverlay translucent progress overlay               #
# Suggested file: gui/busy_overlay.py                                      #
# Depends on: PyQt5 widgets/core                                           #
# Provides: BusyOverlay(QWidget) with setMessage()/showCentered()          #
############################################################################


class BusyOverlay(QFrame):
	def __init__(self, parent: QWidget, *, message: str = "Waiting for beacon…"):
		super().__init__(parent)
		self.setStyleSheet(
			"QFrame { background: rgba(0,0,0,120); border-radius: 8px; }"
			"QLabel { color: #e9eaec; font-size: 13px; }"
		)
		self.setVisible(False)
		self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
		self.setFocusPolicy(Qt.NoFocus)                  # don’t become the focus widget
		self.setAttribute(Qt.WA_ShowWithoutActivating, True)  # don’t activate when shown
		self.setFrameStyle(QFrame.NoFrame)
		lay = QVBoxLayout(self); lay.setContentsMargins(18,18,18,18); lay.setSpacing(10)
		self.lbl = QLabel(message, self)
		self.bar = QProgressBar(self); self.bar.setRange(0, 0); self.bar.setTextVisible(False)
		lay.addWidget(self.lbl, 0, Qt.AlignHCenter); lay.addWidget(self.bar)
		self.raise_()

	def setMessage(self, msg: str): self.lbl.setText(msg)
	def showCentered(self):
		p = self.parent() if isinstance(self.parent(), QWidget) else None
		if p: self.setGeometry(p.rect().adjusted(p.width()//4, p.height()//3, -p.width()//4, -p.height()//3))
		self.setVisible(True); self.raise_()
	def resizeEvent(self, e):
		self.showCentered(); super().resizeEvent(e)

############################################################################
# SECTION [WIDGET]: FileBrowser root widget                                #
# This class aggregates all sub-systems. Internal method groups are also   #
# bannered so you can relocate them into mixins/modules without renaming.  #
# Extraction: keep class name 'FileBrowser' and move groups into mixins    #
# imported here.                                                           #
############################################################################

class FileBrowser(QWidget):
	"""
	Live, OS- and transport-aware file browser with diffed UI updates.
	  • TCP: ~1s live updates.
	  • HTTP/HTTPS: auto-updates on beacon interval (with jitter). A translucent overlay
		shows while a list request is in-flight so users know we’re waiting on the next beacon.
	  • Only re-renders rows when something actually changed.
	"""

	########################################################################
	# SUBSECTION [FB-INIT-UI]: __init__ – UI layout, wiring, WS setup      #
	# Suggested file/mixin: gui/file_browser_init.py :: FileBrowserInitMixin#
	# Depends on: PyQt5, FilesWSClient, logging, BusyOverlay, helpers       #
	# Provides: constructor only                                            #
	########################################################################

	def __init__(self, api, sid: str, start_path: str = ".", os_type: str = "",
				 transport: str = "", beacon_interval: float | None = None, beacon_jitter_pct: int | None = None):
		super().__init__()
		self.api = api
		self.sid = sid
		self.path = start_path
		self._tab_paths: dict[int, str] = {}
		self.os_type = (os_type or "").lower()
		self.transport = (transport or "").lower()
		self.beacon_interval = float(beacon_interval or 0.0)  # seconds
		self.beacon_jitter_pct = int(beacon_jitter_pct or 0)
		self._pending_path: str | None = None
		self._queued_nav: str | None = None
		self._showing_drives = False
		self._showing_quick = False
		#self._drive_rows: dict[int, str] = {}  # row -> root path
		#self._quick_rows: dict[int, str] = {}  # row -> quick path
		self._quickpaths: dict = {}

		# --- Gunner editor / download+save state ---
		self._edl_active = False
		self._edl_remote = None
		self._edl_name = None
		self._edl_buf = bytearray()
		self._editor_save_inflight = False
		self._editor_save_tmp = None
		self._editor_save_done = None

		# --- debug/correlation ---
		self._req_seq = 0
		self._inflight_req = None  # (seq, target, reason, t0)
		self._refresh_reason = "init"

		if self.path in ("", ".", "./"):
			self.path = "C:\\" if self.os_type == "windows" else "/"

		# Cache of last listing for diffing: {name: (is_dir, size)}
		self._last_listing: dict[str, tuple[bool, int]] = {}

		# ---------- Icons ----------
		sty = QApplication.style()
		self.icon_dir = sty.standardIcon(QStyle.SP_DirIcon)
		self.icon_file = sty.standardIcon(QStyle.SP_FileIcon)
		self.icon_up = sty.standardIcon(QStyle.SP_ArrowUp)
		self.icon_computer = sty.standardIcon(QStyle.SP_ComputerIcon)
		self.icon_drive = sty.standardIcon(QStyle.SP_DriveHDIcon)
		# Top toolbar icons
		self.icon_back = sty.standardIcon(QStyle.SP_ArrowLeft)
		self.icon_forward = sty.standardIcon(QStyle.SP_ArrowRight)
		try:
			self.icon_refresh = sty.standardIcon(QStyle.SP_BrowserReload)
		except Exception:
			self.icon_refresh = sty.standardIcon(QStyle.SP_BrowserStop)
		self._top_icon_sz = QSize(22, 22)  # crisp, larger
		self._nav_icon_sz = QSize(22, 22)  # legacy safety if anything still references it

		# ---------- Tabs ----------
		self.tabs = QTabBar(self); self.tabs.setMovable(True); self.tabs.setTabsClosable(True)
		self.tabs.setExpanding(False); self.tabs.setElideMode(Qt.ElideRight); self.tabs.setDocumentMode(True)
		self.tabs.currentChanged.connect(self._on_tab_changed)
		self.tabs.tabCloseRequested.connect(self._on_tab_close)
		self._new_tab_btn = QToolButton(self); self._new_tab_btn.setText("+"); self._new_tab_btn.clicked.connect(self._new_tab)

		# ---------- Path bar (crumbs <-> editable) ----------
		self._path_stack = QStackedWidget(self)
		self.path_edit = QLineEdit(self.path)
		self.path_edit.setPlaceholderText("Type a path and press Enter…")
		# Keep the path field compact instead of stretching vertically
		self.path_edit.setFixedHeight(30)  # ~28–32px looks good with 13px font
		self._path_stack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
		self.path_edit.returnPressed.connect(self._apply_path_edit)
		self.path_edit.editingFinished.connect(self._cancel_edit_to_crumbs)
		
		self._crumbs_host = QWidget(self)
		self._crumbs_host.setObjectName("CrumbsHost")
		self._crumbs_host.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

		self.crumbs = QHBoxLayout(self._crumbs_host); self.crumbs.setSpacing(6); self.crumbs.setContentsMargins(0, 0, 0, 0)
		self._path_stack.addWidget(self._crumbs_host)
		self._path_stack.addWidget(self.path_edit)
		self._path_stack.setCurrentWidget(self._crumbs_host)
		self._crumbs_host.mouseDoubleClickEvent = lambda e: self._switch_to_edit()

		# ---- Header TOP rows: (1) Tabs  (2) Explorer-style TopNavBar ----
		topbar = QHBoxLayout(); topbar.setSpacing(6); topbar.setContentsMargins(0,0,0,0)
		topbar.addWidget(self.tabs, 1); topbar.addWidget(self._new_tab_btn, 0)

		# ===== Explorer-style TopNavBar =====
		self.topnav = QWidget(self); self.topnav.setObjectName("TopNavBar")
		_top = QHBoxLayout(self.topnav); _top.setContentsMargins(8,8,8,8); _top.setSpacing(8)

		def _mk_top_btn(icon: QIcon, tip: str, fallback: str) -> QToolButton:
			b = QToolButton(self.topnav)
			b.setProperty("toolbar", True)
			b.setCursor(Qt.PointingHandCursor)
			b.setToolTip(tip)
			b.setMinimumHeight(36)
			if icon and not icon.isNull():
				b.setIcon(icon); b.setIconSize(self._top_icon_sz)
			else:
				b.setText(fallback)
			return b

		self.btn_top_back    = _mk_top_btn(self.icon_back,    "Back",    "←"); self.btn_top_back.clicked.connect(self.nav_back)
		self.btn_top_forward = _mk_top_btn(self.icon_forward, "Forward", "→"); self.btn_top_forward.clicked.connect(self.nav_forward)
		self.btn_top_up      = _mk_top_btn(self.icon_up,      "Up",      "↑"); self.btn_top_up.clicked.connect(self.up)
		self.btn_top_refresh = _mk_top_btn(self.icon_refresh, "Refresh", "↻"); self.btn_top_refresh.clicked.connect(lambda: self._kick_live(immediate=True))

		left_cluster = QHBoxLayout(); left_cluster.setContentsMargins(0,0,0,0); left_cluster.setSpacing(6)
		_w_left = QWidget(self.topnav); _w_left.setLayout(left_cluster)
		left_cluster.addWidget(self.btn_top_back)
		left_cluster.addWidget(self.btn_top_forward)
		left_cluster.addSpacing(4)
		left_cluster.addWidget(self.btn_top_up)
		left_cluster.addWidget(self.btn_top_refresh)

		# Location icon + crumbs (exact Explorer layout)
		self.lbl_loc_icon = QLabel(self.topnav)
		try: self.lbl_loc_icon.setPixmap(self.icon_computer.pixmap(18,18))
		except Exception: pass
		_loc_wrap = QHBoxLayout(); _loc_wrap.setContentsMargins(0,0,0,0); _loc_wrap.setSpacing(6)
		_w_loc = QWidget(self.topnav); _w_loc.setLayout(_loc_wrap)
		_loc_wrap.addWidget(self.lbl_loc_icon, 0, Qt.AlignVCenter)
		_loc_wrap.addWidget(self._path_stack, 1)

		# Search on the far right (moved from bottom actions)
		self.search = QLineEdit(self.topnav); self.search.setFixedHeight(30); self.search.setPlaceholderText("Search This PC")

		_top.addWidget(_w_left, 0); _top.addWidget(_w_loc, 1); _top.addWidget(self.search, 0)

		# compact header (tabs + TopNavBar)
		header = QVBoxLayout(); header.setSpacing(2); header.setContentsMargins(0,0,0,0)
		header.addLayout(topbar); header.addWidget(self.topnav)


		# ---------- Table ----------
		self.table = QTableWidget(0, 4)
		self._ensure_main_columns()
		self.table.setAlternatingRowColors(False)
		self.table.setSortingEnabled(True)	
		self.table.setEditTriggers(QTableWidget.NoEditTriggers)
		self.table.setSelectionBehavior(QTableWidget.SelectRows)
		self.table.verticalHeader().setVisible(False)
		self.table.cellDoubleClicked.connect(self._cell_dbl)
		# Also allow Enter/Space to open the selected row (safer than relying only on double-click)
		self.table.itemActivated.connect(lambda _: self._open_selection())

		# Background (nothing-selected) context menu
		self.table.setContextMenuPolicy(Qt.CustomContextMenu)
		self.table.customContextMenuRequested.connect(self._on_table_context_menu)

		# internal flags for "New" actions that use silent upload fallbacks
		self._silent_create = False
		self._create_temp_artifacts = []

		# ---------- Left pane: (Quick access / This PC) tree ----------
		self.sidebar = QTreeWidget(self); self.sidebar.setObjectName("Sidebar")
		self.sidebar.setHeaderHidden(True); self.sidebar.setIndentation(14)
		self.sidebar.setExpandsOnDoubleClick(True)
		self._node_quick = QTreeWidgetItem(self.sidebar, ["Quick access"])

		self._node_pc = QTreeWidgetItem(self.sidebar, ["This PC"])
		# NEW: Users inside Quick access
		self._quick_users_item = QTreeWidgetItem(self._node_quick, ["Users"])
		self._quick_users_item.setData(0, Qt.UserRole, self._users_root_path() if self.os_type == "windows" else None)

		self._node_quick.setExpanded(True); self._node_pc.setExpanded(True)
		self.sidebar.itemClicked.connect(self._on_nav_click)

		# fill placeholders until WS replies
		for key, label in [("desktop","Desktop"),("documents","Documents"),
						   ("downloads","Downloads"),("pictures","Pictures"),("videos","Videos")]:
			n = QTreeWidgetItem(self._node_quick, [label]); n.setData(0, Qt.UserRole, None)
		QTreeWidgetItem(self._node_pc, ["Loading drives…"]).setData(0, Qt.UserRole, None)

		# ----- split views (LEFT = toolbar + tree) -----
		self.split = QSplitter(self); self.split.setChildrenCollapsible(False)
		_left = QWidget(self); _left_lay = QVBoxLayout(_left); _left_lay.setContentsMargins(0,0,0,0); _left_lay.setSpacing(6)
		_left_lay.addWidget(self.sidebar, 1)
		self.split.addWidget(_left)
		right = QWidget(self); right_lay = QVBoxLayout(right); right_lay.setContentsMargins(0,0,0,0); right_lay.setSpacing(6)
		right_lay.addLayout(header); right_lay.addWidget(self.table)
		self.split.addWidget(right)
		self.split.setStretchFactor(1, 1)
		_left.setMinimumWidth(220)

		# --- Actions row (Explorer-like) ---
		self.btn_download = QToolButton()
		self.btn_download.setText("Download")
		self.btn_download.setToolButtonStyle(Qt.ToolButtonTextOnly)

		self.btn_upload = QToolButton()
		self.btn_upload.setText("Upload")
		self.btn_upload.setPopupMode(QToolButton.InstantPopup)
		m = QMenu(self.btn_upload)
		act_file = m.addAction("File…")
		act_folder = m.addAction("Folder…")
		self.btn_upload.setMenu(m)

		self.btn_refresh = QToolButton()
		self.btn_refresh.setText("Refresh")

		self.btn_download.setEnabled(False)
		self.table.itemSelectionChanged.connect(
			lambda: self.btn_download.setEnabled(bool(self.table.selectionModel().selectedRows()))
		)

		bottom = QHBoxLayout()
		bottom.addWidget(self.btn_upload)
		bottom.addWidget(self.btn_download)
		bottom.addWidget(self.btn_refresh)
		bottom.addStretch()

		self.status = QLabel("Live")
		self.status.setObjectName("StatusLabel")
		bottom.addWidget(self.status)

		# ---------- Root layout ----------
		# Pull the file table up tight under the outer tab bar
		root = QVBoxLayout(self); root.setContentsMargins(10, 6, 10, 8); root.setSpacing(6)
		root.addWidget(self.split, 1)
		root.addLayout(bottom)

		# ---------- Shortcuts ----------
		# Limit to the file list so they don't steal keys from edits.
		_sc_back = QShortcut(QKeySequence(Qt.Key_Backspace), self.table, activated=self.up)
		_sc_back.setContext(Qt.WidgetWithChildrenShortcut)
		QShortcut(QKeySequence("Ctrl+L"), self, activated=self._switch_to_edit)
		QShortcut(QKeySequence("Ctrl+T"), self, activated=self._new_tab)
		QShortcut(QKeySequence("Ctrl+U"), self, activated=self._upload_pick_files_only)
		QShortcut(QKeySequence("Ctrl+D"), self, activated=self.download)
		# Enter to open selection — only when the table has focus.
		for _k in (Qt.Key_Return, Qt.Key_Enter):  # include keypad Enter
			_sc_open = QShortcut(QKeySequence(_k), self.table, activated=self._open_selection)
			_sc_open.setContext(Qt.WidgetWithChildrenShortcut)
		# keep refs (optional; parent ownership is enough, but harmless)
		self._scoped_shortcuts = [_sc_back]


		# ---------- Wiring ----------
		self.btn_download.clicked.connect(self.download)
		act_file.triggered.connect(self._upload_pick_files_only)
		act_folder.triggered.connect(self._upload_pick_folder_only)
		self.btn_refresh.clicked.connect(lambda: self._kick_live(immediate=True))
		self.search.textChanged.connect(self._apply_search_filter)
		self.search.returnPressed.connect(self._on_search_return)  # allow absolute path -> navigate

		# Initial header text/icon/search placeholder
		self._update_search_placeholder()

		# ---------- WS client ----------
		self.fws = FilesWSClient(self.api.base_url, self.api.token, self)
		self.fws.drives.connect(self._on_drives)
		self.fws.quickpaths.connect(self._on_quickpaths)

		# Optional: if FilesWSClient exposes these signals, capture them.
		# (Safe to connect; if not present, the except keeps this no-op.)
		try:
			self.fws.dl_meta.connect(self._on_dl_meta)  # total_bytes
		except Exception:
			pass

		# connect ALL signals BEFORE opening
		self.fws.connected.connect(self._on_files_ws_connected)
		self.fws.listed.connect(self._on_list)
		self.fws.dl_begin.connect(self._on_dl_begin)
		self.fws.dl_chunk.connect(self._on_dl_chunk)
		self.fws.dl_end.connect(self._on_dl_end)
		self.fws.up_progress.connect(lambda w, t: None)
		self.fws.up_result.connect(self._on_up_result)
		self.fws.error.connect(self._on_error)
		self.fws.created.connect(self._on_created)

		# --- Selection-aware action row state & Delete shortcut ---
		self.table.itemSelectionChanged.connect(self._update_action_row_state)

		# Hide Upload whenever there is a selection
		self._update_action_row_state()  # set initial state

		# Delete key shortcut (only while table focused)
		_sc_del = QShortcut(QKeySequence(Qt.Key_Delete), self.table, activated=self._delete_selection)
		_sc_del.setContext(Qt.WidgetWithChildrenShortcut)
		self._scoped_shortcuts.append(_sc_del)

		# Try to listen for 'deleted' signals from the FilesWSClient (optional)
		try:
			self.fws.deleted.connect(self._on_deleted)
		except Exception:
			pass

		self.fws.open()

		# Overlay for HTTP/S “waiting for beacon”
		self.overlay = BusyOverlay(self, message="Waiting for HTTP/HTTPS beacon…")

		# Download telemetry remembered between frames
		self._dl_expect_total: int | None = None
		self._dl_expect_sha: str | None = None
		self._dl_srv_head: str | None = None
		self._dl_srv_tail: str | None = None

		# Live update timer
		self._busy = False
		self._auto_timer = QTimer(self)
		self._auto_timer.setSingleShot(True)
		self._auto_timer.timeout.connect(self._auto_tick)

		# NEW: busy guard to recover if first request was dropped
		self._busy_guard = QTimer(self)
		self._busy_guard.setSingleShot(True)
		self._busy_guard.timeout.connect(self._busy_timed_out)

		self._apply_theme()
		self._rebuild_breadcrumbs()

		try:
			log.info("FileBrowser init sid=%s os=%s transport=%s start_path=%s beacon=%s jitter=%s",
					 self.sid, self.os_type, self.transport, self.path, self.beacon_interval, self.beacon_jitter_pct)
		except Exception:
			pass

		# --- lock outer splitter (the one with the 3-dot grip) like Payloads does ---
		self._locked_splitter = None
		self._locked_splitter_old_css = None
		self._locked_handle_blockers = []

		# first tab
		self._new_tab(initial=True)
		self._kick_live(initial=True)

		# --- History (Back/Forward) ---
		self._hist: list[str] = [self.path]
		self._hist_idx: int = 0
		self._hist_freeze: bool = False
		self._update_nav_buttons()

		# Lock the *workspace* tab bar while this tab is active (match Payloads)
		self._locked_tabbar: QTabBar | None = None
		self._orig_movable: bool | None = None
		self._lock_parent_tabbar()

		# Defer attaching to the host tab widget until we're parented into it
		QTimer.singleShot(0, self._attach_host_tab_signals)

		# Will be toggled on show/hide
		self._locked_tabbar: QTabBar | None = None
		self._orig_movable: bool | None = None
		self._files_mode_active = False

		# Also collapse the outer header splitter (remove big gap & dots)
		self._host_splitter: QSplitter | None = None
		self._old_split_sizes: list[int] | None = None
		self._old_splitter_css: str | None = None
		self._old_handle_w: int | None = None
		self._collapse_workspace_header(True)

	def _leave_pseudo_and_go(self, target: str):
		# Leaving "This PC" / "Quick access" pseudo views
		self._showing_drives = False
		self._showing_quick = False
		try:
			self.overlay.setVisible(False)
		except Exception:
			pass
		# Normalize "C:" -> "C:\"
		if isinstance(target, str) and re.fullmatch(r"[A-Za-z]:\\?$", target.strip()):
			target = target.strip()[:2] + "\\"
		self._navigate_or_queue(target)

	# ---- Ensure the main 4 columns (Explorer-like) are active ----
	# Keep the main (Explorer-like) columns consistent whenever we show a real folder.
	def _ensure_main_columns(self):
		self.table.setColumnCount(5)
		self.table.setHorizontalHeaderLabels(["Name", "Date modified", "Type", "Owner", "Size"])
		hdr = self.table.horizontalHeader()
		hdr.setStretchLastSection(False)
		hdr.setSectionResizeMode(0, QHeaderView.Interactive)
		try:
			if hdr.sectionSize(0) < 420:
				hdr.resizeSection(0, 420)
		except Exception:
			pass
		# auto-size Date modified, Type, Owner, Size
		for i in (1, 2, 3, 4):
			hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)

	# ----- coercers for back-end variability -----
	def _coerce_is_dir(self, r: dict) -> bool:
		v = r.get("is_dir", r.get("dir", r.get("directory", r.get("isDirectory"))))
		if isinstance(v, bool): return v
		if isinstance(v, (int, float)): return bool(int(v))
		if isinstance(v, str):
			s = v.strip().lower()
			if s in {"1","true","yes","y","dir","folder","directory","d"}: return True
			if s in {"0","false","no","n","file","f"}: return False
		# MIME-style hints
		mime = str(r.get("mime") or r.get("mimetype") or r.get("content_type") or "").lower()
		if mime in {"inode/directory","application/x-directory"}: return True
		# Type labels some back-ends use
		t = str(r.get("type") or "").strip().lower()
		if t in {"dir","folder","directory"}: return True
		if t in {"file"}: return False
		return False

	def _coerce_owner(self, r: dict) -> str:
		o = str(r.get("owner") or r.get("user") or r.get("username") or "").strip()
		if "\\" in o:
			o = o.split("\\")[-1].strip()
		return o

	def _coerce_mtime_ms(self, r: dict) -> int:
		for k in ("mtime_ms","mtime","modified","last_modified","updated","timestamp","time","date"):
			if k in r and r[k] is not None:
				v = r[k]
				# numeric (seconds or ms)
				if isinstance(v, (int, float)):
					return int(v if v > 1e12 else v * 1000)
				# numeric string
				if isinstance(v, str) and v.strip().isdigit():
					n = int(v.strip())
					return int(n if n > 1e12 else n * 1000)
				# ISO 8601 string
				if isinstance(v, str):
					s = v.strip().replace("Z", "+00:00")
					try:
						dt = datetime.datetime.fromisoformat(s)
						return int(dt.timestamp() * 1000)
					except Exception:
						pass
		return 0

	def _coerce_size_int(self, r: dict) -> int:
		for k in ("size","length","bytes","byte_size","st_size"):
			if k in r and r[k] is not None:
				try: return int(float(r[k]))
				except Exception: return 0
		return 0


	# ----- Editor integration -----
	def _open_remote_text_in_editor(self, remote_path: str, display_name: str):
		"""Download file into RAM, decode, show Gunner editor (single instance, tabbed)."""
		# mark editor-download mode so our dl_* handlers route bytes to a RAM buffer
		self._edl_active = True
		self._edl_remote = remote_path
		self._edl_name = display_name
		self._edl_buf = bytearray()
		self.status.setText("Opening in editor…")
		self.fws.start_download(self.sid, remote_path)

	def _get_or_make_editor(self) -> GunnerEditorWindow:
		return GunnerEditorWindow.get_or_create(self)

	def _save_text_back_to_remote(self, remote_path: str, text: str, done_cb):
		"""
		Write text to a temp file and upload back to the same remote path.
		We serialize saves (one at a time) using a tiny guard.
		"""
		if getattr(self, "_editor_save_inflight", False):
			done_cb(False, "Another save is already in progress; please retry in a moment.")
			return
		import tempfile, os
		fd, tmp = tempfile.mkstemp(prefix="gc2_editor_", suffix=".txt")
		os.close(fd)
		try:
			with open(tmp, "w", encoding="utf-8") as f:
				f.write(text)
		except Exception as e:
			try:
				os.remove(tmp)
			except Exception:
				pass
			done_cb(False, f"Failed to stage temp file: {e}")
			return
		# route the next upload result back to this editor save
		self._editor_save_inflight = True
		self._editor_save_tmp = tmp
		self._editor_save_done = done_cb
		self.status.setText("Saving…")
		self.fws.start_upload(self.sid, tmp, remote_path)

	# ---------- Text file detection / decode helpers ----------
	def _is_text_like(self, name: str, type_label: str = "") -> bool:
		"""
		Decide if a file is "text-like" based on extension and any type label.
		Falls back to the class's _guess_type(name, for_icon=False) if present.
		"""
		nm = (name or "").lower()
		ext = nm.rsplit(".", 1)[-1] if "." in nm else ""
		TEXT_EXTS = {
			"txt","md","rtf","csv","tsv","log","ini","cfg","conf","yaml","yml","json","xml","sql",
			"py","js","ts","tsx","jsx","java","c","h","hpp","cpp","cc","go","rs","rb","php","sh","bash","zsh",
			"ps1","bat","cmd","lua","toml","env","properties","gradle","kt","kts","scala","pl","r","m","mm",
			"css","scss","less","html","htm","xhtml","svg","srt","vtt","tex"
		}
		if ext in TEXT_EXTS:
			return True

		guesser = getattr(self, "_guess_type", None)
		guessed = ""
		if not type_label and callable(guesser):
			try:
				guessed = guesser(name, False) or ""
			except Exception:
				guessed = ""
		tl = (type_label or guessed).lower()

		if any(k in tl for k in (
			"text", "markdown", "yaml", "json", "xml", "script", "source",
			"python", "javascript", "typescript", "html", "css", "ini", "log"
		)):
			return True

		return False


	def _decode_text_for_editor(self, data: bytes) -> tuple[str, str]:
		"""
		Decode bytes into text for the editor. Tries utf-8/utf-16 variants first,
		then falls back to latin-1 with replacement so the user always sees something.
		Returns (text, encoding_used).
		"""
		for enc in ("utf-8-sig", "utf-16-le", "utf-16-be", "utf-8"):
			try:
				return data.decode(enc), enc
			except Exception:
				pass
		return data.decode("latin-1", errors="replace"), "latin-1"


	########################################################################
	# SUBSECTION [FB-THEME]: Styling / QSS application                      #
	# Suggested file/mixin: gui/file_browser_theme.py :: FileBrowserTheme…  #
	# Provides: _apply_theme()                                              #
	########################################################################

	# ---------- Styling ----------
	def _apply_theme(self):
		self.setStyleSheet("""
			QWidget { background:#0e1420; color:#e8e8e8; font-size:13px; }
			QLabel { background:transparent; }
			QLabel#StatusLabel { color:#8a93a3; }
			/* Compact tabs */
			QTabBar { margin-bottom: -2px; }
			QTabBar::tab { background:#131a26; border:1px solid #273245; padding:4px 8px; margin-right:6px;
						   border-top-left-radius:8px; border-top-right-radius:8px; min-height: 22px; }
			QTabBar::tab:selected { background:#192235; }
			/* Crumbs host shouldn’t reserve vertical space */
			#CrumbsHost { background:transparent; padding:0; margin:0; min-height: 0; }
			QToolButton[crumb="true"] { background:#131a26; border:1px solid #273245; border-radius:8px; padding:4px 8px; }
			QToolButton[crumb="true"]:hover { background:#172134; }
			QLineEdit { background:#0b111a; color:#e8e8e8; border:1px solid #273245; border-radius:8px; padding:6px 10px; }
			QToolButton, QPushButton {
				background:#131a26; color:#e8e8e8; border:1px solid #273245; border-radius:8px; padding:6px 12px;
			}

			/* ===== Windows 11-style TopNavBar ===== */
			#TopNavBar {
				background:#111722;
				border:1px solid #1d2635;
				border-radius:10px;
			}
			#TopNavBar QToolButton[toolbar="true"] {
				min-width:36px; min-height:36px; border-radius:10px; padding:0;
			}
			#TopNavBar QToolButton[toolbar="true"]:hover { background:#172134; }
			#TopNavBar QToolButton[toolbar="true"]:pressed { background:#101826; }
			#TopNavBar QLineEdit {
				background:#0b111a; color:#e8e8e8; border:1px solid #273245; border-radius:8px; padding:6px 10px;
				min-width:240px;
			}
			/* Breadcrumbs more “to a tee”: flat text-like with chevrons */
			#CrumbsHost { background:transparent; padding:0; margin:0; min-height:0; }
			QToolButton[crumb="true"] {
				background:transparent; border:0; border-radius:6px; padding:2px 6px; color:#e8e8e8;
			}
			QToolButton[crumb="true"]:hover { background:#1a2234; }
			QLabel#CrumbSep { color:#8a93a3; padding:0 4px; }
			/* ===== end TopNavBar ===== */

			/* (Sidebar mini-toolbar CSS left as-is if present elsewhere) */

			QToolButton:hover, QPushButton:hover { background:#172134; }
			QToolButton:pressed, QPushButton:pressed { background:#101826; }
			
			#Sidebar {
				background:#111722;
				border:1px solid #1d2635;
				border-radius:10px;
				selection-background-color:#1b2740;   /* fallback for some styles */
				selection-color:#e8e8e8;
				show-decoration-selected: 0;          /* prevent blue chip on the left */
				outline: 0;                            /* no dotted focus outline */
			}
			QTreeWidget#Sidebar::item { height:26px; padding:2px 10px; }
			QTreeWidget#Sidebar::item:hover { background:#172134; }
			QTreeWidget#Sidebar::item:selected,
			QTreeWidget#Sidebar::item:selected:active,
			QTreeWidget#Sidebar::item:selected:!active {
				background:#1b2740; color:#e8e8e8; border:0;
			}
			QTreeWidget#Sidebar::branch:selected,
			QTreeWidget#Sidebar::branch:selected:active,
			QTreeWidget#Sidebar::branch:selected:!active { background: transparent; }

			QTableWidget {
				background:#0b111a; border:1px solid #1d2635; border-radius:10px; gridline-color:#1b2434;
			}
			QHeaderView::section {
				background:#111722; color:#e8e8e8; padding:6px 8px; border:0px; border-right:1px solid #1b2434;
			}
			QTableWidget::item:selected { background:#193156; }
			QProgressBar { background:#0b111a; border:1px solid #273245; border-radius:6px; }

			/* Hide any splitter grabber “dots” so it doesn’t look draggable here */
			QSplitter::handle { image: none; }
			QToolBar::handle { image: none; }
			QLabel#CrumbSep { color:#8a93a3; padding:0 6px; }
		""")
		# tighter table rows
		self.table.verticalHeader().setDefaultSectionSize(28)

	########################################################################
	# SUBSECTION [FB-WORKSPACE-HEADER]: Collapse/restore workspace header   #
	# Suggested file/mixin: gui/file_browser_workspace.py                   #
	# Provides: _find_host_splitter(), _collapse_workspace_header()         #
	########################################################################

	# ---------- Collapse / restore the outer workspace header (three-dots splitter) ----------
	def _find_host_splitter(self) -> QSplitter | None:
		"""
		Walk up the parents to find the nearest *vertical* QSplitter that hosts this
		page area (the one that shows the draggable 'three dots' between header & content).
		"""
		w = self.parent()
		while w is not None:
			if isinstance(w, QSplitter) and w.orientation() == Qt.Vertical:
				return w
			w = w.parent()
		return None

	def _collapse_workspace_header(self, on: bool):
		sp = self._host_splitter or self._find_host_splitter()
		if not isinstance(sp, QSplitter):
			return
		if on:
			# Save state once
			self._host_splitter = sp
			if self._old_split_sizes is None:
				# Only capture if it doesn't already look collapsed
				try:
					_sizes = list(sp.sizes() or [])
				except Exception:
					_sizes = []
				if len(_sizes) >= 2 and min(_sizes) > 2:
					self._old_split_sizes = _sizes

			if self._old_handle_w is None:
				self._old_handle_w = sp.handleWidth()

			if self._old_splitter_css is None:
				self._old_splitter_css = sp.styleSheet()

			# Collapse the top pane (header/tabs) so Files sits flush at the top
			sizes = sp.sizes()
			total = max(1, sum(sizes) or 1)
			sp.setSizes([0, total])                    # give everything to bottom (tabs)
			try:
				sp.setHandleWidth(0)                   # hide the bar width entirely
			except Exception:
				pass
			# Hide the “three dots” handle while active
			try:
				sp.setStyleSheet(self._old_splitter_css + " QSplitter::handle { image: none; background: transparent; height: 0px; }")
			except Exception:
				pass
		else:
			# Restore splitter to whatever it was before
			try:
				if self._old_split_sizes:
					sp.setSizes(self._old_split_sizes)
				if self._old_handle_w is not None:
					sp.setHandleWidth(self._old_handle_w)
				if self._old_splitter_css is not None:
					sp.setStyleSheet(self._old_splitter_css)
			except Exception:
				pass

	########################################################################
	# SUBSECTION [FB-LOCK-OUTER-SPLITTER]: Lock/unlock 3-dot splitter       #
	# Suggested file/mixin: gui/file_browser_workspace.py                   #
	# Provides: _HandleEater, _find_host_splitter_and_child(),              #
	#           _lock_parent_splitter(), _unlock_parent_splitter()          #
	########################################################################

	# ---------- Lock/unlock the OUTER splitter (the 3-dot grip) ----------
	class _HandleEater(QObject):
		def eventFilter(self, obj, ev):
			# Kill any mouse/hover interaction so the handle can't be dragged
			if ev.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease,
							 QEvent.MouseMove, QEvent.HoverMove, QEvent.HoverEnter):
				return True
			return False

	def _find_host_splitter_and_child(self):
		"""
		Walk up until we find the QSplitter that directly contains this Files tab area.
		Return (splitter, direct_child_widget_in_that_splitter) or (None, None).
		"""
		child = self
		p = self.parent()
		while p is not None and not isinstance(p, QSplitter):
			child = p
			p = p.parent()
		return (p, child) if isinstance(p, QSplitter) else (None, None)

	def _lock_parent_splitter(self):
		# Already locked?
		if self._locked_splitter:
			return
		split, direct_child = self._find_host_splitter_and_child()
		if not split:
			return
		# Eat mouse events on every handle so it can't be dragged
		self._locked_handle_blockers = []
		for i in range(1, split.count()):
			h = split.handle(i)
			if h:
				blocker = FileBrowser._HandleEater(h)
				h.installEventFilter(blocker)
				try:
					h.setCursor(Qt.ArrowCursor)
				except Exception:
					pass
				self._locked_handle_blockers.append((h, blocker))

		# Hide the grip dots on THIS splitter only
		self._locked_splitter_old_css = split.styleSheet()
		split.setStyleSheet("QSplitter::handle { image: none; background: transparent; }")

		# Snap sizes so the file browser sits right up under the top area
		try:
			idx = split.indexOf(direct_child)
			if idx != -1:
				sz = split.sizes()
				total = max(1, sum(sz) or 1)
				new = [1] * len(sz)
				# Give our pane almost everything; keep others 1px so they remain visible
				new[idx] = max(total - (len(sz) - 1), 1)
				split.setSizes(new)
		except Exception:
			pass

		self._locked_splitter = split

	########################################################################
	# SUBSECTION [FB-LOCK-TABBAR]: Lock/unlock host tab bar                 #
	# Suggested file/mixin: gui/file_browser_workspace.py                   #
	# Provides: _lock_parent_tabbar(), _unlock_parent_tabbar()              #
	########################################################################

	# ---------- Lock/unlock workspace tab bar (like Payloads) ----------
	def _lock_parent_tabbar(self):
		"""
		Find the nearest QTabWidget hosting this widget and temporarily make its
		tab bar non-movable while the Files tab is active.
		"""
		w = self.parent()
		host_tabw = None
		while w is not None and not isinstance(w, QTabWidget):
			w = w.parent()
		host_tabw = w
		if not host_tabw:
			return
		tb = host_tabw.tabBar()
		if isinstance(tb, QTabBar):
			self._locked_tabbar = tb
			self._orig_movable = tb.isMovable()
			tb.setMovable(False)
			tb.setDocumentMode(True)
			tb.setFocusPolicy(Qt.NoFocus)

	def _unlock_parent_splitter(self):
		split = self._locked_splitter
		if not split:
			return
		# Remove filters
		for h, blocker in self._locked_handle_blockers:
			try:
				h.removeEventFilter(blocker)
			except Exception:
				pass
		self._locked_handle_blockers = []
		# Restore CSS
		try:
			split.setStyleSheet(self._locked_splitter_old_css or "")
		except Exception:
			pass
		self._locked_splitter = None
		self._locked_splitter_old_css = None

	def _unlock_parent_tabbar(self):
		"""
		Restore the parent tab bar's movable state when leaving the Files tab.
		Safe even if no lock was applied.
		"""
		tb = getattr(self, "_locked_tabbar", None)
		if isinstance(tb, QTabBar) and self._orig_movable is not None:
			try:
				tb.setMovable(bool(self._orig_movable))
			except Exception:
				pass
		self._locked_tabbar = None
		self._orig_movable = None



	########################################################################
	# SUBSECTION [FB-HOST-TAB-COORD]: Host QTabWidget coordination          #
	# Suggested file/mixin: gui/file_browser_workspace.py                   #
	# Provides: _attach_host_tab_signals(), _on_host_tab_changed()          #
	########################################################################

	# ---- Host tab widget coordination ----
	def _attach_host_tab_signals(self):
		host = self._host_tabwidget()
		if host:
			# Important: every Files instance listens; only the one that has
			# _files_mode_active=True will actually release.
			host.currentChanged.connect(self._on_host_tab_changed)

	def _on_host_tab_changed(self, idx: int):
		host = self._host_tabwidget()
		if not host:
			return
		new_w = host.widget(idx)
		# If we’re leaving a heavy context entirely, make sure any hidden
		# FileBrowser releases its locks/CSS and restores the header.
		if not self._is_heavy_widget(new_w) and getattr(self, "_files_mode_active", False):
			self._exit_files_mode()

	def _enter_files_mode(self):
		# Prevent double-enter
		if getattr(self, "_files_mode_active", False):
			return
		self._files_mode_active = True
		# IMPORTANT: capture & collapse BEFORE we touch/lock the handle
		self._collapse_workspace_header(True)
		self._lock_parent_tabbar()
		self._lock_parent_splitter()

	def _exit_files_mode(self):
		if not getattr(self, "_files_mode_active", False):
			return
		self._files_mode_active = False
		self._unlock_parent_splitter()
		self._unlock_parent_tabbar()
		# Put the outer splitter back exactly as it was
		self._collapse_workspace_header(False)

	# ---------- Coordination with Dashboard heavy tabs ----------
	def _host_tabwidget(self) -> QTabWidget | None:
		w = self.parent()
		while w is not None and not isinstance(w, QTabWidget):
			w = w.parent()
		return w if isinstance(w, QTabWidget) else None

	def _is_heavy_widget(self, w: QWidget | None) -> bool:
		"""
		Treat PayloadsTab and FileBrowser as 'heavy'.
		Avoid hard import cycles; fall back to name check.
		"""
		if w is None:
			return False
		try:
			from payloads_tab import PayloadsTab  # type: ignore
			return isinstance(w, (PayloadsTab, FileBrowser))
		except Exception:
			clsname = getattr(w.__class__, "__name__", "")
			return clsname in ("PayloadsTab", "FileBrowser")

	def _leaving_to_heavy(self) -> bool:
		"""
		When this tab hides/closes, is the *next* current tab heavy?
		Used to decide if we should skip restoring the outer splitter/tabbar.
		"""
		host = self._host_tabwidget()
		return self._is_heavy_widget(host.currentWidget() if host else None)

	# --- Pseudo views helper ---
	def _in_pseudo_view(self) -> bool:
		"""True while showing 'This PC' (drives) or 'Quick access' faux tables."""
		return bool(getattr(self, "_showing_drives", False) or getattr(self, "_showing_quick", False))


	def showEvent(self, ev):
		# Capture sizes, collapse header, then lock the handle — like Payloads
		self._enter_files_mode()
		return super().showEvent(ev)

	def hideEvent(self, ev):
		# These releases are handled centrally via _on_host_tab_changed.
		return super().hideEvent(ev)

	def closeEvent(self, ev):
		self._exit_files_mode()
		return super().closeEvent(ev)

	# ----- Inital Refresh Missed Fix -----
	def _busy_timeout_ms(self) -> int:
		# generous: 2× beacon + 2s for HTTP/S; short for TCP
		if self.transport in ("http", "https"):
			base = int((self.beacon_interval or 5.0) * 1000)
			return base * 2 + 2000
		return 4000

	def _busy_timed_out(self):
		# we never got a reply; clear busy and try again right away
		self._busy = False
		self.overlay.setVisible(False)
		self.status.setText("Retrying…")
		log.warning("Busy timed out; retrying list (sid=%s path=%s)", self.sid, self.path)
		self._kick_live(immediate=True) 

	def _on_files_ws_connected(self):
		# first list as soon as the socket is ready
		log.info("FilesWS connected (sid=%s)", self.sid)
		self._kick_live(immediate=True)
		# populate sidebar info
		try:
			self.fws.get_quickpaths(self.sid)
			self.fws.get_drives(self.sid)
		except Exception: pass

	# ----- Queue Actions -----
	def _navigate_to(self, new_path: str):
		self._pending_path = self._norm_path(new_path)
		self.status.setText("Listing…")
		self._refresh_reason = "navigate_to"
		log.debug("navigate_to -> %s (from=%s) flags drives=%s quick=%s busy=%s (sid=%s)",
				  self._pending_path, self.path, self._showing_drives, self._showing_quick, self._busy, self.sid)
		self._kick_live(immediate=True)

	def _navigate_or_queue(self, new_path: str):
		target = self._norm_path(new_path)
		log.debug("navigate_or_queue state busy=%s path=%s showing_drives=%s showing_quick=%s (sid=%s)",
				  self._busy, self.path, self._showing_drives, self._showing_quick, self.sid)
		if self._busy:
			# queue and run as soon as current listing completes
			self._queued_nav = target
			self.status.setText("Listing… (queued)")
			log.debug("navigate_or_queue queued=%s (sid=%s)", target, self.sid)
			return
		log.debug("navigate_or_queue go-now=%s (sid=%s)", target, self.sid)
		self._navigate_to(target)

	# ----- Drain any queued navigation (works for drives/quick and normal lists) -----
	def _drain_queued_nav(self) -> bool:
		"""
		If a navigation was queued while a pseudo-view (drives/quick) or list
		was in-flight, perform it now—independent of pseudo flags.
		Returns True if a queued nav was consumed.
		"""
		queued = getattr(self, "_queued_nav", None)
		if not queued:
			return False
		log.debug("drain_queued_nav -> %s (sid=%s)", queued, self.sid)
		self._queued_nav = None
		self._showing_drives = False
		self._showing_quick  = False
		try: self.overlay.setVisible(False)
		except Exception: pass
		self._navigate_to(self._norm_path(str(queued)))
		return True

	# ----- History controls (Back/Forward) -----
	def _hist_push(self, path: str):
		try:
			path = self._norm_path(path)
		except Exception:
			pass
		# When navigating normally, append and truncate any forward stack
		if self._hist_freeze:
			return
		if self._hist and self._hist_idx >= 0 and self._hist[self._hist_idx] == path:
			self._update_nav_buttons(); return
		if self._hist_idx < len(self._hist) - 1:
			self._hist = self._hist[:self._hist_idx + 1]
		self._hist.append(path)
		self._hist_idx = len(self._hist) - 1
		self._update_nav_buttons()

	def _update_nav_buttons(self):
		try:
			self.btn_hist_back.setEnabled(self._hist_idx > 0)
			self.btn_hist_fwd.setEnabled(self._hist_idx < len(self._hist) - 1)
		except Exception:
			pass

	def nav_back(self):
		if self._hist_idx > 0:
			self._hist_freeze = True
			self._hist_idx -= 1
			self._navigate_or_queue(self._hist[self._hist_idx])
			self._update_nav_buttons()

	def nav_forward(self):
		if self._hist_idx < len(self._hist) - 1:
			self._hist_freeze = True
			self._hist_idx += 1
			self._navigate_or_queue(self._hist[self._hist_idx])
			self._update_nav_buttons()

	# ----- Search placeholder + nav button enable state -----
	def _update_search_placeholder(self):
		"""Match Explorer’s 'Search This PC / Quick access / <folder>' phrasing and icon."""
		try:
			if getattr(self, "_showing_drives", False):
				self.search.setPlaceholderText("Search This PC")
				try: self.lbl_loc_icon.setPixmap(self.icon_computer.pixmap(18,18))
				except Exception: pass
				# Show "This PC" as the lone crumb
				self._render_location_title_crumb("This PC")
				return
			if getattr(self, "_showing_quick", False):
				self.search.setPlaceholderText("Search Quick access")
				try: self.lbl_loc_icon.setPixmap(self.icon_computer.pixmap(18,18))
				except Exception: pass
				self._render_location_title_crumb("Quick access")
				return
			lbl = _basename_for_label(self.path) or self.path or "this folder"
			self.search.setPlaceholderText(f"Search {lbl}")
			try: self.lbl_loc_icon.setPixmap(self.icon_dir.pixmap(18,18))
			except Exception: pass
		except Exception:
			pass

	def _update_nav_buttons(self):
		en_back = self._hist_idx > 0; en_fwd = self._hist_idx < len(self._hist) - 1
		for b in [getattr(self, "btn_top_back", None), getattr(self, "btn_hist_back", None)]:
			if b: b.setEnabled(en_back)
		for b in [getattr(self, "btn_top_forward", None), getattr(self, "btn_hist_fwd", None)]:
			if b: b.setEnabled(en_fwd)

	# ----- Tabs -----
	def _new_tab(self, initial: bool=False):
		idx = self.tabs.addTab(_basename_for_label(self.path) or self.path)
		self._tab_paths[idx] = self.path
		if not initial:
			self.tabs.setCurrentIndex(idx)

	def _on_tab_changed(self, index: int):
		if index < 0: 
			return
		newp = self._tab_paths.get(index, self.path)
		log.debug("tab_changed idx=%s path=%s -> %s (sid=%s)", index, self.path, newp, self.sid)
		if newp != self.path:
			self._navigate_or_queue(newp)

	def _on_tab_close(self, index: int):
		if self.tabs.count() <= 1:
			return
		log.debug("tab_close idx=%s (sid=%s)", index, self.sid)
		self.tabs.removeTab(index)
		self._tab_paths.pop(index, None)
		# re-pack map
		self._tab_paths = {i: self._tab_paths.get(i, self.path) for i in range(self.tabs.count())}

	def _update_tab_title(self):
		i = self.tabs.currentIndex()
		if i >= 0:
			self.tabs.setTabText(i, _basename_for_label(self.path) or self.path)
			self._tab_paths[i] = self.path

	# ----- Path bar mode -----
	def _switch_to_edit(self):
		self._path_stack.setCurrentWidget(self.path_edit)
		self.path_edit.setText(self.path)
		self.path_edit.setFocus()
		self.path_edit.selectAll()
		log.debug("switch_to_edit path=%s (sid=%s)", self.path, self.sid)

	def _cancel_edit_to_crumbs(self):
		self._path_stack.setCurrentWidget(self._crumbs_host)

	"""def _apply_path_edit(self):
		txt = (self.path_edit.text() or "").strip()
		if txt:
			self._cancel_edit_to_crumbs()
			self._navigate_or_queue(_norm_path_os(txt, self.path, self.os_type))"""

	def _apply_path_edit(self):
		# consistent indent + call the helper correctly
		txt = (self.path_edit.text() or "").strip()
		if txt:
			self._cancel_edit_to_crumbs()
			self._navigate_or_queue(self._norm_path_os(txt, self.path, self.os_type))

	# ----- Users root helpers -----
	def _users_root_path(self) -> str:
		# Only defined for Windows per your request
		return "C:\\Users\\" if self.os_type == "windows" else "/home"

	def _is_users_root(self, p: str) -> bool:
		"""True when p is the Users root (C:\\Users\\) on Windows."""
		if self.os_type != "windows":
			return False
		try:
			a = self._norm_path(p).rstrip("\\/").lower()
			b = self._norm_path(self._users_root_path()).rstrip("\\/").lower()
			return a == b
		except Exception:
			return False

	def _entry_is_hidden(self, r: dict) -> bool:
		"""
		Best-effort hidden detector:
		- prefer explicit 'hidden' flag if the server provides it
		- fall back to attributes strings
		- final name heuristics for common Windows hidden profile dirs
		"""
		try:
			if bool(r.get("hidden")):
				return True
		except Exception:
			pass
		attrs = str(r.get("attrs") or r.get("attributes") or "").lower()
		if ("hidden" in attrs) or (" h " in f" {attrs} "):
			return True
		nm = str(r.get("name") or "")
		# dot files (rare on Windows), desktop.ini, and well-known hidden/system profile folders
		wl = nm.lower()
		if nm.startswith(".") or wl in ("desktop.ini",):
			return True
		if self.os_type == "windows":
			if wl in ("all users", "default", "default user") or wl.startswith("default "):
				return True
		return False

	# ---------- Breadcrumbs ----------
	def _rebuild_breadcrumbs(self):
		# Pseudo views show a single location title (This PC / Quick access), like Explorer
		if getattr(self, "_showing_drives", False):
			self._render_location_title_crumb("This PC")
			return
		if getattr(self, "_showing_quick", False):
			self._render_location_title_crumb("Quick access")
			return

		while self.crumbs.count():
			it = self.crumbs.takeAt(0); w = it.widget()
			if w: w.deleteLater()

		path = self.path or ""
		sep = _sep_for(self.path, self.os_type)
		parts = []
		if self.os_type == "windows":
			p = path.replace("/", "\\")
			if p.startswith("\\\\"):
				chunks = [c for c in p.split("\\") if c]
				if len(chunks) >= 2:
					base = "\\\\" + chunks[0] + "\\" + chunks[1]
					parts.append(base); parts.extend(chunks[2:])
				else:
					parts = [p]
			else:
				parts = [c for c in p.split("\\") if c]
				if path.startswith("\\") and parts and not parts[0].endswith(":"):
					parts.insert(0, "\\")
		else:
			if path.startswith("/"):
				parts = ["/"] + [p for p in path.split("/") if p][1:]
			else:
				parts = [p for p in path.split("/") if p]

		def _make_btn(label: str, jump_to: str):
			btn = QToolButton(self); btn.setText(label if label else sep); btn.setAutoRaise(False); btn.setProperty("crumb", True)
			btn.clicked.connect(lambda: self._jump(jump_to)); return btn

		def _make_sep():
			lbl = QLabel("›", self)
			lbl.setObjectName("CrumbSep")
			return lbl

		acc = ""
		if self.os_type == "windows":
			# Drive root as first crumb, e.g. "C:"
			if parts and parts[0].endswith(":"):
				acc = parts[0] + "\\"
				self.crumbs.addWidget(_make_btn(parts[0], acc))
				# add sep if there are more segments
				if len(parts) > 1:
					self.crumbs.addWidget(_make_sep())
				parts = parts[1:]
		elif path.startswith("/"):
			acc = "/"
			self.crumbs.addWidget(_make_btn("/", "/"))
			if len(parts) > 1:
				self.crumbs.addWidget(_make_sep())

		for i, chunk in enumerate(parts):
			if not chunk:
				continue
			# build jump path
			if self.os_type == "windows":
				if not acc:
					# relative-ish on windows (rare in our UI), start with first chunk
					acc = chunk + "\\"
				else:
					# append using backslash unless we're at root "/"
					acc = (acc + chunk) if acc.endswith("\\") else (acc + "\\" + chunk)
			else:
				if acc in ("", "/"):
					acc = (acc + chunk) if acc != "/" else (acc + chunk)
				else:
					acc = acc + sep + chunk
			self.crumbs.addWidget(_make_btn(chunk or sep, acc))
			if i < len(parts) - 1:
				self.crumbs.addWidget(_make_sep())

		# keep crumbs left-aligned but allow row to stretch naturally
		self.crumbs.addStretch(1)

	def _render_location_title_crumb(self, title: str):
		"""Helper to show a single flat crumb title (non-clickable) for pseudo views."""
		while self.crumbs.count():
			it = self.crumbs.takeAt(0); w = it.widget()
			if w: w.deleteLater()
		lbl = QToolButton(self); lbl.setText(title); lbl.setProperty("crumb", True)
		lbl.setEnabled(False)  # Explorer renders this as a label; keep non-clickable
		self.crumbs.addWidget(lbl, 0)
		self.crumbs.addStretch(1)
		try: self.lbl_loc_icon.setPixmap(self.icon_computer.pixmap(18,18))
		except Exception: pass

	def _jump(self, new_path: str):
		if not new_path:
			return
		log.debug("crumb_jump -> %s (sid=%s)", new_path, self.sid)
		self._navigate_or_queue(new_path)

	# ----- Helpers -----
	def _fmt_dt(self, mtime_ms: int) -> str:
		try:
			dt = datetime.datetime.utcfromtimestamp((mtime_ms or 0)/1000.0)
			return dt.strftime("%Y-%m-%d %H:%M")
		except Exception:
			return ""

	def _fmt_bytes(self, n: int | float | None) -> str:
		"""
		Human-friendly byte formatter using 1024 units: B, KB, MB, GB, TB, PB.
		Keeps one decimal for values < 10 (except bytes), otherwise rounds to ints.
		"""
		n = float(n or 0)
		units = ["B", "KB", "MB", "GB", "TB", "PB"]
		i = 0
		while n >= 1024 and i < len(units) - 1:
			n /= 1024.0; i += 1
		return (f"{n:.1f} {units[i]}" if (i > 0 and n < 10) else f"{n:.0f} {units[i]}")

	# ---- Robust "Type" detector (Explorer-like) ----
	def _guess_type(self, name: str, is_dir: bool) -> str:
		if is_dir:
			return "File folder"
		nm = (name or "").lower().rstrip(".")
		# explicit names that Windows treats specially
		specials = {
			"desktop.ini": "Configuration settings",
			"thumbs.db": "Data base file",
		}
		if nm in specials: return specials[nm]
		# common extension → friendly label map
		EXT = {
			# documents
			"pdf":"PDF file", "txt":"Text Document", "rtf":"Rich Text Format",
			"md":"Markdown file", "csv":"CSV file", "tsv":"TSV file",
			"json":"JSON file", "yaml":"YAML file", "yml":"YAML file", "xml":"XML file",
			# office
			"doc":"Microsoft Word 97-2003", "docx":"Microsoft Word Document",
			"dotx":"Word Template", "xls":"Microsoft Excel 97-2003", "xlsx":"Microsoft Excel Worksheet",
			"xlsm":"Excel Macro-Enabled Worksheet", "xltx":"Excel Template",
			"ppt":"PowerPoint 97-2003", "pptx":"PowerPoint Presentation", "ppsx":"PowerPoint Show",
			# images
			"jpg":"JPEG image", "jpeg":"JPEG image", "png":"PNG image", "gif":"GIF image",
			"bmp":"Bitmap image", "tif":"TIFF image", "tiff":"TIFF image", "webp":"WEBP image",
			"svg":"SVG image", "ico":"Icon",
			# audio
			"mp3":"MP3 audio", "wav":"WAVE audio", "flac":"FLAC audio", "aac":"AAC audio",
			"m4a":"MPEG-4 audio", "ogg":"OGG audio", "opus":"OPUS audio", "mid":"MIDI sequence",
			# video
			"mp4":"MPEG-4 video", "mkv":"Matroska video", "mov":"QuickTime movie", "avi":"AVI video",
			"wmv":"Windows Media video", "webm":"WebM video", "mpg":"MPEG video", "mpeg":"MPEG video",
			# archives
			"zip":"ZIP archive", "7z":"7-Zip archive", "rar":"RAR archive",
			"tar":"TAR archive", "gz":"GZIP archive", "tgz":"GZipped TAR archive",
			"bz2":"BZip2 archive", "xz":"XZ archive", "iso":"Disc image",
			# executables / scripts
			"exe":"Application", "msi":"Windows Installer Package",
			"bat":"Windows Batch File", "cmd":"Windows Command Script", "ps1":"PowerShell Script",
			"sh":"Shell script", "bash":"Shell script", "reg":"Registration Entries",
			"py":"Python file", "js":"JavaScript file", "ts":"TypeScript file",
			"java":"Java source file", "c":"C source file", "cpp":"C++ source file",
			"h":"C/C++ header", "hpp":"C++ header", "go":"Go source file",
			"rs":"Rust source file", "rb":"Ruby file", "php":"PHP file", "sql":"SQL file",
			# system
			"dll":"Application extension", "sys":"System file", "drv":"Device driver",
			"lnk":"Shortcut", "ini":"Configuration settings", "log":"Log file",
		}
		# find last extension piece
		ext = nm.rsplit(".", 1)[-1] if "." in nm else ""
		if ext in EXT: return EXT[ext]
		# fallback to mimetypes for unknowns
		kind, _ = mimetypes.guess_type(nm)
		if kind:
			main = kind.split("/", 1)[0]
			label = {
				"image":"Image file", "audio":"Audio file", "video":"Video file",
				"text":"Text file", "application":"Application file",
			}.get(main, "File")
			return label
		return "File"

	def _entries_to_map(self, entries: list[dict]) -> dict[str, tuple[bool, int, int, str, int, str]]:
		"""
		name -> (is_dir, raw_size, mtime_ms, type_label, item_count_for_dir, owner)
		"""
		m: dict[str, tuple[bool, int, int, str, int, str]] = {}
		for r in entries or []:
			name = str(r.get("name") or _basename_for_label(str(r.get("path") or "")) or "")
			is_dir = self._coerce_is_dir(r)
			sz = self._coerce_size_int(r)
			mt = self._coerce_mtime_ms(r)
			tl = "File folder" if is_dir else (self._guess_type(name, False) or "File")
			# optional item counts
			items = 0
			for k in ("items", "child_count", "children", "count"):
				try:
					v = r.get(k)
					if isinstance(v, (int, float)) and int(v) > 0:
						items = int(v); break
				except Exception:
					pass
			owner = self._coerce_owner(r)
			m[name] = (is_dir, sz, mt, tl, items, owner)
		return m

	def _set_row(self, row: int, name: str, is_dir: bool, size: int, mtime_ms: int, type_label: str, owner: str, dir_items: int = 0):
		icon = self.icon_dir if is_dir else self.icon_file
		self.table.setItem(row, 0, NameItem(self._fmt_label(name, is_dir), is_dir, icon))
		self.table.setItem(row, 1, QTableWidgetItem(self._fmt_dt(mtime_ms)))
		self.table.setItem(row, 2, QTableWidgetItem(type_label))
		self.table.setItem(row, 3, QTableWidgetItem(owner or ""))  # <-- Owner

		# Size column (files → bytes; folders → items/bytes/blank)
		if not is_dir:
			disp, sort_v = self._fmt_bytes(size), size
		else:
			if dir_items > 0:
				disp, sort_v = (f"{dir_items} item" if dir_items == 1 else f"{dir_items} items"), dir_items
			elif size > 0:
				disp, sort_v = self._fmt_bytes(size), size
			else:
				disp, sort_v = "", 0
		self.table.setItem(row, 4, SizeItem(disp, sort_v))        # <-- moved to col 4

	def _apply_search_filter(self, text: str):
		text = (text or "").lower()
		for r in range(self.table.rowCount()):
			nm = (self.table.item(r, 0).text() if self.table.item(r,0) else "").lower()
			self.table.setRowHidden(r, bool(text) and text not in nm)

	def _unique_name(self, base: str, *, ext: str = "", is_dir: bool = False) -> str:
		existing = set((self._last_listing or {}).keys())
		first = f"{base}{ext}"
		if first not in existing: return first
		for i in range(2, 500):
			cand = f"{base} ({i}){ext}"
			if cand not in existing: return cand
		return first

	def _action_new_folder(self):
		# Parent dir is current folder (self.path)
		name = self._unique_name("New folder", is_dir=True)
		self.status.setText("Creating folder…")
		try:
			self.fws.new_folder(self.sid, self.path, name)
		except Exception as e:
			QMessageBox.critical(self, "Create folder", f"{e}")
			return

	def _action_new_text(self):
		name = self._unique_name("New Text Document", ext=".txt", is_dir=False)
		self.status.setText("Creating file…")
		try:
			self.fws.new_text(self.sid, self.path, name)
		except Exception as e:
			QMessageBox.critical(self, "Create file", f"{e}")
			return

	def _on_created(self, kind: str, path: str, ok: bool, error: str):
		if ok:
			self.status.setText("Created")
			# quick refresh so the new item appears immediately
			self._kick_live(immediate=True)
		else:
			QMessageBox.critical(self, "Create", error or f"Failed to create {kind}")
			self.status.setText("Create failed")

	# --- Right-click context menu on the file table ---
	def _on_table_context_menu(self, pos):
		idx = self.table.indexAt(pos)
		sel_rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
		has_selection = bool(sel_rows)

		m = QMenu(self)

		if has_selection or idx.isValid():
			# Row context menu (NO "New" here)
			self.table.selectRow(idx.row()) if idx.isValid() else None
			m.addAction("Open", self._open_selection)
			m.addSeparator()
			m.addAction("Download", self.download)
			m.addAction("Refresh", lambda: self._kick_live(immediate=True))
		else:
			# Empty-area context menu → show New ▸ and whatever else you like
			new_menu = m.addMenu("New")
			new_menu.addAction("Folder", self._action_new_folder)
			new_menu.addAction("Text Document", self._action_new_text)
			m.addSeparator()
			m.addAction("Refresh", lambda: self._kick_live(immediate=True))

		m.exec_(self.table.viewport().mapToGlobal(pos))

	def _update_action_row_state(self):
		"""Hide Upload when rows are selected; show when nothing is selected."""
		has_sel = bool(self.table.selectionModel().selectedRows())
		try:
			self.btn_upload.setVisible(not has_sel)
		except Exception:
			pass

	def _delete_selection(self):
		rows = [i.row() for i in self.table.selectionModel().selectedRows()]
		if not rows:
			return

		# Build list of targets
		sep = _sep_for(self.path, self.os_type)
		targets = []
		for r in rows:
			item = self.table.item(r, 0)
			if not item:
				continue
			name = item.text().rstrip("/")
			is_dir = isinstance(item, NameItem) and item.is_dir
			remote = self.path + ("" if self.path.endswith(sep) else sep) + name
			targets.append((name, remote, is_dir))

		# Confirm
		if len(targets) == 1:
			name, _, is_dir = targets[0]
			kind = "folder" if is_dir else "file"
			msg = f"Delete {kind}:\n“{name}”?"
		else:
			display = "\n".join(f"• {n}" for n, _, _ in targets[:10])
			more = "" if len(targets) <= 10 else f"\n…and {len(targets)-10} more"
			msg = f"Delete {len(targets)} item(s)?\n\n{display}{more}"

		if QMessageBox.question(self, "Delete", msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
			return

		# Perform deletes (backend handles file vs folder)
		self.status.setText("Deleting…")
		any_sent = False
		for _, remote, is_dir in targets:
			try:
				# Preferred: WebSocket op
				if hasattr(self.fws, "delete"):
					self.fws.delete(self.sid, remote, folder=bool(is_dir))
					any_sent = True
				else:
					raise AttributeError("FilesWSClient.delete missing")
			except Exception as e:
				log.exception("delete failed to dispatch (sid=%s)", self.sid)
				QMessageBox.critical(self, "Delete", f"{e}")
				self.status.setText("Delete failed")
				return

		if not any_sent:
			QMessageBox.critical(self, "Delete", "Delete operation not available.")
			self.status.setText("Delete failed")
		# The backend will emit 'deleted' (if implemented). If not, just refresh soon:
		QTimer.singleShot(500, lambda: self._kick_live(immediate=True))

	def _on_deleted(self, path: str, ok: bool, error: str):
		if ok:
			self.status.setText("Deleted")
			self._kick_live(immediate=True)
		else:
			QMessageBox.critical(self, "Delete", error or f"Failed to delete:\n{path}")
			self.status.setText("Delete failed")

	def _upload_pick_files_only(self):
		files, _ = QFileDialog.getOpenFileNames(self, "Upload File(s)")
		if not files:
			return
		sep  = _sep_for(self.path, self.os_type)
		base = self.path + ("" if self.path.endswith(sep) else sep)
		self.status.setText("Uploading…")
		for p in files:
			name   = os.path.basename(p)
			remote = base + name
			log.info("upload_file %s -> %s (sid=%s)", p, remote, self.sid)
			self.fws.start_upload(self.sid, p, remote)

	def _upload_pick_folder_only(self):
		local = QFileDialog.getExistingDirectory(self, "Upload Folder")
		if not local:
			return
		sep  = _sep_for(self.path, self.os_type)
		base = self.path + ("" if self.path.endswith(sep) else sep)
		name = os.path.basename(local.rstrip("/\\"))
		remote_dir = base + name
		self.status.setText("Uploading…")
		log.info("upload_folder %s -> %s (sid=%s)", local, remote_dir, self.sid)
		self.fws.start_upload_folder(self.sid, local, remote_dir, os_type=self.os_type)


	def _open_in_new_tab_from_item(self, item: QTableWidgetItem):
		"""Open the clicked item in a new tab. Works for both real folders and
		pseudo rows (drives/quick) that carry a target path in Qt.UserRole."""
		if not item:
			return
		# Resolve target path
		target = item.data(Qt.UserRole)
		if target:
			target = str(target)
		else:
			# Normal folder row
			name = item.text().rstrip("/")
			target = self._join_path(self.path, name)

		# Create tab and navigate there
		idx = self.tabs.addTab(_basename_for_label(target) or target)
		self._tab_paths[idx] = target
		self.tabs.setCurrentIndex(idx)
		self._navigate_or_queue(target)

	def _pick_local_items(self) -> list[str]:
		dlg = QFileDialog(self, "Select files or folders")
		dlg.setOption(QFileDialog.DontUseNativeDialog, True)
		dlg.setFileMode(QFileDialog.ExistingFiles)         # files…
		dlg.setOption(QFileDialog.ShowDirsOnly, False)     # …and folders (via non-native)
		# enable multi-select in internal views
		for view in dlg.findChildren(QAbstractItemView):
			view.setSelectionMode(QAbstractItemView.ExtendedSelection)
		if dlg.exec_():
			# This returns files; for non-native we also get directories when user selects & presses Open
			return dlg.selectedFiles()
		return []

	# ---------- Live logic ----------
	def _compute_next_ms(self) -> int:
		if self.transport in ("http", "https"):
			base = int((self.beacon_interval or 5.0) * 1000)
			j = max(0, min(self.beacon_jitter_pct or 0, 95))
			if j:
				delta = int(base * j / 100.0)
				return max(750, base + random.randint(-delta, delta))
			return max(750, base)
		return 1000  # TCP

	def _kick_live(self, initial: bool = False, immediate: bool = False):
		self._auto_timer.stop()
		self._refresh_reason = f"kick_live(initial={initial}, immediate={immediate})"
		try:
			log.debug("kick_live initial=%s immediate=%s next_ms=%s (sid=%s)", initial, immediate, self._compute_next_ms(), self.sid)
		except Exception:
			pass
		if immediate or initial:
			self.refresh()
		self._auto_timer.start(self._compute_next_ms())

	def _auto_tick(self):
		self._refresh_reason = "auto_tick"
		log.debug("auto_tick -> refresh (sid=%s)", self.sid)
		if not self._busy:
			self.refresh()
		self._auto_timer.start(self._compute_next_ms())

	# ---------- Core ops ----------
	def refresh(self):
		log.debug("refresh reason=%s path=%s pending=%s showing_drives=%s showing_quick=%s transport=%s (sid=%s)",
				  getattr(self, "_refresh_reason", None), self.path, self._pending_path, self._showing_drives, self._showing_quick, self.transport, self.sid)
		# When showing faux tables, do not call list_dir; refresh the faux data instead.
		if self._showing_drives:
			self._busy = True
			self.status.setText("Loading drives…")
			# Only show an overlay for HTTP/S transports
			if self.transport in ("http", "https"):
				try:
					self.overlay.setMessage("Loading drives…"); self.overlay.showCentered()
				except Exception:
					pass
			try:
				self.fws.get_drives(self.sid)
			except Exception:
				self._busy = False
			return
		if self._showing_quick:
			self._busy = True
			self.status.setText("Loading Quick access…")
			# Only show an overlay for HTTP/S transports
			if self.transport in ("http", "https"):
				try:
					self.overlay.setMessage("Loading Quick access…"); self.overlay.showCentered()
				except Exception:
					pass
			try:
				self.fws.get_quickpaths(self.sid)
			except Exception:
				self._busy = False
			return
		# Normal folder listing
		# Make sure we are back on the standard 4-column view
		self._ensure_main_columns()
		self._busy = True
		target = self._pending_path or self.path
		if self.transport in ("http", "https"):
			self.overlay.setMessage("Waiting for HTTP/HTTPS beacon…"); self.overlay.showCentered()
		self.status.setText("Listing…")
		# correlate request/response
		self._req_seq += 1
		self._inflight_req = (self._req_seq, target, getattr(self, "_refresh_reason", None), time.time())
		log.debug("list_dir begin req=%s target=%s reason=%s (sid=%s)", self._req_seq, target, getattr(self, "_refresh_reason", None), self.sid)
		self.fws.list_dir(self.sid, target); self._busy_guard.start(self._busy_timeout_ms())

	def _fmt_label(self, name: str, is_dir: bool) -> str:
		# Don’t suffix folders with a slash on any OS
		return name

	def _on_list(self, path: str, entries: list, ok: bool = True):
		self._busy = False
		self._busy_guard.stop()
		self.overlay.setVisible(False)

		attempted = self._norm_path(path or self._pending_path or self.path)
		log.debug("on_list attempted=%s ok=%s entries=%s (sid=%s)", attempted, ok, len(entries or []), self.sid)

		inflight = getattr(self, "_inflight_req", None)
		if inflight:
			req, tgt, reason, t0 = inflight
			lat_ms = int((time.time() - t0) * 1000)
			tgt_n = self._norm_path(tgt)
			att_n = self._norm_path(attempted)
			#match = (self._norm_path(attempted) == tgt)
			if att_n != tgt_n:
				log.warning("Ignoring stale list reply: requested=%s got=%s latency=%sms (sid=%s)", tgt_n, att_n, lat_ms, self.sid)
				return
			# Only clear after we know it's a match
			self._inflight_req = None

		if not ok:
			self._pending_path = None
			self.status.setText("Path not found")
			log.warning("Path not found: %s (sid=%s)", attempted, self.sid)
			return

		new_path = attempted
		path_changed = (new_path != self.path)

		# commit path
		self.path = new_path
		self._pending_path = None
		if not self._is_path_editing():   # --> SEARCH BAR OVERIDE GUARD!!
			self.path_edit.setText(self.path)
		self._rebuild_breadcrumbs()

		# If we’re listing the Users root, show directories only and exclude hidden
		_entries = entries or []
		if self._is_users_root(attempted):
			try:
				_entries = [
					e for e in _entries
					if bool(e.get("is_dir")) and not self._entry_is_hidden(e)
				]
			except Exception:
				_entries = [e for e in _entries if bool(e.get("is_dir"))]
		new_map = self._entries_to_map(_entries)

		# --- NEW: hard rebuild when navigating into a different folder ---
		if path_changed:
			header = self.table.horizontalHeader()
			sort_col = header.sortIndicatorSection()
			sort_order = header.sortIndicatorOrder()

			was_sort = self.table.isSortingEnabled()
			self.table.setSortingEnabled(False)
			self.table.setUpdatesEnabled(False)
			try:
				self.table.clearSelection()
				# hard rebuild branch
				self._ensure_main_columns()
				self.table.setRowCount(0)
				for name, (is_dir, size, mt, tl, items, owner) in new_map.items():
					r = self.table.rowCount(); self.table.insertRow(r)
					self._set_row(r, name, is_dir, size, mt, tl, owner, items)
			finally:
				self.table.setUpdatesEnabled(True)
				self.table.setSortingEnabled(was_sort)
				if was_sort: self.table.sortItems(sort_col, sort_order)

			self._last_listing = new_map
			self.status.setText(f"Live • {len(new_map)} item(s)")
			# no longer in a pseudo view after a successful folder list
			self._showing_drives = False
			self._showing_quick = False
			self._update_search_placeholder()
			self._update_nav_buttons()
			self._update_tab_title()
			log.info("navigated path=%s items=%s (sid=%s)", self.path, len(new_map), self.sid)

			# ---- History push for path changes (HARD REBUILD branch) ----
			try:
				self._hist_push(self.path)
			except Exception:
				pass
			self._hist_freeze = False
			self._update_nav_buttons()

			if self._drain_queued_nav():
				return
			return

		else:
			# Even if we refreshed in-place, keep buttons in a sane state
			self._update_nav_buttons()

		self._hist_freeze = False

		# Preserve UX state
		vbar = self.table.verticalScrollBar(); scroll_pos = vbar.value()
		header = self.table.horizontalHeader()
		sort_col = header.sortIndicatorSection(); sort_order = header.sortIndicatorOrder()
		selected_names = [self.table.item(i.row(), 0).text().rstrip("/") for i in self.table.selectionModel().selectedRows()]

		# Current rows index
		cur_rows: dict[str, int] = {}
		for r in range(self.table.rowCount()):
			nm = self.table.item(r, 0).text().rstrip("/")
			cur_rows[nm] = r

		# Diff
		old = self._last_listing
		old_names = set(old.keys()); new_names = set(new_map.keys())
		removed = sorted(list(old_names - new_names))
		added   = sorted(list(new_names - old_names))
		intersect = old_names & new_names
		changed = sorted([n for n in intersect if old[n] != new_map[n]])

		# Patch table
		was_sort = self.table.isSortingEnabled()
		self.table.setSortingEnabled(False)
		self.table.setUpdatesEnabled(False)
		try:
			# ensure correct columns in case we previously showed a pseudo view
			self._ensure_main_columns()
			for row in sorted([cur_rows[n] for n in removed if n in cur_rows], reverse=True):
				self.table.removeRow(row)

			# patch branch
			for name in changed:
				row = cur_rows.get(name)
				if row is None: continue
				is_dir, size, mt, tl, items, owner = new_map[name]
				self._set_row(row, name, is_dir, size, mt, tl, owner, items)

			for name in added:
				is_dir, size, mt, tl, items, owner = new_map[name]
				row = self.table.rowCount(); self.table.insertRow(row)
				self._set_row(row, name, is_dir, size, mt, tl, owner, items)

			self.table.sortItems(sort_col, sort_order)
			self.table.clearSelection()
			if selected_names:
				name_to_row = { self.table.item(r, 0).text().rstrip("/"): r for r in range(self.table.rowCount()) }
				for nm in selected_names:
					r = name_to_row.get(nm)
					if r is not None: self.table.selectRow(r)

			vbar.setValue(scroll_pos)
		finally:
			self.table.setUpdatesEnabled(True)
			self.table.setSortingEnabled(was_sort)
			if was_sort: self.table.sortItems(sort_col, sort_order)

		self._last_listing = new_map
		self.status.setText(f"Live • {len(new_map)} item(s)")
		self._showing_drives = False
		self._showing_quick = False
		self._update_search_placeholder()
		self._update_nav_buttons()
		self._update_tab_title()
		log.debug("updated existing path=%s items=%s (sid=%s)", self.path, len(new_map), self.sid)

		# ---- History push for path changes (PATCH branch) ----
		if path_changed:
			try:
				self._hist_push(self.path)
			except Exception:
				pass
		self._hist_freeze = False
		self._update_nav_buttons()

		"""# If a nav was queued during busy, perform it now.
		if self._queued_nav:
			queued = self._queued_nav
			self._queued_nav = None
			if queued and self._norm_path(queued) != self.path:
				self._navigate_to(queued)
				return"""

		# Drain any queued navigation now that this refresh completed.
		if self._drain_queued_nav():
			return

	# ---------- Drives & Quick Access ----------
	def _on_drives(self, rows: list):
		log.debug("on_drives count=%s showing_drives=%s path=%s (sid=%s)", len(rows or []), self._showing_drives, self.path, self.sid)
		# sidebar
		self._node_pc.takeChildren()
		for d in rows:
			label = (d.get("label") or "").strip()
			letter = d.get("letter") or ""
			name = f"{label} ({letter})" if label and len(letter) <= 3 else (letter or label or "Drive")
			item = QTreeWidgetItem(self._node_pc, [name])
			rootp = letter if self.os_type == "windows" else letter  # letter==mountpoint on posix
			item.setData(0, Qt.UserRole, rootp)
		self._node_pc.setExpanded(True)
		# if user clicked "This PC" we also show the drives in table
		if self._showing_drives:
			# clear busy now that the data arrived for the pseudo view
			self._busy = False; self.overlay.setVisible(False)
			self._render_drives_table(rows)
			self._rebuild_breadcrumbs()
			self._update_search_placeholder()
			# NEW: if a navigation was queued while drives were loading, perform it now
			queued = getattr(self, "_queued_nav", None)
			if queued:
				log.debug("on_drives: draining queued nav -> %s (sid=%s)", queued, self.sid)
				self._queued_nav = None
				# leave pseudo view & go directly
				self._showing_drives = False
				self._showing_quick = False
				try: self.overlay.setVisible(False)
				except Exception: pass
				self._navigate_to(self._norm_path(str(queued)))
				return

		self._update_nav_buttons()

		# NEW: always attempt to drain a queued nav, regardless of flags
		if self._drain_queued_nav():
			return

	def _on_quickpaths(self, paths: dict):
		log.debug("on_quickpaths keys=%s (sid=%s)", list((paths or {}).keys()), self.sid)
		self._quickpaths = paths or {}

		labels = [("desktop","Desktop"),("documents","Documents"),("downloads","Downloads"),
				  ("pictures","Pictures"),("videos","Videos")]
		self._node_quick.takeChildren()
		for key, label in labels:
			item = QTreeWidgetItem(self._node_quick, [label])
			item.setData(0, Qt.UserRole, self._quickpaths.get(key))

		# NEW: Users item at the top of Quick access
		users_item = QTreeWidgetItem(self._node_quick, ["Users"])
		users_item.setData(0, Qt.UserRole, self._users_root_path() if self.os_type == "windows" else None)

		self._node_quick.setExpanded(True)
		# If user is on the Quick access root view, refresh the table
		if self._showing_quick:
			self._busy = False; self.overlay.setVisible(False)
			self._render_quick_table(self._quickpaths)
			# NEW: drain any queued navigation that happened during quickpaths fetch
			queued = getattr(self, "_queued_nav", None)
			if queued:
				log.debug("on_quickpaths: draining queued nav -> %s (sid=%s)", queued, self.sid)
				self._queued_nav = None
				self._showing_drives = False
				self._showing_quick = False
				try: self.overlay.setVisible(False)
				except Exception: pass
				self._navigate_to(self._norm_path(str(queued)))
				return

		self._update_nav_buttons()
		self._update_search_placeholder()

		# NEW: always attempt to drain a queued nav, regardless of flags
		if self._drain_queued_nav():
			return

	def up(self):
		p = (self.path or "").rstrip("/\\")
		if "\\" in p and (self.os_type == "windows" or ("\\" in self.path and "/" not in self.path)):
			idx = p.rfind("\\")
		else:
			idx = p.rfind("/")
		if idx <= 0:
			new_path = "/" if ("/" in self.path and self.os_type != "windows") else "C:\\"
		else:
			new_path = p[:idx]
		log.debug("up: %s -> %s (sid=%s)", self.path, new_path, self.sid)
		self._navigate_or_queue(new_path)

	def _open_selection(self):
		rows = self.table.selectionModel().selectedRows()
		log.debug("open_selection rows=%s (sid=%s)", len(rows or []), self.sid)
		if rows:
			self._cell_dbl(rows[0].row(), 0)   # (row, col) – always use Name column

	def _is_path_editing(self) -> bool:
		"""True if the path line edit is currently being edited."""
		try:
			return self._path_stack.currentWidget() is self.path_edit and self.path_edit.hasFocus()
		except Exception:
			return False

	# add this method (and you can delete _dbl if you want)
	def _cell_dbl(self, row: int, col: int):
		log.debug("cell_dbl row=%s col=%s pseudo_drives=%s pseudo_quick=%s (sid=%s)", row, col, self._showing_drives, self._showing_quick, self.sid)
		# Special cases: faux tables ("This PC" drives / Quick access)
		if self._showing_drives or self._showing_quick:
			item0 = self.table.item(row, 0)
			if item0 is not None:
				try:
					log.debug("cell_dbl pseudo item text=%r role=%r (sid=%s)", item0.text(), item0.data(Qt.UserRole), self.sid)
				except Exception:
					log.debug("cell_dbl pseudo item with no text/role (sid=%s)", self.sid)

				target = item0.data(Qt.UserRole)
				if target:
					# We're leaving the pseudo view; drop flags and any overlay immediately
					# Consistent exit path (handles C: -> C:\ normalization and queuing)
					self._leave_pseudo_and_go(str(target))
					return
			# If somehow the role wasn't set, fall through to the generic logic below.

		"""# special case: when showing "Quick access", navigate to quick path by row
		if self._showing_quick:
			qp = self._quick_rows.get(row)
			if qp:
				self._navigate_or_queue(qp)
			return"""

		name_item = self.table.item(row, 0)
		if not name_item:
			return

		# Robust fallback: if the visible text ends with "(X:)" treat it as a drive root.
		try:
			txt = name_item.text()
		except Exception:
			txt = ""
		m = re.search(r"\(([A-Za-z]:)\)\s*$", txt or "")
		if m:
			# Navigate directly to the drive root even if flags desynced.
			self._showing_drives = False
			self._showing_quick = False
			try: self.overlay.setVisible(False)
			except Exception: pass
			self._navigate_or_queue(m.group(1))
			return
		# Another fallback for entries that are just "X:"
		if re.fullmatch(r"[A-Za-z]:", (txt or "").strip()):
			self._navigate_or_queue((txt or "").strip())
			return

		name = name_item.text()
		base = name[:-1] if name.endswith("/") else name
		if isinstance(name_item, NameItem) and name_item.is_dir:
			target = self._join_path(self.path, base)
			self._navigate_or_queue(target)
		else:
			# ---- NEW: open text-like files in Gunner editor; others download as before ----
			type_label = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
			if self._is_text_like(base, type_label):
				remote = self._join_path(self.path, base)
				self._open_remote_text_in_editor(remote, base)
			else:
				log.debug("cell_dbl non-text file -> download (sid=%s)", self.sid)
				self.download()

	def _on_nav_click(self, it: QTreeWidgetItem, col: int):
		label = ""
		try:
			label = it.text(0)
		except Exception:
			pass
		target = it.data(0, Qt.UserRole)
		log.debug("nav_click label=%r role=%r col=%s flags drives=%s quick=%s path=%s (sid=%s)",
				  label, target, col, self._showing_drives, self._showing_quick, self.path, self.sid)

		if target:
			log.debug("nav_click target=%s (sid=%s)", target, self.sid)
			# leaving any pseudo view (drives/quick) -> ensure normal listing path
			self._showing_drives = False
			self._showing_quick = False
			try: self.overlay.setVisible(False)
			except Exception: pass
			self._navigate_or_queue(target)
			return
		else:
			# "This PC" itself -> render drives table
			if it is self._node_pc:
				log.debug("nav_click -> This PC (drives view) (sid=%s)", self.sid)
				self._showing_drives = True
				self._showing_quick = False
				self._rebuild_breadcrumbs(); self._update_search_placeholder()
				self.fws.get_drives(self.sid)
				if self.transport in ("http", "https"):
					try:
						self.overlay.setMessage("Loading drives…"); self.overlay.showCentered()
					except Exception:
						pass

			# "Quick access" itself -> render quick items table
			if it is self._node_quick:
				log.debug("nav_click -> Quick access (sid=%s)", self.sid)
				self._showing_quick = True
				self._showing_drives = False
				self._rebuild_breadcrumbs(); self._update_search_placeholder()
				if not self._quickpaths:
					try: self.fws.get_quickpaths(self.sid)
					except Exception: pass
					if self.transport in ("http", "https"):
						try:
							self.overlay.setMessage("Loading Quick access…"); self.overlay.showCentered()
						except Exception:
							pass
				self._render_quick_table(self._quickpaths)

	def _render_drives_table(self, drives: list):
		log.debug("render_drives_table count=%s (sid=%s)", len(drives or []), self.sid)
		self.overlay.setVisible(False)
		#self._drive_rows.clear()
		# preserve current sort, then disable sorting while we mutate rows
		hdr = self.table.horizontalHeader()
		sort_col = hdr.sortIndicatorSection()
		sort_order = hdr.sortIndicatorOrder()
		self.table.setSortingEnabled(False)
		self.table.setUpdatesEnabled(False)
		try:
			self.table.clearSelection()
			self.table.setRowCount(0)
			self.table.setColumnCount(4)
			self.table.setHorizontalHeaderLabels(["Name", "File system", "Used", "Free"])
			"""# Temporarily freeze sorting to avoid row index churn while inserting
			was_sorting = self.table.isSortingEnabled()
			self.table.setSortingEnabled(False)"""
			for d in drives:
				letter = d.get("letter") or ""
				label = (d.get("label") or "").strip()
				size = int(d.get("size") or 0); used = int(d.get("used") or 0); free = int(d.get("free") or 0)
				name = f"{label} ({letter})" if label and len(letter) <= 6 else (letter or label or "Drive")
				# Normalize a Windows drive like "C:" -> "C:\"
				target = letter
				if self.os_type == "windows" and len(target) == 2 and target[1] == ":":
					target += "\\"

				r = self.table.rowCount(); self.table.insertRow(r)
				item0 = NameItem(name, True, self.icon_drive)
				# Store the target root/mount directly on the item so sorting is safe
				item0.setData(Qt.UserRole, target)
				log.debug("drives_table row=%s name=%s -> target=%s (sid=%s)", r, name, target, self.sid)
				self.table.setItem(r, 0, item0)
				self.table.setItem(r, 1, QTableWidgetItem("" if self.os_type=="windows" else (d.get("label") or "")))
				self.table.setItem(r, 2, SizeItem(self._fmt_bytes(used), used))
				self.table.setItem(r, 3, SizeItem(self._fmt_bytes(free), free))
			hdr.setSectionResizeMode(0, QHeaderView.Stretch)
			for i in (1,2,3): hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)
		finally:
			self.table.setUpdatesEnabled(True)
			self.table.setSortingEnabled(True)
			# restore previous sort choice
			self.table.sortItems(sort_col, sort_order)

	def _render_quick_table(self, quickpaths: dict):
		log.debug("render_quick_table count=%s (sid=%s)", len(quickpaths or {}), self.sid)
		"""
		Show the Quick access items (Desktop/Documents/Downloads/Pictures/Videos) in the table,
		similar to how drives are shown for 'This PC'.
		"""
		self.overlay.setVisible(False)
		#self._quick_rows.clear()
		# preserve current sort, then disable sorting while we mutate rows
		hdr = self.table.horizontalHeader()
		sort_col = hdr.sortIndicatorSection()
		sort_order = hdr.sortIndicatorOrder()
		self.table.setSortingEnabled(False)
		self.table.setUpdatesEnabled(False)
		try:
			self.table.clearSelection()
			self.table.setRowCount(0)
			# Explorer-like: no full path column here; just show friendly names
			self.table.setColumnCount(1)
			self.table.setHorizontalHeaderLabels(["Name"])
			labels = [
				("desktop",   "Desktop"),
				("documents", "Documents"),
				("downloads", "Downloads"),
				("pictures",  "Pictures"),
				("videos",    "Videos"),
			]
			for key, label in labels:
				target = quickpaths.get(key) or ""
				r = self.table.rowCount(); self.table.insertRow(r)
				item0 = NameItem(label, True, self.icon_dir)
				if target:
					# Store the target path on the item; double-click will use this.
					item0.setData(Qt.UserRole, target)
				self.table.setItem(r, 0, item0)
			hdr = self.table.horizontalHeader()
			hdr.setSectionResizeMode(0, QHeaderView.Stretch)
		finally:
			self.table.setUpdatesEnabled(True)
			self.table.setSortingEnabled(True)
			# restore previous sort choice
			self.table.sortItems(sort_col, sort_order)

	def _render_quickaccess_table(self):
		"""Render a faux view of Quick access targets (local client paths)."""
		self.overlay.setVisible(False)
		labels = [("videos","Videos"),("pictures","Pictures"),("downloads","Downloads"),
				  ("documents","Documents"),("desktop","Desktop")]
		self.table.setUpdatesEnabled(False)
		try:
			self.table.clearSelection()
			self.table.setRowCount(0)
			self.table.setHorizontalHeaderLabels(["Name", "Path", "Type", "Size"])
			was_sorting = self.table.isSortingEnabled()
			self.table.setSortingEnabled(False)
			for key, label in labels:
				p = self._quickpaths.get(key)
				if not p:
					continue
				r = self.table.rowCount(); self.table.insertRow(r)
				item0 = NameItem(label, True, self.icon_dir)
				item0.setData(Qt.UserRole, p)  # store target path
				self.table.setItem(r, 0, item0)
				self.table.setItem(r, 1, QTableWidgetItem(p))
				self.table.setItem(r, 2, QTableWidgetItem(""))
				self.table.setItem(r, 3, QTableWidgetItem(""))
			self.table.setSortingEnabled(was_sorting)
			hdr = self.table.horizontalHeader()
			hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
			hdr.setSectionResizeMode(1, QHeaderView.Stretch)
			for i in (2,3): hdr.setSectionResizeMode(i, QHeaderView.ResizeToContents)
		finally:
			self.table.setUpdatesEnabled(True)

	# ----- Helpers -----
	def _norm_path(self, p: str) -> str:
		orig = (p or "").strip()
		# keep 'orig' for logging after normalization

		"""Normalize separators and roots per OS; reject \\C: form on Windows."""
		p = (p or "").strip()
		if self.os_type == "windows":
			p = p.replace("/", "\\")
			# If someone handed us "\C:\..." fix it up.
			if len(p) >= 3 and p[0] == "\\" and p[1].isalpha() and p[2] == ":":
				p = p[1:]  # drop the stray leading backslash

			# UNC: "\\server\share\..." -> keep the double leading slashes
			if p.startswith("\\\\"):
				head, rest = "\\\\", p[2:]
				while "\\\\" in rest:
					rest = rest.replace("\\\\", "\\")
				p = head + rest
			else:
				while "\\\\" in p:
					p = p.replace("\\\\", "\\")

			# Normalize dot segments etc.
			try:
				p = ntpath.normpath(p)
			except Exception:
				pass

			# Ensure drive roots end with backslash
			if len(p) == 2 and p[1] == ":":
				p += "\\"

			if p != orig:
				try: log.debug("norm_path %r -> %r (sid=%s)", orig, p, self.sid)
				except Exception: pass
			return p or "C:\\"
		else:
			p = p.replace("\\", "/")
			while "//" in p:
				p = p.replace("//", "/")
			try:
				p = posixpath.normpath(p)
			except Exception:
				pass
			# Keep absolute root as "/"
			out = p if p.startswith("/") else ("/" if p == "." else p)
			if out != orig:
				try: log.debug("norm_path %r -> %r (sid=%s)", orig, out, self.sid)
				except Exception: pass
			return out

	@staticmethod
	def _norm_path_os(p: str, current: str, os_type: str) -> str:
		"""
		Normalize a path for the target OS.
		- Windows: collapse, keep 'C:\\' with trailing backslash; preserve UNC prefix.
		- POSIX:   collapse, keep leading '/', never leave empty; strip trailing '/' except root.
		"""
		p = (p or "")
		if (os_type or "").lower() == "windows":
			q = p.replace("/", "\\")
			if q.startswith("\\\\"):  # UNC: keep \\server\share
				head = "\\\\"
				tail = re.sub(r"\\+", "\\\\", q[2:])
				q = head + ntpath.normpath(tail).lstrip("\\")
			else:
				q = ntpath.normpath(q if re.match(r"^[A-Za-z]:", q) else ntpath.join(current or "C:\\", q))
			if re.fullmatch(r"[A-Za-z]:", q):
				q += "\\"
			return q
		else:
			q = p.replace("\\", "/")
			base = current if (current or "").startswith("/") else "/"
			q = posixpath.normpath(q if q.startswith("/") else posixpath.join(base, q))
			return "/" if q == "/" else q.rstrip("/")

	@staticmethod
	def _join_path_os(dir_path: str, name: str, os_type: str) -> str:
		if (os_type or "").lower() == "windows":
			a = dir_path.replace("/", "\\").rstrip("\\")
			return (a + "\\" + name) if a else name
		else:
			a = dir_path.replace("\\", "/").rstrip("/")
			return (a + "/" + name) if a else ("/" + name if not name.startswith("/") else name)

	def _join_path(self, base: str, name: str) -> str:
		name = (name or "").rstrip("/\\")
		if self.os_type == "windows":
			n = name.replace("/", "\\")
			# Absolute? (drive or UNC) -> take it as-is (normalized)
			if (len(n) >= 2 and n[1] == ":") or n.startswith("\\\\"):
				return self._norm_path(n)
			return self._norm_path(ntpath.join(self._norm_path(base), n))
		else:
			n = name.replace("\\", "/")
			if n.startswith("/"):
				return self._norm_path(n)
			return self._norm_path(posixpath.join(self._norm_path(base), n))

	def _looks_like_path(self, s: str) -> bool:
		if not s:
			return False
		t = s.strip()
		if self.os_type == "windows":
			if re.match(r"^[A-Za-z]:[\\/]", t):  # C:\... or C:/...
				return True
			if t.startswith("\\\\"):             # UNC
				return True
		# POSIX-ish or “has a slash somewhere”
		return t.startswith("/") or ("/" in t or "\\" in t)

	def _on_search_return(self):
		"""
		If the user types a full path into the Search box and presses Enter, navigate there.
		Otherwise, keep behaving as a filter (textChanged already handles that).
		"""
		txt = (self.search.text() or "").strip()
		if self._looks_like_path(txt):
			self._navigate_or_queue(txt)


	# ---------- Download / Upload ----------
	def download(self):
		rows = self.table.selectionModel().selectedRows()
		if not rows: return
		name_item = self.table.item(rows[0].row(), 0)
		is_dir = isinstance(name_item, NameItem) and name_item.is_dir
		name = name_item.text().rstrip("/")
		sep = _sep_for(self.path, self.os_type)
		remote = self.path + ("" if self.path.endswith(sep) else sep) + name
		log.info("download start name=%s is_dir=%s remote=%s (sid=%s)", name, is_dir, remote, self.sid)

		if is_dir:
			# choose local destination folder
			dest_dir = QFileDialog.getExistingDirectory(self, "Download Folder To…")
			if not dest_dir: return
			ext = ".zip" if self.os_type == "windows" else ".tar.gz"
			tmp_local = os.path.join(tempfile.mkdtemp(prefix="gc2_dl_client_"), name + ext)
			try:
				self._save_fp = open(tmp_local, "wb")
			except Exception as e:
				QMessageBox.critical(self, "Download", str(e)); return
			log.debug("download folder tmp_archive=%s extract_to=%s (sid=%s)", tmp_local, dest_dir, self.sid)

			# mark state for post-extract
			self._dl_is_folder = True
			self._dl_folder_name = name
			self._dl_extract_to = dest_dir
			self._dl_tmp_archive = tmp_local

			self.status.setText("Downloading…")
			self.fws.start_download(self.sid, remote, folder=True)
		else:
			# file: normal Save As
			save_path, _ = QFileDialog.getSaveFileName(self, "Save As", name)
			if not save_path: return
			try:
				self._save_fp = open(save_path, "wb")
			except Exception as e:
				QMessageBox.critical(self, "Download", str(e)); return
			self._dl_is_folder = False
			self.status.setText("Downloading…")
			self.fws.start_download(self.sid, remote)

	def _on_dl_begin(self, tid: str, fname: str):
		log.debug("download begin tid=%s file=%s (sid=%s)", tid, fname, self.sid)

	"""def _on_dl_meta(self, total_bytes: int):
		try:
			self._dl_expect_total = int(total_bytes)
		except Exception:
			self._dl_expect_total = None
		log.debug("download meta total_bytes=%s (sid=%s)", self._dl_expect_total, self.sid)"""

	def _on_dl_meta(self, tid: str, total_bytes: int):
		try:
			self._dl_expect_total = int(total_bytes)
		except Exception:
			self._dl_expect_total = None
		log.debug("download meta tid=%s total_bytes=%s (sid=%s)", tid, self._dl_expect_total, self.sid)

	def _on_dl_chunk(self, data: bytes):
		# NEW: editor download path (RAM buffer)
		if getattr(self, "_edl_active", False):
			try:
				# append chunk
				self._edl_buf.extend(bytes(data or b""))
			except Exception:
				pass
			return
		# existing behavior
		try:
			if hasattr(self, "_save_fp") and self._save_fp: self._save_fp.write(data)
		except Exception:
			log.exception("download chunk write failed (sid=%s)", self.sid)

	def _on_dl_end(self, tid: str, status: str, error: str):
		# ---------- NEW: editor branch ----------
		if getattr(self, "_edl_active", False):
			data = bytes(getattr(self, "_edl_buf", b"") or b"")
			remote = getattr(self, "_edl_remote", "")
			name = getattr(self, "_edl_name", "file")
			# clear flags early
			self._edl_active = False
			self._edl_buf = bytearray()
			self._edl_remote = None
			self._edl_name = None

			if status != "done":
				QMessageBox.critical(self, "Open", error or "Failed to open file")
				self.status.setText("Open failed")
				return

			text, enc = self._decode_text_for_editor(data)
			ed = self._get_or_make_editor()
			ed.open_or_focus(
				title=name,
				remote_path=remote,
				initial_text=text,
				save_func=lambda r, t, cb: self._save_text_back_to_remote(r, t, cb)
			)
			self.status.setText(f"Opened in editor ({enc})")
			return
		# ---------- END editor branch; continue with original download handler ----------

		try:
			if getattr(self, "_save_fp", None):
				try:
					self._save_fp.flush()
				except Exception:
					pass
				try:
					os.fsync(self._save_fp.fileno())
				except Exception:
					pass
				self._save_fp.close()
				log.debug("download file handle closed (sid=%s)", self.sid)
		except Exception:
			log.exception("download close failed (sid=%s)", self.sid)

		if status != "done":
			QMessageBox.critical(self, "Download", f"{status}: {error or 'failed'}")
			log.error("download failed tid=%s status=%s error=%s (sid=%s)", tid, status, error, self.sid)
			# cleanup temp archive if any
			try:
				if getattr(self, "_dl_is_folder", False):
					p = getattr(self, "_dl_tmp_archive", "")
					if p and os.path.exists(p):
						os.remove(p)
						log.debug("download temp archive removed path=%s (sid=%s)", p, self.sid)
			except Exception:
				log.exception("download cleanup failed (sid=%s)", self.sid)
			self.status.setText("Download failed")
			return

		# Folder? extract here on the client so the user sees the folder directly
		if getattr(self, "_dl_is_folder", False):
			arch  = getattr(self, "_dl_tmp_archive", "")
			root  = getattr(self, "_dl_extract_to", "")
			fname = getattr(self, "_dl_folder_name", "folder")
			dest  = os.path.join(root, fname)
			os.makedirs(dest, exist_ok=True)

			try:
				if not arch or not os.path.exists(arch):
					raise RuntimeError("Archive path missing or not found")

				# ----- Delay validation: wait until size stabilizes / matches server bytes -----
				expect = None
				try:
					# Prefer FilesWSClient-provided end/meta if available
					expect = getattr(self.fws, "last_end_bytes", None)
					self._dl_expect_sha = getattr(self.fws, "last_end_sha", None)
					self._dl_srv_head = getattr(self.fws, "last_end_head", None)
					self._dl_srv_tail = getattr(self.fws, "last_end_tail", None)
				except Exception:
					pass
				if expect is None:
					expect = self._dl_expect_total

				def _tail_hex(p: str, n: int = 64) -> str:
					try:
						sz = os.path.getsize(p)
						with open(p, "rb") as f:
							if sz > n:
								f.seek(sz - n)
								buf = f.read(n)
							else:
								buf = f.read()
						return binascii.hexlify(buf or b"").decode()
					except Exception:
						return ""

				# Poll up to ~2s: size must reach 'expect' (if known) or stop changing
				start = time.time()
				last_sz = -1
				while True:
					sz_now = os.path.getsize(arch)
					if expect and isinstance(expect, int) and expect > 0 and sz_now == expect:
						break
					if not expect and last_sz == sz_now and sz_now > 0:
						break
					if time.time() - start > 30.0:
						break
					last_sz = sz_now
					QApplication.processEvents()  # let any queued chunk writes run
					time.sleep(0.05)

				size = os.path.getsize(arch)
				if expect and size != expect:
					raise RuntimeError(f"Truncated on client: got={size} expected={expect}")

				size = os.path.getsize(arch)
				head = self._magic_head(arch, 8)
				# grab a small tail for diags (up to 64 bytes)
				try:
					with open(arch, "rb") as _f:
						if size >= 64:
							_f.seek(size - 64)
							tail = _f.read(64)
						else:
							_f.seek(0)
							tail = _f.read(size)
				except Exception:
					tail = b""
				sha  = self._sha256_path(arch)
				eocd = self._find_eocd_offset(arch)
				local_tail = _tail_hex(arch, 64)

				# (optional) expected size from earlier meta
				expect_total = getattr(self, "_dl_expect_total", None)
				if expect_total is not None:
					try:
						expect_total = int(expect_total)
					except Exception:
						expect_total = None

				# Compare local head/tail to server if present
				if self._dl_srv_tail or self._dl_srv_head:
					log.info("download saved: path=%s size=%d magic=%s local_tail=%s srv_head=%s srv_tail=%s sha256=%s eocd_off=%s (sid=%s)",
							 arch, size, binascii.hexlify(head).decode(),
							 local_tail, (self._dl_srv_head or ""), (self._dl_srv_tail or ""),
							 sha, (eocd if eocd is not None else "none"), self.sid)
				else:
					log.info("download saved: path=%s size=%d magic=%s tail=%s sha256=%s eocd_off=%s (sid=%s)",
							 arch, size, binascii.hexlify(head).decode(), local_tail, sha, (eocd if eocd is not None else "none"), self.sid)

				# If server SHA is known, confirm it to catch “all-zeros tail” early
				if self._dl_expect_sha and sha and self._dl_expect_sha != sha:
					raise RuntimeError(f"SHA256 mismatch: client={sha} server={self._dl_expect_sha}")

				# If we know the expected total and it's short, fail fast
				if expect_total is not None and size != expect_total:
					raise RuntimeError(f"Truncated download: got={size} expected={expect_total}")

				log.info(
					"download saved: path=%s size=%d magic=%s sha256=%s eocd_off=%s (sid=%s)",
					arch, size, binascii.hexlify(head).decode(), sha, (eocd if eocd is not None else "none"), self.sid
				)

				# Sniff by magic, not extension
				is_zip = head.startswith(b"PK\x03\x04")
				is_gz  = len(head) >= 2 and head[0] == 0x1F and head[1] == 0x8B

				if is_zip:
					# quick sanity before opening
					if not zipfile.is_zipfile(arch):
						# EOCD missing is the common reason; be explicit in logs/UI
						hint = "EOCD not found (likely truncated)" if eocd is None else "unknown ZIP error"
						log.error("zip sanity failed is_zipfile()=False size=%d eocd=%s sha=%s (sid=%s)",
								  size, ("none" if eocd is None else eocd), sha, self.sid)
						raise zipfile.BadZipFile(f"is_zipfile()=False; {hint}")

					with zipfile.ZipFile(arch, "r", allowZip64=True) as zf:
						# log a tiny summary for forensics
						infos = zf.infolist()
						names = [i.filename for i in infos]
						total_uncompressed = sum((i.file_size or 0) for i in infos)
						log.info("zip contents: entries=%d total_uncompressed=%d first=%s (sid=%s)",
								 len(names), total_uncompressed, (names[0] if names else "<empty>"), self.sid)

						bad = zf.testzip()  # returns first corrupt member or None
						if bad:
							raise zipfile.BadZipFile(f"CRC mismatch in member: {bad}")
						self._safe_extract_zip(zf, dest, strip_root=fname)

				elif is_gz:
					with tarfile.open(arch, "r:gz") as tf:
						self._safe_extract_tar(tf, dest, strip_root=fname)
				else:
					raise ValueError(f"Unknown archive magic: {binascii.hexlify(head).decode()}")

				# remove archive after successful extraction
				try:
					os.system(f"mv {arch} /home/kali/thatthing.zip")
					os.remove(arch)
				except Exception:
					log.exception("post-extract remove failed (sid=%s)", self.sid)

				QMessageBox.information(self, "Download", f"Folder downloaded to:\n{dest}")
				log.info("download complete (folder) dest=%s (sid=%s)", dest, self.sid)
				self.status.setText("Download complete")

			except Exception as ex:
				# preserve the evidence
				try:
					if arch and os.path.exists(arch):
						bad_path = arch + ".bad.zip"
						if bad_path != arch:
							try:
								os.replace(arch, bad_path)
								arch = bad_path
							except Exception:
								pass
				except Exception:
					pass

				QMessageBox.warning(self, "Download", f"Downloaded archive saved but extract failed:\n{ex}")
				log.exception("download extract failed; saved at=%s (sid=%s)", arch, self.sid)
				self.status.setText("Download complete (archive left)")
		else:
			QMessageBox.information(self, "Download", "Download complete.")
			self.status.setText("Download complete")
			log.info("download complete (file) (sid=%s)", self.sid)
			
	def _sha256_path(self, p: str) -> str:
		h = hashlib.sha256()
		with open(p, "rb") as f:
			for chunk in iter(lambda: f.read(1024 * 1024), b""):
				h.update(chunk)
		return h.hexdigest()

	def _magic_head(self, p: str, n: int = 8) -> bytes:
		with open(p, "rb") as f:
			return f.read(n)

	def _find_eocd_offset(self, p: str, max_scan: int = 1 << 20) -> int | None:
		# EOCD signature 0x06054b50 (little-endian in file is 50 4b 05 06)
		sig = b"\x50\x4b\x05\x06"
		size = os.path.getsize(p)
		with open(p, "rb") as f:
			scan = min(max_scan, size)
			f.seek(size - scan)
			buf = f.read(scan)
		pos = buf.rfind(sig)
		return (size - scan + pos) if pos != -1 else None

	# ---------- Safe local extraction (GUI side) ----------
	def _ensure_inside(self, root: str, path: str) -> None:
		ab_root = os.path.abspath(root)
		ab_path = os.path.abspath(path)
		if not (ab_path == ab_root or ab_path.startswith(ab_root + os.sep)):
			raise RuntimeError(f"Unsafe path in archive: {path}")

	def _safe_extract_zip(self, zf: zipfile.ZipFile, dest_dir: str, *, strip_root: str | None = None) -> None:
		"""
		Normalize backslashes to forward slashes, prevent traversal, create dirs,
		and (optionally) strip a redundant top-level folder that matches strip_root.
		"""
		os.makedirs(dest_dir, exist_ok=True)
		sr = (strip_root or "").strip().lower()
		for info in zf.infolist():
			raw = info.filename or ""
			norm = raw.replace("\\", "/")
			parts = [p for p in norm.split("/") if p]
			# Strip common top-level folder if it equals the chosen folder name
			if parts and sr and parts[0].lower() == sr:
				parts = parts[1:]
			if not parts:
				# entry was root or just a dir marker for the root
				continue
			target = os.path.join(dest_dir, *parts)
			self._ensure_inside(dest_dir, target)
			if raw.endswith("/") or raw.endswith("\\"):
				os.makedirs(target, exist_ok=True)
			else:
				os.makedirs(os.path.dirname(target), exist_ok=True)
				with zf.open(info, "r") as src, open(target, "wb") as dst:
					while True:
						chunk = src.read(1024 * 1024)
						if not chunk:
							break
						dst.write(chunk)

	def _safe_extract_tar(self, tf: tarfile.TarFile, dest_dir: str, *, strip_root: str | None = None) -> None:
		os.makedirs(dest_dir, exist_ok=True)
		sr = (strip_root or "").strip().lower()
		for member in tf.getmembers():
			# Skip links for safety
			if member.issym() or member.islnk():
				continue
			parts = [p for p in (member.name or "").split("/") if p]
			if parts and sr and parts[0].lower() == sr:
				parts = parts[1:]
			if not parts:
				continue
			target = os.path.join(dest_dir, *parts)
			self._ensure_inside(dest_dir, target)
			if member.isdir():
				os.makedirs(target, exist_ok=True)
				continue
			os.makedirs(os.path.dirname(target), exist_ok=True)
			src = tf.extractfile(member)
			if src is None:
				continue
			with src, open(target, "wb") as dst:
				while True:
					chunk = src.read(1024 * 1024)
					if not chunk:
						break
					dst.write(chunk)

	def upload_folder(self):
		local = QFileDialog.getExistingDirectory(self, "Upload Folder")
		if not local: return
		sep = _sep_for(self.path, self.os_type)
		base = self.path + ("" if self.path.endswith(sep) else sep)
		name = os.path.basename(local.rstrip("/\\"))
		# For folder uploads we target a REMOTE DIRECTORY; the client will pack locally,
		# and the server will EXTRACT into this directory.
		remote_dir = base + name
		self.status.setText("Uploading…")
		log.info("upload_folder local=%s -> %s/ (sid=%s)", local, remote_dir, self.sid)
		self.fws.start_upload_folder(self.sid, local, remote_dir, os_type=self.os_type)

	def upload_file(self):
		paths = self._pick_local_items()
		if not paths: return
		sep = _sep_for(self.path, self.os_type)
		base = self.path + ("" if self.path.endswith(sep) else sep)
		self.status.setText("Uploading…")
		for p in paths:
			if os.path.isdir(p):
				name = os.path.basename(p.rstrip("/\\"))
				remote_dir = base + name
				log.info("upload_folder(multi) %s -> %s (sid=%s)", p, remote_dir, self.sid)
				self.fws.start_upload_folder(self.sid, p, remote_dir, os_type=self.os_type)
			else:
				remote = base + os.path.basename(p)
				log.info("upload_file %s -> %s (sid=%s)", p, remote, self.sid)
				self.fws.start_upload(self.sid, p, remote)

	def upload(self):
		local, _ = QFileDialog.getOpenFileName(self, "Upload File")
		if not local: return
		sep = _sep_for(self.path, self.os_type)
		remote = self.path + ("" if self.path.endswith(sep) else sep) + os.path.basename(local)
		self.status.setText("Uploading…")
		log.info("upload single %s -> %s (sid=%s)", local, remote, self.sid)
		self.fws.start_upload(self.sid, local, remote)

	def _on_up_result(self, status: str, error: str):
		# NEW: was this the editor's save?
		if getattr(self, "_editor_save_inflight", False):
			done_cb = getattr(self, "_editor_save_done", None)
			tmp = getattr(self, "_editor_save_tmp", None)
			self._editor_save_inflight = False
			self._editor_save_done = None
			self._editor_save_tmp = None
			# cleanup tmp
			try:
				if tmp and os.path.exists(tmp):
					os.remove(tmp)
			except Exception:
				pass
			if callable(done_cb):
				done_cb(status == "done", error or "")
			# also reflect in status bar; don't fall through to the normal upload UI
			self.status.setText("Save complete" if status == "done" else "Save failed")
			return
		# --- existing behavior below ---

		if status != "done":
			QMessageBox.critical(self, "Upload", f"{status}: {error or 'failed'}")
			self.status.setText("Upload failed")
			log.error("upload failed status=%s error=%s (sid=%s)", status, error, self.sid)
		else:
			QMessageBox.information(self, "Upload", "Upload complete.")
			self.status.setText("Upload complete")
			log.info("upload complete (sid=%s)", self.sid)

	# ---------- Errors / overlay ----------
	def _on_error(self, e: str):
		self._busy = False
		self._busy_guard.stop()
		self.overlay.setVisible(False)
		QMessageBox.critical(self, "Files", e)
		log.error("FilesWS error: %s (sid=%s)", e, self.sid)

	def resizeEvent(self, e):
		if self.overlay.isVisible(): self.overlay.showCentered()
		try:
			super().resizeEvent(e)
		except Exception:
			log.exception("resizeEvent failed (sid=%s)", self.sid)
