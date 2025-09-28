# gui/ldap_browser.py
from __future__ import annotations
import json, html, sip
from typing import Dict, Optional, List, Tuple
from contextlib import suppress

from PyQt5.QtCore import (
	Qt, QAbstractItemModel, QModelIndex, QVariant, pyqtSignal,
	QUrl, QUrlQuery, QTimer, QEvent, QSize, QLineF, QPointF, QObject
)

from PyQt5.QtWidgets import (
	QWidget, QVBoxLayout, QHBoxLayout, QTreeView, QTableWidget, QTableWidgetItem,
	QHeaderView, QLineEdit, QPushButton, QLabel, QComboBox, QSplitter, QFrame, QSpacerItem, QSizePolicy,
	QToolButton, QMenu, QApplication, QShortcut, QTabBar, QStackedWidget, QStyle, QTabWidget
)

from PyQt5.QtWebSockets import QWebSocket
from PyQt5.QtGui import QFont, QKeySequence, QIcon, QPainter, QColor, QPen, QPixmap, QStandardItemModel, QStandardItem

# (safe fallback identical to your pattern)
try:
	from theme_center import theme_color
	import qtawesome as qta
except Exception:
	def theme_color(_k, d): return d
	qta = None


# ---------- Visual helpers ----------------------------------------------------

def _apply_styles(widget: QWidget):
	"""
	Global stylesheet tuned for dark UI; no 'box-shadow' (Qt doesn't support it).
	Clean, subtle, and consistent between tree & table, like the file browser.
	"""
	widget.setStyleSheet("""
	QWidget { color: #dce3ea; }
	QFrame#TopBar {
		background: transparent;
	}

	/* Quick Access header chip */
	QLabel#QuickHdr {
		font-weight: 800;
		color: #eaf2ff;
		padding: 2px 4px;
	}

	/* thin vertical separator used in the connection bar */
	QFrame#VSep {
		background: #243044;
		min-width: 1px; max-width: 1px;
		margin: 0 6px;
	}
	/* chip-like toggle for the Options row */
	QToolButton#OptionsToggle {
		background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
					stop:0 #253242, stop:1 #1b2533);
		border: 1px solid #2b3c5c;
		border-radius: 11px;
		padding: 4px 10px;
		color: #dbe7fb;
	}
	QToolButton#OptionsToggle:hover { background: #243349; }
	QToolButton#OptionsToggle:checked { background: #1e2a3e; }

	QLineEdit, QComboBox, QTableView, QTreeView {
		background: rgba(12,16,22,0.65);
		border: 1px solid #243044;
		border-radius: 9px;
		selection-background-color: #1e293b;
		selection-color: #eaf2ff;
	}
	QLineEdit:focus, QComboBox:focus, QTableView:focus, QTreeView:focus {
		border: 1px solid #365985;
	}
	QHeaderView::section {
		background: #0e1520;
		color: #cdd6e3;
		padding: 6px 8px;
		border: 0;
		border-bottom: 1px solid #1e2a3d;
	}
	QTableWidget {
		gridline-color: #1f2b3e;
		border: 1px solid #243044;
		border-radius: 9px;
	}
	QTreeView {
		background: transparent;
		border: 1px solid #243044;
		border-radius: 9px;
		show-decoration-selected: 1;
	}
	QPushButton, QToolButton {
		background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
					stop:0 #253242, stop:1 #1b2533);
		border: 1px solid #2b3c5c;
		border-radius: 11px;
		padding: 6px 12px;
	}
	QPushButton:hover, QToolButton:hover {
		background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
					stop:0 #2a3a4e, stop:1 #213044);
	}
	QPushButton:pressed, QToolButton:pressed { background: #172130; }

	/* Slim scrollbars */
	QScrollBar:vertical, QScrollBar:horizontal { background: transparent; border: none; margin: 0px; }
	QScrollBar::handle { background: #2b3b52; border-radius: 6px; min-height: 24px; min-width: 24px; }
	QScrollBar::handle:hover { background: #35506f; }
	QScrollBar::add-line, QScrollBar::sub-line { height:0; width:0; }

	/* Polished context menu to match the glassy dark UI */
	QMenu {
		background: #0f1622;
		color: #dde6f3;
		border: 1px solid #33455f;
		border-radius: 10px;
		padding: 6px 4px;
	}
	QMenu::separator {
		height: 1px;
		background: #233145;
		margin: 6px 10px;
	}
	QMenu::item {
		padding: 6px 14px;
		border-radius: 6px;
	}
	QMenu::item:selected { background: #1a2433; }

	/* File-browser style tabs */
	QTabBar::tab {
		background: #1a2330;
		color: #d9e3f0;
		border: 1px solid #2b3c5c;
		padding: 6px 32px 6px 14px; /* room for a bigger close button */
		border-top-left-radius: 9px;
		border-top-right-radius: 9px;
		margin-right: 6px;
	}
	QTabBar::tab:selected {
		background: #202b3a;
		border-bottom-color: #202b3a;
	}
	QTabBar::tab:!selected {
		background: #151d28;
	}

	/* Make the built-in overflow scroller arrows look like premium chips */
	QTabBar::scroller {
		width: 42px;                       /* breathing room */
	}

	/* Gorgeous, crisp close button (real widget, not the style primitive) */
	QToolButton#TabCloseBtn {
		min-width: 24px;  max-width: 24px;
		min-height: 24px; max-height: 24px;
		padding: 0;
		margin-left: 10px;
		margin-right: 6px;              
		border: 1px solid transparent;
		border-radius: 12px;
		background: transparent;
	}
	QToolButton#TabCloseBtn:hover {
		background: rgba(239, 68, 68, 0.15); /* soft halo */
		border: 1px solid rgba(239, 68, 68, 0.65);
	}
	QToolButton#TabCloseBtn:pressed {
		background: rgba(220, 38, 38, 0.22);
		border: 1px solid rgba(220, 38, 38, 0.85);
		padding-top: 1px; padding-left: 1px; /* tiny tactile nudge */
	}

	QToolButton#TabCloseBtn:focus {
		outline: none;
		box-shadow: 0 0 0 2px rgba(95,142,214,0.35); /* subtle focus ring */
		border: 1px solid #5f8ed6;
	}

	QTabBar QToolButton::right-arrow {
		image: url(:/qt-project.org/styles/commonstyle/images/right-32.png);
		width: 12px; height: 12px;
	}
	QTabBar QToolButton::left-arrow {
		image: url(:/qt-project.org/styles/commonstyle/images/left-32.png);
		width: 12px; height: 12px;
	}

	/* Slight spacing between tabs */
	QTabBar { qproperty-movable: true; }
	QTabBar::tab { margin-right: 8px; }

	""")

class _QuickItem(QStandardItem):
	"""Convenience item storing DN & type."""
	def __init__(self, text: str, dn: str = "", kind: str = "", is_group: bool = False):
		super().__init__(text)
		self.setEditable(False)
		# Store metadata
		self.setData(dn, Qt.UserRole + 1)     # DN for leaves
		self.setData(kind, Qt.UserRole + 2)   # 'users' | 'groups' | 'ous' | 'computers' | 'dcs' | ''
		self.setData(is_group, Qt.UserRole + 3)

	@property
	def dn(self) -> str:
		return self.data(Qt.UserRole + 1) or ""
	@property
	def kind(self) -> str:
		return self.data(Qt.UserRole + 2) or ""
	@property
	def is_group(self) -> bool:
		return bool(self.data(Qt.UserRole + 3))


class _GlassCard(QFrame):
	def __init__(self, radius=12, parent=None):
		super().__init__(parent)
		self._r = radius
		self.setAttribute(Qt.WA_StyledBackground, True)
		self.setAutoFillBackground(False)
		self.setStyleSheet("QFrame{background:transparent;border:none;}")

	def paintEvent(self, ev):
		from PyQt5.QtGui import QPainter, QColor, QPainterPath, QLinearGradient, QPen
		from PyQt5.QtCore import QRectF
		p = QPainter(self); p.setRenderHint(QPainter.Antialiasing, True)
		r = self.rect().adjusted(1,1,-1,-1); rf = QRectF(r)
		g = QLinearGradient(rf.topLeft(), rf.bottomRight())
		g.setColorAt(0.0, QColor(theme_color("panel_grad_hi", "#111823")))
		g.setColorAt(1.0, QColor(theme_color("panel_grad_lo", "#0a0f16")))
		path = QPainterPath(); path.addRoundedRect(rf, float(self._r), float(self._r))
		p.fillPath(path, g)
		top = QLinearGradient(rf.topLeft(), rf.topRight())
		top.setColorAt(0.0, QColor(255,255,255,18)); top.setColorAt(1.0, QColor(255,255,255,0))
		p.fillPath(path, top)
		p.setPen(QPen(QColor(theme_color("panel_border", "#243044")), 1))
		p.drawPath(path); p.end()

# --- Tree model (lazy) -------------------------------------------------------
class _Node:
	__slots__ = ("dn","rdn","has_children","loaded","children","attrs")
	def __init__(self, dn:str, rdn:str, has_children:bool):
		self.dn = dn; self.rdn = rdn; self.has_children = bool(has_children)
		self.loaded = False
		self.children: List["_Node"] = []
		self.attrs: Dict[str, List[str]] = {}

class LdapTreeModel(QAbstractItemModel):
	nodeActivated = pyqtSignal(object)  # _Node

	def __init__(self, parent=None):
		super().__init__(parent)
		self.roots: List[_Node] = []

	def columnCount(self, parent): return 1
	def rowCount(self, parent):
		n = self._node(parent)
		return len(n.children) if n else len(self.roots)

	# Make nodes look expandable as soon as we know they can have children
	def hasChildren(self, parent):
		if not parent.isValid():
			return len(self.roots) > 0
		n = self._node(parent)
		if not n: return False
		return bool(n.has_children or n.children)

	def index(self, row, col, parent):
		if col != 0 or row < 0: return QModelIndex()
		if not parent.isValid():
			if 0 <= row < len(self.roots): return self.createIndex(row, col, self.roots[row])
			return QModelIndex()
		p = self._node(parent)
		if not p or row >= len(p.children): return QModelIndex()
		return self.createIndex(row, col, p.children[row])

	def parent(self, idx):
		if not idx.isValid(): return QModelIndex()
		node = self._node(idx); par = self._parent_of(node)
		if par is None: return QModelIndex()
		grand = self._parent_of(par)
		siblings = self.roots if grand is None else grand.children
		try: row = siblings.index(par)
		except Exception: return QModelIndex()
		return self.createIndex(row, 0, par)

	def data(self, idx, role):
		if not idx.isValid(): return QVariant()
		node = self._node(idx)
		if role == Qt.DisplayRole:
			return node.rdn or node.dn
		return QVariant()

	def _node(self, idx) -> Optional[_Node]:
		return idx.internalPointer() if idx.isValid() else None

	def _parent_of(self, node: Optional[_Node]) -> Optional[_Node]:
		if node is None: return None
		def dfs(p: Optional[_Node]) -> Optional[_Node]:
			if p is None: return None
			for ch in p.children:
				if ch is node: return p
				res = dfs(ch)
				if res: return res
			return None
		for r in self.roots:
			if r is node: return None
			res = dfs(r)
			if res: return res
		return None

	# mutate API
	def set_roots(self, dns: List[str]):
		self.beginResetModel()
		self.roots = [_Node(d, d.split(",",1)[0] if d else d, True) for d in dns]
		self.endResetModel()

	def insert_children(self, parent_idx: QModelIndex, rows: List[Dict[str, any]]):
		parent_node = self._node(parent_idx)
		if parent_node is None:
			return
		# If server returned no rows, don't emit an invalid insert range.
		# Keep the expander by leaving has_children as-is and refresh the view.
		if not rows:
			parent_node.loaded = True
			self.dataChanged.emit(parent_idx, parent_idx, [Qt.DisplayRole])
			return

		parent_node.loaded = True
		begin = len(parent_node.children)
		self.beginInsertRows(parent_idx, begin, begin + len(rows) - 1)
		for r in rows:
			ch = _Node(r.get("dn", ""), r.get("rdn", ""), bool(r.get("has_children")))
			ch.attrs = r.get("attrs") or {}
			parent_node.children.append(ch)
		self.endInsertRows()


# --- Single LDAP Pane (one tab) ----------------------------------------------
class _LdapPane(QWidget):
	titleChanged = pyqtSignal(str)  # emit when we can show a nice tab title (e.g., host)
	wantNewTab = pyqtSignal()       # could be used for ctrl+t later

	def __init__(self, api, sid: str = "", hostname: str = "", parent=None):
		super().__init__(parent)
		self.api = api; self.sid = sid; self.hostname = hostname
		self._default_naming_context: str = ""
		_apply_styles(self)

		outer = QVBoxLayout(self); outer.setContentsMargins(10,10,10,10)

		def _vsep() -> QFrame:
			s = QFrame()
			s.setObjectName("VSep")
			s.setFrameShape(QFrame.NoFrame)
			return s

		# Track host + most recent LDAP RDN for dynamic tab names
		self._host_short: str = ""   # e.g. "vagrant"
		self._last_rdn:   str = ""   # e.g. "CN=Users"

		# --- Title + status line (lightweight)
		hdr = QHBoxLayout(); hdr.setSpacing(10)
		self.title = QLabel("LDAP Browser")
		self.title.setStyleSheet("QLabel{font-weight:800;font-size:16pt;color:#eaf2ff;letter-spacing:0.3px;}")
		self.status = QLabel("Disconnected"); self.status.setStyleSheet("QLabel{color:#cbd5e1;}")
		hdr.addWidget(self.title); hdr.addStretch(1); hdr.addWidget(self.status)
		outer.addLayout(hdr)

		# (Old inline auth rows removed in favor of the New Bind dialog)

		# --- Second bar (base + live filter + page + preset + search)
		bar2 = QHBoxLayout(); bar2.setSpacing(12)
		self.ed_base   = QLineEdit(); self.ed_base.setPlaceholderText("Base DN")
		self.btn_copy  = QToolButton(); self.btn_copy.setText("📋"); self.btn_copy.setToolTip("Copy Base DN")
		self.ed_filter = QLineEdit(); self.ed_filter.setPlaceholderText("(type to live search…) e.g. (&(objectCategory=person)(objectClass=user))")
		self.cmb_page  = QComboBox(); self.cmb_page.addItems(["200","500","1000"]); self.cmb_page.setCurrentText("500")
		self.cmb_preset= QComboBox(); self.cmb_preset.addItems(["Preset: All","Preset: Users","Preset: Groups","Preset: Computers"])
		self.btn_search= QPushButton("Search")
		for w in (self.ed_base,self.ed_filter,self.cmb_page,self.cmb_preset,self.btn_search,self.btn_copy):
			w.setMinimumHeight(30)
		bar2.addWidget(QLabel("Base:"));  bar2.addWidget(self.ed_base, 1); bar2.addWidget(self.btn_copy, 0)
		bar2.addWidget(QLabel("Filter:"));bar2.addWidget(self.ed_filter, 3)
		# give the small controls a little air before Search
		bar2.addSpacing(6)
		bar2.addWidget(QLabel("Page:"));  bar2.addWidget(self.cmb_page, 0)
		bar2.addWidget(self.cmb_preset, 0)
		bar2.addWidget(self.btn_search, 0)
		outer.addLayout(bar2)

		# --- Split: tree (left) + right stack (attributes OR search results)
		self.split = QSplitter(Qt.Horizontal); outer.addWidget(self.split, 1)

		# Left: a vertical splitter that hosts Quick Access (top) and the raw Directory tree (bottom)
		self.left = QSplitter(Qt.Vertical)
		self.left.setChildrenCollapsible(False)
		self.split.addWidget(self.left)

		# --- Quick Access (top)
		qa_wrap = QFrame()
		qa_v = QVBoxLayout(qa_wrap); qa_v.setContentsMargins(0,0,0,0); qa_v.setSpacing(6)
		self.quick_hdr = QLabel("Quick Access")
		self.quick_hdr.setObjectName("QuickHdr")
		qa_v.addWidget(self.quick_hdr, 0)

		self.quick = QTreeView()
		self.quick.setUniformRowHeights(True)
		self.quick.setHeaderHidden(True)
		self.quick.setAnimated(True)
		self.quick.setIndentation(16)
		self.quick.setEditTriggers(QTreeView.NoEditTriggers)
		qa_v.addWidget(self.quick, 1)
		self.left.addWidget(qa_wrap)

		# Model for Quick Access
		self.quickModel = QStandardItemModel(self.quick)
		self.quick.setModel(self.quickModel)
		self._quick_built = False
		self.quick.expanded.connect(self._on_quick_expanded)
		self.quick.doubleClicked.connect(self._on_quick_activated)
		# Context menu for quick
		self.quick.setContextMenuPolicy(Qt.CustomContextMenu)
		self.quick.customContextMenuRequested.connect(self._on_quick_ctx)

		# --- Directory tree (bottom)
		dir_wrap = QFrame()
		dir_v = QVBoxLayout(dir_wrap); dir_v.setContentsMargins(0,0,0,0); dir_v.setSpacing(6)
		self.dir_hdr = QLabel("Directory")
		self.dir_hdr.setObjectName("QuickHdr")
		dir_v.addWidget(self.dir_hdr, 0)

		self.tree = QTreeView()
		self.tree.setUniformRowHeights(True); self.tree.setHeaderHidden(True)
		self.tree.setAnimated(True); self.tree.setIndentation(18); self.tree.setExpandsOnDoubleClick(True)
		self.model = LdapTreeModel(self); self.tree.setModel(self.model)
		self.tree.setEditTriggers(QTreeView.NoEditTriggers)
		dir_v.addWidget(self.tree, 1)
		self.left.addWidget(dir_wrap)

		# Right stack
		self.stack = QStackedWidget()
		# 0: Attributes
		self.tbl_attrs = QTableWidget(0, 2)
		self.tbl_attrs.setHorizontalHeaderLabels(["Attribute", "Value"])
		self.tbl_attrs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
		self.tbl_attrs.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
		self.tbl_attrs.verticalHeader().setVisible(False)
		self.tbl_attrs.verticalHeader().setDefaultSectionSize(26)
		self.tbl_attrs.setAlternatingRowColors(True)
		self.stack.addWidget(self.tbl_attrs)
		# 1: Search Results
		self.tbl_results = QTableWidget(0, 3)
		self.tbl_results.setHorizontalHeaderLabels(["RDN", "DN", "Class"])
		self.tbl_results.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
		self.tbl_results.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
		self.tbl_results.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
		self.tbl_results.verticalHeader().setVisible(False)
		self.tbl_results.verticalHeader().setDefaultSectionSize(24)
		self.tbl_results.setAlternatingRowColors(True)
		self.stack.addWidget(self.tbl_results)

		self.split.addWidget(self.stack)
		self.split.setStretchFactor(1, 1)
		self.split.setChildrenCollapsible(False)

		# Give Quick Access a compact default height but keep resizable
		self.left.setSizes([160, 9999])

		# --- WebSocket (per pane)
		self.ws = QWebSocket(); self.ws.setParent(self)

		base = QUrl(self.api.base_url)
		if base.scheme() == "http": base.setScheme("ws")
		elif base.scheme() == "https": base.setScheme("wss")
		base.setPath("/ws/ldap")
		q = QUrlQuery(); q.addQueryItem("token", self.api.token or "")
		if self.sid: q.addQueryItem("sid", self.sid)
		base.setQuery(q)

		# Signals
		def _on_ws_error(*_): self._set_status("Error")
		(getattr(self.ws, "errorOccurred", None) or self.ws.error).connect(_on_ws_error)
		self.ws.textMessageReceived.connect(self._on_msg)
		# Use a real slot that checks widget liveness to avoid crashes when
		# signals arrive after the pane has been destroyed.
		self.ws.disconnected.connect(self._on_ws_disconnected)
		self.ws.connected.connect(lambda: (self._set_status("Connected — discovering…"), self._auto_open_current()))
		self.ws.open(base)

		# Wire UX
		self.btn_search.clicked.connect(self._do_search)
		self.btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.ed_base.text() or ""))
		self.cmb_preset.currentIndexChanged.connect(self._apply_preset)
		self.tree.expanded.connect(self._on_expanded)
		self.tree.clicked.connect(self._on_selected)
		self.tbl_results.cellDoubleClicked.connect(self._open_result_dn)

		# Shortcuts
		QShortcut(QKeySequence.Find, self, activated=lambda: self.ed_filter.setFocus())
		QShortcut(QKeySequence("Ctrl+Return"), self, activated=self._do_search)
		QShortcut(QKeySequence("Ctrl+Enter"),  self, activated=self._do_search)

		# Track host/DN so the parent tab can show: "<host>/<RDN>"
		self._host: str = ""
		self._last_dn: str = ""

		# Debounced live search
		self._debounce = QTimer(self); self._debounce.setSingleShot(True)
		self._debounce.timeout.connect(self._do_search)
		self.ed_filter.textChanged.connect(lambda _t: self._debounce.start(450))

		self._init_quick_model()

	# ---------- helpers ----------
	def _set_status(self, s: str):
		"""Safely set status text. No-ops if label is already deleted."""
		try:
			if hasattr(self, "status") and self.status is not None and not sip.isdeleted(self.status):
				self.status.setText(s)
		except Exception:
			# Ignore any late-arriving signals during teardown
			pass

	# ---------- Quick Access ----------
	def _init_quick_model(self):
		"""Build static category nodes; children are loaded lazily on expand."""
		self.quickModel.clear()
		root = self.quickModel.invisibleRootItem()
		for kind, label in (("users","Users"),
							("groups","Groups"),
							("ous","OUs"),
							("computers","Computers"),
							("dcs","DCs")):
			cat = _QuickItem(label, kind=kind)
			# Give a dummy child so the arrow appears; we will populate on expand
			cat.appendRow(_QuickItem("Loading…", is_group=True))
			root.appendRow(cat)
		self._quick_built = True

	def _on_quick_ctx(self, pt):
		idx = self.quick.indexAt(pt)
		if not idx.isValid(): return
		it: _QuickItem = self.quickModel.itemFromIndex(idx)
		m = QMenu(self)
		a1 = m.addAction("Copy DN")
		a2 = m.addAction("Copy RDN")
		if not it.dn:
			a1.setEnabled(False); a2.setEnabled(False)
		act = m.exec_(self.quick.viewport().mapToGlobal(pt))
		if not act or not it.dn:
			return
		if act is a1:
			QApplication.clipboard().setText(it.dn)
		elif act is a2:
			QApplication.clipboard().setText(it.dn.split(",",1)[0] if it.dn else "")

	def _on_quick_expanded(self, idx):
		"""Fetch category listing on first expand; subsequent expands are no-ops."""
		it: _QuickItem = self.quickModel.itemFromIndex(idx)
		if not it or it.dn:
			return  # real item (leaf), not a category
		# If first child is the dummy loader, populate now
		if it.hasChildren() and it.child(0).text() == "Loading…":
			# Determine base DN
			base = self._default_naming_context or (self.ed_base.text() or "")
			if not base:
				return
			# ask backend for quick list
			self._send({
				"action":"ldap.quick",
				"kind": it.kind,
				"base": base,
				"size": 1000
			})
			# We will replace children when response arrives

	def _on_quick_activated(self, idx):
		it: _QuickItem = self.quickModel.itemFromIndex(idx)
		if not it or not it.dn:
			return
		self.ed_base.setText(it.dn)
		self._last_rdn = it.dn.split(",",1)[0] if it.dn else ""
		self._update_tab_title()
		self._send({"action":"ldap.read","dn": it.dn, "attrs":["*","+"]})
		self.stack.setCurrentWidget(self.tbl_attrs)

	def _populate_quick_category(self, kind: str, rows: List[Dict[str, any]]):
		"""Group results by immediate parent container (e.g., CN=Users / OU=Sales)."""
		# Find the category item
		root = self.quickModel.invisibleRootItem()
		target: Optional[_QuickItem] = None
		for i in range(root.rowCount()):
			it = root.child(i)
			if isinstance(it, _QuickItem) and it.kind == kind and not it.dn:
				target = it
				break
		if target is None:
			return
		target.removeRows(0, target.rowCount())

		# Build buckets by parent RDN
		buckets: Dict[str, List[Tuple[str,str]]] = {}
		for r in rows:
			dn = r.get("dn","") or ""
			if not dn:
				continue
			parent = ""
			parts = dn.split(",",1)
			if len(parts) == 2:
				parent = parts[1].split(",",1)[0] if parts[1] else ""
			key = parent or "(root)"
			buckets.setdefault(key, []).append((dn, parts[0] if parts else dn))

		# Keep groups sorted, then leaves sorted
		for grp_name in sorted(buckets.keys(), key=lambda s: s.lower()):
			grp = _QuickItem(grp_name or "(root)", is_group=True)
			for dn, rdn in sorted(buckets[grp_name], key=lambda t: t[1].lower()):
				leaf = _QuickItem(rdn, dn=dn, kind=kind)
				grp.appendRow(leaf)
			target.appendRow(grp)

		if not buckets:
			empty = _QuickItem("(empty)")
			empty.setEnabled(False)
			target.appendRow(empty)

		# Expand the category and first group for UX
		idx = self.quickModel.indexFromItem(target)
		self.quick.expand(idx)
		if target.rowCount():
			self.quick.expand(target.child(0).index())

	def _on_ws_disconnected(self):
		# Called by the socket; guard against teardown
		self._set_status("Disconnected")

	def _cleanup(self, *args):
		# Stop timers and silence socket signals when the pane is going away.
		for obj in (getattr(self, "_debounce", None),):
			try: obj.stop()
			except Exception: pass
		try:
			self.ws.blockSignals(True)
			self.ws.close()
			self.ws.deleteLater()
		except Exception:
			pass

	# Compose "vagrant/CN=Users" style tab text
	def _update_tab_title(self):
		self.titleChanged.emit(self._host_short if not self._last_rdn else f"{self._host_short}/{self._last_rdn}")


	def _send(self, obj: Dict[str, any]):
		try: self.ws.sendTextMessage(json.dumps(obj, separators=(",",":")))
		except Exception: pass

	def _auto_open_current(self):
		payload = {"action": "ldap.open.current", "timeout": 12.0}
		if self.sid: payload["sid"] = self.sid
		self._send(payload)

	def _apply_preset(self):
		i = self.cmb_preset.currentIndex()
		if   i == 1: self.ed_filter.setText("(&(objectCategory=person)(objectClass=user))")
		elif i == 2: self.ed_filter.setText("(&(objectCategory=group)(objectClass=group))")
		elif i == 3: self.ed_filter.setText("(objectClass=computer)")
		else:        self.ed_filter.setText("(objectClass=*)")

	# ---------- actions ----------
	def _do_search(self):
		base = (self.ed_base.text() or "").strip()
		filt = (self.ed_filter.text() or "").strip() or "(objectClass=*)"
		if not base: return
		page = int(self.cmb_page.currentText())
		self._send({"action":"ldap.search","base":base,"scope":"sub","filter":filt,
					"attrs":["cn","name","distinguishedName","objectClass"],"size":page})

	# ---------- tree / selection ----------
	def _on_expanded(self, idx: QModelIndex):
		node: _Node = idx.internalPointer()
		if not node or node.loaded or not node.has_children:
			return
		self._send({"action":"ldap.children","dn": node.dn, "size": 500, "attrs":["cn","name","objectClass"]})

	def _on_selected(self, idx: QModelIndex):
		node: _Node = idx.internalPointer()
		if not node: return
		# remember last RDN for tab text like vagrant/CN=Users
		self._last_rdn = node.rdn or (node.dn.split(",",1)[0] if node.dn else "")
		self.ed_base.setText(node.dn or self.ed_base.text())
		self._send({"action":"ldap.read","dn": node.dn, "attrs":["*","+"]})

	def _open_result_dn(self, row: int, col: int):
		dn_item = self.tbl_results.item(row, 1)
		if not dn_item: return
		dn = dn_item.text()
		self.ed_base.setText(dn)
		# update last RDN from results
		self._last_rdn = dn.split(",",1)[0] if dn else ""
		self._update_tab_title()
		self._send({"action":"ldap.read","dn": dn, "attrs":["*","+"]})
		self.stack.setCurrentWidget(self.tbl_attrs)  # swap to inspector after opening

	# ---------- inbound frames ----------
	def _on_msg(self, txt: str):
		try: msg = json.loads(txt)
		except Exception: return
		t = msg.get("type")

		# Context menus (copy DN / row)
		def _install_context_copy():
			self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
			def _on_ctx(pt):
				idx = self.tree.indexAt(pt)
				if not idx.isValid(): return
				node: _Node = idx.internalPointer()
				m = QMenu(self)
				a1 = m.addAction("Copy DN"); a2 = m.addAction("Copy RDN")
				act = m.exec_(self.tree.viewport().mapToGlobal(pt))
				if not act: return
				QApplication.clipboard().setText(node.dn if act is a1 else node.rdn)
			try: self.tree.customContextMenuRequested.disconnect()
			except Exception: pass
			self.tree.customContextMenuRequested.connect(_on_ctx)

			self.tbl_attrs.setContextMenuPolicy(Qt.CustomContextMenu)
			def _on_tbl(pt):
				r = self.tbl_attrs.indexAt(pt).row()
				if r < 0: return
				k = self.tbl_attrs.item(r,0).text() if self.tbl_attrs.item(r,0) else ""
				v = self.tbl_attrs.item(r,1).text() if self.tbl_attrs.item(r,1) else ""
				m = QMenu(self)
				a1 = m.addAction("Copy Value"); a2 = m.addAction("Copy Attribute"); a3 = m.addAction("Copy Row")
				act = m.exec_(self.tbl_attrs.viewport().mapToGlobal(pt))
				if not act: return
				if act is a1: QApplication.clipboard().setText(v)
				elif act is a2: QApplication.clipboard().setText(k)
				elif act is a3: QApplication.clipboard().setText(f"{k}: {v}")
			try: self.tbl_attrs.customContextMenuRequested.disconnect()
			except Exception: pass
			self.tbl_attrs.customContextMenuRequested.connect(_on_tbl)

		if t == "ldap.opened":
			if not msg.get("ok"):
				self._set_status(f'Bind failed: {msg.get("error","")}'); return
			info = msg.get("info") or {}
			host = info.get("host") or ""

			self._set_status(f"Connected — {host}" if host else "Connected")
			# derive a short DC hostname (before first dot)
			if host:
				self._host_short = host.split(".",1)[0]
				self._update_tab_title()

			ncs = info.get("namingContexts") or []
			dnc = info.get("defaultNamingContext") or ""
			self._default_naming_context = dnc
			if not ncs and dnc:
				ncs = [dnc]
			self.model.set_roots(ncs)
			if ncs: self.ed_base.setText(ncs[0])
			# Rebuild quick on new bind/context
			self._init_quick_model()

		elif t == "ldap.children":
			if not msg.get("ok"): return
			dn   = msg.get("dn") or ""; rows = msg.get("children") or []

			def _find_index_for_dn(target_dn: str) -> QModelIndex:
				q = [QModelIndex()]
				while q:
					parent = q.pop(0)
					for i in range(self.model.rowCount(parent)):
						ix = self.model.index(i, 0, parent)
						node: _Node = ix.internalPointer()
						if node and node.dn == target_dn:
							return ix
						q.append(ix)
				return QModelIndex()

			parent_ix = _find_index_for_dn(dn)
			if not parent_ix.isValid(): return
			self.model.insert_children(parent_ix, rows)
			# Don't auto-expand/select; keeps the UI calm.

			# keep the tab title in sync if user expanded into a new container next
			self._update_tab_title()

		elif t == "ldap.quick":
			if not msg.get("ok"):
				return
			kind = msg.get("kind","")
			rows = msg.get("rows") or []
			# rows are list of {dn, attrs?}; we only need dn/rdn
			shaped = []
			for r in rows:
				shaped.append({"dn": r.get("dn","") or ""})
			self._populate_quick_category(kind, shaped)

		elif t == "ldap.read":
			if not msg.get("ok"): return
			attrs = msg.get("attrs") or {}
			self.stack.setCurrentWidget(self.tbl_attrs)
			self.tbl_attrs.setRowCount(0)
			mono = QFont("Monospace"); mono.setStyleHint(QFont.TypeWriter)
			for k, v in sorted(attrs.items(), key=lambda kv: kv[0].lower()):
				row = self.tbl_attrs.rowCount(); self.tbl_attrs.insertRow(row)
				key_item = QTableWidgetItem(k)
				if isinstance(v, list):
					val_text = ", ".join(str(x) for x in v[:50]) + (" …" if len(v) > 50 else "")
				else:
					val_text = str(v)
				val_item = QTableWidgetItem(val_text); val_item.setFont(mono)
				self.tbl_attrs.setItem(row, 0, key_item)
				self.tbl_attrs.setItem(row, 1, val_item)
			_install_context_copy()
			# after a read, we likely clicked something; make sure title reflects last RDN
			self._update_tab_title()

		elif t == "ldap.search.page":
			base = msg.get("base",""); rows = msg.get("rows") or []
			# Swap to results view; show nothing if no rows (clean UX)
			self.tbl_results.setRowCount(0)
			if rows:
				for r in rows:
					dn = r.get("dn","") or ""
					rdn = dn.split(",",1)[0] if dn else ""
					oc  = r.get("attrs",{}).get("objectClass",[])
					if isinstance(oc, list): oc = ", ".join(str(x) for x in oc)
					row = self.tbl_results.rowCount(); self.tbl_results.insertRow(row)
					self.tbl_results.setItem(row, 0, QTableWidgetItem(rdn))
					self.tbl_results.setItem(row, 1, QTableWidgetItem(dn))
					self.tbl_results.setItem(row, 2, QTableWidgetItem(oc))
			self.stack.setCurrentWidget(self.tbl_results)


# --- Tabbed LDAP Browser (file-browser style tabs) ---------------------------
class LdapBrowser(QWidget):
	"""
	Shell providing a QTabBar (like your file browser). Each tab hosts one _LdapPane.
	"""
	def __init__(self, api, sid: str = "", hostname: str = "", parent=None):
		super().__init__(parent)
		_apply_styles(self)
		self.api = api; self.sid = sid; self.hostname = hostname

		# --- Workspace splitter/tabbar lock state (match FileBrowser behavior) ---
		self._ldap_mode_active = False
		self._host_splitter: QSplitter | None = None
		self._old_split_sizes: list[int] | None = None
		self._old_splitter_css: str | None = None
		self._old_handle_w: int | None = None

		self._locked_splitter: QSplitter | None = None
		self._locked_splitter_old_css: str | None = None
		self._locked_handle_blockers: list[tuple[QWidget, QObject]] = []

		self._locked_tabbar: QTabBar | None = None
		self._orig_movable: bool | None = None

		# Defer attaching to the host QTabWidget until we're parented
		QTimer.singleShot(0, self._attach_host_tab_signals)

		root = QVBoxLayout(self); root.setContentsMargins(10,10,10,10)

		# Tab bar + plus button
		tabs_row = QHBoxLayout(); tabs_row.setContentsMargins(0,0,0,0); tabs_row.setSpacing(8)
		self.tabbar = QTabBar(movable=True)
		self.tabbar.setDrawBase(False)
		#self.tabbar.tabCloseRequested.connect(self._close_tab)
		self.tabbar.currentChanged.connect(self._tab_changed)

		# Context menu hookup ONCE (avoid sticky menus / crashes)
		self._ctx_menu_connected = False
		self._connect_tab_context_menu()

		# nicer tab text eliding when there are many tabs
		self.tabbar.setElideMode(Qt.ElideRight)
		# watch for scroller buttons being (un)created so we can skin them
		self.tabbar.installEventFilter(self)
		self.btn_new = QToolButton(); self.btn_new.setText("+"); self.btn_new.setToolTip("New LDAP tab")
		self.btn_new.clicked.connect(self._new_tab)
		tabs_row.addWidget(self.tabbar, 1); tabs_row.addWidget(self.btn_new, 0)
		root.addLayout(tabs_row)

		# Stack of panes
		self.stack = QStackedWidget()
		root.addWidget(self.stack, 1)

		# First tab
		self._new_tab()

	# ---------- Workspace header collapse/restore (like FileBrowser) ----------
	def _find_host_splitter(self) -> QSplitter | None:
		"""
		Walk up to find the nearest *vertical* QSplitter that hosts this page area
		(the one with the three-dot handle between header and content).
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
			# Save original state once
			self._host_splitter = sp
			if self._old_split_sizes is None:
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

			# Collapse header/top pane so LDAP sits flush at the top
			sizes = sp.sizes()
			total = max(1, sum(sizes) or 1)
			sp.setSizes([0, total])
			try:
				sp.setHandleWidth(0)
			except Exception:
				pass
			# Hide the “three dots” while active
			try:
				sp.setStyleSheet((self._old_splitter_css or "") + " QSplitter::handle { image: none; background: transparent; height: 0px; }")
			except Exception:
				pass
		else:
			# Restore original splitter visuals/sizes
			try:
				if self._old_split_sizes:
					sp.setSizes(self._old_split_sizes)
				if self._old_handle_w is not None:
					sp.setHandleWidth(self._old_handle_w)
				if self._old_splitter_css is not None:
					sp.setStyleSheet(self._old_splitter_css)
			except Exception:
				pass

	# ---------- Lock/unlock the OUTER splitter so it can't be dragged ----------
	class _HandleEater(QObject):
		def eventFilter(self, obj, ev):
			if ev.type() in (QEvent.MouseButtonPress, QEvent.MouseButtonRelease,
							 QEvent.MouseMove, QEvent.HoverMove, QEvent.HoverEnter):
				return True
			return False

	def _find_host_splitter_and_child(self):
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
		self._locked_handle_blockers = []
		for i in range(1, split.count()):
			h = split.handle(i)
			if h:
				blocker = LdapBrowser._HandleEater(h)
				h.installEventFilter(blocker)
				try:
					h.setCursor(Qt.ArrowCursor)
				except Exception:
					pass
				self._locked_handle_blockers.append((h, blocker))
		# Hide the grip dots on THIS splitter only
		self._locked_splitter_old_css = split.styleSheet()
		split.setStyleSheet("QSplitter::handle { image: none; background: transparent; }")

		# Give our pane almost everything to sit tight under the header
		try:
			idx = split.indexOf(direct_child)
			if idx != -1:
				sz = split.sizes()
				total = max(1, sum(sz) or 1)
				new = [1] * len(sz)
				new[idx] = max(total - (len(sz) - 1), 1)
				split.setSizes(new)
		except Exception:
			pass
		self._locked_splitter = split

	def _unlock_parent_splitter(self):
		split = self._locked_splitter
		if not split:
			return
		for h, blocker in self._locked_handle_blockers:
			try:
				h.removeEventFilter(blocker)
			except Exception:
				pass
		self._locked_handle_blockers = []
		try:
			split.setStyleSheet(self._locked_splitter_old_css or "")
		except Exception:
			pass
		self._locked_splitter = None
		self._locked_splitter_old_css = None

	# ---------- Lock/unlock host tab bar movability ----------
	def _lock_parent_tabbar(self):
		host = self._host_tabwidget()
		if not host:
			return
		tb = host.tabBar()
		if isinstance(tb, QTabBar):
			self._locked_tabbar = tb
			self._orig_movable = tb.isMovable()
			tb.setMovable(False)
			tb.setDocumentMode(True)
			tb.setFocusPolicy(Qt.NoFocus)

	def _unlock_parent_tabbar(self):
		tb = getattr(self, "_locked_tabbar", None)
		if isinstance(tb, QTabBar) and self._orig_movable is not None:
			try:
				tb.setMovable(bool(self._orig_movable))
			except Exception:
				pass
		self._locked_tabbar = None
		self._orig_movable = None

	# ---------- Host QTabWidget coordination ----------
	def _host_tabwidget(self) -> QTabWidget | None:
		w = self.parent()
		while w is not None and not isinstance(w, QTabWidget):
			w = w.parent()
		return w if isinstance(w, QTabWidget) else None

	def _attach_host_tab_signals(self):
		host = self._host_tabwidget()
		if host:
			host.currentChanged.connect(self._on_host_tab_changed)

	def _is_heavy_widget(self, w: QWidget | None) -> bool:
		"""Treat PayloadsTab/FileBrowser/LdapBrowser as 'heavy' (avoid import cycles)."""
		if w is None:
			return False
		try:
			from payloads_tab import PayloadsTab  # type: ignore
			from file_browser import FileBrowser  # type: ignore
			return isinstance(w, (PayloadsTab, FileBrowser, LdapBrowser))
		except Exception:
			clsname = getattr(w.__class__, "__name__", "")
			return clsname in ("PayloadsTab", "FileBrowser", "LdapBrowser")

	def _on_host_tab_changed(self, idx: int):
		host = self._host_tabwidget()
		if not host:
			return
		new_w = host.widget(idx)
		# If we left a heavy context entirely, release locks and restore header.
		if not self._is_heavy_widget(new_w) and getattr(self, "_ldap_mode_active", False):
			self._exit_ldap_mode()

	def _enter_ldap_mode(self):
		if getattr(self, "_ldap_mode_active", False):
			return
		self._ldap_mode_active = True
		self._collapse_workspace_header(True)
		self._lock_parent_tabbar()
		self._lock_parent_splitter()

	def _exit_ldap_mode(self):
		if not getattr(self, "_ldap_mode_active", False):
			return
		self._ldap_mode_active = False
		self._unlock_parent_splitter()
		self._unlock_parent_tabbar()
		self._collapse_workspace_header(False)

	# ---------- Lifecycle ----------
	def showEvent(self, ev):
		self._enter_ldap_mode()
		return super().showEvent(ev)

	def hideEvent(self, ev):
		# Centralized release happens via _on_host_tab_changed when switching tabs.
		return super().hideEvent(ev)

	def closeEvent(self, ev):
		self._exit_ldap_mode()
		return super().closeEvent(ev)

	# --- tab mgmt
	def _new_tab(self):
		pane = _LdapPane(self.api, self.sid, self.hostname, self)
		idx  = self.stack.addWidget(pane)
		tab  = self.tabbar.addTab("LDAP")
		self.tabbar.setCurrentIndex(tab)
		self._skin_tab_scrollers()  # ensure pretty arrows after adding
		self.stack.setCurrentIndex(idx)
		# update tab title when pane learns host
		pane.titleChanged.connect(lambda s, i=tab: self.tabbar.setTabText(i, s))
		# attach our custom close button
		self._attach_close_button(tab)

	# --- utility: create a crisp red "X" icon ------------------------------
	def _make_close_icon(self, size: int = 18, base_hex: str = "#ff4d4f") -> QIcon:
		# Prefer vector icon from QtAwesome if available
		if qta:
			# FA5 solid "times" (a.k.a. ×). You can also try: 'fa5s.times-circle'
			return qta.icon(
				'fa5s.times',
				color=base_hex,                  # normal
				color_active='#ff6666',         # hover/active
				color_selected='#e44545',       # pressed/selected
				color_disabled='#6b7280'        # disabled
			)
		# Fallback to your hand-drawn pixmaps if qtawesome is missing
		return self._make_close_icon_fallback(size, base_hex)

	def _make_close_icon_fallback(self, size: int = 18, base_hex: str = "#ff3b30") -> QIcon:
		def mk_pix(color_hex: str, shadow_alpha: int = 70, inflate: float = 0.0) -> QPixmap:
			pm = QPixmap(size, size)
			pm.fill(Qt.transparent)
			p = QPainter(pm)
			p.setRenderHint(QPainter.Antialiasing, True)

			# Optional micro “press” effect by inflating line width
			line_w = max(2.0, size * (0.16 + inflate))

			# Shadow layer (slight offset for depth on dark tabs)
			if shadow_alpha > 0:
				shadow = QPen(QColor(0, 0, 0, shadow_alpha))
				shadow.setWidthF(line_w)
				shadow.setCapStyle(Qt.RoundCap)
				p.setPen(shadow)
				m = float(size) * 0.26
				offset = QPointF(0.6, 0.6)
				p.drawLine(QPointF(m, m) + offset, QPointF(size - m, size - m) + offset)
				p.drawLine(QPointF(m, size - m) + offset, QPointF(size - m, m) + offset)

			# Foreground “X”
			pen = QPen(QColor(color_hex))
			pen.setWidthF(line_w)
			pen.setCapStyle(Qt.RoundCap)
			p.setPen(pen)
			m = float(size) * 0.26
			p.drawLine(QPointF(m, m), QPointF(size - m, size - m))
			p.drawLine(QPointF(m, size - m), QPointF(size - m, m))
			p.end()
			return pm

		icon = QIcon()
		# Normal
		icon.addPixmap(mk_pix("#ff4d4f", 60), QIcon.Normal, QIcon.Off)
		# Hover (brighter)
		icon.addPixmap(mk_pix("#ff6466", 80), QIcon.Active, QIcon.Off)
		# Pressed (slightly thicker & darker)
		icon.addPixmap(mk_pix("#e44545", 80, inflate=0.02), QIcon.Selected, QIcon.Off)
		# Disabled (muted)
		icon.addPixmap(mk_pix("#6b7280", 0), QIcon.Disabled, QIcon.Off)
		return icon

	def _tab_menu(self, pos):
		i = self.tabbar.tabAt(pos)
		if i < 0: return
		m = QMenu(self)  # modal, will close on click-off
		m.setAttribute(Qt.WA_DeleteOnClose, True)

		a_dup = m.addAction("Duplicate tab")
		# Close submenu
		sm = m.addMenu("Close")
		a_right = sm.addAction("Close all tabs to the right")
		a_left  = sm.addAction("Close all tabs to the left")
		a_others= sm.addAction("Close all other tabs")
		a_this  = sm.addAction("Close this tab")

		act = m.exec_(self.tabbar.mapToGlobal(pos))
		if act is None: return
		if act is a_dup:
			self._new_tab(); return
		if act is a_right:
			# close indices > i
			for idx in range(self.tabbar.count()-1, i, -1):
				self._close_tab(idx)
			return
		if act is a_left:
			# close indices < i
			for idx in range(i-1, -1, -1):
				self._close_tab(idx)
			return
		if act is a_others:
			# close everything except i
			for idx in range(self.tabbar.count()-1, -1, -1):
				if idx != i:
					self._close_tab(idx)
			return
		if act is a_this:
			self._close_tab(i)
			return

	def _close_tab(self, i: int):
		if self.tabbar.count() == 1:
			# keep at least one tab
			return
		w = self.stack.widget(i)
		self.stack.removeWidget(w)
		w.deleteLater()
		self.tabbar.removeTab(i)
		# ensure there is always a visible widget selected
		if self.tabbar.count():
			self.stack.setCurrentIndex(self.tabbar.currentIndex())

	def _tab_changed(self, i: int):
		self.stack.setCurrentIndex(i)

	# Ensure we only connect the context menu once (prevents sticky/crash)
	def _connect_tab_context_menu(self):
		if self._ctx_menu_connected:
			return
		self.tabbar.setContextMenuPolicy(Qt.CustomContextMenu)
		try:
			self.tabbar.customContextMenuRequested.disconnect(self._tab_menu)
		except Exception:
			pass
		self.tabbar.customContextMenuRequested.connect(self._tab_menu)
		self._ctx_menu_connected = True

	# --- custom close button per tab (×) ----------------------------------
	def _attach_close_button(self, index: int):
		"""
		Add a compact '×' button on the right side of a tab.
		Styled via #TabCloseBtn in the global stylesheet.
		"""
		btn = QToolButton(self.tabbar)
		btn.setObjectName("TabCloseBtn")
		icon_px = 18
		btn.setIcon(self._make_close_icon(icon_px, "#ff3b30"))
		btn.setIconSize(QSize(icon_px, icon_px))
		btn.setToolButtonStyle(Qt.ToolButtonIconOnly)
		btn.setFocusPolicy(Qt.NoFocus)
		btn.setCursor(Qt.PointingHandCursor)
		btn.setToolTip("Close tab")
		btn.setAutoRaise(True)
		btn.clicked.connect(self._close_from_button)
		self.tabbar.setTabButton(index, QTabBar.RightSide, btn)

	def _close_from_button(self):
		btn = self.sender()
		# find which tab hosts this button and close it
		for i in range(self.tabbar.count()):
			if self.tabbar.tabButton(i, QTabBar.RightSide) is btn:
				self._close_tab(i)
				break

	# --- style the tiny scroll buttons into gorgeous arrows ----------------
	def eventFilter(self, obj, ev):
		if obj is self.tabbar and ev.type() in (QEvent.Show, QEvent.Resize, QEvent.LayoutRequest, QEvent.ChildAdded):
			QTimer.singleShot(0, self._skin_tab_scrollers)
		return super().eventFilter(obj, ev)

	def _skin_tab_scrollers(self):
		# QTabBar creates two QToolButtons for scrolling when tabs overflow.
		# Give them unicode arrow glyphs + nicer styling.
		for btn in self.tabbar.findChildren(QToolButton):
			# Heuristic: scroll buttons have no text and have an arrowType set
			try:
				at = btn.arrowType()
			except Exception:
				at = Qt.NoArrow
			if at in (Qt.LeftArrow, Qt.RightArrow) or ("scroll" in btn.objectName().lower() if btn.objectName() else False):
				# Make sure we only style scrollers, not our custom close buttons.
				# Close buttons have objectName "TabCloseBtn".
				if btn.objectName() == "TabCloseBtn":
					continue
				btn.setArrowType(Qt.NoArrow)
				btn.setToolButtonStyle(Qt.ToolButtonTextOnly)
				# If at is NoArrow (first pass), infer from position by alternating
				if not btn.text():
					btn.setText("❮" if at == Qt.LeftArrow else "❯")
				btn.setMinimumSize(30, 24)
				btn.setMaximumHeight(24)
				btn.setCursor(Qt.PointingHandCursor)
				btn.setStyleSheet("""
					QToolButton {
						margin-left: 6px; margin-right: 6px;
						padding: 0 10px;
						border: 1px solid #395074;
						border-radius: 12px;
						color: #e4ecf7;
						font-weight: 700;
						background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
								   stop:0 #152132, stop:1 #0f1826);
					}
					QToolButton:hover {
						border: 1px solid #5f8ed6;
						background: #182338;
					}
				""")
