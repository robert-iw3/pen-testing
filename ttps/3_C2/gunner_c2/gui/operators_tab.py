# gui/operators_tab.py
from PyQt5.QtWidgets import (
	QWidget, QTableView, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QVBoxLayout,
	QHeaderView, QAbstractItemView, QMenu, QInputDialog, QMessageBox, QStyledItemDelegate,
	QApplication, QToolButton, QButtonGroup, QFrame, QLabel, QDialog, QDialogButtonBox,
	QGraphicsDropShadowEffect
)

from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QVariant, QSortFilterProxyModel,
    QRect, QObject, QEasingCurve, QPropertyAnimation, pyqtProperty, QEvent,
    QSize, QPoint,
)

from PyQt5.QtGui import QPalette, QColor, QFont, QPainter, QBrush, QPen, QIcon

try:
	from .websocket_client import OperatorsWSClient
except Exception:
	from websocket_client import OperatorsWSClient

from theme_center import theme_color

# ---------- helpers ----------------------------------------------------------

def _qcolor(v, default="#ffffff"):
	"""theme_color() may return QColor or hex/string; normalize to QColor."""
	try:
		if isinstance(v, QColor):
			return v
		if isinstance(v, str) and v:
			return QColor(v)
	except Exception:
		pass
	return QColor(default)

def _ago(ts: str) -> str:
	import datetime
	if not ts:
		return "—"
	try:
		dt = datetime.datetime.fromisoformat(ts.replace("Z","+00:00"))
		if dt.tzinfo:
			dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
		diff = (datetime.datetime.utcnow() - dt).total_seconds()
		if diff < 60:   return "just now"
		if diff < 3600: return f"{int(diff//60)}m"
		if diff < 86400:return f"{int(diff//3600)}h"
		return f"{int(diff//86400)}d"
	except Exception:
		return ts

COLUMNS = [("Username","username"), ("Role","role"), ("ID","id"), ("Created","created_at")]

# ---------- Delegates --------------------------------------------------------

class IDElideDelegate(QStyledItemDelegate):
	"""Monospaced, center-elided UUID with soft ink."""
	def __init__(self, max_px=420, parent=None):
		super().__init__(parent)
		self.max_px = max_px
		self.mono = QFont("Consolas")

	def paint(self, p: QPainter, opt, idx):
		text = idx.data(Qt.DisplayRole) or ""
		p.save()
		p.setRenderHint(QPainter.TextAntialiasing, True)
		p.setFont(self.mono)
		r = opt.rect.adjusted(8, 0, -8, 0)
		fm = p.fontMetrics()
		elided = fm.elidedText(text, Qt.ElideMiddle, self.max_px if self.max_px > 0 else r.width())
		# softer ink for IDs
		ink = opt.palette.color(QPalette.Text)
		ink.setAlpha(210)
		p.setPen(QPen(ink))
		p.drawText(r, Qt.AlignVCenter | Qt.AlignLeft, elided)
		p.restore()

class RoleChip(QStyledItemDelegate):
	"""Theme-aware pill for role."""
	def paint(self, p, opt, idx):
		text = (idx.data(Qt.DisplayRole) or "").lower()
		bg = _qcolor(theme_color("chip_operator_bg") if text == "operator" else theme_color("chip_admin_bg"),
					 "#34425a" if text=="operator" else "#5a3434")
		fg = _qcolor(theme_color("chip_operator_fg") if text == "operator" else theme_color("chip_admin_fg"),
					 "#dbe7ff" if text=="operator" else "#ffd6d6")

		p.save(); p.setRenderHint(QPainter.Antialiasing, True)
		r = opt.rect.adjusted(6, 6, -6, -6)
		p.setPen(Qt.NoPen)
		p.setBrush(QBrush(bg))
		p.drawRoundedRect(r, 9, 9)
		p.setPen(QPen(fg))
		p.drawText(r, Qt.AlignCenter, text or "—")
		p.restore()

class AvatarNameDelegate(QStyledItemDelegate):
	"""Draw a circular avatar with the first letter + username text."""
	def __init__(self, parent=None):
		super().__init__(parent)
		self.name_font = QFont()
		self.name_font.setBold(True)

	def _avatar_color(self, seed: str) -> QColor:
		# Stable small palette, tinted to theme
		palette = [
			"#5cc8ff", "#8f95ff", "#7be1d4", "#f3a86b", "#f57aa2", "#7bd17b", "#b48ef5"
		]
		h = sum(ord(c) for c in seed) if seed else 0
		base = QColor(palette[h % len(palette)])
		# dim a touch to fit GunnerC2
		base.setAlpha(220)
		return base

	def paint(self, p: QPainter, opt, idx):
		uname = idx.data(Qt.DisplayRole) or ""
		first = (uname[:1] or "•").upper()

		p.save()
		p.setRenderHint(QPainter.Antialiasing, True)

		rect = opt.rect
		# avatar
		size = min(rect.height()-8, 22)
		av_rect = QRect(rect.left()+8, rect.center().y() - size//2, size, size)
		p.setPen(Qt.NoPen)
		p.setBrush(QBrush(self._avatar_color(uname)))
		p.drawEllipse(av_rect)

		# avatar letter
		f = QFont("Inter" if QFont("Inter").exactMatch() else p.font().family())
		f.setBold(True); f.setPointSizeF(max(9.0, p.font().pointSizeF()*0.95))
		p.setFont(f)
		p.setPen(QPen(QColor("#0b111a")))
		p.drawText(av_rect, Qt.AlignCenter, first)

		# name text
		name_rect = QRect(av_rect.right()+8, rect.top(), rect.width()-av_rect.width()-20, rect.height())
		p.setPen(QPen(opt.palette.color(QPalette.Text)))
		p.drawText(name_rect, Qt.AlignVCenter | Qt.AlignLeft, uname)
		p.restore()

# ---------- Model / Filter ---------------------------------------------------

class OpsModel(QAbstractTableModel):
	def __init__(self): 
		super().__init__(); self._rows=[]

	def rowCount(self,_=QModelIndex()): 
		return len(self._rows)

	def columnCount(self,_=QModelIndex()): 
		return len(COLUMNS)

	def headerData(self, s, o, r=Qt.DisplayRole):
		if r==Qt.DisplayRole and o==Qt.Horizontal: return COLUMNS[s][0]
		return QVariant()

	def data(self, idx, role=Qt.DisplayRole):
		if not idx.isValid(): 
			return QVariant()

		r = self._rows[idx.row()]
		key = COLUMNS[idx.column()][1]

		if role == Qt.DisplayRole:
			if key == "created_at": return _ago(r.get(key,""))
			return str(r.get(key,""))

		if role == Qt.ToolTipRole:
			if key == "id":         return str(r.get("id", ""))
			if key == "created_at": return str(r.get("created_at", ""))

		if role == Qt.TextAlignmentRole:
			if key in ("role", "id", "created_at"): return Qt.AlignCenter
			return Qt.AlignVCenter | Qt.AlignLeft

		if role == Qt.FontRole and key == "id":
			f = QFont("Consolas"); f.setPointSizeF(f.pointSizeF()*0.95); return f
		return QVariant()

	def set_ops(self, rows): 
		self.layoutAboutToBeChanged.emit()
		self._rows=list(rows or [])
		self.layoutChanged.emit()

	def row_dict(self, proxy_row, proxy): 
		if proxy_row<0: return None
		src = proxy.mapToSource(proxy.index(proxy_row,0)).row()
		return self._rows[src] if 0<=src<len(self._rows) else None

class RoleFilter(QSortFilterProxyModel):
	def __init__(self): super().__init__(); self._needle=""; self._role="all"
	def setText(self, t): self._needle=(t or "").lower(); self.invalidateFilter()
	def setRole(self, role): self._role=role; self.invalidateFilter()
	def filterAcceptsRow(self, r, parent):
		m = self.sourceModel()
		uname = (m.index(r,0,parent).data() or "").lower()
		role  = (m.index(r,1,parent).data() or "").lower()
		ident = (m.index(r,2,parent).data() or "").lower()
		blob = " ".join([uname, role, ident])
		if self._needle and self._needle not in blob: return False
		if self._role in ("operator","admin") and role != self._role: return False
		return True

# ---------- Add Operator dialog ---------------------------------------------

class AddOperatorDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.setWindowTitle("Add Operator")
		self.setModal(True)
		self.setObjectName("AddDialog")

		self.uEdit = QLineEdit(); self.uEdit.setPlaceholderText("Username")
		self.pEdit = QLineEdit(); self.pEdit.setPlaceholderText("Password"); self.pEdit.setEchoMode(QLineEdit.Password)
		self.roleNew = QComboBox(); self.roleNew.addItems(["operator","admin"])

		form = QVBoxLayout()
		form.addWidget(self.uEdit)
		form.addWidget(self.pEdit)
		form.addWidget(self.roleNew)

		btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		btns.accepted.connect(self.accept)
		btns.rejected.connect(self.reject)

		root = QVBoxLayout(self)
		root.addLayout(form)
		root.addWidget(btns)

class _RemoveHoverFX(QObject):
    """Animates a 'destructive' button on hover: color + soft glow."""
    def __init__(self, btn: QPushButton, base="#8b1e2d", hover="#d32f2f", parent=None):
        super().__init__(parent or btn)
        self.btn = btn
        self.c0 = QColor(base)
        self.c1 = QColor(hover)
        self._t = 0.0

        # nice shadow glow
        self.shadow = QGraphicsDropShadowEffect(btn)
        self.shadow.setOffset(0, 0)
        self.shadow.setBlurRadius(0)
        self.shadow.setColor(QColor(211, 47, 47, 0))  # red with 0 alpha initially
        btn.setGraphicsEffect(self.shadow)

        # animation driver
        self.anim = QPropertyAnimation(self, b"t")
        self.anim.setDuration(180)  # ms
        self.anim.setEasingCurve(QEasingCurve.OutCubic)

        # react to enter/leave
        btn.installEventFilter(self)

        # initial paint
        self._apply()

    def eventFilter(self, obj, ev):
        if obj is self.btn:
            if ev.type() == QEvent.Enter:
                self._go(1.0)
            elif ev.type() == QEvent.Leave:
                self._go(0.0)
        return False

    def _go(self, end):
        self.anim.stop()
        self.anim.setStartValue(self._t)
        self.anim.setEndValue(end)
        self.anim.start()

    def getT(self): return self._t
    def setT(self, v: float):
        self._t = max(0.0, min(1.0, float(v)))
        self._apply()

    t = pyqtProperty(float, fget=getT, fset=setT)

    def _apply(self):
        # lerp color
        t = self._t
        r = int(self.c0.red()   + (self.c1.red()   - self.c0.red())   * t)
        g = int(self.c0.green() + (self.c1.green() - self.c0.green()) * t)
        b = int(self.c0.blue()  + (self.c1.blue()  - self.c0.blue())  * t)
        col = QColor(r, g, b)

        # style (scoped to buttons with destructive=True)
        self.btn.setStyleSheet(f"""
            QPushButton[destructive="true"] {{
                background: {col.name()};
                color: #ffffff;
                border: 1px solid #74202a;
                border-radius: 10px;
                padding: 6px 12px;
            }}
            QPushButton[destructive="true"]:pressed {{
                background: {col.darker(115).name()};
            }}
            QPushButton[destructive="true"]:disabled {{
                background: #4c1c1c; color:#aaaaaa; border-color:#3a1515;
            }}
        """)

        # soft glow ramps in
        self.shadow.setBlurRadius(int(12 * t))
        self.shadow.setColor(QColor(211, 47, 47, int(200 * t)))

# ---------- Main Tab ---------------------------------------------------------

class OperatorsTab(QWidget):
	def __init__(self, api):
		super().__init__()
		self.setObjectName("OperatorsTab")

		# ===== Header card =====
		header = QFrame(self); header.setObjectName("OpsHeader")
		h1 = QHBoxLayout(header); h1.setContentsMargins(14,12,14,12); h1.setSpacing(10)

		self.lblTitle = QLabel("Operators")
		self.lblTitle.setObjectName("OpsTitle")

		self.lblCount = QLabel("—")
		self.lblCount.setObjectName("OpsCount")

		h1.addWidget(self.lblTitle, 0, Qt.AlignVCenter)
		h1.addStretch(1)
		h1.addWidget(self.lblCount, 0, Qt.AlignVCenter)

		# Primary actions
		self.btnAdd = QToolButton(); self.btnAdd.setText("Add Operator"); self.btnAdd.setObjectName("Primary")
		self.btnAdd.setCursor(Qt.PointingHandCursor)
		self.btnRemove = QToolButton(); self.btnRemove.setText("Remove"); self.btnRemove.setEnabled(False); self.btnRemove.setProperty("preserveSelection", True)
		self.btnRemove.setProperty("destructive", True)
		self.btnRemove.setCursor(Qt.PointingHandCursor)

		# attach hover animation
		self._remove_fx = _RemoveHoverFX(self.btnRemove)

		self.btnRemove.setObjectName("Danger")
		h1.addSpacing(8)
		h1.addWidget(self.btnAdd, 0)
		h1.addWidget(self.btnRemove, 0)

		# ===== Utility bar (search + role chips) =====
		util = QFrame(self); util.setObjectName("OpsUtil")
		u = QHBoxLayout(util); u.setContentsMargins(12,10,12,10); u.setSpacing(10)

		self.search = QLineEdit(); self.search.setPlaceholderText("Search username, role, or ID…")
		self.search.setClearButtonEnabled(True)
		self.search.setObjectName("SearchField")
		u.addWidget(self.search, 1)

		# segmented filter (All / Operator / Admin)
		self._seg = QButtonGroup(self)
		self.btnAll = QToolButton(); self.btnAll.setText("all"); self.btnAll.setCheckable(True); self.btnAll.setChecked(True)
		self.btnAll.setProperty("seg", True)

		self.btnOp  = QToolButton(); self.btnOp.setText("operator"); self.btnOp.setCheckable(True); self.btnOp.setProperty("seg", True)
		self.btnAd  = QToolButton(); self.btnAd.setText("admin");    self.btnAd.setCheckable(True); self.btnAd.setProperty("seg", True)
		for b in (self.btnAll, self.btnOp, self.btnAd):
			self._seg.addButton(b)
			u.addWidget(b, 0)

		# ===== Table =====
		self.model = OpsModel()
		self.proxy = RoleFilter(); self.proxy.setSourceModel(self.model)

		self.table = QTableView(self); self.table.setObjectName("OpsTable")
		self.table.setModel(self.proxy)
		self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
		self.table.setSelectionMode(QAbstractItemView.SingleSelection)
		self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
		self.table.setSortingEnabled(True)
		self.table.setShowGrid(False)
		self.table.setAlternatingRowColors(False)
		self.table.setWordWrap(False)
		self.table.setTextElideMode(Qt.ElideRight)
		self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
		self.table.verticalHeader().setVisible(False)
		self.table.verticalHeader().setDefaultSectionSize(32)
		self.table.viewport().installEventFilter(self)

		# Also clear when clicking anywhere else in this tab (e.g., the header/title bar)
		QApplication.instance().installEventFilter(self)
		self.destroyed.connect(lambda: QApplication.instance().removeEventFilter(self))

		hdr = self.table.horizontalHeader()
		hdr.setStretchLastSection(False)
		hdr.setSectionResizeMode(QHeaderView.Interactive)
		hdr.setMinimumSectionSize(90)

		hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Username
		hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Role
		hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Created
		hdr.setSectionResizeMode(2, QHeaderView.Stretch)           # ID stretches

		# palette (base matches your file browser theme)
		pal = self.table.palette()
		pal.setColor(QPalette.Base, QColor("#0b111a"))
		pal.setColor(QPalette.AlternateBase, QColor("#0b111a"))
		pal.setColor(QPalette.Text, QColor("#e8e8e8"))
		pal.setColor(QPalette.Highlight, QColor("#193156"))
		pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
		self.table.setPalette(pal)

		# delegates
		self.table.setItemDelegateForColumn(0, AvatarNameDelegate(self.table))
		self.table.setItemDelegateForColumn(1, RoleChip(self.table))
		self.table.setItemDelegateForColumn(2, IDElideDelegate(560, self.table))

		# context menu
		self.table.setContextMenuPolicy(Qt.CustomContextMenu)
		self.table.customContextMenuRequested.connect(self._menu)

		# layout root
		root = QVBoxLayout(self); root.setContentsMargins(10, 8, 10, 10); root.setSpacing(8)
		root.addWidget(header)
		root.addWidget(util)
		root.addWidget(self.table, 1)

		# signals
		self.search.textChanged.connect(self.proxy.setText)
		self._seg.buttonClicked.connect(self._seg_changed)
		self.table.selectionModel().selectionChanged.connect(self._sel_changed)
		self.btnAdd.clicked.connect(self._open_add_dialog)
		self.btnRemove.clicked.connect(self._remove)

		# WS
		self.ws = OperatorsWSClient(api, self)
		self.ws.error.connect(lambda e: None)
		self.ws.snapshot.connect(self._on_snapshot)
		self.ws.open()

		# theme / style
		self._apply_style()

	# ---------- styling ------------------------------------------------------

	def _apply_style(self):
		self.setStyleSheet("""
			QWidget#OperatorsTab { background:#0e1420; }

			/* Header glass card */
			QFrame#OpsHeader {
				background: #111722;
				border: 1px solid #1d2635;
				border-radius: 12px;
			}
			QLabel#OpsTitle {
				color:#e9edf7; font-size:16px; font-weight:600;
			}
			QLabel#OpsCount {
				color:#8a93a3; font-size:12px; padding:4px 8px;
				border:1px solid #273245; border-radius:8px; background:#0b111a;
			}
			QToolButton#Primary {
				background:#1a2540; color:#e8e8e8; border:1px solid #273245;
				border-radius:10px; padding:8px 14px; font-weight:600;
			}
			QToolButton#Primary:hover { background:#1f2d52; }
			QToolButton#Danger {
				background:#2a1b1b; color:#ffdede; border:1px solid #4a2a2a;
				border-radius:10px; padding:8px 12px;
			}
			QToolButton#Danger:disabled { background:#1b1515; color:#8b6f6f; border-color:#3a2626; }

			/* Utility bar */
			QFrame#OpsUtil {
				background:#111722;
				border:1px solid #1d2635;
				border-radius:12px;
			}
			QLineEdit#SearchField {
				background:#0b111a; color:#e8e8e8; border:1px solid #273245; border-radius:10px; padding:8px 12px;
			}
			QLineEdit#SearchField::placeholder { color:#8a93a3; }

			/* Segmented chips */
			QToolButton[seg="true"] {
				background:transparent; color:#cfd6e6; border:1px solid #273245; border-radius:999px;
				padding:6px 12px; min-width: 0px;
			}
			QToolButton[seg="true"]:checked {
				background:#1b2740; color:#ffffff; border-color:#2c3952;
			}
			QToolButton[seg="true"]:hover { background:#172134; }

			/* Table */
			QTableView#OpsTable {
				background:#0b111a; border:1px solid #1d2635; border-radius:12px; gridline-color:#1b2434;
			}
			QHeaderView::section {
				background:#111722; color:#e8e8e8; padding:8px 10px; border:0px; border-right:1px solid #1b2434;
			}
			QTableView#OpsTable::item:hover { background:#14223b; }
			QTableView#OpsTable::item:selected { background:#193156; color:#ffffff; }
		""")

	# ---------- data / ws ----------------------------------------------------

	def _on_snapshot(self, rows):
		self.model.set_ops(rows)
		self._update_count()

	def _update_count(self):
		n = self.proxy.rowCount()
		self.lblCount.setText(f"{n} operator(s)")

	# ---------- selection / filters / actions --------------------------------

	def _seg_changed(self, btn):
		text = btn.text().lower()
		role = "all" if text == "all" else text
		self.proxy.setRole(role)
		self._update_count()

	def _sel_changed(self, *_):
		self.btnRemove.setEnabled(bool(self._current_id()))

	def _current_row(self):
		idxs = self.table.selectionModel().selectedRows()
		return self.model.row_dict(idxs[0].row(), self.proxy) if idxs else None

	def _current_id(self):
		r = self._current_row()
		return r.get("id") if r else None

	# ----- add/remove/update --------------------------------------------------

	def _open_add_dialog(self):
		dlg = AddOperatorDialog(self)
		if dlg.exec_() == QDialog.Accepted:
			u = dlg.uEdit.text().strip()
			p = dlg.pEdit.text()
			r = dlg.roleNew.currentText()
			if not u or not p:
				QMessageBox.warning(self, "Add Operator", "Username and password are required.")
				return
			self.ws.add(u, p, r, cb=lambda m: None)

	def _remove(self):
		ident = self._current_id()
		if not ident: 
			return
		if QMessageBox.question(self, "Remove Operator", "Delete selected operator?",
								QMessageBox.Yes|QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
			return
		self.ws.delete(ident, cb=lambda m: None)

	def _menu(self, pos: QPoint):
		r = self._current_row()
		m = QMenu(self)
		act_copy = m.addAction("Copy ID", self._copy_id); act_copy.setEnabled(bool(r))
		m.addSeparator()
		a_role_op = m.addAction("Set role: operator", lambda: self._update_role("operator"))
		a_role_ad = m.addAction("Set role: admin",    lambda: self._update_role("admin"))
		m.addSeparator()
		a_ren = m.addAction("Rename…", self._rename)
		a_pwd = m.addAction("Reset password…", self._reset_pw)
		m.addSeparator()
		a_rm  = m.addAction("Remove", self._remove)
		if not r:
			for a in (a_role_op, a_role_ad, a_ren, a_pwd, a_rm): a.setEnabled(False)
		m.exec_(self.table.viewport().mapToGlobal(pos))

	def _copy_id(self):
		r = self._current_row()
		if not r: return
		QApplication.clipboard().setText(str(r.get("id", "")))

	def _update_role(self, role):
		ident = self._current_id()
		if ident: self.ws.update(ident, role_new=role, cb=lambda m: None)

	def _rename(self):
		r = self._current_row()
		if not r: return
		text, ok = QInputDialog.getText(self, "Rename Operator", "New username:", QLineEdit.Normal, r.get("username",""))
		if ok and text.strip():
			self.ws.update(r.get("id"), username_new=text.strip(), cb=lambda m: None)

	def _reset_pw(self):
		r = self._current_row()
		if not r: return
		text, ok = QInputDialog.getText(self, "Reset Password", f"New password for {r.get('username')}:", QLineEdit.Password)
		if ok and text.strip():
			self.ws.update(r.get("id"), password_new=text.strip(), cb=lambda m: None)

	def eventFilter(self, obj, ev):
		# 1) Empty area inside the table viewport -> clear
		if obj is self.table.viewport() and ev.type() == QEvent.MouseButtonPress:
			if not self.table.indexAt(ev.pos()).isValid():
				self.table.clearSelection()
			return False

		# 2) Elsewhere in the window -> clear, except whitelisted controls (e.g., Remove)
		if ev.type() == QEvent.MouseButtonPress:
			w = obj if isinstance(obj, QWidget) else None

			# Walk up parents to see if any has preserveSelection=True
			def _preserves_selection(x):
				while isinstance(x, QWidget):
					if bool(x.property("preserveSelection")):
						return True
					x = x.parentWidget()
				return False

			if w and w.window() is self.window():
				# do NOT clear if this click is on/inside a preserveSelection control
				if _preserves_selection(w):
					return False

				# clear if the click is outside the table
				if not (w is self.table or self.table.isAncestorOf(w)):
					self.table.clearSelection()
					return False

		return super().eventFilter(obj, ev)
