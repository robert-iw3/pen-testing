# gui/sessions_tab.py
from PyQt5.QtWidgets import (
    QWidget, QTableView, QPushButton, QHBoxLayout, QVBoxLayout,
    QLineEdit, QHeaderView, QAbstractItemView, QMenu, QAction, QToolButton,
    QLabel, QMessageBox, QStyledItemDelegate, QStyleOptionViewItem, QStyle
)
from PyQt5.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QVariant, pyqtSignal, QSortFilterProxyModel, QRect, QEvent
)
from PyQt5.QtGui import (
    QPalette, QColor, QFont, QPainter, QBrush, QPen, QIcon
)

try:
    from .websocket_client import SessionsWSClient  # package import
except ImportError:
    from websocket_client import SessionsWSClient   # script import


# ----------------------- Helpers -----------------------

def _rel_last_seen(value):
    """Return a friendly 'last seen' label and freshness class."""
    if value in (None, "", "None"):
        return ("—", "stale")
    # Accept epoch seconds, ms, or ISO-ish strings
    import datetime
    now = datetime.datetime.utcnow()

    dt = None
    try:
        # epoch seconds
        if isinstance(value, (int, float)):
            if value > 1e12:  # ms
                dt = datetime.datetime.utcfromtimestamp(value/1000.0)
            else:
                dt = datetime.datetime.utcfromtimestamp(value)
        elif isinstance(value, str):
            s = value.strip().replace("Z", "+00:00")
            try:
                dt = datetime.datetime.fromisoformat(s)
                if dt.tzinfo:
                    dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            except Exception:
                dt = None
    except Exception:
        dt = None

    if not dt:
        return (str(value), "unknown")

    diff = (now - dt).total_seconds()
    if diff < 30:
        return ("live", "live")
    if diff < 90:
        return ("1m", "warm")
    if diff < 60*5:
        return (f"{int(diff//60)}m", "warm")
    if diff < 60*60:
        return (f"{int(diff//60)}m", "cool")
    return (f"{int(diff//3600)}h", "stale")


# ----------------------- Model -----------------------

COLUMNS = [
    ("ID", "id"),
    ("Hostname", "hostname"),
    ("User", "user"),
    ("OS", "os"),
    ("Arch", "arch"),
    ("Transport", "transport"),
    ("Last Seen", "last_checkin"),   # rendered via _rel_last_seen
]

class SessionsModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._rows = []  # list[dict]
        self._sort_col = 1
        self._sort_order = Qt.AscendingOrder

    def rowCount(self, _=QModelIndex()):
        return len(self._rows)

    def columnCount(self, _=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section][0]
        return QVariant()

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return QVariant()

        row = self._rows[index.row()]
        key = COLUMNS[index.column()][1]

        if role == Qt.DisplayRole:
            if key == "last_checkin":
                label, _cls = _rel_last_seen(row.get(key))
                return label
            return str(row.get(key, ""))

        if role == Qt.TextAlignmentRole:
            if key in ("id", "arch", "transport", "last_checkin"):
                return Qt.AlignCenter
            return Qt.AlignVCenter | Qt.AlignLeft

        if role == Qt.FontRole:
            if key in ("id",):
                f = QFont()
                f.setFamily("Consolas")
                f.setPointSizeF(f.pointSizeF() * 0.95)
                return f

        if role == Qt.ForegroundRole:
            if key == "last_checkin":
                label, cls = _rel_last_seen(row.get(key))
                if cls == "stale":   return QColor("#9aa3ad")
                if cls == "cool":    return QColor("#bdc6d1")
                if cls == "warm":    return QColor("#e9d27e")
                if cls == "live":    return QColor("#99e2b4")
                return QColor("#cfd6dd")
        return QVariant()

    # Sorting (so header clicks work)
    def sort(self, column, order):
        key = COLUMNS[column][1]

        def _keyfunc(r):
            if key == "last_checkin":
                label, cls = _rel_last_seen(r.get(key))
                # order live > warm > cool > stale by class + label
                rank = {"live":0, "warm":1, "cool":2, "stale":3, "unknown":4}.get(cls, 5)
                return (rank, label)
            return str(r.get(key, "")).lower()

        self.layoutAboutToBeChanged.emit()
        self._rows.sort(key=_keyfunc, reverse=(order == Qt.DescendingOrder))
        self._sort_col, self._sort_order = column, order
        self.layoutChanged.emit()

    # Public
    def set_sessions(self, sessions: list):
        """Replace data while preserving sort."""
        selected_id = None
        # caller can provide selected id, but we’ll allow external reselect
        self.layoutAboutToBeChanged.emit()
        self._rows = list(sessions or [])
        # keep sort
        self.layoutChanged.emit()
        if self._sort_col is not None:
            self.sort(self._sort_col, self._sort_order)

    def session_at(self, proxy_row: int, proxy_model: QSortFilterProxyModel):
        if proxy_row < 0:
            return None
        src_row = proxy_model.mapToSource(proxy_model.index(proxy_row, 0)).row()
        if 0 <= src_row < len(self._rows):
            return self._rows[src_row]
        return None


# ----------------------- Delegates (badge chips) -----------------------

class ChipDelegateBase:
    """Shared painting for rounded 'chip' labels."""
    RADIUS = 8
    PAD_X = 8
    PAD_Y = 4
    def _paint_chip(self, painter, rect: QRect, text: str, bg: QColor, fg: QColor):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        # background
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(rect.adjusted(6, 4, -6, -4), self.RADIUS, self.RADIUS)
        # text
        painter.setPen(QPen(fg))
        f = painter.font()
        f.setPointSizeF(f.pointSizeF() * 0.95)
        painter.setFont(f)
        painter.drawText(rect, Qt.AlignCenter, text)
        painter.restore()

    def _paint_cell_bg(self, painter, option, index):
        """
        Ask the current style to paint the *background* of the cell
        (base/alternate/selection/focus) so we don't inherit light defaults.
        We blank out text/icon so only the BG is drawn.
        """
        opt = QStyleOptionViewItem(option)
        # init with index so the style knows selected/alternate states
        try:
            # available on QStyledItemDelegate
            self.initStyleOption(opt, index)  # type: ignore[attr-defined]
        except Exception:
            pass
        opt.text = ""
        opt.icon = QIcon()
        w = option.widget
        if w is not None:
            w.style().drawControl(QStyle.CE_ItemViewItem, opt, painter, w)
        else:
            QStyledItemDelegate.paint(self, painter, opt, index)  # fallback

class TransportDelegate(QStyledItemDelegate, ChipDelegateBase):
    def paint(self, painter, option, index):
        self._paint_cell_bg(painter, option, index)
        text = index.data(Qt.DisplayRole) or ""
        palette = {
            "tcp": ("#2b5b8c", "#d7e8ff"),
            "tls": ("#2f6b5f", "#d2fff2"),
            "http":("#6a4c2d", "#ffe9cf"),
            "https":("#345f7a", "#d8f0ff"),
        }
        bg_hex, fg_hex = palette.get(text.lower(), ("#434a57", "#e6edf3"))
        self._paint_chip(painter, option.rect, text, QColor(bg_hex), QColor(fg_hex))

class ArchDelegate(QStyledItemDelegate, ChipDelegateBase):
    def paint(self, painter, option, index):
        self._paint_cell_bg(painter, option, index)
        text = index.data(Qt.DisplayRole) or ""
        palette = {
            "64-bit": ("#454a59", "#eaeef7"),
            "32-bit": ("#4a3c53", "#f1e6ff"),
            "arm64":  ("#3e4f3e", "#e1f3e1"),
        }
        bg_hex, fg_hex = palette.get(text.lower(), ("#454a59", "#eaeef7"))
        self._paint_chip(painter, option.rect, text, QColor(bg_hex), QColor(fg_hex))

class LastSeenDelegate(QStyledItemDelegate, ChipDelegateBase):
    def paint(self, painter, option, index):
        self._paint_cell_bg(painter, option, index)
        text = index.data(Qt.DisplayRole) or "—"
        label, cls = text, "unknown"
        # We don’t have class in the role; recompute from underlying
        # but DisplayRole already is label; tint based on label heuristics
        if label == "live":
            bg, fg = QColor("#174a2a"), QColor("#a0f0c0")
        elif label.endswith("m"):
            bg, fg = QColor("#4a4317"), QColor("#fff0a6")
        elif label.endswith("h"):
            bg, fg = QColor("#3e4552"), QColor("#cfd6dd")
        else:
            bg, fg = QColor("#3e4552"), QColor("#cfd6dd")
        self._paint_chip(painter, option.rect, label, bg, fg)


# ----------------------- Proxy (global filter) -----------------------

class SessionsFilter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self._needle = ""

    def setFilterText(self, text: str):
        self._needle = (text or "").lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._needle:
            return True
        cols = range(len(COLUMNS))
        model = self.sourceModel()
        for c in cols:
            idx = model.index(source_row, c, source_parent)
            s = model.data(idx, Qt.DisplayRole)
            if s and self._needle in str(s).lower():
                return True
        return False


# ----------------------- Sessions Tab -----------------------

class SessionsTab(QWidget):
    session_double_clicked = pyqtSignal(str, str)
    gunnershell_requested = pyqtSignal(str, str)

    def __init__(self, api):
        super().__init__()
        self.api = api

        # --- toolbar (left: search, right: actions) ---
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search sessions (ID, host, user, OS, transport)…")
        self.search.setClearButtonEnabled(True)

        # Make search text + placeholder pure white
        spal = self.search.palette()
        spal.setColor(QPalette.Text, QColor("#ffffff"))
        spal.setColor(QPalette.PlaceholderText, QColor("#ffffff"))
        self.search.setPalette(spal)

        self.btn_gs = QPushButton("Open GunnerShell")
        self.btn_console = QPushButton("Open Console")
        self.btn_kill = QPushButton("Kill Session")

        self.btn_gs.setEnabled(False)
        self.btn_console.setEnabled(False)
        self.btn_kill.setEnabled(False)

        self.columns_btn = QToolButton()
        self.columns_btn.setText("Columns")
        self.columns_btn.setPopupMode(QToolButton.InstantPopup)
        self.columns_menu = QMenu(self)
        self.columns_btn.setMenu(self.columns_menu)

        top = QHBoxLayout()
        top.addWidget(self.search, stretch=1)
        top.addStretch()
        top.addWidget(self.btn_gs)
        top.addWidget(self.btn_console)
        top.addWidget(self.btn_kill)
        top.addWidget(self.columns_btn)

        # --- table view ---
        self.model = SessionsModel()
        self.proxy = SessionsFilter()
        self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(1, Qt.AscendingOrder)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setTextElideMode(Qt.ElideRight)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setFocusPolicy(Qt.NoFocus)

        # Clear selection when clicking on empty space in the table
        self.table.viewport().installEventFilter(self)
 

        # header sizing
        hdr = self.table.horizontalHeader()
        hdr.setHighlightSections(False)
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)

        # reasonable defaults
        self.table.setColumnWidth(0, 180)  # ID
        self.table.setColumnWidth(1, 220)  # Hostname
        self.table.setColumnWidth(2, 220)  # User
        self.table.setColumnWidth(3, 120)  # OS
        self.table.setColumnWidth(4, 90)   # Arch
        self.table.setColumnWidth(5, 100)  # Transport
        self.table.setColumnWidth(6, 120)  # Last Seen

        # row height
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.verticalHeader().setVisible(False)

        # delegates (chips)
        self.table.setItemDelegateForColumn(4, ArchDelegate(self.table))
        self.table.setItemDelegateForColumn(5, TransportDelegate(self.table))
        self.table.setItemDelegateForColumn(6, LastSeenDelegate(self.table))

        # context menu
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)

        # layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(top)
        layout.addWidget(self.table)

        # palette + style
        self._apply_dark_theme()

        # connections
        self.search.textChanged.connect(self.proxy.setFilterText)
        self.table.selectionModel().selectionChanged.connect(self._sel_changed)
        self.table.doubleClicked.connect(self._dbl)
        self.btn_console.clicked.connect(self.open_console)
        self.btn_gs.clicked.connect(self.open_gunnershell)
        self.btn_kill.clicked.connect(self.kill_selected)

        # --- WebSocket live stream ---
        self.ws = SessionsWSClient(api, self)
        self.ws.connected.connect(lambda: None)
        self.ws.disconnected.connect(lambda: None)
        self.ws.error.connect(lambda e: None)
        self.ws.snapshot.connect(self._apply_snapshot)
        self.ws.open()

        # build columns menu
        self._rebuild_columns_menu()

    # ----------- styling -----------
    def _apply_dark_theme(self):
        pal = self.palette()
        # Core colors
        window    = QColor("#141820")
        base      = QColor("#151a22")
        alt_base  = QColor("#1b212b")
        text_col  = QColor("#e6e6e6")
        btn_bg    = QColor("#222834")
        hl_bg     = QColor("#2f3540")
        hl_text   = QColor("#ffffff")

        # Apply to ALL palette groups so inactive/disabled states never flip to light defaults
        for grp in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
            pal.setColor(grp, QPalette.Window,           window)
            pal.setColor(grp, QPalette.Base,             base)
            pal.setColor(grp, QPalette.AlternateBase,    alt_base)
            pal.setColor(grp, QPalette.Text,             text_col)
            pal.setColor(grp, QPalette.Button,           btn_bg)
            pal.setColor(grp, QPalette.ButtonText,       text_col)
            pal.setColor(grp, QPalette.Highlight,        hl_bg)
            pal.setColor(grp, QPalette.HighlightedText,  hl_text)

        self.setPalette(pal)

        self.setStyleSheet("""
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
            }

            QMenu::item:selected {
                background:#2f3540;
                color:#ffffff;
            }

            QMenu::item:disabled {
                color:#9aa3ad;
                font-weight:400;         
            }

            QLineEdit { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#1a1f29; }
            QLineEdit:focus { border-color:#5a93ff; }
            QPushButton { padding:6px 10px; border:1px solid #3b404a; border-radius:6px; background:#222834; }
            QPushButton:disabled { color:#9aa3ad; border-color:#333842; background:#1c212b; }
            QPushButton:hover { background:#2a3140; }
            QPushButton#danger { border-color:#6b2a2a; background:#3a1f1f; }
            QPushButton#danger:hover { background:#4a2a2a; }
            /* Table + rows */
            QTableView { background:#151a22; color:#e6e6e6; gridline-color:#3b404a; }
            /* Make row backgrounds explicit so styles/platforms don't fall back to light alternates */
            QTableView::item { background:#151a22; }
            QTableView::item:alternate { background:#1b212b; }
            /* Selected row (active & inactive window) */
            QHeaderView::section { background:#202633; color:#e6e6e6; border:1px solid #3b404a; padding:6px; }
            QTableView::item:selected { background:#2f3540; }
            QTableView::item:selected:!active { background:#2a303a; }
        """)
        self.btn_kill.setObjectName("danger")

    # ----------- column toggles -----------
    def _rebuild_columns_menu(self):
        self.columns_menu.clear()
        for i, (name, _) in enumerate(COLUMNS):
            act = QAction(name, self, checkable=True, checked=not self.table.isColumnHidden(i))
            act.toggled.connect(lambda checked, col=i: self.table.setColumnHidden(col, not checked))
            self.columns_menu.addAction(act)

    # ----------- selection/activation -----------
    def _sel_changed(self, *_):
        has = self._current_sid() is not None
        self.btn_console.setEnabled(has)
        self.btn_gs.setEnabled(has)
        self.btn_kill.setEnabled(has)

    def _dbl(self, index: QModelIndex):
        self.open_gunnershell()

    def _current_sid(self):
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            return None
        r = idxs[0].row()
        row = self.model.session_at(r, self.proxy)
        return row.get("id") if row else None

    def _current_host(self):
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            return None
        r = idxs[0].row()
        row = self.model.session_at(r, self.proxy)
        return row.get("hostname") if row else None

    # ----------- actions -----------
    def open_console(self):
        sid, host = self._current_sid(), self._current_host()
        if not sid: return
        self.session_double_clicked.emit(sid, host or "")

    def open_gunnershell(self):
        sid, host = self._current_sid(), self._current_host()
        if not sid: return
        self.gunnershell_requested.emit(sid, host or "")

    def kill_selected(self):
        sid, host = self._current_sid(), self._current_host()
        if not sid: return
        if QMessageBox.question(
            self, "Kill Session",
            f"Are you sure you want to kill session:\n\n  {sid}  ({host})",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        ) != QMessageBox.Yes:
            return

        def _done(resp: dict):
            t = (resp.get("type") or "").lower()
            if t == "killed":
                QMessageBox.information(self, "Session Killed",
                    f"Session {resp.get('id','')} closed ({resp.get('transport','')}).")
            elif t == "error":
                QMessageBox.warning(self, "Kill Failed", str(resp.get("error","Unknown error")))
        self.ws.kill(sid, _done)

    def _context_menu(self, pos):
        idxs = self.table.selectionModel().selectedRows()
        m = QMenu(self)

        # force menu to use the same (non-bold) app font
        mf = QFont(self.font())
        mf.setBold(False)
        m.setFont(mf)
        
        a1 = m.addAction("Open GunnerShell", self.open_gunnershell)
        a2 = m.addAction("Open Console", self.open_console)
        m.addSeparator()
        a3 = m.addAction("Copy ID", lambda: self._copy_field("id"))
        a4 = m.addAction("Copy Hostname", lambda: self._copy_field("hostname"))
        a5 = m.addAction("Copy User", lambda: self._copy_field("user"))
        m.addSeparator()
        a6 = m.addAction("Kill Session", self.kill_selected)
        if not idxs:
            for a in (a1,a2,a3,a4,a5,a6): a.setEnabled(False)
        m.exec_(self.table.viewport().mapToGlobal(pos))

    def _copy_field(self, key):
        row = None
        idxs = self.table.selectionModel().selectedRows()
        if idxs:
            row = self.model.session_at(idxs[0].row(), self.proxy)
        if row:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(str(row.get(key, "")))

    # ----------- live updates -----------
    def _apply_snapshot(self, sessions: list):
        # Keep selection & scroll
        prev_sid = self._current_sid()
        self.model.set_sessions(sessions)

        # reselect by id
        if prev_sid:
            id_col = 0
            for r in range(self.proxy.rowCount()):
                if self.proxy.index(r, id_col).data() == prev_sid:
                    self.table.selectRow(r)
                    break

    # Make clicks on empty space deselect the current row
    def eventFilter(self, obj, ev):
        if obj is self.table.viewport():
            if ev.type() == QEvent.MouseButtonPress and ev.button() == Qt.LeftButton:
                # If the click is not on a valid index, clear selection
                if not self.table.indexAt(ev.pos()).isValid():
                    self.table.clearSelection()
                    # Also clear current index so no cell keeps the focus rect
                    self.table.setCurrentIndex(QModelIndex())
                    return True  # consume the event
        return super().eventFilter(obj, ev)

    def closeEvent(self, e):
        try:
            self.ws.close()
        except Exception:
            pass
        super().closeEvent(e)
