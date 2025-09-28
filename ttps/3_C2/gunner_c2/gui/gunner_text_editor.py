# gui/gunner_text_editor.py
from __future__ import annotations
from typing import Callable, Optional, Dict
import os, tempfile, uuid, fnmatch

from PyQt5.QtCore import Qt, QEvent, QSize, QRect, QPoint, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon
from PyQt5.QtWidgets import (
	QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit, QLabel, QTabWidget,
	QGraphicsDropShadowEffect, QShortcut, QStyle, QApplication, QMessageBox,
	QMenu, QDialog, QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
	QLineEdit, QToolButton, QInputDialog, QAction, QTabBar, QAbstractItemView  
)

# TitleBar from your project
from title_bar import TitleBar
# Remote WS client (same one FileBrowser uses)
from files_ws_client import FilesWSClient

RADIUS = 12
SHADOW_BLUR = 36
SHADOW_YOFF = 8


# ---------- Small helpers ----------

def _basename_for_label(p: str) -> str:
	p = (p or "").rstrip("/\\")
	if not p:
		return p
	if "\\" in p and ("/" not in p):
		return p.split("\\")[-1]
	return p.split("/")[-1]

def _sep_for(path: str, os_type: str) -> str:
	return "\\" if (os_type or "").lower() == "windows" else "/"

def _join_path(base: str, name: str, os_type: str) -> str:
	name = (name or "").rstrip("/\\")
	if (os_type or "").lower() == "windows":
		if (len(name) >= 2 and name[1] == ":") or name.startswith("\\\\"):
			return _norm_path(name, os_type)
		return _norm_path((base.rstrip("\\") + "\\" + name) if base else name, os_type)
	else:
		if name.startswith("/"):
			return _norm_path(name, os_type)
		return _norm_path((base.rstrip("/") + "/" + name) if base else name, os_type)

def _norm_path(p: str, os_type: str) -> str:
	p = (p or "").strip()
	if (os_type or "").lower() == "windows":
		p = p.replace("/", "\\")
		# fix stray leading backslash before drive
		if len(p) >= 3 and p[0] == "\\" and p[1].isalpha() and p[2] == ":":
			p = p[1:]
		# collapse dup slashes (except UNC head)
		if p.startswith("\\\\"):
			head, rest = "\\\\", p[2:]
			while "\\\\" in rest:
				rest = rest.replace("\\\\", "\\")
			p = head + rest
		else:
			while "\\\\" in p:
				p = p.replace("\\\\", "\\")
		# ensure drive root ends with backslash
		if len(p) == 2 and p[1] == ":":
			p += "\\"
		return p or "C:\\"
	else:
		p = p.replace("\\", "/")
		while "//" in p:
			p = p.replace("//", "/")
		return p if p.startswith("/") else ("/" if p == "." else p)


# ---------- Table item for dir-first sorting ----------

class _NameItem(QTableWidgetItem):
	def __init__(self, text: str, is_dir: bool):
		super().__init__(text)
		self.is_dir = bool(is_dir)
	def __lt__(self, other):
		if isinstance(other, _NameItem):
			if self.is_dir != other.is_dir:
				return self.is_dir and not other.is_dir
			return self.text().lower() < other.text().lower()
		return super().__lt__(other)


# ---------- Remote Open dialog (agent-side picker) ----------
class RemoteOpenDialog(QDialog):
	def __init__(self, fws: FilesWSClient, sid: str, os_type: str, start_path: str):
		super().__init__()
		self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
		self.setAttribute(Qt.WA_TranslucentBackground, True)
		self._chrome = QWidget(self)
		self._chrome.setObjectName("DlgChrome")
		"""self._chrome.setStyleSheet(
			f"QWidget#DlgChrome {{ background:#1f2430; border-radius:{RADIUS}px; }}"
			"QLineEdit { background:#0b111a; color:#e8e8e8; border:1px solid #2a3446; "
			"            border-radius:8px; padding:8px 12px; selection-background-color:#2c3c57; }"
			"QPushButton { background:#131a26; color:#e8e8e8; border:1px solid #2a3446; border-radius:8px; padding:8px 14px; }"
			"QPushButton:hover { background:#172134; }"
			"QToolButton[toolbar='true'] { background:#131a26; color:#e8e8e8; border:1px solid #2a3446; border-radius:8px; padding:6px 10px; }"
			"QToolButton[toolbar='true']:hover { background:#172134; }"
			"QTableWidget { background:#0b111a; border:1px solid #1d2635; border-radius:10px; gridline-color:#1b2434; }"
			"QHeaderView::section { background:#111722; color:#e8e8e8; padding:8px 10px; border:0px; border-right:1px solid #1b2434; }"
			"QTableWidget::item:selected { background:#193156; }"
		)"""

		self._chrome.setStyleSheet(
			f"QWidget#DlgChrome {{ background:#2a2e36; border-radius:{RADIUS}px; }}"
			"QLineEdit { background:#0b111a; color:#e8e8e8; border:1px solid #273245; border-radius:8px; padding:6px 10px; }"
			"QToolButton[toolbar=\"true\"] { background:#131a26; color:#e8e8e8; border:1px solid #273245; border-radius:8px; padding:6px 12px; }"
			"QToolButton[toolbar=\"true\"]:hover { background:#172134; }"
			"QTableWidget { background:#0b111a; border:1px solid #1d2635; border-radius:10px; gridline-color:#1b2434; }"
			"QHeaderView::section { background:#111722; color:#e8e8e8; padding:6px 8px; border:0px; border-right:1px solid #1b2434; }"
			"QTableWidget::item:selected { background:#193156; }"
		)
		outer = QVBoxLayout(self)
		outer.setContentsMargins(12, 12, 12, 12)
		outer.addWidget(self._chrome)

		sh = QGraphicsDropShadowEffect(self._chrome)
		sh.setBlurRadius(SHADOW_BLUR)
		sh.setOffset(0, SHADOW_YOFF)
		sh.setColor(Qt.black)
		self._chrome.setGraphicsEffect(sh)

		self.fws = fws
		self.sid = sid
		self.os_type = (os_type or "").lower()
		self.cur_path = _norm_path(start_path, os_type) or ("C:\\" if self.os_type == "windows" else "/")
		self.selected_path: Optional[str] = None

		self._all_entries: list[dict] = []   # full list for this dir (unfiltered)
		self._search_timer = QTimer(self)
		self._search_timer.setSingleShot(True)
		self._search_timer.setInterval(200)   # debounce typing

		v = QVBoxLayout(self._chrome)
		v.setContentsMargins(12, 12, 12, 12)
		v.setSpacing(10)

		"""# ===== Row 1: PATH BAR (editable) + GO / UP / REFRESH =====
		row1 = QHBoxLayout()
		self.path_edit = QLineEdit(self.cur_path, self)
		self.path_edit.setClearButtonEnabled(True)
		self.path_edit.setPlaceholderText("Enter path…")
		self.path_edit.returnPressed.connect(self._go_to_path)

		self.btn_go = QToolButton(self); self.btn_go.setProperty("toolbar", True)
		self.btn_go.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))
		self.btn_go.setToolTip("Go to path")
		self.btn_go.clicked.connect(self._go_to_path)

		self.btn_up = QToolButton(self); self.btn_up.setProperty("toolbar", True)
		self.btn_up.setIcon(self.style().standardIcon(QStyle.SP_ArrowUp))
		self.btn_up.setToolTip("Up one level")
		self.btn_up.clicked.connect(self._go_up)

		self.btn_ref = QToolButton(self); self.btn_ref.setProperty("toolbar", True)
		self.btn_ref.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
		self.btn_ref.setToolTip("Refresh")
		self.btn_ref.clicked.connect(lambda: self._list(self.cur_path))

		row1.addWidget(self.path_edit, 1)
		row1.addWidget(self.btn_go)
		row1.addWidget(self.btn_up)
		row1.addWidget(self.btn_ref)
		v.addLayout(row1)"""

		# Top: path field + Back/Forward/Up/Refresh
		row = QHBoxLayout()
		self.path_edit = QLineEdit(self.cur_path, self)
		# allow manual edits; pressing Enter will navigate
		self.path_edit.returnPressed.connect(lambda: self._go_to_path(self.path_edit.text()))
		self.path_edit.setClearButtonEnabled(True)

		# Buttons
		def _mk_tb(text, tip):
			b = QToolButton(self); b.setText(text); b.setToolTip(tip)
			b.setProperty("toolbar", True)
			b.setStyleSheet("QToolButton { background:#131a26; color:#e8e8e8; border:1px solid #273245; "
					"border-radius:8px; padding:6px 12px; } QToolButton:hover { background:#172134; }")
			return b

		self.btn_back = _mk_tb("◀", "Back")
		self.btn_fwd  = _mk_tb("▶", "Forward")
		self.btn_up   = _mk_tb("Up", "Up one folder")
		self.btn_ref  = _mk_tb("Refresh", "Refresh")

		self.btn_back.setIcon(self.style().standardIcon(QStyle.SP_ArrowBack))
		self.btn_fwd.setIcon(self.style().standardIcon(QStyle.SP_ArrowForward))

		self.btn_back.clicked.connect(self._nav_back)
		self.btn_fwd.clicked.connect(self._nav_forward)
		self.btn_up.clicked.connect(self._go_up)
		self.btn_ref.clicked.connect(lambda: self._list(self.cur_path))  # refresh shouldn't change history

		row.addWidget(self.path_edit, 1)
		row.addWidget(self.btn_back)
		row.addWidget(self.btn_fwd)
		row.addWidget(self.btn_up)
		row.addWidget(self.btn_ref)
		v.addLayout(row)

		# --- history state ---
		self._hist = []          # list[str]
		self._hist_idx = -1      # current index in history
		self._hist_cap = 200     # optional cap

		# ===== Row 2: SEARCH BAR =====
		row2 = QHBoxLayout()
		self.search_edit = QLineEdit(self)
		self.search_edit.setPlaceholderText("Search this folder… (supports * and ?)")
		self.search_edit.setClearButtonEnabled(True)
		self.search_edit.textChanged.connect(lambda _=None: self._apply_filter_debounced())
		row2.addWidget(self.search_edit, 1)
		v.addLayout(row2)

		# ===== Table =====
		# Table
		self.table = QTableWidget(0, 3, self)
		self.table.setHorizontalHeaderLabels(["Name", "Type", "Size"])

		hdr = self.table.horizontalHeader()
		hdr.setSectionResizeMode(0, QHeaderView.Stretch)
		hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
		hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)

		self.table.setSelectionBehavior(QTableWidget.SelectRows)
		self.table.setEditTriggers(QTableWidget.NoEditTriggers)
		self.table.setSortingEnabled(True)

		#Fixed-height, non-wrapping rows (replacement for setUniformRowHeights)
		self.table.setWordWrap(False)
		vh = self.table.verticalHeader()
		vh.setDefaultSectionSize(24)
		vh.setMinimumSectionSize(24)

		# Smoother scrolling on big directories
		self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
		self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)

		v.addWidget(self.table, 1)
		"""self.table = QTableWidget(0, 3, self)
		self.table.setHorizontalHeaderLabels(["Name", "Type", "Size"])
		hdr = self.table.horizontalHeader()
		hdr.setSectionResizeMode(0, QHeaderView.Stretch)
		hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
		hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)

		self.table.setUniformRowHeights(True)
		self.table.setVerticalScrollMode(self.table.ScrollPerPixel)
		self.table.setHorizontalScrollMode(self.table.ScrollPerPixel)

		self.table.setSelectionBehavior(QTableWidget.SelectRows)
		self.table.setSelectionMode(QAbstractItemView.SingleSelection)
		self.table.setEditTriggers(QTableWidget.NoEditTriggers)
		self.table.setSortingEnabled(True)
		self.table.setAlternatingRowColors(True)
		self.table.verticalHeader().setVisible(False)
		v.addWidget(self.table, 1)"""

		self.status_lbl = QLabel("", self)
		self.status_lbl.setStyleSheet("color:#8a93a3; padding:4px 6px;")
		v.addWidget(self.status_lbl, 0)

		# batched fill state
		self._pending_rows = []   # list of tuples we will render
		self._fill_index = 0
		self._fill_timer = QTimer(self)
		self._fill_timer.setInterval(0)           # next event-loop tick
		self._fill_timer.timeout.connect(self._fill_batch)
		self._batch_size = 400                    # tune: 200–800 depending on your machine

		# ===== Buttons =====
		btns = QHBoxLayout()
		btns.addStretch(1)
		self.btn_open = QPushButton("Open File", self)
		self.btn_cancel = QPushButton("Cancel", self)
		btns.addWidget(self.btn_open)
		btns.addWidget(self.btn_cancel)
		v.addLayout(btns)

		# Wire
		self.btn_cancel.clicked.connect(self.reject)
		self.btn_open.clicked.connect(self._choose_selected)
		self.table.cellDoubleClicked.connect(self._dbl)
		self._search_timer.timeout.connect(self._apply_filter)

		# Kick it off
		self._navigate_to(self.cur_path, add_to_history=True)
		self.resize(820, 520)

	# ---- WS list -> table ----
	def _list(self, path: str):
		self.cur_path = _norm_path(path, self.os_type)
		self.path_edit.setText(self.cur_path)

		# ensure previous one-shot is gone before reconnecting
		try:
			self.fws.listed.disconnect(self._on_list_once)
		except Exception:
			pass

		# one-shot hook (no UniqueConnection flag)
		self.fws.listed.connect(self._on_list_once)

		try:
			self.fws.list_dir(self.sid, self.cur_path)
		except Exception as e:
			QMessageBox.critical(self, "List", f"{e}")

	def _on_list_once(self, path: str, entries: list, ok: bool = True):
		# make strictly one-shot
		try:
			self.fws.listed.disconnect(self._on_list_once)
		except Exception:
			pass

		if _norm_path(path, self.os_type) != self.cur_path:
			return

		if not ok:
			QMessageBox.critical(self, "List", "Path not found on agent.")
			return

		# Build a lightweight list of rows first (cheap)
		self._all_entries = []
		rows = []
		for r in entries or []:
			name = str(r.get("name") or _basename_for_label(str(r.get("path") or "")) or "")
			v = r.get("is_dir", r.get("dir", r.get("directory", r.get("isDirectory"))))
			is_dir = bool(v) if isinstance(v, (bool, int, float)) else (str(r.get("type") or "").strip().lower() in {"dir","folder","directory"})
			size = 0
			try:
				for k in ("size", "length", "bytes", "byte_size"):
					if k in r and r[k] is not None:
						size = int(r[k]); break
			except Exception:
				size = 0

			disp_name = name + ("/" if is_dir and self.os_type != "windows" else "")
			type_label = "File folder" if is_dir else "File"
			rows.append((disp_name, type_label, size, is_dir))
			self._all_entries.append({"name": name, "is_dir": is_dir, "size": size})

		# Prepare table for fast fill
		self.table.setSortingEnabled(False)
		self.table.setUpdatesEnabled(False)
		self.table.clearContents()
		self.table.setRowCount(len(rows))
		self.table.setUpdatesEnabled(True)

		# Start batched fill
		self._pending_rows = rows
		self._fill_index = 0
		self.status_lbl.setText(f"Loading {len(rows):,} item(s)…")
		self._fill_timer.start()

	# --- Navigation ---
	def _update_history_buttons(self):
		self.btn_back.setEnabled(self._hist_idx > 0)
		self.btn_fwd.setEnabled(0 <= self._hist_idx < len(self._hist) - 1)

	def _push_history(self, path: str):
		# de-dup consecutive
		if self._hist and self._hist[self._hist_idx] == path:
			self._update_history_buttons()
			return
		# drop any forward entries when you branch
		if 0 <= self._hist_idx < len(self._hist) - 1:
			self._hist = self._hist[:self._hist_idx + 1]
		self._hist.append(path)
		# cap
		if len(self._hist) > self._hist_cap:
			drop = len(self._hist) - self._hist_cap
			self._hist = self._hist[drop:]
			self._hist_idx = max(-1, self._hist_idx - drop)
		self._hist_idx = len(self._hist) - 1
		self._update_history_buttons()

	def _navigate_to(self, path: str, *, add_to_history: bool = True):
		path = _norm_path(path, self.os_type)
		if add_to_history:
			self._push_history(path)
		self._list(path)              # actual directory listing
		# _list() will update self.cur_path and self.path_edit

	def _nav_back(self):
		if self._hist_idx > 0:
			self._hist_idx -= 1
			self._update_history_buttons()
			self._list(self._hist[self._hist_idx])

	def _nav_forward(self):
		if 0 <= self._hist_idx < len(self._hist) - 1:
			self._hist_idx += 1
			self._update_history_buttons()
			self._list(self._hist[self._hist_idx])

	def _go_to_path(self, p: Optional[str] = None):
		p = (p or self.path_edit.text() or "").strip()
		if not p:
			return
		self._navigate_to(p, add_to_history=True)

	# --- Populate table from entries (optionally filtered) ---
	def _populate_table(self, entries: list[dict]):
		self.table.setSortingEnabled(False)
		self.table.setRowCount(0)

		for r in entries:
			name = r["name"]
			is_dir = r["is_dir"]
			size = r.get("size", 0)

			type_label = "File folder" if is_dir else "File"
			row = self.table.rowCount()
			self.table.insertRow(row)

			it_name = _NameItem(name + ("/" if is_dir and self.os_type != "windows" else ""), is_dir)
			icon = self.style().standardIcon(QStyle.SP_DirIcon if is_dir else QStyle.SP_FileIcon)
			it_name.setIcon(icon)
			# stash the absolute path right on the item (used by double-click)
			it_name.setData(Qt.UserRole, _join_path(self.cur_path, name, self.os_type))
			self.table.setItem(row, 0, it_name)

			self.table.setItem(row, 1, QTableWidgetItem(type_label))
			self.table.setItem(row, 2, QTableWidgetItem(f"{size:,}" if size else ""))

		self.table.setSortingEnabled(True)
		#self._apply_filter()

	# --- Search (filter current directory) ---
	def _apply_filter_debounced(self):
		self._search_timer.stop()
		self._search_timer.start()

	def _apply_filter(self):
		term = (self.search_edit.text() or "").strip().lower()
		if not term:
			self._populate_table(self._all_entries)
			return

		# Accept wildcards (* ?) via fnmatch; if none present, substring match.
		use_glob = any(ch in term for ch in "*?")
		out = []
		for r in self._all_entries:
			name_l = r["name"].lower()
			if (fnmatch.fnmatchcase(name_l, term) if use_glob else term in name_l):
				out.append(r)
		self._populate_table(out)

	def _fill_batch(self):
		if not self._pending_rows:
			self._fill_timer.stop()
			return

		end = min(self._fill_index + self._batch_size, len(self._pending_rows))

		self.table.setUpdatesEnabled(False)
		for row in range(self._fill_index, end):
			name, type_label, size, is_dir = self._pending_rows[row]

			item = _NameItem(name, is_dir)
			item.setIcon(self.style().standardIcon(QStyle.SP_DirIcon if is_dir else QStyle.SP_FileIcon))
			full = _join_path(self.cur_path, name.rstrip("/\\"), self.os_type)
			item.setData(Qt.UserRole, full)

			self.table.setItem(row, 0, item)
			self.table.setItem(row, 1, QTableWidgetItem(type_label))
			self.table.setItem(row, 2, QTableWidgetItem(f"{size:,}" if size else ""))
		self.table.setUpdatesEnabled(True)

		self._fill_index = end
		self.status_lbl.setText(f"Loaded {end:,} / {len(self._pending_rows):,}")

		if end >= len(self._pending_rows):
			self._fill_timer.stop()
			self.table.setSortingEnabled(True)
			self.status_lbl.setText(f"{len(self._pending_rows):,} item(s)")
			# optional: auto-sort by Name on finish
			# self.table.sortItems(0, Qt.AscendingOrder)
			self._pending_rows = []

	# ---- Actions ----
	def _go_up(self):
		p = (self.cur_path or "").rstrip("/\\")
		if self.os_type == "windows":
			if len(p) <= 3:  # "C:\" (or shorter) => stay
				return
			idx = p.rfind("\\")
			newp = p[:idx] if idx > 2 else p
		else:
			if p == "/":
				return
			idx = p.rfind("/")
			newp = p[:idx] if idx > 0 else "/"
		self._navigate_to(newp, add_to_history=True)

	def _dbl(self, row: int, _col: int):
		it = self.table.item(row, 0)
		if not it:
			return
		is_dir = isinstance(it, _NameItem) and it.is_dir
		full = it.data(Qt.UserRole) or _join_path(self.cur_path, it.text().rstrip("/\\"), self.os_type)
		if is_dir:
			self._navigate_to(full, add_to_history=True)
		else:
			self.selected_path = full
			self.accept()

	def _choose_selected(self):
		sel = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
		if not sel:
			return
		r = sel[0].row()
		it = self.table.item(r, 0)
		if not it:
			return
		if isinstance(it, _NameItem) and it.is_dir:
			full = it.data(Qt.UserRole) or _join_path(self.cur_path, it.text().rstrip("/\\"), self.os_type)
			self._navigate_to(full, add_to_history=True)
			return
		self.selected_path = it.data(Qt.UserRole) or ""
		self.accept()

class RemoteSaveDialog(RemoteOpenDialog):
	"""Same remote browser, but with a filename field and 'Save' semantics."""
	def __init__(self, fws: FilesWSClient, sid: str, os_type: str, start_path: str, suggested_name: str = "untitled.txt"):
		super().__init__(fws, sid, os_type, start_path)
		self.setWindowTitle("Save As…")

		# Add filename row above the buttons
		row = QHBoxLayout()
		self.name_edit = QLineEdit(suggested_name, self)
		self.name_edit.setPlaceholderText("File name")
		row.addWidget(QLabel("Name:", self))
		row.addWidget(self.name_edit, 1)
		self.layout().itemAt(0).widget().layout().insertLayout(2, row)  # insert above table

		# Tweak buttons
		self.btn_open.setText("Save")
		self.btn_open.setDefault(True)

	def _dbl(self, row: int, _col: int):
		# Double-click a file pre-fills the name field instead of immediately accepting
		item = self.table.item(row, 0)
		if not item:
			return
		name = item.text().rstrip("/\\")
		is_dir = isinstance(item, _NameItem) and item.is_dir
		if is_dir:
			self._list(_join_path(self.cur_path, name, self.os_type))
		else:
			self.name_edit.setText(name)

	def _choose_selected(self):
		# If a folder is selected, enter it; else save to current folder + filename
		rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
		if rows:
			r = rows[0].row()
			item = self.table.item(r, 0)
			if isinstance(item, _NameItem) and item.is_dir:
				self._list(_join_path(self.cur_path, item.text().rstrip("/\\"), self.os_type))
				return
		name = (self.name_edit.text() or "").strip()
		if not name:
			QMessageBox.information(self, "Save As", "Please enter a file name.")
			return
		self.selected_path = _join_path(self.cur_path, name, self.os_type)
		self.accept()


# ---------- Editor page ----------

class _EditorPage(QWidget):
	"""One tab = one file."""
	def __init__(self, title: str, remote_path: str, initial_text: str,
				 save_func: Callable[[str, str, Callable[[bool, str], None]], None]):
		super().__init__()
		self.remote_path = remote_path
		self._save_func = save_func
		self._dirty = False
		self._saving = False

		lay = QVBoxLayout(self)
		lay.setContentsMargins(0, 0, 0, 0)
		lay.setSpacing(0)

		self.editor = QPlainTextEdit(self)
		self.editor.setFrameShape(QPlainTextEdit.NoFrame)
		self._set_mono(self.editor)
		self.editor.setTabStopDistance(4 * self.editor.fontMetrics().averageCharWidth())
		self.editor.setPlainText(initial_text or "")
		self.editor.textChanged.connect(self._on_text_changed)

		self.status = QLabel("", self)
		self.status.setStyleSheet("color:#8a93a3; padding:4px 10px;")
		self.status.setVisible(False)

		lay.addWidget(self.editor, 1)
		lay.addWidget(self.status, 0)

	# --- helpers ---
	def _set_mono(self, w: QWidget):
		f = QFont()
		for fam in ("Fira Code", "JetBrains Mono", "Cascadia Code", "DejaVu Sans Mono", "Monospace"):
			f.setFamily(fam)
			w.setFont(f)
			if w.fontInfo().family() == fam:
				break
		f.setPointSizeF(max(10.0, w.fontInfo().pointSizeF()))

	def _on_text_changed(self):
		if not self._dirty:
			self._dirty = True
			self._update_title_mark()

	def set_text_if_clean(self, text: str):
		"""Refresh content only if user hasn't edited."""
		if not self._dirty:
			self.editor.blockSignals(True)
			self.editor.setPlainText(text or "")
			self.editor.blockSignals(False)
			self._dirty = False
			self._update_title_mark()

	def mark_saved(self):
		self._dirty = False
		self._saving = False
		self._update_title_mark()
		self.show_status("Saved")

	def mark_saving(self):
		self._saving = True
		self.show_status("Saving…")

	def show_status(self, msg: str):
		self.status.setText(msg)
		self.status.setVisible(True)

	def clear_status(self):
		self.status.clear()
		self.status.setVisible(False)

	def _update_title_mark(self):
		parent = self.parent()
		if isinstance(parent, QTabWidget):
			idx = parent.indexOf(self)
			if idx >= 0:
				txt = parent.tabText(idx).rstrip(" •")
				parent.setTabText(idx, txt + (" •" if self._dirty else ""))

	def do_save(self, done_cb: Callable[[bool, str], None]):
		if self._saving:
			self.show_status("Save already in progress…")
			return
		self.mark_saving()
		try:
			self._save_func(self.remote_path, self.editor.toPlainText(), done_cb)
		except Exception as e:
			self._saving = False
			done_cb(False, str(e))


# ---------- Main window ----------

class GunnerEditorWindow(QWidget):
	"""
	Frameless, rounded, shadowed editor window with tab management.
	Exposed API expected by FileBrowser:
		- GunnerEditorWindow.get_or_create(owner) -> GunnerEditorWindow
		- open_or_focus(title=..., remote_path=..., initial_text=..., save_func=...)
	"""
	_instance: Optional["GunnerEditorWindow"] = None

	# ---------- Singleton factory ----------
	@classmethod
	def get_or_create(cls, owner=None) -> "GunnerEditorWindow":
		if cls._instance is None:
			cls._instance = cls()
		if owner is not None:
			cls._instance._capture_agent_from_owner(owner)
		cls._instance.show()
		cls._instance.raise_()
		cls._instance.activateWindow()
		return cls._instance

	# ---------- Window ----------
	def __init__(self):
		super().__init__(None, Qt.Window | Qt.FramelessWindowHint)
		self.setAttribute(Qt.WA_TranslucentBackground, True)

		# agent ctx (filled by _capture_agent_from_owner)
		self._api_base_url: Optional[str] = None
		self._api_token: Optional[str] = None
		self._sid: Optional[str] = None
		self._os_type: str = ""
		self.fws: Optional[FilesWSClient] = None

		# download/save state for editor-initiated opens
		self._edl_active = False
		self._edl_remote = None
		self._edl_name = None
		self._edl_buf = bytearray()
		self._editor_save_inflight = False
		self._editor_save_tmp = None
		self._editor_save_done = None

		outer = QVBoxLayout(self)
		outer.setContentsMargins(14, 14, 14, 14)
		outer.setSpacing(0)

		self.chrome = QWidget(self)
		self.chrome.setObjectName("Chrome")
		self.chrome.setStyleSheet(f"""
			QWidget#Chrome {{
				background-color: #2a2e36;
				border-radius: {RADIUS}px;
			}}
			QPlainTextEdit {{
				background: transparent;
				color: #e8e8e8;
				border: none;
				selection-background-color: rgba(255,255,255,0.18);
			}}
			QTabWidget::pane {{ border: 0; }}
			QTabBar::tab {{
				background:#131a26; border:1px solid #273245; padding:6px 10px; margin-right:6px;
				border-top-left-radius:8px; border-top-right-radius:8px; color:#e8e8e8;
			}}
			QTabBar::tab:selected {{ background:#192235; }}
		""")
		outer.addWidget(self.chrome)

		shadow = QGraphicsDropShadowEffect(self.chrome)
		shadow.setBlurRadius(SHADOW_BLUR)
		shadow.setOffset(0, SHADOW_YOFF)
		shadow.setColor(Qt.black)
		self.chrome.setGraphicsEffect(shadow)

		v = QVBoxLayout(self.chrome)
		v.setContentsMargins(0, 0, 0, 0)
		v.setSpacing(6)  # <— small gap so the titlebar controls don't overlap the tab bar

		# Title bar
		self.titlebar = self._make_titlebar()
		v.addWidget(self.titlebar)

		# Add File menu (lives in the TitleBar menubar)
		self._add_file_menu()

		self._untitled_counter = 1  # <— track “Untitled” numbering

		# Tabs
		self.tabs = QTabWidget(self.chrome)
		self.tabs.setDocumentMode(True)
		self.tabs.setTabsClosable(True)
		self.tabs.tabCloseRequested.connect(self._close_tab)
		v.addWidget(self.tabs, 1)

		self._install_plus_corner_button()

		# Right-click context menu on tabs
		tb = self.tabs.tabBar()
		tb.setContextMenuPolicy(Qt.CustomContextMenu)
		tb.customContextMenuRequested.connect(self._show_tab_context_menu)

		# Drag to reorder (Sublime-style)
		self.tabs.tabBar().setMovable(True)

		# --- actions (create once) ---
		self.act_open = QAction("Open File…", self)
		self.act_open.setShortcut("Ctrl+O")
		self.act_open.setShortcutContext(Qt.WidgetWithChildrenShortcut)
		self.act_open.triggered.connect(self._open_remote_file)
		self.addAction(self.act_open)

		self.act_save = QAction("Save", self)
		self.act_save.setShortcut("Ctrl+S")
		self.act_save.setShortcutContext(Qt.WidgetWithChildrenShortcut)
		self.act_save.triggered.connect(self._save_current)
		self.addAction(self.act_save)

		self.act_save_as = QAction("Save As…", self)
		self.act_save_as.setShortcut("Ctrl+Shift+S")
		self.act_save_as.setShortcutContext(Qt.WidgetWithChildrenShortcut)
		self.act_save_as.triggered.connect(self._save_as_current)
		self.addAction(self.act_save_as)

		self.act_new = QAction("New Tab", self)
		self.act_new.setShortcut("Ctrl+T")   # keep consistent with the + tooltip
		self.act_new.setShortcutContext(Qt.WidgetWithChildrenShortcut)
		self.act_new.triggered.connect(self._new_blank_tab)
		self.addAction(self.act_new)

		self.act_new = QAction("New Tab", self)
		self.act_new.setShortcut("Ctrl+Shift+T")   # keep consistent with the + tooltip
		self.act_new.setShortcutContext(Qt.WidgetWithChildrenShortcut)
		self.act_new.triggered.connect(self._new_blank_tab)
		self.addAction(self.act_new)

		QShortcut("Ctrl+W", self, activated=self._close_current)
		QShortcut("Ctrl+Tab", self, activated=self._next_tab)
		QShortcut("Ctrl+Shift+Tab", self, activated=self._prev_tab)

		# Window basics
		if QApplication.windowIcon().isNull():
			self.setWindowIcon(self.style().standardIcon(QStyle.SP_FileIcon))
		self.resize(1000, 720)
		self._center_on_screen()
		self.installEventFilter(self)

		# Track pages by remote path
		self._by_remote: Dict[str, _EditorPage] = {}

	def _make_titlebar(self) -> TitleBar:
		try:
			return TitleBar(owner_window=self, dashboard=None)
		except TypeError:
			try:
				return TitleBar(self, None)  # old: (owner_window, dashboard)
			except TypeError:
				return TitleBar(self)        # very old: (owner_window)

	def _add_file_menu(self):
		m = QMenu("File", self.titlebar)

		act_open = m.addAction("Open File…")
		act_open.triggered.connect(self._open_remote_file)

		m.addSeparator()

		act_save = m.addAction("Save")
		act_save.triggered.connect(self._save_current)

		act_save_as = m.addAction("Save As…")
		act_save_as.triggered.connect(self._save_as_current)

		self.titlebar.menubar.addMenu(m)

	def _is_tab_closable(self, index: int) -> bool:
		# For now, editor tabs are closable; if you have "pinned"/special tabs,
		# set a property on their widget: w.setProperty("closable", False)
		w = self.tabs.widget(index)
		if not w:
			return True
		v = w.property("closable")
		return True if v is None else bool(v)

	def _show_tab_context_menu(self, pos: QPoint):
		tb = self.tabs.tabBar()
		idx = tb.tabAt(pos)
		if idx < 0:
			return

		menu = QMenu(self)
		sub = menu.addMenu("Close")

		act_close = QAction("Close This Tab", self)
		act_close.setEnabled(self._is_tab_closable(idx))
		act_close.triggered.connect(lambda: self._close_tab(idx))
		sub.addAction(act_close)

		# Determine availability for left/right/others
		n = self.tabs.count()
		any_left  = any(self._is_tab_closable(i) for i in range(0, idx))
		any_right = any(self._is_tab_closable(i) for i in range(idx+1, n))
		any_others = any_left or any_right

		act_left = QAction("Close Tabs to the Left", self)
		act_left.setEnabled(any_left)
		act_left.triggered.connect(lambda: self._close_tabs_left(idx))
		sub.addAction(act_left)

		act_right = QAction("Close Tabs to the Right", self)
		act_right.setEnabled(any_right)
		act_right.triggered.connect(lambda: self._close_tabs_right(idx))
		sub.addAction(act_right)

		act_others = QAction("Close Other Tabs", self)
		act_others.setEnabled(any_others and self._is_tab_closable(idx))  # keep current open
		act_others.triggered.connect(lambda: self._close_tabs_others(idx))
		sub.addAction(act_others)

		menu.exec_(tb.mapToGlobal(pos))

	def _close_tabs_left(self, idx: int):
		for i in range(idx - 1, -1, -1):
			if self._is_tab_closable(i):
				self._close_tab(i)

	def _close_tabs_right(self, idx: int):
		for i in range(self.tabs.count() - 1, idx, -1):
			if self._is_tab_closable(i):
				self._close_tab(i)

	def _close_tabs_others(self, idx: int):
		self._close_tabs_right(idx)
		self._close_tabs_left(idx)

	def _apply_per_tab_close_button(self, index: int):
		if not self._is_tab_closable(index):
			self.tabs.tabBar().setTabButton(index, QTabBar.RightSide, None)

	def _install_plus_corner_button(self):
		# Button itself
		btn = QToolButton(self.tabs)
		btn.setObjectName("PlusTabBtn")
		btn.setText("＋")  # full-width plus looks crisp at small sizes
		btn.setToolTip("New Tab (Ctrl+N)")
		btn.setCursor(Qt.PointingHandCursor)
		btn.setAutoRaise(True)
		btn.setFixedSize(28, 28)

		# Subtle “aura”
		glow = QGraphicsDropShadowEffect(btn)
		glow.setBlurRadius(18)
		glow.setOffset(0, 2)
		glow.setColor(QColor(0, 0, 0, 140))
		btn.setGraphicsEffect(glow)

		btn.setStyleSheet("""
			QToolButton#PlusTabBtn {
				background: #0f1726;
				color: #eef3ff;
				border: 1px solid #2f3e57;
				border-radius: 14px;      /* 28x28 -> circle */
				font-weight: 700;
				font-size: 16px;
				padding: 0;
			}
			QToolButton#PlusTabBtn:hover {
				background: #1a2740;
				border-color: #5c7196;
			}
			QToolButton#PlusTabBtn:pressed {
				background: #0c1524;
			}
			QToolButton#PlusTabBtn:disabled {
				color: #6c778a;
				border-color: #263445;
			}
		""")
		btn.clicked.connect(self._new_blank_tab)

		# Wrap to add a little right/top padding so it doesn't touch the edges
		wrap = QWidget(self.tabs)
		lay = QHBoxLayout(wrap)
		lay.setContentsMargins(8, 4, 10, 0)  # left, top, right, bottom
		lay.setSpacing(0)
		lay.addWidget(btn)
		self.tabs.setCornerWidget(wrap, Qt.TopRightCorner)

		self._plus_btn = btn  # keep a ref (optional)

	def _new_blank_tab(self):
		existing = {self.tabs.tabText(i) for i in range(self.tabs.count())}
		n = 1
		title = f"untitled-{n}.txt"
		while title in existing:
			n += 1
			title = f"untitled-{n}.txt"

		remote = f"untitled://{uuid.uuid4().hex[:8]}"

		page = _EditorPage(title, remote, "", lambda r, t, cb: None)
		idx = self.tabs.addTab(page, title)
		self.tabs.setCurrentIndex(idx)
		self._by_remote[remote] = page
		self._apply_per_tab_close_button(idx)
		self._retitle_window()

		def _save_untitled(_remote, text, done_cb, p=page):
			self._save_as_for_page(p, text, done_cb)
		page._save_func = _save_untitled

	def _save_as_current(self):
		page = self._current_page()
		if not page:
			return
		self._save_as_for_page(page, page.editor.toPlainText(), done_cb=None)

	def _save_as_for_page(self, page: "_EditorPage", text: str, done_cb):
		if not (self.fws and self._sid):
			if callable(done_cb): done_cb(False, "No agent connection.")
			else: QMessageBox.critical(self, "Save As", "No agent connection.")
			return

		base = self._start_path or ("C:\\" if (self._os_type or "").lower()=="windows" else "/")
		suggested = _basename_for_label(page.remote_path) if page.remote_path and not str(page.remote_path).startswith("untitled://") else "untitled.txt"

		dlg = RemoteSaveDialog(self.fws, self._sid, self._os_type, base, suggested_name=suggested)
		dlg.setModal(True)
		if dlg.exec_() != QDialog.Accepted or not dlg.selected_path:
			if callable(done_cb): done_cb(False, "Cancelled")
			return

		remote_path = dlg.selected_path

		def _done(ok: bool, msg: str):
			if ok:
				old_key = page.remote_path
				page.remote_path = remote_path
				title = _basename_for_label(remote_path) or "untitled.txt"
				idx = self.tabs.indexOf(page)
				if idx >= 0:
					self.tabs.setTabText(idx, title)
					self._apply_per_tab_close_button(idx)
				if old_key in self._by_remote:
					self._by_remote.pop(old_key, None)
				self._by_remote[remote_path] = page
				page.mark_saved()
				if callable(done_cb): done_cb(True, "")
			else:
				page.show_status("Save failed: " + (msg or ""))
				QMessageBox.critical(self, "Save As", msg or "Failed to save")
				if callable(done_cb): done_cb(False, msg or "")

		self._save_text_back_to_remote(remote_path, text, _done)

	# ---------- Public API ----------
	def open_or_focus(self, *, title: str, remote_path: str,
					  initial_text: str, save_func: Callable[[str, str, Callable[[bool, str], None]], None]):
		"""If remote already open, focus it; else add a new tab."""
		self.show(); self.raise_(); self.activateWindow()

		page = self._by_remote.get(remote_path)
		if page is None:
			page = _EditorPage(title, remote_path, initial_text, save_func)
			idx = self.tabs.addTab(page, title)
			self.tabs.setCurrentIndex(idx)
			self._by_remote[remote_path] = page
		else:
			idx = self.tabs.indexOf(page)
			if idx >= 0:
				self.tabs.setCurrentIndex(idx)
			page.set_text_if_clean(initial_text)
		self._retitle_window()

	# ---------- Agent context ----------
	def _capture_agent_from_owner(self, owner):
		"""Pick up API+sid from FileBrowser (or any host with .api, .sid, .os_type, .path)."""
		try:
			api = getattr(owner, "api", None)
			if api is None:
				return
			self._api_base_url = getattr(api, "base_url", None)
			self._api_token = getattr(api, "token", None)
			self._sid = getattr(owner, "sid", None)
			self._os_type = getattr(owner, "os_type", "") or ""
			if self.fws is None and self._api_base_url and self._api_token:
				self.fws = FilesWSClient(self._api_base_url, self._api_token, self)
				# DL/saves for editor-initiated opens
				try:
					self.fws.dl_begin.connect(self._on_dl_begin)
					self.fws.dl_chunk.connect(self._on_dl_chunk)
					self.fws.dl_end.connect(self._on_dl_end)
					self.fws.up_result.connect(self._on_up_result)
				except Exception:
					pass
				self.fws.open()
		except Exception:
			pass
		# Remember a reasonable start path for the picker
		self._start_path = getattr(owner, "path", None)

	# ---------- Remote "Open File…" ----------
	def _open_remote_file(self):
		if not (self.fws and self._sid):
			QMessageBox.information(self, "Open File", "No agent context yet. Open a file from the Files tab first, then use File → Open File…")
			return
		start = _norm_path(self._start_path or ( "C:\\" if (self._os_type or "").lower()=="windows" else "/" ), self._os_type)
		dlg = RemoteOpenDialog(self.fws, self._sid, self._os_type, start)
		dlg.setModal(True)
		if dlg.exec_() == QDialog.Accepted and dlg.selected_path:
			self._download_and_open(dlg.selected_path)

	def _download_and_open(self, remote_path: str):
		# capture name and kick download
		name = _basename_for_label(remote_path)
		self._edl_active = True
		self._edl_remote = remote_path
		self._edl_name = name
		self._edl_buf = bytearray()
		try:
			self.fws.start_download(self._sid, remote_path)
		except Exception as e:
			self._edl_active = False
			QMessageBox.critical(self, "Open", f"{e}")

	# ---------- Save path for editor-initiated tabs ----------
	def _save_text_back_to_remote(self, remote_path: str, text: str, done_cb):
		if getattr(self, "_editor_save_inflight", False):
			done_cb(False, "Another save is already in progress; please retry in a moment.")
			return
		if not (self.fws and self._sid):
			done_cb(False, "No agent connection.")
			return
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
		self._editor_save_inflight = True
		self._editor_save_tmp = tmp
		self._editor_save_done = done_cb
		try:
			self.fws.start_upload(self._sid, tmp, remote_path)
		except Exception as e:
			self._editor_save_inflight = False
			try:
				os.remove(tmp)
			except Exception:
				pass
			done_cb(False, str(e))

	# ---------- WS callbacks (download/upload) ----------
	def _on_dl_begin(self, *_):
		pass

	def _on_dl_chunk(self, data: bytes):
		if getattr(self, "_edl_active", False):
			try:
				self._edl_buf.extend(bytes(data or b""))
			except Exception:
				pass

	def _on_dl_end(self, *_):
		if not getattr(self, "_edl_active", False):
			return
		data = bytes(getattr(self, "_edl_buf", b"") or b"")
		remote = getattr(self, "_edl_remote", "")
		name = getattr(self, "_edl_name", "file")
		# clear flags
		self._edl_active = False
		self._edl_buf = bytearray()
		self._edl_remote = None
		self._edl_name = None

		if not data:
			QMessageBox.critical(self, "Open", "Failed to open or empty file.")
			return

		text, enc = self._decode_text_for_editor(data)
		self.open_or_focus(
			title=name,
			remote_path=remote,
			initial_text=text,
			save_func=lambda r, t, cb: self._save_text_back_to_remote(r, t, cb),
		)

	def _on_up_result(self, *args):
		# Accept a few possible signatures from FilesWSClient
		ok = False
		err = ""
		if len(args) >= 1:
			ok = bool(args[0])
		if len(args) >= 3:
			err = args[2] or ""
		elif len(args) == 2:
			err = args[1] or ""
		cb = getattr(self, "_editor_save_done", None)
		tmp = getattr(self, "_editor_save_tmp", None)
		self._editor_save_inflight = False
		self._editor_save_tmp = None
		self._editor_save_done = None
		try:
			if tmp and os.path.exists(tmp):
				os.remove(tmp)
		except Exception:
			pass
		if callable(cb):
			cb(bool(ok), err or "")

	# ---------- Text decode ----------
	def _decode_text_for_editor(self, data: bytes) -> tuple[str, str]:
		for enc in ("utf-8-sig", "utf-16-le", "utf-16-be", "utf-8"):
			try:
				return data.decode(enc), enc
			except Exception:
				pass
		return data.decode("latin-1", errors="replace"), "latin-1"

	# ---------- Window internals ----------
	def _center_on_screen(self):
		scr = QApplication.primaryScreen()
		if not scr:
			return
		ag = scr.availableGeometry()
		self.move(ag.center() - self.rect().center())

	def _retitle_window(self):
		idx = self.tabs.currentIndex()
		self.setWindowTitle("Editor" if idx < 0 else self.tabs.tabText(idx).rstrip(" •"))

	def _save_current(self):
		page = self._current_page()
		if not page:
			return
		def done(ok: bool, msg: str):
			if ok:
				page.mark_saved()
			else:
				page.show_status("Save failed: " + (msg or ""))
				QMessageBox.critical(self, "Save", msg or "Failed to save")
		page.do_save(done)

	def _close_current(self):
		idx = self.tabs.currentIndex()
		if idx >= 0:
			self._close_tab(idx)

	def _next_tab(self):  # Ctrl+Tab
		n = self.tabs.count()
		if n:
			self.tabs.setCurrentIndex((self.tabs.currentIndex() + 1) % n)

	def _prev_tab(self):  # Ctrl+Shift+Tab
		n = self.tabs.count()
		if n:
			self.tabs.setCurrentIndex((self.tabs.currentIndex() - 1 + n) % n)

	def _current_page(self) -> Optional[_EditorPage]:
		w = self.tabs.currentWidget()
		return w if isinstance(w, _EditorPage) else None

	def _close_tab(self, index: int):
		w = self.tabs.widget(index)
		if isinstance(w, _EditorPage):
			# (Optional) prompt if dirty
			self._by_remote.pop(w.remote_path, None)
		self.tabs.removeTab(index)
		self._retitle_window()

	# Rounded corners collapse when maximized, restore when normal
	def eventFilter(self, obj, ev):
		if ev.type() in (QEvent.Resize, QEvent.WindowStateChange):
			radius = 0 if self.isMaximized() else RADIUS
			self.chrome.setStyleSheet(
				f"QWidget#Chrome {{ background-color:#2a2e36; border-radius:{radius}px; }} "
				"QPlainTextEdit { background: transparent; color:#e8e8e8; border: none; "
				"selection-background-color: rgba(255,255,255,0.18); }"
				"QTabWidget::pane { border:0; }"
				"QTabBar::tab { background:#131a26; border:1px solid #273245; padding:6px 10px; margin-right:6px; "
				"border-top-left-radius:8px; border-top-right-radius:8px; color:#e8e8e8; }"
				"QTabBar::tab:selected { background:#192235; }"
			)
		if ev.type() == QEvent.WindowActivate:
			self._retitle_window()
		return super().eventFilter(obj, ev)

	def closeEvent(self, e):
		type(self)._instance = None
		return super().closeEvent(e)
