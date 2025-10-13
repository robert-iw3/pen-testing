# gui/title_bar.py
from PyQt5.QtCore import Qt, QPoint, QEvent, QTimer, QSize, QRectF, QRect, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QCursor, QIcon, QPixmap, QPainter, QPen, QBrush, QColor, QGuiApplication

from PyQt5.QtWidgets import (
	QWidget, QHBoxLayout, QLabel, QMenuBar, QMenu, QPushButton,
	QSizePolicy, QStyle, QApplication, QAction, QCheckBox, QWidgetAction
)

from theme_center import theme_color, ThemeManager

# ===================== styled menu checkbox rows ============================

# ---- helpers: convert QColor → CSS string acceptable to QSS --------------
def _css_color(c) -> str:
	"""Return '#RRGGBB' or 'rgba(r,g,b,a)' for a QColor or passthrough string."""
	if isinstance(c, QColor):
		r, g, b, a = c.red(), c.green(), c.blue(), c.alpha()
		if a < 255:
			return f"rgba({r},{g},{b},{a})"
		return f"#{r:02x}{g:02x}{b:02x}"
	# already a string like '#23272e'
	return str(c)

def _menu_check_icon(checked: bool, size: int = 18) -> QIcon:
	"""Rounded box & crisp tick, tinted by theme colors."""
	pm = QPixmap(size, size)
	pm.fill(Qt.transparent)
	p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing, True)
	border = QColor(theme_color("accent", "#6a93ff"))
	fill   = QColor(theme_color("accent", "#6a93ff")) if checked else QColor(0, 0, 0, 0)
	p.setPen(QPen(border, 2))
	p.setBrush(QBrush(fill))
	r = QRectF(1, 1, size-2, size-2)
	p.drawRoundedRect(r, 5, 5)
	if checked:
		p.setPen(QPen(Qt.white, 2.6, cap=Qt.RoundCap, join=Qt.RoundJoin))
		x = size
		p.drawLine(int(x*0.25), int(x*0.55), int(x*0.45), int(x*0.75))
		p.drawLine(int(x*0.45), int(x*0.75), int(x*0.78), int(x*0.34))
	p.end()
	return QIcon(pm)

def _row_stylesheet() -> str:
	# Make rows look native to the menu: no persistent border, soft hover wash.
	fg = _css_color(theme_color("menu_fg", "#e8e8e8"))
	#hover_overlay = "rgba(255,255,255,15)"  # ~6% alpha (Qt needs 0–255)
	return f"""
		QWidget#MenuRow {{
			background-color: transparent;
			border: 0px;
			border-radius: 8px;
		}}
		QWidget#MenuRow[hover="true"] {{
			background-color: transparent;
		}}
		QLabel#MenuText {{ color: {fg}; }}
	"""

def _apply_row_style(row: QWidget) -> None:
	row.setStyleSheet(_row_stylesheet())

def _add_menu_checkbox_row(menu: QMenu, text: str, checked: bool, on_toggled):
	"""
	QWidgetAction row with a custom icon + label. Clicking anywhere toggles.
	Menus stay open (no triggered QAction).
	"""
	act = QWidgetAction(menu)
	row = QWidget(menu); row.setObjectName("MenuRow")
	row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
	lay = QHBoxLayout(row); lay.setContentsMargins(10, 6, 10, 6); lay.setSpacing(10)
	icon = QLabel(row)
	icon.setFixedSize(18, 18)
	icon.setPixmap(_menu_check_icon(checked).pixmap(18, 18))
	label = QLabel(text, row); label.setObjectName("MenuText")

	lay.addWidget(icon)
	lay.addWidget(label, 1)
	lay.addStretch(1)  # ensure the row claims full menu width

	# hidden checkbox to own the state & signals
	cb = QCheckBox(row); cb.setChecked(checked); cb.hide()
	cb.toggled.connect(on_toggled)
	cb.toggled.connect(lambda v, lab=icon: lab.setPixmap(_menu_check_icon(v).pixmap(18, 18)))
	# hover styling via dynamic property
	def enterEvent(_):
		row.setProperty("hover", True); _apply_row_style(row)
	def leaveEvent(_):
		row.setProperty("hover", False); _apply_row_style(row)
	row.enterEvent = enterEvent
	row.leaveEvent = leaveEvent
	# click anywhere on the row
	def mousePressEvent(e):
		cb.toggle(); e.accept()
	row.mousePressEvent = mousePressEvent
	_apply_row_style(row)
	act.setDefaultWidget(row)
	menu.addAction(act)
	return cb, row, icon

def _hide_qmenu_indicator(menu: QMenu, *, min_width: int | None = None) -> None:
	# Hide built-in indicators and ensure the menu's items don't draw
	# mismatched backgrounds behind our QWidgetAction rows.
	bg = _css_color(theme_color("menu_bg", "#23272e"))
	br = _css_color(theme_color("menu_border", "#3b404a"))
	mw = f"min-width: {min_width}px;" if min_width else ""
	menu.setStyleSheet(
		"QMenu {"
		f"  background-color: {bg};"
		f"  border: 1px solid {br};"
		"  border-radius: 10px;"
		"  padding: 6px;"
		f"  {mw}"
		"}"
		"QMenu::item {"
		"  padding: 0px;"
		"  background-color: transparent;"
		"  border: none;"
		"}"
		"QMenu::item:selected {"
		"  background-color: transparent;"
		"  border-radius: 0px;"
		"}"
		"QMenu::indicator { width:0px; height:0px; }"
	)

def _retint_menu_rows(rows) -> None:
	"""Re-apply colors & icons after a theme change."""
	for row, icon_label, cb in rows:
		_apply_row_style(row)
		icon_label.setPixmap(_menu_check_icon(cb.isChecked()).pixmap(18, 18))

class _SnapOverlay(QWidget):
	def __init__(self):
		super().__init__(None, Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
		self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
		self.setAttribute(Qt.WA_NoSystemBackground, True)
		self.setAttribute(Qt.WA_TranslucentBackground, True)
		self._rect = QRect()
		self._radius = 12

	def show_rect(self, rect: QRect):
		self._rect = QRect(rect)
		self.setGeometry(self._rect)
		self.show()
		self.raise_()
		self.update()

	def hide_rect(self):
		self.hide()

	def paintEvent(self, _):
		if self._rect.isNull():
			return
		p = QPainter(self); p.setRenderHint(QPainter.Antialiasing, True)
		# Fill
		p.setBrush(QColor(102, 176, 255, 60))    # soft Win11-ish blue wash
		p.setPen(QPen(QColor(102, 176, 255, 160), 2))
		p.drawRoundedRect(self.rect().adjusted(1,1,-1,-1), self._radius, self._radius)
		p.end()


class _SnapAssist:
	"""
	Lightweight snap assist:
	  - call on_drag_move(globalPos) repeatedly during a drag
	  - call on_drag_release(globalPos) at mouse release to perform the snap animation
	  - call detach_anim(from_geo, to_geo) to animate the tear-off
	"""
	def __init__(self, win: QWidget):
		self.win = win
		self.overlay = _SnapOverlay()
		self.edge_px = 18            # proximity to screen edge
		self.corner_px = 96          # corner zone width/height
		self.snap_target = None      # QRect or None
		self._snap_anim = None

	def _avail_geo(self, gpos: QPoint) -> QRect:
		scr = QGuiApplication.screenAt(gpos) or self.win.screen()
		return scr.availableGeometry()

	def _half(self, ag: QRect, left=False, right=False) -> QRect:
		if left:
			return QRect(ag.left(), ag.top(), ag.width()//2, ag.height())
		if right:
			return QRect(ag.left()+ag.width()//2, ag.top(), ag.width()//2, ag.height())
		return ag

	def _quarter(self, ag: QRect, tl=False, tr=False, bl=False, br=False) -> QRect:
		w2, h2 = ag.width()//2, ag.height()//2
		if tl: return QRect(ag.left(), ag.top(), w2, h2)
		if tr: return QRect(ag.left()+w2, ag.top(), w2, h2)
		if bl: return QRect(ag.left(), ag.top()+h2, w2, h2)
		if br: return QRect(ag.left()+w2, ag.top()+h2, w2, h2)
		return ag

	def _max(self, ag: QRect) -> QRect:
		return ag

	def _compute_target(self, gpos: QPoint) -> QRect | None:
		ag = self._avail_geo(gpos)
		x, y = gpos.x(), gpos.y()

		near_left   = abs(x - ag.left())   <= self.edge_px
		near_right  = abs(x - ag.right())  <= self.edge_px
		near_top    = abs(y - ag.top())    <= self.edge_px
		near_bottom = abs(y - ag.bottom()) <= self.edge_px

		in_left_corner   = (x - ag.left()   <= self.corner_px)
		in_right_corner  = (ag.right() - x  <= self.corner_px)
		in_top_corner    = (y - ag.top()    <= self.corner_px)
		in_bottom_corner = (ag.bottom() - y <= self.corner_px)

		# Corners → quarters
		if (near_top or near_left) and in_left_corner and in_top_corner:
			return self._quarter(ag, tl=True)
		if (near_top or near_right) and in_right_corner and in_top_corner:
			return self._quarter(ag, tr=True)
		if (near_bottom or near_left) and in_left_corner and in_bottom_corner:
			return self._quarter(ag, bl=True)
		if (near_bottom or near_right) and in_right_corner and in_bottom_corner:
			return self._quarter(ag, br=True)

		# Edges → halves/max
		if near_left:
			return self._half(ag, left=True)
		if near_right:
			return self._half(ag, right=True)
		if near_top:
			return self._max(ag)

		# (Optional) bottom edge could be bottom half; Win11 doesn't do this on drag, so skip.
		return None

	def on_drag_move(self, gpos: QPoint):
		target = self._compute_target(gpos)
		if target is None:
			self.snap_target = None
			self.overlay.hide_rect()
		else:
			if self.snap_target != target:
				self.snap_target = target
				self.overlay.show_rect(target)

	def on_drag_release(self, gpos: QPoint):
		target = self._compute_target(gpos)
		self.overlay.hide_rect()
		self.snap_target = None
		if not target:
			return False
		# animate geometry to target
		self._animate_to(target, duration=170)
		return True

	def detach_anim(self, from_geo: QRect, to_geo: QRect, duration=120):
		self._animate_between(from_geo, to_geo, duration)

	def _animate_to(self, to_geo: QRect, duration=170):
		self._animate_between(self.win.geometry(), to_geo, duration)

	def _animate_between(self, g0: QRect, g1: QRect, duration=150):
		if self._snap_anim and self._snap_anim.state() == QPropertyAnimation.Running:
			self._snap_anim.stop()
		anim = QPropertyAnimation(self.win, b"geometry", self.win)
		anim.setDuration(duration)
		anim.setStartValue(QRect(g0))
		anim.setEndValue(QRect(g1))
		anim.setEasingCurve(QEasingCurve.OutCubic)
		self._snap_anim = anim
		anim.start()

	def _compute_target_from_window(self, win_geo: QRect) -> QRect | None:
		# Use the screen under the window’s center
		center = win_geo.center()
		scr = QGuiApplication.screenAt(center) or self.win.screen()
		ag = scr.availableGeometry()

		edge_px = self.edge_px
		corner_px = self.corner_px

		near_left   = abs(win_geo.left()   - ag.left())   <= edge_px
		near_right  = abs(win_geo.right()  - ag.right())  <= edge_px
		near_top    = abs(win_geo.top()    - ag.top())    <= edge_px
		near_bottom = abs(win_geo.bottom() - ag.bottom()) <= edge_px

		in_left_corner   = (win_geo.left()   - ag.left()   <= corner_px)
		in_right_corner  = (ag.right()  - win_geo.right()  <= corner_px)
		in_top_corner    = (win_geo.top()    - ag.top()    <= corner_px)
		in_bottom_corner = (ag.bottom() - win_geo.bottom() <= corner_px)

		if (near_top or near_left) and in_left_corner and in_top_corner:
			return self._quarter(ag, tl=True)
		if (near_top or near_right) and in_right_corner and in_top_corner:
			return self._quarter(ag, tr=True)
		if (near_bottom or near_left) and in_left_corner and in_bottom_corner:
			return self._quarter(ag, bl=True)
		if (near_bottom or near_right) and in_right_corner and in_bottom_corner:
			return self._quarter(ag, br=True)

		if near_left:
			return self._half(ag, left=True)
		if near_right:
			return self._half(ag, right=True)
		if near_top:
			return self._max(ag)
		return None

	def on_drag_move_window(self, win_geo: QRect):
		target = self._compute_target_from_window(win_geo)
		if target is None:
			self.snap_target = None
			self.overlay.hide_rect()
		else:
			if self.snap_target != target:
				self.snap_target = target
				self.overlay.show_rect(target)

	def on_drag_release_window(self, win_geo: QRect):
		target = self._compute_target_from_window(win_geo)
		self.overlay.hide_rect()
		self.snap_target = None
		if not target:
			return False
		self._animate_to(target, duration=170)
		return True

# --- menu that closes itself shortly after the cursor leaves ---------------
class _CloseOnLeaveMenu(QMenu):
	def __init__(self, title="", parent=None, leave_delay_ms=80):
		super().__init__(title, parent)
		self.setFocusPolicy(Qt.NoFocus)
		self._leave_timer = QTimer(self)
		self._leave_timer.setSingleShot(True)
		self._leave_timer.setInterval(leave_delay_ms)
		self._leave_timer.timeout.connect(self._maybe_close)
		self._menu_close_delay = leave_delay_ms

		# If we’re a submenu, stop the parent’s close timer when we show.
		p = self.parentWidget()
		if isinstance(p, _CloseOnLeaveMenu):
			self.aboutToShow.connect(p._leave_timer.stop)

	def enterEvent(self, e):
		# Pointer re-entered: cancel our close timer and our parent's (if any)
		self._leave_timer.stop()
		p = self.parentWidget()
		if isinstance(p, _CloseOnLeaveMenu):
			p._leave_timer.stop()
		super().enterEvent(e)

	def leaveEvent(self, e):
		# Start a delayed close; the timeout will verify pointer location first.
		self._leave_timer.start()
		super().leaveEvent(e)

	def event(self, ev):
		# If the app/window deactivates or we lose focus while a popup is up,
		# don't wait on Qt's long default — arm our 80ms close instead.
		if ev.type() in (QEvent.WindowDeactivate, QEvent.FocusOut):
			self._leave_timer.start()
		return super().event(ev)

	def _maybe_close(self):
		"""
		Close unless the cursor is inside me or any visible submenu.
		Works even when the cursor is over non-Qt areas (OS title bar / desktop).
		"""
		gpos = QCursor.pos()

		# inside me?
		if self.isVisible() and self.rect().contains(self.mapFromGlobal(gpos)):
			return

		# inside any visible submenu?
		for sm in self.findChildren(QMenu):
			if sm.isVisible() and sm.rect().contains(sm.mapFromGlobal(gpos)):
				return

		# cursor is nowhere in our popup tree -> close
		self.hide()

	# --- keep menu open when clicking QWidgetAction rows (our custom rows) --
	def mousePressEvent(self, e):
		act = self.actionAt(e.pos())
		if isinstance(act, QWidgetAction):
			# Our row handles the toggle itself; don't let QMenu treat it as triggered.
			e.accept()
			return
		super().mousePressEvent(e)

	def mouseReleaseEvent(self, e):
		act = self.actionAt(e.pos())
		if isinstance(act, QWidgetAction):
			e.accept()
			return
		super().mouseReleaseEvent(e)

class _ClickOnlyMenuBar(QMenuBar):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.setMouseTracking(False)
		self._pressed = False

	# don’t activate actions on hover
	def mouseMoveEvent(self, e):
		if self._pressed:
			super().mouseMoveEvent(e)

	def enterEvent(self, e):
		# avoid hover selection
		self.setActiveAction(None)

	def mousePressEvent(self, e):
		if e.button() == Qt.LeftButton:
			act = self.actionAt(e.pos())
			if act and act.menu():
				self._pressed = True
				self.setActiveAction(act)
				geo = self.actionGeometry(act)
				act.menu().popup(self.mapToGlobal(geo.bottomLeft()))
				e.accept()
				return
		super().mousePressEvent(e)

	def mouseReleaseEvent(self, e):
		self._pressed = False
		super().mouseReleaseEvent(e)

class TitleBar(QWidget):
	def __init__(self, owner_window, dashboard=None, *, with_graph_menus: bool = True):
		super().__init__(owner_window)
		self._win = owner_window
		self._dash = dashboard
		self._menus_enabled = bool(with_graph_menus and dashboard is not None)
		self._drag_pos = None

		self.setFixedHeight(34)
		self.setAutoFillBackground(True)

		R = 14
		self.setStyleSheet(
			"QWidget { background-color:#2a2e36; }"
			"QMenuBar { background:transparent; color:#e8e8e8;"
			"            selection-background-color: transparent;"
			"            selection-color: #e8e8e8; }"
			"QMenuBar::item { padding:6px 10px; margin:0; background-color:transparent; }"
			"QMenuBar::item:selected { background-color:transparent; color:#e8e8e8; }"
			"QMenuBar::item:pressed  { background-color:transparent; color:#e8e8e8; }"
			"QMenuBar::item:on       { background-color:transparent; color:#e8e8e8; }"
			"QMenu { background-color:#23272e; color:#e8e8e8; }"
			"QMenu::item { background-color:transparent; }"
			"QMenu::item:selected { background:rgba(255,255,255,18); }"
			"QPushButton { border:none; background:transparent; }"
			"QPushButton:hover { background:rgba(255,255,255,0.08); }"
			"#AppLogo { background: transparent; border: none; padding: 0; }"
			"#AppLogo:hover { background: rgba(255,255,255,0.04); border-radius:6px; }"

			f"#winClose {{ background:#e74c3c; border:1px solid rgba(255,255,255,0.20);"
			f"            border-radius:{R}px; }}"
			f"#winClose:hover  {{ background:#ff6b5a; border-color:rgba(255,255,255,0.35); }}"
			f"#winClose:pressed{{ background:#c0392b; }}"

			f"#winMax {{ background:#3498db; border:1px solid rgba(255,255,255,0.20);"
			f"          border-radius:{R}px; }}"
			f"#winMax:hover   {{ background:#5dade2; border-color:rgba(255,255,255,0.35); }}"
			f"#winMax:pressed {{ background:#2c81ba; }}"

			f"#winMin {{ background:#f1c40f; border:1px solid rgba(255,255,255,0.20);"
			f"          border-radius:{R}px; }}"
			f"#winMin:hover   {{ background:#f4d03f; border-color:rgba(255,255,255,0.35); }}"
			f"#winMin:pressed {{ background:#cda70d; }}"
		)

		lay = QHBoxLayout(self)
		lay.setContentsMargins(8, 0, 6, 0)
		lay.setSpacing(6)

		# Logo (also draggable)
		self.logo = QLabel()
		self.logo.setPixmap(QApplication.windowIcon().pixmap(18, 18))
		self.logo.setFixedSize(22, 22)
		self.logo.setAlignment(Qt.AlignCenter)
		self.logo.setObjectName("AppLogo")
		lay.addWidget(self.logo, 0, Qt.AlignVCenter)

		# Menubar
		self.menubar = _ClickOnlyMenuBar()
		self.menubar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
		self.menubar.setNativeMenuBar(False)  # stay inside our title bar on macOS too
		lay.addWidget(self.menubar, 1)

		# --- Graph menu (renamed) ------------------------------------------
		CLOSE_DELAY_MS = 80
		self._menu_close_delay = CLOSE_DELAY_MS
		self._menu_watch = QTimer(self)
		self._menu_watch.setInterval(self._menu_close_delay)
		self._menu_watch.timeout.connect(self._menu_watch_tick)

		if self._menus_enabled:
			self.m_graph = _CloseOnLeaveMenu("Graph", self, leave_delay_ms=CLOSE_DELAY_MS)
			self.menubar.addMenu(self.m_graph)

			act_visit = self.m_graph.addAction("Visit C2")
			act_visit.triggered.connect(lambda: getattr(self._dash.graph, "visit_c2", lambda: None)())

			# Filter submenu
			self.m_filter = _CloseOnLeaveMenu("Filter", self.m_graph, leave_delay_ms=CLOSE_DELAY_MS)
			self.m_graph.addMenu(self.m_filter)

			_hide_qmenu_indicator(self.m_filter)

			# ---- Professional-looking checkbox rows (menu stays open) ----------
			self._styled_rows = []  # [(row, icon_label, checkbox)]
			self.cb_os_win, row, icon = _add_menu_checkbox_row(self.m_filter, "Windows agents", True, self._push_filters)
			self._styled_rows.append((row, icon, self.cb_os_win))
			self.cb_os_lin, row, icon = _add_menu_checkbox_row(self.m_filter, "Linux agents", True, self._push_filters)
			self._styled_rows.append((row, icon, self.cb_os_lin))

			# Transports submenu
			self.m_trans = _CloseOnLeaveMenu("Transports", self.m_filter, leave_delay_ms=CLOSE_DELAY_MS)
			self.m_filter.addMenu(self.m_trans)
			# Make this submenu a bit wider
			_hide_qmenu_indicator(self.m_trans, min_width=230)
			self._proto_cbs = {}
			for proto in ("tcp", "tls", "http", "https"):
				cb, row, icon = _add_menu_checkbox_row(self.m_trans, proto, True, self._push_filters)
				self._proto_cbs[proto] = cb
				self._styled_rows.append((row, icon, cb))

			# Retint rows on theme change (colors + icons)
			ThemeManager.instance().themeChanged.connect(
				lambda _t: _retint_menu_rows(self._styled_rows)
			)

			# Start/stop the watch when any of our menus show/hide
			for m in (self.m_graph, self.m_filter, self.m_trans):
				m.aboutToShow.connect(self._start_menu_watch)
				m.aboutToHide.connect(self._maybe_stop_menu_watch)

		else:
			# still track open/close via helpers; these will just no-op
			self._styled_rows = []
			self._proto_cbs = {}

		# Window buttons
		self.btn_min   = QPushButton()
		self.btn_max   = QPushButton()
		self.btn_close = QPushButton()

		self.btn_min.setObjectName("winMin")
		self.btn_max.setObjectName("winMax")
		self.btn_close.setObjectName("winClose")

		self.btn_min.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMinButton))
		self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMaxButton))
		self.btn_close.setIcon(self.style().standardIcon(QStyle.SP_TitleBarCloseButton))

		BTN_SIZE = 28  # pick 26–32 to taste
		ICON_SIZE = 14

		for b in (self.btn_min, self.btn_max, self.btn_close):
			b.setFixedSize(BTN_SIZE, BTN_SIZE)       # square -> circle possible
			b.setIconSize(QSize(ICON_SIZE, ICON_SIZE))
			lay.addWidget(b, 0, Qt.AlignRight | Qt.AlignVCenter)

		self.btn_min.clicked.connect(self._win.showMinimized)
		self.btn_max.clicked.connect(self._toggle_max_restore)
		self.btn_close.clicked.connect(self._win.close)

		# Drag-from areas
		self.logo.installEventFilter(self)
		self.menubar.installEventFilter(self)
		self._win.installEventFilter(self)

		self._push_filters()  # initial filter sync

		# --- Deterministic tear-off state ---
		self._prev_normal_geo = None
		self._maybe_drag_restore = False
		self._press_pos_in_tb = None
		self._press_gpos = None

		self._drag_pos = None
		self._detaching = False          # true while the tear-off animation is running
		self._pending_gpos = None        # last mouse pos seen during detach
		self._drag_screen_ag = None      # screen's availableGeometry captured at detach
		self._tearoff_anim_ms = 0        # 0 = instant restore; try 100–140ms later if wanted

		self._snap = _SnapAssist(self._win)

	def _open_graph_menus(self):
		# Track exactly the three menus we own; only return the visible ones.
		if not self._menus_enabled:
			return []
		return [m for m in (self.m_graph, self.m_filter, self.m_trans) if m.isVisible()]

	def _pointer_in_any_menu(self):
		pos_g = QCursor.pos()
		for m in self._open_graph_menus():
			if m.isVisible():
				# Geometry-based hit test in global coords (robust even over other windows)
				if m.rect().contains(m.mapFromGlobal(pos_g)):
					return True
		return False

	# ----- Watch Timers -----
	def _start_menu_watch(self):
		if not self._menu_watch.isActive():
			self._menu_watch.start()

	def _maybe_stop_menu_watch(self):
		if not self._open_graph_menus():
			self._menu_watch.stop()

	def _menu_watch_tick(self):
		# If the cursor isn't inside any of our popped menus, arm their 80ms close.
		if self._open_graph_menus() and not self._pointer_in_any_menu():
			for m in self._open_graph_menus():
				m._leave_timer.start(self._menu_close_delay)

	# ----- Filters → SessionGraph -----
	def _push_filters(self):
		if not self._menus_enabled or not self._dash:
			return

		g = self._dash.graph
		if hasattr(g, "set_os_filter"):
			g.set_os_filter(self.cb_os_win.isChecked(), self.cb_os_lin.isChecked())
		if hasattr(g, "set_transports_filter"):
			enabled = {p for p, cb in self._proto_cbs.items() if cb.isChecked()}
			g.set_transports_filter(enabled)

	# ----- Max/restore -----
	def _toggle_max_restore(self):
		if self._win.isMaximized():
			self._win.showNormal()
			if self._prev_normal_geo and self._prev_normal_geo.isValid():
				self._win.setGeometry(self._prev_normal_geo)
			self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarMaxButton))
		else:
			self._prev_normal_geo = self._win.geometry()
			self._win.showMaximized()
			self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarNormalButton))

	def _compute_restore_geom(self, gpos: QPoint, local_anchor: QPoint):
		# Use the screen under the cursor at the moment we detach
		scr = QGuiApplication.screenAt(gpos) or self._win.screen()
		ag  = scr.availableGeometry()

		if self._prev_normal_geo and self._prev_normal_geo.isValid():
			tw, th = self._prev_normal_geo.width(), self._prev_normal_geo.height()
		else:
			tw = max(900, min(ag.width(),  int(ag.width()  * 0.82)))
			th = max(600, min(ag.height(), int(ag.height() * 0.78)))

		# Keep the same fraction under the cursor (so the window doesn't "jump")
		frac_x = max(0.0, min(1.0, local_anchor.x() / max(1, self.width())))
		nx = gpos.x() - int(tw * frac_x)
		ny = gpos.y() - min(local_anchor.y(), 40)

		nx = max(ag.left(),  min(ag.right()  - tw, nx))
		ny = max(ag.top(),   min(ag.bottom() - th, ny))

		return QRect(nx, ny, tw, th), ag

	def _finish_detach(self, gpos_after: QPoint, to_geo: QRect):
		self._detaching = False
		# Anchor vector (cursor -> window topleft) from the *final* restored geo
		self._drag_pos = QPoint(gpos_after.x() - to_geo.x(), gpos_after.y() - to_geo.y())
		self._maybe_drag_restore = False
		# If mouse moved during the animation, catch up once
		if self._pending_gpos:
			self._win.move(self._pending_gpos - self._drag_pos)
			self._pending_gpos = None

	def _begin_drag_restore(self, gpos: QPoint, local_pos_in_tb: QPoint):
		if self._detaching:
			return
		self._detaching = True
		self._pending_gpos = None

		to_geo, ag = self._compute_restore_geom(gpos, local_pos_in_tb)
		self._drag_screen_ag = ag
		from_geo = self._win.geometry()  # maximized geo

		self._win.showNormal()
		self._win.setGeometry(from_geo)  # ensure animation starts from exact current

		if self._tearoff_anim_ms > 0:
			# tiny ease-out to the restored size/pos
			self._snap.detach_anim(from_geo, to_geo, duration=self._tearoff_anim_ms)
			QTimer.singleShot(self._tearoff_anim_ms, lambda: self._finish_detach(QCursor.pos(), to_geo))
		else:
			# instant restore for maximum determinism during drag
			self._win.setGeometry(to_geo)
			self._finish_detach(gpos, to_geo)

	# ========== Dragging ==========
	def _can_start_drag_here(self, pos):
		w = self.childAt(pos)
		if w in (self.btn_min, self.btn_max, self.btn_close):
			return False
		if w is self.menubar:
			mb_pos = self.menubar.mapFrom(self, pos)
			return self.menubar.actionAt(mb_pos) is None
		return True

	def mousePressEvent(self, e):
		if e.button() == Qt.LeftButton and self._can_start_drag_here(e.pos()):
			self._close_all_menus()
			if self._win.isMaximized():
				self._maybe_drag_restore = True
				self._press_pos_in_tb = e.pos()
				self._press_gpos = e.globalPos()
				e.accept(); return
			else:
				self._drag_pos = e.globalPos() - self._win.frameGeometry().topLeft()
				e.accept(); return
		super().mousePressEvent(e)

	def mouseMoveEvent(self, e):
		if e.buttons() & Qt.LeftButton:
			if self._maybe_drag_restore:
				if (e.globalPos() - self._press_gpos).manhattanLength() >= QApplication.startDragDistance():
					self._begin_drag_restore(e.globalPos(), self._press_pos_in_tb)
					# show snap preview right away (window is restored now)
					self._snap.on_drag_move(e.globalPos())
					e.accept(); return
			elif self._drag_pos and not self._win.isMaximized():
				if self._detaching:
					# animation in progress — just remember where the mouse is
					self._pending_gpos = e.globalPos()
					e.accept(); return
				self._win.move(e.globalPos() - self._drag_pos)
				self._snap.on_drag_move(e.globalPos())
				e.accept(); return
		super().mouseMoveEvent(e)

	def mouseReleaseEvent(self, e):
		if e.button() == Qt.LeftButton:
			if not self._detaching:
				if self._snap.on_drag_release(e.globalPos()):
					self.btn_max.setIcon(self.style().standardIcon(QStyle.SP_TitleBarNormalButton))
			self._maybe_drag_restore = False
			self._drag_pos = None
		super().mouseReleaseEvent(e)

	def mouseDoubleClickEvent(self, e):
		if e.button() == Qt.LeftButton and self._can_start_drag_here(e.pos()):
			self._toggle_max_restore(); e.accept(); return
		super().mouseDoubleClickEvent(e)

	# Close menus when leaving the menubar entirely
	def _close_all_menus(self):
		for m in self.menubar.findChildren(QMenu):
			if m.isVisible():
				m.hide()
		self.menubar.setActiveAction(None)

	# Dragging from logo/menubar whitespace, and menu auto-close on leave
	def eventFilter(self, obj, ev):
		# Double-click maximize/restore on menubar whitespace (and logo)
		if obj in (self.menubar, self.logo):
			if ev.type() == QEvent.MouseButtonDblClick and ev.button() == Qt.LeftButton:
				# Only treat as titlebar dbl-click if we're not on a menu action
				if obj is not self.menubar or self.menubar.actionAt(ev.pos()) is None:
					self._close_all_menus()
					self._toggle_max_restore()
					return True

		if obj is self._win and ev.type() in (QEvent.Move, QEvent.Resize, QEvent.WindowStateChange):
			# cache last normal geom to restore to
			if not self._win.isMaximized():
				self._prev_normal_geo = self._win.geometry()
			self._close_all_menus()
			return False

		t = ev.type()
		if t in (QEvent.MouseMove, QEvent.Leave, QEvent.WindowDeactivate,
				QEvent.ApplicationDeactivate, QEvent.FocusOut):
			if self._open_graph_menus() and not self._pointer_in_any_menu():
				for m in self._open_graph_menus():
					m._leave_timer.start(self._menu_close_delay)
			# never consume globally
			if obj is not self.menubar:
				return False

		# existing menubar-drag logic unchanged
		if obj is self.menubar:
			if ev.type() == QEvent.MouseButtonPress and ev.button() == Qt.LeftButton:
				if self.menubar.actionAt(ev.pos()) is None:
					self._close_all_menus()
					if self._win.isMaximized():
						self._maybe_drag_restore = True
						self._press_pos_in_tb = self.menubar.mapTo(self, ev.pos())
						self._press_gpos = ev.globalPos()
						return True
					else:
						self._drag_pos = ev.globalPos() - self._win.frameGeometry().topLeft()
						return True

			elif ev.type() == QEvent.MouseMove and (ev.buttons() & Qt.LeftButton):
				if self._maybe_drag_restore:
					if (ev.globalPos() - self._press_gpos).manhattanLength() >= QApplication.startDragDistance():
						self._begin_drag_restore(ev.globalPos(), self._press_pos_in_tb)
						self._snap.on_drag_move(ev.globalPos())
						return True
				elif self._drag_pos and not self._win.isMaximized():
					if self._detaching:
						self._pending_gpos = ev.globalPos()
						return True
					self._win.move(ev.globalPos() - self._drag_pos)
					self._snap.on_drag_move(ev.globalPos())
					return True

			elif ev.type() == QEvent.MouseButtonRelease:
				if not self._detaching:
					self._snap.on_drag_release(ev.globalPos())
				self._maybe_drag_restore = False
				self._drag_pos = None

		return super().eventFilter(obj, ev)
