# gui/main_window.py
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QVBoxLayout
from PyQt5.QtCore import Qt, QPoint, QRectF
from PyQt5.QtGui import QPainterPath, QRegion

from dashboard import Dashboard
from title_bar import TitleBar

class _EdgeGrip(QWidget):
	def __init__(self, parent, edge: str, margin: int):
		super().__init__(parent)
		self._edge = edge
		self._m = margin
		self._resizing = False
		self._start_geo = None
		self._start_pos = QPoint()
		self.setAttribute(Qt.WA_NoMousePropagation, True)
		self.setMouseTracking(True)
		self.setFocusPolicy(Qt.NoFocus)
		self.setStyleSheet("background: transparent;")  # invisible hit area

		if edge in ("left", "right"):
			self.setCursor(Qt.SizeHorCursor)
		elif edge == "bottom":
			self.setCursor(Qt.SizeVerCursor)
		elif edge == "bottomleft":
			self.setCursor(Qt.SizeBDiagCursor)
		elif edge == "bottomright":
			self.setCursor(Qt.SizeFDiagCursor)

	def _start_system_resize(self):
		wh = self.window().windowHandle()
		if not wh or not hasattr(wh, "startSystemResize"):
			return False
		edges = Qt.Edges(0)
		if "left" in self._edge:   edges |= Qt.LeftEdge
		if "right" in self._edge:  edges |= Qt.RightEdge
		if "top" in self._edge:    edges |= Qt.TopEdge
		if "bottom" in self._edge: edges |= Qt.BottomEdge
		if int(edges) != 0:
			wh.startSystemResize(edges)
			return True
		return False

	def mousePressEvent(self, e):
		if e.button() == Qt.LeftButton:
			# Prefer buttery native resize when available
			if self._start_system_resize():
				e.accept(); return
			# Fallback: manual (runs only during drag)
			win = self.window()
			if win.isMaximized():
				return
			self._resizing = True
			self._start_geo = win.geometry()
			self._start_pos = e.globalPos()
			e.accept()

	def mouseMoveEvent(self, e):
		if not self._resizing:
			return
		win = self.window()
		gpos = e.globalPos()
		geo = self._start_geo
		dx, dy = gpos.x() - self._start_pos.x(), gpos.y() - self._start_pos.y()
		x, y, w, h = geo.x(), geo.y(), geo.width(), geo.height()
		minw, minh = max(1, win.minimumWidth()), max(1, win.minimumHeight())
		maxw, maxh = win.maximumWidth(), win.maximumHeight()

		def clamp(v, lo, hi):
			if not hi or hi >= 16777215:  # QWIDGETSIZE_MAX
				hi = 16777215
			return max(lo, min(hi, v))

		new_x, new_y, new_w, new_h = x, y, w, h
		eid = self._edge

		if "left" in eid:
			nw = clamp(w - dx, minw, maxw); new_x = x + (w - nw); new_w = nw
		if "right" in eid:
			new_w = clamp(w + dx, minw, maxw)
		if "top" in eid:
			nh = clamp(h - dy, minh, maxh); new_y = y + (h - nh); new_h = nh
		if "bottom" in eid:
			new_h = clamp(h + dy, minh, maxh)

		win.setGeometry(new_x, new_y, new_w, new_h)
		e.accept()

	def mouseReleaseEvent(self, e):
		if self._resizing and e.button() == Qt.LeftButton:
			self._resizing = False
			e.accept()

class MainWindow(QMainWindow):
	def __init__(self, api):
		super().__init__()
		self.api = api
		self.setWindowTitle("GunnerC2 — Console")
		self.resize(1240, 780)
		self.setWindowIcon(QApplication.windowIcon())

		# Frameless + transparent so we can clip real rounded corners
		self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
		self.setAttribute(Qt.WA_TranslucentBackground, True)

		self._corner_radius = 12  # tweak to taste

		# Central: our custom title bar on top, dashboard below
		self.dashboard = Dashboard(api)
		wrapper = QWidget()
		lay = QVBoxLayout(wrapper); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)
		self.titlebar = TitleBar(self, self.dashboard)
		lay.addWidget(self.titlebar)
		lay.addWidget(self.dashboard)
		self.setCentralWidget(wrapper)

		# ---- Frameless resize grips (zero overhead unless you hover edges) ----
		self._RESIZE_MARGIN = 8  # try 6–12 to taste
		self._grips = {
			"left":        _EdgeGrip(self, "left",        self._RESIZE_MARGIN),
			"right":       _EdgeGrip(self, "right",       self._RESIZE_MARGIN),
			"bottom":      _EdgeGrip(self, "bottom",      self._RESIZE_MARGIN),
			"bottomleft":  _EdgeGrip(self, "bottomleft",  self._RESIZE_MARGIN),
			"bottomright": _EdgeGrip(self, "bottomright", self._RESIZE_MARGIN),
			# (intentionally skipping top/top corners so we don't interfere with the TitleBar)
		}
		self._position_grips()
		self._apply_round_mask()  # initial

	def _position_grips(self):
		m  = self._RESIZE_MARGIN
		w  = self.width()
		h  = self.height()
		tb = self.titlebar.height() if hasattr(self, "titlebar") and self.titlebar else 34

		# Edges: keep top edge free for the custom title bar interactions
		self._grips["left"].setGeometry(0, tb, m, max(1, h - tb))
		self._grips["right"].setGeometry(max(0, w - m), tb, m, max(1, h - tb))
		self._grips["bottom"].setGeometry(0, max(0, h - m), w, m)

		# Bottom corners (a bit larger for easier grabbing)
		s = m * 2
		self._grips["bottomleft"].setGeometry(0, max(0, h - s), s, s)
		self._grips["bottomright"].setGeometry(max(0, w - s), max(0, h - s), s, s)

		# Make sure grips stay above everything
		for g in self._grips.values():
			g.raise_()

	def resizeEvent(self, e):
		super().resizeEvent(e)
		self._position_grips()
		self._apply_round_mask()

	def _apply_round_mask(self):
		r = float(self._corner_radius)
		rect = self.rect()
		if rect.isNull():
			return
		path = QPainterPath()
		path.addRoundedRect(QRectF(0, 0, rect.width(), rect.height()), r, r)
		self.setMask(QRegion(path.toFillPolygon().toPolygon()))
