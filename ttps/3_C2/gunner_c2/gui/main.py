# gui/main.py

#Normal Imports
import sys, os

#PyQt5 Imports
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor, QIcon
from PyQt5.QtCore import Qt

# GunnerC2 Imports
from login_dialog import LoginDialog
from main_window import MainWindow
from theme_center import ThemeManager

def _asset_path(*parts):
	"""Resolve a path relative to this file (works when packaged, too)."""
	here = os.path.dirname(os.path.abspath(__file__))
	return os.path.join(here, *parts)

def _find_icon_path():
	"""
	Pick the best available icon:
	  1) env GUNNERC2_ICON
	  2) gui/assets/gunnerc2.png
	  3) gui/assets/gunnerc2.ico
	  4) gui/assets/gunnerc2.jpg
	"""
	cand = [
		os.environ.get("GUNNERC2_ICON") or "",
		_asset_path("assets", "gunnerc2.png"),
		_asset_path("assets", "gunnerc2.ico"),
		_asset_path("assets", "gunnerc2.jpg"),
	]
	for p in cand:
		if p and os.path.exists(p):
			return p
	return ""

if __name__ == "__main__":
	# Hi-DPI before QApplication
	QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
	# (optional, helps on some PyQt5 builds)
	try:
		QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
	except Exception:
		pass

	# Windows taskbar grouping/icon
	if sys.platform.startswith("win"):
		try:
			import ctypes
			ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("GunnerC2.App")
		except Exception:
			pass

	app = QApplication(sys.argv)
	ThemeManager.instance().install(app)  # loads saved theme or defaults
	app.setApplicationName("GunnerC2")
	app.setOrganizationName("GunnerC2")

	# 1) Set base style FIRST so QSS can layer on top
	#app.setStyle("Fusion")

	# 2) Keep palette minimal (or remove it entirely).
	# If you want a tiny nudge to system dialogs, tweak only a few roles:
	pal = app.palette()
	pal.setColor(QPalette.Highlight, QColor("#66b0ff"))
	pal.setColor(QPalette.HighlightedText, Qt.black)
	pal.setColor(QPalette.Link, QColor("#66b0ff"))
	app.setPalette(pal)

	# App icon
	icon_path = _find_icon_path()
	if icon_path:
		app.setWindowIcon(QIcon(icon_path))

	# ---- normal flow ----
	dlg = LoginDialog()
	if dlg.exec_() == LoginDialog.Accepted:
		mw = MainWindow(dlg.api_client)
		mw.show()
		sys.exit(app.exec_())
	sys.exit(0)