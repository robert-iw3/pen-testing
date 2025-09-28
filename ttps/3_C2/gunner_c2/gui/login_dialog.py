# gui/login_dialog.py
from PyQt5.QtCore import Qt, QTimer, QSize, QSettings
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
	QDialog, QLabel, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout,
	QFrame, QCheckBox, QToolButton
)
import re
from api_client import APIClient
from style import add_drop_shadow

# --- WS client (package/script safe import) ---
try:
	from .websocket_client import OperatorsWSClient
except ImportError:
	from websocket_client import OperatorsWSClient

LOGO_PATHS = ["gui/assets/gunnerc2.jpg"]

def _load_logo() -> QPixmap:
	for p in LOGO_PATHS:
		pm = QPixmap(p)
		if not pm.isNull():
			return pm
	return QPixmap()

def _normalize_base_url(s: str) -> str:
	s = (s or "").strip()
	s = re.sub(r"^[a-zA-Z]://", "", s)
	if not re.match(r"^https?://", s, re.I):
		s = "http://" + s
	return s.rstrip("/")

class LoginDialog(QDialog):
	def __init__(self, parent=None):
		super().__init__(parent)
		self.setWindowTitle("GunnerC2 — Login")
		self.setModal(True)
		self.setMinimumWidth(520)

		self.api_client: APIClient | None = None
		self._ws: OperatorsWSClient | None = None
		self._login_timer: QTimer | None = None
		self._logged_in = False

		self._apply_style()

		# ---------- Card ----------
		card = QFrame(self); card.setObjectName("card"); card.setFrameShape(QFrame.NoFrame)

		# Logo + title
		self.logo = QLabel()
		pm = _load_logo()
		if not pm.isNull():
			self.logo.setPixmap(pm.scaledToHeight(120, Qt.SmoothTransformation))
			self.logo.setAlignment(Qt.AlignCenter)
		title = QLabel("GUNNERC2"); subtitle = QLabel("Sign in to your operator console")
		title.setObjectName("title"); subtitle.setObjectName("subtitle")
		title.setAlignment(Qt.AlignCenter); subtitle.setAlignment(Qt.AlignCenter)

		# Fields
		self.url_edit  = QLineEdit("http://127.0.0.1:6060")
		self.user_edit = QLineEdit(); self.user_edit.setPlaceholderText("Username")
		self.pass_edit = QLineEdit(); self.pass_edit.setPlaceholderText("Password"); self.pass_edit.setEchoMode(QLineEdit.Password)

		# Remove native frames (prevents the “extra” inner outline)
		for le in (self.url_edit, self.user_edit, self.pass_edit):
			le.setFrame(False)
			self.url_edit.setPlaceholderText("Server URL (e.g., http://127.0.0.1:6060)")

		# Eye button
		self._eye = QToolButton(self.pass_edit); self._eye.setCursor(Qt.PointingHandCursor); self._eye.setCheckable(True)
		self._eye.setIcon(self.style().standardIcon(self.style().SP_DialogYesButton))
		self._eye.setIconSize(QSize(16, 16)); self._eye.setStyleSheet("QToolButton { border: 0; padding: 0 6px; }")
		self._eye.setFixedSize(18, 18); QTimer.singleShot(0, self._position_eye_button); self._eye.toggled.connect(self._toggle_password)

		self.remember = QCheckBox("Remember me")
		self.error = QLabel(""); self.error.setObjectName("error")

		# Buttons & status
		self.btn_login = QPushButton("Login"); self.btn_login.setDefault(True)
		self.btn_login.setObjectName("primary")
		self.btn_cancel = QPushButton("Cancel")
		self.status = QLabel(""); self.status.setObjectName("status"); self.status.setAlignment(Qt.AlignCenter)

		# Layouts
		form = QVBoxLayout(card); form.setContentsMargins(28, 28, 28, 28); form.setSpacing(12)
		if not pm.isNull(): form.addWidget(self.logo)
		form.addWidget(title); form.addWidget(subtitle); form.addSpacing(8)
		form.addWidget(QLabel("Server URL")); form.addWidget(self.url_edit)
		form.addWidget(QLabel("Username"));   form.addWidget(self.user_edit)
		form.addWidget(QLabel("Password"));   form.addWidget(self.pass_edit)

		opts = QHBoxLayout(); opts.addWidget(self.remember); opts.addStretch(1); form.addLayout(opts)
		form.addWidget(self.error); form.addWidget(self.status)

		buttons = QHBoxLayout(); buttons.addStretch(1); buttons.addWidget(self.btn_login); buttons.addWidget(self.btn_cancel)
		form.addLayout(buttons)

		root = QVBoxLayout(self); root.setContentsMargins(18, 18, 18, 18)
		root.addStretch(1); root.addWidget(card, alignment=Qt.AlignHCenter); root.addStretch(1)

		# Wire up
		self.btn_cancel.clicked.connect(self.reject)
		self.btn_login.clicked.connect(self._login)
		self.pass_edit.returnPressed.connect(self._login)
		self.user_edit.returnPressed.connect(self._login)
		self.url_edit.returnPressed.connect(self._login)

		# Soft shadows for a pro look
		add_drop_shadow(card, blur=32, dy=10, alpha=90)       # the big panel
		add_drop_shadow(self.btn_login, blur=20, dy=4, alpha=110)  # primary action

		self._load_settings()

	# keep eye in place on resize
	def resizeEvent(self, e):
		super().resizeEvent(e); self._position_eye_button()

	def _position_eye_button(self):
		m = 6; r = self.pass_edit.rect()
		x = r.right() - self._eye.width() - m; y = r.center().y() - self._eye.height() // 2
		self._eye.move(x, y); self.pass_edit.setStyleSheet("QLineEdit { padding-right: 28px; }")

	def _toggle_password(self, on: bool):
		self.pass_edit.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)

	# -------------------- Login (WebSocket) --------------------
	def _set_busy(self, busy: bool):
		for w in (self.btn_login, self.btn_cancel, self.url_edit, self.user_edit, self.pass_edit):
			w.setEnabled(not busy)
		self.btn_login.setText("Logging in…" if busy else "Login")
		self.status.setText("Authenticating…" if busy else "")

	def _login(self):
		self.error.setText("")
		base = _normalize_base_url(self.url_edit.text())
		user = self.user_edit.text().strip()
		pwd  = self.pass_edit.text()
		if not base or not user or not pwd:
			self.error.setText("Please fill in all fields."); return

		# Prepare API holder (token filled after login_ok)
		self.api_client = APIClient(base)

		# Temporary WS client without token
		if self._ws:
			try: self._ws.close()
			except Exception: pass
		self._ws = OperatorsWSClient(self.api_client)  # api.token is None here

		# signals
		self._ws.connected.connect(lambda: self._ws.login(user, pwd))
		# prefer dedicated signal if present; fallback to raw
		if hasattr(self._ws, "loggedIn"):
			self._ws.loggedIn.connect(self._on_ws_login_ok)
		self._ws.error.connect(self._on_ws_error)
		self._ws.disconnected.connect(self._on_ws_disconnected)
		self._ws.rawMessage.connect(self._maybe_handle_login_ok)

		# timeout guard
		if self._login_timer:
			self._login_timer.stop()
		self._login_timer = QTimer(self); self._login_timer.setSingleShot(True)
		self._login_timer.timeout.connect(lambda: self._fail("Connection timed out"))
		self._login_timer.start(10000)  # 10s guard

		self._logged_in = False
		self._set_busy(True)
		self._ws.open()

	def _maybe_handle_login_ok(self, msg: dict):
		# works even if OperatorsWSClient doesn't expose .loggedIn
		if (msg.get("type") or "").lower() == "login_ok":
			self._on_ws_login_ok({"token": msg.get("token"), "me": msg.get("me") or {}})

	def _on_ws_login_ok(self, payload: dict):
		if self._logged_in:  # ignore duplicates from reconnects
			return
		self._logged_in = True
		if self._login_timer: self._login_timer.stop()
		token = payload.get("token")
		if not token:
			return self._fail("Login failed (no token).")
		# set token on API client
		self.api_client.token = token
		self.api_client.headers = {"Authorization": f"Bearer {token}"}
		# we’re done with this temporary WS
		try: self._ws.close()
		except Exception: pass
		self._set_busy(False)
		if self.remember.isChecked():
			self._save_settings()
		else:
			self._clear_saved_user()
		self.accept()

	def _on_ws_error(self, err: str):
		# Only show if still waiting for login_ok
		if not self._logged_in:
			self.error.setText(str(err))

	def _on_ws_disconnected(self):
		if not self._logged_in and self._login_timer and self._login_timer.isActive():
			# disconnect before login_ok
			self._fail("Disconnected")

	def _fail(self, msg: str):
		if self._login_timer: self._login_timer.stop()
		try:
			if self._ws: self._ws.close()
		except Exception:
			pass
		self._set_busy(False)
		self.error.setText(msg)

	# -------------------- Settings --------------------
	def _settings(self) -> QSettings:
		return QSettings("GunnerC2", "Client")

	def _load_settings(self):
		s = self._settings()
		base = s.value("base_url", "", type=str)
		user = s.value("username", "", type=str)
		if base: self.url_edit.setText(base)
		if user:
			self.user_edit.setText(user)
			self.remember.setChecked(True)

	def _save_settings(self):
		s = self._settings()
		s.setValue("base_url", _normalize_base_url(self.url_edit.text()))
		s.setValue("username", self.user_edit.text().strip())

	def _clear_saved_user(self):
		self._settings().remove("username")

	# -------------------- Style --------------------
	def _apply_style(self):
		self.setStyleSheet("""
			QDialog { background: #0b0f14; }
			#card { background: #12161c; border: 1px solid #1e2430; border-radius: 14px; }
			QLabel#title { color: #e8f0ff; font-size: 18px; font-weight: 700; margin-top: 4px; }
			QLabel#subtitle { color: #98a2b3; font-size: 12px; margin-bottom: 4px; }
			QLabel { color: #cbd5e1; }
			QLineEdit {
				background: #0f141b; color: #e5edf6; border: 1px solid #2a3544;
				border-radius: 8px; padding: 8px 10px; selection-background-color: #1e2a3a;
			}
			QLineEdit:focus { border: 1px solid #2ea043; }
			QPushButton {
				background: #1b242f; color: #e7eef7; border: 1px solid #2a3544;
				border-radius: 8px; padding: 8px 14px; font-weight: 600;
			}
			QPushButton:hover { border-color: #3d4b5e; }
			QPushButton:default { background: #243244; border-color: #2ea043; }
			QLabel#error { color: #ff6b6b; font-weight: 600; min-height: 18px; }
			QLabel#status { color: #9fb5cc; min-height: 16px; }
			QCheckBox { color: #bdc6d3; }
		""")
