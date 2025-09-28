# gui/dialog_create_listener.py
from __future__ import annotations

from typing import Callable, Optional, Tuple, Dict, Any

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import (
	QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
	QLineEdit, QComboBox, QPushButton, QLabel, QWidget, QSpacerItem, QSizePolicy
)

ChipCheck = Callable[[str, int, str], Tuple[bool, str]]
NameCheck = Callable[[str], Tuple[bool, str]]


def _chip_label() -> QLabel:
	lab = QLabel("●")
	lab.setFixedWidth(14)
	lab.setAlignment(Qt.AlignCenter)
	lab.setStyleSheet("color:#8a8f98;")  # neutral
	return lab


def _set_chip(lab: QLabel, ok: Optional[bool]):
	if ok is True:
		lab.setStyleSheet("color:#18c964;")  # green
		lab.setToolTip("OK")
	elif ok is False:
		lab.setStyleSheet("color:#ff5252;")  # red
		lab.setToolTip("Needs attention")
	else:
		lab.setStyleSheet("color:#8a8f98;")
		lab.setToolTip("")


class CreateListenerDialog(QDialog):
	"""
	Single-column, sectioned dialog.
	For HTTP/HTTPS: only Host + Port (no Advanced).
	For TCP: we still show an Advanced box placeholder you can extend later.
	"""
	def __init__(
		self,
		parent: Optional[QWidget] = None,
		*,
		bind_check: Optional[ChipCheck] = None,
		name_check: Optional[NameCheck] = None,
	):
		super().__init__(parent)
		self.setWindowTitle("Create Listener")
		self.setModal(True)
		self.resize(520, 440)

		self._bind_check = bind_check
		self._name_check = name_check

		root = QVBoxLayout(self)
		root.setContentsMargins(12, 12, 12, 12)
		root.setSpacing(10)

		# -------- Basics --------
		box_basic = QGroupBox("Basics")
		f = QFormLayout(box_basic)
		f.setLabelAlignment(Qt.AlignLeft)
		f.setContentsMargins(12, 8, 12, 8)
		f.setSpacing(8)

		self.ed_name = QLineEdit()
		self.chip_name = _chip_label()
		row = QWidget()
		rlay = QHBoxLayout(row); rlay.setContentsMargins(0, 0, 0, 0)
		rlay.addWidget(self.ed_name); rlay.addWidget(self.chip_name)
		f.addRow("Name", row)

		self.cbo_transport = QComboBox()
		self.cbo_transport.addItems(["HTTP", "HTTPS", "TLS", "TCP"])
		f.addRow("Transport", self.cbo_transport)

		root.addWidget(box_basic)

		# -------- Network --------
		box_net = QGroupBox("Network")
		fn = QFormLayout(box_net)
		fn.setLabelAlignment(Qt.AlignLeft)
		fn.setContentsMargins(12, 8, 12, 8)
		fn.setSpacing(8)

		self.ed_host = QLineEdit("0.0.0.0")
		self.chip_host = _chip_label()
		row_host = QWidget(); lay_h = QHBoxLayout(row_host); lay_h.setContentsMargins(0, 0, 0, 0)
		lay_h.addWidget(self.ed_host); lay_h.addWidget(self.chip_host)
		fn.addRow("Bind Host", row_host)

		self.ed_port = QLineEdit()
		self.ed_port.setPlaceholderText("1–65535")
		self.ed_port.setValidator(QIntValidator(1, 65535, self))
		self.chip_port = _chip_label()
		row_port = QWidget(); lay_p = QHBoxLayout(row_port); lay_p.setContentsMargins(0, 0, 0, 0)
		lay_p.addWidget(self.ed_port); lay_p.addWidget(self.chip_port)
		fn.addRow("Port", row_port)

		root.addWidget(box_net)

		# -------- Advanced (TLS options for HTTPS/TLS) --------
		self.box_adv = QGroupBox("Advanced")
		self.box_adv.setCheckable(False)
		fa = QFormLayout(self.box_adv)
		fa.setContentsMargins(12, 8, 12, 8)
		fa.setSpacing(8)

		# TLS bits (visible for HTTPS/TLS)
		from PyQt5.QtWidgets import QFileDialog
		self.ed_cert = QLineEdit(); self.ed_cert.setPlaceholderText("Optional: PEM certificate")
		self.btn_cert = QPushButton("Choose…")
		row_cert = QWidget(); lc = QHBoxLayout(row_cert); lc.setContentsMargins(0,0,0,0)
		lc.addWidget(self.ed_cert); lc.addWidget(self.btn_cert)
		fa.addRow("TLS Cert", row_cert)

		self.ed_key = QLineEdit(); self.ed_key.setPlaceholderText("Optional: PEM private key")
		self.btn_key = QPushButton("Choose…")
		row_key = QWidget(); lk = QHBoxLayout(row_key); lk.setContentsMargins(0,0,0,0)
		lk.addWidget(self.ed_key); lk.addWidget(self.btn_key)
		fa.addRow("TLS Key", row_key)

		root.addWidget(self.box_adv)

		# -------- Footer --------
		footer = QHBoxLayout()
		# live-updated preview label
		self.lbl_preview = QLabel(f"Preview: {self._preview()}")
		self.lbl_preview.setStyleSheet("color:#9aa2ad;")
		footer.addWidget(self.lbl_preview)
		footer.addStretch()
		self.btn_test = QPushButton("Test Bind")
		self.btn_create = QPushButton("Create Listener")
		self.btn_cancel = QPushButton("Cancel")
		footer.addWidget(self.btn_cancel)
		footer.addWidget(self.btn_test)
		footer.addWidget(self.btn_create)
		root.addLayout(footer)

		# Signals
		self.cbo_transport.currentTextChanged.connect(self._on_transport_changed)
		self.ed_host.textChanged.connect(self._on_host_changed)
		self.ed_port.textChanged.connect(self._on_port_changed)
		self.ed_name.textChanged.connect(self._validate_name)
		self.btn_test.clicked.connect(self._test_bind)
		self.btn_cancel.clicked.connect(self.reject)
		self.btn_create.clicked.connect(self._accept_if_valid)
		self.btn_cert.clicked.connect(self._pick_cert)
		self.btn_key.clicked.connect(self._pick_key)

		# Initial state
		self.ed_port.setText("8080")
		self._on_transport_changed(self.cbo_transport.currentText())
		self._validate_all()
		self._update_preview()

	# ---------- UI helpers ----------
	def _on_transport_changed(self, _t: str):
		t = self.transport()
		# Advanced only for HTTPS/TLS (cert/key); HTTP has none; TCP keeps placeholder hidden.
		self.box_adv.setVisible(t in ("https", "tls"))
		# Default port per transport for convenience
		if not self.ed_port.text().strip():
			self.ed_port.setText("8080" if t in ("http", "https") else ("4444" if t == "tcp" else "4443"))
		self._validate_all()
		self._update_preview()

	def _preview(self) -> str:
		t = self.transport()
		host = (self.ed_host.text() or "0.0.0.0").strip()
		port = self.ed_port.text().strip() or "?"
		scheme = "https" if t in ("https","tls") else ("http" if t == "http" else t)
		tail = "/" if t in ("http", "https") else ""
		return f"{scheme}://{host}:{port}{tail}"

	def _test_bind(self):
		if not self._bind_check:
			return
		host = (self.ed_host.text() or "").strip()
		port = int(self.ed_port.text() or 0)
		ok, msg = self._bind_check(host, port, self.transport())
		_set_chip(self.chip_host, ok)
		_set_chip(self.chip_port, ok)
		self.btn_test.setToolTip(msg or "")
		self._update_create_enabled()

	def _validate_name(self):
		txt = (self.ed_name.text() or "").strip()
		if self._name_check:
			ok, _msg = self._name_check(txt) if txt else (False, "Required")
			_set_chip(self.chip_name, ok)
		else:
			_set_chip(self.chip_name, bool(txt))
		self._update_create_enabled()

	def _on_host_changed(self):
		ok = bool((self.ed_host.text() or "").strip())
		_set_chip(self.chip_host, ok)
		self._update_create_enabled()
		self._update_preview()

	def _on_port_changed(self):
		txt = self.ed_port.text().strip()
		ok = txt.isdigit() and 1 <= int(txt) <= 65535
		_set_chip(self.chip_port, ok)
		self._update_create_enabled()
		self._update_preview()

	def _validate_all(self):
		self._validate_name()
		# run the same checks used by the change handlers
		self._on_host_changed()
		self._on_port_changed()

	def _update_preview(self):
		# Keep the preview in sync with transport/host/port
		if hasattr(self, "lbl_preview"):
			self.lbl_preview.setText(f"Preview: {self._preview()}")

	def _update_create_enabled(self):
		ok = all(
			lab.styleSheet().find("#18c964") != -1
			for lab in (self.chip_name, self.chip_host, self.chip_port)
		)
		self.btn_create.setEnabled(ok)

	def _accept_if_valid(self):
		self._validate_all()
		if self.btn_create.isEnabled():
			self.accept()

	# ---------- public API ----------
	def transport(self) -> str:
		return (self.cbo_transport.currentText() or "").lower()

	def data(self) -> Dict[str, Any]:
		"""
		Return a dict compatible with api_client.create_listener_v2.
		"""
		cfg: Dict[str, Any] = {
			"name": (self.ed_name.text() or "").strip(),
			"transport": self.transport(),
			"host": (self.ed_host.text() or "").strip(),
			"port": int(self.ed_port.text() or 0),
		}
		# TLS options for HTTPS/TLS are optional; if absent, backend should self-sign.
		if cfg["transport"] in ("https", "tls"):
			cert = (self.ed_cert.text() or "").strip()
			key  = (self.ed_key.text() or "").strip()
			if cert: cfg["certfile"] = cert
			if key:  cfg["keyfile"]  = key

		return cfg

	# ----- file pickers -----
	def _pick_cert(self):
		from PyQt5.QtWidgets import QFileDialog
		path, _ = QFileDialog.getOpenFileName(self, "Choose TLS certificate (PEM)", "", "PEM files (*.pem *.crt *.cer);;All files (*)")
		if path:
			self.ed_cert.setText(path)
	def _pick_key(self):
		from PyQt5.QtWidgets import QFileDialog
		path, _ = QFileDialog.getOpenFileName(self, "Choose TLS private key (PEM)", "", "PEM files (*.pem *.key);;All files (*)")
		if path:
			self.ed_key.setText(path)
