from PyQt5.QtCore import Qt, QPropertyAnimation, QSequentialAnimationGroup, QEasingCurve, QEvent
from PyQt5.QtGui import QFont, QPalette, QColor, QTextOption, QIntValidator
from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QVBoxLayout,
    QTextEdit, QMessageBox, QFormLayout, QGroupBox, QSpinBox, QCheckBox,
    QSplitter, QFileDialog, QPlainTextEdit, QSizePolicy, QGraphicsOpacityEffect,
    QScrollArea, QFrame, QLayout, QScroller, QScrollerProperties
)


class PayloadsTab(QWidget):
    """
    A clean two-pane generator:
      • Left: Config (Platform, Format, Transport, Target, Advanced options)
      • Right: Output with actions (Generate • Copy • Save • Clear)
    """
    def __init__(self, api):
        super().__init__()
        self.api = api
        self._build_ui()
        self._wire_init()

    def _fix_row_heights(*widgets):
        for w in widgets:
            if hasattr(w, "setMinimumHeight"):
                w.setMinimumHeight(28)


    # ---------- UI ----------
    def _build_ui(self):
        # --- Left: Config ---------------------------------------------------
        # Put the entire left stack inside a scroll area so nothing gets crunched
        left_content = QWidget()
        lyt = QVBoxLayout(left_content); lyt.setContentsMargins(10, 10, 10, 10); lyt.setSpacing(10)

        # Primary group
        grp_core = QGroupBox("Payload")
        form = QFormLayout(grp_core); form.setLabelAlignment(Qt.AlignRight)

        self.platform = QComboBox()
        self.platform.addItems(["Windows", "Linux"])

        self.format = QComboBox()      # populated dynamically
        self.transport = QComboBox()   # populated dynamically

        form.addRow("Platform:", self.platform)
        form.addRow("Format:", self.format)
        form.addRow("Transport:", self.transport)

        # Target group
        grp_target = QGroupBox("Target")
        tform = QFormLayout(grp_target); tform.setLabelAlignment(Qt.AlignRight)
        self.host = QLineEdit(); self.host.setPlaceholderText("C2 host or IP")
        self.port = QLineEdit(); self.port.setPlaceholderText("Port")
        tform.addRow("Host/IP:", self.host)
        tform.addRow("Port:", self.port)

        # HTTP/HTTPS options (visible only when transport is http/https)
        grp_http = QGroupBox("HTTP Options")
        # Prevent shrink-below-content, but still allow width expansion
        grp_http.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        hform = QFormLayout(grp_http)
        hform.setLabelAlignment(Qt.AlignRight)
        hform.setRowWrapPolicy(QFormLayout.DontWrapRows)
        hform.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        hform.setFormAlignment(Qt.AlignTop)
        hform.setSizeConstraint(QLayout.SetMinimumSize)  # <- honor sizeHint vertically

        self.beacon = QSpinBox(); self.beacon.setRange(1, 86400); self.beacon.setValue(5)
        self.jitter = QSpinBox(); self.jitter.setRange(0, 90); self.jitter.setValue(0)
        self.useragent = QLineEdit(); self.useragent.setPlaceholderText("User-Agent (optional)")
        self.accept = QLineEdit(); self.accept.setPlaceholderText("Accept header (optional)")
        self.byte_range = QLineEdit(); self.byte_range.setPlaceholderText("Range header (optional)")
        self.byte_range.setValidator(QIntValidator(0, 2_147_483_647, self))  # numeric only
        # Profile: full path to a *.profile file (picker)
        self.profile = QLineEdit(); self.profile.setPlaceholderText("Select .profile file (optional)")
        self.btn_profile = QPushButton("Browse…")
        self.btn_profile.setCursor(Qt.PointingHandCursor)
        self.btn_profile.setFixedHeight(28)
        self.btn_profile.setStyleSheet(
            "QPushButton { background:#23272e; color:#e6e6e6; border:1px solid #3b404a;"
            "  border-radius:6px; padding:2px 10px; }"
            "QPushButton:hover { border-color:#5a6270; }"
        )
        _prof_row = QWidget(); _prof_lyt = QHBoxLayout(_prof_row); _prof_lyt.setContentsMargins(0,0,0,0); _prof_lyt.setSpacing(6)
        _prof_lyt.addWidget(self.profile, 1); _prof_lyt.addWidget(self.btn_profile, 0)

        # Plain text editor behaves better in forms than rich-text QTextEdit
        self.headers = QPlainTextEdit(); self.headers.setFixedHeight(72)
        self.headers.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.headers.setPlaceholderText("Extra headers (one per line)\nExample: X-Op: RedTeam\nX-Id: 123")

        # Force white placeholder + readable text for the headers box
        hdr_pal = self.headers.palette()
        hdr_pal.setColor(QPalette.PlaceholderText, QColor("#ffffff"))   # <- white placeholder
        hdr_pal.setColor(QPalette.Text, QColor("#e6e6e6"))              # <- entered text
        self.headers.setPalette(hdr_pal)
        # QAbstractScrollArea paints via its viewport; set it too for stubborn themes
        self.headers.viewport().setPalette(hdr_pal)

        hform.addRow("Beacon (s):", self.beacon)
        hform.addRow("Jitter (%):", self.jitter)
        hform.addRow("User-Agent:", self.useragent)
        hform.addRow("Accept:", self.accept)
        hform.addRow("Range:", self.byte_range)
        hform.addRow("Profile:", _prof_row)
        hform.addRow("Headers:", self.headers)

        # Advanced (EXE / PS1 tweaks)
        grp_adv = QGroupBox("Advanced")
        aform = QFormLayout(grp_adv); aform.setLabelAlignment(Qt.AlignRight)
        self.obs = QSpinBox(); self.obs.setRange(0, 5); self.obs.setValue(0)
        self.no_child = QCheckBox("Disable child process (PS1)")
        self.stager_ip = QLineEdit(); self.stager_ip.setPlaceholderText("Stager IP (EXE)")
        self.stager_port = QLineEdit(); self.stager_port.setPlaceholderText("Stager Port (EXE)")
        aform.addRow("Obfuscation:", self.obs)
        aform.addRow("", self.no_child)
        aform.addRow("Stager IP:", self.stager_ip)
        aform.addRow("Stager Port:", self.stager_port)

        # Keep handles to the autogenerated labels so we can hide/show whole rows
        self._lbl_obs        = aform.labelForField(self.obs)
        self._lbl_stager_ip  = aform.labelForField(self.stager_ip)
        self._lbl_stager_prt = aform.labelForField(self.stager_port)

        # Output (optional, like CLI -o/--output for TEXT formats)
        grp_out = QGroupBox("Output")
        oform = QFormLayout(grp_out); oform.setLabelAlignment(Qt.AlignRight)
        self.output_path = QLineEdit(); self.output_path.setPlaceholderText("Write text payload to file (optional)")
        self.btn_output = QPushButton("Browse…")
        self.btn_output.setCursor(Qt.PointingHandCursor)
        self.btn_output.setFixedHeight(28)
        self.btn_output.setStyleSheet(
            "QPushButton { background:#23272e; color:#e6e6e6; border:1px solid #3b404a;"
            "  border-radius:6px; padding:2px 10px; }"
            "QPushButton:hover { border-color:#5a6270; }"
        )
        _out_row = QWidget(); _out_lyt = QHBoxLayout(_out_row); _out_lyt.setContentsMargins(0,0,0,0); _out_lyt.setSpacing(6)
        _out_lyt.addWidget(self.output_path, 1); _out_lyt.addWidget(self.btn_output, 0)
        oform.addRow("File:", _out_row)

        # Generate button row
        self.btn_generate = QPushButton("Generate")
        self.btn_generate.setCursor(Qt.PointingHandCursor)
        self.btn_generate.setMinimumHeight(36)
        self.btn_generate.setStyleSheet(
            "QPushButton { background:#2c313a; color:#e6e6e6; border:1px solid #3b404a;"
            "  border-radius:6px; padding:6px 14px; font-weight:700; }"
            "QPushButton:hover { border-color:#5a6270; }"
        )

        self._fix_row_heights(
            self.platform, self.format, self.transport,
            self.host, self.port,
            self.beacon, self.jitter,
            self.useragent, self.accept, self.byte_range,
            self.profile, self.obs, self.stager_ip, self.stager_port,
            _prof_row, _out_row
        )

        # Left column itself prefers expanding vertically but respects minimums
        left_content.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)

        lyt.addWidget(grp_core)
        lyt.addWidget(grp_target)
        lyt.addWidget(grp_http)
        lyt.addWidget(grp_adv)
        lyt.addWidget(grp_out)
        lyt.addWidget(self.btn_generate)
        lyt.addStretch()

        # Make placeholders white (dark theme)
        pal = self.host.palette()
        pal.setColor(QPalette.PlaceholderText, QColor("#dfe6ee"))
        for w in (self.host, self.port, self.useragent, self.accept, self.byte_range, self.profile,
                  self.stager_ip, self.stager_port, self.output_path):
            w.setPalette(pal)

        # --- Right: Output --------------------------------------------------
        right = QWidget()
        rlyt = QVBoxLayout(right); rlyt.setContentsMargins(10, 10, 10, 10); rlyt.setSpacing(8)

        # Action row
        self.btn_copy = QPushButton("Copy")
        self.btn_save = QPushButton("Save…")
        self.btn_clear = QPushButton("Clear")
        for b in (self.btn_copy, self.btn_save, self.btn_clear):
            b.setCursor(Qt.PointingHandCursor)
            b.setMinimumHeight(30)
            b.setStyleSheet(
                "QPushButton { background:#23272e; color:#e6e6e6; border:1px solid #3b404a;"
                "  border-radius:6px; padding:4px 12px; }"
                "QPushButton:hover { border-color:#5a6270; }"
            )

        # --- Copied! toast just above the Copy button ---
        self._copied_label = QLabel("Copied!")
        self._copied_label.setVisible(False)
        self._copied_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self._copied_label.setStyleSheet(
            "QLabel { color:#00ff00; font-weight:700; padding:0px; }"  # GitHub-green-ish
        )
        self._copied_label.setFixedHeight(16)

        # stack label above the copy button
        copy_box = QWidget()
        copy_box_lyt = QVBoxLayout(copy_box)
        copy_box_lyt.setContentsMargins(0, 0, 0, 0)
        copy_box_lyt.setSpacing(2)
        copy_box_lyt.addWidget(self._copied_label, 0, Qt.AlignHCenter)
        copy_box_lyt.addWidget(self.btn_copy, 0, Qt.AlignHCenter)

        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(copy_box)         # <— use the wrapped copy widget
        actions.addWidget(self.btn_save)
        actions.addWidget(self.btn_clear)

        """actions = QHBoxLayout()
        actions.addStretch(); actions.addWidget(self.btn_copy); actions.addWidget(self.btn_save); actions.addWidget(self.btn_clear)"""

        # Output editor (fast for large plain text)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        f = QFont("DejaVu Sans Mono"); f.setPointSize(10); self.out.setFont(f)
        self.out.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.out.setStyleSheet(
            "QPlainTextEdit { background:#141820; color:#e6e6e6; border:1px solid #2a2f3a; }"
        )
        # micro-optimizations
        self.out.setCenterOnScroll(False)  # keep this one

        rlyt.addLayout(actions)
        rlyt.addWidget(self.out, stretch=1)


        # Make the left column scroll if it can't fit vertically
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.NoFrame)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        left_scroll.setWidget(left_content)
        self._init_smooth_scroll(left_scroll)  # Make the scrollbar feel silky

        # --- Splitter -------------------------------------------------------
        split = QSplitter(Qt.Horizontal)
        split.addWidget(left_scroll)
        split.addWidget(right)
        split.setOpaqueResize(True)        # live-resize, no rubber band
        split.setChildrenCollapsible(False)
        split.setCollapsible(0, False)
        split.setCollapsible(1, False)
        split.setHandleWidth(8)
        split.setStretchFactor(0, 1)       # config column
        split.setStretchFactor(1, 2)       # output column
        split.setSizes([420, 800])

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(split)

        # Save refs for visibility toggles
        self._grp_http = grp_http
        self._grp_adv = grp_adv
        self._grp_out = grp_out
        self._left_scroll = left_scroll  # Keep a handle so the eventFilter can find it
        self._apply_placeholder_color_all("#ffffff")

    def _show_copied_toast(self):
        lbl = self._copied_label
        if not hasattr(self, "_copied_fx"):
            self._copied_fx = QGraphicsOpacityEffect(lbl)
            lbl.setGraphicsEffect(self._copied_fx)

        fx = self._copied_fx
        lbl.setVisible(True)

        # Stop a previous run if still going
        if hasattr(self, "_copied_anim") and self._copied_anim is not None:
            try:
                self._copied_anim.stop()
            except Exception:
                pass

        fade_in = QPropertyAnimation(fx, b"opacity", lbl)
        fade_in.setDuration(150)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.OutCubic)

        hold = QPropertyAnimation(fx, b"opacity", lbl)
        hold.setDuration(700)
        hold.setStartValue(1.0)
        hold.setEndValue(1.0)

        fade_out = QPropertyAnimation(fx, b"opacity", lbl)
        fade_out.setDuration(350)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.setEasingCurve(QEasingCurve.InCubic)

        group = QSequentialAnimationGroup(lbl)
        group.addAnimation(fade_in)
        group.addAnimation(hold)
        group.addAnimation(fade_out)

        def _done():
            lbl.setVisible(False)

        group.finished.connect(_done)
        self._copied_anim = group
        group.start()

    # ---------- smooth scrolling setup ----------
    def _init_smooth_scroll(self, area):
        """
        Smooth, pixel-precise scrolling with:
            • animated wheel steps (no overshoot)
            • kinetic drag/flick (overshoot hard-disabled)
            • slim overlay-style scrollbar
        """
        # --- wheel animation (no bounce) ---
        self._smooth_anim = QPropertyAnimation(area.verticalScrollBar(), b"value", self)
        self._smooth_anim.setDuration(160)
        self._smooth_anim.setEasingCurve(QEasingCurve.OutCubic)
        area.verticalScrollBar().setSingleStep(18)  # small 'tick' but animated

        # --- kinetic scrolling via QScroller, overshoot OFF everywhere ---
        vp = area.viewport()
        vp.setAttribute(Qt.WA_AcceptTouchEvents, True)

        # Enable both mouse-drag and touch flicking
        QScroller.grabGesture(vp, QScroller.LeftMouseButtonGesture)
        QScroller.grabGesture(vp, QScroller.TouchGesture)

        scroller = QScroller.scroller(vp)

        # Version-safe enum handles (PyQt5 can expose these in slightly different places)
        SM = getattr(QScrollerProperties, "ScrollMetric", QScrollerProperties)
        OP = getattr(QScrollerProperties, "OvershootPolicy", None)

        props = scroller.scrollerProperties()
        props.setScrollMetric(SM.DecelerationFactor, 0.08)
        props.setScrollMetric(SM.MaximumVelocity, 0.75)
        props.setScrollMetric(SM.DragStartDistance, 0.002)
        props.setScrollMetric(SM.DragVelocitySmoothingFactor, 0.12)

        # Kill the spring effect completely (this is the key)
        props.setScrollMetric(SM.OvershootDragResistanceFactor, 0.0)
        props.setScrollMetric(SM.OvershootScrollDistanceFactor, 0.0)

        # Set the overshoot policy metric → AlwaysOff (robust across PyQt builds)
        metric_key = getattr(SM, "OvershootPolicy", int(getattr(SM, "OvershootPolicy", 6)))
        if OP and hasattr(OP, "OvershootAlwaysOff"):
            policy_off = getattr(OP, "OvershootAlwaysOff")
        else:
            policy_off = getattr(QScrollerProperties, "OvershootAlwaysOff", 1)
        props.setScrollMetric(metric_key, int(policy_off))

        scroller.setScrollerProperties(props)

        # If kinetic scroll ever tries to leave bounds, snap it back immediately
        def _enforce_edges(_state):
            if _state in (QScroller.Inactive, QScroller.Scrolling):
                sb = area.verticalScrollBar()
                if sb.value() < sb.minimum():
                    sb.setValue(sb.minimum())
                elif sb.value() > sb.maximum():
                    sb.setValue(sb.maximum())
        scroller.stateChanged.connect(_enforce_edges)

        # --- overlay scrollbar look ---
        area.setStyleSheet("""
            QScrollArea { background: transparent; }
            QAbstractScrollArea { background: transparent; }
            QScrollBar:vertical {
                background: transparent;
                width: 10px;
                margin: 4px 2px 4px 0;
            }
            QScrollBar::handle:vertical {
                background: #4a5160;
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::handle:vertical:hover { background: #5b6476; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
        """)

        # Intercept wheel events for pixel-precise, clamped animation
        vp.installEventFilter(self)

    def eventFilter(self, obj, ev):
        # Animate only the left scroller we wired up
        if getattr(self, "_left_scroll", None) and obj is self._left_scroll.viewport() and ev.type() == QEvent.Wheel:
            sb = self._left_scroll.verticalScrollBar()

            # Prefer pixelDelta (trackpads); fall back to angleDelta (traditional wheel)
            dy = ev.pixelDelta().y() if not ev.pixelDelta().isNull() else ev.angleDelta().y() / 8.0
            if dy:
                start = sb.value()
                target = int(max(sb.minimum(), min(sb.maximum(), start - dy)))

                # If we’re landing exactly at an edge, shorten the animation so it
                # feels crisp (and cannot ‘spring’ back).
                self._smooth_anim.stop()
                self._smooth_anim.setTargetObject(sb)
                self._smooth_anim.setStartValue(start)
                self._smooth_anim.setEndValue(target)
                self._smooth_anim.setDuration(110 if target in (sb.minimum(), sb.maximum()) else 160)
                self._smooth_anim.start()

                ev.accept()
                return True
        return super().eventFilter(obj, ev)

    def _apply_placeholder_color_all(self, hex_color: str = "#ffffff"):
        """Force placeholder text to a specific color for all inputs."""
        color = QColor(hex_color)

        def paint_placeholder(w):
            pal = w.palette()
            pal.setColor(QPalette.PlaceholderText, color)
            w.setPalette(pal)
            # QTextEdit/QPlainTextEdit draw on a viewport; set it too
            vp = getattr(w, "viewport", None)
            if callable(vp):
                vp().setPalette(pal)

        # Add every widget that uses placeholder text
        inputs = [
            self.host, self.port,
            self.useragent, self.accept, self.byte_range, self.profile,
            self.stager_ip, self.stager_port, self.output_path,
            self.headers,                      # QPlainTextEdit
        ]

        for w in inputs:
            paint_placeholder(w)


    # ---------- logic wiring / initial population ----------
    def _wire_init(self):
        # wire
        self.platform.currentIndexChanged.connect(self._on_platform_changed)
        self.format.currentIndexChanged.connect(self._refresh_transports)
        self.transport.currentIndexChanged.connect(self._on_transport_changed)
        self.btn_generate.clicked.connect(self._generate)
        self.btn_copy.clicked.connect(self._copy)
        self.btn_save.clicked.connect(self._save)
        self.btn_clear.clicked.connect(lambda: self.out.clear())
        self.btn_profile.clicked.connect(self._choose_profile)
        self.btn_output.clicked.connect(self._choose_output_file)
        # initial population based on current platform
        self._on_platform_changed()

    # ---------- dynamic variants ----------
    def _on_platform_changed(self):
        plat = self.platform.currentText()

        # (re)build formats when platform changes
        self.format.blockSignals(True)
        self.format.clear()
        if plat == "Windows":
            self.format.addItems(["ps1", "exe", "gunnerplant"])
        else:
            self.format.addItems(["bash"])
        self.format.blockSignals(False)

        # after formats exist, refresh transports for current selection
        self._refresh_transports()

    def _refresh_transports(self):
        """Rebuild transports when format OR platform changes, preserving selection when possible."""
        plat = self.platform.currentText()
        fmt = self.format.currentText()
        prev = self.transport.currentText().lower() if self.transport.count() else None

        self.transport.blockSignals(True)
        self.transport.clear()

        if plat == "Windows":
            # transport depends on format (gunnerplant -> https only)
            if fmt == "gunnerplant":
                # Gunnerplant is HTTPS only
                self.transport.addItems(["https"])
            else:
                self.transport.addItems(["tcp", "tls", "http", "https"])
        else:
            self.transport.addItems(["tcp", "http"])

        # choose a sensible current transport
        #  - keep previous if still valid
        #  - else default to https for gunnerplant, tcp otherwise
        if fmt == "gunnerplant":
            self.transport.setCurrentText("https")
            if prev and prev not in ("", "https"):
                # tell user why we switched
                QMessageBox.information(self, "Gunnerplant",
                    "Gunnerplant is only available over HTTPS. Transport has been set to HTTPS.")
        else:
            if prev and any(prev == self.transport.itemText(i).lower() for i in range(self.transport.count())):
                # restore previous
                # find with case-insensitive compare
                for i in range(self.transport.count()):
                    if self.transport.itemText(i).lower() == prev:
                        self.transport.setCurrentIndex(i); break
            else:
                self.transport.setCurrentText("tcp")

        self.transport.blockSignals(False)

        self._on_transport_changed()
        self._toggle_format_specific_fields()

    def _on_transport_changed(self):
        t = self.transport.currentText().lower()
        httpy = t in ("http", "https")
        self._grp_http.setVisible(httpy)
        # Title + enable/disable relevant inputs together
        if httpy:
            self._grp_http.setTitle("HTTPS Options" if t == "https" else "HTTP Options")
        for w in (self.beacon, self.jitter, self.useragent, self.accept, self.byte_range,
                  self.profile, self.btn_profile, self.headers):
            w.setEnabled(httpy)

        # PS1 no_child only affects PS1
        self.no_child.setVisible(self.platform.currentText() == "Windows" and self.format.currentText() == "ps1")
        self._toggle_format_specific_fields()

    def _toggle_format_specific_fields(self):
        """Visibility rules for fields tied to specific formats."""
        fmt = self.format.currentText().lower()
        plat = self.platform.currentText()
        # Stager fields: only for exe & gunnerplant
        is_exe_like = (plat == "Windows" and fmt in ("exe", "gunnerplant"))
        for w in (self.stager_ip, self.stager_port, self._lbl_stager_ip, self._lbl_stager_prt):
            w.setVisible(is_exe_like)
        # Obfuscation: only for ps1 or bash
        show_obs = (fmt in ("ps1", "bash"))
        for w in (self.obs, self._lbl_obs):
            w.setVisible(show_obs)
        # PS1 only: no_child toggle
        self.no_child.setVisible(plat == "Windows" and fmt == "ps1")

    # ---------- helpers ----------
    def _headers_dict(self):
        txt = self.headers.toPlainText().strip()
        if not txt:
            return None
        out = {}
        for line in txt.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
        return out or None

    def _validate_host_port(self):
        host = self.host.text().strip()
        if not host:
            raise ValueError("Host/IP is required")
        try:
            port = int(self.port.text().strip())
        except Exception:
            raise ValueError("Port must be an integer")
        if not (1 <= port <= 65535):
            raise ValueError("Port out of range (1-65535)")
        return host, port

    def _choose_profile(self):
        """Pick a .profile file and store its absolute path."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Profile", "", "Profile files (*.profile);;All files (*)"
        )
        if path:
            self.profile.setText(path)

    def _choose_output_file(self):
        """Pick a local path to write text payloads (ps1/bash)."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Select Output File", "payload.txt", "All Files (*);;Text (*.txt)"
        )
        if path:
            self.output_path.setText(path)

    # ---------- actions ----------
    def _generate(self):
        plat = self.platform.currentText()
        fmt = self.format.currentText().lower()
        t = self.transport.currentText().lower()
        try:
            host, port = self._validate_host_port()
        except Exception as e:
            QMessageBox.warning(self, "Payload", str(e)); return

        try:
            if plat == "Windows":
                # Validate EXE/Gunnerplant stager requirements
                if fmt in ("exe", "gunnerplant"):
                    sip = self.stager_ip.text().strip()
                    sp  = self.stager_port.text().strip()
                    if not sip:
                        QMessageBox.warning(self, "Payload", "Stager IP is required for EXE/Gunnerplant.")
                        return
                    try:
                        sp_int = int(sp)
                    except Exception:
                        QMessageBox.warning(self, "Payload", "Stager Port must be an integer for EXE/Gunnerplant.")
                        return
                    if not (1 <= sp_int <= 65535):
                        QMessageBox.warning(self, "Payload", "Stager Port out of range (1-65535).")
                        return
                cfg = {
                    "format": fmt, "transport": t, "host": host, "port": port,
                    "obs": self.obs.value(),
                    "no_child": bool(self.no_child.isChecked()),
                    "beacon": self.beacon.value(),
                    "jitter": self.jitter.value(),
                    "headers": self._headers_dict(),
                    "useragent": self.useragent.text().strip() or None,
                    "accept": self.accept.text().strip() or None,
                    "byte_range": self.byte_range.text().strip() or None,
                    "profile": (self.profile.text().strip() or None) if t in ("http", "https") else None,
                    "stager_ip": self.stager_ip.text().strip() or "0.0.0.0",
                    "stager_port": int(self.stager_port.text().strip() or "9999"),
                }
                # gunnerplant is HTTPS only; guard gently
                if fmt == "gunnerplant" and t != "https":
                    QMessageBox.warning(self, "Payload", "Gunnerplant requires HTTPS transport")
                    return

                # For EXE/GunnerPlant, give immediate visual feedback in the right pane
                if fmt in ("exe", "gunnerplant"):
                    if fmt == "exe":
                        self.out.setPlainText("Building exe payload …")
                    else:
                        self.out.setPlainText("Building GunnerPlant payload …")
                txt = self.api.generate_windows_payload(cfg)

            else:
                cfg = {
                    "format": "bash", "transport": t, "host": host, "port": port,
                    "obs": self.obs.value(), "beacon": self.beacon.value(),
                    "use_ssl": False
                }
                txt = self.api.generate_linux_payload(cfg)

        except Exception as e:
            QMessageBox.critical(self, "Generate", str(e)); return

        # If an EXE/GunnerPlant build, backend returns the built path. Display a friendly line.
        if plat == "Windows" and fmt in ("exe", "gunnerplant"):
            built = (txt or f"{fmt}").strip()
            if built:
                self.out.setPlainText(f"Successfully built {built}")
            else:
                self.out.setPlainText(txt or "")
            return

        if fmt not in ("exe", "gunnerplant"):
            # Text formats (ps1/bash): optionally auto-write like CLI -o/--output
            out_path = (self.output_path.text() or "").strip()
            if out_path:
                try:
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(txt or "")
                    # Prepend a small confirmation, then the payload body
                    self.out.setPlainText(f"[+] Payload written to {out_path}\n\n{txt or ''}")
                except Exception as e:
                    QMessageBox.critical(self, "Output", f"Failed to write {out_path}:\n{e}")
                    self.out.setPlainText(txt or "")
            else:
                self.out.setPlainText(txt or "")

        else:
            return

    def _copy(self):
        txt = self.out.toPlainText()
        if not txt:
            return
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(txt)
        self._show_copied_toast()

    def _save(self):
        txt = self.out.toPlainText()
        if not txt:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Payload", "payload.txt", "All Files (*);;Text (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
        except Exception as e:
            QMessageBox.critical(self, "Save", str(e))