# gui/theme_center.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Callable, Optional
from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtGui import QPalette, QColor, QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout, QComboBox, QLabel, QPushButton,
    QSlider, QColorDialog, QDialog, QGroupBox, QFormLayout, QCheckBox
)

def qc(x) -> QColor:
    if isinstance(x, QColor): return QColor(x)
    x = str(x).strip()
    return QColor(x) if x.startswith("#") else QColor(x)

@dataclass
class Theme:
    name: str
    # QPalette roles (min set; Qt will derive others)
    window: QColor
    base: QColor
    alt_base: QColor
    text: QColor
    disabled_text: QColor
    button: QColor
    button_text: QColor
    highlight: QColor
    highlighted_text: QColor
    link: QColor
    # custom named colors for paint code / QSS
    colors: Dict[str, QColor] = field(default_factory=dict)
    # default app font point size
    base_font_pt: int = 10

    def with_accent(self, accent: QColor) -> "Theme":
        t = Theme(**{**self.__dict__})
        t.colors = dict(self.colors)
        t.colors["accent"] = qc(accent)
        t.highlight = qc(accent)
        t.link = qc(accent)
        return t

# ---- Built-in themes ----
MIDNIGHT = Theme(
    name="Midnight (Dark)",
    window=qc("#10151c"),
    base=qc("#141820"),
    alt_base=qc("#1b212b"),
    text=qc("#e6e6e6"),
    disabled_text=qc("#9aa3ad"),
    button=qc("#2c313a"),
    button_text=qc("#e9eaec"),
    highlight=qc("#5a93ff"),
    highlighted_text=qc("#ffffff"),
    link=qc("#5a93ff"),
    colors={
        "accent": qc("#5a93ff"),
        "border": qc("#3b404a"),
        "header_bg": qc("#202633"),
        "scroll_handle": qc("#4a5160"),
        "scroll_handle_hover": qc("#5b6476"),
        "chip_operator_bg": qc("#34425a"),
        "chip_operator_fg": qc("#dbe7ff"),
        "chip_admin_bg": qc("#5a3434"),
        "chip_admin_fg": qc("#ffd6d6"),
        "neon": qc("#39ff14"),
        "neon_dim": qc("#2dc810"),
        "danger": qc("#e82e2e"),
        "warning": qc("#ff8c00"),
    },
    base_font_pt=10,
)

LIGHT = Theme(
    name="Light",
    window=qc("#f6f7fb"),
    base=qc("#ffffff"),
    alt_base=qc("#f0f2f6"),
    text=qc("#1f2328"),
    disabled_text=qc("#8b949e"),
    button=qc("#e9ecf3"),
    button_text=qc("#1f2328"),
    highlight=qc("#2e6fff"),
    highlighted_text=qc("#ffffff"),
    link=qc("#2e6fff"),
    colors={
        "accent": qc("#2e6fff"),
        "border": qc("#c9cbd3"),
        "header_bg": qc("#eaedf4"),
        "scroll_handle": qc("#c3c8d4"),
        "scroll_handle_hover": qc("#aeb6c8"),
        "chip_operator_bg": qc("#d6e4ff"),
        "chip_operator_fg": qc("#0a2a66"),
        "chip_admin_bg": qc("#ffe1e1"),
        "chip_admin_fg": qc("#661a1a"),
        "neon": qc("#007a00"),
        "neon_dim": qc("#008f00"),
        "danger": qc("#cc1e1e"),
        "warning": qc("#b36100"),
    },
    base_font_pt=10,
)

HIGH_CONTRAST = Theme(
    name="High Contrast",
    window=qc("#000000"),
    base=qc("#121212"),
    alt_base=qc("#1a1a1a"),
    text=qc("#ffffff"),
    disabled_text=qc("#bdbdbd"),
    button=qc("#1f1f1f"),
    button_text=qc("#ffffff"),
    highlight=qc("#00b7ff"),
    highlighted_text=qc("#000000"),
    link=qc("#00b7ff"),
    colors={
        "accent": qc("#00b7ff"),
        "border": qc("#4d4d4d"),
        "header_bg": qc("#151515"),
        "scroll_handle": qc("#7a7a7a"),
        "scroll_handle_hover": qc("#a0a0a0"),
        "chip_operator_bg": qc("#1f4a6a"),
        "chip_operator_fg": qc("#e0f3ff"),
        "chip_admin_bg": qc("#5a1f1f"),
        "chip_admin_fg": qc("#ffdada"),
        "neon": qc("#00ff3b"),
        "neon_dim": qc("#00c92d"),
        "danger": qc("#ff4040"),
        "warning": qc("#ff9d00"),
    },
    base_font_pt=11,
)

_BUILTINS = {t.name: t for t in (MIDNIGHT, LIGHT, HIGH_CONTRAST)}

def make_palette(t: Theme) -> QPalette:
    pal = QPalette()
    pal.setColor(QPalette.Window, t.window)
    pal.setColor(QPalette.WindowText, t.text)
    pal.setColor(QPalette.Base, t.base)
    pal.setColor(QPalette.AlternateBase, t.alt_base)
    pal.setColor(QPalette.ToolTipBase, t.base)
    pal.setColor(QPalette.ToolTipText, t.text)
    pal.setColor(QPalette.Text, t.text)
    pal.setColor(QPalette.Button, t.button)
    pal.setColor(QPalette.ButtonText, t.button_text)
    pal.setColor(QPalette.Highlight, t.highlight)
    pal.setColor(QPalette.HighlightedText, t.highlighted_text)
    pal.setColor(QPalette.Link, t.link)
    pal.setColor(QPalette.Disabled, QPalette.Text, t.disabled_text)
    pal.setColor(QPalette.Disabled, QPalette.WindowText, t.disabled_text)
    pal.setColor(QPalette.Disabled, QPalette.ButtonText, t.disabled_text)
    pal.setColor(QPalette.Disabled, QPalette.ToolTipText, t.disabled_text)
    return pal

def build_global_qss(t: Theme) -> str:
    c = t.colors
    b = c["border"].name()
    acc = c["accent"].name()
    header_bg = c["header_bg"].name()
    sh = c["scroll_handle"].name()
    shh = c["scroll_handle_hover"].name()

    return f"""
    QWidget {{
        background: {t.window.name()};
        color: {t.text.name()};
        font-size: {t.base_font_pt}pt;
    }}

    /* --- Menus (fixes invisible hover/selection) --- */
    QMenu {{
        background: {t.base.name()};
        color: {t.text.name()};
        border: 1px solid {b};
        padding: 4px;
        border-radius: 6px;
    }}
    QMenu::separator {{
        height: 1px;
        background: {b};
        margin: 6px 8px;
    }}
    QMenu::item {{
        padding: 6px 14px;
        border-radius: 4px;
    }}
    QMenu::item:selected {{
        background: {t.highlight.name()};
        color: {t.highlighted_text.name()};
    }}
    QMenu::item:disabled {{
        color: {t.disabled_text.name()};
    }}
    /* Checkable items — make the indicator visible in stylesheet mode */
    QMenu::indicator {{
        width: 16px; height: 16px;
        border: 1px solid {b};
        border-radius: 3px;
        background: transparent;
        margin-right: 6px;
    }}
    QMenu::indicator:checked {{
        background: {acc};
        border-color: {acc};
    }}

    QGroupBox {{
        border: 1px solid {b};
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 8px;
    }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}

    QPushButton {{
        background: {t.button.name()};
        color: {t.button_text.name()};
        border: 1px solid {b};
        border-radius: 6px;
        padding: 6px 12px;
        font-weight: 600;
    }}
    QPushButton:hover {{ border-color: {acc}; }}

    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox {{
        background: {t.base.name()};
        color: {t.text.name()};
        border: 1px solid {b};
        border-radius: 6px;
        selection-background-color: {t.highlight.name()};
        selection-color: {t.highlighted_text.name()};
    }}
    QHeaderView::section {{
        background: {header_bg};
        color: {t.text.name()};
        border: 1px solid {b};
        padding: 6px;
    }}
    QTableView {{
        gridline-color: {b};
        alternate-background-color: {t.alt_base.name()};
        selection-background-color: {t.highlight.name()};
        selection-color: {t.highlighted_text.name()};
    }}
    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 4px 2px 4px 0;
    }}
    QScrollBar::handle:vertical {{
        background: {sh};
        border-radius: 5px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {shh}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
    """

class ThemeManager(QObject):
    themeChanged = pyqtSignal(object)  # emits Theme

    _instance: Optional["ThemeManager"] = None

    def __init__(self):
        super().__init__()
        self._themes = dict(_BUILTINS)
        self._current: Theme = MIDNIGHT
        self._font_scale = 1.0

    @classmethod
    def instance(cls) -> "ThemeManager":
        if not cls._instance:
            cls._instance = ThemeManager()
        return cls._instance

    def install(self, app: QApplication, theme_name: str | None = None):
        from PyQt5.QtCore import QSettings
        st = QSettings("GunnerC2", "Console")
        name = theme_name or st.value("theme/name", MIDNIGHT.name)
        accent_hex = st.value("theme/accent", "")
        scale = float(st.value("theme/font_scale", 1.0))
        self._font_scale = max(0.8, min(1.4, scale))
        base = self._themes.get(name, MIDNIGHT)
        if accent_hex:
            base = base.with_accent(qc(accent_hex))
        self.apply(app, base)

    def apply(self, app: QApplication, theme: Theme):
        # font scaling
        base_pt = max(7, int(round(theme.base_font_pt * self._font_scale)))
        app.setFont(QFont(app.font().family(), base_pt))

        pal = make_palette(theme)
        app.setPalette(pal)
        app.setStyleSheet(build_global_qss(theme))
        self._current = theme
        self.themeChanged.emit(theme)
        # persist
        from PyQt5.QtCore import QSettings
        st = QSettings("GunnerC2", "Console")
        st.setValue("theme/name", theme.name)
        st.setValue("theme/accent", theme.colors.get("accent", qc("#5a93ff")).name())
        st.setValue("theme/font_scale", self._font_scale)

    def set_theme_by_name(self, app: QApplication, name: str):
        self.apply(app, self._themes.get(name, MIDNIGHT))

    def set_accent(self, app: QApplication, color: QColor):
        self.apply(app, self._current.with_accent(color))

    def set_font_scale(self, app: QApplication, scale: float):
        self._font_scale = max(0.8, min(1.4, float(scale)))
        self.apply(app, self._current)

    def current(self) -> Theme:
        return self._current

    def register_theme(self, theme: Theme):
        self._themes[theme.name] = theme

    def theme_names(self) -> list[str]:
        return list(self._themes.keys())

# Convenience accessor for painter code
def theme_color(key: str, fallback: str | QColor = "#ff00ff") -> QColor:
    try:
        tm = ThemeManager.instance()
        return qc(tm.current().colors.get(key, qc(fallback)))
    except Exception:
        return qc(fallback)

# ---- Small UI panel to switch themes at runtime ----
class ThemePanel(QDialog):
    def __init__(self, app: QApplication, parent: QWidget = None):
        super().__init__(parent)
        self.setWindowTitle("Theme")
        self.setModal(False)
        self._app = app
        self._tm = ThemeManager.instance()

        grp = QGroupBox("Appearance", self)
        form = QFormLayout(grp)

        self.cmb = QComboBox()
        self.cmb.addItems(self._tm.theme_names())
        self.cmb.setCurrentText(self._tm.current().name)

        self.btn_accent = QPushButton("Pick Accent…")
        self.chk_huge = QCheckBox("Large UI")
        self.chk_huge.setToolTip("Increase base font size by ~20%")
        self.chk_huge.setChecked(False)

        form.addRow("Theme:", self.cmb)
        form.addRow("Accent:", self.btn_accent)
        form.addRow("", self.chk_huge)

        btn_apply = QPushButton("Apply")
        btn_close = QPushButton("Close")
        btns = QHBoxLayout()
        btns.addStretch()
        btns.addWidget(btn_apply)
        btns.addWidget(btn_close)

        root = QVBoxLayout(self)
        root.addWidget(grp)
        root.addLayout(btns)

        btn_apply.clicked.connect(self._apply)
        btn_close.clicked.connect(self.close)
        self.btn_accent.clicked.connect(self._pick_accent)

        self.resize(360, self.sizeHint().height())

    def _pick_accent(self):
        c0 = self._tm.current().colors.get("accent", qc("#5a93ff"))
        c = QColorDialog.getColor(c0, self, "Select Accent Color")
        if c.isValid():
            self._tm.set_accent(self._app, c)

    def _apply(self):
        self._tm.set_theme_by_name(self._app, self.cmb.currentText())
        self._tm.set_font_scale(self._app, 1.2 if self.chk_huge.isChecked() else 1.0)
