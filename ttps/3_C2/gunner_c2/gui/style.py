# gui/style.py
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtWidgets import QGraphicsDropShadowEffect

# ---- Theme tokens (tweak these) --------------------------------------------
ACCENT        = "#2ee66b"   # brand accent
ACCENT_HOVER  = "#24c85a"
ACCENT_PRESS  = "#1fae4f"

BG            = "#0b0f14"   # app background
PANEL         = "#11161c"   # elevated panes/cards/menus
PANEL_ALT     = "#0f141b"   # inputs
STROKE        = "#1e2430"   # subtle borders
STROKE_HOVER  = "#2a3544"

TEXT          = "#e7eef7"
MUTED         = "#9fb5cc"

def _global_qss() -> str:
    return f"""
    /* Base */
    QWidget {{
        background: {BG};
        color: {TEXT};
        selection-background-color: {ACCENT};
        selection-color: #0b0f14;
    }}

    /* Remove noisy frames everywhere by default */
    QFrame, QGroupBox {{
        border: none;
    }}

    /* Prevent Fusion’s extra focus rectangle so we don't get a double border */
    QFocusFrame {{ border: 0; padding: 0; margin: 0; }}

    /* Inputs — single, clean border that turns green on focus */
    QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {{
        background: #0f141b;
        color: #e5edf6;
        border: 1px solid #2a3544;
        border-radius: 8px;
        padding: 8px 10px;
        }}

    QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {{
        border: 1px solid #2ea043; /* your brand green */
    }}

    /* Inputs */
    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
        background: {PANEL_ALT};
        border: 1px solid {STROKE};
        border-radius: 8px;
        padding: 6px 10px;
    }}
    QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover,
    QPlainTextEdit:hover, QTextEdit:hover {{
        border-color: {STROKE_HOVER};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus,
    QPlainTextEdit:focus, QTextEdit:focus {{
        border-color: {ACCENT};
    }}
    QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled,
    QPlainTextEdit:disabled, QTextEdit:disabled {{
        color: {MUTED};
        border-color: {STROKE};
        background: {PANEL};
    }}

    /* Buttons (default) */
    QPushButton {{
        background: #1b242f;
        border: 1px solid {STROKE};
        border-radius: 8px;
        padding: 7px 12px;
        color: {TEXT};
        font-weight: 600;
    }}
    QPushButton:hover {{ background: #202b39; border-color: {STROKE_HOVER}; }}
    QPushButton:pressed {{ background: #182230; }}
    QPushButton:disabled {{ color: {MUTED}; background: {PANEL}; border-color: {STROKE}; }}

    /* Primary action variant — set objectName('primary') on the widget */
    QPushButton#primary {{
        background: {ACCENT};
        border-color: {ACCENT};
        color: #0b0f14;
    }}
    QPushButton#primary:hover  {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
    QPushButton#primary:pressed{{ background: {ACCENT_PRESS};  border-color: {ACCENT_PRESS};  }}

    /* Menus */
    QMenu {{
        background: {PANEL};
        color: {TEXT};
        border: 1px solid {STROKE};
    }}
    QMenu::separator {{
        height: 1px; background: {STROKE}; margin: 6px 8px;
    }}
    QMenu::item {{
        padding: 6px 14px;
        background: transparent;
    }}
    QMenu::item:selected {{
        background: #1a2230;
    }}
    QMenu::item:disabled {{
        color: {MUTED};
    }}

    /* Tabs */
    QTabWidget::pane {{
        border: 1px solid {STROKE};
        border-radius: 6px;
        top: -1px;
    }}
    QTabBar::tab {{
        background: {PANEL};
        border: 1px solid {STROKE};
        border-bottom-color: transparent;
        padding: 6px 10px;
        margin-right: 2px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
    }}
    QTabBar::tab:selected {{
        background: {PANEL_ALT};
        border-color: {STROKE_HOVER};
    }}
    QTabBar::tab:disabled {{ color: {MUTED}; }}

    /* Scrollbars (slim, unobtrusive) */
    QScrollBar:vertical {{
        background: {PANEL};
        width: 10px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {STROKE};
        border-radius: 5px;
        min-height: 24px;
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

    QToolTip {{
        background: {PANEL};
        color: {TEXT};
        border: 1px solid {STROKE};
        padding: 4px 8px;
        border-radius: 6px;
    }}
    """

def apply_app_style(app):
    # Fusion + palette, then global QSS
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(BG))
    pal.setColor(QPalette.Base, QColor(PANEL_ALT))
    pal.setColor(QPalette.Button, QColor(PANEL))
    pal.setColor(QPalette.Text, QColor(TEXT))
    pal.setColor(QPalette.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.HighlightedText, QColor("#0b0f14"))
    app.setPalette(pal)
    app.setStyleSheet(_global_qss())

def add_drop_shadow(w, blur=24, dx=0, dy=8, alpha=120):
    eff = QGraphicsDropShadowEffect(w)
    eff.setBlurRadius(blur)
    eff.setOffset(dx, dy)
    eff.setColor(QColor(0, 0, 0, alpha))
    w.setGraphicsEffect(eff)
