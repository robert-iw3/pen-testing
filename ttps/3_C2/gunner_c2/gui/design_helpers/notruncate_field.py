# gui/_table_no_truncate.py
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QStyledItemDelegate, QTableView, QHeaderView, QAbstractItemView

class _NoElideDelegate(QStyledItemDelegate):
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.textElideMode = Qt.ElideNone  # show full text, no "..."

def make_column_not_truncated(view: QTableView, column: int, monospace: bool = True) -> None:
    """
    Ensures the given column never shows '…' and is fully readable.
    - Disables text eliding
    - Uses ResizeToContents for that column
    - Enables horizontal scroll as needed
    - (optional) Monospace font for nice UUID alignment
    """
    # 1) never elide
    view.setTextElideMode(Qt.ElideNone)
    view.setWordWrap(False)
    view.setItemDelegateForColumn(column, _NoElideDelegate(view))

    # 2) size to contents; allow horizontal scroll
    header = view.horizontalHeader()
    header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
    header.setStretchLastSection(False)  # don't steal space from the ID column

    view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    view.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)

    # 3) (nice to have) monospace so IDs are easier to scan/copy
    if monospace:
        f = view.font()
        f.setFamily("Monospace")      # falls back appropriately cross-platform
        f.setStyleHint(QFont.TypeWriter)
        view.setFont(f)
