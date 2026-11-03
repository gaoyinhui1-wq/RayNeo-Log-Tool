"""Quiet Notepad shell; VS Code Light+ log colors live in viewer.py."""

NOTEPAD_STYLE = """
QMainWindow, QWidget { background:#fafafa; color:#202020; }
QMenuBar { background:#f3f3f3; border-bottom:1px solid #e3e3e3; padding:2px 4px; }
QMenuBar::item { padding:5px 10px; background:transparent; }
QMenuBar::item:selected, QMenu::item:selected { background:#e5edf5; }
QMenu { background:white; border:1px solid #dedede; padding:4px; }
QMenu::separator { height:1px; background:#e3e3e3; margin:4px; }
#ToolStrip, #SubStrip { background:#f3f3f3; border-bottom:1px solid #e3e3e3; }
#FilePanel { background:#f8f8f8; border-right:1px solid #e3e3e3; }
QTabBar { background:#f3f3f3; }
QTabBar::tab { background:#eeeeee; color:#5a5a5a; padding:6px 14px; border:0; margin:2px 2px 0 0; }
QTabBar::tab:selected { background:white; color:#202020; border-top:2px solid #2675bf; }
QTabBar::tab:hover:!selected { background:#e5e5e5; }
QTabWidget::pane { border:0; border-top:1px solid #dedede; background:white; }
QPlainTextEdit, QTableView, QListWidget { background:white; color:#24292f; border:0;
 selection-background-color:#ddedfc; selection-color:#202020; }
QPlainTextEdit#ReportView { padding:10px 12px; font:10pt "Segoe UI"; }
QTableView { alternate-background-color:#f7f7f7; gridline-color:#eeeeee; }
QListWidget::item { padding:4px 6px; }
QTableView::item:selected, QListWidget::item:selected { background:#ddedfc; color:#174b78; }
QHeaderView::section { background:#f5f5f5; border:0; border-bottom:1px solid #e3e3e3; padding:4px 7px; }
QPushButton { background:#fafafa; border:1px solid #d6d6d6; border-radius:4px;
 padding:4px 9px; min-height:20px; }
QPushButton:hover { background:#ebebeb; border-color:#b5b5b5; }
QPushButton:pressed { background:#dfdfdf; }
QPushButton:disabled { color:#999; background:#f4f4f4; }
QPushButton#AnalyzeButton { background:#0969da; border-color:#0969da; color:white; }
QPushButton#AnalyzeButton:hover { background:#0550ae; }
QPushButton#AnalyzeButton:disabled { background:#bdcddd; border-color:#bdcddd; }
QLineEdit, QComboBox, QDateEdit, QTimeEdit, QDateTimeEdit {
 background:white; border:1px solid #d4d4d4; border-radius:3px; padding:3px 5px; }
QLineEdit:focus, QComboBox:focus, QDateEdit:focus, QDateTimeEdit:focus { border-color:#2675bf; }
QComboBox QAbstractItemView { background:white; selection-background-color:#ddedfc; }
QSplitter::handle { background:#e7e7e7; }
QSplitter::handle:hover { background:#9cc8ef; }
#SearchBar { background:#fafafa; border:1px solid #c7c7c7; border-radius:4px; }
#BottomStrip, QStatusBar { background:#f3f3f3; border-top:1px solid #e3e3e3; }
#StatusHint { color:#555; }
QProgressBar { background:#e7e7e7; border:0; }
QProgressBar::chunk { background:#0969da; }
QCheckBox { background:transparent; spacing:5px; }
QToolTip { background:#fff; color:#202020; border:1px solid #d4d4d4; padding:4px; }
"""
