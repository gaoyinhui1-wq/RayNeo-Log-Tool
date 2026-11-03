# -*- coding: utf-8 -*-
import os
import sys
import re
import shutil
from pathlib import Path
from datetime import datetime
from collections import Counter, OrderedDict
from bisect import bisect_right
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QFileDialog,
    QListWidget,
    QPlainTextEdit,
    QProgressBar,
    QSplitter,
    QFrame,
    QLineEdit,
    QMessageBox,
    QDateEdit,
    QTimeEdit,
    QDateTimeEdit,
    QComboBox,
    QAbstractItemView,
    QTabWidget,
    QCheckBox,
    QTabBar,
)
from PyQt6.QtCore import Qt, QDate, QTime, QDateTime, QEvent
from PyQt6.QtGui import QFont, QColor, QAction
from PyQt6.QtWidgets import QTableView, QDialog, QDialogButtonBox
from PyQt6.QtCore import QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QBrush
from . import rules as rule_config
from .dialogs import InputDialog
from .background import DecryptExportThread, FileReadThread, PreviewOpenThread
from .rules import open_rules_file
from .search import FindNextThread, MatchResultModel, MatchSearchThread
from .viewer import VSCodeReportHighlighter, VirtualLogViewer


class AppWindow(QMainWindow):
    """Compact Notepad++-style UI. All slow analysis/search/decode jobs are QThreads."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("RayNeo Log Tool")
        screen = (
            QApplication.screenAt(
                QApplication.primaryScreen().availableGeometry().center()
            )
            if QApplication.primaryScreen()
            else None
        )
        available = screen.availableGeometry() if screen else None
        if available:
            # 所有尺寸都使用 Qt 逻辑像素，兼容 Windows 125% / 150% 缩放。
            window_w = min(
                1040,
                max(570, int(available.width() * 0.77)),
                max(570, available.width() - 48),
            )
            window_h = min(
                635,
                max(420, int(available.height() * 0.78)),
                max(420, available.height() - 60),
            )
            window_w = min(window_w, max(450, available.width() - 40))
            window_h = min(window_h, max(360, available.height() - 55))
            self.resize(window_w, window_h)
            self.move(
                available.x() + (available.width() - window_w) // 2,
                available.y() + (available.height() - window_h) // 2,
            )
        else:
            self.resize(900, 580)
        self.setMinimumSize(570, 390)
        self.setAcceptDrops(True)
        self.raw_data = {}
        self.file_list_data = []
        self.incidents = []
        self.current_file = None
        self.last_open_paths = None
        self.last_is_file_list = True
        self.prepared_payload = None
        self.available_dates = []
        self.device_info = {}
        self._analysis_pending = False
        self._preview_pending = False
        self.worker = None
        self.search_worker = None
        self.find_worker = None
        self._find_generation = 0
        self.decrypt_worker = None
        self.preview_worker = None
        self.file_read_worker = None
        self._pending_selected_path = None
        self._pending_goto = None
        self._line_index_cache = OrderedDict()
        self._tab_paths = []
        self.find_key = None
        self.find_offset = 0
        self._search_generation = 0
        self._closing = False
        self._files_are_prepared = False
        self.ui_font = QFont("Segoe UI", 9)
        self.code_font = QFont("Consolas", 9)
        self.build_ui()
        self.update_time_widgets()
        self.setStyleSheet(self.styles())
        self._temp_dirs = set()
        self._import_notes = []
        self._import_metadata_paths = []
        self._input_generation = 0
        self.statusBar().showMessage(
            "就绪 · 拖入文件、文件夹或压缩包 · Ctrl+O 打开 · F5 分析"
        )

    def action(self, menu, title, shortcut, slot):
        act = QAction(title, self)
        if shortcut:
            act.setShortcut(shortcut)
        act.triggered.connect(slot)
        menu.addAction(act)
        return act

    def build_ui(self):
        m_file = self.menuBar().addMenu("文件(&F)")
        self.action(m_file, "打开日志…", "Ctrl+O", self.choose_open_source)
        self.action(m_file, "打开文件 / 压缩包...", None, self.open_file_dialog)
        self.action(m_file, "打开文件夹...", "Ctrl+Shift+O", self.open_folder_dialog)
        self.action(m_file, "导出分析报告...", "Ctrl+E", self.export_analysis)
        m_file.addSeparator()
        self.action(m_file, "退出", "Ctrl+Q", self.close)
        m_search = self.menuBar().addMenu("搜索(&S)")
        self.action(m_search, "查找...", "Ctrl+F", self.show_find)
        self.action(m_search, "全部筛选...", "Ctrl+Shift+F", self.show_filter)
        self.action(m_search, "查找下一个", "F3", self.find_next)
        self.action(m_search, "跳转行...", "Ctrl+G", self.focus_jump)
        m_view = self.menuBar().addMenu("视图(&V)")
        self.action_file_panel = self.action(
            m_view, "切换文件列表", "Alt+1", self.toggle_files
        )
        self.action_result_panel = self.action(
            m_view, "切换结果面板", "Alt+2", self.toggle_results
        )
        m_tool = self.menuBar().addMenu("工具(&T)")
        self.action(
            m_tool, "本地解密 / 解压...", "Ctrl+Shift+D", self.open_decrypt_dialog
        )
        self.action(m_tool, "编辑异常判定规则...", None, self.open_rule_editor)
        self.action_analyze = self.action(m_tool, "开始分析", "F5", self.reanalyze)
        self.action(m_tool, "复制分析报告", None, self.copy_analysis)

        base = QWidget(self)
        self.setCentralWidget(base)
        layout = QVBoxLayout(base)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        # 两行紧凑工具栏：主要操作始终可见，不能被分析范围挤出窗口。
        tools = QFrame()
        tools.setObjectName("ToolStrip")
        tool_col = QVBoxLayout(tools)
        tool_col.setContentsMargins(7, 4, 7, 4)
        tool_col.setSpacing(4)
        actions_row = QHBoxLayout()
        actions_row.setSpacing(5)

        def add_btn(title, fn, tip=None):
            btn = QPushButton(title)
            btn.clicked.connect(fn)
            btn.setToolTip(tip or title)
            actions_row.addWidget(btn)
            return btn

        # 点击按钮直接弹出来源选择，不依赖隐藏的小箭头/菜单。
        self.btn_open = add_btn(
            "打开日志…",
            self.choose_open_source,
            "选择本地文件、压缩包或整个文件夹（Ctrl+O）",
        )
        self.btn_open.setObjectName("OpenButton")
        self.btn_analyze = add_btn("▶ 开始分析", self.reanalyze, "F5 启动异常分析")
        self.btn_analyze.setObjectName("AnalyzeButton")
        self.has_analyzed = False
        self.btn_find = add_btn("查找", self.show_find, "Ctrl+F")
        self.btn_find.setObjectName("SearchButton")
        self.btn_search = add_btn("筛选", self.show_filter, "Ctrl+Shift+F")
        self.btn_search.setObjectName("FilterButton")
        actions_row.addStretch(1)
        tool_col.addLayout(actions_row)
        scope_row = QHBoxLayout()
        scope_row.setSpacing(5)
        scope_row.addWidget(QLabel("分析范围"))
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(
            ["全部日志", "按日期分析", "按时间分析", "多时间点分析", "按测试周期分析"]
        )
        self.combo_mode.currentIndexChanged.connect(self.update_time_widgets)
        scope_row.addWidget(self.combo_mode)
        self.btn_rules = QPushButton("编辑异常规则")
        self.btn_rules.setObjectName("RulesButton")
        self.btn_rules.clicked.connect(self.open_rule_editor)
        scope_row.addWidget(self.btn_rules)
        scope_row.addStretch(1)
        tool_col.addLayout(scope_row)
        self.lbl_status = QLabel("准备就绪")
        self.lbl_status.setObjectName("StatusHint")
        self.lbl_status.setMaximumWidth(180)
        self.statusBar().addPermanentWidget(self.lbl_status)
        layout.addWidget(tools)

        self.time_bar = QFrame()
        self.time_bar.setObjectName("SubStrip")
        t = QHBoxLayout(self.time_bar)
        t.setContentsMargins(6, 2, 6, 2)
        t.setSpacing(4)
        self.date_issue = QDateEdit(QDate.currentDate())
        self.date_issue.setCalendarPopup(True)
        self.date_issue.setDisplayFormat("yyyy-MM-dd")
        self.time_issue = QTimeEdit(QTime.currentTime())
        self.time_issue.setDisplayFormat("HH:mm:ss")
        self.input_window = QLineEdit("10")
        self.input_window.setFixedWidth(45)
        self.time_labels = []

        def label(s):
            w = QLabel(s)
            self.time_labels.append(w)
            t.addWidget(w)
            return w

        self.date_label = label("日期")
        t.addWidget(self.date_issue)
        self.time_label = label("时间")
        t.addWidget(self.time_issue)
        self.window_label = label("前后")
        t.addWidget(self.input_window)
        self.minute_label = label("分钟")
        self.btn_add_point = QPushButton("添加时间点")
        self.btn_add_point.clicked.connect(self.add_point)
        t.addWidget(self.btn_add_point)
        self.points = QComboBox()
        self.points.setMinimumWidth(175)
        t.addWidget(self.points)
        self.btn_del_point = QPushButton("删除时间点")
        self.btn_del_point.clicked.connect(self.remove_point)
        t.addWidget(self.btn_del_point)
        self.period_start = QDateTimeEdit(
            QDateTime(QDate.currentDate().addDays(-1), QTime(20, 0, 0))
        )
        self.period_end = QDateTimeEdit(QDateTime(QDate.currentDate(), QTime(8, 0, 0)))
        for datewidget in (self.period_start, self.period_end):
            datewidget.setCalendarPopup(True)
            datewidget.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.lbl_start = label("开始")
        t.addWidget(self.period_start)
        self.lbl_end = label("结束")
        t.addWidget(self.period_end)
        t.addStretch(1)
        layout.addWidget(self.time_bar)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(3)
        self.progress.setTextVisible(False)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.hsplit = QSplitter(Qt.Orientation.Horizontal)
        self.hsplit.setChildrenCollapsible(False)
        self.hsplit.setHandleWidth(3)
        self.file_panel = QFrame()
        self.file_panel.setObjectName("FilePanel")
        fp = QVBoxLayout(self.file_panel)
        fp.setContentsMargins(4, 4, 4, 4)
        fp.setSpacing(3)
        self.lbl_files = QLabel("文件")
        fp.addWidget(self.lbl_files)
        self.list_files = QListWidget()
        self.list_files.setUniformItemSizes(True)
        self.list_files.currentRowChanged.connect(self.select_file_row)
        fp.addWidget(self.list_files, 1)
        self.hsplit.addWidget(self.file_panel)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        self.tabs = QTabBar()
        self.tabs.setExpanding(False)
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setMovable(False)
        self.tabs.currentChanged.connect(self.select_file_tab)
        rl.addWidget(self.tabs)
        self.vsplit = QSplitter(Qt.Orientation.Vertical, right)
        self.vsplit.setHandleWidth(3)
        container = QWidget(self.vsplit)
        el = QVBoxLayout(container)
        el.setContentsMargins(0, 0, 0, 0)
        el.setSpacing(0)
        self.viewer = VirtualLogViewer(container)
        el.addWidget(self.viewer, 1)
        self.search_box = QFrame(self.viewer)
        self.search_box.setObjectName("SearchBar")
        sl = QHBoxLayout(self.search_box)
        sl.setContentsMargins(6, 4, 6, 4)
        sl.setSpacing(4)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("查找文本 / 正则表达式")
        self.search_input.returnPressed.connect(self.search_enter)
        sl.addWidget(self.search_input, 1)
        self.search_input.installEventFilter(self)
        self.search_scope = QComboBox()
        self.search_scope.addItems(["当前文件", "所有文件"])
        sl.addWidget(self.search_scope)
        self.search_case = QCheckBox("大小写")
        sl.addWidget(self.search_case)
        self.search_regex = QCheckBox("正则")
        sl.addWidget(self.search_regex)
        self.btn_next = QPushButton("下一处")
        self.btn_next.clicked.connect(self.find_next)
        sl.addWidget(self.btn_next)
        self.btn_filter = QPushButton("筛选全部")
        self.btn_filter.clicked.connect(self.filter_all)
        sl.addWidget(self.btn_filter)
        bclose = QPushButton("×")
        bclose.setFixedWidth(28)
        bclose.clicked.connect(self.search_box.hide)
        sl.addWidget(bclose)
        self.search_box.hide()
        self.viewer.installEventFilter(self)
        self.search_box.installEventFilter(self)

        bottom = QFrame()
        bottom.setObjectName("BottomStrip")
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(9, 1, 9, 1)
        bl.setSpacing(9)
        self.lbl_position = QLabel("行 1, 列 1")
        bl.addWidget(self.lbl_position)
        self.viewer.cursorPositionChanged.connect(self.update_cursor_label)
        bl.addWidget(QLabel("|"))
        self.lbl_total = QLabel("0 行")
        bl.addWidget(self.lbl_total)
        bl.addStretch(1)
        self.input_jump = QLineEdit()
        self.input_jump.setFixedWidth(72)
        self.input_jump.setPlaceholderText("行号")
        self.input_jump.returnPressed.connect(self.jump_line)
        bl.addWidget(self.input_jump)
        jump = QPushButton("转到")
        jump.clicked.connect(self.jump_line)
        bl.addWidget(jump)
        # Keep the virtual viewer in its supported horizontal-scroll mode.
        # No inert wrap control: wrapping millions of lines needs its own layout index.
        bl.addWidget(QLabel("字号"))
        self.font_size = QComboBox()
        self.font_size.addItems(["8", "9", "10", "11", "12"])
        self.font_size.setCurrentText("9")
        self.font_size.currentTextChanged.connect(
            lambda s: self.viewer.set_code_font(int(s))
        )
        bl.addWidget(self.font_size)
        el.addWidget(bottom)
        self.vsplit.addWidget(container)

        self.results = QTabWidget(self.vsplit)
        self.results.setObjectName("BottomTabs")
        self.txt_analysis = QPlainTextEdit()
        self.txt_analysis.setObjectName("ReportView")
        self.txt_analysis.setReadOnly(True)
        self.txt_analysis.setUndoRedoEnabled(False)
        self.txt_analysis.setFont(QFont("Segoe UI", 10))
        self.txt_analysis.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.report_highlighter = None  # 首次分析完成时才创建高亮器，减少首次启动开销
        self.results.addTab(self.txt_analysis, "分析报告")
        self.tbl_incidents = QTableView()
        self.tbl_incidents.setAlternatingRowColors(True)
        self.tbl_incidents.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tbl_incidents.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_incidents.verticalHeader().setVisible(False)
        self.tbl_incidents.verticalHeader().setDefaultSectionSize(21)
        self.tbl_incidents.setWordWrap(False)
        self.tbl_incidents.doubleClicked.connect(self.incident_clicked)
        self.results.addTab(self.tbl_incidents, "异常定位")
        self.tbl_matches = QTableView()
        self.tbl_matches.setAlternatingRowColors(True)
        self.tbl_matches.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tbl_matches.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_matches.verticalHeader().setVisible(False)
        self.tbl_matches.verticalHeader().setDefaultSectionSize(21)
        self.tbl_matches.setWordWrap(False)
        self.tbl_matches.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.match_model = MatchResultModel(self)
        self.tbl_matches.setModel(self.match_model)
        self.tbl_matches.setColumnWidth(0, 210)
        self.tbl_matches.setColumnWidth(1, 75)
        self.tbl_matches.horizontalHeader().setStretchLastSection(True)
        self.tbl_matches.doubleClicked.connect(self.match_clicked)
        self.results.addTab(self.tbl_matches, "筛选结果 (0)")
        self.vsplit.addWidget(self.results)
        self.results.setMinimumHeight(105)
        self.txt_analysis.setPlainText(
            "打开日志后，点击「开始分析」或按 F5。\n支持查找、筛选，并在下方查看分析报告和异常定位。"
        )
        self.vsplit.setStretchFactor(0, 4)
        self.vsplit.setStretchFactor(1, 1)
        self.vsplit.setSizes([400, 145])
        rl.addWidget(self.vsplit, 1)
        self.hsplit.addWidget(right)
        self.hsplit.setStretchFactor(0, 0)
        self.hsplit.setStretchFactor(1, 1)
        self.hsplit.setSizes([162, 850])
        layout.addWidget(self.hsplit, 1)
        self.statusBar().setSizeGripEnabled(True)

    def styles(self):
        from .theme import NOTEPAD_STYLE

        return NOTEPAD_STYLE

    def eventFilter(self, obj, event):
        if obj is self.viewer and event.type() in (
            QEvent.Type.Resize,
            QEvent.Type.Show,
        ):
            self.position_find_bar()
        if (
            obj is self.search_input
            and event.type() == QEvent.Type.KeyPress
            and event.key() == Qt.Key.Key_Escape
        ):
            self.search_box.hide()
            self.viewer.setFocus()
            return True
        return super().eventFilter(obj, event)

    def position_find_bar(self):
        if not hasattr(self, "search_box"):
            return
        w = min(790, max(350, self.viewer.width() - 18))
        self.search_box.setFixedWidth(w)
        self.search_box.adjustSize()
        self.search_box.move(max(5, self.viewer.width() - w - 17), 7)
        self.search_box.raise_()

    def show_find(self):
        self.search_scope.setCurrentIndex(0)
        self._show_search_box()

    def show_filter(self):
        self.search_scope.setCurrentIndex(1)
        self._show_search_box()

    def _show_search_box(self):
        self.position_find_bar()
        self.search_box.show()
        self.search_box.raise_()
        self.search_input.setFocus()
        self.search_input.selectAll()

    def search_enter(self):
        self.filter_all() if self.search_scope.currentIndex() else self.find_next()

    def update_time_widgets(self, *_):
        mode = self.combo_mode.currentText()
        period = mode == "按测试周期分析"
        date = mode in ("按日期分析", "按时间分析", "多时间点分析")
        time = mode in ("按时间分析", "多时间点分析")
        multi = mode == "多时间点分析"
        self.time_bar.setVisible(mode != "全部日志")
        for w in [self.date_label, self.date_issue]:
            w.setVisible(date)
        for w in [
            self.time_label,
            self.time_issue,
            self.window_label,
            self.input_window,
            self.minute_label,
        ]:
            w.setVisible(time)
        for w in [self.btn_add_point, self.points, self.btn_del_point]:
            w.setVisible(multi)
        for w in [self.lbl_start, self.period_start, self.lbl_end, self.period_end]:
            w.setVisible(period)

    def current_datetime(self):
        d = self.date_issue.date()
        t = self.time_issue.time()
        return datetime(d.year(), d.month(), d.day(), t.hour(), t.minute(), t.second())

    def add_point(self):
        val = self.current_datetime().strftime("%Y-%m-%d %H:%M:%S")
        if self.points.findText(val) < 0:
            self.points.addItem(val)

    def remove_point(self):
        if self.points.currentIndex() >= 0:
            self.points.removeItem(self.points.currentIndex())

    def issue_times(self):
        mode = self.combo_mode.currentText()
        if mode in ("全部日志", "按测试周期分析"):
            return []
        if mode == "按日期分析":
            return [self.current_datetime().replace(hour=12, minute=0, second=0)]
        if mode == "按时间分析":
            return [self.current_datetime()]
        values = []
        for i in range(self.points.count()):
            try:
                values.append(
                    datetime.strptime(self.points.itemText(i), "%Y-%m-%d %H:%M:%S")
                )
            except ValueError:
                pass
        return values or [self.current_datetime()]

    def choose_open_source(self):
        if self._busy():
            self.statusBar().showMessage("当前任务尚未结束")
            return
        dialog = InputDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.paths:
            self.start_preview(dialog.paths, True)

    def open_file_dialog(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择日志/压缩包", "", "所有文件 (*)"
        )
        if paths:
            self.start_preview(paths, True)

    def open_folder_dialog(self):
        folder = QFileDialog.getExistingDirectory(self, "选择日志文件夹")
        if folder:
            self.start_preview(folder, False)

    def start_preview(self, paths, is_file_list):
        self._search_generation += 1
        self._find_generation += 1
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.requestInterruption()
        if self._busy() or (self.preview_worker and self.preview_worker.isRunning()):
            self.statusBar().showMessage("已有打开或分析任务正在运行")
            return
        self._input_generation += 1
        self.last_open_paths = paths
        self.last_is_file_list = is_file_list
        self._files_are_prepared = False
        self.prepared_payload = None
        self.lbl_status.setText("正在后台解包...")
        self.progress.setValue(0)
        self.progress.show()
        self.preview_worker = PreviewOpenThread(paths, is_file_list)
        self.preview_worker.progress.connect(self.analysis_progress)
        self.preview_worker.completed.connect(self.preview_done)
        self._preview_pending = True
        self.preview_worker.start()

    def preview_done(self, result):
        self._preview_pending = False
        self.progress.hide()
        if result.get("error"):
            self.lbl_status.setText("打开失败")
            QMessageBox.warning(self, "打开失败", result["error"])
            return
        if result.get("tempdir"):
            self._temp_dirs.add(result["tempdir"])
        self._import_notes = list(result.get("notes", []))
        self._import_metadata_paths = list(result.get("metadata_paths", []))
        files = result.get("paths", [])
        record_module = sys.modules.get("rayneo.records")
        if record_module is not None:
            record_module.clear_record_cache()
        self.file_list_data = sorted(files, key=lambda p: os.path.basename(p).lower())
        self.raw_data = OrderedDict()
        self._line_index_cache.clear()
        self.incidents = []
        self.current_file = None
        self._pending_selected_path = None
        self._pending_goto = None
        self.list_files.blockSignals(True)
        self.tabs.blockSignals(True)
        self.list_files.clear()
        while self.tabs.count():
            self.tabs.removeTab(0)
        self._tab_paths = []
        self.list_files.addItems([Path(path).name for path in self.file_list_data])
        self.has_analyzed = False
        self._full_report = ""
        self.btn_analyze.setText("▶ 开始分析")
        self.btn_analyze.setEnabled(True)
        self.action_analyze.setText("开始分析")
        self.action_analyze.setEnabled(True)
        self.list_files.blockSignals(False)
        self.tabs.blockSignals(False)
        self.lbl_files.setText(f"文件 ({len(files)})")
        self.txt_analysis.setPlainText(
            "按「开始分析」或 F5 执行异常分析。"
            + (
                "\n\n导入详情：\n" + "\n".join(self._import_notes)
                if self._import_notes
                else ""
            )
        )
        self.results.show()
        self.btn_filter.setEnabled(True)
        self.match_model.set_rows([])
        self.results.setTabText(2, "筛选结果 (0)")
        self.build_incident_model()
        # F5 直接分析已经解开的文件，不重复解密/解包。
        self.last_open_paths = list(files) + self._import_metadata_paths
        self.last_is_file_list = True
        self._files_are_prepared = True
        if files:
            self.select_file_by_path(self.file_list_data[0])
        msg = f"已载入文件列表：{len(files)} 个 | 按 F5 分析"
        if result.get("notes"):
            msg += f" | 解包提示 {len(result['notes'])} 条"
        self.lbl_status.setText(msg)
        self.statusBar().showMessage(msg)

    def _start_file_read(self, path):
        self._pending_selected_path = path
        if self.file_read_worker and self.file_read_worker.isRunning():
            return
        self.file_read_worker = FileReadThread(path, self.raw_data.get(path))
        generation = self._input_generation
        self.file_read_worker.completed.connect(
            lambda p, data: self._file_read_done(p, data, generation)
        )
        self.file_read_worker.finished.connect(self._file_read_check_pending)
        self.file_read_worker.start()

    def _file_read_done(self, path, payload, generation=None):
        if generation is not None and generation != self._input_generation:
            return
        # 旧文件的后台读取如果晚于下一次“打开目录”结束，直接丢弃，防止污染当前结果。
        if path not in self.file_list_data:
            return
        text, offsets = payload if payload is not None else (None, None)
        if text is not None:
            self._line_index_cache[path] = offsets
            self._line_index_cache.move_to_end(path)
            while len(self._line_index_cache) > 3:
                self._line_index_cache.popitem(last=False)
            self.raw_data[path] = text
            if isinstance(self.raw_data, OrderedDict):
                self.raw_data.move_to_end(path)
            # 只缓存最近打开的三个文件，避免数百 MB 日志重复占内存。
            if self.prepared_payload is None:
                while len(self.raw_data) > 3:
                    self.raw_data.popitem(last=False)
        if path == self.current_file:
            self.viewer.set_log_text(
                text if text is not None else "文件无法作为文本读取", offsets=offsets
            )
            self.viewer.goto(0)
            self.lbl_total.setText(
                f"{self.viewer.line_count():,} 行  |  {(len(text) if text else 0) / 1024 / 1024:.1f} MB"
            )
            if self._pending_goto and self._pending_goto[0] == path:
                _, line, col, length = self._pending_goto
                self.viewer.goto(line, col, length)
                self._pending_goto = None
        self._pending_selected_path = (
            self._pending_selected_path if self._pending_selected_path != path else None
        )

    def _file_read_check_pending(self):
        self.file_read_worker = None
        next_path = self._pending_selected_path
        if next_path and next_path not in self.raw_data:
            self._start_file_read(next_path)

    def _busy(self):
        return (
            self._analysis_pending
            or self._preview_pending
            or (self.worker is not None and self.worker.isRunning())
            or (self.preview_worker is not None and self.preview_worker.isRunning())
            or (self.decrypt_worker is not None and self.decrypt_worker.isRunning())
        )

    def reanalyze(self):
        if self.last_open_paths is None:
            self.choose_open_source()
            return
        self.start_analysis(
            self.last_open_paths, self.last_is_file_list, self.prepared_payload
        )

    def start_analysis(self, paths, is_file_list, prepared=None):
        if self._busy():
            self.statusBar().showMessage("当前打开/分析任务尚未结束")
            return
        start = end = None
        if self.combo_mode.currentText() == "按测试周期分析":
            start = self.period_start.dateTime().toPyDateTime()
            end = self.period_end.dateTime().toPyDateTime()
            if start >= end:
                QMessageBox.warning(self, "时间范围错误", "结束时间必须晚于开始时间")
                return
        try:
            window = max(1, min(180, int(self.input_window.text())))
        except ValueError:
            window = 10
        self._search_generation += 1
        self._find_generation += 1
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.requestInterruption()
        self.btn_filter.setEnabled(True)
        self.lbl_status.setText("分析中...")
        self.progress.setValue(0)
        self.progress.show()
        self.btn_open.setEnabled(False)
        self.btn_analyze.setEnabled(False)
        self.action_analyze.setEnabled(False)
        from .analysis_worker import WorkerThread

        self.worker = WorkerThread(
            paths,
            is_file_list,
            self.issue_times(),
            window,
            prepared=prepared,
            analysis_mode=self.combo_mode.currentText(),
            range_start=start,
            range_end=end,
            already_prepared=self._files_are_prepared,
            initial_texts=dict(self.raw_data),
            initial_notes=self._import_notes,
        )
        self.worker.progress.connect(self.analysis_progress)
        self.worker.finished.connect(self.analysis_done)
        self._analysis_pending = True
        self.worker.start()

    def analysis_progress(self, value, msg):
        self.progress.setValue(value)
        self.lbl_status.setText(msg[:46])
        self.statusBar().showMessage(msg)

    def analysis_done(self, data):
        self._analysis_pending = False
        self.progress.hide()
        self.btn_open.setEnabled(True)
        self.btn_analyze.setEnabled(True)
        self.action_analyze.setEnabled(True)
        if data.get("error"):
            self.lbl_status.setText("分析失败")
            QMessageBox.warning(self, "分析失败", str(data["error"]))
            return
        # Avoid destroying/reconstructing the editor until the worker is finished.
        if data.get("preprocess_dir"):
            self._temp_dirs.add(data["preprocess_dir"])
        self.raw_data = data.get("files_content", {})
        self._line_index_cache.clear()
        self.prepared_payload = data.get("prepared_payload")
        self.incidents = data.get("incidents", [])
        self.device_info = data.get("device_info", {})
        self.available_dates = data.get("available_dates", [])
        self.has_analyzed = True
        self.btn_analyze.setText("↻ 重新分析")
        self.action_analyze.setText("重新分析")
        self._full_report = data.get("report_text", "")
        self.txt_analysis.setPlainText(self._full_report[:2_000_000])
        if self.report_highlighter is None:
            self.report_highlighter = VSCodeReportHighlighter(
                self.txt_analysis.document()
            )
        self.file_list_data = sorted(
            self.raw_data, key=lambda p: os.path.basename(p).lower()
        )
        self._find_generation += 1
        self.find_key = None
        count = Counter(e.get("full_path") for e in self.incidents)
        self.list_files.blockSignals(True)
        self.tabs.blockSignals(True)
        self.list_files.clear()
        while self.tabs.count():
            self.tabs.removeTab(0)
        self._tab_paths = []
        self.list_files.addItems(
            [
                os.path.basename(p) + (f"  ({count[p]})" if count[p] else "")
                for p in self.file_list_data
            ]
        )
        # 虚拟化标签：只保留最近打开的 24 个，不给每个日志创建 Qt Tab。
        for i, p in enumerate(self.file_list_data):
            if count[p]:
                self.list_files.item(i).setForeground(QColor("#CF222E"))
        self.tabs.blockSignals(False)
        self.list_files.blockSignals(False)
        self.lbl_files.setText(f"文件 ({len(self.file_list_data)})")
        self.btn_filter.setEnabled(True)
        self.match_model.set_rows([])
        self.results.setTabText(2, "筛选结果 (0)")
        self.build_incident_model()
        self.results.setCurrentIndex(0)
        self.results.show()
        self.current_file = None
        if self.file_list_data:
            self.select_file_by_path(self.file_list_data[0])
        elapsed = data.get("analysis_seconds")
        tail = f" | {elapsed:.1f}s" if isinstance(elapsed, (float, int)) else ""
        errs = data.get("analysis_errors") or []
        message = (
            f"{len(self.file_list_data)} 文件 | {len(self.incidents)} 异常"
            + (f" | {len(errs)} 文件分析失败" if errs else "")
            + tail
        )
        self.lbl_status.setText(message)
        self.statusBar().showMessage(message)
        if errs:
            self.lbl_status.setToolTip("\n".join(errs[:30]))

    def build_incident_model(self):
        self.incident_rows = sorted(
            self.incidents,
            key=lambda x: (x.get("time") or datetime.min, x.get("file", "")),
        )

        class IncidentModel(QAbstractTableModel):
            def __init__(self, rows, parent=None):
                super().__init__(parent)
                self.rows = rows

            def rowCount(self, p=QModelIndex()):
                return 0 if p.isValid() else len(self.rows)

            def columnCount(self, p=QModelIndex()):
                return 3

            def headerData(self, c, o, r=Qt.ItemDataRole.DisplayRole):
                return (
                    ["时间", "来源", "问题"][c]
                    if r == Qt.ItemDataRole.DisplayRole
                    and o == Qt.Orientation.Horizontal
                    else None
                )

            def data(self, i, r=Qt.ItemDataRole.DisplayRole):
                if not i.isValid():
                    return None
                x = self.rows[i.row()]
                if r == Qt.ItemDataRole.DisplayRole:
                    if i.column() == 0:
                        return (
                            x["time"].strftime("%H:%M:%S")
                            if isinstance(x.get("time"), datetime)
                            else "--:--:--"
                        )
                    if i.column() == 1:
                        return (
                            str(x.get("file", ""))
                            + ":"
                            + str(int(x.get("line", 0)) + 1)
                        )
                    return x.get("name", "异常")
                if (
                    r == Qt.ItemDataRole.ForegroundRole
                    and i.column() == 2
                    and x.get("level") == "HIGH"
                ):
                    return QBrush(QColor("#CF222E"))
                return None

        previous_model = self.tbl_incidents.model()
        self.tbl_incidents.setModel(
            IncidentModel(self.incident_rows, self.tbl_incidents)
        )
        if previous_model is not None:
            previous_model.deleteLater()
        self.tbl_incidents.setColumnWidth(0, 100)
        self.tbl_incidents.setColumnWidth(1, 300)
        self.tbl_incidents.horizontalHeader().setStretchLastSection(True)
        self.results.setTabText(1, f"异常定位 ({len(self.incident_rows)})")

    def select_file_by_path(self, path):
        if path not in self.file_list_data:
            return
        ix = self.file_list_data.index(path)
        if path != self.current_file:
            self._find_generation += 1
            self.find_key = None
            self.current_file = path
            if path in self.raw_data and path in self._line_index_cache:
                self.viewer.set_log_text(
                    self.raw_data[path], self._line_index_cache[path]
                )
                self.viewer.goto(0)
                self._line_index_cache.move_to_end(path)
                self.raw_data.move_to_end(path) if isinstance(
                    self.raw_data, OrderedDict
                ) else None
                text = self.raw_data[path]
                self.lbl_total.setText(
                    f"{self.viewer.line_count():,} 行 | {len(text) / 1024 / 1024:.1f} MB"
                )
            else:
                self.viewer.set_log_text("正在后台建立行索引...")
                self.lbl_total.setText("读取中...")
                self._start_file_read(path)
        self.list_files.blockSignals(True)
        self.tabs.blockSignals(True)
        self.list_files.setCurrentRow(ix)
        if path not in self._tab_paths:
            if len(self._tab_paths) >= 24:
                self._tab_paths.pop(0)
                self.tabs.removeTab(0)
            self._tab_paths.append(path)
            self.tabs.addTab(Path(path).name)
        self.tabs.setCurrentIndex(self._tab_paths.index(path))
        self.list_files.blockSignals(False)
        self.tabs.blockSignals(False)
        self.lbl_position.setText("行 1, 列 1")

    def select_file_row(self, row):
        if 0 <= row < len(self.file_list_data):
            self.select_file_by_path(self.file_list_data[row])

    def select_file_tab(self, index):
        if 0 <= index < len(self._tab_paths):
            self.select_file_by_path(self._tab_paths[index])

    def goto(self, path, lineno, column=0, length=0):
        if path not in self.file_list_data:
            return
        self.select_file_by_path(path)
        if path not in self._line_index_cache or self._pending_selected_path == path:
            self._pending_goto = (path, lineno, column, length)
            return
        self.viewer.goto(max(0, int(lineno)), column, length)
        self.lbl_position.setText(f"行 {int(lineno) + 1:,}, 列 {column + 1}")

    def update_cursor_label(self, *_):
        line, col = self.viewer.current_line_col()
        self.lbl_position.setText(f"行 {line:,}, 列 {col:,}")

    def focus_jump(self):
        self.input_jump.setFocus()
        self.input_jump.selectAll()

    def jump_line(self):
        if not self.current_file:
            return
        raw = self.input_jump.text().strip()
        if not raw.isdigit() or int(raw) < 1:
            self.statusBar().showMessage("请输入正确行号")
            return
        self.goto(self.current_file, int(raw) - 1)

    def find_next(self):
        if not self.current_file or self.current_file not in self.raw_data:
            return
        query = self.search_input.text()
        if not query:
            self.show_find()
            return
        if self.find_worker is not None and self.find_worker.isRunning():
            self.statusBar().showMessage("正在查找...")
            return
        key = (
            self.current_file,
            query,
            self.search_regex.isChecked(),
            self.search_case.isChecked(),
        )
        if key != self.find_key:
            self.find_key = key
            self.find_offset = 0
        self._find_generation += 1
        generation = self._find_generation
        w = FindNextThread(
            self.current_file,
            self.raw_data[self.current_file],
            query,
            self.find_offset,
            self.search_regex.isChecked(),
            self.search_case.isChecked(),
        )
        self.find_worker = w
        w.completed.connect(lambda res: self._find_finished(res, generation))
        w.start()

    def _find_finished(self, result, generation):
        if generation != self._find_generation or result[0] != self.current_file:
            return
        path, match, error = result
        if error:
            self.statusBar().showMessage(f"搜索失败：{error}")
            return
        pos, length = match
        if pos < 0:
            self.statusBar().showMessage(f"没有找到：{self.search_input.text()}")
            return
        self.find_offset = pos + max(1, length)
        lineno = bisect_right(self.viewer._starts, pos) - 1
        text = self.raw_data[path]
        col = pos - (text.rfind("\n", 0, pos) + 1)
        self.goto(path, lineno, col, length)
        self.statusBar().showMessage(f"命中：第 {lineno + 1:,} 行")

    def filter_all(self):
        if self.search_worker and self.search_worker.isRunning():
            self.statusBar().showMessage("筛选正在进行")
            return
        query = self.search_input.text()
        if not query:
            return
        if self.search_scope.currentIndex() == 0:
            if not self.current_file:
                return
            data = {self.current_file: self.raw_data.get(self.current_file)}
        else:
            data = {p: self.raw_data.get(p) for p in self.file_list_data}
        self.btn_filter.setEnabled(False)
        self.results.setCurrentIndex(2)
        self.results.show()
        self.results.setTabText(2, "筛选中...")
        self._search_generation += 1
        epoch = self._search_generation
        worker = MatchSearchThread(
            data, query, self.search_regex.isChecked(), self.search_case.isChecked()
        )
        self.search_worker = worker
        worker.completed.connect(
            lambda rows, trunc: (
                self.search_finished(rows, trunc)
                if epoch == self._search_generation
                else None
            )
        )
        worker.failed.connect(
            lambda error: (
                self.search_failed(error) if epoch == self._search_generation else None
            )
        )
        worker.start()

    def search_finished(self, rows, truncated):
        self.btn_filter.setEnabled(True)
        self.match_model.set_rows(rows)
        label = f"筛选结果 ({len(rows):,}" + ("，已达到上限)" if truncated else ")")
        self.results.setTabText(2, label)
        self.results.setCurrentIndex(2)
        self.statusBar().showMessage(
            f"匹配 {len(rows):,} 行"
            + (
                "；显示上限 2.5 万条，请缩小搜索范围"
                if truncated
                else "；双击跳到原始行"
            )
        )

    def search_failed(self, error):
        self.btn_filter.setEnabled(True)
        self.results.setTabText(2, "筛选失败")
        QMessageBox.warning(self, "筛选失败", error)

    def match_clicked(self, index):
        if index.isValid() and 0 <= index.row() < len(self.match_model.rows):
            path, lineno, raw = self.match_model.rows[index.row()]
            term = self.search_input.text()
            pos = 0
            length = 0
            try:
                if self.search_regex.isChecked():
                    m = re.search(
                        term, raw, 0 if self.search_case.isChecked() else re.I
                    )
                    if m:
                        pos = m.start()
                        length = m.end() - m.start()
                else:
                    pos = (
                        raw if self.search_case.isChecked() else raw.casefold()
                    ).find(term if self.search_case.isChecked() else term.casefold())
                    length = len(term)
            except re.error:
                pass
            self.goto(path, lineno - 1, max(0, pos), length if pos >= 0 else 0)

    def incident_clicked(self, index):
        if index.isValid() and 0 <= index.row() < len(self.incident_rows):
            r = self.incident_rows[index.row()]
            self.goto(r.get("full_path"), r.get("line", 0))

    def toggle_files(self):
        self.file_panel.setVisible(not self.file_panel.isVisible())

    def toggle_results(self):
        self.results.setVisible(not self.results.isVisible())

    def open_decrypt_dialog(self):
        # A single dialog; selected local source and output never leave the computer.
        dialog = QDialog(self)
        dialog.setWindowTitle("本地解密 / 解压 · 输出到指定文件夹")
        dialog.resize(740, 245)
        v = QVBoxLayout(dialog)
        text = QLabel(
            "选择本地日志文件（可多选）或整个文件夹，再选择保存目录。不会上传到网络。"
        )
        v.addWidget(text)
        source = QLineEdit()
        source.setReadOnly(True)
        row1 = QHBoxLayout()
        row1.addWidget(source, 1)
        choice = {"files": []}

        def pick_files():
            paths, _ = QFileDialog.getOpenFileNames(
                dialog, "选择待解密/解压的文件", "", "所有文件 (*)"
            )
            if paths:
                choice["files"] = paths
                source.setText("；".join(paths))

        def pick_folder():
            path = QFileDialog.getExistingDirectory(dialog, "选择待解密/解压的文件夹")
            if path:
                choice["files"] = [path]
                source.setText(path)

        b1 = QPushButton("选择文件")
        b1.clicked.connect(pick_files)
        row1.addWidget(b1)
        b2 = QPushButton("选择文件夹")
        b2.clicked.connect(pick_folder)
        row1.addWidget(b2)
        v.addLayout(row1)
        target = QLineEdit()
        target.setReadOnly(True)
        row2 = QHBoxLayout()
        row2.addWidget(target, 1)

        def pick_dest():
            path = QFileDialog.getExistingDirectory(dialog, "选择输出保存目录")
            if path:
                target.setText(path)

        outbtn = QPushButton("保存到...")
        outbtn.clicked.connect(pick_dest)
        row2.addWidget(outbtn)
        v.addLayout(row2)
        only_compressed = QCheckBox("文件夹模式：只处理加密/压缩文件，跳过普通日志复制")
        only_compressed.setChecked(True)
        v.addWidget(only_compressed)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(
            "开始本地解密 / 解压"
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        v.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        if not choice["files"] or not target.text():
            QMessageBox.information(
                self, "请选择路径", "必须选择源文件/文件夹和输出保存目录"
            )
            return
        self.start_decryption(
            choice["files"], target.text(), only_compressed.isChecked()
        )

    def start_decryption(self, sources, dest, compressed_only=True):
        if self._busy():
            QMessageBox.information(
                self, "处理中", "请先完成当前日志打开、分析或解密任务"
            )
            return
        self.decrypt_worker = DecryptExportThread(sources, dest, compressed_only)
        self.decrypt_worker.progress.connect(self.decryption_progress)
        self.decrypt_worker.completed.connect(self.decryption_finished)
        self.progress.show()
        self.progress.setValue(0)
        self.lbl_status.setText("本地解密/解压中...")
        self.decrypt_worker.start()

    def decryption_progress(self, value, info):
        self.progress.setValue(value)
        self.statusBar().showMessage("本地处理：" + info)

    def decryption_finished(self, result):
        self.progress.hide()
        outputs = result["files"]
        failures = result["failures"]
        self.lbl_status.setText(
            f"解密/解压完成 · {len(outputs)} 文件，{len(failures)} 失败"
        )
        message = f"保存目录：{result['dest']}\n\n生成 {len(outputs)} 个文件。"
        if result.get("cancelled"):
            message += "\n任务已取消，已生成的文件保留。"
        if failures:
            message += "\n\n失败：\n" + "\n".join(failures[:20])
        QMessageBox.information(self, "本地解密 / 解压结果", message)

    def open_rule_editor(self):
        try:
            open_rules_file(rule_config.RULES_PATH)
            self.statusBar().showMessage("规则文件已打开；保存后重新分析生效")
        except Exception as ex:
            QMessageBox.warning(self, "规则编辑", str(ex))

    def copy_analysis(self):
        QApplication.clipboard().setText(
            getattr(self, "_full_report", self.txt_analysis.toPlainText())
        )
        self.statusBar().showMessage("已复制分析报告")

    def export_analysis(self):
        if not self.txt_analysis.toPlainText().strip():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出分析报告", "RayNeo_分析结果.txt", "文本文件 (*.txt)"
        )
        if path:
            Path(path).write_text(
                getattr(self, "_full_report", self.txt_analysis.toPlainText()),
                encoding="utf-8",
            )
            self.statusBar().showMessage("报告已导出 " + path)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and any(
            u.isLocalFile() for u in event.mimeData().urls()
        ):
            event.acceptProposedAction()

    def dropEvent(self, event):
        sources = [u.toLocalFile() for u in event.mimeData().urls() if u.isLocalFile()]
        if sources and not self._busy():
            if len(sources) == 1 and os.path.isdir(sources[0]):
                self.start_preview(sources[0], False)
            else:
                self.start_preview(sources, True)
            event.acceptProposedAction()

    def closeEvent(self, event):
        running = [
            w
            for w in (
                self.worker,
                self.search_worker,
                self.find_worker,
                self.decrypt_worker,
                self.preview_worker,
                self.file_read_worker,
            )
            if w is not None and w.isRunning()
        ]
        if running:
            for w in running:
                w.requestInterruption()
            self.statusBar().showMessage(
                "后台任务尚未结束，正在请求停止；处理完成后再关闭"
            )
            event.ignore()
            return
        for folder in self._temp_dirs:
            shutil.rmtree(folder, ignore_errors=True)
        super().closeEvent(event)
