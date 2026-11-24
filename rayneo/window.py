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
    QHeaderView,
)
from PyQt6.QtCore import Qt, QDate, QTime, QDateTime, QEvent, QSettings, QTimer
from PyQt6.QtGui import QFont, QColor, QAction
from PyQt6.QtWidgets import (
    QTableView,
    QDialog,
    QDialogButtonBox,
    QToolBar,
    QToolButton,
)
from PyQt6.QtCore import QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QBrush
from . import rules as rule_config
from .dialogs import InputDialog
from .background import DecryptExportThread, FileReadThread, PreviewOpenThread
from .rules import open_rules_file
from .search import MatchResultModel
from .matching import SearchSpec
from .filter_results import DiskMatchRows
from .filter_history import FilterHistoryButton
from .notes import NotesDock
from .panels import ConnectionTimingPanel, DeviceInfoPanel, SearchDock
from .large_log import PAGE_LINES
from .result_delegate import MatchHighlightDelegate
from .viewer import VirtualLogViewer, VSCodeReportHighlighter


LOG_VIEW_CACHE_BYTES = 128 * 1024 * 1024


class AppWindow(QMainWindow):
    """Notepad-style viewer with isolated analysis/search and background I/O."""

    def __init__(self, settings=None):
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("RayNeo Log Tool")
        from .app_assets import application_icon

        self.setWindowIcon(application_icon())
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
        self._file_incident_counts = {}
        self.incidents = []
        self.current_file = None
        self.last_open_paths = None
        self.last_is_file_list = True
        self.prepared_payload = None
        self.available_dates = []
        self.device_info = {}
        self.settings = (
            settings if settings is not None else QSettings("RayNeo", "Log Tool")
        )
        self._analysis_pending = False
        self._preview_pending = False
        from .job_process import JobSession

        self._analysis_session = JobSession()
        self._version_session = JobSession()
        self.last_analysis_metadata = {}
        self.worker = None
        self.search_worker = None
        self.find_worker = None
        self._find_generation = 0
        self.decrypt_worker = None
        self.preview_worker = None
        self.version_worker = None
        self._version_pending = False
        self.file_read_worker = None
        self._pending_selected_path = None
        self._pending_goto = None
        self._line_index_cache = OrderedDict()
        self._file_revisions = {}
        self._binary_paths = set()
        self._auxiliary_paths = set()
        self._large_indexes = OrderedDict()
        self._large_pages = {}
        self._tab_paths = []
        self.find_key = None
        self.find_offset = 0
        self._search_generation = 0
        self._search_for_find = False
        self._filter_split_initialized = False
        self._filter_highlights_by_file = {}
        self._closing = False
        self._files_are_prepared = False
        self.ui_font = QFont("Segoe UI", 9)
        self.code_font = QFont("Consolas", 9)
        self.build_ui()
        self._task_ui_timer = QTimer(self)
        self._task_ui_timer.setInterval(150)
        self._task_ui_timer.timeout.connect(self._refresh_cancel_state)
        self._task_ui_timer.start()
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
        self.notes = NotesDock(self)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.notes)
        self.notes.hide()
        self.action(m_file, "新建分析笔记", "Ctrl+N", self.notes.new_note)
        self.action(m_file, "打开日志…", "Ctrl+O", self.choose_open_source)
        self.action(m_file, "打开文件 / 压缩包...", None, self.open_file_dialog)
        self.action(m_file, "打开文件夹...", "Ctrl+Shift+O", self.open_folder_dialog)
        self.action_edit = self.action(m_file, "编辑当前日志…", "F2", self.edit_log)
        self.action_edit.setEnabled(False)
        self.action_binary_export = self.action(
            m_file, "另存二进制预览…", None, self.save_binary_preview
        )
        self.action_binary_export.setEnabled(False)
        self.action(m_file, "查看分析报告", None, self.show_report)
        self.action(m_file, "导出分析报告...", "Ctrl+E", self.export_analysis)
        m_file.addSeparator()
        self.action(m_file, "退出", "Ctrl+Q", self.close)
        m_search = self.menuBar().addMenu("搜索(&S)")
        self.action(m_search, "查找...", "Ctrl+F", self.show_find)
        self.action(m_search, "全部筛选...", "Ctrl+Shift+F", self.show_filter)
        self.action(m_search, "查找下一个", "F3", self.find_next)
        self.action(m_search, "跳转行...", "Ctrl+G", self.focus_jump)
        m_view = self.menuBar().addMenu("视图(&V)")
        m_view.addAction(self.notes.toggleViewAction())
        self.action_show_auxiliary = QAction("显示辅助文件（二进制和元数据）", self)
        self.action_show_auxiliary.setCheckable(True)
        self.action_show_auxiliary.setEnabled(False)
        self.action_show_auxiliary.toggled.connect(self._sync_auxiliary_visibility)
        m_view.addAction(self.action_show_auxiliary)
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
        self.action(m_tool, "配对／回连耗时", None, self.show_connection_timings)
        self.action(m_tool, "复制分析报告", None, self.copy_analysis)

        base = QWidget(self)
        self.setCentralWidget(base)
        layout = QVBoxLayout(base)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        tools = QFrame()
        tools.setObjectName("ToolStrip")
        tool_col = QVBoxLayout(tools)
        tool_col.setContentsMargins(7, 2, 7, 2)
        tool_col.setSpacing(4)
        actions_row = QToolBar("功能", self)
        actions_row.setObjectName("MainToolbar")
        actions_row.setMovable(False)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, actions_row)

        def add_btn(title, fn, tip=None):
            action = actions_row.addAction(title)
            action.triggered.connect(fn)
            action.setToolTip(tip or title)
            button = actions_row.widgetForAction(action)
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
            return button

        # 点击按钮直接弹出来源选择，不依赖隐藏的小箭头/菜单。
        self.btn_open = add_btn(
            "打开",
            self.choose_open_source,
            "选择本地文件、压缩包或整个文件夹（Ctrl+O）",
        )
        self.btn_open.setObjectName("OpenButton")
        self.btn_analyze = add_btn("分析", self.reanalyze, "F5 启动异常分析")
        self.btn_analyze.setObjectName("AnalyzeButton")
        self.btn_cancel = add_btn("取消", self.cancel_tasks, "取消当前后台任务")
        self.btn_cancel.setEnabled(False)
        self.btn_decrypt = add_btn(
            "解密/解压",
            self.open_decrypt_dialog,
            "选择本地日志文件或文件夹，解密/解压到指定目录（Ctrl+Shift+D）",
        )
        self.btn_decrypt.setObjectName("DecryptButton")
        self.btn_new_note = add_btn(
            "新建笔记", self.notes.new_note, "Ctrl+N 新建分析笔记"
        )
        self.btn_float_search = add_btn("悬浮搜索", self.toggle_search_float)
        self.btn_float_results = add_btn("悬浮结果", self.toggle_results_float)
        self.has_analyzed = False
        self.btn_find = add_btn("查找", self.show_find, "Ctrl+F")
        self.btn_find.setObjectName("SearchButton")
        self.btn_search = add_btn("筛选", self.show_filter, "Ctrl+Shift+F")
        self.btn_search.setObjectName("FilterButton")
        self._toolbar_buttons = (
            self.btn_open,
            self.btn_analyze,
            self.btn_cancel,
            self.btn_decrypt,
            self.btn_new_note,
            self.btn_float_search,
            self.btn_float_results,
            self.btn_find,
            self.btn_search,
        )
        self._toolbar_labels = (
            (self.btn_decrypt, "解密/解压", "解密"),
            (self.btn_new_note, "新建笔记", "笔记"),
            (self.btn_float_search, "悬浮搜索", "浮搜"),
            (self.btn_float_results, "悬浮结果", "浮窗"),
        )
        self._compact_toolbar = None
        self._update_toolbar_labels()
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
        self.chk_auto_analyze = QCheckBox("导入后自动分析")
        self.chk_auto_analyze.setChecked(True)
        scope_row.addWidget(self.chk_auto_analyze)
        self.chk_float_results = QCheckBox("筛选结果自动悬浮")
        scope_row.addWidget(self.chk_float_results)
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
        self.device_panel = DeviceInfoPanel(self.file_panel)
        fp.addWidget(self.device_panel)
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
        self.search_dock = SearchDock(self)
        self.search_box = QFrame(self.search_dock)
        self.search_dock.setWidget(self.search_box)
        self.addDockWidget(Qt.DockWidgetArea.TopDockWidgetArea, self.search_dock)
        self.search_box.setObjectName("SearchBar")
        query_row = QHBoxLayout(self.search_box)
        query_row.setContentsMargins(5, 2, 5, 2)
        query_row.setSpacing(3)
        self.search_input = QLineEdit()
        self.search_input.setMinimumWidth(55)
        self.search_input.setPlaceholderText(
            "关键字用逗号分隔，例如 timeout，disconnect，exception"
        )
        self.search_input.returnPressed.connect(self.search_enter)
        query_row.addWidget(self.search_input, 1)
        self.search_input.installEventFilter(self)
        self.filter_history = FilterHistoryButton(
            self.settings,
            self._restore_filter,
            self._add_filter_keyword,
            self.search_box,
        )
        query_row.addWidget(self.filter_history)
        self.search_scope = QComboBox()
        self.search_scope.addItems(["当前文件", "所有文件"])
        query_row.addWidget(self.search_scope)
        self.keyword_mode = QComboBox()
        for label, mode in (
            ("任一关键字", "any"),
            ("全部关键字", "all"),
            ("单个条件", "single"),
        ):
            self.keyword_mode.addItem(label, mode)
        self.keyword_mode.setToolTip(
            "多个关键字用逗号或顿号分隔。全部关键字须在同一行出现。"
        )
        query_row.addWidget(self.keyword_mode)
        self.search_case = QToolButton()
        self.search_case.setText("Aa")
        self.search_case.setCheckable(True)
        self.search_case.setToolTip("区分大小写")
        self.search_case.setAccessibleName("区分大小写")
        query_row.addWidget(self.search_case)
        self.search_regex = QToolButton()
        self.search_regex.setText(".*")
        self.search_regex.setCheckable(True)
        self.search_regex.setAccessibleName("正则表达式")
        self.search_regex.setToolTip("将整个输入作为一个正则表达式")
        self.search_regex.toggled.connect(self._update_search_hint)
        query_row.addWidget(self.search_regex)
        self.btn_next = QPushButton("下一处")
        self.btn_next.clicked.connect(self.find_next)
        query_row.addWidget(self.btn_next)
        self.btn_filter = QPushButton("筛选")
        self.btn_filter.clicked.connect(self.filter_all)
        query_row.addWidget(self.btn_filter)
        self.btn_clear_filter = QPushButton("清除")
        self.btn_clear_filter.setToolTip("清空筛选结果和标记，保留输入条件")
        self.btn_clear_filter.clicked.connect(self.clear_filter_results)
        query_row.addWidget(self.btn_clear_filter)
        self.search_box.show()
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
        self.page_back = QPushButton("‹")
        self.page_next = QPushButton("›")
        for button, label, direction in (
            (self.page_back, "上一页", -1),
            (self.page_next, "下一页", 1),
        ):
            button.setToolTip(label)
            button.setAccessibleName(label)
            button.setFixedWidth(30)
            button.clicked.connect(lambda _, step=direction: self._move_log_page(step))
            bl.addWidget(button)
            button.hide()
        bl.addStretch(1)
        self.btn_edit_log = QPushButton("编辑日志…")
        self.btn_edit_log.setToolTip("编辑当前日志（F2）")
        self.btn_edit_log.clicked.connect(self.edit_log)
        self.btn_edit_log.setEnabled(False)
        bl.addWidget(self.btn_edit_log)
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
        self.report_highlighter = VSCodeReportHighlighter(self.txt_analysis.document())
        self.results.addTab(self.txt_analysis, "分析结果")
        self.tbl_incidents = QTableView()
        self.tbl_incidents.setAlternatingRowColors(True)
        self.tbl_incidents.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tbl_incidents.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_incidents.verticalHeader().setVisible(False)
        self.tbl_incidents.verticalHeader().setDefaultSectionSize(21)
        self.tbl_incidents.setWordWrap(False)
        self.tbl_incidents.clicked.connect(self.incident_clicked)
        self.results.addTab(self.tbl_incidents, "问题定位")
        self.tbl_matches = QTableView()
        self.tbl_matches.setAlternatingRowColors(True)
        self.tbl_matches.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.tbl_matches.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_matches.verticalHeader().setVisible(False)
        self.tbl_matches.verticalHeader().setDefaultSectionSize(21)
        self.tbl_matches.verticalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Fixed
        )
        self.tbl_matches.setVerticalScrollMode(
            QAbstractItemView.ScrollMode.ScrollPerItem
        )
        self.tbl_matches.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOn
        )
        self.tbl_matches.setWordWrap(False)
        self.tbl_matches.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.match_model = MatchResultModel(self)
        self.tbl_matches.setModel(self.match_model)
        self.tbl_matches.setItemDelegateForColumn(
            2, MatchHighlightDelegate(self.tbl_matches)
        )
        self.tbl_matches.setColumnWidth(0, 210)
        self.tbl_matches.setColumnWidth(1, 75)
        self.tbl_matches.horizontalHeader().setStretchLastSection(True)
        self.tbl_matches.doubleClicked.connect(self.match_clicked)
        self.results.addTab(self.tbl_matches, "筛选结果 (0)")
        self.connection_timings = ConnectionTimingPanel(self.results)
        self.connection_timings.scan_requested.connect(self.start_connection_timings)
        self.connection_timings.jump_requested.connect(self.goto)
        self.results.addTab(self.connection_timings, "配对／回连耗时")
        navigation = QWidget()
        match_navigation = QHBoxLayout(navigation)
        match_navigation.setContentsMargins(1, 0, 3, 0)
        match_navigation.setSpacing(3)
        for label, go_to in (
            ("首条", self.tbl_matches.scrollToTop),
            ("末条", self.tbl_matches.scrollToBottom),
        ):
            button = QPushButton(label)
            button.clicked.connect(go_to)
            match_navigation.addWidget(button)
        self.results.setCornerWidget(navigation)
        self.results.currentChanged.connect(
            lambda page: navigation.setVisible(page == 2)
        )
        navigation.hide()
        self.vsplit.addWidget(self.results)
        self.results.setMinimumHeight(92)
        self.txt_analysis.setPlainText(
            "打开日志后，点击「开始分析」或按 F5。\n支持查找、筛选，并在下方查看分析报告和异常定位。"
        )
        self.vsplit.setStretchFactor(0, 4)
        self.vsplit.setStretchFactor(1, 1)
        self.vsplit.setSizes([560, 108])
        rl.addWidget(self.vsplit, 1)
        self.hsplit.addWidget(right)
        self.hsplit.setStretchFactor(0, 0)
        self.hsplit.setStretchFactor(1, 1)
        self.hsplit.setSizes([252, 850])
        layout.addWidget(self.hsplit, 1)
        self.statusBar().setSizeGripEnabled(True)
        self.search_input.textChanged.connect(self._search_text_changed)

    def styles(self):
        from .theme import NOTEPAD_STYLE

        return NOTEPAD_STYLE

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "_toolbar_labels"):
            self._update_toolbar_labels()

    def _update_toolbar_labels(self):
        compact = self.width() < 780
        if compact == self._compact_toolbar:
            return
        self._compact_toolbar = compact
        for button, full, short in self._toolbar_labels:
            button.defaultAction().setText(short if compact else full)
        for button in self._toolbar_buttons:
            button.setMaximumWidth(52 if compact else 16_777_215)

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
            self.viewer.setFocus()
            return True
        return super().eventFilter(obj, event)

    def position_find_bar(self):
        if not hasattr(self, "search_box"):
            return
        # Search has its own dock and no longer obscures source log rows.
        self.search_dock.show()

    def show_find(self):
        self._search_for_find = True
        self.search_scope.setCurrentIndex(0)
        self._show_search_box()

    def show_filter(self):
        self._search_for_find = False
        self.search_scope.setCurrentIndex(1)
        self._show_search_box()

    def _show_search_box(self):
        self.position_find_bar()
        self.search_box.show()
        self.search_dock.show()
        self.search_dock.raise_()
        self.search_input.setFocus()
        self.search_input.selectAll()

    def search_enter(self):
        self.find_next() if self._search_for_find else self.filter_all()

    def _update_search_hint(self, regex):
        self.keyword_mode.setEnabled(not regex)
        self.search_input.setPlaceholderText(
            "输入正则表达式"
            if regex
            else "关键字用逗号分隔，例如 timeout，disconnect，exception"
        )

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
        if self._busy():
            self.statusBar().showMessage("已有打开或分析任务正在运行")
            return
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
            if "已取消" in result["error"]:
                self.lbl_status.setText("已取消导入")
                return
            self.lbl_status.setText("打开失败")
            QMessageBox.warning(self, "打开失败", result["error"])
            return
        self.clear_filter_results()
        self._analysis_session.stop()
        self._input_generation += 1
        if self.file_read_worker is not None:
            self.file_read_worker.requestInterruption()
        self.prepared_payload = None
        if result.get("tempdir"):
            self._temp_dirs.add(result["tempdir"])
        self._import_notes = list(result.get("notes", []))
        self._import_metadata_paths = list(result.get("metadata_paths", []))
        self._auxiliary_paths = set(
            result.get("auxiliary_paths", self._import_metadata_paths)
        )
        files = result.get("paths", []) + self._import_metadata_paths
        record_module = sys.modules.get("rayneo.records")
        if record_module is not None:
            record_module.clear_record_cache()
        self.file_list_data = sorted(files, key=lambda p: os.path.basename(p).lower())
        self.connection_timings.reset(
            any(path not in self._auxiliary_paths for path in files)
        )
        self._file_incident_counts = {}
        self.raw_data = OrderedDict()
        self._line_index_cache.clear()
        self._file_revisions.clear()
        self._binary_paths.clear()
        self._large_indexes.clear()
        self._large_pages.clear()
        self._show_log_extent(None, "")
        self._set_edit_enabled(False)
        self.action_binary_export.setEnabled(False)
        self.incidents = []
        self.current_file = None
        self.viewer.set_log_text("")
        self.lbl_total.setText("0 行")
        self._pending_selected_path = None
        self._pending_goto = None
        self.list_files.blockSignals(True)
        self.tabs.blockSignals(True)
        self.list_files.clear()
        while self.tabs.count():
            self.tabs.removeTab(0)
        self._tab_paths = []
        self.list_files.addItems([Path(path).name for path in self.file_list_data])
        for row, path in enumerate(self.file_list_data):
            self.list_files.item(row).setToolTip(path)
        self.has_analyzed = False
        self._full_report = ""
        self._report_file = None
        self._report_truncated = False
        self.btn_analyze.setToolTip("F5 启动异常分析")
        self.btn_analyze.setEnabled(True)
        self.action_analyze.setText("开始分析")
        self.action_analyze.setEnabled(True)
        self.list_files.blockSignals(False)
        self.tabs.blockSignals(False)
        self._sync_auxiliary_visibility()
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
        self.last_open_paths = list(files)
        self.last_is_file_list = True
        self._files_are_prepared = True
        if files:
            self.select_file_by_path(self._visible_file_paths()[0])
        msg = f"已载入 {len(self._visible_file_paths())} 个文件 | 按 F5 分析"
        if result.get("notes"):
            msg += f" | 解包提示 {len(result['notes'])} 条"
        self.lbl_status.setText(msg)
        self.statusBar().showMessage(msg)
        self.device_info = {}
        if files:
            self._start_version_scan()
        else:
            self.device_panel.hide()

    def _start_version_scan(self, auto=True):
        from .job_process import AnalysisProcess

        self.device_panel.set_text("正在读取设备信息…")
        self._version_pending = True
        generation = self._input_generation
        self.version_worker = AnalysisProcess(
            self._version_session,
            {"operation": "versions", "paths": self.last_open_paths},
        )
        self.version_worker.finished.connect(
            lambda data: self._versions_done(data, generation, auto)
        )
        self.version_worker.start()

    def _versions_done(self, data, generation, auto):
        if generation != self._input_generation or self._closing:
            return
        self._version_pending = False
        self.device_info = data.get("device_info", {})
        self.device_panel.set_info(self.device_info)
        if auto and not data.get("cancelled"):
            self._auto_analyze_after_import()

    def _visible_file_paths(self):
        text_paths = [
            path for path in self.file_list_data if path not in self._auxiliary_paths
        ]
        return (
            self.file_list_data
            if self.action_show_auxiliary.isChecked() or not text_paths
            else text_paths
        )

    def _sync_auxiliary_visibility(self, *_):
        visible_paths = self._visible_file_paths()
        visible = set(visible_paths)
        hidden = len(self.file_list_data) - len(visible)
        self.action_show_auxiliary.setEnabled(
            bool(self._auxiliary_paths)
            and any(p not in self._auxiliary_paths for p in self.file_list_data)
        )
        self.list_files.blockSignals(True)
        self.tabs.blockSignals(True)
        for row, path in enumerate(self.file_list_data):
            self.list_files.item(row).setHidden(path not in visible)
        for index, path in enumerate(self._tab_paths):
            self.tabs.setTabVisible(index, path in visible)
        self.tabs.blockSignals(False)
        self.list_files.blockSignals(False)
        self.lbl_files.setText(f"文件 ({len(visible)})")
        self.lbl_files.setToolTip(
            f"已隐藏 {hidden} 个辅助文件。可从「视图」显示。" if hidden else ""
        )
        if self.current_file and self.current_file not in visible and visible_paths:
            self.clear_filter_results()
            self.select_file_by_path(visible_paths[0])

    def _auto_analyze_after_import(self):
        if (
            self.last_open_paths
            and self._files_are_prepared
            and self.chk_auto_analyze.isChecked()
            and not self._closing
        ):
            self.reanalyze()

    def _refresh_cancel_state(self):
        running = any(
            worker is not None and worker.isRunning()
            for worker in (
                self.worker,
                self.search_worker,
                self.find_worker,
                self.preview_worker,
                self.version_worker,
                self.decrypt_worker,
            )
        )
        self.btn_cancel.setEnabled(running)

    def cancel_tasks(self):
        if self.search_worker is not None and self.search_worker.isRunning():
            self.clear_filter_results()
        self._find_generation += 1
        for worker in (
            self.worker,
            self.find_worker,
            self.preview_worker,
            self.version_worker,
            self.decrypt_worker,
        ):
            if worker is not None and worker.isRunning():
                worker.requestInterruption()
        self._refresh_cancel_state()
        self.statusBar().showMessage("正在取消后台任务，日志预览仍可使用")

    def toggle_search_float(self):
        self.search_dock.setFloating(not self.search_dock.isFloating())
        self.search_dock.show()
        self.search_dock.raise_()
        if self.search_dock.isFloating():
            self.search_dock.resize(
                min(840, self.width()), self.search_dock.minimumSizeHint().height()
            )
        self.search_input.setFocus()

    def toggle_results_float(self):
        dialog = getattr(self, "_results_dialog", None)
        if dialog is not None:
            dialog.close()
            return
        dialog = QDialog(self, Qt.WindowType.Tool)
        dialog.setWindowTitle("筛选与分析结果")
        dialog.resize(1080, 480)
        sizes = self.vsplit.sizes()
        bar = self.tbl_matches.verticalScrollBar()
        top = bar.value()
        panel = QVBoxLayout(dialog)
        panel.setContentsMargins(0, 0, 0, 0)
        panel.addWidget(self.results)
        self._results_dialog = dialog

        def restore(_result):
            old_top = bar.value()
            self._results_dialog = None
            self.results.setParent(self.vsplit)
            self.vsplit.addWidget(self.results)
            self.results.show()
            self.vsplit.setSizes(sizes)
            bar.setValue(old_top)
            dialog.deleteLater()

        dialog.finished.connect(restore)
        dialog.show()
        bar.setValue(top)

    def show_report(self):
        if not hasattr(self, "_report_dialog"):
            self._report_dialog = QDialog(self, Qt.WindowType.Tool)
            self._report_dialog.setWindowTitle("分析报告")
            self._report_dialog.resize(960, 620)
            box = QVBoxLayout(self._report_dialog)
            self._report_view = QPlainTextEdit()
            self._report_view.setObjectName("ReportView")
            self._report_view.setReadOnly(True)
            self._report_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            self._floating_report_highlighter = VSCodeReportHighlighter(
                self._report_view.document()
            )
            box.addWidget(self._report_view)
            button = QPushButton("导出完整报告")
            button.clicked.connect(self.export_analysis)
            box.addWidget(button)
        self._report_view.setPlainText(
            self._report_preview() or "导入日志后开始分析，完成后在这里显示报告。"
        )
        self._report_dialog.show()
        self._report_dialog.raise_()

    def _start_file_read(self, path):
        self._pending_selected_path = path
        # Keep the worker until its queued finished callback is handled, even
        # when isRunning() has just become False. Otherwise an old callback
        # could clear a newly started worker.
        if self.file_read_worker is not None:
            if self.file_read_worker.path != path:
                self.file_read_worker.requestInterruption()
            return
        self.file_read_worker = FileReadThread(path, self.raw_data.get(path))
        worker = self.file_read_worker
        worker.large_index = self._large_indexes.get(path)
        worker.target_line = (
            self._pending_goto[1]
            if self._pending_goto and self._pending_goto[0] == path
            else 0
        )
        generation = self._input_generation
        self.file_read_worker.completed.connect(
            lambda p, data: self._file_read_done(p, data, generation)
        )
        self.file_read_worker.finished.connect(
            lambda: self._file_read_check_pending(worker)
        )
        self.file_read_worker.start()

    def _file_read_done(self, path, payload, generation=None):
        if generation is not None and generation != self._input_generation:
            return
        # 旧文件的后台读取如果晚于下一次“打开目录”结束，直接丢弃，防止污染当前结果。
        if path not in self.file_list_data:
            return
        text, offsets = payload[:2] if payload is not None else (None, None)
        if text is not None:
            index, page = payload[4:6] if len(payload) >= 6 else (None, None)
            if page is not None:
                self._large_pages[path] = page
                self._large_indexes[path] = index
                self._large_indexes.move_to_end(path)
                while len(self._large_indexes) > 8:
                    self._large_indexes.popitem(last=False)
            else:
                self._large_pages.pop(path, None)
                self._large_indexes.pop(path, None)
            if len(payload) > 3 and payload[3]:
                self._binary_paths.add(path)
            else:
                self._binary_paths.discard(path)
            if len(payload) > 2 and payload[2] is not None:
                self._file_revisions[path] = payload[2]
            else:
                self._file_revisions.pop(path, None)
            self._line_index_cache[path] = offsets
            self._line_index_cache.move_to_end(path)
            self.raw_data[path] = text
            if isinstance(self.raw_data, OrderedDict):
                self.raw_data.move_to_end(path)
            cache_bytes = sum(
                sys.getsizeof(self.raw_data[p]) + sys.getsizeof(index)
                for p, index in self._line_index_cache.items()
            )
            while len(self._line_index_cache) > 1 and (
                len(self._line_index_cache) > 3 or cache_bytes > LOG_VIEW_CACHE_BYTES
            ):
                evicted, index = self._line_index_cache.popitem(last=False)
                cache_bytes -= sys.getsizeof(
                    self.raw_data.pop(evicted)
                ) + sys.getsizeof(index)
                self._file_revisions.pop(evicted, None)
                self._binary_paths.discard(evicted)
                self._large_pages.pop(evicted, None)
        if path == self.current_file:
            self._display_log_text(path, text, offsets)
            self._set_edit_enabled(path in self._file_revisions)
            self.action_binary_export.setEnabled(path in self._binary_paths)
            self.viewer.goto(0)
            self._show_log_extent(path, text)
            if self._pending_goto and self._pending_goto[0] == path:
                _, line, col, length = self._pending_goto
                page = self._large_pages.get(path)
                if page is not None:
                    line = min(max(0, line), self._large_indexes[path].total_lines - 1)
                    if not page.contains(line):
                        self._pending_selected_path = path
                        return
                self.viewer.goto(line - (page.start if page else 0), col, length)
                self._pending_goto = None
        self._pending_selected_path = (
            self._pending_selected_path if self._pending_selected_path != path else None
        )

    def _file_read_check_pending(self, worker):
        if self.file_read_worker is not worker:
            return
        self.file_read_worker = None
        next_path = self._pending_selected_path
        # A cached string may still lack line offsets (e.g. after analysis).
        if next_path and next_path in self.file_list_data:
            self._start_file_read(next_path)

    def _display_log_text(self, path, text, offsets=None):
        page = self._large_pages.get(path)
        self.viewer.set_log_text(
            text if text is not None else "文件无法作为文本读取",
            offsets,
            page.start if page else 0,
        )
        if text is not None:
            self.viewer.set_filter_highlights(
                self._filter_highlights_by_file.get(path, {})
            )

    def _show_log_extent(self, path, text):
        page = self._large_pages.get(path)
        self.page_back.setVisible(page is not None)
        self.page_next.setVisible(page is not None)
        if page is not None:
            total = self._large_indexes[path].total_lines
            self.page_back.setEnabled(page.start > 0)
            self.page_next.setEnabled(page.start + page.rows < total)
            self.lbl_total.setText(
                f"{total:,} 行 · {page.start + 1:,}–{page.start + page.rows:,}"
            )
        elif path in self._binary_paths:
            self.lbl_total.setText("二进制预览")
        elif text is not None:
            self.lbl_total.setText(
                f"{self.viewer.line_count():,} 行 · {len(text) / 1024 / 1024:.1f} MB"
            )
        else:
            self.lbl_total.setText("读取失败")

    def _move_log_page(self, direction):
        page = self._large_pages.get(self.current_file)
        if page is not None:
            line = (
                max(0, page.start - PAGE_LINES)
                if direction < 0
                else page.start + page.rows
            )
            self.goto(self.current_file, line)

    def _set_edit_enabled(self, enabled):
        self.btn_edit_log.setEnabled(enabled)
        self.action_edit.setEnabled(enabled)

    def save_binary_preview(self):
        path = self.current_file
        if path not in self._binary_paths or path not in self.raw_data:
            return
        suggestion = Path(path).stem + "_转义.txt"
        target, _ = QFileDialog.getSaveFileName(
            self, "保存二进制预览", suggestion, "文本文件 (*.txt)"
        )
        if not target:
            return
        target = Path(target).resolve()
        if str(target) in self.file_list_data:
            QMessageBox.warning(
                self, "请选择另一个文件", "转义预览需要保存为单独的文本文件。"
            )
            return
        try:
            target.write_text(self.raw_data[path], encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "保存失败", str(exc))
        else:
            self.statusBar().showMessage(f"预览已保存：{target}")

    def _cancel_search_for_log_save(self):
        self._find_generation += 1
        for worker in (self.search_worker, self.find_worker):
            if worker is not None and worker.isRunning():
                worker.requestInterruption()

    def edit_log(self):
        path = self.current_file
        if path not in self._file_revisions:
            return
        if self._busy():
            self.statusBar().showMessage("等待当前任务完成后再编辑日志")
            return
        from .log_edit import LogEditDialog

        line, column = self.viewer.current_line_col()
        page = self._large_pages.get(path)
        dialog = LogEditDialog(
            path,
            self.raw_data[path],
            self._line_index_cache[path],
            self._file_revisions[path],
            self.viewer.selection_range()[0],
            self._temp_dirs,
            self,
            file_offset=page.char_offset if page else 0,
            line_base=page.start if page else 0,
        )
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        destination = str(dialog.destination)
        dialog.deleteLater()
        if not accepted:
            return
        self.clear_filter_results()
        self.find_key = None
        self.find_offset = 0
        self.has_analyzed = False
        self._full_report = ""
        self._report_file = None
        self._report_truncated = False
        self.txt_analysis.setPlainText("日志已保存。按 F5 重新分析。")
        self.connection_timings.reset(True)
        if hasattr(self, "_report_dialog"):
            self._report_dialog.hide()
        self.incidents = []
        self.build_incident_model()
        self._update_file_incident_counts({})
        if destination not in self.file_list_data:
            row = self.file_list_data.index(path)
            self.file_list_data[row] = destination
            self._auxiliary_paths.discard(path)
            item = self.list_files.item(row)
            item.setText(Path(destination).name)
            item.setToolTip(destination)
            if path in self._tab_paths:
                tab = self._tab_paths.index(path)
                self._tab_paths[tab] = destination
                self.tabs.setTabText(tab, Path(destination).name)
                self.tabs.setTabToolTip(tab, destination)
            self.last_open_paths = list(self.file_list_data)
            self.raw_data.pop(path, None)
            self._line_index_cache.pop(path, None)
            self._file_revisions.pop(path, None)
            self._large_pages.pop(path, None)
            self._large_indexes.pop(path, None)
            self._sync_auxiliary_visibility()
        self.raw_data.pop(destination, None)
        self._line_index_cache.pop(destination, None)
        self._file_revisions.pop(destination, None)
        self._large_pages.pop(destination, None)
        self._large_indexes.pop(destination, None)
        self.current_file = None
        self.goto(destination, line - 1, column - 1)
        self.statusBar().showMessage(f"日志已保存：{destination}")

    def _busy(self):
        return (
            self._analysis_pending
            or self._preview_pending
            or self._version_pending
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

    def show_connection_timings(self):
        self.results.show()
        self.results.setCurrentWidget(self.connection_timings)

    def start_connection_timings(self):
        if self._busy():
            self.statusBar().showMessage("当前打开或分析任务尚未结束")
            return
        paths = [
            path
            for path in self.file_list_data
            if path not in self._auxiliary_paths and path not in self._binary_paths
        ]
        if not paths:
            self.connection_timings.message("当前没有可计算的文本日志")
            return
        from .job_process import AnalysisProcess

        self.show_connection_timings()
        self.connection_timings.scan.setEnabled(False)
        self.connection_timings.message("正在扫描日志…")
        self.progress.show()
        self.analysis_progress(0, "正在计算配对／回连耗时…")
        self.worker = AnalysisProcess(
            self._analysis_session, {"operation": "connection_timings", "paths": paths}
        )
        self.worker.progress.connect(self.analysis_progress)
        self.worker.finished.connect(self.connection_timings_done)
        self._analysis_pending = True
        self.btn_cancel.setEnabled(True)
        self.worker.start()

    def connection_timings_done(self, data):
        self._analysis_pending = False
        self._refresh_cancel_state()
        self.progress.hide()
        self.connection_timings.show_result(data)
        self.lbl_status.setText(self.connection_timings.status.text())
        self.statusBar().showMessage(self.connection_timings.status.text())

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
        self.lbl_status.setText("分析中...")
        self.progress.setValue(0)
        self.progress.show()
        self.btn_open.setEnabled(False)
        self.btn_analyze.setEnabled(False)
        self.action_analyze.setEnabled(False)
        from .job_process import AnalysisProcess

        request = dict(
            operation="diagnose",
            paths=self.file_list_data or paths,
            auxiliary_paths=list(self._auxiliary_paths),
            issue_times=self.issue_times(),
            window_minutes=window,
            analysis_mode=self.combo_mode.currentText(),
            range_start=start,
            range_end=end,
            device_info=self.device_info,
            rules_path=str(rule_config.RULES_PATH),
        )
        self.worker = AnalysisProcess(self._analysis_session, request)
        self.worker.progress.connect(self.analysis_progress)
        self.worker.finished.connect(self.analysis_done)
        self._analysis_pending = True
        self.btn_cancel.setEnabled(True)
        self.worker.start()

    def _report_preview(self):
        text = getattr(self, "_full_report", "")
        return text[:100000] + (
            "\n\n界面仅预览前10万字，点击“导出报告”可保存完整报告。"
            if len(text) > 100000 or getattr(self, "_report_truncated", False)
            else ""
        )

    def analysis_progress(self, value, msg):
        self.progress.setValue(value)
        self.lbl_status.setText(msg[:46])
        self.statusBar().showMessage(msg)

    def analysis_done(self, data):
        self._analysis_pending = False
        self.btn_cancel.setEnabled(False)
        self.progress.hide()
        self.btn_open.setEnabled(True)
        self.btn_analyze.setEnabled(True)
        self.action_analyze.setEnabled(True)
        if data.get("cancelled"):
            self.lbl_status.setText("已取消分析")
            return
        if data.get("error"):
            self.lbl_status.setText("分析失败")
            QMessageBox.warning(self, "分析失败", str(data["error"]))
            return
        # Avoid destroying/reconstructing the editor until the worker is finished.
        if data.get("preprocess_dir"):
            self._temp_dirs.add(data["preprocess_dir"])
        files = sorted(
            data.get("file_paths", data.get("files_content", {})),
            key=lambda p: os.path.basename(p).lower(),
        )
        different_files = set(files) != set(self.file_list_data)
        refresh_files = different_files or (
            self.has_analyzed and data.get("source_changed")
        )
        selected_path = self.current_file
        if refresh_files:
            self.clear_filter_results()
            self.connection_timings.reset(
                any(path not in self._auxiliary_paths for path in files)
            )
            self._input_generation += 1
            self._pending_selected_path = self._pending_goto = None
            self.raw_data = OrderedDict()
            self._line_index_cache.clear()
            self._file_revisions.clear()
            self._binary_paths.clear()
            self._large_indexes.clear()
            self._large_pages.clear()
            self.find_key = None
            self.current_file = None
            self.viewer.set_log_text("")
            self._set_edit_enabled(False)
        self.last_analysis_metadata = {
            "reused_cache": data.get("reused_cache"),
            "process_token": data.get("prepared_payload", {}).get("process_token"),
        }
        self.prepared_payload = data.get("prepared_payload")
        self.incidents = data.get("incidents", [])
        self.device_info = data.get("device_info", {})
        self.available_dates = data.get("available_dates", [])
        self.has_analyzed = True
        self.btn_analyze.setToolTip("F5 重新分析")
        self.action_analyze.setText("重新分析")
        self._full_report = data.get("report_text", "")
        self._report_file = data.get("report_path")
        self._report_truncated = data.get("report_truncated", False)
        self.txt_analysis.setPlainText(self._report_preview())
        if different_files:
            self.file_list_data = files
            self._file_incident_counts = {}
            self.list_files.blockSignals(True)
            self.tabs.blockSignals(True)
            self.list_files.clear()
            while self.tabs.count():
                self.tabs.removeTab(0)
            self._tab_paths = []
            self.list_files.addItems([Path(path).name for path in files])
            for row, path in enumerate(files):
                self.list_files.item(row).setToolTip(path)
            self.tabs.blockSignals(False)
            self.list_files.blockSignals(False)
        self._update_file_incident_counts(
            Counter(e.get("full_path") for e in self.incidents)
        )
        self._sync_auxiliary_visibility()
        self.build_incident_model()
        keep_filter = self.results.currentIndex() == 2 and (
            self.match_model.search_spec is not None or not self.btn_filter.isEnabled()
        )
        if (
            not keep_filter
            and self.results.currentWidget() is not self.connection_timings
        ):
            self.results.setCurrentIndex(0)
            self.results.show()
        if self.current_file is None and self.file_list_data:
            self.select_file_by_path(
                selected_path
                if selected_path in self._visible_file_paths()
                else self._visible_file_paths()[0]
            )
        elapsed = data.get("analysis_seconds")
        tail = f" | {elapsed:.1f}s" if isinstance(elapsed, (float, int)) else ""
        errs = data.get("analysis_errors") or []
        message = (
            f"{data.get('analyzed_file_count', len(self._visible_file_paths()))} 个日志 · "
            + (
                f"{len(self.incidents)} 个定位点"
                if self.incidents
                else "未确认直接原因"
            )
            + (f" | {len(errs)} 文件分析失败" if errs else "")
            + tail
        )
        self.lbl_status.setText(message)
        self.statusBar().showMessage(message)
        if errs:
            self.lbl_status.setToolTip("\n".join(errs[:30]))

    def _update_file_incident_counts(self, counts):
        previous = self._file_incident_counts
        for row, path in enumerate(self.file_list_data):
            count = counts.get(path, 0)
            if count != previous.get(path, 0):
                item = self.list_files.item(row)
                item.setText(Path(path).name + (f"  ({count})" if count else ""))
                item.setForeground(QBrush(QColor("#CF222E")) if count else QBrush())
        self._file_incident_counts = counts

    def build_incident_model(self):
        self.incident_rows = list(self.incidents)

        class IncidentModel(QAbstractTableModel):
            def __init__(self, rows, parent=None):
                super().__init__(parent)
                self.rows = rows

            def rowCount(self, p=QModelIndex()):
                return 0 if p.isValid() else len(self.rows)

            def columnCount(self, p=QModelIndex()):
                return 4

            def headerData(self, c, o, r=Qt.ItemDataRole.DisplayRole):
                return (
                    ["问题 / 事件", "判断", "时间", "位置"][c]
                    if r == Qt.ItemDataRole.DisplayRole
                    and o == Qt.Orientation.Horizontal
                    else None
                )

            def data(self, i, r=Qt.ItemDataRole.DisplayRole):
                if not i.isValid():
                    return None
                x = self.rows[i.row()]
                if r == Qt.ItemDataRole.ToolTipRole:
                    return f"{x['custom_analysis']}\n{x['full_path']}:{x['line'] + 1}"
                if r == Qt.ItemDataRole.DisplayRole:
                    if i.column() == 0:
                        return x["name"]
                    if i.column() == 1:
                        return x["status"]
                    if i.column() == 2:
                        return (
                            x["time"].strftime("%H:%M:%S")
                            if isinstance(x.get("time"), datetime)
                            else "--:--:--"
                        )
                    return f"{x['file']}:{x['line'] + 1}"
                if r == Qt.ItemDataRole.ForegroundRole and i.column() == 1:
                    return QBrush(
                        QColor("#245b88" if x["status"] == "明确" else "#8A671C")
                    )
                return None

        previous_model = self.tbl_incidents.model()
        self.tbl_incidents.setModel(
            IncidentModel(self.incident_rows, self.tbl_incidents)
        )
        if previous_model is not None:
            previous_model.deleteLater()
        self.tbl_incidents.setColumnWidth(1, 62)
        self.tbl_incidents.setColumnWidth(2, 76)
        self.tbl_incidents.setColumnWidth(3, 145)
        self.tbl_incidents.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.results.setTabText(1, f"问题定位 ({len(self.incident_rows)})")

    def select_file_by_path(self, path):
        if path not in self.file_list_data:
            return
        ix = self.file_list_data.index(path)
        item = self.list_files.item(ix)
        if item is not None and item.isHidden():
            return
        if path != self.current_file:
            self._find_generation += 1
            self.find_key = None
            self.current_file = path
            if path in self.raw_data and path in self._line_index_cache:
                self._display_log_text(
                    path, self.raw_data[path], self._line_index_cache[path]
                )
                self.viewer.goto(0)
                self._set_edit_enabled(path in self._file_revisions)
                self.action_binary_export.setEnabled(path in self._binary_paths)
                self._line_index_cache.move_to_end(path)
                if path in self._large_indexes:
                    self._large_indexes.move_to_end(path)
                self.raw_data.move_to_end(path) if isinstance(
                    self.raw_data, OrderedDict
                ) else None
                text = self.raw_data[path]
                self._show_log_extent(path, text)
            else:
                self._set_edit_enabled(False)
                self.action_binary_export.setEnabled(False)
                self.page_back.hide()
                self.page_next.hide()
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
            self.tabs.setTabToolTip(self.tabs.count() - 1, path)
        self.tabs.setCurrentIndex(self._tab_paths.index(path))
        self.list_files.blockSignals(False)
        self.tabs.blockSignals(False)
        self.update_cursor_label()

    def select_file_row(self, row):
        if 0 <= row < len(self.file_list_data):
            self.select_file_by_path(self.file_list_data[row])

    def select_file_tab(self, index):
        if 0 <= index < len(self._tab_paths):
            self.select_file_by_path(self._tab_paths[index])

    def goto(self, path, lineno, column=0, length=0):
        if path not in self.file_list_data:
            return
        line = max(0, int(lineno))
        if path not in self._line_index_cache or self._pending_selected_path == path:
            self._pending_goto = (path, line, column, length)
        self.select_file_by_path(path)
        if path not in self._line_index_cache or self._pending_selected_path == path:
            return
        page = self._large_pages.get(path)
        if page:
            line = min(line, self._large_indexes[path].total_lines - 1)
            if not page.contains(line):
                self._pending_goto = (path, line, column, length)
                self._start_file_read(path)
                return
        self.viewer.goto(line - (page.start if page else 0), column, length)

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
        from .job_process import FindProcess

        w = FindProcess(
            self.current_file,
            query,
            self.find_offset,
            self.search_regex.isChecked(),
            self.search_case.isChecked(),
            paged=self.current_file in self._large_indexes,
            escaped=self.current_file in self._binary_paths,
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
        pos, length = match[:2]
        if pos < 0:
            self.statusBar().showMessage(f"没有找到：{self.search_input.text()}")
            return
        self.find_offset = pos + max(1, length)
        if len(match) == 4:
            lineno, col = match[2:]
            self.goto(path, lineno, col, length)
            self.statusBar().showMessage(f"命中：第 {lineno + 1:,} 行")
            return
        text = self.raw_data[path]
        offsets = self._line_index_cache.get(path)
        lineno = (
            bisect_right(offsets, pos) - 1
            if offsets is not None
            else text.count("\n", 0, pos)
        )
        col = pos - (text.rfind("\n", 0, pos) + 1)
        self.goto(path, lineno, col, length)
        self.statusBar().showMessage(f"命中：第 {lineno + 1:,} 行")

    def filter_all(self):
        self._search_for_find = False
        if self.search_worker and self.search_worker.isRunning():
            self.statusBar().showMessage("筛选正在进行")
            return
        query = self.search_input.text()
        if not query:
            return
        mode = self.keyword_mode.currentData()
        if self.search_regex.isChecked() or not any(c in query for c in ",，、"):
            mode = "single"
        if self.search_scope.currentIndex() == 0:
            if not self.current_file:
                return
            paths = [self.current_file]
        else:
            paths = self._visible_file_paths()
        if not paths:
            return
        history_entry = {
            "query": query,
            "scope": self.search_scope.currentIndex(),
            "mode": self.keyword_mode.currentData(),
            "regex": self.search_regex.isChecked(),
            "case": self.search_case.isChecked(),
        }
        self.clear_filter_results()
        self.btn_filter.setEnabled(False)
        self.results.setCurrentIndex(2)
        self.results.show()
        if (
            not self._filter_split_initialized
            and self.vsplit.indexOf(self.results) >= 0
        ):
            self._filter_split_initialized = True
            viewer_height, results_height = self.vsplit.sizes()
            total_height = viewer_height + results_height
            target = min(155, total_height // 4)
            if results_height < target:
                self.vsplit.setSizes([total_height - target, target])
        self.results.setTabText(2, "筛选中...")
        self._search_generation += 1
        epoch = self._search_generation
        from .job_process import SearchProcess

        worker = SearchProcess(
            paths,
            query,
            self.search_regex.isChecked(),
            self.search_case.isChecked(),
            mode,
        )
        self.btn_cancel.setEnabled(True)
        self.search_worker = worker
        worker.completed.connect(
            lambda rows: self._filter_completed(rows, epoch, history_entry)
        )
        worker.failed.connect(
            lambda error: (
                self.search_failed(error) if epoch == self._search_generation else None
            )
        )
        worker.start()

    def _restore_filter(self, entry):
        self._search_for_find = False
        self.search_input.setText(entry["query"])
        self.search_scope.setCurrentIndex(entry.get("scope", 0))
        mode = self.keyword_mode.findData(entry.get("mode", "any"))
        self.keyword_mode.setCurrentIndex(max(mode, 0))
        self.search_regex.setChecked(entry.get("regex", False))
        self.search_case.setChecked(entry.get("case", False))
        self.search_input.setFocus()
        self.search_input.selectAll()

    def _add_filter_keyword(self, word):
        text = self.search_input.text().strip()
        if self.search_regex.isChecked() or self.keyword_mode.currentData() == "single":
            text = ""
            self.search_regex.setChecked(False)
            self.keyword_mode.setCurrentIndex(0)
        self._search_for_find = False
        self.search_input.setText(f"{text}，{word}" if text else word)
        self.search_input.setFocus()

    def _filter_completed(self, rows, generation, history_entry):
        if generation == self._search_generation and not self._closing:
            self.search_finished(rows)
            if isinstance(rows, DiskMatchRows):
                self.filter_history.remember(history_entry)
        elif isinstance(rows, DiskMatchRows):
            rows.close()

    def _search_text_changed(self, text):
        self._find_generation += 1
        self.find_key = None
        self.find_offset = 0
        if not text:
            self.clear_filter_results()

    def clear_filter_results(self):
        self._search_generation += 1
        self._find_generation += 1
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.requestInterruption()
        self._filter_highlights_by_file = {}
        self.viewer.set_filter_highlights({}, clear_active=True)
        self.match_model.set_rows([])
        self.results.setTabText(2, "筛选结果 (0)")
        self.results.setTabToolTip(2, "")
        self.btn_filter.setEnabled(True)

    def search_finished(self, rows):
        self.btn_cancel.setEnabled(False)
        self.btn_filter.setEnabled(True)
        self.match_model.set_rows(rows)
        self._filter_highlights_by_file = self.match_model.source_highlights()
        highlights = (
            self._filter_highlights_by_file.get(self.current_file, {})
            if self.current_file in self._line_index_cache
            and self._pending_selected_path != self.current_file
            else {}
        )
        self.viewer.set_filter_highlights(highlights)
        self.tbl_matches.scrollToTop()
        spec = self.match_model.search_spec
        self.results.setTabToolTip(2, "筛选条件：" + spec.query if spec else "")
        self.results.setTabText(2, f"筛选结果 ({len(rows):,})")
        self.results.setCurrentIndex(2)
        if spec is not None and self.chk_float_results.isChecked():
            if getattr(self, "_results_dialog", None) is None:
                self.toggle_results_float()
            else:
                self._results_dialog.show()
                self._results_dialog.raise_()
        skipped = rows.skipped if isinstance(rows, DiskMatchRows) else 0
        self.statusBar().showMessage(
            f"匹配 {len(rows):,} 行；双击跳到原始行"
            + (f"；{skipped:,} 个文件无法读取" if skipped else "")
        )

    def search_failed(self, error):
        self.btn_filter.setEnabled(True)
        self.results.setTabText(2, "筛选失败")
        QMessageBox.warning(self, "筛选失败", error)

    def match_clicked(self, index):
        if not index.isValid() or not 0 <= index.row() < len(self.match_model.rows):
            return
        path, lineno, raw = self.match_model.rows[index.row()]
        hit = self.match_model.first_match(index.row())
        if hit is None and self.match_model.search_spec is None:
            # Compatibility with programmatically supplied rows; real filter
            # results already carry worker-computed source offsets.
            try:
                pattern = SearchSpec(
                    self.search_input.text(),
                    self.search_regex.isChecked(),
                    self.search_case.isChecked(),
                ).compile()
                match = pattern.search(raw) if self.search_input.text() else None
                hit = match.span() if match else None
            except re.error:
                hit = None
        pos, end = hit if hit is not None else (0, 0)
        self.goto(path, lineno - 1, pos, end - pos)

    def incident_clicked(self, index):
        if index.isValid() and 0 <= index.row() < len(self.incident_rows):
            r = self.incident_rows[index.row()]
            self.goto(r.get("full_path"), r.get("line", 0))
            self.statusBar().showMessage(r["custom_analysis"])

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

    def _complete_report(self):
        path = getattr(self, "_report_file", None)
        if path and Path(path).is_file():
            return Path(path).read_text(encoding="utf-8")
        return getattr(self, "_full_report", self.txt_analysis.toPlainText())

    def copy_analysis(self):
        QApplication.clipboard().setText(self._complete_report())
        self.statusBar().showMessage("已复制分析报告")

    def export_analysis(self):
        if not self.txt_analysis.toPlainText().strip():
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出分析报告", "RayNeo_分析结果.txt", "文本文件 (*.txt)"
        )
        if path:
            Path(path).write_text(
                self._complete_report(),
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
        if not self._closing and not self.notes.can_close():
            event.ignore()
            return
        self._closing = True
        running = [
            w
            for w in (
                self.worker,
                self.search_worker,
                self.find_worker,
                self.decrypt_worker,
                self.preview_worker,
                self.version_worker,
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
            QTimer.singleShot(75, self.close)
            return
        self._analysis_session.stop()
        self._version_session.stop()
        self.viewer.set_filter_highlights({})
        self.match_model.set_rows([])
        for folder in self._temp_dirs:
            shutil.rmtree(folder, ignore_errors=True)
        self._task_ui_timer.stop()
        super().closeEvent(event)
