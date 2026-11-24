"""Recent filter conditions and a compact list of shortcuts."""

from PyQt6.QtWidgets import QMenu, QToolButton


SUGGESTIONS = (
    "disconnected",
    "rssi",
    "error",
    "fail",
    "timeout",
    "404",
    "ANCS",
    "扫描",
    "超时",
    "失败",
)
HISTORY_KEY = "filter/history"
HISTORY_LIMIT = 16


class FilterHistoryButton(QToolButton):
    def __init__(self, settings, restore, add_keyword, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.restore = restore
        self.add_keyword = add_keyword
        self.setText("历史 ▾")
        self.setToolTip("最近的筛选条件和常用关键字")
        menu = QMenu(self)
        menu.aboutToShow.connect(self._populate)
        self.setMenu(menu)
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

    def entries(self):
        return [
            item
            for item in self.settings.value(HISTORY_KEY, [], type=list)
            if isinstance(item, dict) and item.get("query")
        ]

    def remember(self, options):
        if len(options["query"]) > 2048:
            return
        entries = [item for item in self.entries() if item != options]
        self.settings.setValue(HISTORY_KEY, [options, *entries][:HISTORY_LIMIT])

    def _populate(self):
        menu = self.menu()
        menu.clear()
        recent = self.entries()
        if recent:
            menu.addSection("最近筛选")
            for item in recent:
                text = item["query"].replace("&", "&&")
                menu.addAction(
                    text if len(text) <= 52 else text[:51] + "…",
                    lambda _checked=False, item=item: self.restore(item),
                )
            menu.addSeparator()
            menu.addAction("清除历史", lambda: self.settings.remove(HISTORY_KEY))
        recommended = menu.addMenu("常用关键字")
        for word in SUGGESTIONS:
            recommended.addAction(
                word, lambda _checked=False, word=word: self.add_keyword(word)
            )
