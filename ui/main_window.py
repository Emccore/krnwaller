"""
krnwaller 主窗口 UI
使用 PyQt5 构建现代化深色主题防火墙控制界面
"""

import sys
import time
import threading
import random
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
        QHeaderView, QSplitter, QFrame, QTextEdit, QLineEdit, QComboBox,
        QCheckBox, QSpinBox, QGroupBox, QFormLayout, QDialog, QDialogButtonBox,
        QMessageBox, QFileDialog, QProgressBar, QScrollArea, QGridLayout,
        QSystemTrayIcon, QMenu, QAction, QStatusBar, QToolBar, QToolButton,
        QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem,
        QAbstractItemView, QSizePolicy, QStackedWidget, QSlider
    )
    from PyQt5.QtCore import (
        Qt, QTimer, QThread, pyqtSignal, QSize, QPropertyAnimation,
        QEasingCurve, QRect, QPoint, QDateTime, QAbstractTableModel,
        QModelIndex, QVariant
    )
    from PyQt5.QtGui import (
        QIcon, QFont, QColor, QPalette, QPixmap, QPainter, QPen, QBrush,
        QLinearGradient, QFontMetrics, QCursor
    )
    from PyQt5.QtChart import (
        QChart, QChartView, QLineSeries, QValueAxis, QDateTimeAxis,
        QAreaSeries, QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis
    )
    HAS_QT = True
except ImportError:
    HAS_QT = False


logger = logging.getLogger("krnwaller.ui")

# ---------------------------------------------------------------------------
# 颜色主题
# ---------------------------------------------------------------------------

THEME = {
    "bg_primary":     "#0d1117",
    "bg_secondary":   "#161b22",
    "bg_tertiary":    "#21262d",
    "bg_hover":       "#30363d",
    "accent_blue":    "#58a6ff",
    "accent_green":   "#56d364",
    "accent_red":     "#f85149",
    "accent_orange":  "#e3b341",
    "accent_purple":  "#bc8cff",
    "text_primary":   "#c9d1d9",
    "text_secondary": "#8b949e",
    "text_muted":     "#6e7681",
    "border":         "#30363d",
    "border_active":  "#58a6ff",
    "success":        "#56d364",
    "warning":        "#e3b341",
    "danger":         "#f85149",
    "info":           "#58a6ff",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {THEME['bg_primary']};
    color: {THEME['text_primary']};
    font-family: "Segoe UI", "Microsoft YaHei UI", Arial, sans-serif;
    font-size: 13px;
}}

QTabWidget::pane {{
    border: 1px solid {THEME['border']};
    background-color: {THEME['bg_secondary']};
    border-radius: 6px;
}}

QTabBar::tab {{
    background-color: {THEME['bg_tertiary']};
    color: {THEME['text_secondary']};
    padding: 10px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
    font-size: 13px;
}}

QTabBar::tab:selected {{
    background-color: {THEME['bg_secondary']};
    color: {THEME['accent_blue']};
    border-bottom: 2px solid {THEME['accent_blue']};
    font-weight: bold;
}}

QTabBar::tab:hover:!selected {{
    background-color: {THEME['bg_hover']};
    color: {THEME['text_primary']};
}}

QPushButton {{
    background-color: {THEME['bg_tertiary']};
    color: {THEME['text_primary']};
    border: 1px solid {THEME['border']};
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13px;
    min-width: 80px;
}}

QPushButton:hover {{
    background-color: {THEME['bg_hover']};
    border-color: {THEME['accent_blue']};
    color: {THEME['accent_blue']};
}}

QPushButton:pressed {{
    background-color: {THEME['accent_blue']};
    color: white;
}}

QPushButton#btn_primary {{
    background-color: {THEME['accent_blue']};
    color: white;
    border: none;
    font-weight: bold;
}}

QPushButton#btn_primary:hover {{
    background-color: #79b8ff;
    color: white;
}}

QPushButton#btn_danger {{
    background-color: {THEME['accent_red']};
    color: white;
    border: none;
}}

QPushButton#btn_danger:hover {{
    background-color: #ff6b6b;
}}

QPushButton#btn_success {{
    background-color: {THEME['accent_green']};
    color: #0d1117;
    border: none;
    font-weight: bold;
}}

QTableWidget {{
    background-color: {THEME['bg_secondary']};
    border: 1px solid {THEME['border']};
    border-radius: 6px;
    gridline-color: {THEME['border']};
    selection-background-color: {THEME['bg_hover']};
    selection-color: {THEME['text_primary']};
    alternate-background-color: {THEME['bg_tertiary']};
}}

QTableWidget::item {{
    padding: 6px 10px;
    border: none;
}}

QTableWidget::item:selected {{
    background-color: {THEME['bg_hover']};
    color: {THEME['accent_blue']};
}}

QHeaderView::section {{
    background-color: {THEME['bg_tertiary']};
    color: {THEME['text_secondary']};
    padding: 8px 10px;
    border: none;
    border-right: 1px solid {THEME['border']};
    border-bottom: 1px solid {THEME['border']};
    font-weight: bold;
    font-size: 12px;
}}

QLineEdit, QComboBox, QSpinBox, QTextEdit {{
    background-color: {THEME['bg_tertiary']};
    color: {THEME['text_primary']};
    border: 1px solid {THEME['border']};
    border-radius: 5px;
    padding: 6px 10px;
    font-size: 13px;
}}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTextEdit:focus {{
    border-color: {THEME['accent_blue']};
    outline: none;
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    width: 10px;
    height: 10px;
}}

QComboBox QAbstractItemView {{
    background-color: {THEME['bg_tertiary']};
    border: 1px solid {THEME['border']};
    selection-background-color: {THEME['bg_hover']};
    color: {THEME['text_primary']};
}}

QGroupBox {{
    border: 1px solid {THEME['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 10px;
    color: {THEME['text_secondary']};
    font-weight: bold;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 8px;
    color: {THEME['accent_blue']};
}}

QScrollBar:vertical {{
    background: {THEME['bg_primary']};
    width: 8px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical {{
    background: {THEME['bg_hover']};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background: {THEME['accent_blue']};
}}

QScrollBar:horizontal {{
    background: {THEME['bg_primary']};
    height: 8px;
}}

QScrollBar::handle:horizontal {{
    background: {THEME['bg_hover']};
    border-radius: 4px;
}}

QStatusBar {{
    background-color: {THEME['bg_tertiary']};
    color: {THEME['text_secondary']};
    border-top: 1px solid {THEME['border']};
    font-size: 12px;
}}

QToolBar {{
    background-color: {THEME['bg_secondary']};
    border-bottom: 1px solid {THEME['border']};
    spacing: 5px;
    padding: 5px;
}}

QCheckBox {{
    color: {THEME['text_primary']};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 3px;
    border: 1px solid {THEME['border']};
    background: {THEME['bg_tertiary']};
}}

QCheckBox::indicator:checked {{
    background: {THEME['accent_blue']};
    border-color: {THEME['accent_blue']};
}}

QProgressBar {{
    background-color: {THEME['bg_tertiary']};
    border: none;
    border-radius: 5px;
    height: 8px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {THEME['accent_blue']};
    border-radius: 5px;
}}

QListWidget {{
    background-color: {THEME['bg_secondary']};
    border: 1px solid {THEME['border']};
    border-radius: 6px;
}}

QListWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {THEME['bg_tertiary']};
}}

QListWidget::item:selected {{
    background-color: {THEME['bg_hover']};
    color: {THEME['accent_blue']};
}}

QSplitter::handle {{
    background-color: {THEME['border']};
    width: 2px;
    height: 2px;
}}

QMenu {{
    background-color: {THEME['bg_tertiary']};
    border: 1px solid {THEME['border']};
    border-radius: 6px;
    padding: 4px;
}}

QMenu::item {{
    padding: 7px 20px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: {THEME['bg_hover']};
    color: {THEME['accent_blue']};
}}

QLabel#label_title {{
    font-size: 22px;
    font-weight: bold;
    color: {THEME['accent_blue']};
}}

QLabel#label_subtitle {{
    font-size: 12px;
    color: {THEME['text_muted']};
}}
"""


class StatCard(QFrame):
    """统计数字卡片组件"""

    def __init__(self, title: str, value: str = "0",
                 color: str = None, parent=None):
        super().__init__(parent)
        self._color = color or THEME["accent_blue"]
        self._setup_ui(title, value)

    def _setup_ui(self, title: str, value: str):
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumWidth(160)
        self.setMinimumHeight(100)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {THEME['bg_secondary']};
                border: 1px solid {THEME['border']};
                border-radius: 10px;
                border-left: 4px solid {self._color};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        self._label_title = QLabel(title)
        self._label_title.setStyleSheet(
            f"color: {THEME['text_secondary']}; font-size: 12px; border: none;"
        )

        self._label_value = QLabel(value)
        self._label_value.setStyleSheet(
            f"color: {self._color}; font-size: 28px; font-weight: bold; border: none;"
        )

        layout.addWidget(self._label_title)
        layout.addWidget(self._label_value)
        layout.addStretch()

    def set_value(self, value: str):
        self._label_value.setText(value)

    def set_color(self, color: str):
        self._color = color
        self._label_value.setStyleSheet(
            f"color: {color}; font-size: 28px; font-weight: bold; border: none;"
        )


class TrafficMiniChart(QWidget):
    """迷你流量折线图"""

    def __init__(self, max_points: int = 60, color: str = None, parent=None):
        super().__init__(parent)
        self._max_points = max_points
        self._color      = QColor(color or THEME["accent_blue"])
        self._data: List[float] = [0.0] * max_points
        self.setMinimumHeight(60)
        self.setAttribute(Qt.WA_TranslucentBackground, False)

    def push(self, value: float):
        self._data.append(value)
        if len(self._data) > self._max_points:
            self._data.pop(0)
        self.update()

    def paintEvent(self, event):
        if not self._data:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        max_val = max(self._data) or 1

        # 背景
        painter.fillRect(0, 0, w, h, QColor(THEME["bg_secondary"]))

        # 网格线
        pen = QPen(QColor(THEME["border"]))
        pen.setWidth(1)
        painter.setPen(pen)
        for i in range(1, 4):
            y = int(h * i / 4)
            painter.drawLine(0, y, w, y)

        # 折线
        if len(self._data) < 2:
            return
        step = w / (self._max_points - 1)
        points = []
        for i, val in enumerate(self._data):
            x = int(i * step)
            y = int(h - (val / max_val) * (h - 4) - 2)
            points.append(QPoint(x, y))

        # 填充区域
        fill_color = QColor(self._color)
        fill_color.setAlpha(40)
        painter.setBrush(QBrush(fill_color))
        from PyQt5.QtGui import QPolygon
        poly_pts = [QPoint(0, h)] + points + [QPoint(w, h)]
        poly = QPolygon(poly_pts)
        painter.setPen(Qt.NoPen)
        painter.drawPolygon(poly)

        # 线
        pen = QPen(self._color)
        pen.setWidth(2)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        for i in range(len(points) - 1):
            painter.drawLine(points[i], points[i+1])


class StatusIndicator(QLabel):
    """状态指示灯"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False
        self.setFixedSize(14, 14)
        self._update()

    def set_running(self, running: bool):
        self._running = running
        self._update()

    def _update(self):
        color = THEME["accent_green"] if self._running else THEME["accent_red"]
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {color};
                border-radius: 7px;
                border: 2px solid {'rgba(86,211,100,0.3)' if self._running else 'rgba(248,81,73,0.3)'};
            }}
        """)


class EventTableModel(QAbstractTableModel):
    """事件日志表格数据模型"""

    HEADERS = ["时间", "来源 IP", "目标 IP", "协议", "端口", "动作", "规则", "原因"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: List[Dict] = []

    def rowCount(self, parent=QModelIndex()):
        return len(self._events)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return QVariant()

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._events):
            return QVariant()
        evt = self._events[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            mapping = [
                evt.get("time_str", ""),
                evt.get("src_ip", ""),
                evt.get("dst_ip", ""),
                evt.get("protocol", ""),
                str(evt.get("dst_port", "")),
                evt.get("verdict", ""),
                evt.get("rule_id", ""),
                evt.get("reason", ""),
            ]
            return mapping[col] if col < len(mapping) else ""

        if role == Qt.ForegroundRole:
            verdict = evt.get("verdict", "")
            if verdict in ("DROP", "REJECT", "BLOCK"):
                return QColor(THEME["accent_red"])
            elif verdict == "ACCEPT":
                return QColor(THEME["accent_green"])
            return QColor(THEME["text_primary"])

        if role == Qt.TextAlignmentRole:
            return Qt.AlignLeft | Qt.AlignVCenter

        return QVariant()

    def prepend_event(self, evt: Dict):
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._events.insert(0, evt)
        if len(self._events) > 2000:
            self._events = self._events[:2000]
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._events.clear()
        self.endResetModel()


class DashboardTab(QWidget):
    """仪表盘标签页"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # 顶部状态栏
        top_bar = QHBoxLayout()

        self._status_indicator = StatusIndicator()
        self._status_label     = QLabel("防火墙未运行")
        self._status_label.setStyleSheet(
            f"color: {THEME['accent_red']}; font-size: 15px; font-weight: bold;"
        )

        self._btn_start = QPushButton("  启动防火墙")
        self._btn_start.setObjectName("btn_success")
        self._btn_start.setFixedWidth(140)

        self._btn_stop = QPushButton("  停止")
        self._btn_stop.setObjectName("btn_danger")
        self._btn_stop.setFixedWidth(100)
        self._btn_stop.setEnabled(False)

        top_bar.addWidget(self._status_indicator)
        top_bar.addWidget(self._status_label)
        top_bar.addStretch()
        top_bar.addWidget(self._btn_start)
        top_bar.addWidget(self._btn_stop)
        layout.addLayout(top_bar)

        # 统计卡片行
        cards_layout = QHBoxLayout()
        self._card_total   = StatCard("总数据包",  "0",  THEME["accent_blue"])
        self._card_blocked = StatCard("已拦截",     "0",  THEME["accent_red"])
        self._card_allowed = StatCard("已放行",     "0",  THEME["accent_green"])
        self._card_pps     = StatCard("包/秒",      "0",  THEME["accent_orange"])
        self._card_mbps    = StatCard("Mbps",       "0.0", THEME["accent_purple"])
        self._card_conns   = StatCard("活跃连接",   "0",  THEME["accent_blue"])
        cards_layout.addWidget(self._card_total)
        cards_layout.addWidget(self._card_blocked)
        cards_layout.addWidget(self._card_allowed)
        cards_layout.addWidget(self._card_pps)
        cards_layout.addWidget(self._card_mbps)
        cards_layout.addWidget(self._card_conns)
        layout.addLayout(cards_layout)

        # 流量图 + 实时日志
        split = QSplitter(Qt.Horizontal)

        # 左侧流量图
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        chart_title = QLabel("实时流量（包/秒）")
        chart_title.setStyleSheet(
            f"color: {THEME['text_secondary']}; font-size: 12px; font-weight: bold;"
        )
        self._pps_chart = TrafficMiniChart(color=THEME["accent_blue"])
        self._pps_chart.setMinimumHeight(120)

        chart_title2 = QLabel("拦截率（%）")
        chart_title2.setStyleSheet(
            f"color: {THEME['text_secondary']}; font-size: 12px; font-weight: bold;"
        )
        self._drop_chart = TrafficMiniChart(color=THEME["accent_red"])
        self._drop_chart.setMinimumHeight(120)

        left_layout.addWidget(chart_title)
        left_layout.addWidget(self._pps_chart)
        left_layout.addWidget(chart_title2)
        left_layout.addWidget(self._drop_chart)
        left_layout.addStretch()

        # 右侧最近事件
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        events_title = QLabel("最近安全事件")
        events_title.setStyleSheet(
            f"color: {THEME['text_secondary']}; font-size: 12px; font-weight: bold;"
        )
        self._event_list = QListWidget()
        self._event_list.setMaximumHeight(280)

        right_layout.addWidget(events_title)
        right_layout.addWidget(self._event_list)

        # 告警面板
        alerts_title = QLabel("活跃告警")
        alerts_title.setStyleSheet(
            f"color: {THEME['accent_orange']}; font-size: 12px; font-weight: bold;"
        )
        self._alert_list = QListWidget()
        right_layout.addWidget(alerts_title)
        right_layout.addWidget(self._alert_list)
        right_layout.addStretch()

        split.addWidget(left_widget)
        split.addWidget(right_widget)
        split.setSizes([500, 400])
        layout.addWidget(split)

    def update_stats(self, stats: Dict):
        self._card_total.set_value(f"{stats.get('total_packets', 0):,}")
        self._card_blocked.set_value(f"{stats.get('dropped_packets', 0):,}")
        self._card_allowed.set_value(f"{stats.get('accepted_packets', 0):,}")
        self._card_pps.set_value(f"{stats.get('pps_avg', 0):.0f}")
        bps = stats.get("bps_avg", 0) / 1_000_000
        self._card_mbps.set_value(f"{bps:.2f}")
        conn_stats = stats.get("conn_stats", {})
        self._card_conns.set_value(f"{conn_stats.get('total', 0):,}")

        pps = stats.get("pps_avg", 0)
        total = max(1, stats.get("total_packets", 1))
        drop  = stats.get("dropped_packets", 0)
        drop_pct = drop / total * 100
        self._pps_chart.push(pps)
        self._drop_chart.push(drop_pct)

    def set_running(self, running: bool):
        self._status_indicator.set_running(running)
        if running:
            self._status_label.setText("防火墙运行中")
            self._status_label.setStyleSheet(
                f"color: {THEME['accent_green']}; font-size: 15px; font-weight: bold;"
            )
            self._btn_start.setEnabled(False)
            self._btn_stop.setEnabled(True)
        else:
            self._status_label.setText("防火墙未运行")
            self._status_label.setStyleSheet(
                f"color: {THEME['accent_red']}; font-size: 15px; font-weight: bold;"
            )
            self._btn_start.setEnabled(True)
            self._btn_stop.setEnabled(False)

    def add_event_item(self, text: str, color: str = None):
        item = QListWidgetItem(text)
        if color:
            item.setForeground(QColor(color))
        self._event_list.insertItem(0, item)
        if self._event_list.count() > 200:
            self._event_list.takeItem(self._event_list.count() - 1)

    def add_alert_item(self, text: str):
        item = QListWidgetItem(text)
        item.setForeground(QColor(THEME["accent_orange"]))
        self._alert_list.insertItem(0, item)

    @property
    def btn_start(self):
        return self._btn_start

    @property
    def btn_stop(self):
        return self._btn_stop


class RulesTab(QWidget):
    """规则管理标签页"""

    rule_added   = pyqtSignal(dict)
    rule_removed = pyqtSignal(str)
    rule_toggled = pyqtSignal(str, bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # 工具栏
        toolbar = QHBoxLayout()
        self._btn_add    = QPushButton("+ 添加规则")
        self._btn_add.setObjectName("btn_primary")
        self._btn_remove = QPushButton("删除")
        self._btn_remove.setObjectName("btn_danger")
        self._btn_enable = QPushButton("启用/禁用")
        self._btn_import = QPushButton("导入规则")
        self._btn_export = QPushButton("导出规则")
        self._btn_preset = QPushButton("加载预设")

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("搜索规则...")
        self._search_box.setMaximumWidth(220)

        self._chain_combo = QComboBox()
        self._chain_combo.addItems(["INPUT", "OUTPUT", "FORWARD"])

        toolbar.addWidget(self._btn_add)
        toolbar.addWidget(self._btn_remove)
        toolbar.addWidget(self._btn_enable)
        toolbar.addWidget(self._btn_preset)
        toolbar.addStretch()
        toolbar.addWidget(self._chain_combo)
        toolbar.addWidget(self._search_box)
        toolbar.addWidget(self._btn_import)
        toolbar.addWidget(self._btn_export)
        layout.addLayout(toolbar)

        # 规则表格
        self._table = QTableWidget()
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels([
            "启用", "优先级", "名称", "源 IP", "目标 IP",
            "目标端口", "协议", "动作", "命中次数"
        ])
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._table.setColumnWidth(0, 50)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self._table.setColumnWidth(1, 60)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        layout.addWidget(self._table)

        # 连接信号
        self._btn_add.clicked.connect(self._on_add_rule)
        self._btn_remove.clicked.connect(self._on_remove_rule)
        self._search_box.textChanged.connect(self._filter_rules)

    def load_rules(self, rules: List[Dict]):
        self._table.setRowCount(0)
        for rule in rules:
            self._add_rule_row(rule)

    def _add_rule_row(self, rule: Dict):
        row = self._table.rowCount()
        self._table.insertRow(row)

        # 启用复选框
        chk = QCheckBox()
        chk.setChecked(rule.get("enabled", True))
        chk.setStyleSheet("margin-left: 12px;")
        rule_id = rule.get("rule_id", "")
        chk.stateChanged.connect(lambda state, rid=rule_id: self.rule_toggled.emit(rid, state == Qt.Checked))
        self._table.setCellWidget(row, 0, chk)

        def _item(text, color=None):
            item = QTableWidgetItem(str(text))
            if color:
                item.setForeground(QColor(color))
            item.setData(Qt.UserRole, rule_id)
            return item

        self._table.setItem(row, 1, _item(rule.get("priority", 100)))
        self._table.setItem(row, 2, _item(rule.get("name", "")))
        src_ips = ", ".join(rule.get("src_ips", ["any"]) or ["any"])
        dst_ips = ", ".join(rule.get("dst_ips", ["any"]) or ["any"])
        dst_ports = ", ".join(rule.get("dst_ports", ["any"]) or ["any"])
        protos  = ", ".join(rule.get("protocols", ["any"]) or ["any"])
        action  = rule.get("action", "accept")
        action_colors = {
            "accept": THEME["accent_green"],
            "drop":   THEME["accent_red"],
            "reject": THEME["accent_orange"],
            "log":    THEME["accent_blue"],
        }
        self._table.setItem(row, 3, _item(src_ips))
        self._table.setItem(row, 4, _item(dst_ips))
        self._table.setItem(row, 5, _item(dst_ports))
        self._table.setItem(row, 6, _item(protos))
        self._table.setItem(row, 7, _item(action.upper(), action_colors.get(action)))
        self._table.setItem(row, 8, _item(rule.get("hit_count", 0)))

    def _on_add_rule(self):
        dialog = RuleEditDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            form_data = dialog.get_form_data()
            self.rule_added.emit(form_data)

    def _on_remove_rule(self):
        selected = self._table.selectedItems()
        if not selected:
            return
        rule_id = selected[0].data(Qt.UserRole)
        reply = QMessageBox.question(
            self, "确认删除",
            f"确定要删除规则 [{rule_id}] 吗？",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.rule_removed.emit(rule_id)
            self._table.removeRow(self._table.currentRow())

    def _filter_rules(self, text: str):
        for row in range(self._table.rowCount()):
            name_item = self._table.item(row, 2)
            if name_item:
                visible = text.lower() in name_item.text().lower() or not text
                self._table.setRowHidden(row, not visible)


class RuleEditDialog(QDialog):
    """规则编辑对话框"""

    def __init__(self, parent=None, rule: Dict = None):
        super().__init__(parent)
        self._rule = rule or {}
        self.setWindowTitle("编辑防火墙规则")
        self.setMinimumWidth(560)
        self.setMinimumHeight(600)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # 基本信息
        basic_group = QGroupBox("基本信息")
        basic_form  = QFormLayout(basic_group)
        basic_form.setSpacing(10)

        self._name_edit = QLineEdit(self._rule.get("name", ""))
        self._name_edit.setPlaceholderText("规则名称")
        self._desc_edit = QLineEdit(self._rule.get("description", ""))
        self._desc_edit.setPlaceholderText("规则说明（可选）")
        self._priority_spin = QSpinBox()
        self._priority_spin.setRange(1, 999)
        self._priority_spin.setValue(self._rule.get("priority", 100))
        self._enabled_check = QCheckBox("启用规则")
        self._enabled_check.setChecked(self._rule.get("enabled", True))
        self._log_check = QCheckBox("记录命中日志")
        self._log_check.setChecked(self._rule.get("log_enabled", False))

        self._action_combo = QComboBox()
        self._action_combo.addItems(["accept", "drop", "reject", "log"])
        action = self._rule.get("action", "accept")
        idx = self._action_combo.findText(action)
        if idx >= 0:
            self._action_combo.setCurrentIndex(idx)

        basic_form.addRow("名称 *", self._name_edit)
        basic_form.addRow("说明",   self._desc_edit)
        basic_form.addRow("优先级", self._priority_spin)
        basic_form.addRow("动作 *", self._action_combo)
        basic_form.addRow("",       self._enabled_check)
        basic_form.addRow("",       self._log_check)
        layout.addWidget(basic_group)

        # 匹配条件
        match_group = QGroupBox("匹配条件（留空表示匹配所有）")
        match_form  = QFormLayout(match_group)
        match_form.setSpacing(10)

        self._src_ip_edit    = QLineEdit(", ".join(self._rule.get("src_ips", [])))
        self._src_ip_edit.setPlaceholderText("如: 192.168.1.0/24, 10.0.0.1")
        self._dst_ip_edit    = QLineEdit(", ".join(self._rule.get("dst_ips", [])))
        self._dst_ip_edit.setPlaceholderText("如: any, 8.8.8.8")
        self._src_port_edit  = QLineEdit(", ".join(self._rule.get("src_ports", [])))
        self._src_port_edit.setPlaceholderText("如: 1024-65535")
        self._dst_port_edit  = QLineEdit(", ".join(self._rule.get("dst_ports", [])))
        self._dst_port_edit.setPlaceholderText("如: 80, 443, 8080-8090")

        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["any", "tcp", "udp", "icmp", "tcp,udp"])
        protos = self._rule.get("protocols", [])
        proto_str = ",".join(protos) if protos else "any"
        idx = self._proto_combo.findText(proto_str)
        if idx >= 0:
            self._proto_combo.setCurrentIndex(idx)

        self._dir_combo = QComboBox()
        self._dir_combo.addItems(["any", "IN", "OUT", "FORWARD"])

        self._content_edit = QLineEdit()
        self._content_edit.setPlaceholderText("载荷内容特征（可选）")
        self._regex_check = QCheckBox("使用正则表达式")

        match_form.addRow("源 IP / CIDR",  self._src_ip_edit)
        match_form.addRow("目标 IP / CIDR", self._dst_ip_edit)
        match_form.addRow("源端口",          self._src_port_edit)
        match_form.addRow("目标端口",        self._dst_port_edit)
        match_form.addRow("协议",            self._proto_combo)
        match_form.addRow("方向",            self._dir_combo)
        match_form.addRow("内容匹配",        self._content_edit)
        match_form.addRow("",               self._regex_check)
        layout.addWidget(match_group)

        # 按钮
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.button(QDialogButtonBox.Ok).setText("保存规则")
        btn_box.button(QDialogButtonBox.Cancel).setText("取消")
        btn_box.accepted.connect(self._validate_and_accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _validate_and_accept(self):
        if not self._name_edit.text().strip():
            QMessageBox.warning(self, "验证失败", "规则名称不能为空")
            return
        self.accept()

    def get_form_data(self) -> Dict:
        def _split(text: str) -> List[str]:
            return [s.strip() for s in text.split(",") if s.strip()]

        proto_str = self._proto_combo.currentText()
        protos = _split(proto_str) if proto_str != "any" else []
        direction = self._dir_combo.currentText()
        directions = [direction] if direction != "any" else []

        return {
            "name":            self._name_edit.text().strip(),
            "description":     self._desc_edit.text().strip(),
            "priority":        self._priority_spin.value(),
            "enabled":         self._enabled_check.isChecked(),
            "log_enabled":     self._log_check.isChecked(),
            "action":          self._action_combo.currentText(),
            "src_ips":         _split(self._src_ip_edit.text()),
            "dst_ips":         _split(self._dst_ip_edit.text()),
            "src_ports":       _split(self._src_port_edit.text()),
            "dst_ports":       _split(self._dst_port_edit.text()),
            "protocols":       protos,
            "directions":      directions,
            "content_pattern": self._content_edit.text().strip(),
            "content_is_regex": self._regex_check.isChecked(),
            "group":           "default",
        }


class LogTab(QWidget):
    """日志查看标签页"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # 过滤栏
        filter_bar = QHBoxLayout()

        self._filter_type  = QComboBox()
        self._filter_type.addItems(["全部", "BLOCK", "ALLOW", "ATTACK", "ALERT"])

        self._filter_ip   = QLineEdit()
        self._filter_ip.setPlaceholderText("过滤 IP...")
        self._filter_ip.setMaximumWidth(160)

        self._filter_proto = QComboBox()
        self._filter_proto.addItems(["全部协议", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"])

        self._btn_clear    = QPushButton("清空")
        self._btn_export   = QPushButton("导出 CSV")
        self._auto_scroll  = QCheckBox("自动滚动")
        self._auto_scroll.setChecked(True)
        self._pause_check  = QCheckBox("暂停刷新")

        filter_bar.addWidget(QLabel("类型:"))
        filter_bar.addWidget(self._filter_type)
        filter_bar.addWidget(QLabel("IP:"))
        filter_bar.addWidget(self._filter_ip)
        filter_bar.addWidget(QLabel("协议:"))
        filter_bar.addWidget(self._filter_proto)
        filter_bar.addStretch()
        filter_bar.addWidget(self._auto_scroll)
        filter_bar.addWidget(self._pause_check)
        filter_bar.addWidget(self._btn_clear)
        filter_bar.addWidget(self._btn_export)
        layout.addLayout(filter_bar)

        # 事件表格
        self._model = EventTableModel()
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels(
            ["时间", "来源 IP", "目标 IP", "协议", "端口", "动作", "规则", "原因"]
        )
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        layout.addWidget(self._table)

        # 底部详情
        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(120)
        self._detail_text.setPlaceholderText("选择事件查看详情...")
        layout.addWidget(self._detail_text)

        self._table.itemSelectionChanged.connect(self._on_selection)
        self._btn_clear.clicked.connect(self._on_clear)
        self._btn_export.clicked.connect(self._on_export)

    def add_event(self, evt: Dict):
        if self._pause_check.isChecked():
            return

        # 过滤
        type_filter = self._filter_type.currentText()
        if type_filter != "全部" and evt.get("event_type", "") != type_filter:
            return
        ip_filter = self._filter_ip.text().strip()
        if ip_filter and ip_filter not in evt.get("src_ip", "") and ip_filter not in evt.get("dst_ip", ""):
            return

        row = 0
        self._table.insertRow(row)

        def _item(text, color=None):
            item = QTableWidgetItem(str(text or ""))
            if color:
                item.setForeground(QColor(color))
            return item

        verdict = evt.get("verdict", "")
        v_color = THEME["accent_green"]
        if verdict in ("DROP", "REJECT", "BLOCK"):
            v_color = THEME["accent_red"]

        import datetime
        ts = evt.get("timestamp", time.time())
        time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

        self._table.setItem(row, 0, _item(time_str))
        self._table.setItem(row, 1, _item(evt.get("src_ip", "")))
        self._table.setItem(row, 2, _item(evt.get("dst_ip", "")))
        self._table.setItem(row, 3, _item(evt.get("protocol", "")))
        self._table.setItem(row, 4, _item(evt.get("dst_port", "")))
        self._table.setItem(row, 5, _item(verdict, v_color))
        self._table.setItem(row, 6, _item(evt.get("rule_id", "")))
        self._table.setItem(row, 7, _item(evt.get("reason", "")))

        # 限制行数
        if self._table.rowCount() > 1000:
            self._table.removeRow(self._table.rowCount() - 1)

        if self._auto_scroll.isChecked():
            self._table.scrollToTop()

    def _on_selection(self):
        selected = self._table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        info_parts = []
        headers = ["时间", "来源IP", "目标IP", "协议", "端口", "动作", "规则", "原因"]
        for col in range(min(8, self._table.columnCount())):
            item = self._table.item(row, col)
            if item:
                info_parts.append(f"{headers[col]}: {item.text()}")
        self._detail_text.setPlainText("\n".join(info_parts))

    def _on_clear(self):
        self._table.setRowCount(0)
        self._detail_text.clear()

    def _on_export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", "firewall_log.csv", "CSV 文件 (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as f:
                headers = ["时间", "来源IP", "目标IP", "协议", "端口", "动作", "规则", "原因"]
                f.write(",".join(headers) + "\n")
                for row in range(self._table.rowCount()):
                    row_data = []
                    for col in range(8):
                        item = self._table.item(row, col)
                        row_data.append(item.text() if item else "")
                    f.write(",".join(row_data) + "\n")
            QMessageBox.information(self, "导出成功", f"日志已导出至:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", str(e))


class ConnectionsTab(QWidget):
    """活跃连接标签页"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        self._btn_refresh = QPushButton("刷新")
        self._btn_refresh.setObjectName("btn_primary")
        self._btn_kill = QPushButton("终止连接")
        self._btn_kill.setObjectName("btn_danger")
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("过滤 IP 或端口...")
        self._filter_edit.setMaximumWidth(200)
        self._state_combo = QComboBox()
        self._state_combo.addItems(["全部状态", "ESTABLISHED", "SYN_SENT", "SYN_RECV",
                                     "FIN_WAIT", "CLOSE_WAIT", "UDP_OPEN"])
        toolbar.addWidget(self._btn_refresh)
        toolbar.addWidget(self._btn_kill)
        toolbar.addStretch()
        toolbar.addWidget(QLabel("状态:"))
        toolbar.addWidget(self._state_combo)
        toolbar.addWidget(self._filter_edit)
        layout.addLayout(toolbar)

        self._table = QTableWidget()
        self._table.setColumnCount(10)
        self._table.setHorizontalHeaderLabels([
            "协议", "来源 IP", "来源端口", "目标 IP", "目标端口",
            "状态", "收包", "发包", "流量", "持续时间"
        ])
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        layout.addWidget(self._table)

        # 统计摘要
        summary_bar = QHBoxLayout()
        self._label_total = QLabel("总连接: 0")
        self._label_tcp   = QLabel("TCP: 0")
        self._label_udp   = QLabel("UDP: 0")
        self._label_estab = QLabel("已建立: 0")
        for lbl in [self._label_total, self._label_tcp, self._label_udp, self._label_estab]:
            lbl.setStyleSheet(f"color: {THEME['text_secondary']}; font-size: 12px;")
            summary_bar.addWidget(lbl)
        summary_bar.addStretch()
        layout.addLayout(summary_bar)

        self._btn_refresh.clicked.connect(self._on_refresh)

    def load_connections(self, flows: List):
        self._table.setRowCount(0)
        tcp_count = udp_count = estab_count = 0

        for flow in flows:
            row = self._table.rowCount()
            self._table.insertRow(row)

            proto_name = flow.protocol.name if hasattr(flow.protocol, 'name') else str(flow.protocol)
            state = getattr(flow, 'state', 'UNKNOWN')
            is_estab = getattr(flow, 'is_established', False)
            if is_estab:
                estab_count += 1
            if "TCP" in proto_name.upper():
                tcp_count += 1
            elif "UDP" in proto_name.upper():
                udp_count += 1

            duration = getattr(flow, 'duration', 0)
            total_bytes = getattr(flow, 'total_bytes', 0)
            bytes_in = getattr(flow, 'bytes_in', 0)
            bytes_out = getattr(flow, 'bytes_out', 0)
            pkts_in = getattr(flow, 'packets_in', 0)
            pkts_out = getattr(flow, 'packets_out', 0)

            state_colors = {
                "ESTABLISHED": THEME["accent_green"],
                "SYN_SENT":    THEME["accent_orange"],
                "RESET":       THEME["accent_red"],
                "FIN_WAIT":    THEME["accent_purple"],
            }

            def _item(text, color=None):
                item = QTableWidgetItem(str(text))
                if color:
                    item.setForeground(QColor(color))
                return item

            self._table.setItem(row, 0, _item(proto_name))
            self._table.setItem(row, 1, _item(flow.src_ip))
            self._table.setItem(row, 2, _item(flow.src_port))
            self._table.setItem(row, 3, _item(flow.dst_ip))
            self._table.setItem(row, 4, _item(flow.dst_port))
            self._table.setItem(row, 5, _item(state, state_colors.get(state)))
            self._table.setItem(row, 6, _item(f"{pkts_in:,}"))
            self._table.setItem(row, 7, _item(f"{pkts_out:,}"))
            self._table.setItem(row, 8, _item(self._fmt_bytes(total_bytes)))
            self._table.setItem(row, 9, _item(f"{duration:.0f}s"))

        total = self._table.rowCount()
        self._label_total.setText(f"总连接: {total}")
        self._label_tcp.setText(f"TCP: {tcp_count}")
        self._label_udp.setText(f"UDP: {udp_count}")
        self._label_estab.setText(f"已建立: {estab_count}")

    def _fmt_bytes(self, b: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    def _on_refresh(self):
        pass  # 由主窗口定时刷新


class BlacklistTab(QWidget):
    """黑白名单标签页"""

    ip_blocked   = pyqtSignal(str)
    ip_unblocked = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        split = QSplitter(Qt.Horizontal)

        # 封锁IP列表
        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)

        lbl = QLabel("封锁 IP / 网段")
        lbl.setStyleSheet(f"font-weight: bold; color: {THEME['accent_red']};")
        left_lay.addWidget(lbl)

        add_bar = QHBoxLayout()
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("IP 或 CIDR，如 192.168.1.100 或 10.0.0.0/8")
        self._btn_block = QPushButton("封锁")
        self._btn_block.setObjectName("btn_danger")
        self._btn_block.setFixedWidth(70)
        add_bar.addWidget(self._ip_input)
        add_bar.addWidget(self._btn_block)
        left_lay.addLayout(add_bar)

        self._ip_list = QListWidget()
        left_lay.addWidget(self._ip_list)

        unblock_bar = QHBoxLayout()
        self._btn_unblock = QPushButton("解除封锁")
        self._btn_unblock.setObjectName("btn_success")
        self._btn_load  = QPushButton("导入列表")
        unblock_bar.addWidget(self._btn_unblock)
        unblock_bar.addWidget(self._btn_load)
        left_lay.addLayout(unblock_bar)

        # 封锁域名列表
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)

        lbl2 = QLabel("封锁域名（支持通配符 *）")
        lbl2.setStyleSheet(f"font-weight: bold; color: {THEME['accent_orange']};")
        right_lay.addWidget(lbl2)

        add_bar2 = QHBoxLayout()
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("如 *.malware.com 或 ads.tracker.net")
        self._btn_block_domain = QPushButton("封锁")
        self._btn_block_domain.setObjectName("btn_danger")
        self._btn_block_domain.setFixedWidth(70)
        add_bar2.addWidget(self._domain_input)
        add_bar2.addWidget(self._btn_block_domain)
        right_lay.addLayout(add_bar2)

        self._domain_list = QListWidget()
        right_lay.addWidget(self._domain_list)

        split.addWidget(left)
        split.addWidget(right)
        layout.addWidget(split)

        self._btn_block.clicked.connect(self._on_block_ip)
        self._btn_unblock.clicked.connect(self._on_unblock_ip)
        self._btn_block_domain.clicked.connect(self._on_block_domain)
        self._btn_load.clicked.connect(self._on_load_file)

    def _on_block_ip(self):
        ip = self._ip_input.text().strip()
        if ip:
            self._ip_list.addItem(ip)
            self._ip_input.clear()
            self.ip_blocked.emit(ip)

    def _on_unblock_ip(self):
        selected = self._ip_list.selectedItems()
        for item in selected:
            row = self._ip_list.row(item)
            self.ip_unblocked.emit(item.text())
            self._ip_list.takeItem(row)

    def _on_block_domain(self):
        domain = self._domain_input.text().strip()
        if domain:
            self._domain_list.addItem(domain)
            self._domain_input.clear()

    def _on_load_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "导入黑名单", "", "文本文件 (*.txt);;全部文件 (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self._ip_list.addItem(line)
                            self.ip_blocked.emit(line)
            except Exception as e:
                QMessageBox.critical(self, "导入失败", str(e))

    def load_blocked_ips(self, ips: List[str]):
        self._ip_list.clear()
        for ip in ips:
            self._ip_list.addItem(ip)


class SettingsTab(QWidget):
    """设置标签页"""

    settings_changed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        layout  = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # 引擎配置
        engine_group = QGroupBox("防火墙引擎")
        engine_form  = QFormLayout(engine_group)
        engine_form.setSpacing(10)

        self._worker_spin = QSpinBox()
        self._worker_spin.setRange(1, 32)
        self._worker_spin.setValue(4)
        self._queue_spin  = QSpinBox()
        self._queue_spin.setRange(1000, 200000)
        self._queue_spin.setSingleStep(1000)
        self._queue_spin.setValue(20000)
        self._max_conn_spin = QSpinBox()
        self._max_conn_spin.setRange(1000, 1000000)
        self._max_conn_spin.setSingleStep(1000)
        self._max_conn_spin.setValue(65536)

        engine_form.addRow("工作线程数",     self._worker_spin)
        engine_form.addRow("包队列大小",     self._queue_spin)
        engine_form.addRow("最大连接跟踪数", self._max_conn_spin)
        layout.addWidget(engine_group)

        # 防攻击配置
        attack_group = QGroupBox("防攻击配置")
        attack_form  = QFormLayout(attack_group)
        attack_form.setSpacing(10)

        self._syn_threshold = QSpinBox()
        self._syn_threshold.setRange(10, 10000)
        self._syn_threshold.setValue(200)
        self._syn_window = QSpinBox()
        self._syn_window.setRange(1, 60)
        self._syn_window.setValue(1)
        self._scan_threshold = QSpinBox()
        self._scan_threshold.setRange(5, 200)
        self._scan_threshold.setValue(20)
        self._scan_window = QSpinBox()
        self._scan_window.setRange(1, 120)
        self._scan_window.setValue(10)
        self._enable_syn = QCheckBox("启用 SYN Flood 防护")
        self._enable_syn.setChecked(True)
        self._enable_scan = QCheckBox("启用端口扫描防护")
        self._enable_scan.setChecked(True)

        attack_form.addRow("",                  self._enable_syn)
        attack_form.addRow("SYN/秒阈值",        self._syn_threshold)
        attack_form.addRow("SYN 统计窗口(秒)",  self._syn_window)
        attack_form.addRow("",                  self._enable_scan)
        attack_form.addRow("扫描端口数阈值",     self._scan_threshold)
        attack_form.addRow("扫描统计窗口(秒)",   self._scan_window)
        layout.addWidget(attack_group)

        # 日志配置
        log_group = QGroupBox("日志设置")
        log_form  = QFormLayout(log_group)
        log_form.setSpacing(10)

        self._log_dir_edit = QLineEdit("logs")
        self._log_keep_spin = QSpinBox()
        self._log_keep_spin.setRange(1, 365)
        self._log_keep_spin.setValue(30)
        self._log_level_combo = QComboBox()
        self._log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self._log_level_combo.setCurrentIndex(1)

        log_form.addRow("日志目录",      self._log_dir_edit)
        log_form.addRow("保留天数",      self._log_keep_spin)
        log_form.addRow("日志级别",      self._log_level_combo)
        layout.addWidget(log_group)

        # 网络接口
        iface_group = QGroupBox("网络接口")
        iface_form  = QFormLayout(iface_group)
        iface_form.setSpacing(10)

        self._iface_edit = QLineEdit()
        self._iface_edit.setPlaceholderText("留空监听全部接口")
        self._promiscuous = QCheckBox("混杂模式（捕获所有经过的包）")

        iface_form.addRow("监听接口", self._iface_edit)
        iface_form.addRow("",        self._promiscuous)
        layout.addWidget(iface_group)

        # 保存按钮
        btn_bar = QHBoxLayout()
        btn_save  = QPushButton("保存设置")
        btn_save.setObjectName("btn_primary")
        btn_reset = QPushButton("恢复默认")
        btn_bar.addStretch()
        btn_bar.addWidget(btn_reset)
        btn_bar.addWidget(btn_save)
        layout.addLayout(btn_bar)
        layout.addStretch()

        btn_save.clicked.connect(self._on_save)

        scroll_layout = QVBoxLayout(self)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll.setWidget(content)
        scroll_layout.addWidget(scroll)

    def _on_save(self):
        config = {
            "worker_threads":    self._worker_spin.value(),
            "queue_size":        self._queue_spin.value(),
            "max_connections":   self._max_conn_spin.value(),
            "syn_threshold":     self._syn_threshold.value(),
            "syn_window":        float(self._syn_window.value()),
            "scan_port_threshold": self._scan_threshold.value(),
            "scan_window":       float(self._scan_window.value()),
            "log_dir":           self._log_dir_edit.text(),
            "log_keep_days":     self._log_keep_spin.value(),
        }
        self.settings_changed.emit(config)
        QMessageBox.information(self, "设置已保存", "配置已保存，重启防火墙后生效。")

    def get_config(self) -> Dict:
        return {
            "worker_threads":    self._worker_spin.value(),
            "queue_size":        self._queue_spin.value(),
            "max_connections":   self._max_conn_spin.value(),
            "syn_threshold":     self._syn_threshold.value(),
            "syn_window":        float(self._syn_window.value()),
            "scan_port_threshold": self._scan_threshold.value(),
            "scan_window":       float(self._scan_window.value()),
        }


class AboutDialog(QDialog):
    """关于对话框"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于 krnwaller")
        self.setFixedSize(440, 360)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(12)
        layout.setAlignment(Qt.AlignCenter)

        icon_label = QLabel("🛡")
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("font-size: 64px;")

        title_label = QLabel("krnwaller")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(
            f"font-size: 28px; font-weight: bold; color: {THEME['accent_blue']};"
        )

        version_label = QLabel("版本 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet(f"color: {THEME['text_muted']};")

        desc_label = QLabel(
            "高性能软件防火墙\n"
            "支持 IPv4/IPv6 多协议深度检测\n"
            "SYN Flood / 端口扫描 / ARP 欺骗防护\n"
            "状态防火墙 · 实时流量分析 · 规则热更新"
        )
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet(
            f"color: {THEME['text_secondary']}; line-height: 1.6; font-size: 13px;"
        )

        copyright_label = QLabel("© 2026 krnwaller Project")
        copyright_label.setAlignment(Qt.AlignCenter)
        copyright_label.setStyleSheet(f"color: {THEME['text_muted']}; font-size: 11px;")

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.close)
        btn_close.setFixedWidth(100)

        layout.addWidget(icon_label)
        layout.addWidget(title_label)
        layout.addWidget(version_label)
        layout.addWidget(desc_label)
        layout.addStretch()
        layout.addWidget(copyright_label)
        layout.addWidget(btn_close, alignment=Qt.AlignCenter)


class MainWindow(QMainWindow):
    """
    主窗口
    组织所有标签页并协调与防火墙引擎的通信
    """

    def __init__(self):
        super().__init__()
        self._engine  = None
        self._running = False
        self._rule_mgr = None
        self._fw_logger = None

        self._setup_engine()
        self._setup_ui()
        self._setup_tray()
        self._setup_timers()

        logger.info("主窗口已初始化")

    def _setup_engine(self):
        """延迟初始化引擎（避免启动时阻塞）"""
        try:
            from core.engine import FirewallEngine
            from rules.engine import RuleManager
            from utils.logger import FirewallLogger

            self._rule_mgr  = RuleManager("config")
            self._fw_logger = FirewallLogger("logs", "logs/events.db")
            config = {
                "log_dir": "logs",
                "db_path": "logs/events.db",
                "enable_logger": True,
            }
            self._engine = FirewallEngine(config)
            self._engine.set_rule_chain(self._rule_mgr.get_chain("INPUT"))
            self._engine.set_logger(self._fw_logger)

            # 默认使用 auto 后端：有真实抓包库就抓包，没有就自动进入仿真
            self._engine.set_capture_config(
                iface="",
                backend="auto",
                promisc=False,
                bpf_filter="ip or ip6",
            )

            # 注册回调
            self._engine.add_block_callback(self._on_packet_blocked)
            self._engine.add_packet_callback(self._on_packet_seen)
            self._engine.add_alert_callback(self._on_alert)

            self._rule_mgr.load_rules()
            logger.info("防火墙引擎组件初始化成功")
        except Exception as e:
            logger.warning(f"引擎初始化失败（演示模式）: {e}")

    def _setup_ui(self):
        self.setWindowTitle("krnwaller — 高性能软件防火墙")
        self.setMinimumSize(1200, 780)
        self.resize(1400, 900)
        self.setStyleSheet(STYLESHEET)

        # 中央控件
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 顶部 Header
        header = self._build_header()
        main_layout.addWidget(header)

        # 主 TabWidget
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        main_layout.addWidget(self._tabs)

        # 各标签页
        self._dashboard_tab   = DashboardTab()
        self._rules_tab       = RulesTab()
        self._log_tab         = LogTab()
        self._conn_tab        = ConnectionsTab()
        self._blacklist_tab   = BlacklistTab()
        self._settings_tab    = SettingsTab()

        self._tabs.addTab(self._dashboard_tab,   "  仪表盘  ")
        self._tabs.addTab(self._rules_tab,        "  规则管理  ")
        self._tabs.addTab(self._log_tab,          "  安全日志  ")
        self._tabs.addTab(self._conn_tab,         "  活跃连接  ")
        self._tabs.addTab(self._blacklist_tab,    "  黑白名单  ")
        self._tabs.addTab(self._settings_tab,     "  设置  ")

        # 状态栏
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._status_left  = QLabel("就绪")
        self._status_right = QLabel("")
        self._statusbar.addWidget(self._status_left)
        self._statusbar.addPermanentWidget(self._status_right)

        # 信号连接
        self._dashboard_tab.btn_start.clicked.connect(self._start_firewall)
        self._dashboard_tab.btn_stop.clicked.connect(self._stop_firewall)
        self._rules_tab.rule_added.connect(self._on_rule_added)
        self._rules_tab.rule_removed.connect(self._on_rule_removed)
        self._rules_tab.rule_toggled.connect(self._on_rule_toggled)
        self._blacklist_tab.ip_blocked.connect(self._on_ip_blocked)
        self._blacklist_tab.ip_unblocked.connect(self._on_ip_unblocked)

        # 加载初始规则
        self._refresh_rules()

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(
            f"background-color: {THEME['bg_secondary']};"
            f"border-bottom: 1px solid {THEME['border']};"
        )
        layout = QHBoxLayout(header)
        layout.setContentsMargins(16, 0, 16, 0)

        icon_label = QLabel("🛡 krnwaller")
        icon_label.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {THEME['accent_blue']}; border: none;"
        )

        self._header_status = QLabel("● 未运行")
        self._header_status.setStyleSheet(
            f"color: {THEME['accent_red']}; font-size: 13px; border: none;"
        )

        btn_about   = QPushButton("关于")
        btn_about.setFixedWidth(60)
        btn_about.clicked.connect(lambda: AboutDialog(self).exec_())

        btn_report  = QPushButton("导出报告")
        btn_report.clicked.connect(self._export_report)

        layout.addWidget(icon_label)
        layout.addSpacing(20)
        layout.addWidget(self._header_status)
        layout.addStretch()
        layout.addWidget(btn_report)
        layout.addWidget(btn_about)
        return header

    def _setup_tray(self):
        """系统托盘图标"""
        self._tray = QSystemTrayIcon(self)
        tray_menu = QMenu()

        action_show  = QAction("显示主窗口", self)
        action_start = QAction("启动防火墙", self)
        action_stop  = QAction("停止防火墙", self)
        action_quit  = QAction("退出", self)

        action_show.triggered.connect(self.show)
        action_start.triggered.connect(self._start_firewall)
        action_stop.triggered.connect(self._stop_firewall)
        action_quit.triggered.connect(self._quit_app)

        tray_menu.addAction(action_show)
        tray_menu.addSeparator()
        tray_menu.addAction(action_start)
        tray_menu.addAction(action_stop)
        tray_menu.addSeparator()
        tray_menu.addAction(action_quit)

        self._tray.setContextMenu(tray_menu)
        self._tray.activated.connect(self._on_tray_activated)

    def _setup_timers(self):
        # UI 刷新定时器 (1秒)
        self._ui_timer = QTimer(self)
        self._ui_timer.timeout.connect(self._refresh_ui)
        self._ui_timer.start(1000)

        # 连接刷新（5秒）
        self._conn_timer = QTimer(self)
        self._conn_timer.timeout.connect(self._refresh_connections)
        self._conn_timer.start(5000)

        # 演示数据生成（当引擎不可用时）
        self._demo_timer = QTimer(self)
        self._demo_timer.timeout.connect(self._gen_demo_data)
        self._demo_timer.start(800)

        # 时钟
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)

    def _start_firewall(self):
        if self._engine:
            try:
                self._engine.start()
                self._running = True
                self._demo_timer.stop()   # 停止演示数据
            except Exception as e:
                QMessageBox.critical(self, "启动失败", f"防火墙引擎启动失败:\n{e}")
                return
        else:
            # 演示模式
            self._running = True

        self._dashboard_tab.set_running(True)
        self._header_status.setText("● 运行中")
        self._header_status.setStyleSheet(
            f"color: {THEME['accent_green']}; font-size: 13px; border: none;"
        )
        self._status_left.setText("防火墙已启动")
        if self._tray.isSystemTrayAvailable():
            self._tray.showMessage("krnwaller", "防火墙已启动，正在保护您的网络", QSystemTrayIcon.Information, 3000)

    def _stop_firewall(self):
        if self._engine and self._running:
            try:
                self._engine.stop()
            except Exception:
                pass
        self._running = False
        self._demo_timer.start(800)
        self._dashboard_tab.set_running(False)
        self._header_status.setText("● 未运行")
        self._header_status.setStyleSheet(
            f"color: {THEME['accent_red']}; font-size: 13px; border: none;"
        )
        self._status_left.setText("防火墙已停止")

    def _refresh_ui(self):
        if self._engine and self._running:
            stats = self._engine.get_stats()
            self._dashboard_tab.update_stats(stats)

    def _refresh_connections(self):
        if self._engine and self._running:
            flows = self._engine.get_active_connections()
            self._conn_tab.load_connections(flows)

    def _refresh_rules(self):
        if self._rule_mgr:
            rules = [r.to_dict() for r in self._rule_mgr.get_all_rules()]
            self._rules_tab.load_rules(rules)

    def _gen_demo_data(self):
        """生成演示流量数据（无真实引擎时）"""
        import random
        ips      = ["192.168.1.100", "10.0.0.5", "172.16.0.1", "8.8.8.8",
                    "1.1.1.1", "185.220.101.42", "45.33.32.156"]
        protos   = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
        verdicts = ["ACCEPT", "ACCEPT", "ACCEPT", "DROP", "ACCEPT", "DROP"]

        verdict  = random.choice(verdicts)
        src_ip   = random.choice(ips)
        proto    = random.choice(protos)
        dst_port = random.choice([80, 443, 53, 22, 8080, 3389, 445])

        is_blocked = verdict == "DROP"
        color = THEME["accent_red"] if is_blocked else THEME["accent_green"]

        now_str = datetime.now().strftime("%H:%M:%S")
        event_text = (
            f"[{now_str}] {src_ip} → :{dst_port} [{proto}] {verdict}"
        )
        self._dashboard_tab.add_event_item(event_text, color)

        # 模拟统计
        fake_stats = {
            "total_packets":    random.randint(50000, 500000),
            "dropped_packets":  random.randint(1000, 50000),
            "accepted_packets": random.randint(40000, 450000),
            "pps_avg":          random.uniform(100, 5000),
            "bps_avg":          random.uniform(100000, 50000000),
            "conn_stats":       {"total": random.randint(50, 2000)},
        }
        self._dashboard_tab.update_stats(fake_stats)

        evt_data = {
            "timestamp":  time.time(),
            "src_ip":     src_ip,
            "dst_ip":     random.choice(ips),
            "protocol":   proto,
            "dst_port":   dst_port,
            "verdict":    verdict,
            "event_type": "BLOCK" if is_blocked else "ALLOW",
            "rule_id":    f"rule-{random.randint(1, 10):05d}" if is_blocked else "",
            "reason":     "防火墙规则" if is_blocked else "",
        }
        self._log_tab.add_event(evt_data)

        # 随机告警
        if random.random() < 0.04:
            alert_types = [
                "检测到 SYN Flood 攻击",
                "端口扫描行为",
                "DNS 隧道嫌疑",
                "ARP 欺骗尝试",
                "暴力破解 SSH",
            ]
            self._dashboard_tab.add_alert_item(
                f"⚠ {random.choice(alert_types)}: {src_ip}"
            )

    def _update_clock(self):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._status_right.setText(now_str)

    def _on_rule_added(self, form_data: Dict):
        if self._rule_mgr:
            rule = self._rule_mgr.build_rule_from_form(form_data)
            self._rule_mgr.add_rule(rule)
            self._rule_mgr.save_rules()
            self._refresh_rules()
            self._status_left.setText(f"规则已添加: {rule.name}")

    def _on_rule_removed(self, rule_id: str):
        if self._rule_mgr:
            self._rule_mgr.remove_rule(rule_id)
            self._rule_mgr.save_rules()

    def _on_rule_toggled(self, rule_id: str, enabled: bool):
        if self._rule_mgr:
            self._rule_mgr.enable_rule(rule_id, enabled)

    def _on_ip_blocked(self, ip: str):
        if self._rule_mgr:
            self._rule_mgr.blacklist.block_ip(ip, "手动封锁")

    def _on_ip_unblocked(self, ip: str):
        if self._rule_mgr:
            self._rule_mgr.blacklist.unblock_ip(ip)

    def _on_packet_blocked(self, pkt, reason: str):
        """引擎回调：数据包被拦截"""
        evt_text = (
            f"[{datetime.now().strftime('%H:%M:%S')}] 拦截 "
            f"{pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port} "
            f"[{pkt.protocol.name}] {reason}"
        )
        # 通过信号安全更新UI（跨线程）
        QTimer.singleShot(0, lambda: self._dashboard_tab.add_event_item(
            evt_text, THEME["accent_red"]
        ))
        # 写入日志页
        evt_data = {
            "timestamp":  time.time(),
            "src_ip":     pkt.src_ip,
            "dst_ip":     pkt.dst_ip,
            "protocol":   pkt.protocol.name,
            "dst_port":   pkt.dst_port,
            "verdict":    "DROP",
            "event_type": "BLOCK",
            "rule_id":    pkt.rule_hit or "",
            "reason":     reason,
        }
        QTimer.singleShot(0, lambda: self._log_tab.add_event(evt_data))

    def _on_packet_seen(self, pkt):
        """引擎回调：每个被处理的数据包（用于实时事件流）"""
        if pkt.verdict.name in ("DROP", "REJECT"):
            return  # 拦截包已在 _on_packet_blocked 处理
        evt_data = {
            "timestamp":  time.time(),
            "src_ip":     pkt.src_ip,
            "dst_ip":     pkt.dst_ip,
            "protocol":   pkt.protocol.name,
            "dst_port":   pkt.dst_port,
            "verdict":    pkt.verdict.name,
            "event_type": "ALLOW",
            "rule_id":    pkt.rule_hit or "",
            "reason":     "",
        }
        # 限制 ALLOW 日志刷新频率，避免 UI 卡死
        if random.random() < 0.05:
            QTimer.singleShot(0, lambda: self._log_tab.add_event(evt_data))

    def _on_alert(self, title: str, info: Dict):
        QTimer.singleShot(0, lambda: self._dashboard_tab.add_alert_item(
            f"⚠ {title}"
        ))

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.raise_()

    def _export_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "导出安全报告", "firewall_report.html", "HTML 文件 (*.html)"
        )
        if path and self._fw_logger:
            self._fw_logger.export_report(path)
            QMessageBox.information(self, "导出成功", f"报告已导出:\n{path}")

    def _quit_app(self):
        if self._running:
            self._stop_firewall()
        if self._rule_mgr:
            self._rule_mgr.save_rules()
        QApplication.quit()

    def closeEvent(self, event):
        """关闭时最小化到托盘"""
        if self._tray.isSystemTrayAvailable():
            self.hide()
            event.ignore()
        else:
            self._quit_app()
            event.accept()


def main():
    if not HAS_QT:
        print("错误：未安装 PyQt5，请运行: pip install PyQt5")
        print("完整依赖: pip install -r requirements.txt")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("krnwaller")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("krnwaller Project")

    # 高DPI支持
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    # 全局字体
    font = QFont("Microsoft YaHei UI", 9)
    font.setHintingPreference(QFont.PreferFullHinting)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
