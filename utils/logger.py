"""
日志与统计模块
提供结构化日志记录、事件告警、流量统计和报告
"""

import logging
import logging.handlers
import time
import json
import os
import threading
import sqlite3
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
from collections import deque, defaultdict
from enum import Enum


logger = logging.getLogger("krnwaller.logger")


class AlertLevel(Enum):
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"


@dataclass
class FirewallEvent:
    """防火墙事件记录"""
    event_id:    str   = ""
    timestamp:   float = 0.0
    event_type:  str   = ""      # BLOCK / ALLOW / ALERT / ATTACK
    src_ip:      str   = ""
    dst_ip:      str   = ""
    src_port:    int   = 0
    dst_port:    int   = 0
    protocol:    str   = ""
    verdict:     str   = ""
    rule_id:     str   = ""
    rule_name:   str   = ""
    reason:      str   = ""
    size:        int   = 0
    direction:   str   = ""
    iface:       str   = ""
    tags:        List[str] = field(default_factory=list)
    extra:       Dict  = field(default_factory=dict)

    @property
    def time_str(self) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["time_str"] = self.time_str
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class AlertRecord:
    """告警记录"""
    alert_id:   str   = ""
    timestamp:  float = 0.0
    level:      AlertLevel = AlertLevel.WARNING
    title:      str   = ""
    message:    str   = ""
    src_ip:     str   = ""
    dst_ip:     str   = ""
    protocol:   str   = ""
    count:      int   = 1
    first_seen: float = 0.0
    last_seen:  float = 0.0
    resolved:   bool  = False

    @property
    def time_str(self) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")


class EventDatabase:
    """
    基于 SQLite 的事件存储
    支持高效查询和自动清理
    """

    def __init__(self, db_path: str = "logs/events.db"):
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn_local = threading.local()
        self._init_db()
        logger.info(f"事件数据库初始化: {db_path}")

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._conn_local, "conn") or self._conn_local.conn is None:
            self._conn_local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn_local.conn.row_factory = sqlite3.Row
        return self._conn_local.conn

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id   TEXT,
                timestamp  REAL,
                event_type TEXT,
                src_ip     TEXT,
                dst_ip     TEXT,
                src_port   INTEGER,
                dst_port   INTEGER,
                protocol   TEXT,
                verdict    TEXT,
                rule_id    TEXT,
                reason     TEXT,
                size       INTEGER,
                direction  TEXT,
                extra_json TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id   TEXT UNIQUE,
                timestamp  REAL,
                level      TEXT,
                title      TEXT,
                message    TEXT,
                src_ip     TEXT,
                count      INTEGER DEFAULT 1,
                resolved   INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def insert_event(self, event: FirewallEvent):
        try:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO events
                (event_id, timestamp, event_type, src_ip, dst_ip,
                 src_port, dst_port, protocol, verdict, rule_id,
                 reason, size, direction, extra_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event.event_id, event.timestamp, event.event_type,
                event.src_ip, event.dst_ip, event.src_port, event.dst_port,
                event.protocol, event.verdict, event.rule_id,
                event.reason, event.size, event.direction,
                json.dumps(event.extra)
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"插入事件失败: {e}")

    def insert_alert(self, alert: AlertRecord):
        try:
            conn = self._get_conn()
            conn.execute("""
                INSERT OR REPLACE INTO alerts
                (alert_id, timestamp, level, title, message, src_ip, count, resolved)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                alert.alert_id, alert.timestamp, alert.level.value,
                alert.title, alert.message, alert.src_ip,
                alert.count, int(alert.resolved)
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"插入告警失败: {e}")

    def query_events(self, limit: int = 200, offset: int = 0,
                     event_type: str = None, src_ip: str = None,
                     since: float = None) -> List[Dict]:
        try:
            conn = self._get_conn()
            sql = "SELECT * FROM events WHERE 1=1"
            params = []
            if event_type:
                sql += " AND event_type=?"
                params.append(event_type)
            if src_ip:
                sql += " AND src_ip=?"
                params.append(src_ip)
            if since:
                sql += " AND timestamp>=?"
                params.append(since)
            sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"查询事件失败: {e}")
            return []

    def query_alerts(self, resolved: bool = False) -> List[Dict]:
        try:
            conn = self._get_conn()
            rows = conn.execute(
                "SELECT * FROM alerts WHERE resolved=? ORDER BY timestamp DESC",
                (int(resolved),)
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"查询告警失败: {e}")
            return []

    def cleanup_old_events(self, keep_days: int = 30):
        try:
            cutoff = time.time() - keep_days * 86400
            conn = self._get_conn()
            cursor = conn.execute("DELETE FROM events WHERE timestamp<?", (cutoff,))
            conn.commit()
            if cursor.rowcount:
                logger.info(f"清理旧事件 {cursor.rowcount} 条（{keep_days}天前）")
        except Exception as e:
            logger.error(f"清理事件失败: {e}")

    def get_top_blocked_ips(self, limit: int = 10, hours: int = 24) -> List[Dict]:
        """获取封锁次数最多的 IP"""
        try:
            since = time.time() - hours * 3600
            conn = self._get_conn()
            rows = conn.execute("""
                SELECT src_ip, COUNT(*) as count
                FROM events
                WHERE event_type='BLOCK' AND timestamp>=?
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
            """, (since, limit)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"查询封锁IP失败: {e}")
            return []

    def get_traffic_by_hour(self, hours: int = 24) -> List[Dict]:
        """按小时统计流量"""
        try:
            since = time.time() - hours * 3600
            conn = self._get_conn()
            rows = conn.execute("""
                SELECT CAST(timestamp/3600 AS INTEGER)*3600 as hour_ts,
                       COUNT(*) as packets, SUM(size) as bytes
                FROM events
                WHERE timestamp>=?
                GROUP BY hour_ts
                ORDER BY hour_ts
            """, (since,)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            return []


class TrafficStatistics:
    """
    实时流量统计
    使用环形缓冲区存储历史数据
    """

    def __init__(self, history_size: int = 300):
        self._history_size = history_size
        # 每秒统计
        self._pps_history:     deque = deque(maxlen=history_size)
        self._bps_history:     deque = deque(maxlen=history_size)
        self._drop_history:    deque = deque(maxlen=history_size)
        self._timestamps:      deque = deque(maxlen=history_size)

        # 协议分布
        self._proto_counters:  Dict[str, int] = defaultdict(int)
        self._port_counters:   Dict[int, int]  = defaultdict(int)
        self._ip_counters:     Dict[str, int]  = defaultdict(int)

        # 总计数器
        self._total_packets    = 0
        self._total_bytes      = 0
        self._total_dropped    = 0
        self._total_accepted   = 0
        self._session_start    = time.time()

        self._lock = threading.Lock()

    def record_packet(self, protocol: str, size: int, src_ip: str,
                      dst_port: int, dropped: bool = False):
        with self._lock:
            self._total_packets += 1
            self._total_bytes   += size
            self._proto_counters[protocol] += 1
            self._port_counters[dst_port]  += 1
            self._ip_counters[src_ip]      += 1
            if dropped:
                self._total_dropped += 1
            else:
                self._total_accepted += 1

    def snapshot(self, pps: float, bps: float, drop_rate: float):
        """记录当前秒的速率快照"""
        with self._lock:
            self._pps_history.append(pps)
            self._bps_history.append(bps)
            self._drop_history.append(drop_rate)
            self._timestamps.append(time.time())

    def get_pps_history(self) -> List[float]:
        with self._lock:
            return list(self._pps_history)

    def get_bps_history(self) -> List[float]:
        with self._lock:
            return list(self._bps_history)

    def get_proto_distribution(self) -> Dict[str, int]:
        with self._lock:
            return dict(sorted(
                self._proto_counters.items(),
                key=lambda x: x[1], reverse=True
            )[:10])

    def get_top_src_ips(self, n: int = 10) -> List[tuple]:
        with self._lock:
            return sorted(self._ip_counters.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_ports(self, n: int = 10) -> List[tuple]:
        with self._lock:
            return sorted(self._port_counters.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_summary(self) -> Dict:
        with self._lock:
            uptime = time.time() - self._session_start
            return {
                "total_packets":   self._total_packets,
                "total_bytes":     self._total_bytes,
                "total_dropped":   self._total_dropped,
                "total_accepted":  self._total_accepted,
                "drop_rate":       self._total_dropped / max(1, self._total_packets) * 100,
                "uptime_seconds":  uptime,
                "avg_pps":         self._total_packets / max(1, uptime),
            }


class AlertManager:
    """
    告警管理器
    支持告警聚合、去重和通知
    """

    def __init__(self, db: EventDatabase):
        self._db       = db
        self._active:  Dict[str, AlertRecord] = {}
        self._lock     = threading.Lock()
        self._callbacks: List[Callable[[AlertRecord], None]] = []
        self._alert_seq = 0

    def add_callback(self, cb: Callable[[AlertRecord], None]):
        self._callbacks.append(cb)

    def raise_alert(self, title: str, message: str, level: AlertLevel = AlertLevel.WARNING,
                    src_ip: str = "", key: str = None) -> AlertRecord:
        """
        触发告警，相同 key 的告警会聚合
        """
        agg_key = key or f"{title}:{src_ip}"
        now = time.time()

        with self._lock:
            if agg_key in self._active:
                alert = self._active[agg_key]
                alert.count     += 1
                alert.last_seen  = now
                alert.message    = message
            else:
                self._alert_seq += 1
                alert = AlertRecord(
                    alert_id   = f"alert-{self._alert_seq:06d}",
                    timestamp  = now,
                    level      = level,
                    title      = title,
                    message    = message,
                    src_ip     = src_ip,
                    first_seen = now,
                    last_seen  = now,
                )
                self._active[agg_key] = alert

        self._db.insert_alert(alert)
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

        return alert

    def resolve_alert(self, alert_id: str):
        with self._lock:
            for key, alert in list(self._active.items()):
                if alert.alert_id == alert_id:
                    alert.resolved = True
                    del self._active[key]
                    break

    def get_active_alerts(self) -> List[AlertRecord]:
        with self._lock:
            return list(self._active.values())

    def get_alert_count(self) -> Dict[str, int]:
        with self._lock:
            counts = defaultdict(int)
            for a in self._active.values():
                counts[a.level.value] += 1
            return dict(counts)


class FirewallLogger:
    """
    防火墙主日志器
    协调文件日志、数据库存储和实时推送
    """

    def __init__(self, log_dir: str = "logs", db_path: str = "logs/events.db"):
        self._log_dir  = Path(log_dir)
        self._log_dir.mkdir(exist_ok=True)

        # SQLite 存储
        self._db       = EventDatabase(db_path)
        self._stats    = TrafficStatistics()
        self._alerts   = AlertManager(self._db)

        # 内存缓冲（用于UI实时显示）
        self._recent_events: deque = deque(maxlen=1000)
        self._event_lock    = threading.Lock()
        self._event_seq     = 0

        # 回调
        self._event_callbacks: List[Callable[[FirewallEvent], None]] = []

        # 批量写入队列，避免每事件创建线程
        self._write_queue: deque = deque(maxlen=10000)
        self._write_lock  = threading.Lock()
        self._write_event = threading.Event()
        self._writer_thread = threading.Thread(
            target=self._writer_loop, daemon=True, name="fw-writer"
        )
        self._writer_thread.start()

        # 文件日志轮转
        self._setup_file_logging()

        # 定期清理任务
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()

        logger.info("防火墙日志系统已启动")

    def _setup_file_logging(self):
        fw_logger = logging.getLogger("krnwaller")
        fw_logger.setLevel(logging.DEBUG)

        log_file = self._log_dir / "firewall.log"
        handler  = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=50*1024*1024, backupCount=10, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        fw_logger.addHandler(handler)

        # JSON 事件日志
        event_log = self._log_dir / "events.jsonl"
        self._event_file = open(event_log, "a", encoding="utf-8", buffering=1)

    def add_event_callback(self, cb: Callable[[FirewallEvent], None]):
        self._event_callbacks.append(cb)

    def log_packet(self, pkt_info: Dict, event_type: str = "ALLOW"):
        """记录数据包事件"""
        with self._event_lock:
            self._event_seq += 1
            seq = self._event_seq

        event = FirewallEvent(
            event_id   = f"evt-{seq:08d}",
            timestamp  = pkt_info.get("timestamp", time.time()),
            event_type = event_type,
            src_ip     = pkt_info.get("src_ip", ""),
            dst_ip     = pkt_info.get("dst_ip", ""),
            src_port   = pkt_info.get("src_port", 0),
            dst_port   = pkt_info.get("dst_port", 0),
            protocol   = pkt_info.get("protocol", ""),
            verdict    = pkt_info.get("verdict", ""),
            rule_id    = pkt_info.get("rule_id", ""),
            reason     = pkt_info.get("reason", ""),
            size       = pkt_info.get("size", 0),
            direction  = pkt_info.get("direction", ""),
        )

        # 更新统计
        self._stats.record_packet(
            protocol = event.protocol,
            size     = event.size,
            src_ip   = event.src_ip,
            dst_port = event.dst_port,
            dropped  = event_type in ("BLOCK", "DROP"),
        )

        # 内存缓冲
        with self._event_lock:
            self._recent_events.append(event)

        # 异步写入数据库和文件
        self._async_write(event)

        # 触发回调
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception:
                pass

        return event

    def _async_write(self, event: FirewallEvent):
        """入队等批量写入，不再每事件创建线程"""
        with self._write_lock:
            self._write_queue.append(event)
        self._write_event.set()

    def _writer_loop(self):
        """后台单线程批量写入数据库和文件"""
        batch = []
        while True:
            self._write_event.wait(timeout=0.5)
            self._write_event.clear()
            with self._write_lock:
                while self._write_queue:
                    batch.append(self._write_queue.popleft())
            if not batch:
                continue
            try:
                for event in batch:
                    self._db.insert_event(event)
                    self._event_file.write(event.to_json() + "\n")
            except Exception as e:
                logger.error(f"批量写入失败: {e}")
            batch.clear()

    def get_recent_events(self, n: int = 100) -> List[FirewallEvent]:
        with self._event_lock:
            events = list(self._recent_events)
        return events[-n:]

    def get_stats(self) -> Dict:
        return self._stats.get_summary()

    def get_traffic_charts(self) -> Dict:
        return {
            "pps":          self._stats.get_pps_history(),
            "bps":          self._stats.get_bps_history(),
            "proto_dist":   self._stats.get_proto_distribution(),
            "top_src_ips":  self._stats.get_top_src_ips(),
            "top_ports":    self._stats.get_top_ports(),
        }

    @property
    def alert_manager(self) -> AlertManager:
        return self._alerts

    @property
    def event_db(self) -> EventDatabase:
        return self._db

    @property
    def traffic_stats(self) -> TrafficStatistics:
        return self._stats

    def _cleanup_loop(self):
        while True:
            time.sleep(3600)  # 每小时清理一次
            try:
                self._db.cleanup_old_events(keep_days=30)
            except Exception:
                pass

    def export_report(self, output_path: str, hours: int = 24):
        """导出 HTML 流量报告"""
        try:
            summary = self._stats.get_summary()
            top_ips = self._db.get_top_blocked_ips(hours=hours)
            events  = self._db.query_events(limit=50, since=time.time()-hours*3600)
            proto   = self._stats.get_proto_distribution()

            html = self._build_report_html(summary, top_ips, events, proto, hours)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)
            logger.info(f"报告已导出: {output_path}")
        except Exception as e:
            logger.error(f"导出报告失败: {e}")

    def _build_report_html(self, summary, top_ips, events, proto, hours) -> str:
        import datetime
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = ""
        for e in events[:20]:
            import datetime as dt
            ts = dt.datetime.fromtimestamp(e.get("timestamp", 0)).strftime("%H:%M:%S")
            rows += f"""<tr>
                <td>{ts}</td>
                <td>{e.get('src_ip','')}</td>
                <td>{e.get('dst_ip','')}</td>
                <td>{e.get('dst_port','')}</td>
                <td>{e.get('protocol','')}</td>
                <td class="{'text-danger' if e.get('event_type')=='BLOCK' else 'text-success'}">{e.get('event_type','')}</td>
            </tr>"""
        ip_rows = "".join(
            f"<tr><td>{r.get('src_ip','')}</td><td>{r.get('count',0)}</td></tr>"
            for r in top_ips
        )
        proto_rows = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>"
            for k, v in proto.items()
        )
        return f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>krnwaller 安全报告</title>
<style>
  body{{font-family:微软雅黑,Arial,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:8px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:20px}}
  th{{background:#161b22;color:#8b949e;padding:8px;text-align:left}}
  td{{padding:8px;border-bottom:1px solid #21262d}}
  .text-danger{{color:#f85149}} .text-success{{color:#56d364}}
  .stat-box{{display:inline-block;background:#161b22;border:1px solid #30363d;
             border-radius:8px;padding:15px 25px;margin:10px;min-width:150px;text-align:center}}
  .stat-num{{font-size:28px;font-weight:bold;color:#58a6ff}}
  .stat-label{{font-size:12px;color:#8b949e}}
</style>
</head>
<body>
<h1>krnwaller 安全报告</h1>
<p>生成时间：{now_str} &nbsp; | &nbsp; 统计周期：最近 {hours} 小时</p>
<h2>总体统计</h2>
<div>
  <div class="stat-box"><div class="stat-num">{summary.get('total_packets',0):,}</div><div class="stat-label">总数据包</div></div>
  <div class="stat-box"><div class="stat-num">{summary.get('total_dropped',0):,}</div><div class="stat-label">已拦截</div></div>
  <div class="stat-box"><div class="stat-num">{summary.get('drop_rate',0):.1f}%</div><div class="stat-label">拦截率</div></div>
  <div class="stat-box"><div class="stat-num">{summary.get('avg_pps',0):.0f}</div><div class="stat-label">平均PPS</div></div>
</div>
<h2>最近事件</h2>
<table><tr><th>时间</th><th>来源IP</th><th>目标IP</th><th>端口</th><th>协议</th><th>动作</th></tr>{rows}</table>
<h2>封锁 Top IP</h2>
<table><tr><th>IP地址</th><th>封锁次数</th></tr>{ip_rows}</table>
<h2>协议分布</h2>
<table><tr><th>协议</th><th>数据包数</th></tr>{proto_rows}</table>
</body></html>"""
