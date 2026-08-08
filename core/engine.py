"""
krnwaller - 核心防火墙引擎
负责数据包捕获、分发和高性能处理
"""

import threading
import queue
import time
import logging
import socket
import struct
import ctypes
import os
import sys
import ipaddress
from typing import Optional, Callable, List, Dict, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque, defaultdict, OrderedDict
import hashlib
import json

logger = logging.getLogger("krnwaller.engine")

# 尝试导入可选模块
try:
    from utils.logger import FirewallLogger
    HAS_FW_LOGGER = True
except Exception:
    HAS_FW_LOGGER = False
    FirewallLogger = None

try:
    from core.capture import CaptureManager, CaptureBackend, CapturedPacket
    HAS_CAPTURE = True
except Exception:
    HAS_CAPTURE = False
    CaptureManager = None
    CaptureBackend = None
    CapturedPacket = None


class PacketVerdict(Enum):
    """数据包处置结果"""
    ACCEPT   = auto()   # 放行
    DROP     = auto()   # 丢弃（静默）
    REJECT   = auto()   # 拒绝（发送RST/ICMP）
    LOG_ONLY = auto()   # 仅记录不拦截
    QUEUE    = auto()   # 排队等待用户处理


class Protocol(Enum):
    """协议类型"""
    UNKNOWN = 0
    ICMP    = 1
    TCP     = 6
    UDP     = 17
    IPV6    = 41
    GRE     = 47
    ESP     = 50
    AH      = 51
    ICMPv6  = 58
    SCTP    = 132
    HTTP    = 1000
    HTTPS   = 1001
    DNS     = 1002
    FTP     = 1003
    SSH     = 1004
    SMTP    = 1005
    POP3    = 1006
    IMAP    = 1007
    DHCP    = 1008
    ARP     = 1009
    SNMP    = 1010


@dataclass
class PacketInfo:
    """
    数据包元信息，贯穿整个处理管线
    """
    raw_data:      bytes       = b""
    timestamp:     float       = 0.0
    src_ip:        str         = ""
    dst_ip:        str         = ""
    src_port:      int         = 0
    dst_port:      int         = 0
    protocol:      Protocol    = Protocol.UNKNOWN
    ip_version:    int         = 4
    ttl:           int         = 64
    flags:         int         = 0
    seq_num:       int         = 0
    ack_num:       int         = 0
    payload:       bytes       = b""
    payload_size:  int         = 0
    total_size:    int         = 0
    iface:         str         = ""
    direction:     str         = "IN"     # IN / OUT / FORWARD
    verdict:       PacketVerdict = PacketVerdict.ACCEPT
    rule_hit:      str         = ""
    tags:          List[str]   = field(default_factory=list)
    metadata:      Dict        = field(default_factory=dict)

    @property
    def five_tuple(self) -> Tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol.value)

    @property
    def flow_key(self) -> str:
        """双向流标识符，用字符串拼接避免 md5 开销"""
        a = f"{self.src_ip}:{self.src_port}"
        b = f"{self.dst_ip}:{self.dst_port}"
        lo, hi = (a, b) if a <= b else (b, a)
        return f"{lo}-{hi}-{self.protocol.value}"

    def is_tcp_syn(self) -> bool:
        return self.protocol == Protocol.TCP and (self.flags & 0x02) != 0

    def is_tcp_fin(self) -> bool:
        return self.protocol == Protocol.TCP and (self.flags & 0x01) != 0

    def is_tcp_rst(self) -> bool:
        return self.protocol == Protocol.TCP and (self.flags & 0x04) != 0


@dataclass
class FlowRecord:
    """连接流记录，用于状态防火墙跟踪"""
    flow_key:      str
    src_ip:        str
    dst_ip:        str
    src_port:      int
    dst_port:      int
    protocol:      Protocol
    state:         str         = "NEW"
    created_at:    float       = 0.0
    last_seen:     float       = 0.0
    bytes_in:      int         = 0
    bytes_out:     int         = 0
    packets_in:    int         = 0
    packets_out:   int         = 0
    is_established: bool       = False
    tags:          List[str]   = field(default_factory=list)

    def update(self, pkt: PacketInfo, direction: str):
        self.last_seen = time.time()
        if direction == "IN":
            self.bytes_in    += pkt.total_size
            self.packets_in  += 1
        else:
            self.bytes_out   += pkt.total_size
            self.packets_out += 1

    @property
    def duration(self) -> float:
        return self.last_seen - self.created_at

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out


class PacketParser:
    """
    多协议数据包解析器
    支持 IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP 等协议
    """

    # 常见端口到应用层协议映射
    PORT_PROTO_MAP: Dict[int, Protocol] = {
        21:   Protocol.FTP,
        22:   Protocol.SSH,
        25:   Protocol.SMTP,
        53:   Protocol.DNS,
        67:   Protocol.DHCP,
        68:   Protocol.DHCP,
        80:   Protocol.HTTP,
        110:  Protocol.POP3,
        143:  Protocol.IMAP,
        161:  Protocol.SNMP,
        162:  Protocol.SNMP,
        443:  Protocol.HTTPS,
        465:  Protocol.SMTP,
        587:  Protocol.SMTP,
        993:  Protocol.IMAP,
        995:  Protocol.POP3,
    }

    @classmethod
    def parse(cls, raw: bytes, iface: str = "", direction: str = "IN") -> Optional[PacketInfo]:
        if len(raw) < 20:
            return None
        try:
            pkt = PacketInfo()
            pkt.raw_data   = raw
            pkt.timestamp  = time.time()
            pkt.iface      = iface
            pkt.direction  = direction
            pkt.total_size = len(raw)

            version = (raw[0] >> 4) & 0xF
            pkt.ip_version = version

            if version == 4:
                cls._parse_ipv4(pkt, raw)
            elif version == 6:
                cls._parse_ipv6(pkt, raw)
            else:
                pkt.protocol = Protocol.UNKNOWN
                return pkt

            # 尝试识别应用层协议
            cls._detect_app_protocol(pkt)
            return pkt
        except Exception as e:
            logger.debug(f"包解析异常: {e}")
            return None

    @classmethod
    def _parse_ipv4(cls, pkt: PacketInfo, raw: bytes):
        ihl = (raw[0] & 0x0F) * 4
        pkt.ttl         = raw[8]
        proto_num       = raw[9]
        pkt.src_ip      = socket.inet_ntoa(raw[12:16])
        pkt.dst_ip      = socket.inet_ntoa(raw[16:20])

        try:
            pkt.protocol = Protocol(proto_num)
        except ValueError:
            pkt.protocol = Protocol.UNKNOWN

        transport = raw[ihl:]
        if pkt.protocol == Protocol.TCP and len(transport) >= 20:
            cls._parse_tcp(pkt, transport)
        elif pkt.protocol == Protocol.UDP and len(transport) >= 8:
            cls._parse_udp(pkt, transport)
        elif pkt.protocol == Protocol.ICMP and len(transport) >= 4:
            cls._parse_icmp(pkt, transport)

    @classmethod
    def _parse_ipv6(cls, pkt: PacketInfo, raw: bytes):
        if len(raw) < 40:
            return
        pkt.ttl    = raw[7]   # Hop Limit
        next_hdr   = raw[6]
        pkt.src_ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        pkt.dst_ip = socket.inet_ntop(socket.AF_INET6, raw[24:40])

        try:
            pkt.protocol = Protocol(next_hdr)
        except ValueError:
            pkt.protocol = Protocol.UNKNOWN

        transport = raw[40:]
        if pkt.protocol == Protocol.TCP and len(transport) >= 20:
            cls._parse_tcp(pkt, transport)
        elif pkt.protocol == Protocol.UDP and len(transport) >= 8:
            cls._parse_udp(pkt, transport)
        elif pkt.protocol == Protocol.ICMPv6 and len(transport) >= 4:
            cls._parse_icmp(pkt, transport)

    @classmethod
    def _parse_tcp(cls, pkt: PacketInfo, data: bytes):
        pkt.src_port = struct.unpack("!H", data[0:2])[0]
        pkt.dst_port = struct.unpack("!H", data[2:4])[0]
        pkt.seq_num  = struct.unpack("!I", data[4:8])[0]
        pkt.ack_num  = struct.unpack("!I", data[8:12])[0]
        data_off     = ((data[12] >> 4) & 0xF) * 4
        pkt.flags    = data[13]
        pkt.payload  = data[data_off:]
        pkt.payload_size = len(pkt.payload)

    @classmethod
    def _parse_udp(cls, pkt: PacketInfo, data: bytes):
        pkt.src_port     = struct.unpack("!H", data[0:2])[0]
        pkt.dst_port     = struct.unpack("!H", data[2:4])[0]
        pkt.payload      = data[8:]
        pkt.payload_size = len(pkt.payload)

    @classmethod
    def _parse_icmp(cls, pkt: PacketInfo, data: bytes):
        pkt.payload      = data[4:]
        pkt.payload_size = len(pkt.payload)

    @classmethod
    def _detect_app_protocol(cls, pkt: PacketInfo):
        """根据端口和载荷特征识别应用层协议，记录到 metadata 不覆盖传输层协议"""
        port = pkt.dst_port or pkt.src_port
        if port in cls.PORT_PROTO_MAP:
            pkt.metadata["app_protocol"] = cls.PORT_PROTO_MAP[port].name
        elif pkt.payload and len(pkt.payload) >= 4:
            if pkt.payload[:4] in (b"GET ", b"POST", b"HTTP", b"HEAD", b"PUT ", b"DELE"):
                pkt.metadata["app_protocol"] = "HTTP"
            elif pkt.payload[:2] == b"\x16\x03":  # TLS handshake
                pkt.metadata["app_protocol"] = "HTTPS"


class ConnectionTracker:
    """
    有状态连接追踪器
    实现 TCP/UDP/ICMP 连接状态机
    """

    # 超时配置（秒）
    TCP_ESTABLISHED_TIMEOUT = 3600
    TCP_SYN_TIMEOUT         = 60
    TCP_FIN_TIMEOUT         = 120
    TCP_RST_TIMEOUT         = 10
    UDP_TIMEOUT             = 30
    ICMP_TIMEOUT            = 10
    DEFAULT_TIMEOUT         = 60

    def __init__(self, max_connections: int = 65536):
        self._flows:      OrderedDict[str, FlowRecord] = OrderedDict()
        self._lock        = threading.RLock()
        self._max_conns   = max_connections
        self._cleanup_interval = 30
        self._last_cleanup = time.time()
        self._evicted_count = 0
        logger.info(f"连接跟踪器初始化，最大连接数={max_connections}")

    def track(self, pkt: PacketInfo) -> FlowRecord:
        """跟踪数据包所属连接，返回流记录"""
        now = time.time()
        key = pkt.flow_key
        with self._lock:
            # 周期性清理过期连接（在锁内检查避免竞态）
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup_expired_locked()
            if key in self._flows:
                flow = self._flows.pop(key)
                self._flows[key] = flow  # 移到末尾，LRU
                self._update_flow_state(flow, pkt)
                flow.update(pkt, pkt.direction)
            else:
                # 连接数超限时，先淘汰最老的连接
                if len(self._flows) >= self._max_conns:
                    self._evict_oldest()

                flow = FlowRecord(
                    flow_key   = key,
                    src_ip     = pkt.src_ip,
                    dst_ip     = pkt.dst_ip,
                    src_port   = pkt.src_port,
                    dst_port   = pkt.dst_port,
                    protocol   = pkt.protocol,
                    created_at = now,
                    last_seen  = now,
                )
                self._init_flow_state(flow, pkt)
                self._flows[key] = flow
                flow.update(pkt, pkt.direction)

            return flow

    def _init_flow_state(self, flow: FlowRecord, pkt: PacketInfo):
        if pkt.protocol == Protocol.TCP:
            if pkt.is_tcp_syn():
                flow.state = "SYN_SENT"
            else:
                flow.state = "ESTABLISHED"
                flow.is_established = True
        elif pkt.protocol == Protocol.UDP:
            flow.state = "UDP_OPEN"
        elif pkt.protocol in (Protocol.ICMP, Protocol.ICMPv6):
            flow.state = "ICMP_OPEN"
        else:
            flow.state = "OPEN"

    def _update_flow_state(self, flow: FlowRecord, pkt: PacketInfo):
        if pkt.protocol != Protocol.TCP:
            return
        if pkt.is_tcp_rst():
            flow.state = "RESET"
        elif pkt.is_tcp_fin():
            flow.state = "FIN_WAIT" if flow.state == "ESTABLISHED" else "CLOSE_WAIT"
        elif pkt.is_tcp_syn() and (pkt.flags & 0x10):   # SYN+ACK
            flow.state = "SYN_RECV"
        elif (pkt.flags & 0x10) and flow.state == "SYN_RECV":
            flow.state = "ESTABLISHED"
            flow.is_established = True

    def _cleanup_expired_locked(self):
        """在已持锁状态下清理过期连接（调用者必须持有 _lock）"""
        now = time.time()
        to_remove = []
        for key, flow in self._flows.items():
            timeout = self._get_timeout(flow)
            if now - flow.last_seen > timeout:
                to_remove.append(key)
        for key in to_remove:
            del self._flows[key]
        self._last_cleanup = now
        if to_remove:
            logger.debug(f"清理过期连接 {len(to_remove)} 条")

    def _get_timeout(self, flow: FlowRecord) -> float:
        if flow.protocol == Protocol.TCP:
            if flow.state == "ESTABLISHED":
                return self.TCP_ESTABLISHED_TIMEOUT
            elif flow.state in ("RESET", "CLOSE_WAIT", "FIN_WAIT"):
                return self.TCP_FIN_TIMEOUT
            else:
                return self.TCP_SYN_TIMEOUT
        elif flow.protocol == Protocol.UDP:
            return self.UDP_TIMEOUT
        elif flow.protocol in (Protocol.ICMP, Protocol.ICMPv6):
            return self.ICMP_TIMEOUT
        return self.DEFAULT_TIMEOUT

    def _evict_oldest(self):
        """LRU 淘汰，弹出 OrderedDict 第一个元素，O(1)"""
        if self._flows:
            self._flows.popitem(last=False)
            self._evicted_count += 1

    def get_active_flows(self) -> List[FlowRecord]:
        with self._lock:
            return list(self._flows.values())

    def get_stats(self) -> Dict:
        with self._lock:
            total = len(self._flows)
            by_state = defaultdict(int)
            by_proto = defaultdict(int)
            for f in self._flows.values():
                by_state[f.state] += 1
                by_proto[f.protocol.name] += 1
            return {
                "total":    total,
                "by_state": dict(by_state),
                "by_proto": dict(by_proto),
                "evicted":  self._evicted_count,
            }


class PacketQueue:
    """
    高性能数据包队列
    支持优先级和背压控制
    """

    def __init__(self, maxsize: int = 10000):
        self._queue     = queue.Queue(maxsize=maxsize)
        self._dropped   = 0
        self._enqueued  = 0
        self._dequeued  = 0
        self._lock      = threading.Lock()

    def put(self, pkt: PacketInfo, block: bool = False) -> bool:
        try:
            self._queue.put_nowait(pkt)
            with self._lock:
                self._enqueued += 1
            return True
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False

    def get(self, timeout: float = 1.0) -> Optional[PacketInfo]:
        try:
            pkt = self._queue.get(timeout=timeout)
            with self._lock:
                self._dequeued += 1
            return pkt
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> Dict:
        with self._lock:
            return {
                "enqueued":  self._enqueued,
                "dequeued":  self._dequeued,
                "dropped":   self._dropped,
                "current":   self._queue.qsize(),
            }


class RateLimiter:
    """
    令牌桶限速器，用于防止泛洪攻击
    """

    def __init__(self, rate: float, burst: float):
        """
        rate:  每秒允许的令牌数
        burst: 最大突发令牌数
        """
        self._rate      = rate
        self._burst     = burst
        self._tokens    = burst
        self._last_time = time.monotonic()
        self._lock      = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            delta = now - self._last_time
            self._last_time = now
            # 补充令牌
            self._tokens = min(self._burst, self._tokens + delta * self._rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def reset(self):
        with self._lock:
            self._tokens    = self._burst
            self._last_time = time.monotonic()


class SynFloodDetector:
    """
    SYN Flood 攻击检测器
    基于滑动窗口统计
    """

    def __init__(self, threshold: int = 100, window: float = 1.0):
        self._threshold  = threshold   # 每窗口最大 SYN 数
        self._window     = window      # 时间窗口（秒）
        self._counters:  Dict[str, deque] = defaultdict(deque)
        self._blocked:   Dict[str, float] = {}   # IP -> 解封时间
        self._block_dur  = 300.0   # 封禁时长 5 分钟
        self._lock       = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 60.0

    def check(self, pkt: PacketInfo) -> bool:
        """返回 True 表示检测到攻击（应丢弃）"""
        if not pkt.is_tcp_syn():
            return False

        now = time.time()
        src = pkt.src_ip

        with self._lock:
            # 检查是否在封禁名单
            if src in self._blocked:
                if now < self._blocked[src]:
                    return True
                else:
                    del self._blocked[src]

            # 滑动窗口计数
            q = self._counters[src]
            q.append(now)
            # 移除窗口外的记录
            while q and q[0] < now - self._window:
                q.popleft()

            if len(q) >= self._threshold:
                self._blocked[src] = now + self._block_dur
                logger.warning(f"SYN Flood 攻击检测：来源 {src}，封禁 {self._block_dur}s")
                del self._counters[src]
                return True

            # 周期清理过期计数器，防止内存泄漏
            if now - self._last_cleanup > self._cleanup_interval:
                stale = [ip for ip, dq in self._counters.items()
                         if not dq or dq[-1] < now - self._window * 3]
                for ip in stale:
                    del self._counters[ip]
                self._last_cleanup = now

        return False

    def get_blocked_ips(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._blocked)


class PortScanDetector:
    """
    端口扫描检测器
    """

    def __init__(self, port_threshold: int = 20, window: float = 10.0):
        self._port_threshold = port_threshold
        self._window         = window
        self._port_access:   Dict[str, Dict[int, deque]] = defaultdict(lambda: defaultdict(deque))
        self._blocked:       Dict[str, float] = {}
        self._lock           = threading.Lock()
        self._last_cleanup   = time.time()
        self._cleanup_interval = 60.0

    def check(self, pkt: PacketInfo) -> bool:
        if pkt.protocol not in (Protocol.TCP, Protocol.UDP):
            return False
        if pkt.direction != "IN":
            return False

        now = time.time()
        src = pkt.src_ip
        dst_port = pkt.dst_port

        with self._lock:
            if src in self._blocked:
                if now < self._blocked[src]:
                    return True
                else:
                    del self._blocked[src]

            port_map = self._port_access[src]
            q = port_map[dst_port]
            q.append(now)

            # 统计该源IP在时间窗口内访问了多少个不同端口
            active_ports = 0
            for p, pq in port_map.items():
                while pq and pq[0] < now - self._window:
                    pq.popleft()
                if pq:
                    active_ports += 1

            if active_ports >= self._port_threshold:
                self._blocked[src] = now + 600  # 封禁10分钟
                logger.warning(f"端口扫描检测：来源 {src}，访问了 {active_ports} 个端口")
                return True

            if now - self._last_cleanup > self._cleanup_interval:
                stale_ips = []
                for ip, pm in self._port_access.items():
                    if not pm or all(not pq or pq[-1] < now - self._window * 2
                                     for pq in pm.values()):
                        stale_ips.append(ip)
                for ip in stale_ips:
                    del self._port_access[ip]
                self._last_cleanup = now

        return False


class IcmpFloodDetector:
    """
    ICMP Flood / Ping of Death 检测器
    """

    def __init__(self, threshold: int = 500, window: float = 1.0):
        self._threshold = threshold
        self._window    = window
        self._counters: Dict[str, deque] = defaultdict(deque)
        self._blocked:  Dict[str, float] = {}
        self._block_dur = 300.0
        self._lock      = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 60.0

    def check(self, pkt: PacketInfo) -> bool:
        if pkt.protocol not in (Protocol.ICMP, Protocol.ICMPv6):
            return False
        if pkt.direction != "IN":
            return False

        now = time.time()
        src = pkt.src_ip

        with self._lock:
            if src in self._blocked:
                if now < self._blocked[src]:
                    return True
                else:
                    del self._blocked[src]

            q = self._counters[src]
            q.append(now)
            while q and q[0] < now - self._window:
                q.popleft()

            if len(q) >= self._threshold:
                self._blocked[src] = now + self._block_dur
                logger.warning(f"ICMP Flood 攻击检测：来源 {src}，封禁 {self._block_dur}s")
                del self._counters[src]
                return True

            if now - self._last_cleanup > self._cleanup_interval:
                stale = [ip for ip, dq in self._counters.items()
                         if not dq or dq[-1] < now - self._window * 3]
                for ip in stale:
                    del self._counters[ip]
                self._last_cleanup = now

        return False

    def get_blocked_ips(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._blocked)


class FirewallEngine:
    """
    防火墙核心引擎
    协调规则匹配、连接跟踪、攻击检测和统计
    """

    def __init__(self, config: Optional[Dict] = None):
        self._config       = config or {}
        self._running      = False
        self._workers:     List[threading.Thread] = []
        self._pkt_queue    = PacketQueue(maxsize=self._config.get("queue_size", 20000))
        self._conn_tracker = ConnectionTracker(
            max_connections=self._config.get("max_connections", 65536)
        )
        self._syn_detector  = SynFloodDetector(
            threshold=self._config.get("syn_threshold", 200),
            window=self._config.get("syn_window", 1.0),
        )
        self._scan_detector = PortScanDetector(
            port_threshold=self._config.get("scan_port_threshold", 20),
            window=self._config.get("scan_window", 10.0),
        )
        self._icmp_detector = IcmpFloodDetector(
            threshold=self._config.get("icmp_threshold", 500),
            window=self._config.get("icmp_window", 1.0),
        )

        # 规则链 - 将由 RuleManager 注入
        self._rule_chain: Optional[Any] = None

        # 日志器
        self._fw_logger: Optional[Any] = None
        if self._config.get("enable_logger", True) and HAS_FW_LOGGER:
            log_dir = self._config.get("log_dir", "logs")
            db_path = self._config.get("db_path", "logs/events.db")
            try:
                self._fw_logger = FirewallLogger(log_dir, db_path)
            except Exception as e:
                logger.warning(f"日志器初始化失败: {e}")

        # 捕获后端
        self._capture_mgr: Optional[Any] = None
        self._capture_iface: Optional[Any] = None
        self._capture_config = {
            "iface":    self._config.get("capture_iface", ""),
            "backend":  self._config.get("capture_backend", "auto"),
            "promisc":  self._config.get("capture_promisc", False),
            "bpf":      self._config.get("capture_bpf", "ip or ip6"),
        }

        # 统计
        self._stats_lock = threading.Lock()
        self._stats = {
            "total_packets":     0,
            "accepted_packets":  0,
            "dropped_packets":   0,
            "rejected_packets":  0,
            "bytes_total":       0,
            "bytes_accepted":    0,
            "syn_flood_blocked": 0,
            "port_scan_blocked": 0,
            "icmp_flood_blocked":0,
            "start_time":        time.time(),
        }

        # 事件回调
        self._on_packet_callbacks:  List[Callable[[PacketInfo], None]] = []
        self._on_block_callbacks:   List[Callable[[PacketInfo, str], None]] = []
        self._on_alert_callbacks:   List[Callable[[str, Dict], None]] = []

        # 速率统计（滑动窗口）
        self._rate_window_size = 60
        self._pps_history:  deque = deque(maxlen=self._rate_window_size)
        self._bps_history:  deque = deque(maxlen=self._rate_window_size)
        self._last_stats_ts = time.time()
        self._interval_pkts = 0
        self._interval_bytes = 0

        self._num_workers = self._config.get("worker_threads", 4)
        logger.info(f"防火墙引擎初始化完成，工作线程数={self._num_workers}")

    def set_rule_chain(self, rule_chain):
        self._rule_chain = rule_chain

    def add_packet_callback(self, cb: Callable[[PacketInfo], None]):
        self._on_packet_callbacks.append(cb)

    def add_block_callback(self, cb: Callable[[PacketInfo, str], None]):
        self._on_block_callbacks.append(cb)

    def add_alert_callback(self, cb: Callable[[str, Dict], None]):
        self._on_alert_callbacks.append(cb)

    def set_logger(self, fw_logger: Any):
        """外部注入日志器"""
        self._fw_logger = fw_logger

    def set_capture_config(self, iface: str = "", backend: str = "auto",
                           promisc: bool = False, bpf_filter: str = ""):
        """
        配置数据包捕获后端
        backend: auto / scapy / pcap / raw / simulation / windivert
        """
        self._capture_config.update({
            "iface":   iface,
            "backend": backend,
            "promisc": promisc,
            "bpf":     bpf_filter or "ip or ip6",
        })
        logger.info(f"捕获配置更新: {self._capture_config}")

    def _open_capture(self):
        """打开数据包捕获后端"""
        if not HAS_CAPTURE:
            logger.warning("未安装捕获模块，使用内部仿真")
            return None

        cfg = self._capture_config
        backend_enum = CaptureBackend.SIMULATION
        backend_str = cfg["backend"].lower()
        mapping = {
            "scapy":      CaptureBackend.SCAPY,
            "pcap":       CaptureBackend.PYPCAP,
            "raw":        CaptureBackend.SOCKET_RAW,
            "simulation": CaptureBackend.SIMULATION,
            "windivert":  CaptureBackend.WINDIVERT,
        }
        if backend_str in mapping:
            backend_enum = mapping[backend_str]
        elif backend_str != "auto":
            logger.warning(f"未知后端 {backend_str}，使用自动选择")

        self._capture_mgr = CaptureManager(cfg["iface"], backend_enum)
        cap = self._capture_mgr.open(
            prefer=backend_enum,
            promisc=cfg["promisc"],
            bpf_filter=cfg["bpf"],
        )
        cap.set_callback(self._on_captured_packet)
        self._capture_iface = cap
        return cap

    def _on_captured_packet(self, cap_pkt: Any):
        """收到底层数据包时的回调"""
        try:
            verdict = self.inject_packet(
                cap_pkt.raw_data,
                iface=getattr(cap_pkt, "iface", ""),
                direction=getattr(cap_pkt, "direction", "IN"),
            )
            # 如果后端支持注入，且规则要求 DROP/REJECT，可在此执行
            if verdict in (PacketVerdict.DROP, PacketVerdict.REJECT):
                # 真实防火墙这里会丢弃包；仿真/用户态只能做到不转发
                pass
        except Exception as e:
            logger.debug(f"处理捕获包异常: {e}")

    def start(self):
        if self._running:
            return
        self._running = True
        # 启动数据包捕获
        try:
            cap = self._open_capture()
            if cap:
                cap.start_loop()
                logger.info(f"数据包捕获已启动，后端={cap.backend.name}")
        except Exception as e:
            logger.warning(f"启动数据包捕获失败: {e}")

        # 启动工作线程池
        for i in range(self._num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"fw-worker-{i}", daemon=True)
            t.start()
            self._workers.append(t)
        # 启动统计收集线程
        stats_t = threading.Thread(target=self._stats_loop, name="fw-stats", daemon=True)
        stats_t.start()
        self._workers.append(stats_t)
        logger.info("防火墙引擎已启动")

    def stop(self):
        self._running = False
        logger.info("防火墙引擎正在停止...")
        if self._capture_iface:
            try:
                self._capture_iface.stop_loop()
            except Exception:
                pass
        if self._capture_mgr:
            try:
                self._capture_mgr.close()
            except Exception:
                pass
        self._capture_iface = None
        for t in self._workers:
            t.join(timeout=3.0)
        self._workers.clear()
        logger.info("防火墙引擎已停止")

    def inject_packet(self, raw_data: bytes, iface: str = "", direction: str = "IN") -> PacketVerdict:
        """
        注入原始数据包，同步返回处置结果
        用于内核模块或 WinDivert 的直接调用路径
        """
        pkt = PacketParser.parse(raw_data, iface, direction)
        if pkt is None:
            return PacketVerdict.ACCEPT  # 解析失败则放行

        verdict = self._process_packet(pkt)

        # 异步通知回调（不阻塞主路径）
        if self._on_packet_callbacks:
            self._pkt_queue.put(pkt)

        self._update_stats(pkt, verdict)
        return verdict

    def _process_packet(self, pkt: PacketInfo) -> PacketVerdict:
        """核心处理逻辑，追求最低延迟"""

        # 1. 攻击检测（优先）
        if self._syn_detector.check(pkt):
            pkt.verdict  = PacketVerdict.DROP
            pkt.rule_hit = "SYN_FLOOD_PROTECTION"
            self._fire_block(pkt, "SYN Flood")
            self._log_event(pkt, "BLOCK", "SYN Flood 攻击防护")
            with self._stats_lock:
                self._stats["syn_flood_blocked"] += 1
            return PacketVerdict.DROP

        if self._icmp_detector.check(pkt):
            pkt.verdict  = PacketVerdict.DROP
            pkt.rule_hit = "ICMP_FLOOD_PROTECTION"
            self._fire_block(pkt, "ICMP Flood")
            self._log_event(pkt, "BLOCK", "ICMP Flood 攻击防护")
            with self._stats_lock:
                self._stats["icmp_flood_blocked"] += 1
            return PacketVerdict.DROP

        if self._scan_detector.check(pkt):
            pkt.verdict  = PacketVerdict.DROP
            pkt.rule_hit = "PORT_SCAN_PROTECTION"
            self._fire_block(pkt, "Port Scan")
            self._log_event(pkt, "BLOCK", "端口扫描防护")
            with self._stats_lock:
                self._stats["port_scan_blocked"] += 1
            return PacketVerdict.DROP

        # 2. 连接跟踪
        flow = self._conn_tracker.track(pkt)
        pkt.metadata["flow"] = flow

        # 3. 已建立连接快速放行（状态防火墙加速）
        if flow.is_established and pkt.direction == "IN":
            # 对于已建立连接，只需检查规则的快速路径
            if self._rule_chain:
                return self._rule_chain.match_established(pkt)
            return PacketVerdict.ACCEPT

        # 4. 完整规则链匹配
        if self._rule_chain:
            verdict = self._rule_chain.match(pkt)
            pkt.verdict = verdict
            if verdict in (PacketVerdict.DROP, PacketVerdict.REJECT):
                reason = pkt.rule_hit or "Rule Match"
                self._fire_block(pkt, reason)
                self._log_event(pkt, "BLOCK", reason)
            else:
                self._log_event(pkt, "ALLOW", "规则放行")
            return verdict

        # 无规则链时默认放行并记录
        self._log_event(pkt, "ALLOW", "默认策略放行")
        return PacketVerdict.ACCEPT

    def _worker_loop(self):
        """工作线程：处理回调队列"""
        while self._running:
            pkt = self._pkt_queue.get(timeout=1.0)
            if pkt is None:
                continue
            try:
                for cb in self._on_packet_callbacks:
                    cb(pkt)
            except Exception as e:
                logger.error(f"数据包回调异常: {e}")

    def _stats_loop(self):
        """统计收集线程"""
        while self._running:
            time.sleep(1.0)
            now = time.time()
            with self._stats_lock:
                elapsed = now - self._last_stats_ts
                if elapsed > 0:
                    pps = self._interval_pkts / elapsed
                    bps = self._interval_bytes / elapsed
                    self._pps_history.append(pps)
                    self._bps_history.append(bps)
                    self._interval_pkts  = 0
                    self._interval_bytes = 0
                    self._last_stats_ts  = now

    def _update_stats(self, pkt: PacketInfo, verdict: PacketVerdict):
        with self._stats_lock:
            self._stats["total_packets"]  += 1
            self._stats["bytes_total"]    += pkt.total_size
            self._interval_pkts           += 1
            self._interval_bytes          += pkt.total_size
            if verdict == PacketVerdict.ACCEPT:
                self._stats["accepted_packets"] += 1
                self._stats["bytes_accepted"]   += pkt.total_size
            elif verdict == PacketVerdict.DROP:
                self._stats["dropped_packets"]  += 1
            elif verdict == PacketVerdict.REJECT:
                self._stats["rejected_packets"] += 1

    def _fire_block(self, pkt: PacketInfo, reason: str):
        for cb in self._on_block_callbacks:
            try:
                cb(pkt, reason)
            except Exception:
                pass

    def _log_event(self, pkt: PacketInfo, event_type: str, reason: str):
        """同步记录事件到日志器"""
        if self._fw_logger is None:
            return
        try:
            self._fw_logger.log_packet({
                "timestamp":  pkt.timestamp,
                "src_ip":     pkt.src_ip,
                "dst_ip":     pkt.dst_ip,
                "src_port":   pkt.src_port,
                "dst_port":   pkt.dst_port,
                "protocol":   pkt.protocol.name,
                "verdict":    pkt.verdict.name,
                "rule_id":    pkt.rule_hit,
                "reason":     reason,
                "size":       pkt.total_size,
                "direction":  pkt.direction,
                "iface":      pkt.iface,
            }, event_type=event_type)
        except Exception as e:
            logger.debug(f"记录事件失败: {e}")

    def get_stats(self) -> Dict:
        with self._stats_lock:
            s = dict(self._stats)
        s["uptime"]        = time.time() - s["start_time"]
        s["pps_avg"]       = sum(self._pps_history) / len(self._pps_history) if self._pps_history else 0
        s["bps_avg"]       = sum(self._bps_history) / len(self._bps_history) if self._bps_history else 0
        s["queue_stats"]   = self._pkt_queue.stats
        s["conn_stats"]    = self._conn_tracker.get_stats()
        return s

    def get_current_pps(self) -> float:
        return self._pps_history[-1] if self._pps_history else 0.0

    def get_current_bps(self) -> float:
        return self._bps_history[-1] if self._bps_history else 0.0

    def get_active_connections(self) -> List[FlowRecord]:
        return self._conn_tracker.get_active_flows()

    def get_blocked_ips(self) -> Dict[str, Any]:
        return {
            "syn_flood":  self._syn_detector.get_blocked_ips(),
            "icmp_flood": self._icmp_detector.get_blocked_ips(),
        }

    def get_capture_info(self) -> Dict[str, Any]:
        """返回当前捕获后端信息"""
        if self._capture_iface:
            return {
                "backend":      self._capture_iface.backend.name,
                "iface":        self._capture_iface.iface,
                "running":      self._capture_iface.is_running,
                "bpf":          self._capture_config.get("bpf", ""),
            }
        return {"backend": "none", "iface": "", "running": False, "bpf": ""}
