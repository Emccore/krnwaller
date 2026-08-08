"""
krnwaller - 数据包捕获后端
提供跨平台、可插拔的数据包捕获与注入能力

设计目标：
1. 高兼容性：优先使用 scapy，回退到 pcap/pylibpcap、原始套接字、仿真模式
2. 零依赖可用：即使缺少抓包库，也能以仿真模式运行 UI 和规则调试
3. 高性能：批量读取、最小化 Python 层开销、GIL 外尽可能使用 C 库
4. 安全：不依赖管理员权限即可启动引擎核心；实际抓包时提醒权限需求
"""

import socket
import struct
import time
import logging
import threading
import platform
import random
import os
from abc import ABC, abstractmethod
from typing import Optional, Callable, List, Dict, Tuple, Any, Iterator
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

logger = logging.getLogger("krnwaller.capture")


class CaptureBackend(Enum):
    """可用捕获后端枚举"""
    SCAPY      = auto()   # scapy.all.sniff / send
    PYPACPNET  = auto()   # pcap (python-libpcap 风格)
    PYPCAP     = auto()   # pypcap
    SOCKET_RAW = auto()   # 原始套接字 (Linux 仅接收/发送 IP 层)
    WINDIVERT  = auto()   # Windows WinDivert（可选扩展）
    SIMULATION = auto()   # 仿真模式，不捕获真实流量
    NONE       = auto()   # 尚未选择


@dataclass
class CapturedPacket:
    """从底层捕获接口返回的原始数据包"""
    raw_data:  bytes
    timestamp: float
    iface:     str = ""
    direction: str = "IN"
    metadata:  Dict = field(default_factory=dict)


class PacketCaptureError(Exception):
    """捕获层异常"""
    pass


class CaptureInterface(ABC):
    """
    数据包捕获接口抽象基类
    所有后端都实现同一套 open/read/close/inject 语义
    """

    def __init__(self, backend: CaptureBackend, iface: str = ""):
        self.backend   = backend
        self.iface     = iface or "any"
        self._running  = False
        self._callback: Optional[Callable[[CapturedPacket], None]] = None
        self._thread:   Optional[threading.Thread] = None

    @abstractmethod
    def open(self, promisc: bool = False, bpf_filter: str = "") -> bool:
        """打开捕获设备，返回是否成功"""
        raise NotImplementedError

    @abstractmethod
    def read_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        """读取单个数据包"""
        raise NotImplementedError

    @abstractmethod
    def inject(self, raw_data: bytes, dst_addr: Tuple = None) -> bool:
        """向网络注入原始数据包"""
        raise NotImplementedError

    @abstractmethod
    def close(self):
        """关闭捕获设备"""
        raise NotImplementedError

    @property
    def is_running(self) -> bool:
        return self._running

    def set_callback(self, callback: Callable[[CapturedPacket], None]):
        self._callback = callback

    def start_loop(self):
        """在独立线程中持续读取数据包"""
        if self._running or self._thread is not None:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, name=f"capture-{self.backend.name}", daemon=True)
        self._thread.start()
        logger.info(f"捕获后端 {self.backend.name} 读取线程已启动")

    def stop_loop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None

    def _loop(self):
        while self._running:
            try:
                pkt = self.read_packet(timeout=0.5)
                if pkt and self._callback:
                    self._callback(pkt)
            except Exception as e:
                logger.debug(f"捕获循环异常: {e}")
                time.sleep(0.1)


class ScapyCapture(CaptureInterface):
    """
    scapy 后端：最推荐，功能最全
    自动加载 scapy，未安装时直接构造失败
    """

    def __init__(self, iface: str = ""):
        super().__init__(CaptureBackend.SCAPY, iface)
        self._scapy = None
        self._sniffer = None
        self._packets_queue: List[CapturedPacket] = []
        self._lock = threading.Lock()

    def open(self, promisc: bool = False, bpf_filter: str = "") -> bool:
        try:
            import scapy.all as scapy
            self._scapy = scapy
        except ImportError as e:
            logger.warning(f"scapy 未安装: {e}")
            return False

        try:
            ifaces = self._scapy.get_if_list()
            if self.iface != "any" and self.iface not in ifaces:
                logger.warning(f"接口 {self.iface} 不存在，可用接口: {ifaces}")
                self.iface = ifaces[0] if ifaces else "any"

            self._bpf = bpf_filter or "ip or ip6"
            self._promisc = promisc
            logger.info(f"scapy 后端已打开，接口={self.iface}, BPF={self._bpf}, promisc={promisc}")
            return True
        except Exception as e:
            logger.error(f"scapy 打开失败: {e}")
            return False

    def read_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        if self._scapy is None:
            return None
        try:
            iface = None if self.iface == "any" else self.iface
            pkts = self._scapy.sniff(
                iface=iface,
                filter=self._bpf,
                count=1,
                timeout=timeout,
                promisc=getattr(self, "_promisc", False),
            )
            if not pkts:
                return None
            pkt = pkts[0]
            raw = bytes(pkt)
            return CapturedPacket(
                raw_data=raw,
                timestamp=time.time(),
                iface=str(pkt.sniffed_on) if hasattr(pkt, "sniffed_on") else self.iface,
                direction="IN",
                metadata={"backend": "scapy"},
            )
        except Exception as e:
            logger.debug(f"scapy 读取异常: {e}")
            return None

    def inject(self, raw_data: bytes, dst_addr: Tuple = None) -> bool:
        if self._scapy is None:
            return False
        try:
            pkt = self._scapy.Raw(load=raw_data)
            self._scapy.send(pkt, verbose=0)
            return True
        except Exception as e:
            logger.error(f"scapy 注入失败: {e}")
            return False

    def close(self):
        self._running = False
        logger.info("scapy 后端已关闭")


class PcapCapture(CaptureInterface):
    """
    python-libpcap / pypcap 后端
    比 scapy 更轻量，适合只需要抓包的场景
    """

    def __init__(self, iface: str = ""):
        super().__init__(CaptureBackend.PYPCAP, iface)
        self._pcap = None
        self._reader = None
        self._send_packet = None

    def open(self, promisc: bool = False, bpf_filter: str = "") -> bool:
        try:
            import pcap
            self._pcap = pcap
        except ImportError:
            logger.info("pcap 模块未安装，跳过 pcap 后端")
            return False

        try:
            # pypcap 风格：pcap.pcap(name=..., promisc=..., immediate=...)
            self._open_pypcap(promisc, bpf_filter)
            return True
        except (TypeError, AttributeError):
            # python-libpcap 风格：pcap.pcap(iface, promisc=...)
            try:
                self._open_libpcap(promisc, bpf_filter)
                return True
            except Exception as e:
                logger.warning(f"pcap 打开失败: {e}")
                return False
        except Exception as e:
            logger.warning(f"pcap 打开失败: {e}")
            return False

    def _open_pypcap(self, promisc: bool, bpf_filter: str):
        iface = self.iface if self.iface != "any" else self._pcap.lookupdev()
        self._reader = self._pcap.pcap(name=iface, promisc=promisc, immediate=True)
        if bpf_filter:
            self._reader.setfilter(bpf_filter)
        logger.info(f"pypcap 后端已打开，接口={iface}")

    def _open_libpcap(self, promisc: bool, bpf_filter: str):
        iface = self.iface if self.iface != "any" else self._pcap.lookupdev()
        self._reader = self._pcap.pcap(iface, promisc=promisc)
        if bpf_filter:
            self._reader.setfilter(bpf_filter)
        self._send_packet = getattr(self._pcap, "sendpacket", None)
        logger.info(f"libpcap 后端已打开，接口={iface}")

    def read_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        if self._reader is None:
            return None
        try:
            # pypcap 风格
            if hasattr(self._reader, "next"):
                ts, raw = self._reader.next()
                if raw:
                    return CapturedPacket(
                        raw_data=raw,
                        timestamp=ts,
                        iface=self.iface,
                        direction="IN",
                        metadata={"backend": "pypcap"},
                    )
            # libpcap 风格
            elif hasattr(self._reader, "dispatch"):
                result = [None]
                def _cb(ts, pkt):
                    result[0] = CapturedPacket(
                        raw_data=pkt,
                        timestamp=ts,
                        iface=self.iface,
                        direction="IN",
                        metadata={"backend": "libpcap"},
                    )
                self._reader.dispatch(1, _cb)
                return result[0]
        except Exception as e:
            logger.debug(f"pcap 读取异常: {e}")
        return None

    def inject(self, raw_data: bytes, dst_addr: Tuple = None) -> bool:
        if self._send_packet:
            try:
                self._send_packet(raw_data)
                return True
            except Exception as e:
                logger.error(f"pcap 注入失败: {e}")
        return False

    def close(self):
        self._running = False
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
        logger.info("pcap 后端已关闭")


class RawSocketCapture(CaptureInterface):
    """
    原始套接字后端（Linux/macOS 为主）
    只能收发 IP 层及以上数据，需要 root
    """

    def __init__(self, iface: str = ""):
        super().__init__(CaptureBackend.SOCKET_RAW, iface)
        self._sock: Optional[socket.socket] = None

    def open(self, promisc: bool = False, bpf_filter: str = "") -> bool:
        system = platform.system()
        try:
            if system == "Windows":
                # Windows 原始套接字只能发送，不能接收任意包
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self._sock.bind((self._get_local_ip(), 0))
                self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                if self.iface and self.iface != "any":
                    self._sock.bind((self.iface, 0))
            self._sock.settimeout(0.5)
            logger.info(f"原始套接字后端已打开，接口={self.iface}")
            return True
        except PermissionError:
            logger.warning("原始套接字需要管理员/root权限")
            return False
        except Exception as e:
            logger.warning(f"原始套接字打开失败: {e}")
            return False

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def read_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        if self._sock is None:
            return None
        try:
            self._sock.settimeout(timeout)
            raw = self._sock.recv(65535)
            return CapturedPacket(
                raw_data=raw,
                timestamp=time.time(),
                iface=self.iface,
                direction="IN",
                metadata={"backend": "raw_socket"},
            )
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"原始套接字读取异常: {e}")
            return None

    def inject(self, raw_data: bytes, dst_addr: Tuple = None) -> bool:
        if self._sock is None:
            return False
        try:
            if platform.system() == "Windows":
                self._sock.sendto(raw_data, (dst_addr[0], 0) if dst_addr else ("127.0.0.1", 0))
            else:
                self._sock.send(raw_data)
            return True
        except Exception as e:
            logger.error(f"原始套接字注入失败: {e}")
            return False

    def close(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        logger.info("原始套接字后端已关闭")


class SimulationCapture(CaptureInterface):
    """
    仿真捕获后端
    生成可控的测试流量，用于无权限环境、UI 演示、CI 测试
    """

    # 预置仿真流量模板：每行为一条典型数据流
    FLOW_TEMPLATES = [
        # (src_ip, dst_ip, proto_name, dst_port, verdict_hint)
        ("192.168.1.100", "8.8.8.8", "udp", 53, "ACCEPT"),
        ("192.168.1.101", "142.250.185.78", "tcp", 443, "ACCEPT"),
        ("10.0.0.5", "185.220.101.42", "tcp", 22, "DROP"),
        ("172.16.0.20", "45.33.32.156", "tcp", 3389, "DROP"),
        ("192.168.1.105", "1.1.1.1", "udp", 53, "ACCEPT"),
        ("192.168.1.106", "93.184.216.34", "tcp", 80, "ACCEPT"),
        ("10.0.0.99", "192.168.1.1", "icmp", 0, "ACCEPT"),
        ("203.0.113.7", "192.168.1.100", "tcp", 445, "DROP"),
        ("198.51.100.22", "192.168.1.200", "tcp", 23, "DROP"),
        ("192.168.1.110", "142.250.185.78", "tcp", 443, "ACCEPT"),
    ]

    def __init__(self, iface: str = ""):
        super().__init__(CaptureBackend.SIMULATION, iface or "sim0")
        self._seq = 0
        self._rate = 80  # 每秒大约生成多少个包
        self._last_emit = time.time()
        self._rand = random.Random()
        self._rand.seed(42)

    def open(self, promisc: bool = False, bpf_filter: str = "") -> bool:
        logger.info("仿真捕获后端已打开（无需网卡权限）")
        return True

    def read_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        # 按速率生成包，避免 CPU 空转
        now = time.time()
        interval = 1.0 / max(1, self._rate)
        if now - self._last_emit < interval:
            time.sleep(min(timeout, interval))
            return None
        self._last_emit = now

        template = self._rand.choice(self.FLOW_TEMPLATES)
        src_ip, dst_ip, proto, dst_port, verdict_hint = template

        # 随机抖动源端口和序号
        src_port = self._rand.randint(40000, 65000)
        ip_id = self._rand.randint(1, 65535)

        raw = self._build_fake_packet(src_ip, dst_ip, proto, src_port, dst_port, ip_id)
        self._seq += 1

        return CapturedPacket(
            raw_data=raw,
            timestamp=now,
            iface=self.iface,
            direction="IN",
            metadata={
                "backend": "simulation",
                "verdict_hint": verdict_hint,
                "seq": self._seq,
            },
        )

    def _build_fake_packet(self, src_ip: str, dst_ip: str, proto: str,
                           src_port: int, dst_port: int, ip_id: int) -> bytes:
        """构造一个看起来像真实 IP 包的载荷"""
        proto_num = {"icmp": 1, "tcp": 6, "udp": 17}.get(proto, 6)
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)

        # IP 头（20 字节，无选项）
        version_ihl = 0x45
        dscp_ecn = 0
        total_len_placeholder = 0  # 稍后计算
        flags_frag = 0x4000  # 不分片
        ttl = 64

        ip_header_base = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, dscp_ecn, total_len_placeholder,
            ip_id, flags_frag, ttl, proto_num, 0,
            src_bytes, dst_bytes,
        )

        payload = b""
        if proto == "tcp":
            seq = self._rand.randint(0, 0xFFFFFFFF)
            ack = self._rand.randint(0, 0xFFFFFFFF)
            data_offset = (5 << 4)  # 20 字节 TCP 头
            flags = 0x18  # PSH+ACK
            window = 65535
            tcp_header = struct.pack(
                "!HHLLBBHHH",
                src_port, dst_port, seq, ack,
                data_offset, flags, window, 0, 0,
            )
            payload = tcp_header + b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        elif proto == "udp":
            length = 8 + 12
            udp_header = struct.pack("!HHHH", src_port, dst_port, length, 0)
            payload = udp_header + b"\x00" * 12
            if dst_port == 53:
                # 构造一个看起来像 DNS 查询的包
                payload = udp_header + self._build_dns_query("example.com")
        elif proto == "icmp":
            icmp_type = 8  # Echo Request
            icmp_code = 0
            icmp_id = self._rand.randint(1, 65535)
            icmp_seq = self._rand.randint(1, 65535)
            icmp_payload = b"krnwaller simulation packet"
            icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
            payload = icmp_header + icmp_payload
        else:
            payload = b"\x00" * 20

        total_len = len(ip_header_base) + len(payload)
        ip_header = bytearray(ip_header_base)
        struct.pack_into("!H", ip_header, 2, total_len)

        # 计算 IP 校验和
        ip_checksum = self._checksum(ip_header)
        struct.pack_into("!H", ip_header, 10, ip_checksum)

        # TCP 校验和（简化，伪头部）
        if proto == "tcp":
            tcp_with_checksum = bytearray(payload)
            pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, proto_num, len(payload))
            tcp_checksum = self._checksum(pseudo + payload)
            struct.pack_into("!H", tcp_with_checksum, 16, tcp_checksum)
            payload = bytes(tcp_with_checksum)

        return bytes(ip_header) + payload

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_dns_query(self, domain: str) -> bytes:
        """构造最小 DNS A 查询"""
        txid = self._rand.randint(0, 65535)
        flags = 0x0100  # 标准递归查询
        qdcount = 1
        header = struct.pack("!HHHHHH", txid, flags, qdcount, 0, 0, 0)
        body = b""
        for part in domain.encode().split(b"."):
            body += bytes([len(part)]) + part
        body += b"\x00" + struct.pack("!HH", 1, 1)  # A, IN
        return header + body

    def inject(self, raw_data: bytes, dst_addr: Tuple = None) -> bool:
        # 仿真模式不真正注入
        logger.debug(f"仿真模式忽略注入 {len(raw_data)} 字节")
        return True

    def set_rate(self, rate: int):
        self._rate = max(1, rate)

    def close(self):
        self._running = False
        logger.info("仿真捕获后端已关闭")


class WinDivertCapture(CaptureInterface):
    """
    Windows WinDivert 后端占位
    如果未来安装 pydivert，可直接启用
    """

    def __init__(self, iface: str = ""):
        super().__init__(CaptureBackend.WINDIVERT, iface)
        self._handle = None
        self._pydivert = None

    def open(self, promisc: bool = False, bpf_filter: str = "") -> bool:
        try:
            import pydivert
            self._pydivert = pydivert
            filter_str = bpf_filter or "true"
            self._handle = pydivert.WinDivert(filter_str, layer=pydivert.Layer.NETWORK)
            self._handle.open()
            logger.info("WinDivert 后端已打开")
            return True
        except ImportError:
            logger.info("pydivert 未安装，跳过 WinDivert 后端")
            return False
        except Exception as e:
            logger.warning(f"WinDivert 打开失败: {e}")
            return False

    def read_packet(self, timeout: float = 1.0) -> Optional[CapturedPacket]:
        if self._handle is None:
            return None
        try:
            # WinDivert 的 recv 是阻塞的，设个超时避免无法退出
            old_timeout = getattr(self._handle, "_timeout", None)
            self._handle._timeout = timeout
            pkt = self._handle.recv()
            return CapturedPacket(
                raw_data=bytes(pkt.raw),
                timestamp=time.time(),
                iface="windivert",
                direction="IN" if pkt.is_inbound else "OUT",
                metadata={"backend": "windivert"},
            )
        except Exception as e:
            logger.debug(f"WinDivert 读取异常: {e}")
            return None

    def inject(self, raw_data: bytes, dst_addr: Tuple = None) -> bool:
        if self._handle is None:
            return False
        try:
            pkt = self._pydivert.Packet(raw_data)
            self._handle.send(pkt)
            return True
        except Exception as e:
            logger.error(f"WinDivert 注入失败: {e}")
            return False

    def close(self):
        self._running = False
        if self._handle:
            try:
                self._handle.close()
            except Exception:
                pass
        logger.info("WinDivert 后端已关闭")


class CaptureManager:
    """
    捕获管理器：自动探测并选择最佳后端
    """

    def __init__(self, iface: str = "", backend: CaptureBackend = CaptureBackend.NONE):
        self._preferred = backend
        self._iface = iface
        self._backend: Optional[CaptureInterface] = None
        self._available_backends: List[CaptureBackend] = []
        self._detect_backends()

    def _detect_backends(self):
        """按优先级探测可用后端，不真正打开设备"""
        # WinDivert 在 Windows 上优先
        if platform.system() == "Windows":
            try:
                import pydivert  # noqa
                self._available_backends.append(CaptureBackend.WINDIVERT)
            except ImportError:
                pass

        try:
            import scapy.all  # noqa
            self._available_backends.append(CaptureBackend.SCAPY)
        except ImportError:
            pass

        try:
            import pcap  # noqa
            self._available_backends.append(CaptureBackend.PYPCAP)
        except ImportError:
            pass

        if platform.system() in ("Linux", "Darwin"):
            self._available_backends.append(CaptureBackend.SOCKET_RAW)

        # 仿真模式永远可用
        self._available_backends.append(CaptureBackend.SIMULATION)

        logger.info(f"探测到可用捕获后端: {[b.name for b in self._available_backends]}")

    def select_backend(self, prefer: CaptureBackend = CaptureBackend.NONE) -> CaptureBackend:
        """选择最合适的后端"""
        if prefer != CaptureBackend.NONE and prefer in self._available_backends:
            return prefer
        if self._preferred != CaptureBackend.NONE and self._preferred in self._available_backends:
            return self._preferred
        # 按 available_backends 顺序选择第一个非仿真
        for b in self._available_backends:
            if b != CaptureBackend.SIMULATION:
                return b
        return CaptureBackend.SIMULATION

    def open(self, prefer: CaptureBackend = CaptureBackend.NONE,
             promisc: bool = False, bpf_filter: str = "") -> CaptureInterface:
        backend = self.select_backend(prefer)
        logger.info(f"尝试打开捕获后端: {backend.name}")

        if backend == CaptureBackend.SCAPY:
            cap = ScapyCapture(self._iface)
        elif backend in (CaptureBackend.PYPCAP, CaptureBackend.PYPACPNET):
            cap = PcapCapture(self._iface)
        elif backend == CaptureBackend.SOCKET_RAW:
            cap = RawSocketCapture(self._iface)
        elif backend == CaptureBackend.WINDIVERT:
            cap = WinDivertCapture(self._iface)
        else:
            cap = SimulationCapture(self._iface)

        if not cap.open(promisc, bpf_filter):
            logger.warning(f"{backend.name} 打开失败，回退到仿真模式")
            cap = SimulationCapture(self._iface)
            cap.open(promisc, bpf_filter)

        self._backend = cap
        return cap

    @property
    def backend(self) -> Optional[CaptureInterface]:
        return self._backend

    @property
    def available_backends(self) -> List[CaptureBackend]:
        return list(self._available_backends)

    def close(self):
        if self._backend:
            self._backend.close()
            self._backend = None


def list_interfaces() -> List[Dict]:
    """
    列出本机可用网络接口，优先使用 scapy，否则回退
    """
    try:
        import scapy.all as scapy
        ifaces = []
        for name in scapy.get_if_list():
            ip = scapy.conf.ifaces.get(name, {}).get("ip", "") if hasattr(scapy.conf, "ifaces") else ""
            ifaces.append({
                "name": name,
                "ip": ip,
                "mac": "",
                "netmask": "",
                "is_up": True,
            })
        return ifaces
    except ImportError:
        pass

    try:
        from utils.netutils import get_local_interfaces
        return get_local_interfaces()
    except Exception as e:
        logger.debug(f"列出接口失败: {e}")
        return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    mgr = CaptureManager()
    cap = mgr.open()
    print(f"当前后端: {cap.backend.name}")
    cap.set_callback(lambda p: print(f"捕获 {len(p.raw_data)} 字节"))
    cap.start_loop()
    time.sleep(5)
    cap.stop_loop()
    mgr.close()
