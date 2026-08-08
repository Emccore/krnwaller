"""
协议深度检测（DPI）模块
支持 HTTP/HTTPS/DNS/FTP/SSH/SMTP/TLS 等应用层协议分析
"""

import struct
import re
import logging
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("krnwaller.protocols")


# ---------------------------------------------------------------------------
# HTTP 协议分析
# ---------------------------------------------------------------------------

@dataclass
class HttpRequest:
    method:   str = ""
    uri:      str = ""
    version:  str = ""
    headers:  Dict[str, str] = field(default_factory=dict)
    body:     bytes = b""
    host:     str = ""
    user_agent: str = ""
    content_type: str = ""

    @property
    def full_url(self) -> str:
        host = self.headers.get("host", self.host)
        return f"http://{host}{self.uri}" if host else self.uri


@dataclass
class HttpResponse:
    version:      str = ""
    status_code:  int = 0
    reason:       str = ""
    headers:      Dict[str, str] = field(default_factory=dict)
    body:         bytes = b""
    content_type: str = ""
    content_length: int = -1


class HttpAnalyzer:
    """HTTP 协议分析器"""

    # 支持的 HTTP 方法
    HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                    b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}

    # 可疑 URI 特征（SQL 注入、路径穿越、XSS 等）
    SUSPICIOUS_PATTERNS = [
        re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)\b)", re.I),
        re.compile(r"(\.\./|\.\.\\)"),             # 路径穿越
        re.compile(r"(<script|javascript:)", re.I), # XSS
        re.compile(r"(/etc/passwd|/windows/system32)", re.I),  # 敏感路径
        re.compile(r"(\bEVAL\s*\(|\bSYSTEM\s*\()", re.I),     # 代码执行
    ]

    @classmethod
    def parse_request(cls, data: bytes) -> Optional[HttpRequest]:
        try:
            if b"\r\n" not in data:
                return None
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = len(data)
            header_part = data[:header_end].decode("utf-8", errors="replace")
            lines = header_part.split("\r\n")
            if not lines:
                return None

            req_line = lines[0].split(" ")
            if len(req_line) < 2:
                return None

            req = HttpRequest()
            req.method  = req_line[0]
            req.uri     = req_line[1] if len(req_line) > 1 else "/"
            req.version = req_line[2] if len(req_line) > 2 else "HTTP/1.0"

            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    req.headers[k.strip().lower()] = v.strip()

            req.host         = req.headers.get("host", "")
            req.user_agent   = req.headers.get("user-agent", "")
            req.content_type = req.headers.get("content-type", "")
            req.body         = data[header_end + 4:] if header_end < len(data) else b""
            return req
        except Exception as e:
            logger.debug(f"HTTP请求解析失败: {e}")
            return None

    @classmethod
    def parse_response(cls, data: bytes) -> Optional[HttpResponse]:
        try:
            if not data.startswith(b"HTTP/"):
                return None
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = len(data)
            header_part = data[:header_end].decode("utf-8", errors="replace")
            lines = header_part.split("\r\n")
            if not lines:
                return None

            resp = HttpResponse()
            status_parts = lines[0].split(" ", 2)
            resp.version     = status_parts[0]
            resp.status_code = int(status_parts[1]) if len(status_parts) > 1 else 0
            resp.reason      = status_parts[2] if len(status_parts) > 2 else ""

            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    resp.headers[k.strip().lower()] = v.strip()

            resp.content_type   = resp.headers.get("content-type", "")
            cl = resp.headers.get("content-length", "-1")
            try:
                resp.content_length = int(cl)
            except ValueError:
                resp.content_length = -1
            resp.body = data[header_end + 4:] if header_end < len(data) else b""
            return resp
        except Exception as e:
            logger.debug(f"HTTP响应解析失败: {e}")
            return None

    @classmethod
    def detect_attack(cls, req: HttpRequest) -> List[Tuple[str, str]]:
        """检测 HTTP 层攻击，返回 (类型, 描述) 列表"""
        alerts = []
        target = req.uri + " " + req.host
        for pat in cls.SUSPICIOUS_PATTERNS:
            m = pat.search(target)
            if m:
                alerts.append(("HTTP_ATTACK", f"可疑 URI: {m.group(0)[:50]}"))
        return alerts


# ---------------------------------------------------------------------------
# DNS 协议分析
# ---------------------------------------------------------------------------

DNS_QTYPES = {
    1:   "A",
    2:   "NS",
    5:   "CNAME",
    6:   "SOA",
    12:  "PTR",
    15:  "MX",
    16:  "TXT",
    28:  "AAAA",
    33:  "SRV",
    255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class DnsQuery:
    transaction_id: int = 0
    flags:          int = 0
    questions:      List[Tuple[str, int, int]] = field(default_factory=list)  # (name, qtype, qclass)
    is_response:    bool = False
    rcode:          int = 0

    @property
    def is_recursive(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def rcode_name(self) -> str:
        return DNS_RCODES.get(self.rcode, f"RCODE{self.rcode}")


class DnsAnalyzer:
    """DNS 协议分析器，支持 DNS 隧道检测"""

    # 可疑域名特征
    DGA_ENTROPY_THRESHOLD = 3.8   # 高熵值可能是 DGA 域名

    @classmethod
    def parse(cls, data: bytes) -> Optional[DnsQuery]:
        """解析 DNS 报文"""
        if len(data) < 12:
            return None
        try:
            txid  = struct.unpack("!H", data[0:2])[0]
            flags = struct.unpack("!H", data[2:4])[0]
            qdcount = struct.unpack("!H", data[4:6])[0]

            q = DnsQuery()
            q.transaction_id = txid
            q.flags          = flags
            q.is_response    = bool(flags & 0x8000)
            q.rcode          = flags & 0x000F

            offset = 12
            for _ in range(qdcount):
                name, offset = cls._parse_name(data, offset)
                if offset + 4 > len(data):
                    break
                qtype  = struct.unpack("!H", data[offset:offset+2])[0]
                qclass = struct.unpack("!H", data[offset+2:offset+4])[0]
                offset += 4
                q.questions.append((name, qtype, qclass))

            return q
        except Exception as e:
            logger.debug(f"DNS解析失败: {e}")
            return None

    @classmethod
    def _parse_name(cls, data: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        visited = set()
        while offset < len(data):
            if offset in visited:
                break
            visited.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                # 压缩指针
                if offset + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                offset += 2
                label, _ = cls._parse_name(data, ptr)
                labels.append(label)
                break
            else:
                offset += 1
                label = data[offset:offset+length].decode("ascii", errors="replace")
                labels.append(label)
                offset += length
        return ".".join(labels), offset

    @classmethod
    def calc_entropy(cls, domain: str) -> float:
        """计算域名熵值（用于DGA检测）"""
        import math
        freq: Dict[str, int] = {}
        for ch in domain:
            freq[ch] = freq.get(ch, 0) + 1
        total = len(domain)
        if total == 0:
            return 0.0
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
        return entropy

    @classmethod
    def is_dga_domain(cls, domain: str) -> bool:
        """判断是否可能是 DGA 生成的域名"""
        labels = domain.split(".")
        if not labels:
            return False
        main_label = labels[0] if len(labels) > 1 else domain
        if len(main_label) < 8:
            return False
        # 字母数字混合比例
        digits = sum(1 for c in main_label if c.isdigit())
        ratio  = digits / len(main_label)
        entropy = cls.calc_entropy(main_label)
        return entropy > cls.DGA_ENTROPY_THRESHOLD and ratio > 0.3

    @classmethod
    def detect_dns_tunnel(cls, query: DnsQuery) -> bool:
        """检测 DNS 隧道特征"""
        for name, qtype, _ in query.questions:
            # TXT 查询常被用于 DNS 隧道
            if qtype == 16 and len(name) > 50:
                return True
            # 过长的子域名
            labels = name.split(".")
            for label in labels[:-2]:
                if len(label) > 30:
                    return True
        return False


# ---------------------------------------------------------------------------
# TLS/SSL 分析
# ---------------------------------------------------------------------------

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
    24: "Heartbeat",
}


@dataclass
class TlsInfo:
    version:        str = ""
    content_type:   str = ""
    sni:            str = ""   # Server Name Indication
    cipher_suites:  List[int] = field(default_factory=list)
    is_weak:        bool = False


class TlsAnalyzer:
    """TLS/SSL 协议分析器"""

    # 已知弱密码套件
    WEAK_CIPHER_SUITES = {
        0x0000, 0x0001, 0x0002, 0x0003,  # NULL 密码
        0x0018, 0x0019,                    # RC4
        0x0007, 0x0008, 0x0009,            # DES
    }

    @classmethod
    def parse_client_hello(cls, data: bytes) -> Optional[TlsInfo]:
        """解析 TLS Client Hello，提取 SNI 和密码套件"""
        try:
            if len(data) < 5:
                return None
            content_type = data[0]
            if content_type != 22:   # Handshake
                return None
            version = struct.unpack("!H", data[1:3])[0]
            info = TlsInfo()
            info.content_type = TLS_CONTENT_TYPES.get(content_type, str(content_type))
            info.version      = TLS_VERSIONS.get(version, f"0x{version:04X}")

            # 解析 Handshake
            if len(data) < 9:
                return info
            hs_type = data[5]
            if hs_type != 1:  # ClientHello
                return info

            hs_len = struct.unpack("!I", b"\x00" + data[6:9])[0]
            if len(data) < 9 + hs_len:
                return info

            hs_data = data[9:9+hs_len]
            # ClientHello 内容: version(2) + random(32) + session_id_len(1) + ...
            offset = 2 + 32
            if offset >= len(hs_data):
                return info
            sid_len = hs_data[offset]
            offset += 1 + sid_len

            if offset + 2 > len(hs_data):
                return info
            cs_len = struct.unpack("!H", hs_data[offset:offset+2])[0]
            offset += 2
            for i in range(0, cs_len, 2):
                if offset + i + 2 > len(hs_data):
                    break
                cs = struct.unpack("!H", hs_data[offset+i:offset+i+2])[0]
                info.cipher_suites.append(cs)
                if cs in cls.WEAK_CIPHER_SUITES:
                    info.is_weak = True
            offset += cs_len

            # 跳过压缩方法
            if offset >= len(hs_data):
                return info
            comp_len = hs_data[offset]
            offset += 1 + comp_len

            # 解析扩展
            if offset + 2 > len(hs_data):
                return info
            ext_total = struct.unpack("!H", hs_data[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total
            while offset + 4 <= min(ext_end, len(hs_data)):
                ext_type = struct.unpack("!H", hs_data[offset:offset+2])[0]
                ext_len  = struct.unpack("!H", hs_data[offset+2:offset+4])[0]
                offset += 4
                if ext_type == 0:  # SNI
                    sni_data = hs_data[offset:offset+ext_len]
                    if len(sni_data) > 5:
                        sni_name_len = struct.unpack("!H", sni_data[3:5])[0]
                        info.sni = sni_data[5:5+sni_name_len].decode("ascii", errors="replace")
                offset += ext_len

            return info
        except Exception as e:
            logger.debug(f"TLS分析失败: {e}")
            return None


# ---------------------------------------------------------------------------
# ARP 分析
# ---------------------------------------------------------------------------

@dataclass
class ArpPacket:
    operation:  int = 0    # 1=Request, 2=Reply
    sender_mac: str = ""
    sender_ip:  str = ""
    target_mac: str = ""
    target_ip:  str = ""

    @property
    def is_request(self) -> bool:
        return self.operation == 1

    @property
    def is_reply(self) -> bool:
        return self.operation == 2


class ArpAnalyzer:
    """ARP 协议分析，用于 ARP 欺骗检测"""

    @classmethod
    def parse(cls, data: bytes) -> Optional[ArpPacket]:
        if len(data) < 28:
            return None
        try:
            pkt = ArpPacket()
            pkt.operation  = struct.unpack("!H", data[6:8])[0]
            pkt.sender_mac = ":".join(f"{b:02x}" for b in data[8:14])
            pkt.sender_ip  = ".".join(str(b) for b in data[14:18])
            pkt.target_mac = ":".join(f"{b:02x}" for b in data[18:24])
            pkt.target_ip  = ".".join(str(b) for b in data[24:28])
            return pkt
        except Exception:
            return None


class ArpSpoofDetector:
    """ARP 欺骗检测器，维护 IP-MAC 绑定表"""

    def __init__(self):
        self._binding_table: Dict[str, str] = {}   # IP -> MAC
        self._alerts: List[Tuple[str, str, str, str]] = []  # (IP, old_mac, new_mac, time)
        import threading
        self._lock = threading.Lock()

    def check(self, pkt: ArpPacket) -> Optional[str]:
        """检查ARP包，返回告警信息（如有）"""
        if not pkt.is_reply:
            return None
        with self._lock:
            existing_mac = self._binding_table.get(pkt.sender_ip)
            if existing_mac is None:
                self._binding_table[pkt.sender_ip] = pkt.sender_mac
                return None
            if existing_mac.lower() != pkt.sender_mac.lower():
                import time
                alert = (pkt.sender_ip, existing_mac, pkt.sender_mac, time.time())
                self._alerts.append(alert)
                logger.warning(
                    f"ARP欺骗检测！IP={pkt.sender_ip} "
                    f"原MAC={existing_mac} 新MAC={pkt.sender_mac}"
                )
                return (f"ARP欺骗: {pkt.sender_ip} "
                        f"({existing_mac} -> {pkt.sender_mac})")
        return None

    def get_binding_table(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._binding_table)


# ---------------------------------------------------------------------------
# ICMP 分析
# ---------------------------------------------------------------------------

ICMP_TYPES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
    30: "Traceroute",
}


@dataclass
class IcmpInfo:
    icmp_type:  int = 0
    code:       int = 0
    checksum:   int = 0
    identifier: int = 0
    sequence:   int = 0
    payload:    bytes = b""
    type_name:  str = ""


class IcmpAnalyzer:
    """ICMP 协议分析器"""

    @classmethod
    def parse(cls, data: bytes) -> Optional[IcmpInfo]:
        if len(data) < 8:
            return None
        try:
            info = IcmpInfo()
            info.icmp_type = data[0]
            info.code      = data[1]
            info.checksum  = struct.unpack("!H", data[2:4])[0]
            if info.icmp_type in (0, 8):
                info.identifier = struct.unpack("!H", data[4:6])[0]
                info.sequence   = struct.unpack("!H", data[6:8])[0]
            info.payload   = data[8:]
            info.type_name = ICMP_TYPES.get(info.icmp_type, f"Type{info.icmp_type}")
            return info
        except Exception:
            return None

    @classmethod
    def detect_covert_channel(cls, info: IcmpInfo) -> bool:
        """检测 ICMP 隐蔽通道（payload 过大或异常）"""
        if info.icmp_type == 8 and len(info.payload) > 1024:
            return True
        return False


# ---------------------------------------------------------------------------
# SMTP 分析
# ---------------------------------------------------------------------------

@dataclass
class SmtpSession:
    commands:   List[str] = field(default_factory=list)
    from_addr:  str = ""
    to_addrs:   List[str] = field(default_factory=list)
    subject:    str = ""
    has_auth:   bool = False


class SmtpAnalyzer:
    """SMTP 会话分析器"""

    SMTP_COMMANDS = {"EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT",
                     "AUTH", "STARTTLS", "RSET", "VRFY", "NOOP"}

    @classmethod
    def parse_command(cls, data: bytes) -> Optional[Tuple[str, str]]:
        try:
            line = data.decode("utf-8", errors="replace").strip()
            parts = line.split(" ", 1)
            cmd   = parts[0].upper()
            arg   = parts[1] if len(parts) > 1 else ""
            if cmd in cls.SMTP_COMMANDS:
                return cmd, arg
            return None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# FTP 分析
# ---------------------------------------------------------------------------

@dataclass
class FtpCommand:
    command: str = ""
    arg:     str = ""


class FtpAnalyzer:
    """FTP 协议分析器"""

    FTP_COMMANDS = {"USER", "PASS", "PWD", "CWD", "LIST", "RETR",
                    "STOR", "DELE", "QUIT", "PASV", "PORT", "MKD",
                    "RMD", "RNFR", "RNTO", "TYPE", "SYST"}

    @classmethod
    def parse(cls, data: bytes) -> Optional[FtpCommand]:
        try:
            line = data.decode("utf-8", errors="replace").strip()
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            if cmd in cls.FTP_COMMANDS:
                return FtpCommand(command=cmd, arg=parts[1] if len(parts) > 1 else "")
            return None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# 协议分析调度器
# ---------------------------------------------------------------------------

class ProtocolAnalyzer:
    """
    协议分析调度器
    根据数据包特征选择合适的分析器
    """

    def __init__(self):
        self._http   = HttpAnalyzer()
        self._dns    = DnsAnalyzer()
        self._tls    = TlsAnalyzer()
        self._icmp   = IcmpAnalyzer()
        self._arp    = ArpAnalyzer()
        self._smtp   = SmtpAnalyzer()
        self._ftp    = FtpAnalyzer()
        self._arp_detector = ArpSpoofDetector()

    def analyze(self, payload: bytes, dst_port: int, src_port: int,
                proto_hint: str = "") -> Dict[str, Any]:
        """分析载荷，返回协议信息字典"""
        result: Dict[str, Any] = {}
        if not payload:
            return result

        port = dst_port or src_port

        if port == 80 or proto_hint == "HTTP":
            if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                req = HttpAnalyzer.parse_request(payload)
                if req:
                    result["http_request"] = req
                    attacks = HttpAnalyzer.detect_attack(req)
                    if attacks:
                        result["alerts"] = attacks
            elif payload.startswith(b"HTTP/"):
                resp = HttpAnalyzer.parse_response(payload)
                if resp:
                    result["http_response"] = resp

        elif port == 443 or proto_hint == "HTTPS":
            tls = TlsAnalyzer.parse_client_hello(payload)
            if tls:
                result["tls"] = tls

        elif port in (53,):
            dns = DnsAnalyzer.parse(payload)
            if dns:
                result["dns"] = dns
                if DnsAnalyzer.detect_dns_tunnel(dns):
                    result.setdefault("alerts", []).append(
                        ("DNS_TUNNEL", "可疑 DNS 隧道特征")
                    )
                for name, _, _ in dns.questions:
                    if DnsAnalyzer.is_dga_domain(name):
                        result.setdefault("alerts", []).append(
                            ("DGA_DOMAIN", f"可疑 DGA 域名: {name}")
                        )

        elif port in (25, 465, 587):
            smtp = SmtpAnalyzer.parse_command(payload)
            if smtp:
                result["smtp"] = smtp

        elif port == 21:
            ftp = FtpAnalyzer.parse(payload)
            if ftp:
                result["ftp"] = ftp

        return result

    @property
    def arp_spoof_detector(self) -> ArpSpoofDetector:
        return self._arp_detector
