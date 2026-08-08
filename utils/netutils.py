"""
网络接口工具
跨平台获取本机网络接口信息
"""

import socket
import struct
import platform
import logging
import subprocess
from typing import List, Dict, Optional, Tuple
import ipaddress

logger = logging.getLogger("krnwaller.netutils")


def get_local_interfaces() -> List[Dict]:
    """
    获取本机所有网络接口信息
    返回 [{"name": str, "ip": str, "mac": str, "netmask": str, "is_up": bool}]
    """
    interfaces = []
    system = platform.system()

    if system == "Windows":
        interfaces = _get_interfaces_windows()
    elif system == "Linux":
        interfaces = _get_interfaces_linux()
    elif system == "Darwin":
        interfaces = _get_interfaces_macos()
    else:
        interfaces = _get_interfaces_fallback()

    return interfaces


def _get_interfaces_windows() -> List[Dict]:
    """Windows 平台获取接口"""
    result = []
    try:
        import ctypes
        import ctypes.wintypes

        # 尝试使用 socket 方法
        hostname = socket.gethostname()
        try:
            addrs = socket.getaddrinfo(hostname, None)
            seen = set()
            for addr_info in addrs:
                ip = addr_info[4][0]
                if ip not in seen and not ip.startswith("127.") and ":" not in ip:
                    seen.add(ip)
                    result.append({
                        "name":    "Local",
                        "ip":      ip,
                        "mac":     "00:00:00:00:00:00",
                        "netmask": "255.255.255.0",
                        "is_up":   True,
                    })
        except Exception:
            pass

        # 尝试 ipconfig 解析
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"], encoding="gbk", errors="replace", timeout=5
            )
            _parse_ipconfig(out, result)
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"获取Windows接口失败: {e}")

    if not result:
        result = _get_interfaces_fallback()

    return result


def _parse_ipconfig(output: str, result: List[Dict]):
    """解析 ipconfig /all 输出"""
    current_iface = None
    current_ip    = None
    current_mac   = None

    for line in output.splitlines():
        line = line.rstrip()
        if line and not line.startswith(" "):
            # 接口名行
            current_iface = line.rstrip(":").strip()
            current_ip    = None
            current_mac   = None
        elif "IPv4" in line and ":" in line:
            ip_part = line.split(":")[-1].strip()
            ip_part = ip_part.replace("(首选)", "").replace("(Preferred)", "").strip()
            try:
                ipaddress.ip_address(ip_part)
                current_ip = ip_part
            except ValueError:
                pass
        elif "物理地址" in line or "Physical Address" in line:
            mac_part = line.split(":")[-1].strip()
            current_mac = mac_part if len(mac_part) > 10 else None

        if current_iface and current_ip:
            # 检查是否已添加
            existing_ips = [r["ip"] for r in result]
            if current_ip not in existing_ips:
                result.append({
                    "name":    current_iface,
                    "ip":      current_ip,
                    "mac":     current_mac or "00:00:00:00:00:00",
                    "netmask": "255.255.255.0",
                    "is_up":   True,
                })
            current_ip = None


def _get_interfaces_linux() -> List[Dict]:
    """Linux 平台获取接口"""
    result = []
    try:
        import fcntl
        import socket

        SIOCGIFADDR    = 0x8915
        SIOCGIFHWADDR  = 0x8927
        SIOCGIFNETMASK = 0x891b

        with open("/proc/net/if_inet6", "r") as f:
            pass  # 检查IPv6支持

        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]  # 跳过前两行

        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue
            iface_name = parts[0].strip()
            if iface_name in ("lo",):
                continue

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                ifreq = struct.pack("16sh", iface_name.encode()[:15], 0)
                ip_res = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq + b"\0" * 8)
                ip = socket.inet_ntoa(ip_res[20:24])

                mac_res = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, ifreq + b"\0" * 8)
                mac = ":".join(f"{b:02x}" for b in mac_res[18:24])

                result.append({
                    "name":    iface_name,
                    "ip":      ip,
                    "mac":     mac,
                    "netmask": "255.255.255.0",
                    "is_up":   True,
                })
            except Exception:
                pass
            finally:
                sock.close()
    except Exception as e:
        logger.debug(f"获取Linux接口失败: {e}")
        result = _get_interfaces_fallback()
    return result


def _get_interfaces_macos() -> List[Dict]:
    """macOS 平台获取接口"""
    result = []
    try:
        out = subprocess.check_output(["ifconfig"], encoding="utf-8", timeout=5)
        current_iface = None
        for line in out.splitlines():
            if line and not line.startswith("\t") and not line.startswith(" "):
                current_iface = line.split(":")[0]
            elif "inet " in line and current_iface:
                parts = line.strip().split()
                ip_idx = parts.index("inet") + 1 if "inet" in parts else -1
                if ip_idx > 0 and ip_idx < len(parts):
                    ip = parts[ip_idx]
                    if not ip.startswith("127."):
                        result.append({
                            "name":    current_iface,
                            "ip":      ip,
                            "mac":     "00:00:00:00:00:00",
                            "netmask": "255.255.255.0",
                            "is_up":   True,
                        })
    except Exception:
        result = _get_interfaces_fallback()
    return result


def _get_interfaces_fallback() -> List[Dict]:
    """兜底方案"""
    result = []
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        result.append({
            "name":    "default",
            "ip":      ip,
            "mac":     "00:00:00:00:00:00",
            "netmask": "255.255.255.0",
            "is_up":   True,
        })
    except Exception:
        result.append({
            "name":    "localhost",
            "ip":      "127.0.0.1",
            "mac":     "00:00:00:00:00:00",
            "netmask": "255.0.0.0",
            "is_up":   True,
        })
    return result


def is_private_ip(ip: str) -> bool:
    """判断是否为私有 IP"""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def get_ip_geolocation(ip: str) -> Optional[Dict]:
    """
    获取 IP 地理位置（本地 GeoIP 库或离线方式）
    这里提供一个简单的私有IP判断
    """
    if is_private_ip(ip):
        return {"country": "内网", "city": "本地", "isp": "内网地址"}

    # 简单的大块IP归属判断（生产环境应使用 GeoIP2 数据库）
    try:
        first_octet = int(ip.split(".")[0])
        if 1 <= first_octet <= 50:
            return {"country": "美国", "city": "未知", "isp": "未知"}
        elif 51 <= first_octet <= 100:
            return {"country": "欧洲", "city": "未知", "isp": "未知"}
        elif 101 <= first_octet <= 150:
            return {"country": "亚洲", "city": "未知", "isp": "未知"}
        else:
            return {"country": "未知", "city": "未知", "isp": "未知"}
    except Exception:
        return None


def format_bytes(num_bytes: int) -> str:
    """格式化字节数"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def parse_ip_range(text: str) -> List[str]:
    """
    解析 IP 范围字符串，返回 IP 列表
    支持: 单IP, CIDR, 范围(192.168.1.1-10)
    """
    text = text.strip()
    ips  = []

    if "-" in text and "/" not in text:
        # 范围格式: 192.168.1.1-10 或 192.168.1.1-192.168.1.10
        parts = text.split("-", 1)
        base  = parts[0].strip()
        end   = parts[1].strip()
        if "." not in end:
            # 简写末尾
            prefix = ".".join(base.split(".")[:-1])
            start_last = int(base.split(".")[-1])
            end_last   = int(end)
            for i in range(start_last, end_last + 1):
                ips.append(f"{prefix}.{i}")
        else:
            # 完整 IP 范围
            try:
                start_int = int(ipaddress.ip_address(base))
                end_int   = int(ipaddress.ip_address(end))
                for i in range(start_int, min(end_int + 1, start_int + 256)):
                    ips.append(str(ipaddress.ip_address(i)))
            except ValueError:
                pass
    elif "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except ValueError:
            pass
    else:
        ips = [text]

    return ips
