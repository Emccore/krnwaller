"""
规则引擎模块
支持 IP/端口/协议/内容匹配，优先级排序，规则组和规则链
"""

import re
import json
import time
import logging
import ipaddress
import threading
from typing import Optional, List, Dict, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
import fnmatch

logger = logging.getLogger("krnwaller.rules")


class RuleAction(Enum):
    ACCEPT   = "accept"
    DROP     = "drop"
    REJECT   = "reject"
    LOG      = "log"
    LIMIT    = "limit"


class MatchField(Enum):
    SRC_IP       = "src_ip"
    DST_IP       = "dst_ip"
    SRC_PORT     = "src_port"
    DST_PORT     = "dst_port"
    PROTOCOL     = "protocol"
    DIRECTION    = "direction"
    PAYLOAD      = "payload"
    IFACE        = "iface"
    TTL          = "ttl"
    FLAGS        = "flags"
    STATE        = "state"
    TIME         = "time"


@dataclass
class PortRange:
    """端口范围，支持单端口、范围和列表"""
    start: int = 0
    end:   int = 65535

    @classmethod
    def from_str(cls, s: str) -> "PortRange":
        s = s.strip()
        if "-" in s:
            parts = s.split("-", 1)
            return cls(int(parts[0]), int(parts[1]))
        return cls(int(s), int(s))

    def match(self, port: int) -> bool:
        return self.start <= port <= self.end

    def __str__(self):
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"


@dataclass
class IpRange:
    """IP 地址范围，支持 CIDR、单IP和通配符"""
    network: Optional[Any] = None
    raw:     str           = ""

    @classmethod
    def from_str(cls, s: str) -> "IpRange":
        r = cls()
        r.raw = s.strip()
        if s.strip() in ("any", "*", "0.0.0.0/0", "::/0"):
            r.network = None  # 匹配所有
            return r
        try:
            r.network = ipaddress.ip_network(s.strip(), strict=False)
        except ValueError:
            r.network = None
        return r

    def match(self, ip: str) -> bool:
        if self.network is None:
            return True  # any
        try:
            addr = ipaddress.ip_address(ip)
            return addr in self.network
        except ValueError:
            return False

    def __str__(self):
        return self.raw or str(self.network) if self.network else "any"


@dataclass
class ContentMatch:
    """载荷内容匹配条件"""
    pattern:      str  = ""
    is_regex:     bool = False
    case_sensitive: bool = False
    offset:       int  = 0
    depth:        int  = -1
    _compiled:    Any  = field(default=None, repr=False)

    def __post_init__(self):
        if self.is_regex and self.pattern:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            try:
                self._compiled = re.compile(self.pattern.encode(), flags | re.DOTALL)
            except re.error as e:
                logger.error(f"正则表达式编译失败 '{self.pattern}': {e}")

    def match(self, payload: bytes) -> bool:
        if not payload:
            return False
        data = payload
        if self.offset > 0:
            data = data[self.offset:]
        if self.depth > 0:
            data = data[:self.depth]

        if self.is_regex and self._compiled:
            return bool(self._compiled.search(data))
        else:
            needle = self.pattern.encode("utf-8", errors="replace")
            if not self.case_sensitive:
                return needle.lower() in data.lower()
            return needle in data


@dataclass
class TimeRange:
    """时间段限制"""
    start_hour: int = 0
    end_hour:   int = 23
    weekdays:   Set[int] = field(default_factory=lambda: {0,1,2,3,4,5,6})  # 0=Mon

    def is_active(self) -> bool:
        import datetime
        now = datetime.datetime.now()
        if now.weekday() not in self.weekdays:
            return False
        return self.start_hour <= now.hour <= self.end_hour


@dataclass
class FirewallRule:
    """
    防火墙规则
    一条规则包含多个匹配条件（AND逻辑）和一个动作
    """
    rule_id:      str           = ""
    name:         str           = ""
    description:  str           = ""
    enabled:      bool          = True
    priority:     int           = 100      # 数值越小优先级越高
    action:       RuleAction    = RuleAction.ACCEPT
    group:        str           = "default"
    log_enabled:  bool          = False
    log_level:    str           = "INFO"
    comment:      str           = ""
    created_at:   float         = field(default_factory=time.time)
    updated_at:   float         = field(default_factory=time.time)

    # 匹配条件
    src_ips:      List[IpRange]      = field(default_factory=list)
    dst_ips:      List[IpRange]      = field(default_factory=list)
    src_ports:    List[PortRange]    = field(default_factory=list)
    dst_ports:    List[PortRange]    = field(default_factory=list)
    protocols:    List[str]          = field(default_factory=list)  # "tcp","udp","icmp","any"
    directions:   List[str]          = field(default_factory=list)  # "IN","OUT","FORWARD"
    ifaces:       List[str]          = field(default_factory=list)
    content:      List[ContentMatch] = field(default_factory=list)
    time_range:   Optional[TimeRange] = None
    states:       List[str]          = field(default_factory=list)  # "NEW","ESTABLISHED","RELATED"
    flags:        Optional[int]      = None   # TCP flags mask
    ttl_range:    Optional[Tuple[int,int]] = None

    # 统计
    hit_count:    int   = 0
    last_hit:     float = 0.0
    bytes_matched: int  = 0

    def match(self, pkt: Any) -> bool:
        """匹配数据包，所有条件AND"""
        if not self.enabled:
            return False

        # 时间段检查
        if self.time_range and not self.time_range.is_active():
            return False

        # 方向
        if self.directions and pkt.direction not in self.directions:
            return False

        # 接口
        if self.ifaces and pkt.iface and pkt.iface not in self.ifaces:
            return False

        # 协议
        if self.protocols:
            proto_name = pkt.protocol.name.lower()
            if "any" not in self.protocols and proto_name not in self.protocols:
                return False

        # 源IP
        if self.src_ips:
            if not any(r.match(pkt.src_ip) for r in self.src_ips):
                return False

        # 目标IP
        if self.dst_ips:
            if not any(r.match(pkt.dst_ip) for r in self.dst_ips):
                return False

        # 源端口
        if self.src_ports and pkt.src_port:
            if not any(r.match(pkt.src_port) for r in self.src_ports):
                return False

        # 目标端口
        if self.dst_ports and pkt.dst_port:
            if not any(r.match(pkt.dst_port) for r in self.dst_ports):
                return False

        # TCP Flags
        if self.flags is not None:
            if (pkt.flags & self.flags) != self.flags:
                return False

        # TTL 范围
        if self.ttl_range:
            lo, hi = self.ttl_range
            if not (lo <= pkt.ttl <= hi):
                return False

        # 连接状态
        if self.states:
            flow = pkt.metadata.get("flow")
            if flow:
                flow_state = "ESTABLISHED" if flow.is_established else "NEW"
                if flow_state not in self.states:
                    return False

        # 内容匹配（最后执行，开销最大）
        if self.content:
            if not all(cm.match(pkt.payload) for cm in self.content):
                return False

        return True

    def on_match(self, pkt: Any):
        """匹配命中时更新统计"""
        self.hit_count     += 1
        self.last_hit       = time.time()
        self.bytes_matched += pkt.total_size
        pkt.rule_hit        = self.rule_id

    def to_dict(self) -> Dict:
        return {
            "rule_id":     self.rule_id,
            "name":        self.name,
            "description": self.description,
            "enabled":     self.enabled,
            "priority":    self.priority,
            "action":      self.action.value,
            "group":       self.group,
            "log_enabled": self.log_enabled,
            "comment":     self.comment,
            "src_ips":     [r.raw for r in self.src_ips],
            "dst_ips":     [r.raw for r in self.dst_ips],
            "src_ports":   [str(r) for r in self.src_ports],
            "dst_ports":   [str(r) for r in self.dst_ports],
            "protocols":   self.protocols,
            "directions":  self.directions,
            "hit_count":   self.hit_count,
            "last_hit":    self.last_hit,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "FirewallRule":
        r = cls()
        r.rule_id     = d.get("rule_id", "")
        r.name        = d.get("name", "")
        r.description = d.get("description", "")
        r.enabled     = d.get("enabled", True)
        r.priority    = d.get("priority", 100)
        r.group       = d.get("group", "default")
        r.log_enabled = d.get("log_enabled", False)
        r.comment     = d.get("comment", "")

        action_str = d.get("action", "accept")
        try:
            r.action = RuleAction(action_str)
        except ValueError:
            r.action = RuleAction.ACCEPT

        r.src_ips   = [IpRange.from_str(s) for s in d.get("src_ips", [])]
        r.dst_ips   = [IpRange.from_str(s) for s in d.get("dst_ips", [])]
        r.src_ports = [PortRange.from_str(s) for s in d.get("src_ports", [])]
        r.dst_ports = [PortRange.from_str(s) for s in d.get("dst_ports", [])]
        r.protocols  = [p.lower() for p in d.get("protocols", [])]
        r.directions = d.get("directions", [])

        for cm_d in d.get("content", []):
            cm = ContentMatch(
                pattern       = cm_d.get("pattern", ""),
                is_regex      = cm_d.get("is_regex", False),
                case_sensitive = cm_d.get("case_sensitive", False),
            )
            r.content.append(cm)
        return r


class RuleGroup:
    """规则组，包含一组相关规则"""

    def __init__(self, name: str, enabled: bool = True, priority: int = 100):
        self.name     = name
        self.enabled  = enabled
        self.priority = priority
        self.rules:  List[FirewallRule] = []
        self._lock   = threading.RLock()

    def add_rule(self, rule: FirewallRule):
        with self._lock:
            self.rules.append(rule)
            self.rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r.rule_id != rule_id]
            return len(self.rules) < before

    def match(self, pkt: Any) -> Optional[FirewallRule]:
        if not self.enabled:
            return None
        with self._lock:
            for rule in self.rules:
                if rule.match(pkt):
                    rule.on_match(pkt)
                    return rule
        return None


class RuleChain:
    """
    规则链：INPUT / OUTPUT / FORWARD
    实现规则组的有序遍历和默认策略
    """

    def __init__(self, name: str = "INPUT", default_action: RuleAction = RuleAction.ACCEPT):
        self.name           = name
        self.default_action = default_action
        self._groups:       List[RuleGroup] = []
        self._lock          = threading.RLock()
        # 已建立连接的快速路径规则
        self._established_action = RuleAction.ACCEPT

    def add_group(self, group: RuleGroup):
        with self._lock:
            self._groups.append(group)
            self._groups.sort(key=lambda g: g.priority)

    def match(self, pkt: Any) -> Any:
        """完整规则匹配，返回 PacketVerdict"""
        from core.engine import PacketVerdict
        with self._lock:
            for group in self._groups:
                rule = group.match(pkt)
                if rule:
                    if rule.log_enabled:
                        logger.info(
                            f"规则命中 [{rule.name}] "
                            f"{pkt.src_ip}:{pkt.src_port} -> "
                            f"{pkt.dst_ip}:{pkt.dst_port} "
                            f"动作={rule.action.value}"
                        )
                    return self._action_to_verdict(rule.action)

        # 默认策略
        return self._action_to_verdict(self.default_action)

    def match_established(self, pkt: Any) -> Any:
        """已建立连接的快速路径"""
        from core.engine import PacketVerdict
        return self._action_to_verdict(self._established_action)

    @staticmethod
    def _action_to_verdict(action: RuleAction) -> Any:
        from core.engine import PacketVerdict
        return {
            RuleAction.ACCEPT:  PacketVerdict.ACCEPT,
            RuleAction.DROP:    PacketVerdict.DROP,
            RuleAction.REJECT:  PacketVerdict.REJECT,
            RuleAction.LOG:     PacketVerdict.LOG_ONLY,
            RuleAction.LIMIT:   PacketVerdict.ACCEPT,
        }.get(action, PacketVerdict.ACCEPT)


class BlacklistManager:
    """
    IP/域名黑白名单管理器
    支持动态更新和持久化
    """

    def __init__(self):
        self._blocked_ips:    Set[str] = set()
        self._allowed_ips:    Set[str] = set()
        self._blocked_domains: Set[str] = set()
        self._allowed_domains: Set[str] = set()
        self._blocked_networks: List[Any] = []
        self._allowed_networks: List[Any] = []
        self._lock = threading.RLock()

    def block_ip(self, ip: str, reason: str = ""):
        with self._lock:
            try:
                if "/" in ip:
                    self._blocked_networks.append(ipaddress.ip_network(ip, strict=False))
                else:
                    self._blocked_ips.add(ip)
                logger.info(f"封锁IP: {ip} 原因: {reason}")
            except ValueError as e:
                logger.error(f"无效IP格式: {ip} - {e}")

    def allow_ip(self, ip: str):
        with self._lock:
            try:
                if "/" in ip:
                    self._allowed_networks.append(ipaddress.ip_network(ip, strict=False))
                else:
                    self._allowed_ips.add(ip)
            except ValueError:
                pass

    def unblock_ip(self, ip: str):
        with self._lock:
            self._blocked_ips.discard(ip)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            # 先检查白名单（精确匹配，O(1)）
            if ip in self._allowed_ips:
                return False
            # 再检查黑名单精确匹配（O(1)）
            if ip in self._blocked_ips:
                return True
            # CIDR 匹配（较少使用）
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            for net in self._allowed_networks:
                if addr in net:
                    return False
            for net in self._blocked_networks:
                if addr in net:
                    return True
            return False

    def block_domain(self, domain: str):
        with self._lock:
            self._blocked_domains.add(domain.lower())

    def is_domain_blocked(self, domain: str) -> bool:
        domain = domain.lower()
        with self._lock:
            if domain in self._blocked_domains:
                return True
            # 检查通配符
            for blocked in self._blocked_domains:
                if fnmatch.fnmatch(domain, blocked):
                    return True
        return False

    def get_blocked_ips(self) -> List[str]:
        with self._lock:
            return list(self._blocked_ips)

    def get_blocked_domains(self) -> List[str]:
        with self._lock:
            return list(self._blocked_domains)

    def load_from_file(self, path: str):
        """从文件加载黑名单（每行一个IP/CIDR）"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.block_ip(line)
            logger.info(f"从文件加载黑名单: {path}")
        except FileNotFoundError:
            logger.warning(f"黑名单文件不存在: {path}")
        except Exception as e:
            logger.error(f"加载黑名单失败: {e}")

    def save_to_file(self, path: str):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# krnwaller 黑名单\n")
                for ip in sorted(self._blocked_ips):
                    f.write(ip + "\n")
        except Exception as e:
            logger.error(f"保存黑名单失败: {e}")


class RuleManager:
    """
    规则管理器
    负责规则的 CRUD、持久化和热更新
    """

    def __init__(self, config_dir: str = "config"):
        self._config_dir   = Path(config_dir)
        self._config_dir.mkdir(exist_ok=True)
        self._rules_file   = self._config_dir / "rules.json"

        self._groups:      Dict[str, RuleGroup] = {}
        self._chains:      Dict[str, RuleChain] = {}
        self._blacklist    = BlacklistManager()
        self._lock         = threading.RLock()
        self._next_rule_id = 1

        # 初始化默认链
        self._chains["INPUT"]   = RuleChain("INPUT",   RuleAction.ACCEPT)
        self._chains["OUTPUT"]  = RuleChain("OUTPUT",  RuleAction.ACCEPT)
        self._chains["FORWARD"] = RuleChain("FORWARD", RuleAction.DROP)

        # 初始化默认规则组
        self._init_default_groups()
        logger.info("规则管理器初始化完成")

    def _init_default_groups(self):
        """初始化内置规则组"""
        # 基础安全组
        security_group = RuleGroup("基础安全", priority=10)
        # 放行回环接口
        loopback_rule = FirewallRule(
            rule_id     = "builtin-loopback",
            name        = "允许回环接口",
            priority    = 1,
            action      = RuleAction.ACCEPT,
            group       = "基础安全",
            src_ips     = [IpRange.from_str("127.0.0.1")],
        )
        security_group.add_rule(loopback_rule)
        self._groups["基础安全"] = security_group

        # 将默认组注册到 INPUT 链
        self._chains["INPUT"].add_group(security_group)

    def add_rule(self, rule: FirewallRule, chain: str = "INPUT") -> str:
        with self._lock:
            if not rule.rule_id:
                rule.rule_id = f"rule-{self._next_rule_id:05d}"
                self._next_rule_id += 1

            group_name = rule.group or "default"
            if group_name not in self._groups:
                g = RuleGroup(group_name)
                self._groups[group_name] = g
                if chain in self._chains:
                    self._chains[chain].add_group(g)

            self._groups[group_name].add_rule(rule)
            logger.info(f"添加规则: {rule.rule_id} [{rule.name}] -> {rule.action.value}")
            return rule.rule_id

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            for group in self._groups.values():
                if group.remove_rule(rule_id):
                    logger.info(f"删除规则: {rule_id}")
                    return True
        return False

    def enable_rule(self, rule_id: str, enabled: bool):
        with self._lock:
            for group in self._groups.values():
                for rule in group.rules:
                    if rule.rule_id == rule_id:
                        rule.enabled = enabled
                        rule.updated_at = time.time()
                        return

    def get_all_rules(self) -> List[FirewallRule]:
        with self._lock:
            rules = []
            for group in self._groups.values():
                rules.extend(group.rules)
            return sorted(rules, key=lambda r: (r.priority, r.rule_id))

    def get_chain(self, name: str = "INPUT") -> Optional[RuleChain]:
        return self._chains.get(name)

    @property
    def blacklist(self) -> BlacklistManager:
        return self._blacklist

    def save_rules(self):
        """持久化规则到 JSON 文件"""
        try:
            data = {
                "version": "1.0",
                "saved_at": time.time(),
                "rules": [r.to_dict() for r in self.get_all_rules()],
                "blocked_ips": self._blacklist.get_blocked_ips(),
                "blocked_domains": self._blacklist.get_blocked_domains(),
            }
            with open(self._rules_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"规则已保存: {self._rules_file}")
        except Exception as e:
            logger.error(f"保存规则失败: {e}")

    def load_rules(self):
        """从 JSON 文件加载规则"""
        if not self._rules_file.exists():
            logger.info("未找到规则文件，使用默认规则")
            return
        try:
            with open(self._rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            rules_data = data.get("rules", [])
            for rd in rules_data:
                if rd.get("rule_id", "").startswith("builtin-"):
                    continue
                rule = FirewallRule.from_dict(rd)
                self.add_rule(rule)

            for ip in data.get("blocked_ips", []):
                self._blacklist.block_ip(ip)
            for domain in data.get("blocked_domains", []):
                self._blacklist.block_domain(domain)

            # 更新下一个规则ID，避免和已加载规则冲突
            max_id = self._next_rule_id
            for r in self.get_all_rules():
                if r.rule_id.startswith("rule-"):
                    try:
                        num = int(r.rule_id[5:])
                        max_id = max(max_id, num + 1)
                    except ValueError:
                        pass
            self._next_rule_id = max_id

            logger.info(f"加载规则 {len(rules_data)} 条，下一个规则ID={self._next_rule_id}")
        except Exception as e:
            logger.error(f"加载规则失败: {e}")

    def build_rule_from_form(self, form: Dict) -> FirewallRule:
        """从表单数据构建规则对象"""
        rule = FirewallRule()
        rule.name        = form.get("name", "新规则")
        rule.description = form.get("description", "")
        rule.priority    = int(form.get("priority", 100))
        rule.enabled     = bool(form.get("enabled", True))
        rule.group       = form.get("group", "default")
        rule.log_enabled = bool(form.get("log_enabled", False))
        rule.comment     = form.get("comment", "")

        action_str = form.get("action", "accept")
        try:
            rule.action = RuleAction(action_str)
        except ValueError:
            rule.action = RuleAction.ACCEPT

        for ip_str in form.get("src_ips", []):
            if ip_str.strip():
                rule.src_ips.append(IpRange.from_str(ip_str))
        for ip_str in form.get("dst_ips", []):
            if ip_str.strip():
                rule.dst_ips.append(IpRange.from_str(ip_str))
        for port_str in form.get("src_ports", []):
            if port_str.strip():
                rule.src_ports.append(PortRange.from_str(port_str))
        for port_str in form.get("dst_ports", []):
            if port_str.strip():
                rule.dst_ports.append(PortRange.from_str(port_str))

        rule.protocols  = [p.lower().strip() for p in form.get("protocols", []) if p.strip()]
        rule.directions = form.get("directions", [])

        content_pattern = form.get("content_pattern", "")
        if content_pattern:
            rule.content.append(ContentMatch(
                pattern   = content_pattern,
                is_regex  = form.get("content_is_regex", False),
            ))
        return rule


# 内置预设规则集
BUILTIN_RULE_TEMPLATES = [
    {
        "name":        "阻止 Telnet",
        "description": "阻止不安全的 Telnet 连接",
        "action":      "drop",
        "dst_ports":   ["23"],
        "protocols":   ["tcp"],
        "priority":    50,
    },
    {
        "name":        "允许 SSH",
        "description": "允许 SSH 远程管理",
        "action":      "accept",
        "dst_ports":   ["22"],
        "protocols":   ["tcp"],
        "priority":    20,
    },
    {
        "name":        "允许 DNS",
        "description": "允许 DNS 查询",
        "action":      "accept",
        "dst_ports":   ["53"],
        "protocols":   ["udp", "tcp"],
        "priority":    20,
    },
    {
        "name":        "允许 HTTP/HTTPS",
        "description": "允许 Web 流量",
        "action":      "accept",
        "dst_ports":   ["80", "443"],
        "protocols":   ["tcp"],
        "priority":    20,
    },
    {
        "name":        "允许 ICMP Ping",
        "description": "允许 ICMP 回显请求",
        "action":      "accept",
        "protocols":   ["icmp"],
        "priority":    30,
    },
    {
        "name":        "阻止 NetBIOS",
        "description": "阻止 NetBIOS 流量",
        "action":      "drop",
        "dst_ports":   ["137", "138", "139"],
        "protocols":   ["tcp", "udp"],
        "priority":    40,
    },
]
