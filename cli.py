#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
krnwaller CLI —— 独立的无 GUI 版本
不依赖 PyQt5，纯终端交互，适合服务器部署或远程管理。

主要功能：
  - 实时流量监控面板（Top 流量、PPS/BPS 趋势）
  - 规则增删改查、启用/禁用、导入导出
  - 黑白名单管理（IP / CIDR / 域名）
  - 连接表查看（活跃流、状态分布）
  - 事件查询与告警浏览
  - 攻击检测面板（SYN Flood / 端口扫描 / ICMP Flood）
  - 导出 HTML 报告
  - 后台守护模式

用法示例：
  python cli.py                          # 进入交互式面板
  python cli.py --backend simulation     # 指定捕获后端
  python cli.py --daemon                 # 守护模式，仅日志输出
  python cli.py --list-rules             # 打印规则列表后退出
  python cli.py --block 1.2.3.4          # 启动前先封禁指定 IP
  python cli.py --report report.html     # 导出报告后退出
"""

import os
import sys
import time
import json
import signal
import logging
import threading
import argparse
import platform
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Windows GBK 终端编码兼容
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 确保能找到项目自身的模块
_SCRIPT_DIR = Path(__file__).parent.resolve()
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from core.engine import FirewallEngine, PacketVerdict, Protocol, PacketInfo
from rules.engine import RuleManager, FirewallRule, RuleAction, IpRange, PortRange
from utils.netutils import get_local_interfaces, format_bytes, is_private_ip
from utils.logger import FirewallLogger, AlertLevel


# ──────────────────────────────────────────────────────────────
#  全局状态
# ──────────────────────────────────────────────────────────────

_engine:   Optional[FirewallEngine]  = None
_rule_mgr: Optional[RuleManager]     = None
_fw_log:   Optional[FirewallLogger]  = None
_running   = True

# 用于交互式面板控制
_panel_active   = False
_panel_stop_evt = threading.Event()
_refresh_rate   = 1.0   # 面板刷新间隔（秒）


def _setup_logging(level: str, log_dir: str):
    Path(log_dir).mkdir(exist_ok=True)
    numeric = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)-7s] %(name)-18s | %(message)s"
    logging.basicConfig(
        level=numeric,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(f"{log_dir}/cli.log", encoding="utf-8"),
        ],
    )


def _init_engine(args) -> bool:
    """初始化引擎和规则管理器，成功返回 True"""
    global _engine, _rule_mgr, _fw_log

    _rule_mgr = RuleManager(args.config)
    _rule_mgr.load_rules()

    # 预处理命令行指定的 block/allow
    for ip in (args.block or []):
        _rule_mgr.blacklist.block_ip(ip, reason="CLI 启动参数")
    for ip in (args.allow or []):
        _rule_mgr.blacklist.allow_ip(ip)

    engine_config = {
        "worker_threads":  args.workers,
        "queue_size":      20000,
        "max_connections": 65536,
        "log_dir":         args.log_dir,
        "db_path":         os.path.join(args.log_dir, "events.db"),
    }
    _engine = FirewallEngine(engine_config)
    _engine.set_rule_chain(_rule_mgr.get_chain("INPUT"))
    _engine.set_capture_config(
        iface   = args.iface,
        backend = args.backend,
        promisc = args.promisc,
        bpf_filter = args.bpf,
    )

    # 拿到 fw_logger 引用，方便后面查事件
    if _engine._fw_logger:
        _fw_log = _engine._fw_logger

    return True


# ──────────────────────────────────────────────────────────────
#  交互式监控面板
# ──────────────────────────────────────────────────────────────

class Dashboard:
    """
    终端实时监控面板
    用 ANSI 转义码刷新，不依赖第三方库
    """

    # ANSI 颜色
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    GRAY    = "\033[90m"

    def __init__(self):
        self._lines_drawn = 0
        self._start_time  = time.time()
        self._history_pps: List[float] = []
        self._history_bps: List[float] = []
        self._max_hist    = 40

    def _clear(self):
        if self._lines_drawn > 0:
            # 光标回到面板顶部并清行
            sys.stdout.write(f"\033[{self._lines_drawn}A")
            sys.stdout.write("\033[J")
        self._lines_drawn = 0

    def _println(self, text=""):
        sys.stdout.write(text + "\n")
        self._lines_drawn += 1

    def _bar(self, ratio: float, width: int = 30, fill="█", empty="░") -> str:
        ratio = max(0.0, min(1.0, ratio))
        filled = int(ratio * width)
        return fill * filled + empty * (width - filled)

    def _sparkline(self, data: List[float], width: int = 40) -> str:
        """用 block 字符画一个简易趋势线"""
        if not data:
            return "░" * width
        max_val = max(data) or 1
        # 采样到指定宽度
        step = max(1, len(data) / width)
        sampled = []
        i = 0.0
        while i < len(data) and len(sampled) < width:
            idx = int(i)
            sampled.append(data[idx])
            i += step
        blocks = "▁▂▃▄▅▆▇█"
        result = ""
        for v in sampled:
            pos = int((v / max_val) * (len(blocks) - 1))
            result += blocks[max(0, min(len(blocks) - 1, pos))]
        return result.ljust(width)

    def render(self):
        """渲染一帧"""
        self._clear()

        stats     = _engine.get_stats()
        cap_info  = _engine.get_capture_info()
        blocked   = _engine.get_blocked_ips()
        conns     = _engine.get_active_connections()
        conn_stats = stats.get("conn_stats", {})

        now_str   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        uptime    = stats.get("uptime", 0)
        up_str    = f"{int(uptime//3600)}h {int(uptime%3600//60)}m {int(uptime%60)}s"

        # 记录历史
        pps = stats.get("pps_avg", 0)
        bps = stats.get("bps_avg", 0)
        self._history_pps.append(pps)
        self._history_bps.append(bps)
        if len(self._history_pps) > self._max_hist:
            self._history_pps.pop(0)
            self._history_bps.pop(0)

        total   = stats.get("total_packets", 0)
        accept  = stats.get("accepted_packets", 0)
        drop    = stats.get("dropped_packets", 0)
        reject  = stats.get("rejected_packets", 0)
        bytes_t = stats.get("bytes_total", 0)
        syn_b   = stats.get("syn_flood_blocked", 0)
        scan_b  = stats.get("port_scan_blocked", 0)
        icmp_b  = stats.get("icmp_flood_blocked", 0)
        drop_rate = (drop / total * 100) if total else 0

        # ── 标题栏 ──
        self._println(f"{self.BOLD}{self.CYAN}╔{'═'*62}╗{self.RESET}")
        self._println(f"{self.BOLD}{self.CYAN}║{self.RESET} {self.BOLD}krnwaller CLI Monitor{self.RESET}"
                      f"{'':>18}{now_str}  {self.BOLD}{self.CYAN}║{self.RESET}")
        self._println(f"{self.BOLD}{self.CYAN}╚{'═'*62}╝{self.RESET}")

        # ── 引擎状态 ──
        backend   = cap_info.get("backend", "none")
        iface     = cap_info.get("iface", "-")
        cap_run   = cap_info.get("running", False)
        cap_str   = f"{self.GREEN}● 运行中{self.RESET}" if cap_run else f"{self.RED}○ 已停止{self.RESET}"

        self._println(f"  {self.GRAY}引擎状态{self.RESET}  {cap_str}   "
                      f"运行时长 {self.YELLOW}{up_str}{self.RESET}")
        self._println(f"  {self.GRAY}捕获后端{self.RESET}  {self.BLUE}{backend}{self.RESET}"
                      f"   接口 {self.BLUE}{iface}{self.RESET}")
        self._println("")

        # ── 数据包统计 ──
        self._println(f"  {self.BOLD}── 数据包统计 ──{self.RESET}")
        self._println(f"    总包数     {self.BOLD}{total:>12,}{self.RESET}")
        self._println(f"    放行       {self.GREEN}{accept:>12,}{self.RESET}"
                      f"    丢弃 {self.RED}{drop:>10,}{self.RESET}"
                      f"    拒绝 {self.YELLOW}{reject:>8,}{self.RESET}")
        self._println(f"    总流量     {self.MAGENTA}{format_bytes(bytes_t):>12}{self.RESET}"
                      f"    拦截率 {self.RED}{drop_rate:.2f}%{self.RESET}")
        self._println("")

        # ── 吞吐量趋势 ──
        self._println(f"  {self.BOLD}── 吞吐量 ──{self.RESET}")
        self._println(f"    PPS  {self.CYAN}{self._sparkline(self._history_pps)}{self.RESET}"
                      f"  {self.BOLD}{pps:.0f}{self.RESET} pkts/s")
        self._println(f"    BPS  {self.MAGENTA}{self._sparkline(self._history_bps)}{self.RESET}"
                      f"  {self.BOLD}{format_bytes(int(bps))}/s{self.RESET}")
        self._println("")

        # ── 攻击防护 ──
        syn_ips  = len(blocked.get("syn_flood", {}))
        icmp_ips = len(blocked.get("icmp_flood", {}))
        self._println(f"  {self.BOLD}── 攻击防护 ──{self.RESET}")
        self._println(f"    SYN Flood 拦截  {self.RED}{syn_b:>8,}{self.RESET}"
                      f"  封禁IP {syn_ips}")
        self._println(f"    ICMP Flood拦截  {self.RED}{icmp_b:>8,}{self.RESET}"
                      f"  封禁IP {icmp_ips}")
        self._println(f"    端口扫描拦截    {self.YELLOW}{scan_b:>8,}{self.RESET}")
        self._println("")

        # ── 连接表 ──
        total_conn = conn_stats.get("total", 0)
        by_state   = conn_stats.get("by_state", {})
        by_proto   = conn_stats.get("by_proto", {})
        estab      = by_state.get("ESTABLISHED", 0)
        new_conn   = by_state.get("NEW", 0)

        self._println(f"  {self.BOLD}── 连接跟踪 ──{self.RESET}")
        self._println(f"    活跃连接  {self.BOLD}{total_conn:>6}{self.RESET}"
                      f"   已建立 {self.GREEN}{estab:>5}{self.RESET}"
                      f"   新建 {self.YELLOW}{new_conn:>5}{self.RESET}"
                      f"   淘汰 {self.GRAY}{conn_stats.get('evicted',0):>5}{self.RESET}")
        proto_str = "  ".join(f"{k}:{v}" for k, v in sorted(by_proto.items(), key=lambda x: -x[1])[:5])
        self._println(f"    协议分布  {self.GRAY}{proto_str}{self.RESET}")
        self._println("")

        # ── Top 5 活跃连接 ──
        top_conns = sorted(conns, key=lambda c: c.total_bytes, reverse=True)[:5]
        if top_conns:
            self._println(f"  {self.BOLD}── Top 5 活跃流 ──{self.RESET}")
            self._println(f"    {self.GRAY}{'源地址':<22} {'目的地址':<22}"
                          f" {'协议':<6} {'状态':<12} {'流量':>10}{self.RESET}")
            for c in top_conns:
                src = f"{c.src_ip}:{c.src_port}"
                dst = f"{c.dst_ip}:{c.dst_port}"
                proto = c.protocol.name
                state_color = self.GREEN if c.is_established else self.YELLOW
                self._println(f"    {src:<22} {dst:<22}"
                              f" {proto:<6} {state_color}{c.state:<12}{self.RESET}"
                              f" {format_bytes(c.total_bytes):>10}")
            self._println("")

        # ── 队列 ──
        q = stats.get("queue_stats", {})
        self._println(f"  {self.BOLD}── 处理队列 ──{self.RESET}")
        qratio = q.get("current", 0) / max(1, 20000)
        self._println(f"    {self._bar(qratio)}  {q.get('current',0)}/{q.get('enqueued',0)}"
                      f"  丢弃 {self.RED}{q.get('dropped',0)}{self.RESET}")
        self._println("")

        # ── 底部提示 ──
        self._println(f"  {self.GRAY}按 Ctrl+C 退出  |  刷新间隔 {self.DIM}{_refresh_rate}s{self.RESET}")

        sys.stdout.flush()

    def run(self, stop_event: threading.Event):
        """循环渲染直到收到停止信号"""
        while not stop_event.is_set():
            try:
                self.render()
            except Exception as e:
                sys.stderr.write(f"\n面板渲染出错: {e}\n")
            stop_event.wait(_refresh_rate)


# ──────────────────────────────────────────────────────────────
#  命令处理器
# ──────────────────────────────────────────────────────────────

def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S")


def cmd_rules(args):
    """列出所有规则"""
    _print_rules(_rule_mgr)


def _print_rules(rule_mgr):
    """打印规则列表（可独立于全局 _rule_mgr 调用）"""
    rules = rule_mgr.get_all_rules()
    if not rules:
        print("  （没有规则）")
        return

    print(f"\n{'ID':<14} {'优先级':>4} {'状态':<4} {'动作':<7} {'名称':<24} {'组':<12} {'命中':>6}")
    print("-" * 80)
    for r in rules:
        status = "[OK]" if r.enabled else "[X]"
        print(f"{r.rule_id:<14} {r.priority:>4} {status:<4} {r.action.value:<7}"
              f" {r.name[:24]:<24} {r.group[:12]:<12} {r.hit_count:>6}")


def cmd_rule_add(args):
    """交互式添加规则"""
    print("\n=== 添加防火墙规则 ===")
    name = input("规则名称: ").strip()
    if not name:
        print("名称不能为空")
        return

    action_input = input("动作 (accept/drop/reject/log) [accept]: ").strip().lower() or "accept"
    try:
        action = RuleAction(action_input)
    except ValueError:
        print(f"无效动作: {action_input}")
        return

    priority = int(input("优先级 (数字越小越优先) [100]: ").strip() or "100")

    src_ip = input("源IP/CIDR (留空=any): ").strip()
    dst_ip = input("目标IP/CIDR (留空=any): ").strip()
    proto  = input("协议 (tcp/udp/icmp/any) [any]: ").strip().lower()
    dst_port = input("目标端口 (如 80 或 8080-8090，留空=any): ").strip()

    protocols = [proto] if proto and proto != "any" else []
    src_ips = [IpRange.from_str(src_ip)] if src_ip else []
    dst_ips = [IpRange.from_str(dst_ip)] if dst_ip else []
    dst_ports = [PortRange.from_str(dst_port)] if dst_port else []

    rule = FirewallRule(
        name=name,
        priority=priority,
        action=action,
        src_ips=src_ips,
        dst_ips=dst_ips,
        protocols=protocols,
        dst_ports=dst_ports,
    )
    rid = _rule_mgr.add_rule(rule)
    _rule_mgr.save_rules()
    print(f"\n[OK] 规则已添加，ID: {rid}")


def cmd_rule_del(args):
    """删除规则"""
    rid = args.rule_id
    if _rule_mgr.remove_rule(rid):
        _rule_mgr.save_rules()
        print(f"[OK] 规则 {rid} 已删除")
    else:
        print(f"[X] 未找到规则 {rid}")


def cmd_rule_toggle(args):
    """启用/禁用规则"""
    _rule_mgr.enable_rule(args.rule_id, args.enable)
    state = "启用" if args.enable else "禁用"
    print(f"[OK] 规则 {args.rule_id} 已{state}")


def cmd_blacklist(args):
    """查看/管理黑名单"""
    if args.add_ip:
        _rule_mgr.blacklist.block_ip(args.add_ip, reason="CLI 手动添加")
        _rule_mgr.save_rules()
        print(f"[OK] 已封锁 {args.add_ip}")
        return
    if args.del_ip:
        _rule_mgr.blacklist.unblock_ip(args.del_ip)
        _rule_mgr.save_rules()
        print(f"[OK] 已解封 {args.del_ip}")
        return
    if args.add_domain:
        _rule_mgr.blacklist.block_domain(args.add_domain)
        _rule_mgr.save_rules()
        print(f"[OK] 已封锁域名 {args.add_domain}")
        return

    # 列表
    ips = _rule_mgr.blacklist.get_blocked_ips()
    domains = _rule_mgr.blacklist.get_blocked_domains()
    print(f"\n封锁 IP ({len(ips)}):")
    for ip in sorted(ips):
        print(f"  {ip}")
    print(f"\n封锁域名 ({len(domains)}):")
    for d in sorted(domains):
        print(f"  {d}")


def cmd_connections(args):
    """查看活跃连接"""
    conns = _engine.get_active_connections()
    if not conns:
        print("  当前没有活跃连接")
        return

    conns_sorted = sorted(conns, key=lambda c: c.last_seen, reverse=True)
    limit = args.limit if args.limit else 20

    print(f"\n活跃连接 ({len(conns)} 条，显示前 {limit} 条):")
    print(f"{'源地址':<24} {'目的地址':<24} {'协议':<6} {'状态':<14}"
          f" {'入流量':>10} {'出流量':>10} {'持续':>8}")
    print("-" * 102)
    for c in conns_sorted[:limit]:
        dur = int(c.duration)
        dur_str = f"{dur//60}m{dur%60}s" if dur < 3600 else f"{dur//3600}h{(dur%3600)//60}m"
        print(f"{c.src_ip+':'+str(c.src_port):<24} {c.dst_ip+':'+str(c.dst_port):<24}"
              f" {c.protocol.name:<6} {c.state:<14}"
              f" {format_bytes(c.bytes_in):>10} {format_bytes(c.bytes_out):>10}"
              f" {dur_str:>8}")


def cmd_events(args):
    """查询事件"""
    if not _fw_log:
        print("日志系统未初始化")
        return

    db = _fw_log.db
    hours = args.hours if args.hours else 1
    since = time.time() - hours * 3600

    etype = args.type if hasattr(args, "type") and args.type else None
    events = db.query_events(limit=args.limit or 50, since=since, event_type=etype)

    if not events:
        print(f"  最近 {hours} 小时内没有事件记录")
        return

    print(f"\n事件记录 (最近 {hours}h，共 {len(events)} 条):")
    print(f"{'时间':<16} {'类型':<6} {'源IP':<16} {'目的IP':<16}"
          f" {'端口':>5} {'协议':<6} {'规则':<14} {'原因'}")
    print("-" * 110)
    for e in events:
        ts = _fmt_time(e.get("timestamp", 0))
        etype_s = e.get("event_type", "")
        type_color = Dashboard.RED if etype_s == "BLOCK" else Dashboard.GREEN
        print(f"{ts:<16} {type_color}{etype_s:<6}{Dashboard.RESET}"
              f" {e.get('src_ip',''):<16} {e.get('dst_ip',''):<16}"
              f" {str(e.get('dst_port','')):>5} {e.get('protocol',''):<6}"
              f" {e.get('rule_id','')[:14]:<14} {e.get('reason','')}")


def cmd_alerts(args):
    """查看告警"""
    if not _fw_log:
        print("日志系统未初始化")
        return
    alerts = _fw_log.db.query_alerts(resolved=False)
    if not alerts:
        print("  当前没有未处理告警")
        return

    print(f"\n未处理告警 ({len(alerts)} 条):")
    for a in alerts:
        level = a.get("level", "warning")
        color = Dashboard.RED if level == "critical" else Dashboard.YELLOW
        ts = _fmt_time(a.get("timestamp", 0))
        print(f"  {color}[{level.upper()}]{Dashboard.RESET} {ts}  {a.get('title','')}")
        if a.get("message"):
            print(f"    {a['message']}")


def cmd_stats(args):
    """打印详细统计"""
    stats = _engine.get_stats()
    print("\n=== 防火墙统计 ===")
    print(f"  运行时长:     {int(stats['uptime']//3600)}h {int(stats['uptime']%3600//60)}m")
    print(f"  总数据包:     {stats['total_packets']:,}")
    print(f"  放行:         {stats['accepted_packets']:,}")
    print(f"  丢弃:         {stats['dropped_packets']:,}")
    print(f"  拒绝:         {stats['rejected_packets']:,}")
    print(f"  总流量:       {format_bytes(stats['bytes_total'])}")
    print(f"  平均 PPS:     {stats['pps_avg']:.1f}")
    print(f"  平均 BPS:     {format_bytes(int(stats['bps_avg']))}")
    print(f"  SYN Flood拦截: {stats.get('syn_flood_blocked',0):,}")
    print(f"  ICMP Flood拦截:{stats.get('icmp_flood_blocked',0):,}")
    print(f"  端口扫描拦截:  {stats.get('port_scan_blocked',0):,}")

    cs = stats.get("conn_stats", {})
    print(f"\n=== 连接跟踪 ===")
    print(f"  活跃连接:     {cs.get('total',0)}")
    print(f"  已淘汰:       {cs.get('evicted',0)}")
    for state, count in cs.get("by_state", {}).items():
        print(f"    {state:<14} {count}")

    q = stats.get("queue_stats", {})
    print(f"\n=== 处理队列 ===")
    print(f"  入队:         {q.get('enqueued',0):,}")
    print(f"  出队:         {q.get('dequeued',0):,}")
    print(f"  当前队列:     {q.get('current',0):,}")
    print(f"  队列丢弃:     {q.get('dropped',0):,}")


def cmd_report(args):
    """导出 HTML 报告"""
    if not _fw_log:
        print("日志系统未初始化，无法导出报告")
        return
    output = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    hours = args.hours or 24
    _fw_log.export_report(output, hours=hours)
    print(f"[OK] 报告已导出到 {output}")


def cmd_interfaces(args):
    """列出网络接口"""
    ifaces = get_local_interfaces()
    print(f"\n本机网络接口 ({len(ifaces)}):")
    for i, iface in enumerate(ifaces):
        print(f"  [{i}] {iface['name']:<20} IP: {iface['ip']:<16}"
              f"  MAC: {iface.get('mac','')}")
    print("\n使用 --iface <名称> 指定监听接口")


def cmd_export_rules(args):
    """导出规则到文件"""
    rules = _rule_mgr.get_all_rules()
    data = {
        "version": "1.0",
        "exported_at": time.time(),
        "rules": [r.to_dict() for r in rules],
    }
    output = args.output or "rules_export.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[OK] 已导出 {len(rules)} 条规则到 {output}")


def cmd_shell(args):
    """进入交互式命令 Shell"""
    print(f"\n{Dashboard.BOLD}{Dashboard.CYAN}krnwaller Shell{Dashboard.RESET}")
    print("输入 help 查看命令，exit 退出\n")

    commands = {
        "help":     ("显示帮助", _shell_help),
        "rules":    ("列出规则", cmd_rules),
        "add":      ("添加规则", cmd_rule_add),
        "del":      ("删除规则 <id>", _shell_del),
        "conn":     ("查看连接", cmd_connections),
        "events":   ("查看事件", cmd_events),
        "alerts":   ("查看告警", cmd_alerts),
        "stats":    ("查看统计", cmd_stats),
        "block":    ("封锁IP <ip>", _shell_block),
        "unblock":  ("解封IP <ip>", _shell_unblock),
        "bl":       ("查看黑名单", cmd_blacklist),
        "report":   ("导出报告 <path>", _shell_report),
        "iface":    ("网络接口", cmd_interfaces),
        "export":   ("导出规则 <path>", cmd_export_rules),
        "exit":     ("退出", None),
        "quit":     ("退出", None),
    }

    while _running:
        try:
            line = input(f"{Dashboard.CYAN}krnwaller>{Dashboard.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        if cmd in ("exit", "quit"):
            break
        if cmd not in commands:
            print(f"未知命令: {cmd}，输入 help 查看")
            continue

        handler = commands[cmd][1]
        if handler is None:
            break
        try:
            # 简单传参
            class _A:
                pass
            a = _A()
            if len(parts) > 1:
                a.rule_id = parts[1]
                a.output  = parts[1]
                a.add_ip  = parts[1] if cmd == "block" else None
                a.del_ip  = parts[1] if cmd == "unblock" else None
                a.limit   = int(parts[1]) if cmd == "conn" else None
                a.hours   = int(parts[1]) if cmd in ("events","report") else None
                a.type    = parts[2] if cmd == "events" and len(parts) > 2 else None
            else:
                a.limit = 20
                a.hours = 1
                a.output = None
                a.type = None
                a.add_ip = None
                a.del_ip = None
                a.rule_id = None
            handler(a)
        except Exception as e:
            print(f"命令执行出错: {e}")


def _shell_help(args):
    print("\n可用命令:")
    for cmd, (desc, _) in sorted({
        "help":    ("显示帮助", None),
        "rules":   ("列出规则", None),
        "add":     ("添加规则", None),
        "del <id>":("删除规则", None),
        "conn [n]":("查看连接(前n条)", None),
        "events [h] [type]": ("查看事件(最近h小时)", None),
        "alerts":  ("查看告警", None),
        "stats":   ("查看统计", None),
        "block <ip>":  ("封锁IP", None),
        "unblock <ip>":("解封IP", None),
        "bl":      ("查看黑名单", None),
        "report [path]": ("导出报告", None),
        "iface":   ("网络接口", None),
        "export [path]":("导出规则", None),
        "exit":    ("退出", None),
    }.items()):
        print(f"  {cmd:<20} {desc}")
    print()


def _shell_del(args):
    if not getattr(args, "rule_id", None):
        print("用法: del <rule_id>")
        return
    if _rule_mgr.remove_rule(args.rule_id):
        _rule_mgr.save_rules()
        print(f"[OK] 已删除 {args.rule_id}")
    else:
        print(f"[X] 未找到 {args.rule_id}")


def _shell_block(args):
    if not getattr(args, "add_ip", None):
        print("用法: block <ip>")
        return
    _rule_mgr.blacklist.block_ip(args.add_ip, reason="Shell 手动")
    _rule_mgr.save_rules()
    print(f"[OK] 已封锁 {args.add_ip}")


def _shell_unblock(args):
    if not getattr(args, "del_ip", None):
        print("用法: unblock <ip>")
        return
    _rule_mgr.blacklist.unblock_ip(args.del_ip)
    _rule_mgr.save_rules()
    print(f"[OK] 已解封 {args.del_ip}")


def _shell_report(args):
    output = getattr(args, "output", None) or "report.html"
    if _fw_log:
        _fw_log.export_report(output, hours=24)
        print(f"[OK] 报告已导出 {output}")
    else:
        print("日志系统未初始化")


# ──────────────────────────────────────────────────────────────
#  守护模式
# ──────────────────────────────────────────────────────────────

def _daemon_loop():
    """守护模式：定期输出统计到日志，不渲染面板"""
    log = logging.getLogger("krnwaller.daemon")
    log.info("守护模式启动")
    while _running:
        time.sleep(10)
        stats = _engine.get_stats()
        cap   = _engine.get_capture_info()
        log.info(
            f"total={stats['total_packets']:,} "
            f"accept={stats['accepted_packets']:,} "
            f"drop={stats['dropped_packets']:,} "
            f"syn={stats.get('syn_flood_blocked',0)} "
            f"icmp={stats.get('icmp_flood_blocked',0)} "
            f"pps={stats['pps_avg']:.0f} "
            f"backend={cap.get('backend','none')}"
        )


# ──────────────────────────────────────────────────────────────
#  主入口
# ──────────────────────────────────────────────────────────────

def _signal_handler(sig, frame):
    global _running
    _running = False
    _panel_stop_evt.set()
    sys.stdout.write("\n\n收到退出信号，正在停止...\n")
    sys.stdout.flush()


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="krnwaller CLI — 无 GUI 版防火墙控制台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cli.py                          # 交互式监控面板
  python cli.py --shell                  # 进入命令 Shell
  python cli.py --daemon                 # 守护模式
  python cli.py --backend simulation     # 仿真后端
  python cli.py --list-rules             # 打印规则后退出
  python cli.py --block 1.2.3.4 --daemon # 封禁IP并守护运行
  python cli.py --report rep.html        # 导出报告后退出
  python cli.py --iface eth0 --backend scapy --promisc
        """,
    )
    p.add_argument("--config",    default="config",  help="配置目录")
    p.add_argument("--log-level", default="INFO",    help="日志级别")
    p.add_argument("--log-dir",   default="logs",    help="日志目录")
    p.add_argument("--iface",     default="",        help="监听接口")
    p.add_argument("--backend",   default="auto",    help="捕获后端")
    p.add_argument("--promisc",   action="store_true", help="混杂模式")
    p.add_argument("--bpf",       default="ip or ip6", help="BPF 过滤表达式")
    p.add_argument("--workers",   type=int, default=4, help="工作线程数")

    # 运行模式
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--shell",  action="store_true", help="进入交互式 Shell")
    mode.add_argument("--daemon", action="store_true", help="守护模式（仅日志）")
    mode.add_argument("--list-rules",  action="store_true", help="打印规则后退出")
    mode.add_argument("--list-ifaces", action="store_true", help="打印网络接口后退出")
    mode.add_argument("--report", metavar="PATH", help="导出 HTML 报告后退出")

    # 快捷操作
    p.add_argument("--block", action="append", help="启动前封锁 IP（可多次指定）")
    p.add_argument("--allow", action="append", help="启动前白名单 IP（可多次指定）")
    p.add_argument("--refresh", type=float, default=1.0, help="面板刷新间隔(秒)")

    return p


def main():
    global _running, _refresh_rate

    parser = build_arg_parser()
    args = parser.parse_args()

    _setup_logging(args.log_level, args.log_dir)
    log = logging.getLogger("krnwaller.cli")
    log.info("krnwaller CLI 启动")
    log.info("Python %s / %s", sys.version.split()[0], platform.platform())

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ── 不需要启动引擎的快捷操作 ──
    if args.list_ifaces:
        cmd_interfaces(args)
        return 0

    if args.list_rules:
        _rule_mgr_global = RuleManager(args.config)
        _rule_mgr_global.load_rules()
        _print_rules(_rule_mgr_global)
        return 0

    # ── 初始化引擎 ──
    if not _init_engine(args):
        log.error("引擎初始化失败")
        return 1

    # 导出报告后退出
    if args.report:
        _engine.start()
        time.sleep(2)  # 让引擎跑一会收集数据
        cmd_report(type("_A", (), {"output": args.report, "hours": 24})())
        _engine.stop()
        _rule_mgr.save_rules()
        return 0

    _refresh_rate = max(0.3, args.refresh)

    # ── 启动引擎 ──
    _engine.start()
    log.info("引擎已启动，后端=%s", _engine.get_capture_info().get("backend", "none"))

    try:
        if args.daemon:
            _daemon_loop()
        elif args.shell:
            cmd_shell(args)
        else:
            # 默认进入实时面板
            dashboard = Dashboard()
            panel_thread = threading.Thread(
                target=dashboard.run, args=(_panel_stop_evt,), daemon=True
            )
            panel_thread.start()
            # 主线程等待退出信号
            while _running:
                time.sleep(0.5)
    finally:
        _running = False
        _panel_stop_evt.set()
        log.info("正在停止引擎...")
        _engine.stop()
        _rule_mgr.save_rules()
        log.info("krnwaller CLI 已退出")

    return 0


if __name__ == "__main__":
    sys.exit(main())
