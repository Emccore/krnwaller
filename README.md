# krnwaller

用 Python 写的软件防火墙。能抓包、过滤、检测攻击，带个深色主题的 GUI，也带了纯终端版。
跨平台，没装抓包驱动也能跑（仿真模式）。

## 功能

- 抓包：IPv4/IPv6、TCP/UDP/ICMP，往上拆 HTTP/DNS/TLS/ARP
- 过滤：IP/CIDR、端口范围、协议、方向、TCP flags、TTL、时间段、载荷正则，命中后 accept/drop/reject/log/limit
- 状态跟踪：连接表 + LRU 淘汰，已建立的连接直接放行
- 攻击检测：SYN Flood、ICMP Flood、端口扫描、ARP 欺骗，检测器自带周期清理
- 黑白名单：IP/CIDR/域名，运行时动态增删
- 日志：SQLite 批量写入 + JSONL 流水 + HTML 报告
- 两种前端：PyQt5 界面（main.py）、终端版（cli.py），还能 --no-gui 跑后台

## 结构

```
krnwaller/
├── main.py          GUI 入口
├── cli.py           终端版（面板/Shell/守护）
├── build_all.py     构建脚本，支持 --cli / --both
├── build_exe.py     Windows exe 专用
├── build_linux.sh   Linux 专用
├── config/          配置和规则
├── core/            引擎 + 抓包后端
├── protocols/       DPI 解析
├── rules/           规则链 + 黑白名单
├── ui/              PyQt5 界面
└── utils/           日志、网卡工具
```

## 安装

```bash
pip install -r requirements.txt
```

想抓真实流量就再装个 scapy：

```bash
pip install scapy
```

Windows 上抓包需要 Npcap，装的时候勾上 WinPcap 兼容。不装也能跑仿真模式，就是流量是假的。

## 用法

### GUI

```bash
python main.py
```

第一次跑没抓包驱动会自动进仿真模式，界面有模拟流量可以看效果。

### 终端版

服务器上跑或者不想装 PyQt5，用 cli.py：

```bash
python cli.py                          # 实时面板
python cli.py --shell                  # 交互式 Shell
python cli.py --daemon                 # 后台守护
python cli.py --backend simulation     # 指定后端
python cli.py --block 1.2.3.4 --daemon # 启动前封 IP
python cli.py --report rep.html        # 导报告
python cli.py --list-rules             # 看规则
```

Shell 里的命令：

```
rules / add / del <id>     规则
conn [n]                   连接
events [h] [type]          事件
alerts                     告警
stats                      统计
block <ip> / unblock <ip>  黑名单
bl                         看黑名单
report [path]              导报告
iface                      网卡
export [path]              导规则
exit
```

### 无界面模式

main.py 也能 --no-gui：

```bash
python main.py --no-gui
python main.py --no-gui --iface eth0 --backend scapy
python main.py --no-gui --bpf "tcp port 80"
```

## 抓包后端

| 后端 | 平台 | 权限 | 说明 |
|------|------|------|------|
| windivert | Windows | 管理员 | 内核层，最强 |
| scapy | 全平台 | root | 推荐 |
| pcap | 全平台 | root | 要 libpcap |
| raw | Linux/macOS | root | 原始套接字 |
| simulation | 全平台 | 不用 | 假流量 |
| auto | 全平台 | 看情况 | 自动选 |

这东西是用户态防火墙，默认只做看到+决策+记录，不会真掐流量。要真拦截得配 WinDivert（Windows）或 NFQUEUE（Linux）。当前版本重点是流量可视化和规则审计。

## 规则

一条规则 = 若干匹配条件（AND）+ 一个动作。

能匹配：源/目 IP、源/目端口、协议、方向、网卡、TCP flags、TTL、时间段、连接状态、载荷正则。

动作：accept / drop / reject / log / limit。

按 priority 排序，小的先匹配，命中就停。

默认规则在 config/rules.json，大概长这样：

```json
{
  "rule_id": "rule-00001",
  "name": "允许 SSH 远程管理",
  "priority": 20,
  "action": "accept",
  "protocols": ["tcp"],
  "dst_ports": [{"start": 22, "end": 22}]
}
```

Shell 里用 add 命令也能加，或者直接改 JSON 重启。

## 构建

先 `pip install pyinstaller`。

Windows：
```bash
python build_all.py            # GUI 版（73 MB，含 PyQt5）
python build_all.py --cli      # 终端版（17 MB，不含 PyQt5）
python build_all.py --both     # 两个都出
```

出 `dist/krnwaller.exe` 和 `dist/krnwallerCLI.exe`。

Linux/macOS：
```bash
python build_all.py --cli      # 推荐，只要 CLI，体积小
# 或
chmod +x build_linux.sh && ./build_linux.sh
```

出 `dist/krnwallerCLI`。

> Linux 二进制也可以直接从 GitHub Release 下载，每次发版会通过 GitHub Actions 自动构建。

### CLI 版和 GUI 版的区别

| | GUI 版 (krnwaller) | CLI 版 (krnwallerCLI) |
|---|---|---|
| 体积 | ~73 MB | ~17 MB |
| 依赖 | 含 PyQt5/QtChart | 纯 Python 标准库 |
| 入口 | main.py | cli.py |
| 适用 | 桌面、可视化 | 服务器、无界面、CI |

## 配置

config/firewall.json：

```json
{
  "engine": {
    "worker_threads": 4,
    "queue_size": 20000,
    "max_connections": 65536
  },
  "protection": {
    "syn_flood":  { "threshold": 200, "window": 1.0 },
    "icmp_flood": { "threshold": 500, "window": 1.0 },
    "port_scan":  { "port_threshold": 20, "window": 10.0 }
  },
  "logging": {
    "level": "INFO",
    "log_dir": "logs",
    "keep_days": 30
  }
}
```

threshold 调小更敏感但容易误杀，调大宽松但可能漏。

## 日志

跑起来后 logs/ 下有：

- startup.log — 启动日志
- firewall.log — 运行日志，轮转
- events.jsonl — 一行一个事件，方便 grep
- events.db — SQLite，事件和告警都在这

## FAQ

**找不到 PyQt5？**

```bash
pip install PyQt5 PyQtChart
```

或者用 cli.py，不需要 PyQt5。

**scapy 找不到网卡？**

Windows 上 Npcap 没装或没勾 WinPcap 兼容。

**drop 了但流量还通？**

用户态防火墙的 drop 只是记日志，系统网络栈照转。要真拦：Windows 装 pydivert，Linux 对接 NFQUEUE。

**关掉仿真模式？**

装了 scapy/pcap 自动用真实后端，也能 `--backend scapy` 手动指定。

**终端面板乱码？**

Windows 用 Windows Terminal，别用 cmd.exe。Linux/macOS 没这问题。

## 技术栈

Python 3.8+、PyQt5、scapy、SQLite3、PyInstaller。

## License

MIT
