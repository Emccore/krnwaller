"""
krnwaller 入口文件
"""

import sys
import os
import logging
import argparse
from pathlib import Path


def setup_logging(level: str = "INFO", log_dir: str = "logs"):
    Path(log_dir).mkdir(exist_ok=True)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(f"{log_dir}/startup.log", encoding="utf-8"),
        ]
    )


def main():
    parser = argparse.ArgumentParser(
        description="krnwaller - 高性能软件防火墙",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py               # 启动图形界面
  python main.py --log-level DEBUG
  python main.py --config config/custom.json
        """
    )
    parser.add_argument("--log-level",  default="INFO",   help="日志级别 (DEBUG/INFO/WARNING/ERROR)")
    parser.add_argument("--log-dir",    default="logs",   help="日志目录")
    parser.add_argument("--config",     default="config", help="配置目录")
    parser.add_argument("--no-gui",     action="store_true", help="无GUI模式（仅命令行）")
    parser.add_argument("--iface",      default="",       help="监听的网络接口")
    parser.add_argument("--backend",    default="auto",   help="捕获后端: auto/scapy/pcap/raw/simulation/windivert")
    parser.add_argument("--promisc",    action="store_true", help="开启混杂模式")
    parser.add_argument("--bpf",        default="ip or ip6", help="BPF 过滤表达式")
    args = parser.parse_args()

    setup_logging(args.log_level, args.log_dir)
    logger = logging.getLogger("krnwaller.main")
    logger.info("krnwaller 正在启动...")
    logger.info(f"Python {sys.version}")
    logger.info(f"工作目录: {os.getcwd()}")

    # 切换到脚本目录以正确找到模块
    script_dir = Path(__file__).parent.resolve()
    os.chdir(script_dir)
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    if args.no_gui:
        _run_headless(args)
    else:
        _run_gui(args)


def _run_gui(args):
    try:
        from ui.main_window import main as gui_main
        gui_main()
    except ImportError as e:
        print(f"\n无法启动图形界面: {e}")
        print("请安装依赖: pip install -r requirements.txt")
        print("或使用 --no-gui 参数运行无界面模式")
        sys.exit(1)


def _run_headless(args):
    """无界面命令行模式"""
    import time
    from core.engine import FirewallEngine
    from rules.engine import RuleManager

    logger = logging.getLogger("krnwaller.headless")
    logger.info("以无界面模式运行")

    rule_mgr = RuleManager(args.config)
    rule_mgr.load_rules()

    engine_config = {
        "log_dir":   args.log_dir,
        "db_path":   os.path.join(args.log_dir, "events.db"),
    }
    engine = FirewallEngine(engine_config)
    engine.set_rule_chain(rule_mgr.get_chain("INPUT"))
    engine.set_capture_config(
        iface=args.iface,
        backend=args.backend,
        promisc=args.promisc,
        bpf_filter=args.bpf,
    )
    engine.start()

    logger.info("防火墙引擎已启动，按 Ctrl+C 停止")
    try:
        while True:
            time.sleep(10)
            stats = engine.get_stats()
            cap_info = engine.get_capture_info()
            logger.info(
                f"统计: 总包={stats['total_packets']:,} "
                f"放行={stats['accepted_packets']:,} "
                f"丢弃={stats['dropped_packets']:,} "
                f"SYN拦截={stats.get('syn_flood_blocked', 0):,} "
                f"ICMP拦截={stats.get('icmp_flood_blocked', 0):,} "
                f"PPS={stats['pps_avg']:.0f} "
                f"后端={cap_info.get('backend', 'none')}"
            )
    except KeyboardInterrupt:
        logger.info("收到停止信号")
    finally:
        engine.stop()
        rule_mgr.save_rules()
        logger.info("防火墙已停止")


if __name__ == "__main__":
    main()
