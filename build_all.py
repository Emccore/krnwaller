"""
krnwaller 跨平台统一构建脚本
自动识别 Windows / Linux / macOS，调用 PyInstaller 生成单文件可执行程序。

用法:
    python build_all.py              # 自动识别当前平台构建
    python build_all.py --console    # Windows 下生成带控制台窗口的版本（调试用）
"""

import sys
import os
import shutil
import subprocess
import platform
from pathlib import Path


APP_NAME = "krnwaller"

# GUI 版本需要的隐藏导入（包含 PyQt5）
GUI_HIDDEN_IMPORTS = [
    "PyQt5.sip",
    "PyQt5.QtCore",
    "PyQt5.QtGui",
    "PyQt5.QtWidgets",
    "PyQt5.QtChart",
    "core.engine",
    "core.capture",
    "protocols.analyzer",
    "rules.engine",
    "utils.logger",
    "utils.netutils",
    "config.manager",
]

# CLI 版本的隐藏导入（不需要 PyQt5，体积更小）
CLI_HIDDEN_IMPORTS = [
    "core.engine",
    "core.capture",
    "protocols.analyzer",
    "rules.engine",
    "utils.logger",
    "utils.netutils",
    "config.manager",
]

# CLI 版本要排除的大块依赖（GUI/绘图/科学计算库，CLI 用不到）
CLI_EXCLUDES = [
    "PyQt5",
    "matplotlib",
    "PIL",
    "PIL.Image",
    "numpy",
    "pandas",
    "scipy",
    "tkinter",
    "IPython",
    "notebook",
    "jupyter",
    "PyQtChart",
]


def clean_dist(full: bool = True):
    """
    清理构建产物。
    full=True 时清 build/dist/spec（首次构建前用），
    full=False 时只清 build/spec（连续构建第二个时用，保留 dist）。
    """
    targets = ["build", f"{APP_NAME}.spec", f"{APP_NAME}CLI.spec"]
    if full:
        targets.append("dist")
    for name in targets:
        p = Path(name)
        if p.exists():
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
                print(f"已删除目录: {p}")
            else:
                p.unlink(missing_ok=True)
                print(f"已删除文件: {p}")


def build_windows(console: bool = False, cli_only: bool = False, clean_full: bool = True) -> bool:
    """构建 Windows 单文件 exe"""
    clean_dist(full=clean_full)

    name = f"{APP_NAME}CLI" if cli_only else APP_NAME
    entry = "cli.py" if cli_only else "main.py"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        f"--name={name}",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--add-data", "config;config",
    ]
    # CLI 版本始终保留控制台（否则看不到输出）
    # GUI 版本默认 --windowed，调试时可用 --console
    if not console and not cli_only:
        cmd.append("--windowed")

    imports = CLI_HIDDEN_IMPORTS if cli_only else GUI_HIDDEN_IMPORTS
    for imp in imports:
        cmd.extend(["--hidden-import", imp])

    # CLI 版本排除大块 GUI/科学计算依赖，减小体积
    if cli_only:
        for exc in CLI_EXCLUDES:
            cmd.extend(["--exclude-module", exc])

    cmd.append(entry)

    print(f"开始构建 {name} (入口: {entry})...")
    print(" ".join(cmd))
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print(f"{name} 构建失败")
        return False

    # 复制配置到 dist
    dist_dir = Path("dist")
    config_src = Path("config")
    config_dst = dist_dir / "config"
    if config_src.exists():
        if config_dst.exists():
            shutil.rmtree(config_dst)
        shutil.copytree(config_src, config_dst)
        print(f"已复制配置到: {config_dst}")

    ext = ".exe"
    exe_path = dist_dir / f"{name}{ext}"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"构建成功: {exe_path} ({size_mb:.1f} MB)")
        return True
    print(f"未找到 {exe_path}")
    return False


def build_unix(cli_only: bool = False, clean_full: bool = True) -> bool:
    """构建 Linux / macOS 单文件可执行程序"""
    clean_dist(full=clean_full)

    name = f"{APP_NAME}CLI" if cli_only else APP_NAME
    entry = "cli.py" if cli_only else "main.py"
    sep = ":"  # Linux/macOS 的数据分隔符

    cmd = [
        sys.executable, "-m", "PyInstaller",
        f"--name={name}",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--add-data", f"config{sep}config",
    ]

    imports = CLI_HIDDEN_IMPORTS if cli_only else GUI_HIDDEN_IMPORTS
    for imp in imports:
        cmd.extend(["--hidden-import", imp])

    # CLI 版本排除大块 GUI/科学计算依赖，减小体积
    if cli_only:
        for exc in CLI_EXCLUDES:
            cmd.extend(["--exclude-module", exc])

    cmd.append(entry)

    print(f"开始构建 {name} (入口: {entry})...")
    print(" ".join(cmd))
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print(f"{name} 构建失败")
        return False

    dist_dir = Path("dist")
    config_dst = dist_dir / "config"
    if config_dst.exists():
        shutil.rmtree(config_dst)
    shutil.copytree("config", config_dst)
    print(f"已复制配置到: {config_dst}")

    binary_path = dist_dir / name
    if binary_path.exists():
        size_mb = binary_path.stat().st_size / (1024 * 1024)
        print(f"构建成功: {binary_path} ({size_mb:.1f} MB)")
        binary_path.chmod(binary_path.stat().st_mode | 0o111)
        return True
    print(f"未找到 {binary_path}")
    return False


def main():
    import argparse
    p = argparse.ArgumentParser(description="krnwaller 跨平台构建脚本")
    p.add_argument("--console", action="store_true", help="Windows GUI 版保留控制台（调试用）")
    p.add_argument("--cli", action="store_true", help="只构建无 GUI 的 CLI 版本")
    p.add_argument("--both", action="store_true", help="同时构建 GUI 和 CLI 两个版本")
    args = p.parse_args()

    system = platform.system()
    results = []

    if args.both:
        # 先构建 GUI 版（完整清理）
        if system == "Windows":
            results.append(("GUI", build_windows(console=args.console, cli_only=False, clean_full=True)))
        else:
            results.append(("GUI", build_unix(cli_only=False, clean_full=True)))
        # 再构建 CLI 版（只清 build/spec，保留 dist 输出目录）
        if system == "Windows":
            results.append(("CLI", build_windows(console=True, cli_only=True, clean_full=False)))
        else:
            results.append(("CLI", build_unix(cli_only=True, clean_full=False)))
    elif args.cli:
        if system == "Windows":
            results.append(("CLI", build_windows(console=True, cli_only=True, clean_full=True)))
        else:
            results.append(("CLI", build_unix(cli_only=True, clean_full=True)))
    else:
        if system == "Windows":
            results.append(("GUI", build_windows(console=args.console, cli_only=False, clean_full=True)))
        else:
            results.append(("GUI", build_unix(cli_only=False, clean_full=True)))

    print("\n=== 构建结果 ===")
    for name, ok in results:
        status = "成功" if ok else "失败"
        print(f"  {name}: {status}")
    sys.exit(0 if all(ok for _, ok in results) else 1)


if __name__ == "__main__":
    main()
