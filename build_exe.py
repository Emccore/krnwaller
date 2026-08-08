"""
krnwaller Windows 单文件 exe 构建脚本
使用 PyInstaller 打包，输出 dist/krnwaller.exe
"""

import sys
import os
import shutil
import subprocess
from pathlib import Path


def clean_dist():
    """清理旧的构建产物，避免缓存冲突"""
    for name in ("build", "dist", "krnwaller.spec"):
        p = Path(name)
        if p.exists():
            if p.is_dir():
                shutil.rmtree(p)
                print(f"已删除目录: {p}")
            else:
                p.unlink()
                print(f"已删除文件: {p}")


def build():
    clean_dist()

    # 基础参数
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=krnwaller",
        "--onefile",
        "--windowed",          # GUI 程序，不弹控制台
        "--noconfirm",
        "--clean",
        # 图标（如果有的话）
        # "--icon=resources/icon.ico",
        # 把配置和日志目录作为附加数据打包
        "--add-data", "config;config",
        # 隐藏导入，避免运行时报 ImportError
        "--hidden-import", "PyQt5.sip",
        "--hidden-import", "PyQt5.QtCore",
        "--hidden-import", "PyQt5.QtGui",
        "--hidden-import", "PyQt5.QtWidgets",
        "--hidden-import", "PyQt5.QtChart",
        "--hidden-import", "core.engine",
        "--hidden-import", "core.capture",
        "--hidden-import", "protocols.analyzer",
        "--hidden-import", "rules.engine",
        "--hidden-import", "utils.logger",
        "--hidden-import", "utils.netutils",
        "--hidden-import", "config.manager",
        "main.py",
    ]

    print("开始构建 Windows 单文件 exe...")
    print(" ".join(cmd))
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        print("构建失败，请检查 PyInstaller 和依赖是否安装正确。")
        sys.exit(result.returncode)

    # 构建后把 config 目录复制到 dist，方便用户修改
    dist_dir = Path("dist")
    if dist_dir.exists():
        config_src = Path("config")
        config_dst = dist_dir / "config"
        if config_src.exists():
            if config_dst.exists():
                shutil.rmtree(config_dst)
            shutil.copytree(config_src, config_dst)
            print(f"已复制配置到: {config_dst}")

    exe_path = dist_dir / "krnwaller.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"构建成功: {exe_path} ({size_mb:.1f} MB)")
    else:
        print("未找到生成的 exe 文件，请检查 PyInstaller 输出。")


if __name__ == "__main__":
    build()
