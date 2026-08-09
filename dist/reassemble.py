#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
krnwaller 构建产物重组工具

由于网络限制，exe 文件被分成 512KB 的块上传到 GitHub 仓库。
本脚本会从仓库下载所有分块，base64 解码后拼接成完整的 exe 文件。

用法:
    python reassemble.py              # 下载 GUI 版 (krnwaller.exe) 和 CLI 版 (krnwallerCLI.exe)
    python reassemble.py --cli        # 只下载 CLI 版
    python reassemble.py --gui        # 只下载 GUI 版
    python reassemble.py --check      # 只检查 manifest，不下载
"""
import urllib.request
import json
import base64
import os
import sys
import time

REPO_RAW = "https://raw.githubusercontent.com/Emccore/krnwaller/main"
API = "https://api.github.com/repos/Emccore/krnwaller/contents"

TARGETS = {
    "gui": {
        "name": "krnwaller.exe (GUI, 73 MB)",
        "manifest_path": "dist/krnwaller.exe.manifest.json",
        "chunk_prefix": "dist/krnwaller.exe.part",
        "output": "krnwaller.exe",
    },
    "cli": {
        "name": "krnwallerCLI.exe (CLI, 17 MB)",
        "manifest_path": "dist/krnwallerCLI_v1.manifest.json",
        "chunk_prefix": "dist/krnwallerCLI_v1.part",
        "output": "krnwallerCLI.exe",
    },
}


def fetch(url, timeout=60):
    """下载 URL 内容，返回 bytes"""
    req = urllib.request.Request(url, headers={"User-Agent": "krnwaller-reassemble/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_json(url):
    """下载 JSON 并解析"""
    return json.loads(fetch(url).decode())


def fetch_text(url):
    """下载文本内容"""
    return fetch(url).decode()


def download_target(key, target):
    """下载并重组一个目标文件"""
    print(f"\n=== {target['name']} ===")

    # 1) 下载 manifest
    manifest_url = f"{REPO_RAW}/{target['manifest_path']}"
    print(f"  下载 manifest ...")
    try:
        manifest = fetch_json(manifest_url)
    except Exception as e:
        print(f"  失败: {e}")
        return False

    num_chunks = manifest.get("num_chunks", 0)
    total_size = manifest.get("size", 0)
    print(f"  分块数: {num_chunks}, 总大小: {total_size / 1024 / 1024:.2f} MB")

    # 2) 下载每个分块并拼接
    output_path = target["output"]
    with open(output_path, "wb") as out:
        for i in range(num_chunks):
            chunk_name = f"{target['chunk_prefix']}{i:03d}"
            chunk_url = f"{REPO_RAW}/{chunk_name}"
            try:
                b64_data = fetch_text(chunk_url)
                chunk_data = base64.b64decode(b64_data)
                out.write(chunk_data)
                pct = (i + 1) / num_chunks * 100
                print(f"  [{i + 1}/{num_chunks}] {pct:.0f}%  ({len(chunk_data) / 1024:.0f} KB)", end="\r")
            except Exception as e:
                print(f"\n  分块 {i + 1} 下载失败: {e}")
                return False
            time.sleep(0.1)

    # 3) 验证文件大小
    actual_size = os.path.getsize(output_path)
    if actual_size == total_size:
        print(f"  OK: {output_path} ({actual_size / 1024 / 1024:.2f} MB)         ")
        return True
    else:
        print(f"  警告: 大小不匹配 (期望 {total_size}, 实际 {actual_size})")
        return False


def main():
    import argparse
    p = argparse.ArgumentParser(description="krnwaller 构建产物重组工具")
    p.add_argument("--cli", action="store_true", help="只下载 CLI 版")
    p.add_argument("--gui", action="store_true", help="只下载 GUI 版")
    p.add_argument("--check", action="store_true", help="只检查 manifest")
    args = p.parse_args()

    if args.check:
        for key, t in TARGETS.items():
            url = f"{REPO_RAW}/{t['manifest_path']}"
            try:
                m = fetch_json(url)
                print(f"{t['name']}: {m.get('num_chunks', '?')} 块, {m.get('size', 0) / 1024 / 1024:.2f} MB")
            except Exception as e:
                print(f"{t['name']}: 不可用 ({e})")
        return

    if args.cli:
        targets = {"cli": TARGETS["cli"]}
    elif args.gui:
        targets = {"gui": TARGETS["gui"]}
    else:
        targets = TARGETS

    success = []
    for key, t in targets.items():
        ok = download_target(key, t)
        success.append(ok)

    print("\n=== 结果 ===")
    for (key, t), ok in zip(targets.items(), success):
        status = "OK" if ok else "FAIL"
        print(f"  {t['output']}: {status}")

    if all(success):
        print("\n全部完成！可以直接运行下载的 exe 文件。")
    else:
        print("\n部分失败，请重试。")
        sys.exit(1)


if __name__ == "__main__":
    main()
