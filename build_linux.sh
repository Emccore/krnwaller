#!/usr/bin/env bash
#
# krnwaller Linux 单文件可执行构建脚本
# 输出 dist/krnwaller
#

set -e

echo "开始构建 Linux 单文件可执行程序..."

# 检查 PyInstaller
if ! command -v pyinstaller &>/dev/null; then
    echo "PyInstaller 未安装，正在安装..."
    pip install pyinstaller
fi

# 清理旧产物
echo "清理旧构建产物..."
rm -rf build dist krnwaller.spec

# 构建单文件
pyinstaller \
    --name=krnwaller \
    --onefile \
    --noconfirm \
    --clean \
    --hidden-import=PyQt5.sip \
    --hidden-import=PyQt5.QtCore \
    --hidden-import=PyQt5.QtGui \
    --hidden-import=PyQt5.QtWidgets \
    --hidden-import=PyQt5.QtChart \
    --hidden-import=core.engine \
    --hidden-import=core.capture \
    --hidden-import=protocols.analyzer \
    --hidden-import=rules.engine \
    --hidden-import=utils.logger \
    --hidden-import=utils.netutils \
    --hidden-import=config.manager \
    --add-data="config:config" \
    main.py

# 复制配置到 dist
mkdir -p dist/config
cp -r config/* dist/config/

if [ -f "dist/krnwaller" ]; then
    SIZE=$(du -h dist/krnwaller | cut -f1)
    echo "构建成功: dist/krnwaller ($SIZE)"
else
    echo "未找到生成的可执行文件，请检查 PyInstaller 输出。"
    exit 1
fi
