"""
krnwaller 打包与安装脚本
支持源码安装：pip install .
"""

from setuptools import setup, find_packages
from pathlib import Path

ROOT = Path(__file__).parent
README = ROOT / "README.md"
long_description = README.read_text(encoding="utf-8") if README.exists() else ""

setup(
    name="krnwaller",
    version="1.0.0",
    description="高性能软件防火墙 - 多协议深度检测与现代化 UI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="krnwaller Project",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "": ["*.json", "*.md", "*.txt"],
    },
    install_requires=[
        "PyQt5>=5.15.0",
        "PyQtChart>=5.15.0",
    ],
    extras_require={
        "capture": ["scapy>=2.4.5"],
        "pcap": ["pypcap>=1.2.3"],
        "windows": ["pydivert>=2.1.0"],
        "full": ["scapy>=2.4.5", "pypcap>=1.2.3", "pydivert>=2.1.0"],
    },
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "krnwaller=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking :: Firewalls",
    ],
)
