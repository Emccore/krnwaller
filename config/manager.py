"""
配置管理模块
负责加载、验证和持久化防火墙配置
"""

import json
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("krnwaller.config")

DEFAULT_CONFIG = {
    "version":            "1.0",
    "engine": {
        "worker_threads":     4,
        "queue_size":         20000,
        "max_connections":    65536,
        "enable_state_track": True,
    },
    "protection": {
        "syn_flood": {
            "enabled":   True,
            "threshold": 200,
            "window":    1.0,
            "block_duration": 300,
        },
        "port_scan": {
            "enabled":         True,
            "port_threshold":  20,
            "window":          10.0,
            "block_duration":  600,
        },
        "arp_spoof": {
            "enabled": True,
        },
        "icmp_flood": {
            "enabled":   True,
            "threshold": 500,
            "window":    1.0,
        },
    },
    "logging": {
        "level":     "INFO",
        "log_dir":   "logs",
        "keep_days": 30,
        "max_size_mb": 50,
    },
    "network": {
        "interfaces": [],
        "promiscuous": False,
    },
    "ui": {
        "theme":           "dark",
        "language":        "zh_CN",
        "minimize_to_tray": True,
    },
}


class ConfigManager:
    """配置管理器"""

    def __init__(self, config_dir: str = "config"):
        self._config_dir  = Path(config_dir)
        self._config_dir.mkdir(exist_ok=True)
        self._config_file = self._config_dir / "firewall.json"
        self._config:     Dict = {}
        self._load()

    def _load(self):
        if self._config_file.exists():
            try:
                with open(self._config_file, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                self._config = self._merge(DEFAULT_CONFIG, saved)
                logger.info(f"配置已加载: {self._config_file}")
            except Exception as e:
                logger.error(f"加载配置失败: {e}，使用默认配置")
                self._config = dict(DEFAULT_CONFIG)
        else:
            self._config = dict(DEFAULT_CONFIG)
            self._save()

    def _merge(self, base: Dict, override: Dict) -> Dict:
        """递归合并配置，override 覆盖 base"""
        result = dict(base)
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._merge(result[k], v)
            else:
                result[k] = v
        return result

    def _save(self):
        try:
            with open(self._config_file, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存配置失败: {e}")

    def get(self, key: str, default=None) -> Any:
        """支持点号路径：如 get('engine.worker_threads')"""
        parts = key.split(".")
        obj   = self._config
        for p in parts:
            if isinstance(obj, dict) and p in obj:
                obj = obj[p]
            else:
                return default
        return obj

    def set(self, key: str, value: Any):
        parts = key.split(".")
        obj   = self._config
        for p in parts[:-1]:
            if p not in obj or not isinstance(obj[p], dict):
                obj[p] = {}
            obj = obj[p]
        obj[parts[-1]] = value
        self._save()

    def get_engine_config(self) -> Dict:
        return self._config.get("engine", {})

    def get_protection_config(self) -> Dict:
        return self._config.get("protection", {})

    def get_logging_config(self) -> Dict:
        return self._config.get("logging", {})

    def update_section(self, section: str, data: Dict):
        if section in self._config and isinstance(self._config[section], dict):
            self._config[section].update(data)
        else:
            self._config[section] = data
        self._save()
        logger.info(f"配置节 [{section}] 已更新")

    @property
    def raw(self) -> Dict:
        return self._config
