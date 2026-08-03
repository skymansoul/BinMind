# 漏洞检测插件系统——抽象基类+发现机制+注册管理，支持自定义检测器扩展

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Type
import importlib
import os
import sys


@dataclass
class PluginMeta:
    name: str
    version: str = "0.1.0"
    author: str = ""
    description: str = ""
    category: str = "general"  # static/dynamic/supply_chain/sandbox
    priority: int = 50


class PluginBase(ABC):
    """漏洞检测插件基类。

    子类实现analyze(binary_path, **kwargs) → List[Dict]返回漏洞发现列表。
    """

    def __init__(self, meta: Optional[PluginMeta] = None):
        self.meta = meta or PluginMeta(name=self.__class__.__name__)
        self._enabled = True

    name = property(lambda self: self.meta.name)

    @property
    def version(self) -> str:
        return self.meta.version

    @property
    def description(self) -> str:
        return self.meta.description

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, v: bool):
        self._enabled = v

    @abstractmethod
    def analyze(self, binary_path: str, **kwargs) -> List[Dict[str, Any]]:
        """对目标二进制执行分析，返回漏洞发现列表。"""
        ...

    def pre_analyze(self, binary_path: str) -> bool:
        """分析前钩子——返回False则跳过本次分析"""
        return os.path.isfile(binary_path)

    def post_analyze(self, binary_path: str, results: List[Dict]) -> List[Dict]:
        """分析后钩子——可对结果做过滤/增强"""
        return results

    def __repr__(self):
        return f"Plugin({self.name} v{self.version})"


# ---- 插件管理器 ----

class PluginManager:
    """插件注册、发现与调度。

    支持:
    - 按类别选择插件执行
    - 按优先级排序
    - 分析前/后钩子
    """

    def __init__(self):
        self._plugins: Dict[str, PluginBase] = {}
        self._by_category: Dict[str, List[str]] = {}

    def register(self, plugin: PluginBase) -> None:
        self._plugins[plugin.name] = plugin
        cat = plugin.meta.category or "general"
        self._by_category.setdefault(cat, []).append(plugin.name)

    def unregister(self, name: str) -> bool:
        if name in self._plugins:
            p = self._plugins.pop(name)
            for cat in list(self._by_category.keys()):
                self._by_category[cat] = [n for n in self._by_category[cat] if n != name]
            return True
        return False

    def get(self, name: str) -> Optional[PluginBase]:
        return self._plugins.get(name)

    def list_all(self) -> List[PluginBase]:
        return sorted(self._plugins.values(),
                     key=lambda p: (-p.meta.priority, p.name))

    def list_by_category(self, category: str) -> List[PluginBase]:
        names = self._by_category.get(category, [])
        return [self._plugins[n] for n in names if n in self._plugins]

    def run(self, binary_path: str,
            categories: Optional[List[str]] = None,
            **kwargs) -> Dict[str, List[Dict[str, Any]]]:
        """按类别运行所有启用的插件。

        返回 {plugin_name: [vuln_dicts]}。
        """
        results = {}
        if categories:
            plugins = []
            for cat in categories:
                plugins.extend(self.list_by_category(cat))
        else:
            plugins = self.list_all()

        for p in plugins:
            if not p.enabled:
                continue
            if not p.pre_analyze(binary_path):
                continue
            findings = p.analyze(binary_path, **kwargs)
            findings = p.post_analyze(binary_path, findings)
            results[p.name] = findings
        return results

    def plugin_count(self) -> int:
        return len(self._plugins)


# ---- 插件发现 ----

def discover_plugins(plugin_dir: str) -> List[PluginBase]:
    """从指定目录发现所有PluginBase子类。

    扫描目录中.py文件，导入并查找继承PluginBase的类，
    实例化后返回列表。
    """
    plugins = []
    if not plugin_dir or not os.path.isdir(plugin_dir):
        return plugins

    # 添加目录到sys.path确保可导入
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)

    for fname in sorted(os.listdir(plugin_dir)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        mod_name = fname[:-3]
        try:
            mod = importlib.import_module(mod_name)
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (isinstance(attr, type) and
                        issubclass(attr, PluginBase) and
                        attr is not PluginBase):
                    instance = attr()
                    plugins.append(instance)
        except Exception:
            continue

    return plugins


# ---- 内置插件示例 ----

class BufferOverflowDetector(PluginBase):
    """基于objdump反汇编中危险函数调用检测缓冲区溢出"""

    def __init__(self):
        super().__init__(PluginMeta(
            name="buffer_overflow_detector",
            version="1.0.0",
            description="Detect buffer overflow via dangerous function calls",
            category="static",
            priority=90,
        ))

    def analyze(self, binary_path: str, **kwargs) -> List[Dict[str, Any]]:
        dangerous = {"strcpy": "CWE-120", "strcat": "CWE-120",
                     "sprintf": "CWE-120", "gets": "CWE-242",
                     "scanf": "CWE-120", "memcpy": "CWE-119"}
        findings = []
        try:
            import subprocess
            r = subprocess.run(["objdump", "-d", binary_path],
                             capture_output=True, text=True, timeout=30)
            import re
            for line in r.stdout.split("\n"):
                for func, cwe in dangerous.items():
                    if f"<{func}" in line or f"call.*{func}" in line.lower():
                        m = re.match(r'^\s*([0-9a-fA-F]+):', line)
                        addr = int(m.group(1), 16) if m else 0
                        findings.append({
                            "cve_id": "", "cwe_id": cwe,
                            "type": "buffer_overflow",
                            "function": func, "address": addr,
                            "description": f"Dangerous call to {func}",
                        })
        except Exception:
            pass
        return findings


class FormatStringDetector(PluginBase):
    """检测格式化字符串漏洞"""

    def __init__(self):
        super().__init__(PluginMeta(
            name="format_string_detector",
            version="1.0.0",
            description="Detect format string vulnerabilities",
            category="static",
            priority=85,
        ))

    def analyze(self, binary_path: str, **kwargs) -> List[Dict[str, Any]]:
        findings = []
        try:
            import subprocess, re
            r = subprocess.run(["objdump", "-d", binary_path],
                             capture_output=True, text=True, timeout=30)
            for line in r.stdout.split("\n"):
                if "printf" in line.lower() and "<printf" in line.lower():
                    m = re.match(r'^\s*([0-9a-fA-F]+):', line)
                    addr = int(m.group(1), 16) if m else 0
                    findings.append({
                        "cve_id": "", "cwe_id": "CWE-134",
                        "type": "format_string",
                        "function": "printf", "address": addr,
                        "description": "Potential format string vulnerability (printf)",
                    })
        except Exception:
            pass
        return findings
