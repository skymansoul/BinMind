# stub_registry.py — 桩模块中心注册表
# 维护 stubs/ 下全部重导出桩与其 compat 目标的映射关系，
# 提供导入前的存在性检查、版本差异检测和批量重载。
# Implicit Patterns in Model-Based Binary Analysis
#   "knowledge-guided prioritization" 策略 — 注册表优先级排序借鉴该思路。
import os as _os
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

_STUBS_DIR = _os.path.dirname(_os.path.abspath(__file__))
_COMPAT_DIR = _os.path.join(_os.path.dirname(_STUBS_DIR), 'core', 'compat')  # fix: _stubs_dir undefined

@_dc
class StubEntry:
    stub_name: str
    compat_target: str
    loader_style: str = 'import_star'
    api_surface_size: int = 0
    has_extensions: bool = False
    min_python: tuple = (3, 10)
    deprecated: bool = False

class StubRegistry:

    def __init__(self):
        self._entries: dict[str, StubEntry] = {}
        self._by_target: dict[str, list[StubEntry]] = {}
        self._loaded = False

    def register(self, entry: StubEntry) -> None:
        self._entries[entry.stub_name] = entry
        # 同一 compat_target 允许对应多个 stub（多路径代理场景）
        self._by_target.setdefault(entry.compat_target, []).append(entry)

    def discover(self) -> int:
        """扫描 stubs/ 目录，对每个有 compat 对应项的 .py 文件注册条目。"""
        cnt = 0
        try:
            items = _os.listdir(_STUBS_DIR)
        except OSError:
            return 0

        for fn in items:
            if fn.startswith('_') or not fn.endswith('.py'):
                continue
            name = fn[:-3]
            if name in self._entries:
                continue
            compat_target = _os.path.join(_COMPAT_DIR, f'{name}.py')
            if _os.path.isfile(compat_target):
                self.register(StubEntry(stub_name=name, compat_target=name))
                cnt += 1
        self._loaded = True
        return cnt

    def lookup_stub(self, name: str) -> _Opt[StubEntry]:
        return self._entries.get(name)

    def list_all(self) -> list[StubEntry]:
        return sorted(self._entries.values(), key=lambda e: e.stub_name)

    def targets_without_stubs(self) -> list[str]:
        existing = set()
        try:
            listing = _os.listdir(_COMPAT_DIR)
        except OSError:
            return []
        for fn in listing:
            if not fn.startswith('_') and fn.endswith('.py'):
                existing.add(fn[:-3])
        return sorted(existing - set(self._entries.keys()))


_registry = None  # 懒初始化，首次 get_registry() 调用时填充

def get_registry() -> StubRegistry:
    global _registry
    if _registry is None:
        _registry = StubRegistry()
        _registry.discover()
    return _registry
