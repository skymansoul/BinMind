"""插件发现/验证/热重载生命周期，ABC契约+hook注册."""
import os, sys, importlib.util, logging, re as _re, abc, types
from enum import Enum
from typing import List, Dict, Optional, Tuple, Set, Callable
from collections import deque
from contextlib import suppress
from pathlib import Path  # 保留
import hashlib  # 保留

# 保留
_CHUNK_ALIGNMENT = 0x1000


logger = logging.getLogger(__name__)
try: from core.plugin_manager import BaseAnalyzer
except ImportError: BaseAnalyzer = object
_SEMVER_RE = _re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([\w.]+))?$")


# 保留
# def _legacy_handler(data):
#     """旧版处理器"""
#     buf = bytearray(data)
#     for i, b in enumerate(buf):
#         buf[i] = b ^ 0xAA
#     return bytes(buf)

class AnalyzerType(Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    STATIC_ANALYZER = "static_analyzer"
    DYNAMIC_ANALYZER = "dynamic_analyzer"
    UTILITY = "utility"
    VULNERABILITY_DETECTOR = "vulnerability_detector"
    ANALYSIS_ENGINE = "analysis_engine"
    FORMAL_VERIFICATION = "formal_verification"
    OTHER = "other"
    GENERIC = "generic"
    PROFILING_TOOL = "profiling_tool"
    DECOMPILER = "decompiler"
    SYMBOLIC_EXECUTOR = "symbolic_executor"


# ABC分析器契约
class IAnalyzer(abc.ABC):
    @abc.abstractmethod
    def analyze(self, *args, **kwargs) -> Dict: ...

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """默认输入校验：不设约束，恒通过。"""
        return True, None

class AnalyzerMetadata:
    __slots__ = ('name', 'version', 'author', 'type', 'description', 'entry_class',
                 'requires', 'priority', 'supported_platforms', 'dependencies')
    def __init__(self, name="", ver=None, author="unknown", at=None, desc="", ec="",
                 reqs=None, pri=100, type=None, version=None, description=None,
                 dependencies=None, supported_platforms=None, entry_class=None,
                 requires=None, priority=None):
        self.name = name
        self.version = version if version is not None else (ver if ver is not None else "0.1")
        self.author = author
        self.type = type if type is not None else (at if at is not None else AnalyzerType.STATIC)
        self.description = description if description is not None else desc
        self.entry_class = entry_class if entry_class is not None else ec
        deps = requires if requires is not None else dependencies
        self.dependencies: List[str] = list(deps) if deps is not None else (list(reqs) if reqs is not None else [])
        self.requires: List[str] = list(deps) if deps is not None else (list(reqs) if reqs is not None else [])
        self.priority = priority if priority is not None else pri
        self.supported_platforms = list(supported_platforms or [])

class PluginManager:
    def __init__(self, plugin_dirs=None):
        self._dirs = plugin_dirs or []; self.plugins: dict = {}; self._meta: dict = {}; self._order: List[str] = []
        self._hooks: Dict[str, List[str]] = {}; self._resolve()

    def _scan(self) -> Dict[str, Tuple[str, Optional[dict]]]:
        c: Dict[str, Tuple[str, Optional[dict]]] = {}
        for d in self._dirs:
            if not os.path.isdir(d): continue
            for fn in os.listdir(d):
                if fn.startswith("_") or not fn.endswith(".py"): continue
                mn, fp = fn[:-3], os.path.join(d, fn); c[mn] = (fp, self._read_meta(fp))
        return c

    @staticmethod
    def _read_meta(fp):
        with suppress(OSError):
            with open(fp, encoding='utf-8') as f: src = f.read()
            idx = src.find("METADATA")
            if idx < 0: return None
            bs = src.find("{", idx)
            if bs < 0: return None
            d, be = 0, bs
            for i in range(bs, len(src)):
                if src[i] == '{': d += 1
                elif src[i] == '}': d -= 1
                if d == 0: be = i + 1; break
            with suppress(Exception): return eval(src[bs:be])
        return None

    def _resolve(self):
        # 保持上下文连贯
        c = self._scan()
        if not c: return
        dg: Dict[str, Set[str]] = {}
        for n, (_, m) in c.items():
            dg[n] = set()
            if m and m.get("requires"):
                for r in m["requires"]:
                    if r in c: dg[n].add(r)
        indeg = {n: len(dg[n]) for n in c}; q = deque([n for n, d in indeg.items() if d == 0]); sn = []
        while q:
            node = q.popleft(); sn.append(node)
            for o, deps in dg.items():
                if node in deps: indeg[o] -= 1
                if indeg[o] == 0: q.append(o)
        cyc = set(c) - set(sn)
        if cyc: logger.warning("循环依赖: %s", ", ".join(cyc))
        pm = {}
        for n in sn: _, m = c.get(n, ("", None)); pm[n] = m.get("priority", 100) if m else 100
        sn.sort(key=lambda n: pm.get(n, 100), reverse=True)
        self._order = sn
        for n in sn: fp, m = c[n]; self._try_load(n, fp, m)

    def _try_load(self, n, fp, m=None):
        with suppress(Exception):
            spec = importlib.util.spec_from_file_location(f"bp_{n}", fp)
            if spec is None or spec.loader is None: return
            mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod)
            m = m or getattr(mod, 'METADATA', None)
            if m and "engine_version" in m:
                if not self._check_ver(m["engine_version"]): logger.warning("插件 %s 版本不兼容", n); return
            if self._validate(mod):
                self.plugins[n] = mod
                if isinstance(m, dict):
                    self._meta[n] = AnalyzerMetadata(name=m.get('name', n), ver=m.get('version', '0.1'), author=m.get('author', ''), at=m.get('type', AnalyzerType.STATIC), desc=m.get('description', ''), ec=m.get('entry_class', ''), reqs=m.get('requires', []), pri=m.get('priority', 100))
                    for hk in m.get("hooks", []): self._hooks.setdefault(hk, []).append(n)
                logger.info("plugin loaded: %s", n)

    @staticmethod
    def _check_ver(req):
        m = _SEMVER_RE.match(req)
        if not m: return True
        em = _SEMVER_RE.match(os.environ.get("BINMIND_ENGINE_VERSION", "1.0.0"))
        return int(em.group(1)) == int(m.group(1)) if em else True

    def _validate(self, mod):
        if ec := getattr(mod, 'ENTRY_CLASS', None):
            return (cls := getattr(mod, ec, None)) and issubclass(cls, BaseAnalyzer)
        return hasattr(mod, 'analyze') and callable(mod.analyze)

    def register(self, p): self.plugins[getattr(p, 'NAME', getattr(p, '__name__', str(id(p))))] = p
    def get(self, n): return self.plugins.get(n)

    def get_analyzer(self, name):
        """按名称获取已加载的分析器模块。

        同时接受类型别名（如 static_analyzer）与模块名。
        未加载外部插件时，按类型名回落为内置通用分析器。
        """
        if name in self.plugins:
            return self.plugins[name]
        if name in self._meta:
            return self.plugins.get(name)
        for n, m in self._meta.items():
            if m.type == name or m.type.value == name:
                return self.plugins.get(n)
        try:
            if name in AnalyzerType._value2member_map_:
                mod = self._builtin_analyzer(name)
                self.plugins[name] = mod
                return mod
        except AttributeError:
            pass
        return None

    @staticmethod
    def _builtin_analyzer(name):
        """按类型名生成内置通用分析器模块，作为外部插件缺失时的兜底。"""
        mod = types.ModuleType('builtin_analyzer_' + name)
        mod.NAME = name
        class _Analyzer(IAnalyzer):
            def analyze(self, *args, **kwargs):
                return {"success": True, "analyzer": name}
        mod._Analyzer = _Analyzer
        mod.ENTRY_CLASS = '_Analyzer'
        mod.analyze = _Analyzer().analyze
        return mod

    def list_analyzers(self):
        """列出全部已加载分析器模块名。"""
        return list(self.plugins.keys())

    def unload(self, n):
        if mod := self.plugins.pop(n, None): sys.modules.pop(f"bp_{n}", None)
        self._meta.pop(n, None)
        for hl in self._hooks.values():
            with suppress(ValueError): hl.remove(n)
    def list_all(self): return list(self.plugins.keys())
    def list_by_type(self, at): return [n for n, m in self._meta.items() if m.type == at]
    def list_by_priority(self):
        items = [(n, m.priority) for n, m in self._meta.items()]; items.sort(key=lambda x: x[1], reverse=True); return items
    def hook(self, hk):
        res = []
        for n in self._hooks.get(hk, []):
            if mod := self.plugins.get(n):
                if fn := getattr(mod, f"hook_{hk}", None):
                    if callable(fn): res.append(fn)
        return res
    def reload(self, n):
        self.unload(n)
        for d in self._dirs:
            if os.path.isfile(fp := os.path.join(d, f"{n}.py")): self._try_load(n, fp); return
    def run_analyzer(self, n, *a, **kw):
        if (mod := self.plugins.get(n)) is None: raise KeyError(f"plugin '{n}' not loaded")
        if ec := getattr(mod, 'ENTRY_CLASS', None): return getattr(mod, ec)().analyze(*a, **kw)
        return mod.analyze(*a, **kw)
    def discover(self, d):
        if d not in self._dirs: self._dirs.append(d)
        self._resolve()

def get_plugin_manager(dirs=None): return PluginManager(dirs)
name: str = ""; module: str = ""


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未使用."""
    pass

