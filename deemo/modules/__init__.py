# 2026-07-14
# modules/ — BinMind flat-namespace lazy loader
# 按 compat → 子目录的优先级解析 import 请求
# 参考 FastAPI 的 lazy dependency injection 模式
# 2026-08-02: 目录重组后更新子目录搜索列表与 _LAZY_MAP 路径
# _compat_dir 指向 core/compat/，保留兼容层优先解析的原有逻辑
# 引入 sys.meta_path finder: __getattr__ 只能拦截 getattr(obj, name)，
# 但 Python import 语句走 sys.modules → sys.meta_path 链路，
# 必须用 MetaPathFinder 才能在 from modules.xxx import Y 时命中懒加载。
import importlib
import importlib.abc
import importlib.machinery
import os
import sys

_LAZY_MAP = {
    # data layer
    'DataDB': ('data.src.db', 'DataDB'),
    'DataConfig': ('data.src.config', 'DataConfig'),
    'Pipeline': ('data.src.pipeline', 'Pipeline'),
    'SimHashDedup': ('data.src.dedup', 'SimHashDedup'),
    'compress': ('data.src.compression', 'compress'),
    'DataExporter': ('data.src.export', 'DataExporter'),
    'CacheRouter': ('data.src.cache', 'CacheRouter'),
    'MetricsRegistry': ('data.src.metrics', 'MetricsRegistry'),
    # crypto
    'CryptoDetector': ('crypto.src.crypto_detector', 'CryptoDetector'),
    'shannon_entropy': ('crypto.src.utils', 'shannon_entropy'),
    # binary analysis — 路径随目录重组更新
    'Arch': ('analysis.static.binary_analysis.src.utils.constants', 'Arch'),
    'BinaryFormat': ('analysis.static.binary_analysis.src.utils.constants', 'BinaryFormat'),
    # exploit
    'ExploitAdapter': ('exploit.exploit_adapter', 'ExploitAdapter'),
    'ROPChainBuilder': ('exploit.src.core.primitives', 'ROPChainBuilder'),
    # vuln detection — 路径随目录重组更新
    'SBOMGenerator': ('vuln.detection.supply_chain', 'SBOMGenerator'),
    'VulnLifecycleAPI': ('vuln.detection.vuln_lifecycle_api', 'VulnLifecycleAPI'),
    # symbolic — 路径随目录重组更新
    'SymbolicExecutor': ('analysis.symbolic.symbolic_exe', 'SymbolicExecutor'),
    # fuzzing
    'Seed': ('fuzzing.src.core', 'Seed'),
    'EdgeCoverage': ('fuzzing.src.coverage', 'EdgeCoverage'),
}

# compat 目录已迁入 core/compat/，更新路径以保持兼容层优先解析
_compat_dir = os.path.join(os.path.dirname(__file__), 'core', 'compat')
_HAS_COMPAT = os.path.isdir(_compat_dir)

# 子目录搜索列表 — 扁平搜索一层: subdir/{name}.py
# 嵌套子目录需显式列出完整路径
_SUBDIR_LIST = (
    'core',                           # hooks
    'stubs',                          # re-export 桩
    'utils',                          # 运维工具
    'output',                         # 报告与 Web API
    'vuln',                           # vuln_db, vuln_dedup_merger
    'vuln/detection',                 # vuln_detection 内部文件
    'info',                           # info_collect
    'info/info_collection',           # info_collection 内部文件
    'analysis/static',                # static_analysis
    'analysis/static/binary_analysis',# binary_analysis 内部文件
    'analysis/static/tools',          # analysis_tools 内部文件
    'analysis/dynamic',               # crash_analysis, dynamic_taint
    'analysis/dynamic/engine',        # dynamic_analysis 内部文件
    'analysis/symbolic',              # symbolic_exe + 内部文件
    'analysis/decompiler',            # decomp_ai
    'analysis/deobfuscation',         # deobfuscation 内部文件
    'platform/firmware',              # 固件分析
    'platform/kernel',                # 内核分析
    'platform/hardware',              # 硬件安全
    'platform/mobile',                # 移动端分析
    'platform/malware',               # 恶意软件分析
    'platform/smart_contract',        # 智能合约分析
    'ai_ml',                          # AI/ML 模型
    'crypto',                         # 密码学分析
    'data',                           # 数据层
    'distributed',                    # 分布式计算
    'exploit',                        # 漏洞利用
    'fuzzing',                        # Fuzz 引擎
    'multimodal',                     # 多模态分析
    'network',                        # 网络分析
    'patching',                       # 自动修补
    'project',                        # 项目管理
    'testing',                        # 测试框架
)


def _resolve_module(name):
    """按 compat → 子目录 → _LAZY_MAP 顺序查找并加载模块。
    返回 (module, spec_name) 或 None。
    调用方负责将 module 注册到 sys.modules。
    """
    _modules_dir = os.path.dirname(__file__)

    # 优先查 compat 层
    if _HAS_COMPAT:
        compat_path = os.path.join(_compat_dir, f"{name}.py")
        if os.path.isfile(compat_path):
            spec = importlib.util.spec_from_file_location(f"compat.{name}", compat_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    # 次查子目录
    for subdir in _SUBDIR_LIST:
        sub_path = os.path.join(_modules_dir, subdir, f"{name}.py")
        if os.path.isfile(sub_path):
            spec = importlib.util.spec_from_file_location(f"{subdir.replace('/', '.')}.{name}", sub_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    # 最后查懒加载映射
    if name in _LAZY_MAP:
        mod_path, attr = _LAZY_MAP[name]
        mod = importlib.import_module(mod_path)
        return mod

    return None


# --- sys.meta_path finder --------------------------------------------------
# __getattr__ (PEP 562) 仅在 getattr(obj, name) 时触发，
# Python 的 import 语句走 sys.modules → sys.meta_path → 文件系统路径 链路，
# 不经过 __getattr__。必须用 MetaPathFinder 拦截 import 语句。

class _FlatLoader(importlib.abc.Loader):
    """空 loader: 模块已在 _resolve_module 中 exec_module，
    此处仅返回 sys.modules 中已注册的对象。"""
    def create_module(self, spec):
        return sys.modules.get(spec.name)

    def exec_module(self, module):
        pass


class _FlatFinder(importlib.abc.MetaPathFinder):
    """拦截 modules.{name} 形式的 import 语句。
    仅处理单层扁平查找（如 modules.hooks），嵌套子包（如 modules.core.compat）
    由 Python 常规 import 机制通过 __init__.py 解析。"""

    def find_spec(self, fullname, path, target=None):
        # 仅处理 modules.xxx 且 xxx 不含 '.'（单层扁平命名空间）
        if not fullname.startswith('modules.'):
            return None
        if fullname.count('.') != 1:
            return None
        if fullname in sys.modules:
            return None

        name = fullname.split('.', 1)[1]
        mod = _resolve_module(name)
        if mod is None:
            return None

        sys.modules[fullname] = mod
        return importlib.machinery.ModuleSpec(fullname, _FlatLoader(), origin=getattr(mod, '__file__', None))


sys.meta_path.insert(0, _FlatFinder())


# --- __getattr__ 保留: 支持 getattr(modules, 'hooks') 直接属性访问 ---
def __getattr__(name):
    mod = _resolve_module(name)
    if mod is not None:
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
