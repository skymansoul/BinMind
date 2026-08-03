# modules/ 扁平命名空间懒加载入口
# 解析优先级: compat → 子目录 → _LAZY_MAP
# 设计参考 FastAPI lazy dependency injection
# 目录重组后已同步 _SUBDIR_LIST 与 _LAZY_MAP 内各路径
# _compat_dir 指向 core/compat/，保持兼容层优先查找
# ※ Python import 走 sys.modules → sys.meta_path 链路，
# __getattr__ (PEP 562) 无法拦截 from modules.xxx import Y，
# 故通过 MetaPathFinder 在 meta_path 层捕获懒加载请求。
import importlib
import importlib.abc
import importlib.machinery
import os
import sys

_LAZY_MAP = {
    # 数据层
    'DataDB': ('modules.data.src.db', 'DataDB'),
    'DataConfig': ('modules.data.src.config', 'DataConfig'),
    'Pipeline': ('modules.data.src.pipeline', 'Pipeline'),
    'SimHashDedup': ('modules.data.src.dedup', 'SimHashDedup'),
    'compress': ('modules.data.src.compression', 'compress'),
    'DataExporter': ('modules.data.src.export', 'DataExporter'),
    'CacheRouter': ('modules.data.src.cache', 'CacheRouter'),
    'MetricsRegistry': ('modules.data.src.metrics', 'MetricsRegistry'),
    # 密码学检测
    'CryptoDetector': ('modules.crypto.src.crypto_detector', 'CryptoDetector'),
    'shannon_entropy': ('modules.crypto.src.utils', 'shannon_entropy'),
    # 二进制分析 — 路径已随目录重组更新
    'Arch': ('modules.analysis.static.binary_analysis.src.utils.constants', 'Arch'),
    'BinaryFormat': ('modules.analysis.static.binary_analysis.src.utils.constants', 'BinaryFormat'),
    # 漏洞利用
    'ExploitAdapter': ('modules.exploit.exploit_adapter', 'ExploitAdapter'),
    'ROPChainBuilder': ('modules.exploit.src.core.primitives', 'ROPChainBuilder'),
    # 漏洞检测 — 路径已随目录重组更新
    'SBOMGenerator': ('modules.vuln.detection.supply_chain', 'SoftwareBillOfMaterials'),
    'VulnLifecycleAPI': ('modules.vuln.detection.vuln_lifecycle_api', 'VulnLifecycleAPI'),
    # 符号执行 — 路径已随目录重组更新
    'SymbolicExecutor': ('modules.analysis.symbolic.symbolic_exe', 'SymbolicExecutor'),
    # Fuzz 引擎
    'Seed': ('modules.fuzzing.src.core', 'Seed'),
    'EdgeCoverage': ('modules.fuzzing.src.coverage', 'EdgeCoverage'),
}

# compat 目录已迁至 core/compat/，路径常量同步更新
_compat_dir = os.path.join(os.path.dirname(__file__), 'core', 'compat')
_HAS_COMPAT = os.path.isdir(_compat_dir)

# 子目录搜索列表：扁平搜 subdir/{name}.py
# 嵌套子目录需逐条写出完整相对路径
_SUBDIR_LIST = (
    'core',                           # hooks
    'stubs',                          # re-export 桩
    'utils',                          # 运维工具集
    'output',                         # 报告与 Web API
    'vuln',                           # vuln_db、vuln_dedup_merger
    'vuln/detection',                 # vuln_detection 内部
    'info',                           # info_collect
    'info/info_collection',           # info_collection 内部
    'analysis/static',                # static_analysis
    'analysis/static/binary_analysis',# binary_analysis 内部
    'analysis/static/tools',          # analysis_tools
    'analysis/dynamic',               # crash_analysis、dynamic_taint
    'analysis/dynamic/engine',        # dynamic_analysis 内部
    'analysis/symbolic',              # symbolic_exe 及内部文件
    'analysis/decompiler',            # decomp_ai
    'analysis/deobfuscation',         # 去混淆内部
    'platform/firmware',              # 固件分析
    'platform/kernel',                # 内核分析
    'platform/hardware',              # 硬件安全
    'platform/mobile',                # 移动端
    'platform/malware',               # 恶意软件
    'platform/smart_contract',        # 智能合约
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
    """按 compat → 子目录 → _LAZY_MAP 次序查找并加载模块，
    返回模块对象或 None。
    调用方负责将返回的 module 注入 sys.modules。
    """
    _modules_dir = os.path.dirname(__file__)

    # 第一优先级：compat 兼容层
    if _HAS_COMPAT:
        compat_path = os.path.join(_compat_dir, f"{name}.py")
        if os.path.isfile(compat_path):
            spec = importlib.util.spec_from_file_location(f"compat.{name}", compat_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    # 第二优先级：遍历子目录
    for subdir in _SUBDIR_LIST:
        sub_path = os.path.join(_modules_dir, subdir, f"{name}.py")
        if os.path.isfile(sub_path):
            spec = importlib.util.spec_from_file_location(f"{subdir.replace('/', '.')}.{name}", sub_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    # 第三优先级：_LAZY_MAP 懒加载映射
    if name in _LAZY_MAP:
        mod_path, attr = _LAZY_MAP[name]
        mod = importlib.import_module(mod_path)
        return mod

    return None


# --- sys.meta_path finder --------------------------------------------------
# __getattr__ (PEP 562) 仅在 getattr(obj, name) 时触发，
# Python import 语句走 sys.modules → sys.meta_path → 文件系统路径，
# 不经过 __getattr__。必须用 MetaPathFinder 拦截 import 请求。

class _FlatLoader(importlib.abc.Loader):
    """空 loader：模块实例已由 _resolve_module exec_module 完成，
    此处仅返回 sys.modules 中已存在的对象。"""
    def create_module(self, spec):
        return sys.modules.get(spec.name)

    def exec_module(self, module):
        pass


class _FlatFinder(importlib.abc.MetaPathFinder):
    """拦截 modules.{name} 形式的 import 语句。
    限定处理单层扁平查找（如 modules.hooks），嵌套子包
    （如 modules.core.compat）交还常规 import 机制通过
    __init__.py 解析。"""

    def find_spec(self, fullname, path, target=None):
        # 仅处理 modules.xxx 单层，xxx 不含 '.'
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


# --- __getattr__ 保留：支持 getattr(modules, 'hooks') 直接属性访问 ---
def __getattr__(name):
    mod = _resolve_module(name)
    if mod is not None:
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
