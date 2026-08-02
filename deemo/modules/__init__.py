# 2026-07-14
# modules/ — BinMind flat-namespace lazy loader
# 按 compat → 子目录的优先级解析 import 请求
# 参考 FastAPI 的 lazy dependency injection 模式
import importlib
import os

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
    # binary analysis
    'Arch': ('binary_analysis.src.utils.constants', 'Arch'),
    'BinaryFormat': ('binary_analysis.src.utils.constants', 'BinaryFormat'),
    # exploit
    'ExploitAdapter': ('exploit.exploit_adapter', 'ExploitAdapter'),
    'ROPChainBuilder': ('exploit.src.core.primitives', 'ROPChainBuilder'),
    # vuln detection
    'SBOMGenerator': ('vuln_detection.supply_chain', 'SBOMGenerator'),
    'VulnLifecycleAPI': ('vuln_detection.vuln_lifecycle_api', 'VulnLifecycleAPI'),
    # symbolic
    'SymbolicExecutor': ('symbolic.symbolic_exe', 'SymbolicExecutor'),
    # fuzzing
    'Seed': ('fuzzing.src.core', 'Seed'),
    'EdgeCoverage': ('fuzzing.src.coverage', 'EdgeCoverage'),
}

_compat_dir = os.path.join(os.path.dirname(__file__), 'compat')
_HAS_COMPAT = os.path.isdir(_compat_dir)


def __getattr__(name):
    # 优先查 compat 层
    if _HAS_COMPAT:
        compat_path = os.path.join(_compat_dir, f"{name}.py")
        if os.path.isfile(compat_path):
            spec = importlib.util.spec_from_file_location(f"compat.{name}", compat_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    # 次查子目录
    for subdir in ('vuln_detection', 'binary_analysis', 'ai_ml', 'analysis_tools',
                   'crypto', 'deobfuscation', 'dynamic_analysis', 'exploit',
                   'firmware', 'fuzzing', 'hardware', 'info_collection',
                   'kernel', 'malware', 'mobile', 'multimodal', 'network',
                   'patching', 'project', 'smart_contract', 'symbolic',
                   'testing', 'data', 'distributed'):
        sub_path = os.path.join(os.path.dirname(__file__), subdir, f"{name}.py")
        if os.path.isfile(sub_path):
            spec = importlib.util.spec_from_file_location(f"{subdir}.{name}", sub_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    # 最后查懒加载映射
    if name in _LAZY_MAP:
        mod_path, attr = _LAZY_MAP[name]
        mod = importlib.import_module(mod_path)
        return getattr(mod, attr)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
