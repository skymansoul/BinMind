# 核心模块入口: 导出hooks接口, 按需延迟加载compat子模块
from modules.core.hooks import get_hook_manager, HookManager, HOOK_POINTS, run_hook

# 按名惰性解析: 首次访问时import对应子模块, 分摊初始化成本
_LAZY_EXPORTS = {
    'SubRegTaintState': ('modules.core.compat.subreg_taint', 'SubRegTaintState'),
    'propagate_subreg': ('modules.core.compat.subreg_taint', 'propagate_subreg'),
    'DriftCalibrator': ('modules.core.compat.drift_calibrator', 'DriftCalibrator'),
    'WeightImportanceTracker': ('modules.core.compat.drift_calibrator', 'WeightImportanceTracker'),
    'cfg_entropy_fingerprint': ('modules.core.compat.cfg_entropy_fingerprint', 'cfg_entropy_fingerprint'),
    'fingerprint_similarity': ('modules.core.compat.cfg_entropy_fingerprint', 'fingerprint_similarity'),
}


def __getattr__(name):
    import importlib
    if name in _LAZY_EXPORTS:
        mod_path, attr = _LAZY_EXPORTS[name]
        mod = importlib.import_module(mod_path)
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
