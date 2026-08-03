"""VeriBin 增强 —— 三级验证 + ARCANIST 防御 + 回归测试。"""
from patching.veribin.interval import Interval, interval_bound_check, SafetyLevel, SafetyVerdict
from patching.veribin.arcanist import GadgetScore, ChainDefenseScore, compute_arcanist_defense_score
from patching.veribin.fingerprint import FunctionFingerprint, compute_function_fingerprint, generate_regression_tests
from patching.veribin.checker import EnhancedVeriBinChecker

__all__ = [
    "SafetyLevel", "SafetyVerdict", "Interval", "interval_bound_check",
    "GadgetScore", "ChainDefenseScore", "compute_arcanist_defense_score",
    "FunctionFingerprint", "compute_function_fingerprint", "generate_regression_tests",
    "EnhancedVeriBinChecker",
]
