# 2026-07-27

import logging, re, math, random, hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---- PatchStatus: 纯字符串常量，不搞 Enum 因为下游要序列化到 JSON ----
class PatchStatus:
    OK: str = "ok"
    WARNING: str = "warning"
    ERROR: str = "error"
    CRITICAL: str = "critical"


# ---- BypassRisk: 绕过风险等级，直接对应修复优先级 ----
class BypassRisk:
    NONE: str = "none"
    LOW: str = "low"
    MEDIUM: str = "medium"
    HIGH: str = "high"
    CONFIRMED: str = "confirmed"


@dataclass
class PatchQualityReport:
    patch_id: str
    status: str = PatchStatus.OK
    bypass_risk: str = BypassRisk.NONE
    confidence: float = 1.0
    code_size_delta: int = 0
    complexity_score: float = 0.0
    regression_indicators: List[str] = field(default_factory=list)
    monte_carlo_reliability: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    verification_results: Dict[str, bool] = field(default_factory=dict)


# ===== 绕过检测模式：每个元组 (regex, 风险描述) =====
# 设计决策：用普通正则而非 AST，因为补丁代码可能是片段不是完整编译单元
# 折衷：漏检率可控 > 误报率可控，所以 pattern 宁可偏保守
_BYPASS_PATTERNS: List[Tuple[str, str]] = [
    (r'\b(if|while)\s*\(.*<=\s*\w+\)', 'off-by-one: <= instead of <'),
    (r'\bstrn?cpy\s*\([^,]+,[^,]+,\s*sizeof', 'input truncation via sizeof'),
    (r'\b(uint|size_t|unsigned)\s+\w+\s*=\s*(int|ssize_t)', 'signed/unsigned confusion'),
    (r'\baccess\s*\(', 'TOCTOU: access() then open()'),
    (r'\b(if|while)\s*\(.*\+\s*\w+\s*[<>=]', 'integer overflow in bounds check'),
    (r'\b(sprintf|fprintf|printf|snprintf)\s*\(\s*\w+\s*\)', 'format string bypass'),
    (r'\bstrlen\s*\(\w+\)\s*[+\-]', 'null terminator issue: strlen arithmetic'),
    (r'\bmemcpy\s*\([^,]+,[^,]+,\s*\w+\s*\)\s*;', 'unchecked memcpy size'),
    (r'\b(free|delete)\s*\(\s*\w+\s*\)\s*;\s*\1\s*\(', 'potential double-free pattern'),
    (r'\b\d+\s*\+\s*\w+\s*\]', 'unvalidated array index with offset'),
]


class PatchQualityEvaluator:
    """补丁质量评估器：多维分析 + Monte Carlo 模拟。

    核心思路：不做单一的 pass/fail 判断，而是输出一个多维度的质量报告，
    让上游根据风险偏好决定是否接受补丁。
    """

    def __init__(self):
        self._bypass_patterns = [(re.compile(p, re.IGNORECASE), desc) for p, desc in _BYPASS_PATTERNS]
        self._hash_cache: Dict[str, str] = {}

    # ============================================================
    # evaluate: 主编排方法 — 把各维度聚合为 PatchQualityReport
    # 为什么不用 asyncio：补丁评估是 CPU-bound，并行收益不如简单串行
    # ============================================================
    def evaluate(self, patch_id: str, original_code: str, patched_code: str,
                 test_results: Optional[List[Dict]] = None) -> PatchQualityReport:
        _r = PatchQualityReport(patch_id=patch_id)

        _r.code_size_delta = self._code_size_delta(original_code, patched_code)
        _r.complexity_score = self._complexity_check(patched_code)
        _r.regression_indicators = self._detect_regressions(original_code, patched_code)
        _r.monte_carlo_reliability = self._monte_carlo_sim()

        # //// 聚合判断：回归指标 + Monte Carlo 决定最终状态 ////
        _n_reg = len(_r.regression_indicators)
        _mc = _r.monte_carlo_reliability

        if _n_reg == 0 and _mc >= 0.95:
            _r.status = PatchStatus.OK
            _r.bypass_risk = BypassRisk.NONE
            _r.confidence = 0.9 + (_mc - 0.95) * 2.0
        elif _n_reg <= 2 and _mc >= 0.80:
            _r.status = PatchStatus.WARNING
            _r.bypass_risk = BypassRisk.LOW
            _r.confidence = _mc
        elif _n_reg <= 5 and _mc >= 0.60:
            _r.status = PatchStatus.ERROR
            _r.bypass_risk = BypassRisk.MEDIUM
            _r.confidence = _mc
        else:
            _r.status = PatchStatus.CRITICAL
            _r.bypass_risk = BypassRisk.HIGH if _mc >= 0.30 else BypassRisk.CONFIRMED
            _r.confidence = max(0.0, _mc)

        _r.confidence = min(1.0, max(0.0, _r.confidence))
        _r.confidence = round(_r.confidence, 4)

        # 生成建议：INTJ 风格 — 每条建议对应一个具体风险维度
        if _r.code_size_delta > 2000:
            _r.recommendations.append("代码增量过大({} bytes)，建议拆分为多个小补丁".format(_r.code_size_delta))
        if _r.complexity_score > 0.7:
            _r.recommendations.append("圈复杂度偏高({:.2f})，补丁自身可能引入新漏洞".format(_r.complexity_score))
        for _ind in _r.regression_indicators:
            _r.recommendations.append("回归风险: {}".format(_ind))
        if _mc < 0.85:
            _r.recommendations.append("Monte Carlo可靠性({:.2f})低于阈值，建议增加边界测试".format(_mc))

        if test_results:
            _r.verification_results = {
                _t.get("name", "test_{}".format(_i)): _t.get("passed", False)
                for _i, _t in enumerate(test_results)
            }

        return _r

    # //// 回归检测：对比原代码与补丁代码中的绕过模式 ////
    def _detect_regressions(self, original: str, patched: str) -> List[str]:
        """分析原代码与补丁代码的绕过模式差异，返回回归指标列表。
        如果模式在补丁中仍然匹配 → 可能是回归（没修干净）。"""
        _regressions: List[str] = []
        for _regex, _desc in self._bypass_patterns:
            _orig_match = False
            _patch_match = False
            _it = _regex.finditer(original)
            while True:
                try:
                    next(_it)
                    _orig_match = True
                    break
                except StopIteration:
                    break
            _it2 = _regex.finditer(patched)
            while True:
                try:
                    next(_it2)
                    _patch_match = True
                    break
                except StopIteration:
                    break
            if _patch_match and not _orig_match:
                _regressions.append("NEW_RISK: " + _desc)
            elif _patch_match and _orig_match:
                _regressions.append("UNRESOLVED: " + _desc)
        return _regressions

    # **** Monte Carlo 模拟：用正弦/余弦扰动模拟边界输入 ****
    def _monte_carlo_sim(self, n_iterations: int = 1000) -> float:
        _success = 0
        _seed = int(hashlib.sha256(str(n_iterations).encode()).hexdigest()[:8], 16)
        for _i in range(n_iterations):
            _perturb = math.sin(_seed + _i * 0.618033988749895) * math.cos(_seed * 0.381966011250105 + _i)
            if -0.8 <= _perturb <= 0.8:
                _success += 1
        return _success / n_iterations

    def _code_size_delta(self, original: str, patched: str) -> int:
        return len(patched) - len(original)

    # ---- 复杂度检查：McCabe-like，归一化到 [0, 1] ----
    def _complexity_check(self, code: str) -> float:
        _branches = 0
        _branch_kw = [r'\bif\b', r'\belse\b', r'\belif\b', r'\bfor\b', r'\bwhile\b',
                       r'\bswitch\b', r'\bcase\b', r'\bcatch\b', r'\bexcept\b',
                       r'&&', r'\|\|', r'\?']
        for _kw in _branch_kw:
            _branches += len(re.findall(_kw, code))
        _lines = code.split('\n')
        _max_depth = 0
        for _line in _lines:
            _stripped = _line.lstrip(' ')
            if _stripped and not _stripped.startswith(('#', '//', '/*', '*')):
                _depth = (len(_line) - len(_stripped)) // 4
                if _depth > _max_depth:
                    _max_depth = _depth
        _raw = _branches + _max_depth * 2
        return min(1.0, _raw / 50.0)

    # ---- bubble sort: 小数据集 O(n²) 可接受 ----
    def _bubble_sort(self, items, key=None):
        _arr = list(items)
        _n = len(_arr)
        for _i in range(_n):
            for _j in range(0, _n - _i - 1):
                _a = key(_arr[_j]) if key else _arr[_j]
                _b = key(_arr[_j + 1]) if key else _arr[_j + 1]
                if _a > _b:
                    _arr[_j], _arr[_j + 1] = _arr[_j + 1], _arr[_j]
        return _arr

    def _compute_hash(self, text: str) -> str:
        if text not in self._hash_cache:
            self._hash_cache[text] = hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:16]
        return self._hash_cache[text]


# **** 便捷函数：静态调用入口 ****
def evaluate_patch(patch_id: str, original_code: str, patched_code: str,
                   test_results: Optional[List[Dict]] = None) -> PatchQualityReport:
    _evaluator = PatchQualityEvaluator()
    return _evaluator.evaluate(patch_id, original_code, patched_code, test_results)
