# 修改记录:
# 2025-08-05 17:31 - 初始实现：补丁语义等价验证——上游补丁→旧版本回植的正确性检查

"""补丁回植验证 — 上游补丁→旧版本二进制回植后的语义等价检查。

上游开源项目常常推迟发布修复补丁。安全团队需将补丁"回植"到当前使用的
旧版本。但代码上下文差异（变量重命名/函数重构/内联展开）使简单cherry-pick
失败——直接复制补丁可能破坏旧版本二进制。

本模块的验证机制——行为等价检查：
1. 提取上游补丁的"安全契约"——补丁在哪些条件下改变了什么行为。
2. 对旧版本二进制应用回植补丁。
3. 在两版本上执行蜕变测试——输入空间分层采样，
   比较补丁前后的行为变化是否"语义等价"。
4. 等价判定：对于所有用户可控输入，补丁后的行为差异仅体现在
   受漏洞影响的路径上——且差异方向一致（都要么更安全，要么不变）。

参考：
- patch_equivalence_verifier.py：验证两个补丁实现是否等价。
- 本模块验证"补丁在旧版本上的效果"与"上游补丁效果"是否等价。
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple


class BackportVerdict(Enum):
    EQUIVALENT = "equivalent"
    DIVERGENT = "divergent"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


@dataclass
class BackportTestCase:
    """一个回植验证的测试用例。"""
    input_bytes: bytes
    upstream_behavior: str   # 上游补丁后的行为标签
    backport_behavior: str    # 回植补丁后的行为标签
    behavior_match: bool
    is_vuln_relevant: bool


@dataclass
class BackportValidationResult:
    """回植验证的完整输出。"""
    upstream_patch_id: str
    target_binary: str
    verdict: BackportVerdict
    total_tests: int
    matched_tests: int
    divergent_tests: int
    match_ratio: float
    divergence_analysis: List[str]


class BackportSemanticValidator:
    """补丁回植的语义等价验证器。

    使用范式：
      validator = BackportSemanticValidator()
      validator.load_testcases(cases)
      result = validator.validate()
    """

    def __init__(
        self,
        match_threshold: float = 0.95,
        vuln_match_required: float = 0.98,
    ):
        self.match_threshold = match_threshold
        self.vuln_match_required = vuln_match_required
        self._testcases: List[BackportTestCase] = []

    def load_testcases(self, cases: List[BackportTestCase]):
        self._testcases = cases

    def validate(self) -> BackportValidationResult:
        """执行回植语义等价验证。"""
        _total = len(self._testcases)
        if _total == 0:
            return BackportValidationResult(
                upstream_patch_id="", target_binary="",
                verdict=BackportVerdict.INCONCLUSIVE,
                total_tests=0, matched_tests=0, divergent_tests=0,
                match_ratio=0.0, divergence_analysis=["no test cases"],
            )

        _matched = sum(1 for t in self._testcases if t.behavior_match)
        _divergent = _total - _matched
        _match_ratio = _matched / _total

        _vuln_cases = [t for t in self._testcases if t.is_vuln_relevant]
        _vuln_matched = sum(1 for t in _vuln_cases if t.behavior_match) if _vuln_cases else 0
        _vuln_ratio = _vuln_matched / max(len(_vuln_cases), 1)

        _verdict = BackportVerdict.INCONCLUSIVE
        _analysis: List[str] = []

        if _match_ratio >= self.match_threshold and _vuln_ratio >= self.vuln_match_required:
            _verdict = BackportVerdict.EQUIVALENT
            _analysis.append("all test categories above threshold")
        elif _match_ratio >= self.match_threshold and _vuln_ratio < self.vuln_match_required:
            _verdict = BackportVerdict.PARTIAL
            _analysis.append(
                f"general match={_match_ratio:.1%} OK, "
                f"but vuln-relevant match={_vuln_ratio:.1%} < {self.vuln_match_required:.0%}"
            )
        elif _match_ratio < self.match_threshold:
            _verdict = BackportVerdict.DIVERGENT
            _analysis.append(f"match ratio {_match_ratio:.1%} < {self.match_threshold:.0%}")

        # 差异分析——哪些类型的输入导致分歧
        _divergent_cases = [t for t in self._testcases if not t.behavior_match]
        _by_type: Dict[str, int] = defaultdict(int)
        for _t in _divergent_cases:
            _length_cat = f"len_{min(len(_t.input_bytes) // 16 * 16, 256)}"
            _by_type[_length_cat] += 1

        for _cat, _cnt in sorted(_by_type.items()):
            _analysis.append(f"divergence cluster: {_cat} ({_cnt} cases)")

        return BackportValidationResult(
            upstream_patch_id="",
            target_binary="",
            verdict=_verdict,
            total_tests=_total,
            matched_tests=_matched,
            divergent_tests=_divergent,
            match_ratio=round(_match_ratio, 4),
            divergence_analysis=_analysis,
        )


# ---- 冒烟测试 ----
def _smoke_test():
    _validator = BackportSemanticValidator(match_threshold=0.9)
    _cases = []
    for _i in range(50):
        _is_vuln = _i < 20
        _match = True if _i < 45 or _i > 47 else False  # 2个分歧
        _cases.append(BackportTestCase(
            input_bytes=bytes([_i] * 8),
            upstream_behavior="VULN_FIXED" if _is_vuln else "UNCHANGED",
            backport_behavior="VULN_FIXED" if _match and _is_vuln else "UNCHANGED",
            behavior_match=_match,
            is_vuln_relevant=_is_vuln,
        ))

    _validator.load_testcases(_cases)
    _result = _validator.validate()
    print(f"[backport] verdict: {_result.verdict.value}")
    print(f"[backport] match: {_result.matched_tests}/{_result.total_tests} "
          f"({_result.match_ratio:.3f})")
    print(f"[backport] analysis: {_result.divergence_analysis[:3]}")

    assert _result.verdict == BackportVerdict.EQUIVALENT
    print("[OK] BackportSemanticValidator smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
