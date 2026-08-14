"""FCPV 安全格求解器 — 在三值安全格上求解约束联结, 对每个候选沿四类约束推导最终安全标签。
推导规则 (保守性保证): Sink=CONSTANT→SAFE; 有污点且无有效安全化 (或安全化含 %n)→VULN;
无法判定→UNCERTAIN 保留。与 FSCS 的区别: FSCS 乘法评分 (exploit×impact/10) 在 impact 未知时
产生低分→FN, FCPV 用格论推导不依赖数值评分, 消除乘法惩罚效应。"""

import re
from typing import List, Optional

from core.fcpv_constraint_types import (
    ConstraintKind, CrossFuncConstraint, FcpvCandidate, SafetyLabel,
    SanitizeConstraint, SinkConstraint, SinkType, TaintConstraint,
    TaintState,
)
from core.fcpv_constraint_collector import FcpvConstraintCollector


class FcpvSafetySolver:
    """三值安全格上的约束联结求解器."""

    # 安全化格式串中的危险说明符
    _DANGER_SPEC_RE = re.compile(r'%[-+0 #]*\d*(?:\.\d+)?(hh?|ll?|L|z|j|t)?n')
    _SAFE_FMT_RE = re.compile(r'%[-+0 #]*\d*(?:\.\d+)?[diouxXeEfFgGaAcsp]')

    # 字面量赋值模式: char *var = "literal"; 或 char var[] = "literal";
    _LITERAL_ASSIGN_RE = re.compile(
        r'(?:char\s*\*?|const\s+char\s*\*?)\s*(\w[\w]*)\s*=\s*"([^"]*)"\s*;')

    def __init__(self):
        self._collector = FcpvConstraintCollector()
        self._literal_vars: dict = {}

    def solve(self, source: str) -> List[FcpvCandidate]:
        """主入口: 收集约束 → 逐候选求解."""
        candidates = self._collector.collect(source)
        self._literal_vars = self._find_literal_assigns(source)
        for c in candidates:
            c.label, c.confidence, c.reason = self._solve_candidate(c)
        return candidates

    def _find_literal_assigns(self, source: str) -> dict:
        """收集变量→字符串字面量赋值."""
        result = {}
        for m in self._LITERAL_ASSIGN_RE.finditer(source):
            result[m.group(1)] = m.group(2)
        return result

    def _solve_candidate(self, c: FcpvCandidate) -> tuple:
        """对单个候选求解安全标签.

        返回 (SafetyLabel, confidence, reason).
        """
        sink = c.sink

        # 规则 1: 常量格式串 → SAFE
        if sink.sink_type == SinkType.CONSTANT:
            return (SafetyLabel.SAFE, 0.95,
                    f'constant format string: "{sink.constant_text[:40]}"')

        # 规则 8: 变量从字面量赋值且字面量含 %n → VULN
        var = sink.var
        if var in self._literal_vars:
            lit = self._literal_vars[var]
            if self._DANGER_SPEC_RE.search(lit):
                return (SafetyLabel.VULN, 0.90,
                        f'variable "{var}" = "{lit[:30]}" contains %n write primitive')

        # 规则 5: 变量但确认无污点 → SAFE
        has_taint = len(c.taints) > 0
        has_sanitize = len(c.sanitizers) > 0
        has_cross = len(c.cross_funcs) > 0

        if not has_taint and not has_cross:
            # 无污点路径也无跨函数绑定 → 检查变量是否在已知赋值中
            if self._is_clean_var(var):
                return (SafetyLabel.SAFE, 0.80,
                        f'variable "{var}" not tainted by external input')

        # 规则 2/3/4/9: 有污点
        if has_taint:
            if has_sanitize:
                san = c.sanitizers[0]
                if self._sanitize_is_safe(san):
                    # 规则 9: snprintf(dst, sz, "...%s...", tainted_src) → %s 透传用户输入
                    # 格式串含 %s 时用户字符串原样拷贝 (包括 % 字符),
                    # 后续 printf(dst) 会重新解释 → 格式串漏洞
                    if re.search(r'%[-+0 #]*\d*(?:\.\d+)?s', san.constant_fmt):
                        return (SafetyLabel.VULN, 0.75,
                                f'snprintf "%s" passes through user input to "{var}"')
                    return (SafetyLabel.SAFE, 0.85,
                            f'sanitized by {san.sanitizer}("{san.constant_fmt[:30]}")')
                return (SafetyLabel.VULN, 0.90,
                        f'sanitizer {san.sanitizer} still contains %n → unsafe')
            # 有污点无安全化 → VULN
            t = c.taints[0]
            chain_str = '→'.join(c.var_chain[:5])
            return (SafetyLabel.VULN, 0.90,
                    f'tainted: "{t.source}"@{t.source_line} via {chain_str}')

        # 规则 6: 跨函数绑定
        if has_cross:
            for cf in c.cross_funcs:
                if cf.caller_arg in self._collector.tainted_set:
                    chain_str = f'{cf.caller_arg}→{cf.callee}(param {cf.param_index})→{var}'
                    return (SafetyLabel.VULN, 0.85,
                            f'cross-func taint: {chain_str}')

        # 规则 7: 无法判定 → UNCERTAIN
        return (SafetyLabel.UNCERTAIN, 0.40,
                f'cannot determine taint for "{var}"')

    def _sanitize_is_safe(self, san: SanitizeConstraint) -> bool:
        """安全化格式串是否真正安全 (无 %n 系列写入原语)."""
        if self._DANGER_SPEC_RE.search(san.constant_fmt):
            return False
        return True

    def _is_clean_var(self, var: str) -> bool:
        """变量未被污点传播标记为 tainted."""
        return var not in self._collector.tainted_set

    @staticmethod
    def filter_vuln(candidates: List[FcpvCandidate]) -> tuple:
        """过滤: 返回 (vuln_list, safe_list, uncertain_list).

        设计决策: VULN 和 UNCERTAIN 均保留告警 (保守策略),
        SAFE 过滤. 调用方可按 confidence 二次排序.
        """
        vuln = [c for c in candidates if c.label == SafetyLabel.VULN]
        safe = [c for c in candidates if c.label == SafetyLabel.SAFE]
        uncertain = [c for c in candidates if c.label == SafetyLabel.UNCERTAIN]
        return vuln, safe, uncertain


__all__ = ['FcpvSafetySolver']
