"""
整数溢出误报过滤器 — 三阶段抑制通往堆溢出的整数溢出误报 (CWE-190/191/680)。
阶段G: 溢出守卫检测; 阶段T: 类型加宽 (size_t 算术不截断); 阶段C: 常量折叠。
集成: G+T+C 加权多数投票, 全票 SUPPRESS → FILTERED, 2:1 → SUPPRESS, 分歧 → REVIEW。
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# 模式 ─────────────────────────────────────────────────────────────

_OVERFLOW_GUARD = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*[><=!]+\s*(\d+|0x[0-9a-fA-F]+)\s*/\s*sizeof')
_SAFE_MAX = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*>\s*(?:SIZE_MAX|UINT_MAX|INT_MAX|0x[7F]+\s*)\s*/\s*')
_SIZET_VAR = re.compile(r'\b(?:size_t|uint64_t|uint32_t|unsigned\s+long\s+long)\s+(\w[\w.]*)')
_MUL_IN_ALLOC = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*malloc\s*\(\s*(\w[\w.]*)\s*\*\s*(\w[\w.]*|sizeof\([^)]+\))\s*\)')
_CONST_MUL = re.compile(r'malloc\s*\(\s*(\d+)\s*\*\s*(\d+|sizeof\([^)]+\))\s*\)')


# 数据类型 ────────────────────────────────────────────────────────────

@dataclass
class IntOverflowCandidate:
    """malloc 位点的整数溢出候选。"""
    line: int; line_text: str; alloc_var: str = ''
    mul_left: str = ''; mul_right: str = ''
    verdict: str = 'UNCERTAIN'
    confidence: float = 0.50; fp_likelihood: float = 0.50

@dataclass
class IoDecision:
    """单个整数溢出候选的误报过滤判定。"""
    candidate: IntOverflowCandidate
    guard_detected: bool = False; guard_detail: str = ''
    sizet_typed: bool = False; sizet_detail: str = ''
    constant_folded: bool = False
    verdict: str = 'REVIEW'; score: float = 0.50


# 引擎 ───────────────────────────────────────────────────────────────

class IntOverflowFpFilter:
    """三阶段整数溢出误报过滤器。"""

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    def filter(
        self, ir_lines: List[str],
        candidates: List[IntOverflowCandidate],
    ) -> List[IoDecision]:
        """对每个候选执行 G+T+C 三阶段, 返回集成判定。"""
        decisions = []
        for cand in candidates:
            dec = IoDecision(candidate=cand)

            # 阶段G: 溢出守卫
            dec.guard_detected, dec.guard_detail = self._stage_guard(
                ir_lines, cand)

            # 阶段T: 类型加宽
            dec.sizet_typed, dec.sizet_detail = self._stage_type(
                ir_lines, cand)

            # 阶段C: 常量折叠
            dec.constant_folded = self._stage_constant(cand)

            # 集成: 加权投票
            dec.verdict, dec.score = self._decide(dec)
            decisions.append(dec)

        self.stats = {
            'total': len(candidates),
            'suppressed': sum(1 for d in decisions if d.verdict == 'SUPPRESS'),
            'review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
        }
        return decisions

    # 阶段G: 守卫检测 ─────────────────────────────────────

    def _stage_guard(
        self, ir_lines: List[str], cand: IntOverflowCandidate,
    ) -> Tuple[bool, str]:
        """检测约束乘法操作数的溢出守卫。"""
        for i in range(max(0, cand.line - 20), cand.line):
            line = ir_lines[i]
            m = _OVERFLOW_GUARD.search(line)
            if m:
                var = m.group(1)
                if var == cand.mul_left or var == cand.mul_right:
                    return True, f'L{i}: if({var} > MAX/sizeof) guard'
            sm = _SAFE_MAX.search(line)
            if sm:
                return True, f'L{i}: if({sm.group(1)} > MAX) guard'
        return False, ''

    # 阶段T: 类型加宽 ───────────────────────────────────────

    def _stage_type(
        self, ir_lines: List[str], cand: IntOverflowCandidate,
    ) -> Tuple[bool, str]:
        """检查操作数是否使用 size_t — 无 32 位截断。"""
        for i in range(max(0, cand.line - 30), cand.line + 1):
            line = ir_lines[i]
            for m in _SIZET_VAR.finditer(line):
                v = m.group(1)
                if v == cand.mul_left or v == cand.mul_right:
                    return True, f'L{i}: {v} is {m.group(0).split()[0]}'
        # sizeof 恒为 size_t
        if 'sizeof' in cand.mul_right or 'sizeof' in cand.mul_left:
            return True, 'sizeof operand → size_t arithmetic'
        return False, ''

    # 阶段C: 常量折叠 ────────────────────────────────────

    @staticmethod
    def _stage_constant(cand: IntOverflowCandidate) -> bool:
        """检查乘法是否可常量折叠。"""
        return bool(_CONST_MUL.search(cand.line_text))

    # 判定 ─────────────────────────────────────────────────────

    @staticmethod
    def _decide(dec: IoDecision) -> Tuple[str, float]:
        """加权投票: G(0.40) + T(0.35) + C(0.25)。"""
        score = 0.0
        if dec.guard_detected:
            score += 0.40
        if dec.sizet_typed:
            score += 0.35
        if dec.constant_folded:
            score += 0.25

        if score >= 0.60:
            return 'SUPPRESS', score
        elif score <= 0.25:
            return 'KEEP', score
        return 'REVIEW', score


# 提取 ───────────────────────────────────────────────────────────

def extract_int_overflow_candidates(
    ir_lines: List[str],
) -> List[IntOverflowCandidate]:
    """从 IR 行提取整数溢出候选。"""
    candidates = []
    for i, line in enumerate(ir_lines):
        m = _MUL_IN_ALLOC.search(line)
        if m:
            cand = IntOverflowCandidate(
                line=i, line_text=line.strip(),
                alloc_var=m.group(1),
                mul_left=m.group(2).strip(),
                mul_right=m.group(3).strip(),
            )
            # 左右均为常量则跳过
            try:
                int(m.group(2).strip(), 0)
                int(m.group(3).strip().replace('sizeof(int)', '4')
                       .replace('sizeof(char)', '1')
                       .replace('sizeof(char*)', '8'))
                # 双常量 — 无溢出风险 (阶段C处理)
                cand.constant_folded = True
            except (ValueError, AttributeError):
                pass
            candidates.append(cand)
    return candidates


def filter_int_overflow(
    ir_lines: List[str],
) -> Tuple[List[IoDecision], Dict[str, Any]]:
    """便捷接口: 提取并过滤整数溢出候选。"""
    cands = extract_int_overflow_candidates(ir_lines)
    engine = IntOverflowFpFilter()
    decisions = engine.filter(ir_lines, cands)
    return decisions, engine.stats


__all__ = [
    'IntOverflowCandidate', 'IoDecision', 'IntOverflowFpFilter',
    'extract_int_overflow_candidates', 'filter_int_overflow',
]
