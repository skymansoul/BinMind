# 重构：从独立启发式升级为统一编译器pass模拟

"""Optimization Compatibility Analyzer — 编译器优化pass模拟器。

旧版使用6个独立的启发式规则（检查栈帧、检查常量、检查分支...），
新版改为统一的编译器优化pass模拟：

核心思路：模拟编译器在修补后的代码上运行关键优化pass，
检测哪些pass的输出与原始代码的输出不一致。

模拟的优化pass：
  Pass 1 — Inline Expansion: 检查 callee 栈帧是否超出 caller 的 inline 预算
  Pass 2 — Loop Unrolling: 检查循环边界常量是否被补丁改变
  Pass 3 — Constant Propagation: 检查常量值传播链是否被补丁截断
  Pass 4 — Dead Code Elimination: 检查补丁新增的指令是否会被 DCE 误杀
  Pass 5 — Branch Probability: 检查补丁新增分支的静态预测结果

每个pass模拟编译器的IR变换（不是真的IR，是汇编级的模拟），
输出该pass的失效程度(0..1)。多pass结果加权求和 → 兼容性评分。

为什么不用独立启发式：
  孤立的"检查sub rsp变化"不知道这个变化是否超出inline预算。
  Pass模拟可以：已知 caller 的栈帧 + inline 预算 → 精确判断是否溢出。
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class OptimIssueType(str, Enum):
    INLINING_BROKEN = "inlining_broken"
    LOOP_UNROLL_BROKEN = "loop_unroll_broken"
    CONSTANT_PROP_BROKEN = "constant_prop_broken"
    DEAD_CODE_RISK = "dead_code_risk"
    PGO_INVALIDATED = "pgo_invalidated"
    ALIAS_ASSUMPTION_BROKEN = "alias_assumption_broken"


@dataclass
class OptimIssue:
    issue_type: OptimIssueType
    severity: str = "warning"
    description: str = ""
    estimated_impact_pct: float = 0.0


@dataclass
class OptimCompatReport:
    patch_id: str = ""
    function_name: str = ""
    issues: List[OptimIssue] = field(default_factory=list)
    errors: int = 0
    warnings: int = 0
    compatible: bool = True
    estimated_regression_pct: float = 0.0
    pass_scores: Dict[str, float] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id, 'function': self.function_name,
            'compatible': self.compatible, 'errors': self.errors, 'warnings': self.warnings,
            'est_regression_pct': round(self.estimated_regression_pct, 2),
            'pass_scores': {k: round(v, 3) for k, v in self.pass_scores.items()},
            'issues': [{'type': i.issue_type.value, 'severity': i.severity, 'desc': i.description}
                      for i in self.issues[:8]],
            'recommendation': self.recommendation,
        }


# Pass 1: 内联预算检查

def simulate_inline_expansion(orig_asm: List[str], patched_asm: List[str],
                              caller_stack_hint: int = 128) -> Tuple[float, List[str]]:
    """模拟编译器内联决策：检查修补后函数是否超出内联预算。

    编译器内联条件（简化）：
      - callee 指令数 ≤ inline_max_insns (典型值: 50)
      - callee 栈帧 ≤ caller_stack_hint (caller 的可用栈空间)
    若补丁使 callee 超出预算 → 编译器将拒绝内联 → 性能退化。
    """
    orig_frame = _extract_frame(orig_asm)
    patch_frame = _extract_frame(patched_asm)
    patch_insns = len([l for l in patched_asm if l.strip() and not l.strip().startswith('.')])

    details = []
    score = 0.0

    if patch_frame and orig_frame:
        frame_increase = patch_frame - orig_frame if patch_frame > orig_frame else 0
        if frame_increase > 0 and patch_frame > caller_stack_hint * 0.7:
            score += 0.5
            details.append("栈帧 %d bytes 占用 caller 预算的 %.0f%%——可能阻止内联" % (
                patch_frame, patch_frame / max(caller_stack_hint, 1) * 100))

    if patch_insns > 50:
        score += 0.3
        details.append("指令数 %d 超过内联阈值 50——编译器将拒绝内联" % patch_insns)

    return min(score, 1.0), details


# Pass 2: 循环展开检查

def simulate_loop_unrolling(orig_asm: List[str], patched_asm: List[str]) -> Tuple[float, List[str]]:
    """模拟循环展开：检查补丁是否改变了编译器展开假设的trip count。

    编译器展开决策依赖循环边界常量。若补丁改变此常量 → 展开版本失效。
    """
    orig_consts = _cmp_constants(orig_asm)
    patch_consts = _cmp_constants(patched_asm)
    changed = set()
    for val, reg in patch_consts:
        if 2 <= val <= 64:
            orig_vals = {v for v, r in orig_consts if r == reg}
            if orig_vals and val not in orig_vals:
                changed.add((reg, val))

    details = []
    score = 0.0
    if changed:
        score = min(len(changed) * 0.25, 0.8)
        for reg, val in list(changed)[:3]:
            details.append("循环边界寄存器 %s 常量变为 %d——展开版本可能无效" % (reg, val))
    return score, details


# Pass 3: 常量传播检查

def simulate_constant_propagation(orig_asm: List[str], patched_asm: List[str]) -> Tuple[float, List[str]]:
    """模拟常量传播：检测补丁是否新增了编译器已传播并消除的常量。

    编译器将常量值传播到使用点后可能消除原定义。
    若补丁在原始常量位置写入新值 → 已传播的副本仍是旧值 → 不一致。
    """
    details = []
    score = 0.0

    # 找补丁新增的 mov reg, const（可能是被传播消除后重新定义的常量）
    for line in patched_asm:
        stripped = line.strip().lower().replace(',', ' ')
        m = re.search(r'\bmov\s+(\w+),?\s*(0x[0-9a-f]{4,}|\d{4,})', stripped)
        if not m:
            continue
        reg = m.group(1)
        val = m.group(2)
        # 检查原始代码中是否有其他指令直接使用该常量值（已被传播）
        const_int = int(val, 16) if val.startswith('0x') else int(val)
        for orig_line in orig_asm:
            if val in orig_line.lower() and 'mov' not in orig_line.lower().split()[0]:
                score += 0.15
                details.append("常量 %s (值=%d) 在原始代码中已被传播消除——补丁重新定义导致不一致" % (reg, const_int))
                break
    return min(score, 1.0), details


# Pass 4: DCE 风险检查

def simulate_dce_risk(patched_asm: List[str]) -> Tuple[float, List[str]]:
    """模拟死代码消除：检查补丁新增的指令是否可能被DCE误杀。

    编译器DCE移除"无副作用且结果未被使用"的指令。
    若补丁中的写入结果在局部窗口内未被读取 → DCE候选 → 可能被移除。
    """
    details = []
    score = 0.0
    for i, line in enumerate(patched_asm):
        stripped = line.strip().lower().replace(',', ' ')
        parts = stripped.split()
        if len(parts) < 2:
            continue
        mnemonic = parts[0]
        if mnemonic not in ('mov', 'lea', 'add', 'sub', 'xor', 'and', 'or'):
            continue
        dst = parts[1].rstrip(',')
        if not re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3})$', dst):
            continue
        # 在后续8条指令中搜索对该寄存器的读取
        used = False
        for j in range(i + 1, min(i + 9, len(patched_asm))):
            later = patched_asm[j].strip().lower().replace(',', ' ')
            if re.search(r'\b' + re.escape(dst) + r'\b', later):
                # 确认是读取而非覆写
                later_parts = later.split()
                if len(later_parts) >= 2 and later_parts[1].rstrip(',') != dst:
                    used = True
                    break
        if not used:
            score += 0.1
            details.append("写入 %s 后8条指令内未被读取——DCE风险 (%s)" % (dst, line.strip()[:50]))
    return min(score, 0.6), details


# Pass 5: 分支概率检查

def simulate_branch_probability(orig_asm: List[str], patched_asm: List[str]) -> Tuple[float, List[str]]:
    """模拟分支概率预测：检查补丁新增分支的静态预测结果。

    编译器用静态启发式预测分支方向（如向后跳转=循环=likely taken）。
    补丁新增的分支无PGO数据 → 编译器默认50/50 → 误预测率上升。
    """
    details = []
    score = 0.0
    orig_jumps = _count_jumps(orig_asm)
    patch_jumps = _count_jumps(patched_asm)
    new_cond = patch_jumps['conditional'] - orig_jumps['conditional']
    if new_cond > 0:
        score = min(new_cond * 0.2, 0.5)
        details.append("新增 %d 个条件分支——无PGO数据，静态预测默认50/50" % new_cond)
    # 检测数据依赖的分支（cmp源来自内存 → 高度不可预测）
    for line in patched_asm:
        if re.search(r'\bcmp\s+.*\[', line, re.I) and re.search(r'\bj', line, re.I):
            score += 0.25
            details.append("数据依赖分支 (cmp mem + jcc)——分支预测器难以处理")
            break
    return min(score, 1.0), details


# 辅助函数

def _extract_frame(asm: List[str]) -> Optional[int]:
    for line in asm:
        m = re.search(r'sub\s+rsp,\s*(0x[0-9a-f]+|\d+)', line, re.I)
        if m:
            v = m.group(1)
            return int(v, 16) if v.startswith('0x') else int(v)
    return None

def _cmp_constants(asm: List[str]) -> Set[Tuple[int, str]]:
    """提取cmp指令中的 (常量值, 寄存器) 对。"""
    results = set()
    for line in asm:
        m = re.search(r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', line, re.I)
        if m:
            reg = m.group(1)
            val = m.group(2)
            try:
                results.add((int(val, 16) if val.startswith('0x') else int(val), reg))
            except ValueError:
                pass
    return results

def _count_jumps(asm: List[str]) -> Dict[str, int]:
    counts = {'conditional': 0, 'unconditional': 0}
    for line in asm:
        w = line.strip().lower().split()[0] if line.strip() else ''
        if len(w) > 1 and w.startswith('j') and w != 'jmp':
            counts['conditional'] += 1
        elif w == 'jmp':
            counts['unconditional'] += 1
    return counts


# 统一分析器

class OptimCompatAnalyzer:
    """编译器优化pass模拟分析器。

    运行5个模拟pass，输出加权兼容性评分。
    pass权重基于其对运行时性能的影响程度。
    """

    _PASS_WEIGHTS = {
        'inline': 0.30, 'loop_unroll': 0.20, 'const_prop': 0.15,
        'dce': 0.15, 'branch_prob': 0.20,
    }

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                function_name: str = "",
                patch_id: str = "",
                caller_stack_hint: int = 128) -> OptimCompatReport:
        report = OptimCompatReport(patch_id=patch_id, function_name=function_name)
        all_issues = []
        scores = {}

        s1, d1 = simulate_inline_expansion(original_asm, patched_asm, caller_stack_hint)
        scores['inline'] = s1
        for d in d1:
            all_issues.append(OptimIssue(issue_type=OptimIssueType.INLINING_BROKEN,
                                         severity='error' if s1 > 0.5 else 'warning',
                                         description=d, estimated_impact_pct=s1 * 15))

        s2, d2 = simulate_loop_unrolling(original_asm, patched_asm)
        scores['loop_unroll'] = s2
        for d in d2:
            all_issues.append(OptimIssue(issue_type=OptimIssueType.LOOP_UNROLL_BROKEN,
                                         severity='warning', description=d,
                                         estimated_impact_pct=s2 * 10))

        s3, d3 = simulate_constant_propagation(original_asm, patched_asm)
        scores['const_prop'] = s3
        for d in d3:
            all_issues.append(OptimIssue(issue_type=OptimIssueType.CONSTANT_PROP_BROKEN,
                                         severity='warning', description=d,
                                         estimated_impact_pct=s3 * 5))

        s4, d4 = simulate_dce_risk(patched_asm)
        scores['dce'] = s4
        for d in d4:
            all_issues.append(OptimIssue(issue_type=OptimIssueType.DEAD_CODE_RISK,
                                         severity='warning', description=d,
                                         estimated_impact_pct=s4 * 2))

        s5, d5 = simulate_branch_probability(original_asm, patched_asm)
        scores['branch_prob'] = s5
        for d in d5:
            all_issues.append(OptimIssue(issue_type=OptimIssueType.PGO_INVALIDATED,
                                         severity='warning', description=d,
                                         estimated_impact_pct=s5 * 8))

        report.pass_scores = scores
        report.issues = all_issues
        report.errors = sum(1 for i in all_issues if i.severity == 'error')
        report.warnings = sum(1 for i in all_issues if i.severity == 'warning')

        total_regression = sum(scores[k] * self._PASS_WEIGHTS[k] for k in scores)
        report.estimated_regression_pct = total_regression * 100
        report.compatible = report.errors == 0

        if report.compatible and report.warnings == 0:
            report.recommendation = "编译器优化pass模拟通过——补丁与优化兼容"
        elif report.compatible:
            report.recommendation = "%d个pass告警——预计性能退化%.1f%%" % (report.warnings, report.estimated_regression_pct)
        else:
            report.recommendation = "%d个pass错误——补丁破坏了编译器优化假设" % report.errors

        return report
