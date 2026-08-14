"""
路径敏感约束收集器 — 提取并简化分支条件。
区间传播后条件如 if(size>256) 需按路径分别处理；本模块把路径谓词作为
约束（区间交集）求精区间，等价于抽象解释中约束传播的一步，不依赖SMT求解器。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.forward_interval_prop import Interval

# 约束类型 ─────────────────────────────────────────────────

@dataclass
class Constraint:
    """单条路径约束: var <op> value。"""
    var: str
    op: str   # '<' | '<=' | '>' | '>=' | '==' | '!='
    value: int
    at_line: int = 0

    def apply(self, interval: Interval) -> Interval:
        """应用约束收窄区间。"""
        if self.op in ('<',):
            hi = self.value - 1 if self.value > 0 else -1
            return interval.intersect(Interval(-1, hi))
        elif self.op in ('<='):
            return interval.intersect(Interval(-1, self.value))
        elif self.op in ('>',):
            lo = self.value + 1
            return interval.intersect(Interval(lo, 2**63 - 1))
        elif self.op in ('>='):
            return interval.intersect(Interval(self.value, 2**63 - 1))
        elif self.op in ('=='):
            return interval.intersect(Interval.exact(self.value))
        elif self.op in ('!='):
            # 无互补信息时无法有效收窄
            return interval
        return interval

    def negate(self) -> "Constraint":
        """返回约束的否定形式（ELSE分支）。"""
        neg_map = {'<': '>=', '<=': '>', '>': '<=', '>=': '<',
                   '==': '!=', '!=': '=='}
        return Constraint(
            var=self.var, op=neg_map.get(self.op, '!='),
            value=self.value, at_line=self.at_line)

@dataclass
class ConstraintPath:
    """带累积约束的IR路径。"""
    constraints: List[Constraint] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0

    def apply_all(self, iv: Interval) -> Interval:
        result = iv
        for c in self.constraints:
            result = c.apply(result)
        return result

    def copy(self) -> "ConstraintPath":
        return ConstraintPath(
            constraints=list(self.constraints),
            start_line=self.start_line, end_line=self.end_line)

# 模式识别 ──────────────────────────────────────────────

# if (var < N)、if (var <= N)、if (var > N) 等
_IF_CMP_RE = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+|0x[0-9a-fA-F]+)\s*\)')
# var < N（IR中的独立比较）
_CMP_STANDALONE_RE = re.compile(
    r'(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+|0x[0-9a-fA-F]+)')
# cmp reg, imm; jXX label（典型反编译模式）
_CMP_JMP_RE = re.compile(
    r'cmp\s+(\w[\w.]*)\s*,\s*(\d+|0x[0-9a-fA-F]+)\s*\n?\s*'
    r'(j[gl][et]?|jn?[abgl])\s+')

@dataclass
class BranchSite:
    """IR中的条件分支。"""
    line: int
    condition: Constraint
    then_start: int   # line where THEN block starts
    else_start: int    # line where ELSE block starts (-1 if no else)
    merge_point: int   # line where both branches rejoin (-1 if unknown)

class PathConstraintCollector:
    """从IR提取分支约束并应用到区间。

    用法:
      collector = PathConstraintCollector()
      constraints = collector.extract_constraints(ir_lines)
      refined = collector.refine_interval('size', my_interval, constraints,
                                          target_line=42)
    """

    def extract_constraints(self, ir_lines: List[str]) -> List[Constraint]:
        """从IR行提取全部路径约束：每个 `if (var <op> N)` 或
        `cmp var, N; jXX` 生成一条Constraint。"""
        constraints: List[Constraint] = []

        for i, line in enumerate(ir_lines):
            # 模式1: if (var <op> N)
            m = _IF_CMP_RE.search(line)
            if m:
                try:
                    val = int(m.group(3), 0)
                    constraints.append(Constraint(
                        var=m.group(1), op=m.group(2),
                        value=val, at_line=i))
                except ValueError:
                    continue
                continue

            # 模式2: cmp var, N（条件跳转前）
            m = _CMP_JMP_RE.search(line)
            if m:
                try:
                    val = int(m.group(2), 0)
                    jcc = m.group(3).lower()
                    op = _jcc_to_cmp_op(jcc)
                    if op:
                        constraints.append(Constraint(
                            var=m.group(1), op=op,
                            value=val, at_line=i))
                except ValueError:
                    continue

        return constraints

    def find_constraint_for_var(
        self, var_name: str, line: int,
        constraints: List[Constraint],
        window: int = 20,
    ) -> Optional[Constraint]:
        """查找'line'之前影响var_name的最近约束：在IR行窗口内向后搜索。"""
        best = None
        best_dist = window + 1
        for c in constraints:
            if c.var == var_name and c.at_line < line:
                dist = line - c.at_line
                if dist < best_dist and dist <= window:
                    best = c
                    best_dist = dist
        return best

    def refine_interval(
        self, var_name: str, iv: Interval,
        constraints: List[Constraint],
        target_line: int = -1,
    ) -> Interval:
        """应用全部相关约束收窄区间；target_line >= 0 时只应用该行
        之前的约束（遵循执行顺序）。"""
        result = iv
        for c in constraints:
            if c.var != var_name:
                continue
            if target_line >= 0 and c.at_line > target_line:
                continue
            result = c.apply(result)
        return result

    def extract_branch_sites(self, ir_lines: List[str]) -> List[BranchSite]:
        """识别全部条件分支及其基本块边界。"""
        sites: List[BranchSite] = []
        constraint_map: Dict[int, Constraint] = {}

        # 第一遍: 识别约束
        for i, line in enumerate(ir_lines):
            m = _IF_CMP_RE.search(line)
            if m:
                try:
                    val = int(m.group(3), 0)
                    constraint_map[i] = Constraint(
                        var=m.group(1), op=m.group(2), value=val, at_line=i)
                except ValueError:
                    continue

        # 第二遍: 估计分支结构
        for i in sorted(constraint_map.keys()):
            c = constraint_map[i]
            # 粗略块检测: 查找{/}或标签模式
            then_start = i + 1
            else_start = -1
            merge_point = -1

            # 查找else关键字或替代标签
            for j in range(i + 1, min(len(ir_lines), i + 50)):
                line_lower = ir_lines[j].lower()
                if 'else' in line_lower:
                    else_start = j + 1
                    break
                if '}' in line_lower and j > i + 5:
                    merge_point = j
                    break

            sites.append(BranchSite(
                line=i, condition=c,
                then_start=then_start, else_start=else_start,
                merge_point=merge_point))

        return sites

def _jcc_to_cmp_op(jcc: str) -> Optional[str]:
    """将x86条件跳转助记符映射为比较运算符。"""
    mapping = {
        'jl': '<', 'jle': '<=', 'jg': '>', 'jge': '>=',
        'je': '==', 'jne': '!=', 'jb': '<', 'jbe': '<=',
        'ja': '>', 'jae': '>=', 'jnl': '>=', 'jng': '<=',
    }
    return mapping.get(jcc)

def collect_and_refine(
    ir_lines: List[str],
    var_name: str,
    base_interval: Interval,
    target_line: int = -1,
) -> Tuple[Interval, List[Constraint]]:
    """便捷入口: 收集约束并应用到单个变量。返回 (求精区间, 已应用约束)。"""
    collector = PathConstraintCollector()
    constraints = collector.extract_constraints(ir_lines)
    applied = [c for c in constraints
               if c.var == var_name
               and (target_line < 0 or c.at_line <= target_line)]
    refined = collector.refine_interval(var_name, base_interval,
                                        constraints, target_line)
    return refined, applied

__all__ = ['Constraint', 'ConstraintPath', 'BranchSite',
           'PathConstraintCollector', 'collect_and_refine']
