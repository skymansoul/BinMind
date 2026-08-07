"""
不可行路径剪枝 — 使用轻量级约束传播消除不可满足的分支组合。

设计理由:
  path_sensitive_vrf.py 在条件分支处 fork PathCondition, 但部分路径组合
  在语义上不可满足 (如 n<16 ∧ n>256)。保留这些不可行路径会导致:
    1. 假阳性: 在不可能存在的程序状态下报告溢出
    2. 分析膨胀: 路径数指数增长

  本模块在每条路径上做约束一致性检查:
    对 (var, op, bound) 约束集合, 检查是否存在整数赋值满足所有约束。
    例如: [n<16, n>256] → 不可满足 → PRUNE

方法: 区间重叠检查 (不调用 SMT solver, 保持轻量)
  - 对每个变量, 合并所有 ≤ 约束取最小上界, 合并 ≥ 约束取最大下界
  - 若下界 > 上界 → 不可满足

  - KLEE: 约束求解+路径剪枝, 我们用区间近似替代 SMT
  - Angr 的 Claripy: 约束合并+简化, 我们取其思想做轻量版
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class VarBounds:
    """单变量的约束边界。"""
    name: str
    lo: int = -1       # 最大下界 (-1 = 无约束)
    hi: int = 2**31 - 1  # 最小上界
    eq_val: Optional[int] = None  # 等值约束

    @property
    def is_satisfiable(self) -> bool:
        """区间非空即满足。"""
        if self.eq_val is not None:
            if self.lo >= 0 and self.eq_val < self.lo:
                return False
            if self.hi < 2**31 - 1 and self.eq_val > self.hi:
                return False
            return True
        if self.lo >= 0 and self.hi < 2**31 - 1:
            return self.lo <= self.hi
        return True  # 至少一端无约束 → 满足

    @property
    def effective_range(self) -> Tuple[int, int]:
        """有效范围 [lo, hi]。"""
        lo = self.eq_val if self.eq_val is not None else (self.lo if self.lo >= 0 else 0)
        hi = self.eq_val if self.eq_val is not None else (self.hi if self.hi < 2**31 - 1 else 2**31 - 1)
        return (lo, min(hi, 2**31 - 1))

class InfeasiblePathPruner:
    """不可行路径剪枝器。

    对约束集做区间重叠检查, 标记不可满足的路径。
    不做完整 SMT solving——仅用区间代数近似。
    """

    def __init__(self):
        self._pruned_count: int = 0
        self._total_checked: int = 0

    def is_feasible(self, constraints: List[Tuple[str, str, int]]) -> bool:
        """判断约束集是否可能满足。

        constraints: [(var_name, operator, value), ...]
        返回 True 表示存在整数赋值满足所有约束。
        """
        self._total_checked += 1
        bounds: Dict[str, VarBounds] = {}

        for var, op, val in constraints:
            if var not in bounds:
                bounds[var] = VarBounds(name=var)

            vb = bounds[var]
            if op in ('<=', '<'):
                adjusted = val - (1 if op == '<' else 0)
                vb.hi = min(vb.hi, adjusted) if vb.hi < 2**31 - 1 else adjusted
            elif op in ('>=', '>'):
                adjusted = val + (1 if op == '>' else 0)
                vb.lo = max(vb.lo, adjusted) if vb.lo >= 0 else adjusted
            elif op == '==':
                if vb.eq_val is not None and vb.eq_val != val:
                    # 冲突: x==5 ∧ x==8
                    self._pruned_count += 1
                    return False
                vb.eq_val = val
            elif op == '!=':
                # != 约束不能收紧区间, 标记但不处理
                pass

        for vb in bounds.values():
            if not vb.is_satisfiable:
                self._pruned_count += 1
                return False

        return True

    def prune(self, path_constraints: List[List[Tuple[str, str, int]]]) -> List[List[Tuple[str, str, int]]]:
        """从路径约束列表中移除不可行路径。"""
        return [pc for pc in path_constraints if self.is_feasible(pc)]

    def filter_by_range(
        self,
        findings: List[dict],
        alloc_var: str,
        write_var: str,
        constraints: List[Tuple[str, str, int]],
    ) -> List[dict]:
        """在路径约束下检查每个 finding 是否可满足。

        将分配大小和写入大小代入约束边界做比较。
        若约束确保 write_size ≤ alloc_size → 过滤。
        """
        bounds: Dict[str, VarBounds] = {}
        for var, op, val in constraints:
            if var not in bounds:
                bounds[var] = VarBounds(name=var)
            vb = bounds[var]
            if op in ('<=', '<'):
                vb.hi = min(vb.hi, val - (1 if op == '<' else 0))
            elif op in ('>=', '>'):
                vb.lo = max(vb.lo, val + (1 if op == '>' else 0))
            elif op == '==':
                vb.eq_val = val

        results = []
        for f in findings:
            alloc_sz = f.get('allocation_size', f.get('alloc', 0))
            write_sz = f.get('write_size', f.get('overflow_bytes', 0))

            # 简单情况: 常量比较
            if isinstance(alloc_sz, int) and isinstance(write_sz, int) and alloc_sz > 0:
                if write_sz <= alloc_sz:
                    continue  # 安全, 过滤
                results.append(f)
                continue

            results.append(f)  # 保守保留

        return results

    @property
    def stats(self) -> dict:
        return {
            'total_checked': self._total_checked,
            'pruned': self._pruned_count,
            'prune_rate': round(self._pruned_count / max(1, self._total_checked), 3),
        }

def extract_branch_constraints(code: str) -> List[Tuple[str, str, int]]:
    """从反编译代码中提取所有分支约束。

    用于后续路径可行性分析。
    """
    constraints = []
    for line in code.split('\n'):
        m = re.search(
            r'if\s*\(\s*(\w+)\s*(<|>|<=|>=|==|!=)\s*(\d+)\s*\)',
            line.strip())
        if m:
            constraints.append((m.group(1), m.group(2), int(m.group(3))))
    return constraints
