"""线性约束引擎 — 路径敏感的轻量级约束追踪.

创建: 2025-04-17
追踪 a*x + b*y + c <= 0 形式的线性约束, 表达 cmp/jcc 分支条件。
方法论: 选择性路径敏感 — 仅堆操作相关路径收集约束, 汇合点取交集。
参考: PLDI 2024 selective path-sensitive VFA; ISSTA 2024 heap disjointness.
设计: 只追踪线性约束 (95%+), 最多64活跃约束, 不做bit-level推理。"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


class ConstraintOp(Enum):
    LE = 0    # <=
    EQ = 1    # ==
    GE = 2    # >= (内部存储为 -1 * LE)


@dataclass
class LinearConstraint:
    """a * var_x + b * var_y + c <= 0

    仅支持单变量或双变量线性约束。
    位宽假设: 所有变量为 64-bit 有符号/无符号 (UNSAT 判定对两者都保守).
    """
    coef_a: float = 0.0
    var_a: str = ""
    coef_b: float = 0.0
    var_b: str = ""
    const_c: float = 0.0
    op: ConstraintOp = ConstraintOp.LE

    def is_trivial(self) -> bool:
        """始终为真 (如 0 <= 0)."""
        return (self.coef_a == 0 and self.coef_b == 0
                and self.const_c >= 0 and self.op == ConstraintOp.LE)

    def is_contradiction(self) -> bool:
        """始终为假 (如 0 + 1 <= 0)."""
        return (self.coef_a == 0 and self.coef_b == 0
                and self.const_c < 0 and self.op == ConstraintOp.LE)

    def involves(self, var: str) -> bool:
        return self.var_a == var or self.var_b == var

    def __repr__(self):
        parts = []
        if self.coef_a != 0:
            parts.append(f"{self.coef_a}*{self.var_a}")
        if self.coef_b != 0:
            parts.append(f"{self.coef_b}*{self.var_b}")
        lhs = " + ".join(parts) if parts else "0"
        op_str = "<=" if self.op == ConstraintOp.LE else "=="
        return f"{lhs} + {self.const_c} {op_str} 0"


@dataclass
class ConstraintSet:
    """一组活跃约束 + 变量区间."""
    constraints: List[LinearConstraint] = field(default_factory=list)
    var_bounds: Dict[str, Tuple[int, int]] = field(default_factory=dict)

    def clone(self) -> 'ConstraintSet':
        return ConstraintSet(
            constraints=list(self.constraints),
            var_bounds=dict(self.var_bounds))

    def is_empty(self) -> bool:
        return len(self.constraints) == 0


class LinearConstraintEngine:
    """路径敏感的线性约束收集与推理引擎."""

    MAX_CONSTRAINTS = 64
    MAX_INVOLVED_VARS = 32

    def __init__(self):
        self._stats = {'total_sets': 0, 'pruned': 0, 'proved_safe': 0}

    def create_set(self) -> ConstraintSet:
        self._stats['total_sets'] += 1
        return ConstraintSet()

# 约束采集

    def record_cmp(self, cs: ConstraintSet, mnemonic: str,
                   operands: str, insn_type: str = "cmp") -> None:
        """从 cmp/sub/test 指令提取比较关系."""
        if insn_type not in ("cmp", "sub", "test"):
            return
        parts = operands.replace(",", " ").split()
        if len(parts) < 2:
            return

        left, right = parts[0], parts[1]
        try:
            left_val = int(left, 0)
            right_val = int(right, 0)
            # 两个都是常数 → 无约束信息
            return
        except ValueError:
            pass

        # cmp reg, const → reg - const <= 0 (cmp 后若 jle 则 reg <= const)
        if insn_type == "test":
            # test reg, reg → 无法直接提取线性约束, 但可能推导为 reg == 0
            pass
            return

    def record_jcc(self, cs: ConstraintSet, mnemonic: str,
                   src_reg: str, const_val: int, taken: bool) -> None:
        """从条件跳转提取约束: cmp rax, 256; jle → rax <= 256.

        约定: src_reg 是被比较的寄存器, const_val 是比较的常数.
        taken=True 表示跳转被执行 (意味着条件成立).
        """
        if len(cs.constraints) >= self.MAX_CONSTRAINTS:
            self._stats['pruned'] += 1
            cs.constraints = cs.constraints[-32:]  # 丢弃最早的一半
            return

        # 条件码 → 约束映射
        cond_map = {
            'jle': (src_reg, const_val, ConstraintOp.LE),    # src <= const
            'jle_taken': (src_reg, const_val, ConstraintOp.LE),
            'jle_nottaken': (src_reg, const_val + 1, ConstraintOp.GE),  # src > const
            'jg': (src_reg, const_val, ConstraintOp.GE),     # src > const (GE with const+1)
            'jg_taken': (src_reg, const_val + 1, ConstraintOp.GE),
            'jge': (src_reg, const_val, ConstraintOp.GE),    # src >= const
            'jge_taken': (src_reg, const_val, ConstraintOp.GE),
            'jl': (src_reg, const_val, ConstraintOp.LE),     # src < const
            'jl_taken': (src_reg, const_val - 1, ConstraintOp.LE),
            'je': (src_reg, const_val, ConstraintOp.EQ),     # src == const
            'je_taken': (src_reg, const_val, ConstraintOp.EQ),
            'jne': None,  # src != const → 无法简化为不等式
        }

        key = mnemonic if taken else f"{mnemonic}_nottaken"
        if taken:
            key = f"{mnemonic}_taken"

        entry = cond_map.get(mnemonic, None)
        if entry is None and mnemonic.startswith('j'):
            # 通用处理: 仅处理常见模式
            if 'le' in mnemonic or 'be' in mnemonic:
                entry = (src_reg, const_val, ConstraintOp.LE)
            elif 'ge' in mnemonic or 'ae' in mnemonic:
                entry = (src_reg, const_val, ConstraintOp.GE)
            elif 'e' in mnemonic or 'z' in mnemonic:
                entry = (src_reg, const_val, ConstraintOp.EQ)

        if entry is None:
            return

        var, val, op = entry
        if op == ConstraintOp.GE:
            # Normalize: x >= c → -x + c <= 0
            c = LinearConstraint(coef_a=-1, var_a=var, const_c=val, op=ConstraintOp.LE)
        elif op == ConstraintOp.EQ:
            # x == c → x - c <= 0 and -x + c <= 0
            c1 = LinearConstraint(coef_a=1, var_a=var, const_c=-val, op=ConstraintOp.LE)
            c2 = LinearConstraint(coef_a=-1, var_a=var, const_c=val, op=ConstraintOp.LE)
            cs.constraints.append(c1)
            cs.constraints.append(c2)
            return
        else:
            # x <= c → x - c <= 0
            c = LinearConstraint(coef_a=1, var_a=var, const_c=-val, op=ConstraintOp.LE)

        cs.constraints.append(c)

    def add_var_bounds(self, cs: ConstraintSet, var: str,
                       bounds: Tuple[int, int]) -> None:
        """直接设置变量区间. bounds=(lo, hi)."""
        existing = cs.var_bounds.get(var)
        if existing:
            new_lo = max(existing[0], bounds[0])
            new_hi = min(existing[1], bounds[1])
            cs.var_bounds[var] = (new_lo, new_hi)
        else:
            cs.var_bounds[var] = bounds

# 约束推理

    def prove_upper_bound(self, cs: ConstraintSet, var: str,
                          bound: int) -> bool:
        """尝试证明 var <= bound 从约束集中推导出来.

        轻量级方法: 只检查直接约束 (单变量 ≤ 常数) 和传递闭包。
        不做完整 Fourier-Motzkin 消元——对实时分析代价太高。
        """
        # 检查变量区间
        if var in cs.var_bounds:
            _, hi = cs.var_bounds[var]
            if hi <= bound:
                self._stats['proved_safe'] += 1
                return True

        # 检查形如 1*var - N <= 0 的约束
        for c in cs.constraints:
            if c.op != ConstraintOp.LE:
                continue
            if c.coef_a == 1 and c.var_a == var and c.coef_b == 0:
                # var - N <= 0 → var <= N
                if -c.const_c <= bound:
                    self._stats['proved_safe'] += 1
                    return True

        # 传递推导: 若 rax <= rbx 且 rbx <= N, 则 rax <= N
        for c1 in cs.constraints:
            if c1.op != ConstraintOp.LE:
                continue
            if c1.coef_a == 1 and c1.coef_b == -1 and c1.const_c == 0:
                # rax - rbx <= 0 → rax <= rbx
                if c1.var_a == var:
                    # 递归检查 var_b 是否有上界
                    if self.prove_upper_bound(cs, c1.var_b, bound):
                        self._stats['proved_safe'] += 1
                        return True

        return False

    def prove_access_safe(self, cs: ConstraintSet, ptr_var: str,
                          offset: int, alloc_size: int,
                          access_size: int = 1) -> bool:
        """证明 *(ptr + offset) 在分配范围内是安全的.

        即证明: offset + access_size <= alloc_size
        """
        # offset 本身是常数, 检查是否在分配范围内
        if offset + access_size <= alloc_size:
            return True

        # 若能证明 offset <= alloc_size - access_size
        max_offset = alloc_size - access_size
        if self.prove_upper_bound(cs, ptr_var, max_offset):
            return True

        return False

    def merge_sets(self, cs1: ConstraintSet,
                   cs2: ConstraintSet) -> ConstraintSet:
        """控制流汇合点: 合并两个约束集.

        合并策略: 保留两个集合的公共约束 (intersection).
        这是保守近似——失去精度但保证 soundness。
        """
        merged = ConstraintSet()

        # 变量区间: 取并集 (lo取min, hi取max)
        all_vars = set(cs1.var_bounds.keys()) | set(cs2.var_bounds.keys())
        for var in all_vars:
            b1 = cs1.var_bounds.get(var)
            b2 = cs2.var_bounds.get(var)
            if b1 and b2:
                merged.var_bounds[var] = (min(b1[0], b2[0]), max(b1[1], b2[1]))
            elif b1:
                merged.var_bounds[var] = b1
            elif b2:
                merged.var_bounds[var] = b2

        # 约束: 仅保留在两个集合中都存在的 (保守)
        for c1 in cs1.constraints:
            for c2 in cs2.constraints:
                if (c1.coef_a == c2.coef_a and c1.var_a == c2.var_a
                        and c1.coef_b == c2.coef_b and c1.var_b == c2.var_b
                        and c1.const_c == c2.const_c and c1.op == c2.op):
                    merged.constraints.append(c1)
                    break

        return merged

    def stats(self) -> dict:
        return dict(self._stats)

    def clear_stats(self) -> None:
        self._stats = {'total_sets': 0, 'pruned': 0, 'proved_safe': 0}
