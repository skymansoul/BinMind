"""路径敏感值域窄化 — 利用分支条件缩小值集区间, 证明堆访问安全.

创建: 2026-06-23
用途: 现有 constraint_simplifier 只处理单个 cmp/jcc 对, 无法追踪跨基本块
      的约束链。本模块实现路径敏感的区间窄化:
        1. 从潜在溢出点向后遍历控制流图
        2. 收集所有路径条件 (cmp/jcc 对)
        3. 对涉及偏移/大小的操作数, 用区间抽象解释逐步窄化
        4. 若窄化后的区间能证明安全性 → 过滤该告警

方法论:
  - 与 Cod 的 heap disjointness 不同: Cod 需要源码级类型信息,
    本模块工作在 strip 后的二进制上, 仅使用反汇编的 cmp/jcc 信息。
  - 与 ConstraintSimplifier 的区别: 后者仅检查单个 cmp/jcc 对,
    本模块支持跨基本块的约束链 (如 if (x>256) x=256; ... heap_op(x))。
  - 区间抽象解释: 使用区间域做前后向分析,
    O(N) 复杂度, 对堆溢出检测足够 (大多数安全约束是简单的区间比较)。

  - Sparse Abstract Execution: 跨域交互的精化抽象执行
  - Kim et al.: 用 SMT 过滤器减少缓冲区溢出误报
  - Rodrigues et al.: "SimSan" — 区间分析用于C程序的静态分析
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

# 哨兵值
class _Unbounded:
    def __repr__(self):
        return "∞"

UNBOUNDED = _Unbounded()

class ComparisonOp(Enum):
    LT = "lt"
    LE = "le"
    GT = "gt"
    GE = "ge"
    EQ = "eq"
    NE = "ne"

@dataclass
class BranchConstraint:
    """一条从分支条件提取的约束."""
    insn_addr: int              # 比较指令地址
    register: str               # 被约束的寄存器
    op: ComparisonOp            # 比较操作
    bound_value: int            # 边界值 (另一操作数)
    is_taken: bool = True       # 条件为真时此约束生效

    def apply(self, interval: 'ValueRange') -> 'ValueRange':
        """将该约束应用到值域上, 返回窄化后的新值域."""
        lo, hi = interval.lo_val, interval.hi_val

# min: 若 hi 是无界的, 用 bound 替代; 否则取 min
        def _min(a, b):
            if a is UNBOUNDED:
                return b
            return min(a, b)

        def _max(a, b):
            return max(a, b)

        if self.op == ComparisonOp.LT:
            hi = _min(hi, self.bound_value - 1)
        elif self.op == ComparisonOp.LE:
            hi = _min(hi, self.bound_value)
        elif self.op == ComparisonOp.GT:
            lo = _max(lo, self.bound_value + 1)
        elif self.op == ComparisonOp.GE:
            lo = _max(lo, self.bound_value)
        elif self.op == ComparisonOp.EQ:
            lo = _max(lo, self.bound_value)
            hi = _min(hi, self.bound_value)

        return ValueRange(lo_val=lo, hi_val=hi)

@dataclass
class ValueRange:
    """整数区间 [lo_val, hi_val]. UNBOUNDED 表示无界."""
    lo_val: int = 0
    hi_val: object = UNBOUNDED  # int 或 _Unbounded 哨兵

    @property
    def is_unbounded(self) -> bool:
        return self.hi_val is UNBOUNDED

    @property
    def hi(self) -> int:
        return self.hi_val if self.hi_val is not UNBOUNDED else 2**63 - 1

    @property
    def lo(self) -> int:
        return self.lo_val

    def contains(self, val: int) -> bool:
        return self.lo <= val and (self.is_unbounded or val <= self.hi_val)

    def upper_bound(self) -> Optional[int]:
        """返回有限上界, 若无限返回 None."""
        if self.is_unbounded:
            return None
        return self.hi_val

    def intersect(self, other: 'ValueRange') -> 'ValueRange':
        """两个区间的交集."""
        new_lo = max(self.lo, other.lo)

        if self.is_unbounded and other.is_unbounded:
            new_hi = UNBOUNDED
        elif self.is_unbounded:
            new_hi = other.hi_val
        elif other.is_unbounded:
            new_hi = self.hi_val
        else:
            new_hi = min(self.hi_val, other.hi_val)

        if (new_hi is not UNBOUNDED
                and isinstance(new_hi, int)
                and new_lo > new_hi):
            return ValueRange(lo_val=self.lo, hi_val=self.hi_val)
        return ValueRange(lo_val=new_lo, hi_val=new_hi)

    def __repr__(self):
        hi_s = str(self.hi_val) if self.hi_val is not UNBOUNDED else "∞"
        return f"[{self.lo_val}, {hi_s}]"

class PathValueNarrower:
    """路径敏感值域窄化器.

    对给定的潜在溢出点, 沿控制流图向后遍历收集分支约束,
    窄化操作数的值域, 判定访问是否被路径条件保护。

    使用方式:
      narrower = PathValueNarrower()
      narrower.add_branch_constraint(0x401010, 'rax', ComparisonOp.LT, 256, True)
      narrower.set_cfg_edge(0x401010, 0x401030)   # taken
      narrower.set_cfg_edge(0x401010, 0x401015)   # fallthrough

      # 查询: 在 0x401030 处, rax 的值域
      vr = narrower.compute_value_range(0x401030, 'rax')
      if vr.upper_bound() is not None and vr.upper_bound() < alloc_size:
          print("Safe — path condition guarantees no overflow")
    """

    def __init__(self):
        # insn_addr → BranchConstraint
        self._constraints: Dict[int, BranchConstraint] = {}

        # insn_addr → {target_addr, ...} (控制流后继)
        self._cfg_succs: Dict[int, Set[int]] = {}

        # insn_addr → {pred_addr, ...} (控制流前驱, 从 succs 推导)
        self._cfg_preds: Dict[int, Set[int]] = {}

        # 地址 → 在该地址处生效的约束集合
        self._effective_constraints: Dict[int, Set[int]] = {}

        # 窄化缓存
        self._range_cache: Dict[Tuple[int, str], ValueRange] = {}

# 注册

    def add_branch_constraint(self, insn_addr: int, register: str,
                               op: ComparisonOp, bound_value: int,
                               is_taken: bool = True) -> None:
        """注册一条分支约束."""
        self._constraints[insn_addr] = BranchConstraint(
            insn_addr=insn_addr, register=register,
            op=op, bound_value=bound_value, is_taken=is_taken)

    def set_cfg_edge(self, src_addr: int, dst_addr: int) -> None:
        """设置控制流边 src → dst."""
        self._cfg_succs.setdefault(src_addr, set()).add(dst_addr)
        self._cfg_preds.setdefault(dst_addr, set()).add(src_addr)

# 核心算法

    def compute_value_range(self, addr: int, operand: str,
                            max_backward: int = 20) -> ValueRange:
        """需求驱动: 计算 operand 在 addr 处的窄化值域.

        算法:
          1. 从 addr 沿 CFG 反向 BFS, 收集所有可达的约束
          2. 对每个约束涉及 operand 的, 逐步窄化区间
          3. 返回窄化后的最小区间
        """
        cache_key = (addr, operand)
        if cache_key in self._range_cache:
            return self._range_cache[cache_key]

        # 初始区间: [0, ∞) 除非有显式约束
        vr = ValueRange(lo_val=0)

        # 收集在此地址处生效的约束
        effective = self._collect_effective_constraints(addr, max_backward)

        for cid in effective:
            c = self._constraints.get(cid)
            if c is None:
                continue
            if c.register.lower() != operand.lower():
                continue
            vr = c.apply(vr)

        self._range_cache[cache_key] = vr
        return vr

    def _collect_effective_constraints(self, addr: int,
                                       max_steps: int) -> Set[int]:
        """从 addr 反向 BFS, 收集所有可达且在路径上生效的约束."""
        if addr in self._effective_constraints:
            return self._effective_constraints[addr]

        effective: Set[int] = set()
        visited: Set[int] = set()
        queue: List[Tuple[int, int]] = [(addr, 0)]  # (addr, depth)

        while queue:
            cur_addr, depth = queue.pop(0)
            if depth > max_steps:
                continue
            if cur_addr in visited:
                continue
            visited.add(cur_addr)

            # 检查 cur_addr 是否是某个约束的 taken 目标
            # 若 cur_addr 是约束 c 的 taken 目标 → c 在此生效
            for c_addr, c in self._constraints.items():
                succs = self._cfg_succs.get(c_addr, set())
                if cur_addr in succs and c_addr not in effective:
                    effective.add(c_addr)

            # 继续反向遍历
            preds = self._cfg_preds.get(cur_addr, set())
            for pred_addr in preds:
                if pred_addr not in visited:
                    queue.append((pred_addr, depth + 1))

        self._effective_constraints[addr] = effective
        return effective

# 便捷判定

    def is_access_safe(self, insn_addr: int, offset_reg: str,
                       alloc_size: int, access_size: int = 1,
                       max_backward: int = 15) -> bool:
        """判定: 在 insn_addr 处, offset_reg 的值是否被约束在安全范围内.

        返回 True 若 offset + access_size ≤ alloc_size 可被路径条件证明.
        """
        vr = self.compute_value_range(insn_addr, offset_reg, max_backward)
        ub = vr.upper_bound()
        if ub is not None and ub + access_size <= alloc_size:
            return True
        return False

    def stats(self) -> dict:
        return {
            'n_constraints': len(self._constraints),
            'n_cfg_edges': sum(len(v) for v in self._cfg_succs.values()),
            'n_cached_ranges': len(self._range_cache),
        }

    def clear(self) -> None:
        self._constraints.clear()
        self._cfg_succs.clear()
        self._cfg_preds.clear()
        self._effective_constraints.clear()
        self._range_cache.clear()
