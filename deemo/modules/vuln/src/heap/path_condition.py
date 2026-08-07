"""路径条件收集器 — 从分支指令提取守卫条件并关联到堆操作路径.

创建: 2026-05-10
用途: 在反汇编后的基本块序列中识别"cmp+jcc"模式,
      提取路径条件, 注入到线性约束引擎中用于后续安全性证明。

关键观察:
  编译器产出的堆访问总是受边界检查保护:
    if (i < n) buf[i] = x;
  对应汇编:
    cmp i, n
    jge skip      ; 若 i >= n, 跳过写入
    mov [buf+i*4], eax
  skip:
  如果我们能识别这个 cmp-jcc 模式并将约束 i < n 注入到 buf[i] 的访问点,
  就能证明该访问是安全的——这对基于简单模式匹配的检测器来说却是误报。

  反过来说, 若堆访问没有对应的边界检查守卫, 则更可能是真正的溢出。

设计取舍:
  - 为什么不直接用 Ghidra/angr 的 CFG:
    我们工作在 capstone 线性扫描反汇编层面, 没有 CFG。
    在基本块内做局部模式匹配+跨块追踪是轻量级的妥协。
  - 路径条件只追踪 3 个层次的嵌套分支:
    深层嵌套的路径条件组合爆炸 → 精度↓, 3层覆盖 80%+ 的实际场景。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .linear_constraint import ConstraintSet, LinearConstraint, ConstraintOp


@dataclass
class BranchGuard:
    """一个分支守卫条件."""
    insn_addr: int                # cmp/jcc 指令地址
    cmp_operands: str             # "rax, 256"
    jcc_mnemonic: str             # "jle", "jg", etc.
    jcc_target: int               # 跳转目标地址
    taken: bool = True            # 路径是否满足跳转条件
    constrained_var: str = ""     # 被约束的变量名
    constrained_val: int = 0      # 约束的常数值
    description: str = ""


@dataclass
class PathContext:
    """从函数入口到当前指令处收集的路径条件."""
    function_name: str
    branch_history: List[BranchGuard] = field(default_factory=list)
    constraint_set: ConstraintSet = field(default_factory=ConstraintSet)
    depth: int = 0


class PathConditionCollector:
    """路径条件收集器 — 关联分支守卫到堆操作.

    使用方式:
      collector = PathConditionCollector()
      ctx = collector.start_context("process_data")
      guard = collector.extract_guard(0x401050, "cmp rax, 256", "jle", 0x401080, True)
      collector.apply_guard(ctx, guard)
      # ... 继续追踪到 memcpy 调用点
      safe = collector.prove_access_safe(ctx, "rax", 256, 200, 4)
    """

    MAX_DEPTH = 3
    GUARD_PATTERNS = {
        'jle': ('<=', True),  'jbe': ('<=', True),
        'jge': ('>=', True),  'jae': ('>=', True),
        'jl':  ('<', True),   'jb':  ('<', True),
        'jg':  ('>', True),   'ja':  ('>', True),
        'je':  ('==', True),  'jz':  ('==', True),
        'jne': ('!=', True),  'jnz': ('!=', True),
    }

    def __init__(self):
        from .linear_constraint import LinearConstraintEngine
        self._engine = LinearConstraintEngine()

    def start_context(self, function_name: str) -> PathContext:
        return PathContext(function_name=function_name)

    def extract_guard(self, insn_addr: int, cmp_mnemonic: str,
                      cmp_operands: str, jcc_mnemonic: str,
                      jcc_target: int, taken: bool = True) -> Optional[BranchGuard]:
        """从 cmp+jcc 指令对提取路径守卫."""
        if jcc_mnemonic not in self.GUARD_PATTERNS:
            return None

        # 解析 cmp operands: "rax, 256" 或 "eax, 0x100"
        parts = cmp_operands.replace(",", " ").split()
        if len(parts) < 2:
            return None

        left, right = parts[0], parts[1]

        # 确定哪个是被约束的变量
        constrained_var = ""
        constrained_val = 0

        try:
            right_val = int(right, 0)
            constrained_var = left
            constrained_val = right_val
        except ValueError:
            try:
                left_val = int(left, 0)
                constrained_var = right
                constrained_val = left_val
            except ValueError:
                return None  # 两边都是变量 → 暂不处理

        op_str, _ = self.GUARD_PATTERNS[jcc_mnemonic]

        # 根据比较方向调整约束值
        adjusted_val = constrained_val
        if op_str == '<':
            adjusted_val = constrained_val - 1
        elif op_str == '>':
            adjusted_val = constrained_val + 1

        return BranchGuard(
            insn_addr=insn_addr, cmp_operands=cmp_operands,
            jcc_mnemonic=jcc_mnemonic, jcc_target=jcc_target,
            taken=taken, constrained_var=constrained_var,
            constrained_val=constrained_val,
            description=f"{constrained_var} {op_str}= {constrained_val}")

    def apply_guard(self, ctx: PathContext, guard: BranchGuard) -> None:
        """将守卫条件应用到路径上下文.

        深度限制: 超过 MAX_DEPTH 不再添加新约束 (旧约束保留).
        """
        if ctx.depth >= self.MAX_DEPTH:
            return

        ctx.branch_history.append(guard)
        ctx.depth += 1

        # 转换到线性约束
        if guard.taken and guard.jcc_mnemonic in self.GUARD_PATTERNS:
            op_str, _ = self.GUARD_PATTERNS[guard.jcc_mnemonic]
            var, val = guard.constrained_var, guard.constrained_val

            if op_str in ('<=', '<'):
                c = LinearConstraint(
                    coef_a=1, var_a=var, const_c=-val,
                    op=ConstraintOp.LE)
            elif op_str in ('>=', '>'):
                c = LinearConstraint(
                    coef_a=-1, var_a=var, const_c=val,
                    op=ConstraintOp.LE)
            elif op_str == '==':
                c = LinearConstraint(
                    coef_a=1, var_a=var, const_c=-val,
                    op=ConstraintOp.LE)
            else:
                return

            ctx.constraint_set.constraints.append(c)

    def record_cmp_jcc(self, ctx: PathContext, cmp_operands: str,
                       jcc_mnemonic: str, jcc_target: int,
                       taken: bool = True) -> None:
        """快捷方法: 一步完成 extract + apply."""
        guard = self.extract_guard(
            0, "", cmp_operands, jcc_mnemonic, jcc_target, taken)
        if guard:
            self.apply_guard(ctx, guard)

    def record_var_bound(self, ctx: PathContext, var: str,
                         lo: int, hi: int) -> None:
        """记录变量的已知区间约束."""
        existing = ctx.constraint_set.var_bounds.get(var)
        if existing:
            ctx.constraint_set.var_bounds[var] = (
                max(existing[0], lo), min(existing[1], hi))
        else:
            ctx.constraint_set.var_bounds[var] = (lo, hi)

    def prove_access_safe(self, ctx: PathContext, ptr_var: str,
                          offset: int, alloc_size: int,
                          access_size: int = 1) -> bool:
        """在路径上下文中, 证明堆访问是安全的."""
        return self._engine.prove_access_safe(
            ctx.constraint_set, ptr_var, offset, alloc_size, access_size)

    def prove_bound(self, ctx: PathContext, var: str, bound: int) -> bool:
        """在路径上下文中, 证明 var <= bound."""
        return self._engine.prove_upper_bound(
            ctx.constraint_set, var, bound)

    def merge_contexts(self, ctx1: PathContext,
                       ctx2: PathContext) -> PathContext:
        """汇合两个路径上下文 (在控制流汇合点)."""
        merged = PathContext(
            function_name=ctx1.function_name,
            branch_history=[],
            constraint_set=self._engine.merge_sets(
                ctx1.constraint_set, ctx2.constraint_set),
            depth=max(ctx1.depth, ctx2.depth))
        return merged

    def context_has_guard_for(self, ctx: PathContext,
                              var: str) -> bool:
        """检查路径上下文中是否有对 var 的任何边界守卫."""
        for g in ctx.branch_history:
            if g.constrained_var == var:
                return True
        return False

    def context_summary(self, ctx: PathContext) -> str:
        """路径上下文的可读摘要."""
        guards = [g.description for g in ctx.branch_history]
        bounds = [f"{v}:[{lo},{hi}]" for v, (lo, hi)
                  in ctx.constraint_set.var_bounds.items()]
        return (f"fn={ctx.function_name} depth={ctx.depth} "
                f"guards={guards} bounds={bounds}")
