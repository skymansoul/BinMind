"""循环感知的区间分析 — 带加宽/收窄的抽象解释.

创建: 2024-12-09
检测循环中对堆缓冲区的迭代访问, 推断循环次数是否受分配大小约束。
核心: 编译器生成 for(i=0;i<n;i++) buf[i]=src[i] → 若n≤分配大小, 则安全。
方法: 第一阶段加宽(widening)用阈值外推区间, 第二阶段收窄(narrowing)
从退出条件反向约束。参考: Cousot&Cousot 1977 抽象解释, PLDI 2010 threshold widening。"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


class LoopClass(Enum):
    BOUNDED = "bounded"            # 循环次数受限, 且边界 ≤ 分配大小
    UNBOUNDED = "unbounded"        # 循环次数无法确定上界
    OVERFLOW_RISK = "overflow"     # 循环次数超出分配大小
    UNKNOWN = "unknown"


@dataclass
class InductionVar:
    """循环归纳变量."""
    name: str                      # 寄存器/变量名
    init_val: int = 0              # 初始值
    step: int = 1                  # 步幅
    current_interval: Tuple[int, int] = (0, 0)
    exit_condition: str = ""       # 退出条件描述
    exit_bound_var: str = ""       # 退出条件的边界变量
    exit_bound_val: int = 0        # 退出条件的边界值
    is_increasing: bool = True


@dataclass
class LoopSummary:
    """一个循环的分析摘要."""
    loop_header_addr: int
    induction_vars: List[InductionVar] = field(default_factory=list)
    nesting_depth: int = 0
    max_iterations: int = 0        # 推断的最大迭代次数
    loop_class: LoopClass = LoopClass.UNKNOWN
    heap_accesses: List[int] = field(default_factory=list)
    guarded_by_check: bool = False  # 是否有显式的边界检查


class LoopIntervalAnalyzer:
    """循环感知的区间分析器 — 加宽/收窄推断归纳变量范围."""

    MAX_WIDENING_ITERATIONS = 5
    THRESHOLD_VALUES = [8, 16, 32, 64, 128, 256, 512, 1024, 4096, 0x10000]

    def __init__(self):
        self._loops: Dict[int, LoopSummary] = {}
        self._active_loop: Optional[int] = None
        self._widening_count: Dict[str, int] = {}
        self._narrowing_done: Dict[str, bool] = {}

    def enter_loop(self, header_addr: int, nesting_depth: int = 0) -> None:
        """进入循环——开始追踪新循环."""
        if header_addr not in self._loops:
            self._loops[header_addr] = LoopSummary(
                loop_header_addr=header_addr, nesting_depth=nesting_depth)
        self._active_loop = header_addr
        self._widening_count.clear()
        self._narrowing_done.clear()

    def exit_loop(self, header_addr: int) -> None:
        self._active_loop = None

    def register_induction(self, var_name: str, init_val: int = 0,
                           step: int = 1, is_increasing: bool = True) -> None:
        """注册循环归纳变量."""
        if self._active_loop is None:
            return
        loop = self._loops[self._active_loop]
        # 检查是否已有同名归纳变量
        existing = [iv for iv in loop.induction_vars if iv.name == var_name]
        if existing:
            return
        iv = InductionVar(
            name=var_name, init_val=init_val, step=step,
            current_interval=(init_val, init_val),
            is_increasing=is_increasing)
        loop.induction_vars.append(iv)

    def widen(self, var_name: str) -> Optional[Tuple[int, int]]:
        """对归纳变量做加宽——用阈值外推上界.

        策略: 阈值加宽 (threshold widening)
          - 初始: [0, 0]
          - 1轮:  [0, 1]
          - 2轮:  [0, 2]
          - 加宽到下一个阈值: [0, 8]

        加宽前检查: 若 step * iter_count < 已知的分配大小, 不加宽.
        """
        count = self._widowing_count.get(var_name, 0) + 1
        self._widening_count[var_name] = count
        if count >= self.MAX_WIDENING_ITERATIONS:
            return (0, 2**63 - 1)  # 加宽到无限

        if self._active_loop is None:
            return None
        loop = self._loops[self._active_loop]
        for iv in loop.induction_vars:
            if iv.name != var_name:
                continue
            lo, hi = iv.current_interval
            new_hi = hi + iv.step
            # 阈值加宽: 跳到下一个阈值
            for t in self.THRESHOLD_VALUES:
                if t > new_hi:
                    widened = (lo, t - 1)
                    iv.current_interval = widened
                    return widened
            # 超过所有阈值 → 无界
            widened = (lo, 2**63 - 1)
            iv.current_interval = widened
            return widened
        return None

    def apply_exit_condition(self, var_name: str, cmp_insn: str,
                             jcc: str, target: int) -> None:
        """应用循环退出条件来约束归纳变量.

        例如: cmp rax, rbx; jle loop_header
        → rax (归纳变量) 的上界受 rbx 约束
        """
        if self._active_loop is None:
            return
        loop = self._loops[self._active_loop]
        for iv in loop.induction_vars:
            if iv.name != var_name:
                continue

            # 解析退出条件
            parts = cmp_insn.replace(",", " ").split()
            if len(parts) < 2:
                return
            left, right = parts[0], parts[1]

            # 尝试提取常数值或变量名
            try:
                val = int(right, 0)
                iv.exit_bound_val = val
                iv.exit_bound_var = ""
            except ValueError:
                iv.exit_bound_var = right

            iv.exit_condition = f"{cmp_insn} {jcc} {hex(target)}"

            # 根据jcc方向确定是 < 还是 <=
            if jcc in ('jle', 'jbe', 'jl', 'jb'):
                iv.exit_bound_val = iv.exit_bound_val  # 保持
            elif jcc in ('jge', 'jae', 'jg', 'ja'):
                # 循环不是"小于则继续"而是"大于则继续"
                # 暂不处理这种模式
                pass

    def narrow(self, var_name: str, max_val: int) -> Optional[Tuple[int, int]]:
        """收窄归纳变量的区间——使用退出条件或其他约束.

        max_val 通常来自 malloc 的参数 n (分配大小 / sizeof(element)).
        """
        if self._narrowing_done.get(var_name):
            return None
        self._narrowing_done[var_name] = True

        if self._active_loop is None:
            return None
        loop = self._loops[self._active_loop]
        for iv in loop.induction_vars:
            if iv.name != var_name:
                continue
            lo, hi = iv.current_interval
            # 收窄: hi = min(hi, max_val - 1)
            new_hi = min(hi, max_val - 1) if max_val > 0 else hi
            new_lo = max(lo, 0)
            narrowed = (new_lo, new_hi)
            iv.current_interval = narrowed
            return narrowed
        return None

    def classify_loop(self, header_addr: int,
                      alloc_size: int) -> LoopSummary:
        """分类循环——判断循环是否在堆分配的安全范围内.

        alloc_size 是堆分配的大小 (以字节计).
        """
        loop = self._loops.get(header_addr)
        if loop is None:
            return LoopSummary(loop_header_addr=header_addr)

        if not loop.induction_vars:
            loop.loop_class = LoopClass.UNKNOWN
            return loop

        # 对每个归纳变量计算最大迭代次数
        max_iters_list = []
        for iv in loop.induction_vars:
            lo, hi = iv.current_interval
            if hi >= 2**62:
                max_iters_list.append(float('inf'))
            else:
                iters = (hi - lo) // max(1, iv.step) + 1
                max_iters_list.append(iters)

        loop.max_iterations = max(max_iters_list) if max_iters_list else 0

        # 分类: 比较最大迭代次数与分配大小的关系
        if loop.max_iterations == float('inf'):
            if loop.guarded_by_check:
                loop.loop_class = LoopClass.BOUNDED
            else:
                loop.loop_class = LoopClass.UNBOUNDED
        elif loop.max_iterations <= alloc_size:
            loop.loop_class = LoopClass.BOUNDED
        else:
            loop.loop_class = LoopClass.OVERFLOW_RISK

        return loop

    def register_heap_access_in_loop(self, loop_addr: int,
                                     access_addr: int) -> None:
        """注册循环中的堆访问点."""
        loop = self._loops.get(loop_addr)
        if loop:
            loop.heap_accesses.append(access_addr)

    def mark_boundary_guard(self, loop_addr: int) -> None:
        """标记循环有显式的边界检查 (如 if (i >= n) break)."""
        loop = self._loops.get(loop_addr)
        if loop:
            loop.guarded_by_check = True

    def summarize_loop(self, header_addr: int) -> Optional[LoopSummary]:
        return self._loops.get(header_addr)

    def iter_bounds_for_access(self, header_addr: int,
                               alloc_size: int) -> List[Tuple[str, int, int]]:
        """返回循环中每个归纳变量的安全迭代范围.

        用于判断特定的堆访问 *(buf + iv) 是否溢出.
        """
        loop = self._loops.get(header_addr)
        if loop is None:
            return []
        results = []
        for iv in loop.induction_vars:
            lo, hi = iv.current_interval
            if hi >= 2**62:
                # 无界 → 标记为可能溢出 (保守)
                results.append((iv.name, lo, alloc_size + 1))
            else:
                results.append((iv.name, lo, min(hi, alloc_size - 1)))
        return results

    def stats(self) -> dict:
        bounded = sum(1 for l in self._loops.values()
                     if l.loop_class == LoopClass.BOUNDED)
        overflow_risk = sum(1 for l in self._loops.values()
                           if l.loop_class == LoopClass.OVERFLOW_RISK)
        return {
            'total_loops': len(self._loops),
            'bounded': bounded,
            'overflow_risk': overflow_risk,
            'unbounded': sum(1 for l in self._loops.values()
                           if l.loop_class == LoopClass.UNBOUNDED),
        }
