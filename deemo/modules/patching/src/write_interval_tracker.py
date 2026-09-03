# 写侧值流区间抽象 — 从写入调用点提取写大小的取值区间
"""写侧区间抽象的核心动机:
  既有流水线对写入侧仅提取单一常量(或0=未知), 未知时求解器退化为
  "alloc.lower >= 0 → 不溢出" → 真实溢出被误滤为FP, 召回崩塌。
  本模块对 memcpy/strcpy 等写入调用点的 size 参数做需求驱动的值流回溯,
  输出 [w_low, w_high] 区间, 并合并路径守卫(cmov cap / and mask /
  cmp+jcc)对上界的收紧。

设计决策:
  - 复用 heap_expr_tracker 的寄存器回溯逻辑构建表达式, 再转区间
  - 表达式含 cap_value(高) / floor_value(低) → eval_max/eval_min 已生效
  - 额外收集 write size 寄存器的 AND-mask 与 cmp+jcc 守卫
  - 未知写入(无法回溯)返回 is_known=False, 调用方不得判cannot_overflow
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class WriteInterval:
    """写侧区间结果。"""
    low: int = 0
    high: int = 0x7FFFFFFF
    is_known: bool = False       # 能否确定上界
    is_tainted: bool = False
    expr_str: str = ""
    guards_collected: int = 0
    reason: str = ""

    def to_dict(self) -> Dict:
        return {
            'low': self.low, 'high': self.high,
            'is_known': self.is_known, 'is_tainted': self.is_tainted,
            'expr': self.expr_str, 'guards': self.guards_collected,
        }


# 无显式size的写入函数 → 上界不可知, 下界=1
_UNBOUNDED_WRITE_FUNCS = re.compile(
    r'\b(strcpy|strcat|gets|sprintf|wcscpy|mbscpy|vsprintf)\b', re.I)

# 有size参数的写入函数
_SIZE_WRITE_FUNCS = re.compile(
    r'\b(memcpy|memmove|strncpy|strncat|snprintf|bcopy|__mingw_memcpy|'
    r'__mingw_memmove)\b', re.I)

# size寄存器: MS x64 = r8, SysV = rdx
_SIZE_REGS = ('r8', 'r8d', 'rdx', 'edx')


class WriteIntervalTracker:
    """写侧区间追踪器 — 需求驱动, 只在写入调用点回溯。"""

    def __init__(self):
        from .heap_expr_tracker import _is_unbounded_write
        self._is_unbounded = _is_unbounded_write
        # 延迟导入路径守卫收集器
        self._guard_collector = None

    def _get_guard_collector(self):
        if self._guard_collector is None:
            from .heap_guard_collector import PathGuardCollector
            self._guard_collector = PathGuardCollector()
        return self._guard_collector

    def trace(self, asm_lines: List[str], write_line: int,
              func_name: str = "") -> WriteInterval:
        """从写入调用点回溯size参数的取值区间。"""
        func = (func_name or '').lower()

        # 无显式size的写入 → 上界不可知
        if self._is_unbounded(func):
            return WriteInterval(
                low=1, high=0x7FFFFFFF, is_known=False,
                is_tainted=True, expr_str=f'{func}:unbounded',
                reason='无显式size参数, 上界不可知')

        # 有size参数 → 回溯表达式
        try:
            from .heap_expr_tracker import build_write_expr
            lowered = [l.strip().lower().replace(',', ' ') for l in asm_lines]
            w_val, w_tainted, w_expr = build_write_expr(
                asm_lines, lowered, write_line, func)
        except Exception:
            return WriteInterval(reason='expr_trace_failed')

        if w_expr is not None:
            w_max = w_expr.eval_max()
            w_min = w_expr.eval_min()
            # cap_value>0且<MAX → 上界已知
            is_known = w_max < 0x7FFFFFFF
            guards = self._collect_guard_bounds(asm_lines, write_line, w_expr)
            if guards and guards[0] < w_max:
                w_max = guards[0]
                is_known = True
            return WriteInterval(
                low=max(0, w_min), high=w_max, is_known=is_known,
                is_tainted=w_tainted, expr_str=w_expr.to_str(),
                guards_collected=self._count_guards(asm_lines, write_line),
                reason='expr_interval')

        # 表达式无法构建但值已知(常量)
        if w_val > 0:
            return WriteInterval(
                low=w_val, high=w_val, is_known=True,
                is_tainted=False, expr_str=f'const:{w_val}',
                reason='const_write_size')

        return WriteInterval(reason='unknown_write_size')

    # 守卫收集: 对write size寄存器的约束
    def _write_size_reg(self, asm_lines: List[str], write_line: int) -> str:
        """回溯找write size寄存器的来源寄存器(用于守卫收集)。"""
        for j in range(write_line - 1, max(write_line - 8, -1), -1):
            line = asm_lines[j].strip().lower().replace(',', ' ')
            for reg in _SIZE_REGS:
                m = re.search(r'\bmov\s+' + reg + r',?\s*(\w+)', line)
                if m and m.group(1) not in ('qword', 'dword', 'ptr'):
                    return m.group(1)
        return ''

    def _collect_guard_bounds(self, asm_lines: List[str], write_line: int,
                              expr) -> Tuple[int, ...]:
        """收集write size寄存器的守卫上界, 返回候选bound列表。"""
        reg = self._write_size_reg(asm_lines, write_line)
        if not reg:
            return ()
        bounds = []
        collector = self._get_guard_collector()
        start = max(write_line - 40, 0)
        end = write_line
        # TODO: 守卫收集窗口固定40行, 跨函数守卫(调用点约束)未覆盖
        try:
            guards = collector.collect(asm_lines, reg, (start, end))
        except Exception:
            return ()
        for g in guards:
            if g.bound > 0:
                bounds.append(g.bound)
        return tuple(sorted(bounds))

    def _count_guards(self, asm_lines: List[str], write_line: int) -> int:
        reg = self._write_size_reg(asm_lines, write_line)
        if not reg:
            return 0
        try:
            from .heap_path_sensitivity import GuardKind
            collector = self._get_guard_collector()
            start = max(write_line - 40, 0)
            guards = collector.collect(asm_lines, reg, (start, write_line))
            return len(guards)
        except Exception:
            return 0
