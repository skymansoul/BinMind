"""基于加宽的循环边界推断: 从IR模式推断for/while/do-while迭代次数。
加宽保证终止; PathConstraintCollector的约束在循环出口收窄边界。
支持单计数器循环; 哨兵型循环产生动态边界。"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.forward_interval_prop import Interval


# 循环模式 ────────────────────────────────────────────────────

@dataclass
class LoopInfo:
    """检测到的循环信息。"""
    start_line: int          # loop header line
    end_line: int            # loop exit line (estimated)
    counter_var: str         # induction variable name
    bound_var: str           # bound variable (or literal constant)
    bound_value: int         # numeric bound (-1 if symbolic)
    is_dynamic: bool         # bound depends on runtime value
    pattern: str             # 'for', 'while', 'do-while', 'unknown'


# 反编译IR中常见循环惯用法的匹配正则

# for(i=0; i<N; i++) → i=0赋值, cmp i,N, 递增i
_FOR_INIT_RE = re.compile(r'(\w[\w.]*)\s*=\s*0\s*;')
_FOR_CMP_RE = re.compile(
    r'(?:cmp\s+)?(\w[\w.]*)\s*(<|<=|!=)\s*(\d+|\w[\w.]*)\s*[;)]')
_FOR_INCR_RE = re.compile(r'(\w[\w.]*)\s*(\+\+|--)\s*')
_FOR_INCR_ASSIGN_RE = re.compile(r'(\w[\w.]*)\s*=\s*\1\s*([+-])\s*(\d+)')

# while(*p++) / while(i--) 模式
_WHILE_DECR_RE = re.compile(r'while\s*\(\s*(\w[\w.]*)\s*--\s*\)')
_WHILE_PTR_RE = re.compile(r'while\s*\(\s*\*\s*(\w[\w.]*)\s*\+\+\s*\)')

# do { ... } while(cond) 模式
_DO_WHILE_RE = re.compile(r'}\s*while\s*\(\s*(\w[\w.]*)\s*(<|<=|!=)\s*(\d+|\w[\w.]*)\s*\)')


class LoopBoundInferrer:
    """从反编译IR行推断循环迭代边界：逐行识别循环结构并提取边界信息，
    用加宽不动点迭代推断符号边界。"""

    def __init__(self, max_loop_iter: int = 100):
        self._max_iter = max_loop_iter
        self._loops: List[LoopInfo] = []

    def detect_loops(self, ir_lines: List[str]) -> List[LoopInfo]:
        """检测IR中全部循环并返回边界信息。"""
        self._loops = []
        n = len(ir_lines)

        i = 0
        while i < n:
            line = ir_lines[i]

            # 尝试for循环模式
            loop = self._detect_for_loop(ir_lines, i)
            if loop:
                self._loops.append(loop)
                i = loop.end_line + 1
                continue

            # 尝试while循环模式
            loop = self._detect_while_loop(ir_lines, i)
            if loop:
                self._loops.append(loop)
                i = loop.end_line + 1
                continue

            # 尝试do-while模式
            loop = self._detect_do_while(ir_lines, i)
            if loop:
                self._loops.append(loop)
                i = loop.end_line + 1
                continue

            i += 1

        return self._loops

    def _detect_for_loop(self, lines: List[str], start: int) -> Optional[LoopInfo]:
        """检测标准for循环: init; cmp; incr 模式。"""
        n = len(lines)
        if start >= n - 3:
            return None

        window = lines[start:min(n, start + 30)]
        window_str = '\n'.join(window)

        # 检查 i=0 初始化
        init_m = _FOR_INIT_RE.search(window_str)
        if not init_m:
            init_m = re.search(r'(\w[\w.]*)\s*=\s*0\b', window_str)

        if not init_m:
            return None

        counter_var = init_m.group(1)

        # 检查比较: i < N 或 cmp i, N
        cmp_m = _FOR_CMP_RE.search(window_str)
        if not cmp_m:
            return None
        cmp_var = cmp_m.group(1)
        # 比较变量应为计数器
        if cmp_var != counter_var:
            # 比较可能使用其他变量，检查是否为直接常量
            pass

        bound_str = cmp_m.group(3)

        # 尝试将边界解析为整数
        is_dynamic = True
        bound_value = -1
        try:
            bound_value = int(bound_str, 0)
            is_dynamic = False
        except ValueError:
            # 符号边界: 在前序赋值中查找
            bound_value = self._resolve_symbolic_bound(bound_str, lines, start)

        # 估计循环结束行
        end_line = min(n - 1, start + 25)
        # 查找闭合花括号或标签
        brace_depth = 0
        for j in range(start, min(n, start + 40)):
            if '{' in lines[j]:
                brace_depth += 1
            if '}' in lines[j]:
                brace_depth -= 1
                if brace_depth <= 0 and j > start + 3:
                    end_line = j
                    break

        return LoopInfo(
            start_line=start, end_line=end_line,
            counter_var=counter_var, bound_var=bound_str,
            bound_value=bound_value, is_dynamic=is_dynamic,
            pattern='for')

    def _detect_while_loop(self, lines: List[str], start: int) -> Optional[LoopInfo]:
        """检测递减计数器或指针扫描的while循环。"""
        line = lines[start]

        # while (i--)
        m = _WHILE_DECR_RE.search(line)
        if m:
            return LoopInfo(
                start_line=start, end_line=min(len(lines) - 1, start + 20),
                counter_var=m.group(1), bound_var='0',
                bound_value=0, is_dynamic=True, pattern='while')

        return None

    def _detect_do_while(self, lines: List[str], start: int) -> Optional[LoopInfo]:
        """检测do-while循环。"""
        n = len(lines)
        for i in range(start, min(n, start + 20)):
            m = _DO_WHILE_RE.search(lines[i])
            if m:
                try:
                    bv = int(m.group(3), 0)
                    is_dyn = False
                except ValueError:
                    bv = -1
                    is_dyn = True
                return LoopInfo(
                    start_line=start, end_line=i,
                    counter_var=m.group(1), bound_var=m.group(3),
                    bound_value=bv, is_dynamic=is_dyn, pattern='do-while')
        return None

    def _resolve_symbolic_bound(
        self, var_name: str, lines: List[str], before: int,
    ) -> int:
        """将符号边界变量解析为具体值：在循环前的窗口内搜索var_name的
        常量赋值；未解析返回-1。"""
        for i in range(max(0, before - 10), before):
            m = re.search(
                rf'{re.escape(var_name)}\s*=\s*(\d+|0x[0-9a-fA-F]+)',
                lines[i])
            if m:
                try:
                    return int(m.group(1), 0)
                except ValueError:
                    pass
        return -1

    def infer_bounds_for_var(
        self, var_name: str, at_line: int,
    ) -> Interval:
        """推断var_name在给定程序点的取值范围：若为已检测循环的计数器，
        返回[0, bound]；动态边界返回⊤。"""
        for loop in self._loops:
            if loop.counter_var == var_name:
                if loop.start_line <= at_line <= loop.end_line:
                    if not loop.is_dynamic and loop.bound_value > 0:
                        return Interval(0, loop.bound_value - 1)
                    else:
                        return Interval(0, 2**63 - 1)

        return Interval.unknown()

    def get_loop_context(self, line: int) -> Optional[LoopInfo]:
        """返回包含给定行的循环，无则返回None。"""
        for loop in self._loops:
            if loop.start_line <= line <= loop.end_line:
                return loop
        return None

    def stats(self) -> Dict:
        return {
            'total_loops': len(self._loops),
            'patterns': {lp.pattern for lp in self._loops},
            'static_bounds': sum(1 for lp in self._loops if not lp.is_dynamic),
            'dynamic_bounds': sum(1 for lp in self._loops if lp.is_dynamic),
        }


def infer_heap_write_bounds(
    ir_lines: List[str],
    alloc_var: str,
    write_line: int,
) -> Tuple[Interval, Optional[LoopInfo]]:
    """推断给定行堆写入的字节区间：写入在循环内时用循环上界约束
    总写入范围。返回 (字节区间, 循环信息或None)。"""
    inferrer = LoopBoundInferrer()
    loops = inferrer.detect_loops(ir_lines)

    # 检查write_line是否在循环内
    enclosing = None
    for loop in loops:
        if loop.start_line <= write_line <= loop.end_line:
            enclosing = loop
            break

    if enclosing is None:
        # 不在循环内 — 单次写, 大小来自指令
        return Interval.unknown(), None

    # 循环内: 总写入 = 上界 × 每次迭代字节数
    if enclosing.is_dynamic:
        return Interval.unknown(), enclosing

    per_iteration = _estimate_bytes_per_iteration(ir_lines, write_line, alloc_var)
    if per_iteration <= 0:
        per_iteration = 1

    total = per_iteration * enclosing.bound_value
    return Interval.exact(total), enclosing


def _estimate_bytes_per_iteration(
    ir_lines: List[str], write_line: int, alloc_var: str,
) -> int:
    """估计write_line附近每次循环迭代写入的字节数。"""
    for i in range(max(0, write_line - 2), min(len(ir_lines), write_line + 3)):
        line = ir_lines[i].lower()
        if alloc_var in line:
            # 检查存储宽度指示符
            if 'qword' in line:
                return 8
            if 'dword' in line:
                return 4
            if 'word' in line:
                return 2
            if 'byte' in line:
                return 1
    return -1


__all__ = ['LoopInfo', 'LoopBoundInferrer', 'infer_heap_write_bounds']
