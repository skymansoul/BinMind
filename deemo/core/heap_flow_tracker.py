"""
堆分配值流追踪 — 在反编译伪代码上追踪 malloc/calloc/realloc 的 size 参数来源。
定位调用点→反向溯源 (常量/用户输入/算术表达式)→正向检查约束 (if/ternary/min/max),
输出 TraceResult {size_var, source_type, is_constrained, upper_bound}; 仅追踪分配大小的数据流。
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

class SizeSource(Enum):
    CONSTANT = "constant"        # malloc(1024)
    USER_INPUT = "user_input"    # malloc(atoi(argv[1]))
    ARITHMETIC = "arithmetic"    # malloc(len * 2 + 1)
    UNKNOWN = "unknown"

@dataclass
class TraceResult:
    alloc_func: str              # malloc / calloc / realloc
    size_var: str                # size 参数的变量名或表达式
    source_type: SizeSource
    is_constrained: bool         # size 在到达 malloc 前是否经过边界检查
    upper_bound: Optional[int]   # 若 constrained=True, 记录上界
    constraint_desc: str = ""    # 约束描述, 如 "if(size > 1024) size=1024;"
    line: str = ""               # 伪代码中对应的行

class HeapFlowTracker:
    """堆分配值流追踪器 — 定位调用点, 反向溯源来源类型, 正向检测约束。"""

    _ALLOC_PAT = re.compile(
        r'(\w[\w\d_]*)\s*=\s*(?:\([^)]*\*?\s*\))?\s*'
        r'(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)'
    )
    _USER_SOURCES = {'atoi', 'atol', 'strtol', 'strtoul', 'strtoll',
                     'argv', 'getenv', 'scanf', 'fscanf', 'read',
                     'fgets', 'recv', 'getline'}
    _CONSTRAINT_PAT = re.compile(
        r'if\s*\([^)]*\)\s*\n?\s*(\w+)\s*=\s*([^;]+)'
    )

    def trace(self, pseudocode: str) -> List[TraceResult]:
        """在伪代码中追踪所有堆分配调用的 size 来源, 返回 TraceResult 列表。"""
        results: List[TraceResult] = []
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            m = self._ALLOC_PAT.search(line)
            if not m:
                dm = re.search(r'(malloc|calloc|realloc)\s*\(\s*([^)]+)\)', line)
                if dm:
                    alloc_func = dm.group(1)
                    size_expr = dm.group(2).strip().split(',')[0].strip()
                else:
                    continue
            else:
                alloc_func = m.group(2)
                size_expr = m.group(3).strip().split(',')[0].strip()

            source_type, upper_bound, constrained, constraint_desc = \
                self._classify(size_expr, lines, i)

            results.append(TraceResult(
                alloc_func=alloc_func,
                size_var=size_expr,
                source_type=source_type,
                is_constrained=constrained,
                upper_bound=upper_bound,
                constraint_desc=constraint_desc,
                line=line.strip(),
            ))

        return results

    def _classify(
        self, size_expr: str, lines: List[str], call_idx: int,
    ) -> Tuple[SizeSource, Optional[int], bool, str]:
        """分类 size 表达式的来源和约束状态。"""
        # 常量检测
        if re.match(r'^\d+$', size_expr.strip()):
            return SizeSource.CONSTANT, int(size_expr.strip()), True, 'constant literal'

        # 用户输入检测
        for src in self._USER_SOURCES:
            if src in size_expr:
                bound = self._find_constraint(size_expr, lines, call_idx)
                if bound is not None:
                    return SizeSource.USER_INPUT, bound, True, \
                        f'constrained to ≤ {bound}'
                return SizeSource.USER_INPUT, None, False, \
                    f'user-controlled via {src}'

        # 算术表达式
        if re.search(r'[*+\-/<>]', size_expr):
            bound = self._find_constraint(size_expr, lines, call_idx)
            if bound is not None:
                return SizeSource.ARITHMETIC, bound, True, \
                    f'arithmetic, constrained to ≤ {bound}'
            return SizeSource.ARITHMETIC, None, False, 'arithmetic expression'

        return SizeSource.UNKNOWN, None, False, ''

    def _find_constraint(
        self, var_name: str, lines: List[str], call_idx: int,
    ) -> Optional[int]:
        """在 malloc 调用前搜索对 var_name 的约束操作, 检测 if(var>N) var=N 或 min/MAX 模式。"""
        context = lines[max(0, call_idx - 15):call_idx]
        context_str = '\n'.join(context)

        # if(size > N) size = N;
        m = re.search(
            rf'if\s*\([^)]*{re.escape(var_name)}\s*[>]\s*(\d+)[^)]*\)\s*\n?\s*{re.escape(var_name)}\s*=\s*\1',
            context_str,
        )
        if m:
            return int(m.group(1))

        # if(size > N) size = M (M <= N)
        for m in re.finditer(
            rf'if\s*\([^)]*{re.escape(var_name)}\s*[>]\s*(\d+)[^)]*\)',
            context_str,
        ):
            n = int(m.group(1))
            after = context_str[m.end():m.end() + 100]
            assign_m = re.search(
                rf'{re.escape(var_name)}\s*=\s*(\d+)', after,
            )
            if assign_m and int(assign_m.group(1)) <= n:
                return int(assign_m.group(1))

        # min(var, N) / MAX(var, N)
        m = re.search(rf'min\s*\(\s*{re.escape(var_name)}\s*,\s*(\d+)\s*\)', context_str)
        if m:
            return int(m.group(1))
        m = re.search(rf'MAX\s*\(\s*{re.escape(var_name)}\s*,\s*(\d+)\s*\)', context_str)
        if m:
            return int(m.group(1))

        return None

def trace_heap_allocations(pseudocode: str) -> List[dict]:
    """便捷函数: 返回字典格式的追踪结果。"""
    tracker = HeapFlowTracker()
    return [
        {'alloc': r.alloc_func, 'size_expr': r.size_var,
         'source': r.source_type.value, 'constrained': r.is_constrained,
         'upper_bound': r.upper_bound, 'constraint': r.constraint_desc}
        for r in tracker.trace(pseudocode)
    ]

__all__ = ['SizeSource', 'TraceResult', 'HeapFlowTracker', 'trace_heap_allocations']
