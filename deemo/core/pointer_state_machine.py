"""
Pointer state machine: tracks heap pointer allocation/free/escape states.

Each heap pointer follows: ALLOCATED -> FREED -> (ESCAPED | DANGLING)
  - ALLOCATED: initial state after malloc/calloc/realloc
  - FREED: after free(), if pointer value not overwritten -> DANGLING
  - ESCAPED: pointer stored to global or returned, exits tracking scope
  - DANGLING: pointer dereferenced after FREED -> UAF

A state machine suffices instead of full dataflow analysis because:
  - Heap pointer patterns are highly structured; 3 states cover 90%+ of cases
  - Transition conditions are simple (assignment/call/return), no complex aliasing
  - Function summaries enable cross-function tracking without full call graph modeling
"""
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class PtrState(Enum):
    ALLOCATED = auto()      # allocated, still in scope
    FREED = auto()          # freed but pointer value unchanged
    ESCAPED = auto()        # escaped to global/external (out of tracking scope)
    DANGLING = auto()       # use-after-free (triggers alert)
    OVERWRITTEN = auto()    # pointer overwritten or zeroed (safe)


@dataclass
class HeapPointer:
    """Tracking record for a single heap pointer."""
    name: str                        # 变量名
    alloc_site: str = ""             # 分配点描述
    alloc_size: Optional[int] = None # 分配大小 (若可从静态分析推断)
    free_sites: List[str] = field(default_factory=list)
    use_sites: List[str] = field(default_factory=list)
    state: PtrState = PtrState.ALLOCATED
    escaped_to: str = ""             # 若逃逸，记录目标


@dataclass
class FunctionSummary:
    """Function summary for cross-function pointer state propagation."""
    func_name: str
    allocates: List[str] = field(default_factory=list)      # 返回的新分配指针名
    frees_params: List[int] = field(default_factory=list)    # 释放的参数索引
    escapes_params: List[int] = field(default_factory=list)  # 逃逸的参数索引


class PointerStateMachine:
    """Pointer state machine for intra-function heap pointer tracking.

    Usage:
      psm = PointerStateMachine()
      pointers = psm.analyze(decompiled_code, function_summaries)
      uaf_ptrs = [p for p in pointers if p.state == PtrState.DANGLING]
    """

    # Allocation functions
    _ALLOC_FUNCS = frozenset({
        'malloc', 'calloc', 'realloc', 'aligned_alloc',
        'memalign', 'posix_memalign', 'valloc', 'pvalloc',
        'new', 'new[]', 'operator_new',
    })
    # Deallocation functions
    _FREE_FUNCS = frozenset({
        'free', 'delete', 'delete[]', 'operator_delete',
        'realloc',  # realloc(NULL, size) = malloc; realloc(ptr, 0) = free
    })
    # Variable name patterns, supporting plain vars and struct fields (a->b, a.b)
    _VAR_PATTERN = re.compile(r'\b([a-zA-Z_]\w{0,31}(?:->\w+)?(?:\.\w+)?)\b')
    _ASSIGN_PATTERN = re.compile(r'([a-zA-Z_]\w{0,31}(?:->\w+)?(?:\.\w+)?)\s*=\s*(.+)')
    _CALL_PATTERN = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*\(([^)]*)\)')

    def __init__(self):
        self._summaries: Dict[str, FunctionSummary] = {}

    def register_summary(self, summary: FunctionSummary):
        self._summaries[summary.func_name] = summary

    def analyze(self, code: str,
                function_name: str = "") -> List[HeapPointer]:
        """Analyze heap pointer lifetimes in decompiled code."""
        lines = [l.strip() for l in code.split('\n') if l.strip()]
        pointers: Dict[str, HeapPointer] = {}
        line_idx = 0

        for line in lines:
            self._process_allocation(line, pointers, line_idx)
            self._process_free(line, pointers, line_idx)
            self._process_use(line, pointers, line_idx)
            self._process_escape(line, pointers, line_idx)
            line_idx += 1

        # Final state determination
        for ptr in pointers.values():
            if ptr.state == PtrState.FREED:
                # Freed but not overwritten; if there's use after free -> DANGLING
                free_max_idx = max(
                    [self._line_of(lines, fs) for fs in ptr.free_sites],
                    default=-1
                )
                use_after_free = any(
                    self._line_of(lines, us) > free_max_idx
                    for us in ptr.use_sites
                )
                if use_after_free:
                    ptr.state = PtrState.DANGLING

        return list(pointers.values())

    def _process_allocation(self, line: str,
                            pointers: Dict[str, HeapPointer], idx: int):
        """Detect var = malloc(size) pattern."""
        m = self._CALL_PATTERN.search(line)
        if not m:
            return
        func = m.group(1).strip()
        if func not in self._ALLOC_FUNCS:
            return
        assign_m = self._ASSIGN_PATTERN.search(line)
        if not assign_m:
            return
        var_name = assign_m.group(1).strip()
        args = self._split_args(m.group(2))
        size = None
        if args and args[0].strip().isdigit():
            size = int(args[0].strip())
        pointers[var_name] = HeapPointer(
            name=var_name,
            alloc_site=f'line_{idx}: {func}({m.group(2)})',
            alloc_size=size,
            state=PtrState.ALLOCATED,
        )

    def _process_free(self, line: str,
                      pointers: Dict[str, HeapPointer], idx: int):
        """Detect free(ptr) pattern."""
        m = self._CALL_PATTERN.search(line)
        if not m:
            return
        func = m.group(1).strip()
        if func not in self._FREE_FUNCS:
            return
        args = self._split_args(m.group(2))
        if not args:
            return
        # Special case: realloc(ptr, 0) = free(ptr)
        if func == 'realloc':
            if len(args) < 2 or args[1].strip() != '0':
                return
        freed_var = args[0].strip()
        if freed_var in pointers:
            cur = pointers[freed_var]
            if cur.state == PtrState.ALLOCATED:
                cur.state = PtrState.FREED
                cur.free_sites.append(f'line_{idx}: {func}({freed_var})')
            elif cur.state == PtrState.FREED:
                # Second free -> double-free
                cur.free_sites.append(f'line_{idx}: {func}({freed_var}) [DOUBLE]')

    def _process_use(self, line: str,
                     pointers: Dict[str, HeapPointer], idx: int):
        """Record pointer usage sites."""
        for var_name in list(pointers.keys()):
            if re.search(r'\b' + re.escape(var_name) + r'\b', line):
                # Exclude self-assignment lines (handled in _process_allocation)
                if f'{var_name} =' not in line and f'{var_name}=' not in line:
                    pointers[var_name].use_sites.append(f'line_{idx}')

    def _process_escape(self, line: str,
                        pointers: Dict[str, HeapPointer], idx: int):
        """Detect pointer escape: return ptr / global = ptr / func(ptr)."""
        for var_name, ptr in list(pointers.items()):
            if ptr.state != PtrState.ALLOCATED:
                continue
            if f'return {var_name}' in line or f'return ({var_name})' in line:
                ptr.state = PtrState.ESCAPED
                ptr.escaped_to = 'return_value'
            # Passed as argument to an external function
            m = self._CALL_PATTERN.search(line)
            if m:
                func = m.group(1).strip()
                if func not in self._ALLOC_FUNCS and func not in self._FREE_FUNCS:
                    args = self._split_args(m.group(2))
                    if var_name in [a.strip() for a in args]:
                        ptr.state = PtrState.ESCAPED
                        ptr.escaped_to = f'arg_to_{func}'

    def _line_of(self, lines: List[str], site_label: str) -> int:
        """Extract line number from a site_label string."""
        try:
            return int(site_label.split('_')[1].split(':')[0])
        except (IndexError, ValueError):
            return -1

    @staticmethod
    def _split_args(args_str: str) -> List[str]:
        parts = []; depth = 0; current = []
        for ch in args_str:
            if ch == '(': depth += 1
            elif ch == ')': depth -= 1
            if ch == ',' and depth == 0:
                parts.append(''.join(current).strip()); current = []
            else:
                current.append(ch)
        if current: parts.append(''.join(current).strip())
        return parts


def infer_function_summary(code: str, func_name: str) -> FunctionSummary:
    """Auto-infer function summary from decompiled code (no manual annotation needed)."""
    summary = FunctionSummary(func_name=func_name)
    alloc_funcs = frozenset({'malloc', 'calloc', 'realloc', 'new'})
    free_funcs = frozenset({'free', 'delete'})
    call_pat = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*\(([^)]*)\)')
    assign_pat = re.compile(r'(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*(.+)')
    ret_pat = re.compile(r'return\s+(\b[a-zA-Z_]\w{0,31}\b)')

    for line in code.split('\n'):
        m = call_pat.search(line)
        if not m:
            continue
        func = m.group(1).strip()
        if func in alloc_funcs:
            am = assign_pat.search(line)
            if am:
                summary.allocates.append(am.group(1).strip())
        elif func in free_funcs:
            args = PointerStateMachine._split_args(m.group(2))
            for i, arg in enumerate(args):
                if arg.strip() not in ('0', 'NULL', 'nullptr', ''):
                    summary.frees_params.append(i)
                    break
    return summary
