"""
DD-BVF反向值流符号追踪器 — 从告警点反向构建size变量的符号表达式.

当CJ求解器返回INCONCLUSIVE时, 从告警点反向追踪alloc_size和
write_size的完整定义链, 构建符号表达式, 通过相关性证明过滤误报.

追踪规则:
  x = 5           → x = {const: 5}
  x = y           → x = y的expr
  x = y + 3       → x = y.coefs, const = y.const + 3
  x = y * 2       → x = {y: 2}, const = 0
  x = y + z       → x = {y: 1, z: 1}, const = 0
  x = atoi(argv)  → x = {x: 1}, tainted=True

安全性判定委派给cj_bvf_correlator.correlate.
表达式解析委派给cj_bvf_parser.parse_rhs.
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Set, Tuple

from core.cj_bvf_types import SymbolicExpr, CorrelationResult
from core.cj_bvf_parser import parse_rhs, parse_arithmetic
from core.cj_bvf_correlator import correlate as _correlate


_CONST_RE = re.compile(r'^(\d+|0x[0-9a-fA-F]+)$')
_ASSIGN_RE = re.compile(r'(\w+)\s*=\s*(.+?)(?:;|$)', re.MULTILINE)
_TYPED_ASSIGN_RE = re.compile(
    r'(?:(?:int|char|size_t|unsigned|long|short|void|float|double|'
    r'uint\d+_t|int\d+_t|u_int\d+_t|__\w+)\s+\*?\s*)+'
    r'(\w+)\s*=\s*(.+?)(?:;|$)', re.MULTILINE)


class BackwardValueFlow:
    """反向值流符号追踪器.

    从目标行反向扫描, 构建变量的SymbolicExpr.
    支持多跳赋值链(最多max_hops跳).
    """

    def __init__(self, max_hops: int = 12, window: int = 80):
        self._max_hops = max_hops
        self._window = window

    def trace_var(
        self,
        ir_lines: List[str],
        var: str,
        from_line: int,
        visited: Optional[Set[str]] = None,
    ) -> SymbolicExpr:
        """反向追踪var的符号表达式, 从from_line向上搜索."""
        if visited is None:
            visited = set()

        if var in visited:
            return SymbolicExpr(coefs={var: 1.0}, tainted=False,
                                origin=f"{var}(cyclic)")
        visited = visited | {var}

        cm = _CONST_RE.match(var.strip())
        if cm:
            return SymbolicExpr(const=float(int(cm.group(1), 0)),
                                origin=f"const:{var}")

        expr_from_rhs = self._try_parse_expr_direct(
            var, ir_lines, from_line, visited)
        if expr_from_rhs is not None:
            return expr_from_rhs

        for hop in range(self._max_hops):
            def_line, def_rhs = self._find_def(
                ir_lines, var, from_line)
            if def_line < 0:
                return self._handle_no_def(var, ir_lines, from_line)

            # 条件赋值检测: if(var > guard) var = guard → var = min(var_old, guard)
            # 此时var的上界应取初始赋值(而非clamp值), 因为clamp后值域收窄
            guarded = self._check_guarded_clamp(
                ir_lines, var, def_line, def_rhs, visited)
            if guarded is not None:
                return guarded

            expr = parse_rhs(
                def_rhs, ir_lines, def_line, visited, self)
            expr.origin = f"{var}@{def_line}: {def_rhs}"
            return expr

        return SymbolicExpr(coefs={var: 1.0}, origin=f"{var}(max_hops)")

    def trace_alloc_size(
        self,
        ir_lines: List[str],
        alloc_func: str,
        size_expr_str: str,
        alloc_pc: int,
    ) -> SymbolicExpr:
        """追踪分配大小参数的符号表达式."""
        if not size_expr_str:
            return SymbolicExpr()

        cm = _CONST_RE.match(size_expr_str.strip())
        if cm:
            return SymbolicExpr(const=float(int(cm.group(1), 0)),
                                origin=f"const:{size_expr_str}")

        return self.trace_var(ir_lines, size_expr_str.strip(), alloc_pc)

    def trace_write_size(
        self,
        ir_lines: List[str],
        store_line: int,
        mnemonic: str,
        store_size: int,
    ) -> SymbolicExpr:
        """追踪写入大小的符号表达式."""
        if store_size > 0:
            return SymbolicExpr(const=float(store_size),
                                origin=f"store_size:{store_size}")

        line = ir_lines[store_line] if store_line < len(ir_lines) else ""

        m = re.search(
            r'(?:memcpy|memmove|memset|strncpy|strncat)\s*\('
            r'[^,]+,\s*[^,]+,\s*([^)]+)\)', line)
        if m:
            return self.trace_var(ir_lines, m.group(1).strip(), store_line)

        return SymbolicExpr(tainted=True, origin="unbounded_copy")

    def correlate(
        self,
        alloc_expr: SymbolicExpr,
        write_expr: SymbolicExpr,
        offset_expr: SymbolicExpr = None,
    ) -> CorrelationResult:
        """判定alloc-write符号相关性, 委派给correlator模块."""
        return _correlate(alloc_expr, write_expr, offset_expr)

    def _try_parse_expr_direct(
        self,
        expr_str: str,
        ir_lines: List[str],
        from_line: int,
        visited: Set[str],
    ) -> Optional[SymbolicExpr]:
        """尝试直接解析表达式(常量/算术)."""
        expr_str = expr_str.strip().rstrip(';').strip()
        cm = _CONST_RE.match(expr_str)
        if cm:
            return SymbolicExpr(const=float(int(cm.group(1), 0)),
                                origin=f"const:{expr_str}")

        sub = parse_arithmetic(
            expr_str, ir_lines, from_line, visited, self)
        if sub is not None:
            return sub

        return None

    def _find_def(
        self,
        ir_lines: List[str],
        var: str,
        before: int,
    ) -> Tuple[int, str]:
        """从before向上搜索var的赋值语句."""
        start = max(0, before - self._window)
        for i in range(before - 1, start - 1, -1):
            if i >= len(ir_lines):
                continue
            stripped = ir_lines[i].strip()
            m = _ASSIGN_RE.match(stripped)
            if m and m.group(1) == var:
                return i, m.group(2).strip()
            m = _TYPED_ASSIGN_RE.match(stripped)
            if m and m.group(1) == var:
                return i, m.group(2).strip()
        return -1, ""

    def _handle_no_def(
        self,
        var: str,
        ir_lines: List[str],
        from_line: int,
    ) -> SymbolicExpr:
        """变量在窗口内无定义时的处理."""
        param_pat = re.compile(
            rf'\b(?:int|char|size_t|unsigned|long|short|void)\s+\*?\s*'
            rf'{re.escape(var)}\b')
        for i in range(max(0, from_line - self._window), from_line):
            if param_pat.search(ir_lines[i]):
                return SymbolicExpr(
                    coefs={var: 1.0}, tainted=False,
                    origin=f"{var}(param)")
        return SymbolicExpr(
            coefs={var: 1.0}, tainted=False,
            origin=f"{var}(no_def)")

    def _check_guarded_clamp(
        self,
        ir_lines: List[str],
        var: str,
        def_line: int,
        def_rhs: str,
        visited: Set[str],
    ) -> Optional[SymbolicExpr]:
        """检测条件赋值clamp模式: if(var > bound) var = bound.

        语义: var = min(var_old, bound), 此时var的上界仍为var_old,
        而非clamp后的bound. 追踪初始赋值以保留完整值域.
        模式: IR中def_line上方有 'if(var > ...)' 守卫,
        且var在守卫前另有初始赋值.
        """
        # 向上搜索最多10行, 寻找守卫条件
        start = max(0, def_line - 10)
        for i in range(def_line - 1, start - 1, -1):
            if i < 0 or i >= len(ir_lines):
                continue
            line = ir_lines[i].strip()
            # 匹配 if(var > expr) 或 if(var >= expr), 允许行首有 call 等前缀
            m = re.search(
                rf'if\s*\(\s*{re.escape(var)}\s*(>|>=)\s*(.+?)\s*\)', line)
            if m:
                # 找到守卫, 继续向上寻找var的初始赋值(在守卫之前)
                init_line, init_rhs = self._find_def(
                    ir_lines, var, i)
                if init_line >= 0 and init_line < i:
                    init_expr = parse_rhs(
                        init_rhs, ir_lines, init_line, visited, self)
                    init_expr.origin = (
                        f"{var}@{init_line}(clamp_guard): "
                        f"min({init_rhs}, {def_rhs})")
                    return init_expr
                break
            # 遇到非守卫行且是赋值则停止搜索
            if _ASSIGN_RE.match(line) or _TYPED_ASSIGN_RE.match(line):
                break
        return None


__all__ = [
    'SymbolicExpr', 'CorrelationResult', 'BackwardValueFlow',
]
