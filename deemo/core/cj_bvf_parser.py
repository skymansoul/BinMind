"""
DD-BVF表达式解析器 — RHS表达式解析与算术追踪.

提供RHS解析、算术运算处理和函数调用处理.
"""

import re
from typing import Optional, Set

from core.cj_bvf_types import SymbolicExpr


_TAINT_FUNCS = {
    'atoi', 'strtol', 'strtoul', 'atol',
    'scanf', 'fscanf', 'fgets', 'gets',
    'read', 'recv', 'recvfrom', 'getenv',
    'getopt', 'strtod',
}

_CONST_RE = re.compile(r'^(\d+|0x[0-9a-fA-F]+)$')
_VAR_RE = re.compile(r'^(\w+)$')
_MUL_RE = re.compile(r'^(\w+)\s*\*\s*(\d+)$')
_MUL_REV_RE = re.compile(r'^(\d+)\s*\*\s*(\w+)$')
_ADD_RE = re.compile(r'^(\w+)\s*\+\s*(\d+)$')
_SUB_RE = re.compile(r'^(\w+)\s*-\s*(\d+)$')
_ADD_VAR_RE = re.compile(r'^(\w+)\s*\+\s*(\w+)$')
_TERNARY_RE = re.compile(
    r'^\(\s*(\w+)\s*(<=|>=|<|>)\s*(\d+)\s*\)\s*\?\s*(.+?)\s*:\s*(.+)$')


def parse_rhs(
    rhs: str,
    ir_lines: list[str],
    def_line: int,
    visited: Set[str],
    tracer,
) -> SymbolicExpr:
    """解析RHS表达式, 递归追踪子变量."""
    rhs = rhs.strip().rstrip(';').strip()

    cm = _CONST_RE.match(rhs)
    if cm:
        return SymbolicExpr(const=float(int(cm.group(1), 0)),
                            origin=f"const:{rhs}")

    vm = _VAR_RE.match(rhs)
    if vm:
        v = vm.group(1)
        if v in ('NULL', 'null', '0'):
            return SymbolicExpr(const=0.0)
        return tracer.trace_var(ir_lines, v, def_line, visited)

    sub = parse_arithmetic(rhs, ir_lines, def_line, visited, tracer)
    if sub is not None:
        return sub

    ternary = _parse_ternary(rhs, ir_lines, def_line, visited, tracer)
    if ternary is not None:
        return ternary

    func_m = re.match(r'(\w+)\s*\(', rhs)
    if func_m:
        fname = func_m.group(1).lower()
        if fname in _TAINT_FUNCS:
            return _parse_taint_func(fname, rhs)
        if fname in ('malloc', 'calloc', 'realloc', 'strlen',
                     'sizeof', 'min', 'max'):
            return _parse_known_func(fname, rhs)

    return SymbolicExpr(coefs={rhs: 1.0}, origin=f"unparsed:{rhs}")


def parse_arithmetic(
    rhs: str,
    ir_lines: list[str],
    def_line: int,
    visited: Set[str],
    tracer,
) -> Optional[SymbolicExpr]:
    """解析算术表达式 (加/减/乘)."""
    m = _MUL_RE.match(rhs) or _MUL_REV_RE.match(rhs)
    if m:
        var = m.group(1) if m.re is _MUL_RE else m.group(2)
        coef = float(m.group(2) if m.re is _MUL_RE else m.group(1))
        sub = tracer.trace_var(ir_lines, var, def_line, visited)
        return SymbolicExpr(
            coefs={v: c * coef for v, c in sub.coefs.items()},
            const=sub.const * coef,
            tainted=sub.tainted,
            origin=f"{var}*{int(coef)}")

    m = _ADD_RE.match(rhs)
    if m:
        var, c = m.group(1), float(m.group(2))
        sub = tracer.trace_var(ir_lines, var, def_line, visited)
        return SymbolicExpr(
            coefs=dict(sub.coefs), const=sub.const + c,
            tainted=sub.tainted, origin=f"{var}+{int(c)}")

    m = _SUB_RE.match(rhs)
    if m:
        var, c = m.group(1), float(m.group(2))
        sub = tracer.trace_var(ir_lines, var, def_line, visited)
        return SymbolicExpr(
            coefs=dict(sub.coefs), const=sub.const - c,
            tainted=sub.tainted, origin=f"{var}-{int(c)}")

    m = _ADD_VAR_RE.match(rhs)
    if m:
        v1, v2 = m.group(1), m.group(2)
        s1 = tracer.trace_var(ir_lines, v1, def_line, visited)
        s2 = tracer.trace_var(ir_lines, v2, def_line, visited)
        merged = merge_exprs(s1, s2, 1.0, 1.0)
        merged.origin = f"{v1}+{v2}"
        return merged

    if '*' in rhs and '+' not in rhs and '-' not in rhs:
        return _parse_mul_pattern(rhs, ir_lines, def_line, visited, tracer)

    return None


def _parse_mul_pattern(
    rhs: str,
    ir_lines: list[str],
    def_line: int,
    visited: Set[str],
    tracer,
) -> Optional[SymbolicExpr]:
    """解析 var*const 和 const*var 模式."""
    parts = rhs.split('*')
    if len(parts) != 2:
        return None
    vm = _VAR_RE.match(parts[0].strip())
    cm = _CONST_RE.match(parts[1].strip())
    if vm and cm:
        sub = tracer.trace_var(ir_lines, vm.group(1), def_line, visited)
        c = float(int(cm.group(1), 0))
        return SymbolicExpr(
            coefs={v: cf * c for v, cf in sub.coefs.items()},
            const=sub.const * c, tainted=sub.tainted)
    cm2 = _CONST_RE.match(parts[0].strip())
    vm2 = _VAR_RE.match(parts[1].strip())
    if cm2 and vm2:
        sub = tracer.trace_var(ir_lines, vm2.group(1), def_line, visited)
        c = float(int(cm2.group(1), 0))
        return SymbolicExpr(
            coefs={v: cf * c for v, cf in sub.coefs.items()},
            const=sub.const * c, tainted=sub.tainted)
    return None


def _parse_ternary(
    rhs: str,
    ir_lines: list[str],
    def_line: int,
    visited: Set[str],
    tracer,
) -> Optional[SymbolicExpr]:
    """解析三元表达式: (cond) ? expr_true : expr_false.

    保守策略: 取两个分支的紧致上界.
      sz = (n <= 100) ? n : 100  →  上界 = min(n, 100) <= 100
      取else分支(const=100)作为上界, 因为true分支受cond约束.
    当else分支为常量时直接返回常量上界;
    否则取两个分支中较小的常量上界.
    """
    m = _TERNARY_RE.match(rhs)
    if not m:
        return None

    true_expr_str = m.group(4).strip()
    false_expr_str = m.group(5).strip().rstrip(';').strip()

    true_expr = _try_eval_branch(true_expr_str, ir_lines, def_line, visited, tracer)
    false_expr = _try_eval_branch(false_expr_str, ir_lines, def_line, visited, tracer)

    if true_expr is not None and false_expr is not None:
        true_val = true_expr.eval_const()
        false_val = false_expr.eval_const()
        if true_val is not None and false_val is not None:
            return SymbolicExpr(
                const=max(true_val, false_val),
                origin=f"ternary_max({rhs})")
        return false_expr if false_val is not None else true_expr

    if false_expr is not None:
        return false_expr
    if true_expr is not None:
        return true_expr

    return None


def _try_eval_branch(
    expr_str: str,
    ir_lines: list[str],
    def_line: int,
    visited: Set[str],
    tracer,
) -> Optional[SymbolicExpr]:
    """尝试求值三元表达式的一个分支."""
    cm = _CONST_RE.match(expr_str)
    if cm:
        return SymbolicExpr(const=float(int(cm.group(1), 0)),
                            origin=f"ternary_const:{expr_str}")
    vm = _VAR_RE.match(expr_str)
    if vm:
        return tracer.trace_var(ir_lines, vm.group(1), def_line, visited)
    return None


def _parse_taint_func(fname: str, rhs: str) -> SymbolicExpr:
    """解析taint函数调用."""
    arg_m = re.search(r'\(([^)]*)\)', rhs)
    arg_var = arg_m.group(1).strip() if arg_m else rhs
    base_var = re.match(r'(\w+)', arg_var)
    if base_var:
        return SymbolicExpr(
            coefs={base_var.group(1): 1.0},
            tainted=True, origin=f"{fname}({arg_var})")
    return SymbolicExpr(tainted=True, origin=rhs)


def _parse_known_func(fname: str, rhs: str) -> SymbolicExpr:
    """解析已知函数调用."""
    arg_m = re.search(r'\(([^)]*)\)', rhs)
    args = arg_m.group(1).strip() if arg_m else ""

    if fname == 'sizeof':
        cm = _CONST_RE.match(args.strip())
        if cm:
            return SymbolicExpr(const=float(int(cm.group(1), 0)),
                                origin=f"sizeof({args})")
        return SymbolicExpr(tainted=False, origin=f"sizeof({args})")

    if fname == 'strlen':
        return SymbolicExpr(tainted=True, origin=f"strlen({args})")

    if fname == 'min':
        parts = [p.strip() for p in args.split(',')]
        vals = [float(int(cm.group(1), 0)) for p in parts
                if (cm := _CONST_RE.match(p))]
        if vals:
            return SymbolicExpr(const=min(vals), origin=f"min({args})")

    if fname == 'max':
        parts = [p.strip() for p in args.split(',')]
        vals = [float(int(cm.group(1), 0)) for p in parts
                if (cm := _CONST_RE.match(p))]
        if vals:
            return SymbolicExpr(const=max(vals), origin=f"max({args})")

    return SymbolicExpr(coefs={args: 1.0} if args else {},
                        origin=f"{fname}({args})")


def merge_exprs(
    s1: SymbolicExpr, s2: SymbolicExpr,
    w1: float, w2: float,
) -> SymbolicExpr:
    """合并两个符号表达式."""
    merged = SymbolicExpr(const=s1.const * w1 + s2.const * w2)
    all_vars = set(s1.coefs.keys()) | set(s2.coefs.keys())
    for v in all_vars:
        c = s1.coefs.get(v, 0) * w1 + s2.coefs.get(v, 0) * w2
        if abs(c) > 1e-12:
            merged.coefs[v] = c
    merged.tainted = s1.tainted or s2.tainted
    return merged


__all__ = ['parse_rhs', 'parse_arithmetic', 'merge_exprs']
