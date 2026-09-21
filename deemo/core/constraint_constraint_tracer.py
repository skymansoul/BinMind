"""
约束追踪辅助函数: 从 IR/伪代码中反向追踪变量约束: 常量赋值追踪 (var = N 判等式约束)、类型上界推断 (uint8_t var 判 var <= 255)、守卫上界搜索 (if(var>N) var=N 或 var=min(var,N) 判上界约束)。
"""

from __future__ import annotations
import re

from core.constraint_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem,
)


def trace_constant_assignment(
    ir_lines: list[str],
    var: str,
    start_pc: int,
    sys: ConstraintSystem,
    ctype: ConstraintType,
    label: str,
) -> None:
    """反向追踪变量的常量赋值, 生成等式约束.

    支持:
      var = N
      #define VAR N (宏定义)
      var = other_var + N (表达式赋值, 追踪other_var)
    """
    # 模式1: 直接常量赋值 var = N
    pat = re.compile(rf'{re.escape(var)}\s*=\s*(\d+)')
    for i in range(start_pc, -1, -1):
        m = pat.search(ir_lines[i])
        if m:
            val = int(m.group(1))
            sys.add(LinearConstraint(
                coefficients={var: 1.0},
                constant=float(-val),
                operator="==",
                source=ctype,
                confidence=0.95,
                description=f"{label}_var {var} = {val} (const assign)",
            ))
            return

    # 模式2: 宏定义 #define VAR N
    for i in range(min(len(ir_lines), start_pc + 1)):
        line = ir_lines[i].strip()
        m_def = re.match(
            rf'#define\s+{re.escape(var)}\s+(\d+)', line)
        if m_def:
            val = int(m_def.group(1))
            sys.add(LinearConstraint(
                coefficients={var: 1.0},
                constant=float(-val),
                operator="==",
                source=ctype,
                confidence=0.95,
                description=f"{label}_var {var} = {val} (#define)",
            ))
            return

    # 模式3: 表达式赋值 var = other_var + N
    expr_pat = re.compile(
        rf'{re.escape(var)}\s*=\s*(\w+)\s*\+\s*(\d+)')
    for i in range(start_pc, -1, -1):
        m = expr_pat.search(ir_lines[i])
        if m:
            other_var = m.group(1)
            const_offset = int(m.group(2))
            # 递归追踪other_var
            trace_constant_assignment(
                ir_lines, other_var, i, sys, ctype, label)
            # 添加线性关系: var = other_var + N 即 var - other_var = N
            sys.add(LinearConstraint(
                coefficients={var: 1.0, other_var: -1.0},
                constant=float(-const_offset),
                operator="==",
                source=ctype,
                confidence=0.90,
                description=f"{label}_var {var} = {other_var} + {const_offset}",
            ))
            return


def trace_type_bound(
    ir_lines: list[str],
    var: str,
    start_pc: int,
    sys: ConstraintSystem,
    ctype: ConstraintType,
) -> None:
    """从类型声明推断变量上界, 生成不等式约束.

    同时标记函数参数为外部可控(TAINTED), 缺乏上界约束.
    """
    type_bounds = {
        'uint8_t': 255, 'int8_t': 127,
        'uint16_t': 65535, 'int16_t': 32767,
        'uint32_t': 0xFFFFFFFF, 'int32_t': 0x7FFFFFFF,
        'size_t': 0xFFFFFFFFFFFFFFFF,
        'unsigned int': 0xFFFFFFFF,
        'unsigned': 0xFFFFFFFF,
    }
    for i in range(max(0, start_pc - 10), min(len(ir_lines), start_pc + 1)):
        for tname, bound in type_bounds.items():
            if re.search(rf'{tname}\s+.*{re.escape(var)}', ir_lines[i]):
                sys.add(LinearConstraint(
                    coefficients={var: 1.0},
                    constant=float(-bound),
                    operator="<=",
                    source=ctype,
                    confidence=0.90,
                    description=f"type bound: {var} is {tname} <= {bound}",
                ))
                return

    # 函数参数追踪: 标记为外部可控(无上界), 添加到var_names
    func_sig = re.search(
        r'(?:int|void|char|size_t|unsigned)\s+\w+\s*\([^)]*\b'
        rf'{re.escape(var)}\b[^)]*\)',
        '\n'.join(ir_lines[:max(1, start_pc)]))
    if func_sig:
        sys.add(LinearConstraint(
            coefficients={var: 1.0},
            constant=0.0,
            operator="<=",
            source=ctype,
            confidence=0.30,
            description=f"param: {var} is function parameter (external)",
        ))


def trace_guard_upper_bound(
    ir_lines: list[str],
    var: str,
    start_pc: int,
    sys: ConstraintSystem,
    ctype: ConstraintType,
    label: str,
) -> None:
    """在调用点附近搜索if(var>N)var=N或var=min(var,N)约束."""
    context = ir_lines[max(0, start_pc - 15):start_pc]
    context_str = "\n".join(context)

    m = re.search(
        rf'if\s*\([^)]*{re.escape(var)}\s*>\s*(\d+)[^)]*\)\s*\n?\s*'
        rf'{re.escape(var)}\s*=\s*(\d+)',
        context_str)
    if m:
        cap = int(m.group(2))
        sys.add(LinearConstraint(
            coefficients={var: 1.0},
            constant=float(-cap),
            operator="<=",
            source=ctype,
            confidence=0.90,
            description=f"guard: {var} capped to {cap}",
        ))
        return

    m = re.search(
        rf'{re.escape(var)}\s*=\s*min\s*\(\s*\w+\s*,\s*(\d+)\s*\)',
        context_str, re.IGNORECASE)
    if m:
        cap = int(m.group(1))
        sys.add(LinearConstraint(
            coefficients={var: 1.0},
            constant=float(-cap),
            operator="<=",
            source=ctype,
            confidence=0.90,
            description=f"guard: {var} = min(_, {cap})",
        ))


__all__ = [
    'trace_constant_assignment',
    'trace_type_bound',
    'trace_guard_upper_bound',
]
