# analysis/size_expr_evaluator.py — 分配/写入量表达式求值器
# 将C源码中的尺寸表达式 (malloc(N*sizeof(T)), strcpy的unbounded等)
# 映射到 VRA 的抽象区间 [lo, hi], 用于约束求解。
#
# 求值层级:
#   纯数字 → ValueRange.const(val)
# define宏常量 → ValueRange.const(val)
#   var * sizeof(T) → vr.mul(ValueRange.const(sizeof_val))
#   var * CONST → vr.mul(ValueRange.const(CONST))
#   var * var → a.mul(b)
#   var + CONST → vr.add(ValueRange.const(CONST))
#   sizeof(T) → ValueRange.const(type_sz)
#   上述均不匹配 → ValueRange.top()
#
# 多态表达式需提取数值区间。

from __future__ import annotations
import re
from typing import Dict
from value_range_analyzer import ValueRange

# sizeof(T) → 字节数映射 (LP64 数据模型: x86_64)
_SIZEOF_MAP = {
    "char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
    "float": 4, "double": 8, "void*": 4, "size_t": 4,
    "void *": 4, "struct": 8, "wchar_t": 2,
}

def resolve_defines(code: str) -> Dict[str, int]:
    """从C源码提取 #define 宏常量映射。

    malloc(MAX_SIZE) 中的 MAX_SIZE 无法被 VRA 推理,
    因为 VRA 只看运行时的赋值和算术, 不看预处理器。
    """
    defines: Dict[str, int] = {}
    for m in re.finditer(r'#define\s+(\w+)\s+(\d+)\s*$', code, re.MULTILINE):
        try:
            defines[m.group(1)] = int(m.group(2))
        except ValueError:
            pass
    return defines

def eval_size_expr(
    expr: str,
    ranges: Dict[str, ValueRange],
    defines: Dict[str, int] = None,
) -> ValueRange:
    """求值分配量/写入量表达式 → ValueRange。

    支持: 纯数字 | #define宏 | 单变量 | var*sizeof(T) | var*CONST | var*var
    """
    if defines is None:
        defines = {}
    expr = expr.strip()
    if not expr or expr == "unknown":
        return ValueRange.top()

    # 纯数字
    try:
        return ValueRange.const(int(expr))
    except ValueError:
        pass

# define 宏常量
    if expr in defines:
        return ValueRange.const(defines[expr])

    # sizeof(type)
    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        return ValueRange.const(
            _SIZEOF_MAP.get(sm.group(1).strip().replace(" ", ""), 4)
        )

    # 去类型转换: (size_t)n / (unsigned)n → n
    cast = re.match(r"\(\s*\w+(?:\s*\*)?\s*\)\s*(.+)$", expr)
    if cast:
        inner = cast.group(1).strip()
        if re.match(r"^[\w\s*()]+$", inner):
            return eval_size_expr(inner, ranges, defines)

    # CONST * sizeof(T) (常量在前)
    sm = re.match(r"(\d+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        return ValueRange.const(int(sm.group(1)) * _SIZEOF_MAP.get(
            sm.group(2).strip().replace(" ", ""), 4))

    # sizeof(T) * CONST
    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*\*\s*(\d+)", expr)
    if sm:
        return ValueRange.const(_SIZEOF_MAP.get(
            sm.group(1).strip().replace(" ", ""), 4) * int(sm.group(2)))

    # var * sizeof(T)
    sm = re.match(r"(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        sz = _SIZEOF_MAP.get(sm.group(2).strip().replace(" ", ""), 4)
        return vr.mul(ValueRange.const(sz))

    # sizeof(T) * var
    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)\s*\*\s*(\w+)", expr)
    if sm:
        vr = ranges.get(sm.group(2), ValueRange.top())
        sz = _SIZEOF_MAP.get(sm.group(1).strip().replace(" ", ""), 4)
        return vr.mul(ValueRange.const(sz))

    # var * CONST
    sm = re.match(r"(\w+)\s*\*\s*(\d+)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        return vr.mul(ValueRange.const(int(sm.group(2))))

    # CONST * var
    sm = re.match(r"(\d+)\s*\*\s*(\w+)", expr)
    if sm:
        vr = ranges.get(sm.group(2), ValueRange.top())
        return vr.mul(ValueRange.const(int(sm.group(1))))

    # var * var
    sm = re.match(r"(\w+)\s*\*\s*(\w+)", expr)
    if sm:
        a = ranges.get(sm.group(1), ValueRange.top())
        b = ranges.get(sm.group(2), ValueRange.top())
        return a.mul(b)

    # var + CONST
    sm = re.match(r"(\w+)\s*\+\s*(\d+)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        return vr.add(ValueRange.const(int(sm.group(2))))

    # var - CONST
    sm = re.match(r"(\w+)\s*-\s*(\d+)", expr)
    if sm:
        vr = ranges.get(sm.group(1), ValueRange.top())
        return vr.sub(ValueRange.const(int(sm.group(2))))

    # CONST + var
    sm = re.match(r"(\d+)\s*\+\s*(\w+)", expr)
    if sm:
        vr = ranges.get(sm.group(2), ValueRange.top())
        return vr.add(ValueRange.const(int(sm.group(1))))

    # 单变量
    if expr in ranges:
        return ranges[expr]

    return ValueRange.top()

def eval_write_size(
    size_expr: str,
    func: str,
    ranges: Dict[str, ValueRange],
    defines: Dict[str, int] = None,
) -> ValueRange:
    """求值写入量表达式 — 含特殊写入语义。

    strcpy/gets 等无界写入 → TOP
    手动循环写入 → TOP (迭代次数不可静态推断)
    其他 → 委托 eval_size_expr
    """
    if size_expr in ("unbounded", "loop_bounded"):
        return ValueRange.top()
    return eval_size_expr(size_expr, ranges, defines)

def is_size_var(var: str, size_expr: str) -> bool:
    """检查变量是否参与尺寸表达式的乘法因子。"""
    return var in size_expr.split('*') and var.strip() in size_expr
