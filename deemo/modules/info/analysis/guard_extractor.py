# analysis/guard_extractor.py — 路径守卫提取与应用
# 不依赖符号执行: 用正则识别条件守卫模式, 用区间 meet 建模约束。
#
# 守卫类型:
#   数值边界: if (n > MAX) return; → meet(n, [-inf, MAX])
#   上限钳制: if (n > max) n = max; → meet(n, [-inf, max])
#   三元上限: x = var > M ? M : var; → meet(x, [-inf, M])
#   三元下限: x = var < M ? M : var; → meet(x, [M, inf])
#   min/max:   min(x, M) / max(x, M) → meet(x, [-inf, M]) / [M, inf]
#   循环守卫: if (offset + chunk > total) break;
#
# 不做全路径守卫分析; 只对 (alloc, write) 绑定相关的守卫做机会主义利用,
# 只关注能缩小范围的守卫。

from __future__ import annotations
from typing import Dict, List, Optional
import re
from value_range_analyzer import ValueRange

def extract_relevant_guards(
    code: str,
    alloc_var: str = "",
    write_buf: str = "",
) -> List[Dict]:
    """提取与特定分配/写入变量相关的条件守卫。

    只提取能对 alloc_size 或 write_size 产生区间约束的守卫:
    - if (size > N) return;
    - x = var > M ? M : var; (三元上限)
    - min(var, M) / max(var, M)
    - 循环break守卫
    """
    guards: List[Dict] = []

    # 数值边界检查 + early exit
    for m in re.finditer(
        r'if\s*\(\s*(\w+)\s*(<|<=|>|>=|==)\s*(\d+)\s*\)\s*'
        r'(?:return|goto\s+\w+|break|continue)', code):
        guards.append({
            "var": m.group(1), "op": m.group(2),
            "value": int(m.group(3)), "pos": m.start(),
            "action": "early_exit",
        })

    # 上限钳制: if (n > max) n = max;
    for m in re.finditer(
        r'if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*(\w+)\s*=\s*\2', code):
        guards.append({
            "var": m.group(1), "op": "<=",
            "value_var": m.group(2), "pos": m.start(),
            "action": "clamp",
        })

    # 三元上限: x = var > M ? M : var;
    for m in re.finditer(
        r'(\w+)\s*=\s*(\w+)\s*[>]\s*(\d+|\w+)\s*\?\s*(\3)\s*:\s*\2', code):
        limit_val = m.group(3)
        guards.append({
            "var": m.group(1), "op": "<=",
            "value": int(limit_val) if limit_val.isdigit() else None,
            "value_var": None if limit_val.isdigit() else limit_val,
            "pos": m.start(), "action": "ternary_clamp_upper",
        })

    # 三元下限: x = var < M ? M : var;
    for m in re.finditer(
        r'(\w+)\s*=\s*(\w+)\s*[<]\s*(\d+|\w+)\s*\?\s*(\3)\s*:\s*\2', code):
        limit_val = m.group(3)
        guards.append({
            "var": m.group(1), "op": ">=",
            "value": int(limit_val) if limit_val.isdigit() else None,
            "value_var": None if limit_val.isdigit() else limit_val,
            "pos": m.start(), "action": "ternary_clamp_lower",
        })

    # min(x, M) 上限
    for m in re.finditer(r'min\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)', code):
        guards.append({
            "var": m.group(1), "op": "<=",
            "value": int(m.group(2)), "pos": m.start(),
            "action": "min_clamp",
        })

    # max(x, M) 下限
    for m in re.finditer(r'max\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)', code):
        guards.append({
            "var": m.group(1), "op": ">=",
            "value": int(m.group(2)), "pos": m.start(),
            "action": "max_clamp",
        })

    # 循环守卫: if (offset + chunk > total) break;
    for m in re.finditer(
        r'if\s*\([^)]*\+\s*\w+\s*[>]\s*\w+[^)]*\)\s*break', code):
        guards.append({
            "var": write_buf, "op": "loop_break",
            "pos": m.start(), "action": "loop_guard",
        })

    return guards

def apply_guard(
    r: ValueRange,
    guard: Dict,
    defines: Dict[str, int] = None,
) -> ValueRange:
    """对值范围应用守卫约束, 返回收缩后的区间。

    即使输入为 TOP, 也能从守卫自身的数值构建有界区间 —
    这是 CB-HOD 相比纯 VRA 的关键优势: 守卫携带信息,
    不需要先验的变量范围。
    """
    if defines is None:
        defines = {}
    if r.is_bottom:
        return r

    op = guard.get("op", "")
    val = guard.get("value")
    val_var = guard.get("value_var")

    # 若 val 为 None 但 val_var 在 defines 中, 解析之
    if val is None and val_var and val_var in defines:
        val = defines[val_var]

    # 守卫引用符号变量而非具体数值 → 无法求值, 跳过
    if val is None:
        return r

    if op == "<":
        bounded = ValueRange(float("-inf"), val - 1)
    elif op == "<=":
        bounded = ValueRange(float("-inf"), val)
    elif op == ">":
        bounded = ValueRange(val + 1, float("inf"))
    elif op == ">=":
        bounded = ValueRange(val, float("inf"))
    elif op == "==":
        bounded = ValueRange(val, val)
    else:
        return r

    if r.is_top:
        return bounded
    return r.meet(bounded)
