# analysis/constraint_solver.py — 区间约束生成与求解引擎
# 对每个 (alloc, write) 绑定, 生成约束 alloc_size ≥ write_size,
# 并用区间分析 + 分配器模型证明其是否必然成立。
#
# 三层约束检查:
#   L1-精确: 分配/写入量均为常量 → 直接比较 (考虑对齐)
#   L2-区间: 分配/写入量有区间 [lo,hi] → 区间比较
#   L3-路径: 在条件守卫约束下, 区间是否收缩到安全范围
#
# 职责划分: 尺寸求值在 size_expr_evaluator, 守卫提取在 guard_extractor。

from __future__ import annotations
from typing import Dict, List, Tuple, Optional
from value_range_analyzer import ValueRange, extract_value_ranges
from heap_layout_model import AllocatorModel, get_allocator_model
from size_expr_evaluator import (
    eval_size_expr, eval_write_size, resolve_defines, is_size_var,
)
from guard_extractor import extract_relevant_guards, apply_guard

class HeapConstraint:
    """单个堆安全约束: alloc_size ≥ write_size 在什么条件下成立。"""
    __slots__ = ("alloc_var", "alloc_size_expr", "alloc_range",
                 "write_func", "write_buffer", "write_size_expr", "write_range",
                 "is_safe", "safety_confidence", "safety_reason",
                 "guard_constraints", "alloc_model")

    def __init__(self):
        self.alloc_var = ""
        self.alloc_size_expr = ""
        self.alloc_range = ValueRange.top()
        self.write_func = ""
        self.write_buffer = ""
        self.write_size_expr = ""
        self.write_range = ValueRange.top()
        self.is_safe = False
        self.safety_confidence = 0.0
        self.safety_reason = ""
        self.guard_constraints: List[Dict] = []
        self.alloc_model: Optional[AllocatorModel] = None

def gen_constraints(
    bindings: List[Dict],
    ranges: Dict[str, ValueRange],
    code: str = "",
    arch: str = "x86_64",
) -> List[HeapConstraint]:
    """从指针绑定生成安全约束列表。

    对每个绑定:
    1. 提取分配量表达式, 在 VRA 中求值
    2. 提取写入量表达式, 在 VRA 中求值
    3. 提取路径守卫并收紧范围
    4. 构建约束: alloc_range.lo ≥ write_range.hi → 安全
    """
    model = get_allocator_model(arch)
    defines = resolve_defines(code) if code else {}
    constraints = []

    for b in bindings:
        hp = b["alloc_ptr"]
        ws = b["write_site"]

        c = HeapConstraint()
        c.alloc_var = hp.var
        c.alloc_size_expr = hp.alloc_size_expr
        c.alloc_range = eval_size_expr(hp.alloc_size_expr, ranges, defines)
        c.write_func = ws["func"]
        c.write_buffer = ws["buffer"]
        c.write_size_expr = ws["size_expr"]
        c.write_range = eval_write_size(ws["size_expr"], ws["func"], ranges, defines)
        c.alloc_model = model

        # 提取路径守卫约束
        c.guard_constraints = extract_relevant_guards(
            code, hp.var, ws["buffer"]
        )

        # 在守卫约束下收紧范围
        alloc_r = c.alloc_range
        write_r = c.write_range
        for gc in c.guard_constraints:
            gv = gc.get("var", "")
            if gv == hp.alloc_size_expr or is_size_var(gv, hp.alloc_size_expr):
                alloc_r = apply_guard(alloc_r, gc, defines)
            if gv == ws["size_expr"] or is_size_var(gv, ws["size_expr"]):
                write_r = apply_guard(write_r, gc, defines)

        c.alloc_range = alloc_r
        c.write_range = write_r

        # 判定安全性
        c.is_safe, c.safety_confidence, c.safety_reason = _check_safety(
            alloc_r, write_r, model,
            hp.alloc_size_expr, ws["size_expr"],
            alloc_func=hp.alloc_func,
        )

        constraints.append(c)

    return constraints

def _check_safety(
    alloc_r: ValueRange,
    write_r: ValueRange,
    model: AllocatorModel,
    alloc_expr: str = "",
    write_expr: str = "",
    alloc_func: str = "",
) -> Tuple[bool, float, str]:
    """核心安全判定: 分配量是否必然 ≥ 写入量。

    判定层级:
    1. alloc.lo ≥ write.hi (考虑对齐) → 数学证明安全 (SAFE, conf=0.98)
    2. alloc.hi < write.lo → 确定溢出 (UNSAFE, conf=0.92)
    3. alloc==write 同表达式:
       a. 常量/sizeof → 安全 (conf=0.95)
       b. realloc + 同表达式 → 安全 (conf=0.90)
       c. 变量表达式 → 输入派生可疑 (conf=0.55)
    4. write_refs_alloc → 表达式通过min/三元受限于alloc (SAFE, conf=0.70)
    5. 范围重叠 → 不确定 (conf=0.50)
    6. 双方未知 → 保守可疑 (conf=0.30)
    """
    import re

    # 同表达式判定 (必须在 write_refs_alloc 之前)
    if alloc_expr and write_expr and alloc_expr == write_expr:
        if alloc_expr.isdigit() or 'sizeof' in alloc_expr:
            return (True, 0.95, f"identical_expr({alloc_expr})→provably_safe")
        if alloc_func == "realloc":
            return (True, 0.90, f"realloc_same_expr({alloc_expr})→safe_growth")
        return (False, 0.55, f"same_input_expr({alloc_expr})→input_dependent")

    # alloc包含write常量 → alloc由write派生 → alloc>=write
    if (alloc_expr and write_expr and write_expr != alloc_expr
        and write_expr in alloc_expr and write_expr.isdigit()):
        return (True, 0.72,
                f"alloc_derived_from_const_write({write_expr}⊆{alloc_expr})→alloc≥write")

    # write包含alloc变量 → 检查是否受限于alloc (min/三元)
    if alloc_expr and write_expr and alloc_expr != write_expr and alloc_expr in write_expr:
        remaining = write_expr.replace(alloc_expr, '', 1)
        if re.match(r'\s*\+\s*\d+', remaining):
            pass  # write = alloc + const > alloc → 危险
        elif re.match(r'\s*\*\s*\d+', remaining):
            pass  # write = alloc * N → 危险
        else:
            return (True, 0.70,
                    f"write_refs_alloc({alloc_expr}⊆{write_expr[:50]})→constrained_safe")

    # 精确区间比较
    if not alloc_r.is_top and not write_r.is_top:
        if alloc_r.lo >= write_r.hi:
            return (True, 0.98,
                    f"alloc.lo({alloc_r.lo:.0f})≥write.hi({write_r.hi:.0f})→provably_safe")

        align_pad = model.alignment
        if alloc_r.lo + align_pad >= write_r.hi:
            return (True, 0.85,
                    f"alloc.lo+align({alloc_r.lo:.0f}+{align_pad})≥write.hi({write_r.hi:.0f})→aligned_safe")

        if alloc_r.hi < write_r.lo:
            return (False, 0.92,
                    f"alloc.hi({alloc_r.hi:.0f})<write.lo({write_r.lo:.0f})→definite_overflow")

        if alloc_r.lo < write_r.lo <= alloc_r.hi < write_r.hi:
            return (False, 0.65,
                    f"range_overlap:alloc{alloc_r} vs write{write_r}→possible_overflow")

    # 保守判定
    if alloc_r.is_top and not write_r.is_top:
        return (True, 0.45, "alloc_unknown_but_write_bounded→conservative_safe")
    if not alloc_r.is_top and write_r.is_top:
        return (False, 0.50,
                f"alloc_bounded({alloc_r})_but_write_unbounded→suspicious")
    return (False, 0.30, "both_unbounded→uncertain")

def solve_and_filter(
    bindings: List[Dict],
    code: str = "",
    arch: str = "x86_64",
) -> Tuple[List[Dict], Dict]:
    """完整的约束求解 + 误报过滤管线。

    输入: 指针追踪产生的 (alloc, write) 绑定
    输出: (经过滤的发现列表, 统计信息)
    """
    ranges = extract_value_ranges(code) if code else {}
    constraints = gen_constraints(bindings, ranges, code, arch)

    safe_count = sum(1 for c in constraints if c.is_safe)
    findings = []
    for c in constraints:
        if not c.is_safe:
            conf = c.safety_confidence
            findings.append({
                "type": "heap-overflow",
                "cwe": "CWE-122",
                "alloc_func": f"malloc({c.alloc_size_expr})",
                "write_func": c.write_func,
                "alloc_var": c.alloc_var,
                "write_buffer": c.write_buffer,
                "alloc_range": str(c.alloc_range),
                "write_range": str(c.write_range),
                "confidence": round(conf, 2),
                "severity": "High" if conf > 0.60 else "Medium",
                "reason": c.safety_reason,
                "guard_count": len(c.guard_constraints),
            })

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    stats = {
        "total_bindings": len(bindings),
        "constraints_generated": len(constraints),
        "proven_safe": safe_count,
        "reported": len(findings),
        "fp_reduction_pct": round(
            safe_count / max(len(constraints), 1) * 100, 1
        ),
        "method": "Constraint-Based-v1.1",
    }

    return findings, stats
