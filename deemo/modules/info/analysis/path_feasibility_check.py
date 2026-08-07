# analysis/path_feasibility_check — 路径可行性检查
# 对代码中的条件分支 (if/while/for) 建立约束, 并判断
# 分配-写入路径是否在给定约束下是可行的。
#
# 与全符号执行的区别: 不做逐指令执行, 只在条件跳转处建立抽象约束;
#   约束求解退化为区间交集 (O(1)), 而非 SMT solving (NP-hard)
# 放弃路径完备性, 换取速度和零依赖。

from __future__ import annotations
from typing import Dict, List, Set, Tuple, Optional
import re

from value_range_analyzer import (
    ValueRange, extract_value_ranges, apply_constraint,
    check_heap_overflow_by_range,
)

def extract_conditions(code: str) -> List[Dict]:
    """从代码中提取条件约束 (if/while/for)。

    返回 [{var, op, value, negated, line}, ...]
    """
    conds = []
    # if (x < N) / if (x <= N) / if (x > N) / if (x >= N) / if (x == N)
    pat = re.compile(
        r"(?:if|while|for)\s*\(\s*"
        r"(\w+)\s*(<|<=|>|>=|==|!=)\s*"
        r"(\w+)\s*\)"
    )
    for m in pat.finditer(code):
        var, op, rhs = m.group(1), m.group(2), m.group(3)
        # rhs 是否为数值常量?
        try:
            val = int(rhs)
        except ValueError:
            continue  # 忽略非常量比较
        conds.append({
            "var": var, "op": op, "value": val,
            "pos": m.start(), "negated": False,
        })

    # 也提取 if (!expr) 的否定条件: if (!(x < N)) → x >= N
    # 简化版: 不处理复杂取反, 只标记
    return conds

def build_path_constraints(
    code: str,
    target_line: int = -1,
) -> Tuple[Dict[str, ValueRange], List[Dict]]:
    """从代码开头到 target_line, 累积路径约束。

    返回:
    - 累积后的 ranges (变量→值范围)
    - 不可行的约束列表 (冲突的约束)
    """
    ranges: Dict[str, ValueRange] = extract_value_ranges(code)
    infeasible: List[Dict] = []

    conds = extract_conditions(code)
    for c in conds:
        if target_line >= 0 and c["pos"] > target_line:
            continue

        var = c["var"]
        op = c["op"]
        val = c["value"]

        # 对于分支, 我们需要知道走的是 true 还是 false 分支。
        # 在没有控制流图的情况下, 保守假设: 检查约束是否与现有范围冲突。
        if var in ranges:
            rv = ranges[var]
            if op == "<":
                constrained = rv.meet(ValueRange(float("-inf"), val - 1))
            elif op == "<=":
                constrained = rv.meet(ValueRange(float("-inf"), val))
            elif op == ">":
                constrained = rv.meet(ValueRange(val + 1, float("inf")))
            elif op == ">=":
                constrained = rv.meet(ValueRange(val, float("inf")))
            elif op == "==":
                constrained = rv.meet(ValueRange(val, val))
            else:
                constrained = rv

            if constrained.is_bottom:
                infeasible.append({
                    "var": var, "op": op, "value": val,
                    "reason": f"约束 {var} {op} {val} 与范围 {rv} 冲突",
                })
            else:
                ranges[var] = constrained

    return ranges, infeasible

def check_write_reachability(
    code: str,
    write_func: str = "memcpy",
    alloc_func: str = "malloc",
) -> Dict:
    """检查写入点是否在分配点的可达路径上。

    核心思路: 抽取分配点的 size 表达式和写入点的 size 表达式,
    检查在路径约束下写入量是否超过分配量。

    返回:
    {
        "reachable": bool,
        "has_guard": bool,         # 是否有边界检查
        "guard_strength": float,   # 边界检查的强度 0-1
        "overflow_possible": bool,
        "confidence": float,
        "reason": str,
    }
    """
    result = {
        "reachable": True,
        "has_guard": False,
        "guard_strength": 0.0,
        "overflow_possible": False,
        "confidence": 0.0,
        "reason": "",
    }

    # 检测边界检查模式
    guard_patterns = [
        # if (len > sizeof(buf)) return;
        re.compile(r"if\s*\(\s*(\w+)\s*[><]\s*sizeof\s*\(\s*(\w+)\s*\)"),
        # if (n > size) n = size;
        re.compile(r"if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*\w+\s*=\s*\w+"),
        # if (size == 0) return;
        re.compile(r"if\s*\(\s*(\w+)\s*==\s*0\s*\)\s*return"),
        # if (nbytes > limit) goto error;
        re.compile(r"if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)\s*goto\s+\w+"),
    ]

    for pat in guard_patterns:
        if pat.search(code):
            result["has_guard"] = True
            result["guard_strength"] += 0.25

    result["guard_strength"] = min(result["guard_strength"], 1.0)

    # 提取值范围并检查
    ranges = extract_value_ranges(code)
    _, infeasible = build_path_constraints(code)

    alloc_range = ranges.get("__malloc_size__", ValueRange.top())
    # 写入量: 尝试找 memcpy 的第三个参数
    write_range = ValueRange.top()
    write_matches = list(re.finditer(
        r"(?:memcpy|strncpy|read|recv)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)", code))
    if write_matches:
        wvar = write_matches[-1].group(1)
        write_range = ranges.get(wvar, ValueRange.top())

    overflow, conf, reason = check_heap_overflow_by_range(alloc_range, write_range)

    result["overflow_possible"] = overflow
    result["confidence"] = conf
    result["reason"] = reason

    if infeasible:
        result["reachable"] = False
        result["overflow_possible"] = False
        result["confidence"] = 0.05
        result["reason"] = f"路径不可达: {infeasible[0]['reason']}"

    return result

def validate_allocation_site(
    alloc_expr: str,
    write_expr: str,
    ranges: Dict[str, ValueRange],
    allocator_model=None,
    extra_constraints: List[Dict] = None,
) -> Tuple[bool, float, str]:
    """对单个分配点进行完整的可行性验证。

    alloc_expr: malloc 的 size 参数表达式 (如 "n * sizeof(int)")
    write_expr: memcpy 的 size 参数表达式 (如 "n")
    ranges: 当前作用域内的变量值范围
    allocator_model: AllocatorModel 实例或 None
    extra_constraints: 额外的路径约束 [{var, op, value}, ...]

    返回: (is_overflow, confidence, reason)
    """
    # 解析表达式并计算值范围
    alloc_range = _eval_expr_range(alloc_expr, ranges)
    write_range = _eval_expr_range(write_expr, ranges)

    # 应用额外约束
    if extra_constraints:
        rcopy = dict(ranges)
        for ec in extra_constraints:
            rcopy = apply_constraint(rcopy, ec["var"], ec["op"], ec["value"])
        alloc_range = _eval_expr_range(alloc_expr, rcopy)
        write_range = _eval_expr_range(write_expr, rcopy)

    return check_heap_overflow_by_range(alloc_range, write_range)

def _eval_expr_range(expr: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    """简单表达式求值: 变量查表, 常量包装, 乘/加运算。"""
    expr = expr.strip()

    # 纯数字常量
    try:
        return ValueRange.const(int(expr))
    except ValueError:
        pass

    # sizeof(type) → const
    sizeof_map = {"char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
                  "float": 4, "double": 8, "void*": 4, "size_t": 4}
    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        return ValueRange.const(sizeof_map.get(sm.group(1).strip(), 4))

    # var * const
    m = re.match(r"(\w+)\s*\*\s*(\d+)", expr)
    if m:
        vr = ranges.get(m.group(1), ValueRange.top())
        return vr.mul(ValueRange.const(int(m.group(2))))

    # var * sizeof(type)
    m = re.match(r"(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if m:
        vr = ranges.get(m.group(1), ValueRange.top())
        sz = sizeof_map.get(m.group(2).strip(), 4)
        return vr.mul(ValueRange.const(sz))

    # 单变量
    if expr in ranges:
        return ranges[expr]

    # fallthrough: 宽泛的字符级模式匹配
    # var1 * var2
    m = re.match(r"(\w+)\s*\*\s*(\w+)", expr)
    if m:
        a = ranges.get(m.group(1), ValueRange.top())
        b = ranges.get(m.group(2), ValueRange.top())
        return a.mul(b)

    return ValueRange.top()
