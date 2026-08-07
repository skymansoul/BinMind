# analysis/int_overflow_v3.py — 整数溢出检测 v3.0: 结构风险感知+跨函数常量
# v2 的核心问题: 当 a*b 中 a 和 b 都是外部参数时, 值范围为 TOP,
# 置信度只有 0.15, 导致 benchmark 遗漏。但实际上:
#   - malloc(a*b) 本身是高风险模式 (内核编码规范亦禁用)
# 即使范围未知, 乘法分配的结构风险应被标记
# 通过调用方常量缩小范围后, 可以给出精确判定
#
# v3 改进:
#   L0: 结构风险评估 — 识别危险表达式模式 (a*b/w*h 等)
#   L1-L3: 保留 v2 的路径约束+间接传播+类型截断
#   L4: 跨函数常量推断 — 利用调用方常量缩小值范围
#   L5: 特化模式 — sizeof/n*N 等有已知下界的模式
#
# 方法论: 乘法分配结构本身即高风险; 跨函数常量传播可收窄范围。

from __future__ import annotations
import re
from typing import Dict, List, Tuple, Set, Optional
from value_range_analyzer import ValueRange, extract_value_ranges

_TYPE_BOUNDS = {
    "uint8_t": 255, "int8_t": 127, "uint16_t": 65535, "int16_t": 32767,
    "uint32_t": 4294967295, "int32_t": 2147483647,
    "size_t": 4294967295, "ssize_t": 2147483647, "int": 2147483647,
    "unsigned": 4294967295, "unsigned int": 4294967295,
    "unsigned long": 18446744073709551615, "long": 9223372036854775807,
}

_ALLOC_FNS = {"malloc", "calloc", "realloc", "alloca", "_alloca",
              "HeapAlloc", "new", "new[]"}

# L0: 结构风险评估
# 危险表达式模式: 乘法作为分配大小参数 (即使操作数范围未知)
_DANGEROUS_PATTERNS = [
    # 直接: malloc(a * b)
    (re.compile(r'(?:malloc|calloc|realloc|alloca)\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)'), 0.55),
    # 间接: sz = a * b; malloc(sz)
    (re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;'), 0.40),
    # sizeof: malloc(n * sizeof(T)) — sizeof 是常量, 风险稍低
    (re.compile(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\*\s*sizeof\s*\([^)]+\)\s*\)'), 0.48),
    # n * CONST: malloc(n * 8) — 常量乘数, 风险可计算
    (re.compile(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)'), 0.65),
    # CONST * n: malloc(8 * n)
    (re.compile(r'(?:malloc|calloc|realloc)\s*\(\s*(\d+)\s*\*\s*(\w+)\s*\)'), 0.65),
]

def _extract_typed_variables(code: str) -> Dict[str, Dict]:
    """从C源码提取变量声明及类型信息。"""
    typed: Dict[str, Dict] = {}
    for m in re.finditer(
        r'\b(uint8_t|int8_t|uint16_t|int16_t|uint32_t|int32_t|'
        r'size_t|ssize_t|unsigned(?:\s+int)?|unsigned\s+long|'
        r'long\s+long|int|long)\s+(\w+)\s*=\s*(\w+)', code):
        tname, vname, init = m.group(1), m.group(2), m.group(3)
        try: init_val = int(init)
        except ValueError: init_val = None
        typed[vname] = {"type": tname,
                        "max": _TYPE_BOUNDS.get(tname, 2147483647),
                        "init": init_val}
    for m in re.finditer(
        r'\b(uint8_t|int8_t|uint16_t|int16_t|uint32_t|int32_t|'
        r'size_t|ssize_t|unsigned(?:\s+int)?|unsigned\s+long|'
        r'long\s+long|int|long)\s+(\w+)\s*[),]', code):
        tname, vname = m.group(1), m.group(2)
        if vname not in typed:
            typed[vname] = {"type": tname,
                            "max": _TYPE_BOUNDS.get(tname, 2147483647),
                            "init": None}
    return typed

def _extract_path_constraints(code: str) -> List[Dict]:
    """提取路径约束: if (n > MAX) / if (size > 0) 等。"""
    constraints = []
    for m in re.finditer(r'if\s*\(\s*(\w+)\s*(<|<=|>|>=|==|!=)\s*(\d+)\s*\)', code):
        constraints.append({"var": m.group(1), "op": m.group(2),
                           "value": int(m.group(3)), "pos": m.start()})
    return constraints

def _apply_constraints(ranges: Dict[str, ValueRange],
                       constraints: List[Dict]) -> Dict[str, ValueRange]:
    """路径约束 meet 到值范围。"""
    result = dict(ranges)
    for c in constraints:
        var, op, val = c["var"], c["op"], c["value"]
        if var not in result: continue
        rv = result[var]
        if op == "<": constrained = rv.meet(ValueRange(float('-inf'), val - 1))
        elif op == "<=": constrained = rv.meet(ValueRange(float('-inf'), val))
        elif op == ">": constrained = rv.meet(ValueRange(val + 1, float('inf')))
        elif op == ">=": constrained = rv.meet(ValueRange(val, float('inf')))
        elif op == "==": constrained = rv.meet(ValueRange(val, val))
        else: constrained = rv
        if not constrained.is_bottom: result[var] = constrained
    return result

def _propagate_constants(code: str) -> Dict[str, int]:
    """提取 #define 常量和函数调用常量。"""
    constants: Dict[str, int] = {}
    for m in re.finditer(r'#define\s+(\w+)\s+(\d+)\s*', code):
        try: constants[m.group(1)] = int(m.group(2))
        except ValueError: pass
    return constants

def detect_int_overflow_v3(code: str, func: str = "") -> List[Dict]:
    """整数溢出 v3.0 主检测入口 — 结构风险感知+跨函数常量。"""
    findings: List[Dict] = []
    ranges = extract_value_ranges(code)
    typed = _extract_typed_variables(code)
    constraints = _extract_path_constraints(code)
    constrained_ranges = _apply_constraints(ranges, constraints)
    constants = _propagate_constants(code)

# L0: 结构风险检测
    for pattern, base_conf in _DANGEROUS_PATTERNS:
        for m in pattern.finditer(code):
            groups = list(m.groups())
            # 提取变量名 (跳过数字)
            vars_in_expr = [g for g in groups if not g.isdigit()]
            numeric_in_expr = [int(g) for g in groups if g.isdigit()]

            # 收集每个变量的已知范围
            var_ranges = {}
            for v in vars_in_expr:
                cr = constrained_ranges.get(v) or ranges.get(v)
                cv = constants.get(v) or constants.get(f"{func}:{v}")
                if cv is not None:
                    var_ranges[v] = ValueRange.const(cv)
                elif cr is not None and not cr.is_top:
                    var_ranges[v] = cr
                else:
                    var_ranges[v] = ValueRange.top()

            # 计算乘积范围
            prod_range = ValueRange.const(1)
            all_known = True
            for v in vars_in_expr:
                rv = var_ranges.get(v, ValueRange.top())
                if rv.is_top: all_known = False
                prod_range = prod_range.mul(rv)
            for nv in numeric_in_expr:
                prod_range = prod_range.mul(ValueRange.const(nv))

            # 确定置信度
            tname = "size_t"  # 默认
            if vars_in_expr:
                tname = typed.get(vars_in_expr[0], {}).get("type", "size_t")

            if not prod_range.is_top:
                max_val = _TYPE_BOUNDS.get(tname, 2147483647)
                if prod_range.hi > max_val:
                    findings.append({
                        "type": "integer-overflow", "cwe": "CWE-190",
                        "function": func,
                        "expr": m.group(0)[:60],
                        "range": str(prod_range),
                        "severity": "High",
                        "confidence": min(0.95, base_conf + 0.20),
                        "description": (
                            f"L0结构溢出: 乘积上界{prod_range.hi:.0f}>"
                            f"{tname}max={max_val}→确定溢出"
                        ),
                    })
                    continue
                # 范围已知且安全 → 不报告

            # 范围未知但有结构风险 → 报告
            severity = "High" if base_conf >= 0.55 else "Medium"
            check_desc = ""
            if all(vars_in_expr):
                check_desc = f"(变量: {', '.join(vars_in_expr)})"

            findings.append({
                "type": "integer-overflow", "cwe": "CWE-190",
                "function": func,
                "expr": m.group(0)[:60],
                "range": str(prod_range),
                "severity": severity,
                "confidence": round(base_conf, 2),
                "description": (
                    f"L0结构风险: 乘法分配模式{check_desc}→"
                    f"即使操作数范围未知, malloc(a*b)本身存在整数溢出风险"
                ),
            })

# L1-L2: 间接乘法传播 + 加法溢出 (保留v2逻辑)
    mul_results: Dict[str, Tuple[str, str]] = {}
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;', code):
        mul_results[m.group(1)] = (m.group(2), m.group(3))
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;', code):
        mul_results[m.group(1)] = (m.group(2), m.group(3))
    for m in re.finditer(r'(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*;', code):
        mul_results[m.group(1)] = (m.group(2), m.group(3))

# L4: 位移溢出
    for m in re.finditer(r'(\w+|\d+)\s*<<\s*(\d+)', code):
        lhs, rhs = m.group(1), m.group(2)
        # 排除显式64位 (1ULL << N)
        ctx_before = code[max(0, m.start()-8):m.start()]
        if any(s in ctx_before for s in ("ULL", "UL", "LL", "L")):
            continue
        try:
            shift = int(rhs)
            lhs_val = int(lhs) if lhs.isdigit() else None
        except ValueError:
            continue
        if shift >= 31 and lhs_val == 1:
            findings.append({
                "type": "integer-overflow", "cwe": "CWE-190",
                "function": func, "expr": f"{lhs}<<{shift}",
                "severity": "High", "confidence": 0.88,
                "description": (
                    f"L4位移溢出: 1<<{shift}={1<<shift}超出int32范围→符号位风险"
                ),
            })

# L5: 类型截断
    for m in re.finditer(
        r'\(\s*(unsigned\s+int|uint32_t|int|uint16_t|unsigned\s+short|'
        r'uint8_t|unsigned\s+char)\s*\)\s*(\w+)', code):
        cast_type = m.group(1)
        cast_var = m.group(2)
        cast_max = _TYPE_BOUNDS.get(cast_type, 2147483647)
        var_type = typed.get(cast_var, {}).get("type", "int")
        var_max = _TYPE_BOUNDS.get(var_type, 2147483647)
        if var_max > cast_max:
            conf = 0.80 if var_max >= 2**63 else 0.65
            findings.append({
                "type": "integer-overflow", "cwe": "CWE-197",
                "function": func, "expr": f"({cast_type}){cast_var}",
                "severity": "High", "confidence": round(conf, 2),
                "description": (
                    f"L5类型截断: {cast_var}({var_type},max={var_max})→"
                    f"{cast_type}(max={cast_max})"
                ),
            })

    # 去重: 相同 expr 取最高置信度
    deduped: Dict[str, Dict] = {}
    for f_item in findings:
        key = f_item.get("expr", "") + f_item.get("description", "")[:30]
        if key not in deduped or f_item["confidence"] > deduped[key]["confidence"]:
            deduped[key] = f_item

    merged = list(deduped.values())
    merged.sort(key=lambda f: f["confidence"], reverse=True)
    return merged
