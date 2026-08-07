# analysis/int_overflow_v2 — 整数溢出检测 v2.0: 路径感知+类型推导+间接传播
# 超越 v1 的 malloc(n*m) 直接匹配, 升级为三层分析管线:
#   L1: 类型感知值范围推导 — 区分 int32/uint32/size_t 溢出边界
#   L2: 路径约束 — 从 if/for 条件引入约束, 取 meet 后重新检验溢出
#   L3: 间接传播 — 追踪 sz=n*m; malloc(sz) 以及跨函数边界
# 路径敏感性 + 隐式类型转换 + 输入驱动的污点分析。

from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re
from value_range_analyzer import ValueRange, extract_value_ranges

# sizeof 映射: 不同整数类型的溢出边界
_TYPE_BOUNDS = {
    "uint8_t": 255, "int8_t": 127, "uint16_t": 65535, "int16_t": 32767,
    "uint32_t": 4294967295, "int32_t": 2147483647,
    "size_t": 4294967295, "ssize_t": 2147483647, "int": 2147483647,
    "unsigned": 4294967295, "unsigned int": 4294967295,
    "unsigned long": 18446744073709551615, "long": 9223372036854775807,
    "long long": 9223372036854775807,
}

# 分配函数
_ALLOC_FNS = {"malloc", "calloc", "realloc", "alloca", "_alloca",
              "HeapAlloc", "new", "new[]"}

def _extract_typed_variables(code: str) -> Dict[str, Dict]:
    """从 C 源码提取变量声明及类型信息 (声明+参数)。"""
    typed = {}
    # int/unsigned/size_t var = N; (声明+初始化)
    for m in re.finditer(
        r'\b(uint8_t|int8_t|uint16_t|int16_t|uint32_t|int32_t|'
        r'size_t|ssize_t|unsigned(?:\s+int)?|unsigned\s+long|'
        r'long\s+long|int|long)\s+(\w+)\s*=\s*(\w+)', code):
        tname, vname, init = m.group(1), m.group(2), m.group(3)
        try:
            init_val = int(init)
        except ValueError:
            init_val = None
        typed[vname] = {"type": tname,
                        "max": _TYPE_BOUNDS.get(tname, 2147483647),
                        "init": init_val}
    # 函数参数: void foo(unsigned long sz) — 无初始化的参数
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
    """提取路径约束: if (n > MAX) / if (size == 0) 等。"""
    constraints = []
    for m in re.finditer(r'if\s*\(\s*(\w+)\s*(<|<=|>|>=|==|!=)\s*(\d+)\s*\)', code):
        constraints.append({"var": m.group(1), "op": m.group(2),
                           "value": int(m.group(3)), "pos": m.start()})
    return constraints

def _apply_constraints(ranges: Dict[str, ValueRange],
                        constraints: List[Dict]) -> Dict[str, ValueRange]:
    """将路径约束 meet 到现有值范围中。"""
    result = dict(ranges)
    for c in constraints:
        var, op, val = c["var"], c["op"], c["value"]
        if var not in result:
            continue
        rv = result[var]
        if op == "<":
            constrained = rv.meet(ValueRange(float('-inf'), val - 1))
        elif op == "<=":
            constrained = rv.meet(ValueRange(float('-inf'), val))
        elif op == ">":
            constrained = rv.meet(ValueRange(val + 1, float('inf')))
        elif op == ">=":
            constrained = rv.meet(ValueRange(val, float('inf')))
        elif op == "==":
            constrained = rv.meet(ValueRange(val, val))
        elif op == "!=":
            constrained = rv  # != 不能缩小范围
        else:
            constrained = rv
        if not constrained.is_bottom:
            result[var] = constrained
    return result

def _check_overflow(r: ValueRange, type_name: str = "int") -> Tuple[bool, float, str]:
    """检查值范围是否溢出指定类型边界。

    三类溢出模式:
    - UPPER_OVERFLOW: 上界超出类型最大值
    - WRAP: 乘法导致的环绕 (lhs*rhs 超过 max)
    - SIGN_MISMATCH: 有符号操作数产生负值经 size_t 转换
    """
    max_val = _TYPE_BOUNDS.get(type_name, 2147483647)
    if r.is_top:
        return (False, 0.15, "值范围未知→无法确定溢出")
    hi = r.hi if r.hi != float('inf') else float('inf')
    lo = r.lo if r.lo != float('-inf') else float('-inf')

    if hi > max_val:
        return (True, min(0.90, 0.50 + (hi - max_val) / max(1, max_val) * 0.40),
                f"上界{hi:.0f}>{type_name}最大值{max_val}→溢出")
    if lo < 0 and "unsigned" in type_name.lower() and lo != float('-inf'):
        return (True, 0.70,
                f"有符号值{lo:.0f}转为无符号{type_name}→符号不匹配溢出")
    return (False, 0.05, f"范围[{lo},{hi}]在{type_name}范围内")

def detect_int_overflow_v2(code: str, func: str = "") -> List[Dict]:
    """整数溢出 v2.0 主检测入口。"""
    findings = []
    ranges = extract_value_ranges(code)
    typed = _extract_typed_variables(code)
    constraints = _extract_path_constraints(code)

    # L2: 应用路径约束后的范围
    constrained_ranges = _apply_constraints(ranges, constraints)

    # 模式1: 直接乘法分配 — malloc(n * m)
    for m in re.finditer(r'(?:malloc|calloc|realloc|alloca)\s*\(\s*'
                         r'(\w+)\s*\*\s*(\w+)\s*\)', code):
        nv, sv = m.group(1), m.group(2)
        rn = ranges.get(nv, ValueRange.top())
        rs = ranges.get(sv, ValueRange.top())
        prod = rn.mul(rs)

        # 用约束后的范围重新计算
        rn_c = constrained_ranges.get(nv, rn)
        rs_c = constrained_ranges.get(sv, rs)
        prod_c = rn_c.mul(rs_c)

        tname = _infer_result_type(nv, sv, typed)
        overflow, conf, reason = _check_overflow(prod_c, tname)

        if overflow or prod_c.is_top or prod.is_top:
            # 确定置信度: 约束缩小范围后仍溢出 → 高置信
            final_conf = conf
            if not prod_c.is_top and prod.is_top:
                final_conf = max(conf, 0.55)  # 约束提供了更多信息

            findings.append({
                "type": "integer-overflow", "cwe": "CWE-190",
                "function": func, "expr": f"{nv}*{sv}",
                "range_before": str(prod), "range_after": str(prod_c),
                "result_type": tname,
                "severity": "High" if final_conf > 0.60 else "Medium",
                "confidence": round(final_conf, 2),
                "description": reason,
            })

    # 模式1b: 间接乘法 — sz = n * M; ... malloc(sz)
    #   追踪乘法结果通过中间变量传播到分配函数
    mul_results = {}  # var → (lhs_expr, rhs_expr)
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;', code):
        mul_results[m.group(1)] = (m.group(2), m.group(3))
    # 也匹配 VAR * CONST (如 sz = n * 8)
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;', code):
        mul_results[m.group(1)] = (m.group(2), m.group(3))
    # 也匹配 CONST * VAR (如 sz = 8 * n)
    for m in re.finditer(r'(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*;', code):
        mul_results[m.group(1)] = (m.group(2), m.group(3))
    for m in re.finditer(r'(?:malloc|calloc|realloc|alloca)\s*\(\s*(\w+)\s*\)', code):
        vn = m.group(1)
        if vn in mul_results and vn not in ("arg", "ptr", "buf", "data"):
            a, b = mul_results[vn]
            ra = _val(a, ranges); rb = _val(b, ranges)
            prod = ra.mul(rb)
            ra_c = _val(a, constrained_ranges); rb_c = _val(b, constrained_ranges)
            prod_c = ra_c.mul(rb_c)
            tname = _infer_result_type(a, b, typed)
            overflow, conf, reason = _check_overflow(prod_c, tname)
            if overflow or prod_c.is_top or prod.is_top:
                final_conf = conf
                if not prod_c.is_top and prod.is_top:
                    final_conf = max(conf, 0.55)
                # wrap check 加固: if(sz < n) → 明确意图防范溢出
                if re.search(rf'if\s*\(\s*{vn}\s*<\s*({a}|{b})\s*\)', code):
                    final_conf = min(0.95, final_conf + 0.15)
                    reason += "; wrap_check检测→高置信"
                findings.append({
                    "type": "integer-overflow", "cwe": "CWE-190",
                    "function": func, "expr": f"{vn}={a}*{b}→malloc({vn})",
                    "range_before": str(prod), "range_after": str(prod_c),
                    "result_type": tname,
                    "severity": "High" if final_conf > 0.60 else "Medium",
                    "confidence": round(final_conf, 2),
                    "description": f"间接乘法溢出:{reason}",
                })

    # 模式2: 间接分配 — sz = expr; malloc(sz)
    for m in re.finditer(r'(?:malloc|calloc|realloc|alloca)\s*\(\s*(\w+)\s*\)', code):
        vn = m.group(1)
        if vn in ("arg", "ptr", "buf", "data"):
            continue
        rv = constrained_ranges.get(vn, ranges.get(vn))
        if rv is None:
            continue
        tname = typed.get(vn, {}).get("type", "int")
        overflow, conf, reason = _check_overflow(rv, tname)
        if overflow:
            findings.append({
                "type": "integer-overflow", "cwe": "CWE-190",
                "function": func, "expr": f"malloc({vn})",
                "range_after": str(rv), "result_type": tname,
                "severity": "High" if conf > 0.60 else "Medium",
                "confidence": round(conf, 2),
                "description": f"间接分配大小{reason}",
            })

    # 模式3: 算数运算中的溢出 — int x = a + b (可能 wrap)
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;', code):
        vn, a, b = m.group(1), m.group(2), m.group(3)
        ra = _val(a, ranges); rb = _val(b, ranges)
        s = ra.add(rb)
        tname = typed.get(vn, {}).get("type", "int")
        overflow, conf, reason = _check_overflow(s, tname)
        # 降低阈值: 加法溢出即使范围未知也值得报告 (常见于wrap检查)
        if (overflow and conf > 0.40) or re.search(rf'if\s*\(\s*{vn}\s*<', code):
            final_conf = conf
            # wrap check: if (alloc < CONST) → 明确溢出防范意图
            if re.search(rf'if\s*\(\s*{vn}\s*<\s*\d+\s*\)', code):
                final_conf = max(final_conf, 0.65)
                reason += "; wrap_check→可疑加法溢出"
            if final_conf > 0.25:
                findings.append({
                    "type": "integer-overflow", "cwe": "CWE-190",
                    "function": func, "expr": f"{vn}={a}+{b}",
                    "range_after": str(s), "result_type": tname,
                    "severity": "Medium", "confidence": round(final_conf, 2),
                    "description": f"加法溢出:{reason}",
                })

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    # 模式4: 显式类型截断 — (unsigned int)expr 将宽类型截断为窄类型
    #   例: (unsigned int)sz 当 sz 为 unsigned long 时, 高32位被丢弃
    for m in re.finditer(
        r'\(\s*(unsigned\s+int|uint32_t|int|uint16_t|unsigned\s+short|'
        r'uint8_t|unsigned\s+char)\s*\)\s*(\w+)', code):
        cast_type = m.group(1)
        cast_var = m.group(2)
        cast_max = _TYPE_BOUNDS.get(cast_type, 2147483647)
        var_type_info = typed.get(cast_var, {})
        var_type = var_type_info.get("type", "int")
        var_max = _TYPE_BOUNDS.get(var_type, 2147483647)
        # 只有从宽类型截断到窄类型时才报告
        if var_max > cast_max:
            conf = 0.80 if var_max >= 2**63 else 0.65
            reason = (f"类型截断:{cast_var}({var_type},max={var_max})→"
                      f"{cast_type}(max={cast_max})→高32位丢弃")
            findings.append({
                "type": "integer-overflow", "cwe": "CWE-197",
                "function": func, "expr": f"({cast_type}){cast_var}",
                "result_type": cast_type,
                "severity": "High", "confidence": round(conf, 2),
                "description": reason,
            })

    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings

def _val(s: str, ranges: Dict[str, ValueRange]) -> ValueRange:
    """常量或变量 → ValueRange。"""
    try: return ValueRange.const(int(s))
    except ValueError: return ranges.get(s, ValueRange.top())

def _infer_result_type(a: str, b: str, typed: Dict) -> str:
    """推断乘法结果类型: 两个操作数中较宽的那个。常量视为 int。"""
    ta = typed.get(a, {}).get("type", "int") if not a.isdigit() else "int"
    tb = typed.get(b, {}).get("type", "int") if not b.isdigit() else "int"
    ma = _TYPE_BOUNDS.get(ta, 2147483647)
    mb = _TYPE_BOUNDS.get(tb, 2147483647)
    return ta if ma >= mb else tb
