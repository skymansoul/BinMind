"""整数溢出值域传播分析器 — 区间代数的溢出检测 (CWE-190 + 符号转换/移位/下溢/赋值追踪/浮点截断)"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class IntOverflowClass(Enum):
    SAFE = "safe"; POSSIBLE = "possible"; DEFINITE = "definite"; WRAP_TO_HEAP = "wrap_heap"


@dataclass
class IntRange:
    lo: int; hi: int; is_signed: bool = True
    @staticmethod
    def from_type(type_name: str) -> "IntRange":
        t = type_name.strip().lower()
        if t in ('int', 'int32_t', 'long'): return IntRange(-(2**31), 2**31 - 1, True)
        if t in ('unsigned', 'unsigned int', 'uint32_t', 'size_t', 'unsigned long'):
            return IntRange(0, 2**32 - 1, False)
        if t in ('short', 'int16_t'): return IntRange(-(2**15), 2**15 - 1, True)
        if t in ('unsigned short', 'uint16_t'): return IntRange(0, 2**16 - 1, False)
        if t in ('char', 'int8_t'): return IntRange(-128, 127, True)
        if t in ('unsigned char', 'uint8_t', 'bool'): return IntRange(0, 255, False)
        return IntRange(-(2**31), 2**31 - 1, True)
    def intersection(self, other: "IntRange") -> "IntRange":
        return IntRange(max(self.lo, other.lo), min(self.hi, other.hi),
                       self.is_signed and other.is_signed)


@dataclass
class IntOverflowSite:
    lineno: int; expr: str; var_lo: int; var_hi: int
    const_factor: int; product_lo: int; product_hi: int
    overflow_class: IntOverflowClass; heap_impact: str = ""


# 基础正则
_RE_MALLOC_MUL = re.compile(r'malloc\s*\(\s*(\w[\w.\->]*)\s*\*\s*(sizeof\s*\([^)]+\)|\d+)\s*\)')
_RE_CALLOC = re.compile(r'calloc\s*\(\s*([^,)]+)\s*,\s*([^)]+)\s*\)')
_RE_MALLOC_VAR = re.compile(r'malloc\s*\(\s*(\w[\w.\->]*)\s*\)')
_RE_ARITH = re.compile(r'(\w[\w.\->]*)\s*(\*|\+)\s*(\d+|sizeof\s*\([^)]+\))\b')
_RE_ARITH_VAR = re.compile(r'(\w[\w.\->]*)\s*=\s*(\w[\w.\->]*)\s*(\*)\s*(\d+|\w[\w.\->]*)')
_RE_MUL_IN_EXPR = re.compile(r'(\w[\w.\->]*)\s*\*\s*(\w[\w.\->]*|\d+)')
_RE_VAR_DECL = re.compile(
    r'(?:int\b|unsigned\b|size_t|uint\d+_t|long\s+long|long|short|char)\s+(\w[\w.\->]*)')

# v2.1 扩展正则
_RE_S2U = re.compile(
    r'(?:unsigned(?:\s+int)?|uint32_t|size_t)\s+(\w+)\s*=\s*\(\s*'
    r'(?:unsigned(?:\s+int)?|uint32_t|size_t)\s*\)\s*(\w[\w.\->]*)')
_RE_SHIFT = re.compile(r'(\w[\w.\->]*)\s*<<\s*(\d+)')
_RE_USUB = re.compile(r'unsigned\s+(?:int\s+)?(\w[\w.\->]*)\s*=\s*(\w[\w.\->]*)\s*-\s*(\w[\w.\->]*)')
_RE_CALC = re.compile(r'(\w[\w.\->]*)\s*=\s*(\w[\w.\->]*)\s*\*\s*(\w[\w.\->]*)')
_RE_TERNARY = re.compile(
    r'malloc\s*\(\s*(\w[\w.]*)\s*(?:[><]=?\s*\d+|[!=]=\s*\d+)?\s*\?\s*'
    r'(\w[\w.\->]*|\d+)\s*:\s*(\d+)\s*\)')
_RE_FLOAT = re.compile(r'\(\s*int\s*\)\s*(\w[\w.\->]*)')
_RE_ADDACC = re.compile(r'(\w[\w.\->]*)\s*\+=\s*(\w[\w.\->]*)\s*\[.*\]')
_RE_ADD = re.compile(r'(\w[\w.\->]*)\s*=\s*(\w[\w.\->]*)\s*\+\s*(\w[\w.\->]*|\d+)')


def detect_integer_overflows(code: str, var_bounds: dict = None) -> List[IntOverflowSite]:
    findings: List[IntOverflowSite] = []
    if var_bounds is None:
        var_bounds = {}
    types = _infer_types(code)
    bounds = dict(var_bounds)
    for vn, typ in types.items():
        if vn not in bounds:
            bounds[vn] = IntRange.from_type(typ)

    lines = code.split('\n')

    # Pass 1-3: 符号转换 + 移位溢出 + 无符号下溢 (单次扫描)
    for i, line in enumerate(lines, 1):
        m = _RE_S2U.search(line)
        if m:
            dst, src = m.group(1), m.group(2)
            ir = bounds.get(src, IntRange(-(2**31), 2**31 - 1, True))
            if ir.lo < 0:
                findings.append(IntOverflowSite(i, line.strip(), ir.lo, ir.hi, 1,
                    ir.lo + 2**32, ir.hi, IntOverflowClass.DEFINITE,
                    f"{src}(signed)→{dst}(unsigned): 负值回绕"))
        for m in _RE_SHIFT.finditer(line):
            var, shift = m.group(1), int(m.group(2))
            ir = bounds.get(var)
            if ir and (ir.hi << shift) > 2**31 - 1:
                findings.append(IntOverflowSite(i, line.strip(), ir.lo, ir.hi,
                    1 << shift, ir.lo << shift, ir.hi << shift,
                    IntOverflowClass.DEFINITE, f"{var}<<{shift}: 溢出32位"))
        m = _RE_USUB.search(line)
        if m:
            dst, a_var, b_var = m.group(1), m.group(2), m.group(3)
            ir_a = bounds.get(a_var, IntRange(0, 2**32 - 1, False))
            ir_b = bounds.get(b_var, IntRange(0, 2**32 - 1, False))
            if ir_a.lo < ir_b.hi:
                findings.append(IntOverflowSite(i, line.strip(), ir_a.lo, ir_a.hi, -1,
                    ir_a.lo - ir_b.hi, 0xFFFFFFFF, IntOverflowClass.POSSIBLE,
                    f"unsigned {a_var}-{b_var}: 可能下溢"))

    # Pass 4: 乘法赋值追踪
    calc_map: Dict[str, Tuple[str, int]] = {}
    calc_var_map: Dict[str, Tuple[str, str]] = {}
    for i, line in enumerate(lines, 1):
        m = _RE_CALC.search(line)
        if m:
            dst, a, b_text = m.group(1), m.group(2), m.group(3)
            b_val = _try_int(b_text)
            if b_val is not None and b_val > 0:
                calc_map[dst] = (a, b_val)
            elif b_val is not None and b_val <= 0:
                pass
            else:
                calc_var_map[dst] = (a, b_text)

    for i, line in enumerate(lines, 1):
        for m in _RE_CALLOC.finditer(line):
            a1, a2 = m.group(1).strip(), m.group(2).strip()
            c1, c2 = _try_int(a1), _try_int(a2)
            if c1 is not None and c2 is not None and c1 > 0 and c2 > 0:
                prod = c1 * c2
                if prod > 2**32 - 1:
                    findings.append(IntOverflowSite(i, line.strip(), c1, c1, c2,
                        prod, prod, IntOverflowClass.DEFINITE,
                        f"calloc({c1:#x},{c2:#x}): 乘积{prod:#x}溢出"))
                elif prod > 2**31 - 1:
                    findings.append(IntOverflowSite(i, line.strip(), c1, c1, c2,
                        prod, prod, IntOverflowClass.POSSIBLE,
                        f"calloc({c1:#x},{c2:#x}): 接近有符号上界"))
                continue
            factor = _resolve_sizeof(a2) if a2.startswith('sizeof') else _try_int(a2)
            if factor <= 0:
                continue
            if a1 in calc_map:
                src_var, coeff = calc_map[a1]
                ir = bounds.get(src_var, IntRange(-(2**31), 2**31 - 1))
                factor *= coeff
            elif a1 in calc_var_map:
                v1, v2 = calc_var_map[a1]
                ir1 = bounds.get(v1, IntRange(-(2**31), 2**31 - 1))
                ir2 = bounds.get(v2, IntRange(-(2**31), 2**31 - 1))
                combined = IntRange(0, ir1.hi * ir2.hi, ir1.is_signed and ir2.is_signed)
                findings.extend(_check_wrap(a1, combined, factor, i, line,
                                            IntOverflowClass.WRAP_TO_HEAP))
                continue
            else:
                ir = bounds.get(a1, IntRange(-(2**31), 2**31 - 1))
            findings.extend(_check_wrap(a1, ir, factor, i, line, IntOverflowClass.WRAP_TO_HEAP))

        for m in _RE_MALLOC_VAR.finditer(line):
            var = m.group(1).strip()
            if var in calc_map:
                src_var, coeff = calc_map[var]
                ir = bounds.get(src_var, IntRange(-(2**31), 2**31 - 1))
                findings.extend(_check_wrap(var, ir, coeff, i, line, IntOverflowClass.WRAP_TO_HEAP))
            if var in calc_var_map:
                v1, v2 = calc_var_map[var]
                ir1, ir2 = bounds.get(v1, IntRange(-(2**31), 2**31 - 1)), bounds.get(v2, IntRange(-(2**31), 2**31 - 1))
                combined = IntRange(0, ir1.hi * ir2.hi, ir1.is_signed and ir2.is_signed)
                findings.extend(_check_wrap(var, combined, 1, i, line, IntOverflowClass.WRAP_TO_HEAP))
            ir = bounds.get(var, IntRange(-(2**31), 2**31 - 1))
            if ir.lo < 0:
                findings.append(IntOverflowSite(i, line.strip(), ir.lo, ir.hi, 1,
                    ir.lo + 2**32, ir.hi, IntOverflowClass.DEFINITE,
                    f"malloc({var}): signed变量负值转size_t回绕"))
        for m in _RE_TERNARY.finditer(line):
            var = m.group(1); ir = bounds.get(var)
            if ir and ir.lo < 0:
                findings.append(IntOverflowSite(i, line.strip(), ir.lo, ir.hi, 1,
                    ir.lo + 2**32, ir.hi, IntOverflowClass.POSSIBLE,
                    f"malloc({var}>0?{var}:...): 三元含signed变量"))
        if _RE_ADDACC.search(line):
            findings.append(IntOverflowSite(i, line.strip(), 0, 2**32 - 1, 1,
                0, 2**32 - 1, IntOverflowClass.POSSIBLE, "total+=sizes[i]: 循环累积回绕"))
        if _RE_FLOAT.search(line):
            findings.append(IntOverflowSite(i, line.strip(), 0, 2**31 - 1, 1,
                0, 2**31 - 1, IntOverflowClass.POSSIBLE, "double→int截断: 大值截断"))

    # 一般算术表达式溢出
    for i, line in enumerate(lines, 1):
        for m in _RE_ARITH.finditer(line):
            var, op, rhs_text = m.group(1).strip(), m.group(2), m.group(3).strip()
            rhs = _resolve_sizeof(rhs_text) if 'sizeof' in rhs_text else _try_int(rhs_text)
            if rhs is None or rhs <= 0:
                continue
            ir = bounds.get(var, IntRange(-(2**31), 2**31 - 1))
            if op == '*':
                findings.extend(_check_wrap(var, ir, rhs, i, line, IntOverflowClass.POSSIBLE))
            elif op == '+':
                findings.extend(_check_add_wrap(var, ir, rhs, i, line))

        for m in _RE_ARITH_VAR.finditer(line):
            dst, lhs, rhs_text = m.group(1), m.group(2), m.group(4)
            rhs_val = _try_int(rhs_text) or -1
            ir_lhs = bounds.get(lhs, IntRange(-(2**31), 2**31 - 1))
            if rhs_val > 0:
                findings.extend(_check_wrap(lhs, ir_lhs, rhs_val, i, line,
                                            IntOverflowClass.POSSIBLE))
            elif rhs_val == -1 and rhs_text in bounds:
                findings.extend(_check_wrap(lhs, ir_lhs, bounds[rhs_text].hi, i, line,
                                            IntOverflowClass.POSSIBLE))

        for m in _RE_MUL_IN_EXPR.finditer(line):
            a, b_text = m.group(1), m.group(2)
            b_val = _try_int(b_text)
            if b_val is None or b_val <= 0:
                continue
            if 'malloc' not in line and 'calloc' not in line:
                ir = bounds.get(a, IntRange(-(2**31), 2**31 - 1))
                findings.extend(_check_wrap(a, ir, b_val, i, line, IntOverflowClass.POSSIBLE))

        for m in _RE_ADD.finditer(line):
            if 'malloc' in line:
                continue
            a_var, b_text = m.group(1), m.group(2)
            b_val = _try_int(b_text)
            if b_val is not None and b_val > 0:
                ir = bounds.get(a_var, IntRange(-(2**31), 2**31 - 1))
                findings.extend(_check_add_wrap(a_var, ir, b_val, i, line))

    return findings


def _check_wrap(var: str, ir: IntRange, factor: int, lineno: int, line: str,
                ovf_class: IntOverflowClass) -> List[IntOverflowSite]:
    results = []
    plo, phi = ir.lo * factor, ir.hi * factor
    max_val = 2**32 - 1 if not ir.is_signed else 2**31 - 1
    if ir.lo < 0:
        results.append(IntOverflowSite(lineno, line.strip(), ir.lo, ir.hi,
            factor, plo, phi, IntOverflowClass.DEFINITE))
    elif plo > max_val or phi > max_val:
        cls = IntOverflowClass.DEFINITE if plo > max_val else IntOverflowClass.POSSIBLE
        impact = ""
        if ovf_class == IntOverflowClass.WRAP_TO_HEAP:
            impact = f"malloc({var}*{factor}): 期望{phi}B 实际{plo & max_val}B(回绕)"
        results.append(IntOverflowSite(lineno, line.strip(), ir.lo, ir.hi,
            factor, plo, phi, cls, impact))
    return results

def _check_add_wrap(var: str, ir: IntRange, rhs: int, lineno: int, line: str
                    ) -> List[IntOverflowSite]:
    max_val = 2**32 - 1 if not ir.is_signed else 2**31 - 1
    if ir.hi + rhs > max_val:
        return [IntOverflowSite(lineno, line.strip(), ir.lo, ir.hi,
            rhs, ir.lo + rhs, ir.hi + rhs, IntOverflowClass.POSSIBLE)]
    return []

def _infer_types(code: str) -> Dict[str, str]:
    types = {}
    for line in code.split('\n'):
        for m in _RE_VAR_DECL.finditer(line):
            types[m.group(1)] = m.group(0).split()[0]
    return types

def _resolve_sizeof(text: str) -> int:
    m = re.search(r'sizeof\s*\(\s*(\w+)\s*\)?', text)
    if not m: return _try_int(text)
    return {'char': 1, 'short': 2, 'int': 4, 'long': 8, 'float': 4,
            'double': 8, 'void': 1, 'size_t': 8, 'unsigned': 4,
            'long long': 8}.get(m.group(1).strip(), 4)

def _try_int(s: Optional[str]) -> Optional[int]:
    if s is None: return None
    s = s.strip()
    if not s: return None
    try: return int(s)
    except ValueError: pass
    if s.lower().startswith('0x'):
        try: return int(s, 16)
        except ValueError: pass
    return None
