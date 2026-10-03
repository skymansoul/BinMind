"""
整数溢出符号化辅助 — 守卫检测/范围推断/判定逻辑/用户可控性判断.
纯函数, 不依赖 SymbolicProduct, 由 IntOverflowSymbolicAnalyzer 委托调用.
"""
from __future__ import annotations
import re
from typing import List, Tuple


# sizeof 常见类型 → 字节数
_SIZEOF_MAP = {
    'int': 4, 'unsigned': 4, 'unsigned int': 4, 'uint32_t': 4,
    'long': 8, 'unsigned long': 8, 'uint64_t': 8,
    'size_t': 8, 'ssize_t': 8, 'ptrdiff_t': 8,
    'short': 2, 'unsigned short': 2, 'uint16_t': 2,
    'char': 1, 'unsigned char': 1, 'uint8_t': 1,
    'float': 4, 'double': 8,
    'void*': 8, 'char*': 8, 'int*': 8,
    'long long': 8, 'unsigned long long': 8,
    '__int128': 16, '__uint128_t': 16,
}


def find_overflow_guards(source: str, operand_var: str,
                         threshold: int) -> List[str]:
    """查找针对 operand_var 的溢出守卫.
    模式: if(var > SIZE_MAX/sizeof) / __builtin_mul_overflow / if(var > MAX/C)
    """
    guards = []
    guard1 = re.compile(
        rf'if\s*\(\s*{re.escape(operand_var)}\s*[><=]+\s*(\d+)\s*\)',
        re.IGNORECASE)
    guard2 = re.compile(
        r'__builtin_(?:[su])?mul[l]?_overflow\s*\(', re.IGNORECASE)
    guard3 = re.compile(
        rf'if\s*\(\s*{re.escape(operand_var)}\s*>\s*\w*MAX\s*/\s*(\w+)',
        re.IGNORECASE)

    for i, line in enumerate(source.splitlines()):
        m1 = guard1.search(line)
        if m1 and int(m1.group(1)) <= threshold:
            guards.append(f"line {i}: {line.strip()[:80]}")
        if guard2.search(line):
            guards.append(f"line {i}: __builtin_mul_overflow guard")
        if guard3.search(line):
            guards.append(f"line {i}: {line.strip()[:80]}")
    return guards


def infer_var_range(source: str, var: str, platform: str) -> Tuple[int, int]:
    """从源码推断变量的可能范围 [lo, hi]."""
    lo, hi = 0, -1  # -1 = unknown

    if re.search(rf'{re.escape(var)}\s*=\s*atoi', source):
        hi = 0x7FFFFFFF
    elif re.search(rf'{re.escape(var)}\s*=\s*strtol', source):
        hi = 0x7FFFFFFFFFFFFFFF if '64' in platform else 0x7FFFFFFF
    elif re.search(rf'{re.escape(var)}\s*=\s*ato[lf]', source):
        hi = 0x7FFFFFFFFFFFFFFF

    m = re.search(rf'{re.escape(var)}\s*=\s*(\d+)\s*;', source)
    if m:
        lo = hi = int(m.group(1))

    for m in re.finditer(
        rf'if\s*\(\s*{re.escape(var)}\s*<\s*(\d+)\s*\)', source):
        hi = min(hi, int(m.group(1)) - 1) if hi >= 0 else int(m.group(1)) - 1
    for m in re.finditer(
        rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)', source):
        lo = max(lo, int(m.group(1)) + 1)
    return lo, hi


def assess_overflow(operand_var: str, threshold: int,
                    guards: List[str], var_lo: int, var_hi: int,
                    source: str) -> Tuple[str, float]:
    """综合判定溢出风险. 保守: 不能证明安全→保留."""
    if guards:
        return "SAFE", 0.15
    if var_hi >= 0 and var_hi <= threshold:
        return "SAFE", 0.20
    if var_lo > threshold:
        return "OVERFLOW", 0.90
    if _is_user_controlled(source, operand_var):
        if _has_length_check(source, operand_var):
            return "LIKELY_OVERFLOW", 0.50
        return "OVERFLOW", 0.80
    return "UNCERTAIN", 0.40


def is_in_alloc_context(source: str, var: str, line_no: int) -> bool:
    """检查 var 是否在分配上下文中使用 (后续5行内有 malloc(var))."""
    lines = source.splitlines()
    for i in range(line_no, min(line_no + 5, len(lines))):
        if re.search(rf'(?:malloc|calloc|realloc)\s*\(\s*{re.escape(var)}',
                     lines[i]):
            return True
    return False


def _is_user_controlled(source: str, var: str) -> bool:
    """判断变量是否用户可控 (atoi/strtol/argv/fgets/recv/read/getenv)."""
    patterns = [
        rf'{re.escape(var)}\s*=\s*atoi', rf'{re.escape(var)}\s*=\s*strtol',
        rf'{re.escape(var)}\s*=\s*argv', rf'fgets\s*\([^)]*{re.escape(var)}',
        rf'recv\s*\([^)]*{re.escape(var)}', rf'read\s*\([^)]*{re.escape(var)}',
        rf'getenv\s*\(.*{re.escape(var)}',
    ]
    return any(re.search(p, source) for p in patterns)


def _has_length_check(source: str, var: str) -> bool:
    """检查是否有针对 var 的边界检查."""
    return bool(re.search(rf'if\s*\(\s*{re.escape(var)}\s*[><=]+', source))



from analysis.int_overflow_patterns import IntOverflowFinding, _OVERFLOW_GUARD_PAT


def extract_untrusted_vars(source: str) -> set:
    """提取不可信输入变量 (atoi/argv/getenv/recv/scanf)."""
    untrusted = set()
    patterns = [
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?atoi\s*\(',
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?atol\s*\(',
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?strtoul\s*\(',
        r'(\w+)\s*=\s*argv\s*\[',
        r'(\w+)\s*=\s*getenv\s*\(',
        r'scanf\s*\([^,]*,\s*&\s*(\w+)',
        r'recv\s*\([^,]+,\s*(\w+)',
        r'read\s*\([^,]+,\s*(\w+)',
        r'fgets\s*\((\w+)',
    ]
    for pat in patterns:
        for m in re.finditer(pat, source):
            untrusted.add(m.group(1))
    return untrusted


def has_overflow_guard(source: str, line_no: int) -> bool:
    """检查指定行前15行内是否有溢出防护 (if a > INT_MAX / b)."""
    lines = source.splitlines()
    start = max(0, line_no - 15)
    end = min(len(lines), line_no + 3)
    context = '\n'.join(lines[start:end])
    return bool(_OVERFLOW_GUARD_PAT.search(context))


def find_matching_brace(lines: List[str], start: int) -> int:
    """找匹配的 '}'."""
    depth = 0
    started = False
    for j in range(start, len(lines)):
        for ch in lines[j]:
            if ch == '{':
                depth += 1
                started = True
            elif ch == '}':
                depth -= 1
        if started and depth == 0:
            return j
    return min(start + 50, len(lines) - 1)


def add_malloc_mul_finding(
    mm: re.Match, line_no: int, source: str,
    untrusted_vars: set, findings: List[IntOverflowFinding],
) -> None:
    """解析 malloc_mul 匹配组并添加 finding.
    CWE-190 (size_var 不可信) / CWE-680 (size_var 被截断).
    保守过滤: 常量乘法 → 编译器折叠, 跳过.
    """
    result_var = mm.group(1)
    size_var = mm.group(2)
    type_name = mm.group(3) if mm.lastindex >= 3 else "?"

    if size_var.isdigit():
        return

    is_untrusted = size_var in untrusted_vars
    has_guard = has_overflow_guard(source, line_no)

    if is_untrusted and not has_guard:
        findings.append(IntOverflowFinding(
            line=line_no, pattern="malloc_mul_overflow",
            expression=f"malloc({size_var} * sizeof({type_name}))",
            lhs_var=result_var, operand_a=size_var,
            operand_b=f"sizeof({type_name})",
            has_guard=False, overflow_possible=True, confidence=0.80,
            reason=(f"不可信变量 {size_var} 直接用于 malloc 乘法, "
                    f"无溢出守卫 → 可触发 CWE-190 → CWE-122"),
        ))
    elif is_untrusted and has_guard:
        findings.append(IntOverflowFinding(
            line=line_no, pattern="malloc_mul_overflow",
            expression=f"malloc({size_var} * sizeof({type_name}))",
            lhs_var=result_var, operand_a=size_var,
            operand_b=f"sizeof({type_name})",
            has_guard=True, overflow_possible=True, confidence=0.45,
            reason=f"不可信变量 {size_var} 但有溢出守卫 → CONDITIONAL",
        ))
    elif has_guard:
        findings.append(IntOverflowFinding(
            line=line_no, pattern="malloc_mul_overflow",
            expression=f"malloc({size_var} * sizeof({type_name}))",
            lhs_var=result_var, operand_a=size_var,
            operand_b=f"sizeof({type_name})",
            has_guard=True, overflow_possible=False, confidence=0.15,
            reason=f"malloc({size_var}*sizeof({type_name})) 有溢出守卫 → LOW",
        ))
    else:
        findings.append(IntOverflowFinding(
            line=line_no, pattern="malloc_mul_overflow",
            expression=f"malloc({size_var} * sizeof({type_name}))",
            lhs_var=result_var, operand_a=size_var,
            operand_b=f"sizeof({type_name})",
            has_guard=False, overflow_possible=True, confidence=0.55,
            reason=f"malloc({size_var}*sizeof({type_name})) {size_var} 来源未追踪",
        ))


def is_signed_context(source: str, var_name: str) -> bool:
    """检查变量是否声明为有符号类型 (int/int32_t/long/ptrdiff_t/ssize_t/off_t)."""
    signed_types = r'\b(?:int|int32_t|int64_t|long|ptrdiff_t|ssize_t|off_t)\b'
    pat = re.compile(rf'{signed_types}\s+{re.escape(var_name)}\b')
    if pat.search(source):
        return True
    param_pat = re.compile(rf'{signed_types}\s+(?:const\s+)?{re.escape(var_name)}\b')
    return bool(param_pat.search(source))


def is_used_in_malloc(lines: List[str], idx: int, var_name: str) -> bool:
    """检查变量是否在同块后继行中用作分配函数参数 (向后6行)."""
    end = min(idx + 7, len(lines))
    pat = re.compile(
        rf'(?:malloc|calloc|realloc)\s*\([^)]*\b{re.escape(var_name)}\b')
    for j in range(idx + 1, end):
        if pat.search(lines[j]):
            return True
    return False
