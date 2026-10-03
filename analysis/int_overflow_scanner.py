"""
C源码整数溢出 — 行扫描器。

封装逐行模式匹配逻辑, 辅助函数提取至 int_overflow_helpers.py。
"""

from __future__ import annotations

import re
from typing import List

from analysis.int_overflow_patterns import (
    IntOverflowFinding,
    _MALLOC_MUL_PAT, _MALLOC_ADDSUB_PAT,
    _TRUNCATION_PAT, _MALLOC_MUL_RETURN_PAT, _REALLOC_SUB_PAT,
    _SIGNED_ADD_IDX_PAT, _BARE_MUL_PAT, _LOOP_ACCUM_PAT,
)
from analysis.int_overflow_helpers import (
    extract_untrusted_vars, has_overflow_guard, find_matching_brace,
    add_malloc_mul_finding, is_signed_context, is_used_in_malloc,
)


def scan_lines_for_int_overflow(
    source: str, findings: List[IntOverflowFinding],
) -> None:
    """对 C 源码逐行执行 8 种模式匹配, 追加 findings.

    覆盖:
      1. malloc(n * sizeof(T)) — CWE-190
      2. malloc(signed_int) — CWE-681
      3. malloc(var +/- const) — CWE-190/191
      4. int n = (int)size_t — CWE-680
      5a. return malloc(n * sizeof(T))
      5b. malloc(var1 - var2) — signed sub
      5c. int idx = a + b; buf[idx] — CWE-129
      5d. bare n * sizeof(T) used in malloc
      6. loop accumulator +=
      7. contextual mul in malloc context
    """
    lines = source.splitlines()
    untrusted_vars = extract_untrusted_vars(source)

    for i, line in enumerate(lines):
        line_no = i + 1
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            continue

        # 模式 1: malloc(n * sizeof(T)) CWE-190
        mm = _MALLOC_MUL_PAT.search(stripped)
        if mm:
            add_malloc_mul_finding(mm, line_no, source, untrusted_vars, findings)
            continue

        # 模式 2: malloc(signed_int) CWE-681
        sm = re.search(
            r'(?:malloc|calloc)\s*\(\s*(?:\(\s*(?:size_t|int|unsigned)\s*\)\s*)?'
            r'(\w+)\s*\)', stripped)
        if sm and is_signed_context(source, sm.group(1)):
            findings.append(IntOverflowFinding(
                line=line_no, pattern="signed_to_unsigned",
                expression=f"malloc({sm.group(1)})",
                operand_a=sm.group(1),
                has_guard=has_overflow_guard(source, line_no),
                overflow_possible=True, confidence=0.75,
                reason=(f"CWE-681: 有符号变量 {sm.group(1)} 直接传给 malloc "
                        f"→ -1→SIZE_MAX 分配 (巨大/失败)"),
            ))
            continue

        # 模式 3: malloc(var +/- const) CWE-190/191
        am = _MALLOC_ADDSUB_PAT.search(stripped)
        if am:
            var_name = am.group(1)
            op = am.group(2)
            const_val = int(am.group(3))
            is_untrusted = var_name in untrusted_vars
            cwe = "CWE-191" if op == '-' else "CWE-190"
            findings.append(IntOverflowFinding(
                line=line_no,
                pattern="addition_overflow" if op == '+' else "subtraction_underflow",
                expression=stripped[:80],
                operand_a=var_name, operand_b=str(const_val),
                has_guard=has_overflow_guard(source, line_no),
                overflow_possible=True,
                confidence=0.70 if is_untrusted else 0.45,
                reason=(f"{cwe}: {var_name}{op}{const_val} 可能溢出"
                        f"{', 不可信输入' if is_untrusted else ''}"),
            ))
            continue

        # 模式 4: int n = (int)size_t_var CWE-680
        tm = _TRUNCATION_PAT.search(stripped)
        if tm:
            narrow_var = tm.group(1)
            wide_var = tm.group(2)
            findings.append(IntOverflowFinding(
                line=line_no, pattern="type_truncation",
                expression=f"int {narrow_var} = (int){wide_var}",
                lhs_var=narrow_var, operand_a=wide_var,
                has_guard=False, overflow_possible=True, confidence=0.65,
                reason=(f"CWE-680: size_t→int 截断, {wide_var} 的高32位被丢弃 "
                        f"→ {narrow_var} 负值绕过后继检查"),
            ))
            continue

        # 模式 5a: return malloc(n * sizeof(T))
        rm = _MALLOC_MUL_RETURN_PAT.search(stripped)
        if rm:
            mul_var = rm.group(1)
            findings.append(IntOverflowFinding(
                line=line_no, pattern="return_malloc_mul",
                expression=stripped[:80],
                operand_a=mul_var,
                operand_b=rm.group(2) if rm.lastindex >= 2 and rm.group(2) else "sizeof(...)",
                has_guard=has_overflow_guard(source, line_no),
                overflow_possible=True, confidence=0.70,
                reason=(f"分配器包装函数 return malloc({mul_var} * sizeof) "
                        f"— CWE-190 乘法溢出 (CVE-2016-10190 模式)"),
            ))
            continue

        # 模式 5b: realloc/malloc(var1 - var2)
        sm = _REALLOC_SUB_PAT.search(stripped)
        if sm:
            var1, var2 = sm.group(1), sm.group(2)
            if is_signed_context(source, var1) or is_signed_context(source, var2):
                findings.append(IntOverflowFinding(
                    line=line_no, pattern="signed_sub_underflow",
                    expression=f"malloc({var1} - {var2})",
                    operand_a=var1, operand_b=var2,
                    has_guard=has_overflow_guard(source, line_no),
                    overflow_possible=True, confidence=0.70,
                    reason=(f"CWE-191: 有符号减法 {var1}-{var2}, "
                            f"若 {var2}>{var1} 则下溢为巨量 → 分配失败或过量"),
                ))
                continue

        # 模式 5b2: int var = a - b; ... realloc(var)
        ssm = re.search(
            r'(?:int|unsigned\s+int)\s+(\w+)\s*=\s*(\w+)\s*-\s*(\w+)\s*;',
            stripped)
        if ssm:
            result_var = ssm.group(1)
            if is_used_in_malloc(lines, i, result_var):
                findings.append(IntOverflowFinding(
                    line=line_no, pattern="signed_sub_underflow",
                    expression=f"int {result_var} = {ssm.group(2)} - {ssm.group(3)}",
                    lhs_var=result_var,
                    operand_a=ssm.group(2), operand_b=ssm.group(3),
                    has_guard=has_overflow_guard(source, line_no),
                    overflow_possible=True, confidence=0.65,
                    reason=(f"CWE-191: {ssm.group(2)}-{ssm.group(3)} → "
                            f"{result_var} 后继用于 alloc, 下溢风险"),
                ))
                continue

        # 模式 5c: int idx = a + b; buf[idx] — CWE-129
        im = _SIGNED_ADD_IDX_PAT.search(stripped)
        if im:
            idx_var, a_var, b_var = im.group(1), im.group(2), im.group(3)
            near = '\n'.join(lines[i:min(i + 5, len(lines))])
            if re.search(rf'{re.escape(idx_var)}\s*\]', near):
                findings.append(IntOverflowFinding(
                    line=line_no, pattern="signed_add_overflow",
                    expression=f"int {idx_var} = {a_var} + {b_var}",
                    lhs_var=idx_var, operand_a=a_var, operand_b=b_var,
                    has_guard=has_overflow_guard(source, line_no),
                    overflow_possible=True, confidence=0.60,
                    reason=(f"CWE-129: {a_var}+{b_var} 加法溢出 → {idx_var} "
                            f"可能为负, 绕过 if(idx<N) 有符号检查"),
                ))
                continue

        # 模式 5d: 裸乘法 n * sizeof(T) 用于分配
        bm = _BARE_MUL_PAT.search(stripped)
        if bm and is_used_in_malloc(lines, i, bm.group(1)):
            findings.append(IntOverflowFinding(
                line=line_no, pattern="bare_mul_malloc",
                expression=stripped[:80],
                lhs_var=bm.group(1), operand_a=bm.group(2),
                has_guard=has_overflow_guard(source, line_no),
                overflow_possible=True, confidence=0.55,
                reason=f"裸乘法 {bm.group(1)}={bm.group(2)}*sizeof(...) 后继用于 malloc",
            ))

        # 模式 6: 循环累积 +=
        if re.search(r'for\s*\(|while\s*\(', stripped):
            body_end = find_matching_brace(lines, i)
            for j in range(i, min(body_end + 1, len(lines))):
                accum_m = _LOOP_ACCUM_PAT.search(lines[j].strip())
                if accum_m:
                    var_name = accum_m.group(1)
                    has_guard = bool(re.search(
                        rf'if\s*\(.*[><].*{re.escape(var_name)}', source))
                    findings.append(IntOverflowFinding(
                        line=i + 1, pattern="loop_accumulator",
                        expression=f"{var_name} += {accum_m.group(2)} in loop",
                        lhs_var=accum_m.group(1),
                        has_guard=has_guard,
                        overflow_possible=not has_guard,
                        confidence=0.40 if has_guard else 0.55,
                        reason=("循环累积无溢出守卫 → 多次迭代后溢出"
                                if not has_guard else "循环累积有守卫 → CONDITIONAL"),
                    ))
                    break
            continue

        # 模式 7: 非函数调用上下文的乘法 (全局检查)
        if '*' in stripped and not stripped.startswith('//'):
            has_malloc_context = 'malloc' in source[max(0, i-5):min(len(source), i+5)]
            if has_malloc_context:
                mul_vars = re.findall(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)', stripped)
                for lv, a, const in mul_vars:
                    try:
                        c = int(const)
                        if c >= 2:
                            findings.append(IntOverflowFinding(
                                line=line_no, pattern="contextual_mul",
                                expression=f"{lv}={a}*{c}",
                                lhs_var=lv, operand_a=a, operand_b=str(c),
                                has_guard=has_overflow_guard(source, line_no),
                                overflow_possible=True, confidence=0.40,
                                reason=f"malloc上下文中的乘法 {lv}={a}*{c} → 溢出风险",
                            ))
                    except ValueError:
                        pass
