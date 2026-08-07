# [DEPRECATED] 本模块从未被任何管线导入或调用, GAPSBV FP过滤实际使用 fp_filter_stages.py (IR级).
"""C源码级FP过滤阶段 — C源码行 (if/for/malloc 等模式) 的模式匹配.

与 fp_filter_stages.py 语义等价但消费不同输入: IR行 vs C源码行.
"""

import re
from typing import Any, List, Tuple

from analysis._fp_accessors import (
    _get_alloc_size, _get_alloc_var, _get_base_var,
    _get_size_var, _get_store_pc, _get_write_offset, _get_write_size,
    _try_parse_int,
)


# S2: 守卫感知写入

# 匹配 if (var < N) 或 if (... && var < N ...) 复合条件
# 边界可以是数字或变量名 (变量边界需后续与 alloc_var 交叉验证)
_RE_IF_GUARD = re.compile(
    r'if\s*\(.*\b(\w+)\s*(<|<=)\s*(\w+)\b')
_RE_IF_GUARD_GT = re.compile(
    r'if\s*\(.*\b(\w+)\s*(>|>=)\s*(\w+)\b')
_RE_FOR_LOOP = re.compile(
    r'for\s*\(\s*(?:int|size_t|unsigned|long|short|uint\d+_t|int\d+_t)\s+'
    r'(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+|\d+)\s*;')
_RE_ALLOC_TYPE = re.compile(
    r'(\w+)\s*\*\s*(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\)\s*)?(?:malloc|calloc|realloc)\s*\(')


def _detect_element_size(src_lines: List[str], alloc_var: str) -> int:
    """从 malloc 声明推断元素大小 (bytes). 默认1 (保守char)."""
    for line in src_lines:
        m = _RE_ALLOC_TYPE.search(line)
        if m and m.group(2) == alloc_var:
            type_name = m.group(1).lower()
            if type_name in ('char', 'uint8_t', 'int8_t', 'byte'):
                return 1
            elif type_name in ('short', 'uint16_t', 'int16_t'):
                return 2
            elif type_name in ('int', 'long', 'float', 'uint32_t', 'int32_t',
                               'size_t', 'unsigned', 'uint', 'dword'):
                return 4
            elif type_name in ('double', 'uint64_t', 'int64_t', 'qword'):
                return 8
            break
    return 1  # 默认保守: 假设char


def stage2_guard_aware_c(
    integrator, candidates: List[Any], src_lines: List[str],
) -> Tuple[List[Any], int]:
    """S2 C源码版: 检测 if/for 守卫条件, 硬过滤受保护写入.

    模式:
      if (idx < N) { buf[idx] = ... }    → 守卫
      for (i = 0; i < N; i++) { buf[i] = ... }  → 循环守卫

    判定: 若守卫边界 N ≤ alloc_size, 且写入索引受约束, 则安全.
    """
    kept = []
    removed = 0
    for c in candidates:
        alloc_sz = _get_alloc_size(integrator, c)
        write_off = _get_write_offset(integrator, c)
        store_pc = _get_store_pc(integrator, c)
        base_var = _get_base_var(integrator, c)
        alloc_var = _get_alloc_var(integrator, c)
        size_var = _get_size_var(integrator, c)

        if store_pc < 0 or store_pc >= len(src_lines):
            kept.append(c)
            continue

        elem_size = _detect_element_size(src_lines, alloc_var) if alloc_var else 1

        is_guarded = False
        guard_bound = -1
        search_start = max(0, store_pc - 40)

        for pc in range(search_start, store_pc):
            line = src_lines[pc].strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue

            if pc == store_pc:
                continue

            # 模式1: if (idx < N) 或 if (idx <= N)
            m = _RE_IF_GUARD.search(line)
            if m:
                guard_var = m.group(1)
                op = m.group(2)
                bound_str = m.group(3)
                is_cnst, bound_val = _try_parse_int(bound_str)

                if guard_var == base_var or guard_var in (
                        'i', 'idx', 'j', 'k', 'n', alloc_var, size_var):
                    if is_cnst:
                        effective_bound = bound_val if op == '<' else bound_val
                        if op == '<=':
                            effective_bound = bound_val
                        if effective_bound > 0:
                            if alloc_sz > 0:
                                if effective_bound * elem_size <= alloc_sz:
                                    is_guarded = True
                                    guard_bound = effective_bound
                                    break
                            else:
                                is_guarded = True
                                guard_bound = effective_bound
                                break
                    elif bound_str == size_var or bound_str == alloc_var:
                        is_guarded = True
                        guard_bound = 0
                        break

            # 模式2: for (i = 0; i < N; i++) — 考虑起始偏移
            fm = _RE_FOR_LOOP.search(line)
            if fm:
                loop_var = fm.group(1)
                bound_str = fm.group(2)
                is_cnst, bound_val = _try_parse_int(bound_str)
                if is_cnst and bound_val > 0:
                    if elem_size == 1 and alloc_sz > 0:
                        base_off = write_off if write_off >= 0 else 0
                        if base_off + bound_val <= alloc_sz:
                            is_guarded = True
                            guard_bound = bound_val
                            break
                elif (bound_str == alloc_var or bound_str == size_var) and elem_size == 1:
                    is_guarded = True
                    guard_bound = alloc_sz
                    break

        if is_guarded:
            integrator._add_note(
                c, f'S2(CS): guarded idx<{guard_bound} ≤ alloc={alloc_sz}')
            removed += 1
            continue

        kept.append(c)
    return kept, removed


# S3: 上游size约束

_RE_SIZE_CLAMP = re.compile(
    r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)\s*\{?\s*\1\s*=\s*\2\s*;')
_RE_MIN_CALL = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w+\s*\))?\s*min\s*\(\s*\1\s*,\s*(\d+)\s*\)', re.I)
_RE_TERNARY_CLAMP = re.compile(
    r'(\w+)\s*=\s*\(\s*\1\s*>\s*(\d+)\s*\)\s*\?\s*\2\s*:\s*\1\s*;')


def stage3_size_constraints_c(
    integrator, candidates: List[Any], src_lines: List[str],
) -> Tuple[List[Any], int]:
    """S3 C源码版: 检测 malloc 前的 size 约束, 软降级置信度.

    模式:
      if (size > MAX) size = MAX;
      size = min(size, MAX);
      size = (size > MAX) ? MAX : size;
    """
    adjusted = 0
    for c in candidates:
        size_var = _get_size_var(integrator, c)
        if not size_var or not size_var.isidentifier():
            continue
        alloc_sz = _get_alloc_size(integrator, c)
        if alloc_sz > 0:
            continue
        alloc_pc = getattr(
            getattr(c, 'alloc_site', None), 'pc', len(src_lines) // 2)

        search_end = min(alloc_pc, len(src_lines))
        max_bound = -1

        for pc in range(max(0, search_end - 60), search_end):
            line = src_lines[pc].strip()
            if not line or line.startswith('//'):
                continue

            m = _RE_SIZE_CLAMP.search(line)
            if m and m.group(1) == size_var:
                _, bv = _try_parse_int(m.group(2))
                if bv > 0:
                    max_bound = bv

            m2 = _RE_MIN_CALL.search(line)
            if m2 and m2.group(1) == size_var:
                _, bv = _try_parse_int(m2.group(2))
                if bv > 0:
                    max_bound = bv

            m3 = _RE_TERNARY_CLAMP.search(line)
            if m3 and m3.group(1) == size_var:
                _, bv = _try_parse_int(m3.group(2))
                if bv > 0:
                    max_bound = bv

        if max_bound > 0:
            write_sz = _get_write_size(integrator, c)
            write_mnemonic = getattr(
                getattr(c, 'overflow_store', None), 'mnemonic', '')
            if write_sz > 0 and write_sz <= max_bound:
                integrator._adjust_confidence(c, -0.50)
                integrator._add_note(
                    c, f'S3(CS): {size_var}≤{max_bound}, write={write_sz}≤{max_bound}')
                adjusted += 1
            elif write_sz <= 0 and write_mnemonic in (
                    'memcpy', 'memset', 'strncpy', 'copy', 'call', ''):
                integrator._adjust_confidence(c, -0.40)
                integrator._add_note(
                    c, f'S3(CS): {size_var}≤{max_bound}, shared size var→safe')
                adjusted += 1
    return candidates, adjusted


# S4: 证明义务 (C源码版)

_RE_IF_RETURN = re.compile(
    r'if\s*\(\s*(\w+)\s*(<=|<)\s*0\s*\)\s*(?:return|goto\s+\w+)\s*;')
_RE_VAR_GT_CONST = re.compile(r'\b(\w+)\s*(>|>=)\s*(\d+)\b')
_RE_VAR_LE_CONST = re.compile(r'\b(\w+)\s*(<=|<)\s*(\d+)\b')
_RE_COMPOUND_BOUND = re.compile(
    r'if\s*\([^)]*(\w+)\s*[<>=!]+\s*\d+\s*\|\|\s*\1\s*[<>=!]+\s*(\d+)[^)]*\)')
_RE_IF_BOUND_RETURN = re.compile(
    r'if\s*\(\s*(\w+)\s*(>|>=)\s*(\d+)\s*\)\s*(?:return|goto\s+\w+)\s*;')
_RE_MUL_ASSIGN = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;')
_RE_ADD_ASSIGN = re.compile(r'(\w+)\s*\+=\s*(\w+)\s*;')
_RE_MUL_EXPR = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;')


def _detect_int_overflow_risk(
    src_lines: List[str], size_var: str, alloc_pc: int,
) -> bool:
    """检测 size_var 是否源自乘法 (整数溢出风险).

    模式: total = nfrags * frag_size; malloc(total);
    若 total 的计算包含乘法, 存在整数溢出可能 → 不应降低置信度.
    """
    search_start = max(0, alloc_pc - 30)
    for pc in range(search_start, alloc_pc):
        line = src_lines[pc].strip()
        if not line or line.startswith('//'):
            continue

        m = _RE_MUL_ASSIGN.search(line)
        if m and m.group(1) == size_var:
            return True

        m2 = _RE_ADD_ASSIGN.search(line)
        if m2 and m2.group(1) == size_var:
            return True

        m3 = _RE_MUL_EXPR.search(line)
        if m3 and m3.group(1) == size_var:
            return True

    return False


def _extract_store_size_var(line: str) -> str:
    """从 memcpy(buf, src, N) 中提取第三个参数的变量名. 失败返回空字符串."""
    m = re.search(
        r'(?:memcpy|memset|memmove|strncpy)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)',
        line, re.IGNORECASE)
    if m:
        var = m.group(1)
        if var.isidentifier() and not var.isdigit():
            return var
    return ""


def stage4_proof_obligations_c(
    integrator, candidates: List[Any], src_lines: List[str],
) -> Tuple[List[Any], int, int]:
    """S4 C源码版 v3.2: 约束证明 + 共享变量 + store变量约束.

    返回 (kept, hard_filtered, soft_adjusted).
    """
    from analysis.c_source_var_resolver import CSourceVarResolver

    resolver = CSourceVarResolver(src_lines)
    kept = []
    hard_filtered = 0
    soft_adjusted = 0

    for c in candidates:
        alloc_sz = _get_alloc_size(integrator, c)
        size_var = _get_size_var(integrator, c)
        write_sz = _get_write_size(integrator, c)
        store_pc = _get_store_pc(integrator, c)
        store_mnemonic = getattr(
            getattr(c, 'overflow_store', None), 'mnemonic', '')
        alloc_pc = getattr(
            getattr(c, 'alloc_site', None), 'pc', len(src_lines) // 2)

        store_size_var = ""
        if store_mnemonic in ('memcpy', 'memset', 'strncpy', 'call'):
            if 0 <= store_pc < len(src_lines):
                store_size_var = _extract_store_size_var(src_lines[store_pc])
        size_lower = False
        size_upper = False
        size_upper_val = -1
        store_lower = False
        store_upper = False
        store_upper_val = -1

        search_start = max(0, min(alloc_pc, store_pc) - 80)
        search_end = max(alloc_pc, store_pc)

        for pc in range(search_start, search_end):
            line = src_lines[pc].strip()
            if not line or line.startswith('//'):
                continue

            if size_var and size_var in line:
                if not size_lower:
                    m = _RE_IF_RETURN.search(line)
                    if m and m.group(1) == size_var:
                        size_lower = True
                if not size_upper:
                    m2 = _RE_VAR_GT_CONST.search(line)
                    if m2 and m2.group(1) == size_var:
                        _, bv = _try_parse_int(m2.group(3))
                        if bv > 0:
                            size_upper = True
                            size_upper_val = bv
                    m3 = _RE_IF_BOUND_RETURN.search(line)
                    if m3 and m3.group(1) == size_var:
                        _, bv = _try_parse_int(m3.group(2))
                        if bv > 0:
                            size_upper = True
                            size_upper_val = bv
                m4 = _RE_COMPOUND_BOUND.search(line)
                if m4 and m4.group(1) == size_var:
                    _, bv = _try_parse_int(m4.group(2))
                    if bv > 0:
                        size_lower = True
                        size_upper = True
                        size_upper_val = bv

            if store_size_var and store_size_var in line and alloc_sz > 0:
                if not store_lower:
                    m = _RE_IF_RETURN.search(line)
                    if m and m.group(1) == store_size_var:
                        store_lower = True
                if not store_upper:
                    m2 = _RE_VAR_GT_CONST.search(line)
                    if m2 and m2.group(1) == store_size_var:
                        _, bv = _try_parse_int(m2.group(3))
                        if bv > 0:
                            store_upper = True
                            store_upper_val = bv
                    m3 = _RE_IF_BOUND_RETURN.search(line)
                    if m3 and m3.group(1) == store_size_var:
                        _, bv = _try_parse_int(m3.group(2))
                        if bv > 0:
                            store_upper = True
                            store_upper_val = bv
                m4 = _RE_COMPOUND_BOUND.search(line)
                if m4 and m4.group(1) == store_size_var:
                    _, bv = _try_parse_int(m4.group(2))
                    if bv > 0:
                        store_lower = True
                        store_upper = True
                        store_upper_val = bv

        has_intovf_risk = False
        if size_var:
            has_intovf_risk = _detect_int_overflow_risk(
                src_lines, size_var, alloc_pc)
        shares_var = bool(
            size_var and store_size_var and store_size_var == size_var)

        # 硬过滤规则

        # 规则1: store变量有上界 + static alloc + 上界 ≤ alloc → 安全
        if store_upper and store_upper_val > 0 and alloc_sz > 0:
            if store_upper_val <= alloc_sz:
                integrator._add_note(
                    c, f'S4(CS)v3.2: store "{store_size_var}"'
                    f'≤{store_upper_val}≤alloc={alloc_sz}')
                hard_filtered += 1
                continue

        # 规则2: size_var有上界 + 共享变量 + 无整数溢出风险 → 安全
        if (size_upper and size_upper_val > 0
                and shares_var and not has_intovf_risk):
            integrator._add_note(
                c, f'S4(CS)v3: HARD FILTER {size_var}≤{size_upper_val}'
                f' + shared var, no intovf')
            hard_filtered += 1
            continue

        # 规则3: 静态alloc + size_var有下界 + write大小已知且在范围内 → 安全
        if alloc_sz > 0 and size_lower:
            ws = _get_write_size(integrator, c)
            if ws > 0 and ws <= alloc_sz:
                integrator._add_note(
                    c, f'S4(CS): fixed alloc={alloc_sz}, write bounded')
                hard_filtered += 1
                continue

        # 软调整规则

        if store_upper and store_upper_val > 0 and alloc_sz > 0:
            if store_upper_val > alloc_sz:
                integrator._adjust_confidence(c, -0.25)
                integrator._add_note(
                    c, f'S4(CS)v3.2: store "{store_size_var}"'
                    f'≤{store_upper_val}, alloc={alloc_sz}')
                soft_adjusted += 1

        if size_upper and size_upper_val > 0:
            ws = _get_write_size(integrator, c)
            if ws > 0 and ws > size_upper_val:
                integrator._adjust_confidence(c, +0.15)
                integrator._add_note(
                    c, f'S4(CS)v3: write_sz={ws} > max_alloc='
                    f'{size_upper_val} → GUARANTEED OVERFLOW')
                soft_adjusted += 1
            elif size_upper_val <= 4096:
                delta = -0.35 if shares_var else -0.30
                integrator._adjust_confidence(c, delta)
                integrator._add_note(
                    c, f'S4(CS)v3: {size_var}≤{size_upper_val}'
                    f'{"+shared_var" if shares_var else ""}')
                soft_adjusted += 1
        elif size_lower:
            if shares_var:
                integrator._adjust_confidence(c, -0.25)
                integrator._add_note(
                    c, f'S4(CS)v3: {size_var}≥1 + shared var')
                soft_adjusted += 1
            else:
                integrator._adjust_confidence(c, -0.15)
                integrator._add_note(c, f'S4(CS)v3: {size_var}≥1 check exists')
                soft_adjusted += 1
        elif shares_var:
            integrator._adjust_confidence(c, -0.10)
            integrator._add_note(
                c, f'S4(CS)v3: shared var "{size_var}" (no constraints)')
            soft_adjusted += 1

        if has_intovf_risk:
            integrator._adjust_confidence(c, +0.15)
            integrator._add_note(c, f'S4(CS)v3: intovf risk for {size_var}')
            soft_adjusted += 1

        kept.append(c)

    return kept, hard_filtered, soft_adjusted


# S5: Slack空间

def stage5_slack_space_c(
    integrator, candidates: List[Any],
) -> Tuple[List[Any], int]:
    """S5: offset在chunk尾部填充 (alignment padding) 内 → 软降级.

    仅当写入完全落在 [alloc_sz, aligned_chunk] 区间时才降级.
    aligned_chunk = max(32, align_up(alloc_sz, 16)).
    """
    adjusted = 0
    for c in candidates:
        alloc_sz = _get_alloc_size(integrator, c)
        write_off = _get_write_offset(integrator, c)
        write_sz = _get_write_size(integrator, c)
        if alloc_sz <= 0 or write_off < 0:
            continue
        mnemonic = getattr(
            getattr(c, 'overflow_store', None), 'mnemonic', '')
        if mnemonic in ('strcpy', 'memcpy', 'strncpy',
                        'memset', 'strcat', 'copy'):
            continue

        chunk = max(32, ((alloc_sz + 15) // 16) * 16)

        if chunk > alloc_sz and alloc_sz < write_off <= chunk:
            write_end = write_off + (write_sz if write_sz > 0 else 1)
            if write_end <= chunk:
                integrator._adjust_confidence(c, -0.40)
                integrator._add_note(
                    c, f'S5(CS): off={write_off} in ({alloc_sz},{chunk}] padding')
                adjusted += 1
    return candidates, adjusted


# S6: 值域传播

_RE_CONST_ASSIGN = re.compile(
    r'(?:int|size_t|unsigned|long)\s+(\w+)\s*=\s*(\d+)\s*;')
_RE_DEFINE = re.compile(r'#define\s+(\w+)\s+(\d+)')


def stage6_value_range_c(
    integrator, candidates: List[Any], src_lines: List[str],
) -> Tuple[List[Any], int]:
    """S6 C源码版 v3: 解析未知写入大小并与已知alloc比较.

    策略:
      场景A: alloc_sz > 0 且 write_sz ≤ 0 → 解析write大小 → 若 ≤ alloc → 安全
      场景B: alloc_sz ≤ 0 → 解析alloc大小 → 比较
      场景C: 两者皆已知 → 直接比较 (退化为S1逻辑, 处理动态偏移)
    """
    from analysis.c_source_var_resolver import CSourceVarResolver

    resolver = CSourceVarResolver(src_lines)
    adjusted = 0

    for c in candidates:
        alloc_sz = _get_alloc_size(integrator, c)
        write_sz = _get_write_size(integrator, c)
        write_off = _get_write_offset(integrator, c)
        store_pc = _get_store_pc(integrator, c)
        store_mnemonic = getattr(
            getattr(c, 'overflow_store', None), 'mnemonic', '')

        # 场景A: alloc已知但write未知
        if alloc_sz > 0 and write_sz <= 0 and store_pc >= 0:
            resolved_sz = resolver.resolve_store_size(store_pc)
            if resolved_sz > 0:
                write_sz = resolved_sz
                if write_off >= 0 and write_off + write_sz <= alloc_sz:
                    integrator._adjust_confidence(c, -0.40)
                    integrator._add_note(
                        c, f'S6(CS)v3: resolved write_sz={write_sz},'
                        f' write[{write_off}:{write_off+write_sz}] ≤ alloc={alloc_sz}')
                    adjusted += 1
                    continue
                elif write_off < 0 and write_sz <= alloc_sz:
                    integrator._adjust_confidence(c, -0.30)
                    integrator._add_note(
                        c, f'S6(CS)v3: resolved write_sz={write_sz} ≤ alloc={alloc_sz}')
                    adjusted += 1
                    continue

            if store_pc < len(src_lines):
                store_line = src_lines[store_pc]
                store_size_var = _extract_store_size_var(store_line)
                if store_size_var and store_size_var.isidentifier():
                    resolved_sz = resolver.resolve(store_size_var)
                    if resolved_sz > 0 and resolved_sz <= alloc_sz:
                        integrator._adjust_confidence(c, -0.35)
                        integrator._add_note(
                            c, f'S6(CS)v3: var "{store_size_var}"={resolved_sz}'
                            f' ≤ alloc={alloc_sz}')
                        adjusted += 1
                        continue

        # 场景B: alloc未知 → 尝试解析
        if alloc_sz <= 0:
            size_var = _get_size_var(integrator, c)
            alloc_var = _get_alloc_var(integrator, c)
            effective_alloc = alloc_sz

            if size_var and size_var.isidentifier():
                r = resolver.resolve(size_var)
                if r > 0:
                    effective_alloc = r
            elif alloc_var and alloc_var.isidentifier():
                r = resolver.resolve(alloc_var)
                if r > 0:
                    effective_alloc = r

            if effective_alloc > 0:
                if write_sz <= 0 and store_pc >= 0:
                    resolved_sz = resolver.resolve_store_size(store_pc)
                    if resolved_sz > 0:
                        write_sz = resolved_sz

                if write_off >= 0 and write_sz > 0:
                    if write_off + write_sz <= effective_alloc:
                        integrator._adjust_confidence(c, -0.35)
                        integrator._add_note(
                            c, f'S6(CS)v3: eff_alloc={effective_alloc},'
                            f' write in range')
                        adjusted += 1
                elif write_sz > 0 and write_sz <= effective_alloc:
                    integrator._adjust_confidence(c, -0.30)
                    integrator._add_note(
                        c, f'S6(CS)v3: write_sz={write_sz} ≤ eff_alloc={effective_alloc}')
                    adjusted += 1

        # 场景C: 两者皆已知但动态偏移
        if alloc_sz > 0 and write_sz > 0 and write_off >= 0:
            chunk = max(32, ((alloc_sz + 15) // 16) * 16)
            if write_off + write_sz <= alloc_sz:
                is_dynamic = getattr(
                    getattr(c, 'overflow_store', None), 'offset_is_dynamic', False)
                if is_dynamic:
                    integrator._adjust_confidence(c, -0.20)
                    integrator._add_note(
                        c, f'S6(CS)v3: dynamic off but write in alloc range')
                    adjusted += 1
            elif write_off + write_sz <= chunk:
                integrator._adjust_confidence(c, -0.15)
                integrator._add_note(
                    c, f'S6(CS)v3: write in chunk slack [{alloc_sz},{chunk})')
                adjusted += 1

    return candidates, adjusted


# S7: 非堆写入过滤

_RE_LOCAL_ARRAY = re.compile(
    r'(?:char|int|short|long|float|double|uint8_t|uint16_t|uint32_t|uint64_t)'
    r'\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;')
_RE_GLOBAL_DECL = re.compile(
    r'^(?:static\s+)?(?:const\s+)?'
    r'(?:char|int|short|long|float|double|uint8_t|uint16_t|uint32_t|uint64_t)'
    r'\s+(\w+)\s*\[\s*(\d+)\s*\]\s*=\s*\{')


def stage7_non_heap_c(
    integrator, candidates: List[Any], src_lines: List[str],
) -> Tuple[List[Any], int]:
    """S7 C源码版: 过滤对栈/全局变量的写入.

    检测:
      char local_buf[256]; → 栈分配, 非堆
      static char global_buf[1024]; → 全局, 非堆
      char *heap_buf = malloc(64); → 堆分配

    仅保留堆分配上的写入.
    """
    heap_vars = set()
    for c in candidates:
        av = _get_alloc_var(integrator, c)
        if av:
            heap_vars.add(av)

    if not heap_vars:
        return candidates, 0

    non_heap_vars = set()
    for line in src_lines:
        m = _RE_LOCAL_ARRAY.search(line.strip())
        if m:
            non_heap_vars.add(m.group(1))
        m2 = _RE_GLOBAL_DECL.search(line.strip())
        if m2:
            non_heap_vars.add(m2.group(1))

    kept = []
    removed = 0
    for c in candidates:
        base_var = _get_base_var(integrator, c)
        if not base_var:
            kept.append(c)
            continue

        if base_var in non_heap_vars and base_var not in heap_vars:
            integrator._add_note(c, f'S7(CS): {base_var} is stack/global, not heap')
            removed += 1
            continue

        kept.append(c)
    return kept, removed
