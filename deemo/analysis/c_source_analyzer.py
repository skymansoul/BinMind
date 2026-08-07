"""
C源码直接分析器 — 将C源码解析为 HeapOverflowCandidate 供FP过滤管线消费.

与 heap_overflow_detector 的关系: 互补非替代.
  · heap_overflow_detector: 输入为 Ghidra/r2 反编译IR
  · c_source_analyzer: 输入为原始C源码(测试/评估场景)
拆分自: c_source_patterns (纯函数正则), c_source_write_utils (写入端).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)
from analysis.c_source_patterns import (
    parse_alloc_call,
    _STORE_PAT_DIRECT, _STORE_PAT_ARROW,
    _STORE_PAT_DEREF, _STORE_PAT_PTR_ARITH,
    parse_size, infer_loop_bound, is_user_controlled,
    has_any_user_input, resolve_constant,
)
from analysis.c_source_write_utils import (
    _split_args_simple,
    extract_func_write_size, _resolve_vars_in_expr,
    infer_element_size, glibc_usable_size,
)


# 分配点提取

def extract_allocations_from_c(source: str, lines: List[str]) -> List[HeapAllocSite]:
    """两遍扫描: 先声明式 (char *p = malloc), 再赋值式 (p = malloc).

    对变量大小的分配 (如 malloc(n)), 尝试常量传播解析 n 的值.
    """
    allocs: List[HeapAllocSite] = []
    matched: Set[int] = set()

    for i, line in enumerate(lines):
        if _is_comment_or_empty(line):
            continue
        result = parse_alloc_call(line, is_decl=True)
        if result:
            var, func, size, is_dyn, size_expr = result
            allocs.append(HeapAllocSite(
                pc=i, alloc_func=func, size_arg=size,
                size_is_dynamic=is_dyn, result_var=var,
                size_expr=size_expr,
            ))
            matched.add(i)

    for i, line in enumerate(lines):
        if i in matched or _is_comment_or_empty(line):
            continue
        result = parse_alloc_call(line, is_decl=False)
        if result:
            var, func, size, is_dyn, size_expr = result
            allocs.append(HeapAllocSite(
                pc=i, alloc_func=func, size_arg=size,
                size_is_dynamic=is_dyn, result_var=var or '',
                size_expr=size_expr,
            ))

    # 第三遍: 对 size=0 的动态分配, 尝试常量传播
    for alloc in allocs:
        if alloc.size_arg == 0 and alloc.size_is_dynamic:
            # 从源码行中提取原始size参数并做常量传播
            # 行格式如: char *buf = (char *)malloc(n); — 提取 n
            line = lines[alloc.pc]
            # 尝试从 alloc 调用中提取变量名
            resolved = _resolve_alloc_size_from_line(line, alloc.alloc_func, lines, alloc.pc)
            if resolved > 0:
                alloc.size_arg = resolved
                alloc.size_is_dynamic = False

    return allocs


def _resolve_alloc_size_from_line(
    line: str, func: str, lines: List[str], line_idx: int,
) -> int:
    """从分配行提取变量名并做常量传播.

    例如: buf = malloc(n) → 变量 n → resolve_constant('n', lines, line_idx).
    """
    import re
    # 找 malloc/calloc/realloc 调用的参数
    m = re.search(
        r'(?:malloc|calloc|realloc)\s*\(([^)]+)\)',
        line, re.IGNORECASE,
    )
    if not m:
        return -1
    args_str = m.group(1)
    # 对嵌套括号做简单处理
    args = _split_args_simple(args_str)
    if not args:
        return -1

    if func == 'realloc' and len(args) >= 2:
        size_var = args[1].strip()
    elif func == 'calloc' and len(args) >= 2:
        # calloc(n, size) — 尝试分别解析
        n_val, n_dyn = parse_size(args[0].strip())
        s_val, s_dyn = parse_size(args[1].strip())
        if not n_dyn and not s_dyn:
            return n_val * s_val
        return -1
    else:
        size_var = args[0].strip()

    # 纯数字
    try:
        return int(size_var, 0)
    except ValueError:
        pass

    # 简单算术表达式
    val, is_dyn = parse_size(size_var)
    if not is_dyn and val > 0:
        return val

    # 变量名 → 常量传播
    if re.match(r'^\w+$', size_var):
        return resolve_constant(size_var, lines, line_idx)
    return -1


# 写入点提取

def extract_stores_from_c(
    lines: List[str], alloc: HeapAllocSite,
) -> List[HeapStore]:
    """提取对指定分配变量的写入: memcpy/memset, buf[idx]=, *(buf+N)=."""
    stores: List[HeapStore] = []
    var = alloc.result_var
    if not var:
        return stores

    start, end = alloc.pc + 1, min(len(lines), alloc.pc + 80)
    for i in range(start, end):
        line = lines[i]

        # memcpy/memset(buf, ...) / memcpy(ptr->field, ...)
        m = _STORE_PAT_DIRECT.search(line)
        if m:
            matched_var = m.group(1)
            # 检查是否匹配: 直接匹配 var, 或 ptr->field 的 field 部分匹配 var
            is_match = (matched_var == var or
                        ('->' in matched_var and matched_var.split('->')[-1] == var))
            if is_match:
                stores.append(HeapStore(
                    pc=i, base_var=var, offset=0,
                    offset_is_dynamic=False,
                    store_size=extract_func_write_size(line, lines, i),
                    mnemonic='call',
                ))
                continue

        # buf[idx] = val (静态索引)
        for sm in _STORE_PAT_ARROW.finditer(line):
            if sm.group(1) == var:
                try:
                    off = int(sm.group(2), 0)
                    stores.append(HeapStore(
                        pc=i, base_var=var, offset=off,
                        offset_is_dynamic=False, store_size=4, mnemonic='mov',
                    ))
                except ValueError:
                    # 动态索引 (如 buf[i]), 标记以便循环边界推断
                    pass

# (type*)(buf + N) = val
        m3 = _STORE_PAT_DEREF.search(line)
        if m3 and m3.group(1) == var:
            stores.append(HeapStore(
                pc=i, base_var=var, offset=int(m3.group(2), 0),
                offset_is_dynamic=False, store_size=8, mnemonic='mov',
            ))
            continue

# (buf + N) = val
        m4 = _STORE_PAT_PTR_ARITH.search(line)
        if m4 and m4.group(1) == var:
            stores.append(HeapStore(
                pc=i, base_var=var, offset=int(m4.group(2), 0),
                offset_is_dynamic=False, store_size=8, mnemonic='mov',
            ))

    return stores


# 主入口

def _is_comment_or_empty(line: str) -> bool:
    """判断是否为注释行或空行 (提取alloc/store时应跳过)."""
    stripped = line.strip()
    return (not stripped or stripped.startswith('//') or
            stripped.startswith('/*') or stripped.startswith('*') or
            stripped.startswith('#'))


def analyze_c_source(source: str) -> List[HeapOverflowCandidate]:
    """分析C源码, 返回堆溢出候选列表.

    覆盖三类场景:
      1. 静态偏移超出分配大小 (offset=72 > malloc(64))
      2. 动态偏移但有循环上界 (for(i<100) buf[i], malloc(32) → 溢出)
      3. 动态分配大小但来自用户输入 (malloc(atoi(argv[1])) → 保守报告)
    """
    lines = source.splitlines()
    allocs = extract_allocations_from_c(source, lines)
    candidates: List[HeapOverflowCandidate] = []

    for alloc in allocs:
        # 动态分配大小 → 风险判断
        if alloc.size_is_dynamic or alloc.size_arg <= 0:
            # 检查: (1) 变量直连用户输入; (2) 函数内有任意用户输入源
            user_related = (
                is_user_controlled(alloc.result_var, lines)
                or has_any_user_input(lines)
            )
            if user_related:
                candidates.append(HeapOverflowCandidate(
                    alloc_site=alloc, overflow_store=HeapStore(
                        pc=alloc.pc, base_var=alloc.result_var,
                        offset=0, offset_is_dynamic=True, store_size=-1,
                    ),
                    overflow_bytes=0, confidence=0.40,
                    description=(
                        f'{alloc.alloc_func}(dynamic) user-controlled size'
                    ),
                ))
            # 非用户输入的动态分配: 无法确定大小, 保守跳过
            # 后续阶段 (路径约束/符号执行) 可提供更精确分析
            continue

        stores = extract_stores_from_c(lines, alloc)

        # 分配器语义: 使用 glibc 对齐后的实际可用容量而非原始请求大小
        capacity = glibc_usable_size(alloc.size_arg)

        # 循环边界推断 (处理 buf[i] 动态索引)
        if not stores:
            bound = infer_loop_bound(lines, alloc.pc)
            if bound > 0:
                # 元素大小: char* → 1, int* → 4, 用于计算有效写入总量
                elem_size = infer_element_size(lines[alloc.pc])
                effective_bound = bound * elem_size
                if effective_bound > capacity:
                    overflow = effective_bound - capacity
                    candidates.append(HeapOverflowCandidate(
                        alloc_site=alloc, overflow_store=HeapStore(
                            pc=alloc.pc, base_var=alloc.result_var,
                            offset=effective_bound, offset_is_dynamic=False,
                            store_size=1,
                        ),
                        overflow_bytes=overflow, confidence=0.55,
                        description=(
                            f'{alloc.alloc_func}({alloc.size_arg})→usable={capacity} → '
                            f'loop {bound}*{elem_size}B={effective_bound}B'
                            f' > usable (by {overflow}B)'
                        ),
                    ))

        # 静态偏移检查
        for store in stores:
            if store.offset_is_dynamic:
                continue
            write_end = store.offset + max(store.store_size, 1)

            if store.offset >= capacity:
                overflow = write_end - capacity
                conf = 0.85 if store.offset > capacity + 8 else 0.60
                candidates.append(HeapOverflowCandidate(
                    alloc_site=alloc, overflow_store=store,
                    overflow_bytes=max(0, overflow), confidence=conf,
                    description=(
                        f'{alloc.alloc_func}({alloc.size_arg})→usable={capacity} → '
                        f'store offset={store.offset} overflow={overflow}B'
                    ),
                ))
            elif write_end > capacity:
                overflow = write_end - capacity
                candidates.append(HeapOverflowCandidate(
                    alloc_site=alloc, overflow_store=store,
                    overflow_bytes=max(0, overflow), confidence=0.65,
                    description=(
                        f'{alloc.alloc_func}({alloc.size_arg})→usable={capacity} → '
                        f'store [{store.offset}:{write_end}] '
                        f'crosses boundary ({overflow}B)'
                    ),
                ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates
