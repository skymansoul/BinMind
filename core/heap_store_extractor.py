"""
堆写入点追踪器 — 追踪malloc返回值到后续store/memcpy/strcpy指令.
"""
import re
from typing import Dict, Optional

from core.heap_overflow_detector import HeapAllocSite, HeapStore

# 特殊值: strcpy = 无界拷贝
_UNBOUNDED_COPY = -2


def _find_aliases(ir_lines: list[str], base_var: str,
                  start_pc: int) -> dict[str, tuple[str, int]]:
    """扫描 IR 中 base_var 的指针别名: alias = base_var + offset.

    返回 {alias_var: (base_var, offset)} 映射.
    例如: inner = outer + 8 → {'inner': ('outer', 8)}
    """
    aliases = {}
    pat = re.compile(
        rf'(\w+)\s*=\s*{re.escape(base_var)}\s*\+\s*(\d+)')
    for i in range(start_pc, min(len(ir_lines), start_pc + 20)):
        m = pat.search(ir_lines[i])
        if m:
            alias_var = m.group(1)
            try:
                offset = int(m.group(2), 0)
                aliases[alias_var] = (base_var, offset)
            except (ValueError, TypeError):
                pass
    return aliases


def _match_struct_field_store(line: str, field_name: str) -> bool:
    """判断一行是否包含对 struct->field_name 的 copy 操作."""
    pat = re.compile(
        rf'(?:memcpy|memmove|strcpy|strncpy|memset|strcat)\s*\(\s*'
        rf'\w+(?:->|\.)\s*{re.escape(field_name)}',
        re.IGNORECASE,
    )
    return bool(pat.search(line))


def _extract_struct_field_store(line: str, field_name: str) -> tuple[int, int, str]:
    """从 struct->field_name + offset 的 copy 操作中提取偏移、拷贝大小和操作类型.

    memcpy(outer->inner + 0, src, to_copy) → (0, to_copy_value, 'memcpy')
    返回 (offset, copy_size, mnemonic), offset=-1 表示动态.
    """
    # memcpy/strcpy: 目标为 xxx->field + CONST
    m = re.search(
        rf'(?:memcpy|memmove)\s*\(\s*\w+(?:->|\.)\s*{re.escape(field_name)}'
        rf'\s*\+\s*(\d+|\w+)\s*,\s*[^,]+,\s*(\d+|\w+)\s*\)',
        line, re.IGNORECASE)
    if m:
        try:
            off = int(m.group(1), 0)
        except (ValueError, TypeError):
            off = -1
        try:
            sz = int(m.group(2), 0)
        except (ValueError, TypeError):
            sz = -1
        return (off, sz, 'memcpy')

    # memcpy/strcpy: 目标为 xxx->field (无偏移)
    m = re.search(
        rf'(?:memcpy|memmove|strcpy)\s*\(\s*\w+(?:->|\.)\s*{re.escape(field_name)}\s*,',
        line, re.IGNORECASE)
    if m:
        mnemonic = 'memcpy' if 'mem' in m.group(0).lower() else 'strcpy'
        sz_arg = _UNBOUNDED_COPY if mnemonic == 'strcpy' else -1
        sz_m = re.search(
            rf'(?:memcpy|memmove)\s*\(\s*\w+(?:->|\.)\s*{re.escape(field_name)}'
            rf'\s*,\s*[^,]+,\s*(\d+|\w+)\s*\)',
            line, re.IGNORECASE)
        if sz_m:
            try:
                sz_arg = int(sz_m.group(1), 0)
            except (ValueError, TypeError):
                pass
        return (0, sz_arg, mnemonic)

    # strcat(xxx->field, src)
    m = re.search(
        rf'strcat\s*\(\s*\w+(?:->|\.)\s*{re.escape(field_name)}\s*,',
        line, re.IGNORECASE)
    if m:
        return (0, _UNBOUNDED_COPY, 'strcat')

    return (-1, -1, 'copy')


def track_heap_stores(ir_lines: list[str],
                      alloc: HeapAllocSite) -> list[HeapStore]:
    """追踪 malloc 返回值到后续 store 指令, 含指针别名 (如 inner = outer + 8)。"""
    stores = []
    if not alloc.result_var:
        return stores

    var = alloc.result_var

    search_vars: dict[str, int] = {var: 0}
    aliases = _find_aliases(ir_lines, var, alloc.pc)
    for alias_name, (_, alias_off) in aliases.items():
        search_vars[alias_name] = alias_off

    store_fallback = re.compile(
        rf'store.*{re.escape(var)}'
        rf'|{re.escape(var)}\s*\[.*\]\s*='
        rf'|memcpy\s*\(\s*{re.escape(var)}\s*,'
        rf'|strcpy\s*\(\s*{re.escape(var)}\s*,',
        re.IGNORECASE,
    )

    for search_var, alias_offset in search_vars.items():
        for i in range(alloc.pc + 1, min(len(ir_lines), alloc.pc + 50)):
            line = ir_lines[i]

            offset_info = _extract_store_offset(line, search_var)
            if offset_info is not None:
                offset, is_dyn, size, op_type = offset_info
                effective_offset = offset + alias_offset
                stores.append(HeapStore(
                    pc=i, base_var=var,
                    offset=effective_offset,
                    offset_is_dynamic=is_dyn,
                    store_size=size, mnemonic=op_type,
                ))
            elif search_var == var and store_fallback.search(line):
                stores.append(HeapStore(
                    pc=i, base_var=var,
                    offset=-1, offset_is_dynamic=True,
                    store_size=-1,
                ))
            elif _match_struct_field_store(line, search_var):
                off, sz, op = _extract_struct_field_store(line, search_var)
                effective_offset = off + alias_offset
                stores.append(HeapStore(
                    pc=i, base_var=var,
                    offset=effective_offset,
                    offset_is_dynamic=(off < 0),
                    store_size=sz, mnemonic=op,
                ))

    return stores


def _extract_store_offset(line: str, base_var: str) -> Optional[tuple[int, bool, int, str]]:
    """从 store 行提取偏移量和拷贝大小. 支持 [base+offset]/base[offset]/memcpy/strcpy.

    返回 (offset, is_dynamic, copy_or_store_size, op_type) 或 None.
    op_type: 'store' | 'strcpy' | 'strncpy' | 'memcpy' | 'memset'
    copy_or_store_size: 对于 copy 操作, 若可提取则为具体值或_UNBOUNDED_COPY, 否则 -1
    """
    # 模式1: [base + 0x10] 或 [base + 16]
    m = re.search(rf'\[{re.escape(base_var)}\s*\+\s*((?:0x)?[0-9a-fA-F]+)\]', line)
    if m:
        try:
            return (int(m.group(1), 0), False, _infer_store_size(line), 'store')
        except (ValueError, TypeError):
            return (-1, True, -1, 'store')
    # 模式1b: *(base + offset) = value (C风格指针偏移写)
    m = re.search(rf'\*\s*\(\s*{re.escape(base_var)}\s*\+\s*((?:0x)?[0-9a-fA-F]+)\s*\)', line)
    if m:
        try:
            return (int(m.group(1), 0), False, _infer_store_size(line), 'store')
        except (ValueError, TypeError):
            return (-1, True, -1, 'store')
    # 模式2: base[offset] = value (仅常量偏移)
    m = re.search(rf'{re.escape(base_var)}\[(\d+)\]', line)
    if m:
        return (int(m.group(1)), False, _infer_store_size(line), 'store')
    # 模式3: strcpy(base, src) — 无界拷贝
    m = re.search(rf'strcpy\s*\(\s*{re.escape(base_var)}\s*,', line)
    if m:
        return (0, False, _UNBOUNDED_COPY, 'strcpy')
    # 模式5: memcpy(base, src, size) — 提取第三参数 (支持表达式)
    m = re.search(rf'memcpy\s*\(\s*{re.escape(base_var)}\s*,\s*[^,]+,\s*([^)]+)\s*\)', line)
    if m:
        try:
            return (0, False, int(m.group(1).strip(), 0), 'memcpy')
        except (ValueError, TypeError):
            return (0, False, -1, 'memcpy')
    # 模式5b: memmove(base, src, size) — 同 memcpy (支持表达式)
    m = re.search(rf'memmove\s*\(\s*{re.escape(base_var)}\s*,\s*[^,]+,\s*([^)]+)\s*\)', line)
    if m:
        try:
            return (0, False, int(m.group(1).strip(), 0), 'memcpy')
        except (ValueError, TypeError):
            return (0, False, -1, 'memcpy')
    # 模式6: memset(base, val, size) — 提取第三参数 (支持表达式)
    m = re.search(rf'memset\s*\(\s*{re.escape(base_var)}\s*,\s*[^,]+,\s*([^)]+)\s*\)', line)
    if m:
        try:
            return (0, False, int(m.group(1).strip(), 0), 'memset')
        except (ValueError, TypeError):
            return (0, False, -1, 'memset')
    # 模式4: strncpy(base, src, n) — 提取 n (支持表达式)
    m = re.search(rf'strncpy\s*\(\s*{re.escape(base_var)}\s*,\s*[^,]+,\s*([^)]+)\s*\)', line)
    if m:
        try:
            return (0, False, int(m.group(1).strip(), 0), 'strncpy')
        except (ValueError, TypeError):
            return (0, False, -1, 'strncpy')
    # 模式7: strcat(base, src) — 累计缓冲区溢出
    m = re.search(rf'strcat\s*\(\s*{re.escape(base_var)}\s*,', line)
    if m:
        return (0, False, _UNBOUNDED_COPY, 'strcat')
    # 模式8: strncat(base, src, n) — 提取 n (支持表达式)
    m = re.search(rf'strncat\s*\(\s*{re.escape(base_var)}\s*,\s*[^,]+,\s*([^)]+)\s*\)', line)
    if m:
        try:
            return (0, False, int(m.group(1).strip(), 0), 'strncat')
        except (ValueError, TypeError):
            return (0, False, -1, 'strncat')
    # 回退: 模糊匹配任意 copy 族函数
    m = re.search(rf'(?:memcpy|strcpy|strncpy|memset|memmove|strcat|strncat)\s*\(\s*{re.escape(base_var)}\s*,', line)
    if m:
        return (0, False, -1, 'copy')
    # 带偏移的 memcpy/memmove: memcpy(base + offset, src, size)
    m = re.search(rf'(?:memcpy|memmove)\s*\(\s*{re.escape(base_var)}\s*\+\s*(\d+|\w+)\s*,\s*[^,]+,\s*([^)]+)\s*\)', line)
    if m:
        try:
            off = int(m.group(1), 0)
        except (ValueError, TypeError):
            off = -1
        try:
            sz = int(m.group(2).strip(), 0)
        except (ValueError, TypeError):
            sz = -1
        return (off, False, sz, 'memcpy')
    # 无第三参数的带偏移 memcpy/memmove
    m = re.search(rf'(?:memcpy|memmove)\s*\(\s*{re.escape(base_var)}\s*\+\s*(\d+|\w+)\s*,', line)
    if m:
        try:
            return (int(m.group(1), 0), False, -1, 'memcpy')
        except (ValueError, TypeError):
            return (-1, True, -1, 'memcpy')
    # scanf(fmt, base, ...) — 无界写入到 base
    m = re.search(rf'scanf\s*\(\s*"[^"]*"\s*,\s*{re.escape(base_var)}\s*[,\)]', line)
    if m:
        return (0, False, _UNBOUNDED_COPY, 'strcpy')
    # scanf_s / fscanf 同理
    m = re.search(rf'(?:scanf_s|fscanf)\s*\(\s*[^,]+,\s*{re.escape(base_var)}\s*[,\)]', line)
    if m:
        return (0, False, _UNBOUNDED_COPY, 'strcpy')
    return None


def _infer_store_size(line: str) -> int:
    """从 store 指令的操作数大小标记推断写入字节数."""
    lowered = line.lower()
    if any(s in lowered for s in ('qword', 'mov q', 'fstp', 'stosq', 'sqword')):
        return 8
    if any(s in lowered for s in ('dword', 'mov d', 'movsd', 'stosd')):
        return 4
    if any(s in lowered for s in ('word', 'mov w', 'stosw')):
        return 2
    if any(s in lowered for s in ('byte', 'mov b', 'stosb', 'movzx')):
        return 1
    return -1
