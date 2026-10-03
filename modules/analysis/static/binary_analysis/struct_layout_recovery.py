from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict, Counter
from typing import Optional


@dataclass
class MemoryAccess:
    """一次内存访问 - 指令 + 偏移 + 大小。"""
    pc: int
    base_reg: str = ''        # 基址寄存器 (rbp/rdi/rsi)
    offset: int = 0           # 相对基址的偏移 (字节)
    access_size: int = 4      # 1/2/4/8 字节
    is_write: bool = False
    mnemonic: str = ''        # 指令助记符


@dataclass
class StructField:
    """推断出的结构体字段。"""
    field_name: str = ''      # 推断的名称 (如 field_00)
    offset: int = 0
    size: int = 4
    inferred_type: str = ''   # 'int' | 'short' | 'char' | 'long' | 'pointer' | 'array' | 'struct'
    array_element_count: int = 1
    confidence: float = 0.0


@dataclass
class StructLayout:
    """恢复出的结构体完整布局。"""
    struct_name: str = ''
    total_size: int = 0
    alignment: int = 8
    fields: list[StructField] = field(default_factory=list)
    confidence: float = 0.0
    source_code: str = ''     # 生成的 C struct 定义


# 访问模式收集

def collect_struct_accesses(instructions: list[dict],
                            base_reg: str = 'rdi',
                            base_reg_alt: str = '') -> list[MemoryAccess]:
    """从指令序列中收集对结构体的内存访问。"""
    import re
    accesses = []
    for ins in instructions:
        mnemonic = ins.get('mnemonic', '').lower()
        ops = str(ins.get('operands', ''))
        addr = ins.get('address', 0)

        regs_to_check = [base_reg]
        if base_reg_alt:
            regs_to_check.append(base_reg_alt)

        for reg in regs_to_check:
            # 匹配 [reg + offset] 模式
            pattern = rf'{reg}\s*[\+\-]\s*(0x[0-9a-fA-F]+|\d+)'
            match = re.search(pattern, ops, re.IGNORECASE)
            if not match:
                pattern2 = rf'\[{reg}\]'
                match2 = re.search(pattern2, ops, re.IGNORECASE)
                offset = 0
                if not match2:
                    continue
            else:
                offset_str = match.group(1)
                offset = int(offset_str, 16) if offset_str.startswith('0x') else int(offset_str)
                if '-' in ops[ops.find(reg) + len(reg):ops.find(reg) + len(reg) + 8]:
                    offset = -offset

            # 推断访问大小
            size = _infer_access_size(mnemonic, ops)

            accesses.append(MemoryAccess(
                pc=addr, base_reg=reg, offset=offset,
                access_size=size, is_write=('mov' in mnemonic and
                ops.strip().startswith('[') or 'str' in mnemonic),
                mnemonic=mnemonic,
            ))
            break  # 一个寄存器匹配即可

    return accesses


def _infer_access_size(mnemonic: str, operands: str) -> int:
    m = mnemonic.lower()
    if 'qword' in operands.lower() or m in ('movsd', 'movq', 'ldr x'):
        return 8
    if 'dword' in operands.lower() or m in ('movss', 'ldr w'):
        return 4
    if 'word' in operands.lower() or 'movzx' in m:
        return 2
    if 'byte' in operands.lower() or 'movzbl' in m:
        return 1
    if 'rax' in operands.lower() or 'x0' in operands.lower():
        return 8
    if 'eax' in operands.lower():
        return 4
    return 4  # 默认


# 边界推断

def infer_field_boundaries(accesses: list[MemoryAccess],
                           alignment: int = 8) -> list[StructField]:
    """从内存访问序列推断结构体字段边界。"""
    if not accesses:
        return []

    # 按偏移分组——统计每个偏移处的访问模式
    by_offset: dict[int, list[MemoryAccess]] = defaultdict(list)
    for a in accesses:
        by_offset[a.offset].append(a)

    offsets = sorted(by_offset.keys())
    fields: list[StructField] = []
    field_start = 0
    prev_size = 4

    for i, off in enumerate(offsets):
        accs = by_offset[off]
        # 此偏移处的主导访问大小
        size_counts = Counter(a.access_size for a in accs)
        dominant_size = size_counts.most_common(1)[0][0]

        # 检测字段边界: 访问大小切换 或 存在间隙
        gap = off - (field_start + prev_size)
        size_switch = (dominant_size != prev_size and
                      (off - field_start) >= prev_size)

        if gap >= alignment or size_switch or i == 0:
            if i > 0:
                # 关闭前一个字段
                prev_offsets = [o for o in offsets if field_start <= o < off]
                if prev_offsets:
                    field = _make_field(
                        field_start, max(prev_offsets) - field_start + prev_size,
                        by_offset, alignment)
                    fields.append(field)
            field_start = off
            prev_size = dominant_size

    # 最后一个字段
    if field_start <= offsets[-1]:
        last_size = Counter(
            a.access_size for a in by_offset[offsets[-1]]).most_common(1)[0][0]
        field = _make_field(
            field_start, offsets[-1] - field_start + last_size,
            by_offset, alignment)
        fields.append(field)

    # 对齐填充
    total = fields[-1].offset + fields[-1].size if fields else 0
    if total % alignment:
        pad = alignment - (total % alignment)
        total += pad

    return fields


def _make_field(offset: int, raw_size: int,
                by_offset: dict, alignment: int) -> StructField:
    """从偏移范围的访问模式推断字段类型。"""
    size = min(raw_size, 8)
    # 对齐到 1/2/4/8
    if size >= 8:
        size = 8
    elif size >= 4:
        size = 4
    elif size >= 2:
        size = 2
    else:
        size = 1

    type_map = {8: 'long', 4: 'int', 2: 'short', 1: 'char'}
    inferred = type_map.get(size, 'int')

    # 检查是否为指针 (任何 4/8 字节加载后跟 [reg] 使用)
    related = by_offset.get(offset, [])
    if related and size in (4, 8):
        for a in related:
            if '[' in a.mnemonic or a.mnemonic in ('call', 'jmp', 'br'):
                inferred = 'pointer'
                break

    conf = min(1.0, len(related) / 3.0) if related else 0.3

    return StructField(
        field_name=f'field_{offset:02x}',
        offset=offset, size=size,
        inferred_type=inferred, confidence=round(conf, 2),
    )


# C 代码生成

def generate_struct_source(layout: StructLayout) -> str:
    """从布局生成 C struct 定义。"""
    lines = [f'typedef struct {"{"}']
    for f in layout.fields:
        type_str = f.inferred_type
        if f.array_element_count > 1:
            type_str += f'[{f.array_element_count}]'
        lines.append(f'    {type_str} {f.field_name};  // offset=0x{f.offset:x}, size={f.size}')
    lines.append(f'}} {layout.struct_name};  // total_size={layout.total_size}, align={layout.alignment}')
    return '\n'.join(lines)


class StructLayoutRecoverer:
    """结构体布局恢复器 - 访问模式→字段边界→C struct。"""

    def recover(self, instructions: list[dict],
                base_reg: str = 'rdi',
                struct_name: str = 'RecoveredStruct') -> StructLayout:
        accesses = collect_struct_accesses(instructions, base_reg)
        fields = infer_field_boundaries(accesses)

        total = fields[-1].offset + fields[-1].size if fields else 0
        align = max((f.size for f in fields), default=8)
        total = ((total + align - 1) // align) * align  # 对齐

        layout = StructLayout(
            struct_name=struct_name, total_size=total,
            alignment=align, fields=fields,
            confidence=(sum(f.confidence for f in fields) /
                       max(1, len(fields))),
        )
        layout.source_code = generate_struct_source(layout)
        return layout

    def stats(self) -> dict:
        return {}


__all__ = [
    'StructLayoutRecoverer', 'StructLayout', 'StructField',
    'MemoryAccess', 'collect_struct_accesses', 'infer_field_boundaries',
    'generate_struct_source',
]
