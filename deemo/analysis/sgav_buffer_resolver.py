"""
SGAV 缓冲区解析器 — 别名闭包 + struct field + VLA/alloca 识别.
resolve 是 phase-1: 从源码提取所有栈缓冲区并构建别名关系.
"""
from __future__ import annotations
import re
from typing import List, Dict, Set, Tuple
from analysis.sgav_types import BufferDesc

# 缓冲区声明正则
_BUF_FIXED = re.compile(
    r'(?:char|unsigned\s+char|signed\s+char|int|unsigned\s+int|short|long|'
    r'float|double|wchar_t|uint8_t|int8_t|uint16_t|int16_t|uint32_t|int32_t|'
    r'uint64_t|int64_t|size_t|ssize_t)\s+(\w+)\s*\[\s*(\d+)\s*\]')
_BUF_VLA = re.compile(
    r'(?:char|int|unsigned\s+int|short|long|float|double|size_t)\s+(\w+)\s*\[\s*(\w[\w]*)\s*\]')
_ALLOCA = re.compile(
    r'(?:\w[\w]*\s*\*?\s+)?(\w+)\s*=\s*(?:\(\s*\w[\w]*\s*\*?\s*\)\s*)?alloca\s*\(\s*([^)]+)\s*\]\)')
_ALLOCA2 = re.compile(
    r'(?:\w[\w]*\s*\*?\s+)?(\w+)\s*=\s*(?:\(\s*\w[\w]*\s*\*?\s*\)\s*)?alloca\s*\(\s*([^)]+)\)')
# struct 成员 buf
_STRUCT_FIELD_BUF = re.compile(
    r'(?:struct\s+)?(\w+)\s+(\w+)\s*;\s*//.*?buf.*?(\d+)', re.I)
# 别名赋值: p = buf; q = p; 等
_ALIAS_ASSIGN = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;')
# 指针算术: p = buf + offset
_PTR_ARITH = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*([+-])\s*(\d+)\s*;')
# sizeof(T)
_SIZEOF = re.compile(r'sizeof\s*\(\s*(\w[\w]*)\s*\)')
# 类型到元素大小映射
_TYPE_SIZES = {
    'char': 1, 'unsigned char': 1, 'signed char': 1,
    'int8_t': 1, 'uint8_t': 1,
    'short': 2, 'int16_t': 2, 'uint16_t': 2,
    'int': 4, 'unsigned int': 4, 'unsigned': 4,
    'int32_t': 4, 'uint32_t': 4, 'size_t': 8, 'ssize_t': 8,
    'long': 8, 'int64_t': 8, 'uint64_t': 8,
    'float': 4, 'double': 8, 'wchar_t': 4,
}
_ELEM_TYPE = re.compile(
    r'(char|unsigned\s+char|signed\s+char|int8_t|uint8_t|'
    r'short|int16_t|uint16_t|int|unsigned\s+int|unsigned|'
    r'int32_t|uint32_t|size_t|ssize_t|long|int64_t|uint64_t|'
    r'float|double|wchar_t)\s+\w+\s*\[')


def _elem_size_from_line(line: str) -> int:
    m = _ELEM_TYPE.search(line)
    if m and m.group(1) in _TYPE_SIZES:
        return _TYPE_SIZES[m.group(1)]
    return 1


class BufferResolver:
    """缓冲区识别 + 别名闭包构建."""

    def resolve(self, lines: List[str]) -> List[BufferDesc]:
        bufs = self._find_buffers(lines)
        self._build_alias_closure(lines, bufs)
        return bufs

    def _find_buffers(self, lines: List[str]) -> List[BufferDesc]:
        bufs: List[BufferDesc] = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*', '*')): continue
            found = False
            # VLA: char buf[n] where n is variable
            vm = _BUF_VLA.search(text)
            if vm and not vm.group(2).isdigit():
                bufs.append(BufferDesc(
                    name=vm.group(1), size=-1, kind='vla',
                    line=i, base_buf=vm.group(1),
                    elem_size=_elem_size_from_line(text)))
                found = True
            # fixed: char buf[64]
            if not found:
                for m in _BUF_FIXED.finditer(text):
                    bufs.append(BufferDesc(
                        name=m.group(1), size=int(m.group(2)), kind='fixed',
                        line=i, base_buf=m.group(1),
                        elem_size=_elem_size_from_line(text)))
            # alloca
            for m in _ALLOCA2.finditer(text):
                bufs.append(BufferDesc(
                    name=m.group(1), size=-2, kind='alloca',
                    line=i, base_buf=m.group(1), elem_size=1))
        return bufs

    def _build_alias_closure(self, lines: List[str],
                             bufs: List[BufferDesc]) -> None:
        buf_names = {b.name: b for b in bufs}
        # 追踪别名: p = buf -> p 是 buf 的别名
        alias_map: Dict[str, str] = {}  # alias -> root buf
        ptr_offsets: Dict[str, Tuple[str, int]] = {}  # alias -> (root, offset)
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            # p = buf
            for m in _ALIAS_ASSIGN.finditer(text):
                lhs, rhs = m.group(1), m.group(2)
                if rhs in buf_names:
                    alias_map[lhs] = rhs
                    buf_names[rhs].aliases.add(lhs)
                elif rhs in alias_map:
                    root = alias_map[rhs]
                    alias_map[lhs] = root
                    buf_names[root].aliases.add(lhs)
            # p = buf + offset
            for m in _PTR_ARITH.finditer(text):
                lhs, rhs, op, off = (
                    m.group(1), m.group(2), m.group(3), int(m.group(4)))
                root = rhs if rhs in buf_names else alias_map.get(rhs)
                if root and root in buf_names:
                    actual_off = off if op == '+' else -off
                    ptr_offsets[lhs] = (root, actual_off)
                    buf_names[root].aliases.add(lhs)
        # 把别名写回 BufferDesc
        for b in bufs:
            b.aliases.add(b.name)


__all__ = ['BufferResolver']
