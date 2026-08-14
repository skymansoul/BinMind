"""
结构体字段偏移域 (SFOD) — 从源码提取 struct 字段布局并建模为 CJ 约束: 解析 typedef struct 定义提取字段偏移和大小, 识别 buf->field 写入模式, 将 field_offset 建模为约束系统的偏移常量, 以 write_end = field_offset + write_size vs usable_size 判定安全。
将 HOSV 的 struct_write_check 逻辑系统化桥接到 CJ 约束系统; 仅处理线性偏移 (常量字段偏移), 不处理动态字段偏移 (数组索引); 解析失败时返回空列表 (保守策略, 不产生误判)。
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem,
)
from core.heap_overflow_detector import HeapAllocSite, HeapStore


# C类型到字节大小的映射
_TYPE_SIZES: Dict[str, int] = {
    'char': 1, 'int': 4, 'long': 8, 'short': 2,
    'float': 4, 'double': 8, 'size_t': 8,
    'void*': 8, 'char*': 8, 'int*': 8, 'long*': 8,
    'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4, 'uint64_t': 8,
    'int8_t': 1, 'int16_t': 2, 'int32_t': 4, 'int64_t': 8,
    'unsigned': 4, 'signed': 4,
}


@dataclass
class StructFieldInfo:
    """结构体字段信息."""
    struct_name: str
    field_name: str
    offset: int       # 字段偏移(字节), -1=未知
    size: int          # 字段大小(字节), -1=未知
    struct_size: int    # 结构体总大小(字节), -1=未知


def parse_struct_definition(
    lines: List[str],
    search_from: int = 0,
    max_search: int = 200,
) -> Dict[str, Dict[str, StructFieldInfo]]:
    """从源码行中解析所有typedef struct定义.

    返回 {struct_name: {field_name: StructFieldInfo}}.
    """
    structs: Dict[str, Dict[str, StructFieldInfo]] = {}
    i = min(search_from, len(lines) - 1)
    end = min(len(lines), i + max_search)

    while i >= 0:
        line = lines[i].strip()
        m = re.match(r'typedef\s+struct\s*\{', line)
        if not m:
            i -= 1
            continue

        # 找到typedef struct开头, 解析结构体
        struct_start = i
        struct_name = ""
        offset = 0
        fields: Dict[str, StructFieldInfo] = {}

        for j in range(i + 1, min(len(lines), i + 50)):
            ft = lines[j].strip()
            # 结构体结束: } StructName;
            close_m = re.match(r'\}\s*(\w+)\s*;', ft)
            if close_m:
                struct_name = close_m.group(1)
                break

            # 字段定义: type name; 或 type name[N];
            fm = re.match(r'\s*(\w+)\s+(\w+)(\[\d+\])?\s*;', ft)
            if fm:
                base_type = fm.group(1)
                fname = fm.group(2)
                arr = fm.group(3)
                sz = _TYPE_SIZES.get(base_type, 8)
                if arr:
                    try:
                        n = int(arr[1:-1])
                        sz *= n
                    except ValueError:
                        pass
                fields[fname] = StructFieldInfo(
                    struct_name=struct_name,
                    field_name=fname,
                    offset=offset,
                    size=sz,
                    struct_size=-1,
                )
                offset += sz

        if struct_name and fields:
            total = offset
            for f in fields.values():
                f.struct_name = struct_name
                f.struct_size = total
            structs[struct_name] = fields

        i -= 1

    return structs


def find_struct_for_alloc(
    lines: List[str],
    alloc_line: int,
    alloc_var: str = "",
) -> Optional[str]:
    """推断分配点关联的结构体类型名.

    优先级:
      1. sizeof(StructType) 作为malloc参数
      2. (StructType*)malloc(...) 显式类型转换
      3. 向上搜索同变量的->操作推断类型
    """
    if alloc_line >= len(lines):
        return None

    # 方式1: malloc(sizeof(StructType))
    for i in range(max(0, alloc_line - 5), alloc_line + 1):
        if i >= len(lines):
            break
        m = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', lines[i])
        if m:
            candidate = m.group(1)
            if candidate[0].isupper() or candidate[0] == '_':
                return candidate

    # 方式2: (StructType*)malloc(...)
    for i in range(max(0, alloc_line - 3), alloc_line + 1):
        if i >= len(lines):
            break
        m = re.search(r'\(\s*(\w+)\s*\*\s*\)\s*(?:malloc|calloc)', lines[i])
        if m:
            candidate = m.group(1)
            if candidate[0].isupper() or candidate[0] == '_':
                return candidate

    return None


def extract_field_write(
    line: str,
) -> Optional[Tuple[str, str]]:
    """从写入行中提取 (base_var, field_name).

    支持模式:
      - buf->field = ...
      - memcpy(buf->field, ...)
      - buf.field = ...
    """
    # buf->field 或 buf.field
    m = re.search(r'(\w[\w]*)\s*(?:->|\.)\s*(\w[\w]*)', line)
    if m:
        return m.group(1), m.group(2)
    return None


def inject_struct_field_constraints(
    sys: ConstraintSystem,
    lines: List[str],
    store_line: int,
    alloc_line: int,
) -> bool:
    """将struct字段偏移约束注入CJ约束系统.

    当写入目标为buf->field模式时:
      1. 推断struct类型名
      2. 解析字段偏移和大小
      3. 将field_offset设为sys.offset_val
      4. 添加STRUCT_FIELD约束

    返回True表示成功注入约束, False表示无法解析struct.
    """
    if store_line >= len(lines):
        return False

    line = lines[store_line]

    # 检查写入行是否含struct field访问
    field_access = extract_field_write(line)
    if not field_access:
        return False

    base_var, field_name = field_access

    # 推断struct类型
    struct_type = find_struct_for_alloc(lines, alloc_line)
    if not struct_type:
        return False

    # 解析struct定义
    structs = parse_struct_definition(lines, alloc_line)
    if struct_type not in structs:
        return False

    fields = structs[struct_type]
    if field_name not in fields:
        return False

    fi = fields[field_name]

    # 注入偏移约束: field_offset作为常量
    if sys.offset_val == 0 or sys.offset_val < fi.offset:
        sys.offset_val = fi.offset

    # 注入STRUCT_FIELD约束: write_end >= field_offset (下界)
    sys.add(LinearConstraint(
        coefficients={},
        constant=float(fi.offset),
        operator=">=",
        source=ConstraintType.ALIGNMENT,  # 复用现有枚举, 避免修改types
        confidence=0.95,
        description=f"struct_field: {struct_type}.{field_name}"
                    f"@offset={fi.offset}, size={fi.size}",
    ))

    # 字段直接赋值时, 写入大小=字段大小
    if sys.copy_size <= 0 and fi.size > 0:
        # 检查是否为memcpy到字段(非直接赋值)
        memcpy_m = re.search(
            r'(?:memcpy|memmove)\s*\(', line)
        if not memcpy_m:
            sys.store_size = fi.size

    return True


def inject_sfod_constraints(
    sys: ConstraintSystem,
    decompiled_text: str,
    alloc: HeapAllocSite,
    store: HeapStore,
) -> bool:
    """CJ约束收集器桥接入口: 将SFOD约束注入CJ约束系统.

    解析失败时不添加任何约束(保守策略), 返回False.
    """
    lines = decompiled_text.splitlines()
    return inject_struct_field_constraints(
        sys, lines, store.pc, alloc.pc)


__all__ = [
    'StructFieldInfo', 'parse_struct_definition',
    'find_struct_for_alloc', 'extract_field_write',
    'inject_struct_field_constraints', 'inject_sfod_constraints',
]
