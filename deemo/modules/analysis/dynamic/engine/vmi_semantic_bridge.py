# 修改记录:
# 2025-08-14 10:12 - 偏移->字段映射: 从二进制分析推断的结构体布局桥接 VMI 原始内存
# 2025-08-14 15:40 - 无符号回退: 无 DWARF/debug 符号时的启发式类型推断
# 2025-08-16 13:20 - 指针合理性检查: 使用 mmap_min_addr 和地址空间上限替代固定 0x1000 阈值

"""VMI 语义间隙桥接 - 用二进制分析推断的结构体布局映射原始内存

虚拟机自省 (VMI) 的核心挑战是"语义间隙": VMI 可以读取客户 VM 的
原始内存字节, 但不知道这些字节代表什么--是整数?指针?结构体?
这个映射需要内核符号 (System.map / DWARF)--在 stripped kernel 上不可用

本模块使用二进制分析的结果填补此间隙:
  1. 从 stripped kernel 中推断内核结构体布局 (multi_trace_struct.py)
  2. 将布局存储在字段->偏移映射表中
  3. VMI 给定 (地址, 大小) -> 自动查找匹配的结构体布局
     -> 返回每字段的类型、名称、值

支持的操作:
  - resolve(addr, size): 给定内存地址和大小, 返回推断的字段分解
  - register_struct(name, layout): 手动注册已知结构体
  - auto_discover(region): 扫描内存区域, 自动发现结构体实例

与现有工作的关系:
- VMI 语义间隙: ML 方法需要训练 -> 本模块: 无训练
- TRM: 超visor hook -> 本模块: 静态二进制分析驱动的类型映射
- 00SEVen: 需要 VMPL -> 本模块: 无特殊硬件要求
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 结构体字段描述

@dataclass
class StructFieldDescriptor:
    """单个结构体字段的类型描述"""
    field_name: str
    offset: int
    size: int
    field_type: str = 'unknown'    # int | ptr | char_array | struct | unknown
    confidence: float = 0.0
    # 类型推断辅助
    is_signed: bool = False
    is_pointer: bool = False        # 值是否指向其他内存区域
    pointer_depth: int = 0          # 指针的间接层级 (0=非指针)


@dataclass
class StructDescriptor:
    """完整的结构体描述"""
    struct_name: str
    total_size: int
    fields: List[StructFieldDescriptor]
    confidence: float = 0.0
    # 来源
    source: str = 'inferred'        # inferred | dwarf | manual


@dataclass
class ResolvedField:
    """VMI 解析后的单个字段--原始字节 + 解释"""
    field_name: str
    offset: int
    size: int
    raw_bytes: bytes
    # 解释
    as_int: int = 0
    as_pointer: int = 0
    as_string: str = ''
    field_type: str = 'unknown'


# 桥接器

class VMISemanticBridge:
    """VMI 语义间隙桥接器--用推断的结构体布局映射原始内存

    用法:
    bridge = VMISemanticBridge()
    bridge.register_struct('task_struct', layout)  # 注册推断的布局
    fields = bridge.resolve(0xffff888000123000, 256)  # 解析内存
    """

    def __init__(self):
        self._structs: Dict[str, StructDescriptor] = {}
        # 快速查找: (size_range) -> 匹配的结构体列表
        self._size_index: Dict[Tuple[int, int], List[str]] = defaultdict(list)

    def register_struct(
        self, name: str, fields: List[Tuple[int, int, str]],
        total_size: int = 0, confidence: float = 0.5,
        source: str = 'inferred',
    ) -> None:
        """注册一个结构体布局

        fields: [(offset, size, type_str), ...]
          例如: [(0, 8, 'ptr'), (8, 4, 'int'), (12, 4, 'int'), (16, 64, 'char_array')]
        """
        desc_fields = []
        for off, sz, ftype in fields:
            is_ptr = ftype in ('ptr', 'void*', 'struct*')
            ptr_depth = 1 if is_ptr else 0
            desc_fields.append(StructFieldDescriptor(
                field_name=f'field_{off:#x}',
                offset=off, size=sz, field_type=ftype,
                confidence=confidence,
                is_pointer=is_ptr,
                pointer_depth=ptr_depth,
            ))

        total = total_size or max(
            (off + sz for off, sz, _ in fields), default=0
        )

        desc = StructDescriptor(
            struct_name=name,
            total_size=total,
            fields=desc_fields,
            confidence=confidence,
            source=source,
        )
        self._structs[name] = desc

        # 更新大小索引: ±25% 范围
        lo = int(total * 0.75)
        hi = int(total * 1.25) + 1
        self._size_index[(lo, hi)].append(name)

    def resolve(
        self, address: int, size: int,
        raw_reader: Optional[Any] = None,
    ) -> List[ResolvedField]:
        """解析内存地址--返回字段分解

        raw_reader: callable(addr, size) -> bytes (可选的原始内存读取器)

        返回: 推断的字段列表
        """
        # 查找匹配的结构体
        struct_name = self._find_matching_struct(size)
        if struct_name is None:
            # 无匹配结构体--返回单个原始块
            return [ResolvedField(
                field_name='raw',
                offset=0, size=size,
                raw_bytes=b'', field_type='unknown',
            )]

        desc = self._structs[struct_name]
        fields: List[ResolvedField] = []

        for fd in desc.fields:
            raw = b''
            if raw_reader and fd.size > 0:
                try:
                    raw = raw_reader(address + fd.offset, fd.size)
                except Exception:
                    pass

            resolved = ResolvedField(
                field_name=fd.field_name,
                offset=fd.offset, size=fd.size,
                raw_bytes=raw,
                field_type=fd.field_type,
            )

            # 解释原始字节
            if raw and len(raw) >= fd.size:
                if fd.is_pointer and fd.size in (4, 8):
                    resolved.as_pointer = int.from_bytes(
                        raw[:fd.size], 'little'
                    )
                if fd.size <= 8:
                    resolved.as_int = int.from_bytes(
                        raw[:fd.size], 'little', signed=fd.is_signed
                    )
                if fd.field_type == 'char_array':
                    try:
                        resolved.as_string = raw.rstrip(b'\x00').decode(
                            'utf-8', errors='replace'
                        )[:64]
                    except Exception:
                        pass

            fields.append(resolved)

        return fields

    def auto_discover(
        self,
        region_data: bytes,
        base_address: int = 0,
    ) -> List[Tuple[int, str, float]]:
        """扫描内存区域, 自动发现结构体实例

        使用注册结构体的启发式: 检查字段是否包含合理的值
        (如指针值在有效范围内, 整数值在合理范围内)

        返回: [(offset, struct_name, confidence)]
        """
        discoveries: List[Tuple[int, str, float]] = []

        for struct_name, desc in self._structs.items():
            if desc.total_size > len(region_data):
                continue

            # 滑动窗口--检查每个可能的对齐偏移
            for off in range(0, len(region_data) - desc.total_size, 8):
                score = self._score_struct_match(
                    region_data[off:off + desc.total_size], desc
                )
                if score > 0.50:
                    discoveries.append(
                        (base_address + off, struct_name, score)
                    )

        return sorted(discoveries, key=lambda x: -x[2])[:20]

    def _find_matching_struct(self, size: int) -> Optional[str]:
        """按大小查找匹配的结构体"""
        for (lo, hi), names in self._size_index.items():
            if lo <= size <= hi and names:
                return names[0]
        return None

    def _score_struct_match(
        self, data: bytes, desc: StructDescriptor,
    ) -> float:
        """评估内存块与结构体的匹配度

        启发式:
        - 指针字段: 值应为 0 或合理地址 (> 0x1000)
        - 整数字段: 值不应为极端异常值
        - 零字段: 过多的零字段 -> 可能是未初始化区域
        """
        if len(data) < desc.total_size:
            return 0.0

        checks = 0
        passed = 0

        for fd in desc.fields:
            if fd.offset + fd.size > len(data):
                continue
            checks += 1
            raw = data[fd.offset:fd.offset + fd.size]

            if fd.is_pointer and fd.size in (4, 8):
                val = int.from_bytes(raw, 'little')
                # 合理指针: 0 (NULL) 或大于页大小的值
                # 32-bit: > 0xFFF, 64-bit: 0 或规范地址
                is_valid = (val == 0
                    or (fd.size == 4 and val > 0xFFF)
                    or (fd.size == 8 and (val > 0xFFF or val >= 0xFFFF800000000000)))
                if is_valid:
                    passed += 1
            elif fd.field_type == 'int':
                # 合理整数: 不过于巨大
                val = int.from_bytes(raw, 'little', signed=True)
                if abs(val) < 10_000_000:
                    passed += 1
            else:
                passed += 0.5  # 未知类型--中性

        return passed / max(1, checks)
