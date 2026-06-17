"""
智能内存分析: 对象指针图重建模块

功能:
    1. 在 Core Dump 取证或内存快照分析中, 扫描内存找出潜在对象引用
    2. 重建 C++ 对象关系和虚表指向
    3. 辅助发现 UAF 或类型混淆证据
    4. 输出对象交互图

核心技术:
    - 启发式指针扫描 (基于对齐 + 可寻址范围)
    - 虚表签名匹配 (连续函数指针 + 虚表继承)
    - 引用图构建
    - 风险评分: 悬空指针 / 类型不匹配
"""

import logging
import os
import json
import struct
import re
from typing import Dict, Any, List, Optional, Set, Tuple, BinaryIO
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ObjectKind(Enum):
    """对象类型"""
    UNKNOWN = "unknown"
    CP_OBJECT = "c++_object"
    CP_VTABLE = "c++_vtable"
    CP_STRING = "c++_string"
    HEAP_CHUNK = "heap_chunk"
    STACK_FRAME = "stack_frame"
    THREAD_LOCAL = "thread_local"
    KERNEL_OBJECT = "kernel_object"


@dataclass
class CandidateObject:
    """候选对象"""
    address: int
    size: int
    kind: ObjectKind
    vtable_ptr: Optional[int] = None
    inferred_type: str = ""
    refs: List[int] = field(default_factory=list)
    is_dangling: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectReference:
    """对象间引用"""
    src: int
    dst: int
    field: str = ""
    kind: str = "ptr"     # ptr / vtable / member


@dataclass
class ObjectPointerGraph:
    """对象指针图"""
    objects: Dict[int, CandidateObject] = field(default_factory=dict)
    references: List[ObjectReference] = field(default_factory=list)
    dangling: List[int] = field(default_factory=list)
    type_confusions: List[Tuple[int, int, str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'object_count': len(self.objects),
            'reference_count': len(self.references),
            'dangling_count': len(self.dangling),
            'type_confusion_count': len(self.type_confusions),
            'objects': [
                {
                    'address': hex(o.address),
                    'size': o.size,
                    'kind': o.kind.value,
                    'vtable_ptr': hex(o.vtable_ptr) if o.vtable_ptr else None,
                    'inferred_type': o.inferred_type,
                    'is_dangling': o.is_dangling,
                    'ref_count': len(o.refs)
                }
                for o in self.objects.values()
            ],
            'dangling': [hex(d) for d in self.dangling],
            'type_confusions': [
                {
                    'src': hex(a),
                    'dst': hex(b),
                    'src_type': ta,
                    'dst_type': tb
                }
                for a, b, ta, tb in self.type_confusions
            ]
        }


class PointerScanHeuristics:
    """指针扫描启发式"""

    # x86_64 典型用户态地址范围
    DEFAULT_RANGES = [
        (0x0000000000400000, 0x00007FFFFFFFFFFF),  # 用户二进制 + 库
        (0x00007F0000000000, 0x00007FFFFFFFFFFF),  # 共享库
        (0x0000550000000000, 0x00005FFFFFFFFFFF),  # PIE
    ]

    @classmethod
    def looks_like_pointer(cls, value: int,
                           addr_ranges: Optional[List[Tuple[int, int]]] = None
                           ) -> bool:
        if value == 0:
            return False
        ranges = addr_ranges or cls.DEFAULT_RANGES
        for lo, hi in ranges:
            if lo <= value < hi:
                return True
        return False

    @classmethod
    def looks_like_vtable(cls, ptrs: List[int],
                          addr_ranges: Optional[List[Tuple[int, int]]] = None
                          ) -> bool:
        if len(ptrs) < 3:
            return False
        valid = sum(1 for p in ptrs if cls.looks_like_pointer(p, addr_ranges))
        return valid >= max(3, len(ptrs) * 0.7)


class ObjectPointerReconstructor:
    """
    对象指针图重建器
    """

    def __init__(self, *, ptr_size: int = 8, little_endian: bool = True,
                 addr_ranges: Optional[List[Tuple[int, int]]] = None,
                 vtable_min_entries: int = 3):
        self.ptr_size = ptr_size
        self.little_endian = little_endian
        self.addr_ranges = addr_ranges
        self.vtable_min_entries = vtable_min_entries
        self.endian = "<" if little_endian else ">"
        self.fmt = self.endian + ("Q" if ptr_size == 8 else "I")

    def _read_ptr(self, data: bytes, offset: int) -> int:
        if offset + self.ptr_size > len(data):
            return 0
        return struct.unpack(self.fmt, data[offset:offset + self.ptr_size])[0]

    def scan_memory(self, data: bytes, base_addr: int = 0x400000) -> ObjectPointerGraph:
        graph = ObjectPointerGraph(metadata={'base': hex(base_addr),
                                            'size': len(data)})
        # 第一遍: 找 vtable (连续可执行函数指针)
        vtables: List[Tuple[int, List[int]]] = []
        step = self.ptr_size
        for off in range(0, len(data) - step * self.vtable_min_entries, step * 4):
            ptrs = [self._read_ptr(data, off + i * step)
                    for i in range(self.vtable_min_entries)]
            if PointerScanHeuristics.looks_like_vtable(ptrs, self.addr_ranges):
                # 进一步扩展扫描 vtable 长度
                length = self.vtable_min_entries
                while True:
                    nxt_off = off + (length + 1) * step
                    if nxt_off + step > len(data):
                        break
                    nxt = self._read_ptr(data, nxt_off)
                    if not PointerScanHeuristics.looks_like_pointer(nxt, self.addr_ranges):
                        break
                    length += 1
                vtables.append((base_addr + off, ptrs + [
                    self._read_ptr(data, off + i * step)
                    for i in range(self.vtable_min_entries, length)
                ]))

        # 第二遍: 找对象 (首字段为 vtable 指针的连续区域)
        vtable_set: Set[int] = {v[0] for v in vtables}
        # 缓存 vtable 首地址 -> (vtable_addr, length)
        vtable_info: Dict[int, Tuple[int, int]] = {
            v[0]: (v[0], len(v[1])) for v in vtables
        }
        for off in range(0, len(data) - step, step * 8):
            first_ptr = self._read_ptr(data, off)
            if first_ptr in vtable_set:
                # 尝试扫描对象大小
                size_guess = self._estimate_object_size(data, off, step)
                if size_guess <= 0 or size_guess > 4096:
                    size_guess = 64
                obj = CandidateObject(
                    address=base_addr + off,
                    size=size_guess,
                    kind=ObjectKind.CP_OBJECT,
                    vtable_ptr=first_ptr,
                    inferred_type=f"VT@{hex(first_ptr)}"
                )
                graph.objects[obj.address] = obj

        # 第三遍: 找对象间引用 (从对象起始扫描成员指针)
        for obj in list(graph.objects.values()):
            start = obj.address - base_addr
            for i in range(0, obj.size, step):
                ptr = self._read_ptr(data, start + i)
                if ptr in graph.objects:
                    obj.refs.append(ptr)
                    graph.references.append(ObjectReference(
                        src=obj.address, dst=ptr,
                        field=f"offset_{i}", kind="ptr"
                    ))
                elif PointerScanHeuristics.looks_like_pointer(ptr, self.addr_ranges):
                    # 可能是悬空指针
                    if not (base_addr <= ptr < base_addr + len(data)):
                        # 指向内存范围外 -> 可能是悬空
                        obj.refs.append(ptr)
                        graph.references.append(ObjectReference(
                            src=obj.address, dst=ptr,
                            field=f"offset_{i}", kind="ptr"
                        ))

        # 第四遍: 检测悬空
        live_set = set(graph.objects.keys())
        for obj in list(graph.objects.values()):
            for ref in obj.refs:
                if ref not in live_set and not (base_addr <= ref < base_addr + len(data)):
                    if not obj.is_dangling:
                        obj.is_dangling = True
                        graph.dangling.append(obj.address)

        # 第五遍: 检测类型混淆 (同一 vtable 用于不同 vtable_info 的对象)
        vt_to_objs: Dict[int, List[int]] = defaultdict(list)
        for obj in graph.objects.values():
            if obj.vtable_ptr:
                vt_to_objs[obj.vtable_ptr].append(obj.address)
        # 这里简单检测: 同一对象引用了多个不同 vtable 的对象
        for obj in list(graph.objects.values()):
            referenced_vts: Set[int] = set()
            for ref in obj.refs:
                if ref in graph.objects and graph.objects[ref].vtable_ptr:
                    referenced_vts.add(graph.objects[ref].vtable_ptr)
            if len(referenced_vts) > 1:
                types = [graph.objects[ref].inferred_type
                         for ref in obj.refs if ref in graph.objects]
                graph.type_confusions.append((
                    obj.address,
                    obj.refs[0] if obj.refs else 0,
                    obj.inferred_type,
                    " | ".join(set(types))
                ))

        return graph

    def _estimate_object_size(self, data: bytes, start: int, step: int) -> int:
        """基于成员指针密度估算对象大小"""
        # 简单策略: 扫描到连续 64 字节没有有效指针就停止
        size = step
        while size < 1024:
            ptr = self._read_ptr(data, start + size)
            if not PointerScanHeuristics.looks_like_pointer(ptr, self.addr_ranges):
                # 检查下一个 slot
                if start + size + step >= len(data):
                    break
                ptr2 = self._read_ptr(data, start + size + step)
                if not PointerScanHeuristics.looks_like_pointer(ptr2, self.addr_ranges):
                    break
            size += step
        return size

    def load_dump(self, path: str) -> Tuple[bytes, int]:
        """加载内存快照文件 (裸二进制)"""
        with open(path, 'rb') as f:
            data = f.read()
        return data, 0


def reconstruct_from_dump(dump_path: str,
                          base_addr: int = 0x400000) -> Dict[str, Any]:
    """便捷入口"""
    re = ObjectPointerReconstructor()
    data, _ = re.load_dump(dump_path)
    graph = re.scan_memory(data, base_addr=base_addr)
    return {
        'success': True,
        'graph': graph.to_dict()
    }


def find_uaf_evidence(graph: ObjectPointerGraph) -> List[Dict[str, Any]]:
    """根据对象指针图找出可能的 UAF 证据"""
    evidence = []
    for addr in graph.dangling:
        obj = graph.objects.get(addr)
        if obj is None:
            continue
        evidence.append({
            'type': 'dangling_pointer',
            'object': hex(addr),
            'inferred_type': obj.inferred_type,
            'reason': '对象存在悬空引用, 指向已释放内存'
        })
    for src, dst, ta, tb in graph.type_confusions:
        evidence.append({
            'type': 'type_confusion',
            'src': hex(src),
            'dst': hex(dst),
            'src_type': ta,
            'dst_type': tb,
            'reason': '对象引用了不同 vtable 的目标, 可能是类型混淆'
        })
    return evidence
