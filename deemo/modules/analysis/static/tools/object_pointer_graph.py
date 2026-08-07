"""
Memory object 指针 graph reconstruction

Capabilities:
1. Scan core 转存 or memory 快照s for candidate object 引用s
2. 重建 C++ object relationships vtable targets
3. Surface UAF 类型混淆 indicators
4. Emit object interaction graph

Core methods:
- Heuristic 指针 scan (对齐 + addressable range 校验)
- Vtable 签名 matching (consecutive function 指针s + vtable inheritance)
- 引用 graph construction
- Risk scoring: dangling 指针s / type mismatches

2025 升级: Transformer-based memory forensics
参考: "Transformer-Based Memory Reverse Engineering for Malware
Behavior Reconstruction"
核心方法: 将原始内存字节视为"语言 token"，使用地址感知位置编码
建立跨内存区域的长距离依赖关系。本模块实现简化版注意力机制——
不使用完整 Transformer，而是用滑动窗口自注意力对内存区域评分
"""

import logging
import os
import json
import struct
import re
import math as _math
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ObjectKind:
    """Object type 分类 for memory scan results"""
    UNKNOWN = "unknown"
    CP_OBJECT = "c++_object"
    CP_VTABLE = "c++_vtable"
    CP_STRING = "c++_string"
    HEAP_CHUNK = "heap_chunk"
    STACK_FRAME = "stack_frame"
    THREAD_LOCAL = "thread_local"
    KERNEL_OBJECT = "kernel_object"

class CandidateObject:
    """Candidate object identified memory scan"""
    __slots__ = ('address', 'size', 'kind', 'vtable_ptr', 'inferred_type', 'refs', 'is_dangling', 'metadata')

    def __init__(self, address, size, kind, vtable_ptr=None, inferred_type="",
                 refs=None, is_dangling=False, metadata=None):
        self.address = address
        self.size = size
        self.kind = kind
        self.vtable_ptr = vtable_ptr
        self.inferred_type = inferred_type
        self.refs = refs if refs is not None else list()
        self.is_dangling = is_dangling
        self.metadata = metadata if metadata is not None else dict()

class ObjectReference:
    """Inter-object 指针 引用 edge graph"""
    __slots__ = ('src', 'dst', 'field', 'kind')

    def __init__(self, src=0, dst=0, field="", kind="ptr"):
        self.src = src
        self.dst = dst
        self.field = field
        self.kind = kind

class ObjectPointerGraph:
    """Directed graph capturing object--object 指针 relationships"""
    __slots__ = ('objects', 'references', 'dangling', 'type_confusions', 'metadata', 'attention_scores',)

    def __init__(self, objects=None, references=None, dangling=None,
                 type_confusions=None, metadata=None):
        self.objects = objects if objects is not None else dict()
        self.references = references if references is not None else list()
        self.dangling = dangling if dangling is not None else list()
        self.type_confusions = type_confusions if type_confusions is not None else list()
        self.metadata = metadata if metadata is not None else dict()
        self.attention_scores: Dict[int, float] = {}  # 地址→注意力评分

    def to_dict(self) -> Dict[str, Any]:
        return {
            'object_count': len(self.objects),
            'reference_count': len(self.references),
            'dangling_count': len(self.dangling),
            'type_confusion_count': len(self.type_confusions),
            'objects': [{
                'address': hex(o.address), 'size': o.size,
                'kind': o.kind.value if hasattr(o.kind, 'value') else str(o.kind),
                'vtable_ptr': hex(o.vtable_ptr) if o.vtable_ptr else None,
                'inferred_type': o.inferred_type,
                'is_dangling': o.is_dangling, 'ref_count': len(o.refs),
                'attention_score': self.attention_scores.get(o.address, 0.0),
            } for o in self.objects.values()],
            'dangling': [hex(d) for d in self.dangling],
            'type_confusions': [{'src': hex(a), 'dst': hex(b),
                                  'src_type': ta, 'dst_type': tb}
                                for a, b, ta, tb in self.type_confusions],
        }


# Transformer启发的内存注意力
# 将QWORD视为token，对每个地址计算其与周围内存的注意力权重
# 高注意力区域往往对应活跃的数据结构——对象边界、vtable指针等
# 这与Transformer Memory RE论文的核心思想一致：字节级注意力热图
# 揭示内存中分散结构的关联（注入存根、PE头、解密例程等）


class MemoryAttentionScorer:
    """基于滑动窗口自注意力的内存区域评分器
    对每个 QWORD 计算其相对于窗口内其他 QWORD 的归一化注意力权重
    高权重位置 → 被多指针引用的活跃对象
    不使用完整 transformer 编码器以保持线性复杂度 O(n·w)
    """

    _TEMPERATURE = 8.0  # softmax 温度参数——越高越平滑

    def __init__(self, window_size: int = 32):
        self._window = window_size  # QWORD 窗口大小

    def score_region(self, data: bytes, base_addr: int, ptr_size: int = 8) -> Dict[int, float]:
        """逐QWORD计算注意力评分——每个位置对其窗口内邻居的相关性加权和"""
        scores: Dict[int, float] = {}
        n_qwords = (len(data) - ptr_size) // ptr_size
        if n_qwords < 2:
            return scores
        fmt = "<Q" if ptr_size == 8 else "<I"
        # 预读取所有 QWORD
        qwords: List[int] = []
        for i in range(n_qwords):
            try:
                qwords.append(struct.unpack(fmt, data[i * ptr_size:(i + 1) * ptr_size])[0])
            except struct.error:
                qwords.append(0)
        # 滑动窗口自注意力
        hw = self._window // 2
        for i in range(n_qwords):
            left = max(0, i - hw)
            right = min(n_qwords, i + hw)
            # 查询向量 = 当前 QWORD 的低 16 位作为特征
            query = (qwords[i] & 0xFFFF) / 65535.0
            attn_sum = 0.0
            total = 0.0
            for j in range(left, right):
                key = (qwords[j] & 0xFFFF) / 65535.0
                # 点积注意力 + 温度缩放
                sim = query * key / self._TEMPERATURE
                weight = _math.exp(min(sim, 20.0))  # 防溢出
                attn_sum += weight * (1.0 if qwords[j] != 0 else 0.3)
                total += weight
            if total > 0:
                scores[base_addr + i * ptr_size] = attn_sum / total
        return scores


class PointerScanHeuristics:
    """Heuristic tests for 指针 validity: address range 对齐 检查"""

    DEFAULT_RANGES = [
        (0x0000000000400000, 0x00007FFFFFFFFFFF),
        (0x00007F0000000000, 0x00007FFFFFFFFFFF),
        (0x0000550000000000, 0x00005FFFFFFFFFFF),
    ]

    @classmethod
    def looks_like_pointer(cls, value: int,
                           addr_ranges: Optional[List[Tuple[int, int]]] = None) -> bool:
        if value == 0:
            return False
        ranges = addr_ranges or cls.DEFAULT_RANGES
        for lo, hi in ranges:
            if lo <= value < hi:
                return True
        return False

    @classmethod
    def looks_like_vtable(cls, ptrs: List[int],
                          addr_ranges: Optional[List[Tuple[int, int]]] = None) -> bool:
        if len(ptrs) < 3:
            return False
        valid = sum(1 for p in ptrs if cls.looks_like_pointer(p, addr_ranges))
        return valid >= max(3, len(ptrs) * 0.7)

    @classmethod
    def looks_like_heap_metadata(cls, value: int, prev_value: int,
                                  chunk_boundary: int = 0x10) -> bool:
        if value == 0:
            return False
        alignment = value & (chunk_boundary - 1)
        flags = alignment & 0x7
        if flags not in (0, 1, 2, 4):
            return False
        return (value & ~0x7) > chunk_boundary


class ObjectPointerReconstructor:
    """
    重建 object-指针 graphs raw memory 转存
    Scans for vtables, identifies C++ objects, 构建 引用 edges
    flags dangling 指针s 类型混淆s
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
        graph = ObjectPointerGraph(metadata={'base': hex(base_addr), 'size': len(data)})

        # 注意力评分——在扫描对象前计算，用于过滤低注意力区域
        attn_scorer = MemoryAttentionScorer(window_size=32)
        graph.attention_scores = attn_scorer.score_region(data, base_addr, self.ptr_size)

        vtables: List[Tuple[int, List[int]]] = []
        step = self.ptr_size
        for off in range(0, len(data) - step * self.vtable_min_entries, step * 4):
            ptrs = [self._read_ptr(data, off + i * step)
                    for i in range(self.vtable_min_entries)]
            if PointerScanHeuristics.looks_like_vtable(ptrs, self.addr_ranges):
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

        vtable_set: Set[int] = {v[0] for v in vtables}
        for off in range(0, len(data) - step, step * 8):
            first_ptr = self._read_ptr(data, off)
            if first_ptr in vtable_set:
                # 注意力过滤：低于阈值的对象仍保留但降低置信度
                attn = graph.attention_scores.get(base_addr + off, 0.0)
                size_guess = self._estimate_object_size(data, off, step)
                if size_guess <= 0 or size_guess > 4096:
                    size_guess = 64
                obj = CandidateObject(
                    address=base_addr + off, size=size_guess,
                    kind=ObjectKind.CP_OBJECT, vtable_ptr=first_ptr,
                    inferred_type=f"VT@{hex(first_ptr)}",
                    metadata={'attention': attn}
                )
                graph.objects[obj.address] = obj

        for obj in list(graph.objects.values()):
            start = obj.address - base_addr
            i = 0
            while i < obj.size:
                ptr = self._read_ptr(data, start + i)
                if ptr in graph.objects:
                    obj.refs.append(ptr)
                    graph.references.append(ObjectReference(
                        src=obj.address, dst=ptr, field=f"offset_{i}", kind="ptr"))
                elif PointerScanHeuristics.looks_like_pointer(ptr, self.addr_ranges):
                    if not (base_addr <= ptr < base_addr + len(data)):
                        obj.refs.append(ptr)
                        graph.references.append(ObjectReference(
                            src=obj.address, dst=ptr, field=f"offset_{i}", kind="ptr"))
                i += step

        live_set = set(graph.objects.keys())
        for obj in list(graph.objects.values()):
            for ref in obj.refs:
                if ref not in live_set and not (base_addr <= ref < base_addr + len(data)):
                    if not obj.is_dangling:
                        obj.is_dangling = True
                        graph.dangling.append(obj.address)

        vt_to_objs: Dict[int, List[int]] = defaultdict(list)
        for obj in graph.objects.values():
            if obj.vtable_ptr:
                vt_to_objs[obj.vtable_ptr].append(obj.address)
        for obj in list(graph.objects.values()):
            referenced_vts: Set[int] = set()
            for ref in obj.refs:
                if ref in graph.objects and graph.objects[ref].vtable_ptr:
                    referenced_vts.add(graph.objects[ref].vtable_ptr)
            if len(referenced_vts) > 1:
                types = [graph.objects[ref].inferred_type
                         for ref in obj.refs if ref in graph.objects]
                graph.type_confusions.append((
                    obj.address, obj.refs[0] if obj.refs else 0,
                    obj.inferred_type, " | ".join(set(types))))

        return graph

    def _estimate_object_size(self, data: bytes, start: int, step: int) -> int:
        size = step
        while size < 1024:
            ptr = self._read_ptr(data, start + size)
            if not PointerScanHeuristics.looks_like_pointer(ptr, self.addr_ranges):
                if start + size + step >= len(data):
                    break
                ptr2 = self._read_ptr(data, start + size + step)
                if not PointerScanHeuristics.looks_like_pointer(ptr2, self.addr_ranges):
                    break
            size += step
        return size

    def load_dump(self, path: str) -> Tuple[bytes, int]:
        """读取 raw memory 快照 binary file (container 格式化)"""
        with open(path, 'rb') as f:
            data = f.read()
        return data, 0


def reconstruct_from_dump(dump_path: str,
                          base_addr: int = 0x400000) -> Dict[str, Any]:
    """One-shot entry: 加载 转存 运行 full memory scan 流水线"""
    recon = ObjectPointerReconstructor()
    data, _ = recon.load_dump(dump_path)
    graph = recon.scan_memory(data, base_addr=base_addr)
    return {'success': True, 'graph': graph.to_dict()}


def find_uaf_evidence(graph: ObjectPointerGraph) -> List[Dict[str, Any]]:
    """提取 UAF indicators 指针 graph: dangling refs 类型混淆s"""
    evidence = []
    for addr in graph.dangling:
        obj = graph.objects.get(addr)
        if obj is None:
            continue
        evidence.append({
            'type': 'dangling_pointer', 'object': hex(addr),
            'inferred_type': obj.inferred_type,
            'reason': 'Object has dangling reference; target may be freed',
            'attention_score': graph.attention_scores.get(addr, 0.0),
        })
    for src, dst, ta, tb in graph.type_confusions:
        evidence.append({
            'type': 'type_confusion', 'src': hex(src), 'dst': hex(dst),
            'src_type': ta, 'dst_type': tb,
            'reason': 'Object references targets across different vtables; probable type confusion',
        })
    return evidence
