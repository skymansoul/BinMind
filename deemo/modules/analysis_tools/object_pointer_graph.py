"""
Memory object pointer graph reconstruction.

Capabilities:
    1. Scan core dumps or memory snapshots for candidate object references
    2. Reconstruct C++ object relationships and vtable targets
    3. Surface UAF and type confusion indicators
    4. Emit object interaction graph

Core methods:
    - Heuristic pointer scan (alignment + addressable range validation)
    - Vtable signature matching (consecutive function pointers + vtable inheritance)
    - Reference graph construction
    - Risk scoring: dangling pointers / type mismatches
"""

import logging
import os
import json
import struct
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ObjectKind:
    """Object type classification for memory scan results."""
    UNKNOWN = "unknown"
    CP_OBJECT = "c++_object"
    CP_VTABLE = "c++_vtable"
    CP_STRING = "c++_string"
    HEAP_CHUNK = "heap_chunk"
    STACK_FRAME = "stack_frame"
    THREAD_LOCAL = "thread_local"
    KERNEL_OBJECT = "kernel_object"

class CandidateObject:
    """Candidate object identified during memory scan."""
    __slots__ = ('address', 'size', 'kind', 'vtable_ptr', 'inferred_type', 'refs', 'is_dangling', 'metadata')

    def __init__(
            self,
            address,
            size,
            kind,
            vtable_ptr=None,
            inferred_type="",
            refs=None,
            is_dangling=False,
            metadata=None,
    ):
        self.vtable_ptr = vtable_ptr
        self.inferred_type = inferred_type
        self.refs = refs if refs is not None else list()
        self.is_dangling = is_dangling
        self.metadata = metadata if metadata is not None else dict()

class ObjectReference:
    """Inter-object pointer reference edge in the graph."""
    __slots__ = ('src', 'dst', 'field', 'kind')

    def __init__(self, src, dst, field="", kind="ptr"):
        self.src = src
        self.dst = dst
        self.field = field
        self.kind = kind

class ObjectPointerGraph:
    """Directed graph capturing object-to-object pointer relationships."""
    __slots__ = ('objects', 'references', 'dangling', 'type_confusions', 'metadata')

    def __init__(
            self,
            objects=None,
            references=None,
            dangling=None,
            type_confusions=None,
            metadata=None,
    ):
        self.objects = objects if objects is not None else dict()
        self.references = references if references is not None else list()
        self.dangling = dangling if dangling is not None else list()
        self.type_confusions = type_confusions if type_confusions is not None else list()
        self.metadata = metadata if metadata is not None else dict()

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
    """Heuristic tests for pointer validity: address range and alignment checks."""

    DEFAULT_RANGES = [
        (0x0000000000400000, 0x00007FFFFFFFFFFF),
        (0x00007F0000000000, 0x00007FFFFFFFFFFF),
        (0x0000550000000000, 0x00005FFFFFFFFFFF),
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
    Reconstructs object-pointer graphs from raw memory dumps.
    Scans for vtables, identifies C++ objects, builds reference edges,
    and flags dangling pointers and type confusions.
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
        vtable_info: Dict[int, Tuple[int, int]] = {
            v[0]: (v[0], len(v[1])) for v in vtables
        }
        for off in range(0, len(data) - step, step * 8):
            first_ptr = self._read_ptr(data, off)
            if first_ptr in vtable_set:
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
                    if not (base_addr <= ptr < base_addr + len(data)):
                        obj.refs.append(ptr)
                        graph.references.append(ObjectReference(
                            src=obj.address, dst=ptr,
                            field=f"offset_{i}", kind="ptr"
                        ))

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
                    obj.address,
                    obj.refs[0] if obj.refs else 0,
                    obj.inferred_type,
                    " | ".join(set(types))
                ))

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
        """Read raw memory snapshot from binary file (no container format)."""
        with open(path, 'rb') as f:
            data = f.read()
        return data, 0


def reconstruct_from_dump(dump_path: str,
                          base_addr: int = 0x400000) -> Dict[str, Any]:
    """One-shot entry: load dump and run full memory scan pipeline."""
    recons = ObjectPointerReconstructor()
    data, _ = recons.load_dump(dump_path)
    graph = recons.scan_memory(data, base_addr=base_addr)
    return {
        'success': True,
        'graph': graph.to_dict()
    }


def find_uaf_evidence(graph: ObjectPointerGraph) -> List[Dict[str, Any]]:
    """Extract UAF indicators from the pointer graph: dangling refs and type confusions."""
    evidence = []
    for addr in graph.dangling:
        obj = graph.objects.get(addr)
        if obj is None:
            continue
        evidence.append({
            'type': 'dangling_pointer',
            'object': hex(addr),
            'inferred_type': obj.inferred_type,
            'reason': 'Object has dangling reference; target may be freed'
        })
    for src, dst, ta, tb in graph.type_confusions:
        evidence.append({
            'type': 'type_confusion',
            'src': hex(src),
            'dst': hex(dst),
            'src_type': ta,
            'dst_type': tb,
            'reason': 'Object references targets across different vtables; probable type confusion'
        })
    return evidence
