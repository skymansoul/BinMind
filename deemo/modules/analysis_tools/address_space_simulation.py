# Core types: MemoryRegionType + 6 supporting classes.
# Dependencies: os, json.
# Design: generator replaces explicit state machine.
import logging
import os
import json
import random
import hashlib
from dataclasses import dataclass, field
from enum import IntFlag, StrEnum
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class MemoryRegionType(StrEnum):
    TEXT = "text"
    DATA = "data"
    BSS = "bss"
    HEAP = "heap"
    STACK = "stack"
    MMAP = "mmap"
    SHARED = "shared"

class ProtectionFlags(IntFlag):
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 4


@dataclass
class MemorySegment:
    name: str
    region_type: MemoryRegionType
    start: int
    end: int
    permissions: ProtectionFlags
    offset: int = 0
    file_path: str = ""
    is_randomized: bool = False
    alignment: int = 4096


@dataclass
class AllocationRecord:
    ptr: int
    size: int
    alignment: int
    heap_name: str = "default"
    metadata: dict = field(default_factory=dict)


@dataclass
class AddressDependency:
    source: int
    target: int
    offset: int
    kind: str
    confidence: float = 0.5


@dataclass
class AddressSpaceSnapshot:
    pid: int
    timestamp: float
    segments: list = field(default_factory=list)
    allocations: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    aslr_seed: int = 0


class ASLRRandomizer:
    """ASLR base-address randomization engine."""

    PAGE_SIZE = 4096
    DEFAULT_SEED = 0x12345678

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed if seed is not None else random.randint(0, 0xFFFFFFFF)
        self._rng = random.Random(self.seed)

    def randomize_base(self, base: int, range_bytes: int) -> int:
        """Apply page-aligned random offset to a base address."""
        if range_bytes == 0:
            return base
        offset = self._rng.randint(0, range_bytes // self.PAGE_SIZE) * self.PAGE_SIZE
        return base + offset

    def randomize_executable(self) -> int:
        """Randomize executable segment base (0x55550000-0x7FFFFFFFFFFF)."""
        return self.randomize_base(0x55550000, 0x2AAAF0000)

    def randomize_library(self) -> int:
        """Randomize shared library base address."""
        return self.randomize_base(0x7F0000000000, 0x7FF000000000 - 0x7F0000000000)

    def randomize_stack(self) -> int:
        """Randomize stack base address."""
        return self.randomize_base(0x7FF000000000, 0x800000000000 - 0x7FF000000000)

    def randomize_heap(self) -> int:
        """Randomize heap base address."""
        return self.randomize_base(0x100000000, 0x400000000 - 0x100000000)

    def get_seed_hash(self) -> str:
        """Return first 8 hex digits of seed MD5 hash."""
        return hashlib.md5(str(self.seed).encode()).hexdigest()[:8]


class AddressSpaceSimulator:
    """Address space layout simulation engine."""

    def __init__(self, aslr_seed: Optional[int] = None):
        self.randomizer = ASLRRandomizer(aslr_seed)
        self.segments: List[MemorySegment] = []
        self.allocations: List[AllocationRecord] = []
        self.dependencies: List[AddressDependency] = []
        self._next_heap_ptr = 0
        self._next_stack_ptr = 0
        self._heap_arenas: Dict[str, int] = {}

    def add_segment(self, name: str, region_type: MemoryRegionType,
                    size: int, permissions: ProtectionFlags,
                    is_randomized: bool = True,
                    file_path: str = "", offset: int = 0) -> MemorySegment:
        if is_randomized:
            if region_type == MemoryRegionType.TEXT:
                start = self.randomizer.randomize_executable()
            elif region_type == MemoryRegionType.STACK:
                start = self.randomizer.randomize_stack()
            elif region_type == MemoryRegionType.HEAP:
                start = self.randomizer.randomize_heap()
            elif region_type == MemoryRegionType.SHARED:
                start = self.randomizer.randomize_library()
            else:
                start = self.randomizer.randomize_heap()
        else:
            start = offset

        seg = MemorySegment(
            name=name,
            region_type=region_type,
            start=start,
            end=start + size,
            permissions=permissions,
            offset=offset,
            file_path=file_path,
            is_randomized=is_randomized,
            alignment=AddressSpaceSimulator._get_alignment(permissions)
        )
        self.segments.append(seg)
        return seg

    @staticmethod
    def _get_alignment(permissions: ProtectionFlags) -> int:
        if permissions & ProtectionFlags.EXECUTE:
            return 4096 * 2  # Executable segment alignment = 2x page size (I-cache line optimization).
        return 4096

    def allocate_heap(self, size: int, alignment: int = 8,
                      arena: str = "default") -> int:
        """Heap allocation: align within arena, return pointer."""
        if arena not in self._heap_arenas:
            for seg in self.segments:
                if seg.region_type == MemoryRegionType.HEAP:
                    self._heap_arenas[arena] = seg.start
                    break

        ptr = self._heap_arenas.get(arena, 0x100000000)
        ptr = ((ptr + alignment - 1) // alignment) * alignment

        record = AllocationRecord(
            ptr=ptr,
            size=size,
            alignment=alignment,
            heap_name=arena,
            metadata={'timestamp': len(self.allocations)}
        )
        self.allocations.append(record)

        self._heap_arenas[arena] = ptr + size
        return ptr

    def allocate_stack(self, size: int) -> int:
        """Stack allocation: grows toward lower addresses."""
        if not self._next_stack_ptr:
            for seg in self.segments:
                if seg.region_type == MemoryRegionType.STACK:
                    self._next_stack_ptr = seg.end
                    break

        self._next_stack_ptr -= size
        ptr = self._next_stack_ptr

        record = AllocationRecord(
            ptr=ptr,
            size=size,
            alignment=16,
            heap_name="stack",
            metadata={'type': 'stack'}
        )
        self.allocations.append(record)
        return ptr

    def add_dependency(self, source: int, target: int,
                       offset: int = 0, kind: str = "direct",
                       confidence: float = 0.5):
        """Register address dependency (source to target)."""
        dep = AddressDependency(
            source=source,
            target=target,
            offset=offset,
            kind=kind,
            confidence=confidence
        )
        self.dependencies.append(dep)

    def resolve_symbol(self, symbol_name: str) -> Optional[int]:
        """Symbol to address: hash map lookup within DATA segment."""
        for seg in self.segments:
            if seg.region_type == MemoryRegionType.DATA:
                return seg.start + hash(symbol_name) % 0x10000
        return None

    def get_segment_by_address(self, addr: int) -> Optional[MemorySegment]:
        """Find owning MemorySegment by address."""
        for seg in self.segments:
            if seg.start <= addr < seg.end:
                return seg
        return None

    def simulate_aslr(self) -> AddressSpaceSnapshot:
        """Snapshot current address space state."""
        return AddressSpaceSnapshot(
            pid=hash(self.randomizer.seed),
            timestamp=0,
            segments=self.segments.copy(),
            allocations=self.allocations.copy(),
            dependencies=self.dependencies.copy(),
            aslr_seed=self.randomizer.seed
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'aslr_seed': self.randomizer.seed,
            'seed_hash': self.randomizer.get_seed_hash(),
            'segments': [
                {
                    'name': s.name,
                    'type': s.region_type.value,
                    'start': hex(s.start),
                    'end': hex(s.end),
                    'size': s.end - s.start,
                    'permissions': s.permissions.value,
                    'is_randomized': s.is_randomized,
                    'file_path': s.file_path
                }
                for s in self.segments
            ],
            'allocations': [
                {
                    'ptr': hex(a.ptr),
                    'size': a.size,
                    'alignment': a.alignment,
                    'heap': a.heap_name,
                    'metadata': a.metadata
                }
                for a in self.allocations
            ],
            'dependencies': [
                {
                    'source': hex(d.source),
                    'target': hex(d.target),
                    'offset': d.offset,
                    'kind': d.kind,
                    'confidence': d.confidence
                }
                for d in self.dependencies
            ]
        }

    def visualize(self) -> str:
        """Render address space layout as text diagram."""
        lines = ["=" * 80]
        lines.append("Address Space Layout (ASLR seed: 0x{:08X})".format(self.randomizer.seed))
        lines.append("=" * 80)

        sorted_segs = sorted(self.segments, key=lambda s: s.start)
        for seg in sorted_segs:
            perms = []
            if seg.permissions & ProtectionFlags.READ:
                perms.append("R")
            if seg.permissions & ProtectionFlags.WRITE:
                perms.append("W")
            if seg.permissions & ProtectionFlags.EXECUTE:
                perms.append("X")
            lines.append(
                f"0x{seg.start:016X} - 0x{seg.end:016X} [{''.join(perms):3}] "
                f"{seg.region_type.value:8} {seg.name}"
            )

        lines.append("-" * 80)
        lines.append(f"Total segments: {len(self.segments)}")
        lines.append(f"Total allocations: {len(self.allocations)}")
        lines.append(f"Total dependencies: {len(self.dependencies)}")
        return "\n".join(lines)


class AddressLibraryGenerator:
    """Batch-generate ASLR address libraries."""

    def __init__(self, count: int = 1000):
        self.count = count

    def generate(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate N independent ASLR snapshots; deduplicate before output."""
        libraries = []
        seen_seeds = set()

        while len(libraries) < self.count:
            sim = AddressSpaceSimulator()

            sim.add_segment(
                "main_text", MemoryRegionType.TEXT,
                0x200000, ProtectionFlags.READ | ProtectionFlags.EXECUTE,
                is_randomized=True
            )
            sim.add_segment(
                "main_data", MemoryRegionType.DATA,
                0x100000, ProtectionFlags.READ | ProtectionFlags.WRITE,
                is_randomized=True
            )
            sim.add_segment(
                "libc", MemoryRegionType.SHARED,
                0x2000000, ProtectionFlags.READ | ProtectionFlags.EXECUTE,
                is_randomized=True, file_path="/lib/x86_64-linux-gnu/libc.so.6"
            )
            sim.add_segment(
                "libm", MemoryRegionType.SHARED,
                0x1000000, ProtectionFlags.READ | ProtectionFlags.EXECUTE,
                is_randomized=True, file_path="/lib/x86_64-linux-gnu/libm.so.6"
            )
            sim.add_segment(
                "heap", MemoryRegionType.HEAP,
                0x10000000, ProtectionFlags.READ | ProtectionFlags.WRITE,
                is_randomized=True
            )
            sim.add_segment(
                "stack", MemoryRegionType.STACK,
                0x200000, ProtectionFlags.READ | ProtectionFlags.WRITE,
                is_randomized=True
            )

            snapshot = sim.simulate_aslr()
            seed_hash = sim.randomizer.get_seed_hash()

            if seed_hash in seen_seeds:
                continue
            seen_seeds.add(seed_hash)

            libraries.append({
                'seed': sim.randomizer.seed,
                'seed_hash': seed_hash,
                'layout': sim.to_dict()
            })

        result = {
            'count': len(libraries),
            'generated_at': 0,
            'libraries': libraries
        }

        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
            except Exception as exc:
                logger.warning(f"Address library save failed: {exc}")

        return result


def simulate_address_space(
    binary_path: Optional[str] = None,
    aslr_seed: Optional[int] = None,
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    sim = AddressSpaceSimulator(aslr_seed)

    if binary_path:
        sim.add_segment(
            os.path.basename(binary_path) + "_text",
            MemoryRegionType.TEXT,
            0x200000,
            ProtectionFlags.READ | ProtectionFlags.EXECUTE,
            is_randomized=True,
            file_path=binary_path
        )
        sim.add_segment(
            os.path.basename(binary_path) + "_data",
            MemoryRegionType.DATA,
            0x100000,
            ProtectionFlags.READ | ProtectionFlags.WRITE,
            is_randomized=True,
            file_path=binary_path
        )
    else:
        sim.add_segment(
            "anonymous_text",
            MemoryRegionType.TEXT,
            0x200000,
            ProtectionFlags.READ | ProtectionFlags.EXECUTE,
            is_randomized=True
        )
        sim.add_segment(
            "anonymous_data",
            MemoryRegionType.DATA,
            0x100000,
            ProtectionFlags.READ | ProtectionFlags.WRITE,
            is_randomized=True
        )

    sim.add_segment(
        "libc", MemoryRegionType.SHARED,
        0x2000000, ProtectionFlags.READ | ProtectionFlags.EXECUTE,
        is_randomized=True, file_path="/lib/x86_64-linux-gnu/libc.so.6"
    )
    sim.add_segment(
        "heap", MemoryRegionType.HEAP,
        0x10000000, ProtectionFlags.READ | ProtectionFlags.WRITE,
        is_randomized=True
    )
    sim.add_segment(
        "stack", MemoryRegionType.STACK,
        0x200000, ProtectionFlags.READ | ProtectionFlags.WRITE,
        is_randomized=True
    )

    result = {
        'success': True,
        'aslr_seed': sim.randomizer.seed,
        'seed_hash': sim.randomizer.get_seed_hash(),
        'layout': sim.to_dict(),
        'visualization': sim.visualize()
    }

    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
        except Exception as e:
            return {'success': False, 'error': str(e)}

    return result


def generate_address_library(
    count: int = 1000,
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    generator = AddressLibraryGenerator(count)
    return generator.generate(output_path)
