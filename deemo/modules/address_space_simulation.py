"""
结构感知的地址空间布局模拟模块

功能：
1. 随机化地址库模拟ASLR
2. 结构感知的内存布局
3. 支持多种内存分配策略

核心组件：
- AddressSpace: 地址空间
- MemoryAllocator: 内存分配器
- ASLRManager: ASLR管理器
"""

import os
import random
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MemoryRegionType(Enum):
    CODE = "code"
    DATA = "data"
    STACK = "stack"
    HEAP = "heap"
    SHARED = "shared"


class AllocationStrategy(Enum):
    FIRST_FIT = "first_fit"
    BEST_FIT = "best_fit"
    WORST_FIT = "worst_fit"
    RANDOM = "random"


@dataclass
class MemoryRegion:
    start: int
    size: int
    region_type: MemoryRegionType
    permissions: str
    name: Optional[str] = None
    allocated: bool = False


@dataclass
class Allocation:
    address: int
    size: int
    region_type: MemoryRegionType
    name: Optional[str] = None


class ASLRManager:

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)
        self._base_addresses = {}
        self._page_size = 4096

    def randomize_base(self, region_type: MemoryRegionType) -> int:
        base = self._generate_random_base()
        self._base_addresses[region_type] = base
        return base

    def _generate_random_base(self) -> int:
        return random.randint(0x10000000, 0xF0000000) & ~0xFFF

    def get_base(self, region_type: MemoryRegionType) -> Optional[int]:
        return self._base_addresses.get(region_type)

    def get_offset(self, region_type: MemoryRegionType, offset: int) -> int:
        base = self.get_base(region_type)
        if base is None:
            base = self.randomize_base(region_type)
        return base + offset


class MemoryAllocator:

    def __init__(self, strategy: AllocationStrategy = AllocationStrategy.FIRST_FIT):
        self._strategy = strategy
        self._regions: List[MemoryRegion] = []
        self._allocations: Dict[int, Allocation] = {}

    def add_region(self, start: int, size: int, region_type: MemoryRegionType,
                   permissions: str = "rwx", name: Optional[str] = None):
        region = MemoryRegion(
            start=start,
            size=size,
            region_type=region_type,
            permissions=permissions,
            name=name,
            allocated=False
        )
        self._regions.append(region)

    def allocate(self, size: int, region_type: MemoryRegionType) -> Optional[int]:
        available_regions = [r for r in self._regions 
                            if r.region_type == region_type and not r.allocated]
        
        if not available_regions:
            return None

        if self._strategy == AllocationStrategy.FIRST_FIT:
            region = available_regions[0]
        elif self._strategy == AllocationStrategy.BEST_FIT:
            region = min(available_regions, key=lambda r: abs(r.size - size))
        elif self._strategy == AllocationStrategy.WORST_FIT:
            region = max(available_regions, key=lambda r: r.size)
        else:
            region = random.choice(available_regions)

        if region.size >= size:
            region.allocated = True
            allocation = Allocation(
                address=region.start,
                size=size,
                region_type=region_type,
                name=region.name
            )
            self._allocations[region.start] = allocation
            return region.start

        return None

    def deallocate(self, address: int) -> bool:
        if address in self._allocations:
            allocation = self._allocations[address]
            for region in self._regions:
                if region.start == address and region.region_type == allocation.region_type:
                    region.allocated = False
                    break
            del self._allocations[address]
            return True
        return False

    def get_allocations(self) -> List[Allocation]:
        return list(self._allocations.values())


class AddressSpace:

    def __init__(self, aslr_enabled: bool = True):
        self._aslr_manager = ASLRManager()
        self._allocator = MemoryAllocator()
        self._aslr_enabled = aslr_enabled
        self._regions: List[MemoryRegion] = []

    def initialize(self, code_size: int = 0x100000, data_size: int = 0x100000,
                   stack_size: int = 0x400000, heap_size: int = 0x400000):
        if self._aslr_enabled:
            code_base = self._aslr_manager.randomize_base(MemoryRegionType.CODE)
            data_base = self._aslr_manager.randomize_base(MemoryRegionType.DATA)
            stack_base = self._aslr_manager.randomize_base(MemoryRegionType.STACK)
            heap_base = self._aslr_manager.randomize_base(MemoryRegionType.HEAP)
        else:
            code_base = 0x400000
            data_base = 0x1000000
            stack_base = 0x7FFFFFFF0000
            heap_base = 0x2000000

        self._allocator.add_region(code_base, code_size, MemoryRegionType.CODE, "rx", ".text")
        self._allocator.add_region(data_base, data_size, MemoryRegionType.DATA, "rw", ".data")
        self._allocator.add_region(stack_base - stack_size, stack_size, MemoryRegionType.STACK, "rw", "stack")
        self._allocator.add_region(heap_base, heap_size, MemoryRegionType.HEAP, "rw", "heap")

    def allocate_memory(self, size: int, region_type: MemoryRegionType) -> Optional[int]:
        return self._allocator.allocate(size, region_type)

    def free_memory(self, address: int) -> bool:
        return self._allocator.deallocate(address)

    def get_layout(self) -> Dict[str, Any]:
        layout = {}
        allocations = self._allocator.get_allocations()
        
        for alloc in allocations:
            layout[hex(alloc.address)] = {
                "size": alloc.size,
                "type": alloc.region_type.value,
                "name": alloc.name
            }
        
        return {
            "aslr_enabled": self._aslr_enabled,
            "base_addresses": {
                region_type.value: hex(base)
                for region_type, base in self._aslr_manager._base_addresses.items()
            },
            "allocations": layout
        }

    def simulate_memory_access(self, address: int, size: int, write: bool = False) -> bool:
        allocations = self._allocator.get_allocations()
        
        for alloc in allocations:
            if alloc.address <= address < alloc.address + alloc.size:
                permissions = self._get_permissions(alloc.region_type)
                if write and "w" not in permissions:
                    return False
                return True
        
        return False

    def _get_permissions(self, region_type: MemoryRegionType) -> str:
        permissions = {
            MemoryRegionType.CODE: "rx",
            MemoryRegionType.DATA: "rw",
            MemoryRegionType.STACK: "rw",
            MemoryRegionType.HEAP: "rw",
            MemoryRegionType.SHARED: "rw"
        }
        return permissions.get(region_type, "r")


def create_address_space(aslr_enabled: bool = True) -> AddressSpace:
    space = AddressSpace(aslr_enabled=aslr_enabled)
    space.initialize()
    return space


def simulate_allocation(aslr_enabled: bool = True) -> Dict[str, Any]:
    space = create_address_space(aslr_enabled)
    
    code_addr = space.allocate_memory(0x10000, MemoryRegionType.CODE)
    data_addr = space.allocate_memory(0x20000, MemoryRegionType.DATA)
    heap_addr = space.allocate_memory(0x1000, MemoryRegionType.HEAP)
    
    return {
        "layout": space.get_layout(),
        "allocations": {
            "code": hex(code_addr) if code_addr else None,
            "data": hex(data_addr) if data_addr else None,
            "heap": hex(heap_addr) if heap_addr else None
        }
    }