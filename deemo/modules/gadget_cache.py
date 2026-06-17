"""
基于缓存的利用部件复用模块

功能：
1. gadget搜索缓存
2. 跨二进制复用
3. 快速查找

核心组件：
- GadgetCache: Gadget缓存
- GadgetFinder: Gadget查找器
- GadgetDatabase: Gadget数据库
"""

import os
import hashlib
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class GadgetType(Enum):
    RET = "ret"
    JMP = "jmp"
    CALL = "call"
    POP = "pop"
    XOR = "xor"
    ADD = "add"
    SUB = "sub"


@dataclass
class Gadget:
    address: int
    instructions: List[str]
    type: GadgetType
    binary_hash: str
    length: int


class GadgetCache:

    def __init__(self):
        self._cache: Dict[str, List[Gadget]] = {}
        self._binary_gadgets: Dict[str, List[Gadget]] = {}

    def add_gadgets(self, binary_hash: str, gadgets: List[Gadget]):
        self._binary_gadgets[binary_hash] = gadgets
        
        for gadget in gadgets:
            key = gadget.type.value
            if key not in self._cache:
                self._cache[key] = []
            self._cache[key].append(gadget)

    def find_by_type(self, gadget_type: GadgetType) -> List[Gadget]:
        return self._cache.get(gadget_type.value, [])

    def find_by_binary(self, binary_hash: str) -> List[Gadget]:
        return self._binary_gadgets.get(binary_hash, [])

    def search(self, pattern: str) -> List[Gadget]:
        results = []
        for gadgets in self._cache.values():
            for gadget in gadgets:
                if pattern in str(gadget.instructions):
                    results.append(gadget)
        return results

    def clear(self):
        self._cache.clear()
        self._binary_gadgets.clear()

    def get_stats(self) -> Dict[str, Any]:
        total_gadgets = sum(len(gadgets) for gadgets in self._cache.values())
        return {
            "total_gadgets": total_gadgets,
            "by_type": {key: len(gadgets) for key, gadgets in self._cache.items()},
            "binaries_indexed": len(self._binary_gadgets)
        }


class GadgetFinder:

    def __init__(self):
        self._cache = GadgetCache()

    def find_gadgets(self, binary_data: bytes, max_length: int = 15) -> List[Gadget]:
        binary_hash = hashlib.sha256(binary_data).hexdigest()
        
        cached = self._cache.find_by_binary(binary_hash)
        if cached:
            return cached
        
        gadgets = self._scan_binary(binary_data, max_length)
        self._cache.add_gadgets(binary_hash, gadgets)
        
        return gadgets

    def _scan_binary(self, data: bytes, max_length: int) -> List[Gadget]:
        gadgets = []
        
        for i in range(len(data) - 1):
            if data[i] == 0xc3:
                gadget = self._extract_gadget(data, i, max_length)
                if gadget:
                    gadgets.append(gadget)
        
        return gadgets

    def _extract_gadget(self, data: bytes, offset: int, max_length: int) -> Optional[Gadget]:
        instructions = []
        current_offset = offset
        length = 0
        
        while current_offset >= 0 and length < max_length:
            byte = data[current_offset]
            
            if byte == 0xc3:
                instructions.append("ret")
            elif byte == 0xc2:
                instructions.append("ret imm16")
            elif byte == 0xeb:
                instructions.append(f"jmp short {data[current_offset + 1]}")
                current_offset -= 1
            else:
                instructions.append(f"byte 0x{byte:02x}")
            
            current_offset -= 1
            length += 1
        
        instructions.reverse()
        
        return Gadget(
            address=offset,
            instructions=instructions,
            type=GadgetType.RET,
            binary_hash="",
            length=length
        )


def cache_gadgets(binary_data: bytes) -> List[Gadget]:
    finder = GadgetFinder()
    return finder.find_gadgets(binary_data)