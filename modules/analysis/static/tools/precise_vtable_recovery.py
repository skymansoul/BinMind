#!/usr/bin/env python3
import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class VTableEntryType(Enum):
    FUNCTION = "function"
    DATA = "data"
    VTABLE_PTR = "vtable_ptr"
    RTTI = "rtti"
    UNKNOWN = "unknown"

class CallType:
    DIRECT = "direct"
    VIRTUAL = "virtual"
    INDIRECT = "indirect"
    CALLBACK = "callback"

@dataclass
class VTableEntry:
    address: int = 0
    target_address: int = 0
    entry_type: VTableEntryType = VTableEntryType.UNKNOWN
    name: str = ""
    offset: int = 0

@dataclass
class VTableInfo:
    address: int = 0
    entries: List[VTableEntry] = field(default_factory=list)
    class_name: str = ""
    parent_vtable: Optional[int] = None
    children_vtables: List[int] = field(default_factory=list)
    rtti_address: Optional[int] = None

@dataclass
class VirtualCallSite:
    address: int = 0
    vtable_ptr_address: int = 0
    vtable_offset: int = 0
    possible_targets: List[int] = field(default_factory=list)
    resolved_type: str = ""
    confidence: float = 0.0

@dataclass
class ConstructorInfo:
    address: int = 0
    name: str = ""
    vtable_init_points: List[int] = field(default_factory=list)
    class_name: str = ""

@dataclass
class VTableRecoveryResult:
    vtables: Dict[int, VTableInfo] = field(default_factory=dict)
    virtual_call_sites: List[VirtualCallSite] = field(default_factory=list)
    constructors: List[ConstructorInfo] = field(default_factory=list)
    class_hierarchy: Dict[str, List[str]] = field(default_factory=dict)
    enhanced_call_graph: Dict[int, List[Tuple[int, str]]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False

class PreciseVTableRecovery:

    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.vtables: Dict[int, VTableInfo] = {}
        self.virtual_call_sites: List[VirtualCallSite] = []
        self.constructors: List[ConstructorInfo] = []
        self.class_hierarchy: Dict[str, List[str]] = {}

        logger.info("VTable recovery engine initialized.")

    def recover_vtables(self, pseudocode: str = "", assembly: str = "") -> VTableRecoveryResult:
        logger.info("VTable recovery initiated.")

        result = VTableRecoveryResult()

        try:
            self._extract_vtables(pseudocode, assembly)
            self._identify_constructors(pseudocode, assembly)
            self._find_virtual_call_sites(pseudocode, assembly)
            self._resolve_virtual_calls()
            self._build_class_hierarchy()
            self._enhance_call_graph()

            result.vtables = self.vtables
            result.virtual_call_sites = self.virtual_call_sites
            result.constructors = self.constructors
            result.class_hierarchy = self.class_hierarchy
            result.enhanced_call_graph = self._build_enhanced_call_graph()
            result.analysis_success = True

            logger.info(f"VTable recovery complete: {len(self.vtables)} vtables, {len(self.virtual_call_sites)} virtual call sites found.")

        except Exception as e:
            logger.error(f"VTable recovery failed: {e}")
            result.warnings.append(f"Error during recovery: {e}")

        return result

    def _extract_vtables(self, pseudocode: str, assembly: str) -> None:
        vtable_patterns = [
            r'(\w+_vtable)\s*=\s*\{',
            r'virtual_table\s*\[(\d+)\]',
            r'(\*vtable)\s*=\s*&?(\w+)',
        ]

        for pattern in vtable_patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                if isinstance(match, tuple):
                    vtable_name = match[0]
                else:
                    vtable_name = match

                vtable_info = VTableInfo(
                    address=0,
                    class_name=vtable_name.replace("_vtable", ""),
                    entries=[]
                )
                vid = abs(hash(vtable_name)) % (2**31)
                self.vtables[vid] = vtable_info

        mov_pattern = r'mov\s+qword ptr \[([^\]]+)\],\s*offset\s+(\w+_vtable)'
        matches = re.findall(mov_pattern, assembly)
        existing_names = {v.class_name for v in self.vtables.values()}
        for dest, vtable_name in matches:
            if vtable_name not in existing_names:
                vtable_info = VTableInfo(
                    address=0,
                    class_name=vtable_name.replace("_vtable", ""),
                    entries=[]
                )
                vid = abs(hash(vtable_name)) % (2**31)
                self.vtables[vid] = vtable_info

    def _identify_constructors(self, pseudocode: str, assembly: str) -> None:
        constructor_patterns = [
            r'(\w+)::(\w+)\(\)',
            r'_ZN(\d+)(\w+)C1Ev',
            r'_ZN(\d+)(\w+)C2Ev',
        ]

        for pattern in constructor_patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    class_name = match[-1]
                    constructor_name = f"{class_name}::{class_name}"

                    vtable_init_pattern = rf'{class_name}_vtable'
                    if vtable_init_pattern in pseudocode:
                        constructor_info = ConstructorInfo(
                            address=0,
                            name=constructor_name,
                            class_name=class_name,
                            vtable_init_points=[]
                        )
                        self.constructors.append(constructor_info)

    def _find_virtual_call_sites(self, pseudocode: str, assembly: str) -> None:
        virtual_call_patterns = [
            r'this->(\w+)\(\)',
            r'\(\*this->vtable\[(\d+)\]\)\(this\)',
            r'\(\*(\w+->vtable)\[(\d+)\]\)\([^)]*\)'
        ]

        for pattern in virtual_call_patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                if isinstance(match, tuple):
                    offset = int(match[-1]) if match[-1].isdigit() else 0
                else:
                    offset = 0

                call_site = VirtualCallSite(
                    address=0,
                    vtable_ptr_address=0,
                    vtable_offset=offset,
                    possible_targets=[],
                    confidence=0.5
                )
                self.virtual_call_sites.append(call_site)

        call_pattern = r'call\s+\*(\[rbx|rdx|rax|rcx)\s*\+\s*(\d+)'
        matches = re.findall(call_pattern, assembly)
        for reg, offset in matches:
            call_site = VirtualCallSite(
                address=0,
                vtable_ptr_address=0,
                vtable_offset=int(offset),
                possible_targets=[],
                confidence=0.6
            )
            self.virtual_call_sites.append(call_site)

    def _resolve_virtual_calls(self) -> None:
        for call_site in self.virtual_call_sites:
            possible_targets = []

            for vtable in self.vtables.values():
                for i, entry in enumerate(vtable.entries):
                    if i * 8 == call_site.vtable_offset:
                        possible_targets.append(entry.target_address)
                        call_site.resolved_type = vtable.class_name

            call_site.possible_targets = possible_targets
            call_site.confidence = min(1.0, len(possible_targets) * 0.3 + 0.4)

    def _build_class_hierarchy(self) -> None:
        for vtable in self.vtables.values():
            class_name = vtable.class_name

            parent_candidates = []
            for other_vtable in self.vtables.values():
                other_name = other_vtable.class_name
                if other_name != class_name and other_name in class_name:
                    parent_candidates.append(other_name)

            if parent_candidates:
                self.class_hierarchy[class_name] = parent_candidates
            else:
                self.class_hierarchy[class_name] = []

    def _enhance_call_graph(self) -> None:
        pass

    def _build_enhanced_call_graph(self) -> Dict[int, List[Tuple[int, str]]]:
        call_graph: Dict[int, List[Tuple[int, str]]] = {}

        for call_site in self.virtual_call_sites:
            for target in call_site.possible_targets:
                if call_site.address not in call_graph:
                    call_graph[call_site.address] = []
                call_graph[call_site.address].append((target, CallType.VIRTUAL))

        return call_graph

    def resolve_polymorphic_type(self, object_address: int, context: str = "") -> Optional[str]:
        for constructor in self.constructors:
            if constructor.class_name and context:
                if constructor.class_name.lower() in context.lower():
                    return constructor.class_name
        return None

    def get_virtual_call_targets(self, call_site_address: int) -> List[int]:
        for call_site in self.virtual_call_sites:
            if call_site.address == call_site_address:
                return call_site.possible_targets
        return []

def recover_vtables(binary_path: str, pseudocode: str = "", assembly: str = "") -> VTableRecoveryResult:
    recoverer = PreciseVTableRecovery(binary_path)
    return recoverer.recover_vtables(pseudocode, assembly)
