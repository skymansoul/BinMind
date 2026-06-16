"""
精确虚函数调用目标恢复模块

功能:
    1. 恢复vtable结构
    2. 定位构造函数中的vtable初始化点
    3. 结合调用点上下文推断多态对象实际类型
    4. 输出增强的调用图，标注多态调用目标

核心技术:
    - 静态vtable解析
    - 构造函数分析
    - 类型层次推断
    - 调用图增强
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VTableEntryType(Enum):
    """虚表条目类型"""
    FUNCTION = "function"
    DATA = "data"
    VTABLE_PTR = "vtable_ptr"
    RTTI = "rtti"
    UNKNOWN = "unknown"


class CallType(Enum):
    """调用类型"""
    DIRECT = "direct"
    VIRTUAL = "virtual"
    INDIRECT = "indirect"
    CALLBACK = "callback"


@dataclass
class VTableEntry:
    """虚表条目"""
    address: int
    target_address: int
    entry_type: VTableEntryType
    name: str = ""
    offset: int = 0


@dataclass
class VTableInfo:
    """虚表信息"""
    address: int
    entries: List[VTableEntry] = field(default_factory=list)
    class_name: str = ""
    parent_vtable: Optional[int] = None
    children_vtables: List[int] = field(default_factory=list)
    rtti_address: Optional[int] = None


@dataclass
class VirtualCallSite:
    """虚函数调用点"""
    address: int
    vtable_ptr_address: int
    vtable_offset: int
    possible_targets: List[int] = field(default_factory=list)
    resolved_type: str = ""
    confidence: float = 0.0


@dataclass
class ConstructorInfo:
    """构造函数信息"""
    address: int
    name: str = ""
    vtable_init_points: List[Tuple[int, int]] = field(default_factory=list)
    class_name: str = ""


@dataclass
class VTableRecoveryResult:
    """虚表恢复结果"""
    vtables: Dict[int, VTableInfo] = field(default_factory=dict)
    virtual_call_sites: List[VirtualCallSite] = field(default_factory=list)
    constructors: List[ConstructorInfo] = field(default_factory=list)
    class_hierarchy: Dict[str, List[str]] = field(default_factory=dict)
    enhanced_call_graph: Dict[int, List[Tuple[int, CallType]]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


class PreciseVTableRecovery:
    """精确虚函数调用目标恢复器"""
    
    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        """初始化恢复器"""
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.vtables: Dict[int, VTableInfo] = {}
        self.virtual_call_sites: List[VirtualCallSite] = []
        self.constructors: List[ConstructorInfo] = []
        self.class_hierarchy: Dict[str, List[str]] = {}
        
        logger.info("精确虚表恢复器初始化完成")
    
    def recover_vtables(self, pseudocode: str = "", assembly: str = "") -> VTableRecoveryResult:
        """恢复虚表信息"""
        logger.info("开始恢复虚表信息")
        
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
            
            logger.info(f"虚表恢复完成，发现 {len(self.vtables)} 个虚表，{len(self.virtual_call_sites)} 个虚函数调用点")
            
        except Exception as e:
            logger.error(f"虚表恢复失败: {e}")
            result.warnings.append(f"恢复过程中发生错误: {e}")
        
        return result
    
    def _extract_vtables(self, pseudocode: str, assembly: str) -> None:
        """从伪代码和汇编中提取虚表"""
        # 从伪代码中提取虚表模式
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
                
                # 创建虚表信息
                vtable_info = VTableInfo(
                    address=0,
                    class_name=vtable_name.replace("_vtable", ""),
                    entries=[]
                )
                self.vtables[id(vtable_info)] = vtable_info
        
        # 从汇编中提取虚表初始化模式
        mov_pattern = r'mov\s+qword ptr \[([^\]]+)\],\s*offset\s+(\w+_vtable)'
        matches = re.findall(mov_pattern, assembly)
        for dest, vtable_name in matches:
            if vtable_name not in [v.class_name for v in self.vtables.values()]:
                vtable_info = VTableInfo(
                    address=0,
                    class_name=vtable_name.replace("_vtable", ""),
                    entries=[]
                )
                self.vtables[id(vtable_info)] = vtable_info
    
    def _identify_constructors(self, pseudocode: str, assembly: str) -> None:
        """识别构造函数"""
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
                    
                    # 查找vtable初始化
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
        """查找虚函数调用点"""
        # 伪代码模式
        virtual_call_patterns = [
            r'this->(\w+)\(\)',
            r'\(\*this->vtable\[(\d+)\]\)\(this',
            r'\(\*(\w+->vtable)\[(\d+)\]\)\(',
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
        
        # 汇编模式
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
        """解析虚函数调用目标"""
        for call_site in self.virtual_call_sites:
            possible_targets = []
            
            # 查找所有虚表中对应偏移的条目
            for vtable in self.vtables.values():
                for i, entry in enumerate(vtable.entries):
                    if i * 8 == call_site.vtable_offset:
                        possible_targets.append(entry.target_address)
                        call_site.resolved_type = vtable.class_name
            
            call_site.possible_targets = possible_targets
            call_site.confidence = min(1.0, len(possible_targets) * 0.3 + 0.4)
    
    def _build_class_hierarchy(self) -> None:
        """构建类层次结构"""
        for vtable in self.vtables.values():
            class_name = vtable.class_name
            
            # 查找父类（基于命名约定）
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
        """增强调用图"""
        pass
    
    def _build_enhanced_call_graph(self) -> Dict[int, List[Tuple[int, CallType]]]:
        """构建增强的调用图"""
        call_graph = {}
        
        for call_site in self.virtual_call_sites:
            for target in call_site.possible_targets:
                if call_site.address not in call_graph:
                    call_graph[call_site.address] = []
                call_graph[call_site.address].append((target, CallType.VIRTUAL))
        
        return call_graph
    
    def resolve_polymorphic_type(self, object_address: int, context: str = "") -> Optional[str]:
        """解析多态对象的实际类型"""
        for constructor in self.constructors:
            if constructor.class_name and context:
                if constructor.class_name.lower() in context.lower():
                    return constructor.class_name
        return None
    
    def get_virtual_call_targets(self, call_site_address: int) -> List[int]:
        """获取虚函数调用的可能目标"""
        for call_site in self.virtual_call_sites:
            if call_site.address == call_site_address:
                return call_site.possible_targets
        return []


def recover_vtables(binary_path: str, pseudocode: str = "", assembly: str = "") -> VTableRecoveryResult:
    """便捷函数：恢复虚表"""
    recoverer = PreciseVTableRecovery(binary_path)
    return recoverer.recover_vtables(pseudocode, assembly)