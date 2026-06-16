from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import struct
import logging

logger = logging.getLogger(__name__)


class VTableType(Enum):
    """虚函数表类型枚举"""
    STATIC = "static"
    DYNAMIC = "dynamic"
    WEAK = "weak"
    OVERRIDE = "override"


class ClassAccessType(Enum):
    """类访问类型枚举"""
    PUBLIC = "public"
    PROTECTED = "protected"
    PRIVATE = "private"


@dataclass
class VTableEntry:
    """虚函数表条目"""
    address: int
    function_name: Optional[str] = None
    function_address: Optional[int] = None
    offset: int = 0


@dataclass
class VTable:
    """虚函数表"""
    address: int
    entries: List[VTableEntry] = field(default_factory=list)
    vtable_type: VTableType = VTableType.STATIC
    associated_class: Optional[str] = None


@dataclass
class ClassInfo:
    """类信息"""
    name: str
    vtable_address: Optional[int] = None
    vtable: Optional[VTable] = None
    parent_classes: List[Tuple[str, ClassAccessType]] = field(default_factory=list)
    child_classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    size: int = 0
    is_abstract: bool = False


@dataclass
class VTableRecoveryResult:
    """虚函数表恢复结果"""
    vtables: Dict[int, VTable] = field(default_factory=dict)
    classes: Dict[str, ClassInfo] = field(default_factory=dict)
    class_hierarchy: Dict[str, List[str]] = field(default_factory=dict)
    recovered_methods: int = 0
    recovered_classes: int = 0


class VTableScanner:
    """虚函数表扫描器"""
    
    def __init__(self, binary_data: bytes, base_address: int = 0):
        """
        初始化扫描器
        
        Args:
            binary_data: 二进制数据
            base_address: 基地址
        """
        self.binary_data = binary_data
        self.base_address = base_address
        self.pointer_size = 8 if len(binary_data) > 0 else 4
        self.possible_vtables: Set[int] = set()
    
    def _read_pointer(self, offset: int) -> Optional[int]:
        """读取指针值"""
        if offset + self.pointer_size > len(self.binary_data):
            return None
        
        if self.pointer_size == 8:
            return struct.unpack('<Q', self.binary_data[offset:offset+8])[0]
        else:
            return struct.unpack('<I', self.binary_data[offset:offset+4])[0]
    
    def _is_executable_section(self, offset: int) -> bool:
        """检查偏移是否在可执行区域"""
        return True
    
    def scan_for_vtables(self) -> List[int]:
        """扫描虚函数表"""
        logger.info("开始扫描虚函数表...")
        
        vtable_candidates = []
        offset = 0
        
        while offset < len(self.binary_data) - self.pointer_size:
            ptr = self._read_pointer(offset)
            
            if ptr is None:
                break
            
            if self._looks_like_vtable(offset, ptr):
                vtable_candidates.append(self.base_address + offset)
                self.possible_vtables.add(self.base_address + offset)
            
            offset += self.pointer_size
        
        logger.info(f"发现 {len(vtable_candidates)} 个潜在的虚函数表")
        return vtable_candidates
    
    def _looks_like_vtable(self, offset: int, first_ptr: int) -> bool:
        """判断是否看起来像虚函数表"""
        if first_ptr == 0:
            return False
        
        entry_count = 0
        max_entries = 100
        current_offset = offset + self.pointer_size
        
        while entry_count < max_entries:
            ptr = self._read_pointer(current_offset)
            
            if ptr is None:
                break
            
            if ptr == 0:
                break
            
            entry_count += 1
            current_offset += self.pointer_size
        
        return entry_count >= 1 and entry_count <= max_entries


class ClassHierarchyAnalyzer:
    """类层次结构分析器"""
    
    def __init__(self):
        self.classes: Dict[str, ClassInfo] = {}
        self.class_hierarchy: Dict[str, List[str]] = {}
    
    def build_hierarchy(self, vtables: List[VTable]) -> Dict[str, List[str]]:
        """构建类层次结构"""
        logger.info("开始构建类层次结构...")
        
        for vtable in vtables:
            class_name = self._infer_class_name(vtable)
            if class_name not in self.classes:
                self.classes[class_name] = ClassInfo(
                    name=class_name,
                    vtable_address=vtable.address,
                    vtable=vtable
                )
        
        self._detect_inheritance(vtables)
        logger.info(f"构建了 {len(self.class_hierarchy)} 个类继承关系")
        return self.class_hierarchy
    
    def _infer_class_name(self, vtable: VTable) -> str:
        """推断类名"""
        if vtable.associated_class:
            return vtable.associated_class
        
        return f"Class_{hex(vtable.address)[2:]}"
    
    def _detect_inheritance(self, vtables: List[VTable]):
        """检测继承关系"""
        for i, vtable1 in enumerate(vtables):
            for j, vtable2 in enumerate(vtables):
                if i == j:
                    continue
                
                similarity = self._compare_vtables(vtable1, vtable2)
                if similarity > 0.7:
                    class1 = self._infer_class_name(vtable1)
                    class2 = self._infer_class_name(vtable2)
                    
                    if class1 not in self.class_hierarchy:
                        self.class_hierarchy[class1] = []
                    if class2 not in self.class_hierarchy[class1]:
                        self.class_hierarchy[class1].append(class2)
    
    def _compare_vtables(self, v1: VTable, v2: VTable) -> float:
        """比较两个虚函数表的相似度"""
        entries1 = {e.function_address for e in v1.entries if e.function_address}
        entries2 = {e.function_address for e in v2.entries if e.function_address}
        
        if not entries1 and not entries2:
            return 0.0
        
        intersection = entries1 & entries2
        union = entries1 | entries2
        
        return len(intersection) / len(union) if union else 0.0


class VTableRecoveryEngine:
    """
    C++虚函数表恢复引擎
    
    从二进制文件中自动识别和恢复C++虚函数表结构，包括：
    - 虚函数表定位
    - 类层次结构重建
    - 虚函数调用关系分析
    """
    
    def __init__(self):
        """初始化恢复引擎"""
        self.scanner = None
        self.analyzer = ClassHierarchyAnalyzer()
    
    def analyze(self, binary_data: bytes, base_address: int = 0) -> VTableRecoveryResult:
        """
        分析二进制文件，恢复虚函数表
        
        Args:
            binary_data: 二进制数据
            base_address: 基地址
            
        Returns:
            虚函数表恢复结果
        """
        logger.info("开始分析二进制文件中的虚函数表...")
        
        self.scanner = VTableScanner(binary_data, base_address)
        vtable_addresses = self.scanner.scan_for_vtables()
        
        vtables = self._parse_vtables(vtable_addresses)
        self.analyzer.build_hierarchy(list(vtables.values()))
        
        result = VTableRecoveryResult(
            vtables=vtables,
            classes=self.analyzer.classes,
            class_hierarchy=self.analyzer.class_hierarchy,
            recovered_methods=sum(len(v.entries) for v in vtables.values()),
            recovered_classes=len(self.analyzer.classes)
        )
        
        logger.info(f"虚函数表恢复完成: {len(vtables)} 个虚函数表, {result.recovered_methods} 个方法")
        return result
    
    def _parse_vtables(self, addresses: List[int]) -> Dict[int, VTable]:
        """解析虚函数表"""
        vtables = {}
        
        for addr in addresses:
            vtable = self._parse_single_vtable(addr)
            if vtable:
                vtables[addr] = vtable
        
        return vtables
    
    def _parse_single_vtable(self, address: int) -> Optional[VTable]:
        """解析单个虚函数表"""
        if not self.scanner:
            return None
        
        offset = address - self.scanner.base_address
        entries = []
        
        if offset < 0 or offset >= len(self.scanner.binary_data):
            return None
        
        entry_offset = offset
        entry_index = 0
        
        while entry_index < 200:
            func_addr = self.scanner._read_pointer(entry_offset)
            
            if func_addr is None or func_addr == 0:
                break
            
            entries.append(VTableEntry(
                address=entry_offset + self.scanner.base_address,
                function_address=func_addr,
                offset=entry_index
            ))
            
            entry_offset += self.scanner.pointer_size
            entry_index += 1
        
        if not entries:
            return None
        
        return VTable(
            address=address,
            entries=entries,
            vtable_type=VTableType.STATIC
        )
    
    def generate_report(self, result: VTableRecoveryResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 恢复结果
            
        Returns:
            报告字符串
        """
        report = ["=" * 60]
        report.append("C++ 虚函数表恢复报告")
        report.append("=" * 60)
        report.append("")
        report.append(f"恢复的虚函数表数量: {len(result.vtables)}")
        report.append(f"恢复的类数量: {result.recovered_classes}")
        report.append(f"恢复的方法数量: {result.recovered_methods}")
        report.append("")
        report.append("类层次结构:")
        report.append("-" * 40)
        
        for class_name, children in result.class_hierarchy.items():
            report.append(f"{class_name}")
            for child in children:
                report.append(f"  └─ {child}")
        
        report.append("")
        report.append("虚函数表详情:")
        report.append("-" * 40)
        
        for addr, vtable in result.vtables.items():
            report.append(f"VTable: {hex(addr)}")
            report.append(f"  类型: {vtable.vtable_type.value}")
            report.append(f"  关联类: {vtable.associated_class or '未知'}")
            report.append(f"  方法数量: {len(vtable.entries)}")
            
            for entry in vtable.entries[:5]:
                func_addr = hex(entry.function_address) if entry.function_address else "未知"
                report.append(f"    [{entry.offset}] {func_addr}")
            
            if len(vtable.entries) > 5:
                report.append(f"    ... (还有 {len(vtable.entries) - 5} 个)")
        
        return "\n".join(report)
    
    def save_result(self, result: VTableRecoveryResult, filename: str):
        """
        保存结果到文件
        
        Args:
            result: 恢复结果
            filename: 输出文件名
        """
        report = self.generate_report(result)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"结果已保存到 {filename}")