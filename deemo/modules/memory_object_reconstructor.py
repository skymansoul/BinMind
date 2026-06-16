"""
内存对象重构模块

功能:
    1. 从内存转储或运行时内存中重构对象结构
    2. 分析对象生命周期和引用关系
    3. 识别对象类型和字段布局
    4. 支持多种内存分配器分析

核心技术:
    - 内存模式识别
    - 对象边界检测
    - 引用追踪
    - 类型推断
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AllocatorType(Enum):
    """内存分配器类型"""
    PTMALLOC = "ptmalloc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    MIMALLOC = "mimalloc"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class ObjectType(Enum):
    """对象类型枚举"""
    STRUCT = "struct"
    CLASS = "class"
    ARRAY = "array"
    STRING = "string"
    VECTOR = "vector"
    MAP = "map"
    LIST = "list"
    TREE = "tree"
    UNKNOWN = "unknown"


@dataclass
class MemoryObject:
    """内存对象"""
    address: int
    size: int
    object_type: ObjectType
    fields: Dict[str, Any] = field(default_factory=dict)
    references: List[int] = field(default_factory=list)
    allocator: AllocatorType = AllocatorType.UNKNOWN
    is_freed: bool = False
    confidence: float = 0.0


@dataclass
class ObjectField:
    """对象字段"""
    name: str
    offset: int
    size: int
    value: Any = None
    is_pointer: bool = False
    pointer_target: Optional[int] = None


@dataclass
class ReconstructionResult:
    """重构结果"""
    objects: List[MemoryObject] = field(default_factory=list)
    object_graph: Dict[int, List[int]] = field(default_factory=dict)
    type_definitions: Dict[str, List[ObjectField]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


class MemoryObjectReconstructor:
    """内存对象重构器"""
    
    def __init__(self, memory_dump_path: str = "", allocator_type: AllocatorType = AllocatorType.UNKNOWN):
        """初始化重构器"""
        self.memory_dump_path = memory_dump_path
        self.allocator_type = allocator_type
        self.objects: List[MemoryObject] = []
        self.object_graph: Dict[int, List[int]] = {}
        self.type_definitions: Dict[str, List[ObjectField]] = {}
        
        logger.info(f"内存对象重构器初始化完成，分配器类型: {allocator_type.value}")
    
    def reconstruct(self, memory_data: bytes = None, start_address: int = 0) -> ReconstructionResult:
        """执行内存对象重构"""
        logger.info("开始内存对象重构")
        
        result = ReconstructionResult()
        
        try:
            if memory_data is None and self.memory_dump_path:
                memory_data = self._load_memory_dump()
            
            if memory_data:
                self._detect_allocator_type(memory_data)
                self._scan_for_objects(memory_data, start_address)
                self._analyze_object_references(memory_data)
                self._infer_object_types()
                self._build_object_graph()
                
                result.objects = self.objects
                result.object_graph = self.object_graph
                result.type_definitions = self.type_definitions
                result.analysis_success = True
                
                logger.info(f"内存对象重构完成，发现 {len(self.objects)} 个对象")
            else:
                result.warnings.append("无法加载内存数据")
                
        except Exception as e:
            logger.error(f"内存对象重构失败: {e}")
            result.warnings.append(f"重构过程中发生错误: {e}")
        
        return result
    
    def _load_memory_dump(self) -> Optional[bytes]:
        """加载内存转储文件"""
        try:
            with open(self.memory_dump_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"加载内存转储失败: {e}")
            return None
    
    def _detect_allocator_type(self, memory_data: bytes) -> None:
        """检测内存分配器类型"""
        allocator_signatures = {
            AllocatorType.PTMALLOC: [0x00000000, 0xffffffff],
            AllocatorType.JEMALLOC: [0x00000000, 0x00000001],
            AllocatorType.TCMALLOC: [0x00000000, 0x00000002],
        }
        
        # 检查内存中的分配器特征
        for allocator, signatures in allocator_signatures.items():
            for sig in signatures:
                if sig in memory_data[:1024]:
                    self.allocator_type = allocator
                    logger.debug(f"检测到分配器类型: {allocator.value}")
                    return
    
    def _scan_for_objects(self, memory_data: bytes, start_address: int) -> None:
        """扫描内存中的对象"""
        # 模拟扫描对象
        chunk_size = 64
        offset = 0
        
        while offset < len(memory_data):
            chunk = memory_data[offset:offset + chunk_size]
            
            if len(chunk) >= 16:
                # 检查是否可能是对象（包含有效指针）
                potential_object = self._analyze_chunk(chunk, start_address + offset)
                if potential_object:
                    self.objects.append(potential_object)
            
            offset += chunk_size
    
    def _analyze_chunk(self, chunk: bytes, address: int) -> Optional[MemoryObject]:
        """分析内存块是否为对象"""
        # 检查是否包含有效指针模式
        pointer_count = 0
        references = []
        
        for i in range(0, len(chunk) - 8, 8):
            try:
                potential_ptr = int.from_bytes(chunk[i:i+8], 'little')
                if potential_ptr > 0x10000 and potential_ptr < 0x7fffffffffff:
                    pointer_count += 1
                    references.append(potential_ptr)
            except Exception:
                pass
        
        if pointer_count >= 1:
            obj = MemoryObject(
                address=address,
                size=len(chunk),
                object_type=ObjectType.UNKNOWN,
                references=references,
                allocator=self.allocator_type,
                confidence=0.5 + pointer_count * 0.1
            )
            return obj
        
        return None
    
    def _analyze_object_references(self, memory_data: bytes) -> None:
        """分析对象引用关系"""
        for obj in self.objects:
            for ref_addr in obj.references:
                # 检查引用地址是否指向已知对象
                for target_obj in self.objects:
                    if target_obj.address <= ref_addr < target_obj.address + target_obj.size:
                        if obj.address not in self.object_graph:
                            self.object_graph[obj.address] = []
                        self.object_graph[obj.address].append(target_obj.address)
    
    def _infer_object_types(self) -> None:
        """推断对象类型"""
        for obj in self.objects:
            # 根据引用数量和模式推断类型
            ref_count = len(obj.references)
            
            if ref_count == 0:
                obj.object_type = ObjectType.STRUCT
            elif ref_count == 1:
                obj.object_type = ObjectType.STRING
            elif ref_count >= 2 and ref_count <= 4:
                obj.object_type = ObjectType.VECTOR
            elif ref_count > 4:
                obj.object_type = ObjectType.MAP
            
            # 更新置信度
            obj.confidence = min(1.0, obj.confidence + 0.2)
    
    def _build_object_graph(self) -> None:
        """构建对象图"""
        # 确保所有对象都在图中
        for obj in self.objects:
            if obj.address not in self.object_graph:
                self.object_graph[obj.address] = []
    
    def reconstruct_object_at_address(self, memory_data: bytes, address: int) -> Optional[MemoryObject]:
        """重构指定地址的对象"""
        # 计算相对偏移
        if address >= 0:
            offset = address
            if offset < len(memory_data):
                chunk = memory_data[offset:offset + 256]
                return self._analyze_chunk(chunk, address)
        return None
    
    def get_object_fields(self, obj: MemoryObject, memory_data: bytes) -> List[ObjectField]:
        """获取对象的字段"""
        fields = []
        offset = obj.address
        
        for i in range(0, min(obj.size, 256), 8):
            try:
                value = int.from_bytes(memory_data[offset + i:offset + i + 8], 'little')
                is_pointer = value > 0x10000 and value < 0x7fffffffffff
                
                field = ObjectField(
                    name=f"field_{i}",
                    offset=i,
                    size=8,
                    value=value,
                    is_pointer=is_pointer,
                    pointer_target=value if is_pointer else None
                )
                fields.append(field)
            except Exception:
                pass
        
        return fields


def reconstruct_objects(memory_dump_path: str = "", memory_data: bytes = None) -> ReconstructionResult:
    """便捷函数：重构内存对象"""
    reconstructor = MemoryObjectReconstructor(memory_dump_path)
    return reconstructor.reconstruct(memory_data)