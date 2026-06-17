"""
内存对象重构模块

功能:
    1. 从内存转储或运行时内存中重构对象结构
    2. 分析对象生命周期和引用关系
    3. 识别对象类型和字段布局
    4. 支持多种内存分配器分析
    5. 结合DWARF/PDB类型信息重构C++/Rust对象

核心技术:
    - 内存模式识别
    - 对象边界检测
    - 引用追踪
    - 类型推断
    - DWARF/PDB调试信息解析
"""

import os
import re
import logging
import struct
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import elftools
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


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
class TypeInfo:
    """类型信息"""
    name: str
    size: int
    align: int
    type_kind: str  # 'struct', 'class', 'union', 'enum', 'typedef'
    fields: List['FieldInfo'] = field(default_factory=list)
    base_classes: List[str] = field(default_factory=list)
    template_params: List[str] = field(default_factory=list)
    is_polymorphic: bool = False
    vtable_offset: int = 0


@dataclass
class FieldInfo:
    """字段信息"""
    name: str
    offset: int
    size: int
    type_name: str
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[int] = None
    bit_offset: int = 0
    bit_size: int = 0


@dataclass
class DWARFTypeCache:
    """DWARF类型缓存"""
    types: Dict[str, TypeInfo] = field(default_factory=dict)
    type_by_offset: Dict[int, TypeInfo] = field(default_factory=dict)
    structs: Dict[str, TypeInfo] = field(default_factory=dict)
    classes: Dict[str, TypeInfo] = field(default_factory=dict)


class DWARFParser:
    """DWARF调试信息解析器"""
    
    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.type_cache = DWARFTypeCache()
        self._parse_dwarf()
    
    def _parse_dwarf(self):
        """解析DWARF信息"""
        if not self.binary_path or not os.path.exists(self.binary_path):
            return
        
        try:
            if ELFTOOLS_AVAILABLE:
                from elftools.elf.elffile import ELFFile
                
                with open(self.binary_path, 'rb') as f:
                    elf = ELFFile(f)
                    if not elf.has_dwarf_info():
                        return
                    
                    dwarf_info = elf.get_dwarf_info()
                    
                    for CU in dwarf_info.iter_CUs():
                        for DIE in CU.iter_DIEs():
                            self._process_die(DIE)
            else:
                self._parse_dwarf_fallback()
        except Exception as e:
            logger.debug(f"DWARF解析失败: {e}")
    
    def _process_die(self, die):
        """处理DWARF DIE条目"""
        tag = die.tag
        name = die.get_attribute('DW_AT_name')
        name = name.value.decode('utf-8') if name else None
        
        if tag == 'DW_TAG_structure_type':
            self._parse_struct(die, name)
        elif tag == 'DW_TAG_class_type':
            self._parse_class(die, name)
        elif tag == 'DW_TAG_union_type':
            self._parse_union(die, name)
    
    def _parse_struct(self, die, name: Optional[str]):
        """解析结构体类型"""
        if not name:
            return
        
        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0
        
        type_info = TypeInfo()
            name=name,
            size=size,
            align=0,
            type_kind='struct',
            fields=[],
            base_classes=[],
            is_polymorphic=False
        
        
        for child in die.iter_children():
            if child.tag == 'DW_TAG_member':
                field = self._parse_field(child)
                if field:
                    type_info.fields.append(field)
        
        self.type_cache.types[name] = type_info
        self.type_cache.structs[name] = type_info
    
    def _parse_class(self, die, name: Optional[str]):
        """解析类类型"""
        if not name:
            return
        
        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0
        
        type_info = TypeInfo()
            name=name,
            size=size,
            align=0,
            type_kind='class',
            fields=[],
            base_classes=[],
            is_polymorphic=False
        
        
        for child in die.iter_children():
            if child.tag == 'DW_TAG_member':
                field = self._parse_field(child)
                if field:
                    type_info.fields.append(field)
            elif child.tag == 'DW_TAG_inheritance':
                base_name = child.get_attribute('DW_AT_name')
                if base_name:
                    type_info.base_classes.append(base_name.value.decode('utf-8'

            elif child.tag == 'DW_TAG_vtable_entry':
                type_info.is_polymorphic = True
        
        self.type_cache.types[name] = type_info
        self.type_cache.classes[name] = type_info
    
    def _parse_union(self, die, name: Optional[str]):
        """解析联合体类型"""
        if not name:
            return
        
        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0
        
        type_info = TypeInfo()
            name=name,
            size=size,
            align=0,
            type_kind='union',
            fields=[],
            base_classes=[]
        
        
        for child in die.iter_children():
            if child.tag == 'DW_TAG_member':
                field = self._parse_field(child)
                if field:
                    type_info.fields.append(field)
        
        self.type_cache.types[name] = type_info
    
    def _parse_field(self, die) -> Optional[FieldInfo]:
        """解析字段信息"""
        name_attr = die.get_attribute('DW_AT_name')
        if not name_attr:
            return None
        
        name = name_attr.value.decode('utf-8')
        
        offset_attr = die.get_attribute('DW_AT_data_member_location')
        offset = 0,
        if offset_attr:
            if isinstance(offset_attr.value, int):
                offset = offset_attr.value
        
        type_name = 'void'
        type_attr = die.get_attribute('DW_AT_type')
        if type_attr:
            try:
                type_die = type_attr.value,
                if hasattr(type_die, 'get_attribute'):
                    type_name_attr = type_die.get_attribute('DW_AT_name')
                    if type_name_attr:
                        type_name = type_name_attr.value.decode('utf-8')
            except:
                pass
        
        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0
        
        return FieldInfo(
            name=name,
            offset=offset,
            size=size,
            type_name=type_name,
            is_pointer=type_name.endswith('*'),
            is_array='[' in type_name)
        

    
    def _parse_dwarf_fallback(self):
        """DWARF解析降级方案"""
        logger.debug("使用DWARF解析降级方案")
    
    def get_type_info(self, type_name: str) -> Optional[TypeInfo]:
        """获取类型信息"""
        return self.type_cache.types.get(type_name)
    
    def get_struct_info(self, struct_name: str) -> Optional[TypeInfo]:
        """获取结构体信息"""
        return self.type_cache.structs.get(struct_name)
    
    def get_class_info(self, class_name: str) -> Optional[TypeInfo]:
        """获取类信息"""
        return self.type_cache.classes.get(class_name)
    
    def get_all_types(self) -> List[str]:
        """获取所有类型名称"""
        return list(self.type_cache.types.keys(



class PDBParser:
    """PDB调试信息解析器 (Windows)"""
    
    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.type_cache = DWARFTypeCache()
        self._parse_pdb()
    
    def _parse_pdb(self):
        """解析PDB信息"""
        if not self.binary_path or not os.path.exists(self.binary_path):
            return
        
        try:
            pdb_path = self._find_pdb_path()
            if pdb_path:
                self._parse_pdb_file(pdb_path)
        except Exception as e:
            logger.debug(f"PDB解析失败: {e}")
    
    def _find_pdb_path(self) -> Optional[str]:
        """查找PDB文件路径"""
        pdb_path = self.binary_path + '.pdb',
        if os.path.exists(pdb_path):
            return pdb_path
        
        pdb_dir = os.path.join(os.path.dirname(self.binary_path), 'pdb')
        pdb_name = os.path.basename(self.binary_path) + '.pdb'
        pdb_path = os.path.join(pdb_dir, pdb_name)
        if os.path.exists(pdb_path):
            return pdb_path
        
        return None
    
    def _parse_pdb_file(self, pdb_path: str):
        """解析PDB文件"""
        self._parse_pdb_fallback()
    
    def _parse_pdb_fallback(self):
        """PDB解析降级方案"""
        logger.debug("使用PDB解析降级方案")
    
    def get_type_info(self, type_name: str) -> Optional[TypeInfo]:
        """获取类型信息"""
        return self.type_cache.types.get(type_name)
    
    def get_struct_info(self, struct_name: str) -> Optional[TypeInfo]:
        """获取结构体信息"""
        return self.type_cache.structs.get(struct_name)
    
    def get_class_info(self, class_name: str) -> Optional[TypeInfo]:
        """获取类信息"""
        return self.type_cache.classes.get(class_name)
    
    def get_all_types(self) -> List[str]:
        """获取所有类型名称"""
        return list(self.type_cache.types.keys(



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
    
    def __init__(self, memory_dump_path: str = "", allocator_type: AllocatorType = AllocatorType.UNKNOWN, binary_path: str = ""):
        """初始化重构器"""
        self.memory_dump_path = memory_dump_path
        self.allocator_type = allocator_type
        self.objects: List[MemoryObject] = []
        self.object_graph: Dict[int, List[int]] = {}
        self.type_definitions: Dict[str, List[ObjectField]] = {}
        self.binary_path = binary_path
        self.dwarf_parser: Optional[DWARFParser] = None
        self.pdb_parser: Optional[PDBParser] = None
        
        if binary_path:
            self._init_type_parsers()
        
        logger.info(f"内存对象重构器初始化完成，分配器类型: {allocator_type.value}")
    
    def _init_type_parsers(self):
        """初始化类型解析器"""
        if self.binary_path.endswith('.exe') or self.binary_path.endswith('.dll'):
            self.pdb_parser = PDBParser(self.binary_path)
            logger.info("已初始化PDB解析器")
        else:
            self.dwarf_parser = DWARFParser(self.binary_path)
            logger.info("已初始化DWARF解析器")
    
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
            obj = MemoryObject()
                address=address,
                size=len(chunk),
                object_type=ObjectType.UNKNOWN,
                references=references,
                allocator=self.allocator_type,
                confidence=0.5 + pointer_count * 0.1
            
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
            type_info = self._find_matching_type(obj)
            if type_info:
                obj.object_type = ObjectType.CLASS if type_info.type_kind == 'class' else ObjectType.STRUCT
                obj.fields['type_info'] = type_info
                obj.confidence = min(1.0, obj.confidence + 0.3)
                logger.debug(f"为对象 {hex(obj.address)} 匹配类型: {type_info.name}")
            else:
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
                
                obj.confidence = min(1.0, obj.confidence + 0.2)
    
    def _find_matching_type(self, obj: MemoryObject) -> Optional[TypeInfo]:
        """根据对象大小查找匹配的类型"""
        if self.dwarf_parser:
            for type_name, type_info in self.dwarf_parser.type_cache.types.items():
                if type_info.size > 0 and abs(type_info.size - obj.size) <= 8:
                    return type_info
        if self.pdb_parser:
            for type_name, type_info in self.pdb_parser.type_cache.types.items():
                if type_info.size > 0 and abs(type_info.size - obj.size) <= 8:
                    return type_info
        return None
    
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
            offset = address,
            if offset < len(memory_data):
                chunk = memory_data[offset:offset + 256]
                return self._analyze_chunk(chunk, address)
        return None
    
    def get_object_fields(self, obj: MemoryObject, memory_data: bytes) -> List[ObjectField]:
        """获取对象的字段"""
        fields = []
        offset = obj.address
        
        type_info = obj.fields.get('type_info')
        if type_info:
            fields = self._get_fields_from_type_info(obj, type_info, memory_data)
        else:
            for i in range(0, min(obj.size, 256), 8):
                try:
                    value = int.from_bytes(memory_data[offset + i:offset + i + 8], 'little')
                    is_pointer = value > 0x10000 and value < 0x7fffffffffff
                    
                    field = ObjectField()
                        name=f"field_{i}",
                        offset=i,
                        size=8,
                        value=value,
                        is_pointer=is_pointer,
                        pointer_target=value if is_pointer else None
                    
                    fields.append(field)
                except Exception:
                    pass
        
        return fields
    
    def _get_fields_from_type_info(self, obj: MemoryObject, type_info: TypeInfo, memory_data: bytes) -> List[ObjectField]:
        """使用类型信息获取字段"""
        fields = []
        offset = obj.address
        
        for field_info in type_info.fields:
            try:
                field_offset = field_info.offset
                field_size = field_info.size
                field_end = field_offset + field_size
                
                if field_end > obj.size:
                    continue
                
                raw_value = memory_data[offset + field_offset:offset + field_end]
                
                value = self._parse_field_value(raw_value, field_info)
                
                field = ObjectField()
                    name=field_info.name,
                    offset=field_offset,
                    size=field_size,
                    value=value,
                    is_pointer=field_info.is_pointer,
                    pointer_target=value if field_info.is_pointer and value else None
                
                fields.append(field)
            except Exception as e:
                logger.debug(f"解析字段 {field_info.name} 失败: {e}")
        
        return fields
    
    def _parse_field_value(self, raw_value: bytes, field_info: FieldInfo) -> Any:
        """解析字段值"""
        if field_info.is_pointer:
            if len(raw_value) >= 8:
                return int.from_bytes(raw_value[:8], 'little')
            elif len(raw_value) >= 4:
                return int.from_bytes(raw_value[:4], 'little')
        elif field_info.type_name == 'int' or field_info.type_name == 'long':
            if len(raw_value) >= 8:
                return int.from_bytes(raw_value[:8], 'little', signed=True)
            elif len(raw_value) >= 4:
                return int.from_bytes(raw_value[:4], 'little', signed=True)
        elif field_info.type_name == 'unsigned int' or field_info.type_name == 'unsigned long':
            if len(raw_value) >= 8:
                return int.from_bytes(raw_value[:8], 'little', signed=False)
            elif len(raw_value) >= 4:
                return int.from_bytes(raw_value[:4], 'little', signed=False)
        elif field_info.type_name == 'float':
            if len(raw_value) >= 4:
                return struct.unpack('<f', raw_value[:4])[0]
        elif field_info.type_name == 'double':
            if len(raw_value) >= 8:
                return struct.unpack('<d', raw_value[:8])[0]
        
        return raw_value.hex( if raw_value else None)


def reconstruct_objects(memory_dump_path: str = "", memory_data: bytes = None) -> ReconstructionResult:
    """便捷函数：重构内存对象"""
    reconstructor = MemoryObjectReconstructor(memory_dump_path)
    return reconstructor.reconstruct(memory_data)))))))