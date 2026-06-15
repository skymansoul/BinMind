import os
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class FieldType(Enum):
    """字段类型枚举"""
    INT8 = 'int8_t'
    INT16 = 'int16_t'
    INT32 = 'int32_t'
    INT64 = 'int64_t'
    UINT8 = 'uint8_t'
    UINT16 = 'uint16_t'
    UINT32 = 'uint32_t'
    UINT64 = 'uint64_t'
    CHAR = 'char'
    CHAR_PTR = 'char*'
    VOID_PTR = 'void*'
    INT = 'int'
    UINT = 'unsigned int'
    LONG = 'long'
    FLOAT = 'float'
    DOUBLE = 'double'
    STRUCT = 'struct'
    UNION = 'union'
    ARRAY = 'array'
    FUNCTION_PTR = 'function_ptr'
    UNKNOWN = 'unknown'

class AccessType(Enum):
    """访问类型枚举"""
    READ = 'read'
    WRITE = 'write'
    READ_WRITE = 'read_write'
    UNKNOWN = 'unknown'

@dataclass
class FieldInfo:
    """字段信息"""
    name: str
    offset: int
    size: int
    field_type: FieldType = FieldType.UNKNOWN
    is_pointer: bool = False
    array_size: int = 0
    access_type: AccessType = AccessType.UNKNOWN
    alignment: int = 4
    comment: str = ''
    confidence: float = 0.0

@dataclass
class StructDefinition:
    """结构体定义"""
    name: str
    fields: List[FieldInfo]
    size: int = 0
    alignment: int = 4
    is_union: bool = False
    parent_struct: Optional[str] = None
    nested_structs: List[str] = None
    source_function: str = ''
    description: str = ''
    
    def __post_init__(self):
        if self.nested_structs is None:
            self.nested_structs = []

@dataclass
class MemoryAccess:
    """内存访问记录"""
    address: int
    offset: int
    size: int
    access_type: AccessType
    instruction_address: int
    function_name: str
    context: str = ''

@dataclass
class StructRecoveryResult:
    """结构体恢复结果"""
    structs: List[StructDefinition]
    num_structs: int
    recovered_fields: int
    avg_confidence: float
    source_functions: List[str]
    warnings: List[str]

class StructRecovery:
    """结构体自动恢复引擎"""
    
    # 类型推断模式
    TYPE_PATTERNS = {
        FieldType.CHAR: [
            b'strlen', b'strcpy', b'strcat', b'memcmp',
            b'puts', b'printf', b'fgets', b'getc',
        ],
        FieldType.CHAR_PTR: [
            b'strcpy', b'strcat', b'strlen', b'fgets',
            b'sscanf', b'snprintf', b'gets', b'puts',
            b'strcmp', b'strstr', b'strchr',
        ],
        FieldType.INT32: [
            b'atoi', b'itoa', b'sprintf', b'scanf',
            b'abs', b'sqrt', b'rand', b'srand',
        ],
        FieldType.INT64: [
            b'_atoi64', b'_itoa64', b'_stscanf',
            b'lldiv', b'llabs',
        ],
        FieldType.FLOAT: [
            b'sqrtf', b'cosf', b'sinf', b'tanf',
            b'printf', b'scanf',
        ],
        FieldType.DOUBLE: [
            b'sqrt', b'cos', b'sin', b'tan',
            b'printf', b'scanf',
        ],
        FieldType.FUNCTION_PTR: [
            b'CreateThread', b'_beginthread',
            b'pthread_create', b'calloc',
        ],
    }
    
    SIZE_TO_TYPE = {
        1: [FieldType.INT8, FieldType.UINT8, FieldType.CHAR],
        2: [FieldType.INT16, FieldType.UINT16],
        4: [FieldType.INT32, FieldType.UINT32, FieldType.INT, FieldType.UINT, FieldType.FLOAT],
        8: [FieldType.INT64, FieldType.UINT64, FieldType.LONG, FieldType.DOUBLE],
    }
    
    def __init__(self, binary_path: str = None):
        """初始化结构体恢复引擎"""
        self.binary_path = binary_path
        self.memory_accesses: List[MemoryAccess] = []
        self.structs: List[StructDefinition] = []
        self.type_hints: Dict[str, FieldType] = {}
        
    def add_memory_access(self, access: MemoryAccess):
        """添加内存访问记录"""
        self.memory_accesses.append(access)
        
    def add_memory_accesses(self, accesses: List[MemoryAccess]):
        """批量添加内存访问记录"""
        self.memory_accesses.extend(accesses)
        
    def _extract_access_patterns(self) -> Dict[int, List[MemoryAccess]]:
        """提取访问模式，按基址分组"""
        patterns: Dict[int, List[MemoryAccess]] = {}
        
        for access in self.memory_accesses:
            base_addr = access.address - access.offset
            if base_addr not in patterns:
                patterns[base_addr] = []
            patterns[base_addr].append(access)
        
        return patterns
    
    def _infer_field_type(self, accesses: List[MemoryAccess]) -> Tuple[FieldType, float]:
        """根据访问模式推断字段类型"""
        if not accesses:
            return FieldType.UNKNOWN, 0.0
        
        sizes = set(a.size for a in accesses)
        
        if len(sizes) == 1:
            size = list(sizes)[0]
            if size in self.SIZE_TO_TYPE:
                candidates = self.SIZE_TO_TYPE[size]
                
                for candidate in candidates:
                    patterns = self.TYPE_PATTERNS.get(candidate, [])
                    for access in accesses:
                        for pattern in patterns:
                            if pattern in access.context.lower().encode('utf-8'):
                                return candidate, 0.8
                    
                return candidates[0], 0.5
        
        return FieldType.UNKNOWN, 0.3
    
    def _cluster_fields(self, accesses: List[MemoryAccess]) -> List[FieldInfo]:
        """聚类访问偏移为字段"""
        fields: List[FieldInfo] = []
        offset_to_accesses: Dict[int, List[MemoryAccess]] = {}
        
        for access in accesses:
            if access.offset not in offset_to_accesses:
                offset_to_accesses[access.offset] = []
            offset_to_accesses[access.offset].append(access)
        
        for offset, offset_accesses in sorted(offset_to_accesses.items()):
            sizes = sorted(set(a.size for a in offset_accesses))
            size = sizes[-1] if sizes else 4
            
            inferred_type, confidence = self._infer_field_type(offset_accesses)
            
            access_types = set(a.access_type for a in offset_accesses)
            access_type = AccessType.READ_WRITE if len(access_types) > 1 else list(access_types)[0]
            
            field = FieldInfo(
                name=f'field_{offset:04X}',
                offset=offset,
                size=size,
                field_type=inferred_type,
                is_pointer=size in [4, 8] and any(b'ptr' in a.context.lower().encode() for a in offset_accesses),
                access_type=access_type,
                confidence=confidence,
                comment=f"从 {len(offset_accesses)} 次访问推断"
            )
            fields.append(field)
        
        return fields
    
    def _calculate_struct_size(self, fields: List[FieldInfo]) -> int:
        """计算结构体大小"""
        if not fields:
            return 0
        
        last_field = fields[-1]
        return last_field.offset + last_field.size
    
    def _detect_nested_structs(self, struct: StructDefinition) -> List[str]:
        """检测嵌套结构体"""
        nested_names = []
        
        for field in struct.fields:
            if field.field_type == FieldType.STRUCT or field.is_pointer:
                nested_name = f"{struct.name}_{field.name}"
                nested_names.append(nested_name)
        
        return nested_names
    
    def _generate_field_name(self, field: FieldInfo, index: int) -> str:
        """生成字段名称"""
        type_prefixes = {
            FieldType.CHAR: 'char',
            FieldType.CHAR_PTR: 'str',
            FieldType.INT8: 'int8',
            FieldType.INT16: 'int16',
            FieldType.INT32: 'int32',
            FieldType.INT64: 'int64',
            FieldType.UINT8: 'uint8',
            FieldType.UINT16: 'uint16',
            FieldType.UINT32: 'uint32',
            FieldType.UINT64: 'uint64',
            FieldType.FLOAT: 'float',
            FieldType.DOUBLE: 'double',
            FieldType.VOID_PTR: 'ptr',
            FieldType.FUNCTION_PTR: 'func',
        }
        
        prefix = type_prefixes.get(field.field_type, 'field')
        return f"{prefix}_{index}"
    
    def _analyze_single_function(self, function_name: str, accesses: List[MemoryAccess]) -> List[StructDefinition]:
        """分析单个函数的结构体"""
        structs = []
        patterns = self._extract_access_patterns()
        
        for base_addr, base_accesses in patterns.items():
            if len(base_accesses) < 2:
                continue
            
            fields = self._cluster_fields(base_accesses)
            if len(fields) < 2:
                continue
            
            struct_size = self._calculate_struct_size(fields)
            
            struct = StructDefinition(
                name=f'struct_{function_name}_{len(structs)}',
                fields=fields,
                size=struct_size,
                alignment=4,
                source_function=function_name,
                description=f"从函数 {function_name} 的内存访问模式恢复"
            )
            
            struct.nested_structs = self._detect_nested_structs(struct)
            
            for i, field in enumerate(struct.fields):
                field.name = self._generate_field_name(field, i)
            
            structs.append(struct)
        
        return structs
    
    def _validate_structs(self) -> List[str]:
        """验证恢复的结构体"""
        warnings = []
        
        for struct in self.structs:
            if struct.size == 0:
                warnings.append(f"结构体 {struct.name} 大小为0")
            
            for field in struct.fields:
                if field.offset >= struct.size:
                    warnings.append(f"字段 {field.name} 偏移 {field.offset} 超出结构体范围")
                
                if field.offset + field.size > struct.size:
                    warnings.append(f"字段 {field.name} 超出结构体边界")
        
        return warnings
    
    def analyze(self, functions: List[str] = None) -> StructRecoveryResult:
        """执行结构体恢复分析"""
        if not self.memory_accesses:
            logger.warning("没有内存访问记录，无法恢复结构体")
            return StructRecoveryResult(
                structs=[],
                num_structs=0,
                recovered_fields=0,
                avg_confidence=0.0,
                source_functions=[],
                warnings=[]
            )
        
        if functions:
            filtered_accesses = [a for a in self.memory_accesses if a.function_name in functions]
        else:
            filtered_accesses = self.memory_accesses
        
        if not filtered_accesses:
            logger.warning("没有匹配的内存访问记录")
            return StructRecoveryResult(
                structs=[],
                num_structs=0,
                recovered_fields=0,
                avg_confidence=0.0,
                source_functions=[],
                warnings=[]
            )
        
        function_names = set(a.function_name for a in filtered_accesses)
        
        for func_name in function_names:
            func_accesses = [a for a in filtered_accesses if a.function_name == func_name]
            structs = self._analyze_single_function(func_name, func_accesses)
            self.structs.extend(structs)
        
        warnings = self._validate_structs()
        
        total_fields = sum(len(s.fields) for s in self.structs)
        total_confidence = sum(f.confidence for s in self.structs for f in s.fields)
        avg_confidence = total_confidence / total_fields if total_fields > 0 else 0.0
        
        return StructRecoveryResult(
            structs=self.structs,
            num_structs=len(self.structs),
            recovered_fields=total_fields,
            avg_confidence=avg_confidence,
            source_functions=list(function_names),
            warnings=warnings
        )
    
    def generate_c_code(self, structs: List[StructDefinition] = None) -> str:
        """生成C语言结构体定义代码"""
        code_lines = []
        target_structs = structs or self.structs
        
        for struct in target_structs:
            struct_type = 'union' if struct.is_union else 'struct'
            code_lines.append(f"// {struct.description}")
            code_lines.append(f"{struct_type} {struct.name} {{")
            
            for field in struct.fields:
                type_str = field.field_type.value
                if field.is_pointer:
                    type_str += '*'
                if field.array_size > 0:
                    type_str += f'[{field.array_size}]'
                
                comment = f"/* offset: 0x{field.offset:04X}, size: {field.size}, confidence: {field.confidence:.2f} */"
                code_lines.append(f"    {type_str} {field.name}; {comment}")
            
            code_lines.append(f"}}; /* size: {struct.size} bytes */")
            code_lines.append("")
        
        return '\n'.join(code_lines)
    
    def generate_header_file(self, output_path: str, structs: List[StructDefinition] = None) -> bool:
        """生成C语言头文件"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("// 自动生成的结构体定义头文件\n")
                f.write("// 通过二进制分析自动恢复\n")
                f.write("// ============================================\n\n")
                f.write("#pragma once\n\n")
                
                code = self.generate_c_code(structs)
                f.write(code)
            
            logger.info(f"结构体头文件已生成: {output_path}")
            return True
        except Exception as e:
            logger.error(f"生成头文件失败: {e}")
            return False
    
    def get_struct_by_name(self, name: str) -> Optional[StructDefinition]:
        """根据名称查找结构体"""
        for struct in self.structs:
            if struct.name == name:
                return struct
        return None
    
    def get_structs_by_function(self, function_name: str) -> List[StructDefinition]:
        """获取指定函数中的结构体"""
        return [s for s in self.structs if s.source_function == function_name]
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        if not self.structs:
            self.analyze()
        
        return {
            'num_structs': len(self.structs),
            'total_fields': sum(len(s.fields) for s in self.structs),
            'avg_confidence': sum(f.confidence for s in self.structs for f in s.fields) / max(1, sum(len(s.fields) for s in self.structs)),
            'source_functions': list(set(s.source_function for s in self.structs)),
            'structs': [{
                'name': s.name,
                'size': s.size,
                'num_fields': len(s.fields),
                'source_function': s.source_function,
                'nested_structs': s.nested_structs,
            } for s in self.structs]
        }
    
    def refine_struct_name(self, struct_name: str, new_name: str) -> bool:
        """重命名结构体"""
        for struct in self.structs:
            if struct.name == struct_name:
                struct.name = new_name
                return True
        return False
    
    def refine_field_name(self, struct_name: str, field_name: str, new_name: str) -> bool:
        """重命名字段"""
        struct = self.get_struct_by_name(struct_name)
        if struct:
            for field in struct.fields:
                if field.name == field_name:
                    field.name = new_name
                    return True
        return False