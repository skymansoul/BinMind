import os
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

class FieldType(Enum):
    INT8 = "int8_t"
    INT16 = "int16_t"
    INT32 = "int32_t"
    INT64 = "int64_t"
    UINT8 = "uint8_t"
    UINT16 = "uint16_t"
    UINT32 = "uint32_t"
    UINT64 = "uint64_t"
    CHAR = "char"
    CHAR_PTR = "char*"
    VOID_PTR = "void*"
    INT = "int"
    UINT = "unsigned int"
    LONG = "long"
    FLOAT = "float"
    DOUBLE = "double"
    STRUCT = "struct"
    UNION = "union"
    ARRAY = "array"
    FUNCTION_PTR = "function_ptr"
    UNKNOWN = "unknown"

class AccessType(Enum):
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"
    UNKNOWN = "unknown"
@dataclass
class FieldInfo:
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

class StructDefinition:
    __slots__ = ('name', 'fields', 'size', 'alignment', 'is_union', 'parent_struct', 'nested_structs', 'source_function', 'description',)

    def __init__(self, name, fields, size=0, alignment=4, is_union=False, parent_struct=None, nested_structs=None, source_function='', description=''):
        self.name = name
        self.fields = fields
        self.size = size
        self.alignment = alignment
        self.is_union = is_union
        self.parent_struct = parent_struct
        self.nested_structs = nested_structs
        self.source_function = source_function
        self.description = description

    def __post_init__(self):
        if self.nested_structs is None:
            self.nested_structs = []

@dataclass
class MemoryAccess:
    address: int
    offset: int
    size: int
    access_type: AccessType
    instruction_address: int
    function_name: str
    context: str = ''

@dataclass
class StructRecoveryResult:
    structs: List[StructDefinition]
    num_structs: int
    recovered_fields: int
    avg_confidence: float
    source_functions: List[str]
    warnings: List[str]

class StructRecovery:
    TYPE_PATTERNS = {
        FieldType.CHAR: [b'strlen', b'strcpy', b'strcat', b'memcmp', b'puts', b'printf', b'fgets', b'getc'],
        FieldType.CHAR_PTR: [b'strcpy', b'strcat', b'strlen', b'fgets', b'sscanf', b'snprintf', b'gets', b'puts', b'strcmp', b'strstr', b'strchr'],
        FieldType.INT32: [b'atoi', b'itoa', b'sprintf', b'scanf', b'abs', b'sqrt', b'rand', b'srand'],
        FieldType.INT64: [b'_atoi64', b'_itoa64', b'_stscanf', b'lldiv', b'llabs'],
        FieldType.FLOAT: [b'sqrtf', b'cosf', b'sinf', b'tanf', b'printf', b'scanf'],
        FieldType.DOUBLE: [b'sqrt', b'cos', b'sin', b'tan', b'printf', b'scanf'],
        FieldType.FUNCTION_PTR: [b'CreateThread', b'_beginthread', b'pthread_create', b'calloc'],
    }

    SIZE_TO_TYPE = {
        1: [FieldType.INT8, FieldType.UINT8, FieldType.CHAR],
        2: [FieldType.INT16, FieldType.UINT16],
        4: [FieldType.INT32, FieldType.UINT32, FieldType.INT, FieldType.UINT, FieldType.FLOAT],
        8: [FieldType.INT64, FieldType.UINT64, FieldType.LONG, FieldType.DOUBLE],
    }

    def __init__(self, binary_path: str = None):
        self.binary_path = binary_path
        self.memory_accesses: List[MemoryAccess] = []
        self.structs: List[StructDefinition] = []
        self.type_hints: Dict[str, FieldType] = {}

    def add_memory_access(self, access: MemoryAccess):
        self.memory_accesses.append(access)

    def add_memory_accesses(self, accesses: List[MemoryAccess]):
        self.memory_accesses.extend(accesses)

    def _extract_access_patterns(self) -> Dict[int, List[MemoryAccess]]:
        patterns: Dict[int, List[MemoryAccess]] = {}
        for access in self.memory_accesses:
            base_addr = access.address - access.offset
            if base_addr not in patterns:
                patterns[base_addr] = []
            patterns[base_addr].append(access)
        return patterns

    def _infer_field_type(self, accesses: List[MemoryAccess]) -> Tuple[FieldType, float]:
        if not accesses:
            return FieldType.UNKNOWN, 0.0
        sizes = set(a.size for a in accesses)
        if len(sizes) == 1:
            size = list(sizes)[0]
            if size in self.SIZE_TO_TYPE:
                candidates = self.SIZE_TO_TYPE[size]
                for candidate in candidates:
                    for a in accesses:
                        for p in self.TYPE_PATTERNS.get(candidate, []):
                            if p in a.context.lower().encode('utf-8'):
                                return candidate, 0.8
                return candidates[0], 0.5
        return FieldType.UNKNOWN, 0.3

    def _cluster_fields(self, accesses: List[MemoryAccess]) -> List[FieldInfo]:
        offset_map: Dict[int, List[MemoryAccess]] = {}
        for a in accesses:
            offset_map.setdefault(a.offset, []).append(a)
        fields = []
        for offset, accs in sorted(offset_map.items()):
            size = sorted(set(a.size for a in accs))[-1] if accs else 4
            ftype, conf = self._infer_field_type(accs)
            atypes = set(a.access_type for a in accs)
            fields.append(FieldInfo(name=f'field_{offset:04X}', offset=offset, size=size,
                                     field_type=ftype,
                                     is_pointer=size in [4, 8] and any(b'ptr' in a.context.lower().encode() for a in accs),
                                     access_type=AccessType.READ_WRITE if len(atypes) > 1 else list(atypes)[0],
                                     confidence=conf,
                                     comment=f"从 {len(accs)} 次访问infer"))
        return fields

    def _calculate_struct_size(self, fields: List[FieldInfo]) -> int:
        return fields[-1].offset + fields[-1].size if fields else 0

    def _detect_nested_structs(self, struct: StructDefinition) -> List[str]:
        return [f"{struct.name}_{f.name}" for f in struct.fields if f.field_type == FieldType.STRUCT or f.is_pointer]

    def _generate_field_name(self, field: FieldInfo, index: int) -> str:
        prefixes = {FieldType.CHAR: 'char', FieldType.CHAR_PTR: 'str', FieldType.INT8: 'int8',
                    FieldType.INT16: 'int16', FieldType.INT32: 'int32', FieldType.INT64: 'int64',
                    FieldType.UINT8: 'uint8', FieldType.UINT16: 'uint16', FieldType.UINT32: 'uint32',
                    FieldType.UINT64: 'uint64', FieldType.FLOAT: 'float', FieldType.DOUBLE: 'double',
                    FieldType.VOID_PTR: 'ptr', FieldType.FUNCTION_PTR: 'func'}
        return f"{prefixes.get(field.field_type, 'field')}_{index}"

    def _analyze_single_function(self, function_name: str, accesses: List[MemoryAccess]) -> List[StructDefinition]:
        structs = []
        for base_addr, base_accs in self._extract_access_patterns().items():
            if len(base_accs) < 2:
                continue
            fields = self._cluster_fields(base_accs)
            if len(fields) < 2:
                continue
            struct = StructDefinition(name=f'struct_{function_name}_{len(structs)}', fields=fields,
                                      size=self._calculate_struct_size(fields), alignment=4,
                                      source_function=function_name,
                                      description=f"从函数 {function_name} 的memory访问moderestore")
            struct.nested_structs = self._detect_nested_structs(struct)
            for i, f in enumerate(struct.fields):
                f.name = self._generate_field_name(f, i)
            structs.append(struct)
        return structs

    def _validate_structs(self) -> List[str]:
        warnings = []
        for s in self.structs:
            if s.size == 0:
                warnings.append(f"结构体 {s.name} size为0")
            for f in s.fields:
                if f.offset >= s.size:
                    warnings.append(f"field {f.name} offset {f.offset} 超出结构体range")
                if f.offset + f.size > s.size:
                    warnings.append(f"field {f.name} 超出结构体boundary")
        return warnings

    def analyze(self, functions: List[str] = None) -> StructRecoveryResult:
        if not self.memory_accesses:
            logger.warning("没有memory访问记录，无法restore结构体")
            return StructRecoveryResult([], 0, 0, 0.0, [], [])
        accs = [a for a in self.memory_accesses if a.function_name in functions] if functions else self.memory_accesses
        if not accs:
            logger.warning("没有match的memory访问记录")
            return StructRecoveryResult([], 0, 0, 0.0, [], [])
        for fn in set(a.function_name for a in accs):
            self.structs.extend(self._analyze_single_function(fn, [a for a in accs if a.function_name == fn]))
        warnings = self._validate_structs()
        total_fields = sum(len(s.fields) for s in self.structs)
        total_conf = sum(f.confidence for s in self.structs for f in s.fields)
        return StructRecoveryResult(self.structs, len(self.structs), total_fields,
                                     total_conf / total_fields if total_fields else 0.0,
                                     list(set(a.function_name for a in accs)), warnings)

    def generate_c_code(self, structs: List[StructDefinition] = None) -> str:
        lines = []
        for s in (structs or self.structs):
            lines.append(f"// {s.description}")
            lines.append(f"{'union' if s.is_union else 'struct'} {s.name} {{")
            for f in s.fields:
                t = f.field_type.value + ('*' if f.is_pointer else '') + (f'[{f.array_size}]' if f.array_size > 0 else '')
                lines.append(f"    {t} {f.name}; /* offset: 0x{f.offset:04X}, size: {f.size}, confidence: {f.confidence:.2f} */")
            lines.append(f"}}; /* size: {s.size} bytes */\n")
        return '\n'.join(lines)

    def generate_header_file(self, output_path: str, structs: List[StructDefinition] = None) -> bool:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("// auto-generated的结构体定义头file\n// 通过binary_analysis自动restore\n// ============================================\n\n#pragma once\n\n")
                f.write(self.generate_c_code(structs))
            logger.info(f"结构体头file已生成: {output_path}")
            return True
        except Exception as e:
            logger.error(f"生成头filefailed: {e}")
            return False

    def get_struct_by_name(self, name: str) -> Optional[StructDefinition]:
        for s in self.structs:
            if s.name == name:
                return s
        return None

    def get_structs_by_function(self, function_name: str) -> List[StructDefinition]:
        return [s for s in self.structs if s.source_function == function_name]

    def get_analysis_summary(self) -> Dict[str, Any]:
        if not self.structs:
            self.analyze()
        total_fields = sum(len(s.fields) for s in self.structs)
        return {'num_structs': len(self.structs), 'total_fields': total_fields,
                'avg_confidence': sum(f.confidence for s in self.structs for f in s.fields) / max(1, total_fields),
                'source_functions': list(set(s.source_function for s in self.structs)),
                'structs': [{'name': s.name, 'size': s.size, 'num_fields': len(s.fields),
                             'source_function': s.source_function, 'nested_structs': s.nested_structs} for s in self.structs]}

    def refine_struct_name(self, struct_name: str, new_name: str) -> bool:
        for s in self.structs:
            if s.name == struct_name:
                s.name = new_name
                return True
        return False

    def refine_field_name(self, struct_name: str, field_name: str, new_name: str) -> bool:
        s = self.get_struct_by_name(struct_name)
        if s:
            for f in s.fields:
                if f.name == field_name:
                    f.name = new_name
                    return True
        return False


