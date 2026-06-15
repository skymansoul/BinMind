"""
自动数据类型推断与伪代码增强模块

功能:
    1. 利用静态分析技术从二进制中推断变量数据类型
    2. 推断数组边界和结构体字段
    3. 将推断结果以注释形式插入反编译伪代码
    4. 提升伪代码可读性，辅助人工分析
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class InferredType(Enum):
    """
    推断的数据类型枚举
    """
    INT = "int"
    UNSIGNED_INT = "unsigned int"
    SHORT = "short"
    UNSIGNED_SHORT = "unsigned short"
    CHAR = "char"
    UNSIGNED_CHAR = "unsigned char"
    LONG = "long"
    UNSIGNED_LONG = "unsigned long"
    FLOAT = "float"
    DOUBLE = "double"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    STRING = "string"
    SIZE_T = "size_t"
    VOID = "void"
    BOOL = "bool"
    UNKNOWN = "unknown"


@dataclass
class TypeInfo:
    """
    类型推断信息
    """
    name: str
    inferred_type: InferredType
    confidence: float
    source: str  # 推断来源
    size: int = 0  # 大小（字节）
    array_size: int = 0  # 数组大小
    struct_fields: List[Dict[str, Any]] = field(default_factory=list)  # 结构体字段
    pointer_target: str = ""  # 指针指向的类型
    comment: str = ""  # 注释说明


@dataclass
class StructField:
    """
    结构体字段信息
    """
    offset: int
    name: str
    type_info: TypeInfo
    size: int


@dataclass
class TypeInferenceResult:
    """
    类型推断结果
    """
    variables: List[TypeInfo] = field(default_factory=list)
    structs: Dict[str, List[StructField]] = field(default_factory=dict)
    arrays: Dict[str, int] = field(default_factory=dict)  # 变量名 -> 数组大小
    enhanced_pseudocode: str = ""
    confidence_score: float = 0.0
    warnings: List[str] = field(default_factory=list)


# 指令类型推断规则
INSTRUCTION_TYPE_RULES = {
    # 有符号整数操作
    'sar': InferredType.INT,
    'imul': InferredType.INT,
    'idiv': InferredType.INT,
    
    # 无符号整数操作
    'shr': InferredType.UNSIGNED_INT,
    'mul': InferredType.UNSIGNED_INT,
    'div': InferredType.UNSIGNED_INT,
    
    # 浮点操作
    'fadd': InferredType.FLOAT,
    'fsub': InferredType.FLOAT,
    'fmul': InferredType.FLOAT,
    'fdiv': InferredType.FLOAT,
    'fld': InferredType.FLOAT,
    'fstp': InferredType.FLOAT,
    'addss': InferredType.FLOAT,  # SSE
    'subss': InferredType.FLOAT,
    'mulss': InferredType.FLOAT,
    'divss': InferredType.FLOAT,
    'addsd': InferredType.DOUBLE,  # SSE double
    'subsd': InferredType.DOUBLE,
    'mulsd': InferredType.DOUBLE,
    'divsd': InferredType.DOUBLE,
    
    # 字符操作
    'movsb': InferredType.CHAR,
    'cmpsb': InferredType.CHAR,
    
    # 指针操作
    'lea': InferredType.POINTER,
    'mov': InferredType.POINTER,  # 可能是指针
}

# 库函数参数类型推断
LIBRARY_FUNC_TYPES = {
    'strlen': {'return': InferredType.SIZE_T, 'param0': InferredType.STRING},
    'strcpy': {'return': InferredType.POINTER, 'param0': InferredType.STRING, 'param1': InferredType.STRING},
    'strncpy': {'return': InferredType.POINTER, 'param0': InferredType.STRING, 'param1': InferredType.STRING, 'param2': InferredType.SIZE_T},
    'strcmp': {'return': InferredType.INT, 'param0': InferredType.STRING, 'param1': InferredType.STRING},
    'strncmp': {'return': InferredType.INT, 'param0': InferredType.STRING, 'param1': InferredType.STRING, 'param2': InferredType.SIZE_T},
    'malloc': {'return': InferredType.POINTER, 'param0': InferredType.SIZE_T},
    'free': {'param0': InferredType.POINTER},
    'calloc': {'return': InferredType.POINTER, 'param0': InferredType.SIZE_T, 'param1': InferredType.SIZE_T},
    'realloc': {'return': InferredType.POINTER, 'param0': InferredType.POINTER, 'param1': InferredType.SIZE_T},
    'memcpy': {'return': InferredType.POINTER, 'param0': InferredType.POINTER, 'param1': InferredType.POINTER, 'param2': InferredType.SIZE_T},
    'memset': {'return': InferredType.POINTER, 'param0': InferredType.POINTER, 'param1': InferredType.INT, 'param2': InferredType.SIZE_T},
    'printf': {'param0': InferredType.STRING},
    'sprintf': {'param0': InferredType.STRING, 'param1': InferredType.STRING},
    'snprintf': {'param0': InferredType.STRING, 'param1': InferredType.SIZE_T, 'param2': InferredType.STRING},
    'scanf': {'param0': InferredType.STRING},
    'fopen': {'return': InferredType.POINTER, 'param0': InferredType.STRING, 'param1': InferredType.STRING},
    'fread': {'return': InferredType.SIZE_T, 'param0': InferredType.POINTER, 'param1': InferredType.SIZE_T, 'param2': InferredType.SIZE_T, 'param3': InferredType.POINTER},
    'fwrite': {'return': InferredType.SIZE_T, 'param0': InferredType.POINTER, 'param1': InferredType.SIZE_T, 'param2': InferredType.SIZE_T, 'param3': InferredType.POINTER},
    'fgets': {'return': InferredType.STRING, 'param0': InferredType.STRING, 'param1': InferredType.INT, 'param2': InferredType.POINTER},
    'atoi': {'return': InferredType.INT, 'param0': InferredType.STRING},
    'atol': {'return': InferredType.LONG, 'param0': InferredType.STRING},
    'atof': {'return': InferredType.DOUBLE, 'param0': InferredType.STRING},
    'strtol': {'return': InferredType.LONG, 'param0': InferredType.STRING, 'param1': InferredType.POINTER, 'param2': InferredType.INT},
    'strtoul': {'return': InferredType.UNSIGNED_LONG, 'param0': InferredType.STRING, 'param1': InferredType.POINTER, 'param2': InferredType.INT},
    'getchar': {'return': InferredType.INT},
    'putchar': {'return': InferredType.INT, 'param0': InferredType.INT},
    'socket': {'return': InferredType.INT, 'param0': InferredType.INT, 'param1': InferredType.INT, 'param2': InferredType.INT},
    'bind': {'return': InferredType.INT, 'param0': InferredType.INT, 'param1': InferredType.POINTER, 'param2': InferredType.SIZE_T},
    'recv': {'return': InferredType.INT, 'param0': InferredType.INT, 'param1': InferredType.POINTER, 'param2': InferredType.SIZE_T, 'param3': InferredType.INT},
    'send': {'return': InferredType.INT, 'param0': InferredType.INT, 'param1': InferredType.POINTER, 'param2': InferredType.SIZE_T, 'param3': InferredType.INT},
}

# 常见结构体模式
STRUCT_PATTERNS = [
    # 通过偏移访问推断结构体
    {'pattern': r'\*\(\(.*?\)\s*\+\s*(\d+)\)', 'description': '偏移访问'},
    {'pattern': r'\[([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*(\d+)\]', 'description': '基址+偏移'},
]


class TypeInferrer:
    """
    数据类型推断器
    
    利用静态分析技术从二进制中推断变量数据类型、数组边界和结构体字段。
    """
    
    def __init__(
        self,
        use_angr: bool = False,
        min_confidence: float = 0.5
    ):
        """
        初始化类型推断器
        
        Args:
            use_angr: 是否使用 angr 进行深度分析
            min_confidence: 最小置信度阈值
        """
        self.use_angr = use_angr
        self.min_confidence = min_confidence
        self.inferred_types: Dict[str, TypeInfo] = {}
        self.struct_candidates: Dict[str, List[StructField]] = {}
        
        logger.info(f"类型推断器初始化完成，使用 angr: {use_angr}")
    
    def infer_from_pseudocode(
        self,
        pseudocode: str,
        assembly: str = None,
        binary_info: Dict[str, Any] = None
    ) -> TypeInferenceResult:
        """
        从伪代码推断类型
        
        Args:
            pseudocode: 反编译伪代码
            assembly: 汇编代码（可选）
            binary_info: 二进制信息（可选）
            
        Returns:
            类型推断结果
        """
        result = TypeInferenceResult()
        
        # 解析伪代码中的变量声明
        variables = self._parse_variable_declarations(pseudocode)
        
        # 推断变量类型
        for var_name, var_info in variables.items():
            type_info = self._infer_variable_type(
                var_name, var_info, pseudocode, assembly, binary_info
            )
            if type_info.confidence >= self.min_confidence:
                result.variables.append(type_info)
                self.inferred_types[var_name] = type_info
        
        # 推断结构体
        structs = self._infer_structs(pseudocode, result.variables)
        result.structs = structs
        
        # 推断数组大小
        arrays = self._infer_array_sizes(pseudocode, result.variables, binary_info)
        result.arrays = arrays
        
        # 生成增强伪代码
        enhanced = self._enhance_pseudocode(pseudocode, result)
        result.enhanced_pseudocode = enhanced
        
        # 计算置信度评分
        if result.variables:
            result.confidence_score = sum(v.confidence for v in result.variables) / len(result.variables)
        
        return result
    
    def _parse_variable_declarations(
        self,
        pseudocode: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        解析伪代码中的变量声明
        
        Args:
            pseudocode: 伪代码
            
        Returns:
            变量信息字典
        """
        variables = {}
        
        # 匹配变量声明模式
        # 格式: type name; 或 type name = value;
        patterns = [
            r'(int|char|long|short|float|double|void|unsigned\s+\w+|size_t|ssize_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'(\w+\s*\*+)\s+([a-zA-Z_][a-zA-Z0-9_]*)',  # 指针
            r'(\w+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*(\d+)?\s*\]',  # 数组
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                if len(match) >= 2:
                    type_str = match[0]
                    var_name = match[1]
                    array_size = int(match[2]) if len(match) > 2 and match[2] else 0
                    
                    variables[var_name] = {
                        'declared_type': type_str,
                        'array_size': array_size,
                        'is_pointer': '*' in type_str,
                    }
        
        # 匹配未声明的变量（通过使用推断）
        # 格式: name = value 或 name(...)
        usage_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;,]+)'
        usage_matches = re.findall(usage_pattern, pseudocode)
        
        for var_name, value in usage_matches:
            if var_name not in variables and not self._is_function_name(var_name, pseudocode):
                variables[var_name] = {
                    'declared_type': 'unknown',
                    'assigned_value': value.strip(),
                }
        
        return variables
    
    def _is_function_name(
        self,
        name: str,
        pseudocode: str
    ) -> bool:
        """
        判断是否为函数名
        
        Args:
            name: 名称
            pseudocode: 伪代码
            
        Returns:
            是否为函数名
        """
        # 检查是否有函数定义
        func_def_pattern = r'\b' + re.escape(name) + r'\s*\([^)]*\)\s*\{'
        if re.search(func_def_pattern, pseudocode):
            return True
        
        # 检查是否为库函数
        if name in LIBRARY_FUNC_TYPES:
            return True
        
        # 检查是否有函数调用特征
        call_pattern = rf'{name}\s*\([^)]*\)\s*;'
        if re.search(call_pattern, pseudocode):
            return True
        
        return False
    
    def _infer_variable_type(
        self,
        var_name: str,
        var_info: Dict[str, Any],
        pseudocode: str,
        assembly: str = None,
        binary_info: Dict[str, Any] = None
    ) -> TypeInfo:
        """
        推断单个变量的类型
        
        Args:
            var_name: 变量名
            var_info: 变量信息
            pseudocode: 伪代码
            assembly: 汇编代码
            binary_info: 二进制信息
            
        Returns:
            类型推断信息
        """
        # 如果已有声明类型，优先使用
        declared_type = var_info.get('declared_type', 'unknown')
        
        if declared_type != 'unknown':
            inferred_type = self._map_declared_type(declared_type)
            return TypeInfo(
                name=var_name,
                inferred_type=inferred_type,
                confidence=0.9,
                source='declaration',
                size=self._get_type_size(inferred_type),
                array_size=var_info.get('array_size', 0),
                comment=f'// [declared: {declared_type}]'
            )
        
        # 从赋值推断
        assigned_value = var_info.get('assigned_value', '')
        if assigned_value:
            inferred_type = self._infer_from_value(assigned_value)
            if inferred_type != InferredType.UNKNOWN:
                return TypeInfo(
                    name=var_name,
                    inferred_type=inferred_type,
                    confidence=0.7,
                    source='assignment',
                    comment=f'// [inferred: {inferred_type.value}, from assignment]'
                )
        
        # 从使用推断
        inferred_type = self._infer_from_usage(var_name, pseudocode)
        if inferred_type != InferredType.UNKNOWN:
            return TypeInfo(
                name=var_name,
                inferred_type=inferred_type,
                confidence=0.6,
                source='usage',
                comment=f'// [inferred: {inferred_type.value}, from usage]'
            )
        
        # 从汇编推断
        if assembly:
            inferred_type = self._infer_from_assembly(var_name, assembly)
            if inferred_type != InferredType.UNKNOWN:
                return TypeInfo(
                    name=var_name,
                    inferred_type=inferred_type,
                    confidence=0.65,
                    source='assembly',
                    comment=f'// [inferred: {inferred_type.value}, from assembly]'
                )
        
        # 从库函数参数推断
        inferred_type = self._infer_from_library_call(var_name, pseudocode)
        if inferred_type != InferredType.UNKNOWN:
            return TypeInfo(
                name=var_name,
                inferred_type=inferred_type,
                confidence=0.75,
                source='library_function',
                comment=f'// [inferred: {inferred_type.value}, from library function]'
            )
        
        # 默认返回未知类型
        return TypeInfo(
            name=var_name,
            inferred_type=InferredType.UNKNOWN,
            confidence=0.0,
            source='none',
            comment='// [type unknown, needs manual analysis]'
        )
    
    def _map_declared_type(
        self,
        declared_type: str
    ) -> InferredType:
        """
        将声明类型映射到推断类型
        
        Args:
            declared_type: 声明的类型
            
        Returns:
            推断类型
        """
        declared_lower = declared_type.lower().strip()
        
        type_map = {
            'int': InferredType.INT,
            'char': InferredType.CHAR,
            'long': InferredType.LONG,
            'short': InferredType.SHORT,
            'float': InferredType.FLOAT,
            'double': InferredType.DOUBLE,
            'void': InferredType.VOID,
            'size_t': InferredType.SIZE_T,
            'ssize_t': InferredType.LONG,
            'bool': InferredType.BOOL,
            'unsigned int': InferredType.UNSIGNED_INT,
            'unsigned char': InferredType.UNSIGNED_CHAR,
            'unsigned long': InferredType.UNSIGNED_LONG,
            'unsigned short': InferredType.UNSIGNED_SHORT,
        }
        
        # 检查指针
        if '*' in declared_type:
            return InferredType.POINTER
        
        # 检查数组
        if '[' in declared_type:
            return InferredType.ARRAY
        
        return type_map.get(declared_lower, InferredType.UNKNOWN)
    
    def _get_type_size(
        self,
        inferred_type: InferredType
    ) -> int:
        """
        获取类型大小
        
        Args:
            inferred_type: 推断类型
            
        Returns:
            大小（字节）
        """
        size_map = {
            InferredType.CHAR: 1,
            InferredType.UNSIGNED_CHAR: 1,
            InferredType.SHORT: 2,
            InferredType.UNSIGNED_SHORT: 2,
            InferredType.INT: 4,
            InferredType.UNSIGNED_INT: 4,
            InferredType.LONG: 8,
            InferredType.UNSIGNED_LONG: 8,
            InferredType.FLOAT: 4,
            InferredType.DOUBLE: 8,
            InferredType.POINTER: 8,
            InferredType.SIZE_T: 8,
            InferredType.BOOL: 1,
        }
        
        return size_map.get(inferred_type, 0)
    
    def _infer_from_value(
        self,
        value: str
    ) -> InferredType:
        """
        从赋值值推断类型
        
        Args:
            value: 赋值值
            
        Returns:
            推断类型
        """
        value = value.strip()
        
        # 字符串字面量
        if value.startswith('"') and value.endswith('"'):
            return InferredType.STRING
        
        # 字符字面量
        if value.startswith("'") and value.endswith("'"):
            return InferredType.CHAR
        
        # 浮点数
        if '.' in value and not value.startswith('0x'):
            try:
                float(value)
                return InferredType.DOUBLE if 'f' not in value.lower() else InferredType.FLOAT
            except ValueError:
                pass
        
        # 整数（十进制）
        if value.isdigit():
            return InferredType.INT
        
        # 整数（十六进制）
        if value.startswith('0x') or value.startswith('-0x'):
            return InferredType.INT
        
        # 地址/指针
        if value.startswith('&') or 'malloc' in value or 'calloc' in value:
            return InferredType.POINTER
        
        # NULL
        if value.lower() in ['null', 'nullptr', '0']:
            return InferredType.POINTER
        
        return InferredType.UNKNOWN
    
    def _infer_from_usage(
        self,
        var_name: str,
        pseudocode: str
    ) -> InferredType:
        """
        从使用方式推断类型
        
        Args:
            var_name: 变量名
            pseudocode: 伪代码
            
        Returns:
            推断类型
        """
        # 查找变量的使用模式
        
        # 指针解引用
        if re.search(rf'\*\s*{var_name}', pseudocode) or re.search(rf'{var_name}\s*\[', pseudocode):
            return InferredType.POINTER
        
        # 字符串函数使用
        string_funcs = ['strlen', 'strcpy', 'strcmp', 'strcat', 'printf', 'sprintf']
        for func in string_funcs:
            if re.search(rf'{func}\s*\([^)]*{var_name}', pseudocode):
                return InferredType.STRING
        
        # 内存函数使用
        if re.search(rf'malloc\s*\([^)]*\)\s*=\s*{var_name}', pseudocode):
            return InferredType.POINTER
        
        # 数值比较
        if re.search(rf'{var_name}\s*[<>=!]+\s*\d+', pseudocode):
            return InferredType.INT
        
        # 循环变量
        if re.search(rf'for\s*\([^)]*{var_name}\s*=\s*\d+', pseudocode):
            return InferredType.INT
        
        return InferredType.UNKNOWN
    
    def _infer_from_assembly(
        self,
        var_name: str,
        assembly: str
    ) -> InferredType:
        """
        从汇编代码推断类型
        
        Args:
            var_name: 变量名
            assembly: 汇编代码
            
        Returns:
            推断类型
        """
        # 查找与变量相关的指令
        
        for instruction, type_enum in INSTRUCTION_TYPE_RULES.items():
            if re.search(rf'{instruction}\s+[^,]*{var_name}', assembly, re.IGNORECASE):
                return type_enum
        
        # 检查寄存器大小
        # 64位寄存器 (rax, rbx, ...) -> long/pointer
        if re.search(rf'[re][a-z]x\s*,\s*{var_name}', assembly):
            return InferredType.LONG
        
        # 32位寄存器 (eax, ebx, ...) -> int
        if re.search(rf'e[a-z]x\s*,\s*{var_name}', assembly):
            return InferredType.INT
        
        # 16位寄存器 (ax, bx, ...) -> short
        if re.search(rf'[a-z]{2}x\s*,\s*{var_name}', assembly) and not re.search(rf'e[a-z]x', assembly):
            return InferredType.SHORT
        
        # 8位寄存器 (al, bl, ...) -> char
        if re.search(rf'[a-z]l\s*,\s*{var_name}', assembly):
            return InferredType.CHAR
        
        return InferredType.UNKNOWN
    
    def _infer_from_library_call(
        self,
        var_name: str,
        pseudocode: str
    ) -> InferredType:
        """
        从库函数调用推断类型
        
        Args:
            var_name: 变量名
            pseudocode: 伪代码
            
        Returns:
            推断类型
        """
        for func_name, type_info in LIBRARY_FUNC_TYPES.items():
            # 检查函数调用
            pattern = rf'{func_name}\s*\(([^)]*)\)'
            matches = re.findall(pattern, pseudocode)
            
            for match in matches:
                params = match.split(',')
                for i, param in enumerate(params):
                    param = param.strip()
                    if param == var_name or var_name in param:
                        param_key = f'param{i}'
                        if param_key in type_info:
                            return type_info[param_key]
        
        return InferredType.UNKNOWN
    
    def _infer_structs(
        self,
        pseudocode: str,
        variables: List[TypeInfo]
    ) -> Dict[str, List[StructField]]:
        """
        推断结构体
        
        Args:
            pseudocode: 伪代码
            variables: 已推断的变量
            
        Returns:
            结构体信息
        """
        structs = {}
        
        # 查找偏移访问模式
        # 格式: *(base + offset) 或 base[offset]
        offset_pattern = r'\*\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*(\d+)\s*\)'
        matches = re.findall(offset_pattern, pseudocode)
        
        for base_var, offset in matches:
            offset_val = int(offset)
            
            if base_var not in structs:
                structs[base_var] = []
            
            # 添加字段
            field_name = f'field_{offset_val}'
            field_type = self._infer_field_type(offset_val)
            
            structs[base_var].append(StructField(
                offset=offset_val,
                name=field_name,
                type_info=TypeInfo(
                    name=field_name,
                    inferred_type=field_type,
                    confidence=0.6,
                    source='offset_access'
                ),
                size=self._get_type_size(field_type)
            ))
        
        # 查找数组索引访问模式
        # 格式: base[index]
        array_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*([a-zA-Z_][a-zA-Z0-9_]*|\d+)\s*\]'
        array_matches = re.findall(array_pattern, pseudocode)
        
        for base_var, index in array_matches:
            # 如果是数字索引，可能是数组而非结构体
            if index.isdigit():
                continue
            
            # 如果索引是变量，可能是结构体字段访问
            if base_var not in structs:
                structs[base_var] = []
        
        # 合并相近偏移为结构体
        for base_var, fields in structs.items():
            # 按偏移排序
            fields.sort(key=lambda f: f.offset)
            
            # 检查是否有合理的结构体布局
            # 假设结构体字段大小为 4/8 字节
            expected_offsets = set()
            for i in range(0, max(f.offset for f in fields) + 8, 4):
                expected_offsets.add(i)
            
            actual_offsets = set(f.offset for f in fields)
            
            # 如果偏移不连续，可能是数组而非结构体
            if len(actual_offsets) < len(expected_offsets) * 0.5:
                # 可能是数组，移除
                if len(fields) < 3:
                    del structs[base_var]
        
        return structs
    
    def _infer_field_type(
        self,
        offset: int
    ) -> InferredType:
        """
        根据偏移推断字段类型
        
        Args:
            offset: 偏移值
            
        Returns:
            推断类型
        """
        # 常见偏移对应类型
        if offset % 8 == 0:
            return InferredType.LONG
        elif offset % 4 == 0:
            return InferredType.INT
        elif offset % 2 == 0:
            return InferredType.SHORT
        else:
            return InferredType.CHAR
    
    def _infer_array_sizes(
        self,
        pseudocode: str,
        variables: List[TypeInfo],
        binary_info: Dict[str, Any] = None
    ) -> Dict[str, int]:
        """
        推断数组大小
        
        Args:
            pseudocode: 伪代码
            variables: 已推断的变量
            binary_info: 二进制信息
            
        Returns:
            数组大小字典
        """
        arrays = {}
        
        # 从声明获取
        for var in variables:
            if var.array_size > 0:
                arrays[var.name] = var.array_size
        
        # 从 malloc 参数推断
        malloc_pattern = r'malloc\s*\(\s*(\d+)\s*\)'
        malloc_matches = re.findall(malloc_pattern, pseudocode)
        
        for size in malloc_matches:
            size_val = int(size)
            # 假设是字符数组
            arrays['malloc_buffer'] = size_val
        
        # 从循环边界推断
        loop_pattern = r'for\s*\([^)]*<\s*(\d+)[^)]*\)'
        loop_matches = re.findall(loop_pattern, pseudocode)
        
        for bound in loop_matches:
            bound_val = int(bound)
            arrays['loop_bound'] = bound_val
        
        # 从比较推断
        cmp_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*(\d+)'
        cmp_matches = re.findall(cmp_pattern, pseudocode)
        
        for var_name, bound in cmp_matches:
            bound_val = int(bound)
            if var_name in arrays:
                arrays[var_name] = max(arrays[var_name], bound_val)
            else:
                arrays[var_name] = bound_val
        
        return arrays
    
    def _enhance_pseudocode(
        self,
        pseudocode: str,
        inference_result: TypeInferenceResult
    ) -> str:
        """
        增强伪代码，添加类型注释
        
        Args:
            pseudocode: 原始伪代码
            inference_result: 推断结果
            
        Returns:
            增强后的伪代码
        """
        enhanced = pseudocode
        
        # 为变量添加类型注释
        for var_info in inference_result.variables:
            if var_info.comment:
                # 查找变量声明位置
                pattern = rf'(\w+\s+{var_info.name}\s*[;=])'
                replacement = rf'\1 {var_info.comment}'
                enhanced = re.sub(pattern, replacement, enhanced)
        
        # 为结构体添加注释
        for struct_name, fields in inference_result.structs.items():
            if fields:
                struct_comment = f'// [struct candidate: {struct_name} with fields at offsets: {", ".join(str(f.offset) for f in fields)}]'
                # 在结构体使用前添加注释
                pattern = rf'({struct_name}\s*[;=])'
                replacement = rf'{struct_comment}\n\1'
                enhanced = re.sub(pattern, replacement, enhanced)
        
        # 为数组添加注释
        for array_name, size in inference_result.arrays.items():
            if size > 0:
                array_comment = f'// [array size inferred: {size}]'
                pattern = rf'({array_name}\s*\[)'
                replacement = rf'\1{array_comment} '
                enhanced = re.sub(pattern, replacement, enhanced)
        
        return enhanced
    
    def enhance_decompilation(
        self,
        pseudocode: str,
        assembly: str = None,
        binary_info: Dict[str, Any] = None
    ) -> Tuple[str, TypeInferenceResult]:
        """
        增强反编译结果
        
        Args:
            pseudocode: 反编译伪代码
            assembly: 汇编代码
            binary_info: 二进制信息
            
        Returns:
            (增强后的伪代码, 推断结果)
        """
        result = self.infer_from_pseudocode(pseudocode, assembly, binary_info)
        
        return result.enhanced_pseudocode, result
    
    def get_type_annotation(
        self,
        var_name: str
    ) -> Optional[str]:
        """
        获取变量的类型注解
        
        Args:
            var_name: 变量名
            
        Returns:
            类型注解字符串
        """
        if var_name in self.inferred_types:
            type_info = self.inferred_types[var_name]
            return f"{type_info.inferred_type.value} {var_name}"
        
        return None


def infer_types(
    pseudocode: str,
    assembly: str = None,
    binary_info: Dict[str, Any] = None,
    min_confidence: float = 0.5
) -> TypeInferenceResult:
    """
    类型推断的便捷函数
    
    Args:
        pseudocode: 反编译伪代码
        assembly: 汇编代码
        binary_info: 二进制信息
        min_confidence: 最小置信度
        
    Returns:
        类型推断结果
    """
    inferrer = TypeInferrer(min_confidence=min_confidence)
    return inferrer.infer_from_pseudocode(pseudocode, assembly, binary_info)


def enhance_pseudocode(
    pseudocode: str,
    assembly: str = None,
    binary_info: Dict[str, Any] = None
) -> str:
    """
    增强伪代码的便捷函数
    
    Args:
        pseudocode: 反编译伪代码
        assembly: 汇编代码
        binary_info: 二进制信息
        
    Returns:
        增强后的伪代码
    """
    inferrer = TypeInferrer()
    enhanced, _ = inferrer.enhance_decompilation(pseudocode, assembly, binary_info)
    return enhanced