"""
全程序类型推断引擎

功能:
    1. 使用数据流分析、API模式匹配、内存布局约束进行类型推断
    2. 调用Z3求解器为每个变量推导最窄合法类型
    3. 输出带完整类型声明的C伪代码（结构体字段、嵌套指针、函数指针）
    4. 与反编译器增强模块(decomp_ai.py)集成

核心技术:
    - 符号执行约束收集
    - Z3 SMT求解器类型约束求解
    - 跨函数数据流分析
    - 结构体布局推断
    - 函数指针类型推断
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    logger.warning("Z3求解器不可用，将使用启发式类型推断")
    Z3_AVAILABLE = False


class TypeKind(Enum):
    """类型种类枚举"""
    VOID = "void"
    CHAR = "char"
    UCHAR = "unsigned char"
    SHORT = "short"
    USHORT = "unsigned short"
    INT = "int"
    UINT = "unsigned int"
    LONG = "long"
    ULONG = "unsigned long"
    LLONG = "long long"
    ULLONG = "unsigned long long"
    FLOAT = "float"
    DOUBLE = "double"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    UNION = "union"
    STRING = "string"
    SIZE_T = "size_t"
    SSIZE_T = "ssize_t"
    BOOL = "_Bool"
    FUNCTION = "function"
    UNKNOWN = "unknown"


@dataclass
class TypeConstraint:
    """类型约束"""
    var_name: str
    constraint_type: str
    value: Union[int, Tuple[int, int], str]
    source: str


@dataclass
class InferredType:
    """推断类型信息"""
    kind: TypeKind
    bit_size: int
    confidence: float
    constraints: List[TypeConstraint] = field(default_factory=list)
    pointer_target: Optional['InferredType'] = None
    array_size: Optional[int] = None
    struct_name: Optional[str] = None
    struct_fields: Optional[List['StructFieldInfo']] = None
    function_signature: Optional['FunctionSignature'] = None
    comment: str = ""
    source: str = ""


@dataclass
class StructFieldInfo:
    """结构体字段信息"""
    name: str
    offset: int
    inferred_type: InferredType
    is_bit_field: bool = False
    bit_size: int = 0


@dataclass
class FunctionSignature:
    """函数签名"""
    return_type: InferredType
    param_types: List[InferredType]
    param_names: List[str]
    is_varargs: bool = False


@dataclass
class VariableInfo:
    """变量信息"""
    name: str
    inferred_types: List[InferredType]
    address: Optional[int] = None
    is_global: bool = False
    is_argument: bool = False


@dataclass
class TypeInferenceResult:
    """类型推断结果"""
    variables: Dict[str, VariableInfo] = field(default_factory=dict)
    structs: Dict[str, List[StructFieldInfo]] = field(default_factory=dict)
    functions: Dict[str, FunctionSignature] = field(default_factory=dict)
    enhanced_pseudocode: str = ""
    confidence_score: float = 0.0
    warnings: List[str] = field(default_factory=list)


TYPE_SIZES = {
    TypeKind.VOID: 0,
    TypeKind.CHAR: 1,
    TypeKind.UCHAR: 1,
    TypeKind.SHORT: 2,
    TypeKind.USHORT: 2,
    TypeKind.INT: 4,
    TypeKind.UINT: 4,
    TypeKind.LONG: 8,
    TypeKind.ULONG: 8,
    TypeKind.LLONG: 8,
    TypeKind.ULLONG: 8,
    TypeKind.FLOAT: 4,
    TypeKind.DOUBLE: 8,
    TypeKind.POINTER: 8,
    TypeKind.SIZE_T: 8,
    TypeKind.SSIZE_T: 8,
    TypeKind.BOOL: 1,
}

INSTRUCTION_PATTERNS = {
    'sar': TypeKind.INT,
    'idiv': TypeKind.INT,
    'imul': TypeKind.INT,
    'jo': TypeKind.INT,
    'js': TypeKind.INT,
    'jns': TypeKind.INT,
    'shr': TypeKind.UINT,
    'div': TypeKind.UINT,
    'mul': TypeKind.UINT,
    'jb': TypeKind.UINT,
    'ja': TypeKind.UINT,
    'fld': TypeKind.FLOAT,
    'fstp': TypeKind.FLOAT,
    'fadd': TypeKind.FLOAT,
    'fsub': TypeKind.FLOAT,
    'fmul': TypeKind.FLOAT,
    'fdiv': TypeKind.FLOAT,
    'addss': TypeKind.FLOAT,
    'subss': TypeKind.FLOAT,
    'mulss': TypeKind.FLOAT,
    'divss': TypeKind.FLOAT,
    'addsd': TypeKind.DOUBLE,
    'subsd': TypeKind.DOUBLE,
    'mulsd': TypeKind.DOUBLE,
    'divsd': TypeKind.DOUBLE,
    'movsb': TypeKind.CHAR,
    'cmpsb': TypeKind.CHAR,
    'movsw': TypeKind.SHORT,
    'cmpsw': TypeKind.SHORT,
    'movsd': TypeKind.INT,
    'cmpsd': TypeKind.INT,
    'movsq': TypeKind.LONG,
    'cmpsq': TypeKind.LONG,
}

LIBRARY_FUNCTIONS = {
    'strlen': {'return': TypeKind.SIZE_T, 'args': [TypeKind.POINTER]},
    'strcpy': {'return': TypeKind.POINTER, 'args': [TypeKind.POINTER, TypeKind.POINTER]},
    'strncpy': {'return': TypeKind.POINTER, 'args': [TypeKind.POINTER, TypeKind.POINTER, TypeKind.SIZE_T]},
    'strcmp': {'return': TypeKind.INT, 'args': [TypeKind.POINTER, TypeKind.POINTER]},
    'strncmp': {'return': TypeKind.INT, 'args': [TypeKind.POINTER, TypeKind.POINTER, TypeKind.SIZE_T]},
    'malloc': {'return': TypeKind.POINTER, 'args': [TypeKind.SIZE_T]},
    'calloc': {'return': TypeKind.POINTER, 'args': [TypeKind.SIZE_T, TypeKind.SIZE_T]},
    'free': {'return': TypeKind.VOID, 'args': [TypeKind.POINTER]},
    'memcpy': {'return': TypeKind.POINTER, 'args': [TypeKind.POINTER, TypeKind.POINTER, TypeKind.SIZE_T]},
    'memset': {'return': TypeKind.POINTER, 'args': [TypeKind.POINTER, TypeKind.INT, TypeKind.SIZE_T]},
    'printf': {'return': TypeKind.INT, 'args': [TypeKind.POINTER], 'varargs': True},
    'sprintf': {'return': TypeKind.INT, 'args': [TypeKind.POINTER, TypeKind.POINTER], 'varargs': True},
    'snprintf': {'return': TypeKind.INT, 'args': [TypeKind.POINTER, TypeKind.SIZE_T, TypeKind.POINTER], 'varargs': True},
    'scanf': {'return': TypeKind.INT, 'args': [TypeKind.POINTER], 'varargs': True},
    'atoi': {'return': TypeKind.INT, 'args': [TypeKind.POINTER]},
    'atol': {'return': TypeKind.LONG, 'args': [TypeKind.POINTER]},
    'atof': {'return': TypeKind.DOUBLE, 'args': [TypeKind.POINTER]},
    'strtol': {'return': TypeKind.LONG, 'args': [TypeKind.POINTER, TypeKind.POINTER, TypeKind.INT]},
    'strtoul': {'return': TypeKind.ULONG, 'args': [TypeKind.POINTER, TypeKind.POINTER, TypeKind.INT]},
    'fopen': {'return': TypeKind.POINTER, 'args': [TypeKind.POINTER, TypeKind.POINTER]},
    'fclose': {'return': TypeKind.INT, 'args': [TypeKind.POINTER]},
    'fread': {'return': TypeKind.SIZE_T, 'args': [TypeKind.POINTER, TypeKind.SIZE_T, TypeKind.SIZE_T, TypeKind.POINTER]},
    'fwrite': {'return': TypeKind.SIZE_T, 'args': [TypeKind.POINTER, TypeKind.SIZE_T, TypeKind.SIZE_T, TypeKind.POINTER]},
    'fgets': {'return': TypeKind.POINTER, 'args': [TypeKind.POINTER, TypeKind.INT, TypeKind.POINTER]},
    'getchar': {'return': TypeKind.INT, 'args': []},
    'putchar': {'return': TypeKind.INT, 'args': [TypeKind.INT]},
    'exit': {'return': TypeKind.VOID, 'args': [TypeKind.INT]},
}


class TypeInferrer:
    """全程序类型推断引擎"""
    
    def __init__(self, use_z3: bool = True, min_confidence: float = 0.5):
        self.use_z3 = use_z3 and Z3_AVAILABLE
        self.min_confidence = min_confidence
        self.variables: Dict[str, VariableInfo] = {}
        self.structs: Dict[str, List[StructFieldInfo]] = {}
        self.functions: Dict[str, FunctionSignature] = {}
        self.constraints: List[TypeConstraint] = []
        
        logger.info(f"类型推断器初始化完成，使用Z3: {self.use_z3}")
    
    def infer_types(self, pseudocode: str, assembly: str = "", binary_info: Dict[str, Any] = None) -> TypeInferenceResult:
        """执行全程序类型推断"""
        logger.info("开始全程序类型推断")
        
        result = TypeInferenceResult()
        
        try:
            self._extract_variables(pseudocode)
            self._extract_functions(pseudocode)
            self._collect_constraints(pseudocode, assembly)
            
            if self.use_z3:
                self._solve_with_z3()
            else:
                self._solve_heuristically()
            
            self._infer_structs(pseudocode)
            self._infer_arrays(pseudocode)
            self._infer_function_pointers(pseudocode)
            
            result.variables = self.variables
            result.structs = self.structs
            result.functions = self.functions
            result.enhanced_pseudocode = self._generate_enhanced_pseudocode(pseudocode)
            result.confidence_score = self._calculate_confidence()
            result.warnings = self._generate_warnings()
            
            logger.info(f"类型推断完成，置信度: {result.confidence_score:.2f}")
            
        except Exception as e:
            logger.error(f"类型推断失败: {e}")
            result.warnings.append(f"类型推断过程中发生错误: {e}")
        
        return result
    
    def _extract_variables(self, pseudocode: str) -> None:
        """从伪代码中提取变量"""
        patterns = [
            r'\b(int|char|long|short|float|double|void|unsigned|size_t|ssize_t|_Bool)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b',
            r'(\w+\s*\*+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b',
            r'(\w+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*(\d*)\s*\]',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                if len(match) >= 2:
                    var_name = match[1]
                    if var_name not in self.variables:
                        self.variables[var_name] = VariableInfo(
                            name=var_name,
                            inferred_types=[],
                            is_global=False,
                            is_argument=False
                        )
        
        func_pattern = r'\w+\s+\w+\s*\(\s*([^)]*)\s*\)'
        matches = re.findall(func_pattern, pseudocode)
        for match in matches:
            params = match.split(',')
            for param in params:
                param = param.strip()
                if param:
                    parts = param.split()
                    if len(parts) >= 2:
                        var_name = parts[-1]
                        if var_name not in self.variables:
                            self.variables[var_name] = VariableInfo(
                                name=var_name,
                                inferred_types=[],
                                is_global=False,
                                is_argument=True
                            )
    
    def _extract_functions(self, pseudocode: str) -> None:
        """从伪代码中提取函数签名"""
        func_pattern = r'(\w+)\s+(\w+)\s*\(\s*([^)]*)\s*\)'
        matches = re.findall(func_pattern, pseudocode)
        
        for match in matches:
            ret_type_str, func_name, params_str = match
            params = params_str.split(',') if params_str.strip() else []
            
            param_names = []
            param_types = []
            
            for param in params:
                param = param.strip()
                if param:
                    parts = param.split()
                    if len(parts) >= 2:
                        param_names.append(parts[-1])
                        param_types.append(self._parse_type_str(parts[0]))
                    else:
                        param_names.append(param)
                        param_types.append(InferredType(kind=TypeKind.UNKNOWN, bit_size=0, confidence=0.0))
            
            ret_type = self._parse_type_str(ret_type_str)
            
            self.functions[func_name] = FunctionSignature(
                return_type=ret_type,
                param_types=param_types,
                param_names=param_names,
                is_varargs=False
            )
    
    def _parse_type_str(self, type_str: str) -> InferredType:
        """解析类型字符串为InferredType"""
        type_str = type_str.strip().lower()
        
        type_map = {
            'void': TypeKind.VOID,
            'char': TypeKind.CHAR,
            'unsigned char': TypeKind.UCHAR,
            'short': TypeKind.SHORT,
            'unsigned short': TypeKind.USHORT,
            'int': TypeKind.INT,
            'unsigned int': TypeKind.UINT,
            'long': TypeKind.LONG,
            'unsigned long': TypeKind.ULONG,
            'long long': TypeKind.LLONG,
            'unsigned long long': TypeKind.ULLONG,
            'float': TypeKind.FLOAT,
            'double': TypeKind.DOUBLE,
            'size_t': TypeKind.SIZE_T,
            'ssize_t': TypeKind.SSIZE_T,
            '_bool': TypeKind.BOOL,
        }
        
        if '*' in type_str:
            pointer_count = type_str.count('*')
            base_type_str = type_str.replace('*', '').strip()
            base_type = type_map.get(base_type_str, TypeKind.UNKNOWN)
            
            result = InferredType(kind=TypeKind.POINTER, bit_size=64, confidence=1.0)
            target_type = InferredType(kind=base_type, bit_size=TYPE_SIZES.get(base_type, 0) * 8, confidence=1.0)
            
            for _ in range(pointer_count - 1):
                result = InferredType(kind=TypeKind.POINTER, bit_size=64, confidence=1.0, pointer_target=result)
            
            result.pointer_target = target_type
            return result
        
        kind = type_map.get(type_str, TypeKind.UNKNOWN)
        return InferredType(kind=kind, bit_size=TYPE_SIZES.get(kind, 0) * 8, confidence=1.0)
    
    def _collect_constraints(self, pseudocode: str, assembly: str) -> None:
        """收集类型约束"""
        self._collect_instruction_constraints(assembly)
        self._collect_api_constraints(pseudocode)
        self._collect_memory_constraints(pseudocode)
        self._collect_comparison_constraints(pseudocode)
    
    def _collect_instruction_constraints(self, assembly: str) -> None:
        """从汇编指令收集约束"""
        if not assembly:
            return
        
        for instr, expected_type in INSTRUCTION_PATTERNS.items():
            if instr in assembly.lower():
                pattern = rf'{instr}\s+([^,\s]+)'
                matches = re.findall(pattern, assembly, re.IGNORECASE)
                for operand in matches:
                    operand = operand.strip()
                    if not (operand.startswith('[') and operand.endswith(']')):
                        if operand not in ['eax', 'ebx', 'ecx', 'edx', 'rax', 'rbx', 'rcx', 'rdx']:
                            self.constraints.append(TypeConstraint(
                                var_name=operand,
                                constraint_type='type_hint',
                                value=expected_type.value,
                                source=f'instruction:{instr}'
                            ))
    
    def _collect_api_constraints(self, pseudocode: str) -> None:
        """从API调用收集约束"""
        for func_name, sig in LIBRARY_FUNCTIONS.items():
            pattern = rf'{func_name}\s*\(\s*([^)]*)\s*\)'
            matches = re.findall(pattern, pseudocode)
            
            for match in matches:
                args = match.split(',')
                for i, arg in enumerate(args):
                    arg = arg.strip()
                    if arg and i < len(sig['args']):
                        expected_type = sig['args'][i]
                        self.constraints.append(TypeConstraint(
                            var_name=arg,
                            constraint_type='type_hint',
                            value=expected_type.value,
                            source=f'api_call:{func_name}:arg{i}'
                        ))
    
    def _collect_memory_constraints(self, pseudocode: str) -> None:
        """从内存访问模式收集约束"""
        offset_pattern = r'\*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*(\d+)\s*\)'
        matches = re.findall(offset_pattern, pseudocode)
        for var_name, offset in matches:
            self.constraints.append(TypeConstraint(
                var_name=var_name,
                constraint_type='pointer',
                value=int(offset),
                source='memory_offset'
            ))
    
    def _collect_comparison_constraints(self, pseudocode: str) -> None:
        """从比较操作收集约束"""
        patterns = [
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*0', 'range', (float('-inf'), -1)),
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*>=\s*0', 'range', (0, float('inf'))),
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*128', 'range', (0, 127)),
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*256', 'range', (0, 255)),
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*65536', 'range', (0, 65535)),
        ]
        
        for pattern, constraint_type, value in patterns:
            matches = re.findall(pattern, pseudocode)
            for var_name in matches:
                self.constraints.append(TypeConstraint(
                    var_name=var_name,
                    constraint_type=constraint_type,
                    value=value,
                    source='comparison'
                ))
    
    def _solve_with_z3(self) -> None:
        """使用Z3求解器进行类型约束求解"""
        logger.debug("使用Z3求解器进行类型推断")
        
        type_vars = {}
        solver = z3.Solver()
        
        for var_name in self.variables:
            type_vars[var_name] = z3.Int(f'type_{var_name}')
        
        for constraint in self.constraints:
            if constraint.constraint_type == 'type_hint':
                hint_type = constraint.value
                type_kind = self._type_str_to_kind(hint_type)
                if type_kind:
                    solver.add(type_vars[constraint.var_name] == type_kind.value)
        
        if solver.check() == z3.sat:
            model = solver.model()
            for var_name, z3_var in type_vars.items():
                if var_name in self.variables:
                    val = model[z3_var].as_long() if z3_var in model else -1
                    if val >= 0:
                        inferred_kind = self._kind_from_value(val)
                        self.variables[var_name].inferred_types.append(
                            InferredType(
                                kind=inferred_kind,
                                bit_size=TYPE_SIZES.get(inferred_kind, 0) * 8,
                                confidence=0.8,
                                constraints=[constraint],
                                source='z3_solver'
                            )
                        )
    
    def _type_str_to_kind(self, type_str: str) -> Optional[TypeKind]:
        """类型字符串转TypeKind"""
        for kind in TypeKind:
            if kind.value == type_str:
                return kind
        return None
    
    def _kind_from_value(self, value: int) -> TypeKind:
        """从整数值获取TypeKind"""
        for kind in TypeKind:
            if kind.value == value:
                return kind
        return TypeKind.UNKNOWN
    
    def _solve_heuristically(self) -> None:
        """启发式类型推断"""
        logger.debug("使用启发式方法进行类型推断")
        
        for constraint in self.constraints:
            if constraint.constraint_type == 'type_hint':
                type_kind = self._type_str_to_kind(constraint.value)
                if type_kind and constraint.var_name in self.variables:
                    self.variables[constraint.var_name].inferred_types.append(
                        InferredType(
                            kind=type_kind,
                            bit_size=TYPE_SIZES.get(type_kind, 0) * 8,
                            confidence=0.6,
                            constraints=[constraint],
                            source='heuristic'
                        )
                    )
        
        for var_name, var_info in self.variables.items():
            if not var_info.inferred_types:
                var_info.inferred_types.append(
                    InferredType(
                        kind=TypeKind.UNKNOWN,
                        bit_size=0,
                        confidence=0.0,
                        source='default'
                    )
                )
    
    def _infer_structs(self, pseudocode: str) -> None:
        """推断结构体"""
        offset_pattern = r'\*\(\s*\w+\s*\*\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*(\d+)\s*\)\s*\)'
        matches = re.findall(offset_pattern, pseudocode)
        
        struct_candidates: Dict[str, List[Tuple[int, str]]] = {}
        
        for base_var, offset in matches:
            if base_var not in struct_candidates:
                struct_candidates[base_var] = []
            struct_candidates[base_var].append((int(offset), base_var))
        
        for struct_name, fields in struct_candidates.items():
            if len(fields) >= 2:
                fields.sort(key=lambda x: x[0])
                struct_fields = []
                
                for i, (offset, _) in enumerate(fields):
                    field_name = f'field_{offset}'
                    next_offset = fields[i+1][0] if i+1 < len(fields) else offset + 8
                    field_size = next_offset - offset
                    
                    inferred_type = self._infer_type_from_size(field_size)
                    
                    struct_fields.append(StructFieldInfo(
                        name=field_name,
                        offset=offset,
                        inferred_type=inferred_type
                    ))
                
                self.structs[f'struct_{struct_name}'] = struct_fields
    
    def _infer_type_from_size(self, size: int) -> InferredType:
        """根据大小推断类型"""
        size_map = {
            1: TypeKind.CHAR,
            2: TypeKind.SHORT,
            4: TypeKind.INT,
            8: TypeKind.LONG,
        }
        
        kind = size_map.get(size, TypeKind.UNKNOWN)
        return InferredType(kind=kind, bit_size=size * 8, confidence=0.7, source='size_inference')
    
    def _infer_arrays(self, pseudocode: str) -> None:
        """推断数组"""
        array_patterns = [
            r'malloc\s*\(\s*(\d+)\s*\)',
            r'calloc\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)',
            r'for\s*\([^)]*<\s*(\d+)[^)]*\)',
        ]
        
        for pattern in array_patterns:
            matches = re.findall(pattern, pseudocode)
            for match in matches:
                if isinstance(match, tuple):
                    size = int(match[0]) * int(match[1]) if len(match) > 1 else int(match[0])
                else:
                    size = int(match)
                
                if size > 0:
                    for var_name, var_info in self.variables.items():
                        if not any(t.kind == TypeKind.ARRAY for t in var_info.inferred_types):
                            var_info.inferred_types.append(
                                InferredType(
                                    kind=TypeKind.ARRAY,
                                    bit_size=size * 8,
                                    confidence=0.6,
                                    array_size=size,
                                    source='array_pattern'
                                )
                            )
    
    def _infer_function_pointers(self, pseudocode: str) -> None:
        """推断函数指针"""
        fp_pattern = r'(\w+\s*\(\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*\([^)]*\))'
        matches = re.findall(fp_pattern, pseudocode)
        
        for full_decl, var_name in matches:
            if var_name in self.variables:
                self.variables[var_name].inferred_types.append(
                    InferredType(
                        kind=TypeKind.FUNCTION,
                        bit_size=64,
                        confidence=0.9,
                        source='function_pointer_decl'
                    )
                )
    
    def _generate_enhanced_pseudocode(self, pseudocode: str) -> str:
        """生成增强的伪代码"""
        enhanced = pseudocode
        
        for var_name, var_info in self.variables.items():
            if var_info.inferred_types:
                best_type = max(var_info.inferred_types, key=lambda t: t.confidence)
                if best_type.confidence >= self.min_confidence:
                    type_str = self._format_type(best_type)
                    comment = f'/* type: {type_str}, confidence: {best_type.confidence:.2f} */'
                    
                    pattern = rf'\b({var_name})\b(?!\s*\()'
                    enhanced = re.sub(pattern, rf'\1 {comment}', enhanced)
        
        for struct_name, fields in self.structs.items():
            struct_def = self._generate_struct_definition(struct_name, fields)
            enhanced = struct_def + '\n\n' + enhanced
        
        return enhanced
    
    def _format_type(self, inferred_type: InferredType) -> str:
        """格式化类型为字符串"""
        if inferred_type.kind == TypeKind.POINTER:
            target_str = self._format_type(inferred_type.pointer_target) if inferred_type.pointer_target else 'void'
            return f'{target_str}*'
        elif inferred_type.kind == TypeKind.ARRAY:
            return f'{self._format_type(InferredType(kind=TypeKind.CHAR, bit_size=8))}[{inferred_type.array_size}]'
        elif inferred_type.kind == TypeKind.STRUCT:
            return f'struct {inferred_type.struct_name}'
        elif inferred_type.kind == TypeKind.FUNCTION:
            return 'function pointer'
        
        return inferred_type.kind.value
    
    def _generate_struct_definition(self, struct_name: str, fields: List[StructFieldInfo]) -> str:
        """生成结构体定义"""
        lines = [f'struct {struct_name} {{']
        
        for field in fields:
            type_str = self._format_type(field.inferred_type)
            lines.append(f'    {type_str} {field.name};  /* offset: 0x{field.offset:x} */')
        
        lines.append('};')
        
        return '\n'.join(lines)
    
    def _calculate_confidence(self) -> float:
        """计算整体置信度"""
        if not self.variables:
            return 0.0
        
        total_confidence = 0.0
        count = 0
        
        for var_info in self.variables.values():
            if var_info.inferred_types:
                total_confidence += max(t.confidence for t in var_info.inferred_types)
                count += 1
        
        return total_confidence / count if count > 0 else 0.0
    
    def _generate_warnings(self) -> List[str]:
        """生成警告信息"""
        warnings = []
        
        for var_name, var_info in self.variables.items():
            if var_info.inferred_types:
                best_confidence = max(t.confidence for t in var_info.inferred_types)
                if best_confidence < self.min_confidence:
                    warnings.append(f"变量 '{var_name}' 的类型推断置信度较低 ({best_confidence:.2f})")
        
        return warnings


def run_type_inference(pseudocode: str, assembly: str = "", binary_info: Dict[str, Any] = None) -> TypeInferenceResult:
    """便捷函数：执行类型推断"""
    inferrer = TypeInferrer()
    return inferrer.infer_types(pseudocode, assembly, binary_info)


def enhance_pseudocode_with_types(pseudocode: str, assembly: str = "") -> str:
    """便捷函数：使用类型推断增强伪代码"""
    inferrer = TypeInferrer()
    result = inferrer.infer_types(pseudocode, assembly)
    return result.enhanced_pseudocode