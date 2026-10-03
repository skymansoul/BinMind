import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    logger.warning("Z3求解器unavailable，将使用启发式typeinfer")
    Z3_AVAILABLE = False

class TypeKind(Enum):
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
    var_name: str = ""
    constraint_type: str = ""
    value: str = ""
    source: str = ""

@dataclass
class InferredType:
    kind: str = ""
    bit_size: int = 0
    confidence: float = 0.0
    constraints: list = field(default_factory=list)
    pointer_target: str = None
    array_size: int = None
    struct_name: str = None
    struct_fields: list = None
    function_signature: str = None
    comment: str = ""
    source: str = ""

@dataclass
class StructFieldInfo:
    name: str = ""
    offset: int = 0
    inferred_type: str = ""
    is_bit_field: bool = False
    bit_size: int = 0

@dataclass
class FunctionSignature:
    return_type: str = ""
    param_types: list = field(default_factory=list)
    param_names: list = field(default_factory=list)
    is_varargs: bool = False

@dataclass
class VariableInfo:
    name: str = ""
    inferred_types: list = field(default_factory=list)
    address: int = None
    is_global: bool = False
    is_argument: bool = False

@dataclass
class TypeInferenceResult:
    variables: dict = field(default_factory=dict)
    structs: dict = field(default_factory=dict)
    functions: dict = field(default_factory=dict)
    enhanced_pseudocode: str = ""
    confidence_score: float = 0.0
    warnings: list = field(default_factory=list)

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
    # 全程序typeinferengine

    def __init__(self, use_z3: bool = True, min_confidence: float = 0.5):
        self.use_z3 = use_z3 and Z3_AVAILABLE
        self.min_confidence = min_confidence
        self.variables: Dict[str, VariableInfo] = {}
        self.structs: Dict[str, List[StructFieldInfo]] = {}
        self.functions: Dict[str, FunctionSignature] = {}
        self.constraints: List[TypeConstraint] = []

        logger.info(f"typeinfer器initializecomplete，使用Z3: {self.use_z3}")

    def infer_types(self, pseudocode: str, assembly: str = "", binary_info: Dict[str, Any] = None) -> TypeInferenceResult:
        # execute全程序typeinfer
        logger.info("start全程序typeinfer")

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

            logger.info(f"typeinfercomplete，confidence: {result.confidence_score:.2f}")

        except Exception as e:
            logger.error(f"typeinferfailed: {e}")
            result.warnings.append(f"typeinfer过程中发生error: {e}")

        return result

    def _extract_variables(self, pseudocode: str) -> None:
        # 从pseudocode中extract变量
        patterns = [
            r'\b(int|char|long|short|float|double|void|unsigned|size_t|ssize_t|_Bool)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b',
            r'(\w+\s*\*+)\s*([a-zA-Z_][a-zA-Z0-9_]*)\b',
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
                        # 声明即证据：按声明形态写入首个推断类型，供后续约束叠加
                        self._record_declared_type(var_name, match[0])

        func_pattern = r'\w+\s+\w+\s*\(\s*([^)]*)\s*\)'
        matches = re.findall(func_pattern, pseudocode)
        for match in matches:
            params = match.split(',')
            for param in params:
                param = param.strip()
                if param:
                    parts = param.split()
                    if len(parts) >= 2:
                        raw_name = parts[-1]
                        # 指针声明形如 char *buffer —— 变量名剥离前导解引用符
                        var_name = raw_name.lstrip('*').strip()
                        if var_name and var_name not in self.variables:
                            self.variables[var_name] = VariableInfo(
                                name=var_name,
                                inferred_types=[],
                                is_global=False,
                                is_argument=True
                            )
                            # 参数类型同样计入声明证据；指针标记取自剥离前的名称形态
                            self._record_declared_type(
                                var_name, ' '.join(parts[:-1]),
                                is_pointer=('*' in raw_name))

    def _record_declared_type(self, var_name: str, type_str: str,
                              is_pointer: bool = False) -> None:
        """声明形态转 InferredType 并写入变量列表；声明视为高置信证据。"""
        is_ptr = is_pointer or '*' in type_str
        base_str = type_str.replace('*', '').strip()
        if is_ptr:
            base = self._parse_type_str(base_str)
            self.variables[var_name].inferred_types.append(InferredType(
                kind=TypeKind.POINTER, bit_size=64, confidence=0.9,
                pointer_target=base, source='declaration'))
        else:
            parsed = self._parse_type_str(base_str)
            if parsed.kind != TypeKind.UNKNOWN:
                self.variables[var_name].inferred_types.append(InferredType(
                    kind=parsed.kind, bit_size=parsed.bit_size, confidence=0.9,
                    source='declaration'))

    def _extract_functions(self, pseudocode: str) -> None:
        """从pseudocode中extract函数sign"""
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
        # 解析typestring为InferredType
        type_str = type_str.strip().lower()
        # 剥离 const/unsigned 前缀后查表；指针层数单独展开
        type_str = type_str.replace('const ', '').strip()

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
        """收集type约束"""
        self._collect_instruction_constraints(assembly)
        self._collect_api_constraints(pseudocode)
        self._collect_memory_constraints(pseudocode)
        self._collect_comparison_constraints(pseudocode)

    def _collect_instruction_constraints(self, assembly: str) -> None:
        # 从汇编指令收集约束
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
        # 从API调用收集约束
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

        # 返回值约束：var = api(...) 把返回类型作为左值提示
        ret_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*([^)]*)\s*\)'
        for match in re.findall(ret_pattern, pseudocode):
            lhs, called, _args_str = match
            if called in LIBRARY_FUNCTIONS and lhs in self.variables:
                ret_kind = LIBRARY_FUNCTIONS[called]['return']
                self.constraints.append(TypeConstraint(
                    var_name=lhs,
                    constraint_type='type_hint',
                    value=ret_kind.value,
                    source=f'api_return:{called}'
                ))

    def _collect_memory_constraints(self, pseudocode: str) -> None:
        # 从memory访问mode收集约束
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
        # 从比较操作收集约束
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
        # 使用Z3求解器进行type约束求解
        logger.debug("使用Z3求解器进行typeinfer")

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
        # typestring转TypeKind
        for kind in TypeKind:
            if kind.value == type_str:
                return kind
        return None

    def _kind_from_value(self, value: int) -> TypeKind:
        # 从整数value获取TypeKind
        for kind in TypeKind:
            if kind.value == value:
                return kind
        return TypeKind.UNKNOWN

    def _solve_heuristically(self) -> None:
        # 启发式typeinfer
        logger.debug("使用启发式method进行typeinfer")

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
        # infer结构体
        # 形态为 *(type *)(base + off)：`(type *)` 与 `(base + off)` 各一个闭括号，
        # 此前模式错放且多写了一个闭括号，导致零匹配
        offset_pattern = r'\*\(\s*\w+\s*\*\s*\)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*(\d+)\s*\)'
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
        """persizeinfertype"""
        size_map = {
            1: TypeKind.CHAR,
            2: TypeKind.SHORT,
            4: TypeKind.INT,
            8: TypeKind.LONG,
        }

        kind = size_map.get(size, TypeKind.UNKNOWN)
        return InferredType(kind=kind, bit_size=size * 8, confidence=0.7, source='size_inference')

    def _infer_arrays(self, pseudocode: str) -> None:
        # inferarray
        # 归属语义：ARRAY 只加给分配结果的接收者，不再向全部变量广播；
        # 循环数字上界降级为循环索引变量的 range 约束（数组证据不足，避免误标）
        assign_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\(?[^;]*?\)?\s*(?:malloc|calloc)\s*\(\s*([^)]*)\s*\)'
        for match in re.findall(assign_pattern, pseudocode):
            lhs, args_str = match
            size = self._parse_alloc_size(args_str)
            if size > 0 and lhs in self.variables:
                self._attach_array_type(lhs, size)

        # 返回形态归属到所在函数名变量（声明模式已把函数名注册为变量）；
        # 函数体按无嵌套花括号解析，嵌套控制流会漏配，属保守边界
        func_body_pattern = r'\b(\w+)\s*\([^)]*\)\s*\{([^{}]*)\}'
        for func_name, body in re.findall(func_body_pattern, pseudocode):
            for args_str in re.findall(
                    r'return\s+\(?[^;]*?\)?\s*(?:malloc|calloc)\s*\(\s*([^)]*)\s*\)',
                    body):
                size = self._parse_alloc_size(args_str)
                if size > 0 and func_name in self.variables:
                    self._attach_array_type(func_name, size)

        # 循环上界：只对索引变量记 range 约束，不再产生数组证据
        loop_pattern = r'for\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=[^;]*;\s*[^;]*<\s*(\d+)\s*;'
        for idx_var, upper in re.findall(loop_pattern, pseudocode):
            self.constraints.append(TypeConstraint(
                var_name=idx_var,
                constraint_type='range',
                value=(0, int(upper) - 1),
                source='loop_bound'
            ))

    def _parse_alloc_size(self, args_str: str) -> int:
        """解析 malloc/calloc 参数为字节数；calloc 两参数相乘，非数字参数返回 0。"""
        parts = [p.strip() for p in args_str.split(',') if p.strip().isdigit()]
        if not parts:
            return 0
        size = 1
        for p in parts:
            size *= int(p)
        return size

    def _attach_array_type(self, var_name: str, size: int) -> None:
        """给单一变量附加 ARRAY 类型；已有 ARRAY 时不重复。"""
        var_info = self.variables[var_name]
        if any(t.kind == TypeKind.ARRAY for t in var_info.inferred_types):
            return
        var_info.inferred_types.append(InferredType(
            kind=TypeKind.ARRAY,
            bit_size=size * 8,
            confidence=0.6,
            array_size=size,
            source='array_pattern'
        ))

    def _infer_function_pointers(self, pseudocode: str) -> None:
        # infer函数指针
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
        """生成增强的pseudocode"""
        enhanced = pseudocode

        for var_name, var_info in self.variables.items():
            if var_info.inferred_types:
                best_type = max(var_info.inferred_types, key=lambda t: t.confidence)
                if best_type.confidence >= self.min_confidence:
                    type_str = self._format_type(best_type)
                    comment = f'/* type: {type_str}, confidence: {best_type.confidence:.2f} */'

                    # 避免replace函数调用中的变量名
                    pattern = rf'\b({re.escape(var_name)})\b(?!\s*\()'
                    enhanced = re.sub(pattern, rf'\1 {comment}', enhanced)

        for struct_name, fields in self.structs.items():
            struct_def = self._generate_struct_definition(struct_name, fields)
            enhanced = struct_def + '\n\n' + enhanced

        return enhanced

    def _format_type(self, inferred_type: InferredType) -> str:
        """格式化type为string"""
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
        # 生成结构体定义
        lines = [f'struct {struct_name} {{']

        for field in fields:
            type_str = self._format_type(field.inferred_type)
            lines.append(f'    {type_str} {field.name};  /* offset: 0x{field.offset:x} */')

        lines.append('};')

        return '\n'.join(lines)

    def _calculate_confidence(self) -> float:
        # 计算整体confidence
        if not self.variables:
            return 0.0

        total_confidence = 0.0


        nCount = 0

        for var_info in self.variables.values():
            if var_info.inferred_types:
                total_confidence += max(t.confidence for t in var_info.inferred_types)
                nCount += 1

        return total_confidence / nCount if nCount > 0 else 0.0

    def _generate_warnings(self) -> List[str]:
        """生成warninginfo"""
        warnings = []

        for var_name, var_info in self.variables.items():
            if var_info.inferred_types:
                best_confidence = max(t.confidence for t in var_info.inferred_types)
                if best_confidence < self.min_confidence:
                    warnings.append(f"变量 '{var_name}' 的typeinferconfidence较低 ({best_confidence:.2f})")

        return warnings

def run_type_inference(pseudocode: str, assembly: str = "", binary_info: Dict[str, Any] = None) -> TypeInferenceResult:
    # debug周期：完整工作日投入
    # convenience function：executetypeinfer
    inferrer = TypeInferrer()
    return inferrer.infer_types(pseudocode, assembly, binary_info)

def enhance_pseudocode_with_types(pseudocode: str, assembly: str = "") -> str:
    """convenience function：使用typeinfer增强pseudocode"""
    inferrer = TypeInferrer()
    result = inferrer.infer_types(pseudocode, assembly)
    return result.enhanced_pseudocode
