import re
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
# from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

class StructuredType(Enum):
    IF = "if"
    IF_ELSE = "if_else"
    IF_ELIF_ELSE = "if_elif_else"
    SWITCH = "switch"
    FOR = "for"
    WHILE = "while"
    DO_WHILE = "do_while"
    BREAK = "break"
    CONTINUE = "continue"
    RETURN = "return"
    BLOCK = "block"
    EXPRESSION = "expression"
    DECLARATION = "declaration"
    FUNCTION_CALL = "function_call"
    UNKNOWN = "unknown"

class OperatorType(Enum):
    ARITHMETIC = "arithmetic"
    LOGICAL = "logical"
    COMPARISON = "comparison"
    BITWISE = "bitwise"
    ASSIGNMENT = "assignment"
# 手工data类——__slots__声明完全可控
@dataclass
class Statement:
    type
    content = ""
    condition = None
    body = field(default_factory=list)
    else_body = field(default_factory=list)
    cases = field(default_factory=dict)
    default_case = field(default_factory=list)
    init_expr = None
    loop_expr = None
    update_expr = None
    address = 0
    indent_level = 0
    comments = field(default_factory=list)

@dataclass
class Variable:
    name
    original_name
    inferred_type = "int"
    size = 0
    is_array = False
    is_pointer = False
    is_parameter = False
    is_local = True
    is_global = False
    initial_value = None
    scope = "local"

@dataclass
class FunctionSignature:
    name
    return_type = "int"
    parameters = field(default_factory=list)
    is_static = False
    is_inline = False

@dataclass
class StructuredOutput:
    original_pseudocode = ""
    structured_code = ""
    statements = field(default_factory=list)
    variables = field(default_factory=list)
    function_signature = None
    control_flow_graph = field(default_factory=dict)
    warnings = field(default_factory=list)
    success = False

class ControlFlowAnalyzer:
    # control flowanalyzer

    def __init__(self):
        self.cfg: Dict[int, List[int]] = {}
        self.basic_blocks: Dict[int, List[str]] = {}
        self._current_address = 0

    def analyze(self, pseudocode: str) -> Dict[int, List[int]]:
        # 分析control flow
        self.cfg = {}
        self.basic_blocks = {}

        # 解析address标记
        addr_pattern = r'addr_([0-9a-fA-F]+):'
        addresses = re.findall(addr_pattern, pseudocode)

        # 构建basic block
        lines = pseudocode.split('\n')
        current_block = []

        current_addr = 0

        for line in lines:
            addr_match = re.match(addr_pattern, line)
            if addr_match:
                if current_block:
                    self.basic_blocks[current_addr] = current_block
                current_addr = int(addr_match.group(1), 16)
                current_block = []
            else:
                if line.strip():
                    current_block.append(line.strip())

        if current_block:
            self.basic_blocks[current_addr] = current_block

        # 构建CFG
        for addr, block in self.basic_blocks.items():
            self.cfg[addr] = []

            # 分析跳转target
            for stmt in block:
                jump_targets = self._extract_jump_targets(stmt)
                for target in jump_targets:
                    self.cfg[addr].append(target)

        return self.cfg

    def _extract_jump_targets(self, statement: str) -> List[int]:
        """extract跳转target"""
        targets = []

        # goto语句
        goto_pattern = r'goto\s+addr_([0-9a-fA-F]+)'
        matches = re.findall(goto_pattern, statement)
        for match in matches:
            targets.append(int(match, 16))

        # condition跳转
        if_pattern = r'if\s*\([^)]*\)\s*goto\s+addr_([0-9a-fA-F]+)'
        matches = re.findall(if_pattern, statement)
        for match in matches:
            targets.append(int(match, 16))

        return targets

class StructuredCodeGenerator:
    # structured代码generator

    def __init__(self):
        self.indent_char = "    "
        self.max_indent = 20

    def generate(self, statements: List[Statement], indent: int = 0) -> str:
        """生成structured代码"""
        output = []

        for stmt in statements:
            stmt.indent_level = indent
            output.append(self._generate_statement(stmt))

        return '\n'.join(output)

    def _generate_statement(self, stmt: Statement) -> str:
        # 生成单个语句
        indent_str = self.indent_char * stmt.indent_level

        if stmt.type == StructuredType.IF:
            return self._generate_if(stmt, indent_str)
        elif stmt.type == StructuredType.IF_ELSE:
            return self._generate_if_else(stmt, indent_str)
        elif stmt.type == StructuredType.IF_ELIF_ELSE:
            return self._generate_if_elif_else(stmt, indent_str)
        elif stmt.type == StructuredType.SWITCH:
            return self._generate_switch(stmt, indent_str)
        elif stmt.type == StructuredType.FOR:
            return self._generate_for(stmt, indent_str)
        elif stmt.type == StructuredType.WHILE:
            return self._generate_while(stmt, indent_str)
        elif stmt.type == StructuredType.DO_WHILE:
            return self._generate_do_while(stmt, indent_str)
        elif stmt.type == StructuredType.BLOCK:
            return self._generate_block(stmt, indent_str)
        elif stmt.type == StructuredType.EXPRESSION:
            return f"{indent_str}{stmt.content};"
        elif stmt.type == StructuredType.DECLARATION:
            return f"{indent_str}{stmt.content}"
        elif stmt.type == StructuredType.RETURN:
            return f"{indent_str}return {stmt.content};" if stmt.content else f"{indent_str}return;"
        elif stmt.type == StructuredType.BREAK:
            return f"{indent_str}break;"
        elif stmt.type == StructuredType.CONTINUE:
            return f"{indent_str}continue;"
        elif stmt.type == StructuredType.FUNCTION_CALL:
            return f"{indent_str}{stmt.content};"
        else:
            return f"{indent_str}{stmt.content}"

    def _generate_if(self, stmt: Statement, indent: str) -> str:
        # 生成if语句
        lines = []
        lines.append(f"{indent}if ({stmt.condition}) {{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}}")
        return '\n'.join(lines)

    def _generate_if_else(self, stmt: Statement, indent: str) -> str:
        # 生成if-else语句
        lines = []
        lines.append(f"{indent}if ({stmt.condition}) {{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}} else {{")

        for else_stmt in stmt.else_body:
            else_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(else_stmt))

        lines.append(f"{indent}}}")
        return '\n'.join(lines)

    def _generate_if_elif_else(self, stmt: Statement, indent: str) -> str:
        # 生成if-elif-else语句
        lines = []
        lines.append(f"{indent}if ({stmt.condition}) {{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}}")

        # elif部分存储在else_body中，需要特殊处理
        for i, else_stmt in enumerate(stmt.else_body):
            if else_stmt.type == StructuredType.IF or else_stmt.type == StructuredType.IF_ELSE:
                else_stmt.indent_level = stmt.indent_level
                elif_code = self._generate_statement(else_stmt)
                # 将if改为elif
                elif_code = elif_code.replace('if (', 'else if (', 1)
                lines.append(elif_code)
            else:
                if i == 0:
                    lines.append(f"{indent}else {{")
                else_stmt.indent_level = stmt.indent_level + 1
                lines.append(self._generate_statement(else_stmt))

        if stmt.else_body and stmt.else_body[-1].type not in [StructuredType.IF, StructuredType.IF_ELSE]:
            lines.append(f"{indent}}}")

        return '\n'.join(lines)

    def _generate_switch(self, stmt: Statement, indent: str) -> str:
        # 生成switch语句
        lines = []
        lines.append(f"{indent}switch ({stmt.condition}) {{")

        for case_value, case_stmts in stmt.cases.items():
            lines.append(f"{indent}    case {case_value}:")
            for case_stmt in case_stmts:
                case_stmt.indent_level = stmt.indent_level + 2
                lines.append(self._generate_statement(case_stmt))

            lines.append(f"{indent}        break;")

        if stmt.default_case:
            lines.append(f"{indent}    default:")
            for default_stmt in stmt.default_case:
                default_stmt.indent_level = stmt.indent_level + 2
                lines.append(self._generate_statement(default_stmt))

        lines.append(f"{indent}}}")
        return '\n'.join(lines)

    def _generate_for(self, stmt: Statement, indent: str) -> str:
        """生成forloop"""
        lines = []
        init = stmt.init_expr or ""
        loop = stmt.loop_expr or ""
        update = stmt.update_expr or ""

        lines.append(f"{indent}for ({init}; {loop}; {update}) {{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}}")
        return '\n'.join(lines)

    def _generate_while(self, stmt: Statement, indent: str) -> str:
        # 生成whileloop
        lines = []
        lines.append(f"{indent}while ({stmt.condition}) {{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}}")
        return '\n'.join(lines)

    def _generate_do_while(self, stmt: Statement, indent: str) -> str:
        # 生成do-whileloop
        lines = []
        lines.append(f"{indent}do {{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}} while ({stmt.condition});")
        return '\n'.join(lines)

    def _generate_block(self, stmt: Statement, indent: str) -> str:
        # 生成代码块
        lines = []
        lines.append(f"{indent}{{")

        for body_stmt in stmt.body:
            body_stmt.indent_level = stmt.indent_level + 1
            lines.append(self._generate_statement(body_stmt))

        lines.append(f"{indent}}}")
        return '\n'.join(lines)

class PseudocodeStructurer:
    """
    反compilepseudocodestructured器

    将扁平pseudocodeconvert为structured的C风格代码
    """

    def __init__(self, pseudocode: str = ""):
        self.pseudocode = pseudocode
        self.statements: List[Statement] = []
        self.variables: List[Variable] = []
        self.cfg_analyzer = ControlFlowAnalyzer()
        self.code_generator = StructuredCodeGenerator()
        self._label_map: Dict[str, int] = {}
        self._processed_labels: Set[str] = set()

    def structure(self, pseudocode: str = None) -> StructuredOutput:
        # executestructuredconvert
        if pseudocode:
            self.pseudocode = pseudocode

        result = StructuredOutput()
        result.original_pseudocode = self.pseudocode

        try:
            # 1. 预处理pseudocode
            processed = self._preprocess()

            # 2. 分析control flow
            cfg = self.cfg_analyzer.analyze(processed)
            result.control_flow_graph = cfg

            # 3. extract变量
            self._extract_variables()
            result.variables = self.variables

            # 4. 构建label映射
            self._build_label_map(processed)

            # 5. 解析语句
            self.statements = self._parse_statements(processed)
            result.statements = self.statements

            # 6. structuredconvert
            structured = self._structure_statements()

            # 7. 生成代码
            result.structured_code = self.code_generator.generate(structured)

            # 8. 添加注释
            result.structured_code = self._add_comments(result.structured_code)

            result.success = True
            logger.info("pseudocodestructuredcomplete")

        except Exception as e:
            logger.error(f"pseudocodestructuredfailed: {e}")
            result.warnings.append(f"structuredfailed: {e}")

        return result

    def _preprocess(self) -> str:
        """预处理pseudocode"""
        processed = self.pseudocode

        # removeANSIescape序列
        processed = re.sub(r'\x1b\[[0-9;]*m', '', processed)

        # normalizeaddresslabel
        processed = re.sub(r'0x([0-9a-fA-F]+):', r'addr_\1:', processed)

        # remove多余空白
        processed = re.sub(r'\s+', ' ', processed)
        processed = re.sub(r'\n\s*\n', '\n', processed)

        # normalize运算符
        processed = re.sub(r'\s*=\s*', ' = ', processed)
        processed = re.sub(r'\s*==\s*', ' == ', processed)
        processed = re.sub(r'\s*!=\s*', ' != ', processed)

        return processed

    def _extract_variables(self) -> None:
        # extract变量info
        # extract变量声明
        var_patterns = [
            r'(int|char|long|short|float|double|void|unsigned|size_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*\[\s*([0-9]+)\s*\])?',
            r'(int|char|long|short|float|double|void|unsigned|size_t)\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)',
        ]

        for pattern in var_patterns:
            matches = re.findall(pattern, self.pseudocode)
            for match in matches:
                if len(match) >= 2:
                    var_type = match[0]
                    var_name = match[1]
                    is_array = len(match) > 2 and match[2]
                    is_pointer = '*' in var_type

                    var = Variable(
                        name=var_name,
                        original_name=var_name,
                        inferred_type=var_type.replace('*', ''),
                        is_array=bool(is_array),
                        is_pointer=is_pointer
                    )

                    if is_array:
                        var.size = int(match[2]) if match[2] else 0

                    self.variables.append(var)

    def _build_label_map(self, code: str) -> None:
        # 构建label映射
        label_pattern = r'addr_([0-9a-fA-F]+):'
        matches = re.findall(label_pattern, code)

        for i, label in enumerate(matches):
            self._label_map[f"addr_{label}"] = i

    def _parse_statements(self, code: str) -> List[Statement]:
        # 解析语句
        statements = []

        # 按行解析
        lines = code.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # skipaddresslabel
            if re.match(r'addr_[0-9a-fA-F]+:', line):
                continue

            stmt = self._parse_single_statement(line)
            if stmt:
                statements.append(stmt)

        return statements

    def _parse_single_statement(self, line: str) -> Optional[Statement]:
        # 解析单个语句

        # if语句
        if_match = re.match(r'if\s*\(\s*([^)]+)\s*\)\s*(?:goto\s+addr_([0-9a-fA-F]+)|\{)', line)
        if if_match:
            condition = if_match.group(1)
            goto_target = if_match.group(2)

            if goto_target:
                # condition跳转
                stmt = Statement(
                    type=StructuredType.IF,
                    condition=condition,
                    body=[Statement(type=StructuredType.EXPRESSION, content=f"goto addr_{goto_target}")]
                )
            else:
                stmt = Statement(
                    type=StructuredType.IF,
                    condition=condition
                )

            return stmt

        # whileloop
        while_match = re.match(r'while\s*\(\s*([^)]+)\s*\)', line)
        if while_match:
            return Statement(
                type=StructuredType.WHILE,
                condition=while_match.group(1))

        # forloop
        for_match = re.match(r'for\s*\(\s*([^;]+)\s*;\s*([^;]+)\s*;\s*([^)]+)\s*\)', line)
        if for_match:
            return Statement(
                type=StructuredType.FOR,
                init_expr=for_match.group(1),
                loop_expr=for_match.group(2),
                update_expr=for_match.group(3))

        # return语句
        if line.startswith('return'):
            ret_match = re.match(r'return\s+(.+)?', line)
            return Statement(
                type=StructuredType.RETURN,
                content=ret_match.group(1) if ret_match and ret_match.group(1) else "")

        # break语句
        if line == 'break':
            return Statement(type=StructuredType.BREAK)

        # continue语句
        if line == 'continue':
            return Statement(type=StructuredType.CONTINUE)

        # goto语句
        goto_match = re.match(r'goto\s+addr_([0-9a-fA-F]+)', line)
        if goto_match:
            return Statement(
                type=StructuredType.EXPRESSION,
                content=f"goto addr_{goto_match.group(1)}")

        # 变量声明
        decl_match = re.match(r'(int|char|long|short|float|double|void|unsigned|size_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*=\s*(.+))?', line)
        if decl_match:
            var_type = decl_match.group(1)
            var_name = decl_match.group(2)
            init_val = decl_match.group(3)

            content = f"{var_type} {var_name}"
            if init_val:
                content += f" = {init_val}"

            return Statement(
                type=StructuredType.DECLARATION,
                content=content)

        # 函数调用
        call_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)', line)
        if call_match and '=' not in line:
            return Statement(
                type=StructuredType.FUNCTION_CALL,
                content=line)

        # 赋value表达式
        assign_match = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)', line)
        if assign_match:
            return Statement(
                type=StructuredType.EXPRESSION,
                content=line)

        # 默认：表达式
        return Statement(
            type=StructuredType.EXPRESSION,
            content=line)

    def _structure_statements(self) -> List[Statement]:
        # structured语句
        structured = []

        # identifyloop结构
        loops = self._identify_loops()

        # identifycondition结构
        conditions = self._identify_conditions()

        # identifyswitch结构
        switches = self._identify_switches()

        # 构建structured语句list
        i = 0
        while i < len(self.statements):
            stmt = self.statements[i]

            # check是否属于已identify的结构
            if self._is_loop_start(i, loops):
                loop_stmt = self._build_loop(i, loops)
                structured.append(loop_stmt)
                i = self._get_loop_end(i, loops) + 1
            elif self._is_condition_start(i, conditions):
                cond_stmt = self._build_condition(i, conditions)
                structured.append(cond_stmt)
                i = self._get_condition_end(i, conditions) + 1
            elif self._is_switch_start(i, switches):
                switch_stmt = self._build_switch(i, switches)
                structured.append(switch_stmt)
                i = self._get_switch_end(i, switches) + 1
            else:
                structured.append(stmt)
                i += 1

        return structured

    def _identify_loops(self) -> Dict[int, int]:
        # identifyloop结构
        loops = {}

        # 检测whileloop
        for i, stmt in enumerate(self.statements):
            if stmt.type == StructuredType.WHILE:
                # foundloop体结束
                end = self._find_loop_end(i)
                loops[i] = end

        # 检测forloop
        for i, stmt in enumerate(self.statements):
            if stmt.type == StructuredType.FOR:
                end = self._find_loop_end(i)
                loops[i] = end

        # 检测do-whileloop（通过goto回跳检测）
        for i, stmt in enumerate(self.statements):
            if stmt.type == StructuredType.EXPRESSION and 'goto' in stmt.content:
                # check是否回跳到之前的address
                goto_match = re.search(r'goto\s+addr_([0-9a-fA-F]+)', stmt.content)
                if goto_match:
                    target = goto_match.group(1)
                    # 查找loop起始
                    start = self._find_loop_start_for_goto(i, target)
                    if start is not None:
                        loops[start] = i

        return loops

    def _find_loop_end(self, start: int) -> int:
        """foundloop结束位置"""
        depth = 1
        for i in range(start + 1, len(self.statements)):
            stmt = self.statements[i]
            if stmt.type in [StructuredType.WHILE, StructuredType.FOR, StructuredType.IF]:
                depth += 1
            elif stmt.type == StructuredType.BREAK:
                return i
            elif stmt.type in [StructuredType.BLOCK]:
                depth -= 1
                if depth == 0:
                    return i
        return len(self.statements) - 1

    def _find_loop_start_for_goto(self, goto_pos: int, target: str) -> Optional[int]:
        # pergototarget找loop起始
        # 向前查找targetaddress
        for i in range(goto_pos - 1, -1, -1):
            stmt = self.statements[i]
            if stmt.type == StructuredType.IF:
                # checkcondition跳转
                for body_stmt in stmt.body:
                    if f"addr_{target}" in body_stmt.content:
                        return i
        return None

    def _identify_conditions(self) -> Dict[int, int]:
        """identifycondition结构"""
        conditions = {}

        for i, stmt in enumerate(self.statements):
            if stmt.type == StructuredType.IF:
                end = self._find_condition_end(i)
                conditions[i] = end

        return conditions

    def _find_condition_end(self, start: int) -> int:
        # foundcondition结束位置
        for i in range(start + 1, len(self.statements)):
            stmt = self.statements[i]
            if stmt.type in [StructuredType.IF, StructuredType.WHILE, StructuredType.FOR]:
                # 嵌套结构
                continue
            elif stmt.type == StructuredType.EXPRESSION and 'goto' in stmt.content:
                # condition跳转结束
                return i
        return len(self.statements) - 1

    def _identify_switches(self) -> Dict[int, int]:
        # identifyswitch结构
        switches = {}

        # 检测连续的if-eqmode
        i = 0
        while i < len(self.statements):
            stmt = self.statements[i]
            if stmt.type == StructuredType.IF:
                # check是否是switchmode
                switch_end = self._check_switch_pattern(i)
                if switch_end:
                    switches[i] = switch_end
                    i = switch_end + 1
                else:
                    i += 1
            else:
                i += 1

        return switches

    def _check_switch_pattern(self, start: int) -> Optional[int]:
        # check是否是switchmode
        # 检测连续的 if (var == value) mode
        eq_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*==\s*([0-9]+)'

        first_stmt = self.statements[start]
        if not first_stmt.condition:
            return None

        match = re.search(eq_pattern, first_stmt.condition)
        if not match:
            return None

        var_name = match.group(1)

        nCount = 0

        for i in range(start, min(start + 10, len(self.statements))):
            stmt = self.statements[i]
            if stmt.type == StructuredType.IF and stmt.condition:
                match = re.search(eq_pattern, stmt.condition)
                if match and match.group(1) == var_name:
                    nCount += 1
                else:
                    break
            else:
                break

        if nCount >= 3:
            return start + nCount - 1

        return None

    def _is_loop_start(self, pos: int, loops: Dict[int, int]) -> bool:
        # check是否是loop起始
        return pos in loops

    def _get_loop_end(self, pos: int, loops: Dict[int, int]) -> int:
        # 获取loop结束位置
        return loops.get(pos, pos)

    def _is_condition_start(self, pos: int, conditions: Dict[int, int]) -> bool:
        """check是否是condition起始"""
        return pos in conditions

    def _get_condition_end(self, pos: int, conditions: Dict[int, int]) -> int:
        """获取condition结束位置"""
        return conditions.get(pos, pos)

    def _is_switch_start(self, pos: int, switches: Dict[int, int]) -> bool:
        # check是否是switch起始
        return pos in switches

    def _get_switch_end(self, pos: int, switches: Dict[int, int]) -> int:
        """获取switch结束位置"""
        return switches.get(pos, pos)

    def _build_loop(self, start: int, loops: Dict[int, int]) -> Statement:
        """构建loop语句"""
        original = self.statements[start]
        end = loops[start]

        body = []
        for i in range(start + 1, end):
            body.append(self.statements[i])

        if original.type == StructuredType.WHILE:
            stmt = Statement(
                type=StructuredType.WHILE,
                condition=original.condition,
                body=body
            )
        elif original.type == StructuredType.FOR:
            stmt = Statement(
                type=StructuredType.FOR,
                init_expr=original.init_expr,
                loop_expr=original.loop_expr,
                update_expr=original.update_expr,
                body=body
            )
        else:
            # do-while
            stmt = Statement(
                type=StructuredType.DO_WHILE,
                condition=self._extract_do_while_condition(end),
                body=body
            )

        return stmt

    def _extract_do_while_condition(self, end: int) -> str:
        # extractdo-whilecondition
        stmt = self.statements[end]
        if stmt.type == StructuredType.IF and stmt.condition:
            return stmt.condition
        return "true"

    def _build_condition(self, start: int, conditions: Dict[int, int]) -> Statement:
        # 构建condition语句
        original = self.statements[start]
        end = conditions[start]

        body = []
        else_body = []

        # check是否有else分支
        has_else = False
        for i in range(start + 1, end + 1):
            stmt = self.statements[i]
            if stmt.type == StructuredType.IF and i > start:
                # 可能是else if
                has_else = True
                else_body.append(stmt)
            elif has_else:
                else_body.append(stmt)
            else:
                body.append(stmt)

        if else_body:
            stmt = Statement(
                type=StructuredType.IF_ELSE,
                condition=original.condition,
                body=body,
                else_body=else_body
            )
        else:
            stmt = Statement(
                type=StructuredType.IF,
                condition=original.condition,
                body=body
            )

        return stmt

    def _build_switch(self, start: int, switches: Dict[int, int]) -> Statement:
        # 构建switch语句
        end = switches[start]

        eq_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*==\s*([0-9]+)'

        # extractswitch变量
        first_stmt = self.statements[start]
        match = re.search(eq_pattern, first_stmt.condition)
        if not match:
            return first_stmt

        var_name = match.group(1)
        cases: Dict[str, List[Statement]] = {}
        default_case: List[Statement] = []

        for i in range(start, end + 1):
            stmt = self.statements[i]
            if stmt.type == StructuredType.IF and stmt.condition:
                match = re.search(eq_pattern, stmt.condition)
                if match:
                    case_value = match.group(2)
                    cases[case_value] = stmt.body
            else:
                # 默认分支
                default_case.append(stmt)

        return Statement(
            type=StructuredType.SWITCH,
            condition=var_name,
            cases=cases,
            default_case=default_case)

    def _add_comments(self, code: str) -> str:
        # 添加注释
        lines = code.split('\n')
        commented_lines = []

        # 添加file头注释
        commented_lines.append("/* structured反compile代码 */")
        commented_lines.append("/* 由 PseudocodeStructurer auto-generated */")
        commented_lines.append("")

        for line in lines:
            # 为关key结构添加注释
            if line.strip().startswith('if'):
                commented_lines.append(line)
                commented_lines.append("    // condition分支")
            elif line.strip().startswith('while'):
                commented_lines.append(line)
                commented_lines.append("    // loop结构")
            elif line.strip().startswith('for'):
                commented_lines.append(line)
                commented_lines.append("    // 计数loop")
            elif line.strip().startswith('switch'):
                commented_lines.append(line)
                commented_lines.append("    // 分支选择")
            else:
                commented_lines.append(line)

        return '\n'.join(commented_lines)

def structure_pseudocode(pseudocode: str) -> StructuredOutput:
    # convenience function：structuredpseudocode
    structurer = PseudocodeStructurer(pseudocode)
    return structurer.structure()

def convert_to_c_style(pseudocode: str) -> str:
    """convenience function：convert为C风格代码"""
    result = structure_pseudocode(pseudocode)
    return result.structured_code if result.success else pseudocode

class BatchPseudocodeStructurer:
    """批量pseudocodestructured器"""

    def __init__(self):
        self.results: Dict[str, StructuredOutput] = {}

    def structure_batch(self, pseudocodes: Dict[str, str]) -> Dict[str, StructuredOutput]:
        # 批量structured
        for func_name, pseudocode in pseudocodes.items():
            structurer = PseudocodeStructurer(pseudocode)
            self.results[func_name] = structurer.structure()

        return self.results

    def generate_report(self) -> str:
        # 生成批量处理报告
        lines = [
            "# 批量pseudocodestructured报告",
            "",
            f"**处理函数数量**: {len(self.results)}",
            ""
        ]

        success_count = sum(1 for r in self.results.values() if r.success)
        lines.append(f"**successful**: {success_count}")
        lines.append(f"**failed**: {len(self.results) - success_count}")
        lines.append("")

        for func_name, result in self.results.items():
            lines.append(f"## {func_name}")
            lines.append(f"- **status**: {'successful' if result.success else 'failed'}")
            lines.append(f"- **变量数量**: {len(result.variables)}")
            lines.append(f"- **语句数量**: {len(result.statements)}")
            if result.warnings:
                lines.append(f"- **warning**: {', '.join(result.warnings)}")
            lines.append("")

        return "\n".join(lines)
