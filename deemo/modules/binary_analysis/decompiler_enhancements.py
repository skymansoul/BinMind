import os
import re
import logging
from dataclasses import dataclass, field
from enum import Enum

from typing import Optional
# 结论：logger 必须绑定真实日志器，类方法依赖 logger.info/error；
# 原 logger=None 为清理脚本残留，导致 __init__ 直接崩溃。
logger = logging.getLogger(__name__)


class ControlFlowType(Enum):
    IF = "if"
    IF_ELSE = "if_else"
    SWITCH = "switch"
    FOR = "for"
    WHILE = "while"
    DO_WHILE = "do_while"
    BREAK = "break"
    CONTINUE = "continue"
    RETURN = "return"
    GOTO = "goto"
    UNKNOWN = "unknown"

class StatementType(Enum):
    DECLARATION = "declaration"
    ASSIGNMENT = "assignment"
    CALL = "call"
    CONDITION = "condition"
    LOOP = "loop"
    RETURN = "return"
    BLOCK = "block"
    UNKNOWN = "unknown"


@dataclass
class ControlFlowNode:
    address: int
    type: ControlFlowType
    condition: str = ""
    statements: list = field(default_factory=list)
    children: list = field(default_factory=list)
    parent: typing.Optional[Any] = None


@dataclass
class VariableInfo:
    name: str
    original_name: str
    inferred_type: str = ""
    scope: str = ""
    is_parameter: bool = False
    is_return_value: bool = False


@dataclass
class EnhancementResult:
    original_pseudocode: str = ""
    enhanced_pseudocode: str = ""
    control_flow_graph: list = field(default_factory=list)
    variables: list = field(default_factory=list)
    simplified_conditions: list = field(default_factory=list)
    recovered_loops: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    analysis_success: bool = False


class DecompilerEnhancer:

    def __init__(self, pseudocode: str = ""):
        self.pseudocode = pseudocode
        self.control_flow_nodes: list[ControlFlowNode] = []
        self.variables: list[VariableInfo] = []
        logger.info("Decompiler enhancer initialized")

    def enhance(self, pseudocode: str = None) -> EnhancementResult:
        logger.info("Starting pseudocode enhancement")

        result = EnhancementResult()

        try:
            if pseudocode:
                self.pseudocode = pseudocode

            if self.pseudocode:
                result.original_pseudocode = self.pseudocode

                self._parse_control_flow()
                self._extract_variables()
                self.__simplify_conditions()
                self.__recover_loops()
                self.__recover_switches()
                self.__rename_variables()
                self.__format_code()

                result.enhanced_pseudocode = self.__generate_enhanced_code()
                result.control_flow_graph = self.control_flow_nodes
                result.variables = self.variables
                result.analysis_success = True

                logger.info("Pseudocode enhancement complete")
            else:
                result.warnings.append("No pseudocode provided")

        except Exception as e:
            logger.error(f"Pseudocode enhancement failed: {e}")
            result.warnings.append(f"Error during enhancement: {e}")

        return result

    def _parse_control_flow(self) -> None:
        if_pattern = r'if\s*\(\s*([^)]+)\s*\)\s*\{'
        matches = re.findall(if_pattern, self.pseudocode)
        for condition in matches:
            node = ControlFlowNode(
                address=0,
                type=ControlFlowType.IF,
                condition=condition
            )
            self.control_flow_nodes.append(node)

        while_pattern = r'while\s*\(\s*([^)]+)\s*\)\s*\{'
        matches = re.findall(while_pattern, self.pseudocode)
        for condition in matches:
            node = ControlFlowNode(
                address=0,
                type=ControlFlowType.WHILE,
                condition=condition
            )
            self.control_flow_nodes.append(node)

        for_pattern = r'for\s*\(\s*([^)]+)\s*\)\s*\{'
        matches = re.findall(for_pattern, self.pseudocode)
        for condition in matches:
            node = ControlFlowNode(
                address=0,
                type=ControlFlowType.FOR,
                condition=condition
            )
            self.control_flow_nodes.append(node)

    def _extract_variables(self) -> None:
        var_pattern = r'\b(int|char|long|short|float|double|void|unsigned|size_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.findall(var_pattern, self.pseudocode)

        for type_str, name in matches:
            var_info = VariableInfo(
                name=name,
                original_name=name,
                inferred_type=type_str
            )
            self.variables.append(var_info)

    def __simplify_conditions(self) -> None:
        simplified = self.pseudocode

        patterns = [
            (r'if\s*\(\s*([^)]+)\s*\)\s*\{\s*if\s*\(\s*([^)]+)\s*\)', r'if (\1 && \2)'),
            (r'if\s*\(\s*([^)]+)\s*\)\s*\{\s*\}\s*else\s*\{\s*if\s*\(\s*([^)]+)\s*\)', r'if (\1) { } else if (\2)'),
        ]

        for pattern, replacement in patterns:
            simplified = re.sub(pattern, replacement, simplified)

        self.pseudocode = simplified

    def __recover_loops(self) -> None:
        while_to_for_pattern = r'while\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*([a-zA-Z0-9_]+)\s*\)\s*\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\+\s*;'

        matches = re.findall(while_to_for_pattern, self.pseudocode)
        for var, limit, increment_var in matches:
            if var == increment_var:
                self.pseudocode = re.sub(
                    while_to_for_pattern,
                    f'for ({var} = 0; {var} < {limit}; {var}++)',
                    self.pseudocode
                )

    def __recover_switches(self) -> None:
        switch_pattern = r'if\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*==\s*([0-9]+)\s*\)'
        matches = re.findall(switch_pattern, self.pseudocode)

        if len(matches) >= 3:
            var_name = matches[0][0]
            cases = []
            for var, value in matches:
                if var == var_name:
                    cases.append("case " + value + ":")

            switch_code = "switch (" + var_name + ") {" + chr(10)
            for case in cases:
                switch_code += "    " + case + chr(10)
            switch_code += "}" + chr(10)

    def __rename_variables(self) -> None:
        name_mappings = {
            'v1': 'result',
            'v2': 'index',
            'v3': 'count',
            'v4': 'size',
            'v5': 'buffer',
            'v6': 'ptr',
            'v7': 'temp',
            'v8': 'value',
        }

        for var in self.variables:
            if var.original_name in name_mappings:
                var.name = name_mappings[var.original_name]
                self.pseudocode = re.sub(
                    rf'\b{var.original_name}\b',
                    var.name,
                    self.pseudocode
                )

    def __format_code(self) -> None:
        lines = self.pseudocode.split('\n')
        formatted_lines = []
        indent_level = 0

        for line in lines:
            stripped = line.strip()

            if stripped.startswith('}') or stripped.endswith('}'):
                indent_level = max(indent_level - 1, 0)

            formatted_lines.append('    ' * indent_level + stripped)

            if stripped.endswith('{'):
                indent_level += 1

        self.pseudocode = '\n'.join(formatted_lines)

    def __generate_enhanced_code(self) -> str:
        enhanced = "/* Enhanced pseudocode */\n\n"
        enhanced += self.pseudocode

        if self.variables:
            enhanced += "\n/* Variable descriptions */\n"
            for var in self.variables:
                enhanced += f"/* {var.name}: {var.inferred_type} */\n"

        return enhanced

    def detect_obfuscated_logic(self) -> List[str]:
        obfuscated_patterns = [
            r'goto\s+\w+',
            r'\w+\s*=\s*\w+\s*\?\s*\w+\s*:\s*\w+',
            r'\(\s*\w+\s*&&\s*\w+\s*\)\s*\|\|\s*\(',
        ]

        detected = []
        for pattern in obfuscated_patterns:
            matches = re.findall(pattern, self.pseudocode)
            for match in matches:
                detected.append(f"Detected obfuscation pattern: {match}")

        return detected

    def simplify_expression(self, expression: str) -> str:
        simplified = expression

        patterns = [
            (r'0\s*\+\s*([a-zA-Z_][a-zA-Z0-9_]*)', r'\1'),
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*0', r'\1'),
            (r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\*\s*1', r'\1'),
            (r'1\s*\*\s*([a-zA-Z_][a-zA-Z0-9_]*)', r'\1'),
        ]

        for pattern, replacement in patterns:
            simplified = re.sub(pattern, replacement, simplified)

        return simplified


def enhance_pseudocode(pseudocode: str) -> EnhancementResult:
    enhancer = DecompilerEnhancer(pseudocode)
    return enhancer.enhance()
