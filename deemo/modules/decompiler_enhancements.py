"""
逻辑重构增强模块

功能:
    1. 增强反编译器的伪代码输出
    2. 重构复杂的控制流结构
    3. 简化嵌套条件语句
    4. 恢复循环和switch语句

核心技术:
    - 控制流分析
    - 结构化重构
    - 变量命名优化
    - 代码简化
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ControlFlowType(Enum):
    """控制流类型"""
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
    """语句类型"""
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
    """控制流节点"""
    address: int
    type: ControlFlowType
    condition: str = ""
    statements: List[str] = field(default_factory=list)
    children: List['ControlFlowNode'] = field(default_factory=list)
    parent: Optional['ControlFlowNode'] = None


@dataclass
class VariableInfo:
    """变量信息"""
    name: str
    original_name: str
    inferred_type: str = ""
    scope: str = ""
    is_parameter: bool = False
    is_return_value: bool = False


@dataclass
class EnhancementResult:
    """增强结果"""
    original_pseudocode: str = ""
    enhanced_pseudocode: str = ""
    control_flow_graph: List[ControlFlowNode] = field(default_factory=list)
    variables: List[VariableInfo] = field(default_factory=list)
    simplified_conditions: List[str] = field(default_factory=list)
    recovered_loops: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


class DecompilerEnhancer:
    """反编译器增强器"""
    
    def __init__(self, pseudocode: str = ""):
        """初始化增强器"""
        self.pseudocode = pseudocode
        self.control_flow_nodes: List[ControlFlowNode] = []
        self.variables: List[VariableInfo] = []
        
        logger.info("反编译器增强器初始化完成")
    
    def enhance(self, pseudocode: str = None) -> EnhancementResult:
        """执行伪代码增强"""
        logger.info("开始伪代码增强")
        
        result = EnhancementResult()
        
        try:
            if pseudocode:
                self.pseudocode = pseudocode
            
            if self.pseudocode:
                result.original_pseudocode = self.pseudocode
                
                self._parse_control_flow()
                self._extract_variables()
                self._simplify_conditions()
                self._recover_loops()
                self._recover_switches()
                self._rename_variables()
                self._format_code()
                
                result.enhanced_pseudocode = self._generate_enhanced_code()
                result.control_flow_graph = self.control_flow_nodes
                result.variables = self.variables
                result.analysis_success = True
                
                logger.info("伪代码增强完成")
            else:
                result.warnings.append("未提供伪代码")
                
        except Exception as e:
            logger.error(f"伪代码增强失败: {e}")
            result.warnings.append(f"增强过程中发生错误: {e}")
        
        return result
    
    def _parse_control_flow(self) -> None:
        """解析控制流"""
        # 解析if语句
        if_pattern = r'if\s*\(\s*([^)]+)\s*\)\s*\{'
        matches = re.findall(if_pattern, self.pseudocode)
        for condition in matches:
            node = ControlFlowNode(
                address=0,
                type=ControlFlowType.IF,
                condition=condition
            )
            self.control_flow_nodes.append(node)
        
        # 解析while语句
        while_pattern = r'while\s*\(\s*([^)]+)\s*\)\s*\{'
        matches = re.findall(while_pattern, self.pseudocode)
        for condition in matches:
            node = ControlFlowNode(
                address=0,
                type=ControlFlowType.WHILE,
                condition=condition
            )
            self.control_flow_nodes.append(node)
        
        # 解析for语句
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
        """提取变量"""
        # 提取变量声明
        var_pattern = r'\b(int|char|long|short|float|double|void|unsigned|size_t)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.findall(var_pattern, self.pseudocode)
        
        for type_str, name in matches:
            var_info = VariableInfo(
                name=name,
                original_name=name,
                inferred_type=type_str
            )
            self.variables.append(var_info)
    
    def _simplify_conditions(self) -> None:
        """简化条件语句"""
        # 简化嵌套if语句
        simplified = self.pseudocode
        
        # 合理合并条件
        patterns = [
            (r'if\s*\(\s*([^)]+)\s*\)\s*\{\s*if\s*\(\s*([^)]+)\s*\)', r'if (\1 && \2)'),
            (r'if\s*\(\s*([^)]+)\s*\)\s*\{\s*\}\s*else\s*\{\s*if\s*\(\s*([^)]+)\s*\)', r'if (\1) { } else if (\2)'),
        ]
        
        for pattern, replacement in patterns:
            simplified = re.sub(pattern, replacement, simplified)
        
        self.pseudocode = simplified
    
    def _recover_loops(self) -> None:
        """恢复循环结构"""
        # 将while循环转换为for循环（如果可能）
        while_to_for_pattern = r'while\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*<\s*([a-zA-Z0-9_]+)\s*\)\s*\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\+\s*;'
        
        matches = re.findall(while_to_for_pattern, self.pseudocode)
        for var, limit, increment_var in matches:
            if var == increment_var:
                # 可以转换为for循环
                self.pseudocode = re.sub(
                    while_to_for_pattern,
                    f'for ({var} = 0; {var} < {limit}; {var}++)',
                    self.pseudocode
                )
    
    def _recover_switches(self) -> None:
        """恢复switch语句"""
        # 检测连续的if-else模式，转换为switch
        switch_pattern = r'if\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*==\s*([0-9]+)\s*\)'
        matches = re.findall(switch_pattern, self.pseudocode)
        
        if len(matches) >= 3:
            # 可能可以转换为switch
            var_name = matches[0][0]
            cases = []
            for var, value in matches:
                if var == var_name:
                    cases.append("case " + value + ":")
            
            # 生成switch语句
            switch_code = "switch (" + var_name + ") {" + chr(10)
            for case in cases:
                switch_code += "    " + case + chr(10)
            switch_code += "}" + chr(10)
    
    def _rename_variables(self) -> None:
        """重命名变量"""
        # 根据上下文推断更好的变量名
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
    
    def _format_code(self) -> None:
        """格式化代码"""
        # 添加适当的缩进
        lines = self.pseudocode.split('\n')
        formatted_lines = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            
            if stripped.startswith('}') or stripped.endswith('}'):
                indent_level = max(0, indent_level - 1)
            
            formatted_lines.append('    ' * indent_level + stripped)
            
            if stripped.endswith('{'):
                indent_level += 1
        
        self.pseudocode = '\n'.join(formatted_lines)
    
    def _generate_enhanced_code(self) -> str:
        """生成增强后的代码"""
        # 添加注释
        enhanced = "/* 增强后的伪代码 */\n\n"
        enhanced += self.pseudocode
        
        # 添加变量说明
        if self.variables:
            enhanced += "\n/* 变量说明 */\n"
            for var in self.variables:
                enhanced += f"/* {var.name}: {var.inferred_type} */\n"
        
        return enhanced
    
    def detect_obfuscated_logic(self) -> List[str]:
        """检测混淆的逻辑"""
        obfuscated_patterns = [
            r'goto\s+\w+',  # goto语句
            r'\w+\s*=\s*\w+\s*\?\s*\w+\s*:\s*\w+',  # 三元运算符
            r'\(\s*\w+\s*&&\s*\w+\s*\)\s*\|\|\s*\(',  # 复杂条件
        ]
        
        detected = []
        for pattern in obfuscated_patterns:
            matches = re.findall(pattern, self.pseudocode)
            for match in matches:
                detected.append(f"检测到混淆模式: {match}")
        
        return detected
    
    def simplify_expression(self, expression: str) -> str:
        """简化表达式"""
        # 移除多余的括号
        simplified = expression
        
        # 常量折叠
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
    """便捷函数：增强伪代码"""
    enhancer = DecompilerEnhancer(pseudocode)
    return enhancer.enhance()