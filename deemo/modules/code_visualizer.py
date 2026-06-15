#!/usr/bin/env python3
"""
反编译代码自动生成流程图与结构图模块

本模块为反编译后的关键函数自动生成控制流图（CFG）和结构图，
支持Mermaid语法和Graphviz DOT格式输出。

Author: Deemo Analysis Team
Version: 1.3.1
"""

import os
import re
import logging
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    """输出格式枚举"""
    MERMAID = "mermaid"
    DOT = "dot"
    ASCII = "ascii"


class BlockType(Enum):
    """基本块类型枚举"""
    NORMAL = "normal"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    EXCEPTION = "exception"
    CALL = "call"
    RETURN = "return"


@dataclass
class BasicBlock:
    """
    基本块
    
    表示控制流图中的一个基本块
    """
    id: str
    instructions: List[str]
    block_type: BlockType = BlockType.NORMAL
    is_entry: bool = False
    is_exit: bool = False
    color: Optional[str] = None


@dataclass
class ControlFlowGraph:
    """
    控制流图
    
    表示函数的控制流图结构
    """
    function_name: str
    blocks: List[BasicBlock]
    edges: List[Tuple[str, str]]
    loops: List[List[str]] = field(default_factory=list)
    conditionals: List[Tuple[str, str, str]] = field(default_factory=list)


class CodeVisualizer:
    """
    代码可视化器主类
    
    基于反编译伪代码生成控制流图和结构图
    """
    
    def __init__(self):
        """初始化代码可视化器"""
        logger.info("代码可视化器初始化完成")
    
    def generate_cfg(self, pseudocode: str, function_name: str = "function") -> ControlFlowGraph:
        """
        从反编译伪代码生成控制流图
        
        Args:
            pseudocode: 反编译的伪代码
            function_name: 函数名
        
        Returns:
            控制流图对象
        """
        logger.info(f"为函数 {function_name} 生成控制流图...")
        
        blocks = []
        edges = []
        loops = []
        conditionals = []
        
        lines = [line.strip() for line in pseudocode.split('\n') if line.strip()]
        
        current_block = []
        block_id = 0
        in_comment = False
        
        for line in lines:
            if line.startswith('/*'):
                in_comment = True
                continue
            if line.endswith('*/'):
                in_comment = False
                continue
            if in_comment:
                continue
            
            if line.startswith('if') or line.startswith('else') or line.startswith('for') or \
               line.startswith('while') or line.startswith('switch') or line.startswith('return'):
                
                if current_block:
                    blocks.append(BasicBlock(
                        id=f"B{block_id}",
                        instructions=current_block,
                        block_type=BlockType.NORMAL
                    ))
                    block_id += 1
                    current_block = []
                
                if line.startswith('if'):
                    blocks.append(BasicBlock(
                        id=f"B{block_id}",
                        instructions=[line],
                        block_type=BlockType.CONDITIONAL,
                        color="#FFE4E1"
                    ))
                    block_id += 1
                    
                    match = re.search(r'if\s*\((.+?)\)', line)
                    if match:
                        cond = match.group(1)
                        conditionals.append((f"B{block_id-1}", f"B{block_id}", f"B{block_id+1}"))
                
                elif line.startswith('for') or line.startswith('while'):
                    blocks.append(BasicBlock(
                        id=f"B{block_id}",
                        instructions=[line],
                        block_type=BlockType.LOOP,
                        color="#E0FFE0"
                    ))
                    block_id += 1
                    loops.append([f"B{block_id-1}"])
                
                elif line.startswith('return'):
                    blocks.append(BasicBlock(
                        id=f"B{block_id}",
                        instructions=[line],
                        block_type=BlockType.RETURN,
                        is_exit=True,
                        color="#E6E6FA"
                    ))
                    block_id += 1
            
            else:
                current_block.append(line)
        
        if current_block:
            blocks.append(BasicBlock(
                id=f"B{block_id}",
                instructions=current_block,
                block_type=BlockType.NORMAL
            ))
        
        for i in range(len(blocks) - 1):
            edges.append((blocks[i].id, blocks[i+1].id))
        
        if blocks:
            blocks[0].is_entry = True
            if blocks[-1].block_type != BlockType.RETURN:
                blocks[-1].is_exit = True
        
        cfg = ControlFlowGraph(
            function_name=function_name,
            blocks=blocks,
            edges=edges,
            loops=loops,
            conditionals=conditionals
        )
        
        logger.info(f"控制流图生成完成: {len(blocks)} 个基本块, {len(edges)} 条边")
        return cfg
    
    def generate_mermaid(self, cfg: ControlFlowGraph) -> str:
        """
        生成Mermaid流程图文本
        
        Args:
            cfg: 控制流图对象
        
        Returns:
            Mermaid语法字符串
        """
        lines = ["flowchart TD"]
        
        for block in cfg.blocks:
            label = "<br/>".join(block.instructions[:5])
            if len(block.instructions) > 5:
                label += "<br/>..."
            
            style = ""
            if block.color:
                style = f" style {block.id} fill:{block.color},stroke:#333,stroke-width:2px"
            
            if block.is_entry:
                lines.append(f"    {block.id}([入口]){style}")
            elif block.is_exit:
                lines.append(f"    {block.id}([出口]){style}")
            elif block.block_type == BlockType.CONDITIONAL:
                lines.append(f"    {block.id}{{\"{label}\"}}")
            else:
                lines.append(f"    {block.id}[\"{label}\"]{style}")
        
        for from_block, to_block in cfg.edges:
            lines.append(f"    {from_block} --> {to_block}")
        
        for cond in cfg.conditionals:
            if len(cond) >= 3:
                lines.append(f"    {cond[0]} -->|是| {cond[1]}")
                lines.append(f"    {cond[0]} -->|否| {cond[2]}")
        
        return "\n".join(lines)
    
    def generate_dot(self, cfg: ControlFlowGraph) -> str:
        """
        生成Graphviz DOT格式文本
        
        Args:
            cfg: 控制流图对象
        
        Returns:
            DOT格式字符串
        """
        lines = ["digraph CFG {", "    rankdir=TD;"]
        
        for block in cfg.blocks:
            label = "\\n".join(block.instructions[:5])
            if len(block.instructions) > 5:
                label += "\\n..."
            
            shape = "box"
            color = ""
            
            if block.is_entry:
                shape = "ellipse"
                label = "入口"
            elif block.is_exit:
                shape = "ellipse"
                label = "出口"
            elif block.block_type == BlockType.CONDITIONAL:
                shape = "diamond"
                color = 'fillcolor="#FFE4E1",style=filled'
            elif block.block_type == BlockType.LOOP:
                color = 'fillcolor="#E0FFE0",style=filled'
            elif block.block_type == BlockType.RETURN:
                color = 'fillcolor="#E6E6FA",style=filled'
            
            color_attr = f", {color}" if color else ""
            lines.append(f'    {block.id} [label="{label}", shape={shape}{color_attr}];')
        
        for from_block, to_block in cfg.edges:
            lines.append(f"    {from_block} -> {to_block};")
        
        for cond in cfg.conditionals:
            if len(cond) >= 3:
                lines.append(f'    {cond[0]} -> {cond[1]} [label="是"];')
                lines.append(f'    {cond[0]} -> {cond[2]} [label="否"];')
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def generate_ascii(self, cfg: ControlFlowGraph) -> str:
        """
        生成ASCII文本图形
        
        Args:
            cfg: 控制流图对象
        
        Returns:
            ASCII图形字符串
        """
        lines = []
        
        max_instructions = max(len(block.instructions) for block in cfg.blocks) if cfg.blocks else 1
        
        for i, block in enumerate(cfg.blocks):
            if i > 0:
                lines.append(" " * 4 + "|" + "_" * 40)
            
            header = f"┌── {block.id} {'(入口)' if block.is_entry else '(出口)' if block.is_exit else ''}"
            lines.append(header + "─" * (45 - len(header)) + "┐")
            
            for j, instr in enumerate(block.instructions):
                instr = instr[:40]
                lines.append(f"│  {instr}" + " " * (40 - len(instr)) + " │")
            
            for j in range(len(block.instructions), max_instructions):
                lines.append("│" + " " * 42 + "│")
            
            lines.append("└" + "─" * 44 + "┘")
        
        for from_block, to_block in cfg.edges:
            lines.append(f"    {from_block} ──> {to_block}")
        
        return "\n".join(lines)
    
    def visualize(self, pseudocode: str, function_name: str = "function", 
                  output_format: OutputFormat = OutputFormat.MERMAID) -> str:
        """
        生成可视化输出
        
        Args:
            pseudocode: 反编译伪代码
            function_name: 函数名
            output_format: 输出格式
        
        Returns:
            可视化文本
        """
        cfg = self.generate_cfg(pseudocode, function_name)
        
        if output_format == OutputFormat.MERMAID:
            return self.generate_mermaid(cfg)
        elif output_format == OutputFormat.DOT:
            return self.generate_dot(cfg)
        elif output_format == OutputFormat.ASCII:
            return self.generate_ascii(cfg)
        else:
            return self.generate_mermaid(cfg)
    
    def save_visualization(self, pseudocode: str, output_path: str, 
                           function_name: str = "function", 
                           output_format: OutputFormat = OutputFormat.MERMAID) -> bool:
        """
        保存可视化结果到文件
        
        Args:
            pseudocode: 反编译伪代码
            output_path: 输出文件路径
            function_name: 函数名
            output_format: 输出格式
        
        Returns:
            是否成功
        """
        try:
            content = self.visualize(pseudocode, function_name, output_format)
            
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"可视化结果已保存到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"保存可视化结果失败: {e}")
            return False
    
    def analyze_pseudocode(self, pseudocode: str) -> Dict[str, Any]:
        """
        分析伪代码结构
        
        Args:
            pseudocode: 反编译伪代码
        
        Returns:
            分析结果字典
        """
        analysis = {
            'lines': 0,
            'functions': 0,
            'loops': 0,
            'conditionals': 0,
            'returns': 0,
            'calls': 0
        }
        
        lines = pseudocode.split('\n')
        analysis['lines'] = len(lines)
        
        for line in lines:
            line = line.strip()
            if line.startswith('int ') or line.startswith('void ') or line.startswith('char ') or line.startswith('bool '):
                if '(' in line and ')' in line:
                    analysis['functions'] += 1
            elif line.startswith('for '):
                analysis['loops'] += 1
            elif line.startswith('while '):
                analysis['loops'] += 1
            elif line.startswith('if '):
                analysis['conditionals'] += 1
            elif line.startswith('return '):
                analysis['returns'] += 1
            elif '(' in line and ')' in line and ';' in line:
                func_name = line.split('(')[0].strip()
                if func_name and not line.startswith('if') and not line.startswith('for') and not line.startswith('while'):
                    analysis['calls'] += 1
        
        return analysis


def get_code_visualizer() -> CodeVisualizer:
    """
    获取代码可视化器实例（工厂函数）
    
    Returns:
        CodeVisualizer实例
    """
    return CodeVisualizer()
