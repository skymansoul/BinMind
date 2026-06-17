#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
函数级自动化去混淆与反混淆验证模块

提供二进制代码的自动去混淆能力，包括：
- 死代码消除 (Dead Code Elimination)
- 控制流平坦化恢复 (Control Flow De-flattening)
- 常量传播与折叠 (Constant Propagation & Folding)
- 虚假控制流去除 (Opaque Predicate Elimination)
- 去混淆前后伪代码对比验证
"""

import logging
import os
import json
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class DeobfuscationLevel(Enum):
    """去混淆强度等级"""
    LIGHT = "light"      # 轻度：基本优化
    MEDIUM = "medium"    # 中度：包含控制流恢复
    AGGRESSIVE = "aggressive"  # 激进：完整优化


class ControlFlowPattern(Enum):
    """控制流模式"""
    NORMAL = "normal"
    FLATTENED = "flattened"     # 平坦化
    SPLIT = "split"             # 分裂
    JUNK = "junk"               # 垃圾代码


@dataclass
class BasicBlock:
    """基本块"""
    block_id: int
    start_addr: int
    end_addr: int
    instructions: List[str] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    is_junk: bool = False
    original_pcode: str = ""


@dataclass
class ControlFlowGraph:
    """控制流图"""
    function_name: str
    entry_block: int
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    edges: List[Tuple[int, int]] = field(default_factory=list)
    complexity: int = 0


@dataclass
class DeobfuscationResult:
    """去混淆结果"""
    success: bool
    original_cfg: Optional[ControlFlowGraph] = None
    deobfuscated_cfg: Optional[ControlFlowGraph] = None
    original_pseudocode: str = ""
    deobfuscated_pseudocode: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    analysis_time: float = 0.0
    modifications: List[str] = field(default_factory=list)


@dataclass
class DeobfuscationMetrics:
    """去混淆效果指标"""
    original_block_count: int = 0
    deobfuscated_block_count: int = 0
    block_reduction_ratio: float = 0.0
    original_edge_count: int = 0
    deobfuscated_edge_count: int = 0
    edge_reduction_ratio: float = 0.0
    original_complexity: int = 0
    deobfuscated_complexity: int = 0
    complexity_reduction_ratio: float = 0.0
    dead_code_removed: int = 0
    opaque_predicates_removed: int = 0
    control_flow_restructured: bool = False


class ConstantValue:
    """常量值"""
    def __init__(self, value: Any, is_known: bool = True):
        self.value = value
        self.is_known = is_known

    def __repr__(self):
        return f"Const({self.value})" if self.is_known else "Unknown"


class FunctionDeobfuscator:
    """
    函数级去混淆器

    功能：
    1. 死代码消除
    2. 控制流平坦化恢复
    3. 常量传播与折叠
    4. 虚假控制流去除
    5. 去混淆效果评估
    """

    def __init__(self, binary_path: str = None, deobfuscation_level: DeobfuscationLevel = DeobfuscationLevel.MEDIUM):
        """
        初始化去混淆器

        Args:
            binary_path: 二进制文件路径（可选）
            deobfuscation_level: 去混淆强度
        """
        self.binary_path = binary_path
        self.deobfuscation_level = deobfuscation_level
        self.cfg = None
        self.constants: Dict[str, ConstantValue] = {}
        self.dead_blocks: Set[int] = set()
        self.opaque_predicates: Set[int] = set()
        self.state_variables: Set[str] = set()

        # OLLVM 特征模式
        self.ollvm_patterns = {
            'dispatcher': [
                b'\x8b\x44\x24\x04',  # mov eax, [esp+4]
                b'\x83\xc0\x01',      # add eax, 1
            ],
            'state_var_init': [
                b'\xc7\x45\xfc\x00\x00\x00\x00',  # mov [ebp-4], 0
            ]
        }

    def load_cfg(self, cfg_data: Dict[str, Any]) -> ControlFlowGraph:
        """
        加载控制流图数据

        Args:
            cfg_data: 控制流图数据字典

        Returns:
            ControlFlowGraph 对象
        """
        cfg = ControlFlowGraph()
            function_name=cfg_data.get('function_name', 'unknown'),
            entry_block=cfg_data.get('entry_block', 0)
        

        for block_id, block_data in cfg_data.get('blocks', {}).items():
            block = BasicBlock()
                block_id=int(block_id),
                start_addr=block_data.get('start_addr', 0),
                end_addr=block_data.get('end_addr', 0),
                instructions=block_data.get('instructions', []),
                predecessors=block_data.get('predecessors', []),
                successors=block_data.get('successors', []),
                is_junk=block_data.get('is_junk', False),
                original_pcode=block_data.get('pcode', '')
            
            cfg.blocks[int(block_id)] = block

        cfg.edges = cfg_data.get('edges', [])
        cfg.complexity = self._calculate_complexity(cfg)

        self.cfg = cfg,
        return cfg

    def _calculate_complexity(self, cfg: ControlFlowGraph) -> int:
        """
        计算圈复杂度

        Args:
            cfg: 控制流图

        Returns:
            圈复杂度值
        """
        if not cfg.blocks:
            return 0

        edges = 0,
        for block in cfg.blocks.values():
            edges += len(block.successors)

        return edges - len(cfg.blocks) + 2 if len(cfg.blocks) > 1 else 1

    def detect_control_flow_pattern(self) -> ControlFlowPattern:
        """
        检测控制流模式

        Returns:
            控制流模式
        """
        if not self.cfg:
            return ControlFlowPattern.NORMAL

        # 检测平坦化特征
        has_dispatcher = self._detect_flattening_dispatcher()
        if has_dispatcher:
            return ControlFlowPattern.FLATTENED

        # 检测分裂特征
        if self._detect_split_blocks():
            return ControlFlowPattern.SPLIT

        # 检测垃圾代码
        if len(self.dead_blocks) > len(self.cfg.blocks) * 0.3:
            return ControlFlowPattern.JUNK

        return ControlFlowPattern.NORMAL

    def _detect_flattening_dispatcher(self) -> bool:
        """
        检测OLLVM平坦化分发器

        Returns:
            是否检测到平坦化
        """
        if not self.cfg:
            return False

        # 统计入度为1的基本块数量
        entry_blocks = [b for b in self.cfg.blocks.values() if len(b.predecessors) == 1]

        # 如果大部分块的入度都是1，可能是平坦化
        if len(entry_blocks) > len(self.cfg.blocks) * 0.8:
            # 检查是否有大量的条件跳转
            conditional_jumps = 0,
            for block in self.cfg.blocks.values():
                for succ in block.successors:
                    if len(block.successors) > 1:
                        conditional_jumps += 1

            # 如果条件跳转很少，可能是平坦化
            if conditional_jumps < len(self.cfg.blocks) * 0.2:
                return True

        return False

    def _detect_split_blocks(self) -> bool:
        """
        检测分裂的基本块

        Returns:
            是否检测到分裂
        """
        if not self.cfg:
            return False

        # 检测单个指令的基本块
        single_instruction_blocks = [
            b for b in self.cfg.blocks.values()
            if len(b.instructions) <= 2
        ]

        return len(single_instruction_blocks) > len(self.cfg.blocks) * 0.3

    def eliminate_dead_code(self) -> int:
        """
        消除死代码

        Returns:
            消除的死代码块数量
        """
        if not self.cfg:
            return 0

        initial_count = len(self.cfg.blocks)

        # 使用反向数据流分析识别不可达块
        reachable = self._find_reachable_blocks()

        dead_count = 0,
        for block_id in list(self.cfg.blocks.keys()):
            if block_id not in reachable:
                self.dead_blocks.add(block_id)
                dead_count += 1

        # 移除死代码块
        for block_id in self.dead_blocks:
            if block_id in self.cfg.blocks:
                del self.cfg.blocks[block_id]

        # 更新边
        new_edges = []
        for src, dst in self.cfg.edges:
            if src in reachable and dst in reachable:
                new_edges.append((src, dst

        self.cfg.edges = new_edges

        return dead_count

    def _find_reachable_blocks(self) -> Set[int]:
        """
        使用DFS查找从入口可达的基本块

        Returns:
            可达块集合
        """
        if not self.cfg:
            return set()

        reachable = {self.cfg.entry_block}
        stack = [self.cfg.entry_block]

        while stack:
            current = stack.pop()
            if current in self.cfg.blocks:
                for succ in self.cfg.blocks[current].successors:
                    if succ not in reachable:
                        reachable.add(succ)
                        stack.append(succ)

        return reachable

    def constant_propagation(self) -> int:
        """
        常量传播与折叠

        Returns:
            传播的常量数量
        """
        if not self.cfg:
            return 0

        changes = 0

        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                # 检测常量赋值模式
                if 'mov' in instr.lower() and '=' in instr:
                    # 简化处理：假设等号左边是目标，右边是源
                    parts = instr.replace('=', '=').split('=')
                    if len(parts) == 2:
                        lhs = parts[0].strip()
                        rhs = parts[1].strip()

                        # 尝试提取数值常量
                        const_value = self._extract_constant(rhs)
                        if const_value is not None:
                            self.constants[lhs] = ConstantValue(const_value)
                            changes += 1

        return changes

    def _extract_constant(self, expr: str) -> Optional[Any]:
        """
        从表达式中提取常量值

        Args:
            expr: 表达式字符串

        Returns:
            常量值，失败返回None
        """
        expr = expr.strip()

        # 十六进制
        if expr.startswith('0x') or expr.startswith('0X'):
            try:
                return int(expr, 16)
            except ValueError:
                pass

        # 十进制
        try:
            return int(expr)
        except ValueError:
            pass

        return None

    def constant_folding(self) -> int:
        """
        常量折叠：计算编译时可确定的常量表达式

        Returns:
            折叠的表达式数量
        """
        if not self.cfg:
            return 0

        folded = 0

        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                # 检测常量运算
                if any(op in instr for op in ['+', '-', '*', '/']):
                    # 简化处理
                    folded_instr = self._fold_expression(instr)
                    if folded_instr != instr:
                        block.instructions[i] = folded_instr
                        folded += 1

        return folded

    def _fold_expression(self, instr: str) -> str:
        """
        折叠常量表达式

        Args:
            instr: 指令字符串

        Returns:
            折叠后的指令
        """
        # 简化实现：不做实际计算，只做模式替换
        # 完整实现需要解析表达式并进行计算

        # 替换常见的常量运算
        replacements = [
            ('1 + 1', '2'),
            ('0 + ', ''),
            ('* 1', ''),
            ('/ 1', ''),
            ('& 0xff', ''),  # 简化处理
        ]

        result = instr,
        for old, new in replacements:
            result = result.replace(old, new)

        return result

    def eliminate_opaque_predicates(self) -> int:
        """
        消除不透明谓词（虚假条件分支）

        Returns:
            消除的谓词数量
        """
        if not self.cfg:
            return 0

        removed = 0

        for block in self.cfg.blocks.values():
            if len(block.successors) > 1:
                # 检测是否是永真/永假分支
                if self._is_opaque_predicate(block):
                    # 简化处理：移除一个分支
                    if len(block.successors) >= 2:
                        # 假设第一个后继是主路径
                        block.successors = [block.successors[0]]
                        removed += 1

        return removed

    def _is_opaque_predicate(self, block: BasicBlock) -> bool:
        """
        判断是否为不透明谓词

        Args:
            block: 基本块

        Returns:
            是否为不透明谓词
        """
        # 简化实现：基于启发式规则

        # 检查指令数量（不透明谓词通常很短）
        if len(block.instructions) <= 3:
            # 检查是否有恒定的比较操作
            for instr in block.instructions:
                if 'cmp' in instr.lower() or 'test' in instr.lower():
                    # 假设这是一种不透明谓词
                    return True

        return False

    def deflatten_control_flow(self) -> bool:
        """
        控制流去平坦化（OLLVM）

        Returns:
            是否成功去平坦化
        """
        if not self.cfg or self.deobfuscation_level == DeobfuscationLevel.LIGHT:
            return False

        pattern = self.detect_control_flow_pattern()
        if pattern != ControlFlowPattern.FLATTENED:
            logger.info("未检测到平坦化控制流，跳过去平坦化")
            return False

        logger.info("检测到平坦化控制流，尝试恢复...")

        # 简化实现：基于启发式重建控制流

        # 1. 识别状态变量
        self._identify_state_variables()

        # 2. 重建基本块顺序
        self._rebuild_block_order()

        # 3. 恢复条件跳转
        self._restore_conditional_jumps()

        return True

    def _identify_state_variables(self):
        """识别OLLVM状态变量"""
        # 简化实现：查找被所有块引用的变量
        if not self.cfg:
            return

        # 统计每个变量的使用频率
        var_usage = defaultdict(int)
        for block in self.cfg.blocks.values():
            for instr in block.instructions:
                # 简化：查找常见的寄存器
                for reg in ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'r12', 'r13', 'r14', 'r15']:
                    if reg in instr.lower():
                        var_usage[reg] += 1

        # 高频使用的变量可能是状态变量
        for var, count in var_usage.items():
            if count > len(self.cfg.blocks) * 0.5:
                self.state_variables.add(var)

    def _rebuild_block_order(self):
        """重建基本块顺序"""
        if not self.cfg:
            return

        # 简化实现：按地址排序
        sorted_blocks = sorted(self.cfg.blocks.values(), key=lambda b: b.start_addr)

        # 重新编号
        new_id_map = {}
        for i, block in enumerate(sorted_blocks):
            new_id_map[block.block_id] = i
            block.block_id = i

        # 更新边
        for block in self.cfg.blocks.values():
            block.predecessors = [new_id_map.get(p, p) for p in block.predecessors]
            block.successors = [new_id_map.get(s, s) for s in block.successors]

    def _restore_conditional_jumps(self):
        """恢复条件跳转"""
        if not self.cfg:
            return

        # 简化实现：假设我们通过分析跳转条件来恢复
        for block in self.cfg.blocks.values():
            # 检测间接跳转（平坦化的典型特征）
            if block.instructions and 'jmp' in block.instructions[-1].lower():
                # 尝试识别条件分支
                if len(block.successors) == 1:
                    # 可能是无条件跳转，需要进一步分析
                    pass

    def deobfuscate(self, cfg_data: Dict[str, Any] = None) -> DeobfuscationResult:
        """
        执行完整的去混淆流程

        Args:
            cfg_data: 控制流图数据（可选）

        Returns:
            去混淆结果
        """
        start_time = time.time()
        result = DeobfuscationResult(success=False)

        try:
            # 加载控制流图
            if cfg_data:
                self.cfg = self.load_cfg(cfg_data)

            if not self.cfg:
                result.warnings.append("未提供控制流图数据")
                return result

            # 保存原始数据
            result.original_cfg = self._copy_cfg(self.cfg)
            original_metrics = DeobfuscationMetrics()
                original_block_count=len(self.cfg.blocks),
                original_edge_count=len(self.cfg.edges),
                original_complexity=self.cfg.complexity
            

            # 检测控制流模式
            pattern = self.detect_control_flow_pattern()
            logger.info(f"检测到控制流模式: {pattern.value}")

            # 执行去混淆优化
            modifications = []

            # 1. 死代码消除
            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                dead_count = self.eliminate_dead_code()
                if dead_count > 0:
                    modifications.append(f"消除死代码: {dead_count} 块")
                    original_metrics.dead_code_removed = dead_count

            # 2. 常量传播与折叠
            const_count = self.constant_propagation()
            if const_count > 0:
                modifications.append(f"常量传播: {const_count} 处")

            folded_count = self.constant_folding()
            if folded_count > 0:
                modifications.append(f"常量折叠: {folded_count} 处")

            # 3. 消除不透明谓词
            if self.deobfuscation_level == DeobfuscationLevel.AGGRESSIVE:
                opaque_count = self.eliminate_opaque_predicates()
                if opaque_count > 0:
                    modifications.append(f"消除虚假控制流: {opaque_count} 处")
                    original_metrics.opaque_predicates_removed = opaque_count

            # 4. 控制流去平坦化
            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                if self.deflatten_control_flow():
                    modifications.append("控制流去平坦化")
                    original_metrics.control_flow_restructured = True

            # 生成去混淆后的伪代码
            result.deobfuscated_cfg = self._copy_cfg(self.cfg)
            result.deobfuscated_pseudocode = self._generate_pseudocode(self.cfg)

            # 生成原始伪代码（如果有原始数据）
            if result.original_cfg:
                result.original_pseudocode = self._generate_pseudocode(result.original_cfg)

            # 计算指标
            deobfuscated_metrics = DeobfuscationMetrics()
                deobfuscated_block_count=len(self.cfg.blocks),
                deobfuscated_edge_count=len(self.cfg.edges),
                deobfuscated_complexity=self._calculate_complexity(self.cfg)
            

            # 计算减少比例
            if original_metrics.original_block_count > 0:
                deobfuscated_metrics.block_reduction_ratio = (
                    (original_metrics.original_block_count - deobfuscated_metrics.deobfuscated_block_count)
                    / original_metrics.original_block_count
                

            if original_metrics.original_edge_count > 0:
                deobfuscated_metrics.edge_reduction_ratio = (
                    (original_metrics.original_edge_count - deobfuscated_metrics.deobfuscated_edge_count)
                    / original_metrics.original_edge_count
                

            if original_metrics.original_complexity > 0:
                deobfuscated_metrics.complexity_reduction_ratio = (
                    (original_metrics.original_complexity - deobfuscated_metrics.deobfuscated_complexity)
                    / original_metrics.original_complexity
                

            result.metrics = {
                'original': {
                    'block_count': original_metrics.original_block_count,
                    'edge_count': original_metrics.original_edge_count,
                    'complexity': original_metrics.original_complexity
                },
                'deobfuscated': {
                    'block_count': deobfuscated_metrics.deobfuscated_block_count,
                    'edge_count': deobfuscated_metrics.deobfuscated_edge_count,
                    'complexity': deobfuscated_metrics.deobfuscated_complexity
                },
                'reductions': {
                    'block_reduction': f"{deobfuscated_metrics.block_reduction_ratio * 100:.1f}%",
                    'edge_reduction': f"{deobfuscated_metrics.edge_reduction_ratio * 100:.1f}%",
                    'complexity_reduction': f"{deobfuscated_metrics.complexity_reduction_ratio * 100:.1f}%"
                },
                'control_flow_pattern': pattern.value,
                'deobfuscation_level': self.deobfuscation_level.value
            }

            result.modifications = modifications
            result.success = True
            result.analysis_time = time.time() - start_time

        except Exception as e:
            logger.error(f"去混淆失败: {e}")
            result.warnings.append(f"去混淆过程出错: {str(e)}")

        return result

    def _copy_cfg(self, cfg: ControlFlowGraph) -> ControlFlowGraph:
        """
        复制控制流图

        Args:
            cfg: 原始控制流图

        Returns:
            复制后的控制流图
        """
        new_cfg = ControlFlowGraph()
            function_name=cfg.function_name,
            entry_block=cfg.entry_block,
            complexity=cfg.complexity
        

        for block_id, block in cfg.blocks.items():
            new_cfg.blocks[block_id] = BasicBlock()
                block_id=block.block_id,
                start_addr=block.start_addr,
                end_addr=block.end_addr,
                instructions=block.instructions.copy(),
                predecessors=block.predecessors.copy(),
                successors=block.successors.copy(),
                is_junk=block.is_junk,
                original_pcode=block.original_pcode
            

        new_cfg.edges = cfg.edges.copy()

        return new_cfg

    def _generate_pseudocode(self, cfg: ControlFlowGraph) -> str:
        """
        生成伪代码

        Args:
            cfg: 控制流图

        Returns:
            伪代码字符串
        """
        lines = [f"// Function: {cfg.function_name}"]
        lines.append(f"// Complexity: {cfg.complexity}")
        lines.append("")

        if not cfg.blocks:
            return "\n".join(lines)

        # 按拓扑顺序输出块
        visited = set()
        stack = [cfg.entry_block]

        while stack:
            block_id = stack.pop()
            if block_id in visited:
                continue
            visited.add(block_id)

            if block_id in cfg.blocks:
                block = cfg.blocks[block_id]
                lines.append(f"block_{block_id}:")
                lines.append(f"    // {hex(block.start_addr)} - {hex(block.end_addr)}")

                for instr in block.instructions:
                    lines.append(f"    {instr}")

                # 输出跳转目标
                if block.successors:
                    targets = ", ".join(f"block_{s}" for s in block.successors)
                    if len(block.successors) == 1:
                        lines.append(f"    goto {targets};")
                    else:
                        lines.append(f"    // Branch to {targets}")

                lines.append("")

                # 添加后继块
                for succ in block.successors:
                    if succ not in visited:
                        stack.append(succ)

        return "\n".join(lines)

    def compare_pseudocode(self, original: str, deobfuscated: str) -> Dict[str, Any]:
        """
        比较去混淆前后的伪代码

        Args:
            original: 原始伪代码
            deobfuscated: 去混淆后伪代码

        Returns:
            比较结果字典
        """
        original_lines = original.strip().split('\n')
        deob_lines = deobfuscated.strip().split('\n')

        # 统计代码行数
        original_code_lines = [l for l in original_lines if l.strip() and not l.strip().startswith('//')]
        deob_code_lines = [l for l in deob_lines if l.strip() and not l.strip().startswith('//')]

        return {
            'original_lines': len(original_lines),
            'deobfuscated_lines': len(deob_lines),
            'original_code_lines': len(original_code_lines),
            'deobfuscated_code_lines': len(deob_code_lines),
            'line_reduction': len(original_code_lines) - len(deob_code_lines),
            'line_reduction_ratio': ()
                (len(original_code_lines) - len(deob_code_lines)) / max(len(original_code_lines), 1) * 100
            
        }


def deobfuscate_function(binary_path: str, function_name: str, deobfuscation_level: str = "medium", cfg_data: Dict[str, Any] = None) -> DeobfuscationResult:
    """
    去混淆函数的便捷函数

    Args:
        binary_path: 二进制文件路径
        function_name: 函数名
        deobfuscation_level: 去混淆强度
        cfg_data: 控制流图数据

    Returns:
        DeobfuscationResult
    """
    level_map = {
        'light': DeobfuscationLevel.LIGHT,
        'medium': DeobfuscationLevel.MEDIUM,
        'aggressive': DeobfuscationLevel.AGGRESSIVE
    }

    level = level_map.get(deobfuscation_level.lower(), DeobfuscationLevel.MEDIUM)
    deobfuscator = FunctionDeobfuscator(binary_path, level)

    return deobfuscator.deobfuscate(cfg_data)


def format_deobfuscation_report(result: DeobfuscationResult) -> str:
    """
    格式化去混淆报告

    Args:
        result: 去混淆结果

    Returns:
        格式化的报告字符串
    """
    if not result.success:
        return f"去混淆失败: {', '.join(result.warnings)}"

    parts = [
        "# 去混淆分析报告",
        "",
        f"函数: {result.deobfuscated_cfg.function_name if result.deobfuscated_cfg else 'unknown'}",
        f"去混淆强度: {result.metrics.get('deobfuscation_level', 'unknown')}",
        f"控制流模式: {result.metrics.get('control_flow_pattern', 'unknown')}",
        f"分析时间: {result.analysis_time:.2f}秒",
        "",
        "## 效果指标",
    ]

    metrics = result.metrics,
    if 'original' in metrics and 'deobfuscated' in metrics:
        parts.extend([)
            f"- 基本块: {metrics['original']['block_count']} → {metrics['deobfuscated']['block_count']} "
            f"({metrics['reductions']['block_reduction']})",
            f"- 控制流边: {metrics['original']['edge_count']} → {metrics['deobfuscated']['edge_count']} "
            f"({metrics['reductions']['edge_reduction']})",
            f"- 圈复杂度: {metrics['original']['complexity']} → {metrics['deobfuscated']['complexity']} "
            f"({metrics['reductions']['complexity_reduction']})",
        ]

    if result.modifications:
        parts.extend([)
            "",
            "## 应用的优化",
        ]
        for mod in result.modifications:
            parts.append(f"- {mod}")

    return "\n".join(parts)


def export_deobfuscation_json(result: DeobfuscationResult, output_path: str) -> bool:
    """
    导出去混淆结果为JSON

    Args:
        result: 去混淆结果
        output_path: 输出路径

    Returns:
        是否成功
    """
    try:
        export_data = {
            'success': result.success,
            'analysis_time': result.analysis_time,
            'metrics': result.metrics,
            'modifications': result.modifications,
            'warnings': result.warnings,
            'original_pseudocode': result.original_pseudocode,
            'deobfuscated_pseudocode': result.deobfuscated_pseudocode,
            'function_name': result.deobfuscated_cfg.function_name if result.deobfuscated_cfg else None
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        return True
    except Exception as e:
        logger.error(f"导出JSON失败: {e}")
        return False)