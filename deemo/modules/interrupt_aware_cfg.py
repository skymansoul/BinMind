#!/usr/bin/env python3
"""
中断驱动的控制流恢复

分析中断向量表，为每个ISR构建独立控制流图。
检测中断嵌套、资源共享引发的并发漏洞。
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class InterruptType(Enum):
    """中断类型枚举"""
    IRQ = "irq"
    FIQ = "fiq"
    SWI = "swi"
    RESET = "reset"
    ABORT = "abort"
    UNDEF = "undefined"


class ISRStatus(Enum):
    """ISR状态枚举"""
    ENABLED = "enabled"
    DISABLED = "disabled"
    PENDING = "pending"


class ConcurrencyIssueType(Enum):
    """并发问题类型枚举"""
    RACE_CONDITION = "race_condition"
    DEADLOCK = "deadlock"
    PRIORITY_INVERSION = "priority_inversion"
    NESTING_VIOLATION = "nesting_violation"
    UNSAFE_SHARED_ACCESS = "unsafe_shared_access"


@dataclass
class ISRInfo:
    """ISR信息"""
    vector_number: int
    interrupt_type: InterruptType
    address: int
    name: str = ""
    status: ISRStatus = ISRStatus.ENABLED
    priority: int = 0
    description: str = ""


@dataclass
class ControlFlowNode:
    """控制流图节点"""
    address: int
    instruction_count: int = 0
    is_call: bool = False
    is_return: bool = False
    is_interrupt_entry: bool = False
    is_interrupt_exit: bool = False


@dataclass
class ControlFlowEdge:
    """控制流图边"""
    from_address: int
    to_address: int
    edge_type: str = "direct"  # direct, conditional, indirect, interrupt


@dataclass
class ISRControlFlowGraph:
    """ISR控制流图"""
    isr_info: ISRInfo
    nodes: List[ControlFlowNode]
    edges: List[ControlFlowEdge]
    entry_points: List[int] = field(default_factory=list)
    exit_points: List[int] = field(default_factory=list)


@dataclass
class SharedResource:
    """共享资源"""
    name: str
    address: int
    size: int
    accessors: List[str] = field(default_factory=list)  # ISR或函数名列表
    is_protected: bool = False


@dataclass
class ConcurrencyIssue:
    """并发问题"""
    issue_type: ConcurrencyIssueType
    description: str
    isr_names: List[str]
    resources: List[SharedResource]
    severity: str = "medium"
    location: Optional[int] = None


@dataclass
class InterruptCFGResult:
    """中断CFG分析结果"""
    success: bool
    isrs: List[ISRInfo]
    isr_cfgs: List[ISRControlFlowGraph]
    shared_resources: List[SharedResource]
    concurrency_issues: List[ConcurrencyIssue]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class VectorTableParser(ABC):
    """向量表解析器基类"""
    
    @abstractmethod
    def parse(self, binary_data: bytes, base_address: int = 0) -> List[ISRInfo]:
        """
        解析向量表
        
        Args:
            binary_data: 二进制数据
            base_address: 基地址
        
        Returns:
            ISR信息列表
        """
        pass


class ARMVectorTableParser(VectorTableParser):
    """ARM向量表解析器"""
    
    def parse(self, binary_data: bytes, base_address: int = 0) -> List[ISRInfo]:
        """解析ARM向量表"""
        isrs = []
        
        # ARM向量表布局
        vector_info = [
            (0, InterruptType.RESET, "Reset"),
            (1, InterruptType.UNDEF, "Undefined"),
            (2, InterruptType.SWI, "SWI"),
            (3, InterruptType.ABORT, "PrefetchAbort"),
            (4, InterruptType.ABORT, "DataAbort"),
            (5, InterruptType.IRQ, "IRQ"),
            (6, InterruptType.FIQ, "FIQ"),
        ]
        
        for vector_num, int_type, name in vector_info:
            offset = vector_num * 4
            if offset + 4 <= len(binary_data):
                address = int.from_bytes(binary_data[offset:offset+4], 'little')
                if address != 0:
                    isrs.append(ISRInfo(
                        vector_number=vector_num,
                        interrupt_type=int_type,
                        address=address,
                        name=name,
                        status=ISRStatus.ENABLED
                    ))
        
        # 解析向量表之后的ISR向量
        offset = 0x1C  # 第七个向量之后
        vector_num = 7
        
        while offset + 4 <= len(binary_data):
            address = int.from_bytes(binary_data[offset:offset+4], 'little')
            if address == 0:
                break
            
            isrs.append(ISRInfo(
                vector_number=vector_num,
                interrupt_type=InterruptType.IRQ,
                address=address,
                name=f"IRQ_{vector_num}",
                status=ISRStatus.ENABLED
            ))
            
            offset += 4
            vector_num += 1
        
        return isrs


class X86VectorTableParser(VectorTableParser):
    """x86向量表解析器"""
    
    def parse(self, binary_data: bytes, base_address: int = 0) -> List[ISRInfo]:
        """解析x86中断向量表"""
        isrs = []
        
        # x86 IDT通常包含256个中断向量
        for i in range(256):
            offset = i * 8  # 每个IDT条目8字节
            if offset + 8 <= len(binary_data):
                # 低2字节是偏移低16位，高2字节是段选择子，最后2字节是偏移高16位
                offset_low = int.from_bytes(binary_data[offset:offset+2], 'little')
                segment = int.from_bytes(binary_data[offset+2:offset+4], 'little')
                offset_high = int.from_bytes(binary_data[offset+6:offset+8], 'little')
                
                address = (offset_high << 16) | offset_low
                
                if address != 0:
                    isrs.append(ISRInfo(
                        vector_number=i,
                        interrupt_type=InterruptType.IRQ,
                        address=address,
                        name=f"INT_{i}",
                        status=ISRStatus.ENABLED
                    ))
        
        return isrs


class ISRCFGBuilder:
    """ISR控制流图构建器"""
    
    def __init__(self):
        """初始化CFG构建器"""
        self.nodes: Dict[int, ControlFlowNode] = {}
        self.edges: List[ControlFlowEdge] = []
    
    def build(self, isr_info: ISRInfo, instructions: List[Dict]) -> ISRControlFlowGraph:
        """
        构建ISR的控制流图
        
        Args:
            isr_info: ISR信息
            instructions: 指令列表
        
        Returns:
            ISR控制流图
        """
        self.nodes = {}
        self.edges = []
        
        if not instructions:
            return ISRControlFlowGraph(
                isr_info=isr_info,
                nodes=[],
                edges=[],
                entry_points=[isr_info.address],
                exit_points=[]
            )
        
        # 创建节点
        for instr in instructions:
            addr = instr.get('address', 0)
            self.nodes[addr] = ControlFlowNode(
                address=addr,
                instruction_count=1,
                is_call=instr.get('mnemonic') in ['bl', 'call'],
                is_return=instr.get('mnemonic') in ['bx', 'ret', 'pop'],
                is_interrupt_entry=(addr == isr_info.address),
                is_interrupt_exit=instr.get('mnemonic') in ['bx', 'ret']
            )
        
        # 创建边
        for i, instr in enumerate(instructions[:-1]):
            from_addr = instr.get('address', 0)
            next_instr = instructions[i+1]
            to_addr = next_instr.get('address', 0)
            
            edge_type = "direct"
            mnemonic = instr.get('mnemonic', '')
            
            if mnemonic in ['b', 'jmp']:
                edge_type = "direct"
            elif mnemonic in ['bl', 'call']:
                edge_type = "direct"
                # 添加返回边
                self.edges.append(ControlFlowEdge(
                    from_address=to_addr,
                    to_address=from_addr + instr.get('size', 4),
                    edge_type="direct"
                ))
            elif mnemonic in ['bne', 'beq', 'jne', 'je', 'jcc']:
                edge_type = "conditional"
                # 添加条件分支的两条边
                self.edges.append(ControlFlowEdge(
                    from_address=from_addr,
                    to_address=to_addr,
                    edge_type="direct"  # fallthrough
                ))
            
            self.edges.append(ControlFlowEdge(
                from_address=from_addr,
                to_address=to_addr,
                edge_type=edge_type
            ))
        
        entry_points = [isr_info.address]
        exit_points = [n.address for n in self.nodes.values() if n.is_return]
        
        return ISRControlFlowGraph(
            isr_info=isr_info,
            nodes=list(self.nodes.values()),
            edges=self.edges,
            entry_points=entry_points,
            exit_points=exit_points
        )


class InterruptAwareCFG:
    """
    中断驱动的控制流恢复
    
    分析中断向量表，为每个ISR构建独立控制流图。
    检测中断嵌套、资源共享引发的并发漏洞。
    """
    
    def __init__(self, architecture: str = "arm"):
        """
        初始化分析器
        
        Args:
            architecture: 目标架构（arm, x86）
        """
        self.architecture = architecture
        self.vector_parser = self._create_vector_parser()
        self.cfg_builder = ISRCFGBuilder()
    
    def _create_vector_parser(self) -> VectorTableParser:
        """创建向量表解析器"""
        if self.architecture.lower() == "x86":
            return X86VectorTableParser()
        else:
            return ARMVectorTableParser()
    
    def parse_vector_table(self, binary_path: str, vector_table_address: int = 0) -> List[ISRInfo]:
        """
        解析中断向量表
        
        Args:
            binary_path: 二进制文件路径
            vector_table_address: 向量表地址（默认0）
        
        Returns:
            ISR信息列表
        """
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return []
        
        try:
            with open(binary_path, 'rb') as f:
                f.seek(vector_table_address)
                vector_data = f.read(1024)  # 读取1KB足够解析向量表
            
            return self.vector_parser.parse(vector_data, vector_table_address)
        
        except Exception as e:
            logger.error(f"解析向量表失败: {e}")
            return []
    
    def build_isr_cfgs(self, binary_path: str, isrs: List[ISRInfo]) -> List[ISRControlFlowGraph]:
        """
        为每个ISR构建控制流图
        
        Args:
            binary_path: 二进制文件路径
            isrs: ISR列表
        
        Returns:
            ISR控制流图列表
        """
        cfgs = []
        
        for isr in isrs:
            instructions = self._extract_isr_instructions(binary_path, isr.address)
            cfg = self.cfg_builder.build(isr, instructions)
            cfgs.append(cfg)
        
        return cfgs
    
    def _extract_isr_instructions(self, binary_path: str, start_address: int) -> List[Dict]:
        """提取ISR指令"""
        instructions = []
        
        try:
            import capstone
            
            with open(binary_path, 'rb') as f:
                f.seek(0)
                data = f.read()
            
            # 找到相对于文件的偏移
            offset = start_address  # 假设地址是相对于文件的
            
            if self.architecture.lower() == "x86":
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            else:
                md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            
            md.detail = True
            
            max_instructions = 100  # 限制指令数量
            count = 0
            
            for insn in md.disasm(data[offset:], start_address):
                instructions.append({
                    'address': insn.address,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': bytes(insn.bytes),
                    'size': insn.size
                })
                
                count += 1
                if count >= max_instructions:
                    break
                
                # 检测ISR结束
                if insn.mnemonic in ['bx', 'ret', 'pop']:
                    break
        
        except ImportError:
            logger.warning("capstone未安装，无法反汇编")
        
        return instructions
    
    def detect_shared_resources(self, isr_cfgs: List[ISRControlFlowGraph]) -> List[SharedResource]:
        """
        检测共享资源
        
        Args:
            isr_cfgs: ISR控制流图列表
        
        Returns:
            共享资源列表
        """
        memory_accesses: Dict[int, List[str]] = {}
        
        for cfg in isr_cfgs:
            isr_name = cfg.isr_info.name
            
            # 简化实现：假设所有内存访问都是对全局变量的访问
            for node in cfg.nodes:
                if node.address != cfg.isr_info.address:
                    # 将指令地址作为资源地址的代理
                    if node.address not in memory_accesses:
                        memory_accesses[node.address] = []
                    if isr_name not in memory_accesses[node.address]:
                        memory_accesses[node.address].append(isr_name)
        
        shared_resources = []
        
        for addr, accessors in memory_accesses.items():
            if len(accessors) > 1:
                shared_resources.append(SharedResource(
                    name=f"resource_{hex(addr)}",
                    address=addr,
                    size=4,
                    accessors=accessors,
                    is_protected=False
                ))
        
        return shared_resources
    
    def detect_concurrency_issues(self, isr_cfgs: List[ISRControlFlowGraph], 
                                  shared_resources: List[SharedResource]) -> List[ConcurrencyIssue]:
        """
        检测并发问题
        
        Args:
            isr_cfgs: ISR控制流图列表
            shared_resources: 共享资源列表
        
        Returns:
            并发问题列表
        """
        issues = []
        
        # 检测不安全的共享访问
        for resource in shared_resources:
            if not resource.is_protected and len(resource.accessors) >= 2:
                issues.append(ConcurrencyIssue(
                    issue_type=ConcurrencyIssueType.UNSAFE_SHARED_ACCESS,
                    description=f"资源 {resource.name} 被多个ISR访问但未保护",
                    isr_names=resource.accessors,
                    resources=[resource],
                    severity="high",
                    location=resource.address
                ))
        
        # 检测中断嵌套问题
        for cfg in isr_cfgs:
            nesting_depth = 0
            for node in cfg.nodes:
                if node.is_interrupt_entry:
                    nesting_depth += 1
                    if nesting_depth > 1:
                        issues.append(ConcurrencyIssue(
                            issue_type=ConcurrencyIssueType.NESTING_VIOLATION,
                            description=f"ISR {cfg.isr_info.name} 可能导致中断嵌套过深",
                            isr_names=[cfg.isr_info.name],
                            resources=[],
                            severity="medium",
                            location=node.address
                        ))
        
        # 检测优先级反转（简化：高优先级ISR等待低优先级ISR释放资源）
        for resource in shared_resources:
            if len(resource.accessors) >= 2:
                priorities = []
                for isr_name in resource.accessors:
                    isr = next((cfg.isr_info for cfg in isr_cfgs if cfg.isr_info.name == isr_name), None)
                    if isr:
                        priorities.append((isr_name, isr.priority))
                
                if priorities:
                    priorities.sort(key=lambda x: x[1])
                    if priorities[0][1] < priorities[-1][1]:
                        issues.append(ConcurrencyIssue(
                            issue_type=ConcurrencyIssueType.PRIORITY_INVERSION,
                            description=f"资源 {resource.name} 存在优先级反转风险",
                            isr_names=[p[0] for p in priorities],
                            resources=[resource],
                            severity="high"
                        ))
        
        return issues
    
    def analyze(self, binary_path: str, vector_table_address: int = 0) -> InterruptCFGResult:
        """
        执行完整分析
        
        Args:
            binary_path: 二进制文件路径
            vector_table_address: 向量表地址
        
        Returns:
            分析结果
        """
        if not os.path.exists(binary_path):
            return InterruptCFGResult(
                success=False,
                isrs=[],
                isr_cfgs=[],
                shared_resources=[],
                concurrency_issues=[],
                errors=[f"文件不存在: {binary_path}"]
            )
        
        try:
            # 解析向量表
            isrs = self.parse_vector_table(binary_path, vector_table_address)
            
            if not isrs:
                return InterruptCFGResult(
                    success=False,
                    isrs=[],
                    isr_cfgs=[],
                    shared_resources=[],
                    concurrency_issues=[],
                    errors=["未找到ISR"]
                )
            
            # 构建ISR控制流图
            isr_cfgs = self.build_isr_cfgs(binary_path, isrs)
            
            # 检测共享资源
            shared_resources = self.detect_shared_resources(isr_cfgs)
            
            # 检测并发问题
            concurrency_issues = self.detect_concurrency_issues(isr_cfgs, shared_resources)
            
            return InterruptCFGResult(
                success=True,
                isrs=isrs,
                isr_cfgs=isr_cfgs,
                shared_resources=shared_resources,
                concurrency_issues=concurrency_issues
            )
        
        except Exception as e:
            logger.error(f"分析失败: {e}")
            return InterruptCFGResult(
                success=False,
                isrs=[],
                isr_cfgs=[],
                shared_resources=[],
                concurrency_issues=[],
                errors=[str(e)]
            )
    
    def generate_dot_graph(self, isr_cfgs: List[ISRControlFlowGraph], output_path: str) -> bool:
        """
        生成DOT格式的控制流图
        
        Args:
            isr_cfgs: ISR控制流图列表
            output_path: 输出路径
        
        Returns:
            是否成功
        """
        try:
            with open(output_path, 'w') as f:
                f.write("digraph ISR_CFGS {\n")
                f.write("    rankdir=TB;\n")
                
                for cfg in isr_cfgs:
                    f.write(f"    subgraph cluster_{cfg.isr_info.name} {{\n")
                    f.write(f"        label=\"{cfg.isr_info.name}\";\n")
                    f.write(f"        color=blue;\n")
                    
                    for node in cfg.nodes:
                        shape = "ellipse"
                        if node.is_interrupt_entry:
                            shape = "doublecircle"
                        elif node.is_return:
                            shape = "diamond"
                        
                        f.write(f"        n_{node.address} [label=\"0x{node.address:x}\", shape={shape}];\n")
                    
                    for edge in cfg.edges:
                        f.write(f"        n_{edge.from_address} -> n_{edge.to_address};\n")
                    
                    f.write("    }\n")
                
                f.write("}\n")
            
            logger.info(f"DOT图已保存: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"生成DOT图失败: {e}")
            return False
    
    def generate_report(self, result: InterruptCFGResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 分析结果
        
        Returns:
            报告字符串
        """
        report = []
        report.append("=" * 60)
        report.append("中断驱动控制流分析报告")
        report.append("=" * 60)
        report.append(f"架构: {self.architecture}")
        report.append(f"成功: {result.success}")
        report.append(f"ISR数量: {len(result.isrs)}")
        report.append(f"共享资源数量: {len(result.shared_resources)}")
        report.append(f"并发问题数量: {len(result.concurrency_issues)}")
        report.append("")
        
        if result.isrs:
            report.append("ISR列表:")
            report.append("-" * 40)
            for isr in result.isrs:
                report.append(f"向量 {isr.vector_number}: {isr.name}")
                report.append(f"  地址: 0x{isr.address:x}")
                report.append(f"  类型: {isr.interrupt_type.value}")
                report.append(f"  状态: {isr.status.value}")
                report.append("")
        
        if result.shared_resources:
            report.append("共享资源:")
            report.append("-" * 40)
            for resource in result.shared_resources:
                report.append(f"资源: {resource.name}")
                report.append(f"  地址: 0x{resource.address:x}")
                report.append(f"  访问者: {', '.join(resource.accessors)}")
                report.append(f"  已保护: {'是' if resource.is_protected else '否'}")
                report.append("")
        
        if result.concurrency_issues:
            report.append("并发问题:")
            report.append("-" * 40)
            for issue in result.concurrency_issues:
                report.append(f"类型: {issue.issue_type.value}")
                report.append(f"  描述: {issue.description}")
                report.append(f"  涉及ISR: {', '.join(issue.isr_names)}")
                report.append(f"  严重程度: {issue.severity}")
                if issue.location:
                    report.append(f"  位置: 0x{issue.location:x}")
                report.append("")
        
        return "\n".join(report)
