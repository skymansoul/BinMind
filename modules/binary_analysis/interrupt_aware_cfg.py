"""
中断感知control flowgraph

support多architecture中断vector表解析和ISRcontrol flowgraph构建
检测并发问题如race condition和priority反转
"""

import logging
import os
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class InterruptType:
    """中断type"""
    __slots__ = ('_val',)

    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

    IRQ: 'InterruptType'
    FIQ: 'InterruptType'
    SWI: 'InterruptType'
    RESET: 'InterruptType'
    ABORT: 'InterruptType'
    UNDEF: 'InterruptType'

InterruptType.IRQ = InterruptType("irq")
InterruptType.FIQ = InterruptType("fiq")
InterruptType.SWI = InterruptType("swi")
InterruptType.RESET = InterruptType("reset")
InterruptType.ABORT = InterruptType("abort")
InterruptType.UNDEF = InterruptType("undefined")


class ISRStatus:
    """ISRstatus"""
    __slots__ = ('_val',)

    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

    ENABLED: 'ISRStatus'
    DISABLED: 'ISRStatus'
    PENDING: 'ISRStatus'

ISRStatus.ENABLED = ISRStatus("enabled")
ISRStatus.DISABLED = ISRStatus("disabled")
ISRStatus.PENDING = ISRStatus("pending")


class ConcurrencyIssueType:
    """并发问题type"""
    __slots__ = ('_val',)

    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

    RACE_CONDITION: 'ConcurrencyIssueType'
    DEADLOCK: 'ConcurrencyIssueType'
    PRIORITY_INVERSION: 'ConcurrencyIssueType'
    NESTING_VIOLATION: 'ConcurrencyIssueType'
    UNSAFE_SHARED_ACCESS: 'ConcurrencyIssueType'

ConcurrencyIssueType.RACE_CONDITION = ConcurrencyIssueType("race_condition")
ConcurrencyIssueType.DEADLOCK = ConcurrencyIssueType("deadlock")
ConcurrencyIssueType.PRIORITY_INVERSION = ConcurrencyIssueType("priority_inversion")
ConcurrencyIssueType.NESTING_VIOLATION = ConcurrencyIssueType("nesting_violation")
ConcurrencyIssueType.UNSAFE_SHARED_ACCESS = ConcurrencyIssueType("unsafe_shared_access")


class ISRInfo:
    """ISRinfo"""
    __slots__ = ('vector_number', 'interrupt_type', 'address', 'name', 'status', 'priority', 'description')

    def __init__(self, vector_number: int, interrupt_type: InterruptType, address: int, name: str = "", status: ISRStatus = None, priority: int = 0, description: str = ""):
        self.vector_number = vector_number
        self.interrupt_type = interrupt_type
        self.address = address
        self.name = name
        self.status = status if status is not None else ISRStatus.ENABLED
        self.priority = priority
        self.description = description


class ControlFlowNode:
    """control flownode"""
    __slots__ = ('address', 'instruction_count', 'is_call', 'is_return', 'is_interrupt_entry', 'is_interrupt_exit')

    def __init__(self, address: int, instruction_count: int = 0, is_call: bool = False, is_return: bool = False, is_interrupt_entry: bool = False, is_interrupt_exit: bool = False):
        self.address = address
        self.instruction_count = instruction_count
        self.is_call = is_call
        self.is_return = is_return
        self.is_interrupt_entry = is_interrupt_entry
        self.is_interrupt_exit = is_interrupt_exit


class ControlFlowEdge:
    """control flow边"""
    __slots__ = ('from_address', 'to_address', 'edge_type')

    def __init__(self, from_address: int, to_address: int, edge_type: str = "direct"):
        self.from_address = from_address
        self.to_address = to_address
        self.edge_type = edge_type


class ISRControlFlowGraph:
    """ISRcontrol flowgraph"""
    __slots__ = ('isr_info', 'nodes', 'edges', 'entry_points', 'exit_points')

    def __init__(self, isr_info: ISRInfo, nodes: List[ControlFlowNode], edges: List[ControlFlowEdge], entry_points: Optional[List[int]] = None, exit_points: Optional[List[int]] = None):
        self.isr_info = isr_info
        self.nodes = nodes
        self.edges = edges
        self.entry_points = entry_points if entry_points is not None else []
        self.exit_points = exit_points if exit_points is not None else []


class SharedResource:
    """共享资源"""
    __slots__ = ('name', 'address', 'size', 'accessors', 'is_protected')

    def __init__(self, name: str, address: int, size: int, accessors: Optional[List[str]] = None, is_protected: bool = False):
        self.name = name
        self.address = address
        self.size = size
        self.accessors = accessors if accessors is not None else []
        self.is_protected = is_protected


class ConcurrencyIssue:
    """并发问题"""
    __slots__ = ('issue_type', 'description', 'isr_names', 'resources', 'severity', 'location')

    def __init__(self, issue_type: ConcurrencyIssueType, description: str, isr_names: List[str], resources: List[SharedResource], severity: str = "medium", location: Optional[int] = None):
        self.issue_type = issue_type
        self.description = description
        self.isr_names = isr_names
        self.resources = resources
        self.severity = severity
        self.location = location


class InterruptCFGResult:
    """中断CFGanalysis results"""
    __slots__ = ('success', 'isrs', 'isr_cfgs', 'shared_resources', 'concurrency_issues', 'warnings', 'errors')

    def __init__(self, success: bool, isrs: List[ISRInfo], isr_cfgs: List[ISRControlFlowGraph], shared_resources: List[SharedResource], concurrency_issues: List[ConcurrencyIssue], warnings: Optional[List[str]] = None, errors: Optional[List[str]] = None):
        self.success = success
        self.isrs = isrs
        self.isr_cfgs = isr_cfgs
        self.shared_resources = shared_resources
        self.concurrency_issues = concurrency_issues
        self.warnings = warnings if warnings is not None else []
        self.errors = errors if errors is not None else []


class VectorTableParser:
    """中断vector表解析器"""

    def parse(self, binary_data: bytes, base_address: int = 0) -> List[ISRInfo]:
        """
        解析中断vector表
        """
        pass


class ARMVectorTableParser(VectorTableParser):
    """ARM中断vector表解析器"""

    def parse(self, binary_data: bytes, base_address: int = 0) -> List[ISRInfo]:
        """解析ARMvector表"""
        isrs = []

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

        offset = 0x1C
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
    """x86中断vector表解析器"""

    def parse(self, binary_data: bytes, base_address: int = 0) -> List[ISRInfo]:
        """解析x86中断description符表"""
        isrs = []

        for i in range(256):
            offset = i * 8
            if offset + 8 <= len(binary_data):
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
    """ISRcontrol flowgraph构建器"""

    def __init__(self):
        """initializeCFG构建器"""
        self.nodes: Dict[int, ControlFlowNode] = {}
        self.edges: List[ControlFlowEdge] = []

    def build(self, isr_info: ISRInfo, instructions: List[Dict]) -> ISRControlFlowGraph:
        """
        构建ISRcontrol flowgraph
        """
        self.nodes = {}
        self.edges = []

        if not instructions:
            return ISRControlFlowGraph(
                isr_info=isr_info,
                nodes=[],
                edges=[],
                entry_points=[isr_info.address],
                exit_points=[])

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
                self.edges.append(ControlFlowEdge(
                    from_address=to_addr,
                    to_address=from_addr + instr.get('size', 4),
                    edge_type="direct"
                ))

            elif mnemonic in ['bne', 'beq', 'jne', 'je', 'jcc']:
                edge_type = "conditional"
                self.edges.append(ControlFlowEdge(
                    from_address=from_addr,
                    to_address=to_addr,
                    edge_type="direct"
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
            exit_points=exit_points)


class InterruptAwareCFG:
    """
    中断感知control flowgraphanalyzer

    support解析中断vector表并构建ISRcontrol flowgraph
    检测共享资源访问和并发安全问题
    """

    def __init__(self, architecture: str = "arm"):
        """
        initializeanalyzer
        """
        self.architecture = architecture
        self.vector_parser = self._create_vector_parser()
        self.cfg_builder = ISRCFGBuilder()

    def _create_vector_parser(self) -> VectorTableParser:
        """createvector表解析器"""
        if self.architecture.lower() == "x86":
            return X86VectorTableParser()
        else:
            return ARMVectorTableParser()

    def parse_vector_table(self, binary_path: str, vector_table_address: int = 0) -> List[ISRInfo]:
        """
        解析中断vector表
        """
        if not os.path.exists(binary_path):
            logger.error(f"file not found: {binary_path}")
            return []

        try:
            with open(binary_path, 'rb') as f:
                f.seek(vector_table_address)
                vector_data = f.read(1024)

            return self.vector_parser.parse(vector_data, vector_table_address)

        except Exception as e:
            logger.error(f"解析vector表failed: {e}")
            return []

    def build_isr_cfgs(self, binary_path: str, isrs: List[ISRInfo]) -> List[ISRControlFlowGraph]:
        """
        构建ISRcontrol flowgraphlist
        """
        cfgs = []

        for isr in isrs:
            instructions = self._extract_isr_instructions(binary_path, isr.address)
            cfg = self.cfg_builder.build(isr, instructions)
            cfgs.append(cfg)

        return cfgs

    def _extract_isr_instructions(self, binary_path: str, start_address: int) -> List[Dict]:
        """extractISR指令"""
        instructions = []

        try:
            import capstone

            with open(binary_path, 'rb') as f:
                f.seek(0)
                data = f.read()

            offset = start_address

            if self.architecture.lower() == "x86":
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            else:
                md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

            md.detail = True

            max_instructions = 100
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

                if insn.mnemonic in ['bx', 'ret', 'pop']:
                    break

        except ImportError:
            logger.warning("capstone库not installed，skip指令extract")

        return instructions

    def detect_shared_resources(self, isr_cfgs: List[ISRControlFlowGraph]) -> List[SharedResource]:
        """
        检测共享资源
        """
        memory_accesses: Dict[int, List[str]] = {}

        for cfg in isr_cfgs:
            isr_name = cfg.isr_info.name

            for node in cfg.nodes:
                if node.address != cfg.isr_info.address:
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

    def detect_concurrency_issues(self, isr_cfgs: List[ISRControlFlowGraph], shared_resources: List[SharedResource]) -> List[ConcurrencyIssue]:
        """
        检测并发问题
        """
        issues = []

        for resource in shared_resources:
            if not resource.is_protected and len(resource.accessors) >= 2:
                issues.append(ConcurrencyIssue(
                    issue_type=ConcurrencyIssueType.UNSAFE_SHARED_ACCESS,
                    description=f"资源 {resource.name} 被多个ISR无保护访问",
                    isr_names=resource.accessors,
                    resources=[resource],
                    severity="high",
                    location=resource.address
                ))

        for cfg in isr_cfgs:
            nesting_depth = 0
            for node in cfg.nodes:
                if node.is_interrupt_entry:
                    nesting_depth += 1
                    if nesting_depth > 1:
                        issues.append(ConcurrencyIssue(
                            issue_type=ConcurrencyIssueType.NESTING_VIOLATION,
                            description=f"ISR {cfg.isr_info.name} 可能存在嵌套中断",
                            isr_names=[cfg.isr_info.name],
                            resources=[],
                            severity="medium",
                            location=node.address
                        ))

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
                            description=f"资源 {resource.name} 可能存在priority反转",
                            isr_names=[p[0] for p in priorities],
                            resources=[resource],
                            severity="high"
                        ))

        return issues

    def analyze(self, binary_path: str, vector_table_address: int = 0) -> InterruptCFGResult:
        """
        完整分析流程
        """
        if not os.path.exists(binary_path):
            return InterruptCFGResult(
                success=False,
                isrs=[],
                isr_cfgs=[],
                shared_resources=[],
                concurrency_issues=[],
                errors=[f"file not found: {binary_path}"])

        try:
            isrs = self.parse_vector_table(binary_path, vector_table_address)

            if not isrs:
                return InterruptCFGResult(
                    success=False,
                    isrs=[],
                    isr_cfgs=[],
                    shared_resources=[],
                    concurrency_issues=[],
                    errors=["未发现ISR"])

            isr_cfgs = self.build_isr_cfgs(binary_path, isrs)

            shared_resources = self.detect_shared_resources(isr_cfgs)

            concurrency_issues = self.detect_concurrency_issues(isr_cfgs, shared_resources)

            return InterruptCFGResult(
                success=True,
                isrs=isrs,
                isr_cfgs=isr_cfgs,
                shared_resources=shared_resources,
                concurrency_issues=concurrency_issues)

        except Exception as e:
            logger.error(f"analysis failed: {e}")
            return InterruptCFGResult(
                success=False,
                isrs=[],
                isr_cfgs=[],
                shared_resources=[],
                concurrency_issues=[],
                errors=[str(e)])

    def generate_dot_graph(self, isr_cfgs: List[ISRControlFlowGraph], output_path: str) -> bool:
        """
        生成DOT格式graph形file
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

            logger.info(f"DOTgraph形已save: {output_path}")
            return True

        except Exception as e:
            logger.error(f"生成DOTgraph形failed: {e}")
            return False

    def generate_report(self, result: InterruptCFGResult) -> str:
        """
        generate analysis report
        """
        report = []
        report.append("=" * 60)
        report.append("中断驱动control flowanalysis report")
        report.append("=" * 60)
        report.append(f"architecture: {self.architecture}")
        report.append(f"successful: {result.success}")
        report.append(f"ISR数量: {len(result.isrs)}")
        report.append(f"共享资源数: {len(result.shared_resources)}")
        report.append(f"并发问题数: {len(result.concurrency_issues)}")
        report.append("")

        if result.isrs:
            report.append("ISRlist:")
            report.append("-" * 40)
            for isr in result.isrs:
                report.append(f"vector {isr.vector_number}: {isr.name}")
                report.append(f"  address: 0x{isr.address:x}")
                report.append(f"  type: {isr.interrupt_type.value}")
                report.append(f"  status: {isr.status.value}")
                report.append("")

        if result.shared_resources:
            report.append("共享资源:")
            report.append("-" * 40)
            for resource in result.shared_resources:
                report.append(f"名称: {resource.name}")
                report.append(f"  address: 0x{resource.address:x}")
                report.append(f"  访问者: {', '.join(resource.accessors)}")
                report.append(f"  受保护: {'是' if resource.is_protected else '否'}")
                report.append("")

        if result.concurrency_issues:
            report.append("并发问题:")
            report.append("-" * 40)
            for issue in result.concurrency_issues:
                report.append(f"type: {issue.issue_type.value}")
                report.append(f"  description: {issue.description}")
                report.append(f"  相关ISR: {', '.join(issue.isr_names)}")
                report.append(f"  severity: {issue.severity}")
                if issue.location:
                    report.append(f"  位置: 0x{issue.location:x}")
                report.append("")

        return "\n".join(report)
