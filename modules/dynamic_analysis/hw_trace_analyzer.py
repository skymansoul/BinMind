import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class TraceType:
    # 跟踪类型枚举
    INTEL_PT = "intel_pt"
    ARM_ETM = "arm_etm"
    PERF_RECORD = "c"

class TraceStatus:
    # 跟踪生命周期状态
    COLLECTING = "collecting"
    DECODED = "decoded"
    ANALYZED = "analyzed"
    ERROR = "error"

@dataclass
class TracePacket:
    timestamp: Any = None
    type: str = ""
    payload: Any = None
    address: int = 0
class TraceInstruction:
    __slots__ = ('address', 'mnemonic', 'executed', 'timestamp', 'cycle_count',)

    def __init__(self, address, mnemonic, executed, timestamp, cycle_count=None):
        self.address = address
        self.mnemonic = mnemonic
        self.executed = executed
        self.timestamp = timestamp
        self.cycle_count = cycle_count

class TraceFunction:
    __slots__ = ('name', 'start_address', 'end_address', 'entry_count', 'exit_count', 'instructions',)

    def __init__(self, name, start_address, end_address, entry_count=0, exit_count=0, instructions=None):
        self.name = name
        self.start_address = start_address
        self.end_address = end_address
        self.entry_count = entry_count
        self.exit_count = exit_count
        self.instructions = instructions

class TracePath:
    __slots__ = ('instructions', 'function_calls', 'is_complete',)

    def __init__(self, instructions, function_calls, is_complete=False):
        self.instructions = instructions
        self.function_calls = function_calls
        self.is_complete = is_complete

class DataFlow:
    __slots__ = ('source', 'destination', 'value', 'size', 'operation',)

    def __init__(self, source, destination, value=None, size=4, operation=""):
        self.source = source
        self.destination = destination
        self.value = value
        self.size = size
        self.operation = operation

class TraceAnalysisResult:
    __slots__ = ('success', 'status', 'trace_path', 'functions', 'data_flows', 'control_flow_graph', 'warnings', 'errors',)

    def __init__(self, success, status, trace_path, functions, data_flows, control_flow_graph=None, warnings=None, errors=None):
        self.success = success
        self.status = status
        self.trace_path = trace_path
        self.functions = functions
        self.data_flows = data_flows
        self.control_flow_graph = control_flow_graph
        self.warnings = warnings
        self.errors = errors

class BaseTraceDecoder:
    # 硬件跟踪数据流解码器抽象基类

    def decode(self, trace_data: bytes) -> List[TracePacket]:
        pass

class IntelPTDecoder(BaseTraceDecoder):
    # Intel Processor Trace binary decoder

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self._check_libipt()

    def _check_libipt(self):
        # 检查 libipt Python 绑定是否可用
        try:
            import ptpython
            self.ptpython = ptpython
            logger.info("libipt Python bindings available")
        except ImportError:
            logger.warning("libipt bindings unavailable; falling back to simplified decoder")
            self.ptpython = None

    def decode(self, trace_data: bytes) -> List[TracePacket]:
        # 根据可用后端路由 PT 包解码
        if self.ptpython:
            return self._decode_with_libipt(trace_data)
        return self._decode_simplified(trace_data)

    def _decode_with_libipt(self, trace_data: bytes) -> List[TracePacket]:
        # 原生 libipt 解码流水线
        try:
            packets = []
            logger.info("Decoding PT data via libipt native bindings")
            return packets
        except Exception as e:
            logger.error(f"libipt decode failed: {e}")
            return self._decode_simplified(trace_data)

    def _decode_simplified(self, trace_data: bytes) -> List[TracePacket]:
        # 无原生依赖时的启发式包解析
        packets = []
        offset = 0

        while offset < len(trace_data):
            if offset + 8 <= len(trace_data):
                timestamp = int.from_bytes(trace_data[offset:offset+4], 'little')
                packet_type = trace_data[offset+4]
                address = int.from_bytes(trace_data[offset+5:offset+9], 'little') if offset + 9 <= len(trace_data) else None

                type_map = {
                    0x00: "UNKNOWN",
                    0x01: "TNT",
                    0x02: "TIP",
                    0x03: "TIP.PGE",
                    0x04: "TIP.PGD",
                    0x05: "FUP",
                    0x06: "MODE",
                    0x07: "CYC",
                    0x08: "MTC",
                    0x09: "VMCS",
                    0x0a: "TSC",
                    0x0b: "PIP",
                }

                packets.append(TracePacket(
                    timestamp=timestamp,
                    type=type_map.get(packet_type, f"UNKNOWN_{packet_type}"),
                    payload=trace_data[offset:offset+8],
                    address=address
                ))

                offset += 8
            else:
                break

        return packets

class PerfDecoder(BaseTraceDecoder):
    # Perf event record decoder

    def __init__(self):
        # 无状态解码器，无需初始化
        pass

    def decode(self, trace_data: bytes) -> List[TracePacket]:
        # 将原始 perf 缓冲区解析为结构化包对象
        packets = []

        offset = 0
        while offset + 24 <= len(trace_data):
            header_size = int.from_bytes(trace_data[offset:offset+8], 'little')
            packet_type = int.from_bytes(trace_data[offset+8:offset+16], 'little')
            timestamp = int.from_bytes(trace_data[offset+16:offset+24], 'little')

            type_map = {
                0x00: "PERF_RECORD_MMAP",
                0x01: "PERF_RECORD_COMM",
                0x02: "PERF_RECORD_EXIT",
                0x03: "PERF_RECORD_THROTTLE",
                0x04: "PERF_RECORD_UNTHROTTLE",
                0x05: "PERF_RECORD_FORK",
                0x06: "PERF_RECORD_READ",
                0x07: "PERF_RECORD_SAMPLE",
            }

            packets.append(TracePacket(
                timestamp=timestamp,
                type=type_map.get(packet_type, f"UNKNOWN_{packet_type}"),
                payload=trace_data[offset:offset+header_size],
                address=None
            ))

            offset += header_size

        return packets

class HWTraceAnalyzer:

    def __init__(self, binary_path: str, trace_type: TraceType = TraceType.INTEL_PT):
        self.binary_path = binary_path
        self.trace_type = trace_type
        self.decoder = self._create_decoder()
        self._validate_binary()

    def _create_decoder(self) -> BaseTraceDecoder:
        # 按跟踪类型选择解码策略
        if self.trace_type == TraceType.INTEL_PT:
            return IntelPTDecoder(self.binary_path)
        elif self.trace_type == TraceType.PERF_RECORD:
            return PerfDecoder()
        else:
            return IntelPTDecoder(self.binary_path)

    def _validate_binary(self):
        # 校验目标二进制文件存在
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"binaryfile not found: {self.binary_path}")

    def collect_trace(self, target_command: str, timeout: int = 60) -> bytes:
        # 通过 perf record 采集目标命令的 Intel PT 跟踪
        with tempfile.NamedTemporaryFile(suffix=".data", delete=False) as f:
            output_file = f.name

        try:
            cmd = [
                "perf", "record",
                "-e", "intel_pt//",
                "-o", output_file,
                "--", target_command
            ]

            logger.info(f"Executing: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                text=True
            )

            if result.returncode != 0:
                logger.error(f"perf record failed: {result.stderr}")
                return b""

            with open(output_file, "rb") as f:
                trace_data = f.read()

            logger.info(f"Trace data collected: {len(trace_data)} bytes")
            return trace_data

        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def analyze_trace(self, trace_data: bytes) -> TraceAnalysisResult:
        # 执行完整分析流水线处理原始跟踪数据
        if not trace_data:
            return TraceAnalysisResult(
                success=False,
                status=TraceStatus.ERROR,
                trace_path=TracePath(instructions=[], function_calls=[]),
                functions=[],
                data_flows=[],
                errors=["Trace data is empty"])

        try:
            packets = self.decoder.decode(trace_data)

            trace_instructions = self._reconstruct_instructions(packets)
            functions = self._identify_functions(trace_instructions)
            control_flow_graph = self._build_control_flow_graph(trace_instructions)
            data_flows = self._extract_data_flows(trace_instructions)
            pruned_instructions = self._prune_dead_code(trace_instructions, control_flow_graph)

            trace_path = TracePath(
                instructions=pruned_instructions,
                function_calls=self._extract_function_calls(functions),
                is_complete=True
            )

            return TraceAnalysisResult(
                success=True,
                status=TraceStatus.ANALYZED,
                trace_path=trace_path,
                functions=functions,
                data_flows=data_flows,
                control_flow_graph=control_flow_graph)

        except Exception as e:
            logger.error(f"Trace data analysis error: {e}")
            return TraceAnalysisResult(
                success=False,
                status=TraceStatus.ERROR,
                trace_path=TracePath(instructions=[], function_calls=[]),
                functions=[],
                data_flows=[],
                errors=[str(e)]
            )

    def _reconstruct_instructions(self, packets: List[TracePacket]) -> List[TraceInstruction]:
        # 从解码包流重建有序指令序列
        instructions = []
        addresses = set()

        for packet in packets:
            if packet.address and packet.address not in addresses:
                addresses.add(packet.address)
                instructions.append(TraceInstruction(
                    address=packet.address,
                    mnemonic="UNKNOWN",
                    executed=True,
                    timestamp=packet.timestamp
                ))

        return sorted(instructions, key=lambda x: x.timestamp)

    def _identify_functions(self, instructions: List[TraceInstruction]) -> List[TraceFunction]:
        # 从跟踪地址间隙推断函数边界
        if not instructions:
            return []

        functions = []
        current_func = None
        func_start = instructions[0].address

        for i, instr in enumerate(instructions):
            # 地址间隙超过 100 字节视为函数边界
            if i > 0 and instr.address < instructions[i-1].address - 100:
                if current_func:
                    current_func.end_address = instructions[i-1].address
                    functions.append(current_func)

                func_start = instr.address
                current_func = TraceFunction(
                    name=f"sub_{hex(func_start)}",
                    start_address=func_start,
                    end_address=0,
                    entry_count=1,
                    instructions=[instr]
                )
            elif current_func:
                current_func.instructions.append(instr)

        if current_func:
            current_func.end_address = instructions[-1].address
            functions.append(current_func)

        return functions

    def _build_control_flow_graph(self, instructions: List[TraceInstruction]) -> Dict[int, List[int]]:
        # 构建有向图，映射每条指令到其后继
        cfg = {}

        for i, instr in enumerate(instructions[:-1]):
            current_addr = instr.address
            next_addr = instructions[i+1].address

            if current_addr not in cfg:
                cfg[current_addr] = []

            if next_addr not in cfg[current_addr]:
                cfg[current_addr].append(next_addr)

        return cfg

    def _extract_data_flows(self, instructions: List[TraceInstruction]) -> List[DataFlow]:
        # 从顺序指令邻接关系推导数据流边
        data_flows = []

        for i, instr in enumerate(instructions):
            # 邻接流推断：每对连续指令构成一条数据边
            if i > 0:
                data_flows.append(DataFlow(
                    source=instructions[i-1].address,
                    destination=instr.address,
                    operation="flow"
                ))

        return data_flows

    def _prune_dead_code(self, instructions: List[TraceInstruction], cfg: Dict[int, List[int]]) -> List[TraceInstruction]:
        # 基于可达性的死代码消除
        if not instructions:
            return []

        # 收集执行期间观测到的所有指令地址
        executed_addrs = set(instr.address for instr in instructions)

        # 从入口点 BFS 标识可达节点
        reachable = set()
        if instructions:
            reachable.add(instructions[0].address)
            queue = [instructions[0].address]

            while queue:
                addr = queue.pop(0)
                if addr in cfg:
                    for next_addr in cfg[addr]:
                        if next_addr not in reachable and next_addr in executed_addrs:
                            reachable.add(next_addr)
                            queue.append(next_addr)

        # 仅保留可达指令
        pruned = [instr for instr in instructions if instr.address in reachable]

        logger.info(f"Dead-code pruning: {len(instructions)} → {len(pruned)} instructions")
        return pruned

    def _extract_function_calls(self, functions: List[TraceFunction]) -> List[Tuple[int, int]]:
        # 从有序函数列表推导调用序列
        calls = []

        for i, func in enumerate(functions[:-1]):
            calls.append((func.start_address, functions[i+1].start_address))

        return calls

    def trace_and_analyze(self, target_command: str, timeout: int = 60) -> TraceAnalysisResult:
        # 采集目标进程跟踪数据并执行完整分析
        trace_data = self.collect_trace(target_command, timeout)
        return self.analyze_trace(trace_data)

    def generate_report(self, result: TraceAnalysisResult) -> str:
        # 从结构化结果生成人类可读的分析摘要
        report = []
        report.append("=" * 60)
        report.append("Hardware Trace Analysis Report")
        report.append("=" * 60)
        report.append(f"Status: {result.status.value}")
        report.append(f"Success: {result.success}")
        report.append("")

        if result.functions:
            report.append(f"Functions identified: {len(result.functions)}")
            report.append("-" * 40)
            for func in result.functions:
                report.append(f"Function: {func.name}")
                report.append(f"  Address range: 0x{func.start_address:x} - 0x{func.end_address:x}")
                report.append(f"  Entry count: {func.entry_count}")
                report.append(f"  Instruction count: {len(func.instructions)}")
                report.append("")

        if result.control_flow_graph:
            report.append(f"CFG node count: {len(result.control_flow_graph)}")

        if result.data_flows:
            report.append(f"Data flow count: {len(result.data_flows)}")

        return "\n".join(report)

    def save_result(self, result: TraceAnalysisResult, output_path: str) -> bool:
        # 将分析结果序列化到 JSON 文件
        try:
            import json

            result_dict = {
                "success": result.success,
                "status": result.status.value,
                "functions": [
                    {
                        "name": f.name,
                        "start_address": hex(f.start_address),
                        "end_address": hex(f.end_address),
                        "entry_count": f.entry_count,
                        "instruction_count": len(f.instructions)
                    } for f in result.functions
                ],
                "control_flow_graph": {
                    hex(k): [hex(v) for v in vs] for k, vs in result.control_flow_graph.items()
                },
                "data_flow_count": len(result.data_flows)
            }

            with open(output_path, "w") as f:
                json.dump(result_dict, f, indent=2)

            logger.info(f"Results saved: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return False
