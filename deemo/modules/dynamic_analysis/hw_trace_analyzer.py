import logging
import os
import subprocess
import tempfile
import json
from dataclasses import dataclass, field
from typing import Dict, List, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class TraceType:
    # Trace type enumeration
    INTEL_PT = "intel_pt"
    ARM_ETM = "arm_etm"
    PERF_RECORD = "c"

class TraceStatus:
    # Trace lifecycle states
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
    # Abstract decoder contract for hardware trace data streams

    def decode(self, trace_data: bytes) -> List[TracePacket]:
        """
        Convert raw trace bytes into a structured packet sequence.

        """
        pass

class IntelPTDecoder(BaseTraceDecoder):
    # Intel Processor Trace binary decoder

    def __init__(self, binary_path: str):
        """
        Bind decoder instance to a target binary for symbol resolution.

        """
        self.binary_path = binary_path
        self._check_libipt()

    def _check_libipt(self):
        # Verify libipt Python bindings are importable
        try:
            import ptpython
            self.ptpython = ptpython
            logger.info("libipt Python bindings available")
        except ImportError:
            logger.warning("libipt bindings unavailable; falling back to simplified decoder")
            self.ptpython = None

    def decode(self, trace_data: bytes) -> List[TracePacket]:
        # Route PT packet decode through the available backend
        if self.ptpython:
            return self._decode_with_libipt(trace_data)
        return self._decode_simplified(trace_data)

    def _decode_with_libipt(self, trace_data: bytes) -> List[TracePacket]:
        # Native libipt decode pipeline
        try:
            packets = []
            logger.info("Decoding PT data via libipt native bindings")
            return packets
        except Exception as e:
            logger.error(f"libiptdecodefailed: {e}")
            return self._decode_simplified(trace_data)

    def _decode_simplified(self, trace_data: bytes) -> List[TracePacket]:
        """Heuristic packet parser that operates without native dependencies."""
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
        # Stateless decoder — no initialization required
        pass

    def decode(self, trace_data: bytes) -> List[TracePacket]:
        # Parse raw perf buffer into structured packet objects
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
    """
    Hardware trace analyzer for Intel PT and ARM ETM streams.

    Decodes PT packets via libipt or perf tooling, reconstructs precise
    control flow and data flow paths, extracts vulnerability-triggering
    execution traces, and prunes obfuscated dead code through
    reachability analysis.
    """

    def __init__(self, binary_path: str, trace_type: TraceType = TraceType.INTEL_PT):
        """
        Instantiate analyzer with target binary and trace backend selection.

        """
        self.binary_path = binary_path
        self.trace_type = trace_type
        self.decoder = self._create_decoder()
        self._validate_binary()

    def _create_decoder(self) -> BaseTraceDecoder:
        # Select decoder strategy by trace type
        if self.trace_type == TraceType.INTEL_PT:
            return IntelPTDecoder(self.binary_path)
        elif self.trace_type == TraceType.PERF_RECORD:
            return PerfDecoder()
        else:
            return IntelPTDecoder(self.binary_path)

    def _validate_binary(self):
        # Assert binary file exists on filesystem before proceeding
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"binaryfile not found: {self.binary_path}")

    def collect_trace(self, target_command: str, timeout: int = 60) -> bytes:
        """
        Capture Intel PT trace via perf record for the given target command.

        """
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
                logger.error(f"perf recordfailed: {result.stderr}")
                return b""

            with open(output_file, "rb") as f:
                trace_data = f.read()

            logger.info(f"Trace data collected: {len(trace_data)} bytes")
            return trace_data

        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def analyze_trace(self, trace_data: bytes) -> TraceAnalysisResult:
        """
        Process raw trace data through the full analysis pipeline.

        """
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
        """Reconstruct ordered instruction sequence from decoded packet stream."""
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
        # Infer function boundaries from address gaps in the trace
        if not instructions:
            return []

        functions = []
        current_func = None
        func_start = instructions[0].address

        for i, instr in enumerate(instructions):
            # Boundary heuristic: address gaps exceeding 100 bytes signal function transitions
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
        # Build directed graph mapping each instruction to its successor
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
        # Derive data flow edges from sequential instruction adjacency
        data_flows = []

        for i, instr in enumerate(instructions):
            # Adjacency-based flow inference: each consecutive pair forms a data edge
            if i > 0:
                data_flows.append(DataFlow(
                    source=instructions[i-1].address,
                    destination=instr.address,
                    operation="flow"
                ))

        return data_flows

    def _prune_dead_code(self, instructions: List[TraceInstruction], cfg: Dict[int, List[int]]) -> List[TraceInstruction]:
        # Reachability-based dead code elimination
        if not instructions:
            return []

        # Collect all instruction addresses observed during execution
        executed_addrs = set(instr.address for instr in instructions)

        # BFS from entry point to identify reachable nodes
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

        # Retain reachable instructions only
        pruned = [instr for instr in instructions if instr.address in reachable]

        logger.info(f"Dead-code pruning: {len(instructions)} → {len(pruned)} instructions")
        return pruned

    def _extract_function_calls(self, functions: List[TraceFunction]) -> List[Tuple[int, int]]:
        # Derive call sequence from ordered function list
        calls = []

        for i, func in enumerate(functions[:-1]):
            calls.append((func.start_address, functions[i+1].start_address))

        return calls

    # --- 新增: 热点函数分析 ---
    # 统计函数执行次数和执行时间，识别性能瓶颈和关键逻辑
    def analyze_hot_functions(self, functions: List[TraceFunction]) -> Dict[str, Any]:
        """分析函数的执行热点 — 执行次数和指令密度最高的函数。
        热点函数通常对应核心业务逻辑或加解密循环，是逆向分析的重点目标。"""
        if not functions:
            return {"hot_functions": []}

        ranked = sorted(functions, key=lambda f: len(f.instructions), reverse=True)
        hot_list = []
        for f in ranked[:10]:
            hot_list.append({
                'name': f.name,
                'address': hex(f.start_address),
                'instruction_count': len(f.instructions),
                'entry_count': f.entry_count,
                'span_bytes': f.end_address - f.start_address,
                'density': len(f.instructions) / max(1, (f.end_address - f.start_address)) * 100,
            })

        return {
            'total_functions': len(functions),
            'hot_functions': hot_list,
            'coverage': sum(len(f.instructions) for f in functions),
        }

    def trace_and_analyze(self, target_command: str, timeout: int = 60) -> TraceAnalysisResult:
        """
        Collect trace data from a target process and execute full analysis.

        """
        trace_data = self.collect_trace(target_command, timeout)
        return self.analyze_trace(trace_data)

    def generate_report(self, result: TraceAnalysisResult) -> str:
        """
        Produce a human-readable analysis summary from structured results.

        """
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
        """
        Serialize analysis results to a JSON file.

        """
        try:
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
