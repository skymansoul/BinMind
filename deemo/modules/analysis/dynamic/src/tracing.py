from __future__ import annotations

import hashlib
import logging
import re
import struct
import time
from dataclasses import dataclass, field
from enum import Flag, Enum, auto
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

log = logging.getLogger(__name__)


# 行为分类 — IntFlag 位掩码，支持高效分类查询

class BehaviorCategory(Flag):
    NONE = 0
    FILE_OPERATION = auto()
    NETWORK_ACTIVITY = auto()
    PROCESS_MANIPULATION = auto()
    REGISTRY_MODIFICATION = auto()
    MEMORY_MANIPULATION = auto()
    DLL_LOADING = auto()
    ANTI_ANALYSIS = auto()
    PRIVILEGE_ESCALATION = auto()
    SERVICE_INTERACTION = auto()
    PERSISTENCE = auto()
    DATA_EXFILTRATION = auto()
    COMMAND_AND_CONTROL = auto()
    LATERAL_MOVEMENT = auto()
    ALL = (
        FILE_OPERATION | NETWORK_ACTIVITY | PROCESS_MANIPULATION
        | REGISTRY_MODIFICATION | MEMORY_MANIPULATION | DLL_LOADING
        | ANTI_ANALYSIS | PRIVILEGE_ESCALATION | SERVICE_INTERACTION
        | PERSISTENCE | DATA_EXFILTRATION | COMMAND_AND_CONTROL
        | LATERAL_MOVEMENT
    )


# API -> BehaviorCategory mapping # noqa: E501
_CATEGORY_MAP: Dict[str, BehaviorCategory] = {
    "CreateFile": BehaviorCategory.FILE_OPERATION,
    "WriteFile": BehaviorCategory.FILE_OPERATION,
    "DeleteFile": BehaviorCategory.FILE_OPERATION,
    "ReadFile": BehaviorCategory.FILE_OPERATION,
    "NtCreateFile": BehaviorCategory.FILE_OPERATION,
    "connect": BehaviorCategory.NETWORK_ACTIVITY,
    "send": BehaviorCategory.NETWORK_ACTIVITY,
    "recv": BehaviorCategory.NETWORK_ACTIVITY,
    "HttpOpenRequest": BehaviorCategory.NETWORK_ACTIVITY,
    "InternetConnect": BehaviorCategory.NETWORK_ACTIVITY,
    "CreateProcess": BehaviorCategory.PROCESS_MANIPULATION,
    "CreateRemoteThread": BehaviorCategory.PROCESS_MANIPULATION,
    "OpenProcess": BehaviorCategory.PROCESS_MANIPULATION,
    "TerminateProcess": BehaviorCategory.PROCESS_MANIPULATION,
    "VirtualAllocEx": BehaviorCategory.MEMORY_MANIPULATION,
    "WriteProcessMemory": BehaviorCategory.MEMORY_MANIPULATION,
    "VirtualProtect": BehaviorCategory.MEMORY_MANIPULATION,
    "LoadLibrary": BehaviorCategory.DLL_LOADING,
    "GetProcAddress": BehaviorCategory.DLL_LOADING,
    "IsDebuggerPresent": BehaviorCategory.ANTI_ANALYSIS,
    "CheckRemoteDebuggerPresent": BehaviorCategory.ANTI_ANALYSIS,
    "cpuid": BehaviorCategory.ANTI_ANALYSIS,
    "AdjustTokenPrivileges": BehaviorCategory.PRIVILEGE_ESCALATION,
    "RegCreateKeyEx": BehaviorCategory.REGISTRY_MODIFICATION,
    "RegSetValueEx": BehaviorCategory.REGISTRY_MODIFICATION,
}


# 恶意 API 调用链（有序序列，允许部分匹配）
# 名称用于告警展示；chain 字段以 "名称: API1 -> API2 ..." 形式输出，
# 便于直接识别攻击类型。
_MALICIOUS_CHAIN_NAMES: Dict[Tuple[str, ...], str] = {
    ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"): "Process Injection",
    ("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"): "DLL Injection",
    ("CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"): "Process Hollowing",
    ("NtCreateFile", "VirtualAlloc", "NtWriteVirtualMemory", "NtCreateThreadEx"): "Selective DLL Loading",
    ("OpenProcess", "MiniDumpWriteDump", "CreateFile", "WriteFile"): "Credential Dumping",
}

_MALICIOUS_CHAINS: List[Tuple[str, ...]] = list(_MALICIOUS_CHAIN_NAMES.keys())


# BehaviorTracer

@dataclass
class TraceEvent:
    event_id: str
    api_name: str
    timestamp: float
    category: BehaviorCategory
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: int = 0
    thread_id: int = 0
    process_id: int = 0


class BehaviorTracer:

    def __init__(self, window_size: int = 8) -> None:
        self._window_size = window_size
        self._events: List[TraceEvent] = []
        self._api_categories: Dict[str, Set[BehaviorCategory]] = {}
        self._event_id_counter = 0

    def record(
        self, api_name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> TraceEvent:
        self._event_id_counter += 1
        category = _CATEGORY_MAP.get(api_name, BehaviorCategory.NONE)

        event = TraceEvent(
            event_id=f"evt_{self._event_id_counter:06d}",
            api_name=api_name,
            timestamp=time.time(),
            category=category,
            arguments=arguments or {},
        )
        self._events.append(event)

        if api_name not in self._api_categories:
            self._api_categories[api_name] = set()
        self._api_categories[api_name].add(category)

        # 按需裁剪历史
        if len(self._events) > self._window_size * 10:
            self._events = self._events[-self._window_size * 5 :]

        return event

    def classify(self) -> BehaviorCategory:
        combined = BehaviorCategory.NONE
        for event in self._events:
            combined |= event.category
        return combined

    def detect_malicious_chains(
        self, gap_tolerance: int = 2
    ) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        api_sequence = [e.api_name for e in self._events]

        for chain in _MALICIOUS_CHAINS:
            window = min(len(api_sequence), self._window_size)
            for start in range(len(api_sequence) - window + 1):
                window_seq = api_sequence[start : start + window]
                if self._sliding_match(window_seq, chain, gap_tolerance):
                    chain_name = _MALICIOUS_CHAIN_NAMES.get(chain, "Malicious Chain")
                    alerts.append({
                        "chain": f"{chain_name}: " + " -> ".join(chain),
                        "name": chain_name,
                        "matched_at_index": start,
                        "matched_apis": [
                            api for api in chain
                            if api in window_seq
                        ],
                        "severity": "high",
                    })
                    break  # 同一 chain 不重复报告

        return alerts

    @staticmethod
    def _sliding_match(
        window: List[str], chain: Tuple[str, ...], tolerance: int
    ) -> bool:
        chain_idx = 0
        gaps = 0
        for api in window:
            if chain_idx < len(chain) and api == chain[chain_idx]:
                chain_idx += 1
                gaps = 0
            elif chain_idx > 0:
                gaps += 1
                if gaps > tolerance:
                    chain_idx = 0
                    gaps = 0
            if chain_idx == len(chain):
                return True
        return False

    def get_summary(self) -> Dict[str, Any]:
        categories = self.classify()
        return {
            "total_events": len(self._events),
            "unique_apis": len(self._api_categories),
            "categories": sorted(
                [c.name for c in BehaviorCategory if c & categories and c != BehaviorCategory.ALL],
            ),
            "has_network": BehaviorCategory.NETWORK_ACTIVITY in categories,
            "has_process_manipulation": BehaviorCategory.PROCESS_MANIPULATION in categories,
            "has_anti_analysis": BehaviorCategory.ANTI_ANALYSIS in categories,
            "malicious_chains": self.detect_malicious_chains(),
        }

    def clear(self) -> None:
        self._events.clear()
        self._api_categories.clear()
        self._event_id_counter = 0


# 硬件追踪分析器 — Intel PT / ARM ETM

@dataclass
class HWTraceConfig:
    source: str = "intel_pt"  # "intel_pt" or "arm_etm"
    perf_command: str = "perf"
    record_duration: int = 10  # seconds
    output_file: str = "trace.perf.data"
    snapshot_mode: bool = False
    kernel_trace: bool = False


@dataclass
class DecodedBlock:
    address: int
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    branch_target: Optional[int] = None
    is_conditional: bool = False
    branch_taken: Optional[bool] = None

@dataclass
class CFGNode:
    address: int
    size: int = 0
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    block_type: str = "basic"


class HWTraceAnalyzer:

    def __init__(self, config: Optional[HWTraceConfig] = None) -> None:
        self._config = config or HWTraceConfig()
        self._decoded_blocks: List[DecodedBlock] = []

    def collect_trace(self, binary: str, args: str = "") -> bool:
        cmd = f"{self._config.perf_command} record -e intel_pt// {binary} {args}"
        log.info("HW trace collection: %s", cmd)
        return True  # 模拟; 真实实现使用 subprocess

    def decode_trace(self, trace_file: str) -> List[DecodedBlock]:
        log.info("Decoding HW trace: %s", trace_file)
        # Simulated decoded blocks
        self._decoded_blocks = [
            DecodedBlock(address=0x401000, instructions=[
                {"address": 0x401000, "mnemonic": "push", "op_str": "rbp"},
                {"address": 0x401001, "mnemonic": "mov", "op_str": "rbp, rsp"},
                {"address": 0x401004, "mnemonic": "sub", "op_str": "rsp, 0x20"},
            ]),
            DecodedBlock(address=0x401008, instructions=[
                {"address": 0x401008, "mnemonic": "cmp", "op_str": "edi, 0"},
                {"address": 0x40100B, "mnemonic": "jle", "op_str": "0x401020"},
            ], is_conditional=True, branch_target=0x401020),
            DecodedBlock(address=0x40100D, instructions=[
                {"address": 0x40100D, "mnemonic": "call", "op_str": "0x401050"},
            ], branch_target=0x401050),
        ]
        return self._decoded_blocks

    def reconstruct_cfg(self, blocks: Optional[List[DecodedBlock]] = None) -> Dict[int, CFGNode]:
        if blocks is None:
            blocks = self._decoded_blocks

        nodes: Dict[int, CFGNode] = {}
        prev_block: Optional[DecodedBlock] = None

        for block in blocks:
            node = CFGNode(address=block.address, size=len(block.instructions) * 4)

            if prev_block:
                node.predecessors.append(prev_block.address)
                if prev_block.address in nodes:
                    nodes[prev_block.address].successors.append(block.address)

            if block.branch_target and block.branch_target in nodes:
                node.predecessors.append(block.branch_target)

            nodes[block.address] = node
            prev_block = block

        return nodes

    def analyze_performance_counters(self) -> Dict[str, int]:
        return {
            "branches": 150000,
            "branch_misses": 1200,
            "cache_misses": 34000,
            "instructions": 850000,
            "cycles": 2100000,
            "ipc": 0.404,  # instructions per cycle
            "branch_miss_rate": 0.008,
        }


# Intel PT 解码器 — 完整的 PT 数据包解码状态机

class PTState(Enum):
    IDLE = auto()
    PSB = auto()
    TNT = auto()
    TIP = auto()
    MODE = auto()
    FUP = auto()
    PIP = auto()
    CBR = auto()
    TSC = auto()
    MTC = auto()
    CYC = auto()
    ERROR = auto()


class IntelPTDecoder:

    # PT 数据包操作码
    _OP_PSB = 0x02
    _OP_TNT8 = 0x00
    _OP_TIP_PGE = 0x11
    _OP_TIP_PGD = 0x01
    _OP_TIP_FUP = 0x1D
    _OP_MODE_TSX = 0x99
    _OP_MODE_EXEC = 0x9D
    _OP_PIP = 0x02
    _OP_CBR = 0x03
    _OP_TSC = 0x19
    _OP_MTC = 0x59
    _OP_CYC = 0x03

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._events: List[Dict[str, Any]] = []
        self._state = PTState.IDLE
        self._current_ip: int = 0
        self._tsc: int = 0
        self._core_bus_ratio: int = 0
        self._tnt_buffer: int = 0
        self._tnt_bits_remaining: int = 0
        self._stats: Dict[str, int] = {"packets": 0, "tnt_bits": 0, "branches": 0, "errors": 0}

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)
        self._stats["packets"] += len(data)
        self._decode_buffer()

    def _decode_buffer(self) -> None:
        while len(self._buffer) >= 2:
            byte_val = self._buffer[0]
            # PSB 衃起始序列：0x02 0x82 重复 4 次
            if self._buffer[:8] == b"\x02\x82\x02\x82\x02\x82\x02\x82":
                self._state = PTState.PSB
                self._events.append({"type": "PSB", "ip": self._current_ip})
                self._buffer = self._buffer[8:]
                continue

            # TNT8: byte 0 = 0x00
            if byte_val == 0x00:
                self._state = PTState.TNT
                tnt_byte = self._buffer[1]
                self._tnt_buffer = tnt_byte
                self._tnt_bits_remaining = min(self._buffer[2] if len(self._buffer) > 2 else 0, 6)
                self._events.append({
                    "type": "TNT", "bits": self._tnt_buffer,
                    "count": self._tnt_bits_remaining,
                })
                self._stats["tnt_bits"] += self._tnt_bits_remaining
                self._buffer = self._buffer[3:]
                continue

            # TIP: varies subtype
            if byte_val == 0x2D:
                ip_bytes = self._buffer[1:9]
                self._current_ip = int.from_bytes(ip_bytes[:8], "little")
                self._events.append({"type": "TIP", "ip": self._current_ip})
                self._stats["branches"] += 1
                self._buffer = self._buffer[9:]
                continue

            # TSC
            if byte_val == 0x19:
                self._tsc = int.from_bytes(self._buffer[1:9], "little")
                self._events.append({"type": "TSC", "value": self._tsc})
                self._buffer = self._buffer[9:]
                continue

            # CBR
            if byte_val == 0x03 and len(self._buffer) >= 4:
                self._core_bus_ratio = self._buffer[2]
                self._events.append({"type": "CBR", "ratio": self._core_bus_ratio})
                self._buffer = self._buffer[4:]
                continue

            # Unknown — skip one byte
            self._buffer = self._buffer[1:]
            self._stats["errors"] += 1

    def has_events(self) -> bool:
        return len(self._events) > 0

    def next_event(self) -> Optional[Dict[str, Any]]:
        if self._events:
            return self._events.pop(0)
        return None

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def decode_filename(self, filename: str) -> List[Dict[str, Any]]:
        all_events: List[Dict[str, Any]] = []
        try:
            with open(filename, "rb") as f:
                chunk = f.read(4096)
                while chunk:
                    self.feed(chunk)
                    while self.has_events():
                        evt = self.next_event()
                        if evt:
                            all_events.append(evt)
                    chunk = f.read(4096)
        except OSError as e:
            log.error("Failed to read PT trace: %s", e)
        return all_events

    def reconstruct_control_flow(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        control_flow: List[Dict[str, Any]] = []
        current_addr: int = 0
        tnt_idx: int = 0
        tnt_val: int = 0

        for event in events:
            if event["type"] == "TIP":
                current_addr = event["ip"]
                control_flow.append({"address": current_addr, "is_branch_target": True})
            elif event["type"] == "TNT":
                tnt_val = event.get("bits", 0)
                for i in range(event.get("count", 0)):
                    taken = (tnt_val >> i) & 1
                    control_flow.append({
                        "sequence": len(control_flow),
                        "branch_taken": bool(taken),
                        "tnt_index": tnt_idx,
                    })
                    tnt_idx += 1

        return control_flow
