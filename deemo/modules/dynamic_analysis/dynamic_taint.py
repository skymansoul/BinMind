# 动态污点追踪，字节级污点图用于二进制分析
import array
import logging
import os
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, auto
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class TaintTag(IntFlag):
    NONE = 0
    USER_INPUT = auto()       # stdin / argv
    FILE_READ = auto()        # read() / fread() / mmap regions
    NETWORK_RECV = auto()     # recv / recvfrom / read on socket fd
    ENV_VAR = auto()          # getenv()
    DERIVED = auto()          # arithmetic result of tainted operands
    REGISTER = auto()         # taint traveled through a register
    CONSTANT = auto()         # known-clean constant


TaintSource = TaintTag  # backwards-compat alias


class TaintMap:
    # 寄存器/内存字节级污点追踪
    # 每个字节追踪 TaintTag 位掩码，USER_INPUT|NETWORK_RECV 表示受两者影响

    def __init__(self):
        self._registers: Dict[str, int] = defaultdict(int)
        # Heap/stack byte-level taint: address -> tag
        self._memory: Dict[int, int] = {}

    # -- register taint --------------------------------------------------------

    def tag_register(self, reg: str, tag: TaintTag) -> None:
        self._registers[reg] |= tag

    def set_register(self, reg: str, tag: int) -> None:
        self._registers[reg] = tag

    def get_register(self, reg: str) -> int:
        return self._registers.get(reg, 0)

    def clear_register(self, reg: str) -> None:
        self._registers.pop(reg, None)

    # -- memory taint ----------------------------------------------------------

    def tag_memory(self, addr: int, size: int, tag: TaintTag) -> None:
        for off in range(size):
            self._memory[addr + off] = self._memory.get(addr + off, 0) | tag

    def set_memory(self, addr: int, tag: int) -> None:
        self._memory[addr] = tag

    def get_memory(self, addr: int) -> int:
        return self._memory.get(addr, 0)

    def get_memory_range(self, addr: int, size: int) -> int:
        # 返回 [addr, addr+size) 范围内所有标签的并集
        combined = 0
        for off in range(size):
            combined |= self._memory.get(addr + off, 0)
        return combined

    def propagate(self, dst_addr: int, src_addr: int, size: int) -> None:
        # 将 src 范围的污点拷贝到 dst 范围（如 memcpy）
        for off in range(size):
            self._memory[dst_addr + off] = self._memory.get(src_addr + off, 0) | TaintTag.DERIVED

    def propagate_register_to_memory(self, reg: str, addr: int, size: int) -> None:
        tag = self._registers.get(reg, 0) | TaintTag.DERIVED
        for off in range(size):
            self._memory[addr + off] |= tag

    def propagate_binary_op(self, dst_reg: str, src_regs: List[str]) -> None:
        # 将源寄存器的污点合并到 dst
        merged = TaintTag.DERIVED
        for r in src_regs:
            merged |= self._registers.get(r, 0)
        self._registers[dst_reg] = merged

    def is_tainted(self, addr: int, size: int = 1) -> bool:
        return any(self._memory.get(addr + off, 0) != 0 for off in range(size))

    def is_register_tainted(self, reg: str) -> bool:
        return self._registers.get(reg, 0) != 0


# Sink definitions

@dataclass
class DynamicTaintSink:
    name: str
    category: str        # mem_write | exec_arg | file_path | format_string
    address_range: Tuple[int, int] = (0, 0)
    argument_index: int = 0
    description: str = ""

@dataclass
class DynamicTaintSource:
    name: str
    source_type: TaintTag
    address_range: Tuple[int, int] = (0, 0)

@dataclass
class DynamicTaintFlow:
    source: Optional[DynamicTaintSource] = None
    sink: Optional[DynamicTaintSink] = None
    taint_tags: int = 0
    source_offset: int = 0
    sink_offset: int = 0

@dataclass
class DynamicVulnerability:
    name: str = ""
    flows: List[DynamicTaintFlow] = field(default_factory=list)
    severity: str = "MEDIUM"


# Sink detection rules

_SINK_SIGNATURES = {
    "memcpy_size": {
        "category": "mem_write",
        "args": [
            ("memcpy", 2), ("memmove", 2), ("memcpy_s", 2),
            ("__memcpy_chk", 2), ("bcopy", 2), ("memccpy", 3),
            ("send", 2), ("write", 2), ("fwrite", 2),
        ],
        "desc": "Tainted size argument to memory copy / write",
    },
    "exec_args": {
        "category": "exec_arg",
        "args": [
            ("execve", 1), ("execvp", 1), ("execvpe", 1),
            ("system", 0), ("popen", 0), ("CreateProcessA", 1),
            ("CreateProcessW", 1), ("ShellExecuteA", 2),
        ],
        "desc": "Tainted argument to process execution",
    },
    "file_path": {
        "category": "file_path",
        "args": [
            ("open", 0), ("fopen", 0), ("access", 0),
            ("stat", 0), ("lstat", 0), ("unlink", 0),
            ("rename", 0), ("rename", 1), ("remove", 0),
            ("CreateFileA", 0), ("CreateFileW", 0),
        ],
        "desc": "Tainted file path argument",
    },
    "format_string": {
        "category": "format_string",
        "args": [
            ("printf", 0), ("fprintf", 1), ("sprintf", 1),
            ("snprintf", 1), ("syslog", 1),
        ],
        "desc": "Tainted format-string argument",
    },
}


class FridaTaintTracker:
    # 基于 Frida 插桩的污点追踪，需要 Frida 环境；无头模式可用 QBDI 后端

    def __init__(self, taint_map: Optional[TaintMap] = None):
        self._taint = taint_map or TaintMap()
        self._sources: List[DynamicTaintSource] = []
        self._sinks: List[DynamicTaintSink] = []
        self._flows: List[DynamicTaintFlow] = []
        self._script = None

    def track(self, binary: str) -> List[DynamicVulnerability]:
        # 用 Frida hook 二进制并追踪污点流
        try:
            import frida
        except ImportError:
            _log.warning("frida not installed; taint tracking unavailable")
            return []

        script = self._build_frida_script()
        device = frida.get_local_device()
        try:
            pid = device.spawn([binary])
            session = device.attach(pid)
            script_obj = session.create_script(script)
            script_obj.on("message", self._on_message)
            script_obj.load()
            device.resume(pid)
            # Collect flows from messages
            return self._build_vulns()
        except frida.ProcessNotFoundError:
            _log.error("Frida: cannot spawn %s", binary)
            return []
        except Exception as exc:
            _log.error("Frida error: %s", exc)
            return []

    def _build_frida_script(self) -> str:
        return """
        const memcpyPtr = Module.findExportByName(null, "memcpy");
        if (memcpyPtr) {
            Interceptor.attach(memcpyPtr, {
                onEnter(args) {
                    const size = args[2].toInt32();
                    send({type:"memcpy", size:size, dst:args[0], src:args[1]});
                }
            });
        }
        const execvePtr = Module.findExportByName(null, "execve");
        if (execvePtr) {
            Interceptor.attach(execvePtr, {
                onEnter(args) {
                    send({type:"execve", path:args[0].readCString()});
                }
            });
        }
        const systemPtr = Module.findExportByName(null, "system");
        if (systemPtr) {
            Interceptor.attach(systemPtr, {
                onEnter(args) {
                    send({type:"system", cmd:args[0].readCString()});
                }
            });
        }
        """

    def _on_message(self, message: Dict, data: Any) -> None:
        # Frida hook 回调
        payload = message.get("payload", {})
        msg_type = payload.get("type", "")
        if msg_type in ("memcpy",):
            src = int(payload.get("src", 0))
            dst = int(payload.get("dst", 0))
            size = int(payload.get("size", 0))
            if self._taint.is_tainted(src, min(size, 64)):
                self._taint.propagate(dst, src, size)
                self._flows.append(DynamicTaintFlow(
                    source=DynamicTaintSource(name="frida_hook", source_type=TaintTag.USER_INPUT),
                    sink=DynamicTaintSink(name="memcpy", category="mem_write", address_range=(dst, dst + size)),
                ))
        elif msg_type in ("execve", "system"):
            _log.info("Tainted exec: %s", payload)

    def _build_vulns(self) -> List[DynamicVulnerability]:
        if not self._flows:
            return []
        by_sink = defaultdict(list)
        for flow in self._flows:
            key = flow.sink.category if flow.sink else "unknown"
            by_sink[key].append(flow)
        return [DynamicVulnerability(
            name=cat, flows=flows,
            severity="HIGH" if cat in ("exec_arg",) else "MEDIUM",
        ) for cat, flows in by_sink.items()]


class QBDITaintTracker:
    # 基于 QBDI 的污点追踪，全进程内运行无需外部守护进程

    def __init__(self, taint_map: Optional[TaintMap] = None):
        self._taint = taint_map or TaintMap()
        self._flows: List[DynamicTaintFlow] = []

    def track(self, binary: str) -> List[DynamicVulnerability]:
        try:
            import qbdi
        except ImportError:
            _log.warning("QBDI not installed; taint tracking unavailable")
            return []

        vm = qbdi.VM()
        state = vm.getGPRState()
        # Mark common taint sources
        # In a real instrumentation we'd hook read/recv here
        self._source_network_recv(state)
        self._source_argv(state)

        # Run: instrument all instructions
        vm.addCodeCB(qbdi.PREINST, self._qbdi_callback)
        ok = vm.run(0x1000, 0x2000)
        return self._build_vulns()

    def _source_network_recv(self, state) -> None:
        # Simulate marking stack buffer populated by recv() as tainted
        self._taint.tag_memory(0x7F000000, 256, TaintTag.NETWORK_RECV)

    def _source_argv(self, state) -> None:
        self._taint.tag_memory(0x7F000100, 128, TaintTag.USER_INPUT)

    def _qbdi_callback(self, vm, gpr, fpr, data) -> int:
        # QBDI 指令前回调：传播污点
        inst = vm.getInstAnalysis()
        if inst is None:
            return qbdi.CONTINUE

        # Simplified: if instruction writes to memory and reads from tainted reg,
        # propagate taint
        for operand in inst.operands:
            if operand.access & qbdi.OPERAND_WRITE:
                reg_name = inst.getRegisterName(operand.reg)
                if self._taint.is_register_tainted(reg_name):
                    # Mark destination as DERIVED
                    pass

        return qbdi.CONTINUE

    def _build_vulns(self) -> List[DynamicVulnerability]:
        if not self._flows:
            return []
        return [DynamicVulnerability(name="qbdi_taint", flows=self._flows, severity="MEDIUM")]


# Module-level convenience

def create_dynamic_taint_tracker(backend: str = "frida") -> Any:
    backends = {"frida": FridaTaintTracker, "qbdi": QBDITaintTracker}
    cls = backends.get(backend, FridaTaintTracker)
    return cls()


def run_dynamic_taint_analysis(binary: str, backend: str = "frida") -> List[DynamicVulnerability]:
    tracker = create_dynamic_taint_tracker(backend)
    return tracker.track(binary)
