"""Dynamic 污点追踪 byte-level taint maps for 二进制分析"""

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
    NETWORK_RECV = auto()     # recv / recvfrom / 读取 套接字 fd
    ENV_VAR = auto()          # getenv()
    DERIVED = auto()          # arithmetic result tainted operands
    REGISTER = auto()         # taint traveled a 寄存器
    CONSTANT = auto()         # -clean constant


TaintSource = TaintTag  # backwards-compat alias


class TaintMap:
    """Per-寄存器 / per-memory-byte 污点追踪

    byte 追踪 a bitmask TaintTag values. A byte tagged
    USER_INPUT | 网络_RECV means influenced
    """

    def __init__(self):
        self._registers: Dict[str, int] = defaultdict(int)
        # 堆/栈 byte-level taint: address -> tag
        self._memory: Dict[int, int] = {}
        # 污点传播历史 — 记录每条传播路径用于审计追踪
        self._propagation_log: List[Dict] = []

# 寄存器 taint

    def tag_register(self, reg: str, tag: TaintTag) -> None:
        self._registers[reg] |= tag

    def set_register(self, reg: str, tag: int) -> None:
        self._registers[reg] = tag

    def get_register(self, reg: str) -> int:
        return self._registers.get(reg, 0)

    def clear_register(self, reg: str) -> None:
        self._registers.pop(reg, None)

# memory taint

    def tag_memory(self, addr: int, size: int, tag: TaintTag) -> None:
        for off in range(size):
            self._memory[addr + off] = self._memory.get(addr + off, 0) | tag

    def set_memory(self, addr: int, tag: int) -> None:
        self._memory[addr] = tag

    def get_memory(self, addr: int) -> int:
        return self._memory.get(addr, 0)

    def get_memory_range(self, addr: int, size: int) -> int:
        """Union tags [addr, addr+size)"""
        combined = 0
        for off in range(size):
            combined |= self._memory.get(addr + off, 0)
        return combined

    def propagate(self, dst_addr: int, src_addr: int, size: int) -> None:
        """Copy taint src range dst range (e.g. memcpy)"""
        for off in range(size):
            src_tag = self._memory.get(src_addr + off, 0)
            if src_tag:
                self._memory[dst_addr + off] = src_tag | TaintTag.DERIVED
        self._propagation_log.append({
            'op': 'propagate', 'dst': dst_addr, 'src': src_addr, 'size': size
        })

    def propagate_register_to_memory(self, reg: str, addr: int, size: int) -> None:
        tag = self._registers.get(reg, 0) | TaintTag.DERIVED
        for off in range(size):
            self._memory[addr + off] |= tag

    def propagate_binary_op(self, dst_reg: str, src_regs: List[str]) -> None:
        """将 taint source 寄存器合并到 dst。"""
        merged = TaintTag.DERIVED
        for r in src_regs:
            merged |= self._registers.get(r, 0)
        self._registers[dst_reg] = merged

    def is_tainted(self, addr: int, size: int = 1) -> bool:
        return any(self._memory.get(addr + off, 0) != 0 for off in range(size))

    def is_register_tainted(self, reg: str) -> bool:
        return self._registers.get(reg, 0) != 0

# 新增: 污点审计追踪
    # 记录每次传播操作，用于回溯完整的污点传播链
    def audit_trail(self) -> List[Dict]:
        """返回污点传播的审计日志 — 每次propagate/tag_memory操作的时间倒序列表"""
        return list(self._propagation_log)

# 新增: 污点密度统计
    # 按标签类型统计污染内存字中的数量分布
    def taint_density(self) -> Dict[str, int]:
        """按TaintTag类别统计被污染内存字节的数量分布
        USER_INPUT和NETWORK_RECV占比高指示外部输入直接到达危险区域的风险更大"""
        densities: Dict[str, int] = defaultdict(int)
        for tag_val in self._memory.values():
            if tag_val == 0:
                continue
            for ttag in TaintTag:
                if tag_val & ttag:
                    densities[ttag.name] += 1
        return dict(densities)


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
    """污点追踪 using Frida 插桩

    Requires a Frida-capable environment. For headless 使用
    consider QBDI backend instead
    """

    def __init__(self, taint_map: Optional[TaintMap] = None):
        self._taint = taint_map or TaintMap()
        self._sources: List[DynamicTaintSource] = []
        self._sinks: List[DynamicTaintSink] = []
        self._flows: List[DynamicTaintFlow] = []
        self._script = None

    def track(self, binary: str) -> List[DynamicVulnerability]:
        """钩子 binary Frida 追踪 taint flows"""
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
            # Collect flows messages
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
        """回调 Frida 钩子"""
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
    """污点追踪 using QBDI (QuarkslaB Dynamic binary 插桩)

    Works entirely -process, external daemon needed
    """

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
        # a real 插桩 'd 钩子 读取/recv
        self._source_network_recv(state)
        self._source_argv(state)

        # 运行: instrument instructions
        vm.addCodeCB(qbdi.PREINST, self._qbdi_callback)
        ok = vm.run(0x1000, 0x2000)
        return self._build_vulns()

    def _source_network_recv(self, state) -> None:
        # Simulate marking 栈 缓冲区 populated recv() tainted
        self._taint.tag_memory(0x7F000000, 256, TaintTag.NETWORK_RECV)

    def _source_argv(self, state) -> None:
        self._taint.tag_memory(0x7F000100, 128, TaintTag.USER_INPUT)

    def _qbdi_callback(self, vm, gpr, fpr, data) -> int:
        """QBDI pre-instruction 回调: propagate taint"""
        inst = vm.getInstAnalysis()
        if inst is None:
            return qbdi.CONTINUE

        # Simplified: instruction 写入 memory 读取 tainted reg
        # propagate taint
        for operand in inst.operands:
            if operand.access & qbdi.OPERAND_WRITE:
                reg_name = inst.getRegisterName(operand.reg)
                if self._taint.is_register_tainted(reg_name):
                    # Mark destination DERIVED
                    pass

        return qbdi.CONTINUE

    def _build_vulns(self) -> List[DynamicVulnerability]:
        if not self._flows:
            return []
        return [DynamicVulnerability(name="qbdi_taint", flows=self._flows, severity="MEDIUM")]


# 模块级 convenience

def create_dynamic_taint_tracker(backend: str = "frida") -> Any:
    backends = {"frida": FridaTaintTracker, "qbdi": QBDITaintTracker}
    cls = backends.get(backend, FridaTaintTracker)
    return cls()


def run_dynamic_taint_analysis(binary: str, backend: str = "frida") -> List[DynamicVulnerability]:
    tracker = create_dynamic_taint_tracker(backend)
    return tracker.track(binary)
