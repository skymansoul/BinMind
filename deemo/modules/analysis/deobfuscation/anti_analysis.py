"""反分析检测绕过引擎

对二进制文件执行反分析特征检测（调试器/虚拟机/时间检测/沙箱），
为每个检出的技术构造绕过输入。检测基于字节模式匹配，绕过基于
技术类型的固定 payload，不依赖符号执行。
"""

import ctypes
import ctypes.util as _ctypes_util
import logging
import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 系统调用 / libc 绑定
# ---------------------------------------------------------------------------

_libc = None
_prctl = None

def _load_libc():
    global _libc, _prctl
    if _libc is not None:
        return
    for soname in ("libc.so.6", "libc.so", "libc.dylib", None):
        path = _ctypes_util.find_library(soname) if soname else None
        if path:
            try:
                _libc = ctypes.CDLL(path, use_errno=True)
                _prctl = _libc.prctl
                _prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                                    ctypes.c_ulong, ctypes.c_ulong)
                _prctl.restype = ctypes.c_int
                return
            except Exception:
                _libc = None


PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2


def _check_seccomp_filter() -> bool:
    _load_libc()
    if _prctl is None:
        return False
    try:
        ret = _prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0, 0, 0)
        if ret == 0:
            return False
        err = ctypes.get_errno()
        return err in (13, 14)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# /proc/self/auxv 扫描 - ELF 辅助向量 (Auxiliary Vector)
# 调试器/沙箱可能注入异常的 AT_* 条目。正常 auxv 中:
#   AT_PHDR (3), AT_PHENT (4), AT_PHNUM (5), AT_ENTRY (9),
#   AT_UID (11), AT_EUID (12), AT_GID (13), AT_EGID (14),
#   AT_SECURE (23), AT_RANDOM (25), AT_EXECFN (31)
# 异常值（如 AT_UID=0 但 AT_SECURE=1，或缺失 AT_RANDOM）指示
# 正在被 ptrace 或被沙箱修改
# ---------------------------------------------------------------------------

_AT_NAMES = {3: "PHDR", 4: "PHENT", 5: "PHNUM", 6: "PAGESZ",
             7: "BASE", 8: "FLAGS", 9: "ENTRY", 11: "UID",
             12: "EUID", 13: "GID", 14: "EGID", 15: "PLATFORM",
             23: "SECURE", 25: "RANDOM", 31: "EXECFN",
             32: "SYSINFO_EHDR", 33: "HWCAP"}

_WORD_SIZE = struct.calcsize("P")  # 4 (32-bit) or 8 (64-bit)
_AUXV_ENTRY_SIZE = _WORD_SIZE * 2


def _check_auxv_anomalies() -> Tuple[bool, str]:
    """读取 /proc/self/auxv 并检测异常项
    auxv 格式: [a_type, a_val] 对的数组，以 a_type=AT_NULL(0) 终止
    每个条目均为 word_size 字节
    """
    try:
        with open("/proc/self/auxv", "rb") as fh:
            auxv_data = fh.read()
    except (OSError, FileNotFoundError):
        return False, ""

    anomalies = []
    seen_types = set()
    fmt = "I" if _WORD_SIZE == 4 else "Q"

    for i in range(0, len(auxv_data) - _AUXV_ENTRY_SIZE + 1, _AUXV_ENTRY_SIZE):
        atype = struct.unpack_from(fmt, auxv_data, i)[0]
        aval = struct.unpack_from(fmt, auxv_data, i + _WORD_SIZE)[0]
        if atype == 0:
            break
        seen_types.add(atype)

        # AT_SECURE (23) = 1 表示进程认为自己在运行 setuid 程序，
        # 但在非特权环境中的调试器常设置此值
        if atype == 23 and aval != 0:
            anomalies.append(f"AT_SECURE={aval} (setuid/setgid mode)")
        # AT_UID=0 但非 root 启动 → 可能被 ptrace 修改
        if atype == 11 and aval == 0:
            anomalies.append("AT_UID=0 (running as root in container/sandbox)")

    # 核心条目缺失检测
    required_types = {3, 4, 5, 9, 25}
    missing = required_types - seen_types
    if missing:
        missing_names = [_AT_NAMES.get(t, f"UNKNOWN({t})") for t in missing]
        anomalies.append(f"missing auxv entries: {missing_names}")

    if anomalies:
        return True, "; ".join(anomalies)
    return False, ""


def _check_cgroup_sandbox() -> Tuple[bool, str]:
    indicators = ("docker", "lxc", "kubepods", "containerd", "sandbox", "firecracker")
    try:
        with open("/proc/self/cgroup") as fh:
            cg = fh.read().lower()
        for ind in indicators:
            if ind in cg:
                return True, f"cgroup contains '{ind}'"
    except (OSError, FileNotFoundError):
        pass
    return False, ""


def _check_disk_size_sandbox() -> Tuple[bool, str]:
    try:
        st = os.statvfs("/")
        total_bytes = st.f_frsize * st.f_blocks
        gb = total_bytes / (1024 ** 3)
        if gb < 60:
            return True, f"disk size {gb:.1f}GB < 60GB threshold"
    except (OSError, AttributeError):
        pass
    return False, ""


def _check_uptime_sandbox() -> Tuple[bool, str]:
    try:
        with open("/proc/uptime") as fh:
            uptime_sec = float(fh.read().split()[0])
        if uptime_sec < 600:
            return True, f"uptime {uptime_sec:.0f}s < 600s"
    except (OSError, FileNotFoundError, ValueError):
        pass
    return False, ""


def _check_proc_exe_symlink() -> Tuple[bool, str]:
    try:
        target = os.readlink("/proc/self/exe")
        suspicious = ("frida", "gdb", "lldb", "ltrace", "strace", "qemu")
        base = os.path.basename(target).lower()
        for s in suspicious:
            if s in base:
                return True, f"exe symlink points to '{base}'"
    except (OSError, FileNotFoundError):
        pass
    return False, ""


# 独立检测原语

def _check_ptrace_call(binary_path: str) -> bool:
    """检测 PTRACE_TRACEME (值 0) 的导入/plt。"""
    try:
        with open(binary_path, "rb") as fh:
            raw = fh.read()
        # ptrace() arg0==0 (PTRACE_TRACEME) — 扫描常见模式
        return b"ptrace" in raw and (b"\x31\xff" in raw or b"\x6a\x00" in raw)
    except OSError:
        return False


def _check_ld_preload(raw_data: bytes) -> bool:
    return b"LD_PRELOAD" in raw_data


def _check_tracer_pid() -> bool:
    """读取 /proc/self/status; TracerPid 非零表示被调试。"""
    try:
        with open("/proc/self/status") as fh:
            content = fh.read()
        m = re.search(r"TracerPid:\s*(\d+)", content)
        return m is not None and int(m.group(1)) != 0
    except (OSError, FileNotFoundError):
        return False


def _check_ptrace_scope() -> bool:
    """返回 True 表示 ptrace_scope!=0 (阻止 attach)。"""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            return fh.read().strip() != "0"
    except (OSError, FileNotFoundError):
        return False


def _check_timing_anomaly() -> bool:
    """粗略时序检查: 两次时钟读取差 >2ms 则可能被断点。"""
    t1 = time.perf_counter()
    time.perf_counter()
    t2 = time.perf_counter()
    return (t2 - t1) > 0.002


def _check_proc_self_stat() -> bool:
    try:
        with open("/proc/self/stat") as fh:
            content = fh.read()
        m = re.search(r"\)\s+\w\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+", content)
        if m:
            fields = m.group(0).split()
            if len(fields) >= 7 and int(fields[6]) != 0:
                return True
    except (OSError, FileNotFoundError, ValueError, IndexError):
        pass
    return False


def _check_maps_breakpoints(raw_data: bytes) -> bool:
    try:
        with open("/proc/self/maps") as fh:
            content = fh.read()
        anon_exec = 0
        for line in content.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                perms = parts[1]
                path = parts[-1] if len(parts) >= 6 else ""
                if "x" in perms and path == "" and "r" in perms:
                    anon_exec += 1
        return anon_exec > 3
    except (OSError, FileNotFoundError):
        return False


def _check_sigtrap_handler() -> bool:
    """检测 SIGTRAP 处理器注册（需具体二进制上下文，此处保留接口）"""
    return False


_DEBUGGER_PORTS = (23946, 4444, 5555, 31337, 1337, 27042, 27043, 9999)


def _scan_debugger_ports() -> List[int]:
    """返回已开放的调试器常用端口列表 (connect 扫描)。"""
    open_ports = []
    for port in _DEBUGGER_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                open_ports.append(port)
        except Exception:
            logger.debug("suppressed", exc_info=True)
        finally:
            s.close()
    return open_ports


_BAYES_PRIORS = {
    "ptrace": (0.90, 0.99), "ld_preload": (0.85, 0.97),
    "tracer_pid": (0.99, 0.995), "timing": (0.40, 0.70),
    "ptrace_scope": (0.90, 0.95), "debugger_port": (0.70, 0.90),
    "seccomp": (0.80, 0.95), "maps_breakpoints": (0.55, 0.85),
    "proc_stat": (0.75, 0.90), "cgroup": (0.60, 0.88),
    "disk_size": (0.35, 0.92), "uptime": (0.45, 0.80),
    "exe_symlink": (0.90, 0.98), "auxv_anomaly": (0.85, 0.93),
}


def _bayesian_combine(present_techniques: Set[str], all_techniques: Set[str]) -> float:
    P_PRIOR = 0.01
    logit_prior = P_PRIOR / (1.0 - P_PRIOR)
    log_lr_sum = 0.0
    for tech in all_techniques:
        sens, spec = _BAYES_PRIORS.get(tech, (0.5, 0.5))
        sens = max(0.01, min(0.99, sens))
        spec = max(0.01, min(0.99, spec))
        if tech in present_techniques:
            lr = sens / (1.0 - spec)
        else:
            lr = (1.0 - sens) / spec
        if lr > 0:
            log_lr_sum += lr
    posterior_odds = logit_prior * log_lr_sum
    return posterior_odds / (1.0 + posterior_odds)


_BYPASS_STRATEGIES: Dict[str, str] = {
    "ptrace": (
        "Override ptrace via LD_PRELOAD shim: intercept the call and return 0 "
        "when arg0==PTRACE_TRACEME.  Or patch the binary: NOP the call site."
    ),
    "ld_preload": (
        "Binary checks for LD_PRELOAD in /proc/self/environ.  Use a loader shim "
        "that unsets LD_PRELOAD before exec, or patch the strcmp target in .rodata."
    ),
    "tracer_pid": (
        "Frida/frida-gadget hides TracerPid automatically.  Alternatively, "
        "hook fopen/fgets to fake /proc/self/status output (return TracerPid: 0)."
    ),
    "timing": (
        "NOP or hook clock_gettime / gettimeofday at the comparison site.  "
        "For x64: overwrite the conditional jump after the timing check."
    ),
    "debugger_port": (
        "The binary connects to known debugger ports.  Spoof the response with a "
        "simple TCP server that returns the expected handshake, or patch the "
        "port numbers in the binary's .rodata / immediate operands."
    ),
    "ptrace_scope": (
        "Echo 0 into /proc/sys/kernel/yama/ptrace_scope (needs root).  "
        "In a container, use --cap-add=SYS_PTRACE."
    ),
    "seccomp": (
        "seccomp filter detected-binary likely restricts syscalls via BPF. "
        "Bypass: LD_PRELOAD hook prctl() to drop SECCOMP_SET_MODE_FILTER calls."
    ),
    "maps_breakpoints": (
        "匿名可执行内存区域过多。若使用 GDB: 'set disable-randomization on' + "
        "检查 vDSO 映射是否正常。"
    ),
    "proc_stat": (
        "目标扫描 /proc/self/stat 的 TracerPid。Frida 自动隐藏此字段；"
        "自定义调试器需 hook read/readv。"
    ),
    "sigtrap": (
        "SIGTRAP handler registered-use LD_PRELOAD to intercept sigaction; "
        "or patch the handler table to SIG_DFL."
    ),
    "cgroup": (
        "容器/沙箱环境检测。绕过：使用 --cgroup-parent 改名；或在 privileged 容器中 "
        "挂载伪造的 /proc/self/cgroup。"
    ),
    "disk_size": (
        "磁盘容量低于沙箱阈值。在 VM 中分配 > 80GB 虚拟磁盘。"
    ),
    "uptime": (
        "系统运行时间过短。在启动分析环境后等待 > 15 分钟。"
    ),
    "exe_symlink": (
        "可执行文件路径暴露了调试工具名。用 exec -a 或符号链接重命名。"
    ),
    "auxv_anomaly": (
        "ELF auxiliary vector 异常-可能是 ptrace 或沙箱修改了 AT_SECURE/AT_UID。"
        "检查 auxv 内容: xxd /proc/self/auxv。使用 Frida 的 --realm=emulated 可伪造。"
    ),
}


class AntiAnalysisTechnique:
    DEBUGGER = "debugger"
    VM = "vm"
    SANDBOX = "sandbox"


@dataclass
class AntiAnalysisTechnique:
    """单项反分析技术及其检测位置。"""
    name: str
    location: int
    detection_code: str
    bypass_input: Optional[bytes] = None


@dataclass
class BypassResult:
    """绕过结果 - success 标记整体是否成功，techniques 为检测项。"""
    success: bool
    techniques: List[AntiAnalysisTechnique]
    bypass_inputs: Dict[str, bytes] = field(default_factory=dict)


class AntiAnalysisDetector:
    """对二进制运行反分析检测。"""

    ANTI_PATTERNS: Dict[str, List[bytes]] = {
        "is_debugger": [b"IsDebuggerPresent", b"CheckRemoteDebugger",
                        b"ptrace", b"NtQueryInformationProcess"],
        "vm_check": [b"cpuid", b"vmware", b"virtualbox", b"qemu"],
        "timing": [b"rdtsc", b"QueryPerformanceCounter", b"Sleep"],
        "sandbox": [b"mouse_event", b"GetAsyncKeyState", b"username"],
    }

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect(self) -> List[AntiAnalysisTechnique]:
        """扫描二进制内容，返回所有命中的反分析技术。

        同一模式多处出现时逐处记录位置。
        """
        techniques: List[AntiAnalysisTechnique] = []
        try:
            with open(self.binary_path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            logger.warning("反分析检测失败: %s", exc)
            return techniques

        for category, patterns in self.ANTI_PATTERNS.items():
            for pattern in patterns:
                pos = 0
                while True:
                    idx = data.find(pattern, pos)
                    if idx == -1:
                        break
                    techniques.append(AntiAnalysisTechnique(
                        name=category,
                        location=idx,
                        detection_code=pattern.decode("ascii", errors="ignore"),
                    ))
                    pos = idx + 1
        return techniques


class BypassSolver:
    """基于检测结果构造具体绕过步骤。"""

    _DIFFICULTY_MAP = {
        "ptrace_scope": "medium", "timing": "medium",
        "seccomp": "high", "maps_breakpoints": "medium",
        "sigtrap": "medium", "cgroup": "high",
        "disk_size": "low", "uptime": "low", "exe_symlink": "medium",
        "auxv_anomaly": "high",
    }

    @staticmethod
    def solve(technique: AntiAnalysisTechnique) -> Optional[bytes]:
        """返回该技术的绕过输入；未知类型返回 None。"""
        if technique.name == "is_debugger":
            return b"\x00" * 4
        if technique.name == "vm_check":
            return b"\x01"
        if technique.name == "timing":
            return b"\x00" * 8
        if technique.name == "sandbox":
            return b"user" + b"\x00" * 60
        return None

    @staticmethod
    def generate_frida_script(techniques: List[AntiAnalysisTechnique]) -> str:
        """为检测项生成 Frida 拦截脚本；无检测项返回空串。"""
        if not techniques:
            return ""
        parts = ["// Anti-analysis bypass hooks"]
        for tech in techniques:
            code = tech.detection_code
            parts.append(
                f"Interceptor.attach(Module.findExportByName(null, '{code}'), "
                f"{{ onEnter: function(args) {{ args[0] = ptr('0'); }} }});"
            )
        return "\n".join(parts)

    @staticmethod
    def generate_ld_preload_stub(techniques: List[AntiAnalysisTechnique]) -> str:
        """为检测项生成 LD_PRELOAD 桩代码。

        is_debugger 类别固定声明 IsDebuggerPresent 覆盖；其余检测码
        按可变参数原型生成同名函数。桩内保留检测码标识便于定位。
        """
        parts = ["// LD_PRELOAD bypass stub"]
        has_debugger = False
        for tech in techniques:
            code = tech.detection_code
            parts.append(f"// bypass {code}")
            if tech.name == "is_debugger":
                has_debugger = True
                parts.append("int ptrace(int request, ...) { return 0; }")
            else:
                parts.append(f"int {code}(void) {{ return 0; }}")
        if has_debugger and not any(
                t.detection_code == "IsDebuggerPresent" for t in techniques):
            parts.append("int IsDebuggerPresent(void) { return 0; }")
        return "\n".join(parts)


class AntiAnalysisBypass:
    """反分析绕过执行器 - 检测后生成并保存绕过输入。"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.detector = AntiAnalysisDetector(binary_path)
        self.solver = BypassSolver()

    def run(self) -> BypassResult:
        """执行完整检测与绕过流程。"""
        try:
            techniques = self.detector.detect()
            bypass_inputs: Dict[str, bytes] = {}
            for tech in techniques:
                inp = self.solver.solve(tech)
                if inp is not None:
                    tech.bypass_input = inp
                    bypass_inputs[tech.detection_code] = inp
            return BypassResult(
                success=True, techniques=techniques, bypass_inputs=bypass_inputs)
        except Exception as exc:
            logger.error("反分析绕过失败: %s", exc)
            return BypassResult(success=False, techniques=[])


def create_anti_analysis_bypass(binary_path: str) -> AntiAnalysisBypass:
    """创建反分析绕过执行器。"""
    return AntiAnalysisBypass(binary_path)


name = "anti_analysis"
module = "anti_analysis"
