"""Anti-analysis detection and bypass engine.

Detects common reverse-engineering countermeasures in Linux ELF binaries:
ptrace, LD_PRELOAD hooks, /proc/self/status TracerPid, timing-based
anti-debug, and debugger port scanning. Generates bypass strategies
for each detected technique.
"""

import ctypes
import ctypes.util as _ctypes_util
import logging
import os
import re
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Optional, Set, Tuple

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
# /proc/self/auxv 扫描 —— ELF 辅助向量 (Auxiliary Vector)
# 调试器/沙箱可能注入异常的 AT_* 条目。正常 auxv 中:
#   AT_PHDR (3), AT_PHENT (4), AT_PHNUM (5), AT_ENTRY (9),
#   AT_UID (11), AT_EUID (12), AT_GID (13), AT_EGID (14),
#   AT_SECURE (23), AT_RANDOM (25), AT_EXECFN (31)
# 异常值（如 AT_UID=0 但 AT_SECURE=1，或缺失 AT_RANDOM）指示
# 正在被 ptrace 或被沙箱修改。
# ---------------------------------------------------------------------------

_AT_NAMES = {3: "PHDR", 4: "PHENT", 5: "PHNUM", 6: "PAGESZ",
             7: "BASE", 8: "FLAGS", 9: "ENTRY", 11: "UID",
             12: "EUID", 13: "GID", 14: "EGID", 15: "PLATFORM",
             23: "SECURE", 25: "RANDOM", 31: "EXECFN",
             32: "SYSINFO_EHDR", 33: "HWCAP"}

_WORD_SIZE = struct.calcsize("P")  # 4 (32-bit) or 8 (64-bit)
_AUXV_ENTRY_SIZE = _WORD_SIZE * 2


def _check_auxv_anomalies() -> Tuple[bool, str]:
    """读取 /proc/self/auxv 并检测异常项。
    auxv 格式: [a_type, a_val] 对的数组，以 a_type=AT_NULL(0) 终止。
    每个条目均为 word_size 字节。
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


# Detection primitives -- each is a standalone check

def _check_ptrace_call(binary_path: str) -> bool:
    """Look for PTRACE_TRACEME (value 0) in the binary's import/plt."""
    try:
        with open(binary_path, "rb") as fh:
            raw = fh.read()
        # ptrace() with arg0 == 0 (PTRACE_TRACEME) -- scan for common patterns
        return b"ptrace" in raw and (b"\x31\xff" in raw or b"\x6a\x00" in raw)
    except OSError:
        return False


def _check_ld_preload(raw_data: bytes) -> bool:
    return b"LD_PRELOAD" in raw_data


def _check_tracer_pid() -> bool:
    """Read /proc/self/status on Linux; non-zero TracerPid => debugged."""
    try:
        with open("/proc/self/status") as fh:
            content = fh.read()
        m = re.search(r"TracerPid:\s*(\d+)", content)
        return m is not None and int(m.group(1)) != 0
    except (OSError, FileNotFoundError):
        return False


def _check_ptrace_scope() -> bool:
    """Return True if ptrace_scope != 0 (may block attach)."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as fh:
            return fh.read().strip() != "0"
    except (OSError, FileNotFoundError):
        return False


def _check_timing_anomaly() -> bool:
    """Crude timing check: two successive clock reads are >2ms apart => breakpoint."""
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
    """检测 SIGTRAP 处理器注册（需具体二进制上下文，此处保留接口）。"""
    return False


_DEBUGGER_PORTS = (23946, 4444, 5555, 31337, 1337, 27042, 27043, 9999)


def _scan_debugger_ports() -> List[int]:
    """Return list of open debugger-common ports via connect scan."""
    import socket
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
        "seccomp filter detected—binary likely restricts syscalls via BPF. "
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
        "SIGTRAP handler registered—use LD_PRELOAD to intercept sigaction; "
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
        "ELF auxiliary vector 异常——可能是 ptrace 或沙箱修改了 AT_SECURE/AT_UID。"
        "检查 auxv 内容: xxd /proc/self/auxv。使用 Frida 的 --realm=emulated 可伪造。"
    ),
}


class AntiAnalysisTechnique:
    DEBUGGER = "debugger"
    VM = "vm"
    SANDBOX = "sandbox"


@dataclass
class DetectionResult:
    technique: str
    present: bool
    detail: str = ""
    bypass: str = ""


@dataclass
class BypassResult:
    technique: str
    strategy: str
    difficulty: str = "low"


@dataclass
class AntiAnalysisBypass:
    detections: List[DetectionResult] = field(default_factory=list)
    bypasses: List[BypassResult] = field(default_factory=list)
    overall_confidence: float = 0.0
    category_breakdown: Dict[str, int] = field(default_factory=dict)


class AntiAnalysisDetector:
    """Run all anti-analysis checks against a given binary."""

    def __init__(self):
        self._raw: Optional[bytes] = None

    def detect(self, binary: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        try:
            with open(binary, "rb") as fh:
                self._raw = fh.read()
        except OSError:
            return results

        static_checks = [
            ("ptrace", _check_ptrace_call(binary), ""),
            ("ld_preload", _check_ld_preload(self._raw), ""),
        ]
        for technique, present, detail in static_checks:
            results.append(DetectionResult(
                technique=technique, present=present, detail=detail,
                bypass=_BYPASS_STRATEGIES.get(technique, "")))

        runtime_checks = [
            ("tracer_pid", _check_tracer_pid(), ""),
            ("timing", _check_timing_anomaly(), ""),
            ("ptrace_scope", _check_ptrace_scope(), ""),
            ("seccomp", _check_seccomp_filter(), "seccomp filter locked"),
            ("proc_stat", _check_proc_self_stat(), "non-zero TracerPid in /proc/self/stat"),
            ("maps_breakpoints", _check_maps_breakpoints(self._raw), "anonymous r-x mappings > 3"),
        ]
        for technique, present, detail in runtime_checks:
            results.append(DetectionResult(
                technique=technique, present=present, detail=detail,
                bypass=_BYPASS_STRATEGIES.get(technique, "")))

        cg_present, cg_detail = _check_cgroup_sandbox()
        results.append(DetectionResult(
            technique="cgroup", present=cg_present, detail=cg_detail,
            bypass=_BYPASS_STRATEGIES.get("cgroup", "")))
        ds_present, ds_detail = _check_disk_size_sandbox()
        results.append(DetectionResult(
            technique="disk_size", present=ds_present, detail=ds_detail,
            bypass=_BYPASS_STRATEGIES.get("disk_size", "")))
        ut_present, ut_detail = _check_uptime_sandbox()
        results.append(DetectionResult(
            technique="uptime", present=ut_present, detail=ut_detail,
            bypass=_BYPASS_STRATEGIES.get("uptime", "")))
        ex_present, ex_detail = _check_proc_exe_symlink()
        results.append(DetectionResult(
            technique="exe_symlink", present=ex_present, detail=ex_detail,
            bypass=_BYPASS_STRATEGIES.get("exe_symlink", "")))

        # auxv 异常检测
        auxv_present, auxv_detail = _check_auxv_anomalies()
        results.append(DetectionResult(
            technique="auxv_anomaly", present=auxv_present, detail=auxv_detail,
            bypass=_BYPASS_STRATEGIES.get("auxv_anomaly", "")))

        open_ports = _scan_debugger_ports()
        if open_ports:
            results.append(DetectionResult(
                technique="debugger_port", present=True,
                detail=f"Open: {open_ports}",
                bypass=_BYPASS_STRATEGIES["debugger_port"]))
        else:
            results.append(DetectionResult(
                technique="debugger_port", present=False, detail=""))

        return results


class BypassSolver:
    """Given detection results, produce concrete bypass steps."""

    _DIFFICULTY_MAP = {
        "ptrace_scope": "medium", "timing": "medium",
        "seccomp": "high", "maps_breakpoints": "medium",
        "sigtrap": "medium", "cgroup": "high",
        "disk_size": "low", "uptime": "low", "exe_symlink": "medium",
        "auxv_anomaly": "high",
    }

    @staticmethod
    def solve(detections: List[DetectionResult]) -> List[BypassResult]:
        out = []
        for d in detections:
            if d.present:
                diff = BypassSolver._DIFFICULTY_MAP.get(d.technique, "low")
                strategy = _BYPASS_STRATEGIES.get(d.technique, "Unknown")
                out.append(BypassResult(
                    technique=d.technique, strategy=strategy, difficulty=diff))
        diff_order = {"high": 0, "medium": 1, "low": 2}
        out.sort(key=lambda x: diff_order.get(x.difficulty, 99))
        return out


def _calc_confidence(detections: List[DetectionResult]) -> float:
    if not detections:
        return 0.0
    present_techs = {d.technique for d in detections if d.present}
    all_techs = {d.technique for d in detections}
    if not present_techs:
        return 0.0
    return round(_bayesian_combine(present_techs, all_techs), 3)


def create_anti_analysis_bypass(binary_path: str) -> AntiAnalysisBypass:
    detector = AntiAnalysisDetector()
    detections = detector.detect(binary_path)
    bypasses = BypassSolver.solve(detections)
    confidence = _calc_confidence(detections)
    breakdown: Dict[str, int] = {}
    for d in detections:
        if d.present:
            if d.technique in ("ptrace", "tracer_pid", "timing", "proc_stat",
                               "ptrace_scope", "sigtrap", "debugger_port", "auxv_anomaly"):
                cat = "debugger"
            elif d.technique in ("seccomp", "maps_breakpoints", "ld_preload"):
                cat = "anti_tamper"
            elif d.technique in ("cgroup", "disk_size", "uptime", "exe_symlink"):
                cat = "sandbox"
            else:
                cat = "other"
            breakdown[cat] = breakdown.get(cat, 0) + 1
    return AntiAnalysisBypass(
        detections=detections, bypasses=bypasses,
        overall_confidence=confidence, category_breakdown=breakdown)


name = "anti_analysis"
module = "anti_analysis"
