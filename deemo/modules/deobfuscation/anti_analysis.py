"""Anti-analysis detection and bypass engine.

Detects common reverse-engineering countermeasures in Linux ELF binaries:
ptrace, LD_PRELOAD hooks, /proc/self/status TracerPid, timing-based
anti-debug, and debugger port scanning. Generates bypass strategies
for each detected technique.
"""

import logging
import os
import re
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

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


_DEBUGGER_PORTS = (23946, 4444, 5555, 31337, 1337)


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


# Bypass strategies

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
}


# Public interfaces

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
    difficulty: str = "low"  # low / medium / high


@dataclass
class AntiAnalysisBypass:
    detections: List[DetectionResult] = field(default_factory=list)
    bypasses: List[BypassResult] = field(default_factory=list)


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

        checks = [
            ("ptrace", _check_ptrace_call(binary), ""),
            ("ld_preload", _check_ld_preload(self._raw), ""),
            ("tracer_pid", _check_tracer_pid(), ""),
            ("timing", _check_timing_anomaly(), ""),
            ("ptrace_scope", _check_ptrace_scope(), ""),
        ]
        for technique, present, detail in checks:
            results.append(DetectionResult(
                technique=technique, present=present, detail=detail,
                bypass=_BYPASS_STRATEGIES.get(technique, ""),
            ))

        open_ports = _scan_debugger_ports()
        if open_ports:
            results.append(DetectionResult(
                technique="debugger_port", present=True,
                detail=f"Open: {open_ports}",
                bypass=_BYPASS_STRATEGIES["debugger_port"],
            ))
        else:
            results.append(DetectionResult(technique="debugger_port", present=False, detail=""))

        return results


class BypassSolver:
    """Given detection results, produce concrete bypass steps."""

    @staticmethod
    def solve(detections: List[DetectionResult]) -> List[BypassResult]:
        out = []
        for d in detections:
            if d.present:
                diff = "medium" if d.technique in ("ptrace_scope", "timing") else "low"
                out.append(BypassResult(
                    technique=d.technique,
                    strategy=_BYPASS_STRATEGIES.get(d.technique, "Unknown"),
                    difficulty=diff,
                ))
        return out


def create_anti_analysis_bypass(binary_path: str) -> AntiAnalysisBypass:
    detector = AntiAnalysisDetector()
    detections = detector.detect(binary_path)
    bypasses = BypassSolver.solve(detections)
    return AntiAnalysisBypass(detections=detections, bypasses=bypasses)


name = "anti_analysis"
module = "anti_analysis"
