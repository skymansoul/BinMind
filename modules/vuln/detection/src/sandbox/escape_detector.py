"""沙箱逃逸检测器——检测syscall模式中的逃逸尝试: ptrace/mount/kexec/容器突破等."""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Set
from collections import Counter
import os


# 逃逸系统调用集合——按逃逸类型分类
_ESCAPE_SYSCALLS = {
    "ptrace": {
        "syscalls": {"ptrace", "process_vm_readv", "process_vm_writev"},
        "description": "Process tracing/debugging attempt",
        "severity": "high",
    },
    "mount_ns": {
        "syscalls": {"mount", "umount", "pivot_root", "chroot"},
        "description": "Mount namespace escape attempt",
        "severity": "critical",
    },
    "kernel_exploit": {
        "syscalls": {"kexec_load", "kexec_file_load", "create_module",
                     "init_module", "finit_module", "delete_module"},
        "description": "Kernel module/exec load attempt",
        "severity": "critical",
    },
    "container_breakout": {
        "syscalls": {"unshare", "setns", "clone", "nsenter"},
        "description": "Container namespace breakout attempt",
        "severity": "high",
    },
    "capability_abuse": {
        "syscalls": {"capset", "prctl", "seccomp"},
        "description": "Capability/seccomp manipulation",
        "severity": "medium",
    },
    "file_escape": {
        "syscalls": {"open", "openat", "mknod", "mknodat",
                     "creat", "link", "symlink"},
        "description": "File-based escape (device nodes, symlinks)",
        "severity": "low",
    },
    "network_escape": {
        "syscalls": {"socket", "connect", "sendto", "sendmsg",
                     "bind", "listen", "accept"},
        "description": "Unauthorized network access",
        "severity": "medium",
    },
}


@dataclass
class EscapeAttempt:
    attempt_type: str
    syscall: str
    description: str = ""
    severity: str = "low"
    count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempt_type": self.attempt_type,
            "syscall": self.syscall,
            "description": self.description,
            "severity": self.severity,
            "count": self.count,
        }


class SandboxEscapeDetector:
    """沙箱逃逸行为检测。

    分析syscall trace序列，匹配已知逃逸模式(ptrace/mount/kernel-load/ns-breakout)。
    按逃逸类型分组统计，产出severity排序的逃逸尝试列表。
    """

    def __init__(self, syscall_log: str = ""):
        self.syscall_log = syscall_log
        self._syscalls: List[str] = []
        self._detections: List[EscapeAttempt] = []
        self._all_escape_syscalls: Set[str] = set()
        for cat in _ESCAPE_SYSCALLS.values():
            self._all_escape_syscalls.update(cat["syscalls"])

    def analyze(self) -> List[EscapeAttempt]:
        self._load_syscalls()
        if not self._syscalls:
            return []

        counts = Counter(self._syscalls)
        self._detections = []

        for cat_name, cat_info in _ESCAPE_SYSCALLS.items():
            for sc in cat_info["syscalls"]:
                cnt = counts.get(sc, 0)
                if cnt > 0:
                    self._detections.append(EscapeAttempt(
                        attempt_type=cat_name,
                        syscall=sc,
                        description=cat_info["description"],
                        severity=cat_info["severity"],
                        count=cnt,
                    ))

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self._detections.sort(key=lambda d: (sev_order.get(d.severity, 99), -d.count))
        return self._detections

    def _load_syscalls(self) -> None:
        if not self.syscall_log or not os.path.isfile(self.syscall_log):
            return
        try:
            with open(self.syscall_log, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        sc = line.split("(")[0].strip()
                        if sc in self._all_escape_syscalls:
                            self._syscalls.append(sc)
        except Exception:
            pass

    def is_escape_detected(self) -> bool:
        return any(d.severity in ("critical", "high") for d in self._detections)

    def _debug_print_detections(self) -> str:
        return "\n".join(f"[{d.severity}] {d.syscall}: {d.description}"
                         for d in self._detections)

    detection_count = property(lambda self: len(self._detections))

    def to_report(self) -> Dict:
        return {
            "escape_detected": self.is_escape_detected(),
            "total_detections": self.detection_count,
            "detections": [d.to_dict() for d in self._detections],
        }


def escape_check(syscall_log: str) -> Dict:
    detector = SandboxEscapeDetector(syscall_log)
    detector.analyze()
    return detector.to_report()
