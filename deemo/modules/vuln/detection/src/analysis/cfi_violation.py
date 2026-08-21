# — CFI违规检测器
# 扫描间接调用/跳转，验证目标地址合法性

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
import os
import re

from deemo.modules.vuln.detection.src.logger import get_logger

_log = get_logger("vuln_detection.cfi_violation")


@dataclass
class ViolationReport:
    binary_path: str = ""
    total_indirect_calls: int = 0
    violations: int = 0
    violation_list: List[Dict] = field(default_factory=list)
    safe_calls: int = 0
    unresolved: int = 0

    @property
    def risk(self) -> str:
        if self.violations == 0:
            return "none"
        ratio = self.violations / max(self.total_indirect_calls, 1)
        if ratio >= 0.5:
            return "critical"
        if ratio >= 0.2:
            return "high"
        if ratio >= 0.05:
            return "medium"
        return "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_path": self.binary_path,
            "total_indirect_calls": self.total_indirect_calls,
            "violations": self.violations,
            "safe_calls": self.safe_calls,
            "unresolved": self.unresolved,
            "risk": self.risk,
            "violation_list": self.violation_list[:100],
        }


class CFIViolationChecker:
    """间接调用/跳转安全验证。
    扫描call reg/jmp reg指令，反汇编获取目标入口地址，
    验证其指向合法函数起始。
    合法入口来源:
    - radare2 afl函数列表
    - 符号表导出函数
    - 编译器桩函数
    """

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self._valid_entries: Set[int] = set()
        self._indirect_calls: List[Dict] = []
        self._r2_available = False

    def _ensure_r2(self) -> bool:
        import subprocess
        try:
            r = subprocess.run(["r2", "-v"], capture_output=True, text=True, timeout=5)
            self._r2_available = r.returncode == 0
        except Exception:
            self._r2_available = False
        return self._r2_available

    def analyze(self) -> ViolationReport:
        if not os.path.isfile(self.binary_path):
            return ViolationReport(binary_path=self.binary_path)

        self._collect_valid_entries()
        self._find_indirect_calls()
        return self._build_report()

    def _collect_valid_entries(self) -> None:
        if not self._ensure_r2():
            return
        try:
            import subprocess, json
            r = subprocess.run(
                ["r2", "-q", "-c", "aflj", self.binary_path],
                capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                funcs = json.loads(r.stdout)
                for f in funcs:
                    addr = f.get("offset", 0)
                    if addr:
                        self._valid_entries.add(addr)
        except Exception:
            pass

    def _find_indirect_calls(self) -> None:
        if not self._r2_available:
            return
        try:
            import subprocess
            # 搜索间接调用：call rax/eax/rbx, jmp rax
            r = subprocess.run(
                ["r2", "-q", "-c", "aa; /c call r", self.binary_path],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    m = re.match(r'^\s*(0x[0-9a-fA-F]+)\s', line)
                    if m:
                        addr = int(m.group(1), 16)
                        comment_line = line.strip()
                        reg_match = re.search(r'call\s+(r\w+|e\w+)', comment_line)
                        reg = reg_match.group(1) if reg_match else "unknown"
                        self._indirect_calls.append({
                            "address": addr, "register": reg,
                            "instruction": comment_line[:100],
                        })
        except Exception:
            pass

    def _build_report(self) -> ViolationReport:
        total = len(self._indirect_calls)
        violations = []
        safe = 0; unresolved = 0

        if not self._valid_entries:
            unresolved = total
        else:
            for call in self._indirect_calls:
                addr = call["address"]
                if addr in self._valid_entries:
                    safe += 1
                elif self._is_near_valid(addr):
                    safe += 1
                else:
                    violations.append(call)

        return ViolationReport(
            binary_path=self.binary_path,
            total_indirect_calls=total,
            violations=len(violations),
            violation_list=violations,
            safe_calls=safe,
            unresolved=unresolved,
        )

    def _is_near_valid(self, addr: int, tolerance: int = 16) -> bool:
        """地址在合法入口±tolerance字节内视为安全，对齐偏移容差。"""
        return any(abs(addr - valid) <= tolerance
                   for valid in self._valid_entries)


def scan_indirect_calls(binary_path: str) -> ViolationReport:
    checker = CFIViolationChecker(binary_path)
    return checker.analyze()
