#!/usr/bin/env python3
"""
CFI 违规预检模块 - 构建合法调用目标集，检查间接调用点
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)


@dataclass
class IndirectCall:
    call_site: int
    target_register: str
    possible_targets: List[int] = field(default_factory=list)


@dataclass
class CFIViolation:
    call_site: int
    target: int
    reason: str
    severity: str


@dataclass
class CheckResult:
    success: bool
    indirect_calls: List[IndirectCall]
    violations: List[CFIViolation]


class FunctionEntryCollector:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.entries: Set[int] = set()

    def collect(self) -> Set[int]:
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", "aa; afl", self.binary_path],
                capture_output=True, text=True, timeout=180,
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if parts:
                        try:
                            self.entries.add(int(parts[0], 16))

                        except ValueError:
                            pass
        except Exception:
            pass
        return self.entries


class IndirectCallScanner:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def scan(self) -> List[IndirectCall]:
        calls = []
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", "aa; pdf @ entry0", self.binary_path],
                capture_output=True, text=True, timeout=60,
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "call rax" in line or "call rbx" in line or "call rcx" in line:
                        parts = line.split()
                        try:
                            addr = int(parts[0], 16)
                            reg = "rax" if "rax" in line else ("rbx" if "rbx" in line else "rcx")
                            calls.append(IndirectCall(call_site=addr, target_register=reg))

                        except ValueError:
                            pass
        except Exception:
            pass
        return calls


class CFIChecker:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.collector = FunctionEntryCollector(binary_path)
        self.scanner = IndirectCallScanner(binary_path)

    def run(self) -> CheckResult:
        try:
            entries = self.collector.collect()
            calls = self.scanner.scan()
            violations = []
            for call in calls:
                for target in call.possible_targets:
                    if target not in entries:
                        violations.append(CFIViolation())
                            call_site=call.call_site, target=target,
                            reason="Target not in valid function entries",
                            severity="high",
                        

            return CheckResult(success=True, indirect_calls=calls, violations=violations)
        except Exception as e:
            logger.error("CFI check failed: %s", e)
            return CheckResult(success=False, indirect_calls=[], violations=[])


def create_cfi_checker(binary_path: str) -> CFIChecker:
    return CFIChecker(binary_path)
