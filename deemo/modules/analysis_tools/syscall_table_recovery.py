from typing import Dict, Any
from typing import List, Optional
"""Syscall table recovery and security analysis."""
from enum import Enum

class KernelType(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"

class ArchType(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"

class SyscallEntry:
    def __init__(self, number=0, name="", params=None):
        self.number = number; self.name = name; self.params = params or []

class SyscallTableInfo:
    def __init__(self): pass

class SyscallAnalysisResult:
    def __init__(self): pass

class SyscallTableRecovery:
    def __init__(self, binary_path=""): self.binary_path = binary_path
    def parse_parameters(self, syscall): return []
    def assess_security_level(self, syscall): return "medium"

def recover_syscall_table(binary): return []
def analyze_syscall_sequence(seq): return SyscallAnalysisResult()
# Production syscall tables — 300+ entries per table. Placeholder stubs for now.
LINUX_X64_SYSCALLS = {i: f"syscall_{i}" for i in range(350)}
WINDOWS_SYSCALLS = {i: f"nt_{i}" for i in range(60)}
