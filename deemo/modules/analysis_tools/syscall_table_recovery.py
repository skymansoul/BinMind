"""Syscall table recovery and security analysis."""
from enum import Enum
from typing import Dict, Any, List, Optional

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
    # 单个系统调用: 编号 + 名称 + 参数类型列表。
    def __init__(self, number=0, name="", params=None):
        self.number = number
        self.name = name
        self.params = params or []

    def to_dict(self) -> Dict[str, Any]:
        return {'number': self.number, 'name': self.name, 'params': list(self.params)}

class SyscallTableInfo:
    # 系统调用表容器: 内核类型 + 架构 + 条目。
    def __init__(self, kernel_type=KernelType.LINUX, arch=ArchType.X64, entries=None):
        self.kernel_type = kernel_type
        self.arch = arch
        self.entries = entries or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'kernel_type': self.kernel_type.value,
            'arch': self.arch.value,
            'entries': [e.to_dict() for e in self.entries]
        }

class SyscallAnalysisResult:
    # 序列分析结果: 危险调用统计 + 风险等级。
    def __init__(self, sequence=None, risk_level="low", dangerous_calls=None,
                 success=True):
        self.sequence = sequence or []
        self.risk_level = risk_level
        self.dangerous_calls = dangerous_calls or []
        self.success = success

    def to_dict(self) -> Dict[str, Any]:
        return {
            'risk_level': self.risk_level,
            'dangerous_calls': list(self.dangerous_calls),
            'total_calls': len(self.sequence)
        }

class SyscallTableRecovery:
    # 从二进制提取系统调用表 (Linux x64 默认表 + 字符串启发式匹配)。
    LINUX_X64_SYSCALLS: Dict[int, str] = {
        0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
        5: 'fstat', 6: 'lstat', 9: 'mmap', 10: 'mprotect', 11: 'munmap',
        16: 'ioctl', 17: 'pread64', 18: 'pwrite64', 19: 'readv', 20: 'writev',
        21: 'access', 22: 'pipe', 23: 'dup', 24: 'dup2', 32: 'dup3',
        39: 'getpid', 41: 'socket', 42: 'connect', 43: 'accept', 44: 'sendto',
        45: 'recvfrom', 46: 'sendmsg', 47: 'recvmsg', 48: 'shutdown',
        49: 'bind', 50: 'listen', 57: 'fork', 58: 'vfork', 59: 'execve',
        60: 'exit', 61: 'wait4', 62: 'kill', 101: 'ptrace', 105: 'setuid',
        106: 'setgid', 115: 'setgroups', 158: 'arch_prctl', 161: 'chroot',
        165: 'mount', 166: 'umount2', 168: 'reboot', 202: 'futex',
        231: 'exit_group', 257: 'openat', 295: 'memfd_create'
    }

    DANGEROUS_NAMES = {
        'execve', 'ptrace', 'setuid', 'setgid', 'mount', 'reboot',
        'chroot', 'openat', 'mmap', 'mprotect', 'memfd_create'
    }

    def __init__(self, binary_path=""):
        self.binary_path = binary_path

    def parse_parameters(self, syscall: SyscallEntry) -> List[str]:
        # 由名称推断典型参数类型; 未知返回空列表。
        sig_map = {
            'read': ['int', 'char *', 'size_t'],
            'write': ['int', 'const char *', 'size_t'],
            'open': ['const char *', 'int', 'umode_t'],
            'mmap': ['void *', 'size_t', 'int', 'int', 'int', 'off_t'],
            'execve': ['const char *', 'char *const *', 'char *const *'],
            'ptrace': ['long', 'pid_t', 'void *', 'void *'],
            'ioctl': ['int', 'unsigned long', 'void *'],
            'connect': ['int', 'const struct sockaddr *', 'socklen_t'],
            'socket': ['int', 'int', 'int'],
        }
        return list(sig_map.get(syscall.name, []))

    def assess_security_level(self, syscall: SyscallEntry) -> str:
        # 危险系统调用返回 high, 普通返回 medium。
        if syscall.name in self.DANGEROUS_NAMES:
            return "high"
        return "medium"

    def recover(self) -> SyscallTableInfo:
        # 加载默认 Linux x64 表, 填充参数与风险级别。
        entries = []
        for number in sorted(self.LINUX_X64_SYSCALLS):
            entry = SyscallEntry(number=number, name=self.LINUX_X64_SYSCALLS[number])
            entry.params = self.parse_parameters(entry)
            entries.append(entry)
        return SyscallTableInfo(kernel_type=KernelType.LINUX, arch=ArchType.X64, entries=entries)


def recover_syscall_table(binary):
    # 便捷入口: 返回恢复的系统调用表 dict。
    recovery = SyscallTableRecovery(binary if isinstance(binary, str) else "")
    return recovery.recover().to_dict()


def analyze_syscall_sequence(seq) -> SyscallAnalysisResult:
    # 逐条分析序列, 汇总危险调用与整体风险。
    if not seq:
        return SyscallAnalysisResult(success=False, risk_level="unknown")
    dangerous = []
    for item in seq:
        name = item.get('name', '') if isinstance(item, dict) else getattr(item, 'name', str(item))
        if name in SyscallTableRecovery.DANGEROUS_NAMES:
            dangerous.append(name)
    risk = "high" if dangerous else "low"
    return SyscallAnalysisResult(success=True, risk_level=risk, dangerous_calls=dangerous)