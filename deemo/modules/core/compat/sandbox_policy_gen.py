"""沙箱策略生成 —— 系统调用推断、seccomp/AppArmor 策略生成。

根据二进制导入函数推断所需系统调用，识别危险调用，
生成最小权限的沙箱策略。
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class PolicyType(Enum):
    """沙箱策略类型。"""
    SECCOMP = "seccomp"
    APPARMOR = "apparmor"


@dataclass
class SyscallInfo:
    """单条系统调用信息。"""
    name: str = ""
    number: int = 0
    architecture: str = "x86_64"
    is_dangerous: bool = False
    category: str = ""


@dataclass
class SandboxPolicy:
    """生成的沙箱策略。"""
    policy_type: PolicyType = PolicyType.SECCOMP
    allowed_syscalls: List[SyscallInfo] = field(default_factory=list)
    denied_syscalls: List[SyscallInfo] = field(default_factory=list)
    policy_content: str = ""
    source_binary: str = ""
    risk_level: str = "low"


# x86_64 常用系统调用号
SYSCALL_MAP_X64 = {
    'read': 0, 'write': 1, 'open': 2, 'close': 3, 'stat': 4,
    'fstat': 5, 'lstat': 6, 'poll': 7, 'mmap': 9, 'mprotect': 10,
    'brk': 12, 'rt_sigaction': 13, 'readv': 19, 'writev': 20,
    'access': 21, 'pipe': 22, 'dup': 32, 'nanosleep': 35,
    'getpid': 39, 'sendfile': 40, 'socket': 41, 'connect': 42,
    'accept': 43, 'sendto': 44, 'recvfrom': 45, 'sendmsg': 46,
    'recvmsg': 47, 'shutdown': 48, 'bind': 49, 'listen': 50,
    'getsockname': 51, 'getpeername': 52, 'socketpair': 53,
    'setsockopt': 54, 'getsockopt': 55, 'clone': 56, 'fork': 57,
    'vfork': 58, 'execve': 59, 'exit': 60, 'wait4': 61,
    'kill': 62, 'uname': 63, 'fcntl': 72, 'fadvise64': 221,
    'exit_group': 231, 'set_tid_address': 218, 'futex': 202,
    'openat': 257, 'newfstatat': 262, 'unlink': 87, 'mkdir': 83,
    'chmod': 90, 'readlink': 89, 'ptrace': 101, 'mount': 165,
    'unshare': 272, 'setuid': 105, 'setgid': 106,
}

DANGEROUS_SYSCALLS = {'execve', 'ptrace', 'mount', 'unshare', 'setuid',
                      'setgid', 'reboot', 'init_module', 'delete_module',
                      'kexec_load', 'personality'}

FUNCTION_TO_SYSCALL = {
    'printf': 'write', 'puts': 'write', 'fprintf': 'write',
    'fopen': 'open', 'fclose': 'close', 'fread': 'read',
    'fwrite': 'write', 'read': 'read', 'write': 'write',
    'socket': 'socket', 'connect': 'connect', 'send': 'sendto',
    'recv': 'recvfrom', 'open': 'open', 'execve': 'execve',
    'system': 'execve', 'popen': 'execve', 'malloc': 'brk',
    'free': 'brk', 'mmap': 'mmap', 'exit': 'exit',
}

_PATH_TRAVERSAL = re.compile(r'(\.\.|[/\\]etc[/\\]|[/\\]proc[/\\])')


class SandboxPolicyGenerator:
    """沙箱策略生成器。"""

    def __init__(self):
        self.imports: List[str] = []

    def _generate_seccomp_policy(self, syscalls: List[SyscallInfo],
                                 default_deny: bool = False) -> str:
        """生成 seccomp-bpf 策略文本。"""
        lines = ['# seccomp policy', 'SCMP_ACT_ALLOW']
        for syscall in syscalls:
            lines.append(f'# {syscall.name} (nr={syscall.number})')
        if default_deny:
            lines.append('SCMP_ACT_KILL')
        return '\n'.join(lines)

    def _generate_apparmor_policy(self, syscalls: List[SyscallInfo],
                                  file_paths: List[str],
                                  network_permissions: Optional[Dict] = None) -> str:
        """生成 AppArmor profile 文本。"""
        lines = ['profile sandbox {', '  # generated policy']
        for path in file_paths:
            lines.append(f'  {path} r,')
        if network_permissions:
            for proto, ports in network_permissions.items():
                for port in ports:
                    lines.append(f'  network {proto} {port},')
        lines.append('}')
        return '\n'.join(lines)

    def _infer_syscalls_from_imports(self, imports: List[str]) -> List[SyscallInfo]:
        """按导入函数名推断系统调用集合。"""
        inferred = {}
        for func in imports:
            syscall_name = FUNCTION_TO_SYSCALL.get(func)
            if syscall_name and syscall_name not in inferred:
                number = self._get_syscall_number(syscall_name, 'x86_64')
                inferred[syscall_name] = SyscallInfo(
                    name=syscall_name,
                    number=number,
                    architecture='x86_64',
                    is_dangerous=syscall_name in DANGEROUS_SYSCALLS,
                    category='process' if syscall_name == 'execve' else 'io',
                )
        return list(inferred.values())

    def _get_syscall_number(self, name: str, architecture: str) -> int:
        """返回指定架构下的系统调用号。"""
        if architecture == 'x86_64':
            return SYSCALL_MAP_X64.get(name, -1)
        return -1

    def _identify_dangerous_syscalls(self, syscalls: List[SyscallInfo]) -> List[SyscallInfo]:
        """标记危险系统调用。"""
        dangerous = []
        for syscall in syscalls:
            if syscall.name in DANGEROUS_SYSCALLS:
                syscall.is_dangerous = True
                dangerous.append(syscall)
        return dangerous

    def _assess_risk_level(self, syscalls: List[SyscallInfo]) -> str:
        """按危险调用数量评估风险等级。"""
        dangerous_count = sum(1 for s in syscalls if s.is_dangerous)
        if dangerous_count >= 2:
            return 'high'
        if dangerous_count == 1:
            return 'medium'
        return 'low'

    def generate_policy(self, binary_path: str,
                        policy_type: str = 'seccomp') -> Dict:
        """为二进制生成沙箱策略。"""
        if _PATH_TRAVERSAL.search(binary_path):
            return {'error': '非法路径'}

        if not os.path.isfile(binary_path):
            return {'error': '文件不存在'}

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
        except OSError:
            return {'error': '文件读取失败'}

        self.imports = self._extract_imports(data)
        syscalls = self._infer_syscalls_from_imports(self.imports)
        self._identify_dangerous_syscalls(syscalls)

        if policy_type not in ('seccomp', 'apparmor'):
            policy_type = 'seccomp'

        if policy_type == 'apparmor':
            content = self._generate_apparmor_policy(syscalls, file_paths=[])
        else:
            content = self._generate_seccomp_policy(syscalls)

        policy = SandboxPolicy(
            policy_type=PolicyType(policy_type),
            allowed_syscalls=syscalls,
            denied_syscalls=[s for s in syscalls if s.is_dangerous],
            policy_content=content,
            source_binary=binary_path,
            risk_level=self._assess_risk_level(syscalls),
        )
        return policy.to_dict() if hasattr(policy, 'to_dict') else {
            'policy_type': policy.policy_type.value,
            'allowed_syscalls': [s.name for s in policy.allowed_syscalls],
            'denied_syscalls': [s.name for s in policy.denied_syscalls],
            'risk_level': policy.risk_level,
        }

    def _extract_imports(self, data: bytes) -> List[str]:
        """提取二进制中的常见库函数符号。"""
        imports = []
        for token in (b'printf', b'malloc', b'free', b'fopen', b'fclose',
                      b'fread', b'fwrite', b'read', b'write', b'socket',
                      b'connect', b'send', b'recv', b'open', b'execve',
                      b'system', b'mmap', b'exit'):
            if token in data:
                imports.append(token.decode())
        return imports

    def _save_policy(self, policy: SandboxPolicy, path: str) -> str:
        """将策略写入文件。"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(policy.policy_content)
        return path


def generate_sandbox_policy(binary_path: str,
                            policy_type: str = 'seccomp') -> Dict:
    """便捷入口: 生成沙箱策略。"""
    return SandboxPolicyGenerator().generate_policy(binary_path, policy_type)
