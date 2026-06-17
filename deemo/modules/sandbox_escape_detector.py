import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class EscapeAttemptType(Enum):
    SYSCALL_HOOK = "syscall_hook"
    PTRACE_ATTACK = "ptrace_attack"
    MEMORY_EXEC = "memory_exec"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    PROCESS_CREATION = "process_creation"
    CAPABILITY_ESCALATION = "capability_escalation"
    NAMESPACE_ESCAPE = "namespace_escape"
    UNKNOWN = "unknown"


class EscapeSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EscapeAttempt:
    attempt_type: EscapeAttemptType
    syscall: Optional[str]
    arguments: Dict[str, Any]
    severity: EscapeSeverity
    description: str
    timestamp: str
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'attempt_type': self.attempt_type.value,
            'syscall': self.syscall,
            'arguments': self.arguments,
            'severity': self.severity.value,
            'description': self.description,
            'timestamp': self.timestamp,
            'context': self.context
        }


@dataclass
class SandboxMonitoringResult:
    binary_path: str
    escape_attempts: List[EscapeAttempt]
    sandbox_policies: List[str]
    violations: int
    suspicious_syscalls: List[str]
    is_escaped: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'escape_attempts': [e.to_dict() for e in self.escape_attempts],
            'sandbox_policies': self.sandbox_policies,
            'violations': self.violations,
            'suspicious_syscalls': self.suspicious_syscalls,
            'is_escaped': self.is_escaped
        }


class SandboxEscapeDetector:
    
    def __init__(self):
        self.dangerous_syscalls = {
            'ptrace': EscapeAttemptType.PTRACE_ATTACK,
            'execve': EscapeAttemptType.PROCESS_CREATION,
            'execveat': EscapeAttemptType.PROCESS_CREATION,
            'fork': EscapeAttemptType.PROCESS_CREATION,
            'clone': EscapeAttemptType.PROCESS_CREATION,
            'setuid': EscapeAttemptType.CAPABILITY_ESCALATION,
            'setgid': EscapeAttemptType.CAPABILITY_ESCALATION,
            'setgroups': EscapeAttemptType.CAPABILITY_ESCALATION,
            'chroot': EscapeAttemptType.NAMESPACE_ESCAPE,
            'pivot_root': EscapeAttemptType.NAMESPACE_ESCAPE,
            'mount': EscapeAttemptType.FILE_SYSTEM,
            'umount': EscapeAttemptType.FILE_SYSTEM,
            'open': EscapeAttemptType.FILE_SYSTEM,
            'openat': EscapeAttemptType.FILE_SYSTEM,
            'socket': EscapeAttemptType.NETWORK,
            'socketpair': EscapeAttemptType.NETWORK,
            'connect': EscapeAttemptType.NETWORK,
            'bind': EscapeAttemptType.NETWORK,
            'listen': EscapeAttemptType.NETWORK,
            'sendto': EscapeAttemptType.NETWORK,
            'recvfrom': EscapeAttemptType.NETWORK,
            'mmap': EscapeAttemptType.MEMORY_EXEC,
            'mprotect': EscapeAttemptType.MEMORY_EXEC,
            'mremap': EscapeAttemptType.MEMORY_EXEC,
            'syscall': EscapeAttemptType.SYSCALL_HOOK,
            'sysenter': EscapeAttemptType.SYSCALL_HOOK,
            'int': EscapeAttemptType.SYSCALL_HOOK
        }
        
        self.syscall_arguments_to_check = {
            'mmap': ['prot'],
            'mprotect': ['prot'],
            'open': ['flags'],
            'openat': ['flags'],
            'clone': ['flags'],
            'socket': ['domain', 'type']
        }
    
    def analyze_syscall_sequence(self, syscall_log: List[Dict[str, Any]]) -> SandboxMonitoringResult:
        escape_attempts = []
        suspicious_syscalls = []
        violations = 0
        is_escaped = False
        
        for syscall in syscall_log:
            name = syscall.get('name', '').lower()
            
            if name in self.dangerous_syscalls:
                attempt = self._analyze_dangerous_syscall(syscall)
                
                if attempt:
                    escape_attempts.append(attempt)
                    suspicious_syscalls.append(name)
                    
                    if attempt.severity == EscapeSeverity.CRITICAL:
                        is_escaped = True
                        violations += 1
        
        sandbox_policies = self._extract_sandbox_policies(syscall_log)
        
        return SandboxMonitoringResult(
            binary_path=syscall_log[0].get('binary', '') if syscall_log else '',
            escape_attempts=escape_attempts,
            sandbox_policies=sandbox_policies,
            violations=violations,
            suspicious_syscalls=suspicious_syscalls,
            is_escaped=is_escaped)
        

    
    def _analyze_dangerous_syscall(self, syscall: Dict[str, Any]) -> Optional[EscapeAttempt]:
        name = syscall.get('name', '').lower()
        attempt_type = self.dangerous_syscalls.get(name)
        
        if not attempt_type:
            return None
        
        severity = self._determine_severity(name, syscall)
        description = self._generate_description(name, syscall)
        
        return EscapeAttempt(
            attempt_type=attempt_type,
            syscall=name,
            arguments=syscall.get('arguments', {}),
            severity=severity,
            description=description,
            timestamp=syscall.get('timestamp', ''),
            context=self._extract_context(syscall))
        

    
    def _determine_severity(self, syscall_name: str, syscall: Dict[str, Any]) -> EscapeSeverity:
        critical_syscalls = ['ptrace', 'execve', 'execveat', 'setuid', 'setgid', 'chroot', 'pivot_root']
        
        if syscall_name in critical_syscalls:
            return EscapeSeverity.CRITICAL
        
        args = syscall.get('arguments', {})
        
        if syscall_name == 'mmap' or syscall_name == 'mprotect':
            prot = args.get('prot', 0)
            if prot & 0x4:
                return EscapeSeverity.CRITICAL
        
        if syscall_name == 'open' or syscall_name == 'openat':
            flags = args.get('flags', 0)
            if flags & 0x40000:
                return EscapeSeverity.HIGH
        
        high_syscalls = ['fork', 'clone', 'mount', 'umount']
        if syscall_name in high_syscalls:
            return EscapeSeverity.HIGH
        
        return EscapeSeverity.MEDIUM
    
    def _generate_description(self, syscall_name: str, syscall: Dict[str, Any]) -> str:
        descriptions = {
            'ptrace': '检测到 ptrace 调用，可能尝试调试或注入代码',
            'execve': '检测到 execve 调用，可能尝试执行恶意程序',
            'execveat': '检测到 execveat 调用，可能尝试执行恶意程序',
            'fork': '检测到 fork 调用，可能尝试创建子进程',
            'clone': '检测到 clone 调用，可能尝试创建新进程',
            'setuid': '检测到 setuid 调用，可能尝试提升权限',
            'setgid': '检测到 setgid 调用，可能尝试提升权限',
            'chroot': '检测到 chroot 调用，可能尝试突破沙箱',
            'pivot_root': '检测到 pivot_root 调用，可能尝试突破命名空间',
            'mount': '检测到 mount 调用，可能尝试挂载文件系统',
            'mmap': '检测到 mmap 调用，可能尝试映射可执行内存',
            'mprotect': '检测到 mprotect 调用，可能尝试修改内存保护',
            'socket': '检测到 socket 调用，可能尝试建立网络连接',
            'syscall': '检测到直接 syscall 调用，可能尝试绕过钩子'
        }
        
        return descriptions.get(syscall_name, f"检测到危险系统调用: {syscall_name}")
    
    def _extract_context(self, syscall: Dict[str, Any]) -> Dict[str, Any]:
        context = {}
        
        if syscall.get('pid'):
            context['pid'] = syscall['pid']
        
        if syscall.get('tid'):
            context['tid'] = syscall['tid']
        
        if syscall.get('return_value'):
            context['return_value'] = syscall['return_value']
        
        if syscall.get('stack_trace'):
            context['stack_trace'] = syscall['stack_trace']
        
        return context
    
    def _extract_sandbox_policies(self, syscall_log: List[Dict[str, Any]]) -> List[str]:
        policies = []
        
        for syscall in syscall_log:
            if syscall.get('seccomp_filtered'):
                policies.append('seccomp')
            if syscall.get('apparmor_denied'):
                policies.append('apparmor')
            if syscall.get('selinux_denied'):
                policies.append('selinux')
        
        return list(set(policies



def detect_sandbox_escape(syscall_log: List[Dict[str, Any]]) -> SandboxMonitoringResult:
    detector = SandboxEscapeDetector()
    return detector.analyze_sys))