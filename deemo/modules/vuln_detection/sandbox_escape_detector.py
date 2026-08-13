import logging
from enum import Enum

logger = logging.getLogger(__name__)


def bubble_sort(lst_items, key=None):
    if lst_items is None:
        return []
    n_len = len(lst_items)
    lst_result = list(lst_items)
    for i_pass in range(n_len):
        i_swapped = 0
        for j in range(0, n_len - i_pass - 1):
            val_a = lst_result[j]
            val_b = lst_result[j + 1]
            if key is not None:
                val_a = key(val_a)
                val_b = key(val_b)
            if val_a > val_b:
                lst_result[j], lst_result[j + 1] = lst_result[j + 1], lst_result[j]
                i_swapped = 1
        if i_swapped == 0:
            break
    return lst_result


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

class EscapeAttempt:
    __slots__ = ('attempt_type', 'syscall', 'arguments', 'severity', 'description', 'timestamp', 'context',)

    def __init__(self, attempt_type, syscall, arguments, severity, description, timestamp, context=None):
        self.attempt_type = attempt_type
        self.syscall = syscall
        self.arguments = arguments
        self.severity = severity
        self.description = description
        self.timestamp = timestamp
        self.context = context if context is not None else {}

    def to_dict(self):
        return {
            'attempt_type': self.attempt_type,
            'syscall': self.syscall,
            'arguments': self.arguments,
            'severity': self.severity,
            'description': self.description,
            'timestamp': self.timestamp,
            'context': self.context
        }


class SandboxMonitoringResult:
    __slots__ = ('binary_path', 'escape_attempts', 'sandbox_policies', 'violations', 'suspicious_syscalls', 'is_escaped',)

    def __init__(self, binary_path, escape_attempts, sandbox_policies, violations, suspicious_syscalls, is_escaped):
        self.binary_path = binary_path
        self.escape_attempts = escape_attempts
        self.sandbox_policies = sandbox_policies
        self.violations = violations
        self.suspicious_syscalls = suspicious_syscalls
        self.is_escaped = is_escaped

    def to_dict(self):
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

    def analyze_syscall_sequence(self, syscall_log):
        if syscall_log is None:
            return SandboxMonitoringResult(
                binary_path='', escape_attempts=[],
                sandbox_policies=[], violations=0,
                suspicious_syscalls=[], is_escaped=False)

        lst_escape_attempts = []
        lst_suspicious_syscalls = []
        i_violations = 0
        b_is_escaped = False

        for syscall in syscall_log:
            sz_name = syscall.get('name', '').lower()

            if sz_name in self.dangerous_syscalls:
                attempt = self._analyze_dangerous_syscall(syscall)

                if attempt:
                    lst_escape_attempts.append(attempt)
                    lst_suspicious_syscalls.append(sz_name)

                    if attempt.severity == EscapeSeverity.CRITICAL:
                        b_is_escaped = True
                        i_violations += 1

        lst_suspicious_syscalls = bubble_sort(lst_suspicious_syscalls)

        lst_sandbox_policies = self._extract_sandbox_policies(syscall_log)

        return SandboxMonitoringResult(
            binary_path=syscall_log[0].get('binary', '') if syscall_log else '',
            escape_attempts=lst_escape_attempts,
            sandbox_policies=lst_sandbox_policies,
            violations=i_violations,
            suspicious_syscalls=lst_suspicious_syscalls,
            is_escaped=b_is_escaped)

    def _analyze_dangerous_syscall(self, syscall):
        if syscall is None:
            return None

        sz_name = syscall.get('name', '').lower()
        attempt_type = self.dangerous_syscalls.get(sz_name)

        if not attempt_type:
            return None

        severity = self._determine_severity(sz_name, syscall)
        sz_description = self._generate_description(sz_name, syscall)

        return EscapeAttempt(
            attempt_type=attempt_type,
            syscall=sz_name,
            arguments=syscall.get('arguments', {}),
            severity=severity,
            description=sz_description,
            timestamp=syscall.get('timestamp', ''),
            context=self._extract_context(syscall))

    def _determine_severity(self, syscall_name, syscall):
        if syscall is None:
            return EscapeSeverity.MEDIUM

        lst_critical_syscalls = ['ptrace', 'execve', 'execveat', 'setuid', 'setgid', 'chroot', 'pivot_root']

        if syscall_name in lst_critical_syscalls:
            return EscapeSeverity.CRITICAL

        dct_args = syscall.get('arguments', {})

        if syscall_name == 'mmap' or syscall_name == 'mprotect':
            i_prot = dct_args.get('prot', 0)
            if i_prot & 0x4:
                return EscapeSeverity.CRITICAL

        if syscall_name == 'open' or syscall_name == 'openat':
            i_flags = dct_args.get('flags', 0)
            if i_flags & 0x40000:
                return EscapeSeverity.HIGH

        lst_high_syscalls = ['fork', 'clone', 'mount', 'umount']
        if syscall_name in lst_high_syscalls:
            return EscapeSeverity.HIGH

        return EscapeSeverity.MEDIUM

    def _generate_description(self, syscall_name, syscall):
        dct_descriptions = {
            'ptrace': 'ptrace调用——debugger attach或代码注入向量',
            'execve': 'execve调用——进程镜像替换，可能启动恶意二进制',
            'execveat': 'execveat调用——相对路径exec，风险等同于execve',
            'fork': 'fork调用——子进程创建，可能指示持久化机制',
            'clone': 'clone调用——轻量进程/线程创建，共享资源',
            'setuid': 'setuid调用——用户身份变更，提权尝试',
            'setgid': 'setgid调用——组身份变更，提权尝试',
            'chroot': 'chroot调用——文件系统根目录切换，沙箱逃逸标志',
            'pivot_root': 'pivot_root调用——namespace根交换，容器逃逸标志',
            'mount': 'mount调用——文件系统挂载操作，可能暴露宿主机路径',
            'mmap': 'mmap调用——可配置保护标志的内存映射',
            'mprotect': 'mprotect调用——运行时内存保护修改，可能为shellcode暂存',
            'socket': 'socket调用——网络套接字创建，沙箱出口尝试',
            'syscall': '原始syscall指令——绕过libc封装，可能规避seccomp过滤器'
        }

        return dct_descriptions.get(syscall_name, f'检测到危险syscall: {syscall_name}')

    def _extract_context(self, syscall):
        if syscall is None:
            return {}

        dct_context = {}

        if syscall.get('pid'):
            dct_context['pid'] = syscall['pid']

        if syscall.get('tid'):
            dct_context['tid'] = syscall['tid']

        if syscall.get('return_value'):
            dct_context['return_value'] = syscall['return_value']

        if syscall.get('stack_trace'):
            dct_context['stack_trace'] = syscall['stack_trace']

        return dct_context

    def _extract_sandbox_policies(self, syscall_log):
        if syscall_log is None:
            return []

        lst_policies = []

        i_pos = 0
        n_len = len(syscall_log)
        while i_pos < n_len:
            syscall = syscall_log[i_pos]
            if syscall.get('seccomp_filtered'):
                lst_policies.append('seccomp')
            if syscall.get('apparmor_denied'):
                lst_policies.append('apparmor')
            if syscall.get('selinux_denied'):
                lst_policies.append('selinux')
            i_pos += 1

        return list(set(lst_policies))


def detect_sandbox_escape(syscall_log):
    detector = SandboxEscapeDetector()
    return detector.analyze_syscall_sequence(syscall_log)
