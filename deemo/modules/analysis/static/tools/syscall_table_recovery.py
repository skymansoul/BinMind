#!/usr/bin/env python3
"""系统调用表恢复与安全分析。

从二进制中恢复系统调用表条目，解析参数原型，评估系统调用的
安全等级，并对一次执行序列做风险汇总。
"""
import re
from enum import Enum
from typing import Any, Dict, List, Optional


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
    """系统调用表条目。"""

    def __init__(self, number=0, name="", address=0, handler_name="",
                 params=None, security_level="medium"):
        self.number = number
        self.name = name
        self.address = address
        self.handler_name = handler_name
        self.params = params or []
        self.security_level = security_level


class SyscallTableInfo:
    def __init__(self, kernel_type: KernelType = KernelType.LINUX,
                 arch: ArchType = ArchType.X64, entries: List[SyscallEntry] = None):
        self.kernel_type = kernel_type
        self.arch = arch
        self.entries = entries or []


class SyscallAnalysisResult:
    def __init__(self):
        self.total_syscalls = 0
        self.potential_hooks = 0
        self.security_findings: List[Dict[str, Any]] = []
        self.dangerous_syscalls: List[SyscallEntry] = []
        self.risk_assessment: Dict[str, Any] = {}


class SyscallTableRecovery:
    """系统调用表恢复器。"""

    _CRITICAL = {
        'execve', 'execveat', 'setuid', 'setgid', 'setresuid', 'setresgid',
        'setreuid', 'setregid', 'ptrace', 'process_vm_writev',
        'create_module', 'init_module', 'finit_module', 'delete_module',
        'reboot', 'kexec_load', 'kexec_file_load', 'perf_event_open',
        'bpf', 'userfaultfd', 'keyctl', 'add_key', 'request_key',
    }
    _HIGH = {
        'socket', 'connect', 'accept', 'accept4', 'bind', 'listen',
        'open', 'openat', 'creat', 'truncate', 'ftruncate',
        'mprotect', 'mmap', 'mremap', 'ioctl', 'sendfile',
        'write', 'writev', 'pwrite64', 'readlink', 'readlinkat',
        'unlink', 'unlinkat', 'rmdir', 'mount', 'umount2',
        'pivot_root', 'chroot', 'chmod', 'chown', 'rename',
        'kill', 'tgkill', 'tkill', 'rt_sigaction',
    }
    _LOW = {
        'read', 'getpid', 'getppid', 'getuid', 'geteuid', 'getgid',
        'getegid', 'getcwd', 'clock_gettime', 'gettimeofday', 'time',
        'nanosleep', 'brk', 'munmap', 'exit', 'exit_group',
    }

    def __init__(self, binary_path=""):
        self.binary_path = binary_path
        self._kernel_type = KernelType.LINUX
        self.syscall_categories = {
            'dangerous': sorted(self._CRITICAL),
            'high_risk': sorted(self._HIGH),
            'low_risk': sorted(self._LOW),
        }

    def detect_kernel(self) -> KernelType:
        """通过二进制中嵌入的字符串检测目标内核类型"""
        try:
            with open(self.binary_path, 'rb') as fh:
                data = fh.read(4096)
            if b'Linux' in data or b'linux_' in data:
                return KernelType.LINUX
            if b'NT' in data or b'ntoskrnl' in data:
                return KernelType.WINDOWS
            if b'macOS' in data or b'xnu' in data:
                return KernelType.MACOS
        except Exception:
            pass
        return KernelType.LINUX

    def _parse_parameters(self, prototype: str) -> List[Dict[str, Any]]:
        """从函数原型解析参数列表。"""
        params = []
        m = re.search(r'\((.*?)\)', prototype, re.DOTALL)
        if not m:
            return params
        for part in m.group(1).split(','):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if len(tokens) < 2:
                continue
            type_tokens = list(tokens[:-1])
            name = tokens[-1].rstrip(';')
            # 指针可附着于类型 (`void *buf`) 或名字 (`void* buf` / `*buf`)
            is_pointer = any('*' in t for t in type_tokens)
            if name.startswith('*'):
                is_pointer = True
                type_tokens.append('*')
                name = name.lstrip('*')
            params.append({
                'name': name,
                'type': ' '.join(type_tokens),
                'is_pointer': is_pointer,
            })
        return params

    def _assess_security_level(self, syscall: str) -> str:
        """评估单个系统调用的安全等级。"""
        if syscall in self._CRITICAL:
            return 'critical'
        if syscall in self._HIGH:
            return 'high'
        if syscall in self._LOW:
            return 'low'
        return 'medium'

    def parse_parameters(self, syscall):
        return self._parse_parameters(syscall)

    def assess_security_level(self, syscall):
        return self._assess_security_level(syscall)

    def recover_table(self, arch: ArchType = ArchType.X64) -> List[SyscallEntry]:
        """根据架构恢复系统调用表条目, 从静态表中按 syscall 号匹配名称"""
        kernel = self.detect_kernel()
        entries: List[SyscallEntry] = []
        if kernel == KernelType.LINUX:
            table = LINUX_X64_SYSCALLS if arch in (ArchType.X64, ArchType.ARM64) else {}
            for number, entry in sorted(table.items()):
                name = entry[0] if isinstance(entry, tuple) else entry
                entries.append(SyscallEntry(
                    number=number,
                    name=name,
                    handler_name=f'sys_{name}',
                    security_level=self._assess_security_level(name),
                ))
        elif kernel == KernelType.WINDOWS:
            entries.append(SyscallEntry(
                number=0, name='NtCreateFile', handler_name='NtCreateFile',
                security_level='high'))
        return entries

    def analyze_syscall_usage(self, syscall_numbers: List[int]) -> SyscallAnalysisResult:
        """分析一次系统调用执行序列的安全风险。"""
        result = SyscallAnalysisResult()
        result.total_syscalls = len(syscall_numbers)
        for number in syscall_numbers:
            entry = LINUX_X64_SYSCALLS.get(number)
            if entry is None:
                continue
            name = entry[0] if isinstance(entry, tuple) else entry
            syscall_entry = SyscallEntry(
                number=number, name=name,
                handler_name=f'sys_{name}',
                security_level=self._assess_security_level(name))
            if syscall_entry.security_level in ('critical', 'high'):
                result.dangerous_syscalls.append(syscall_entry)
            result.security_findings.append({
                'number': number, 'name': name,
                'level': syscall_entry.security_level,
            })
        result.risk_assessment = {
            'total_syscalls_used': result.total_syscalls,
            'dangerous_count': len(result.dangerous_syscalls),
            'max_level': max(
                (f.get('level') for f in result.security_findings),
                default='low'),
        }
        result.potential_hooks = len(result.dangerous_syscalls)
        return result


def recover_syscall_table(binary):
    recovery = SyscallTableRecovery(binary) if isinstance(binary, str) else SyscallTableRecovery("")
    return recovery.recover_table()


def analyze_syscall_sequence(seq):
    return SyscallTableRecovery("").analyze_syscall_usage(seq)

# Production 系统调用 tables , 300+ entries per table
LINUX_X64_SYSCALLS = {
    0: ('read',), 1: ('write',), 2: ('open',), 3: ('close',), 4: ('stat',),
    5: ('fstat',), 6: ('lstat',), 7: ('poll',), 8: ('lseek',), 9: ('mmap',),
    10: ('mprotect',), 11: ('munmap',), 12: ('brk',), 13: ('rt_sigaction',),
    14: ('rt_sigprocmask',), 15: ('rt_sigreturn',), 16: ('ioctl',), 17: ('pread64',),
    18: ('pwrite64',), 19: ('readv',), 20: ('writev',), 21: ('access',), 22: ('pipe',),
    23: ('select',), 24: ('sched_yield',), 25: ('mremap',), 26: ('msync',),
    27: ('mincore',), 28: ('madvise',), 29: ('shmget',), 30: ('shmat',),
    31: ('shmctl',), 32: ('dup',), 33: ('dup2',), 34: ('pause',), 35: ('nanosleep',),
    37: ('alarm',), 38: ('setitimer',), 39: ('getpid',), 40: ('sendfile',),
    41: ('socket',), 42: ('connect',), 43: ('accept',), 44: ('sendto',),
    45: ('recvfrom',), 46: ('sendmsg',), 47: ('recvmsg',), 48: ('shutdown',),
    49: ('bind',), 50: ('listen',), 51: ('getsockname',), 52: ('getpeername',),
    53: ('socketpair',), 54: ('setsockopt',), 55: ('getsockopt',), 56: ('clone',),
    57: ('fork',), 58: ('vfork',), 59: ('execve',), 60: ('exit',), 61: ('wait4',),
    62: ('kill',), 63: ('uname',), 64: ('semget',), 65: ('semop',), 66: ('semctl',),
    67: ('shmdt',), 68: ('msgget',), 69: ('msgsnd',), 70: ('msgrcv',), 71: ('msgctl',),
    72: ('fcntl',), 73: ('flock',), 74: ('fsync',), 75: ('fdatasync',),
    76: ('truncate',), 77: ('ftruncate',), 78: ('getdents',), 79: ('getcwd',),
    80: ('chdir',), 81: ('fchdir',), 82: ('rename',), 83: ('mkdir',),
    84: ('rmdir',), 85: ('creat',), 86: ('link',), 87: ('unlink',), 88: ('symlink',),
    89: ('readlink',), 90: ('chmod',), 91: ('fchmod',), 92: ('chown',),
    93: ('fchown',), 94: ('lchown',), 95: ('umask',), 96: ('gettimeofday',),
    97: ('getrlimit',), 98: ('getrusage',), 99: ('sysinfo',), 100: ('times',),
    101: ('ptrace',), 102: ('getuid',), 103: ('syslog',), 104: ('getgid',),
    105: ('setuid',), 106: ('setgid',), 107: ('geteuid',), 108: ('getegid',),
    109: ('setpgid',), 110: ('getppid',), 111: ('getpgrp',), 112: ('setsid',),
    113: ('setreuid',), 114: ('setregid',), 115: ('getgroups',), 116: ('setgroups',),
    117: ('setresuid',), 118: ('getresuid',), 119: ('setresgid',), 120: ('getresgid',),
    121: ('getpgid',), 122: ('setfsuid',), 123: ('setfsgid',), 124: ('getsid',),
    125: ('capget',), 126: ('capset',), 127: ('rt_sigpending',),
    128: ('rt_sigtimedwait',), 129: ('rt_sigqueueinfo',), 130: ('rt_sigsuspend',),
    131: ('sigaltstack',), 132: ('utime',), 133: ('mknod',), 135: ('personality',),
    136: ('ustat',), 137: ('statfs',), 138: ('fstatfs',), 139: ('sysfs',),
    140: ('getpriority',), 141: ('setpriority',), 142: ('sched_setparam',),
    143: ('sched_getparam',), 144: ('sched_setscheduler',),
    145: ('sched_getscheduler',), 146: ('sched_get_priority_max',),
    147: ('sched_get_priority_min',), 148: ('sched_rr_get_interval',),
    149: ('mlock',), 150: ('munlock',), 151: ('mlockall',), 152: ('munlockall',),
    153: ('vhangup',), 154: ('modify_ldt',), 155: ('pivot_root',), 156: ('_sysctl',),
    157: ('prctl',), 158: ('arch_prctl',), 159: ('adjtimex',), 160: ('setrlimit',),
    161: ('chroot',), 162: ('sync',), 163: ('acct',), 164: ('settimeofday',),
    165: ('mount',), 166: ('umount2',), 167: ('swapon',), 168: ('swapoff',),
    169: ('reboot',), 170: ('sethostname',), 171: ('setdomainname',),
    172: ('iopl',), 173: ('ioperm',), 174: ('create_module',), 175: ('init_module',),
    176: ('delete_module',), 177: ('get_kernel_syms',), 178: ('query_module',),
    179: ('quotactl',), 180: ('nfsservctl',), 181: ('getpmsg',), 182: ('putpmsg',),
    183: ('afs_syscall',), 184: ('tuxcall',), 185: ('security',), 186: ('gettid',),
    187: ('readahead',), 188: ('setxattr',), 189: ('lsetxattr',), 190: ('fsetxattr',),
    191: ('getxattr',), 192: ('lgetxattr',), 193: ('fgetxattr',), 194: ('listxattr',),
    195: ('llistxattr',), 196: ('flistxattr',), 197: ('removexattr',),
    198: ('lremovexattr',), 199: ('fremovexattr',), 200: ('tkill',),
    201: ('time',), 202: ('futex',), 203: ('sched_setaffinity',),
    204: ('sched_getaffinity',), 205: ('set_thread_area',), 206: ('io_setup',),
    207: ('io_destroy',), 208: ('io_getevents',), 209: ('io_submit',),
    210: ('io_cancel',), 211: ('get_thread_area',), 212: ('lookup_dcookie',),
    213: ('epoll_create',), 214: ('epoll_ctl_old',), 215: ('epoll_wait_old',),
    216: ('remap_file_pages',), 217: ('getdents64',), 218: ('set_tid_address',),
    219: ('restart_syscall',), 220: ('semtimedop',), 221: ('fadvise64',),
    222: ('timer_create',), 223: ('timer_settime',), 224: ('timer_gettime',),
    225: ('timer_getoverrun',), 226: ('timer_delete',), 227: ('clock_settime',),
    228: ('clock_gettime',), 229: ('clock_getres',), 230: ('clock_nanosleep',),
    231: ('exit_group',), 232: ('epoll_wait',), 233: ('epoll_ctl',), 234: ('tgkill',),
    235: ('utimes',), 236: ('vserver',), 237: ('mbind',), 238: ('set_mempolicy',),
    239: ('get_mempolicy',), 240: ('mq_open',), 241: ('mq_unlink',), 242: ('mq_timedsend',),
    243: ('mq_timedreceive',), 244: ('mq_notify',), 245: ('mq_getsetattr',),
    246: ('kexec_load',), 247: ('waitid',), 248: ('add_key',), 249: ('request_key',),
    250: ('keyctl',), 251: ('ioprio_set',), 252: ('ioprio_get',), 253: ('inotify_init',),
    254: ('inotify_add_watch',), 255: ('inotify_rm_watch',), 256: ('migrate_pages',),
    257: ('openat',), 258: ('mkdirat',), 259: ('mknodat',), 260: ('fchownat',),
    261: ('futimesat',), 262: ('newfstatat',), 263: ('unlinkat',), 264: ('renameat',),
    265: ('linkat',), 266: ('symlinkat',), 267: ('readlinkat',), 268: ('fchmodat',),
    269: ('faccessat',), 270: ('pselect6',), 271: ('ppoll',), 272: ('unshare',),
    273: ('set_robust_list',), 274: ('get_robust_list',), 275: ('splice',),
    276: ('tee',), 277: ('sync_file_range',), 278: ('vmsplice',), 279: ('move_pages',),
    280: ('utimensat',), 281: ('epoll_pwait',), 282: ('signalfd',), 283: ('timerfd_create',),
    284: ('eventfd',), 285: ('fallocate',), 286: ('timerfd_settime',),
    287: ('timerfd_gettime',), 288: ('accept4',), 289: ('signalfd4',), 290: ('eventfd2',),
    291: ('epoll_create1',), 292: ('dup3',), 293: ('pipe2',), 294: ('inotify_init1',),
    295: ('preadv',), 296: ('pwritev',), 297: ('rt_tgsigqueueinfo',), 298: ('perf_event_open',),
    299: ('recvmmsg',), 300: ('fanotify_init',), 301: ('fanotify_mark',),
    302: ('prlimit64',), 303: ('name_to_handle_at',), 304: ('open_by_handle_at',),
    305: ('clock_adjtime',), 306: ('syncfs',), 307: ('sendmmsg',), 308: ('setns',),
    309: ('getcpu',), 310: ('process_vm_readv',), 311: ('process_vm_writev',),
    312: ('kcmp',), 313: ('finit_module',), 314: ('sched_setattr',),
    315: ('sched_getattr',), 316: ('renameat2',), 317: ('seccomp',), 318: ('getrandom',),
    319: ('memfd_create',), 320: ('kexec_file_load',), 321: ('bpf',),
    322: ('execveat',), 323: ('userfaultfd',), 324: ('membarrier',), 325: ('mlock2',),
    326: ('copy_file_range',), 327: ('preadv2',), 328: ('pwritev2',), 329: ('pkey_mprotect',),
    330: ('pkey_alloc',), 331: ('pkey_free',), 332: ('statx',), 333: ('io_pgetevents',),
    334: ('rseq',), 424: ('pidfd_send_signal',), 425: ('io_uring_setup',),
    426: ('io_uring_enter',), 427: ('io_uring_register',), 428: ('open_tree',),
    429: ('move_mount',), 430: ('fsopen',), 431: ('fsconfig',), 432: ('fsmount',),
    433: ('fspick',), 434: ('pidfd_open',), 435: ('clone3',), 436: ('close_range',),
    437: ('openat2',), 438: ('pidfd_getfd',), 439: ('faccessat2',), 440: ('process_madvise',),
    441: ('epoll_pwait2',), 442: ('mount_setattr',), 443: ('quotactl_fd',),
    444: ('landlock_create_ruleset',), 445: ('landlock_add_rule',),
    446: ('landlock_restrict_self',), 447: ('memfd_secret',), 448: ('process_mrelease',),
    449: ('futex_waitv',), 450: ('set_mempolicy_home_node',),
}


# Windows NT 系统调用名 → 编号（x64 syscall index）
WINDOWS_SYSCALLS = {
    'NtCreateFile': 0x54,
    'NtOpenFile': 0x55,
    'NtClose': 0x0f,
    'NtReadFile': 0x06,
    'NtWriteFile': 0x08,
    'NtQueryInformationFile': 0x0a,
    'NtSetInformationFile': 0x0b,
    'NtQueryDirectoryFile': 0x0c,
    'NtCreateKey': 0x5c,
    'NtOpenKey': 0x5d,
    'NtDeleteKey': 0x5e,
    'NtQueryValueKey': 0x67,
    'NtSetValueKey': 0x68,
    'NtAllocateVirtualMemory': 0x18,
    'NtFreeVirtualMemory': 0x1e,
    'NtProtectVirtualMemory': 0x50,
    'NtCreateProcess': 0x66,
    'NtTerminateProcess': 0x2c,
    'NtCreateThread': 0x67,
    'NtTerminateThread': 0x53,
    'NtSuspendThread': 0x76,
    'NtResumeThread': 0x77,
    'NtOpenProcess': 0x26,
    'NtOpenThread': 0x27,
    'NtDuplicateObject': 0x28,
    'NtQuerySystemInformation': 0x36,
    'NtSetSystemInformation': 0x37,
    'NtCreateEvent': 0x40,
    'NtOpenEvent': 0x41,
    'NtSetEvent': 0x43,
    'NtResetEvent': 0x44,
    'NtWaitForSingleObject': 0x04,
    'NtCreateMutant': 0x46,
    'NtOpenMutant': 0x47,
    'NtCreateSemaphore': 0x48,
    'NtOpenSemaphore': 0x49,
    'NtCreateTimer': 0x69,
    'NtOpenTimer': 0x6a,
    'NtCreateKeyedEvent': 0x6c,
    'NtOpenKeyedEvent': 0x6d,
    'NtCreateSection': 0x4a,
    'NtOpenSection': 0x4b,
    'NtMapViewOfSection': 0x29,
    'NtUnmapViewOfSection': 0x2b,
    'NtQueryVirtualMemory': 0x23,
    'NtCreateIoCompletion': 0x7a,
    'NtOpenIoCompletion': 0x7b,
    'NtSetIoCompletion': 0x7c,
    'NtRemoveIoCompletion': 0x7d,
    'NtQueryIoCompletion': 0x7e,
    'NtCreateWaitCompletionPacket': 0x9e,
    'NtCreateToken': 0x9d,
    'NtDuplicateToken': 0x9c,
    'NtOpenProcessToken': 0x2a,
    'NtOpenProcessTokenEx': 0x2c,
    'NtAdjustPrivilegesToken': 0x30,
    'NtImpersonateClientOfThread': 0x31,
    'NtSetInformationThread': 0x0d,
    'NtQueryInformationThread': 0x0e,
    'NtSetInformationProcess': 0x22,
    'NtQueryInformationProcess': 0x19,
    'NtWriteVirtualMemory': 0x3a,
    'NtReadVirtualMemory': 0x3f,
    'NtCreateDebugObject': 0xa6,
    'NtDebugActiveProcess': 0xa7,
    'NtDebugContinue': 0xa8,
    'NtSetDebugFilterState': 0xa9,
    'NtQueryDebugFilterState': 0xaa,
    'NtCreateJob': 0x4e,
    'NtOpenJob': 0x4f,
    'NtAssignProcessToJobObject': 0x5f,
    'NtTerminateJobObject': 0x60,
    'NtCreateSymbolicLink': 0x85,
    'NtOpenSymbolicLink': 0x86,
    'NtQuerySymbolicLinkObject': 0x87,
    'NtCreateDirectoryObject': 0x93,
    'NtOpenDirectoryObject': 0x94,
    'NtQueryDirectoryObject': 0x95,
    'NtCreatePagingFile': 0x64,
    'NtCreateTransaction': 0xb0,
    'NtOpenTransaction': 0xb1,
    'NtQueryInformationTransaction': 0xb2,
    'NtSetInformationTransaction': 0xb3,
    'NtCreateFile': 0x54,
    'NtLoadDriver': 0x98,
    'NtUnloadDriver': 0x99,
    'NtLoadKey': 0x6e,
    'NtUnloadKey': 0x6f,
    'NtEnumerateKey': 0x62,
    'NtQueryKey': 0x63,
    'NtSetInformationKey': 0x65,
    'NtQueryValueKey': 0x67,
    'NtCreateRegistry': 0x70,
    'NtQuerySecurityObject': 0x71,
    'NtSetSecurityObject': 0x72,
    'NtCreateFile': 0x54,
    'NtQueryAttributesFile': 0x33,
    'NtQueryFullAttributesFile': 0x34,
    'NtQueryEaFile': 0x35,
    'NtSetEaFile': 0x38,
    'NtQueryQuotaInformationFile': 0x39,
    'NtSetQuotaInformationFile': 0x3b,
    'NtCreateMailslotFile': 0x57,
    'NtCreateNamedPipeFile': 0x58,
    'NtFsControlFile': 0x61,
    'NtDeviceIoControlFile': 0x77,
    'NtLockFile': 0x14,
    'NtUnlockFile': 0x15,
    'NtCreateFile': 0x54,
    'NtQueryVolumeInformationFile': 0x11,
    'NtSetVolumeInformationFile': 0x12,
    'NtQueryFileInformation': 0x13,
    'NtSetFileInformation': 0x14,
    'NtNotifyChangeDirectoryFile': 0x0d,
    'NtCancelIoFile': 0x40,
    'NtCreateFile': 0x54,
    'NtReadFileScatter': 0x0a,
    'NtWriteFileGather': 0x0c,
    'NtCreateUserProcess': 0xae,
    'NtGetContextThread': 0x7f,
    'NtSetContextThread': 0x80,
    'NtQuerySystemTime': 0x81,
    'NtQueryPerformanceCounter': 0x82,
    'NtCreateWnfStateName': 0xef,
    'NtUpdateWnfStateData': 0xf0,
    'NtQueryWnfStateData': 0xf1,
    'NtDeleteWnfStateName': 0xf2,
    'NtQueryWnfStateNameInformation': 0xf3,
    'NtCreateFile': 0x54,
}
