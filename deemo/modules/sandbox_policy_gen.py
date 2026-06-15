"""
系统调用过滤策略自动生成模块

根据二进制静态分析和动态追踪到的系统调用，自动生成最小权限的
seccomp-bpf 规则或 AppArmor 配置文件，限制应用可执行的系统调用。
"""

import logging
import os
import re
import json
import subprocess
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from config import Config, ensure_directories

logger = logging.getLogger(__name__)


class PolicyType(Enum):
    """策略类型枚举"""
    SECCOMP = 'seccomp'
    APPARMOR = 'apparmor'
    BOTH = 'both'


@dataclass
class SyscallInfo:
    """系统调用信息数据类"""
    name: str
    number: int
    frequency: int = 0
    source: str = 'static'  # 'static' 或 'dynamic'
    arguments: List[str] = field(default_factory=lambda: [])
    context: str = ''


@dataclass
class SandboxPolicy:
    """沙箱策略数据类"""
    policy_type: PolicyType
    allowed_syscalls: List[str] = field(default_factory=lambda: [])
    denied_syscalls: List[str] = field(default_factory=lambda: [])
    file_paths: List[str] = field(default_factory=lambda: [])
    network_rules: List[str] = field(default_factory=lambda: [])
    capabilities: List[str] = field(default_factory=lambda: [])
    policy_code: str = ''
    summary: str = ''


class SandboxPolicyGenerator:
    """
    沙箱策略生成器
    
    根据二进制分析结果生成最小权限的 seccomp/AppArmor 策略。
    """
    
    # Linux 系统调用映射（x86_64）
    SYSCALL_MAP_X64 = {
        0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
        5: 'fstat', 6: 'lstat', 7: 'poll', 8: 'lseek', 9: 'mmap',
        10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction',
        14: 'rt_sigprocmask', 15: 'rt_sigreturn', 16: 'ioctl', 17: 'pread64',
        18: 'pwrite64', 19: 'readv', 20: 'writev', 21: 'access', 22: 'pipe',
        23: 'select', 24: 'sched_yield', 25: 'mremap', 26: 'msync',
        27: 'mincore', 28: 'madvise', 29: 'shmget', 30: 'shmctl',
        31: 'shmat', 32: 'shmdt', 33: 'dup', 34: 'dup2', 35: 'pause',
        36: 'nanosleep', 37: 'getitimer', 38: 'alarm', 39: 'setitimer',
        40: 'getpid', 41: 'sendfile', 42: 'socket', 43: 'connect',
        44: 'accept', 45: 'sendto', 46: 'recvfrom', 47: 'sendmsg',
        48: 'recvmsg', 49: 'shutdown', 50: 'bind', 51: 'listen',
        52: 'getsockname', 53: 'getpeername', 54: 'socketpair',
        55: 'setsockopt', 56: 'getsockopt', 57: 'clone', 58: 'fork',
        59: 'vfork', 60: 'execve', 61: 'exit', 62: 'wait4',
        63: 'kill', 64: 'uname', 65: 'semget', 66: 'semop',
        67: 'semctl', 68: 'shmdt', 69: 'msgget', 70: 'msgsnd',
        71: 'msgrcv', 72: 'msgctl', 73: 'fcntl', 74: 'flock',
        75: 'fsync', 76: 'fdatasync', 77: 'truncate', 78: 'ftruncate',
        79: 'getdents', 80: 'getcwd', 81: 'chdir', 82: 'fchdir',
        83: 'rename', 84: 'mkdir', 85: 'rmdir', 86: 'creat',
        87: 'link', 88: 'unlink', 89: 'symlink', 90: 'readlink',
        91: 'chmod', 92: 'fchmod', 93: 'chown', 94: 'fchown',
        95: 'lchown', 96: 'umask', 97: 'gettimeofday', 98: 'getrlimit',
        99: 'getrusage', 100: 'sysinfo', 101: 'times', 102: 'ptrace',
        103: 'getuid', 104: 'syslog', 105: 'getgid', 106: 'setuid',
        107: 'setgid', 108: 'geteuid', 109: 'getegid', 110: 'setpgid',
        111: 'getppid', 112: 'getpgrp', 113: 'setsid', 114: 'setreuid',
        115: 'setregid', 116: 'getgroups', 117: 'setgroups',
        118: 'setresuid', 119: 'getresuid', 120: 'setresgid',
        121: 'getresgid', 122: 'getpgid', 123: 'setfsuid',
        124: 'setfsgid', 125: 'getsid', 126: 'capget', 127: 'capset',
        128: 'rt_sigpending', 129: 'rt_sigtimedwait', 130: 'rt_sigqueueinfo',
        131: 'rt_sigsuspend', 132: 'sigaltstack', 133: 'utime',
        134: 'mknod', 135: 'uselib', 136: 'personality', 137: 'ustat',
        138: 'statfs', 139: 'fstatfs', 140: 'sysfs', 141: 'getpriority',
        142: 'setpriority', 143: 'sched_setparam', 144: 'sched_getparam',
        145: 'sched_setscheduler', 146: 'sched_getscheduler',
        147: 'sched_get_priority_max', 148: 'sched_get_priority_min',
        149: 'sched_rr_get_interval', 150: 'mlock', 151: 'munlock',
        152: 'mlockall', 153: 'munlockall', 154: 'vhangup', 155: 'pivot_root',
        156: 'prctl', 157: 'arch_prctl', 158: 'adjtimex', 159: 'setrlimit',
        160: 'chroot', 161: 'sync', 162: 'acct', 163: 'settimeofday',
        164: 'mount', 165: 'umount2', 166: 'swapon', 167: 'swapoff',
        168: 'reboot', 169: 'sethostname', 170: 'setdomainname',
        171: 'iopl', 172: 'ioperm', 173: 'create_module', 174: 'init_module',
        175: 'delete_module', 176: 'get_kernel_syms', 177: 'query_module',
        178: 'quotactl', 179: 'nfsservctl', 180: 'getpmsg', 181: 'putpmsg',
        182: 'afs_syscall', 183: 'tuxcall', 184: 'security',
        185: 'gettid', 186: 'readahead', 187: 'setxattr', 188: 'lsetxattr',
        189: 'fsetxattr', 190: 'getxattr', 191: 'lgetxattr',
        192: 'fgetxattr', 193: 'listxattr', 194: 'llistxattr',
        195: 'flistxattr', 196: 'removexattr', 197: 'lremovexattr',
        198: 'fremovexattr', 199: 'tkill', 200: 'time', 201: 'futex',
        202: 'sched_setaffinity', 203: 'sched_getaffinity',
        204: 'set_thread_area', 205: 'io_setup', 206: 'io_destroy',
        207: 'io_getevents', 208: 'io_submit', 209: 'io_cancel',
        210: 'get_thread_area', 211: 'epoll_create', 212: 'epoll_ctl',
        213: 'epoll_wait', 214: 'remap_file_pages', 215: 'getdents64',
        216: 'set_tid_address', 217: 'restart_syscall', 218: 'semtimedop',
        219: 'fadvise64', 220: 'timer_create', 221: 'timer_settime',
        222: 'timer_gettime', 223: 'timer_getoverrun', 224: 'timer_delete',
        225: 'clock_settime', 226: 'clock_gettime', 227: 'clock_getres',
        228: 'clock_nanosleep', 229: 'exit_group', 230: 'epoll_wait',
        231: 'epoll_ctl', 232: 'tgkill', 233: 'utimes', 234: 'mbind',
        235: 'set_mempolicy', 236: 'get_mempolicy', 237: 'mq_open',
        238: 'mq_unlink', 239: 'mq_timedsend', 240: 'mq_timedreceive',
        241: 'mq_notify', 242: 'mq_getsetattr', 243: 'kexec_load',
        244: 'waitid', 245: 'add_key', 246: 'request_key', 247: 'keyctl',
        248: 'ioprio_set', 249: 'ioprio_get', 250: 'inotify_init',
        251: 'inotify_add_watch', 252: 'inotify_rm_watch',
        253: 'migrate_pages', 254: 'openat', 255: 'mkdirat',
        256: 'mknodat', 257: 'fchownat', 258: 'futimesat',
        259: 'newfstatat', 260: 'unlinkat', 261: 'renameat',
        262: 'linkat', 263: 'symlinkat', 264: 'readlinkat',
        265: 'fchmodat', 266: 'faccessat', 267: 'pselect6',
        268: 'ppoll', 269: 'unshare', 270: 'set_robust_list',
        271: 'get_robust_list', 272: 'splice', 273: 'tee',
        274: 'sync_file_range', 275: 'vmsplice', 276: 'move_pages',
        277: 'utimensat', 278: 'epoll_pwait', 279: 'signalfd',
        280: 'timerfd_create', 281: 'eventfd', 282: 'fallocate',
        283: 'timerfd_settime', 284: 'timerfd_gettime', 285: 'accept4',
        286: 'signalfd4', 287: 'eventfd2', 288: 'epoll_create1',
        289: 'dup3', 290: 'pipe2', 291: 'inotify_init1',
        292: 'preadv', 293: 'pwritev', 294: 'rt_tgsigqueueinfo',
        295: 'perf_event_open', 296: 'recvmmsg', 297: 'fanotify_init',
        298: 'fanotify_mark', 299: 'prlimit64', 300: 'name_to_handle_at',
        301: 'open_by_handle_at', 302: 'clock_adjtime', 303: 'syncfs',
        304: 'sendmmsg', 305: 'setns', 306: 'getcpu', 307: 'process_vm_readv',
        308: 'process_vm_writev', 309: 'kcmp', 310: 'finit_module',
        311: 'getdents', 312: 'setns', 313: 'getrandom', 314: 'memfd_create',
        315: 'kexec_file_load', 316: 'bpf', 317: 'execveat',
        318: 'userfaultfd', 319: 'membarrier', 320: 'mlock2',
        321: 'copy_file_range', 322: 'preadv2', 323: 'pwritev2',
        324: 'pkey_mprotect', 325: 'pkey_alloc', 326: 'pkey_free',
        327: 'statx', 328: 'io_pgetevents', 329: 'rseq',
        330: 'pidfd_send_signal', 331: 'io_uring_setup',
        332: 'io_uring_enter', 333: 'io_uring_register',
    }
    
    # 危险系统调用（应默认拒绝）
    DANGEROUS_SYSCALLS = {
        'execve': '执行新程序 - 可能被利用执行恶意代码',
        'execveat': '执行新程序 - 可能被利用执行恶意代码',
        'fork': '创建子进程 - 可能被利用创建恶意进程',
        'vfork': '创建子进程 - 可能被利用创建恶意进程',
        'clone': '创建新进程/线程 - 可能被利用',
        'ptrace': '进程追踪 - 高危，可用于调试和注入',
        'mount': '挂载文件系统 - 高危',
        'umount2': '卸载文件系统 - 高危',
        'chroot': '改变根目录 - 可能被利用',
        'pivot_root': '改变根目录 - 高危',
        'reboot': '重启系统 - 高危',
        'kexec_load': '加载新内核 - 高危',
        'kexec_file_load': '加载新内核 - 高危',
        'init_module': '加载内核模块 - 高危',
        'finit_module': '加载内核模块 - 高危',
        'delete_module': '删除内核模块 - 高危',
        'swapon': '启用交换 - 高危',
        'swapoff': '禁用交换 - 高危',
        'setuid': '设置用户ID - 可能被利用提权',
        'setgid': '设置组ID - 可能被利用提权',
        'setreuid': '设置用户ID - 可能被利用提权',
        'setregid': '设置组ID - 可能被利用提权',
        'setresuid': '设置用户ID - 可能被利用提权',
        'setresgid': '设置组ID - 可能被利用提权',
        'setfsuid': '设置文件系统用户ID - 可能被利用',
        'setfsgid': '设置文件系统组ID - 可能被利用',
        'capset': '设置能力 - 高危',
        'prctl': '进程控制 - 可能被利用',
        'seccomp': '设置seccomp - 可能被利用绕过',
        'bpf': 'BPF系统调用 - 高危',
        'keyctl': '内核密钥管理 - 高危',
        'add_key': '添加密钥 - 高危',
        'request_key': '请求密钥 - 高危',
        'iopl': 'IO权限级别 - 高危',
        'ioperm': 'IO权限 - 高危',
        'acct': '进程记账 - 高危',
        'settimeofday': '设置时间 - 高危',
        'stime': '设置时间 - 高危',
        'clock_settime': '设置时钟 - 高危',
        'adjtimex': '调整时间 - 高危',
        'sethostname': '设置主机名 - 高危',
        'setdomainname': '设置域名 - 高危',
        'quotactl': '磁盘配额控制 - 高危',
        'nfsservctl': 'NFS服务控制 - 高危',
        'syslog': '系统日志 - 高危',
        'perf_event_open': '性能事件 - 可能被利用',
        'userfaultfd': '用户页错误 - 可能被利用',
        'memfd_create': '创建内存文件 - 可能被利用',
        'unshare': '取消共享 - 可能被利用',
        'setns': '加入命名空间 - 高危',
    }
    
    # 函数到系统调用的映射
    FUNCTION_TO_SYSCALL = {
        # 文件操作
        'open': ['open', 'openat'],
        'openat': ['openat'],
        'read': ['read', 'pread64', 'readv', 'preadv'],
        'write': ['write', 'pwrite64', 'writev', 'pwritev'],
        'close': ['close'],
        'stat': ['stat', 'fstat', 'lstat', 'newfstatat'],
        'fstat': ['fstat'],
        'lstat': ['lstat'],
        'access': ['access', 'faccessat'],
        'faccessat': ['faccessat'],
        'mkdir': ['mkdir', 'mkdirat'],
        'mkdirat': ['mkdirat'],
        'rmdir': ['rmdir'],
        'unlink': ['unlink', 'unlinkat'],
        'unlinkat': ['unlinkat'],
        'rename': ['rename', 'renameat'],
        'renameat': ['renameat'],
        'link': ['link', 'linkat'],
        'linkat': ['linkat'],
        'symlink': ['symlink', 'symlinkat'],
        'symlinkat': ['symlinkat'],
        'readlink': ['readlink', 'readlinkat'],
        'readlinkat': ['readlinkat'],
        'chmod': ['chmod', 'fchmod', 'fchmodat'],
        'fchmod': ['fchmod'],
        'fchmodat': ['fchmodat'],
        'chown': ['chown', 'fchown', 'lchown', 'fchownat'],
        'fchown': ['fchown'],
        'lchown': ['lchown'],
        'fchownat': ['fchownat'],
        'creat': ['creat'],
        'truncate': ['truncate', 'ftruncate'],
        'ftruncate': ['ftruncate'],
        'fsync': ['fsync', 'fdatasync'],
        'fdatasync': ['fdatasync'],
        'getdents': ['getdents', 'getdents64'],
        'getdents64': ['getdents64'],
        'getcwd': ['getcwd'],
        'chdir': ['chdir', 'fchdir'],
        'fchdir': ['fchdir'],
        
        # 内存操作
        'malloc': ['brk', 'mmap'],
        'free': ['munmap'],
        'mmap': ['mmap', 'mmap2'],
        'munmap': ['munmap'],
        'mprotect': ['mprotect'],
        'mlock': ['mlock', 'mlockall'],
        'munlock': ['munlock', 'munlockall'],
        'brk': ['brk'],
        'sbrk': ['brk'],
        
        # 进程操作
        'fork': ['fork', 'clone'],
        'vfork': ['vfork'],
        'clone': ['clone'],
        'exec': ['execve', 'execveat'],
        'execve': ['execve'],
        'execveat': ['execveat'],
        'exit': ['exit', 'exit_group'],
        '_exit': ['exit', 'exit_group'],
        'wait': ['wait4', 'waitid'],
        'waitpid': ['wait4', 'waitid'],
        'waitid': ['waitid'],
        'kill': ['kill', 'tkill', 'tgkill'],
        'tkill': ['tkill'],
        'tgkill': ['tgkill'],
        'getpid': ['getpid'],
        'getppid': ['getppid'],
        'gettid': ['gettid'],
        
        # 信号
        'signal': ['rt_sigaction', 'sigaction'],
        'sigaction': ['rt_sigaction', 'sigaction'],
        'sigprocmask': ['rt_sigprocmask'],
        'sigsuspend': ['rt_sigsuspend'],
        'sigpending': ['rt_sigpending'],
        'sigaltstack': ['sigaltstack'],
        
        # 网络
        'socket': ['socket'],
        'bind': ['bind'],
        'listen': ['listen'],
        'accept': ['accept', 'accept4'],
        'accept4': ['accept4'],
        'connect': ['connect'],
        'send': ['sendto', 'sendmsg', 'sendmmsg'],
        'sendto': ['sendto'],
        'sendmsg': ['sendmsg'],
        'sendmmsg': ['sendmmsg'],
        'recv': ['recvfrom', 'recvmsg', 'recvmmsg'],
        'recvfrom': ['recvfrom'],
        'recvmsg': ['recvmsg'],
        'recvmmsg': ['recvmmsg'],
        'shutdown': ['shutdown'],
        'getsockname': ['getsockname'],
        'getpeername': ['getpeername'],
        'socketpair': ['socketpair'],
        'setsockopt': ['setsockopt'],
        'getsockopt': ['getsockopt'],
        
        # IO
        'poll': ['poll', 'ppoll'],
        'ppoll': ['ppoll'],
        'select': ['select', 'pselect6'],
        'pselect': ['pselect6'],
        'epoll_create': ['epoll_create', 'epoll_create1'],
        'epoll_create1': ['epoll_create1'],
        'epoll_ctl': ['epoll_ctl'],
        'epoll_wait': ['epoll_wait', 'epoll_pwait'],
        'epoll_pwait': ['epoll_pwait'],
        'pipe': ['pipe', 'pipe2'],
        'pipe2': ['pipe2'],
        'dup': ['dup', 'dup2', 'dup3'],
        'dup2': ['dup2'],
        'dup3': ['dup3'],
        'fcntl': ['fcntl'],
        'ioctl': ['ioctl'],
        
        # 时间
        'time': ['time', 'stime'],
        'stime': ['stime'],
        'gettimeofday': ['gettimeofday'],
        'settimeofday': ['settimeofday'],
        'clock_gettime': ['clock_gettime'],
        'clock_settime': ['clock_settime'],
        'nanosleep': ['nanosleep', 'clock_nanosleep'],
        'clock_nanosleep': ['clock_nanosleep'],
        'sleep': ['nanosleep'],
        'usleep': ['nanosleep'],
        'alarm': ['alarm'],
        'setitimer': ['setitimer'],
        'getitimer': ['getitimer'],
        'timer_create': ['timer_create'],
        'timer_settime': ['timer_settime'],
        'timer_gettime': ['timer_gettime'],
        'timer_delete': ['timer_delete'],
        
        # 用户/组
        'getuid': ['getuid'],
        'geteuid': ['geteuid'],
        'getgid': ['getgid'],
        'getegid': ['getegid'],
        'setuid': ['setuid', 'setreuid', 'setresuid'],
        'setreuid': ['setreuid'],
        'setresuid': ['setresuid'],
        'setgid': ['setgid', 'setregid', 'setresgid'],
        'setregid': ['setregid'],
        'setresgid': ['setresgid'],
        'getgroups': ['getgroups'],
        'setgroups': ['setgroups'],
        'getrlimit': ['getrlimit', 'prlimit64'],
        'setrlimit': ['setrlimit', 'prlimit64'],
        'getrusage': ['getrusage'],
        'getpriority': ['getpriority'],
        'setpriority': ['setpriority'],
        
        # 其他
        'uname': ['uname'],
        'sysinfo': ['sysinfo'],
        'gethostname': ['gethostname'],
        'sethostname': ['sethostname'],
        'getdomainname': ['getdomainname'],
        'setdomainname': ['setdomainname'],
        'syslog': ['syslog'],
        'prctl': ['prctl'],
        'arch_prctl': ['arch_prctl'],
        'getrandom': ['getrandom'],
        'urandom': ['getrandom'],
    }
    
    def __init__(
        self,
        binary_path: str,
        output_dir: str = None,
        policy_type: PolicyType = PolicyType.SECCOMP
    ):
        """
        初始化沙箱策略生成器
        
        Args:
            binary_path: 二进制文件路径
            output_dir: 输出目录
            policy_type: 策略类型
        """
        self.binary_path = binary_path
        self.output_dir = output_dir or os.path.join(Config.DATA_DIR, 'sandbox_policies')
        self.policy_type = policy_type
        
        ensure_directories(self.output_dir)
        
        self.syscalls: Dict[str, SyscallInfo] = {}
        self.allowed_syscalls: Set[str] = set()
        self.denied_syscalls: Set[str] = set()
        self.file_paths: Set[str] = set()
        self.network_ports: Set[int] = set()
    
    def analyze(self) -> SandboxPolicy:
        """
        执行分析并生成策略
        
        Returns:
            SandboxPolicy 策略对象
        """
        logger.info(f"[Sandbox] 分析二进制: {self.binary_path}")
        
        # 静态分析系统调用
        self._static_analyze_syscalls()
        
        # 确定允许和拒绝的系统调用
        self._determine_allowed_syscalls()
        
        # 生成策略代码
        policy_code = self._generate_policy_code()
        
        # 生成摘要
        summary = self._generate_summary()
        
        # 保存策略
        self._save_policy(policy_code)
        
        return SandboxPolicy(
            policy_type=self.policy_type,
            allowed_syscalls=list(self.allowed_syscalls),
            denied_syscalls=list(self.denied_syscalls),
            file_paths=list(self.file_paths),
            network_rules=[f'port {p}' for p in self.network_ports],
            policy_code=policy_code,
            summary=summary
        )
    
    def _static_analyze_syscalls(self) -> None:
        """
        静态分析二进制推断系统调用
        """
        try:
            # 使用 radare2 获取导入函数
            result = subprocess.run(
                ['r2', '-q', '-c', 'is', self.binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            
            if result.returncode == 0:
                self._parse_symbols(result.stdout)
            
            # 使用 radare2 获取字符串
            result = subprocess.run(
                ['r2', '-q', '-c', 'iz', self.binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            
            if result.returncode == 0:
                self._parse_strings(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.warning("[Sandbox] radare2 分析超时")
        except FileNotFoundError:
            logger.warning("[Sandbox] radare2 未安装，使用基础分析")
            self._basic_analyze()
        except Exception as e:
            logger.error(f"[Sandbox] 静态分析失败: {e}")
            self._basic_analyze()
    
    def _parse_symbols(self, output: str) -> None:
        """
        解析符号表
        
        Args:
            output: radare2 输出
        """
        for line in output.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 6:
                # 提取函数名
                func_name = parts[-1]
                
                # 去除前缀
                if func_name.startswith('sym.'):
                    func_name = func_name[4:]
                if func_name.startswith('imp.'):
                    func_name = func_name[4:]
                
                # 映射到系统调用
                syscalls = self.FUNCTION_TO_SYSCALL.get(func_name, [])
                for syscall in syscalls:
                    if syscall not in self.syscalls:
                        self.syscalls[syscall] = SyscallInfo(
                            name=syscall,
                            number=self._get_syscall_number(syscall),
                            source='static'
                        )
                    self.syscalls[syscall].frequency += 1
    
    def _parse_strings(self, output: str) -> None:
        """
        解析字符串
        
        Args:
            output: radare2 输出
        """
        for line in output.strip().split('\n'):
            # 提取路径
            if '/' in line:
                path_match = re.search(r'/[\w./\-]+', line)
                if path_match:
                    path = path_match.group()
                    if len(path) > 3:
                        self.file_paths.add(path)
            
            # 提取端口
            port_match = re.search(r'(\d{1,5})', line)
            if port_match:
                port = int(port_match.group(1))
                if 1 <= port <= 65535:
                    self.network_ports.add(port)
    
    def _basic_analyze(self) -> None:
        """
        基础分析（当 radare2 不可用时）
        """
        # 添加基本必需的系统调用
        basic_syscalls = [
            'read', 'write', 'open', 'close', 'stat', 'fstat',
            'mmap', 'munmap', 'brk', 'exit', 'exit_group',
            'rt_sigaction', 'rt_sigprocmask', 'ioctl',
            'getuid', 'getgid', 'geteuid', 'getegid',
        ]
        
        for syscall in basic_syscalls:
            if syscall not in self.syscalls:
                self.syscalls[syscall] = SyscallInfo(
                    name=syscall,
                    number=self._get_syscall_number(syscall),
                    source='basic'
                )
    
    def _get_syscall_number(self, name: str) -> int:
        """
        获取系统调用号
        
        Args:
            name: 系统调用名称
            
        Returns:
            系统调用号
        """
        for num, syscall_name in self.SYSCALL_MAP_X64.items():
            if syscall_name == name:
                return num
        return -1
    
    def _determine_allowed_syscalls(self) -> None:
        """
        确定允许和拒绝的系统调用
        """
        # 添加分析发现的系统调用到允许列表
        for syscall in self.syscalls:
            # 检查是否是危险系统调用
            if syscall in self.DANGEROUS_SYSCALLS:
                self.denied_syscalls.add(syscall)
                logger.warning(f"[Sandbox] 拒绝危险系统调用: {syscall}")
            else:
                self.allowed_syscalls.add(syscall)
        
        # 添加必需的基础系统调用
        required_syscalls = [
            'read', 'write', 'open', 'close', 'stat', 'fstat', 'lstat',
            'mmap', 'munmap', 'brk', 'mprotect',
            'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn',
            'ioctl', 'fcntl', 'dup', 'dup2', 'dup3',
            'getuid', 'getgid', 'geteuid', 'getegid',
            'getpid', 'getppid', 'gettid',
            'exit', 'exit_group', 'wait4', 'waitid',
            'clock_gettime', 'gettimeofday', 'nanosleep',
            'arch_prctl', 'set_tid_address', 'set_robust_list',
        ]
        
        for syscall in required_syscalls:
            if syscall not in self.DANGEROUS_SYSCALLS:
                self.allowed_syscalls.add(syscall)
    
    def _generate_policy_code(self) -> str:
        """
        生成策略代码
        
        Returns:
            策略代码字符串
        """
        if self.policy_type == PolicyType.SECCOMP:
            return self._generate_seccomp_policy()
        elif self.policy_type == PolicyType.APPARMOR:
            return self._generate_apparmor_policy()
        elif self.policy_type == PolicyType.BOTH:
            seccomp = self._generate_seccomp_policy()
            apparmor = self._generate_apparmor_policy()
            return f"{seccomp}\n\n{'='*50}\n\n{apparmor}"
        
        return ''
    
    def _generate_seccomp_policy(self) -> str:
        """
        生成 seccomp-bpf 策略
        
        Returns:
            seccomp 策略代码
        """
        lines = [
            '// Seccomp-BPF Policy for ' + os.path.basename(self.binary_path),
            '// Generated by LLM-Assisted Binary Vulnerability Analysis Tool',
            '//',
            '// Policy: Default DENY, explicit ALLOW',
            '',
            '#include <linux/seccomp.h>',
            '#include <linux/filter.h>',
            '#include <linux/bpf.h>',
            '#include <sys/syscall.h>',
            '#include <stddef.h>',
            '',
            '// Allowed syscalls:',
            '// ' + ', '.join(sorted(self.allowed_syscalls)),
            '',
            '// Denied syscalls:',
            '// ' + ', '.join(sorted(self.denied_syscalls)) if self.denied_syscalls else '// None explicitly denied',
            '',
            'static struct sock_filter seccomp_filter[] = {',
            '    // Validate architecture (x86_64)',
            '    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),',
            '    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),',
            '    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),',
            '',
            '    // Load syscall number',
            '    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),',
        ]
        
        # 为每个允许的系统调用添加规则
        for syscall in sorted(self.allowed_syscalls):
            num = self._get_syscall_number(syscall)
            if num >= 0:
                lines.append(f'    // Allow {syscall}')
                lines.append(f'    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_{syscall}, 0, 1),')
                lines.append('    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),')
        
        # 默认拒绝
        lines.extend([
            '',
            '    // Default: DENY',
            '    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),',
            '};',
            '',
            'static struct sock_fprog seccomp_prog = {',
            '    .len = sizeof(seccomp_filter) / sizeof(seccomp_filter[0]),',
            '    .filter = seccomp_filter,',
            '};',
            '',
            '// Apply seccomp filter',
            'int apply_seccomp() {',
            '    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {',
            '        return -1;',
            '    }',
            '    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_prog) == -1) {',
            '        return -1;',
            '    }',
            '    return 0;',
            '}',
            '',
            '// Python wrapper using libseccomp',
            '/*',
            'import seccomp',
            '',
            'def setup_seccomp():',
            '    ctx = seccomp.SyscallFilter(seccomp.KILL)',
        ])
        
        for syscall in sorted(self.allowed_syscalls):
            lines.append(f'    ctx.add_rule(seccomp.ALLOW, "{syscall}")')
        
        lines.extend([
            '    ctx.load()',
            '*/',
        ])
        
        return '\n'.join(lines)
    
    def _generate_apparmor_policy(self) -> str:
        """
        生成 AppArmor 策略
        
        Returns:
            AppArmor 策略代码
        """
        binary_name = os.path.basename(self.binary_path)
        
        lines = [
            '# AppArmor Profile for ' + binary_name,
            '# Generated by LLM-Assisted Binary Vulnerability Analysis Tool',
            '#',
            '# Policy: Default DENY, explicit ALLOW',
            '',
            f'#include <tunables/global>',
            '',
            f'profile {binary_name} /** {binary_name} {self.binary_path} {{',
            '  #include <abstractions/base>',
            '',
            '  # File access rules',
        ]
        
        # 文件路径规则
        if self.file_paths:
            for path in sorted(self.file_paths)[:20]:
                # 清理路径
                if path.startswith('/'):
                    lines.append(f'  {path} r,')
        else:
            lines.append('  /** r,')
        
        lines.extend([
            '',
            '  # Network rules',
        ])
        
        # 网络规则
        if self.network_ports:
            for port in sorted(self.network_ports)[:10]:
                lines.append(f'  network inet stream,')
                lines.append(f'  network inet dgram,')
        else:
            lines.append('  network inet,')
        
        lines.extend([
            '',
            '  # Capabilities',
            '  capability dac_read_search,',
            '',
            '  # Denied dangerous operations',
            '  deny /bin/** x,',
            '  deny /sbin/** x,',
            '  deny /usr/bin/** x,',
            '  deny /** w,',
            '',
            '  # Signal restrictions',
            '  signal (receive) set=(term kill) peer=unconfined,',
            '',
            '  # Ptrace restrictions',
            '  deny ptrace (trace) peer=unconfined,',
            '',
            '}',
        ])
        
        return '\n'.join(lines)
    
    def _generate_summary(self) -> str:
        """
        生成策略摘要
        
        Returns:
            摘要字符串
        """
        lines = [
            f'沙箱策略摘要 ({self.policy_type.value})',
            f'二进制文件: {os.path.basename(self.binary_path)}',
            f'允许的系统调用数: {len(self.allowed_syscalls)}',
            f'拒绝的系统调用数: {len(self.denied_syscalls)}',
            f'文件路径数: {len(self.file_paths)}',
            f'网络端口数: {len(self.network_ports)}',
            '',
            '允许的系统调用:',
            '  ' + ', '.join(sorted(self.allowed_syscalls)[:20]),
        ]
        
        if self.denied_syscalls:
            lines.extend([
                '',
                '拒绝的危险系统调用:',
            ])
            for syscall in sorted(self.denied_syscalls):
                reason = self.DANGEROUS_SYSCALLS.get(syscall, '未知')
                lines.append(f'  - {syscall}: {reason}')
        
        return '\n'.join(lines)
    
    def _save_policy(self, policy_code: str) -> None:
        """
        保存策略文件
        
        Args:
            policy_code: 策略代码
        """
        binary_name = os.path.basename(self.binary_path)
        
        if self.policy_type == PolicyType.SECCOMP:
            filename = f'{binary_name}_seccomp.c'
        elif self.policy_type == PolicyType.APPARMOR:
            filename = f'{binary_name}_apparmor.profile'
        else:
            filename = f'{binary_name}_sandbox_policy.txt'
        
        output_path = os.path.join(self.output_dir, filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(policy_code)
        
        logger.info(f"[Sandbox] 策略已保存: {output_path}")
    
    def test_policy(self) -> Dict[str, Any]:
        """
        测试生成的策略
        
        Returns:
            测试结果
        """
        result = {
            'success': False,
            'message': '',
            'details': []
        }
        
        try:
            # 检查是否有 Docker 可用
            docker_check = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                timeout=5
            )
            
            if docker_check.returncode != 0:
                result['message'] = 'Docker 不可用，无法测试策略'
                return result
            
            # 构建测试命令
            binary_name = os.path.basename(self.binary_path)
            
            # 这里只是示意，实际测试需要构建 Docker 镜像
            result['details'].append('策略测试需要手动在 Docker 中验证')
            result['details'].append(f'建议命令: docker run --rm --security-opt seccomp={binary_name}_seccomp.json ...')
            
            result['success'] = True
            result['message'] = '策略生成完成，建议手动测试'
            
        except subprocess.TimeoutExpired:
            result['message'] = '测试超时'
        except FileNotFoundError:
            result['message'] = 'Docker 未安装'
        except Exception as e:
            result['message'] = f'测试失败: {e}'
        
        return result
    
    def load_dynamic_trace(self, trace_file: str) -> None:
        """
        加载动态追踪日志
        
        Args:
            trace_file: 追踪日志文件路径
        """
        try:
            with open(trace_file, 'r', encoding='utf-8') as f:
                trace_data = json.load(f)
            
            # 解析系统调用
            syscalls = trace_data.get('syscalls', [])
            for syscall_entry in syscalls:
                syscall_name = syscall_entry.get('name', '')
                syscall_number = syscall_entry.get('number', -1)
                
                if syscall_name:
                    if syscall_name not in self.syscalls:
                        self.syscalls[syscall_name] = SyscallInfo(
                            name=syscall_name,
                            number=syscall_number,
                            source='dynamic'
                        )
                    self.syscalls[syscall_name].frequency += 1
            
            # 解析文件路径
            file_ops = trace_data.get('file_operations', [])
            for file_op in file_ops:
                path = file_op.get('path', '')
                if path:
                    self.file_paths.add(path)
            
            # 解析网络连接
            network_ops = trace_data.get('network_operations', [])
            for net_op in network_ops:
                port = net_op.get('port', 0)
                if 1 <= port <= 65535:
                    self.network_ports.add(port)
            
            logger.info(f"[Sandbox] 加载动态追踪: {len(syscalls)} 个系统调用")
            
        except json.JSONDecodeError:
            logger.error(f"[Sandbox] 追踪日志格式错误")
        except FileNotFoundError:
            logger.error(f"[Sandbox] 追踪日志文件不存在: {trace_file}")
        except Exception as e:
            logger.error(f"[Sandbox] 加载动态追踪失败: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式
        
        Returns:
            策略信息字典
        """
        return {
            'binary_path': self.binary_path,
            'policy_type': self.policy_type.value,
            'allowed_syscalls': sorted(self.allowed_syscalls),
            'denied_syscalls': sorted(self.denied_syscalls),
            'file_paths': sorted(self.file_paths),
            'network_ports': sorted(self.network_ports),
            'syscall_count': len(self.syscalls),
            'summary': self._generate_summary()
        }


def generate_sandbox_policy(
    binary_path: str,
    policy_type: str = 'seccomp',
    output_dir: str = None,
    trace_file: str = None
) -> SandboxPolicy:
    """
    生成沙箱策略的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        policy_type: 策略类型 ('seccomp', 'apparmor', 'both')
        output_dir: 输出目录
        trace_file: 动态追踪日志文件
        
    Returns:
        SandboxPolicy 策略对象
    """
    policy_enum = PolicyType(policy_type) if policy_type in ['seccomp', 'apparmor', 'both'] else PolicyType.SECCOMP
    
    generator = SandboxPolicyGenerator(binary_path, output_dir, policy_enum)
    
    if trace_file:
        generator.load_dynamic_trace(trace_file)
    
    return generator.analyze()