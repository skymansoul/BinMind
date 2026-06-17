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


# Linux 系统调用映射（x86_64）name -> number
SYSCALL_MAP_X64 = {
    'read': 0, 'write': 1, 'open': 2, 'close': 3, 'stat': 4,
    'fstat': 5, 'lstat': 6, 'poll': 7, 'lseek': 8, 'mmap': 9,
    'mprotect': 10, 'munmap': 11, 'brk': 12, 'rt_sigaction': 13,
    'rt_sigprocmask': 14, 'rt_sigreturn': 15, 'ioctl': 16, 'pread64': 17,
    'pwrite64': 18, 'readv': 19, 'writev': 20, 'access': 21, 'pipe': 22,
    'select': 23, 'sched_yield': 24, 'mremap': 25, 'msync': 26,
    'mincore': 27, 'madvise': 28, 'shmget': 29, 'shmctl': 30,
    'shmat': 31, 'shmdt': 32, 'dup': 33, 'dup2': 34, 'pause': 35,
    'nanosleep': 36, 'getitimer': 37, 'alarm': 38, 'setitimer': 39,
    'getpid': 40, 'sendfile': 41, 'socket': 42, 'connect': 43,
    'accept': 44, 'sendto': 45, 'recvfrom': 46, 'sendmsg': 47,
    'recvmsg': 48, 'shutdown': 49, 'bind': 50, 'listen': 51,
    'getsockname': 52, 'getpeername': 53, 'socketpair': 54,
    'setsockopt': 55, 'getsockopt': 56, 'clone': 57, 'fork': 58,
    'vfork': 59, 'execve': 59, 'exit': 60, 'wait4': 61, 'waitid': 61,
    'kill': 62, 'uname': 63, 'semget': 64, 'semop': 65,
    'semctl': 66, 'msgget': 67, 'msgsnd': 68, 'msgrcv': 69, 'msgctl': 70,
    'fcntl': 72, 'flock': 73, 'fsync': 74, 'fdatasync': 75,
    'truncate': 76, 'ftruncate': 77, 'getdents': 78, 'getcwd': 79,
    'chdir': 80, 'fchdir': 81, 'rename': 82, 'mkdir': 83,
    'rmdir': 84, 'creat': 85, 'link': 86, 'unlink': 87,
    'symlink': 88, 'readlink': 89, 'chmod': 90, 'fchmod': 91,
    'chown': 92, 'fchown': 93, 'lchown': 94, 'umask': 95,
    'gettimeofday': 96, 'getrlimit': 97, 'getrusage': 98,
    'sysinfo': 99, 'times': 100, 'ptrace': 101, 'getuid': 102,
    'syslog': 103, 'getgid': 104, 'setuid': 105, 'setgid': 106,
    'geteuid': 107, 'getegid': 108, 'setpgid': 109, 'getppid': 110,
    'getpgrp': 111, 'setsid': 112, 'setreuid': 113, 'setregid': 114,
    'getgroups': 115, 'setgroups': 116, 'setresuid': 117,
    'getresuid': 118, 'setresgid': 119, 'getresgid': 120,
    'getpgid': 121, 'setfsuid': 122, 'setfsgid': 123, 'getsid': 124,
    'capget': 125, 'capset': 126, 'rt_sigpending': 127,
    'rt_sigtimedwait': 128, 'rt_sigqueueinfo': 129, 'rt_sigsuspend': 130,
    'sigaltstack': 131, 'utime': 132, 'mknod': 133,
    'personality': 135, 'ustat': 136, 'statfs': 137, 'fstatfs': 138,
    'sysfs': 139, 'getpriority': 140, 'setpriority': 141,
    'sched_setparam': 142, 'sched_getparam': 143, 'sched_setscheduler': 144,
    'sched_getscheduler': 145, 'sched_get_priority_max': 146,
    'sched_get_priority_min': 147, 'sched_rr_get_interval': 148,
    'mlock': 149, 'munlock': 150, 'mlockall': 151, 'munlockall': 152,
    'vhangup': 153, 'pivot_root': 154, 'prctl': 157, 'arch_prctl': 158,
    'adjtimex': 159, 'setrlimit': 160, 'chroot': 161, 'sync': 162,
    'acct': 163, 'settimeofday': 164, 'mount': 165, 'umount2': 166,
    'swapon': 167, 'swapoff': 168, 'reboot': 169, 'sethostname': 170,
    'setdomainname': 171, 'iopl': 172, 'ioperm': 173,
    'init_module': 175, 'delete_module': 176, 'quotactl': 179,
    'gettid': 186, 'readahead': 187, 'setxattr': 188,
    'fsetxattr': 190, 'getxattr': 191, 'listxattr': 194,
    'removexattr': 196, 'tkill': 200, 'time': 201, 'futex': 202,
    'sched_setaffinity': 203, 'sched_getaffinity': 204,
    'io_setup': 206, 'io_destroy': 207, 'io_getevents': 208,
    'io_submit': 209, 'io_cancel': 210, 'epoll_create': 211,
    'epoll_ctl': 213, 'epoll_wait': 214, 'set_tid_address': 218,
    'restart_syscall': 219, 'semtimedop': 220, 'fadvise64': 221,
    'timer_create': 222, 'timer_settime': 223, 'timer_gettime': 224,
    'timer_getoverrun': 225, 'timer_delete': 226, 'clock_settime': 227,
    'clock_gettime': 228, 'clock_getres': 229, 'clock_nanosleep': 230,
    'exit_group': 231, 'epoll_pwait': 281, 'signalfd': 282,
    'eventfd': 284, 'fallocate': 285, 'timerfd_settime': 286,
    'timerfd_gettime': 287, 'accept4': 288, 'signalfd4': 289,
    'eventfd2': 290, 'epoll_create1': 291, 'dup3': 292, 'pipe2': 293,
    'inotify_init1': 294, 'preadv': 295, 'pwritev': 296,
    'recvmmsg': 299, 'fanotify_init': 300, 'fanotify_mark': 301,
    'prlimit64': 302, 'getrandom': 318, 'memfd_create': 319,
    'bpf': 321, 'execveat': 322, 'userfaultfd': 323, 'membarrier': 324,
    'mlock2': 325, 'copy_file_range': 326, 'preadv2': 327,
    'pwritev2': 328, 'pkey_mprotect': 329, 'pkey_alloc': 330,
    'pkey_free': 331, 'statx': 332, 'rseq': 334,
    'pidfd_send_signal': 424, 'io_uring_setup': 425,
    'openat': 257, 'mkdirat': 258, 'mknodat': 259, 'fchownat': 260,
}

# 危险系统调用列表
DANGEROUS_SYSCALLS = {
    'ptrace': '进程跟踪，可能被用于调试攻击',
    'chroot': '改变根目录，可能被用于容器逃逸',
    'mount': '挂载文件系统，可能被用于提权',
    'umount2': '卸载文件系统',
    'swapon': '启用交换分区',
    'swapoff': '禁用交换分区',
    'reboot': '重启系统',
    'kexec_load': '加载内核执行',
    'kexec_file_load': '加载内核文件执行',
    'bpf': 'BPF 程序加载，可能被用于提权',
    'setuid': '设置用户ID，可能被用于提权',
    'setgid': '设置组ID，可能被用于提权',
    'setreuid': '设置真实用户ID',
    'setregid': '设置真实组ID',
    'setresuid': '设置真实、有效、保存的用户ID',
    'setresgid': '设置真实、有效、保存的组ID',
    'capset': '设置能力',
    'clone': '创建进程，可能被用于容器逃逸',
    'fork': '创建进程',
    'vfork': '创建进程（特殊方式）',
    'execve': '执行程序',
    'execveat': '执行程序（扩展）',
    'exit': '退出进程',
    'exit_group': '退出进程组',
    'kill': '发送信号，可能被用于拒绝服务',
    'tgkill': '向特定线程发送信号',
    'tkill': '向线程发送信号',
    'personality': '改变进程个性',
    'unshare': '取消共享命名空间，可能被用于容器逃逸',
    'setns': '加入命名空间，可能被用于容器逃逸',
    'mount': '挂载文件系统',
    'umount2': '卸载文件系统',
    'chroot': '改变根目录',
    'pivot_root': '切换根目录',
    'ioctl': '设备控制，可能被用于提权',
    'iopl': '设置I/O特权级别',
    'ioperm': '设置I/O权限',
    'create_module': '创建内核模块',
    'init_module': '初始化内核模块',
    'delete_module': '删除内核模块',
    'syslog': '系统日志',
    'acct': '进程记账',
    'adjtimex': '调整系统时间',
    'settimeofday': '设置系统时间',
    'clock_settime': '设置时钟',
    'getcpu': '获取CPU信息',
    'process_vm_readv': '读取进程内存',
    'process_vm_writev': '写入进程内存',
    'kcmp': '进程比较',
    'perf_event_open': '性能事件',
    'fanotify_init': '文件系统通知',
    'fanotify_mark': '文件系统标记',
    'memfd_create': '创建匿名文件',
    'userfaultfd': '用户缺页处理',
    'membarrier': '内存屏障',
    'mlock2': '内存锁定',
    'copy_file_range': '复制文件范围',
    'preadv2': '分散读取',
    'pwritev2': '分散写入',
    'pkey_mprotect': '保护键内存',
    'pkey_alloc': '分配保护键',
    'pkey_free': '释放保护键',
    'statx': '扩展文件状态',
    'io_pgetevents': '获取I/O事件',
    'rseq': '重启序列',
    'pidfd_send_signal': '向进程文件描述符发送信号',
    'io_uring_setup': '设置IO_URING',
}

# 函数到系统调用的映射
FUNCTION_TO_SYSCALL = {
    # 文件操作
    'open': ['open', 'openat', 'open_by_handle_at'],
    'fopen': ['open', 'openat', 'open_by_handle_at'],
    'fclose': ['close'],
    'fread': ['read', 'pread64', 'preadv', 'preadv2'],
    'fwrite': ['write', 'pwrite64', 'pwritev', 'pwritev2'],
    'fseek': ['lseek'],
    'ftell': ['lseek'],
    'rewind': ['lseek'],
    'fstat': ['fstat', 'newfstatat'],
    'close': ['close'],
    'read': ['read', 'pread64', 'preadv', 'preadv2'],
    'write': ['write', 'pwrite64', 'pwritev', 'pwritev2'],
    'readv': ['readv', 'preadv', 'preadv2'],
    'writev': ['writev', 'pwritev', 'pwritev2'],
    'lseek': ['lseek'],
    'stat': ['stat', 'fstat', 'lstat', 'newfstatat', 'statx'],
    'fstat': ['fstat'],
    'lstat': ['lstat'],
    'access': ['access', 'faccessat'],
    'chmod': ['chmod', 'fchmod', 'fchmodat'],
    'chown': ['chown', 'fchown', 'lchown', 'fchownat'],
    'truncate': ['truncate', 'ftruncate'],
    'ftruncate': ['ftruncate'],
    'rename': ['rename', 'renameat'],
    'unlink': ['unlink', 'unlinkat'],
    'link': ['link', 'linkat'],
    'symlink': ['symlink', 'symlinkat'],
    'readlink': ['readlink', 'readlinkat'],
    'mkdir': ['mkdir', 'mkdirat'],
    'rmdir': ['rmdir'],
    'creat': ['creat'],
    'utime': ['utime', 'utimes', 'futimesat', 'utimensat'],
    'utimes': ['utimes'],
    'futimesat': ['futimesat'],
    'utimensat': ['utimensat'],
    'getcwd': ['getcwd'],
    'chdir': ['chdir', 'fchdir'],
    'fchdir': ['fchdir'],
    'sync': ['sync', 'fsync', 'fdatasync', 'syncfs'],
    'fsync': ['fsync'],
    'fdatasync': ['fdatasync'],
    'syncfs': ['syncfs'],
    'flock': ['flock'],
    'fcntl': ['fcntl'],
    'ioctl': ['ioctl'],
    
    # 网络操作
    'socket': ['socket'],
    'bind': ['bind'],
    'listen': ['listen'],
    'accept': ['accept', 'accept4'],
    'connect': ['connect'],
    'send': ['sendto', 'sendmsg', 'sendmmsg'],
    'recv': ['recvfrom', 'recvmsg', 'recvmmsg'],
    'sendto': ['sendto'],
    'recvfrom': ['recvfrom'],
    'setsockopt': ['setsockopt'],
    'getsockopt': ['getsockopt'],
    'shutdown': ['shutdown'],
    
    # 内存操作
    'mmap': ['mmap'],
    'mmap64': ['mmap'],
    'mprotect': ['mprotect'],
    'munmap': ['munmap'],
    'mremap': ['mremap'],
    'brk': ['brk'],
    'mlock': ['mlock', 'mlock2'],
    'munlock': ['munlock'],
    'mlockall': ['mlockall'],
    'munlockall': ['munlockall'],
    'mincore': ['mincore'],
    'madvise': ['madvise'],
    'remap_file_pages': ['remap_file_pages'],
    
    # 进程操作
    'fork': ['fork'],
    'vfork': ['vfork'],
    'clone': ['clone'],
    'execve': ['execve', 'execveat'],
    'execveat': ['execveat'],
    'exit': ['exit', 'exit_group'],
    'exit_group': ['exit_group'],
    'wait': ['wait4'],
    'wait4': ['wait4'],
    'waitid': ['waitid'],
    'getpid': ['getpid'],
    'getppid': ['getppid'],
    'getuid': ['getuid'],
    'geteuid': ['geteuid'],
    'getgid': ['getgid'],
    'getegid': ['getegid'],
    'setuid': ['setuid', 'setreuid', 'setresuid'],
    'setgid': ['setgid', 'setregid', 'setresgid'],
    'setreuid': ['setreuid'],
    'setregid': ['setregid'],
    'setresuid': ['setresuid'],
    'setresgid': ['setresgid'],
    'getresuid': ['getresuid'],
    'getresgid': ['getresgid'],
    'getgroups': ['getgroups'],
    'setgroups': ['setgroups'],
    'getpgid': ['getpgid'],
    'setpgid': ['setpgid'],
    'getpgrp': ['getpgrp'],
    'setsid': ['setsid'],
    'getsid': ['getsid'],
    'setfsuid': ['setfsuid'],
    'setfsgid': ['setfsgid'],
    'nice': ['setpriority'],
    'getpriority': ['getpriority'],
    'setpriority': ['setpriority'],
    'sched_getparam': ['sched_getparam'],
    'sched_setparam': ['sched_setparam'],
    'sched_getscheduler': ['sched_getscheduler'],
    'sched_setscheduler': ['sched_setscheduler'],
    'sched_get_priority_max': ['sched_get_priority_max'],
    'sched_get_priority_min': ['sched_get_priority_min'],
    'sched_rr_get_interval': ['sched_rr_get_interval'],
    'sched_yield': ['sched_yield'],
    'sched_setaffinity': ['sched_setaffinity'],
    'sched_getaffinity': ['sched_getaffinity'],
    'prctl': ['prctl'],
    'arch_prctl': ['arch_prctl'],
    'personality': ['personality'],
    'ptrace': ['ptrace'],
    'getrusage': ['getrusage'],
    'getrlimit': ['getrlimit', 'prlimit64'],
    'setrlimit': ['setrlimit', 'prlimit64'],
    'prlimit64': ['prlimit64'],
    'times': ['times'],
    'sysinfo': ['sysinfo'],
    'uname': ['uname'],
    
    # 线程操作
    'gettid': ['gettid'],
    'set_tid_address': ['set_tid_address'],
    'restart_syscall': ['restart_syscall'],
    'get_thread_area': ['get_thread_area'],
    'set_thread_area': ['set_thread_area'],
    
    # 信号操作
    'signal': ['rt_sigaction'],
    'sigaction': ['rt_sigaction'],
    'rt_sigaction': ['rt_sigaction'],
    'rt_sigprocmask': ['rt_sigprocmask'],
    'rt_sigreturn': ['rt_sigreturn'],
    'rt_sigpending': ['rt_sigpending'],
    'rt_sigtimedwait': ['rt_sigtimedwait'],
    'rt_sigqueueinfo': ['rt_sigqueueinfo'],
    'rt_sigsuspend': ['rt_sigsuspend'],
    'sigaltstack': ['sigaltstack'],
    'kill': ['kill'],
    'tgkill': ['tgkill'],
    'tkill': ['tkill'],
    'signalfd': ['signalfd', 'signalfd4'],
    'signalfd4': ['signalfd4'],
    'timer_create': ['timer_create'],
    'timer_settime': ['timer_settime'],
    'timer_gettime': ['timer_gettime'],
    'timer_delete': ['timer_delete'],
    'timerfd_create': ['timerfd_create'],
    'timerfd_settime': ['timerfd_settime'],
    'timerfd_gettime': ['timerfd_gettime'],
    
    # 时间操作
    'time': ['time'],
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


class PolicyType(Enum):
    """策略类型枚举"""
    SECCOMP = 'seccomp'
    APPARMOR = 'apparmor'
    BOTH = 'both'


# 模块级别常量（测试需要）
# 名称 -> 系统调用号（x86_64）
@dataclass
class SyscallInfo:
    """系统调用信息数据类"""
    name: str
    number: int
    frequency: int = 0
    source: str = 'static'  # 'static' 或 'dynamic'
    arguments: List[str] = field(default_factory=lambda: [])
    context: str = ''
    architecture: str = 'x86_64'
    is_dangerous: bool = False
    category: str = ''


@dataclass
class SandboxPolicy:
    """沙箱策略数据类"""
    policy_type: PolicyType
    allowed_syscalls: List[Any] = field(default_factory=lambda: [])
    denied_syscalls: List[str] = field(default_factory=lambda: [])
    file_paths: List[str] = field(default_factory=lambda: [])
    network_rules: List[str] = field(default_factory=lambda: [])
    capabilities: List[str] = field(default_factory=lambda: [])
    policy_code: str = ''
    policy_content: str = ''
    summary: str = ''
    source_binary: str = ''
    risk_level: str = 'low'


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
        59: 'execve', 60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname',
        64: 'semget', 65: 'semop', 66: 'semctl', 67: 'shmdt', 68: 'msgget',
        69: 'msgsnd', 70: 'msgrcv', 71: 'msgctl', 72: 'fcntl', 73: 'flock',
        74: 'fsync', 75: 'fdatasync', 76: 'truncate', 77: 'ftruncate',
        78: 'getdents', 79: 'getcwd', 80: 'chdir', 81: 'fchdir',
        82: 'rename', 83: 'mkdir', 84: 'rmdir', 85: 'creat',
        86: 'link', 87: 'unlink', 88: 'symlink', 89: 'readlink',
        90: 'chmod', 91: 'fchmod', 92: 'chown', 93: 'fchown',
        94: 'lchown', 95: 'umask', 96: 'gettimeofday', 97: 'getrlimit',
        98: 'getrusage', 99: 'sysinfo', 100: 'times', 101: 'ptrace',
        102: 'getuid', 103: 'syslog', 104: 'getgid', 105: 'setuid',
        106: 'setgid', 107: 'geteuid', 108: 'getegid', 109: 'setpgid',
        110: 'getppid', 111: 'getpgrp', 112: 'setsid', 113: 'setreuid',
        114: 'setregid', 115: 'getgroups', 116: 'setgroups',
        117: 'setresuid', 118: 'getresuid', 119: 'setresgid',
        120: 'getresgid', 121: 'getpgid', 122: 'setfsuid',
        123: 'setfsgid', 124: 'getsid', 125: 'capget', 126: 'capset',
        127: 'rt_sigpending', 128: 'rt_sigtimedwait', 129: 'rt_sigqueueinfo',
        130: 'rt_sigsuspend', 131: 'sigaltstack', 132: 'utime',
        133: 'mknod', 134: 'uselib', 135: 'personality', 136: 'ustat',
        137: 'statfs', 138: 'fstatfs', 139: 'sysfs', 140: 'getpriority',
        141: 'setpriority', 142: 'sched_setparam', 143: 'sched_getparam',
        144: 'sched_setscheduler', 145: 'sched_getscheduler',
        146: 'sched_get_priority_max', 147: 'sched_get_priority_min',
        148: 'sched_rr_get_interval', 149: 'mlock', 150: 'munlock',
        151: 'mlockall', 152: 'munlockall', 153: 'vhangup', 154: 'pivot_root',
        155: 'prctl', 156: 'arch_prctl', 157: 'adjtimex', 158: 'setrlimit',
        159: 'chroot', 160: 'sync', 161: 'acct', 162: 'settimeofday',
        163: 'mount', 164: 'umount2', 165: 'swapon', 166: 'swapoff',
        167: 'reboot', 168: 'sethostname', 169: 'setdomainname',
        170: 'iopl', 171: 'ioperm', 172: 'create_module', 173: 'init_module',
        174: 'delete_module', 175: 'get_kernel_syms', 176: 'query_module',
        177: 'quotactl', 178: 'nfsservctl', 179: 'getpmsg', 180: 'putpmsg',
        181: 'afs_syscall', 182: 'tuxcall', 183: 'security',
        184: 'gettid', 185: 'readahead', 186: 'setxattr', 187: 'lsetxattr',
        188: 'fsetxattr', 189: 'getxattr', 190: 'lgetxattr',
        191: 'fgetxattr', 192: 'listxattr', 193: 'llistxattr',
        194: 'flistxattr', 195: 'removexattr', 196: 'lremovexattr',
        197: 'fremovexattr', 198: 'tkill', 199: 'time', 200: 'futex',
        201: 'sched_setaffinity', 202: 'sched_getaffinity',
        203: 'set_thread_area', 204: 'io_setup', 205: 'io_destroy',
        206: 'io_getevents', 207: 'io_submit', 208: 'io_cancel',
        209: 'get_thread_area', 210: 'epoll_create', 211: 'epoll_ctl_old',
        212: 'epoll_ctl', 213: 'epoll_wait', 214: 'remap_file_pages', 215: 'getdents64',
        216: 'set_tid_address', 217: 'restart_syscall', 218: 'semtimedop',
        219: 'fadvise64', 220: 'timer_create', 221: 'timer_settime',
        222: 'timer_gettime', 223: 'timer_getoverrun', 224: 'timer_delete',
        225: 'clock_settime', 226: 'clock_gettime', 227: 'clock_getres',
        228: 'clock_nanosleep', 229: 'exit_group', 230: 'epoll_wait_old',
        231: 'epoll_ctl_old2', 232: 'tgkill', 233: 'utimes', 234: 'mbind',
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
        311: 'getdents', 312: 'setns_dup', 313: 'getrandom', 314: 'memfd_create',
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
        'fopen': ['open', 'openat'],  # fopen -> open/openat
        'fclose': ['close'],
        'fread': ['read', 'pread64', 'readv', 'preadv'],
        'fwrite': ['write', 'pwrite64', 'writev', 'pwritev'],
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
    
    def __init__(, self)
        binary_path: str = None,
        output_dir: str = None,
        policy_type: PolicyType = PolicyType.SECCOMP
    ):
        """
        初始化沙箱策略生成器

        Args:
            binary_path: 二进制文件路径（可选）
            output_dir: 输出目录
            policy_type: 策略类型
        """
        self.binary_path = binary_path
        self.output_dir = output_dir or os.path.join(Config.DATA_DIR, 'sandbox_policies')
        self.policy_type = policy_type

        # 确保输出目录存在
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir, exist_ok=True)
            except Exception as e:
                logger.warning(f"创建输出目录失败: {e}")

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
            summary=summary)
        


    def generate_policy(, self)
        binary_path: str = None,
        policy_type: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        生成沙箱策略（统一入口）

        Args:
            binary_path: 二进制文件路径
            policy_type: 策略类型 ('seccomp', 'apparmor', 'both')
            **kwargs: 其他参数

        Returns:
            包含策略信息的字典
        """
        if binary_path is not None:
            self.binary_path = binary_path,
        if policy_type is not None:
            if policy_type in ['seccomp', 'apparmor', 'both']:
                self.policy_type = PolicyType(policy_type)
            else:
                logger.warning(f"未知的策略类型: {policy_type}, 使用默认值 seccomp")

        # 检查文件是否存在
        if self.binary_path is None or not os.path.exists(self.binary_path):
            return {
                'error': 'binary file not found',
                'binary_path': self.binary_path
            }

        try:
            policy = self.analyze()
            result = self.to_dict()
            result['policy_code'] = policy.policy_code
            result['policy_content'] = policy.policy_code
            result['source_binary'] = self.binary_path
            result['risk_level'] = self._assess_risk_level()
                [self.syscalls[s] for s in self.syscalls]
            
            return result
        except Exception as e:
            logger.error(f"[Sandbox] 生成策略失败: {e}")
            return {
                'error': str(e),
                'binary_path': self.binary_path
            }
    
    def _static_analyze_syscalls(self) -> None:
        """
        静态分析二进制推断系统调用
        """
        try:
            # 使用 radare2 获取导入函数
            result = subprocess.run()
                ['r2', '-q', '-c', 'is', self.binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            
            
            if result.returncode == 0:
                self._parse_symbols(result.stdout)
            
            # 使用 radare2 获取字符串
            result = subprocess.run()
                ['r2', '-q', '-c', 'iz', self.binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            
            
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
                        self.syscalls[syscall] = SyscallInfo()
                            name=syscall,
                            number=self._get_syscall_number(syscall),
                            source='static'
                        
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
                port = int(port_match.group(1

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
                self.syscalls[syscall] = SyscallInfo()
                    name=syscall,
                    number=self._get_syscall_number(syscall),
                    source='basic'
                
    
    def _get_syscall_number(self, name: str, architecture: str = 'x86_64') -> int:
        """
        获取系统调用号

        Args:
            name: 系统调用名称
            architecture: 架构 (默认 'x86_64')

        Returns:
            系统调用号
        """
        if architecture != 'x86_64':
            logger.warning(f"暂不支持架构: {architecture}，默认使用 x86_64")
        for num, syscall_name in self.SYSCALL_MAP_X64.items():
            if syscall_name == name:
                return num
        return -1

    def _infer_syscalls_from_imports(self, imports: List[str]) -> List[SyscallInfo]:
        """
        从导入函数推断系统调用

        Args:
            imports: 导入的函数名列表

        Returns:
            推断出的系统调用信息列表
        """
        syscalls = []
        seen = set()
        for imp in imports:
            # 去除前缀
            func_name = imp,
            if func_name.startswith('sym.'):
                func_name = func_name[4:]
            if func_name.startswith('imp.'):
                func_name = func_name[4:]

            # 映射到系统调用
            mapped = self.FUNCTION_TO_SYSCALL.get(func_name, [])
            for syscall in mapped:
                if syscall in seen:
                    continue
                seen.add(syscall)
                syscalls.append(SyscallInfo(
                    name=syscall,
                    number=self._get_syscall_number(syscall),
                    source='static',
                    architecture='x86_64'
                

        return syscalls

    def _identify_dangerous_syscalls(self, syscalls: List[SyscallInfo]) -> List[SyscallInfo]:
        """
        识别危险系统调用

        Args:
            syscalls: 系统调用信息列表

        Returns:
            危险系统调用信息列表
        """
        dangerous = []
        for sc in syscalls:
            if sc.name in self.DANGEROUS_SYSCALLS:
                sc.is_dangerous = True
                dangerous.append(sc)
            else:
                sc.is_dangerous = False,
        return dangerous

    def _assess_risk_level(self, syscalls: List[SyscallInfo]) -> str:
        """
        评估系统调用风险等级

        Args:
            syscalls: 系统调用信息列表

        Returns:
            风险等级: 'low' | 'medium' | 'high' | 'critical'
        """
        if not syscalls:
            return 'low'

        dangerous_count = sum()
            1 for s in syscalls
            if (s.is_dangerous if s.is_dangerous is not None else False) or s.name in self.DANGEROUS_SYSCALLS
        
        total = len(syscalls)

        if dangerous_count == 0:
            return 'low'

        # 高危系统调用（极高风险）
        critical_syscalls = {
            'kexec_load', 'kexec_file_load', 'init_module',
            'finit_module', 'delete_module', 'reboot',
            'swapon', 'swapoff', 'bpf', 'setns', 'unshare',
        }

        # 中度危险系统调用
        high_syscalls = {
            'execve', 'execveat', 'ptrace', 'mount', 'umount2',
            'chroot', 'pivot_root', 'userfaultfd', 'memfd_create',
            'setuid', 'setgid', 'setreuid', 'setregid', 'setresuid',
            'setresgid', 'setfsuid', 'setfsgid', 'capset', 'prctl',
            'acct', 'settimeofday', 'clock_settime', 'sethostname',
            'setdomainname', 'keyctl', 'add_key', 'request_key',
            'iopl', 'ioperm', 'syslog', 'clone', 'fork', 'vfork',
        }

        critical_hits = sum()
            1 for s in syscalls
            if s.name in critical_syscalls
        
        high_hits = sum(1 for s in syscalls if s.name in high_syscalls)

        # execve/ptrace 在 high_syscalls 中（不是 critical），单独命中返回 high
        if critical_hits > 0:
            return 'critical'
        if high_hits > 0 or dangerous_count >= 3:
            return 'high'
        if dangerous_count >= 1 or (total > 0 and dangerous_count / total > 0.05):
            return 'medium'
        return 'low'
    
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
    
    def _generate_seccomp_policy(, self)
        syscalls: List[SyscallInfo] = None,
        default_deny: bool = True
    ) -> str:
        """
        生成 seccomp-bpf 策略

        Args:
            syscalls: 系统调用信息列表
            default_deny: 是否使用默认拒绝

        Returns:
            seccomp 策略代码
        """
        if syscalls is None:
            syscalls = [self.syscalls[s] for s in self.syscalls if s in self.syscalls]

        syscall_names = sorted([s.name for s in syscalls]) if syscalls else sorted(self.allowed_syscalls)

        lines = [
            '// Seccomp-BPF Policy for ' + os.path.basename(self.binary_path or 'unknown'),
            '// Generated by LLM-Assisted Binary Vulnerability Analysis Tool',
            '//',
            f'// Policy: Default {"DENY" if default_deny else "ALLOW"}, explicit {"DENY" if default_deny else "ALLOW"}',
            '',
            '#include <seccomp.h>',
            '#include <sys/syscall.h>',
            '',
            '// Allowed syscalls:',
            '// ' + ', '.join(syscall_names),
            '',
            'static int install_seccomp_filter() {',
            '    scmp_filter_ctx ctx;',
            '    int rc = 0;',
            '',
            f'    ctx = seccomp_init(SCMP_ACT_KILL);  // default action: KILL',
            '',
        ]

        # 为每个允许的系统调用添加规则
        for syscall in syscall_names:
            lines.append(f'    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS({syscall}), 0);')
            lines.append(f'    if (rc != 0) return rc;')

        lines.extend([)
            '',
            '    rc = seccomp_load(ctx);',
            '    seccomp_release(ctx);',
            '    return rc;',
            '}',
            '',
            '// BPF-style variant (for reference)',
            '/*',
            '#include <linux/seccomp.h>',
            '#include <linux/filter.h>',
            '#include <linux/bpf.h>',
            '#include <stddef.h>',
            '',
            'static struct sock_filter seccomp_filter[] = {',
            '    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),',
            '    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),',
            f'    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),',
            '    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),',
        ]

        for syscall in syscall_names:
            num = self._get_syscall_number(syscall)
            if num >= 0:
                lines.append(f'    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_{syscall}, 0, 1),')
                lines.append('    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),')

        if default_deny:
            lines.append(f'    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),')
        else:
            lines.append(f'    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),')
        lines.append('};')
        lines.append('*/')

        lines.extend([)
            '',
            '// Python wrapper using libseccomp',
            '/*',
            'import seccomp',
            '',
            'def setup_seccomp():',
            '    ctx = seccomp.SyscallFilter(seccomp.KILL)',
        ]

        for syscall in syscall_names:
            lines.append(f'    ctx.add_rule(seccomp.ALLOW, "{syscall}")')

        lines.extend([)
            '    ctx.load()',
            '*/',
        ]

        return '\n'.join(lines)
    
    def _generate_apparmor_policy(, self)
        syscalls: List[SyscallInfo] = None,
        file_paths: List[str] = None,
        network_permissions: Dict[str, List[str]] = None
    ) -> str:
        """
        生成 AppArmor 策略

        Args:
            syscalls: 系统调用信息列表
            file_paths: 文件路径列表
            network_permissions: 网络权限配置

        Returns:
            AppArmor 策略代码
        """
        if file_paths is None:
            file_paths = sorted(self.file_paths)
        if network_permissions is None:
            network_permissions = {}
        if syscalls is None:
            syscall_names = sorted(self.allowed_syscalls)
        else:
            syscall_names = sorted([s.name for s in syscalls])

        binary_name = os.path.basename(self.binary_path) if self.binary_path else 'unknown'

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
        if file_paths:
            for path in file_paths[:20]:
                if path.startswith('/'):
                    lines.append(f'  {path} r,')
        else:
            lines.append('  /** r,')

        lines.extend([)
            '',
            '  # Network rules',
        ]

        # 网络规则
        if network_permissions:
            if 'outbound' in network_permissions:
                lines.append('  network inet stream,')
                lines.append('  network inet dgram,')
            else:
                lines.append('  network inet,')
        elif self.network_ports:
            for port in sorted(self.network_ports)[:10]:
                lines.append(f'  network inet stream,')
                lines.append(f'  network inet dgram,')
        else:
            lines.append('  network inet,')

        lines.extend([)
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
        ]

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
            lines.extend([)
                '',
                '拒绝的危险系统调用:',
            ]
            for syscall in sorted(self.denied_syscalls):
                reason = self.DANGEROUS_SYSCALLS.get(syscall, '未知')
                lines.append(f'  - {syscall}: {reason}')
        
        return '\n'.join(lines)
    
    def _save_policy(, self)
        policy_code: Any = None,
        output_path: str = None
    ) -> str:
        """
        保存策略文件

        Args:
            policy_code: 策略代码字符串或 SandboxPolicy 对象
            output_path: 输出路径

        Returns:
            保存的文件路径
        """
        # 兼容两种调用方式:
        # 1) _save_policy(policy_code_str) - 旧版签名

        # 2) _save_policy(policy_obj, output_path) - 测试用
        if isinstance(policy_code, SandboxPolicy):
            policy_obj = policy_code
            policy_code_str = policy_obj.policy_code or policy_obj.policy_content or '',
            if output_path is None:
                binary_name = os.path.basename(self.binary_path) if self.binary_path else 'unknown'
                ext = '.c' if policy_obj.policy_type == PolicyType.SECCOMP else '.profile'
                output_path = os.path.join(self.output_dir, f'{binary_name}_policy{ext}')
        else:
            policy_code_str = policy_code or ''
            policy_obj = None,
            if output_path is None:
                binary_name = os.path.basename(self.binary_path) if self.binary_path else 'unknown',
                if self.policy_type == PolicyType.SECCOMP:
                    filename = f'{binary_name}_seccomp.c'
                elif self.policy_type == PolicyType.APPARMOR:
                    filename = f'{binary_name}_apparmor.profile'
                else:
                    filename = f'{binary_name}_sandbox_policy.txt'
                output_path = os.path.join(self.output_dir, filename)

        # 确保输出目录存在
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                logger.warning(f"创建输出目录失败: {e}")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(policy_code_str)

        logger.info(f"[Sandbox] 策略已保存: {output_path}")
        return output_path
    
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
            docker_check = subprocess.run()
                ['docker', '--version'],
                capture_output=True,
                timeout=5
            
            
            if docker_check.returncode != 0:
                result['message'] = 'Docker 不可用，无法测试策略',
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
                        self.syscalls[syscall_name] = SyscallInfo()
                            name=syscall_name,
                            number=syscall_number,
                            source='dynamic'
                        
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


def generate_sandbox_policy(, binary_path: str, policy_type: str = 'seccomp', output_dir: str = None, trace_file: str = None) -> Dict[str, Any]:
    """
    生成沙箱策略的便捷函数

    Args:
        binary_path: 二进制文件路径
        policy_type: 策略类型 ('seccomp', 'apparmor', 'both')
        output_dir: 输出目录
        trace_file: 动态追踪日志文件

    Returns:
        包含策略信息的字典
    """
    policy_enum = PolicyType(policy_type) if policy_type in ['seccomp', 'apparmor', 'both'] else PolicyType.SECCOMP

    generator = SandboxPolicyGenerator(binary_path, output_dir, policy_enum)

    if trace_file:
        generator.load_dynamic_trace(trace_file)

    # 使用统一入口 generate_policy 以返回字典
    return generator.generate_policy(binary_path=binary_path, policy_type=policy_type