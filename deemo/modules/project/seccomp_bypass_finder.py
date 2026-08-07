# Seccomp沙箱绕过路径发现器: BPF过滤器解析→可用syscall映射→逃逸路径
# 技术问题: seccomp-tools dump输出BPF过滤器但需要手工分析哪些syscall
#   可用、哪些被阻止、哪些syscall可以替代被阻止的syscall.
#   例如: open被阻止但openat可用→通过/proc/self/mem读写任意内存.
#   DEF CON 33 披露了11个eBPF verifier漏洞,
#   但经典seccomp-bpf绕过 (不依赖eBPF漏洞) 的分析仍需手工
# 解决手段: 解析seccomp-BPF过滤器, 自动映射:
#   1. 系统调用矩阵: 每个syscall→{allowed, killed, errno, trapped}
#   2. 替代路径: 对每个被阻止的syscall, 查找功能等价的未阻止syscall
#   3. 逃逸评估: 检测/proc/self/mem可用性、命名空间逃逸可能性、
#      prctl/seccomp(SECCOMP_SET_MODE_FILTER)的自身修改能力
# 技术效果: 自动化了通常需要30-60分钟的手工BPF过滤器审计
#
#   经典seccomp-bpf绕过技术 (基于CTF writeup和公开研究)
#   CTF ORW绕过体系 — open→openat→/proc/self/mem链
#   sbe_core sandbox — KILL/ERRNO双列表架构
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# syscall名称→编号映射 (x86_64, 常见子集)
_SYSCALL_X86_64: Dict[str, int] = {
    "read": 0, "write": 1, "open": 2, "close": 3,
    "stat": 4, "fstat": 5, "mmap": 9, "mprotect": 10,
    "munmap": 11, "brk": 12, "rt_sigaction": 13,
    "rt_sigprocmask": 14, "ioctl": 16, "pread64": 17,
    "pwrite64": 18, "readv": 19, "writev": 20,
    "access": 21, "pipe": 22, "select": 23,
    "sched_yield": 24, "mremap": 25, "mincore": 27,
    "madvise": 28, "shmget": 29, "shmat": 30,
    "dup": 32, "dup2": 33, "nanosleep": 35,
    "getitimer": 36, "alarm": 37, "setitimer": 38,
    "getpid": 39, "sendfile": 40, "socket": 41,
    "connect": 42, "accept": 43, "sendto": 44,
    "recvfrom": 45, "sendmsg": 46, "recvmsg": 47,
    "shutdown": 48, "bind": 49, "listen": 50,
    "getsockname": 51, "getpeername": 52, "socketpair": 53,
    "setsockopt": 54, "getsockopt": 55, "clone": 56,
    "fork": 57, "vfork": 58, "execve": 59,
    "exit": 60, "wait4": 61, "kill": 62,
    "uname": 63, "fcntl": 72, "flock": 73,
    "fsync": 74, "fdatasync": 75, "truncate": 76,
    "ftruncate": 77, "getdents": 78, "getcwd": 79,
    "chdir": 80, "fchdir": 81, "rename": 82,
    "mkdir": 83, "rmdir": 84, "creat": 85,
    "link": 86, "unlink": 87, "symlink": 88,
    "readlink": 89, "chmod": 90, "fchmod": 91,
    "chown": 92, "fchown": 93, "umask": 95,
    "gettimeofday": 96, "getrlimit": 97, "getrusage": 98,
    "sysinfo": 99, "times": 100, "ptrace": 101,
    "getuid": 102, "syslog": 103, "getgid": 104,
    "setuid": 105, "setgid": 106, "geteuid": 107,
    "getegid": 108, "setpgid": 109, "getppid": 110,
    "getpgrp": 111, "setsid": 112, "setreuid": 113,
    "setregid": 114, "getgroups": 115, "setgroups": 116,
    "setresuid": 117, "getresuid": 118, "setresgid": 119,
    "getresgid": 120, "getpgid": 121, "setfsuid": 122,
    "setfsgid": 123, "getsid": 124, "capget": 125,
    "capset": 126, "sigaltstack": 131, "vfork": 58,
    "personality": 135, "statfs": 137, "fstatfs": 138,
    "getpriority": 140, "setpriority": 141, "sched_setparam": 142,
    "sched_getparam": 143, "sched_setscheduler": 144,
    "sched_getscheduler": 145, "mlock": 149, "munlock": 150,
    "mlockall": 151, "munlockall": 152, "sched_get_priority_max": 146,
    "prctl": 157, "arch_prctl": 158, "setrlimit": 160,
    "getrlimit_": 160, "gettid": 186, "futex": 202,
    "openat": 257, "newfstatat": 262, "preadv": 295,
    "pwritev": 296, "seccomp": 317, "getrandom": 318,
    "memfd_create": 319, "execveat": 322, "statx": 332,
    "process_vm_readv": 347, "process_vm_writev": 348,
    "pidfd_open": 434, "close_range": 436, "openat2": 437,
}

# 功能等价替代: blocked_syscall → [(alternative_syscall, description)]
_SYSCALL_ALTERNATIVES: Dict[str, List[Tuple[str, str]]] = {
    "open":  [("openat", "openat(AT_FDCWD, path, flags) 等价open"),
              ("openat2", "openat2(AT_FDCWD, path, &how) 现代化版本")],
    "read":  [("pread64", "pread64(fd, buf, len, offset) 需已知fd"),
              ("readv", "readv(fd, iov, iovcnt) 向量读")],
    "write": [("pwrite64", "pwrite64(fd, buf, len, offset) 需已知fd"),
              ("writev", "writev(fd, iov, iovcnt) 向量写"),
              ("process_vm_writev", "跨进程写入 (需ptrace权限)")],
    "fork":  [("clone", "clone(flags) 灵活进程创建")],
    "execve":[("execveat", "execveat(AT_FDCWD, path, argv, envp, 0) 等价execve")],
    "close": [("close_range", "close_range(first, last, flags) 批量关闭")],
    "stat":  [("newfstatat", "newfstatat(AT_FDCWD, path, ...) 等价stat"),
              ("statx", "statx(AT_FDCWD, path, 0, STATX_ALL, buf) 扩展stat")],
    "mmap":  [("mremap", "重映射现有映射 (非完整替代)")],
}

# 高价值逃逸相关syscall (即使沙箱中也常被允许的)
_ESCAPE_INTERESTING = {
    "openat": "通过/proc/self/mem读写任意内存",
    "prctl": "修改进程属性/设置seccomp",
    "seccomp": "修改或移除自身seccomp过滤器",
    "process_vm_writev": "跨进程写入内存",
    "process_vm_readv": "跨进程读取内存",
    "memfd_create": "创建内存文件描述符",
    "ptrace": "附加到其他进程",
    "clone": "创建子进程/线程 (可能继承受限seccomp)",
    "pidfd_open": "通过pidfd操作其他进程",
}


@dataclass
class SeccompAnalysis:
    """seccomp过滤器分析结果."""
    total_rules: int
    allowed_syscalls: List[str]
    killed_syscalls: List[str]
    errno_syscalls: List[Tuple[str, int]]  # (name, errno_value)
    alternative_paths: List[Tuple[str, str, str]]
    escape_vectors: List[Tuple[str, str]]
    overall_risk: str  # 'locked_down' | 'restricted' | 'moderate' | 'open'


class SeccompBypassFinder:
    """seccomp沙箱绕过路径发现器.

    从BPF过滤器规则文本或syscall列表分析可用逃逸路径.
    """

    def analyze_from_blocklist(self, blocked_syscalls: List[str],
                               kill_on_violation: bool = True
                               ) -> SeccompAnalysis:
        """从阻止列表分析."""
        blocked = set(blocked_syscalls)
        all_syscalls = set(_SYSCALL_X86_64.keys())
        allowed = all_syscalls - blocked
        alt_paths = []
        for blocked_sys in blocked_syscalls:
            if blocked_sys in _SYSCALL_ALTERNATIVES:
                for alt, desc in _SYSCALL_ALTERNATIVES[blocked_sys]:
                    if alt in allowed:
                        alt_paths.append((blocked_sys, alt, desc))
        escape = []
        for interesting_sys, desc in _ESCAPE_INTERESTING.items():
            if interesting_sys in allowed:
                escape.append((interesting_sys, desc))
        risk = self._assess_risk(allowed, blocked, kill_on_violation)
        return SeccompAnalysis(
            total_rules=len(blocked),
            allowed_syscalls=sorted(allowed)[:30],
            killed_syscalls=sorted(blocked_syscalls),
            errno_syscalls=[],
            alternative_paths=alt_paths,
            escape_vectors=escape,
            overall_risk=risk)

    def analyze_from_bpf(self, bpf_rules: List[str]) -> SeccompAnalysis:
        """从BPF过滤器规则文本分析.

        简化解析: 识别 BPF_JMP+BPF_JEQ 指令中的syscall编号.
        """
        blocked: Set[str] = set()
        killed: Set[str] = set()
        errno: List[Tuple[str, int]] = []
        for line in bpf_rules:
            # 匹配 seccomp-tools dump格式: ".... if (arch != 0x...) goto KILL"
            m = re.search(r'if\s*\(\s*\w+\s*!=\s*(0x[0-9a-fA-F]+)\s*\)\s*goto\s+KILL',
                         line)
            if m:
                val = int(m.group(1), 16)
                for name, num in _SYSCALL_X86_64.items():
                    if num == val:
                        killed.add(name)
            # 匹配 errno返回: "return ERRNO(13)" → EACCES
            m = re.search(r'return\s+ERRNO\((\d+)\)', line)
            if m:
                errno_val = int(m.group(1))
                for name, num in _SYSCALL_X86_64.items():
                    if name not in killed and name not in blocked:
                        errno.append((name, errno_val))
        # 反推允许的syscall
        import re
        all_set = set(_SYSCALL_X86_64.keys())
        blocked = killed | set(e[0] for e in errno)
        allowed = all_set - blocked
        alt_paths = []
        for bs in blocked:
            if bs in _SYSCALL_ALTERNATIVES:
                for alt, desc in _SYSCALL_ALTERNATIVES[bs]:
                    if alt in allowed:
                        alt_paths.append((bs, alt, desc))
        escape = []
        for interesting_sys, desc in _ESCAPE_INTERESTING.items():
            if interesting_sys in allowed:
                escape.append((interesting_sys, desc))
        risk = self._assess_risk(allowed, blocked, len(killed) > 0)
        return SeccompAnalysis(
            total_rules=len(bpf_rules),
            allowed_syscalls=sorted(allowed)[:30],
            killed_syscalls=sorted(killed),
            errno_syscalls=errno,
            alternative_paths=alt_paths,
            escape_vectors=escape,
            overall_risk=risk)

    def _assess_risk(self, allowed: Set[str], blocked: Set[str],
                     kill_on_violation: bool) -> str:
        critical_leaked = {
            "ptrace", "process_vm_writev", "process_vm_readv", "seccomp"}
        high_risk = {"openat", "openat2", "open", "mmap", "mprotect",
                     "memfd_create", "prctl", "clone"}
        leaked_critical = allowed & critical_leaked
        leaked_high = allowed & high_risk
        if leaked_critical:
            return "open"
        if len(leaked_high) >= 3:
            return "moderate"
        if leaked_high:
            return "restricted"
        if not kill_on_violation:
            return "restricted"  # errno返回可被探测
        return "locked_down"

    def generate_orw_chain(self, fd: int = 0,
                           file_path: str = "/flag"
                           ) -> List[str]:
        """生成标准Open-Read-Write绕过链.

        假设seccomp阻止了open但允许openat:
          openat(AT_FDCWD, path, O_RDONLY) → read → write.
        若open/read/write全部阻止:
          openat + sendfile(fd_out, fd_in, NULL, size) → 零拷贝传输.
        """
        return [
            f"int fd = openat(AT_FDCWD, \"{file_path}\", O_RDONLY);",
            f"// 或通过/proc/self/mem: fd=openat(AT_FDCWD, \"/proc/self/mem\", O_RDWR)",
            "if (fd < 0) {",
            "    // fallback: sendfile或splice",
            "    fd = openat(AT_FDCWD, path, O_RDONLY);",
            "}",
            "char buf[256];",
            f"ssize_t n = read(fd, buf, sizeof(buf));  // 或 pread64",
            "write(1, buf, n);  // 或 sendto(1, buf, n, 0, NULL, 0)",
        ]


import re  # noqa: E402 (用于analyze_from_bpf)
