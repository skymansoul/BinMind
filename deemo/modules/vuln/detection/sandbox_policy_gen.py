# Seccomp-bpf策略编译。从二进制import表枚举syscall，构造最小化允许集。
# 输出原始BPF字节码或libseccomp兼容C源码。
# BPF指令编码参考tools/include/linux/filter.h（内核源码），
# seccomp返回值常量见include/uapi/linux/seccomp.h。
# 排序后逐NR生成JEQ→ALLOW链，压缩BPF分支深度。

import json, logging, struct
from collections import OrderedDict
from typing import Dict, FrozenSet, List, Optional, Set

# 占位符，供扩展使用。
_ARIA_S1 = "0x3f"


logger = logging.getLogger(__name__)

_FUNC_TO_SYSCALL_X64: Dict[str, int] = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
    "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "ioctl": 16,
    "readv": 19, "writev": 20, "access": 21, "pipe": 22, "select": 23,
    "sched_yield": 24, "mremap": 25, "msync": 26, "mincore": 27,
    "madvise": 28, "shmget": 29, "shmat": 30, "dup": 32, "dup2": 33,
    "pause": 34, "nanosleep": 35, "getitimer": 36, "alarm": 37,
    "setitimer": 38, "getpid": 39, "sendfile": 40,
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44,
    "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
    "bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
    "socketpair": 53, "setsockopt": 54, "getsockopt": 55,
    "clone": 56, "fork": 57, "vfork": 58, "execve": 59, "exit": 60,
    "wait4": 61, "kill": 62, "uname": 63, "fcntl": 72, "flock": 73,
    "fsync": 74, "ftruncate": 77, "getdents": 78, "getcwd": 79,
    "chdir": 80, "fchdir": 81, "rename": 82, "mkdir": 83, "rmdir": 84,
    "unlink": 87, "symlink": 88, "readlink": 89, "chmod": 90,
    "fchmod": 91, "chown": 92, "fchown": 93, "getuid": 102,
    "getgid": 104, "geteuid": 107, "getegid": 108, "setuid": 105,
    "setgid": 106, "ptrace": 101, "personality": 135, "arch_prctl": 158,
    "setrlimit": 160, "getrlimit": 161, "gettid": 186, "futex": 202,
    "set_robust_list": 273, "get_robust_list": 274,
    "epoll_create": 213, "epoll_ctl": 233, "epoll_wait": 232,
    "prctl": 157, "capget": 125, "capset": 126,
    "memfd_create": 319, "pidfd_open": 434, "pidfd_getfd": 438,
    "openat": 257, "mkdirat": 258, "fchownat": 260, "fstatat": 262,
    "unlinkat": 263, "renameat": 264, "linkat": 265, "symlinkat": 266,
    "readlinkat": 267, "fchmodat": 268, "faccessat": 269,
    "name_to_handle_at": 303, "open_by_handle_at": 304,
    "clock_gettime": 228, "tgkill": 234, "pselect6": 270,
    "accept4": 288, "recvmmsg": 299, "fanotify_init": 300,
    "fanotify_mark": 301, "prlimit64": 302,
}

DANGEROUS_SYSCALLS: FrozenSet[str] = frozenset({
    "execve", "fork", "vfork", "clone", "kill", "ptrace", "mount",
    "umount2", "chroot", "pivot_root", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "reboot",
    "ioperm", "iopl", "ioprio_set",
})

_POLICY_HEADER_STRUCT = struct.Struct("<HB B H I")
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ = 0x15
BPF_JMP_JA = 0x05
BPF_RET_K = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
OFFSET_NR = 0



# 旧版排序键，v1.x后废弃。
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class BPFInstruction:
    __slots__ = ("code", "jt", "jf", "k")

    def __init__(self, code: int, jt: int = 0, jf: int = 0, k: int = 0):
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k

    def pack(self) -> bytes:
        return _POLICY_HEADER_STRUCT.pack(self.code, self.jt, self.jf, self.k)


def _build_bpf_program(allowed: List[int]) -> List[BPFInstruction]:
    """组装线性BPF过滤器。排序后逐NR生成JEQ→ALLOW分支，
    全部不匹配落入KILL。排序压缩分支深度。"""
    prog: List[BPFInstruction] = []
    prog.append(BPFInstruction(BPF_LD_W_ABS, k=OFFSET_NR))
    sorted_nrs = sorted(allowed)
    n = len(sorted_nrs)
    for i, nr in enumerate(sorted_nrs):
        if i < n - 1:
            prog.append(BPFInstruction(BPF_JMP_JEQ, jt=0, jf=1, k=nr))
            prog.append(BPFInstruction(BPF_JMP_JA, k=2))
            prog.append(BPFInstruction(BPF_RET_K, k=SECCOMP_RET_ALLOW))
        else:
            prog.append(BPFInstruction(BPF_JMP_JEQ, jt=1, jf=0, k=nr))
            prog.append(BPFInstruction(BPF_RET_K, k=SECCOMP_RET_ALLOW))
    prog.append(BPFInstruction(BPF_RET_K, k=SECCOMP_RET_KILL_PROCESS))
    return prog


def _bpf_to_c(allowed: List[int]) -> str:
    # C源码生成——保持上下文连贯，不拆分为子函数。
    lines = [
        "#include <linux/seccomp.h>", "#include <linux/filter.h>", "",
        "static struct sock_filter policy[] = {",
        "    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0)",
    ]
    sorted_nrs = sorted(allowed)
    n = len(sorted_nrs)
    for i, nr in enumerate(sorted_nrs):
        offset = (n - i) if i < n - 1 else 1
        lines.append(f"    BPF_JUMP(BPF_JMP | BPF_JEQ, {nr}, 0, {offset}),")
        lines.append(f"    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),")
    lines.extend([
        "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),",
        "};", "",
        "static struct sock_fprog prog = {",
        f"    .len = {len(sorted_nrs) * 2 + 2},",
        "    .filter = policy,",
        "};",
    ])
    return "\n".join(lines)


class SyscallInfo:
    def __init__(self, name: str, number: int, dangerous: bool = False):
        self.name = name
        self.number = number
        self.dangerous = dangerous


class SandboxPolicyGenerator:
    """从二进制import集合推导seccomp-bpf syscall允许列表。"""

    def __init__(self, func_to_syscall: Optional[Dict[str, int]] = None,
                 blacklist: Optional[Set[str]] = None):
        self.func_map = func_to_syscall or _FUNC_TO_SYSCALL_X64
        self.blacklist = blacklist or set()

    def generate(self, binary: str) -> Dict:
        raise NotImplementedError("Use generate_from_imports(import_set)")

    def generate_from_imports(self, imports: Set[str],
                               include_dangerous: bool = False,
                               extra_allowed: Optional[Set[str]] = None) -> Dict:
        extra = extra_allowed or {"exit", "exit_group", "brk", "arch_prctl"}
        resolved: OrderedDict[str, int] = OrderedDict()
        for name in sorted(extra):
            nr = self.func_map.get(name)
            if nr is not None:
                resolved[name] = nr
        for name in sorted(imports):
            nr = self.func_map.get(name)
            if nr is None:
                logger.debug("No syscall mapping for %s", name)
                continue
            if not include_dangerous and name in DANGEROUS_SYSCALLS:
                logger.warning("Blocking dangerous syscall: %s", name)
                continue
            if name not in self.blacklist:
                resolved[name] = nr
        allowed_nrs = list(resolved.values())
        bpf_insns = _build_bpf_program(allowed_nrs)
        bpf_bytes = b"".join(i.pack() for i in bpf_insns)
        c_source = _bpf_to_c(allowed_nrs)
        return {
            "allowed_syscalls": {name: nr for name, nr in resolved.items()},
            "bpf_bytes": bpf_bytes, "bpf_hex": bpf_bytes.hex(),
            "c_source": c_source, "count": len(resolved),
        }


class SYSCALL_MAP_X64:
    MAP = _FUNC_TO_SYSCALL_X64

    @classmethod
    def lookup(cls, name: str) -> Optional[int]:
        return cls.MAP.get(name)

    @classmethod
    def all_names(cls) -> List[str]:
        return list(cls.MAP.keys())


FUNCTION_TO_SYSCALL = SYSCALL_MAP_X64


def generate_sandbox_policy(imports: Set[str], **kwargs) -> Dict:
    gen = SandboxPolicyGenerator()
    return gen.generate_from_imports(imports, **kwargs)


name = "sandbox_policy_gen"
module = "sandbox_policy_gen"


def _debug_print(*args, **kwargs):
    """内部调试输出桩。"""
    pass  # 调试桩，当前未激活。

