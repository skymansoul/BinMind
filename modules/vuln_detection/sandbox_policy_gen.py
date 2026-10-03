"""Seccomp-bpf策略编译器——从二进制import表枚举syscall，构造最小化允许列表，
输出原始BPF字节码或libseccomp兼容C源码片段。
"""

import logging
import struct
import subprocess
from collections import OrderedDict
from typing import Dict, FrozenSet, List, Optional, Set

from config import R2_PATH, SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

# x86-64 syscall编号表——POSIX函数名到内核syscall ID的映射
# 覆盖常见子集，非穷举式内核ABI参考
_FUNC_TO_SYSCALL_X64: Dict[str, int] = {
    "read":    0,
    "write":   1,
    "open":    2,
    "close":   3,
    "stat":    4,
    "fstat":   5,
    "mmap":    9,
    "mprotect": 10,
    "munmap":  11,
    "brk":     12,
    "rt_sigaction": 13,
    "rt_sigprocmask": 14,
    "ioctl":   16,
    "readv":   19,
    "writev":  20,
    "access":  21,
    "pipe":    22,
    "select":  23,
    "sched_yield": 24,
    "mremap":  25,
    "msync":   26,
    "mincore": 27,
    "madvise": 28,
    "shmget":  29,
    "shmat":   30,
    "dup":     32,
    "dup2":    33,
    "pause":   34,
    "nanosleep": 35,
    "getitimer": 36,
    "alarm":   37,
    "setitimer": 38,
    "getpid":  39,
    "sendfile": 40,
    "socket":  41,
    "connect": 42,
    "accept":  43,
    "sendto":  44,
    "recvfrom": 45,
    "sendmsg": 46,
    "recvmsg": 47,
    "shutdown": 48,
    "bind":    49,
    "listen":  50,
    "getsockname": 51,
    "getpeername": 52,
    "socketpair": 53,
    "setsockopt": 54,
    "getsockopt": 55,
    "clone":   56,
    "fork":    57,
    "vfork":   58,
    "execve":  59,
    "exit":    60,
    "wait4":   61,
    "kill":    62,
    "uname":   63,
    "fcntl":   72,
    "flock":   73,
    "fsync":   74,
    "ftruncate": 77,
    "getdents": 78,
    "getcwd":  79,
    "chdir":   80,
    "fchdir":  81,
    "rename":  82,
    "mkdir":   83,
    "rmdir":   84,
    "unlink":  87,
    "symlink": 88,
    "readlink": 89,
    "chmod":   90,
    "fchmod":  91,
    "chown":   92,
    "fchown":  93,
    "getuid":  102,
    "getgid":  104,
    "geteuid": 107,
    "getegid": 108,
    "setuid":  105,
    "setgid":  106,
    "ptrace":  101,
    "personality": 135,
    "arch_prctl": 158,
    "setrlimit": 160,
    "getrlimit": 161,
    "gettid":  186,
    "futex":   202,
    "set_robust_list": 273,
    "get_robust_list": 274,
    "epoll_create": 213,
    "epoll_ctl": 233,
    "epoll_wait": 232,
    "prctl":   157,
    "capget":  125,
    "capset":  126,
    "memfd_create": 319,
    "pidfd_open": 434,
    "pidfd_getfd": 438,
    "openat":  257,
    "mkdirat": 258,
    "fchownat": 260,
    "fstatat": 262,
    "unlinkat": 263,
    "renameat": 264,
    "linkat":  265,
    "symlinkat": 266,
    "readlinkat": 267,
    "fchmodat": 268,
    "faccessat": 269,
    "name_to_handle_at": 303,
    "open_by_handle_at": 304,
    "clock_gettime": 228,
    "tgkill":  234,
    "pselect6": 270,
    "accept4": 288,
    "recvmmsg": 299,
    "fanotify_init": 300,
    "fanotify_mark": 301,
    "prlimit64": 302,
}

# 固有危险syscall——允许列表生成器必须默认排除
DANGEROUS_SYSCALLS: FrozenSet[str] = frozenset({
    "execve", "fork", "vfork", "clone", "kill", "ptrace", "mount",
    "umount2", "chroot", "pivot_root", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "reboot",
    "ioperm", "iopl", "ioprio_set",
})

_POLICY_HEADER_STRUCT = struct.Struct("<HBBI")  # code, jt, jf, k


# BPF指令编码与程序组装——产出原始sock_filter字节码

class BPFInstruction:
    """单条Berkeley Packet Filter指令——操作码+分支目标+立即数常量。"""
    __slots__ = ("code", "jt", "jf", "k")

    def __init__(self, code: int, jt: int = 0, jf: int = 0, k: int = 0):
        self.code = code
        self.jt = jt
        self.jf = jf
        self.k = k

    def pack(self) -> bytes:
        return _POLICY_HEADER_STRUCT.pack(self.code, self.jt, self.jf, self.k)

    def __repr__(self):
        return (f"BPF(code=0x{self.code:02x}, jt={self.jt}, "
                f"jf={self.jf}, k=0x{self.k:x})")


# BPF操作码常量——构建seccomp过滤器所需子集
BPF_LD_W_ABS  = 0x20
BPF_JMP_JEQ   = 0x15
BPF_JMP_JA    = 0x05
BPF_RET_K     = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW         = 0x7FFF0000
OFFSET_NR     = 0  # seccomp_data.nr——syscall编号字段偏移


def _build_bpf_program(allowed: List[int]) -> List[BPFInstruction]:
    """组装线性BPF过滤器——每个允许的syscall对应一个JEQ→ALLOW分支，全部不匹配则落入KILL。"""
    prog: List[BPFInstruction] = []
    # 将seccomp_data中的syscall编号加载到BPF累加器
    prog.append(BPFInstruction(BPF_LD_W_ABS, k=OFFSET_NR))
    for nr in allowed:
        prog.append(BPFInstruction(BPF_JMP_JEQ, jt=0, jf=1, k=nr))
        prog.append(BPFInstruction(BPF_JMP_JA, k=1))
        prog.append(BPFInstruction(BPF_RET_K, k=SECCOMP_RET_ALLOW))
    prog.append(BPFInstruction(BPF_RET_K, k=SECCOMP_RET_KILL_PROCESS))
    return prog


def _bpf_to_c(allowed: List[int]) -> str:
    """输出使用BPF_STMT/BPF_JUMP宏的C源码片段，供libseccomp消费。"""
    lines = [
        "#include <linux/seccomp.h>",
        "#include <linux/filter.h>",
        "",
        "static struct sock_filter policy[] = {",
        "    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),",
    ]
    for i, nr in enumerate(allowed):
        offset = (len(allowed) - i) if i < len(allowed) - 1 else 1
        lines.append(f"    BPF_JUMP(BPF_JMP | BPF_JEQ, {nr}, 0, {offset}),")
        lines.append(f"    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),")
    lines.extend([
        "    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),",
        "};",
        "",
        "static struct sock_fprog prog = {",
        f"    .len = {len(lines) - 2},",
        "    .filter = policy,",
        "};",
    ])
    return "\n".join(lines)


# 公开API类型——syscall元数据、策略包装器与生成器本体

class SyscallInfo:
    def __init__(self, name: str, number: int, dangerous: bool = False):
        self.name = name
        self.number = number
        self.dangerous = dangerous

    def __repr__(self):
        return f"Syscall[{self.number}] {self.name}"

class PolicyType:
    SECCOMP = "seccomp"
    APPARMOR = "apparmor"
    SELINUX = "selinux"

class SandboxPolicy:
    def __init__(self):
        self.rules: List[str] = []


class SandboxPolicyGenerator:
    """从二进制文件的已解析import集合推导seccomp-bpf syscall允许列表。"""

    def __init__(self,
                 func_to_syscall: Optional[Dict[str, int]] = None,
                 blacklist: Optional[Set[str]] = None):
        self.func_map = func_to_syscall or _FUNC_TO_SYSCALL_X64
        self.blacklist = blacklist or set()

    def generate(self, binary: str) -> Dict:
        """从二进制导入表推导策略。

        经 r2 `ii` 提取导入符号名集合后委托 generate_from_imports;
        r2 缺失或超时按空导入集生成基础策略并记警告。
        """
        imports: Set[str] = set()
        try:
            cmd = [R2_PATH, '-q', '-e', 'io.color=false',
                   '-c', 'ii', binary]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=SUBPROCESS_TIMEOUT)
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                # ii 列: nth vaddr bind type lib name
                sym = parts[-1]
                if sym.startswith('sym.imp.'):
                    sym = sym[len('sym.imp.'):]
                if sym:
                    imports.add(sym)
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            logger.warning("import scan failed for %s: %s", binary, err)
        return self.generate_from_imports(imports)

    def generate_from_imports(self,
                               imports: Set[str],
                               include_dangerous: bool = False,
                               extra_allowed: Optional[Set[str]] = None,
                               ) -> Dict:
        """由导入函数名集合推导允许列表。

        include_dangerous=False 时剔除 execve/fork/clone 等危险 syscall;
        extra_allowed 缺省放行 exit/exit_group/brk/arch_prctl。
        返回 allowed_syscalls/bpf_bytes/bpf_hex/c_source/count。
        """
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
            "bpf_bytes": bpf_bytes,
            "bpf_hex": bpf_bytes.hex(),
            "c_source": c_source,
            "count": len(resolved),
        }


# 便捷入口——静态syscall查找类与模块级入口点

class SYSCALL_MAP_X64:
    """不可变x86-64 syscall名称→编号查找表。"""
    MAP = _FUNC_TO_SYSCALL_X64

    @classmethod
    def lookup(cls, name: str) -> Optional[int]:
        return cls.MAP.get(name)

    @classmethod
    def all_names(cls) -> List[str]:
        return list(cls.MAP.keys())


# 向后兼容别名——为已有测试导入保留
FUNCTION_TO_SYSCALL = SYSCALL_MAP_X64


def generate_sandbox_policy(imports: Set[str], **kwargs) -> Dict:
    gen = SandboxPolicyGenerator()
    return gen.generate_from_imports(imports, **kwargs)


name = "sandbox_policy_gen"
module = "sandbox_policy_gen"
