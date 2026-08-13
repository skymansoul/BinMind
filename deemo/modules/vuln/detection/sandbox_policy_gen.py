# Seccomp-bpf策略编译。从二进制import表枚举syscall，构造最小化允许集。
# 输出原始BPF字节码或libseccomp兼容C源码。
# BPF指令编码参考tools/include/linux/filter.h（内核源码），
# seccomp返回值常量见include/uapi/linux/seccomp.h。
# 排序后逐NR生成JEQ→ALLOW链，压缩BPF分支深度。

import json, logging, os, struct
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
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
    "setgid": 106, "getgroups": 115, "setgroups": 116, "uname2": 63,
    "fopen": 2, "openat": 257, "printf": 1, "malloc": 12, "free": 12,
    "exit_group": 231, "arch_prctl": 158, "brk2": 12,
    "prctl": 157, "capget": 125, "capset": 126, "getrandom": 318,
    "sched_getaffinity": 204, "sched_setaffinity": 203,
}

DANGEROUS_SYSCALLS: FrozenSet[str] = frozenset({
    "execve", "fork", "vfork", "clone", "kill", "ptrace", "mount",
    "umount2", "chroot", "pivot_root", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "reboot",
    "ioperm", "iopl", "ioprio_set",
})

# x86_64 系统调用映射表（供直接下标访问与成员判断）
SYSCALL_MAP_X64: Dict[str, int] = dict(_FUNC_TO_SYSCALL_X64)

FUNCTION_TO_SYSCALL: Dict[str, int] = SYSCALL_MAP_X64


# 策略类型与数据类

class PolicyType(Enum):
    SECCOMP = "seccomp"
    APPARMOR = "apparmor"


@dataclass
class SyscallInfo:
    name: str
    number: int
    architecture: str = "x86_64"
    is_dangerous: bool = False
    category: str = ""

    @property
    def dangerous(self) -> bool:
        return self.is_dangerous


@dataclass
class SandboxPolicy:
    policy_type: PolicyType
    allowed_syscalls: List[SyscallInfo] = field(default_factory=list)
    denied_syscalls: List[SyscallInfo] = field(default_factory=list)
    policy_content: str = ""
    source_binary: str = ""
    risk_level: str = "low"


_POLICY_HEADER_STRUCT = struct.Struct("<HBB I")
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

    # 系统调用辅助

    def _get_syscall_number(self, name: str, architecture: str = "x86_64") -> int:
        """返回指定架构下的系统调用号；未知返回 -1。"""
        if architecture not in ("x86_64", "amd64"):
            return -1
        return self.func_map.get(name, -1)

    def _identify_dangerous_syscalls(self, syscalls: List[SyscallInfo]) -> List[SyscallInfo]:
        """筛选出危险系统调用。"""
        return [s for s in syscalls if s.name in DANGEROUS_SYSCALLS]

    def _assess_risk_level(self, syscalls: List[SyscallInfo]) -> str:
        """按危险系统调用占比评估策略风险等级。"""
        if any(s.name in DANGEROUS_SYSCALLS or s.is_dangerous for s in syscalls):
            return "high"
        return "low"

    def _infer_syscalls_from_imports(self, imports: List[str]) -> List[SyscallInfo]:
        """将函数导入名映射为系统调用信息列表。"""
        syscalls: List[SyscallInfo] = []
        for name in imports:
            nr = self.func_map.get(name)
            if nr is None:
                continue
            syscalls.append(SyscallInfo(
                name=name, number=nr, architecture="x86_64",
                is_dangerous=name in DANGEROUS_SYSCALLS))
        return syscalls

    # 策略文本生成

    def _generate_seccomp_policy(self, syscalls: List[SyscallInfo],
                                 default_deny: bool = False) -> str:
        """生成 libseccomp 风格 C 策略源码。"""
        lines = [
            "#include <seccomp.h>",
            "#include <stdio.h>",
            "",
            "void apply_policy(void) {",
            "    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_%s);" % (
                "KILL" if default_deny else "ALLOW"),
        ]
        for s in syscalls:
            lines.append(
                f"    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS({s.name}), 0);")
        lines.append("    seccomp_load(ctx);")
        lines.append("}")
        return "\n".join(lines)

    def _generate_apparmor_policy(self, syscalls: List[SyscallInfo],
                                  file_paths: Optional[List[str]] = None,
                                  network_permissions: Optional[Dict[str, list]] = None) -> str:
        """生成 AppArmor profile 文本。"""
        lines = ["#include <tunables/global>", "", "profile sandbox /usr/bin/** {", "  #include <abstractions/base>"]
        for s in syscalls:
            lines.append(f"  {s.name},")
        for fp in file_paths or []:
            lines.append(f"  {fp} r,")
            lines.append(f"  {fp} w,")
        for perm, ports in (network_permissions or {}).items():
            for p in ports:
                lines.append(f"  network {perm} {p},")
        lines.append("}")
        return "\n".join(lines)

    # 主入口

    def generate_policy(self, binary_path: str,
                        policy_type: str = "seccomp") -> Dict:
        """为二进制生成策略报告；文件缺失或路径非法时返回错误字典。"""
        if not binary_path or ".." in binary_path:
            return {"error": f"invalid path: {binary_path}"}
        if not os.path.exists(binary_path):
            return {"error": f"file not found: {binary_path}"}
        try:
            with open(binary_path, "rb") as f:
                blob = f.read()
        except OSError as exc:
            return {"error": f"read failed: {exc}"}
        imports = _extract_import_names(blob)
        syscalls = self._infer_syscalls_from_imports(imports)
        ptype = PolicyType(policy_type) if policy_type in (
            "seccomp", "apparmor") else PolicyType.SECCOMP
        if ptype == PolicyType.SECCOMP:
            content = self._generate_seccomp_policy(syscalls)
        else:
            content = self._generate_apparmor_policy(syscalls)
        allowed_nrs = sorted(s.number for s in syscalls)
        return {
            "policy_type": ptype.value,
            "policy_content": content,
            "allowed_syscalls": {s.name: s.number for s in syscalls},
            "risk_level": self._assess_risk_level(syscalls),
            "bpf_bytes": b"".join(i.pack() for i in _build_bpf_program(allowed_nrs)).hex(),
            "count": len(syscalls),
        }

    def _save_policy(self, policy: SandboxPolicy, output_path: str) -> str:
        """将策略内容写入文件并返回路径。"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(policy.policy_content)
        return output_path

    def generate_from_imports(self, imports: Set[str],
                              include_dangerous: bool = False,
                              extra_allowed: Optional[Set[str]] = None) -> Dict:
        """从导入集合生成 BPF 字节码与 C 源码报告。"""
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


def _extract_import_names(blob: bytes) -> List[str]:
    """粗略抽取二进制可打印字符串作为导入名候选。"""
    import re as _re
    return [m.group().decode("ascii", errors="replace")
            for m in _re.finditer(rb"[\x20-\x7e]{3,}", blob)]


def generate_sandbox_policy(binary_path: str, policy_type: str = "seccomp",
                            **kwargs) -> Dict:
    """便捷入口：为二进制文件生成沙箱策略。"""
    gen = SandboxPolicyGenerator()
    return gen.generate_policy(binary_path, policy_type=policy_type)


name = "sandbox_policy_gen"
module = "sandbox_policy_gen"


def _debug_print(*args, **kwargs):
    """内部调试输出桩。"""
    pass  # 调试桩，当前未激活。

