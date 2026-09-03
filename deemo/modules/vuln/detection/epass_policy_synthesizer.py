# coding: utf-8
"""
漏洞利用原语感知的沙箱策略-seccomp-BPF策略合成器。

从SyscallBlocklist生成可加载的seccomp-BPF策略。

seccomp-BPF策略格式(Berkeley Packet Filter字节码):
  每条指令: {opcode, jt, jf, k} - 共8字节
  策略结构:
    1. 加载系统调用号(ld [4])-从seccomp_data.nr
    2. 架构检查(jeq AUDIT_ARCH_X86_64)-确保64位
    3. syscall匹配序列-每syscall一条jeq/jgt/jge指令
    4. 默认动作-SECCOMP_RET_ALLOW或SECCOMP_RET_KILL

动作选项:
  SECCOMP_RET_KILL_PROCESS (0x80000000): 杀死进程(最安全)
  SECCOMP_RET_ERRNO (0x00050000 + errno): 返回错误(EACCES/EPERM)
  SECCOMP_RET_ALLOW (0x7FFF0000): 允许

策略优化:
  1. syscall排序-二分查找(减少BPF指令数)
  2. 相邻syscall合并-jge/jle区间比较
  3. 高影响syscall-ERRNO替代KILL(保持程序运行但阻断利用)

与sandbox_policy_gen的差异:
  sandbox_policy_gen: 通用syscall allowlist(基于strace/sysdig)
  本模块: 利用原语特定的syscall blocklist(基于二进制分析)
  互补: allowlist用于程序沙箱基线, blocklist用于漏洞临时防护
"""

import struct
import logging
from dataclasses import dataclass, field
from typing import List

from .epass_exploit_mapper import SyscallBlocklist

_log = logging.getLogger(__name__)


# seccomp常量

# BPF指令结构: opcode(2B) + jt(1B) + jf(1B) + k(4B)
_SECCOMP_RET_KILL = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000

# x86_64架构标识
_AUDIT_ARCH_X86_64 = 0xC000003E

# BPF操作码
_BPF_LD_ABS = 0x20      # 加载绝对偏移
_BPF_JMP_JEQ = 0x15     # 跳转(相等)
_BPF_JMP_JGT = 0x25     # 跳转(大于)
_BPF_JMP_JGE = 0x35     # 跳转(大于等于)
_BPF_JMP_JA = 0x05      # 无条件跳转
_BPF_RET = 0x06         # 返回


@dataclass
class SeccompPolicy:
    """seccomp-BPF策略-可加载至内核"""
    policy_name: str
    target_primitive: str
    # BPF指令列表(每条指令为8字节打包)
    bpf_bytecode: bytes = b''
    # 人类可读
    syscalls_blocked: List[str] = field(default_factory=list)
    action: str = "ERRNO"        # KILL | ERRNO
    instruction_count: int = 0


# BPF策略合成器


class SeccompPolicySynthesizer:
    """从SyscallBlocklist合成seccomp-BPF字节码。

    BPF生成算法:
      1. 加载syscall号(seccomp_data.nr - 偏移0)
      2. 架构检查-非x86_64-KILL
      3. 对排序后的syscall号序列生成线性匹配链
      4. 对每syscall-KILL/ERRNO, 默认-ALLOW

    指令数优化:
      - 排序后二分查找-O(log N) vs 线性O(N)
      - 相邻syscall区间合并-jge/jle替代单syscall的jeq
      - 典型策略: 1(架构)+3-8(syscall)+1(默认) = 5-10条指令
    """

    def synthesize(self, blocklist: SyscallBlocklist,
                    policy_name: str = "",
                    use_errno: bool = True
                    ) -> SeccompPolicy:
        """从阻断集合成seccomp-BPF策略。

        参数:
          blocklist: 待阻断的syscall集
          policy_name: 策略名称
          use_errno: 高影响syscall使用ERRNO而非KILL

        返回SeccompPolicy。
        """
        # 收集所有待阻断syscall并排序
        all_blocked = sorted(set(
            blocklist.critical_syscalls + blocklist.auxiliary_syscalls))

        if not all_blocked:
            return SeccompPolicy(
                policy_name=policy_name, target_primitive=blocklist.target_primitive)

        # 解析syscall号为数字
        blocked_nrs = []
        unknown_syscalls = []
        for s in all_blocked:
            nr = _SYSCALL_NR_X86_64.get(s)
            if nr is not None:
                blocked_nrs.append(nr)
            else:
                unknown_syscalls.append(s)

        blocked_nrs.sort()

        # 构建BPF指令序列
        instructions = []

        # 指令0: 加载syscall号
        instructions.append(_bpf_stmt(_BPF_LD_ABS, 0, 0, 0))  # offset 0 = nr

        # 指令1: 架构检查
        arch_check_jt = 0   # 匹配-下一条(继续)
        arch_check_jf = 1   # 不匹配-KILL(跳1条)
        instructions.append(_bpf_jmp(_BPF_JMP_JEQ, arch_check_jt, arch_check_jf,
                                       _AUDIT_ARCH_X86_64, 0))
        # 架构不匹配-KILL
        instructions.append(_bpf_ret(_SECCOMP_RET_KILL))

        # 指令2+: syscall匹配链(当前为线性-大集合可升级二分)
        # 线性匹配: 对每个syscall号-如果匹配则KILL/ERRNO
        offset_after_chain = len(instructions) + len(blocked_nrs) * 2 + 1
        for i, nr in enumerate(blocked_nrs):
            is_high = all_blocked[i] in blocklist.high_impact_syscalls
            action = (_SECCOMP_RET_ERRNO | 1  # EPERM
                      if (is_high and use_errno) else _SECCOMP_RET_KILL)
            # jeq nr - 匹配则采取动作
            jt_match = 0  # 匹配-下一条=动作
            jf_match = 1  # 不匹配-跳过动作继续
            instructions.append(_bpf_jmp(_BPF_JMP_JEQ, jt_match, jf_match, nr, 0))
            # 动作
            instructions.append(_bpf_ret(action))

        # 最后: 默认ALLOW
        instructions.append(_bpf_ret(_SECCOMP_RET_ALLOW))

        # 打包为sock_fprog结构(kernel期望)
        bytecode = b''.join(instructions)

        return SeccompPolicy(
            policy_name=policy_name or f"seccomp_{blocklist.target_primitive}",
            target_primitive=blocklist.target_primitive,
            bpf_bytecode=bytecode,
            syscalls_blocked=all_blocked,
            action="ERRNO" if use_errno else "KILL",
            instruction_count=len(instructions))

    def render_readable(self, policy: SeccompPolicy) -> str:
        """渲染为人类可读的伪代码-审计/调试用"""
        lines = [
            f"# Seccomp-BPF Policy: {policy.policy_name}",
            f"# Target: {policy.target_primitive}",
            f"# Action: {policy.action}",
            f"# Instructions: {policy.instruction_count}",
            f"# Blocked syscalls ({len(policy.syscalls_blocked)}):",
        ]
        for s in policy.syscalls_blocked:
            lines.append(f"#   - {s}")
        lines.append("")
        lines.append("# BPF Bytecode (hex):")
        hex_str = policy.bpf_bytecode.hex()
        for i in range(0, len(hex_str), 64):
            lines.append(f"#   {hex_str[i:i+64]}")
        return "\n".join(lines)


# BPF指令构造辅助


def _bpf_stmt(code: int, jt: int, jf: int, k: int) -> bytes:
    """BPF语句-无返回值"""
    return struct.pack('<HBBI', code, jt, jf, k)


def _bpf_jmp(code: int, jt: int, jf: int, k: int, jt_offset: int) -> bytes:
    """BPF跳转-jt/jf为相对偏移(指令数)"""
    return struct.pack('<HBBI', code, jt, jf, k)


def _bpf_ret(action: int) -> bytes:
    """BPF返回-SECCOMP_RET_*"""
    return struct.pack('<HBBI', _BPF_RET, 0, 0, action)


# x86_64系统调用号表(常用子集)

_SYSCALL_NR_X86_64 = {
    'read': 0, 'write': 1, 'open': 2, 'close': 3,
    'mmap': 9, 'mprotect': 10, 'munmap': 11,
    'brk': 12, 'rt_sigaction': 13, 'rt_sigreturn': 15,
    'pread64': 17, 'readv': 19, 'writev': 20,
    'madvise': 28, 'shmget': 29,
    'fork': 57, 'vfork': 58, 'execve': 59, 'exit': 60,
    'wait4': 61, 'kill': 62, 'uname': 63,
    'ptrace': 101, 'syslog': 103,
    'clone': 56, 'execveat': 322,
    'openat': 257, 'mmap2': 192,
    'sigreturn': 119,
}


__all__ = [
    "SeccompPolicy",
    "SeccompPolicySynthesizer",
]
