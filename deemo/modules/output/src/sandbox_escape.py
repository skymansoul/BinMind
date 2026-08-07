"""
沙箱逃逸难度评分 — seccomp×capabilities×namespace 的三维约束模型。

问题定义:
  漏洞被利用后，攻击者获得代码执行。下一步是逃逸沙箱。
  现有工具 (checksec, seccomp-tools) 只报告沙箱配置，不评估逃逸难度。
  全网检索 "sandbox escape difficulty scoring" 零形式化结果 — 仅有 CTF 技术描述。

  本模块提供第一个形式化的沙箱逃逸难度评分模型:
    1. seccomp 层: 系统调用过滤的严格度 (阻止的关键逃逸 syscall)
    2. capabilities 层: 进程权能集合 (CAP_SYS_ADMIN 等危险权能)
    3. namespace 层: 隔离类型和挂载暴露面 (host /proc, /sys 等)

  逃逸难度 = 1 - min(seccomp_bypass, cap_abuse, ns_escape)
  取 min 而非 product — 攻击者只需找到最弱的环节。

  No formal scoring system exists.
  CTF techniques documented at book.jorianwoltjer.com.
  Google Project Zero sandbox escape writeups.

修改记录:
  2026-08-01 13:40 - 初始版本，三元约束模型
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# 关键逃逸 syscall — 这些调用被阻止时，逃逸难度显著提升
_ESCAPE_SYSCALLS: Dict[str, float] = {
    'execve':      0.35,  # 新进程执行 — 最直接的逃逸
    'execveat':    0.30,
    'fork':        0.10,  # fork + exec 组合
    'vfork':       0.08,
    'clone':       0.12,  # 创建新命名空间
    'unshare':     0.15,  # 修改命名空间
    'mount':       0.20,  # 挂载操作 — 访问 host 文件系统
    'pivot_root':  0.18,
    'chroot':      0.12,
    'chdir':       0.05,
    'open':        0.10,  # 文件系统逃逸
    'openat':      0.10,
    'openat2':     0.08,
    'ptrace':      0.25,  # 进程注入 — 逃逸到 host 进程
    'process_vm_writev': 0.15,
    'process_vm_readv':  0.12,
    'write':       0.05,  # 数据渗出
    'sendto':      0.05,
    'sendmsg':     0.05,
    'socket':      0.10,  # 网络连通性
    'connect':     0.10,
    'ioctl':       0.08,  # 设备交互
    'io_uring_setup': 0.15,  # io_uring 逃逸 (CVE-2023-25947)
    'keyctl':      0.08,  # 内核密钥环
    'bpf':         0.12,  # BPF 程序加载
    'init_module': 0.18,  # 内核模块加载
    'finit_module':0.15,
    'kexec_load':  0.25,
    'reboot':      0.05,
}

# 危险 capabilities
_DANGEROUS_CAPS: Dict[str, float] = {
    'CAP_SYS_ADMIN':    0.40,  # 几乎等同于 root
    'CAP_SYS_PTRACE':   0.30,  # 进程注入
    'CAP_SYS_MODULE':   0.30,  # 内核模块
    'CAP_SYS_RAWIO':    0.25,  # 直接 I/O
    'CAP_SYS_BOOT':     0.15,
    'CAP_SYS_CHROOT':   0.20,
    'CAP_SYS_NICE':     0.05,
    'CAP_NET_ADMIN':    0.20,  # 网络配置
    'CAP_NET_RAW':      0.15,
    'CAP_DAC_OVERRIDE': 0.25,  # 绕过文件权限
    'CAP_DAC_READ_SEARCH': 0.15,
    'CAP_FOWNER':       0.15,
    'CAP_SETUID':       0.25,  # UID 操作
    'CAP_SETGID':       0.15,
    'CAP_SETPCAP':      0.15,
    'CAP_SYS_PTRACE':   0.30,
}

# namespace 逃逸面
_NS_ESCAPE_FACTORS: Dict[str, float] = {
    'host_proc_mounted':    0.40,  # /proc 暴露 → 大量信息泄露
    'host_sys_mounted':     0.30,  # /sys 暴露 → 设备/内核配置访问
    'host_root_mounted':    0.25,  # host 根文件系统可见
    'host_dev_mounted':     0.20,  # /dev 暴露 → 设备文件访问
    'cgroup_v1_mounted':    0.15,  # cgroup v1 通知逃逸
    'docker_sock_mounted':  0.50,  # Docker socket → 容器逃逸经典向量
    'no_new_privs':        -0.30,  # PR_SET_NO_NEW_PRIVS → 提升逃逸难度
    'user_ns_enabled':      0.10,  # 用户命名空间 → 可能用于提权
}

@dataclass
class SandboxEscapeScore:
    """沙箱逃逸难度评估。"""
    seccomp_bypass_potential: float     # 0-10, 越高越容易逃逸
    capability_abuse_potential: float    # 0-10
    namespace_escape_potential: float    # 0-10
    overall_escape_difficulty: float     # 0-10, 越高越难逃逸 (10=几乎不可能)
    weakest_link: str                   # seccomp / capabilities / namespace
    tier: str = ''                      # trivial / easy / moderate / hard / hardened

    def __post_init__(self):
        if self.overall_escape_difficulty >= 9.0:
            self.tier = 'hardened'
        elif self.overall_escape_difficulty >= 7.0:
            self.tier = 'hard'
        elif self.overall_escape_difficulty >= 5.0:
            self.tier = 'moderate'
        elif self.overall_escape_difficulty >= 3.0:
            self.tier = 'easy'
        else:
            self.tier = 'trivial'

def _seccomp_score(
    blocked_syscalls: List[str],
    default_action: str = 'kill',
    arch_mismatch: bool = False,
) -> float:
    """
    seccomp 逃逸潜力。

    default_action: kill/errno/trap/log — kill 最严格。
    arch_mismatch: 32/64-bit 过滤不一致 → 攻击者切换架构绕过。
    """
    blocked = set(s.lower() for s in blocked_syscalls)
    total_weight = sum(_ESCAPE_SYSCALLS.values())
    blocked_weight = sum(
        w for s, w in _ESCAPE_SYSCALLS.items() if s in blocked
    )
    # 未被阻止的逃逸相关 syscall — 攻击者可利用
    unblocked_ratio = 1.0 - (blocked_weight / total_weight if total_weight > 0 else 0)

    action_penalty = {'kill': 0.8, 'errno': 0.5, 'trap': 0.6, 'log': 0.2, 'allow': 0.0}
    penalty = action_penalty.get(default_action.lower(), 0.5)

    bypass_potential = unblocked_ratio * (1.0 - penalty)
    if arch_mismatch:
        bypass_potential += 0.25  # 架构混淆显著降低有效性

    return round(min(bypass_potential, 1.0) * 10, 1)

def _capability_score(capabilities: List[str]) -> float:
    """capability 滥用潜力 — 保留的危险权能。"""
    caps_lower = set(c.lower() for c in capabilities)
    total = sum(_DANGEROUS_CAPS.values())
    retained = sum(w for c, w in _DANGEROUS_CAPS.items() if c.lower() in caps_lower)
    # retained / total → 越多的危险权能保留 → 越容易逃逸
    return round((retained / total) * 10, 1) if total > 0 else 0.0

def _namespace_score(factors: Dict[str, bool]) -> float:
    """namespace 逃逸潜力 — 暴露面加权。"""
    score = 0.0
    for factor, weight in _NS_ESCAPE_FACTORS.items():
        if factors.get(factor, False):
            score += weight
    # Clamp 到 [0, 1]
    score = max(0.0, min(1.0, score))
    return round(score * 10, 1)

def score_sandbox_escape(
    blocked_syscalls: Optional[List[str]] = None,
    seccomp_default_action: str = 'kill',
    seccomp_arch_mismatch: bool = False,
    capabilities: Optional[List[str]] = None,
    namespace_factors: Optional[Dict[str, bool]] = None,
) -> SandboxEscapeScore:
    """
    评估沙箱逃逸难度。

    blocked_syscalls: seccomp 阻止的 syscall 名列表
    capabilities: 进程保留的 capability 列表
    namespace_factors: {factor_name: is_present, ...}
    """
    seccomp_potential = _seccomp_score(
        blocked_syscalls or [], seccomp_default_action, seccomp_arch_mismatch
    )
    cap_potential = _capability_score(capabilities or [])
    ns_potential = _namespace_score(namespace_factors or {})

    # 最弱环节决定整体逃逸难度
    weakest = max(seccomp_potential, cap_potential, ns_potential)
    difficulty = round(10.0 - weakest, 1)

    # 确定最弱环节标签
    max_val = max(seccomp_potential, cap_potential, ns_potential)
    if max_val == seccomp_potential:
        link = 'seccomp'
    elif max_val == cap_potential:
        link = 'capabilities'
    else:
        link = 'namespace'

    return SandboxEscapeScore(
        seccomp_bypass_potential=seccomp_potential,
        capability_abuse_potential=cap_potential,
        namespace_escape_potential=ns_potential,
        overall_escape_difficulty=difficulty,
        weakest_link=link,
    )

def escape_summary(score: SandboxEscapeScore) -> Dict[str, Any]:
    """沙箱逃逸评估摘要 — 可直接嵌入报告。"""
    recommendations = []
    if score.weakest_link == 'seccomp':
        recommendations.append(
            'seccomp 过滤不完整。考虑: 1) 升级默认动作为 kill 而非 errno; '
            '2) 阻止 execve/mount/ptrace; 3) 检查 32/64-bit 过滤一致性'
        )
    elif score.weakest_link == 'capabilities':
        recommendations.append(
            '保留过多危险权能。移除 CAP_SYS_ADMIN/CAP_SYS_PTRACE/CAP_DAC_OVERRIDE'
        )
    elif score.weakest_link == 'namespace':
        recommendations.append(
            '命名空间隔离不足。避免挂载 host /proc 和 Docker socket'
        )

    return {
        'escape_difficulty': score.overall_escape_difficulty,
        'tier': score.tier,
        'weakest_link': score.weakest_link,
        'seccomp_bypass': score.seccomp_bypass_potential,
        'capability_abuse': score.capability_abuse_potential,
        'namespace_escape': score.namespace_escape_potential,
        'recommendations': recommendations,
    }
