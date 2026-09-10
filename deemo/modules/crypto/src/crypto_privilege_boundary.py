"""
密码学权限边界分析 — 识别密码学操作跨越的特权边界并评估隔离安全性。

设计意图:
  密码学操作常跨越硬件或软件定义的特权边界:
    (a) 用户态应用→内核加密API (如Linux crypto_user socket)
    (b) 普通世界→安全世界 (ARM TrustZone: EL0/EL1→EL3/S-EL1)
    (c) 主处理器→加密协处理器 (MMIO crypto accelerator)
    (d) 应用→飞地 (Intel SGX/AMD SEV/ARM CCA)

  每个边界跨越都是潜在的侧信道源或权限提升攻击面:
    (a) 用户→内核: 密钥材料通过系统调用传递→内核内存中的残留。
    (b) Normal→Secure World: TrustZone切换的缓存状态→跨世界侧信道。
    (c) 飞地边界: SGX的AEX(异步飞地退出)→L1TF/MDS类推测执行攻击。

  本模块识别密码学操作跨越的权限边界, 评估:
    B1 (边界类型): 用户-内核/TrustZone/飞地/协处理器。
    B2 (密钥传递方式): 寄存器/共享内存/DMA/加密通道。
    B3 (隔离保证): 基于硬件特性的隔离强度评估。
    B4 (已知攻击面): 映射到已知CVE/攻击类别。

  - ARM TrustZone (ARMv8-M/v9): 安全扩展 — S/NS状态切换的密码学影响。
  - Intel SGX: 飞地加密 — AEX处理和侧信道缓解。
  - Linux Crypto API (kernel 6.x): 用户态访问接口 — crypto_user socket。
  - Spectre/Meltdown类: 推测执行跨边界攻击。

边界条件:
  - 权限边界检测依赖字符串/SMC指令/SGX指令识别 — 间接调用可能漏检。
  - 隔离强度评估是架构相关的近似 — ARM TrustZone和Intel SGX的保证不同。
  - 自定义安全监视器(proprietary TEE)的边界检测精度有限。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class BoundaryType(Enum):
    USER_KERNEL = 0     # 用户态↔内核态
    TRUSTZONE = 1       # Normal World↔Secure World (ARM)
    ENCLAVE = 2         # 应用↔飞地 (SGX/SEV/CCA)
    COPROCESSOR = 3     # 主CPU↔加密协处理器 (MMIO/DMA)
    HYPERVISOR = 4      # VM↔Hypervisor
    UNKNOWN = 5

@dataclass
class PrivilegeBoundary:
    boundary_type: BoundaryType = BoundaryType.UNKNOWN
    crypto_operation: str = ""     # 跨越边界的密码学操作
    key_transport: str = ""        # 密钥传递方式
    isolation_assurance: str = ""  # HIGH / MEDIUM / LOW / NONE
    known_attack_vectors: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    location: int = 0

# 边界检测模式

_TRUSTZONE_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'SMC', 'SMC调用 (Secure Monitor Call)', 0.88),
    (b'smc(', 'SMC指令 — TrustZone切换', 0.85),
    (b'__smc', 'SMC wrapper — 安全世界调用', 0.85),
    (b'TEE_', '可信执行环境API (GlobalPlatform TEE)', 0.82),
    (b'TA_Invoke', 'Trusted Application调用', 0.88),
    (b'OPTEE', 'OP-TEE安全OS', 0.90),
    (b'optee_', 'OP-TEE接口', 0.88),
    (b'trustzone', 'TrustZone引用', 0.90),
    (b'secure_world', '安全世界标识', 0.82),
]

_ENCLAVE_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'enclave', 'SGX飞地引用', 0.85),
    (b'ENCLU', 'SGX用户态飞地指令', 0.92),
    (b'EENTER', 'SGX飞地进入', 0.92),
    (b'EEXIT', 'SGX飞地退出', 0.92),
    (b'ERESUME', 'SGX飞地恢复(AEX后)', 0.90),
    (b'sgx_', 'SGX API', 0.88),
    (b'SEV', 'AMD SEV加密虚拟化', 0.85),
    (b'sev_', 'AMD SEV API', 0.85),
    (b'CCA', 'ARM CCA机密计算架构', 0.82),
]

_USER_KERNEL_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'syscall', '系统调用', 0.75),
    (b'SYSCALL', '系统调用指令(x86)', 0.85),
    (b'SVC', 'Supervisor Call (ARM)', 0.85),
    (b'ioctl', 'ioctl设备控制', 0.70),
    (b'crypto_user', 'Linux crypto_user socket', 0.85),
    (b'NETLINK_CRYPTO', 'netlink crypto接口', 0.88),
    (b'sendmsg', 'sendmsg(可能AF_ALG)', 0.55),
    (b'af_alg', 'AF_ALG socket (Linux内核加密)', 0.88),
    (b'socket(AF_ALG', 'AF_ALG创建', 0.90),
]

_COPROCESSOR_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'MMIO', '内存映射IO', 0.65),
    (b'mmio_', 'MMIO访问', 0.70),
    (b'DMA', '直接内存访问', 0.60),
    (b'dma_', 'DMA操作', 0.65),
]

def detect_privilege_boundaries(data: bytes,
                                strings: Optional[List[str]] = None,
                                hw_peripherals: Optional[List] = None
                                ) -> List[PrivilegeBoundary]:
    """识别密码学操作跨越的特权边界。"""
    boundaries: List[PrivilegeBoundary] = []
    strs = strings or []

    # TrustZone
    tz_evidence = []
    for pat, desc, conf in _TRUSTZONE_PATTERNS:
        if pat in data:
            tz_evidence.append(desc)
    if tz_evidence:
        boundaries.append(PrivilegeBoundary(
            boundary_type=BoundaryType.TRUSTZONE,
            crypto_operation='安全世界密码学操作',
            key_transport='SMC寄存器或共享内存',
            isolation_assurance='HIGH (硬件隔离: NS↔S世界)',
            known_attack_vectors=['跨世界缓存侧信道', 'SMC参数验证'],
            evidence=tz_evidence))

    # 飞地
    encl_evidence = []
    for pat, desc, conf in _ENCLAVE_PATTERNS:
        if pat in data:
            encl_evidence.append(desc)
    if encl_evidence:
        boundaries.append(PrivilegeBoundary(
            boundary_type=BoundaryType.ENCLAVE,
            crypto_operation='飞地内密码学操作',
            key_transport='密封(Sealed)存储或远程认证(RA)',
            isolation_assurance='HIGH (硬件飞地+内存加密)',
            known_attack_vectors=['AEX侧信道', 'L1TF/MDS推测执行', '页表攻击'],
            evidence=encl_evidence))

    # 用户-内核
    uk_evidence = []
    for pat, desc, conf in _USER_KERNEL_PATTERNS:
        if pat in data:
            uk_evidence.append(desc)
    if uk_evidence:
        boundaries.append(PrivilegeBoundary(
            boundary_type=BoundaryType.USER_KERNEL,
            crypto_operation='用户态→内核加密API',
            key_transport='系统调用参数(寄存器)或AF_ALG sendmsg',
            isolation_assurance='MEDIUM (OS强制但无硬件隔离)',
            known_attack_vectors=['内核内存残留', 'ptrace密钥提取', 'AF_ALG竞态'],
            evidence=uk_evidence))

    # 协处理器
    if hw_peripherals:
        detected = [p for p in hw_peripherals if getattr(p, 'detected', False)]
        if detected:
            names = [getattr(p.peripheral, 'peripheral_name', 'unknown')
                     for p in detected]
            boundaries.append(PrivilegeBoundary(
                boundary_type=BoundaryType.COPROCESSOR,
                crypto_operation=f'加密协处理器: {", ".join(names[:3])}',
                key_transport='MMIO寄存器写入或DMA描述符链',
                isolation_assurance='MEDIUM (外设总线隔离, 但DMA可访问主存)',
                known_attack_vectors=['DMA攻击', 'MMIO嗅探', '总线监听'],
                evidence=[f'{len(detected)} crypto peripheral(s)']))

    return boundaries

def boundary_risk_assessment(boundaries: List[PrivilegeBoundary]) -> str:
    if not boundaries:
        return '未检测到密码学权限边界跨越 — 所有密码学操作均为本地同特权级'
    n = len(boundaries)
    tz = any(b.boundary_type == BoundaryType.TRUSTZONE for b in boundaries)
    encl = any(b.boundary_type == BoundaryType.ENCLAVE for b in boundaries)
    uk = any(b.boundary_type == BoundaryType.USER_KERNEL for b in boundaries)

    if tz and encl:
        return f'CRITICAL: 多层权限边界({n}个) — TrustZone+飞地共存; 审计所有跨边界的密钥传递'
    elif uk and not tz:
        return f'MODERATE: 用户-内核边界({n}个) — 确保AF_ALG或crypto_user的使用安全'
    elif tz:
        return f'MODERATE: TrustZone边界({n}个) — 验证SMC参数和跨世界缓存策略'
    return f'LOW: {n}个边界 — 标准权限隔离'
