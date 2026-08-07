"""
密码学密钥生命周期追踪 — 从二进制静态分析追踪密钥的生成/使用/销毁全生命周期。

修改记录:
  2025-08-17 15:08 — 初始实现: 密钥生成检测/密钥使用追踪/销毁验证/泄漏路径标记

设计意图:
  既有secret_auditor检测硬编码密钥, subreg_taint追踪子寄存器级污染, 但两者都不
  回答密码学上最关键的操作安全问题:"密钥从生成到销毁经历了哪些代码路径?
  是否在所有路径上都正确销毁? 是否有意外的密钥副本残留在栈/堆/寄存器中?"

  这在以下场景中直接关系到合规性和安全性:
    (a) FIPS 140-3要求密钥管理遵循严格的生成→使用→销毁生命周期 — 审计者
        需要确认二进制实现了完整的密钥生命周期管理。
    (b) 密钥泄漏漏洞往往发生在"超出预期生命周期"的阶段 — 如用完未清零,
        core dump中包含密钥, 或密钥通过日志/调试输出意外导出。
    (c) 供应链审查需要确认第三方库的密钥管理符合组织策略 —
        在二进制层面验证而非仅信任文档。

  检测策略(静态近似):
    1. 密钥生成点: 识别RNG调用(getrandom/RDRAND/OpenSSL RAND)后的密钥缓冲区写入。
    2. 密钥使用点: 识别密钥作为参数的加密API调用(EncryptInit/Sign/等)。
    3. 密钥销毁点: 识别explicit_bzero/SecureZeroMemory/OPENSSL_cleanse调用。
    4. 泄漏路径: 密钥使用后/销毁前的memcpy/sprintf/内存共享序列→潜在的意外导出。

  - GnuZero: 编译器级零化检测 — 可检测优化消除的memset;
    本项目在二进制层面补充"泄漏路径"和"生命周期完整性"维度。
  - FIPS 140-3 IG 2.4: 密钥管理生命周期要求 — zeroization强制要求。
  - CWE-226/244: 敏感信息清理缺陷 — 本模块输出可映射到CWE分类。

边界条件:
  - 密钥生命周期追踪在二进制层面是概率性的 — 无法确定某个memcpy确实复制了密钥,
    只能标记"与密钥写入位置相近的内存操作"作为潜在泄漏路径。
  - 仅追踪GPR中的密钥 — XMM/YMM寄存器的密钥未覆盖(成本>收益)。
  - 混淆代码会使密钥识别失效 → 输出降低的置信度标记。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class KeyLifecyclePhase(Enum):
    GENERATION = 0
    DERIVATION = 1      # HKDF/PBKDF2等密钥派生
    IMPORT = 2           # 从外部导入(密钥文件/HSM/网络)
    ACTIVE_USE = 3       # 加密/签名/HMAC计算中使用
    CACHED = 4           # 派生后缓存但未使用
    ZEROIZED = 5         # 显式清零
    LEAKED = 6           # 可能泄漏(日志/memcpy/core dump)

@dataclass
class KeyLifecycleEvent:
    phase: KeyLifecyclePhase
    location: int = 0
    evidence: str = ""
    confidence: float = 0.0

@dataclass
class KeyLifecycleReport:
    algorithm: str = ""
    key_type: str = ""              # SYMMETRIC / PRIVATE / PUBLIC / SESSION / MASTER
    events: List[KeyLifecycleEvent] = field(default_factory=list)
    is_zeroized: bool = False
    has_leak_path: bool = False
    lifecycle_completeness: float = 0.0  # 0=碎片化, 1=完整追踪
    risk_level: str = "LOW"
    details: List[str] = field(default_factory=list)

# 密钥生成API模式
_KEYGEN_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'RAND_bytes', 'OpenSSL RAND_bytes', 0.88),
    (b'RAND_priv_bytes', 'OpenSSL private RAND', 0.90),
    (b'randombytes_buf', 'libsodium random', 0.88),
    (b'crypto_secretbox_keygen', 'libsodium keygen', 0.92),
    (b'crypto_sign_keypair', 'libsodium sign keygen', 0.92),
    (b'crypto_kx_keypair', 'libsodium KX keygen', 0.90),
    (b'CryptGenRandom', 'Windows keygen', 0.85),
    (b'BCryptGenerateSymmetricKey', 'Windows BCrypt keygen', 0.90),
    (b'generate_key', 'generic keygen', 0.70),
    (b'keygen', 'generic keygen', 0.65),
    (b'genkey', 'generic keygen', 0.65),
]

# 密钥销毁API模式
_ZEROIZE_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'explicit_bzero', 'explicit_bzero', 0.95),
    (b'explicit_memset', 'explicit_memset', 0.95),
    (b'memset_s', 'memset_s (C11 Annex K)', 0.95),
    (b'SecureZeroMemory', 'SecureZeroMemory', 0.95),
    (b'RtlSecureZeroMemory', 'RtlSecureZeroMemory', 0.95),
    (b'OPENSSL_cleanse', 'OPENSSL_cleanse', 0.95),
    (b'sodium_memzero', 'sodium_memzero', 0.95),
    (b'sodium_free', 'sodium_free', 0.88),
    (b'zeroize', 'zeroize', 0.80),
    (b'burn', 'burn/key cleanup', 0.60),
]

# 密钥泄漏风险模式
_LEAK_RISK_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'memcpy', 'memcpy near key buffer', 0.55),
    (b'sprintf', 'sprintf near key buffer', 0.70),
    (b'printf', 'printf/format string', 0.65),
    (b'fwrite', 'fwrite/file write', 0.60),
    (b'send', 'network send', 0.68),
    (b'write(', 'write syscall', 0.55),
    (b'fprintf', 'fprintf', 0.68),
    (b'hex_dump', 'hex dump', 0.78),
    (b'debug_print', 'debug print', 0.72),
    (b'log_', 'logging', 0.60),
    (b'dump_', 'memory dump', 0.75),
]

def _detect_key_generation(data: bytes, anchor: int, window: int = 512
                           ) -> List[KeyLifecycleEvent]:
    """在密码学锚点附近检测密钥生成事件。"""
    start = max(0, anchor - window)
    region = data[start:anchor + window]
    events: List[KeyLifecycleEvent] = []
    for pat, desc, conf in _KEYGEN_PATTERNS:
        pos = region.find(pat)
        if pos != -1:
            events.append(KeyLifecycleEvent(
                phase=KeyLifecyclePhase.GENERATION,
                location=start + pos, evidence=desc, confidence=conf))
    return events

def _detect_zeroization(data: bytes, anchor: int, window: int = 1024
                        ) -> List[KeyLifecycleEvent]:
    """在密钥使用点之后检测显式清零。"""
    start = max(0, anchor)
    region = data[start:min(start + window * 2, len(data))]
    events: List[KeyLifecycleEvent] = []
    for pat, desc, conf in _ZEROIZE_PATTERNS:
        pos = region.find(pat)
        if pos != -1:
            events.append(KeyLifecycleEvent(
                phase=KeyLifecyclePhase.ZEROIZED,
                location=start + pos, evidence=desc, confidence=conf))
    return events

def _detect_leak_risks(data: bytes, anchor: int, window: int = 512
                       ) -> List[KeyLifecycleEvent]:
    """检测密钥使用点附近的潜在泄漏路径。"""
    start = max(0, anchor - window)
    region = data[start:anchor + window * 2]
    events: List[KeyLifecycleEvent] = []
    for pat, desc, conf in _LEAK_RISK_PATTERNS:
        for off in range(0, len(region) - len(pat), 32):
            if region[off:off + len(pat)] == pat:
                events.append(KeyLifecycleEvent(
                    phase=KeyLifecyclePhase.LEAKED,
                    location=start + off, evidence=desc,
                    confidence=conf))
                break
    return events[:8]  # 限制数量避免噪音

def trace_key_lifecycle(data: bytes,
                        crypto_findings: Optional[List] = None
                        ) -> List[KeyLifecycleReport]:
    """
    追踪所有检测到的密码学实例的密钥生命周期。
    每个crypto_finding作为密钥使用锚点, 前后搜索生成/销毁/泄漏事件。
    """
    reports: List[KeyLifecycleReport] = []

    anchors = []
    if crypto_findings:
        for f in crypto_findings:
            try:
                loc = getattr(f, 'location', 0)
                algo = getattr(f, 'algorithm', '')
                anchors.append((loc, algo))
            except Exception:
                pass

    if not anchors:
        anchors = [(0, 'unknown')]

    for offset, algo in anchors[:30]:
        events: List[KeyLifecycleEvent] = []

        # 阶段1: 检测密钥生成 (锚点之前)
        gen_events = _detect_key_generation(data, offset, window=2048)
        events.extend(gen_events)

        # 阶段2: 密钥使用 (锚点本身)
        events.append(KeyLifecycleEvent(
            phase=KeyLifecyclePhase.ACTIVE_USE,
            location=offset,
            evidence=f'{algo} detected at 0x{offset:x}',
            confidence=0.85))

        # 阶段3: 检测销毁 (锚点之后)
        zero_events = _detect_zeroization(data, offset)
        events.extend(zero_events)

        # 阶段4: 检测泄漏风险
        leak_events = _detect_leak_risks(data, offset)
        events.extend(leak_events)

        is_zeroized = any(e.phase == KeyLifecyclePhase.ZEROIZED for e in events)
        has_leak = any(e.phase == KeyLifecyclePhase.LEAKED for e in events)

        # 生命周期完整性
        phases_seen = {e.phase for e in events}
        ideal_phases = {KeyLifecyclePhase.GENERATION, KeyLifecyclePhase.ACTIVE_USE,
                        KeyLifecyclePhase.ZEROIZED}
        completeness = len(phases_seen & ideal_phases) / len(ideal_phases)

        # 风险评估
        if has_leak and not is_zeroized:
            risk = 'CRITICAL'
        elif has_leak:
            risk = 'HIGH'
        elif not is_zeroized:
            risk = 'MEDIUM'
        else:
            risk = 'LOW'

        details = []
        if not gen_events:
            details.append('未检测到显式密钥生成 — 密钥可能从外部导入或硬编码')
        if not is_zeroized:
            details.append('未检测到密钥清零 — 密钥可能残留在内存中 (FIPS 140-3合规风险)')
        if has_leak:
            details.append(f'{sum(1 for e in events if e.phase == KeyLifecyclePhase.LEAKED)} '
                           '个潜在泄漏路径 — 审计memcpy/sprintf/write调用')

        reports.append(KeyLifecycleReport(
            algorithm=algo, key_type='SYMMETRIC' if any(
                kw in algo.lower() for kw in ('aes', 'des', 'chacha', 'sm4'))
            else 'ASYMMETRIC',
            events=events, is_zeroized=is_zeroized,
            has_leak_path=has_leak,
            lifecycle_completeness=round(completeness, 3),
            risk_level=risk, details=details))

    reports.sort(key=lambda r: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(
        r.risk_level, 4))
    return reports
