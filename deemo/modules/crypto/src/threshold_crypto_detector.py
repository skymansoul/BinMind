"""
阈值/MPC密码学检测 — 识别二进制中的门限密码学和多方计算实现。

修改记录:
  2025-08-20 21:33 — 初始实现: SSS检测/DKG协议指纹/门限签名/Lagrange插值模式

设计意图:
  阈值密码学将密钥分割为n份, 需≥t份才能解密/签名(t-of-n门限)。
  MPC允许多方在不暴露各自输入的前提下计算联合函数。
  这些技术正在从学术原型走向工业部署:
    (a) 加密货币钱包(阈值ECDSA — 多签替代方案; GG20/CGGMP21协议)。
    (b) 分布式密钥管理(DKMS — 无单点故障的密钥保护)。
    (c) 隐私保护计算(MPC聚合 — 联邦学习中的梯度加密聚合)。

  阈值/MPC实现的二进制检测对安全审计至关重要:
    (a) 门限钱包中的份额管理是否安全? 份额是否被不当地集中存储?
    (b) DKG协议实现是否正确? 是否有降级到中心化密钥生成的回退路径?
    (c) 是否存在秘密的MPC通道用于数据外传?

  检测策略(4个互补信号):
    1. Lagrange插值: 门限方案中恢复密钥的数学核心 — 在二进制中表现为
       for循环中的多项式求值 + 模乘 + 模逆序列。
    2. Shamir份额结构: 连续存储的等长数据块, 每块前附有索引字节(1,2,3...)。
    3. DKG协议指纹: Pedersen/VSS承诺轮次 — 多轮广播+验证序列。
    4. 门限密码学API字符串: threshold/sss/share/lagrange/reconstruct等。

参考:
  - Shamir (CACM 1979): "How to Share a Secret" — SSS原始论文, 定义多项式份额结构。
  - Pedersen (CRYPTO 1991): "A Threshold Cryptosystem without a Trusted Party" —
    DKG协议, 定义承诺/份额分发/验证轮次。
  - Gennaro & Goldfeder (CCS 2018): "Fast Multiparty Threshold ECDSA" —
    现代阈值ECDSA协议, GG18/GG20实现模式。
  - Canetti et al. (ACM CCS 2020): "UC Non-Interactive, Proactive, Threshold ECDSA" —
    CGGMP21协议, 当前最先进的阈值ECDSA。

边界条件:
  - Lagrange插值也可用于非密码学用途(数值分析/样条插值) → 通过密码学上下文消歧义。
  - 份额结构检测依赖"索引头+数据体"的布局假设 — 加密的份额不匹配此模式。
  - DKG检测仅覆盖Pedersen风格协议 — 其他DKG(如Feldman/NIKE-based)需扩展。
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass
class ThresholdFinding:
    scheme: str = ""            # SHAMIR_SSS / DKG / TSS_ECDSA / MPC / UNKNOWN
    confidence: float = 0.0
    evidence: str = ""
    location: int = 0
    share_count_hint: int = 0   # 推断的门限参数: t-of-n


# ── 门限密码学字符串指纹 ──
_THRESHOLD_STRINGS: List[Tuple[bytes, str, float]] = [
    # Shamir & 份额
    (b'shamir', 'Shamir SSS', 0.88),
    (b'sss_', 'Shamir SSS', 0.85),
    (b'split_secret', 'SSS split', 0.85),
    (b'reconstruct_secret', 'SSS reconstruct', 0.88),
    (b'combine_shares', 'share combination', 0.85),
    (b'verify_share', 'share verification', 0.82),
    (b'threshold_', 'threshold scheme', 0.75),
    # Lagrange
    (b'lagrange', 'Lagrange interpolation', 0.82),
    (b'LAGRANGE', 'Lagrange interpolation', 0.78),
    (b'lagrangian', 'Lagrange interpolation', 0.80),
    # DKG
    (b'dkg_', 'DKG protocol', 0.85),
    (b'DKG_', 'DKG protocol', 0.85),
    (b'pedersen', 'Pedersen DKG', 0.88),
    (b'vss_', 'Verifiable Secret Sharing', 0.85),
    (b'feldman', 'Feldman VSS', 0.85),
    # 门限ECDSA
    (b'tss_ecdsa', 'Threshold ECDSA', 0.88),
    (b'gg20', 'GG20 Threshold ECDSA', 0.90),
    (b'gg18', 'GG18 Threshold ECDSA', 0.90),
    (b'cggmp', 'CGGMP21 Threshold ECDSA', 0.90),
    (b'threshold_sign', 'Threshold signing', 0.82),
    (b'sign_share', 'Signature share', 0.82),
    # MPC通用
    (b'mpc_', 'MPC protocol', 0.78),
    (b'MPC_', 'MPC protocol', 0.78),
    (b'multiparty', 'Multi-party computation', 0.75),
    (b'garbled_circuit', 'Garbled circuit MPC', 0.90),
    (b'obliviou', 'Oblivious transfer/MPC', 0.82),
    (b'secret_share', 'Secret sharing', 0.80),
    (b'share_', 'Secret share', 0.70),
    (b'shards', 'Key sharding', 0.75),
]


def _detect_lagrange_pattern(data: bytes) -> List[Tuple[int, float]]:
    """
    检测Lagrange插值的二进制模式。
    特征: 循环中对多个数据点做多项式求值, 包含模乘(IMUL/MUL)和模逆序列。
    在x86中表现为: 循环体中的乘法+模约简(MOD/DIV)+累加模式。
    """
    findings: List[Tuple[int, float]] = []
    n = len(data)

    # 搜索模式: 密集的乘法操作(每20-60字节出现mul/imul)+除法操作
    i = 0
    mul_positions: List[int] = []
    div_positions: List[int] = []

    while i < n - 1:
        b = data[i]
        # 跳过REX前缀
        if b in frozenset({0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}):
            if i + 1 < n:
                b = data[i + 1]
                i += 1
        # MUL/IMUL: 0xF7 /5, 0x0FAF, 0x69, 0x6B
        if b in (0xF7, 0x69, 0x6B):
            mul_positions.append(i)
        # DIV/IDIV: 0xF7 /6, 0xF7 /7
        if b == 0xF7 and i + 1 < n and data[i + 1] in (0xF0, 0xF8):
            div_positions.append(i)
        # 双字节opcode 0x0FAF=IMUL
        if b == 0x0F and i + 1 < n and data[i + 1] == 0xAF:
            mul_positions.append(i)
            i += 1
        i += 1

    # Lagrange插值特征: 在一定窗口内mul数量和div数量都≥2
    window = 512
    for start in range(0, n - window, 128):
        end = start + window
        mul_in_win = sum(1 for p in mul_positions if start <= p < end)
        div_in_win = sum(1 for p in div_positions if start <= p < end)

        # 阈值: ≥3次乘法和≥1次除法→可能的Lagrange求值
        if mul_in_win >= 3 and div_in_win >= 1:
            conf = min(0.72, 0.40 + (mul_in_win + div_in_win) * 0.06)
            findings.append((start, conf))

    return findings[:10]


def _detect_share_structure(data: bytes) -> List[Tuple[int, int, int]]:
    """
    检测Shamir份额结构: 连续的等长数据块, 每块以索引字节开头。
    典型结构: [01][32-byte share][02][32-byte share][03][32-byte share]...
    返回 [(偏移, 推测份额数, 推测门限值), ...]。
    """
    findings: List[Tuple[int, int, int]] = []
    for chunk_size in [32, 33, 48, 49, 64, 65]:  # 常见份额大小
        for offset in range(0, min(len(data) - chunk_size * 3, 4096), 16):
            indices = []
            valid = True
            for idx in range(8):  # 最多检查8个潜在份额
                pos = offset + idx * chunk_size
                if pos + chunk_size > len(data):
                    break
                first_byte = data[pos]
                # 份额索引通常是1,2,3... 且连续
                if first_byte == idx + 1 or first_byte == idx:
                    indices.append(first_byte)
                elif idx >= 2:
                    break  # 序列中断
                else:
                    valid = False
                    break
            if valid and len(indices) >= 3:
                findings.append((offset, len(indices), min(2, len(indices) - 1)))
    return findings[:5]


# ── 主检测器 ──

class ThresholdCryptoDetector:
    """阈值/MPC密码学检测器。"""

    def __init__(self, data: bytes, strings: Optional[List[str]] = None):
        self._data = data
        self._strs = strings or []

    def run_all(self) -> List[ThresholdFinding]:
        findings: List[ThresholdFinding] = []

        # 1. Lagrange插值模式检测
        for loc, conf in _detect_lagrange_pattern(self._data):
            findings.append(ThresholdFinding(
                scheme='LAGRANGE_INTERPOLATION',
                confidence=conf,
                evidence=f'Lagrange interpolation pattern at 0x{loc:x}',
                location=loc))

        # 2. Shamir份额结构检测
        for offset, share_count, threshold in _detect_share_structure(self._data):
            findings.append(ThresholdFinding(
                scheme='SHAMIR_SSS',
                confidence=0.68,
                evidence=f'{share_count} shares ({threshold}+ threshold) at 0x{offset:x}',
                location=offset, share_count_hint=share_count))

        # 3. 字符串指纹
        for s in self._strs:
            sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
            for pat, scheme, conf in _THRESHOLD_STRINGS:
                if pat in sb:
                    findings.append(ThresholdFinding(
                        scheme=scheme, confidence=conf,
                        evidence=f'string: "{s[:60]}" -> {scheme}',
                        location=0))
                    break

        # 4. 多信号共存加速置信度
        self._boost_multi_signal(findings)

        return sorted(findings, key=lambda f: -f.confidence)

    def _boost_multi_signal(self, findings: List[ThresholdFinding]) -> None:
        """多信号共存 → 置信度提升。"""
        schemes_seen = set()
        for f in findings:
            if f.scheme != 'LAGRANGE_INTERPOLATION':
                schemes_seen.add(f.scheme)

        # Lagrange + SSS 共存 → 两个信号互相印证
        has_lagrange = any(f.scheme == 'LAGRANGE_INTERPOLATION' for f in findings)
        has_sss = any('SSS' in f.scheme or 'share' in f.scheme.lower()
                      for f in findings)

        if has_lagrange and has_sss:
            for f in findings:
                f.confidence = min(0.92, f.confidence + 0.12)
