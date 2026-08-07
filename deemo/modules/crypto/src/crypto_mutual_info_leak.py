"""
密码学侧信道容量启发式估计 — 从静态特征估算各信道可泄漏密钥信息的上界。

修改记录:
  2025-09-12 08:55 — 初始实现: 四信道容量/有效安全级别估算
  2025-09-19 17:30 — 修正: 将"互信息"术语替换为"信道容量估计"，避免与信息论严格定义混淆

设计意图:
  leakage_scorer做0-1复合评分, 但评分0.75意味着什么? 攻击者能提取多少bit密钥?
  本模块从静态分析估计四个侧信道的容量上界(以bit为单位), 聚合后估算
  残余有效安全级别。注意: 这不是严格的Shannon互信息计算 — 真正的I(S;O)需要
  运行时测量数据和统计模型。本模块提供的是基于静态指令计数的启发式近似,
  用于快速筛选高泄漏风险实现, 而非密码学证明。

  四种信道容量估计:
    CH1 (时序): 条件分支数×每分支1bit → max(N, log2(N!))上界
    CH2 (缓存): 索引寻址数×log2(缓存组数≈6)
    CH3 (功率): ALU操作数×每操作≈2bit Hamming差异
    CH4 (直接泄漏): memcpy/send/printf → 可达全部密钥bit

  - Standaert et al.: 侧信道泄漏的信息论框架 — 互信息的形式化定义
    和测量方法论。本模块的启发式方法与严格信息论分析有本质区别。
  - SILENT: 非参数时序测量 — 展示了
    从实际trace中做统计推断所需的样本量和检验方法。

边界条件:
  - 信道容量估计是启发式上界 — 实际泄漏取决于测量噪声和攻击者能力。
  - 基于x86单字节操作码的简化计数 — 精确值需完整反汇编和硬件特性校准。
  - 各信道之间存在相关性(同一指令可能同时产生时序+功率泄漏) — 简单求和可能
    高估总泄漏量。折扣因子0.7是经验值, 需根据目标架构调整。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class ChannelCapacity:
    channel_name: str = ""         # TIMING / CACHE / POWER / DIRECT
    raw_capacity_bits: float = 0.0 # 信道总容量(bit)
    leaked_bits: float = 0.0       # 估计泄漏的密钥bit数
    secret_entropy: float = 0.0    # 秘密的总熵(bit)
    mutual_info: float = 0.0       # I(S;O) 估计
    confidence: float = 0.0

@dataclass
class ChannelCapacityReport:
    """侧信道容量启发式估计报告 — 非严格信息论互信息。"""
    algorithm: str = ""
    key_size_bits: int = 128
    channels: List[ChannelCapacity] = field(default_factory=list)
    total_estimated_leak_bits: float = 0.0   # 聚合泄漏上界
    effective_security_bits: float = 0.0     # 扣除估计泄漏后的残余安全性
    leakage_ratio: float = 0.0               # 泄漏比例 = 估计泄漏/key_size
    risk_assessment: str = ""

# 信道容量估计

def _estimate_timing_capacity(data: bytes, anchor: int, window: int = 2048) -> ChannelCapacity:
    """估计时序侧信道容量: 每个秘密依赖分支→1bit, N个分支→max(N, log2(N!))bit。"""
    region = data[max(0, anchor):anchor + window]
    branch_bytes = frozenset({
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x7C, 0x7D, 0x7E, 0x7F, 0xEB, 0xE3,
    })
    rex_prefixes = frozenset(range(0x40, 0x50))

    n = len(region)
    branch_count = 0
    cmov_count = 0
    i = 0
    while i < n:
        b = region[i]
        if b in rex_prefixes and i + 1 < n:
            i += 1
            b = region[i]
        if b in branch_bytes:
            if 0x70 <= b <= 0x7F:  # 条件分支
                branch_count += 1
            elif b == 0xE3:  # JCXZ
                branch_count += 1
        # cmov检测 (0F 4x)
        if b == 0x0F and i + 1 < n and 0x40 <= region[i + 1] <= 0x4F:
            cmov_count += 1
            i += 1
        i += 1

    total_branch_signals = branch_count + cmov_count
    if total_branch_signals == 0:
        return ChannelCapacity('TIMING', 0.0, 0.0, 0.0, 0.0, 0.7)

    raw_cap = max(total_branch_signals, math.log2(math.factorial(total_branch_signals))
                  if total_branch_signals <= 10 else total_branch_signals * 3)
    leaked = min(raw_cap, raw_cap * 0.7)
    return ChannelCapacity('TIMING', round(raw_cap, 2), round(leaked, 2),
                           0.0, 0.0, min(0.85, 0.4 + total_branch_signals * 0.04))

def _estimate_cache_capacity(data: bytes, anchor: int, window: int = 2048) -> ChannelCapacity:
    """估计缓存侧信道容量: 每个秘密依赖的索引寻址→log2(缓存组数)≈6-10bit。"""
    region = data[max(0, anchor):anchor + window]
    # 检测索引寻址模式 [base+index*scale+disp] — ModRM (mod≠11, R/M=100=SIB)
    indexed_accesses = 0
    i = 0
    n = len(region)
    while i < n - 1:
        b = region[i]
        if b in frozenset(range(0x40, 0x50)) and i + 1 < n:
            i += 1
            b = region[i]
        # ModRM字节检测: (0x00-0x3F或0x80-0xBF)且mod≠3
        if ((0x00 <= b <= 0x3F) or (0x80 <= b <= 0xBF)):
            if i + 1 < n:
                modrm = region[i + 1]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod != 3:  # 内存操作数
                    indexed_accesses += 1
                    if rm == 4 and i + 2 < n:  # SIB → 索引寻址
                        indexed_accesses += 1
                i += 2
                continue
        i += 1

    if indexed_accesses == 0:
        return ChannelCapacity('CACHE', 0.0, 0.0, 0.0, 0.0, 0.6)

    # 典型L1缓存: 64组×8路×64B → log2(64)=6bit/访问
    bits_per_access = 6
    raw_cap = indexed_accesses * bits_per_access
    leaked = min(raw_cap, raw_cap * 0.5)
    return ChannelCapacity('CACHE', round(raw_cap, 2), round(leaked, 2),
                           0.0, 0.0, min(0.80, 0.35 + indexed_accesses * 0.03))

def _estimate_power_capacity(data: bytes, anchor: int, window: int = 2048) -> ChannelCapacity:
    """估计功率侧信道容量: Hamming重量差异×操作数≈每指令可区分bit数。"""
    region = data[max(0, anchor):anchor + window]
    # 简单ALU操作(每操作≈1-3bit可区分功率差异)
    alu_ops = 0
    for b in region:
        if b in frozenset({0x31, 0x33, 0x01, 0x03, 0x29, 0x2B, 0x21,
                            0x23, 0x09, 0x0B, 0x39, 0x3B, 0x85, 0x84}):
            alu_ops += 1

    if alu_ops == 0:
        return ChannelCapacity('POWER', 0.0, 0.0, 0.0, 0.0, 0.5)

    bits_per_op = 2  # 每ALU操作约2bit可观测差异
    raw_cap = alu_ops * bits_per_op
    leaked = min(raw_cap, raw_cap * 0.4)
    return ChannelCapacity('POWER', round(raw_cap, 2), round(leaked, 2),
                           0.0, 0.0, 0.5)

def _estimate_direct_capacity(data: bytes, anchor: int, window: int = 4096,
                               key_size_bits: int = 128) -> ChannelCapacity:
    """估计直接导出信道: memcpy/printf/send→全部密钥bit可能被导出。"""
    region = data[max(0, anchor - window):anchor + window]
    direct_exports = 0
    leak_patterns = [b'memcpy', b'send(', b'write(', b'printf(', b'fwrite(']
    for pat in leak_patterns:
        direct_exports += region.count(pat)

    if direct_exports == 0:
        return ChannelCapacity('DIRECT', 0.0, 0.0, key_size_bits, 0.0, 0.90)

    leaked = key_size_bits * min(1.0, direct_exports * 0.5)
    return ChannelCapacity('DIRECT', float(key_size_bits), leaked,
                           float(key_size_bits), leaked, 0.95 if direct_exports >= 2 else 0.80)

def estimate_channel_capacity(data: bytes,
                               crypto_findings: Optional[List] = None,
                               leakage_paths: Optional[List] = None
                               ) -> ChannelCapacityReport:
    """
    启发式估计密码学实现的侧信道容量上界。
    注意: 返回的是静态启发式估计，非严格的Shannon互信息。
    """
    anchors = []
    key_bits = 128
    algo_name = 'unknown'

    if crypto_findings:
        for f in crypto_findings:
            try:
                anchors.append(getattr(f, 'location', 0))
                algo = getattr(f, 'algorithm', '')
                if algo:
                    algo_name = algo
                    import re
                    m = re.search(r'(\d+)', algo)
                    if m:
                        kb = int(m.group(1))
                        if kb >= 64:
                            key_bits = kb
            except Exception:
                pass

    if not anchors:
        anchors = [0]

    anchor = anchors[0]
    channels: List[ChannelCapacity] = [
        _estimate_timing_capacity(data, anchor),
        _estimate_cache_capacity(data, anchor),
        _estimate_power_capacity(data, anchor),
        _estimate_direct_capacity(data, anchor, key_size_bits=key_bits),
    ]

    # 信道容量聚合(启发式上界; 信道间有相关性需折扣)
    total_raw = sum(c.raw_capacity_bits for c in channels)
    # 相关性折扣因子≈0.7(基于典型x86微架构的指令级并行度)
    total_leak = total_raw * 0.7
    total_leak = min(total_leak, key_bits)  # 不超过密钥熵

    effective = max(0.0, key_bits - total_leak)
    ratio = total_leak / key_bits if key_bits > 0 else 0.0

    if ratio < 0.05:
        risk = 'NEGLIGIBLE'
    elif ratio < 0.20:
        risk = 'LOW'
    elif ratio < 0.50:
        risk = 'MEDIUM'
    elif ratio < 0.80:
        risk = 'HIGH'
    else:
        risk = 'CRITICAL'

    return ChannelCapacityReport(
        algorithm=algo_name, key_size_bits=key_bits,
        channels=channels,
        total_estimated_leak_bits=round(total_leak, 2),
        effective_security_bits=round(effective, 1),
        leakage_ratio=round(ratio, 4),
        risk_assessment=risk)
