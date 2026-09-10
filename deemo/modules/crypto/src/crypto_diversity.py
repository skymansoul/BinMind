"""
密码学实现多样性分析 — 检测同一二进制中同一算法的多个独立实现并评估供应链风险。

设计意图:
  供应链安全的一条基本原则是"最小化密码学实现多样性" — 每多一个AES实现,
  就多一个潜在漏洞面。但现有工具(crypto_lib_fingerprint, crypto_lineage)仅
  识别"哪个库", 不回答"同一算法有多少个不同的实现"。

  这在以下场景中构成实质性风险:
    (a) 固件同时静态链接了OpenSSL的AES和mbedTLS的AES — 任何一个库的AES漏洞
        都会影响固件。两个实现的维护成本和攻击面是单个实现的两倍。
    (b) 主固件用硬件AES-NI, 但bootloader用软件AES查找表 — 软件实现的缓存侧信道
        可能成为攻击入口, 即使主固件是常量时间。
    (c) 多个协议栈各自携带独立的密码学实现 — IoT设备可能同时有TLS库的AES+
        SSH库的AES+应用层自实现的AES=3个独立的攻击面。

  检测策略:
    1. 从crypto_detector输出中按算法名分组。
    2. 对每组, 使用crypto_semantic_hash提取每个实例的语义指纹。
    3. 计算组内成对汉明距离 → 聚类为独立实现。
    4. 推断实现来源(硬件加速/软件查表/bit-sliced)。
    5. 输出多样性评分和风险等级。

  - Nadi et al.: "Where Do Cryptographic Libraries Come From?" —
    开源项目中密码学实现的来源多样性研究。本项目将同一分析推广到二进制。
  - Synopsys 2024 OSSRA Report: 78%的代码库包含开源组件, 其中密码学库
    是最常被重复引入的类别。
  - CWE-1104: Use of Unmaintained Third-Party Components — 多个密码学实现
    增加了无意中使用过时/脆弱版本的概率。

边界条件:
  - 多样性检测的精度依赖crypto_detector的完整性 — 漏检的实现不参与计数。
  - 高度混淆的代码可能导致同一实现被误判为多个 → 通过聚类阈值得分调整。
  - 硬件加速实现(SIMD/AES-NI)vs软件实现在语义类空间中可区分。
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# crypto_semantic_hash的延迟导入 — 避免循环依赖
# 运行时导入确保仅在实际执行多样性分析时才加载

_IMPL_TYPE_PATTERNS: Dict[str, List[bytes]] = {
    'AES-NI': [b'aesni', b'_mm_aes', b'vaesenc', b'aesenc',
               b'0f 38 dd', b'0f 38 de', b'0f 38 db', b'0f 38 dc'],
    'ARM-CE': [b'aese', b'aesmc', b'aesd', b'0f 38 dd'],
    'software-T': [b'Te0', b'Te1', b'Te2', b'Te3', b'Td0',
                   b'sbox', b'SBOX', b'S-box', b'aes_table'],
    'bit-sliced': [b'bitslice', b'bit_slice', b'bs_aes', b'bs_{'],
    'hardware-PKE': [b'PKCS11', b'pkcs11', b'C_Encrypt', b'C_Decrypt'],
}

@dataclass
class ImplementationVariant:
    algorithm: str = ""
    impl_type: str = ""           # AES-NI / software-T / bit-sliced / etc.
    anchor_offset: int = 0
    confidence: float = 0.0
    lib_hint: str = ""            # 推断的库来源

@dataclass
class DiversityReport:
    algorithm: str = ""
    variant_count: int = 0
    variants: List[ImplementationVariant] = field(default_factory=list)
    diversity_score: float = 0.0     # 0=单一实现, 1=高度多样化
    risk_level: str = "LOW"         # LOW / MEDIUM / HIGH / CRITICAL
    supply_chain_risk: str = ""     # 人类可读的风险描述
    recommendations: List[str] = field(default_factory=list)

def _infer_impl_type(data: bytes, anchor: int, window: int = 512) -> Tuple[str, float]:
    """推断密码学实现的类型(硬件加速/软件查表/bit-sliced)。"""
    start = max(0, anchor - window // 2)
    region = data[start:anchor + window // 2]

    scores: Dict[str, int] = {}
    for impl_type, patterns in _IMPL_TYPE_PATTERNS.items():
        score = 0
        for pat in patterns:
            if pat in region:
                score += 1
        scores[impl_type] = score

    if not scores:
        return 'unknown', 0.3

    best = max(scores, key=scores.get)
    max_score = scores[best]
    if max_score == 0:
        return 'software-generic', 0.4

    conf = min(0.90, 0.45 + max_score * 0.15)
    return best, conf

def _infer_lib_source(strings: List[str], anchor_strings: List[str]) -> str:
    """从字符串上下文推断库来源。"""
    lib_hints = {
        'OpenSSL': [b'OpenSSL', b'openssl', b'SSL_', b'EVP_'],
        'mbedTLS': [b'mbedtls', b'mbed TLS'],
        'wolfSSL': [b'wolfSSL', b'wolfssl', b'wc_Aes'],
        'libsodium': [b'libsodium', b'sodium', b'crypto_secretbox'],
        'BoringSSL': [b'BoringSSL', b'bssl'],
        'Crypto++': [b'CryptoPP', b'Crypto++'],
        'Go crypto': [b'crypto/aes', b'crypto/sha256'],
        'custom': [b'custom', b'proprietary'],
    }
    all_strs = [s.encode('ascii', errors='replace') if isinstance(s, str) else s
                for s in (strings or []) + (anchor_strings or [])]
    scores = defaultdict(int)
    for lib, patterns in lib_hints.items():
        for pat in patterns:
            for s in all_strs:
                if pat in s:
                    scores[lib] += 1

    if not scores:
        return 'unknown'
    return max(scores, key=scores.get)

def analyze_diversity(data: bytes,
                      crypto_findings: Optional[List] = None,
                      strings: Optional[List[str]] = None,
                      hamming_cluster_threshold: int = 12
                      ) -> List[DiversityReport]:
    """
    分析密码学实现多样性。
    按算法分组, 对每组内的实例做语义指纹聚类, 统计独立实现数。
    """
    if not crypto_findings:
        return []

    # 按算法分组
    algo_groups: Dict[str, List] = defaultdict(list)
    for f in crypto_findings:
        try:
            algo = getattr(f, 'algorithm', 'unknown')
            algo_groups[algo].append(f)
        except Exception:
            pass

    reports: List[DiversityReport] = []

    # 延迟导入语义哈希模块
    try:
        from .crypto_semantic_hash import extract_fingerprint, SemanticFingerprint
    except ImportError:
        # 降级: 不进行语义聚类, 仅统计检测次数
        for algo, findings in algo_groups.items():
            reports.append(DiversityReport(
                algorithm=algo, variant_count=len(findings),
                diversity_score=min(1.0, len(findings) / 10.0),
                risk_level='MEDIUM' if len(findings) > 1 else 'LOW',
                supply_chain_risk=f'{len(findings)} detection(s) of {algo}'))
        return reports

    for algo, findings in algo_groups.items():
        if len(findings) < 2:
            impl_type, conf = _infer_impl_type(data, getattr(findings[0], 'location', 0))
            reports.append(DiversityReport(
                algorithm=algo, variant_count=1, diversity_score=0.0,
                risk_level='LOW',
                variants=[ImplementationVariant(
                    algorithm=algo, impl_type=impl_type,
                    anchor_offset=getattr(findings[0], 'location', 0),
                    confidence=conf)]))
            continue

        # 提取各实例的语义指纹
        fingerprints: List[SemanticFingerprint] = []
        for f in findings:
            try:
                fp = extract_fingerprint(data,
                                         anchor_offset=getattr(f, 'location', 0),
                                         window_size=512, algorithm=algo)
                fingerprints.append(fp)
            except Exception:
                continue

        if len(fingerprints) < 2:
            reports.append(DiversityReport(
                algorithm=algo, variant_count=len(findings),
                diversity_score=0.0, risk_level='LOW'))
            continue

        # 成对汉明距离聚类 → 独立实现数
        n = len(fingerprints)
        clusters: List[Set[int]] = []
        assigned: Set[int] = set()

        for i in range(n):
            if i in assigned:
                continue
            cluster: Set[int] = {i}
            for j in range(i + 1, n):
                if j in assigned:
                    continue
                hd = fingerprints[i].hamming_distance(fingerprints[j])
                if hd <= hamming_cluster_threshold:
                    cluster.add(j)
            clusters.append(cluster)
            assigned.update(cluster)

        # 构建各聚类的实现变体
        variants: List[ImplementationVariant] = []
        for cluster_idx, indices in enumerate(clusters):
            rep_idx = min(indices)
            rep_f = findings[rep_idx]
            loc = getattr(rep_f, 'location', 0)
            impl_type, conf = _infer_impl_type(data, loc)
            anchor_strs = []  # 可从data[loc:loc+256]提取, 此处省略以控制复杂度
            lib_hint = _infer_lib_source(strings or [], anchor_strs)
            variants.append(ImplementationVariant(
                algorithm=algo, impl_type=impl_type,
                anchor_offset=loc, confidence=conf,
                lib_hint=lib_hint))

        # 多样性评分
        div_score = min(1.0, (len(clusters) - 1) / max(1, len(findings) - 1) * 2.0)

        # 风险等级
        if len(clusters) == 1:
            risk = 'LOW'
        elif len(clusters) == 2:
            risk = 'MEDIUM'
        elif len(clusters) <= 4:
            risk = 'HIGH'
        else:
            risk = 'CRITICAL'

        # 风险描述与建议
        impl_types = set(v.impl_type for v in variants)
        recs = []
        if 'software-T' in impl_types:
            recs.append('软件查表实现 → 考虑迁移到硬件加速或bit-sliced常量时间实现')
        if len(clusters) >= 3:
            recs.append(f'{len(clusters)}个独立实现 → 审计每个实现的已知CVE; 考虑统一到单一库')
        if len(clusters) >= 2 and 'AES-NI' in impl_types and 'software-T' in impl_types:
            recs.append('混合硬件/软件实现 → 确认软件路径不会降级安全性')

        risk_desc = f'{len(clusters)} independent implementation(s) detected for {algo}'
        if len(impl_types) > 1:
            risk_desc += f' across {len(impl_types)} implementation types'

        reports.append(DiversityReport(
            algorithm=algo, variant_count=len(clusters),
            variants=variants, diversity_score=round(div_score, 3),
            risk_level=risk, supply_chain_risk=risk_desc,
            recommendations=recs))

    return reports
