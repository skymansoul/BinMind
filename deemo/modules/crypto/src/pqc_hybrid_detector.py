"""
后量子混合方案检测 — 识别二进制中同时部署经典和PQC算法的混合密码学构造。

修改记录:
  2025-08-27 16:53 — 初始实现: 混合密钥交换/双证书链/串联KDF/Chrome-BoringSSL模式检测

设计意图:
  后量子迁移的过渡期策略是"混合" — 同时使用经典算法(X25519/ECDH)和PQC算法
  (ML-KEM), 将两者的密钥材料串联后输入KDF, 确保即使PQC被破解, 经典算法仍提供
  保护。Chrome/Cloudflare/Apple已在TLS中部署X25519+ML-KEM-768混合密钥交换。

  混合方案的二进制检测对审计至关重要:
    (a) 混合实现是否正确 — 是否有回退到纯经典的降级路径?
    (b) 密钥材料组合是否正确 — 是否真的串联了两者的输出?
    (c) 是否存在"假混合" — 声称混合但仅使用了其中一种算法的输出?

  检测策略:
    1. 双密钥交换结构: 同一TLS握手中先后调用经典KEX+PQC KEM。
    2. 串联KDF模式: HKDF-Extract的输入是classical_shared_secret || pq_shared_secret。
    3. 双证书检测: 经典证书链 + PQC证书链共存。
    4. 库版本指纹: BoringSSL/OpenSSL 3.x/liboqs中混合方案的特有API序列。

参考:
  - Chrome/Google (2024): "A new path for Kyber on the web" —
    Chrome 131+使用X25519MLKEM768, 迁移路径从KyberDraft00到ML-KEM。
  - IETF TLS WG Hybrid Key Exchange (draft-ietf-tls-hybrid-design, 2024):
    混合密钥交换的设计规范和串联KDF构造。
  - rustls (2024): "prefer-post-quantum"特性支持混合KEX。
  - OpenSSL 3.5+ (2025): 原生ML-KEM支持及混合模式。

边界条件:
  - 混合方案检测需要识别两种不同算法的API调用在相近代码区域共存。
  - 若PQC和经典KEX实现在不同编译单元, 检测窗口可能需要扩大到函数间调用图。
  - 自定义混合方案(非标准串联KDF)可能漏检。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class HybridDetection:
    scheme_type: str = ""          # HYBRID_KEX / HYBRID_SIGNATURE / DUAL_CERT
    classical_algo: str = ""
    pq_algo: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    location_hint: int = 0
    downgrade_risk: str = ""       # 是否存在纯经典回退路径
    kdf_combiner: str = ""         # 密钥材料组合方式(串联/异或/独立)


# ── 经典+PQC算法配对模式 ──
# 混合方案要求在相近代码区域内同时检测到经典和PQC算法
_HYBRID_PAIRS: List[Tuple[str, str, str, float]] = [
    # (经典算法名片段, PQC算法名片段, 方案描述, 置信度)
    ('X25519', 'ML-KEM', 'X25519+ML-KEM-768 hybrid KEX (Chrome/Cloudflare)', 0.88),
    ('Curve25519', 'ML-KEM', 'X25519+ML-KEM-768 hybrid KEX', 0.85),
    ('ECDH', 'ML-KEM', 'ECDH+ML-KEM hybrid KEX', 0.82),
    ('X25519', 'Kyber', 'X25519+Kyber768Draft00 (legacy hybrid)', 0.78),
    ('secp256r1', 'ML-KEM', 'P-256+ML-KEM hybrid KEX', 0.82),
    ('secp384r1', 'ML-KEM', 'P-384+ML-KEM-1024 hybrid KEX', 0.82),
    ('ECDSA', 'ML-DSA', 'ECDSA+ML-DSA hybrid signature', 0.80),
    ('Ed25519', 'ML-DSA', 'Ed25519+ML-DSA hybrid signature', 0.80),
    ('RSA', 'ML-DSA', 'RSA+ML-DSA hybrid signature (dual cert)', 0.78),
]

# ── 串联KDF模式 ──
_CONCAT_KDF_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'HKDF_extract', 'HKDF-Extract串联(标准)', 0.82),
    (b'concat_kdf', 'concatenation KDF', 0.85),
    (b'hybrid_kdf', 'named hybrid KDF', 0.90),
    (b'hybrid_shared_secret', 'hybrid shared secret concat', 0.88),
    (b'classical_shared', 'classical+PQC key material', 0.85),
    (b'pq_shared_secret', 'PQC key material', 0.82),
    (b'concatenated_key', 'concatenated key material', 0.78),
]

# ── 混合方案库指纹 ──
_HYBRID_LIB_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'X25519Kyber768', 'Chrome legacy hybrid (KyberDraft00)', 0.90),
    (b'X25519MLKEM768', 'Chrome/Cloudflare hybrid (ML-KEM)', 0.95),
    (b'SecP256r1MLKEM768', 'P-256+ML-KEM hybrid', 0.92),
    (b'SecP384r1MLKEM1024', 'P-384+ML-KEM hybrid', 0.92),
    (b'SSL_GROUP_X25519_KYBER', 'BoringSSL hybrid group', 0.90),
    (b'SSL_GROUP_X25519_MLKEM', 'BoringSSL hybrid ML-KEM group', 0.92),
    (b'OQS_KEM_', 'OpenQuantumSafe hybrid', 0.80),
    (b'pqc_hybrid', 'generic PQC hybrid', 0.75),
    (b'hybrid_kex', 'hybrid key exchange', 0.78),
    (b'prefer-post-quantum', 'rustls PQ preference', 0.85),
    (b'hybrid_certificate', 'dual/hybrid certificate chain', 0.82),
]


def _find_algo_in_findings(findings: List, name_fragment: str) -> List[int]:
    """在crypto findings中搜索匹配算法的位置。"""
    locations = []
    for f in findings:
        try:
            algo = getattr(f, 'algorithm', '')
            if name_fragment.lower() in algo.lower():
                locations.append(getattr(f, 'location', 0))
        except Exception:
            pass
    return locations


def _co_location_score(locs_a: List[int], locs_b: List[int],
                        window: int = 4096) -> float:
    """评估两组位置是否在相同代码区域内。返回共区位得分 0-1。"""
    if not locs_a or not locs_b:
        return 0.0
    close_pairs = 0
    for la in locs_a:
        for lb in locs_b:
            if abs(la - lb) <= window:
                close_pairs += 1
    max_pairs = max(len(locs_a), len(locs_b))
    return min(1.0, close_pairs / max_pairs) if max_pairs > 0 else 0.0


def detect_hybrid_schemes(data: bytes,
                          strings: Optional[List[str]] = None,
                          crypto_findings: Optional[List] = None
                          ) -> List[HybridDetection]:
    """
    检测二进制中的混合PQC方案。
    crypto_findings: crypto_detector的检测结果(含PQC和经典算法)。
    """
    detections: List[HybridDetection] = []
    findings = crypto_findings or []
    strs = strings or []

    # 1. 算法配对检测(经典+PQC共现)
    for classical, pq, desc, base_conf in _HYBRID_PAIRS:
        classical_locs = _find_algo_in_findings(findings, classical)
        pq_locs = _find_algo_in_findings(findings, pq)
        if classical_locs and pq_locs:
            colocation = _co_location_score(classical_locs, pq_locs)
            if colocation > 0.3:
                conf = base_conf * (0.6 + 0.4 * colocation)
                evidence = [
                    f'{classical}: {len(classical_locs)} instance(s)',
                    f'{pq}: {len(pq_locs)} instance(s)',
                    f'co-location score: {colocation:.2f}']
                detections.append(HybridDetection(
                    scheme_type='HYBRID_KEX' if 'KEM' in pq or 'Kyber' in pq
                    else 'HYBRID_SIGNATURE',
                    classical_algo=classical, pq_algo=pq,
                    confidence=conf, evidence=evidence,
                    location_hint=classical_locs[0]))

    # 2. 串联KDF检测
    for pat, desc, conf in _CONCAT_KDF_PATTERNS:
        if pat in data:
            detections.append(HybridDetection(
                scheme_type='HYBRID_KEX',
                classical_algo='unknown', pq_algo='unknown',
                confidence=conf,
                evidence=[f'KDF pattern: {desc}'],
                kdf_combiner='HKDF-Extract concatenation'))

    # 3. 库字符串指纹
    for pat, desc, conf in _HYBRID_LIB_PATTERNS:
        if pat in data:
            detections.append(HybridDetection(
                scheme_type='HYBRID_KEX',
                classical_algo='X25519/ECDH', pq_algo='ML-KEM',
                confidence=conf,
                evidence=[f'Library fingerprint: {desc}'],
                downgrade_risk='取决于库版本'))

        for s in strs:
            sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
            if pat in sb:
                detections.append(HybridDetection(
                    scheme_type='HYBRID_KEX',
                    classical_algo='X25519/ECDH', pq_algo='ML-KEM',
                    confidence=conf * 0.90,
                    evidence=[f'String: "{s[:50]}" -> {desc}'],
                    downgrade_risk='字符串可能存在但运行时不可达'))

    # 4. 降级风险评估
    for d in detections:
        if d.downgrade_risk == '':
            # 检查是否存在纯经典回退路径
            has_classical_only = any(
                f for f in findings
                if getattr(f, 'algorithm', '') in ('X25519', 'ECDH', 'secp256r1')
                and getattr(f, 'algorithm', '') not in ('ML-KEM', 'Kyber'))
            if has_classical_only:
                d.downgrade_risk = '存在纯经典回退路径 — 可能被降级攻击'
                d.evidence.append('downgrade: 纯经典算法实例同时存在')

    return sorted(detections, key=lambda d: -d.confidence)
