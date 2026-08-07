"""
ML-QED-Lite 库版本指纹检测 — QED-Lite 轻量级静态二进制分析。

参考: QED-Lite: 855x 加速，100% 真阳性率。
三阶段: 文件级 → API 级 → 调用图级。
简化实现以字节级模式匹配 + 调用约定推断近似 Phase 1/2。
"""

import struct
from typing import List

__all__ = [
    "_simulate_qed_lite_fingerprint",
]


def _simulate_qed_lite_fingerprint(data: bytes) -> List[dict]:
    """
    QED-Lite 库版本指纹检测。

    QED-Lite 三阶段:
      Phase 1: 文件级 — 二进制格式 + 导入表
      Phase 2: API 级 — 已知 PQC API 函数名匹配
      Phase 3: 调用图级 — PQC API 调用序列合法性验证

    简化: 字节级模式匹配 + 调用约定推断 ≈ Phase 1/2。
    Phase 3 需完整反汇编/IR，当前不可行；可放入 Tier 2 完整版。

    检测库: liboqs 0.7.0-0.11.0, PQClean, OpenSSL 3.2+ OSSL_PROVIDER
    """
    findings = []

    # Phase 1: 文件级 — PQC 命名符号导出检测
    lib_version_patterns = [
        # (pattern_bytes, lib, version, confidence)
        (rb'OQS_KEM_kyber_512', 'liboqs', '>=0.7.0', 0.92),
        (rb'OQS_KEM_kyber_768', 'liboqs', '>=0.7.0', 0.92),
        (rb'OQS_KEM_kyber_1024', 'liboqs', '>=0.7.0', 0.92),
        (rb'OQS_SIG_dilithium_2', 'liboqs', '>=0.7.0', 0.92),
        (rb'OQS_SIG_dilithium_3', 'liboqs', '>=0.7.0', 0.92),
        (rb'OQS_SIG_dilithium_5', 'liboqs', '>=0.7.0', 0.92),
        (rb'OQS_SIG_falcon_512', 'liboqs', '>=0.8.0', 0.90),
        (rb'OQS_SIG_falcon_1024', 'liboqs', '>=0.8.0', 0.90),
        (rb'OQS_SIG_sphincs', 'liboqs', '>=0.9.0', 0.88),
        (rb'pqcrystals_kyber', 'PQClean', 'commit-based', 0.94),
        (rb'pqcrystals_dilithium', 'PQClean', 'commit-based', 0.94),
        (rb'PQCLEAN_KYBER', 'PQClean', 'commit-based', 0.94),
        (rb'PQCLEAN_DILITHIUM', 'PQClean', 'commit-based', 0.94),
        (rb'OSSL_PROVIDER_load.*pqc', 'OpenSSL3+', '>=3.2.0', 0.82),
        (rb'OSSL_ALGORITHM.*kyber', 'OpenSSL3+', '>=3.2.0', 0.82),
        (rb'Botan::KYBER', 'Botan_PQC', '>=3.0.0', 0.88),
        (rb'crypto_kem_keypair', 'libsodium_PQC', '>=1.0.20', 0.80),
        (rb'PQCLEAN_FALCON', 'PQClean', 'commit-based', 0.94),
        # BIKE + HQC
        (rb'OQS_KEM_bike', 'liboqs', '>=0.10.0', 0.90),
        (rb'OQS_KEM_hqc', 'liboqs', '>=0.10.0', 0.90),
        (rb'crypto_kem_bike', 'liboqs', '>=0.10.0', 0.88),
    ]

    for pattern, lib, version, conf in lib_version_patterns:
        if pattern in data:
            findings.append({
                "lib": lib,
                "version": version,
                "confidence": conf,
                "evidence": f"QED-Lite Phase 2 匹配: {pattern.decode('ascii', errors='replace')}",
            })

    # Phase 2: NIST 参数指纹 — 标准化参数常量组合
    # (q=3329, n=256) → Kyber; (q=8380417, n=256) → Dilithium
    param_pairs = [
        (3329, 256, "Kyber/ML-KEM NIST FIPS 203"),
        (8380417, 256, "Dilithium/ML-DSA NIST FIPS 204"),
        (12289, 512, "Falcon/FN-DSA NIST FIPS 206"),
    ]
    for q_val, n_val, desc in param_pairs:
        q_packed = struct.pack("<H", q_val)
        n_packed = struct.pack("<H", n_val)
        if q_packed in data and n_packed in data:
            findings.append({
                "lib": "any_NIST_PQC",
                "version": "NIST-standard",
                "confidence": 0.78,
                "evidence": f"QED-Lite Phase 2 参数: {desc} (q={q_val}, n={n_val})",
            })

    return findings
