"""
密码学敏捷性审计 — 从二进制静态特征评估加密实现迁移到新算法的难易程度。

修改记录:
  2025-08-05 10:18 — 初始实现: 5维敏捷性评分 + 算法耦合度/参数外置化/抽象层检测

设计意图:
  后量子密码学迁移(PQC migration)是当前最紧迫的密码学工程问题。OMB M-23-02和
  CNSA 2.0要求联邦系统在2030年前完成PQC迁移。迁移的最大障碍不是算法安全性,
  而是密码学实现的"敏捷性" — 代码是否被设计为可替换算法。

  已有crypto_lib_fingerprint识别"此二进制使用了OpenSSL 3.2", 但无法回答
  "从该OpenSSL版本迁移到PQC需要改多少处代码"。本模块从5个维度量化敏捷性:

  D1 (算法耦合度): 算法名/模式是否硬编码在二进制字符串中? 越多越难替换。
  D2 (密钥尺寸柔性): 密钥/分组/摘要尺寸是否可配置? 硬编码尺寸使PQC大密钥无法适配。
  D3 (库抽象层): 调用是否通过通用API(EVP)还是直接调用底层函数?
  D4 (配置外置化): 算法参数是否在可写数据段(配置文件/环境变量)而非只读段?
  D5 (更新表面): 需要修改多少处代码位置才能完成一次算法替换?

  敏捷性评分 0-1: 0=完全僵化(固定算法, 需重写), 1=完全敏捷(配置驱动替换)。

  - Comcast CARAF: 密码学敏捷性测量框架 — 11项yes/no评分。本模块将其
    概念从组织级别移植到二进制级别。
  - CAMM Maturity Model: 5级敏捷性成熟度 — 本模块的输出可映射到CAMM级别。
  - QED: 量子脆弱可执行文件检测 — 检测哪些二进制需要PQC迁移。
    本模块补充QED: QED告诉你"要改", 本模块告诉你"改起来多难"。
  - OMB M-23-02 / NSM-10 / CNSA 2.0: 联邦PQC迁移政策要求。

边界条件:
  - 敏捷性评分基于静态特征估计 — 不执行代码, 不确认运行时行为。
  - 加壳/混淆的二进制 → 字符串分析失效 → 评分趋近于0(保守估计)。
  - 解释型语言(Python/Java)的字节码具有不同的敏捷性特征 — 当前聚焦原生二进制。
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 评分权重
_W1 = 0.30  # 算法耦合度: 占比最高 — 这是迁移的主障碍
_W2 = 0.20  # 密钥尺寸柔性: PQC密钥更大, 硬编码尺寸是最常见的迁移阻断
_W3 = 0.20  # 库抽象层: 抽象层存在性决定迁移工作量级
_W4 = 0.15  # 配置外置化: 无需重编译即可替换 → 运维成本大幅降低
_W5 = 0.15  # 更新表面: 需改动的代码位置数量

@dataclass
class AgilityReport:
    algorithm: str = ""
    file_path: str = ""
    d1_coupling: float = 0.0       # 0=完全抽象, 1=完全焊死
    d2_key_flex: float = 0.0       # 0=充分柔性, 1=硬编码
    d3_abstraction: float = 0.0    # 0=高度抽象, 1=无抽象
    d4_config: float = 0.0         # 0=全外置, 1=全硬编码
    d5_surface: float = 0.0        # 0=单点变更, 1=散弹式修改
    composite_score: float = 0.0
    agility_level: str = "UNKNOWN"  # PETRIFIED / LOW / MODERATE / HIGH / FULLY_AGILE
    flags: List[str] = field(default_factory=list)
    estimated_change_points: int = 0

# 算法名硬编码模式
# 字符串中出现以下模式 → 算法耦合信号
_ALGO_NAME_PATTERNS: List[Tuple[bytes, float]] = [
    # 明确的算法名引用 (权重较高)
    (b'AES-128-CBC', 0.95), (b'AES-256-GCM', 0.95),
    (b'AES_128', 0.85), (b'AES_256', 0.85),
    (b'SHA-256', 0.80), (b'SHA-512', 0.80),
    (b'RSA-2048', 0.90), (b'RSA-4096', 0.90),
    (b'ECDSA', 0.75), (b'ECDHE', 0.75),
    (b'secp256r1', 0.85), (b'secp384r1', 0.85),
    (b'ChaCha20-Poly1305', 0.90), (b'X25519', 0.80),
    # 较弱的信号 (可能出现在注释/调试字符串中)
    (b'cipher', 0.30), (b'encrypt', 0.25),
]
# 抽象模式 — 出现这些降低耦合得分
_ABSTRACTION_PATTERNS: List[Tuple[bytes, float]] = [
    (b'EVP_CIPHER', 0.90), (b'EVP_MD', 0.85),
    (b'EVP_PKEY', 0.90), (b'EVP_AEAD', 0.90),
    (b'Cipher.getInstance', 0.80),  # Java JCA抽象层
    (b'crypto/cipher.Block', 0.80),  # Go crypto抽象接口
    (b'AlgorithmParameterSpec', 0.75),
    (b'OSSL_PROVIDER', 0.85),  # OpenSSL 3.0 provider架构
    (b'crypto_aead_', 0.70),  # libsodium通用AEAD接口
]
# 密钥尺寸硬编码模式
_KEY_SIZE_PATTERNS: List[Tuple[bytes, float]] = [
    (b'AES_KEY_128', 0.90), (b'AES_KEY_192', 0.90), (b'AES_KEY_256', 0.90),
    (b'KEY_LENGTH', 0.60), (b'KEY_SIZE', 0.60), (b'key_len', 0.50),
    (b'RSA_KEY_SZ', 0.85), (b'RSA_KEY_SIZE', 0.85),
    (b'DH_KEY_SIZE', 0.80), (b'EC_KEY_SIZE', 0.80),
    (b'#define AES_KEY', 0.85), (b'#define RSA_KEY', 0.85),
    (b'const int key_size', 0.70), (b'static const int ksize', 0.70),
]

def _count_patterns(data: bytes, patterns: List[Tuple[bytes, float]],
                    strings: Optional[List[str]] = None) -> Tuple[int, float]:
    """统计区域内模式匹配。返回(命中数, 加权得分)"""
    hits = 0
    weighted = 0.0
    for pat, weight in patterns:
        count = data.count(pat)
        if count > 0:
            hits += count
            weighted += weight * min(count, 3)
    # 也在字符串列表中搜索
    if strings:
        for s in strings:
            sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
            for pat, weight in patterns:
                if pat in sb:
                    hits += 1
                    weighted += weight * 0.5
    return hits, min(1.0, weighted / max(len(patterns), 1))

def _score_coupling(data: bytes, strings: Optional[List[str]] = None) -> Tuple[float, int]:
    """D1: 算法耦合度 — 硬编码算法名越多, 耦合越紧。"""
    algo_hits, algo_score = _count_patterns(data, _ALGO_NAME_PATTERNS, strings)
    _, abstract_score = _count_patterns(data, _ABSTRACTION_PATTERNS, strings)
    # 耦合 = 硬编码得分 - 抽象层得分 (抽象层抵消部分耦合)
    raw = algo_score - abstract_score * 0.6
    return max(0.0, min(1.0, raw)), algo_hits

def _score_key_flexibility(data: bytes, strings: Optional[List[str]] = None) -> Tuple[float, int]:
    """D2: 密钥尺寸柔性 — 硬编码的密钥尺寸限制PQC大密钥。"""
    hits, score = _count_patterns(data, _KEY_SIZE_PATTERNS, strings)
    return score, hits

def _score_abstraction(strings: Optional[List[str]] = None) -> Tuple[float, int]:
    """D3: 库抽象层 — 统计抽象API vs 直接调用底层函数的比例。"""
    if not strings:
        return 0.5, 0

    abstract_count = 0
    direct_count = 0

    abstract_sigs = {b'EVP_', b'Cipher.getInstance', b'crypto.Cipher',
                     b'KeyGenerator', b'Mac.getInstance', b'crypto_aead',
                     b'crypto_secretbox', b'OSSL_PROVIDER'}
    direct_sigs = {b'AES_encrypt', b'AES_decrypt', b'SHA256_Init',
                   b'RSA_private_encrypt', b'aesni_', b'_mm_aes',
                   b'rijndael', b'serpent_', b'twofish_'}

    for s in strings:
        sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
        if any(pat in sb for pat in abstract_sigs):
            abstract_count += 1
        if any(pat in sb for pat in direct_sigs):
            direct_count += 1

    total = abstract_count + direct_count
    if total == 0:
        return 0.5, 0

    # 抽象比例 = abstract/(abstract+direct); 转换为得分: 高抽象→低分(好)
    abstract_ratio = abstract_count / total
    score = 1.0 - abstract_ratio  # 0=全抽象(好), 1=全直接(差)
    return score, total

def _score_config_externalization(data: bytes) -> Tuple[float, int]:
    """D4: 配置外置化 — 统计配置路径/env var引用。"""
    config_patterns = [
        (b'/etc/', 0.85), (b'.conf', 0.75), (b'.yaml', 0.70),
        (b'.json', 0.65), (b'getenv', 0.80), (b'environ', 0.75),
        (b'config_file', 0.75), (b'crypto_policy', 0.85),
        (b'OPENSSL_CONF', 0.90), (b'SSL_CONF', 0.80),
    ]
    hits, weighted = 0, 0.0
    for pat, w in config_patterns:
        c = data.count(pat)
        if c > 0:
            hits += c
            weighted += w * min(c, 2)

    if hits > 0:
        score = max(0.1, 1.0 - min(1.0, weighted / 5.0))
    else:
        score = 0.90
    return score, hits

def _score_update_surface(data: bytes, findings_count: int = 0) -> Tuple[float, int]:
    """D5: 更新表面 — 估计需要修改的位置数。"""
    # 统计密码学相关的唯一字符串引用点
    crypto_refs = set()
    for m in re.finditer(rb'(aes|AES|des|DES|rsa|RSA|sha|SHA|md5|MD5'
                         rb'|chacha|ecdsa|ECDSA|ed25519|curve25519'
                         rb'|dh|DH|ecdh|ECDH)', data):
        crypto_refs.add(m.start() // 256)  # 每256B一个区块

    estimated_points = max(1, len(crypto_refs) + findings_count)
    # 1个点→0.05; 5个点→0.5; 20+个点→0.95
    if estimated_points <= 1:
        score = 0.05
    elif estimated_points <= 3:
        score = 0.25
    elif estimated_points <= 8:
        score = 0.55
    elif estimated_points <= 15:
        score = 0.80
    else:
        score = 0.95
    return score, estimated_points

def audit_agility(data: bytes, strings: Optional[List[str]] = None,
                  findings: Optional[List] = None,
                  algorithm: str = "", file_path: str = "") -> AgilityReport:
    d1, n1 = _score_coupling(data, strings)
    d2, n2 = _score_key_flexibility(data, strings)
    d3, n3 = _score_abstraction(strings)
    d4, n4 = _score_config_externalization(data)
    d5, n5 = _score_update_surface(data, len(findings) if findings else 0)

    composite = _W1 * d1 + _W2 * d2 + _W3 * d3 + _W4 * d4 + _W5 * d5
    # 得分低=敏捷; 得分高=僵化
    if composite < 0.20:
        level = "FULLY_AGILE"
    elif composite < 0.35:
        level = "HIGH"
    elif composite < 0.55:
        level = "MODERATE"
    elif composite < 0.75:
        level = "LOW"
    else:
        level = "PETRIFIED"

    flags = []
    if d1 > 0.7:
        flags.append("tightly_coupled_algorithms")
    if d2 > 0.7:
        flags.append("hardcoded_key_sizes")
    if d3 > 0.7:
        flags.append("no_crypto_abstraction_layer")
    if d4 > 0.7:
        flags.append("no_external_configuration")
    if d5 > 0.7:
        flags.append("scattered_change_points")

    return AgilityReport(
        algorithm=algorithm, file_path=file_path,
        d1_coupling=round(d1, 4), d2_key_flex=round(d2, 4),
        d3_abstraction=round(d3, 4), d4_config=round(d4, 4),
        d5_surface=round(d5, 4),
        composite_score=round(composite, 4),
        agility_level=level, flags=flags,
        estimated_change_points=n5,
    )
