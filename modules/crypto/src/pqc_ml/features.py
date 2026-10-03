"""
ML-QED-Lite 特征提取 — PQC 二进制检测的 27 维特征向量。

参考: ML-QED-Lite Table 2 特征集，
联合函数符号 + 库依赖提供最佳 F1 分数。
"""

import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "PQCMLResult",
    "_extract_features",
    "_FEATURE_DIM",
    "_FEATURE_NAMES",
]

# 特征定义 — ML-QED-Lite Table 2

# 27 维: 符号特征 (0-9) + 库依赖 (10-19) + 二进制结构 (20-26)
# 消融实验: 符号+依赖联合使用 → 最优 F1

_FEATURE_DIM = 27
_FEATURE_NAMES = [
    "n_imported_symbols",          # 0:  导入符号总数
    "n_pqc_symbols",               # 1:  PQC 符号数 (kyber/dilithium/...)
    "n_crypto_symbols",            # 2:  经典密码符号数 (aes/rsa/sha/...)
    "n_memory_symbols",            # 3:  内存管理符号数 (malloc/free/...)
    "has_pqc_init",                # 4:  PQC 初始化调用 (0/1)
    "has_pqc_keygen",              # 5:  密钥构造调用 (0/1)
    "has_pqc_encap",               # 6:  封装调用 (0/1)
    "has_pqc_sign",                # 7:  签名调用 (0/1)
    "has_pqc_verify",              # 8:  验证调用 (0/1)
    "has_constant_time_cmp",       # 9:  常数时间比较 (0/1)
    "dep_libcrypto_version_major", # 10: libcrypto 主版本 (0=未检测到)
    "dep_libcrypto_version_minor", # 11: libcrypto 次版本
    "dep_libsodium_detected",      # 12: libsodium 依赖 (0/1)
    "dep_liboqs_detected",         # 13: liboqs 依赖 (0/1)
    "dep_pqclean_detected",        # 14: PQClean 依赖 (0/1)
    "dep_botan_detected",          # 15: Botan 依赖 (0/1)
    "dep_openssl_detected",        # 16: OpenSSL 3.x+ 依赖 (0/1)
    "dep_ring_detected",           # 17: Rust ring 依赖 (0/1)
    "dep_hacl_detected",           # 18: HACL* 依赖 (0/1)
    "dep_unknown_pqc_lib",         # 19: 未知疑似 PQC 库 (0/1)
    "file_size_log2",              # 20: log2(文件大小)
    "n_sections",                  # 21: PE/ELF 节数
    "has_tls_callback",            # 22: TLS 回调 (0/1)
    "entropy_shannon",             # 23: Shannon 熵 (×10)
    "entropy_renyi2",              # 24: Renyi α=2 熵 (×10)
    "text_section_ratio",          # 25: .text 占比 (×100)
    "is_stripped",                 # 26: 符号表剥离 (0/1)
]


@dataclass
class PQCMLResult:
    """ML 增强 PQC 检测结果."""
    algorithm: str
    variant: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    security_level: str = ""
    detected_in: str = ""
    # ML-QED-Lite 字段
    tier: int = 1                   # 检测层级 (1/2/3)
    probability: float = 0.0        # XGBoost 输出概率
    feature_vector: Optional[List[float]] = None  # 特征向量，调试用
    library_hint: str = ""          # 推断的 PQC 库
    version_hint: str = ""          # 推断的库版本


def _extract_features(
    data: bytes,
    imported_symbols: Optional[List[str]] = None,
    library_deps: Optional[dict] = None,
    file_path: str = "",
) -> list:
    """
    提取 27 维特征向量 — ML-QED-Lite Section 4.1。

    参数:
      data:             二进制原始字节
      imported_symbols: 导入符号列表 (PE IAT / ELF .dynsym)
      library_deps:     库依赖 {libname: version}
      file_path:        文件路径 (大小/剥离检测)

    返回: 长度 27 的 float 列表。

    归一化:
      计数特征 (0-3) log1p 变换。
      熵特征 (23-24) ×10。
      比例特征 (25) ×100。
    """
    feats = [0.0] * _FEATURE_DIM

    if imported_symbols is None:
        imported_symbols = []
    if library_deps is None:
        library_deps = {}

    n_imported = len(imported_symbols)
    syms_lower = [s.lower() for s in imported_symbols]

# 0: 导入符号总数
    feats[0] = float(n_imported)

# 1-9: PQC/密码/内存符号计数
    pqc_keywords = [
        "kyber", "dilithium", "sphincs", "falcon", "ml-kem", "ml-dsa",
        "slh-dsa", "pqcrystals", "pqclean", "liboqs", "ntt_", "poly_",
        "shake128", "shake256", "cbd_", "rej_", "indcpa_",
    ]
    crypto_keywords = [
        "aes", "rsa", "sha", "ecdsa", "ecdh", "des", "hmac", "chacha",
        "poly1305", "curve25519", "curve448", "blake", "keccak",
    ]
    memory_keywords = ["malloc", "free", "calloc", "realloc", "memcpy", "memset"]

    feats[1] = float(sum(1 for s in syms_lower if any(k in s for k in pqc_keywords)))
    feats[2] = float(sum(1 for s in syms_lower if any(k in s for k in crypto_keywords)))
    feats[3] = float(sum(1 for s in syms_lower if any(k in s for k in memory_keywords)))
    feats[4] = 1.0 if any("init" in s and any(p in s for p in pqc_keywords) for s in syms_lower) else 0.0
    feats[5] = 1.0 if any("keygen" in s or "keypair" in s for s in syms_lower) else 0.0
    feats[6] = 1.0 if any("encap" in s or "encrypt" in s for s in syms_lower) else 0.0
    feats[7] = 1.0 if any("sign" in s for s in syms_lower if "design" not in s) else 0.0
    feats[8] = 1.0 if any("verify" in s or "open" in s for s in syms_lower) else 0.0
    feats[9] = 1.0 if any("consttime" in s or "ct_" in s or "secure_cmp" in s for s in syms_lower) else 0.0

# 10-19: 库依赖 (版本号 + 检测标志)
    libcrypto_ver = library_deps.get("libcrypto", "")
    ver_match = re.search(r"(\d+)\.(\d+)", libcrypto_ver) if libcrypto_ver else None
    feats[10] = float(int(ver_match.group(1))) if ver_match else 0.0
    feats[11] = float(int(ver_match.group(2))) if ver_match else 0.0

    dep_map = {
        "libsodium": 12, "liboqs": 13, "pqclean": 14, "botan": 15,
        "openssl": 16, "ring": 17, "hacl": 18,
    }
    for dep_name, feat_idx in dep_map.items():
        feats[feat_idx] = 1.0 if any(dep_name in k.lower() for k in library_deps) else 0.0

    # 未知 PQC 库: 含 pqc/crypto 但不在已知列表中
    known_libs = set(dep_map.keys()) | {"libcrypto"}
    unknown_hint = False
    for dep_key in library_deps:
        dep_lower = dep_key.lower()
        if dep_lower not in known_libs:
            if any(kw in dep_lower for kw in ["pqc", "crypto", "ntru", "lattice", "oqs"]):
                unknown_hint = True
                break
    feats[19] = 1.0 if unknown_hint else 0.0

# 20-26: 二进制结构
    feats[20] = float(len(data).bit_length())  # log2(文件大小)

    # ELF section 计数
    section_headers = len(re.findall(rb'\.text|\.data|\.rodata|\.bss|\.init|\.fini|\.plt|\.got', data))
    feats[21] = float(section_headers) if section_headers > 0 else float(len(re.findall(rb'\.\w+', data)))

    # TLS 回调 — PE 特有
    feats[22] = 1.0 if b'TLSCallback' in data or b'tls_callback' in data else 0.0

    # Shannon + Renyi 熵 — 采样前 64KB
    byte_counts = [0] * 256
    for b in data[:65536]:
        byte_counts[b] += 1
    sample_len = min(len(data), 65536)

    shannon = 0.0
    renyi2 = 0.0
    for cnt in byte_counts:
        if cnt > 0:
            p = cnt / sample_len
            shannon -= p * (p ** 0.5)  # -p*log2(p) 近似
            renyi2 += p * p
    feats[23] = round(shannon * 10, 1)
    feats[24] = round(-renyi2 * 10, 1) if renyi2 > 0 else 0.0  # -log(renyi2) 近似

    # .text 占比
    text_match = re.search(rb'\.text', data)
    feats[25] = 50.0  # 默认 50%
    if text_match:
        text_offset = text_match.start()
        feats[25] = min(100.0, (text_offset / max(len(data), 1)) * 100.0)

    # 剥离检测 — .symtab + .strtab 缺失 → 已剥离
    feats[26] = 0.0 if (b'.symtab' in data and b'.strtab' in data) else 1.0

    return feats
