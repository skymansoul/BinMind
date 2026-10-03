# binary_profiling — 二进制深度分析原语
# 提供 binary_scanner.py 所需的熵/ngram/加密常量/shellcode/APIhashing/XOR混淆/IOC 函数
# 原有代码从 ..info_collect 导入但函数未定义，此处补齐实现
# PE/ELF 深度解析见 pe_elf_analysis.py

import math, re, struct
from typing import Dict, List, Optional
from collections import Counter
from ._shared import shannon_entropy as _shannon_entropy

_SUSPICIOUS_ENTROPY_RATIO = 0.35
_WINDOW_SIZE = 256



def compute_section_entropy_profile(raw: bytes, window: int = _WINDOW_SIZE) -> Dict:
    """滑动窗口 Shannon 熵扫描，返回均值/最大值/高熵比/方差。"""
    if len(raw) < window:
        e = _shannon_entropy(raw)
        return {"mean_entropy": round(e,4), "max_entropy": round(e,4),
                "min_entropy": round(e,4), "high_window_ratio": 1.0 if e > 7.0 else 0.0,
                "entropy_variance": 0.0, "window_size": window, "total_windows": 1}
    ents, hi = [], 0
    for off in range(0, len(raw) - window + 1, window // 2):
        ent = _shannon_entropy(raw[off:off + window]); ents.append(ent)
        if ent > 7.0: hi += 1
    mean_e = sum(ents) / len(ents)
    return {"mean_entropy": round(mean_e,4), "max_entropy": round(max(ents),4),
            "min_entropy": round(min(ents),4),
            "high_window_ratio": round(hi / len(ents),4),
            "entropy_variance": round(sum((e - mean_e)**2 for e in ents) / len(ents),4),
            "window_size": window, "total_windows": len(ents)}


def compute_ngram_fingerprint(raw: bytes, n: int = 4, top_k: int = 50) -> Dict:
    """4-gram 频率指纹。unique_ngram_ratio 低 → 重复结构（加密/填充）。"""
    if len(raw) < n:
        return {"unique_ngram_ratio": 0.0, "top_ngrams": [], "total_ngrams": 0}
    ngrams = Counter(raw[i:i + n] for i in range(len(raw) - n + 1))
    total = sum(ngrams.values())
    return {"unique_ngram_ratio": round(len(ngrams) / max(total, 1), 6),
            "top_ngrams": [(h.hex(), c) for h, c in ngrams.most_common(top_k)],
            "total_ngrams": total, "unique_ngrams": len(ngrams)}


_CRYPTO_CONSTANTS = {
    "AES": [b"\x63\x7c\x77\x7b"], "DES": [b"\x01\x01\x02\x02"],
    "MD5": [bytes([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef])],
    "SHA1": [bytes([0x67,0x45,0x23,0x01,0xef,0xcd,0xab,0x89])],
    "SHA256": [bytes([0x6a,0x09,0xe6,0x67,0xbb,0x67,0xae,0x85])],
    "CRC32": [b"\x00\x00\x00\x00"],
    "Base64": [b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"],
}


def scan_crypto_constants(raw: bytes) -> List[Dict]:
    """扫描已知加密常量（S-box/IV/初始哈希值），返回算法名+偏移。"""
    hits = []
    for algo, patterns in _CRYPTO_CONSTANTS.items():
        for pat in patterns:
            off = 0
            while True:
                pos = raw.find(pat, off)
                if pos == -1: break
                hits.append({"algorithm": algo, "offset": pos, "pattern_hex": pat.hex()})
                off = pos + 1
                if len(hits) > 100: break
    return hits


_SHELLCODE_PATS = [b'\xfc\x48\x83', b'\x31\xc0\x50', b'\xe8\x00\x00\x00\x00',
                   b'\x55\x8b\xec', bytes([0x0f,0xa2]), bytes([0x0f,0x31])]


def detect_shellcode_patterns(raw: bytes) -> Dict:
    """已知 shellcode 字节模式扫描。"""
    found = [p.hex() for p in _SHELLCODE_PATS if p in raw]
    return {"patterns_found": found, "pattern_count": len(found)}


def detect_api_hashing(raw: bytes) -> Dict:
    """API 哈希检测：高密度 4 字节小整数暗示 API 名被哈希化。"""
    if len(raw) < 256: return {"likely_api_hashing": False, "hash_density": 0.0}
    hash_like = 0
    for i in range(0, len(raw) - 4, 4):
        val = struct.unpack_from('<I', raw, i)[0]
        if 0x1000 < val < 0xFFFF0000: hash_like += 1
    density = hash_like / max(len(raw) // 4, 1)
    return {"likely_api_hashing": density > 0.3, "hash_density": round(density, 4)}


def detect_xor_obfuscated_strings(raw: bytes, entropy_profile: Dict = None) -> Dict:
    """XOR 混淆字符串检测：高熵+低可打印比+单字节 XOR 密钥枚举。"""
    if len(raw) < 256: return {"xor_obfuscation_likely": False, "best_key": None, "confidence": 0.0}
    high_ent = entropy_profile.get("high_window_ratio", 0.0) if entropy_profile else 0.0
    printable = sum(1 for b in raw[:4096] if 0x20 <= b <= 0x7E)
    if high_ent <= 0.2 or printable / min(len(raw), 4096) >= 0.3:
        return {"xor_obfuscation_likely": False, "best_key": None, "confidence": 0.0}
    best_key, best_ratio = None, 0.0
    for key in [0x00, 0x20, 0x41, 0x55, 0xAA, 0xFF]:
        pr = sum(1 for b in (bytes(b ^ key for b in raw[:1024])) if 0x20 <= b <= 0x7E) / 1024
        if pr > best_ratio: best_ratio, best_key = pr, key
    if best_ratio > 0.6:
        return {"xor_obfuscation_likely": True, "best_key": hex(best_key),
                "confidence": round(best_ratio - 0.5, 4)}
    return {"xor_obfuscation_likely": False, "best_key": None, "confidence": 0.0}


def analyze_import_table_anomalies(strings: List[str]) -> Dict:
    """导入表异常检测：短、高熵、无元音字母的导入名 → 疑似哈希化。"""
    if not strings: return {"likely_hashed_imports": False, "anomalous_count": 0}
    hashed = sum(1 for s in strings if 6 <= len(s.strip()) <= 20
                 and not any(c in 'aeiou' for c in s.strip().lower()))
    return {"likely_hashed_imports": hashed > 5, "anomalous_count": hashed}


_IP_PAT = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_URL_PAT = re.compile(r'https?://[^\s\'\"<>]{4,}')
_DOMAIN_PAT = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,})\b')
_NAMED_OBJ_PAT = re.compile(r'(?:CreateMutex|CreateEvent|CreateSemaphore)\s*\(\s*["\']([^"\']+)["\']')


def extract_network_iocs(strings: List[str]) -> Dict:
    """字符串 → IP/URL/域名 IOC 提取。"""
    text = '\n'.join(str(s) for s in strings)
    ips = list(set(_IP_PAT.findall(text)))[:50]
    urls = list(set(_URL_PAT.findall(text)))[:50]
    domains = [d for d in set(_DOMAIN_PAT.findall(text))
               if d not in ips and not d.endswith('.exe')][:100]
    return {"total": len(ips) + len(urls) + len(domains),
            "ips": ips[:20], "urls": urls[:20], "domains": domains[:30]}


def extract_named_objects(strings: List[str]) -> Dict:
    """提取命名内核对象（Mutex/Event/Semaphore）。"""
    text = '\n'.join(str(s) for s in strings)
    matches = _NAMED_OBJ_PAT.findall(text)
    return {"total": len(matches), "objects": list(set(matches))[:30]}
