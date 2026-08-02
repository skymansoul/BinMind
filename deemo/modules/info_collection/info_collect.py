"""二进制信息采集 — 格式识别、字符串/导入表提取、熵分析、N-gram 指纹、节区权限、密码常量、Rich Header、签名、Overlay。"""

import logging, os, math, re, struct
from collections import Counter

logger = logging.getLogger(__name__)

DANGEROUS_FUNCTIONS = {"gets", "strcpy", "system", "execve", "scanf", "free",
                        "sprintf", "strcat", "memcpy", "popen"}
KEY_STRING_PATTERNS = {"system", "bin/sh", "flag", "password", "secret", "key"}
KERNEL_DANGEROUS_FUNCTIONS = ["copy_from_user", "copy_to_user", "sprintf",
                               "strcpy", "strncpy", "memcpy"]
KERNEL_DRIVER_DANGEROUS_FUNCTIONS = ["IoControlCode", "MmMapIoSpace",
                                      "ExAllocatePool", "ZwOpenProcess"]

# ── 熵分析：区分压缩/加密段与正常代码段 ──────────────────────────────────
# 参照 PROTEUS 的 section-level entropy 策略，但使用滑动窗口而非全段单值，
# 以避免大段内局部高熵区被均值淹没。窗口大小 256B，步长 128B。
_ENTROPY_WINDOW = 256
_ENTROPY_STEP = 128
# 经验阈值：正常代码/数据段熵中位数约 4.5–5.5，加密/压缩段通常 > 7.0
_HIGH_ENTROPY_THRESHOLD = 7.2
_SUSPICIOUS_ENTROPY_RATIO = 0.15  # 高熵窗口占比超此值则标记可疑


def _shannon_entropy(data: bytes) -> float:
    """单窗口 Shannon 熵，取值 [0, 8]，8 表示完全随机。"""
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def compute_section_entropy_profile(raw: bytes) -> dict:
    """对任意字节块计算滑动窗口熵分布，返回统计摘要。

    返回 dict: min, max, median, mean, high_window_ratio (高熵窗口占比)
    设计意图：单次 O(n) 遍历，避免重复分片带来的内存分配开销。
    """
    n = len(raw)
    if n < _ENTROPY_WINDOW:
        e = _shannon_entropy(raw)
        return {"min": e, "max": e, "median": e, "mean": e,
                "high_window_ratio": 1.0 if e > _HIGH_ENTROPY_THRESHOLD else 0.0}

    entropies = []
    pos = 0
    while pos + _ENTROPY_WINDOW <= n:
        entropies.append(_shannon_entropy(raw[pos:pos + _ENTROPY_WINDOW]))
        pos += _ENTROPY_STEP
    if pos < n:
        tail = raw[pos:]
        if len(tail) >= 64:
            entropies.append(_shannon_entropy(tail))

    if not entropies:
        return {"min": 0, "max": 0, "median": 0, "mean": 0, "high_window_ratio": 0}

    entropies.sort()
    mid = len(entropies) // 2
    median = entropies[mid] if len(entropies) % 2 else (entropies[mid - 1] + entropies[mid]) / 2
    high_cnt = sum(1 for e in entropies if e > _HIGH_ENTROPY_THRESHOLD)

    return {
        "min": entropies[0],
        "max": entropies[-1],
        "median": median,
        "mean": sum(entropies) / len(entropies),
        "high_window_ratio": high_cnt / len(entropies),
    }


# ── 字节 N-gram 指纹：参照 Zipf-Gramming (CIKM 2025) ──────────────────
# 统计 top-K 4-gram 及其频率，作为二进制结构的紧凑指纹。
# 4-gram 选择理由：单字节无上下文，2/3-gram 区分度不足，
# 5+ gram 在小型样本上稀疏度过高。4-gram 在 256^4 空间中
# 经 Zipf 定律压缩后，top-64 通常覆盖 40–60% 的区分信息。
_NGRAM_N = 4
_NGRAM_TOP_K = 64
# 字节类别：0x00 空字节、0x20–0x7E 可打印 ASCII、
# 0x80–0xBF 非首字节 UTF-8、0xC0–0xFF 首字节/高位
_BYTE_CLASS_THRESHOLDS = [
    (0x00, 0x01, "null"),
    (0x01, 0x20, "control"),
    (0x20, 0x7F, "printable"),
    (0x7F, 0xC0, "high_byte"),
    (0xC0, 0x100, "utf8_lead"),
]


def _classify_byte(b: int) -> str:
    for lo, hi, label in _BYTE_CLASS_THRESHOLDS:
        if lo <= b < hi:
            return label
    return "unknown"


def compute_ngram_fingerprint(raw: bytes) -> dict:
    """提取二进制文件的 top-K 4-gram 及字节类别分布。

    返回字典: top_ngrams (list of (hex_string, count)),
              byte_class_distribution (dict class → fraction),
              unique_ngram_ratio (唯一 4-gram 数 / 总窗口数)
    算法：单次 O(n) 滑动窗口 + Counter，k=4 小常数。
    """
    n = len(raw)
    if n < _NGRAM_N:
        return {"top_ngrams": [], "byte_class_distribution": {},
                "unique_ngram_ratio": 0.0}

    ngram_counter = Counter()
    byte_classes = Counter()
    window_count = n - _NGRAM_N + 1

    # 单次遍历同时收集 n-gram 与字节类别
    i = 0
    while i < window_count:
        ngram = raw[i:i + _NGRAM_N]
        ngram_counter[ngram] += 1
        byte_classes[_classify_byte(raw[i])] += 1
        i += 1
    # 尾字节类别统计
    while i < n:
        byte_classes[_classify_byte(raw[i])] += 1
        i += 1

    top_ngrams = [(ng.hex(), cnt) for ng, cnt in ngram_counter.most_common(_NGRAM_TOP_K)]
    unique_ratio = len(ngram_counter) / max(1, window_count)

    total_bytes = max(1, n)
    byte_dist = {label: round(byte_classes[label] / total_bytes, 4)
                 for label, _, _ in _BYTE_CLASS_THRESHOLDS
                 for label in (label,)}

    return {
        "top_ngrams": top_ngrams,
        "byte_class_distribution": byte_dist,
        "unique_ngram_ratio": round(unique_ratio, 4),
    }


# ── 跨二进制相似度 ─────────────────────────────────────────────────────────

def compute_ngram_jaccard(fp_a: dict, fp_b: dict) -> float:
    """两个 N-gram 指纹的 Jaccard 相似系数。

    J(A,B) = |A ∩ B| / |A ∪ B|。仅比较 top-64 以达到亚毫秒级速度。
    用于快速判定两个二进制是否共享相同的静态链接库、编译器或代码片段。
    """
    ngrams_a = {ng for ng, _ in (fp_a.get("top_ngrams") or [])}
    ngrams_b = {ng for ng, _ in (fp_b.get("top_ngrams") or [])}
    if not ngrams_a or not ngrams_b:
        return 0.0
    intersection = ngrams_a & ngrams_b
    union = ngrams_a | ngrams_b
    return len(intersection) / len(union) if union else 0.0


# ── 密码学常量扫描 ────────────────────────────────────────────────────────
# 常见对称加密/哈希算法的初始化常量与 S-Box。匹配静态链接的常量表，
# 不检测动态加载的加密库。

_CRYPTO_SIGNATURES: list[tuple[str, bytes, str]] = [
    ("AES_SBOX", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]),
     "AES encryption (Rijndael S-box)"),
    ("AES_INV_SBOX", bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
                            0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]),
     "AES decryption (inverse S-box)"),
    ("SHA256_IV", bytes([0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
                         0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A]),
     "SHA-256 IV constants"),
    ("SHA1_IV", bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
                       0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76]),
     "SHA-1 IV constants"),
    ("MD5_IV", bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]),
     "MD5 IV constants"),
    ("CHACHA20", b"expand 32-byte k", "ChaCha20 constant"),
    ("XTEA_DELTA", bytes([0xB9, 0x79, 0x37, 0x9E]), "TEA/XTEA delta constant"),
    ("BLOWFISH_PI", bytes([0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3]),
     "Blowfish Pi P-array"),
    ("BASE64_ALPH", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", "Base64 encoding alphabet"),
]

# 仅通过 GetProcAddress 获取而无静态导入字符串的函数 → 动态解析嫌疑
_DYNAMIC_RESOLVE_SUSPICIOUS = {
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
    "WriteProcessMemory", "NtUnmapViewOfSection", "QueueUserAPC",
    "OpenProcess", "ReadProcessMemory", "LoadLibraryA",
}


def scan_crypto_constants(raw: bytes) -> list[dict]:
    """在二进制数据中搜索已知密码学常量表。

    返回: [{"algorithm": str, "constant_name": str, "offset": int, "desc": str}, ...]
    遍历 _CRYPTO_SIGNATURES 中所有签名 → 全文件字节搜索。
    复杂度：O(k·n)，k=签名数固定 < 20，n=文件长度。
    """
    hits = []
    raw_len = len(raw)
    for name, sig, desc in _CRYPTO_SIGNATURES:
        pos = -1
        while True:
            pos = raw.find(sig, pos + 1)
            if pos == -1:
                break
            # 去重：避免同一常量在相邻偏移的重复匹配
            if not any(h.get('offset', -1) == pos for h in hits):
                hits.append({
                    "algorithm": name.split('_')[0] if '_' in name else name,
                    "constant_name": name, "offset": pos, "description": desc,
                })
            pos += max(1, len(sig) // 2)
            if pos >= raw_len:
                break
    hits.sort(key=lambda h: h['offset'])
    return hits


# ── PE 节区权限分析：W^X 违规检测 ────────────────────────────────────────
# 同时具有 EXECUTE + WRITE 权限的节区 → 自修改代码/shellcode/JIT 特征。
# 非 JIT 的正常二进制中极为罕见。

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE   = 0x80000000
_KNOWN_EXEC_SECTIONS = {
    b'.text', b'CODE', b'.code', b'INIT', b'PAGE',
    b'INITK', b'PAGEKD', b'.itext', b'.rdata',
}


def analyze_pe_sections(raw: bytes) -> dict:
    """分析 PE 节区表，检测 W^X 违规与可疑节区名。"""
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"sections": [], "wxe_violations": 0, "exec_in_data": []}
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        num_sects = struct.unpack_from("<H", raw, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", raw, pe_off + 20)[0]
        sec_base = pe_off + 24 + opt_hdr_size
        sections = []
        wxe_count = 0
        exec_in_data = []
        for i in range(num_sects):
            off = sec_base + i * 40
            name_bytes = raw[off:off + 8].rstrip(b'\x00')
            name = name_bytes.decode('ascii', errors='replace').strip('\x00')
            flags = struct.unpack_from("<I", raw, off + 36)[0]
            is_exec = bool(flags & _IMAGE_SCN_MEM_EXECUTE)
            is_write = bool(flags & _IMAGE_SCN_MEM_WRITE)
            wxe = is_exec and is_write
            vsize = struct.unpack_from("<I", raw, off + 8)[0]
            sections.append({
                "name": name, "virtual_size": vsize,
                "characteristics": f"0x{flags:08x}",
                "executable": is_exec, "writable": is_write, "wxe_violation": wxe,
            })
            if wxe:
                wxe_count += 1
            if is_exec and name_bytes not in _KNOWN_EXEC_SECTIONS:
                exec_in_data.append(name)
        return {"sections": sections, "wxe_violations": wxe_count,
                "exec_in_data": exec_in_data}
    except Exception:
        return {"sections": [], "wxe_violations": 0, "exec_in_data": []}


def analyze_import_table_anomalies(strings_in_binary: list[str]) -> dict:
    """检测导入表异常：GetProcAddress 存在但敏感 API 无明文静态引用。

    恶意软件常用模式：通过 GetProcAddress + 运行时计算的 API 名
    （哈希/解密）规避静态导入表检测。
    """
    if not strings_in_binary:
        return {"dynamic_only_apis": [], "score": 0.0}
    strs_lower = set(s.lower() for s in strings_in_binary)
    has_gpa = "getprocaddress" in strs_lower
    if not has_gpa:
        return {"dynamic_only_apis": [], "score": 0.0}

    dynamic_only = []
    for api in _DYNAMIC_RESOLVE_SUSPICIOUS:
        if api.lower() not in strs_lower:
            dynamic_only.append(api)

    score = len(dynamic_only) / max(1, len(_DYNAMIC_RESOLVE_SUSPICIOUS))
    return {
        "dynamic_only_apis": dynamic_only,
        "score": round(score, 2),
        "likely_hashed_imports": score > 0.5,
    }


# ── 网络 IOC 提取 ─────────────────────────────────────────────────────────
# C2 域名、IP、URL 模式提取。正则匹配 ASCII 字符串中的网络资源引用，
# 仅提取而不过滤 — 过滤由上层调用者按场景决定。

_HOSTNAME_RE = re.compile(
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
)
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
)
_URL_RE = re.compile(
    r'https?://[a-zA-Z0-9][-a-zA-Z0-9_.]{0,63}(?::\d{1,5})?'
    r'(?:/[^\s"\'<>]*)?',
)


def extract_network_iocs(strings_in_binary: list[str]) -> dict:
    """从二进制字符串中提取网络 IOC（域名/IP/URL）。

    返回: {"domains": [...], "ips": [...], "urls": [...], "total": int}
    不做合法性过滤；内网 IP 和公共 IP 均保留。
    """
    domains = set()
    ips = set()
    urls = set()

    for s in strings_in_binary:
        for m in _HOSTNAME_RE.finditer(s):
            dom = m.group(0).lower()
            # 排除纯数字 TLD 误匹配（如文件版本号）
            if not dom.split('.')[-1].isdigit():
                domains.add(dom)
        for m in _IPV4_RE.finditer(s):
            ips.add(m.group(0))
        for m in _URL_RE.finditer(s):
            urls.add(m.group(0))

    return {
        "domains": sorted(domains)[:100],
        "ips": sorted(ips)[:50],
        "urls": sorted(urls)[:50],
        "total": len(domains) + len(ips) + len(urls),
    }


# ── Shellcode 启发式检测 ──────────────────────────────────────────────────
# 参照 libemu/libscizzle 的 GetPC 识别与解码器循环检测策略。
# 不执行模拟 — 仅通过字节模式匹配识别常见 shellcode 惯用法。

_SHELLCODE_PATTERNS: list[tuple[str, bytes, str]] = [
    # GetPC: call $+5; pop eax (E8 00 00 00 00 58)
    ("GetPC_call_pop", b'\xE8\x00\x00\x00\x00\x58', "call $+5; pop eax"),
    # GetPC: call $+5; pop ecx
    ("GetPC_call_pop_ecx", b'\xE8\x00\x00\x00\x00\x59', "call $+5; pop ecx"),
    # GetPC: fldz; fnstenv (D9 EE D9 74 24 F4)
    ("GetPC_fpu", b'\xD9\xEE\xD9\x74\x24\xF4', "fldz; fnstenv GetPC"),
    # 解码器循环: xor [reg+offset], key (30 / 31 / 80 31 opcodes)
    # 简化检测：连续 4+ 条 XOR byte [reg+disp] 指令特征
    # 栈迁移: mov esp, ebp; popad; ret (89 EC 61 C3)
    ("stack_pivot", b'\x89\xEC\x61\xC3', "mov esp,ebp; popad; ret"),
    # pushad → shellcode 入口点常见的全寄存器保存
    ("pushad", b'\x60', "pushad"),
    # pushfd → 标志保存（反调试/shellcode 通用）
    ("pushfd", b'\x9C', "pushfd"),
]

# 解码器循环特征：连续 3 条以上 XOR/MOV byte [reg+disp] 指令
# x86 XOR [reg+disp8], imm8 = 80 / 30 / 31 前缀
_XOR_MEM_BYTE_PAT = re.compile(
    b'(?:\x80[\x70-\x7F\xB0-\xBF]|\x30[\x40-\x7F\x80-\xBF]|\x31[\x40-\x7F\x80-\xBF]){3,}'
)


def detect_shellcode_patterns(raw: bytes) -> dict:
    """检测二进制中的 shellcode 惯用法字节模式。

    返回: {"patterns_found": [...], "decoder_loop": bool, "getpc_methods": [...],
            "shellcode_likelihood": float}
    likelihood 由各项加权求和：GetPC 模式 +0.3，解码器循环 +0.4，
    pushad/pushfd +0.1。
    """
    found = []
    likelihood = 0.0
    getpc_methods = []
    decoder = False

    for name, sig, desc in _SHELLCODE_PATTERNS:
        if sig in raw:
            found.append({"pattern": name, "description": desc})
            if name.startswith("GetPC"):
                getpc_methods.append(name)
            if name == "stack_pivot":
                likelihood += 0.3
            elif name == "pushad":
                likelihood += 0.1
            elif name == "pushfd":
                likelihood += 0.1

    # 解码器循环检测
    if _XOR_MEM_BYTE_PAT.search(raw):
        found.append({"pattern": "decoder_loop", "description": "连续 XOR byte [mem] 解码器循环"})
        decoder = True
        likelihood += 0.4

    if getpc_methods:
        likelihood += 0.3

    return {
        "patterns_found": found,
        "decoder_loop_detected": decoder,
        "getpc_methods": getpc_methods,
        "shellcode_likelihood": min(round(likelihood, 2), 1.0),
    }


# ── 跨检测器统一威胁评分 ─────────────────────────────────────────────────
# Bayesian 元融合：将多个独立检测器的输出置信度合并为单一威胁评分。
# 假设各检测器输出独立（检测维度不同），使用乘积形式：
#   combined = 1 - Π(1 - c_i)
# 每个检测器提供 (name, confidence) 对。

def compute_unified_threat(scores: list[tuple[str, float]]) -> dict:
    """融合多检测器置信度为统一威胁评分。

    参数: scores — [(detector_name, confidence_0_to_1), ...]
    返回: {"combined_score": float, "contributors": int, "highest": [...]}
    """
    if not scores:
        return {"combined_score": 0.0, "contributors": 0, "highest": []}
    prod = 1.0
    for _, c in scores:
        if c > 0:
            prod *= (1.0 - min(c, 1.0))
    ranked = sorted(scores, key=lambda x: x[1], reverse=True)
    return {
        "combined_score": round(1.0 - prod, 3),
        "contributors": len(scores),
        "highest": ranked[:3],
    }


# ── API 哈希检测 ──────────────────────────────────────────────────────────
# 恶意软件常用 ROR13/DJB2/CRC32 等哈希算法动态解析 API，
# 以规避静态导入表检测。检测策略：在二进制字节流中搜索
# 已知哈希算法的特征常数与常见 API 名的预计算哈希值。
# 参照 HashDB (OALabs) 与 FLARE shellcode_hashes 的预计算哈希数据库。

# DJB2 种子
_DJB2_SEED = b'\x05\x15\x00\x00'  # 5381 in LE

# CRC32 多项式常见表示 (0xEDB88320 LE)
_CRC32_POLY_LE = b'\x20\x83\xB8\xED'

# 常见 API 名的 ROR13 预计算哈希 (LE dword)
_ROR13_KNOWN_HASHES: dict[bytes, str] = {
    bytes([0x5B, 0xBC, 0x4A, 0x6A]): "kernel32.dll",
    bytes([0x5D, 0x68, 0xFA, 0x3C]): "ntdll.dll",
    bytes([0x8E, 0x4E, 0x0E, 0xEC]): "LoadLibraryA",
    bytes([0xAA, 0xFC, 0x0D, 0x7C]): "GetProcAddress",
    bytes([0x54, 0xCA, 0xAF, 0x91]): "VirtualAlloc",
    bytes([0x16, 0x12, 0xB2, 0x86]): "VirtualProtect",
    bytes([0x7C, 0x0E, 0x5F, 0x1E]): "CreateRemoteThread",
    bytes([0x67, 0x6B, 0xD5, 0x16]): "WriteProcessMemory",
    bytes([0xB8, 0x0A, 0x34, 0x53]): "NtFlushInstructionCache",
    bytes([0x6A, 0x51, 0xA9, 0xE5]): "WinExec",
    bytes([0x2A, 0xD1, 0xCD, 0x60]): "IsDebuggerPresent",
}


def detect_api_hashing(raw: bytes) -> dict:
    """检测二进制中 API 哈希使用的迹象。

    三步检测：哈希常量扫描 (DJB2 seed / CRC32 poly) →
    ROR13 预计算哈希匹配 → 综合评分。
    返回: {"hash_constants_found": [...], "ror13_matches": [...],
            "likely_api_hashing": bool, "score": float}
    """
    found_constants = []
    ror13_matches = []
    score = 0.0

    # 步骤一：搜索哈希算法常量
    if _DJB2_SEED in raw:
        found_constants.append("DJB2_seed (5381)")
        score += 0.2
    if _CRC32_POLY_LE in raw:
        found_constants.append("CRC32_polynomial (0xEDB88320)")
        score += 0.2

    # 步骤二：搜索 ROR13 预计算哈希值
    for hash_bytes, label in _ROR13_KNOWN_HASHES.items():
        if hash_bytes in raw:
            ror13_matches.append({"hash_hex": hash_bytes.hex(), "api": label})
            score += 0.15

    # 步骤三：GetProcAddress 存在 + 稀疏导入表 = 强指示
    # (稀疏导入表由 analyze_import_table_anomalies 独立检测)

    return {
        "hash_constants_found": found_constants,
        "ror13_matches": ror13_matches,
        "likely_api_hashing": score > 0.3,
        "score": round(min(score, 1.0), 2),
    }


# ── XOR 编码字符串启发式 ──────────────────────────────────────────────────
# 恶意软件常用的 XOR 编码字符串特征：
# 1. 数据段中存在大量非 ASCII 字节块，但单字节 XOR 后可转为可打印 ASCII。
# 2. 堆栈字符串：连续的 MOV byte [reg+offset], imm 指令序列。
# 检测策略：遍历二进制，对每个字节块测试常见的单字节 XOR key (0x01–0xFF)，
# 若解码后 ASCII 占比 > 0.85 且长度为 8–512 字节，则标记为可疑 XOR 块。

_XOR_CANDIDATE_MIN_LEN = 8
_XOR_CANDIDATE_MAX_LEN = 512
_XOR_ASCII_RATIO_THRESHOLD = 0.85
# 仅在非代码段（高熵段）中搜索，避免对正常代码的误报
_XOR_SEARCH_MIN_ENTROPY = 4.5


def _try_xor_decode(data: bytes, key: int) -> str:
    return ''.join(chr(b ^ key) for b in data)


def _ascii_ratio(decoded: str) -> float:
    if not decoded:
        return 0.0
    return sum(1 for c in decoded if 0x20 <= ord(c) <= 0x7E) / len(decoded)


def detect_xor_obfuscated_strings(raw: bytes, entropy_profile: dict = None) -> dict:
    """检测二进制中的单字节 XOR 编码字符串。

    对高熵区域 (entropy > 4.5) 中的每个 8–512 字节窗口测试
    256 种 XOR key，统计解码后可打印 ASCII 占比。
    复杂度：O(k·n)，k=256, n=窗口数。对大文件采样前 512KB。
    """
    sample = raw[:524_288] if len(raw) > 524_288 else raw
    n = len(sample)
    if n < _XOR_CANDIDATE_MIN_LEN:
        return {"xor_blocks": [], "unique_keys": []}

    # 仅在高熵区搜索
    if entropy_profile and entropy_profile.get("mean", 0) < _XOR_SEARCH_MIN_ENTROPY:
        return {"xor_blocks": [], "unique_keys": []}

    found_blocks = []
    keys_seen = set()

    # 滑动窗口：步长 = 候选长度 // 2
    step = max(4, _XOR_CANDIDATE_MIN_LEN // 2)
    for win_size in (_XOR_CANDIDATE_MIN_LEN, 16, 32, 64, 128, 256, 512):
        pos = 0
        while pos + win_size <= n:
            chunk = sample[pos:pos + win_size]
            # 跳过全零/全相同块
            if len(set(chunk)) <= 2:
                pos += step
                continue
            for key in range(1, 256):
                decoded = _try_xor_decode(chunk, key)
                if _ascii_ratio(decoded) > _XOR_ASCII_RATIO_THRESHOLD:
                    preview = decoded[:64]
                    found_blocks.append({
                        "offset": pos, "size": win_size,
                        "xor_key_hex": f"0x{key:02x}",
                        "decoded_preview": preview,
                    })
                    keys_seen.add(key)
                    break  # 每个窗口仅记录首个有效 key
            pos += step

    # 去重：相同 key 且重叠的窗口合并为最佳候选
    if len(found_blocks) > 20:
        found_blocks = found_blocks[:20]

    return {
        "xor_blocks": found_blocks,
        "unique_keys": sorted(keys_seen),
        "xor_obfuscation_likely": len(found_blocks) >= 3,
        "common_xor_keys": _analyze_xor_key_distribution(found_blocks),
    }


def _analyze_xor_key_distribution(blocks: list[dict]) -> list[dict]:
    """分析 XOR key 分布 — 识别最常见的 XOR key。"""
    if not blocks:
        return []
    key_counts = Counter(b["xor_key_hex"] for b in blocks)
    return [{"key": k, "count": c} for k, c in key_counts.most_common(5)]


# ── PE Rich Header 解析 ──────────────────────────────────────────────────
# Rich Header 由 Microsoft 链接器插入，位于 DOS Stub 之后、PE 签名之前，
# 以 "Rich" + XOR key 结尾。XOR 解码后包含 @comp.id 标记 + 产品 ID/版本/计数
# 的编码数组，可唯一标识编译器工具链版本。
# 参照 Daniel Pistelli 的发现及 pefile 库的实现。

_RICH_MAGIC = b'Rich'
_RICH_XOR_OFFSET_FROM_MAGIC = 4  # "Rich" 后的 4 字节为 XOR key


def _locate_rich_header(raw: bytes) -> int | None:
    """定位 Rich Header 的起始偏移。在 DOS Stub 区域中搜索 "Rich" 标记。

    DOS Stub 位于偏移 0x40 到 PE 签名 (e_lfanew) 之间。
    返回 Rich Header 的 @comp.id 起始偏移，未找到返回 None。
    """
    if len(raw) < 128 or raw[:2] != b'MZ':
        return None
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
    except Exception:
        return None
    stub_end = pe_off
    if stub_end <= 0x40 or stub_end > len(raw):
        return None
    # 在 DOS Stub 区域中搜索 "@comp.id" 的 XOR 编码形式
    # Rich Header 的 XOR key 在 "Rich" 标记后 4 字节
    rich_pos = raw.rfind(_RICH_MAGIC, 0x40, stub_end)
    if rich_pos == -1:
        return None
    # "@comp.id" 的 XOR 解码形式可能紧跟在 DWORD 计数后
    # 反向搜索 "DanS" 标记（Rich Header 结束签名 = 0x536E6144 = "DanS" LE）
    dans_pos = raw.rfind(b'\x44\x61\x6E\x53', 0x40, rich_pos + 8)
    if dans_pos == -1:
        return None
    return dans_pos


def parse_pe_rich_header(raw: bytes) -> dict | None:
    """解析 PE Rich Header 中的编译器工具链信息。

    返回: {"xor_key": int, "products": [{"prod_id": int, "build_id": int, "count": int}, ...],
            "raw_entries": int, "suspicious_missing": bool}
    若 Rich Header 不存在或无法解析则返回 None。
    """
    dans_pos = _locate_rich_header(raw)
    if dans_pos is None:
        return None

    try:
        # DanS 之后是 3 个 DWORD 填充 (0,0,0 或 0,0,1)，然后 XOR key
        # XOR key 存储在 "Rich" 标记后的 4 字节
        rich_pos = raw.rfind(_RICH_MAGIC, dans_pos, dans_pos + 256)
        if rich_pos == -1:
            return None

        xor_key = struct.unpack_from("<I", raw, rich_pos + _RICH_XOR_OFFSET_FROM_MAGIC)[0]

        # 在 DanS 和 Rich 之间是 XOR 编码的 comp.id 条目数组
        # 每个条目 = 2 个 DWORD (解码为 prod_id, build_count) 各 XOR key
        data_start = dans_pos + 16  # 跳过 DanS(4) + 3×padding(12)
        entry_count_raw = struct.unpack_from("<I", raw, data_start)[0] ^ xor_key
        # 合理性校验：条目数通常 < 50
        if entry_count_raw > 100 or entry_count_raw < 1:
            return None

        products = []
        entry_base = data_start + 4
        for i in range(min(entry_count_raw, 50)):
            off = entry_base + i * 8
            if off + 8 > len(raw):
                break
            prod_field = struct.unpack_from("<I", raw, off)[0] ^ xor_key
            count_field = struct.unpack_from("<I", raw, off + 4)[0] ^ xor_key
            # product ID 高 16 位 = 产品类型, 低 16 位 = build 号
            prod_id = prod_field >> 16
            build_id = prod_field & 0xFFFF
            products.append({
                "prod_id": prod_id,
                "build_id": build_id,
                "count": count_field ^ xor_key if count_field != 0 else count_field,
            })

        return {
            "xor_key": xor_key,
            "products": products,
            "raw_entries": entry_count_raw,
            "suspicious_missing": len(products) == 0 and entry_count_raw > 0,
        }
    except Exception:
        return None


# ── PE 数字签名状态 ──────────────────────────────────────────────────────
# PE 可选头 DataDirectory[4] 指向 IMAGE_DIRECTORY_ENTRY_SECURITY，
# 包含 Authenticode 签名。检测签名存在性即可快速判定是否经过签名。

_IMAGE_DIRECTORY_ENTRY_SECURITY = 4


def check_pe_signature(raw: bytes) -> dict:
    """检测 PE 文件的 Authenticode 数字签名状态。

    不验证签名有效性（需要 Windows CryptoAPI），仅检测签名存在性及大小。
    返回: {"signed": bool, "signature_size": int, "certificate_offset": int}
    """
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"signed": False, "signature_size": 0, "certificate_offset": 0}
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        magic = struct.unpack_from("<H", raw, pe_off + 24)[0]
        is_pe32 = (magic == 0x10b)
        # DataDirectory 在 PE32 可选头偏移 96，PE32+ 偏移 112
        dd_base = pe_off + 24 + (96 if is_pe32 else 112)
        sec_off = dd_base + _IMAGE_DIRECTORY_ENTRY_SECURITY * 8
        cert_rva = struct.unpack_from("<I", raw, sec_off)[0]
        cert_size = struct.unpack_from("<I", raw, sec_off + 4)[0]
        signed = cert_rva > 0 and cert_size > 0
        return {
            "signed": signed,
            "signature_size": cert_size if signed else 0,
            "certificate_offset": cert_rva if signed else 0,
        }
    except Exception:
        return {"signed": False, "signature_size": 0, "certificate_offset": 0}


# ── PE Overlay 检测 ──────────────────────────────────────────────────────
# Overlay = 文件末尾超出最后一节数据范围之外的附加字节。
# 常见用途：附加 payload、配置数据、隐藏的 DLL、调试信息泄露。

def detect_pe_overlay(raw: bytes) -> dict:
    """检测 PE 文件末尾的覆盖层（overlay）数据。

    计算最后一节的 (raw_offset + raw_size) 与文件总大小之差。
    返回: {"has_overlay": bool, "overlay_size": int, "overlay_ratio": float}
    """
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"has_overlay": False, "overlay_size": 0, "overlay_ratio": 0.0}
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        num_sects = struct.unpack_from("<H", raw, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", raw, pe_off + 20)[0]
        sec_base = pe_off + 24 + opt_hdr_size

        # 找最后一节的 raw_end
        max_raw_end = 0
        for i in range(num_sects):
            off = sec_base + i * 40
            raw_offset = struct.unpack_from("<I", raw, off + 20)[0]
            raw_size = struct.unpack_from("<I", raw, off + 16)[0]
            raw_end = raw_offset + raw_size
            if raw_end > max_raw_end:
                max_raw_end = raw_end

        overlay_sz = len(raw) - max_raw_end
        return {
            "has_overlay": overlay_sz > 0,
            "overlay_size": overlay_sz,
            "overlay_ratio": round(overlay_sz / max(1, len(raw)), 4),
        }
    except Exception:
        return {"has_overlay": False, "overlay_size": 0, "overlay_ratio": 0.0}


# ── PE 资源段枚举 ────────────────────────────────────────────────────────
# 资源目录树遍历：三级结构 (Type → Name/ID → Language)。
# 重点关注 RT_RCDATA(10) 含嵌入 PE、高熵资源、自定义类型。
# 参照 Detect-It-Easy 的资源分析策略与 MITRE T1027.009。

_IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
_RT_RCDATA = 10
_RT_MANIFEST = 24
_RT_VERSION = 16
_RT_ICON = 3
# 恶意软件常用资源类型名 (字符串类型)
_SUSPICIOUS_RESOURCE_NAMES = {
    'BIN', 'PAYLOAD', 'DLL', 'EXE', 'CFG', 'DAT', 'SETTINGS',
    'ENCRYPTED', 'PACKAGE', 'SCRIPT', 'ZIP', 'CAB',
}

_RESOURCE_TYPE_NAMES: dict[int, str] = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
    5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
    9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
    17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD",
    21: "RT_ANICURSOR", 22: "RT_ANIICON", 23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _rva_to_offset_pe(raw: bytes, rva: int) -> int:
    """PE RVA → 文件偏移转换（复用节区表）。"""
    if len(raw) < 64 or raw[:2] != b'MZ':
        return 0
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        num_sects = struct.unpack_from("<H", raw, pe_off + 6)[0]
        opt_sz = struct.unpack_from("<H", raw, pe_off + 20)[0]
        sec_base = pe_off + 24 + opt_sz
        for i in range(num_sects):
            s_off = sec_base + i * 40
            va = struct.unpack_from("<I", raw, s_off + 12)[0]
            vsize = struct.unpack_from("<I", raw, s_off + 8)[0]
            raw_off = struct.unpack_from("<I", raw, s_off + 20)[0]
            if va <= rva < va + vsize:
                return rva - va + raw_off
    except Exception:
        pass
    return 0


def enumerate_pe_resources(raw: bytes) -> dict:
    """遍历 PE 资源目录树，提取所有资源条目摘要。

    三级递归：Type → Name/ID → Language → DataEntry。
    返回每个资源的 type_id/name/size/lang/offset，
    以及衍生分析：嵌入 PE 检测、高熵资源标记。
    """
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"resources": [], "embedded_pe": [], "total_resources": 0}

    resources = []
    embedded = []

    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        magic = struct.unpack_from("<H", raw, pe_off + 24)[0]
        is_pe32 = (magic == 0x10b)
        dd_base = pe_off + 24 + (96 if is_pe32 else 112)
        res_rva = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_RESOURCE * 8)[0]
        res_size = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_RESOURCE * 8 + 4)[0]
        if res_rva == 0 or res_size == 0:
            return {"resources": [], "embedded_pe": [], "total_resources": 0}

        base_off = _rva_to_offset_pe(raw, res_rva)
        if base_off == 0:
            return {"resources": [], "embedded_pe": [], "total_resources": 0}

        # 迭代 Type 级目录
        _walk_resource_tree(raw, base_off, base_off, 1, resources, embedded)
    except Exception:
        pass

    return {
        "resources": resources,
        "embedded_pe": embedded,
        "total_resources": len(resources),
        "high_entropy_resources": sum(1 for r in resources if r.get('entropy', 0) > 7.0),
        "suspicious_names": [r for r in resources
                            if r.get('name', '').upper() in _SUSPICIOUS_RESOURCE_NAMES],
    }


def _walk_resource_tree(raw: bytes, root: int, node_off: int, depth: int,
                        resources: list, embedded: list, max_depth: int = 4):
    """递归遍历 PE 资源目录树。"""
    if depth > max_depth or node_off + 16 > len(raw):
        return
    try:
        # IMAGE_RESOURCE_DIRECTORY: Characteristics + TimeDateStamp + MajorVersion + MinorVersion
        # + NumberOfNamedEntries + NumberOfIdEntries
        named_count = struct.unpack_from("<H", raw, node_off + 12)[0]
        id_count = struct.unpack_from("<H", raw, node_off + 14)[0]
        total_entries = named_count + id_count
        if total_entries > 256:  # 合理性上限
            return
        entry_off = node_off + 16
        for i in range(total_entries):
            e_off = entry_off + i * 8
            if e_off + 8 > len(raw):
                break
            name_or_id = struct.unpack_from("<I", raw, e_off)[0]
            offset_or_rva = struct.unpack_from("<I", raw, e_off + 4)[0]

            if depth == 1:
                # Type 级：name_or_id = resource type ID
                res_type_id = name_or_id
                res_type_name = _RESOURCE_TYPE_NAMES.get(res_type_id, f"TYPE_{res_type_id}")
            elif depth == 2:
                # Name 级
                res_type_name = ""  # 由上层传递
                res_type_id = 0
            else:
                res_type_name = ""
                res_type_id = 0

            is_leaf = bool(offset_or_rva & 0x80000000)
            next_off = root + (offset_or_rva & 0x7FFFFFFF)

            if is_leaf and depth >= 2:
                # 到达叶子节点 → IMAGE_RESOURCE_DATA_ENTRY
                if next_off + 16 <= len(raw):
                    data_rva = struct.unpack_from("<I", raw, next_off)[0]
                    data_size = struct.unpack_from("<I", raw, next_off + 4)[0]
                    file_off = _rva_to_offset_pe(raw, data_rva)
                    if file_off > 0 and data_size > 0 and file_off + data_size <= len(raw):
                        chunk = raw[file_off:file_off + min(data_size, 1_048_576)]
                        ent = _shannon_entropy(chunk[:4096]) if len(chunk) >= 256 else 0.0
                        res_entry = {
                            "type_id": res_type_id if depth == 2 else name_or_id if depth == 3 else 0,
                            "type_name": _RESOURCE_TYPE_NAMES.get(
                                res_type_id if depth == 2 else name_or_id if depth == 3 else 0,
                                f"TYPE_{res_type_id if depth == 2 else name_or_id}"),
                            "size": data_size, "offset": file_off,
                            "entropy": round(ent, 2),
                        }
                        resources.append(res_entry)
                        # 嵌入 PE 检测：至少在文件名偏移处发现 MZ 头
                        if b'MZ' in chunk[:2] and data_size > 512:
                            embedded.append({
                                "resource_type": res_entry["type_name"],
                                "offset": file_off, "size": data_size,
                                "match": "PE_header_at_start",
                            })
                        elif b'MZ' in chunk and data_size > 1024:
                            embedded.append({
                                "resource_type": res_entry["type_name"],
                                "offset": file_off, "size": data_size,
                                "match": "PE_header_found_in_blob",
                            })
            else:
                _walk_resource_tree(raw, root, next_off, depth + 1,
                                   resources, embedded, max_depth)
    except Exception:
        pass


# ── PE 导出表分析 ────────────────────────────────────────────────────────
# 检测可疑导出模式：纯序号导出（恶意软件常用，规避按名检测）、
# 转发导出（指向其他 DLL）、大量导出但仅少量合法。

_IMAGE_DIRECTORY_ENTRY_EXPORT = 0


def analyze_pe_exports(raw: bytes) -> dict:
    """分析 PE 导出表，检测可疑模式。

    返回: {"export_count": int, "named_count": int, "ordinal_only_count": int,
            "forwarded_count": int, "names": [...], "suspicious_patterns": [...]}
    """
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"export_count": 0, "named_count": 0, "ordinal_only_count": 0,
                "forwarded_count": 0, "names": [], "suspicious_patterns": []}

    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        magic = struct.unpack_from("<H", raw, pe_off + 24)[0]
        is_pe32 = (magic == 0x10b)
        dd_base = pe_off + 24 + (96 if is_pe32 else 112)
        exp_rva = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_EXPORT * 8)[0]
        exp_size = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_EXPORT * 8 + 4)[0]
        if exp_rva == 0 or exp_size == 0:
            return {"export_count": 0, "named_count": 0, "ordinal_only_count": 0,
                    "forwarded_count": 0, "names": [], "suspicious_patterns": []}

        exp_off = _rva_to_offset_pe(raw, exp_rva)
        if exp_off == 0:
            return {"export_count": 0, "named_count": 0, "ordinal_only_count": 0,
                    "forwarded_count": 0, "names": [], "suspicious_patterns": []}

        # IMAGE_EXPORT_DIRECTORY 结构
        name_rva = struct.unpack_from("<I", raw, exp_off + 12)[0]   # DLL 名
        ordinal_base = struct.unpack_from("<I", raw, exp_off + 16)[0]
        num_funcs = struct.unpack_from("<I", raw, exp_off + 20)[0]
        num_names = struct.unpack_from("<I", raw, exp_off + 24)[0]
        addr_table_rva = struct.unpack_from("<I", raw, exp_off + 28)[0]
        name_table_rva = struct.unpack_from("<I", raw, exp_off + 32)[0]
        ordinal_table_rva = struct.unpack_from("<I", raw, exp_off + 36)[0]

        names = []
        forwarded = 0
        # 提取命名导出
        name_off = _rva_to_offset_pe(raw, name_table_rva)
        ord_off = _rva_to_offset_pe(raw, ordinal_table_rva)
        addr_off = _rva_to_offset_pe(raw, addr_table_rva)
        if name_off and ord_off:
            for ni in range(min(num_names, 200)):
                if name_off + ni * 4 + 4 > len(raw):
                    break
                entry_name_rva = struct.unpack_from("<I", raw, name_off + ni * 4)[0]
                entry_ord_idx = struct.unpack_from("<H", raw, ord_off + ni * 2)[0]
                name_str_off = _rva_to_offset_pe(raw, entry_name_rva)
                if name_str_off and name_str_off < len(raw):
                    end = raw.find(b'\x00', name_str_off)
                    if end == -1:
                        end = name_str_off + 64
                    export_name = raw[name_str_off:end].decode('ascii', errors='replace')
                    names.append(export_name)
                # 检测转发导出：函数地址 RVA 落在导出表段内则为转发
                if addr_off and entry_ord_idx < num_funcs:
                    func_rva = struct.unpack_from("<I", raw,
                                                  addr_off + entry_ord_idx * 4)[0]
                    if exp_rva <= func_rva < exp_rva + exp_size:
                        forwarded += 1

        ordinal_only = num_funcs - num_names
        suspicious = []
        if ordinal_only > num_funcs * 0.5 and num_funcs > 5:
            suspicious.append(f"纯序号导出占比 {ordinal_only}/{num_funcs} — 规避按名检测的常见手法")
        if forwarded > 0:
            suspicious.append(f"转发导出 {forwarded} 个 — 可能用于 DLL 劫持或 API 代理")
        if num_names == 0 and num_funcs > 0:
            suspicious.append("全部为纯序号导出 — 高度可疑")

        return {
            "export_count": num_funcs,
            "named_count": num_names,
            "ordinal_only_count": ordinal_only,
            "forwarded_count": forwarded,
            "names": names[:50],
            "suspicious_patterns": suspicious,
        }
    except Exception:
        return {"export_count": 0, "named_count": 0, "ordinal_only_count": 0,
                "forwarded_count": 0, "names": [], "suspicious_patterns": ["解析错误"]}


# ── ELF 深度解析 ─────────────────────────────────────────────────────────
# 解析 ELF Program Headers 获取段权限与动态链接信息。
# PT_LOAD 段标志 (PF_X/PF_W/PF_R) 等同于 PE 节区权限分析，
# PT_DYNAMIC → NEEDED 库列表、PT_INTERP → 动态链接器路径。

_ELF_PT_LOAD = 1
_ELF_PT_DYNAMIC = 2
_ELF_PT_INTERP = 3
_ELF_PT_NOTE = 4
_ELF_PT_GNU_STACK = 0x6474E551
_ELF_PT_GNU_RELRO = 0x6474E552

_PF_X = 1
_PF_W = 2
_PF_R = 4


def analyze_elf_segments(raw: bytes) -> dict:
    """解析 ELF Program Headers，提取段权限与安全特性。

    返回: {"segments": [...], "interp": str|None, "needed": [...],
            "has_gnu_stack": bool, "gnu_stack_exec": bool, "has_relro": bool}
    """
    if len(raw) < 52 or raw[:4] != b'\x7fELF':
        return {"segments": [], "interp": None, "needed": [],
                "has_gnu_stack": False, "gnu_stack_exec": False, "has_relro": False}

    try:
        ei_class = raw[4]   # 1=32bit, 2=64bit
        is_64 = (ei_class == 2)
        endian = '<' if raw[5] == 1 else '>'
        phoff = struct.unpack_from(f"{endian}{'Q' if is_64 else 'I'}", raw, 28 if is_64 else 32)[0]
        phnum = struct.unpack_from(f"{endian}H", raw, 52 if is_64 else 44)[0]
        phentsize = struct.unpack_from(f"{endian}H", raw, 54 if is_64 else 46)[0]

        segments = []
        interp = None
        needed = []
        has_gnu_stack = False
        gnu_stack_exec = False
        has_relro = False
        phdr_word = 'Q' if is_64 else 'I'

        for i in range(phnum):
            off = phoff + i * phentsize
            if off + (56 if is_64 else 32) > len(raw):
                break
            p_type = struct.unpack_from(f"{endian}I", raw, off)[0]
            p_flags = struct.unpack_from(f"{endian}I", raw, off + (4 if is_64 else 28))[0]
            p_vaddr = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (16 if is_64 else 8))[0]
            p_memsz = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (40 if is_64 else 20))[0]
            p_offset = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (8 if is_64 else 4))[0]
            p_filesz = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (32 if is_64 else 16))[0]

            if p_type == _ELF_PT_LOAD:
                segments.append({
                    "type": "PT_LOAD",
                    "vaddr": f"0x{p_vaddr:x}",
                    "memsz": p_memsz,
                    "flags": f"{'R' if p_flags & _PF_R else ''}{'W' if p_flags & _PF_W else ''}{'E' if p_flags & _PF_X else ''}",
                    "is_wxe": bool((p_flags & _PF_X) and (p_flags & _PF_W)),
                })

            elif p_type == _ELF_PT_DYNAMIC and p_filesz > 0:
                # 解析 .dynamic 段中的 DT_NEEDED 条目
                dyn_off = p_offset
                dt_entry_sz = 16 if is_64 else 8
                DT_NEEDED = 1
                DT_STRTAB = 5
                DT_NULL = 0
                strtab_off_file = 0
                # 第一遍：找 DT_STRTAB
                j = 0
                while dyn_off + j * dt_entry_sz + dt_entry_sz <= len(raw) and j < 500:
                    e_off = dyn_off + j * dt_entry_sz
                    d_tag = struct.unpack_from(f"{endian}{phdr_word}", raw, e_off)[0]
                    d_val = struct.unpack_from(f"{endian}{phdr_word}", raw, e_off + (8 if is_64 else 4))[0]
                    if d_tag == DT_NULL:
                        break
                    if d_tag == DT_STRTAB:
                        strtab_off_file = _elf_rva_to_offset(raw, d_val)
                        break
                    j += 1
                # 第二遍：找 DT_NEEDED
                if strtab_off_file > 0:
                    j = 0
                    while dyn_off + j * dt_entry_sz + dt_entry_sz <= len(raw) and j < 500:
                        e_off = dyn_off + j * dt_entry_sz
                        d_tag = struct.unpack_from(f"{endian}{phdr_word}", raw, e_off)[0]
                        d_val = struct.unpack_from(f"{endian}{phdr_word}", raw, e_off + (8 if is_64 else 4))[0]
                        if d_tag == DT_NULL:
                            break
                        if d_tag == DT_NEEDED:
                            str_off = strtab_off_file + d_val
                            if str_off < len(raw):
                                end = raw.find(b'\x00', str_off)
                                if end == -1:
                                    end = str_off + 64
                                needed.append(raw[str_off:end].decode('ascii', errors='replace'))
                        j += 1

            elif p_type == _ELF_PT_INTERP and p_filesz > 0:
                interp_off = p_offset
                end = raw.find(b'\x00', interp_off)
                if end == -1:
                    end = interp_off + p_filesz
                interp = raw[interp_off:end].decode('ascii', errors='replace')

            elif p_type == _ELF_PT_GNU_STACK:
                has_gnu_stack = True
                gnu_stack_exec = bool(p_flags & _PF_X)

            elif p_type == _ELF_PT_GNU_RELRO:
                has_relro = True

        return {
            "segments": segments,
            "interp": interp,
            "needed": needed,
            "has_gnu_stack": has_gnu_stack,
            "gnu_stack_exec": gnu_stack_exec,
            "has_relro": has_relro,
        }
    except Exception:
        return {"segments": [], "interp": None, "needed": [],
                "has_gnu_stack": False, "gnu_stack_exec": False, "has_relro": False}


def _elf_rva_to_offset(raw: bytes, vaddr: int) -> int:
    """ELF 虚拟地址 → 文件偏移的简化转换：遍历 PT_LOAD 段。"""
    if raw[:4] != b'\x7fELF':
        return 0
    try:
        ei_class = raw[4]
        is_64 = (ei_class == 2)
        endian = '<' if raw[5] == 1 else '>'
        phoff = struct.unpack_from(f"{endian}{'Q' if is_64 else 'I'}", raw, 28 if is_64 else 32)[0]
        phnum = struct.unpack_from(f"{endian}H", raw, 52 if is_64 else 44)[0]
        phentsize = struct.unpack_from(f"{endian}H", raw, 54 if is_64 else 46)[0]
        phdr_word = 'Q' if is_64 else 'I'
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type = struct.unpack_from(f"{endian}I", raw, off)[0]
            if p_type != _ELF_PT_LOAD:
                continue
            p_vaddr = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (16 if is_64 else 8))[0]
            p_memsz = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (40 if is_64 else 20))[0]
            p_offset = struct.unpack_from(f"{endian}{phdr_word}", raw, off + (8 if is_64 else 4))[0]
            if p_vaddr <= vaddr < p_vaddr + p_memsz:
                return vaddr - p_vaddr + p_offset
    except Exception:
        pass
    return 0


# ── PE 调试目录解析 ──────────────────────────────────────────────────────
# IMAGE_DIRECTORY_ENTRY_DEBUG (DataDirectory[6]) 包含 CodeView/PDB 路径。
# PDB 路径泄露可揭示原始构建环境路径、用户名、项目名，是重要的
# 信息泄露源与威胁情报信号。

_IMAGE_DIRECTORY_ENTRY_DEBUG = 6
_IMAGE_DEBUG_TYPE_CODEVIEW = 2


def parse_pe_debug_directory(raw: bytes) -> dict:
    """解析 PE 调试目录，提取 PDB 路径及 CodeView 数据。

    返回: {"has_debug": bool, "pdb_path": str|None, "cv_signature": str|None,
            "debug_entries": [...], "info_leak_risk": bool}
    """
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"has_debug": False, "pdb_path": None, "cv_signature": None,
                "debug_entries": [], "info_leak_risk": False}

    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        magic = struct.unpack_from("<H", raw, pe_off + 24)[0]
        is_pe32 = (magic == 0x10b)
        dd_base = pe_off + 24 + (96 if is_pe32 else 112)
        dbg_rva = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_DEBUG * 8)[0]
        dbg_size = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_DEBUG * 8 + 4)[0]
        if dbg_rva == 0 or dbg_size == 0:
            return {"has_debug": False, "pdb_path": None, "cv_signature": None,
                    "debug_entries": [], "info_leak_risk": False}

        dbg_off = _rva_to_offset_pe(raw, dbg_rva)
        if dbg_off == 0:
            return {"has_debug": False, "pdb_path": None, "cv_signature": None,
                    "debug_entries": [], "info_leak_risk": False}

        entries = []
        pdb_path = None
        cv_sig = None
        info_leak = False
        # IMAGE_DEBUG_DIRECTORY = 28 bytes
        num_entries = dbg_size // 28
        for i in range(min(num_entries, 16)):
            e_off = dbg_off + i * 28
            if e_off + 28 > len(raw):
                break
            dbg_type = struct.unpack_from("<I", raw, e_off + 12)[0]
            data_ptr = struct.unpack_from("<I", raw, e_off + 20)[0]
            data_sz = struct.unpack_from("<I", raw, e_off + 24)[0]
            data_off = _rva_to_offset_pe(raw, data_ptr) if dbg_type == _IMAGE_DEBUG_TYPE_CODEVIEW else data_ptr
            entries.append({"type": dbg_type, "size": data_sz})

            if dbg_type == _IMAGE_DEBUG_TYPE_CODEVIEW and data_off > 0 and data_sz > 4:
                cv_sig_raw = raw[data_off:data_off + 4]
                if cv_sig_raw == b'RSDS':
                    cv_sig = "RSDS (PDB v7)"
                elif cv_sig_raw == b'NB10':
                    cv_sig = "NB10 (PDB v2)"
                else:
                    cv_sig = cv_sig_raw.hex()
                # PDB 路径在签名 + GUID(16) + Age(4) 之后
                pdb_off = data_off + 24  # 跳过 RSDS(4) + GUID(16) + Age(4)
                if pdb_off < len(raw):
                    end = raw.find(b'\x00', pdb_off)
                    if end == -1:
                        end = pdb_off + min(data_sz - 24, 260)
                    pdb_path = raw[pdb_off:end].decode('ascii', errors='replace')
                    # 信息泄露风险：PDB 路径含用户名/项目路径
                    if '\\' in pdb_path or '/' in pdb_path:
                        info_leak = True

        return {
            "has_debug": len(entries) > 0,
            "pdb_path": pdb_path,
            "cv_signature": cv_sig,
            "debug_entries": entries,
            "info_leak_risk": info_leak,
        }
    except Exception:
        return {"has_debug": False, "pdb_path": None, "cv_signature": None,
                "debug_entries": [], "info_leak_risk": False}


# ── PE 重定位表分析 ──────────────────────────────────────────────────────
# IMAGE_DIRECTORY_ENTRY_BASERELOC (DataDirectory[5]) 包含基址重定位数据。
# 存在性 = ASLR 兼容；大段重定位块 = 可疑（正常 PE 通常 < 1% 文件大小）。
# 基址重定位的缺失在 PIE 编译的现代二进制中反而罕见 → 标记为非 ASLR。

_IMAGE_DIRECTORY_ENTRY_BASERELOC = 5


def analyze_pe_relocations(raw: bytes) -> dict:
    """分析 PE 基址重定位表，判定 ASLR 兼容性与可疑模式。

    返回: {"has_relocs": bool, "total_size": int, "block_count": int,
            "file_size_ratio": float, "aslr_compatible": bool,
            "suspicious_large_relocs": bool}
    """
    if len(raw) < 64 or raw[:2] != b'MZ':
        return {"has_relocs": False, "total_size": 0, "block_count": 0,
                "file_size_ratio": 0.0, "aslr_compatible": False,
                "suspicious_large_relocs": False}
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        magic = struct.unpack_from("<H", raw, pe_off + 24)[0]
        is_pe32 = (magic == 0x10b)
        dd_base = pe_off + 24 + (96 if is_pe32 else 112)
        reloc_rva = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_BASERELOC * 8)[0]
        reloc_size = struct.unpack_from("<I", raw, dd_base + _IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4)[0]

        has_relocs = reloc_rva > 0 and reloc_size > 0
        if not has_relocs:
            # 检查是否为 DLL（Characteristics & 0x2000 = IMAGE_FILE_DLL）
            chars = struct.unpack_from("<H", raw, pe_off + 22)[0]
            is_dll = bool(chars & 0x2000)
            return {"has_relocs": False, "total_size": 0, "block_count": 0,
                    "file_size_ratio": 0.0,
                    "aslr_compatible": not is_dll,  # EXE 无重定位表 = 非 ASLR
                    "suspicious_large_relocs": False}

        # 遍历重定位块计算实际条目数
        reloc_off = _rva_to_offset_pe(raw, reloc_rva)
        block_count = 0
        pos = reloc_off
        if pos > 0:
            while pos + 8 <= min(reloc_off + reloc_size, len(raw)):
                page_rva = struct.unpack_from("<I", raw, pos)[0]
                block_sz = struct.unpack_from("<I", raw, pos + 4)[0]
                if block_sz == 0:
                    break
                block_count += 1
                pos += block_sz
                if page_rva == 0 and block_sz > 0:
                    # 畸形重定位块 — 可能为刻意构造
                    pass

        ratio = reloc_size / max(1, len(raw))
        return {
            "has_relocs": True,
            "total_size": reloc_size,
            "block_count": block_count,
            "file_size_ratio": round(ratio, 4),
            "aslr_compatible": True,
            # 重定位表占比 > 2% 为异常（常见于加壳/混淆后的二进制）
            "suspicious_large_relocs": ratio > 0.02,
        }
    except Exception:
        return {"has_relocs": False, "total_size": 0, "block_count": 0,
                "file_size_ratio": 0.0, "aslr_compatible": False,
                "suspicious_large_relocs": False}


# ── 命名内核对象检测 ─────────────────────────────────────────────────────
# 恶意软件常用 CreateMutex/CreateEvent/CreatePipe 等 API 创建命名对象
# 作为单实例互斥锁或 C2 通信通道。从字符串中提取命名对象可揭示
# 恶意软件家族特征（Campaign ID、Bot 名、版本号等）。

_NAMED_OBJECT_RE = re.compile(
    r'(?:Global\\|Local\\)?[A-Za-z0-9_\-\.]{6,64}'
)
# 恶意软件常见互斥锁名模式
_MUTEX_INDICATORS = [
    'Global\\', 'Local\\', '_mutex', 'bot_', 'install_',
    'run_', 'active_', '_started', '_running', 'SingleInstance',
]

_PIPE_INDICATORS = [
    '\\\\.\\pipe\\', '\\\\pipe\\\\', 'namedpipe',
]


def extract_named_objects(strings_in_binary: list[str]) -> dict:
    """从二进制字符串中提取命名内核对象（mutex/pipe/event）。

    返回: {"mutex_candidates": [...], "pipe_candidates": [...],
            "suspicious": [...], "total": int}
    """
    mutexes = set()
    pipes = set()
    suspicious = []

    for s in strings_in_binary:
        # 管道检测
        for pi in _PIPE_INDICATORS:
            if pi.lower() in s.lower():
                pipe_name = s[s.lower().find(pi.lower()):].split('\x00')[0][:128]
                if len(pipe_name) > 8:
                    pipes.add(pipe_name)
                break

        # 互斥锁/事件检测 — 需同时满足长度+前缀条件
        if any(ind in s for ind in _MUTEX_INDICATORS):
            for m in _NAMED_OBJECT_RE.finditer(s):
                obj_name = m.group(0)
                if len(obj_name) >= 8:
                    mutexes.add(obj_name)

        # 通用可疑命名模式
        for m in _NAMED_OBJECT_RE.finditer(s):
            obj = m.group(0)
            lo = obj.lower()
            if any(kw in lo for kw in ('mutex', 'global\\', 'bot_', 'campaign',
                                        'lock_', 'singleton', 'instance_')):
                suspicious.append(obj)
                break

    return {
        "mutex_candidates": sorted(mutexes)[:20],
        "pipe_candidates": sorted(pipes)[:10],
        "suspicious": suspicious[:15],
        "total": len(mutexes) + len(pipes),
    }


# ── 基础格式识别 ───────────────────────────────────────────────────────────

def detect_language(binary):
    return "unknown"


def detect_binary_format(path):
    """通过魔数字节判定二进制格式（ELF/PE/Mach-O）。"""
    if not os.path.exists(path):
        return "unknown"
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"MZ":
        return "PE"
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def format_info_for_report(info):
    """将二进制信息渲染为中文标签的摘要字符串。"""
    if not info:
        return "无info"
    lines = []
    if "format" in info:
        lines.append(f"格式: {info['format']}")
    if "size" in info:
        lines.append(f"size: {info['size']} 字节")
    if "arch" in info:
        lines.append(f"architecture: {info['arch']}")
    if "strings" in info:
        key_strs = [s for s in info.get("strings", [])
                    if any(p in s.lower() for p in KEY_STRING_PATTERNS)]
        if key_strs:
            lines.append(f"关keystring: {', '.join(key_strs[:5])}")
    if "dangerous" in info:
        lines.append(f"dangerous function: {', '.join(info['dangerous'][:10])}")
    return "\n".join(lines) if lines else "无可报告info"


def _extract_pe_arch(raw: bytes) -> str:
    """从 PE optional header 中提取 Machine 字段，映射到架构名。"""
    if len(raw) < 64:
        return "unknown"
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        machine = struct.unpack_from("<H", raw, pe_off + 4)[0]
        return {0x014C: "x86", 0x8664: "x64", 0x01C4: "ARM",
                0xAA64: "ARM64", 0x0200: "IA64"}.get(machine, f"machine_{machine:#06x}")
    except Exception:
        return "unknown"


def _extract_elf_arch(raw: bytes) -> str:
    """从 ELF header e_machine + EI_CLASS 映射到架构名。"""
    if len(raw) < 20:
        return "unknown"
    try:
        ei_class = raw[4]   # 1=32bit, 2=64bit
        bits = "64" if ei_class == 2 else "32"
        machine = struct.unpack_from("<H", raw, 18)[0]
        arch_map = {3: "x86", 62: "x64", 40: "ARM", 183: "ARM64",
                    8: "MIPS", 21: "PPC", 43: "SPARC"}
        base = arch_map.get(machine, f"elf_machine_{machine}")
        return f"{base}_{bits}"
    except Exception:
        return "unknown"


def _extract_ascii_strings(raw: bytes, min_len: int = 4) -> list[str]:
    """从二进制中提取 ASCII 可打印字符串，用于导入表分析等下游任务。"""
    strings = []
    run = b""
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if 0x20 <= b <= 0x7E:
            run += bytes([b])
        else:
            if len(run) >= min_len:
                strings.append(run.decode("ascii", errors="replace"))
            run = b""
        i += 1
    if len(run) >= min_len:
        strings.append(run.decode("ascii", errors="replace"))
    return strings


def get_binary_info(path):
    """提取二进制文件的格式、大小、架构及可疑指标。"""
    if not os.path.exists(path):
        return {"error": "file not found"}

    fmt = detect_binary_format(path)
    size = os.path.getsize(path)
    arch = "unknown"
    entropy_profile = None
    ngram_fp = None
    crypto_hits = None
    section_analysis = None
    import_anomalies = None

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        raw = b""

    if raw:
        if fmt == "PE":
            arch = _extract_pe_arch(raw)
            section_analysis = analyze_pe_sections(raw)
        elif fmt == "ELF":
            arch = _extract_elf_arch(raw)
        # 全文件分析 — 对大文件采样前 2MB 以控制耗时
        sample = raw[:2_097_152] if len(raw) > 2_097_152 else raw
        entropy_profile = compute_section_entropy_profile(sample)
        ngram_fp = compute_ngram_fingerprint(sample)
        crypto_hits = scan_crypto_constants(sample)
        strings = _extract_ascii_strings(raw)
        import_anomalies = analyze_import_table_anomalies(strings)

    result = {
        "format": fmt,
        "size": size,
        "arch": arch,
        "strings": [],
        "dangerous": [],
    }
    if entropy_profile:
        result["entropy"] = entropy_profile
        if entropy_profile["high_window_ratio"] > _SUSPICIOUS_ENTROPY_RATIO:
            result["suspicious_packing"] = True
    if ngram_fp:
        result["ngram_fingerprint"] = ngram_fp
        if ngram_fp["unique_ngram_ratio"] < 0.02 and len(raw) > 1024:
            result["repetitive_structure"] = True
    if crypto_hits:
        result["crypto_constants"] = crypto_hits
        result["crypto_algorithms"] = sorted(set(h["algorithm"] for h in crypto_hits))
    if section_analysis:
        result["section_analysis"] = section_analysis
        if section_analysis["wxe_violations"] > 0:
            result["wxe_warning"] = (
                f"检测到 {section_analysis['wxe_violations']} 个可写可执行节区，"
                "可能为自修改代码或 shellcode 执行"
            )
    if import_anomalies and import_anomalies.get("likely_hashed_imports"):
        result["import_anomaly"] = import_anomalies

    # 网络 IOC
    if strings:
        net_iocs = extract_network_iocs(strings)
        if net_iocs["total"] > 0:
            result["network_iocs"] = net_iocs

    # Shellcode 检测
    if raw:
        shellcode = detect_shellcode_patterns(raw)
        if shellcode["patterns_found"]:
            result["shellcode_analysis"] = shellcode

    # API 哈希检测
    if raw:
        hashing = detect_api_hashing(raw)
        if hashing["likely_api_hashing"]:
            result["api_hashing"] = hashing

    # XOR 编码字符串检测
    if raw and entropy_profile:
        xor_result = detect_xor_obfuscated_strings(raw, entropy_profile)
        if xor_result["xor_obfuscation_likely"]:
            result["xor_obfuscation"] = xor_result

    # ELF 深层解析
    if raw and fmt == "ELF":
        elf_seg = analyze_elf_segments(raw)
        if elf_seg["segments"]:
            result["elf_segments"] = elf_seg
            if elf_seg["needed"]:
                result["elf_needed_libs"] = elf_seg["needed"]
            if elf_seg["interp"]:
                result["elf_interp"] = elf_seg["interp"]
            # W^X 段检测（ELF 版本）
            wxe_segments = [s for s in elf_seg["segments"] if s.get("is_wxe")]
            if wxe_segments:
                result["elf_wxe_warning"] = f"检测到 {len(wxe_segments)} 个可写可执行 PT_LOAD 段"
            # NX 栈缺失
            if elf_seg["has_gnu_stack"] and elf_seg["gnu_stack_exec"]:
                result["elf_exec_stack"] = True

    # PE 深层解析（仅 PE 格式）
    if raw and fmt == "PE":
        # Rich Header — 编译器工具链指纹
        rich = parse_pe_rich_header(raw)
        if rich:
            result["rich_header"] = rich

        # 数字签名状态
        sig_info = check_pe_signature(raw)
        result["signature"] = sig_info
        if not sig_info["signed"]:
            result["unsigned"] = True  # 快捷标记，便于上层过滤

        # Overlay 检测
        overlay_info = detect_pe_overlay(raw)
        if overlay_info["has_overlay"]:
            result["overlay"] = overlay_info

        # 资源段枚举 + 嵌入 PE 检测
        res_info = enumerate_pe_resources(raw)
        if res_info["total_resources"] > 0:
            result["resources"] = res_info
            if res_info["embedded_pe"]:
                result["embedded_pe_in_resources"] = True
                result["embedded_pe_details"] = res_info["embedded_pe"]

        # 导出表分析
        exp_info = analyze_pe_exports(raw)
        if exp_info["export_count"] > 0:
            result["export_table"] = exp_info
            if exp_info["suspicious_patterns"]:
                result["suspicious_exports"] = True

        # 调试目录 — PDB 路径泄露
        debug_info = parse_pe_debug_directory(raw)
        if debug_info["has_debug"]:
            result["debug_directory"] = debug_info
            if debug_info["info_leak_risk"]:
                result["pdb_path_leak"] = True

        # 重定位表 — ASLR 兼容性
        reloc_info = analyze_pe_relocations(raw)
        if not reloc_info["aslr_compatible"]:
            result["no_aslr"] = True
            result["relocation_info"] = reloc_info
        elif reloc_info["suspicious_large_relocs"]:
            result["relocation_info"] = reloc_info

    # 命名内核对象（跨格式通用）
    if strings:
        named_objs = extract_named_objects(strings)
        if named_objs["total"] > 0:
            result["named_objects"] = named_objs

    return result


def get_language_specific_dangerous_functions(lang):
    """按语言返回对应的危险函数列表。"""
    if lang == "c" or lang == "c++":
        return list(DANGEROUS_FUNCTIONS)
    return []


def validate_elf_file(path):
    """验证文件偏移 0 处的 ELF 魔数。"""
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        return f.read(4) == b"\x7fELF"

def get_language_specific_dangerous_functions(lang): return []

def get_language_analysis_hints(lang): return []

# 占位数据 — 由语言特定插件在集成时填充。
GO_SYMBOLS = []

RUST_SYMBOLS = []
GO_SYMBOLS = []

GO_SECTIONS = []

GO_SECTIONS = []

RUST_SECTIONS = []

GO_DANGEROUS_FUNCTIONS = []

RUST_DANGEROUS_FUNCTIONS = []
