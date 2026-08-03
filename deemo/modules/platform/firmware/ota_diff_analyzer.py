"""
OTA固件差分分析。对两个固件版本进行二进制差分：
检测新增/修改/删除的代码块，按安全相关性分类。

2026.07新增：sdhash模糊哈希同源检测 + FSS功能敏感度评分 + Beyond Embeddings可解释差分特征。
参考：Khorrami et al. "Binary Diff Summarization Using LLMs", arXiv 2509.23970。
      "Beyond Embeddings: Interpretable Feature Extraction for Binary Code Similarity", arXiv 2509.23449。
"""

import hashlib, re, struct
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict


class RiskLevel(str, Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"

class ChangeType(str, Enum):
    ADDED = "added"; MODIFIED = "modified"; DELETED = "deleted"


@dataclass
class CodeBlock:
    name: str; offset: int; size: int; hash: str = ""; fss: float = 0.0
    # Beyond Embeddings可解释特征：I/O类型、副作用、显著常量
    interpretable_features: dict = None
    def __hash__(self):
        return hash((self.name, self.offset, self.size))
    def __post_init__(self):
        if self.interpretable_features is None:
            self.interpretable_features = {}


@dataclass
class DiffEntry:
    change: ChangeType; block: CodeBlock
    old_block: CodeBlock | None = None
    risk: RiskLevel = RiskLevel.LOW; reason: str = ""


@dataclass
class OTADiffResult:
    old_file: str; new_file: str; diffs: list[DiffEntry]; stats: dict = None
    def __post_init__(self):
        if self.stats is None:
            self.stats = {}


_SECURITY_SENSITIVE = [
    ("auth", RiskLevel.HIGH, "authentication"), ("bypass", RiskLevel.HIGH, "auth bypass"),
    ("password", RiskLevel.HIGH, "credential"), ("root", RiskLevel.HIGH, "privilege escalation"),
    ("admin", RiskLevel.HIGH, "admin privilege"), ("encrypt", RiskLevel.MEDIUM, "encryption"),
    ("decrypt", RiskLevel.MEDIUM, "decryption"), ("aes_", RiskLevel.MEDIUM, "AES"),
    ("rsa_", RiskLevel.MEDIUM, "RSA"), ("sha", RiskLevel.MEDIUM, "hash"),
    ("ssl_", RiskLevel.MEDIUM, "TLS"), ("tls_", RiskLevel.MEDIUM, "TLS"),
    ("key_", RiskLevel.HIGH, "crypto key"), ("nonce", RiskLevel.MEDIUM, "nonce/IV"),
    ("socket", RiskLevel.LOW, "network"), ("connect", RiskLevel.LOW, "network"),
    ("recv", RiskLevel.LOW, "network"), ("http_", RiskLevel.LOW, "HTTP"),
    ("bootloader", RiskLevel.HIGH, "bootloader"), ("firmware_update", RiskLevel.HIGH, "update"),
    ("signature", RiskLevel.HIGH, "signature"), ("certificate", RiskLevel.HIGH, "certificate"),
    ("unlock", RiskLevel.MEDIUM, "unlock"), ("debug", RiskLevel.MEDIUM, "debug"),
    ("cmd_", RiskLevel.LOW, "command handler"), ("handler", RiskLevel.LOW, "handler"),
    ("device_tree", RiskLevel.HIGH, "device tree"), ("dtb_", RiskLevel.HIGH, "DTB"),
    ("memory_map", RiskLevel.HIGH, "memory map"), ("mmu_", RiskLevel.HIGH, "MMU"),
    ("mpu_", RiskLevel.HIGH, "MPU"), ("interrupt", RiskLevel.MEDIUM, "interrupt"),
    ("nvic", RiskLevel.MEDIUM, "NVIC"), ("dma_", RiskLevel.MEDIUM, "DMA"),
    ("clock_", RiskLevel.LOW, "clock"), ("gpio_", RiskLevel.LOW, "GPIO"),
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _sdhash_features(blob: bytes, chunk_sz: int = 64) -> set[bytes]:
    feats = set()
    for off in range(0, len(blob) - chunk_sz, chunk_sz // 2):
        feats.add(hashlib.sha1(blob[off:off + chunk_sz]).digest()[:5])
        if len(feats) > 2048:
            break
    return feats


def _sdhash_similarity(feats_a, feats_b) -> float:
    if not feats_a or not feats_b:
        return 0.0
    inter = len(feats_a & feats_b)
    return inter / len(feats_a | feats_b)


# Beyond Embeddings可解释特征提取：从函数原始字节中提取人类可读属性。
# 无需训练，直接从二进制提取：I/O类型、副作用、显著常量、算法意图。
def _extract_interpretable_features(raw: bytes, name: str) -> dict:
    feats = {}
    # 常量提取：32-bit立即数（魔数或尺寸常量）
    if len(raw) >= 4:
        consts = set()
        for i in range(0, min(len(raw) - 4, 128), 2):
            val = struct.unpack_from('<I', raw, i)[0]
            if val in (0x10001, 0x10001, 0xFFFFFFFF, 0x01000100) or 0x20000000 <= val <= 0xFFFFFFFF:
                consts.add(hex(val))
        if consts:
            feats["notable_constants"] = sorted(consts)[:4]
    # 副作用检测：字符串中是否含memcpy/memset/branch指令
    feats["has_memcpy"] = b"memcpy" in raw[:256]
    feats["has_branch"] = any(raw[i:i+2] in (b'\x00\xd0', b'\xff\xe7') for i in range(min(len(raw)-1, 128)))
    feats["size_category"] = "large" if len(raw) > 16384 else ("medium" if len(raw) > 4096 else "small")
    return feats


def _functional_sensitivity(name: str, size: int, raw_data: bytes) -> float:
    score = 0.0; name_lower = name.lower()
    weights = {"auth": 0.9, "crypt": 0.85, "sign": 0.85, "key_": 0.8, "boot": 0.8,
               "cert": 0.8, "admin": 0.7, "root": 0.7, "firmware": 0.65, "secure": 0.7,
               "bypass": 0.95, "exploit": 0.95, "shell": 0.8, "cmd_": 0.5, "handler": 0.5}
    for kw, w in weights.items():
        if kw in name_lower:
            score += w
    if size > 16384:
        score *= 1.3
    if b"memcpy" in raw_data[:256] or b"strcpy" in raw_data[:256]:
        score += 0.15
    return min(score, 1.0)


def _find_function_boundaries(data: bytes) -> list[CodeBlock]:
    blocks = []
    arm_p = re.compile(rb'\x00\x48\x2d\xe9|\x04\xe0\x2d\xe5')
    thumb_p = re.compile(rb'\x80\xb5|\x2d\xe9\xf0[\x40-\x4f]')
    x86_p = re.compile(rb'\x55\x48\x89[\xe5\xec]')
    mips_p = re.compile(rb'\x27\xbd[\xff\xfe]..\xaf\xbf')
    for pat, arch in ((arm_p, "arm"), (thumb_p, "thumb"), (x86_p, "x86"), (mips_p, "mips")):
        for m in pat.finditer(data):
            off = m.start(); sz = 64 * 1024
            for m2 in pat.finditer(data, off + 1):
                sz = m2.start() - off; break
            sz = min(sz, 65536); raw = data[off:off + min(256, len(data) - off)]
            b = CodeBlock(name=f"{arch}_fn_{off:06x}", offset=off, size=sz, hash=_sha256(raw))
            b.fss = _functional_sensitivity(b.name, sz, raw)
            b.interpretable_features = _extract_interpretable_features(raw, b.name)
            blocks.append(b)
    if not blocks:
        for off in range(0, len(data) - 4096, 4096):
            raw = data[off:off + 4096]
            b = CodeBlock(name=f"blk_{off:08x}", offset=off, size=4096, hash=_sha256(raw))
            b.fss = _functional_sensitivity(b.name, 4096, raw)
            b.interpretable_features = _extract_interpretable_features(raw, b.name)
            blocks.append(b)
    return blocks


def _classify_risk(name: str) -> tuple:
    for pat, risk, reason in _SECURITY_SENSITIVE:
        if pat in name.lower():
            return risk, reason
    return RiskLevel.LOW, ""


def _rolling_chunk(data: bytes, window=48, chunk_mask=0x1FFF) -> list[CodeBlock]:
    if len(data) < window * 2:
        return _find_function_boundaries(data)
    blocks = []; hash_val = 0; chunk_start = 0
    for i, b in enumerate(data):
        hash_val = ((hash_val << 1) ^ b) & 0xFFFFFFFF
        if i >= window:
            hash_val ^= (data[i - window] << (window % 32)) & 0xFFFFFFFF
        if (hash_val & chunk_mask) == chunk_mask or i - chunk_start > 65536:
            if i - chunk_start >= 64:
                chunk = data[chunk_start:i]
                blk = CodeBlock(name=f"rc_{chunk_start:08x}", offset=chunk_start, size=len(chunk), hash=_sha256(chunk))
                blk.fss = _functional_sensitivity(blk.name, len(chunk), chunk)
                blk.interpretable_features = _extract_interpretable_features(chunk, blk.name)
                blocks.append(blk)
            chunk_start = i + 1; hash_val = 0
    if len(data) - chunk_start >= 64:
        chunk = data[chunk_start:]
        blk = CodeBlock(name=f"rc_{chunk_start:08x}", offset=chunk_start, size=len(chunk), hash=_sha256(chunk))
        blk.fss = _functional_sensitivity(blk.name, len(chunk), chunk)
        blk.interpretable_features = _extract_interpretable_features(chunk, blk.name)
        blocks.append(blk)
    return blocks if blocks else _find_function_boundaries(data)


def _ngram_similarity(a, b, n=3):
    if len(a) < n or len(b) < n:
        return 0.0
    ga = {a[i:i+n] for i in range(min(len(a)-n, 256))}
    gb = {b[i:i+n] for i in range(min(len(b)-n, 256))}
    if not ga or not gb:
        return 0.0
    return len(ga & gb) / len(ga | gb)


def _risk_weight(entry: DiffEntry) -> int:
    w = {RiskLevel.HIGH: 30, RiskLevel.MEDIUM: 20, RiskLevel.LOW: 10}.get(entry.risk, 5)
    c = {ChangeType.ADDED: 3, ChangeType.MODIFIED: 2, ChangeType.DELETED: 1}.get(entry.change, 1)
    return min(int(w * c * (1.0 + entry.block.fss)), 100)


class OTADiffAnalyzer:
    def __init__(self, block_size=4096):
        self._block_size = block_size; self._last_result: OTADiffResult | None = None

    def analyze(self, old, new, old_path="old.bin", new_path="new.bin"):
        old_blocks = _rolling_chunk(old); new_blocks = _rolling_chunk(new)
        old_sd = _sdhash_features(old[:4194304]); new_sd = _sdhash_features(new[:4194304])
        homology = _sdhash_similarity(old_sd, new_sd)

        old_bh = defaultdict(list); new_bh = defaultdict(list)
        for b in old_blocks:
            old_bh[b.hash].append(b)
        for b in new_blocks:
            new_bh[b.hash].append(b)

        oh = set(old_bh); nh = set(new_bh); diffs = []

        for h in oh - nh:
            for b in old_bh[h]:
                rk, rs = _classify_risk(b.name)
                diffs.append(DiffEntry(ChangeType.DELETED, b, risk=rk, reason=rs))
        for h in nh - oh:
            for b in new_bh[h]:
                rk, rs = _classify_risk(b.name)
                diffs.append(DiffEntry(ChangeType.ADDED, b, risk=rk, reason=rs or "new code"))
        for nb in new_blocks:
            for ob in old_blocks:
                if ob.name == nb.name and ob.hash != nb.hash:
                    rk, rs = _classify_risk(nb.name)
                    diffs.append(DiffEntry(ChangeType.MODIFIED, nb, old_block=ob, risk=rk, reason=rs or "modified"))

        del_only = [d for d in diffs if d.change == ChangeType.DELETED]
        add_only = [d for d in diffs if d.change == ChangeType.ADDED]; reconciled = 0
        for d_del in del_only[:]:
            for d_add in add_only[:]:
                if d_del not in diffs or d_add not in diffs:
                    continue
                if d_add.block.offset + min(d_add.block.size, 256) > len(new):
                    continue
                if d_del.block.offset + min(d_del.block.size, 256) > len(old):
                    continue
                sim = _ngram_similarity(new[d_add.block.offset:d_add.block.offset + min(d_add.block.size, 256)],
                                        old[d_del.block.offset:d_del.block.offset + min(d_del.block.size, 256)])
                if sim > 0.6:
                    diffs.remove(d_del); diffs.remove(d_add)
                    rk, rs = _classify_risk(d_add.block.name)
                    diffs.append(DiffEntry(ChangeType.MODIFIED, d_add.block, old_block=d_del.block,
                                           risk=rk, reason=rs or f"semantic (sim={sim:.2f})"))
                    reconciled += 1; break

        seen = set(); unique = []
        for d in diffs:
            k = (d.change, d.block.name, d.block.hash)
            if k not in seen:
                seen.add(k); unique.append(d)

        hi = sum(1 for d in unique if d.risk == RiskLevel.HIGH)
        med = sum(1 for d in unique if d.risk == RiskLevel.MEDIUM)
        scores = [_risk_weight(d) for d in unique]
        avg = (sum(scores) / len(scores)) if scores else 0.0

        by_fss = sorted(unique, key=lambda d: d.block.fss, reverse=True)
        top_fss = [{"name": d.block.name, "fss": round(d.block.fss, 2),
                    "reason": d.reason, "features": d.block.interpretable_features}
                   for d in by_fss[:10] if d.block.fss > 0.5]

        res = OTADiffResult(old_file=old_path, new_file=new_path, diffs=unique, stats={
            "added": sum(1 for d in unique if d.change == ChangeType.ADDED),
            "modified": sum(1 for d in unique if d.change == ChangeType.MODIFIED),
            "deleted": sum(1 for d in unique if d.change == ChangeType.DELETED),
            "high_risk": hi, "medium_risk": med,
            "total_changed_blocks": len(unique),
            "avg_risk_score": round(avg, 1),
            "reconciled_by_similarity": reconciled,
            "sdhash_homology": round(homology, 3),
            "top_fss_changes": top_fss,
        })
        self._last_result = res; return res

    @property
    def last_result(self) -> OTADiffResult | None:
        return self._last_result
