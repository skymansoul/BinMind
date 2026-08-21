# SimHash 二进制相似度 — 指纹生成与大规模近似匹配
# Charikar (2002) "Similarity Estimation Techniques from Rounding Algorithms"
#       — SimHash 的原始 STOC 论文，提出基于超平面舍入的 LSH 方案
# Manku et al. (2007) "Detecting Near-Duplicates for Web Crawling" (WWW)
#       — SimHash 指纹在海量网页去重中的工程化应用 (Hamming 距离 + 分块索引)
# "SAFE: Self-Attentive Function Embeddings" (Massarelli et al. 2019, ACSAC)
#       — 图感知的函数嵌入与 SimHash 的互补使用 (嵌入 → 精确匹配, SimHash → 快速初筛)

import hashlib as _hl
import struct as _struct
import math as _math
from typing import Any

# ===== SimHash 核心 =====
# 将任意字节序列映射到固定位宽的指纹，满足：
# - 相似输入的指纹汉明距离小 (局部敏感)
# - 不同输入的指纹均匀分布 (抗碰撞)
# 默认 64 位 — 平衡精度和存储 (128 位精度更高但索引空间翻倍)


class SimHash:
    # 64b SimHash — Charikar (STOC 2002)
    # 特征权重策略: insn n-gram=1.0, bb_size/avg=0.5, API call=1.5
    def __init__(self, n_bits: int = 64):
        self.n = n_bits

    def compute(self, features: list[tuple[bytes, float]]) -> int:
        # 加权特征 → 64b 指纹, O(N*K)
        if not features:
            return 0

        # 累加向量 (每一位独立)
        accumulator = [0] * self.n
        for feat_bytes, weight in features:
            h = _hl.sha256(feat_bytes).digest()
            # 将 hash 的每 bit 映射为 +weight 或 -weight
            for byte_idx in range(min(32, len(h))):
                byte_val = h[byte_idx]
                for bit in range(8):
                    idx = byte_idx * 8 + bit
                    if idx >= self.n:
                        break
                    if (byte_val >> bit) & 1:
                        accumulator[idx] += weight
                    else:
                        accumulator[idx] -= weight

        # 符号判定
        result = 0
        for idx, val in enumerate(accumulator):
            if val >= 0:
                result |= (1 << idx)
        return result

    def hamming_distance(self, fp1: int, fp2: int) -> int:
        """两个 SimHash 指纹的汉明距离 (不同位数)。"""
        xor = fp1 ^ fp2
        return xor.bit_count()

    def similarity(self, fp1: int, fp2: int) -> float:
        """归一化相似度 [0, 1] — 汉明距离越小越相似。"""
        return 1.0 - (self.hamming_distance(fp1, fp2) / self.n)


# ===== 函数级 SimHash 特征提取 =====
# 将函数分解为以下特征:
# - 归一化指令 n-gram (权重 1.0)
# - 基本块大小分布 (权重 0.5)
# - API 调用名 (权重 1.5 — API 调用在相似度判断中更重要)
# SAFE 的特征选择策略 — 调和静态特征与结构特征的权重

def extract_function_features(insns: list[tuple[str, str]],
                                basic_blocks: list[dict] | None = None,
                                api_calls: list[str] | None = None) -> list[tuple[bytes, float]]:
    """为函数提取 SimHash 输入特征。
    返回加权特征列表。"""
    features: list[tuple[bytes, float]] = []

    # 指令 3-gram
    norm_insns = []
    import re as _re
    for mnem, ops in insns:
        n_ops = _re.sub(r'0x[0-9a-fA-F]+', 'IMM', ops)
        n_ops = _re.sub(r'-?\d+', 'IMM', n_ops)
        norm_insns.append(f'{mnem}|{n_ops}')

    for i in range(len(norm_insns) - 2):
        gram = ';;'.join(norm_insns[i:i + 3])
        features.append((gram.encode('utf-8', errors='replace'), 1.0))

    # 基本块大小 (如提供)
    if basic_blocks:
        sizes = []
        for bb in basic_blocks:
            sz = len(bb.get('instructions', []))
            sizes.append(sz)
        avg_sz = sum(sizes) / max(len(sizes), 1)
        for i, bb in enumerate(basic_blocks):
            sz = sizes[i] if i < len(sizes) else 1
            bb_id = f'bb_{i}_size_{sz}'.encode()
            weight = sz / max(avg_sz, 1) * 0.5
            features.append((bb_id, weight))

    # API 调用 (权重提升 — 强语义信号)
    if api_calls:
        for api in api_calls:
            features.append((f'API:{api}'.encode('utf-8', errors='replace'), 1.5))

    return features


# ===== 分块索引 (Block-Based Indexing) =====
# 汉明距离 ≤ k 的搜索 — 将指纹分成 b 块，至少有一块完全匹配
# 这个性质来自鸽巢原理: 若两指纹距离 ≤ k，则 b > k 时至少一个块完全相同
# Manku et al. (2007) 的 Web Crawling 去重系统

class SimHashIndex:
    """多表 SimHash 索引 — 支持近似最近邻查找。

    原理: 将 64 位指纹分为 b 块 (默认 4 块 x 16 位)。
    查询时，检查每个块在对应哈希表中的精确命中，
    然后对候选集计算完整汉明距离过滤。n_blocks 分块数
    (默认 4) → 能发现距离 ≤ 3 的所有匹配, max_distance
    汉明距离阈值 (默认 3)。
    """

    def __init__(self, n_blocks: int = 4, max_distance: int = 3):
        self._n_blocks = n_blocks
        self._block_bits = 64 // n_blocks
        self._block_mask = (1 << self._block_bits) - 1
        self._max_dist = max_distance
        # 每个块一个哈希表: {block_value: set of (item_id, full_fingerprint)}
        self._tables: list[dict[int, set[tuple[str, int]]]] = [
            {} for _ in range(n_blocks)
        ]
        self._hasher = SimHash(64)

    def insert(self, item_id: str, fingerprint: int):
        """将指纹插入索引。O(b)。"""
        for block_idx in range(self._n_blocks):
            shift = block_idx * self._block_bits
            block_val = (fingerprint >> shift) & self._block_mask
            self._tables[block_idx].setdefault(block_val, set()).add((item_id, fingerprint))

    def query(self, fingerprint: int) -> list[dict]:
        """查询与给定指纹汉明距离 ≤ max_distance 的所有条目。
        先按块精确匹配 → 候选合并 → 完整汉明距离验证。"""
        candidates: set[tuple[str, int]] = set()
        for block_idx in range(self._n_blocks):
            shift = block_idx * self._block_bits
            block_val = (fingerprint >> shift) & self._block_mask
            bucket = self._tables[block_idx].get(block_val, set())
            candidates.update(bucket)

        # 完整汉明距离过滤
        results = []
        for item_id, fp in candidates:
            dist = self._hasher.hamming_distance(fingerprint, fp)
            if dist <= self._max_dist:
                results.append({
                    'item_id': item_id,
                    'fingerprint': fp,
                    'hamming_distance': dist,
                    'similarity': round(1.0 - dist / 64, 3),
                })

        results.sort(key=lambda r: r['hamming_distance'])
        return results

    def size(self) -> int:
        """唯一条目总数。"""
        all_items = set()
        for table in self._tables:
            for bucket in table.values():
                all_items.update(item_id for item_id, _ in bucket)
        return len(all_items)


# ===== 二进制级 SimHash (文件整体指纹) =====
# 适用于: 快速判断两个二进制文件是否来自同一源码 (跨编译器版本/优化级别)
# 对 .text 节计算全局 SimHash，忽略绝对地址和字符串的微小差异

def binary_level_simhash(pe_data: bytes) -> int | None:
    """计算 PE 文件 .text 节的 SimHash 指纹。
    仅分析代码节，忽略数据/资源节以减少噪音。
    若 PE 格式无效返回 None。"""
    if len(pe_data) < 64 or pe_data[:2] != b'MZ':
        return None

    pe_off = _struct.unpack_from('<I', pe_data, 0x3c)[0]
    if pe_off + 256 > len(pe_data):
        return None

    num_sec = _struct.unpack_from('<H', pe_data, pe_off + 6)[0]
    opt_hdr_size = _struct.unpack_from('<H', pe_data, pe_off + 20)[0]
    sec_hdr_off = pe_off + 24 + opt_hdr_size

    text_data = b''
    for i in range(num_sec):
        hdr = sec_hdr_off + i * 40
        if hdr + 40 > len(pe_data):
            break
        name = pe_data[hdr:hdr + 8].rstrip(b'\x00')
        if name in (b'.text', b'CODE', b'.code'):
            raw_off = _struct.unpack_from('<I', pe_data, hdr + 20)[0]
            raw_size = _struct.unpack_from('<I', pe_data, hdr + 16)[0]
            if raw_off + raw_size <= len(pe_data):
                text_data = pe_data[raw_off:raw_off + raw_size]
            break

    if not text_data:
        return None

    # 特征: 16 字节块，每块作为独立特征
    import re as _re
    features = []
    chunk_size = 16
    for i in range(0, len(text_data) - chunk_size, chunk_size):
        chunk = text_data[i:i + chunk_size]
        # 归一化: 将绝对地址替换为占位符 (x86: E8 xx xx xx xx → E8 00 00 00 00)
        normalized = _re.sub(
            rb'(\xe8|\xe9)[\x00-\xff]{4}',
            lambda m: m.group(1) + b'\x00\x00\x00\x00',
            chunk
        )
        features.append((normalized, 1.0))

    hasher = SimHash(64)
    return hasher.compute(features)


# --- 函数搜索管道 ---
# SimHash 初筛 → 精确嵌入匹配 → LLM 验证
# 三级级联大幅降低搜索延迟 — SimHash 过滤可将候选集缩小 100-1000x
# SAFE 的级联匹配策略

def cascaded_function_search(query_insns: list[tuple[str, str]],
                               index: SimHashIndex,
                               candidate_insns: dict[str, list[tuple[str, str]]],
                               top_k: int = 10) -> list[dict]:
    """三级级联函数搜索管道。
    1. SimHash 快速初筛 (O(b) 块查找)
    2. 指令序列 Jaccard 相似度精排
    3. 返回 top_k 候选"""
    # Level 1: SimHash
    features = extract_function_features(query_insns)
    hasher = SimHash(64)
    fp = hasher.compute(features)
    candidates = index.query(fp)

    # Level 2: Jaccard 精排
    query_set = {f'{m}|{o}' for m, o in query_insns}
    ranked = []
    for cand in candidates:
        cand_insns = candidate_insns.get(cand['item_id'], [])
        if not cand_insns:
            continue
        cand_set = {f'{m}|{o}' for m, o in cand_insns}
        inter = len(query_set & cand_set)
        union = len(query_set | cand_set)
        jaccard = inter / union if union > 0 else 0.0
        ranked.append({
            **cand,
            'jaccard_similarity': round(jaccard, 3),
            'combined_score': round(0.4 * cand['similarity'] + 0.6 * jaccard, 3),
        })

    ranked.sort(key=lambda r: -r['combined_score'])
    return ranked[:top_k]
