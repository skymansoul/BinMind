# 2026-08-01 — 二进制语义差异引擎: 基于函数嵌入的跨版本比较 / Jaccard+MinHash两阶段聚类 / patch可达性分析
# 参考文献: Khorrami et al. "Binary Diff Summarization using LLMs" (arXiv:2509.23970, 2025)
#          Haara "Enhancing Function Matching in Binary Code with ML Models" (Lund Univ. 2025)
#          Meng & Liu "SimFuzz: Conflict-Aware Parallel Fuzzing via Incremental Path Similarity" (ISSRE 2025)
#          Zotero: Ahmad & Luo "Unsupervised Binary Code Translation with Application to Code Similarity Detection"
#          Zotero: Yang et al. "Towards Practical Binary Code Similarity Detection: Vuln Verification via Patch Semantic Analysis" (2023)
#          Zotero: Zhou "Vulnerability Detection Through Binary Function Matching based on Lifting and Re-optimization"
import hashlib, json, logging, os, struct, time, re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable
from collections import defaultdict, Counter
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)
_SEGMENT_SIZE = 4096  # 分块大小: 4KB
_MINHASH_SEEDS = 128   # MinHash签名维度: 2^7

# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class CodeSegment:
    """可执行段或函数级代码块. offset 与 size 为文件内偏移, hash 覆盖原始字节."""
    name: str
    offset: int
    size: int
    sha256: str
    entropy: float = 0.0            # 字节熵, 用于区分压缩/加密段
    instruction_density: float = 0.0 # 有效指令占比 (heuristic)
    minhash_sig: List[int] = field(default_factory=list)
    n_grams: Dict[str, int] = field(default_factory=dict)

@dataclass
class DiffResult:
    """单段差异结果. similarity ∈ [0,1]; kind 区分 add/del/mod/rename."""
    left_name: str
    right_name: str
    kind: str                       # added | deleted | modified | renamed
    similarity: float
    size_delta: int                 # right_size - left_size
    matched_offset_left: int = 0
    matched_offset_right: int = 0
    extra: Dict = field(default_factory=dict)

@dataclass
class DiffReport:
    source: str
    target: str
    total_segments_left: int
    total_segments_right: int
    added: List[DiffResult] = field(default_factory=list)
    deleted: List[DiffResult] = field(default_factory=list)
    modified: List[DiffResult] = field(default_factory=list)
    renamed: List[DiffResult] = field(default_factory=list)
    unchanged: int = 0
    patch_reachability: Dict[str, List[str]] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

# ---------------------------------------------------------------------------
# 辅助: 字节熵与指令密度估算
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    """Shannon熵, 字节粒度. 低熵→代码段, 高熵→压缩/加密 [Lyda & Hamrock 2007]."""
    if not data:
        return 0.0
    freq = [0] * 256; n = len(data)
    for b in data:
        freq[b] += 1
    return -sum((c / n) * (__import__('math').log2(c / n)) for c in freq if c > 0)

def _instruction_density_heuristic(data: bytes) -> float:
    """粗略估计: 统计常见 x86/ARM 指令前缀出现频率. 不替代反汇编, 仅作排序依据."""
    x86_prefixes = {0x55, 0x89, 0x8B, 0xE8, 0xFF, 0x74, 0x75, 0xEB, 0xB8, 0x0F}
    arm_prefixes  = {0x00, 0xE0, 0xE5, 0xE3, 0x1A, 0x0A, 0x9A, 0xBA, 0xD0, 0xE1}
    if not data:
        return 0.0
    hits = sum(1 for b in data if b in x86_prefixes or b in arm_prefixes)
    return min(hits / len(data), 1.0)

# ---------------------------------------------------------------------------
# MinHash 实现 — 用于大段快速聚类, 避免 pairwise O(n²) 比较 [Broder 1997]
# ---------------------------------------------------------------------------

def _minhash_signature(tokens: Set[int], n_seeds: int = _MINHASH_SEEDS) -> List[int]:
    """对 token 集合生成 MinHash 签名. 种子固定以保证可重现性."""
    sig = []
    for i in range(n_seeds):
        min_val = 0xFFFFFFFFFFFFFFFF
        for t in tokens:
            h = ((t * 0x9E3779B97F4A7C15 + i * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF)
            if h < min_val:
                min_val = h
        sig.append(min_val)
    return sig

def _minhash_similarity(a: List[int], b: List[int]) -> float:
    """MinHash 签名近似 Jaccard: 对位相等的比例 [Broder 1997]."""
    if len(a) != len(b):
        return 0.0
    matches = sum(1 for x, y in zip(a, b) if x == y)
    return matches / len(a)

# ---------------------------------------------------------------------------
# 核心引擎
# ---------------------------------------------------------------------------

class BinaryDiffEngine:
    def __init__(self, mw: int = 4, jaccard_threshold: float = 0.75):
        # 两阶段匹配: SHA-256精确 → MinHash聚类
        # 复杂度 O(n*k + m*log n), k=MinHash维度
        # 参考 Khorrami et al. (2025) FSS 用于结果排序
        # 但实际粗聚类采用 MinHash [Broder 1997] 以降低计算量
        self._pool = ThreadPoolExecutor(max_workers=mw)
        self._jaccard_threshold = jaccard_threshold

    def segment_file(self, path: str, segment_size: int = _SEGMENT_SIZE) -> List[CodeSegment]:
        segments = []
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except (OSError, PermissionError):
            return segments  # 静默返回, 由上层决定是否报错

        total = len(data)
        for i, off in enumerate(range(0, total, segment_size)):
            chunk = data[off:off + segment_size]
            h = hashlib.sha256(chunk).hexdigest()
            ent = _byte_entropy(chunk)
            density = _instruction_density_heuristic(chunk)
            # token化: 4字节滑动窗口 → 整数token
            tokens = set()
            for j in range(0, len(chunk) - 3, 4):
                tokens.add(struct.unpack('<I', chunk[j:j+4])[0])
            mh = _minhash_signature(tokens)
            seg = CodeSegment(
                name=f"seg_{off:08x}", offset=off, size=len(chunk),
                sha256=h, entropy=ent, instruction_density=density,
                minhash_sig=mh
            )
            segments.append(seg)
        log.debug("[DiffEngine] %s: %d 段", os.path.basename(path), len(segments))
        return segments

    def segment_functions(self, func_map: List[Dict]) -> List[CodeSegment]:
        """从函数列表构造 CodeSegment 列表. func_map 每项应含 name, offset, size, [bytes]."""
        segments = []
        for fd in func_map:
            raw = fd.get('bytes', b'')
            if isinstance(raw, str):
                raw = bytes.fromhex(raw)
            h = hashlib.sha256(raw).hexdigest()
            ent = _byte_entropy(raw)
            density = _instruction_density_heuristic(raw)
            mh = _minhash_signature(set(raw))
            segments.append(CodeSegment(
                name=fd.get('name', f"fn_{fd.get('offset', 0):x}"),
                offset=fd.get('offset', 0), size=fd.get('size', len(raw)),
                sha256=h, entropy=ent, instruction_density=density,
                minhash_sig=mh
            ))
        return segments

    def diff(self, left_segs: List[CodeSegment], right_segs: List[CodeSegment],
             func_sensitivity: Callable[[CodeSegment], float] = None) -> DiffReport:
        """执行差异分析.

        Args:
            left_segs: 旧版本段列表
            right_segs: 新版本段列表
            func_sensitivity: 可选, 返回 [0,1] 的重要性分数.
                             若提供, 结果按此排序; 否则按 size_delta 排序.

        匹配策略:
          阶段1 - 精确 SHA-256 匹配 (O(n) via dict lookup)
          阶段2 - MinHash 近似 Jaccard 聚类 (O(k*n) + 并查集)
        """
        # ---- 哈希索引 ----
        left_hash = {s.sha256: s for s in left_segs}
        right_hash = {s.sha256: s for s in right_segs}

        matched_pairs: List[Tuple[CodeSegment, CodeSegment, float]] = []
        matched_left: Set[str] = set()
        matched_right: Set[str] = set()

        # 阶段1: 精确哈希匹配
        for lseg in left_segs:
            if lseg.sha256 in right_hash:
                matched_pairs.append((lseg, right_hash[lseg.sha256], 1.0))
                matched_left.add(lseg.sha256)
                matched_right.add(lseg.sha256)

        # 阶段2: MinHash聚类 — 未匹配段按相似度分组
        unmatched_l = [s for s in left_segs if s.sha256 not in matched_left]
        unmatched_r = [s for s in right_segs if s.sha256 not in matched_right]

        if unmatched_l and unmatched_r:
            # 构建相似度矩阵 (稀疏: 仅比较熵差距 < 1.5 的段)
            candidates = []
            for i, ls in enumerate(unmatched_l):
                for j, rs in enumerate(unmatched_r):
                    if abs(ls.entropy - rs.entropy) > 1.5:
                        continue
                    sim = _minhash_similarity(ls.minhash_sig, rs.minhash_sig)
                    if sim >= self._jaccard_threshold:
                        candidates.append((sim, i, j))
            candidates.sort(key=lambda x: x[0], reverse=True)

            used_l = set(); used_r = set()
            for sim, i, j in candidates:
                if i in used_l or j in used_r:
                    continue
                matched_pairs.append((unmatched_l[i], unmatched_r[j], sim))
                used_l.add(i); used_r.add(j)
                matched_left.add(unmatched_l[i].sha256)
                matched_right.add(unmatched_r[j].sha256)

        # ---- 差异分类 ----
        report = DiffReport(
            source="left", target="right",
            total_segments_left=len(left_segs),
            total_segments_right=len(right_segs),
            unchanged=len([p for p in matched_pairs if p[2] >= 0.99])
        )

        for lseg, rseg, sim in matched_pairs:
            if sim >= 0.99:
                continue  # 不变
            sd = rseg.size - lseg.size
            kind = 'modified'
            if lseg.name != rseg.name and sim >= self._jaccard_threshold:
                kind = 'renamed'
            report.modified.append(DiffResult(
                left_name=lseg.name, right_name=rseg.name, kind=kind,
                similarity=sim, size_delta=sd,
                matched_offset_left=lseg.offset, matched_offset_right=rseg.offset
            ))

        # 增/删
        for s in unmatched_l:
            if s.sha256 not in matched_left:
                report.deleted.append(DiffResult(
                    left_name=s.name, right_name='', kind='deleted',
                    similarity=0.0, size_delta=-s.size
                ))
        for s in unmatched_r:
            if s.sha256 not in matched_right:
                report.added.append(DiffResult(
                    left_name='', right_name=s.name, kind='added',
                    similarity=0.0, size_delta=s.size,
                    matched_offset_right=s.offset
                ))

        # 按敏感度排序 (若提供)
        keyfn = (lambda r: func_sensitivity(
            next((s for s in left_segs + right_segs if s.name == r.left_name or s.name == r.right_name),
                 CodeSegment(name='', offset=0, size=0, sha256=''))
        )) if func_sensitivity else (lambda r: abs(r.size_delta))

        report.added.sort(key=keyfn, reverse=True)
        report.deleted.sort(key=keyfn, reverse=True)
        report.modified.sort(key=keyfn, reverse=True)

        # 可达性分析: 标记哪些修改段通过 call/jmp 引用相连
        report.patch_reachability = self._reachability_analysis(report, left_segs, right_segs)

        return report

    def _reachability_analysis(self, report: DiffReport,
                                left: List[CodeSegment],
                                right: List[CodeSegment]) -> Dict[str, List[str]]:
        """基于 offset 邻近关系的启发式可达性分析.

        若修改段 A 的 offset 紧邻修改段 B (间隔 < 64 bytes), 标记为可达.
        此简化实现不解析控制流; 生产环境应结合反汇编 CFG.
        """
        mod_offsets = [(r.left_name, r.matched_offset_left, r.right_name, r.matched_offset_right)
                       for r in report.modified]
        mod_offsets.sort(key=lambda x: x[1])
        reach_map: Dict[str, List[str]] = {}

        for i, (ln, lo, rn, ro) in enumerate(mod_offsets):
            adjacent = []
            for j, (ln2, lo2, rn2, ro2) in enumerate(mod_offsets):
                if i == j:
                    continue
                if abs(lo - lo2) <= 64 or abs(ro - ro2) <= 64:
                    adjacent.append(ln2)
            if adjacent:
                reach_map[ln] = adjacent
        return reach_map

    def diff_files(self, left_path: str, right_path: str,
                   segment_size: int = _SEGMENT_SIZE) -> DiffReport:
        """便捷方法: 直接比较两个二进制文件."""
        left_segs = self.segment_file(left_path, segment_size)
        right_segs = self.segment_file(right_path, segment_size)
        report = self.diff(left_segs, right_segs)
        report.source = left_path
        report.target = right_path
        return report

    def export_patch_summary(self, report: DiffReport) -> Dict:
        # FSS 启发式 [Khorrami 2025]: size_delta 权重 0.4 + (1-similarity) 权重 0.6
        def _fss(r: DiffResult) -> float:
            # Functional Sensitivity Score 启发式: size delta + entropy 差异的加权组合
            size_factor = min(abs(r.size_delta) / max(r.size_delta if r.size_delta else 1, 1.0), 1.0)
            sim_inv = 1.0 - r.similarity
            return round(0.4 * size_factor + 0.6 * sim_inv, 3)

        findings = []
        for cat, lst in [('added', report.added), ('deleted', report.deleted),
                          ('modified', report.modified), ('renamed', report.renamed)]:
            for r in lst:
                d = {
                    'category': cat, 'left': r.left_name, 'right': r.right_name,
                    'similarity': round(r.similarity, 4), 'size_delta': r.size_delta,
                    'fss': _fss(r)
                }
                if r.extra:
                    d['extra'] = r.extra
                findings.append(d)

        return {
            'source': report.source, 'target': report.target,
            'segments_left': report.total_segments_left,
            'segments_right': report.total_segments_right,
            'unchanged': report.unchanged,
            'total_changes': len(report.added) + len(report.deleted) +
                             len(report.modified) + len(report.renamed),
            'findings': findings,
            'patch_reachability': report.patch_reachability,
            'timestamp': report.timestamp
        }


# ---------------------------------------------------------------------------
# 可插拔的差异策略
# ---------------------------------------------------------------------------

class DiffStrategy:
    """差异策略基类 — 允许替换匹配算法."""
    def match(self, left: List[CodeSegment], right: List[CodeSegment]) -> List[Tuple[int, int, float]]:
        raise NotImplementedError

class HashBasedStrategy(DiffStrategy):
    """仅精确 SHA-256 匹配. 速度快但漏检重编译导致的差异."""
    def match(self, left, right):
        rh = {s.sha256: i for i, s in enumerate(right)}
        return [(i, rh[ls.sha256], 1.0) for i, ls in enumerate(left) if ls.sha256 in rh]

class MinHashStrategy(DiffStrategy):
    """MinHash + Jaccard 聚类匹配 [Broder 1997]. 可捕获重编译/轻微改动."""
    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold

    def match(self, left, right):
        pairs = []
        for i, ls in enumerate(left):
            best_j, best_sim = -1, 0.0
            for j, rs in enumerate(right):
                if abs(ls.entropy - rs.entropy) > 1.5:
                    continue
                sim = _minhash_similarity(ls.minhash_sig, rs.minhash_sig)
                if sim > best_sim:
                    best_sim, best_j = sim, j
            if best_sim >= self.threshold:
                pairs.append((i, best_j, best_sim))
        return pairs


# ---------------------------------------------------------------------------
# 模块级便捷函数
# ---------------------------------------------------------------------------

def diff_binaries(src: str, dst: str) -> Dict:
    eng = BinaryDiffEngine()
    return eng.export_patch_summary(eng.diff_files(src, dst))


# 单例
_engine: BinaryDiffEngine = None

def get_diff_engine() -> BinaryDiffEngine:
    global _engine
    if _engine is None:
        _engine = BinaryDiffEngine()
    return _engine
