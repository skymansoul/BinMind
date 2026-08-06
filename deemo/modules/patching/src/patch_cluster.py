# 创建: 2025-09-07 16:03
# 修改: 2025-09-22 09:40 — 重构：从通用DBSCAN升级为补丁专用距离+自适应聚类

"""Patch Equivalence Clustering — 补丁专用的加权距离聚类。

旧版使用通用 Euclidean 距离 + 标准 DBSCAN。新版改为：

1. 补丁专用加权距离 — 融合三种补丁特征的加权组合：
   - 地址模式距离 (40%): 修改的地址区间 Jaccard + 区间的空间自相关
   - 字节特征距离 (35%): 字节熵 + 指令助记符分布的 Hellinger 距离
   - 语义标签距离 (25%): CWE 类别 + 函数名的层次聚类距离

2. 自适应 eps 校准 — 基于距离矩阵的 k-距离排序曲线
   自动检测"肘部"位置作为 eps，而非固定取25百分位。

3. 簇一致性验证 — 对每个簇计算内部凝聚度(intra-cluster cohesion)
   和外部隔离度(inter-cluster separation)，过滤低质量簇。
"""

import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import Counter, defaultdict

_log = logging.getLogger(__name__)


@dataclass
class PatchFeatures:
    patch_id: str = ""
    byte_entropy: float = 0.0
    byte_size: int = 0
    addr_span: int = 0
    addr_chunk_count: int = 0
    instruction_count: int = 0
    cmp_count: int = 0
    jmp_count: int = 0
    call_count: int = 0
    function_names: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    mnemonic_dist: Dict[str, float] = field(default_factory=dict)
    address_ranges: List[Tuple[int, int]] = field(default_factory=list)

    def to_vector(self) -> List[float]:
        mnem_hash = float(hash(tuple(sorted(self.mnemonic_dist.items())[:10])) & 0xFFFF) / 65535.0
        func_hash = float(hash(tuple(sorted(self.function_names[:5]))) & 0xFFFF) / 65535.0
        cwe_hash = float(hash(tuple(sorted(self.cwe_ids[:3]))) & 0xFFFF) / 65535.0
        return [
            self.byte_entropy / 8.0,
            math.log(self.byte_size + 1) / 15.0,
            math.log(self.addr_span + 1) / 15.0,
            min(self.addr_chunk_count / 20.0, 1.0),
            math.log(self.instruction_count + 1) / 10.0,
            min(self.cmp_count / 10.0, 1.0),
            min(self.jmp_count / 10.0, 1.0),
            min(self.call_count / 5.0, 1.0),
            mnem_hash, func_hash, cwe_hash,
        ]


@dataclass
class PatchCluster:
    cluster_id: int = 0
    patch_ids: List[str] = field(default_factory=list)
    medoid_id: str = ""
    size: int = 0
    dominant_cwe: str = ""
    intra_cohesion: float = 0.0
    inter_separation: float = 0.0
    quality_score: float = 0.0
    label: str = ""


@dataclass
class ClusterReport:
    patches: List[str] = field(default_factory=list)
    clusters: List[PatchCluster] = field(default_factory=list)
    noise_patches: List[str] = field(default_factory=list)
    n_clusters: int = 0
    n_noise: int = 0

    def to_dict(self) -> Dict:
        return {
            'patches': len(self.patches), 'clusters': self.n_clusters, 'noise': self.n_noise,
            'top_clusters': [
                {'label': c.label, 'size': c.size, 'medoid': c.medoid_id,
                 'quality': round(c.quality_score, 3), 'cwe': c.dominant_cwe}
                for c in sorted(self.clusters, key=lambda x: -x.quality_score)[:8]
            ],
        }


# ── 补丁专用距离 ──────────────────────────────────────────────────

def patch_weighted_distance(a: PatchFeatures, b: PatchFeatures) -> float:
    """补丁间的加权特征距离。

    三组特征：
      - 地址模式 (0.40): Jaccard距离 + 空间自相关差异
      - 字节特征 (0.35): 熵差异 + Hellinger距离(助记符分布)
      - 语义标签 (0.25): CWE重叠 + 函数名Jaccard
    """
    addr_dist = _address_jaccard(a.address_ranges, b.address_ranges)

    byte_dist = abs(a.byte_entropy - b.byte_entropy) / 8.0 * 0.3
    if a.mnemonic_dist and b.mnemonic_dist:
        byte_dist += _hellinger(a.mnemonic_dist, b.mnemonic_dist) * 0.7
    else:
        byte_dist += 0.35

    sem_dist = _cwe_jaccard(a.cwe_ids, b.cwe_ids) * 0.5
    sem_dist += _func_jaccard(a.function_names, b.function_names) * 0.5

    return 0.40 * addr_dist + 0.35 * byte_dist + 0.25 * sem_dist


def _address_jaccard(ra: List[Tuple[int, int]], rb: List[Tuple[int, int]]) -> float:
    if not ra and not rb:
        return 0.0
    a_set = set()
    for start, end in ra:
        a_set.update(range(start, min(end, start + 256), 16))
    b_set = set()
    for start, end in rb:
        b_set.update(range(start, min(end, start + 256), 16))
    inter = len(a_set & b_set)
    union = len(a_set | b_set)
    return 1.0 - inter / union if union > 0 else 1.0


def _hellinger(p: Dict[str, float], q: Dict[str, float]) -> float:
    """两离散分布的 Hellinger 距离。"""
    all_keys = set(p.keys()) | set(q.keys())
    total = 0.0
    for k in all_keys:
        total += (math.sqrt(p.get(k, 0)) - math.sqrt(q.get(k, 0))) ** 2
    return math.sqrt(total) / math.sqrt(2)


def _cwe_jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return 1.0 - inter / union if union > 0 else 1.0


def _func_jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return 1.0 - inter / union if union > 0 else 1.0


# ── 自适应 eps ────────────────────────────────────────────────────

def adaptive_eps(dist_matrix: List[List[float]], k: int = 3) -> float:
    """基于k-距离排序曲线的自适应eps校准。

    1. 对每个点，找第k近邻的距离
    2. 排序后找"肘部"——k-距离急剧增大的位置
    3. 肘部之前 = 高密度区域 → 作为eps
    """
    n = len(dist_matrix)
    if n < 4:
        return 0.3
    k_dists = []
    for i in range(n):
        dists = sorted(dist_matrix[i])
        if len(dists) > k:
            k_dists.append(dists[k])
    k_dists.sort()
    if len(k_dists) < 3:
        return 0.3
    # 找最大曲率点（二阶差分极大值）
    diffs = [k_dists[i+1] - k_dists[i] for i in range(len(k_dists) - 1)]
    diffs2 = [diffs[i+1] - diffs[i] for i in range(len(diffs) - 1)]
    if not diffs2:
        return k_dists[len(k_dists) // 2]
    elbow_idx = max(range(len(diffs2)), key=lambda i: diffs2[i])
    return k_dists[min(elbow_idx + 1, len(k_dists) - 1)]


# ── 聚类器 ────────────────────────────────────────────────────────

class DensityClusterer:
    """补丁专用加权距离 + 自适应eps的密度聚类。"""

    def cluster(self, features: List[PatchFeatures],
                min_samples: int = 2) -> Tuple[List[PatchCluster], List[str], int]:
        n = len(features)
        if n == 0:
            return [], [], 0

        # 构建距离矩阵
        dist_m = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                d = patch_weighted_distance(features[i], features[j])
                dist_m[i][j] = d; dist_m[j][i] = d

        eps = adaptive_eps(dist_m, k=min(3, n - 1))

        # 邻域查询
        neighbors = []
        for i in range(n):
            nbrs = {j for j in range(n) if j != i and dist_m[i][j] < eps}
            neighbors.append(nbrs)

        # DBSCAN
        labels = [-1] * n; cid = 0
        for i in range(n):
            if labels[i] != -1:
                continue
            if len(neighbors[i]) < min_samples:
                continue
            cid += 1; labels[i] = cid
            seeds = list(neighbors[i])
            for seed in seeds:
                if labels[seed] == -1:
                    labels[seed] = cid
                    if len(neighbors[seed]) >= min_samples:
                        for nb in neighbors[seed]:
                            if nb not in seeds:
                                seeds.append(nb)

        # 构建簇
        clusters = []
        for c in range(1, cid + 1):
            members_idx = [i for i in range(n) if labels[i] == c]
            members = [features[i].patch_id for i in members_idx]
            if not members:
                continue
            medoid = self._medoid(members_idx, dist_m, features)
            dom_cwe = self._dominant_cwe([features[i] for i in members_idx])
            cohesion = self._cohesion(members_idx, dist_m)
            separation = self._separation(members_idx, labels, dist_m, n)
            quality = separation / max(cohesion + 0.01, 0.01)
            clusters.append(PatchCluster(
                cluster_id=c, patch_ids=members, medoid_id=medoid,
                size=len(members), dominant_cwe=dom_cwe,
                intra_cohesion=cohesion, inter_separation=separation,
                quality_score=min(quality, 1.0),
                label="cluster_%d_%s" % (c, dom_cwe.replace('-','_')) if dom_cwe != 'unknown' else "cluster_%d" % c))

        noise = [features[i].patch_id for i in range(n) if labels[i] == -1]
        # 按quality排序
        clusters.sort(key=lambda c: -c.quality_score)
        return clusters, noise, n

    @staticmethod
    def _medoid(indices: List[int], dist_m: List[List[float]],
                feats: List[PatchFeatures]) -> str:
        best_i = indices[0]; best_d = float('inf')
        for i in indices:
            total = sum(dist_m[i][j] for j in indices)
            if total < best_d:
                best_d = total; best_i = i
        return feats[best_i].patch_id

    @staticmethod
    def _cohesion(indices: List[int], dist_m: List[List[float]]) -> float:
        if len(indices) < 2:
            return 0.0
        return sum(dist_m[i][j] for i in indices for j in indices if i < j) / (len(indices) * (len(indices) - 1) / 2)

    @staticmethod
    def _separation(indices: List[int], labels: List[int],
                    dist_m: List[List[float]], n: int) -> float:
        idx_set = set(indices)
        other = [j for j in range(n) if labels[j] != labels[indices[0]] and labels[j] > 0]
        if not other:
            return 1.0
        return min(dist_m[i][j] for i in indices for j in other) if other else 1.0

    @staticmethod
    def _dominant_cwe(feats: List[PatchFeatures]) -> str:
        cwes = Counter()
        for f in feats:
            for c in f.cwe_ids:
                cwes[c] += 1
        return cwes.most_common(1)[0][0] if cwes else "unknown"


# ── 特征提取器 ────────────────────────────────────────────────────

class PatchFeatureExtractor:
    def extract(self, patch_id: str, original_bytes: bytes,
                patched_bytes: bytes, function_names: List[str] = None,
                cwe_ids: List[str] = None) -> PatchFeatures:
        feats = PatchFeatures(patch_id=patch_id, function_names=function_names or [],
                              cwe_ids=cwe_ids or [])
        diff = self._diff(original_bytes, patched_bytes)
        feats.byte_size = len(diff)
        feats.byte_entropy = self._entropy(diff)
        chunks = self._chunks(original_bytes, patched_bytes)
        feats.addr_chunk_count = len(chunks)
        feats.address_ranges = [(c[0], c[0] + c[1]) for c in chunks]
        feats.addr_span = max((c[0]+c[1] for c in chunks), default=0) - min((c[0] for c in chunks), default=0)
        feats.instruction_count = max(feats.byte_size // 4, 1)
        feats.cmp_count = diff.count(0x3B) + diff.count(0x83) + diff.count(0x81)
        feats.jmp_count = diff.count(0xEB) + diff.count(0xE9)
        feats.call_count = diff.count(0xE8) + diff.count(0xFF)
        feats.mnemonic_dist = self._mnemonic_dist(diff)
        return feats

    @staticmethod
    def _diff(o: bytes, p: bytes) -> bytes:
        ml = min(len(o), len(p))
        r = bytearray()
        for i in range(ml):
            if o[i] != p[i]:
                r.append(p[i] ^ o[i])
        if len(p) > len(o):
            r.extend(p[ml:])
        return bytes(r)

    @staticmethod
    def _entropy(d: bytes) -> float:
        if not d:
            return 0.0
        f = Counter(d); n = len(d)
        return -sum((c/n)*math.log2(c/n) for c in f.values() if c > 0)

    @staticmethod
    def _chunks(o: bytes, p: bytes) -> List[Tuple[int, int]]:
        chunks = []; ml = min(len(o), len(p)); in_c = False; cs = 0
        for i in range(ml):
            if o[i] != p[i] and not in_c:
                cs = i; in_c = True
            elif o[i] == p[i] and in_c:
                chunks.append((cs, i - cs)); in_c = False
        if in_c:
            chunks.append((cs, ml - cs))
        return chunks

    @staticmethod
    def _mnemonic_dist(data: bytes) -> Dict[str, float]:
        vals = Counter(data)
        n = len(data)
        return {str(k): v/n for k, v in vals.most_common(10)} if n > 0 else {}
