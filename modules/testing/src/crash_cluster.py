# 崩溃聚类引擎 — 基于多维特征的崩溃相似度分析与自动分组
# 核心: 对大量崩溃样本计算pairwise相似度矩阵，用层次聚类(UPGMA)
# 或DBSCAN将同类崩溃归组，大幅缩减人工triage工作量。
#
# 聚类特征维度:
#   F1: 信号号+崩溃类型 (categorical, exact match)
#   F2: 栈帧签名 (top-3 frames模糊哈希)
#   F3: 故障地址区域 (stack/heap/global/null五分类)
#   F4: Sanitizer指纹 (ASan第一行错误描述)
#   F5: 输入结构相似度 (MinHash / SimHash)
#   F6: 执行时间轮廓 (快/中/慢/超时)
#
# 文献:
#   CrashTalk: automated generation of
#     precise descriptions of software security bugs
#   ClusterFuzz: crash deduplication pipeline
#   crashwalk: AFL crash analysis toolkit
#   LibAFL: modular fuzzer framework with
#     built-in crash triage
import hashlib
import math
import re
import struct
import zlib
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field


@dataclass
class CrashFeature:
    """崩溃的多维特征向量。"""
    crash_id: str
    signal_num: int = 0
    crash_type: str = ""
    top_frames: List[str] = field(default_factory=list)
    fault_addr: int = 0
    sanitizer_first_line: str = ""
    input_hash: str = ""
    input_size: int = 0
    exec_time_ms: float = 0.0
    category: str = "unknown"  # 聚类后填充


@dataclass
class CrashCluster:
    """一组同类崩溃。"""
    cluster_id: int
    members: List[CrashFeature]
    representative: Optional[CrashFeature] = None
    label: str = ""
    size: int = 0
    cohesion: float = 0.0  # 簇内平均相似度 [0, 1]


class CrashClusterer:
    """崩溃聚类器 — 层次聚类(UPGMA)+多维特征距离。

    距离度量: 加权Jaccard x Manhattan混合。
    不使用单一特征（会导致去重过度或不足），而是加权组合
    6个特征维度的归一化距离。

    权重设计: 栈帧签名权重最高 (直接反映崩溃位置), sanitizer
    指纹次之 (精确语义), 故障地址区域辅助, 输入相似度为弱信号。
    """

    # 默认特征权重
    DEFAULT_WEIGHTS = {
        'signal_type': 0.25,       # 信号+崩溃类型 (exact)
        'stack_signature': 0.35,   # top-3 frames模糊哈希
        'fault_region': 0.15,      # 故障地址区域
        'sanitizer_line': 0.15,    # sanitizer第一行
        'input_similarity': 0.05,  # 输入MinHash
        'exec_profile': 0.05,      # 执行时间
    }

    def __init__(self, weights: Dict[str, float] = None):
        self._weights = weights or self.DEFAULT_WEIGHTS
        self._features: List[CrashFeature] = []
        self._clusters: List[CrashCluster] = []
        self._distance_cache: Dict[Tuple[int, int], float] = {}

    def add_crash(self, feature: CrashFeature) -> None:
        self._features.append(feature)

    def add_crashes(self, features: List[CrashFeature]) -> None:
        self._features.extend(features)

    # 特征提取
    @staticmethod
    def _stack_signature(frames: List[str]) -> str:
        """top-3帧的稳定签名: 函数名+偏移模糊哈希。"""
        top3 = frames[:3]
        if not top3:
            return "empty"
        # 提取函数名（去掉地址部分）
        func_names = []
        for f in top3:
            # 匹配 'func_name+0xNN' 或 '0xADDR in func_name'
            m = re.search(r'(?:in\s+)?(\w+)(?:\+0x[0-9a-f]+)?', f)
            if m:
                func_names.append(m.group(1).lower())
            else:
                func_names.append(f[:20])
        payload = '|'.join(func_names)
        return hashlib.md5(payload.encode()).hexdigest()[:12]

    @staticmethod
    def _fault_region(addr: int) -> str:
        """将故障地址映射到内存区域分类。"""
        if addr == 0:
            return 'null'
        if addr < 0x1000:
            return 'low_addr'
        if addr == 0x41414141:
            return 'controlled_pattern'
        if 0x7F0000000000 <= addr <= 0x7FFFFFFFFFFF:
            return 'high_user_space'
        if 0x100000 <= addr <= 0x400000:
            return 'heap_like'
        return 'other'

    @staticmethod
    def _input_minhash(data: bytes, num_hashes: int = 64) -> int:
        """输入的MinHash签名 (64-bit)。"""
        if not data:
            return 0
        min_vals = []
        chunk_size = max(1, len(data) // num_hashes)
        for seed in range(4):  # 4个哈希种子
            h = float('inf')
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                val = zlib.crc32(chunk + struct.pack('B', seed))
                h = min(h, val)
            min_vals.append(h)
        # 合并为64-bit
        result = 0
        for mv in min_vals:
            result = ((result << 16) ^ mv) & 0xFFFFFFFFFFFFFFFF
        return result

    # 距离计算
    def distance(self, a: CrashFeature, b: CrashFeature) -> float:
        """计算两个崩溃之间的加权距离 [0, 1]。0=完全相同, 1=完全不同。"""
        cache_key = (hash(a.crash_id), hash(b.crash_id))
        if cache_key in self._distance_cache:
            return self._distance_cache[cache_key]

        d_signal = 0.0 if (a.signal_num == b.signal_num
                           and a.crash_type == b.crash_type) else 1.0

        a_sig = self._stack_signature(a.top_frames)
        b_sig = self._stack_signature(b.top_frames)
        d_stack = 0.0 if a_sig == b_sig else 1.0

        a_region = self._fault_region(a.fault_addr)
        b_region = self._fault_region(b.fault_addr)
        d_region = 0.0 if a_region == b_region else 1.0

        a_san_line = a.sanitizer_first_line[:80] if a.sanitizer_first_line else ""
        b_san_line = b.sanitizer_first_line[:80] if b.sanitizer_first_line else ""
        d_san = 0.0 if a_san_line == b_san_line else (
            0.5 if a_san_line and b_san_line and a_san_line[:30] == b_san_line[:30]
            else 1.0)

        d_input = 1.0
        if a.input_hash and b.input_hash:
            d_input = 0.0 if a.input_hash == b.input_hash else 0.5

        time_ratio = (abs(a.exec_time_ms - b.exec_time_ms) /
                      max(1.0, a.exec_time_ms + b.exec_time_ms)) if (
            a.exec_time_ms + b.exec_time_ms) > 0 else 0.0
        d_time = min(1.0, time_ratio)

        dist = (
            self._weights['signal_type'] * d_signal
            + self._weights['stack_signature'] * d_stack
            + self._weights['fault_region'] * d_region
            + self._weights['sanitizer_line'] * d_san
            + self._weights['input_similarity'] * d_input
            + self._weights['exec_profile'] * d_time
        )

        self._distance_cache[cache_key] = dist
        return dist

    def similarity(self, a: CrashFeature, b: CrashFeature) -> float:
        return 1.0 - self.distance(a, b)

    # 层次聚类
    def cluster_upgma(self, threshold: float = 0.35) -> List[CrashCluster]:
        """UPGMA (Unweighted Pair Group Method with Arithmetic Mean):
        自底向上合并最相似的簇，直到所有簇间距离 > threshold。
        """
        n = len(self._features)
        if n == 0:
            return []
        if n == 1:
            self._clusters = [CrashCluster(
                cluster_id=1, members=[self._features[0]],
                label=self._features[0].crash_type, size=1, cohesion=1.0)]
            return self._clusters

        # 初始化: 每个崩溃一个簇
        clusters = [CrashCluster(
            cluster_id=i, members=[self._features[i]],
            label=self._features[i].crash_type,
            size=1, cohesion=1.0)
            for i in range(n)]

        # 距离矩阵
        dist_matrix = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                d = self.distance(self._features[i], self._features[j])
                dist_matrix[i][j] = d
                dist_matrix[j][i] = d

        active = set(range(n))

        while len(active) > 1:
            # 找最近的一对簇
            min_dist = float('inf')
            merge_pair = (0, 0)
            for i in active:
                for j in active:
                    if i >= j:
                        continue
                    if dist_matrix[i][j] < min_dist:
                        min_dist = dist_matrix[i][j]
                        merge_pair = (i, j)

            if min_dist > threshold:
                break  # 停止合并

            ci, cj = merge_pair
            # 合并cj到ci
            clusters[ci].members.extend(clusters[cj].members)
            clusters[ci].size = len(clusters[ci].members)
            clusters[ci].cohesion = 1.0 - min_dist
            # UPGMA: 新簇间距离=两簇成员距离的算术平均
            merged_members = clusters[ci].members
            for k in active:
                if k == ci or k == cj:
                    continue
                # 平均距离
                total_d = 0.0
                count = 0
                for ma in merged_members:
                    for mb in clusters[k].members:
                        total_d += self.distance(ma, mb)
                        count += 1
                avg_d = total_d / count if count > 0 else 1.0
                dist_matrix[ci][k] = avg_d
                dist_matrix[k][ci] = avg_d

            active.discard(cj)

        self._clusters = [clusters[i] for i in active]
        # 选择代表 (离簇中心最近的成员)
        for cl in self._clusters:
            cl.representative = self._find_representative(cl)

        return self._clusters

    def _find_representative(self,
                             cluster: CrashCluster) -> Optional[CrashFeature]:
        """选择离簇内所有成员平均距离最小的崩溃为代表。"""
        if cluster.size <= 1:
            return cluster.members[0] if cluster.members else None
        best = None
        best_avg_dist = float('inf')
        for a in cluster.members:
            avg_d = sum(
                self.distance(a, b) for b in cluster.members) / cluster.size
            if avg_d < best_avg_dist:
                best_avg_dist = avg_d
                best = a
        return best

    # 报告
    def cluster_report(self) -> Dict[str, Any]:
        return {
            'total_crashes': len(self._features),
            'num_clusters': len(self._clusters),
            'clusters': [
                {
                    'id': c.cluster_id,
                    'size': c.size,
                    'label': c.label,
                    'cohesion': round(c.cohesion, 3),
                    'representative_id': (
                        c.representative.crash_id
                        if c.representative else 'N/A'),
                    'top_frames': (
                        c.representative.top_frames[:3]
                        if c.representative else []),
                }
                for c in self._clusters
            ],
            'reduction_ratio': round(
                1.0 - len(self._clusters) / max(1, len(self._features)), 3),
        }

    def largest_clusters(self, k: int = 5) -> List[CrashCluster]:
        return sorted(self._clusters, key=lambda c: -c.size)[:k]

    def reset(self) -> None:
        self._features.clear()
        self._clusters.clear()
        self._distance_cache.clear()


# 便捷入口
def quick_crash_cluster(crash_records: List[Dict[str, Any]],
                        threshold: float = 0.35) -> List[CrashCluster]:
    """从crash record字典列表快速执行聚类。"""
    clusterer = CrashClusterer()
    for rec in crash_records:
        cf = CrashFeature(
            crash_id=rec.get('id', hashlib.md5(
                str(rec).encode()).hexdigest()[:8]),
            signal_num=rec.get('signal', 0),
            crash_type=rec.get('type', 'unknown'),
            top_frames=rec.get('frames', []),
            fault_addr=rec.get('fault_addr', 0),
            sanitizer_first_line=rec.get('sanitizer', ''),
            input_hash=rec.get('input_hash', ''),
            input_size=rec.get('input_size', 0),
            exec_time_ms=rec.get('exec_time_ms', 0.0),
        )
        clusterer.add_crash(cf)
    return clusterer.cluster_upgma(threshold)
