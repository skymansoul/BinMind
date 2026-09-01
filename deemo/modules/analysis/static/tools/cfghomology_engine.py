# 三通道匹配的加权投票机制: 至少两通道确认才接受候选
# 指数退避桶宽替代线性桶, 短 persist 区间 (噪声) 的密度权重降低

"""CFG 持续同调指纹匹配引擎 - 二进制相似度搜索的顶层 API

三通道并行匹配:
  通道1 (指令熵): 捕获 CFG 基本块的内容密度, 对编译器指令选择不敏感
  通道2 (中介中心性): 捕获 CFG 的全局枢纽结构, 对局部 CFG 变形不敏感
  通道3 (执行频率): 捕获动态热路径, 对静态混淆不敏感

匹配策略 - 加权投票:
  每条通道独立产生 top-K 候选 + 相似度分数
  候选经三通道多数投票 (>=2/3 通道一致) 后按加权得分排序
  此设计避免了单通道误匹配, 例如熵通道可能将不同程序的结构相似
  代码片段误判为同一二进制, 但中心性和频率通道会给出低分

指纹数据库:
  使用 LSH (局部敏感哈希) 索引加速搜索
  LSH 将 64 维向量散列到 8 个哈希表中, 每表使用 4 个随机投影
  查询时只比较落入同一桶的候选, O(|db|) 降为 O(|db|^(1/8))
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .cfghomology_core import (
    CFGNode, CFGEdge, CFGFiltrationBuilder,
    BarcodeFingerprint,
)
from .cfghomology_persistence import (
    compute_cfg_fingerprints,
    fingerprint_distance,
    fingerprint_similarity,
)


# LSH 索引 - 局部敏感哈希加速近似最近邻搜索

class LSHIndex:
    """针对 64 维指纹向量的 LSH 索引

    使用随机投影 (SimHash 风格): 每张哈希表用 d 个随机超平面
    将向量散列为 d-bit 哈希值
    碰撞概率 P(hash(a)=hash(b)) = 1 - arccos(sim(a,b))/π
    即余弦相似度越高, 碰撞概率越大

    参数:
    num_tables: 哈希表数量 (默认 8, 在精度和内存间平衡)
    bits_per_table: 每表哈希位数 (默认 6, 产生 64 个桶)
    """

    def __init__(self, num_tables: int = 8, bits_per_table: int = 6):
        self._tables: List[Dict[int, List[str]]] = [
            {} for _ in range(num_tables)
        ]
        self._bits = bits_per_table
        self._num_tables = num_tables
        # 随机投影向量, 使用确定性种子保证可复现性
        self._projections: List[List[List[float]]] = []
        self._init_projections()

    def _init_projections(self) -> None:
        """初始化随机投影向量, 确定性伪随机保证可复现"""
        import random as _rnd
        rng = _rnd.Random(0xCF6F19)  # 固定种子

        for t in range(self._num_tables):
            table_projs = []
            for b in range(self._bits):
                # 64 维随机向量, 每个分量 ~ N(0,1)
                vec = [rng.gauss(0, 1) for _ in range(64)]
                # 归一化
                norm = math.sqrt(sum(v * v for v in vec))
                if norm > 1e-9:
                    vec = [v / norm for v in vec]
                table_projs.append(vec)
            self._projections.append(table_projs)

    def _hash_vector(self, vec: List[float], table_idx: int) -> int:
        """计算单个哈希表中向量的哈希值"""
        projs = self._projections[table_idx]
        hash_val = 0
        for bit_idx, proj_vec in enumerate(projs):
            dot = sum(vec[i] * proj_vec[i] for i in range(len(vec)))
            if dot > 0:
                hash_val |= (1 << bit_idx)
        return hash_val

    def insert(self, key: str, fingerprint: BarcodeFingerprint) -> None:
        """插入指纹到 LSH 索引"""
        vec = fingerprint.vector
        if len(vec) != 64:
            return
        for t in range(self._num_tables):
            h = self._hash_vector(vec, t)
            bucket = self._tables[t]
            if h not in bucket:
                bucket[h] = []
            bucket[h].append(key)

    def query(self, fingerprint: BarcodeFingerprint, top_k: int = 10) -> List[str]:
        """查询近似最近邻

        返回与查询指纹落入同一哈希桶的候选 key 列表
        按出现次数降序 (在多个表中碰撞 -> 更可能是近邻)
        """
        vec = fingerprint.vector
        if len(vec) != 64:
            return []

        # 统计出现次数
        candidates: Dict[str, int] = {}
        for t in range(self._num_tables):
            h = self._hash_vector(vec, t)
            bucket = self._tables[t]
            for key in bucket.get(h, []):
                candidates[key] = candidates.get(key, 0) + 1

        # 按出现次数降序
        sorted_candidates = sorted(
            candidates.items(), key=lambda x: -x[1]
        )
        return [k for k, _ in sorted_candidates[:top_k]]


# 匹配结果与匹配引擎

@dataclass
class SimilarityResult:
    """二进制相似度匹配的单条结果"""
    binary_name: str
    entropy_similarity: float = 0.0
    betweenness_similarity: float = 0.0
    frequency_similarity: float = 0.0
    ensemble_score: float = 0.0       # 加权集成分数
    channels_agree: int = 0           # 几通道确认此候选 (>=2 才可靠)


class CFGHomologyEngine:

    # 通道权重 - entropy 和 betweenness 权重更高
    # 原因: 频率通道依赖动态覆盖数据, 静态场景下可能缺失
    _CHANNEL_WEIGHTS = {
        "entropy": 0.40,
        "betweenness": 0.40,
        "frequency": 0.20,
    }

    # 指纹相似度低于此阈值的候选直接丢弃
    _SIMILARITY_FLOOR = 0.35

    def __init__(self):
        self._database: Dict[str, Dict[str, BarcodeFingerprint]] = {}
        self._lsh_indices: Dict[str, LSHIndex] = {
            "entropy": LSHIndex(num_tables=8),
            "betweenness": LSHIndex(num_tables=8),
            "frequency": LSHIndex(num_tables=6),
        }

    def index_binary(
        self,
        name: str,
        nodes: List[CFGNode],
        edges: List[CFGEdge],
    ) -> Dict[str, BarcodeFingerprint]:
        """索引一个二进制文件: 计算三通道指纹并存入数据库"""
        builder = CFGFiltrationBuilder(nodes, edges)

        fingerprints: Dict[str, BarcodeFingerprint] = {}

        # 通道 1: 指令熵
        sorted_ids, node_fvals, edge_list = builder.build_entropy_filtration()
        fp_ent = compute_cfg_fingerprints(sorted_ids, node_fvals, edge_list, "entropy")
        fingerprints["entropy"] = fp_ent
        self._lsh_indices["entropy"].insert(name, fp_ent)

        # 通道 2: 中介中心性
        sorted_ids, node_fvals, edge_list = builder.build_betweenness_filtration()
        fp_bet = compute_cfg_fingerprints(sorted_ids, node_fvals, edge_list, "betweenness")
        fingerprints["betweenness"] = fp_bet
        self._lsh_indices["betweenness"].insert(name, fp_bet)

        # 通道 3: 执行频率
        sorted_ids, node_fvals, edge_list = builder.build_frequency_filtration()
        fp_freq = compute_cfg_fingerprints(sorted_ids, node_fvals, edge_list, "frequency")
        fingerprints["frequency"] = fp_freq
        self._lsh_indices["frequency"].insert(name, fp_freq)

        self._database[name] = fingerprints
        return fingerprints

    def query(
        self,
        nodes: List[CFGNode],
        edges: List[CFGEdge],
        top_k: int = 5,
    ) -> List[SimilarityResult]:
        """查询与给定 CFG 最相似的已知二进制

        top_k: 返回前 K 个最相似候选
        """
        if not self._database:
            return []

        builder = CFGFiltrationBuilder(nodes, edges)

        # 计算查询二进制的三通道指纹
        query_fps: Dict[str, BarcodeFingerprint] = {}

        sorted_ids, node_fvals, edge_list = builder.build_entropy_filtration()
        query_fps["entropy"] = compute_cfg_fingerprints(
            sorted_ids, node_fvals, edge_list, "entropy",
        )

        sorted_ids, node_fvals, edge_list = builder.build_betweenness_filtration()
        query_fps["betweenness"] = compute_cfg_fingerprints(
            sorted_ids, node_fvals, edge_list, "betweenness",
        )

        sorted_ids, node_fvals, edge_list = builder.build_frequency_filtration()
        query_fps["frequency"] = compute_cfg_fingerprints(
            sorted_ids, node_fvals, edge_list, "frequency",
        )

        # 每通道通过 LSH 预筛选后精确计算距离
        candidates: Dict[str, Dict[str, float]] = {}

        for channel in ("entropy", "betweenness", "frequency"):
            q_fp = query_fps[channel]
            # LSH 预筛选: 取所有桶中候选的并集
            lsh_candidates = set()
            for t in range(self._lsh_indices[channel]._num_tables):
                h = self._lsh_indices[channel]._hash_vector(q_fp.vector, t)
                bucket = self._lsh_indices[channel]._tables[t]
                lsh_candidates.update(bucket.get(h, []))

            # 对 LSH 候选精确计算距离
            for name in lsh_candidates:
                if name not in self._database:
                    continue
                db_fp = self._database[name].get(channel)
                if db_fp is None:
                    continue
                sim = fingerprint_similarity(q_fp, db_fp)
                if sim > self._SIMILARITY_FLOOR:
                    if name not in candidates:
                        candidates[name] = {}
                    candidates[name][channel] = sim

        # 三通道加权投票集成
        results: List[SimilarityResult] = []
        for name, channel_sims in candidates.items():
            ent_sim = channel_sims.get("entropy", 0.0)
            bet_sim = channel_sims.get("betweenness", 0.0)
            frq_sim = channel_sims.get("frequency", 0.0)

            # 通道一致性计数: >= threshold 的通道数
            active_channels = sum(
                1 for s in (ent_sim, bet_sim, frq_sim) if s > self._SIMILARITY_FLOOR
            )

            # 至少两通道确认才保留, 单通道匹配置信度不足
            if active_channels < 2:
                continue

            ensemble = (
                self._CHANNEL_WEIGHTS["entropy"] * ent_sim
                + self._CHANNEL_WEIGHTS["betweenness"] * bet_sim
                + self._CHANNEL_WEIGHTS["frequency"] * frq_sim
            )
            # 一致性奖励: 三通道一致->奖励 0.05
            if active_channels >= 3:
                ensemble += 0.05

            results.append(SimilarityResult(
                binary_name=name,
                entropy_similarity=ent_sim,
                betweenness_similarity=bet_sim,
                frequency_similarity=frq_sim,
                ensemble_score=min(1.0, ensemble),
                channels_agree=active_channels,
            ))

        results.sort(key=lambda r: -r.ensemble_score)
        return results[:top_k]

    def remove_binary(self, name: str) -> bool:
        """从数据库中移除一个二进制 (LSH 索引不重建, 仅标记删除)

        LSH 索引的删除代价高, 采用惰性删除: 移除 database 中的条目
        但不重建 LSH 表。查询时会跳过 database 中不存在的 key
        """
        if name in self._database:
            del self._database[name]
            return True
        return False

    @property
    def database_size(self) -> int:
        return len(self._database)

    def list_indexed(self) -> List[str]:
        return sorted(self._database.keys())
