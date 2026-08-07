# Created: 2026-06-22 18:12:11
#
# binary_phylogeny — 零训练多模态二进制遗传谱系重建
# CFG熵 + MREM + 编译器归一化 + TTP 五维距离融合 → Neighbor-Joining 建树
# 区别于 MalTree (ICML'26)/Amalan (TU Delft'24)/Razaulla: 零训练，纯结构度量

import math
from typing import Dict, List, Tuple, Optional, Set


def _cosine_distance(a: List[float], b: List[float]) -> float:
    """1 - cosine_similarity, 范围 [0, 2]。"""
    _dot = sum(x * y for x, y in zip(a, b))
    _na = math.sqrt(sum(x ** 2 for x in a))
    _nb = math.sqrt(sum(y ** 2 for y in b))
    if _na < 1e-9 or _nb < 1e-9:
        return 1.0
    return max(0.0, 1.0 - _dot / (_na * _nb))


def _jaccard_distance(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    _intersection = len(a & b)
    _union = len(a | b)
    return 1.0 - _intersection / _union if _union > 0 else 1.0


def _normalized_euclidean(a: List[float], b: List[float]) -> float:
    """欧氏距离 / sqrt(维度)，范围 [0, 1] (假定分量已归一化)。"""
    if not a:
        return 0.0
    _sq = sum((x - y) ** 2 for x, y in zip(a, b))
    return min(1.0, math.sqrt(_sq / len(a)))


def compute_pairwise_distances(
    samples: Dict[str, Dict],
) -> Tuple[List[str], List[List[float]]]:
    """计算样本集合的融合距离矩阵。

    samples: {sample_id: {fingerprint, mrem, ttp_profile, ...}}
      每个样本字典可含:
      - cfg_fingerprint: compute_cfg_fingerprint() 输出
      - compiler_normalized: compiler_normalizer.normalize_fingerprint() 输出
      - mrem_summary: compute_mrem() 输出中提取的摘要向量
      - ttp_profile: ttp_correlation.correlate_ttps() 输出
      - import_entropy: cfg_entropy_fingerprint.compute_import_topology_entropy() 输出

    返回: (sorted_ids, distance_matrix)
    """
    _ids = sorted(samples.keys())
    _n = len(_ids)
    if _n < 2:
        return (_ids, [[0.0]])

    # 为每个样本提取特征向量
    _features: Dict[str, Dict[str, List[float]]] = {}

    for _sid in _ids:
        _s = samples[_sid]
        _feat: Dict[str, List[float]] = {}

        # CFG fingerprint composite vector (4D)
        _cfg = _s.get("cfg_fingerprint", {})
        _feat["cfg_vec"] = _cfg.get("composite_vector", [0.0, 0.0, 0.0, 0.0])

        # Compiler-normalized vector (4D)
        _cn = _s.get("compiler_normalized", {})
        _feat["norm_vec"] = _cn.get("normalized_vector", _feat["cfg_vec"])

        # MREM summary vector: [mean_entropy, structural_complexity/100, scale_invariant_ratio]
        _mrem = _s.get("mrem_summary", {})
        _mean_ent = sum(_mrem.get("mean_entropy_across_scales", [0.0])) / max(
            len(_mrem.get("mean_entropy_across_scales", [1.0])), 1)
        _complexity = _mrem.get("structural_complexity", 0.0) / 100.0
        _invariant_ratio = len(_mrem.get("scale_invariant_regions", [])) / max(
            _mrem.get("resolution", [1, 1])[1], 1)
        _feat["mrem_vec"] = [round(_mean_ent / 8.0, 4),
                             round(_complexity, 4),
                             round(min(_invariant_ratio, 1.0), 4)]

        # TTP profile: 简化为 kill_chain_completeness + detected_count/10
        _ttp = _s.get("ttp_profile", {})
        _feat["ttp_vec"] = [
            _ttp.get("kill_chain_completeness", 0.0),
            min(_ttp.get("boosted_ttp_count", 0) / 10.0, 1.0),
        ]

        # Import topology: [inter_library_entropy, dangerous_concentration]
        _imp = _s.get("import_entropy", {})
        _feat["import_vec"] = [
            min(_imp.get("inter_library_entropy", 0.0) / 4.0, 1.0),
            _imp.get("dangerous_concentration", 0.0),
        ]

        _features[_sid] = _feat

    # 构建融合距离矩阵
    _dist_matrix = [[0.0] * _n for _ in range(_n)]

    for _i in range(_n):
        for _j in range(_i + 1, _n):
            _fa = _features[_ids[_i]]
            _fb = _features[_ids[_j]]

            _d_cfg = _cosine_distance(_fa["cfg_vec"], _fb["cfg_vec"])
            _d_norm = _cosine_distance(_fa["norm_vec"], _fb["norm_vec"])
            _d_mrem = _normalized_euclidean(_fa["mrem_vec"], _fb["mrem_vec"])
            _d_ttp = _normalized_euclidean(_fa["ttp_vec"], _fb["ttp_vec"])
            _d_imp = _normalized_euclidean(_fa["import_vec"], _fb["import_vec"])

            _d_fused = (
                _d_cfg * 0.30 + _d_norm * 0.25 + _d_mrem * 0.20 +
                _d_ttp * 0.15 + _d_imp * 0.10
            )

            _dist_matrix[_i][_j] = round(_d_fused, 6)
            _dist_matrix[_j][_i] = round(_d_fused, 6)

    return (_ids, _dist_matrix)


def _neighbor_joining(ids, dist_matrix):
    """Neighbor-Joining (Saitou & Nei 1987)。"""
    _n = len(ids)
    if _n <= 1: return {"name": ids[0] if _n == 1 else "root", "children": []}
    if _n == 2:
        d = dist_matrix[0][1]
        return {"name": "node", "distance": round(d,6),
                "children": [{"name": ids[0], "distance": round(d/2,6)},
                             {"name": ids[1], "distance": round(d/2,6)}]}
    _d = [r[:] for r in dist_matrix]
    _labels = list(range(_n))
    _trees = {i: {"name": ids[i], "children": []} for i in range(_n)}
    _next = _n
    while len(_labels) > 2:
        _m = len(_labels)
        _r = [sum(_d[i][j] for j in range(_m) if j != i) / max(_m - 2, 1) for i in range(_m)]
        _mi, _mj, _mq = -1, -1, float("inf")
        for i in range(_m):
            for j in range(i + 1, _m):
                q = _d[i][j] - _r[i] - _r[j]
                if q < _mq: _mq, _mi, _mj = q, i, j
        _di = max(0, _d[_mi][_mj] / 2 + (_r[_mi] - _r[_mj]) / (2 * (_m - 2)))
        _dj = max(0, _d[_mi][_mj] - _di)
        _new = {"name": f"node_{_next}", "distance": round(_d[_mi][_mj],6),
                "children": [{**_trees[_labels[_mi]], "distance": round(_di,6)},
                             {**_trees[_labels[_mj]], "distance": round(_dj,6)}]}
        _new_row = [max(0, (_d[_mi][k] + _d[_mj][k] - _d[_mi][_mj]) / 2)
                    for k in range(_m) if k not in (_mi, _mj)] + [0.0]
        for a in sorted([_mi, _mj], reverse=True):
            for r in _d: r.pop(a)
            _d.pop(a)
        for r in _d: r.append(_new_row[len(_d)])
        _d.append(_new_row)
        _labels = [l for l in _labels if l not in (_labels[_mi], _labels[_mj])] + [_next]
        _trees[_next] = _new; _next += 1
    d = _d[0][1]
    return {"name": "root", "distance": round(d,6),
            "children": [{**_trees[_labels[0]], "distance": round(d/2,6)},
                         {**_trees[_labels[1]], "distance": round(d/2,6)}]}


def _to_newick(node: Dict) -> str:
    """树字典 → Newick 格式字符串。"""
    if not node.get("children"):
        _name = node.get("name", "")
        _dist = node.get("distance", 0.0)
        return f"{_name}:{_dist:.4f}"

    _children = []
    for _c in node["children"]:
        _children.append(_to_newick(_c))

    _name = node.get("name", "")
    _dist = node.get("distance", 0.0)
    return f"({','.join(_children)}){_name}:{_dist:.4f}"


def reconstruct_phylogeny(
    samples: Dict[str, Dict],
    min_samples: int = 3,
) -> Dict:
    """二进制谱系重建主入口。

    samples: {sample_id: {cfg_fingerprint, compiler_normalized, mrem_summary,
                          ttp_profile, import_entropy, metadata}}

    返回:
    - tree: 系统发育树 (字典结构)
    - newick: Newick 格式树字符串
    - distance_matrix: 融合距离矩阵
    - sample_ids: 样本 ID 列表
    - clusters: 基于距离阈值的聚类分组
    - outlier_ids: 与所有其他样本距离均大的离群样本
    """
    if len(samples) < min_samples:
        return {"error": f"need at least {min_samples} samples",
                "sample_count": len(samples)}

    _ids, _dist = compute_pairwise_distances(samples)
    _n = len(_ids)

    if _n < 2:
        return {"error": "need at least 2 samples for phylogeny",
                "sample_count": _n, "sample_ids": _ids}

    # 离群检测: 每个样本与所有其他样本的最小距离 > 2σ → outlier
    _min_dists = []
    for _i in range(_n):
        _min_d = min(_dist[_i][_j] for _j in range(_n) if _j != _i)
        _min_dists.append(_min_d)

    _mean_min = sum(_min_dists) / _n
    _std_min = math.sqrt(sum((d - _mean_min) ** 2 for d in _min_dists) / _n)
    _threshold = _mean_min + 2.0 * _std_min
    _outliers = [_ids[_i] for _i in range(_n) if _min_dists[_i] > _threshold]

    # NJ 建树
    _tree = _neighbor_joining(_ids, _dist)
    _newick = _to_newick(_tree)

    # 简单聚类: 距离 < 0.30 → 同组 (单链接)
    _visited: Set[int] = set()
    _clusters: List[List[str]] = []
    for _i in range(_n):
        if _i in _visited:
            continue
        _group = [_ids[_i]]
        _visited.add(_i)
        for _j in range(_i + 1, _n):
            if _j not in _visited and _dist[_i][_j] < 0.30:
                _group.append(_ids[_j])
                _visited.add(_j)
        _clusters.append(_group)

    return {
        "tree": _tree,
        "newick": _newick,
        "distance_matrix": _dist,
        "sample_ids": _ids,
        "sample_count": _n,
        "clusters": _clusters,
        "cluster_count": len(_clusters),
        "outlier_ids": _outliers,
        "mean_pairwise_distance": round(_mean_min, 6),
        "distance_std": round(_std_min, 6),
    }


def find_closest_relatives(
    target_id: str,
    samples: Dict[str, Dict],
    top_k: int = 5,
) -> Dict:
    """快速最近邻查询：给定目标样本 ID，返回距离最近的 K 个亲属样本。"""
    _ids, _dist = compute_pairwise_distances(samples)

    if target_id not in _ids:
        return {"error": "target_not_found", "target_id": target_id}

    _ti = _ids.index(target_id)
    _ranked = sorted(
        [(_ids[_j], _dist[_ti][_j]) for _j in range(len(_ids)) if _j != _ti],
        key=lambda x: x[1],
    )

    return {
        "target_id": target_id,
        "nearest_relatives": [
            {"sample_id": _sid, "distance": _d}
            for _sid, _d in _ranked[:top_k]
        ],
        "max_distance": round(_ranked[-1][1], 6) if _ranked else 0.0,
    }
