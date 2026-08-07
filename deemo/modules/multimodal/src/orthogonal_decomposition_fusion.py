# 修改记录:
# 2025-08-05 17:52 - 初始实现：基于迭代Gram-Schmidt的模态冗余正交分解融合

"""正交分解融合 — 模态间共享信息与私有信息的正交分离。

核心机制：不同于标准融合将各模态特征直接相加/拼接，
本模块先将每个新模态分解为两部分——
1. 已融合子空间中的投影（共享/冗余分量）
2. 与已融合子空间正交的残差（新颖/私有分量）
仅累加新颖分量，避免维度膨胀和信息冗余。

问题背景：
标准注意力融合和门控融合对所有模态维度平等处理，
导致：两种模态高度相关的维度获得双倍权值，
而独特但微弱的信号被淹没在多模态噪声中。
典型场景：静态分析的脆弱函数列表与动态trace的函数调用频率
共享大量重叠信息——简单的逐元素相加会过拟合这部分信号。

解决方案：
1. 将模态按优先级（可指定或由熵驱动）排为序列。
2. 第1个模态直接入融合空间。
3. 第k个模态：计算其在已融合子空间的Gram-Schmidt投影，
   投影分量 = 与前面模态共享的信息（冗余），
   正交残差 = 该模态独有的信息（新颖）。
4. 仅累加正交残差 → 最终融合维度不因冗余而虚高。

复杂度优势：
- O(N·d·M²) 而非 HSIC 类方法的 O(N²·d)，
  M（模态数）通常 ≤ 5，d ≥ 64，N ≥ 100 时本方案更快。
- 无需核函数选择、无需训练，在线执行。

- Gretton et al. "Measuring Statistical Dependence with HSIC." JMLR 2005.
- Lu et al. "Orthogonal Decomposition for Cross-Modal Re-ID." IEEE TNNLS 2025.
  本实现区别于上述方法：
  (a) 使用迭代Gram-Schmidt替代矩阵分解，O(M²·d) 替代 O(M·d²)
  (b) 保留完整残差向量而非仅保留投影得分，信息损失更少
  (c) 支持在线增量添加模态，无需重训
"""

import math
from typing import Dict, List, Optional, Tuple

_EPS: float = 1e-9

class OrthogonalDecompositionFusion:
    """正交分解融合器——迭代Gram-Schmidt分离共享/私有信息。

    每融合一个模态，将在已积累子空间中的投影分量标记为"冗余"，
    仅将正交残差加入融合表示。残差的L2范数占比即为该模态的"新颖度得分"。

    使用范式：
      odf = OrthogonalDecompositionFusion(dim=128)
      fused, novelty_scores = odf.fuse(
          modal_features={"static": [...], "dynamic": [...], "symbolic": [...]},
          priority_order=["static", "dynamic", "symbolic"],  # 可选
      )
    """

    def __init__(
        self,
        dim: int = 64,
        redundancy_threshold: float = 0.05,
        max_modalities: int = 8,
    ):
        """
        dim: 特征统一维度。
        redundancy_threshold: 残差L2范数占比低于此值的模态视为完全冗余，
                              其信息不会被加入融合空间。
        max_modalities: 最大模态数（影响内存预分配）。
        """
        self.dim = dim
        self.redundancy_threshold = redundancy_threshold
        self.max_modalities = max_modalities

        # 累积的正交基向量集合（用于逐模态Gram-Schmidt投影）
        # 存储格式：基向量的单位向量表示
        self._orthonormal_basis: List[List[float]] = []
        # 每次融合的新颖度历史
        self._novelty_history: List[Dict[str, float]] = []
        # 累积冗余度统计
        self._cumulative_redundancy: Dict[str, float] = {}

    # 公开 API

    def fuse(
        self,
        modal_features: Dict[str, List[List[float]]],
        priority_order: Optional[List[str]] = None,
    ) -> Tuple[List[List[float]], Dict[str, float]]:
        """执行正交分解融合。

        参数：
          modal_features: {name: [N, d_i]}，d_i 会自适应对齐到 self.dim
          priority_order: 模态优先级列表（先处理高优先级模态以保留更多信息）。
                         未指定时按特征L2能量降序自动排列。

        返回：
          (fused_features [N, dim], novelty_scores {name: score})
          fused_features: 去冗余融合特征
          novelty_scores: 各模态的新颖度（0=全冗余，1=完全新颖）
        """
        _names = list(modal_features.keys())
        if not _names:
            return [], {}

        _n = len(modal_features[_names[0]])
        _aligned = self._align_all(modal_features)

        # 清零累积基，每次融合独立
        self._orthonormal_basis.clear()

        if priority_order:
            _order = [n for n in priority_order if n in _aligned]
            _order += [n for n in _names if n not in _order]
        else:
            _order = self._rank_by_energy(_aligned)

        _fused = [[0.0] * self.dim for _ in range(_n)]
        _novelty_scores: Dict[str, float] = {}
        _total_energy_added = 0.0

        for _name in _order:
            _feat = _aligned[_name]
            _feat_energy = self._total_energy(_feat)
            if _feat_energy < _EPS:
                _novelty_scores[_name] = 0.0
                self._cumulative_redundancy[_name] = (
                    self._cumulative_redundancy.get(_name, 0.0) * 0.9 + 1.0 * 0.1
                )
                continue

            # 分解：获得新颖残差
            _novel_residual, _redundancy_ratio = self._decompose(_feat)

            _novelty = 1.0 - _redundancy_ratio
            _novelty_scores[_name] = _novelty

            # 更新累积冗余度（EMA 平滑）
            _prev_red = self._cumulative_redundancy.get(_name, 0.5)
            self._cumulative_redundancy[_name] = (
                _prev_red * 0.8 + _redundancy_ratio * 0.2
            )

            # 仅当新颖度高于门限时才贡献到融合空间
            if _novelty >= self.redundancy_threshold:
                _novel_energy = self._total_energy(_novel_residual)
                # 加权因子：新颖部分能量 / 总能量 × 新颖度
                if _novel_energy > _EPS and _feat_energy > _EPS:
                    _contrib_weight = _novel_energy / _feat_energy
                else:
                    _contrib_weight = _novelty

                for _i in range(_n):
                    for _j in range(self.dim):
                        _fused[_i][_j] += (
                            _contrib_weight * _novel_residual[_i][_j]
                        )
                _total_energy_added += _novel_energy * _contrib_weight

                # 用新颖残差中的基向量扩充正交基
                self._extend_basis(_novel_residual)

        self._novelty_history.append(_novelty_scores)
        if len(self._novelty_history) > 100:
            self._novelty_history = self._novelty_history[-100:]

        return _fused, _novelty_scores

    def get_cumulative_redundancy(self) -> Dict[str, float]:
        """返回各模态的累积冗余度（EMA后）。

        高值 → 该模态在过往融合中的信息大部分与先前模态重叠。
        可用于决定是否从管线中移除某个冗余模态以节省计算。
        """
        return dict(self._cumulative_redundancy)

    def get_novelty_trend(self, modal_name: str, window: int = 10) -> Optional[float]:
        """检测某模态新颖度的变化趋势。

        返回最近 window 次融合的新颖度线性回归斜率。
        负斜率 → 该模态的信息正逐渐与其他模态重叠（可能因模型收敛）。
        历史不足时返回 None。
        """
        _vals = [
            h.get(modal_name, 0.0)
            for h in self._novelty_history[-window:]
        ]
        if len(_vals) < 2:
            return None

        _n = len(_vals)
        _mean_x = (_n - 1) / 2.0
        _mean_y = sum(_vals) / _n
        _num = sum((i - _mean_x) * (_vals[i] - _mean_y) for i in range(_n))
        _den = sum((i - _mean_x) ** 2 for i in range(_n))
        return _num / max(_den, _EPS) if abs(_den) > _EPS else 0.0

    # 内部方法

    def _decompose(
        self, features: List[List[float]]
    ) -> Tuple[List[List[float]], float]:
        """将特征矩阵分解为正交基投影 + 正交残差。

        返回：(残差矩阵 [N, dim], 冗余比率 ∈ [0,1])。
        若尚无基向量，特征本身即为残差，冗余度 = 0。
        """
        _n = len(features)
        _d = len(features[0]) if features else self.dim

        if not self._orthonormal_basis:
            return [_row[:] for _row in features], 0.0

        # 逐样本计算投影分量与残差
        _residual = [[0.0] * _d for _ in range(_n)]
        _total_orig_energy = 0.0
        _total_proj_energy = 0.0

        for _i in range(_n):
            _row = features[_i]
            _orig_norm_sq = sum(v * v for v in _row)
            _total_orig_energy += _orig_norm_sq

            # 在正交基上的投影坐标
            _proj_coords = [0.0] * len(self._orthonormal_basis)
            for _k, _basis_vec in enumerate(self._orthonormal_basis):
                _dot = sum(
                    _row[_j] * _basis_vec[_j]
                    for _j in range(min(_d, len(_basis_vec)))
                )
                _proj_coords[_k] = _dot

            _proj_norm_sq = sum(c * c for c in _proj_coords)
            _total_proj_energy += _proj_norm_sq

            # 残差 = 原始 - 投影重构
            for _j in range(_d):
                _proj_val = sum(
                    _proj_coords[_k] * self._orthonormal_basis[_k][_j]
                    for _k in range(len(self._orthonormal_basis))
                    if _j < len(self._orthonormal_basis[_k])
                )
                _residual[_i][_j] = _row[_j] - _proj_val

        _redundancy = (
            _total_proj_energy / max(_total_orig_energy, _EPS)
            if _total_orig_energy > _EPS
            else 1.0
        )
        # 钳制在 [0, 1]
        _redundancy = min(max(_redundancy, 0.0), 1.0)
        return _residual, _redundancy

    def _extend_basis(self, residual: List[List[float]]):
        """从残差矩阵提取主方向并正交化后加入基向量集。

        取 L2 范数最大的样本残差作为新基向量的候选方向，
        对其做 Gram-Schmidt 正交化（相对于已有基），归一化后加入。
        限制基数量 ≤ dim 且 ≤ 2 * max_modalities 防溢出。
        """
        _d = len(residual[0]) if residual else 0
        if _d == 0:
            return

        _max_basis = min(self.dim, 2 * self.max_modalities)
        if len(self._orthonormal_basis) >= _max_basis:
            # 基集已满：替换范数最小的基
            _norms = [
                math.sqrt(sum(v * v for v in bv))
                for bv in self._orthonormal_basis
            ]
            _min_idx = _norms.index(min(_norms))
        else:
            _min_idx = -1

        # 选 L2 范数最大的样本残差作为新基方向
        _best_idx = max(
            range(len(residual)),
            key=lambda i: sum(v * v for v in residual[i]),
        )
        _candidate = residual[_best_idx][:]

        # Gram-Schmidt 正交化
        for _basis_vec in self._orthonormal_basis:
            _dot = sum(
                _candidate[_j] * _basis_vec[_j]
                for _j in range(min(_d, len(_basis_vec)))
            )
            for _j in range(_d):
                _candidate[_j] -= _dot * (_basis_vec[_j] if _j < len(_basis_vec) else 0.0)

        # 归一化
        _norm = math.sqrt(sum(v * v for v in _candidate))
        if _norm > _EPS:
            _unit = [v / _norm for v in _candidate]
            if _min_idx >= 0:
                self._orthonormal_basis[_min_idx] = _unit
            else:
                self._orthonormal_basis.append(_unit)

    def _align_all(
        self, modal_features: Dict[str, List[List[float]]]
    ) -> Dict[str, List[List[float]]]:
        """将所有模态特征维度对齐到 self.dim。

        不足补零，溢出截断。
        """
        _aligned: Dict[str, List[List[float]]] = {}
        for _name, _feat in modal_features.items():
            if not _feat or not _feat[0]:
                _n = len(_feat) if _feat else 0
                _aligned[_name] = (
                    [[0.0] * self.dim for _ in range(_n)] if _n > 0 else []
                )
                continue
            _n = len(_feat)
            _d = len(_feat[0])
            if _d == self.dim:
                _aligned[_name] = _feat
                continue
            _out = [[0.0] * self.dim for _ in range(_n)]
            _copy_dim = min(_d, self.dim)
            for _i in range(_n):
                for _j in range(_copy_dim):
                    _out[_i][_j] = _feat[_i][_j]
            _aligned[_name] = _out
        return _aligned

    @staticmethod
    def _rank_by_energy(
        aligned: Dict[str, List[List[float]]]
    ) -> List[str]:
        """按特征 L2 总能量降序排列模态。

        能量高 → 信息量大 → 优先进入融合空间，做后续模态的基底。
        """
        _energies: List[Tuple[str, float]] = []
        for _name, _feat in aligned.items():
            _energy = OrthogonalDecompositionFusion._total_energy(_feat)
            _energies.append((_name, _energy))
        _energies.sort(key=lambda x: x[1], reverse=True)
        return [e[0] for e in _energies]

    @staticmethod
    def _total_energy(features: List[List[float]]) -> float:
        """特征矩阵的 Frobenius 范数平方。"""
        if not features:
            return 0.0
        return sum(sum(v * v for v in row) for row in features)

def orthogonal_decompose_fuse(
    modal_features: Dict[str, List[List[float]]],
    dim: int = 64,
    priority_order: Optional[List[str]] = None,
) -> Tuple[List[List[float]], Dict[str, float]]:
    """正交分解融合的便捷函数接口。"""
    _odf = OrthogonalDecompositionFusion(dim=dim)
    return _odf.fuse(modal_features, priority_order=priority_order)

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _dim = 32
    _n = 20

    # 模态A 与 模态B 高度相关（模拟静态与动态分析的结果重叠）
    _modal_a = [[math.sin(i * 0.1 + j * 0.3) for j in range(_dim)] for i in range(_n)]
    _modal_b = [[math.sin(i * 0.1 + j * 0.3 + 0.05) + random.gauss(0, 0.02)
                 for j in range(_dim)] for i in range(_n)]
    # 模态C 加载独立信号
    _modal_c = [[math.cos(i * 0.25 + j * 0.15) for j in range(_dim)] for i in range(_n)]

    _odf = OrthogonalDecompositionFusion(dim=_dim)
    _modals = {"static": _modal_a, "dynamic": _modal_b, "symbolic": _modal_c}
    _fused, _novelty = _odf.fuse(_modals)

    print(f"[ortho_fuse] novelty scores: {[(n, round(s, 4)) for n, s in _novelty.items()]}")
    # 第一个被处理的模态（按能量排序）新颖度应为 1.0
    _first_modal = max(_novelty, key=_novelty.get)
    assert _novelty.get(_first_modal, 0.0) > 0.99, (
        f"first processed modal should have novelty ~1.0, got {_novelty.get(_first_modal)}"
    )
    # B 与 A 高度类似，如果 B 不是第一个处理，其新颖度应显著低于 A 的
    _non_first = [n for n in _novelty if n != _first_modal]
    if _non_first:
        assert any(_novelty[n] < 0.8 for n in _non_first), (
            f"at least one non-first modal should show reduced novelty, got {_novelty}"
        )
    assert len(_fused) == _n and len(_fused[0]) == _dim, "output dim mismatch"

    # 累积冗余度
    _cum_red = _odf.get_cumulative_redundancy()
    print(f"[ortho_fuse] cumulative redundancy: {[(n, round(r, 4)) for n, r in _cum_red.items()]}")

    # 新颖度趋势（初轮仅1次记录 → None）
    _trend = _odf.get_novelty_trend("dynamic", window=5)
    print(f"[ortho_fuse] novelty trend (dynamic): {_trend}")

    print("[OK] OrthogonalDecompositionFusion smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
