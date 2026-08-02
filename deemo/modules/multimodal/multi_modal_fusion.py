# 2026-07-30
# 多模态融合策略 — 早期/中期/晚期/门控/张量/双线性融合
# 参考：Zadeh et al. Tensor Fusion Network (EMNLP 2017)
#       Arevalo et al. Gated Multimodal Units (ICLR 2017)
#       Kim et al. Bilinear Attention Networks (NeurIPS 2018)
#       Nagrani et al. Multimodal Bottleneck Transformer (NeurIPS 2021)

import math
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict

_EPS: float = 1e-9


# ============================================================================
# 早期融合 — 原始特征直接拼接，最简形式
# 优点：保留全部信息；缺点：维度爆炸，低层语义差异被忽略
# ============================================================================

def early_fusion(modalities: Dict[str, List[List[float]]]) -> List[List[float]]:
    """直接拼接所有模态的特征向量（特征维度方向）。

    要求所有模态的样本数一致（batch size 对齐）。
    输出维度 = Σ d_m，对大模态组合维度很高。
    """
    _names = list(modalities.keys())
    if not _names:
        return []
    _n = len(modalities[_names[0]])
    _total_dim = sum(len(m[_names[0]][0]) for m in [modalities])
    # 直接拼接
    _fused = [[0.0] * _total_dim for _ in range(_n)]
    _col = 0
    for _name in _names:
        _feat = modalities[_name]
        _d = len(_feat[0]) if _feat else 0
        for _i in range(_n):
            for _j in range(_d):
                _fused[_i][_col + _j] = _feat[_i][_j]
        _col += _d
    return _fused


# ============================================================================
# 晚期融合 — 各模态独立编码后融合（平均/拼接/最大值）
# 假定输入已经是各模态的高层特征
# ============================================================================

def late_fusion_avg(modalities: Dict[str, List[List[float]]]) -> List[List[float]]:
    """对各模态特征逐元素平均融合。

    要求所有模态特征维度相同。
    对噪声模态具有天然鲁棒性（平均值平滑异常）。
    """
    _names = list(modalities.keys())
    if not _names:
        return []
    _n = len(modalities[_names[0]])
    _d = len(modalities[_names[0]][0])
    _fused = [[0.0] * _d for _ in range(_n)]
    for _name in _names:
        _feat = modalities[_name]
        for _i in range(_n):
            for _j in range(min(_d, len(_feat[_i]))):
                _fused[_i][_j] += _feat[_i][_j]
    _inv = 1.0 / len(_names)
    for _i in range(_n):
        for _j in range(_d):
            _fused[_i][_j] *= _inv
    return _fused


def late_fusion_max(modalities: Dict[str, List[List[float]]]) -> List[List[float]]:
    """逐元素最大值融合——信号增强，适合互补模态。"""
    _names = list(modalities.keys())
    if not _names:
        return []
    _n = len(modalities[_names[0]])
    _d = len(modalities[_names[0]][0])
    _fused = [[-1e9] * _d for _ in range(_n)]
    for _name in _names:
        _feat = modalities[_name]
        for _i in range(_n):
            for _j in range(min(_d, len(_feat[_i]))):
                if _feat[_i][_j] > _fused[_i][_j]:
                    _fused[_i][_j] = _feat[_i][_j]
    return _fused


# ============================================================================
# 门控多模态单元 (GMU) — 学习每模态的门控权重
# 参考：Arevalo et al. Gated Multimodal Units. ICLR 2017 workshop.
# 核心：gate = σ(W_g · [h_1; ...; h_m])，输出 = Σ gate_i · h_i
# ============================================================================

class GatedMultimodalUnit:
    """门控多模态融合：每个模态学习一个标量门控权重。

    门控向量通过全连接层 + sigmoid 激活生成，
    各模态特征按其对应门控值加权求和。
    适合模态质量不均匀的场景（如噪声图像+清晰文本）。
    """

    def __init__(self, total_dim: int, n_modalities: int):
        self.total_dim = total_dim
        self.n_modalities = n_modalities
        # 门控权重矩阵：total_dim × n_modalities
        self._Wg: List[List[float]] = [
            [(math.sin((i * 1.73 + j * 0.91)) - 0.5) * 0.2
             for j in range(n_modalities)]
            for i in range(total_dim)
        ]

    def _sigmoid(self, x: float) -> float:
        return 1.0 / (1.0 + math.exp(-min(max(x, -20), 20)))

    def forward(self, modality_features: List[List[float]],
                modality_dim: int) -> Tuple[List[List[float]], List[List[float]]]:
        """前向：计算门控 → 加权融合。

        返回：(融合特征 [N, d], 门控权重 [N, n_modalities])
        门控权重可审计——观察每步哪些模态被信任。
        """
        _N = len(modality_features[0])
        _M = len(modality_features)

        # 拼接 → (N, total_dim)
        _concat = [[0.0] * self.total_dim for _ in range(_N)]
        _col = 0
        _mod_starts: List[int] = []
        for _m in range(_M):
            _mod_starts.append(_col)
            _feat = modality_features[_m]
            _fd = len(_feat[0]) if _feat else 0
            for _i in range(_N):
                for _j in range(_fd):
                    _concat[_i][_col + _j] = _feat[_i][_j]
            _col += _fd

        # 门控计算
        _gates = [[0.0] * _M for _ in range(_N)]
        for _i in range(_N):
            _gate_logits = [0.0] * _M
            for _j in range(self.total_dim):
                _ci = _concat[_i][_j]
                for _m in range(_M):
                    _gate_logits[_m] += _ci * self._Wg[_j][_m]
            _gate_sum = 0.0
            for _m in range(_M):
                _gates[_i][_m] = self._sigmoid(_gate_logits[_m])
                _gate_sum += _gates[_i][_m]
            # 归一化门控权重
            if _gate_sum > _EPS:
                for _m in range(_M):
                    _gates[_i][_m] /= _gate_sum

        # 加权融合
        _fused = [[0.0] * modality_dim for _ in range(_N)]
        for _m in range(_M):
            _feat = modality_features[_m]
            for _i in range(_N):
                _gate = _gates[_i][_m]
                for _j in range(min(modality_dim, len(_feat[_i]))):
                    _fused[_i][_j] += _gate * _feat[_i][_j]

        return _fused, _gates


# ============================================================================
# 张量融合 — 外积捕获多模态间的乘法交互
# 参考：Zadeh et al. Tensor Fusion Network. EMNLP 2017.
# 显式建模任意阶的多模态交互 (singleton, pairwise, triplet, ...)
# ============================================================================

def tensor_fusion_outer(modality_features: List[List[List[float]]]
                        ) -> List[List[float]]:
    """张量外积融合。维度指数增长——仅适用于小维度+少模态。"""
    if not modality_features:
        return []

    _N = len(modality_features[0])
    _M = len(modality_features)
    _dims = [len(mf[0]) if mf else 0 for mf in modality_features]

    _flat_dim = 1
    for _d in _dims:
        _flat_dim *= _d

    _fused: List[List[float]] = []
    for _n in range(_N):
        _tensor = [modality_features[0][_n][:]]
        for _m in range(1, _M):
            _prev = _tensor
            _cur = modality_features[_m][_n]
            _tensor = [[0.0] * (len(_prev[0]) * len(_cur))
                       for _ in range(len(_prev))]
            _flat_prev = _prev[0] if _prev else []
            _flat_new = [0.0] * (len(_flat_prev) * len(_cur))
            _idx = 0
            for _pv in _flat_prev:
                for _cv in _cur:
                    _flat_new[_idx] = _pv * _cv
                    _idx += 1
            _tensor = [_flat_new]
        _fused.append(_tensor[0])

    return _fused


# ============================================================================
# 双线性池化 — 低秩双线性交互，比完整外积更参数高效
# 参考：Kim et al. Bilinear Attention Networks. NeurIPS 2018.
# 使用两个低秩投影矩阵替代完整双线性形式: W ≈ U·V^T
# ============================================================================

class LowRankBilinearFusion:
    """低秩双线性融合：对两个模态应用低秩双线性交互。

    h = P^T · (U^T·x ⊙ V^T·y) + b
    其中 U、V 是降维投影矩阵，⊙ 是逐元素乘。
    rank_factor 控制低秩近似的阶数——越低参数越少但有损。
    """

    def __init__(self, dim_a: int, dim_b: int, output_dim: int,
                 rank_factor: int = 8):
        self.dim_a = dim_a
        self.dim_b = dim_b
        self.output_dim = output_dim
        self.rank = rank_factor

        # 投影矩阵
        self._U: List[List[float]] = [
            [(math.sin((i * 1.73 + j * 0.67)) - 0.5) * math.sqrt(2.0 / dim_a)
             for j in range(rank_factor)] for i in range(dim_a)]
        self._V: List[List[float]] = [
            [(math.sin((i * 0.91 + j * 1.13)) - 0.5) * math.sqrt(2.0 / dim_b)
             for j in range(rank_factor)] for i in range(dim_b)]
        self._P: List[List[float]] = [
            [(math.sin((i * 0.53 + j * 1.37)) - 0.5) * math.sqrt(2.0 / rank_factor)
             for j in range(output_dim)] for i in range(rank_factor)]

    def forward(self, x_a: List[List[float]], x_b: List[List[float]]
                ) -> List[List[float]]:
        """前向双线性融合。"""
        _N = len(x_a)
        _out: List[List[float]] = [[0.0] * self.output_dim for _ in range(_N)]

        for _n in range(_N):
            # U^T · x_a
            _a_proj = [0.0] * self.rank
            for _r in range(self.rank):
                _acc = 0.0
                for _i in range(min(len(x_a[_n]), self.dim_a)):
                    _acc += x_a[_n][_i] * self._U[_i][_r]
                _a_proj[_r] = _acc

            # V^T · x_b
            _b_proj = [0.0] * self.rank
            for _r in range(self.rank):
                _acc = 0.0
                for _j in range(min(len(x_b[_n]), self.dim_b)):
                    _acc += x_b[_n][_j] * self._V[_j][_r]
                _b_proj[_r] = _acc

            # Hadamard product: a_proj ⊙ b_proj
            _hadamard = [_a_proj[_r] * _b_proj[_r] for _r in range(self.rank)]

            # P^T · hadamard
            for _o in range(self.output_dim):
                _val = 0.0
                for _r in range(self.rank):
                    _val += _hadamard[_r] * self._P[_r][_o]
                _out[_n][_o] = _val

        return _out


# ============================================================================
# 多模态Transformer融合 — 使用交叉注意力迭代融合 (MBT风格)
# 参考：Nagrani et al. Attention Bottlenecks for Multimodal Fusion. NeurIPS 2021.
# 核心思想：用少量瓶颈token在各模态间传递信息，避免 O(M²) 注意力
# ============================================================================

class BottleneckFusionTransformer:
    """瓶颈注意力融合：固定数量的可学习瓶颈令牌在各模态间汇聚信息。

    流程：模态A→瓶颈←模态B，瓶颈 token 在各模态间迭代更新。
    num_bottleneck_tokens 通常远小于序列长度（如4-16个），
    使计算复杂度从 O(N²·M²) 降至 O(N·B·M)。
    """

    def __init__(self, dim: int = 64, num_bottleneck_tokens: int = 8):
        self.dim = dim
        self.num_btokens = num_bottleneck_tokens
        # 可学习瓶颈令牌：正弦初始化
        self._bottleneck_tokens: List[List[float]] = [
            [math.sin((b * 2.37 + d * 0.73)) * 0.1
             for d in range(dim)]
            for b in range(num_bottleneck_tokens)
        ]

    def forward(self, modality_features: Dict[str, List[List[float]]]
                ) -> List[List[float]]:
        """瓶颈注意力融合：瓶颈令牌顺序关注各模态特征。

        每个模态：瓶颈token作为Q，模块特征作为K/V → 更新瓶颈token。
        所有模态处理后，瓶颈token聚合 → 最终融合表示。
        """
        _bottleneck = [_row[:] for _row in self._bottleneck_tokens]
        _d = self.dim
        _B = self.num_btokens

        for _mod_name, _feat in modality_features.items():
            _N = len(_feat)
            if _N == 0:
                continue
            _fd = len(_feat[0])
            _limit = min(_fd, _d)

            # 瓶颈 → 模态：Q=bottleneck, K/V=modality_feat
            # 简化注意力：softmax(Q·K^T/√d)·V
            _scale = 1.0 / math.sqrt(max(_limit, 1))
            _updated_bt = [[0.0] * _d for _ in range(_B)]

            for _b in range(_B):
                _attn_scores = [0.0] * _N
                for _n in range(_N):
                    _dot = sum(_bottleneck[_b][_j] * _feat[_n][_j]
                             for _j in range(_limit))
                    _attn_scores[_n] = _dot * _scale

                # softmax
                _mx = max(_attn_scores)
                _exps = [math.exp(_s - _mx) for _s in _attn_scores]
                _sum_exp = sum(_exps) + _EPS
                _attn_w = [_e / _sum_exp for _e in _exps]

                # 加权聚合
                for _j in range(_limit):
                    _acc = 0.0
                    for _n in range(_N):
                        if _j < len(_feat[_n]):
                            _acc += _attn_w[_n] * _feat[_n][_j]
                    _updated_bt[_b][_j] = _acc

            # 残差更新瓶颈
            for _b in range(_B):
                for _j in range(_d):
                    _bottleneck[_b][_j] = 0.5 * _bottleneck[_b][_j] + 0.5 * _updated_bt[_b][_j]

        # 瓶颈聚合 → 最终表示 (B, d) → (d,)
        _fused = [0.0] * _d
        for _b in range(_B):
            for _j in range(_d):
                _fused[_j] += _bottleneck[_b][_j] / _B

        return _bottleneck


# ============================================================================
# 动态融合 — 根据输入自适应选择融合策略
# 参考：Hu et al. Dynamic Fusion with Intra- and Inter-modality Attention (2022)
# 对简单输入使用均值融合，对复杂输入使用门控/双线性融合
# ============================================================================

def adaptive_fusion(modalities: Dict[str, List[List[float]]],
                    method: str = 'auto') -> List[List[float]]:
    """自适应融合策略选择。

    auto模式：基于模态间的特征差异自动选择融合方式。
    差异小（cos_sim > 0.7）→ 晚期均值融合（各模态一致，无需复杂交互）
    差异中 → 门控融合
    差异大（cos_sim < 0.3）→ 双线性融合（需捕获复杂跨模态交互）
    """
    _names = list(modalities.keys())
    if len(_names) < 2:
        return modalities.get(_names[0], []) if _names else []

    if method != 'auto':
        if method == 'early':
            return early_fusion(modalities)
        elif method == 'avg':
            return late_fusion_avg(modalities)
        elif method == 'max':
            return late_fusion_max(modalities)
        return late_fusion_avg(modalities)

    # auto: 计算模态间平均余弦相似度
    _cos_sims: List[float] = []
    for _i in range(len(_names)):
        for _j in range(_i + 1, len(_names)):
            _a = modalities[_names[_i]]
            _b = modalities[_names[_j]]
            _N = min(len(_a), len(_b))
            if _N == 0:
                continue
            _batch_sim = 0.0
            for _n in range(_N):
                _dot = sum(_a[_n][_k] * _b[_n][_k] for _k in range(
                    min(len(_a[_n]), len(_b[_n]))))
                _na = math.sqrt(sum(x * x for x in _a[_n])) + _EPS
                _nb = math.sqrt(sum(x * x for x in _b[_n])) + _EPS
                _batch_sim += _dot / (_na * _nb)
            _cos_sims.append(_batch_sim / _N)

    _avg_sim = sum(_cos_sims) / len(_cos_sims) if _cos_sims else 0.5

    if _avg_sim > 0.7:
        return late_fusion_avg(modalities)
    elif _avg_sim > 0.3:
        # 门控融合
        _feat_list = [modalities[n] for n in _names]
        _d = min(len(f[0]) for f in _feat_list if f)
        _total_d = sum(len(f[0]) for f in _feat_list if f)
        _gmu = GatedMultimodalUnit(total_dim=_total_d, n_modalities=len(_names))
        _fused, _ = _gmu.forward(_feat_list, _d)
        return _fused
    else:
        return late_fusion_max(modalities)


# ============================================================================
# 模态重要性评估 — 基于消融的模态贡献度评分
# ============================================================================

def modality_ablation_scores(modalities: Dict[str, List[List[float]]],
                              labels: List[int],
                              eval_fn) -> Dict[str, float]:
    """逐模态消融：评估每个模态对下游任务的边际贡献。

    每次移除一个模态，计算性能下降幅度。
    贡献度 = (full_fusion_score - ablated_score) / full_fusion_score。
    正分 = 该模态有正向贡献；负分 = 该模态可能含噪或冗余。
    """
    _full = eval_fn(modalities, labels)
    _scores: Dict[str, float] = {}
    for _rm in modalities:
        _ablated = {k: v for k, v in modalities.items() if k != _rm}
        if len(_ablated) < 1:
            _scores[_rm] = 0.0
            continue
        _abl_score = eval_fn(_ablated, labels)
        _scores[_rm] = round((_full - _abl_score) / max(1e-6, _full), 4)
    return _scores


__all__ = [
    "early_fusion", "late_fusion_avg", "late_fusion_max",
    "tensor_fusion_outer", "adaptive_fusion",
    "GatedMultimodalUnit", "LowRankBilinearFusion",
    "BottleneckFusionTransformer",
    "modality_ablation_scores",
]
