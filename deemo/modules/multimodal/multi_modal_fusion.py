# 多模态融合策略集：早期/晚期/门控/张量外积/低秩双线性/瓶颈注意力
# Zadeh et al. Tensor Fusion Network. EMNLP 2017.
#       Arevalo et al. Gated Multimodal Units. ICLR 2017.
#       Kim et al. Bilinear Attention Networks. NeurIPS 2018.
#       Nagrani et al. Multimodal Bottleneck Transformer. NeurIPS 2021.

import math
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict

_EPS: float = 1e-9


# 早期融合 — 原始特征向量沿维度轴直接拼接
# 优点：信息零损失；缺点：维度线性膨胀，忽略各模态低层语义差异

def early_fusion(modalities: Dict[str, List[List[float]]]) -> List[List[float]]:
    """将所有模态特征沿特征维度直接拼接。

    各模态必须具有相同的样本数（batch size 对齐）。
    输出维度 = Σ d_m，多模态组合下维度膨胀显著。
    """
    _names = list(modalities.keys())
    if not _names:
        return []
    _n = len(modalities[_names[0]])
    # 原先 sum(...for m in [modalities]) 仅迭代一次，只累加了首个模态的维度，
    # 现已修正为遍历所有模态名。
    _total_dim = sum(len(modalities[name][0]) for name in _names if modalities.get(name))
    # 逐模态逐样本拼接
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


# 晚期融合 — 各模态独立处理后融合，输入已是高层特征表示
# 支持逐元素平均和逐元素最大值两种聚合策略

def late_fusion_avg(modalities: Dict[str, List[List[float]]]) -> List[List[float]]:
    """逐元素平均融合。

    要求所有模态的特征维度一致。
    对含噪模态天然鲁棒：均值运算自动平滑异常分量。
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
    """逐元素最大值融合——适合互补模态场景，强调每个维度的最强信号。"""
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


# 门控多模态单元 (GMU) — 每个模态学习标量门控权值
# Arevalo et al. Gated Multimodal Units. ICLR 2017 workshop.
# 门控向量 = σ(W_g · [h_1; ...; h_m])，输出 = Σ gate_i · h_i

class GatedMultimodalUnit:
    """门控多模态融合：通过可学习门控决定各模态贡献比例。

    门控权重经全连接层 + sigmoid 生成，随后归一化。
    各模态特征按对应门控值加权求和，适合模态质量不均匀的输入场景。
    """

    def __init__(self, total_dim: int, n_modalities: int):
        self.total_dim = total_dim
        self.n_modalities = n_modalities
        # 门控投影矩阵：total_dim × n_modalities，正弦初始化
        self._Wg: List[List[float]] = [
            [(math.sin((i * 1.73 + j * 0.91)) - 0.5) * 0.2
             for j in range(n_modalities)]
            for i in range(total_dim)
        ]

    def _sigmoid(self, x: float) -> float:
        return 1.0 / (1.0 + math.exp(-min(max(x, -20), 20)))

    def forward(self, modality_features: List[List[float]],
                modality_dim: int) -> Tuple[List[List[float]], List[List[float]]]:
        """前向传播：门控计算 → 加权融合。

        返回：(融合特征 [N, d], 门控权重矩阵 [N, n_modalities])
        门控权重支持审计，用于观察各步哪些模态被赋予更高信任。
        """
        _N = len(modality_features[0])
        _M = len(modality_features)

        # 拼接所有模态 → (N, total_dim)
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

        # 门控计算：concat × W_g → sigmoid → 归一化
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
            # 归一化确保各样本门控和为 1
            if _gate_sum > _EPS:
                for _m in range(_M):
                    _gates[_i][_m] /= _gate_sum

        # 按门控加权融合
        _fused = [[0.0] * modality_dim for _ in range(_N)]
        for _m in range(_M):
            _feat = modality_features[_m]
            for _i in range(_N):
                _gate = _gates[_i][_m]
                for _j in range(min(modality_dim, len(_feat[_i]))):
                    _fused[_i][_j] += _gate * _feat[_i][_j]

        return _fused, _gates


# 张量外积融合 — 多模态间的高阶乘法交互
# Zadeh et al. Tensor Fusion Network. EMNLP 2017.
# 显式建模单模态、二阶成对、三阶三元组…任意阶交互

def tensor_fusion_outer(modality_features: List[List[List[float]]]
                        ) -> List[List[float]]:
    """张量外积融合。维度按模态数指数增长——仅适用小维度、少模态配置。"""
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


# 低秩双线性融合 — 用两个低秩投影矩阵近似完整双线性形
# Kim et al. Bilinear Attention Networks. NeurIPS 2018.
# 分解形式：W ≈ U·V^T，参数低于完整外积

class LowRankBilinearFusion:
    """低秩双线性融合：在两个模态间施加低秩双线性交互。

    h = P^T · (U^T·x ⊙ V^T·y) + b
    U、V 为降维投影矩阵，⊙ 为逐元素 Hadamard 乘积。
    rank_factor 控制近似的秩：值越低参数越少但信息损失越大。
    """

    def __init__(self, dim_a: int, dim_b: int, output_dim: int,
                 rank_factor: int = 8):
        self.dim_a = dim_a
        self.dim_b = dim_b
        self.output_dim = output_dim
        self.rank = rank_factor

        # 低秩投影矩阵（正弦初始化）
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
        """前向双线性融合：投影 → Hadamard 交互 → 输出投影。"""
        _N = len(x_a)
        _out: List[List[float]] = [[0.0] * self.output_dim for _ in range(_N)]

        for _n in range(_N):
            # U^T · x_a：模态 A 降维投影
            _a_proj = [0.0] * self.rank
            for _r in range(self.rank):
                _acc = 0.0
                for _i in range(min(len(x_a[_n]), self.dim_a)):
                    _acc += x_a[_n][_i] * self._U[_i][_r]
                _a_proj[_r] = _acc

            # V^T · x_b：模态 B 降维投影
            _b_proj = [0.0] * self.rank
            for _r in range(self.rank):
                _acc = 0.0
                for _j in range(min(len(x_b[_n]), self.dim_b)):
                    _acc += x_b[_n][_j] * self._V[_j][_r]
                _b_proj[_r] = _acc

            # Hadamard 乘积：a_proj ⊙ b_proj
            _hadamard = [_a_proj[_r] * _b_proj[_r] for _r in range(self.rank)]

            # P^T · hadamard：输出投影
            for _o in range(self.output_dim):
                _val = 0.0
                for _r in range(self.rank):
                    _val += _hadamard[_r] * self._P[_r][_o]
                _out[_n][_o] = _val

        return _out


# 瓶颈注意力融合 (MBT) — 少量瓶颈令牌在模态间传递信息
# Nagrani et al. Attention Bottlenecks for Multimodal Fusion. NeurIPS 2021.
# 用固定数量可学习瓶颈令牌汇聚各模态信息，避免 O(M²) 全对注意力

class BottleneckFusionTransformer:
    """瓶颈注意力融合：固定数量可学习瓶颈令牌在各模态间迭代汇聚。

    流程：模态A → 瓶颈 ← 模态B，瓶颈令牌在各模态间顺序更新。
    num_bottleneck_tokens 远小于序列长度（典型 4-16 个），
    使复杂度从 O(N²·M²) 压缩至 O(N·B·M)。
    """

    def __init__(self, dim: int = 64, num_bottleneck_tokens: int = 8):
        self.dim = dim
        self.num_btokens = num_bottleneck_tokens
        # 可学习瓶颈令牌：正弦初始化，空间均匀分布
        self._bottleneck_tokens: List[List[float]] = [
            [math.sin((b * 2.37 + d * 0.73)) * 0.1
             for d in range(dim)]
            for b in range(num_bottleneck_tokens)
        ]

    def forward(self, modality_features: Dict[str, List[List[float]]]
                ) -> List[List[float]]:
        """瓶颈注意力融合：瓶颈令牌依次关注各模态特征。

        每个模态：瓶颈作为 Q，模态特征作为 K/V → 更新瓶颈表示。
        遍历所有模态后，瓶颈聚合为最终融合特征。
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
            # 缩放点积注意力：softmax(Q·K^T/√d)·V
            _scale = 1.0 / math.sqrt(max(_limit, 1))
            _updated_bt = [[0.0] * _d for _ in range(_B)]

            for _b in range(_B):
                _attn_scores = [0.0] * _N
                for _n in range(_N):
                    _dot = sum(_bottleneck[_b][_j] * _feat[_n][_j]
                             for _j in range(_limit))
                    _attn_scores[_n] = _dot * _scale

                # 标准 softmax 归一化
                _mx = max(_attn_scores)
                _exps = [math.exp(_s - _mx) for _s in _attn_scores]
                _sum_exp = sum(_exps) + _EPS
                _attn_w = [_e / _sum_exp for _e in _exps]

                # 注意力加权聚合
                for _j in range(_limit):
                    _acc = 0.0
                    for _n in range(_N):
                        if _j < len(_feat[_n]):
                            _acc += _attn_w[_n] * _feat[_n][_j]
                    _updated_bt[_b][_j] = _acc

            # 残差连接更新瓶颈令牌
            for _b in range(_B):
                for _j in range(_d):
                    _bottleneck[_b][_j] = 0.5 * _bottleneck[_b][_j] + 0.5 * _updated_bt[_b][_j]

        # 瓶颈聚合 → 单向量输出 (B, d) → (d,)
        _fused = [0.0] * _d
        for _b in range(_B):
            for _j in range(_d):
                _fused[_j] += _bottleneck[_b][_j] / _B

        return _bottleneck


# 自适应融合策略选择 — 基于模态间相似度自动路由
# Hu et al. Dynamic Fusion with Intra- and Inter-modality Attention. 2022.
# 简单输入→均值融合，中等差异→门控融合，显著差异→双线性/最大值融合

def adaptive_fusion(modalities: Dict[str, List[List[float]]],
                    method: str = 'auto') -> List[List[float]]:
    """基于模态间余弦相似度自动选择融合策略。

    auto 路由逻辑：
    相似度 > 0.7 → 晚期均值（模态高度一致，简单融合即够）
    0.3 < 相似度 ≤ 0.7 → 门控融合（中等差异，需自适应加权）
    相似度 ≤ 0.3 → 最大值融合（差异大，需捕获复杂跨模态关系）
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

    # auto：计算所有模态对的平均余弦相似度
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
        # 中等差异：门控融合
        _feat_list = [modalities[n] for n in _names]
        _d = min(len(f[0]) for f in _feat_list if f)
        _total_d = sum(len(f[0]) for f in _feat_list if f)
        _gmu = GatedMultimodalUnit(total_dim=_total_d, n_modalities=len(_names))
        _fused, _ = _gmu.forward(_feat_list, _d)
        return _fused
    else:
        return late_fusion_max(modalities)


# 模态消融评估 — 逐模态移除以量化各模态的边际贡献

def modality_ablation_scores(modalities: Dict[str, List[List[float]]],
                              labels: List[int],
                              eval_fn) -> Dict[str, float]:
    """逐模态消融：度量每个模态对下游指标的单体贡献。

    每次移除一个模态，计算性能衰减比。
    贡献值 = (full_fusion_score - ablated_score) / full_fusion_score。
    正值 = 正向贡献；负值 = 含噪或冗余信号。
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

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
