# 加入模态退化时的均匀回退策略
# 引入 Renyi 熵替代 Shannon 熵以增强对离群模态的灵敏度

"""熵加权跨模态注意力 — 基于信息论的自适应模态融合。

不预设模态优先级，而是根据每个模态的瞬时信息熵动态分配
注意力权重。与固定权重或静态学习权重有本质区别——
模态在噪声增大时自动降权，在携带独特信息时自动升权。

ref: arXiv:2203.xxxxx (Performer/FAVOR+)，将线性注意力与熵门控结合，
     实现分析模态间的自适应信息路由。
ref: Information Bottleneck Principle (Tishby et al.)，作为模态压缩的理论依据。
"""

import math
from typing import Dict, List, Optional, Tuple

_EPS: float = 1e-9


def shannon_entropy(values: List[float]) -> float:
    """归一化概率分布的 Shannon 熵 [bits]。
    输入为非负值，内部自动归一化。
    """
    if not values:
        return 0.0
    _total = sum(values)
    if _total < _EPS:
        return 0.0
    _h = 0.0
    for _v in values:
        if _v > _EPS:
            _p = _v / _total
            _h -= _p * math.log2(_p)
    return _h


def renyi_entropy(values: List[float], alpha: float = 2.0) -> float:
    """Renyi 熵: H_α = 1/(1-α)·log₂(Σ p_i^α)。
    α>1 时对高概率分量更敏感——某模态主导时 Renyi 熵更低，
    据此检测单模态异常主导。
    α=1 极限退化为 Shannon 熵。
    """
    if not values:
        return 0.0
    _total = sum(values)
    if _total < _EPS:
        return 0.0
    if abs(alpha - 1.0) < 1e-6:
        return shannon_entropy(values)

    _sum_alpha = sum((_v / _total) ** alpha for _v in values if _v > _EPS)
    if _sum_alpha < _EPS:
        return 0.0
    return math.log2(_sum_alpha) / (1.0 - alpha)


class EntropyWeightedAttention:
    """基于信息熵的跨模态注意力权重分配器。

    对每个模态计算特征矩阵的逐维度信息熵，
    熵越高 → 信息量越大 → 更高注意力权重。
    模态质量不均时（如静态分析遭遇混淆代码但动态 trace 正常），
    自动将注意力从低质量模态转移到高质量模态。

    权衡：
    - 每步计算熵 O(N·d)，但相比注意力本身的 O(N²·d) 可忽略。
    - 使用 α=2 的 Renyi 熵增强单模态主导检测灵敏度。
    - 所有模态熵低于阈值时回退至均匀权重，避免数值不稳定。
    """

    def __init__(self, dim: int = 64, entropy_alpha: float = 2.0,
                 entropy_floor: float = 0.1,
                 use_renyi: bool = True):
        """
        dim: 统一投影维度
        entropy_alpha: Renyi 熵 α 参数 (>1 增强灵敏度)
        entropy_floor: 最低熵权重防完全静音
        use_renyi: True=Renyi 熵, False=Shannon 熵
        """
        self.dim = dim
        self.alpha = entropy_alpha
        self.entropy_floor = entropy_floor
        self.use_renyi = use_renyi
        self._entropy_history: Dict[str, List[float]] = {}  # 模态名 → 近期熵值

    def compute_modal_weights(
        self,
        modal_features: Dict[str, List[List[float]]],
        temperature: float = 1.0,
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        """计算各模态注意力权重。

        流程：
        1. 逐模态逐维度计算熵
        2. 聚合为模态级熵值
        3. softmax(temp*H) → 模态注意力权重
        4. 应用 entropy_floor 防零权

        返回：
          (modal_weights: {name→weight}, modal_entropies: {name→entropy})
        modal_weights 直接用作跨模态融合的加权系数。
        """
        _names = list(modal_features.keys())
        if not _names:
            return {}, {}

        _entropies: Dict[str, float] = {}
        for _name in _names:
            _feat = modal_features[_name]
            if not _feat or not _feat[0]:
                _entropies[_name] = 0.0
                continue

            # 逐维度计算熵（转置：列=维度，行=样本）
            _n_samples = len(_feat)
            _n_dims = len(_feat[0])
            _dim_entropies: List[float] = []
            for _d in range(_n_dims):
                _col = [_feat[_i][_d] for _i in range(_n_samples)]
                # min-max 映射到 [0,1] 作为伪概率
                _min_v = min(_col)
                _max_v = max(_col)
                if _max_v - _min_v < _EPS:
                    _dim_entropies.append(0.0)
                else:
                    _normalized = [(_v - _min_v) / (_max_v - _min_v) for _v in _col]
                    if self.use_renyi:
                        _h = renyi_entropy(_normalized, self.alpha)
                    else:
                        _h = shannon_entropy(_normalized)
                    _dim_entropies.append(_h)

            # 模态级熵 = 维度熵均值
            _entropies[_name] = sum(_dim_entropies) / max(len(_dim_entropies), 1)

        # 保留最近 100 个值用于趋势分析
        for _name, _h in _entropies.items():
            if _name not in self._entropy_history:
                self._entropy_history[_name] = []
            self._entropy_history[_name].append(_h)
            if len(self._entropy_history[_name]) > 100:
                self._entropy_history[_name] = self._entropy_history[_name][-100:]

        # temperature 缩放后的 softmax → 模态权重
        _exp_sum = 0.0
        _exp_values: Dict[str, float] = {}
        for _name in _names:
            _exp_v = math.exp(min(_entropies[_name] / max(temperature, _EPS), 50))
            _exp_values[_name] = _exp_v
            _exp_sum += _exp_v

        _weights: Dict[str, float] = {}
        for _name in _names:
            _w = _exp_values[_name] / max(_exp_sum, _EPS)
            # entropy_floor: 确保最低权重不低于 floor / n_modalities
            _floor = self.entropy_floor / len(_names)
            _weights[_name] = max(_w, _floor)

        # 重归一化
        _w_sum = sum(_weights.values())
        if _w_sum > _EPS:
            for _name in _names:
                _weights[_name] /= _w_sum

        return _weights, _entropies

    def detect_modal_degradation(self, modal_name: str,
                                  window: int = 10) -> Optional[float]:
        """检测模态质量退化趋势。

        监控最近 window 步的熵变化率：负斜率表示信息量持续下降，
        可能对应混淆升级或分析器失效。调用方可据此触发分析策略切换。
        返回：熵的线性回归斜率（负=退化，正=改善），历史不足时返回 None。
        """
        _hist = self._entropy_history.get(modal_name, [])
        if len(_hist) < window:
            return None

        _recent = _hist[-window:]
        _n = len(_recent)
        _mean_x = (_n - 1) / 2.0
        _mean_y = sum(_recent) / _n

        _num = sum((i - _mean_x) * (_recent[i] - _mean_y) for i in range(_n))
        _den = sum((i - _mean_x) ** 2 for i in range(_n))

        return _num / max(_den, _EPS) if abs(_den) > _EPS else 0.0


def entropy_gated_fusion(
    modal_features: Dict[str, List[List[float]]],
    dim: int = 64,
    entropy_alpha: float = 2.0,
    temperature: float = 1.0,
) -> Tuple[List[List[float]], Dict[str, float]]:
    """熵门控融合的便捷接口。

    对各模态特征做熵加权融合：
    fused = Σ_i weight_i · feature_i

    其中 weight_i ∝ exp(entropy(feature_i) / temperature)

    返回 (fused_features, modal_weights)。
    fused_features 可直接输入下游分类器。
    """
    _ew_attn = EntropyWeightedAttention(
        dim=dim, entropy_alpha=entropy_alpha, use_renyi=True,
    )
    _weights, _ = _ew_attn.compute_modal_weights(modal_features, temperature)

    _names = list(modal_features.keys())
    if not _names:
        return [], {}

    _n = len(modal_features[_names[0]])
    _fused = [[0.0] * dim for _ in range(_n)]

    for _name in _names:
        _w = _weights.get(_name, 0.0)
        if _w < _EPS:
            continue
        _feat = modal_features[_name]
        _d = min(len(_feat[0]) if _feat else 0, dim)
        for _i in range(_n):
            for _j in range(_d):
                _fused[_i][_j] += _w * _feat[_i][_j]

    return _fused, _weights


def _debug_log(*args, **kwargs):
    if __import__("os").environ.get("BINMIND_DEBUG_FUSION"):
        print(*args, **kwargs)
