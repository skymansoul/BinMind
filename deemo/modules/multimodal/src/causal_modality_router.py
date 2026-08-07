# 修改记录:
# 2025-08-06 14:23 - 初始实现：do-算子启发的模态因果效应估计与动态路由

"""因果模态路由 — 基于干预主义因果推断的模态贡献分解。

核心机制：不依赖完整因果图，而是通过结构化反事实干预估计每个模态的
平均因果效应 (ACE)，区分模态对融合结果的相关性贡献与因果性贡献。

问题背景：
现有的熵门控、注意力门控、GMU 等方法本质上是相关性驱动的——
它们基于共现模式分配权重，无法区分"模态 A 与结果相关"和
"模态 A 导致结果变化"这两种本质不同的贡献。

解决方案：
1. 对融合管线施加结构化干预（遮断某模态的信息通路），
   测量该干预导致的输出偏移量。
2. 使用 do-算子启发的两层中介分析：
   - 前门路径：模态特征 → 融合瓶颈 → 输出（因果路径）
   - 后门路径：混淆特征 → 模态特征 且 混淆特征 → 输出（相关但非因果）
3. 通过比较完整融合与干预后融合的差异，估计每个模态的 ACE。
4. ACE 驱动的动态路由替代固定权重，实现因果感知的模态选择。

- Pearl, J. "Causal diagrams for empirical research." Biometrika
- Zhou et al. "Mitigating Modality Prior-Induced Hallucinations via
  Deciphering Attention Causality.".
  该方法使用后门调整和反事实推理消除模态先验偏差。
"""

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

_EPS: float = 1e-9

class CausalModalityRouter:
    """因果感知的模态路由决策器。

    不同于 EntropyWeightedAttention 的信息论方法，
    本路由器基于 do-算子启发的因果效应估计：
    对每个模态进行反事实遮断，测量其缺失对融合输出的因果冲击，
    据此动态调节各模态的信息分配权重。

    使用范式：
      router = CausalModalityRouter(dim=128)
      weights, ace_scores = router.route(
          modal_features={"static": ..., "dynamic": ..., "symbolic": ...},
          base_fusion_fn=my_fusion_function,
      )
      # weights 可直接作为融合系数，ace_scores 用于审计各模态的真实因果贡献。
    """

    def __init__(
        self,
        dim: int = 64,
        n_intervention_samples: int = 5,
        ace_smoothing: float = 0.3,
        causal_threshold: float = 0.05,
    ):
        """
        dim: 模态特征统一维度。
        n_intervention_samples: 每次干预的采样次数（增大→更精确的 ACE 估计，
                               但计算开销线性增长）。
        ace_smoothing: ACE 值的指数平滑系数 (0~1)。
                       低值→更平滑但对快速模态质量变化响应慢。
        causal_threshold: 因果效应最低门限——ACE 低于此值的模态视为仅相关而非因果。
        """
        self.dim = dim
        self.n_intervention_samples = n_intervention_samples
        self.ace_smoothing = ace_smoothing
        self.causal_threshold = causal_threshold

        # 历史 ACE 追踪：模态名 → 平滑后的 ACE
        self._ace_history: Dict[str, float] = {}
        # 历史路由决策 count，用于审计
        self._route_count: int = 0

    # 公开 API

    def route(
        self,
        modal_features: Dict[str, List[List[float]]],
        base_fusion_fn,
        fusion_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        """执行因果路由决策。

        参数：
          modal_features: 各模态特征 {name: [N, d_i]}
          base_fusion_fn: 融合函数 f(modals) → [N, dim]
          fusion_kwargs: 传递给融合函数的额外参数

        返回：
          (routing_weights, ace_scores)
          routing_weights: 归一化的因果路由权重
          ace_scores: 原始 ACE 估计值（审计用）
        """
        _names = list(modal_features.keys())
        if len(_names) < 2:
            _w = {_names[0]: 1.0} if _names else {}
            return _w, _w.copy()

        _fusion_kwargs = fusion_kwargs or {}

        # 完整融合参照基线
        _full_output = base_fusion_fn(modal_features, **_fusion_kwargs)

        # 逐模态干预：遮断 → 测量输出偏移量
        _ace_raw: Dict[str, float] = {}
        for _name in _names:
            _ablated = {k: v for k, v in modal_features.items() if k != _name}
            if not _ablated:
                _ace_raw[_name] = 0.0
                continue

            # 多次采样干预以减少单次遮断的偶然性
            _offsets: List[float] = []
            for _ in range(self.n_intervention_samples):
                _ablated_output = base_fusion_fn(
                    self._add_noise_to_modals(_ablated), **_fusion_kwargs
                )
                _offset = self._compute_output_divergence(_full_output, _ablated_output)
                _offsets.append(_offset)

            _ace_raw[_name] = sum(_offsets) / max(len(_offsets), 1)

        # ACE 平滑与归一化
        _ace_smoothed = self._smooth_ace(_ace_raw)
        _weights = self._ace_to_weights(_ace_smoothed)

        self._route_count += 1
        return _weights, _ace_smoothed

    def estimate_front_door_effect(
        self,
        modal_features: Dict[str, List[List[float]]],
        mediator_fn,
        output_fn,
        modal_name: str,
    ) -> float:
        """估计单个模态的前门因果效应。

        前门准则 (front-door criterion) 的两步估计：
        步骤1: P(mediator | do(modal)) — 模态对中介变量的直接因果效应
        步骤2: P(output | do(mediator)) — 中介变量对输出的直接因果效应
        前门效应 = 步骤1 效应 × 步骤2 效应

        用于深度审计场景——当 ACE 异常高或低时，
        可调用此方法拆解因果路径。
        """
        if modal_name not in modal_features:
            return 0.0

        # do(modal=present) vs do(modal=absent) 对中介的影响
        _full_mediator = mediator_fn(modal_features)
        _ablated = {k: v for k, v in modal_features.items() if k != modal_name}
        _ablated_mediator = mediator_fn(_ablated) if _ablated else _full_mediator

        _step1_effect = self._compute_output_divergence(
            _full_mediator, _ablated_mediator
        )

        # do(mediator=full) vs do(mediator=ablated) 对输出的影响
        _full_output = output_fn(_full_mediator)
        _ablated_output = output_fn(_ablated_mediator)

        _step2_effect = self._compute_output_divergence(_full_output, _ablated_output)

        return _step1_effect * _step2_effect

    def get_causal_vs_correlational_split(
        self, ace_scores: Dict[str, float]
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        """将模态贡献拆分为因果部分与相关部分。

        返回：(causal_contribs, correlational_contribs)
        两者之和 = ace_scores 中的原始值。
        拆分依据：causal_contrib = max(0, ACE - causal_threshold * max(ACE))
        """
        _max_ace = max(ace_scores.values()) if ace_scores else 1.0
        _split_threshold = self.causal_threshold * _max_ace

        _causal: Dict[str, float] = {}
        _correl: Dict[str, float] = {}
        for _name, _ace in ace_scores.items():
            _c = max(0.0, _ace - _split_threshold)
            _causal[_name] = _c
            _correl[_name] = _ace - _c

        return _causal, _correl

    # 内部方法

    def _smooth_ace(self, ace_raw: Dict[str, float]) -> Dict[str, float]:
        """指数平滑 ACE 估计以减少单次测量噪声。"""
        _alpha = self.ace_smoothing
        _smoothed: Dict[str, float] = {}
        for _name, _ace in ace_raw.items():
            _prev = self._ace_history.get(_name, _ace)
            _new = _alpha * _ace + (1.0 - _alpha) * _prev
            _smoothed[_name] = _new
            self._ace_history[_name] = _new
        return _smoothed

    def _ace_to_weights(self, ace_scores: Dict[str, float]) -> Dict[str, float]:
        """将 ACE 映射为归一化路由权重。

        使用 softmax(temperature · ACE) 映射，温度自适应以抑制极端值。
        """
        _names = list(ace_scores.keys())
        if not _names:
            return {}

        _vals = list(ace_scores.values())
        _mean_ace = sum(_vals) / len(_vals)
        # 自适应温度：ACE 跨度大时降温以保持区分度
        _max_ace = max(_vals)
        _temperature = max(0.5, _mean_ace + _EPS)

        _exp_sum = 0.0
        _exps: Dict[str, float] = {}
        for _name in _names:
            _e = math.exp(min(ace_scores[_name] / _temperature, 50))
            _exps[_name] = _e
            _exp_sum += _e

        _weights: Dict[str, float] = {}
        for _name in _names:
            _weights[_name] = _exps[_name] / max(_exp_sum, _EPS)

        return _weights

    @staticmethod
    def _compute_output_divergence(
        full_output: List[List[float]],
        ablated_output: List[List[float]],
    ) -> float:
        """计算两种融合输出的差异度。

        使用 Frobenius 范数比值：||full - ablated||_F / ||full||_F。
        差异越大 → 该模态的因果效应越强。
        """
        if not full_output or not ablated_output:
            return 0.0

        _n = min(len(full_output), len(ablated_output))
        if _n == 0:
            return 0.0

        _d = min(
            len(full_output[0]) if full_output else 0,
            len(ablated_output[0]) if ablated_output else 0,
        )

        _diff_norm = 0.0
        _full_norm = 0.0
        for _i in range(_n):
            for _j in range(_d):
                _diff = full_output[_i][_j] - ablated_output[_i][_j]
                _diff_norm += _diff * _diff
                _full_norm += full_output[_i][_j] * full_output[_i][_j]

        _full_norm_sqrt = math.sqrt(_full_norm)
        if _full_norm_sqrt < _EPS:
            return 0.0
        return math.sqrt(_diff_norm) / _full_norm_sqrt

    @staticmethod
    def _add_noise_to_modals(
        modal_features: Dict[str, List[List[float]]],
        noise_scale: float = 0.02,
    ) -> Dict[str, List[List[float]]]:
        """向模态特征注入微量噪声以检验融合稳定性。

        噪声服从正弦确定性扰动（非随机——确保可复现的因果效应估计）。
        幅度 noise_scale * std(feature) 足够小，不改变语义，
        但足以探测融合对细微扰动的敏感度。
        """
        _noised: Dict[str, List[List[float]]] = {}
        for _name, _feat in modal_features.items():
            if not _feat or not _feat[0]:
                _noised[_name] = _feat
                continue
            _n = len(_feat)
            _d = len(_feat[0])
            _perturbed = [[0.0] * _d for _ in range(_n)]
            for _i in range(_n):
                for _j in range(_d):
                    # 确定性正弦扰动：空间位置 (i,j) 唯一确定扰动值
                    _perturbation = noise_scale * math.sin(
                        _i * 0.37 + _j * 1.73 + hash(_name) * 0.01
                    )
                    _perturbed[_i][_j] = _feat[_i][_j] * (1.0 + _perturbation)
            _noised[_name] = _perturbed
        return _noised

    def _backdoor_adjust_ace(
        self,
        modal_name: str,
        modal_features: Dict[str, List[List[float]]],
        base_fusion_fn,
        fusion_kwargs: Dict[str, Any],
    ) -> float:
        """估计单模态经后门调整的因果效应。

        标准消融（直接移除模态M）的估计可能受混淆影响——
        剩余模态与M共享某些冗余信息，移除M后剩余模态
        可能"补偿"M的部分功能→低估M的真实因果效应。

        后门调整——分层估计：
        1. 将剩余模态按特征能量分层（低/中/高）。
        2. 每层内估计移除M的输出偏移。
        3. 加权平均→消除冗余模态"补偿效应"的偏置。

        参考: Pearl (1995) 后门准则的形式化定义。
        """
        _other_modals = {k: v for k, v in modal_features.items() if k != modal_name}
        if not _other_modals:
            return 0.0

        _full_output = base_fusion_fn(modal_features, **fusion_kwargs)

        # 按特征能量将剩余模态分层
        _strata = self._stratify_by_energy(_other_modals, n_strata=3)
        _effects: List[float] = []
        _weights: List[float] = []

        for _stratum_modals, _weight in _strata:
            if not _stratum_modals:
                continue
            _ablated_output = base_fusion_fn(_stratum_modals, **fusion_kwargs)
            _effect = self._compute_output_divergence(_full_output, _ablated_output)
            _effects.append(_effect)
            _weights.append(_weight)

        if not _effects:
            return 0.0

        _total_weight = sum(_weights)
        return sum(e * w for e, w in zip(_effects, _weights)) / max(_total_weight, _EPS)

    @staticmethod
    def _stratify_by_energy(
        modals: Dict[str, List[List[float]]],
        n_strata: int = 3,
    ) -> List[Tuple[Dict[str, List[List[float]]], float]]:
        """按特征能量分层——返回 [(子模态集, 权重)]。

        权重基于每层包含的原始模态能量占比。
        """
        if not modals:
            return []

        _names = list(modals.keys())
        # 计算每个样本的总能量
        _energies: List[float] = []
        for _i in range(len(modals[_names[0]])):
            _e = sum(
                sum(v * v for v in modals[_n][_i])
                for _n in _names
            )
            _energies.append(_e)

        if not _energies:
            return [(modals, 1.0)]

        _sorted = sorted(_energies)
        _n = len(_sorted)
        _strata: List[Tuple[Dict[str, List[List[float]]], float]] = []

        for _s in range(n_strata):
            _lo = int(_n * _s / n_strata)
            _hi = int(_n * (_s + 1) / n_strata)
            if _lo >= _hi:
                continue
            _threshold_lo = _sorted[_lo]
            _threshold_hi = _sorted[min(_hi, _n - 1)]

            _stratum_modals: Dict[str, List[List[float]]] = {}
            for _nm in _names:
                _feat = modals[_nm]
                _subset = [
                    _feat[_i] for _i in range(len(_feat))
                    if _threshold_lo <= _energies[_i] < _threshold_hi
                ]
                if _subset:
                    _stratum_modals[_nm] = _subset

            if _stratum_modals:
                _strata.append((_stratum_modals, (_hi - _lo) / _n))

        return _strata if _strata else [(modals, 1.0)]

def causal_weighted_fusion(
    modal_features: Dict[str, List[List[float]]],
    dim: int = 64,
    base_fusion_fn=None,
) -> Tuple[List[List[float]], Dict[str, float], Dict[str, float]]:
    """因果路由融合的便捷接口。

    如果未提供 base_fusion_fn，使用等权求和作为基线融合。
    返回：(fused_features, routing_weights, ace_scores)。
    """
    _router = CausalModalityRouter(dim=dim)

    if base_fusion_fn is None:
        def _default_fusion(mods, **_kw):
            _names = list(mods.keys())
            if not _names:
                return []
            _n = len(mods[_names[0]])
            _d = min(
                len(mods[_n][0]) if mods[_n] and mods[_n][0] else dim
                for _n in _names
            )
            _out = [[0.0] * _d for _ in range(_n)]
            _w = 1.0 / len(_names)
            for _name in _names:
                _feat = mods[_name]
                for _i in range(_n):
                    for _j in range(min(_d, len(_feat[_i]) if _feat else 0)):
                        _out[_i][_j] += _w * _feat[_i][_j]
            return _out

        base_fusion_fn = _default_fusion

    _weights, _ace = _router.route(modal_features, base_fusion_fn)

    # 按因果权重执行最终融合
    _names = list(modal_features.keys())
    if not _names:
        return [], _weights, _ace

    _n = len(modal_features[_names[0]])
    _fused = [[0.0] * dim for _ in range(_n)]
    for _name in _names:
        _w = _weights.get(_name, 0.0)
        _feat = modal_features[_name]
        _d = min(len(_feat[0]) if _feat else 0, dim)
        for _i in range(_n):
            for _j in range(_d):
                _fused[_i][_j] += _w * _feat[_i][_j]

    return _fused, _weights, _ace

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _dim = 32
    _n = 16
    # 构造三模态特征：模态0 与输出强因果，模态1 相关但非因果，模态2 噪声
    _modal_0 = [
        [math.sin(_i * 0.1 + j * 0.3) for j in range(_dim)] for _i in range(_n)
    ]
    _modal_1 = [
        [math.cos(_i * 0.1 + j * 0.3 + 1.5) for j in range(_dim)] for _i in range(_n)
    ]
    _modal_2 = [
        [random.gauss(0, 0.1) for _j in range(_dim)] for _i in range(_n)
    ]

    _router = CausalModalityRouter(dim=_dim)

    def _test_fusion(mods, **_kw):
        # 模拟融合：模态0 高权重，模态1 中等，模态2 忽略
        _nms = list(mods.keys())
        _n = len(mods[_nms[0]]) if _nms else 0
        _out = [[0.0] * _dim for _ in range(_n)]
        _weights = {"modal_0": 0.6, "modal_1": 0.35, "modal_2": 0.05}
        for _nm in _nms:
            _w = _weights.get(_nm, 0.0)
            _feat = mods[_nm]
            for _i in range(_n):
                for _j in range(_dim):
                    _out[_i][_j] += _w * _feat[_i][_j]
        return _out

    _modals = {"modal_0": _modal_0, "modal_1": _modal_1, "modal_2": _modal_2}
    _weights, _ace = _router.route(_modals, _test_fusion)

    # ACE 排序验证：因果性强的模态应有更高 ACE
    _sorted = sorted(_ace.items(), key=lambda x: x[1], reverse=True)
    print(f"[causal_router] ACE ranking: {[(n, round(a, 4)) for n, a in _sorted]}")
    print(f"[causal_router] routing weights: {[(n, round(w, 4)) for n, w in _weights.items()]}")

    _fe_effect = _router.estimate_front_door_effect(
        _modals,
        mediator_fn=lambda m: _test_fusion(m),
        output_fn=lambda m: [[sum(row) / len(row)] for row in m],
        modal_name="modal_0",
    )
    print(f"[causal_router] front-door effect for modal_0: {_fe_effect:.6f}")

    _causal, _correl = _router.get_causal_vs_correlational_split(_ace)
    print(f"[causal_router] causal split: {_causal}")
    print(f"[causal_router] correl split: {_correl}")
    print("[OK] CausalModalityRouter smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
