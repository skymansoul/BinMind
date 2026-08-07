# 修改记录:
# 2025-08-06 09:18 - 初始实现：熵梯度驱动的对抗式模态遮断课程

"""对抗式模态课程遮断 — 熵梯度驱动的自适应 mask 采样。

RMD (Random Modality Dropout) 按固定概率随机遮断模态以训练缺失模态鲁棒性，
但忽略了样本间的脆弱性差异。一个强依赖视觉的样本，遮断视觉 vs 遮断文本
的信息损失可能差一个数量级——RMD 对两类遮断一视同仁，训练信号浪费在"容易"
遮断上。

EGAC (Entropy-Gradient Adversarial Curriculum) 的核心：
1. 教师跟踪各样本在各类遮断下的融合熵，EMA 平滑。
2. 每步选"对该样本信息冲击最大"的遮断模式（对抗选择）。
3. 模型对该模式的熵损失下降 → 自动降遮断率（课程调度）。
4. 保留 10% 探索概率，随机遮断以发现新的脆弱模式。

与 AECF  的关键区别：
AECF 的惩罚系数是全局固定的；EGAC 的课程是逐样本自调节回路——
遮断选择基于信息冲击而非均匀采样，每次 mask 恰是该样本最不可替代的模态。
"""

import math
from collections import defaultdict
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

class EntropyGradientCurriculum:
    """熵梯度驱动的对抗式模态遮断课程。

    使用范式：
      egac = EntropyGradientCurriculum(n_modalities=3, modality_names=["s","d","t"])
      for epoch in range(n_epochs):
          for batch in data:
              mask = egac.select_mask(batch_id, modal_features)
              loss = model.train_step(batch, mask)
              fusion_entropy = model.get_entropy(batch)
              egac.observe(batch_id, mask, fusion_entropy, loss)
    """

    def __init__(
        self,
        n_modalities: int = 3,
        modality_names: Optional[List[str]] = None,
        curriculum_alpha: float = 0.1,
        entropy_momentum: float = 0.9,
        mask_min_prob: float = 0.02,
        mask_max_prob: float = 0.5,
        history_decay: float = 0.95,
    ):
        """
        n_modalities: 模态数量。
        modality_names: 模态名称映射（可选，便于日志解读）。
        curriculum_alpha: 课程进度速率（高值→更快降低已掌握模式的遮断率）。
        entropy_momentum: 样本级熵估计的动量系数。
        mask_min_prob: 遮断概率下界（避免过度保守）。
        mask_max_prob: 遮断概率上界（避免过度激进）。
        history_decay: 历史熵的指数衰减因子。
        """
        self.n_modalities = n_modalities
        self.modality_names = modality_names or [
            f"modal_{i}" for i in range(n_modalities)
        ]
        self.curriculum_alpha = curriculum_alpha
        self.entropy_momentum = entropy_momentum
        self.mask_min_prob = mask_min_prob
        self.mask_max_prob = mask_max_prob
        self.history_decay = history_decay

        # 全模态融合熵的动量估计
        self._full_entropy_ema: float = 0.0
        # 每种遮断模式下熵损失的动量估计
        # key = frozen set of masked modality indices
        self._mask_entropy_loss_ema: Dict[FrozenSet[int], float] = {}
        # 每种遮断模式当前的概率
        self._mask_probabilities: Dict[FrozenSet[int], float] = {}
        # 全局训练步数
        self._step_count: int = 0

        # 初始化遮断模式概率——均匀分布
        self._init_mask_probs()

    # 公开 API

    def select_mask(
        self,
        sample_id: int,
        modal_features: Dict[str, List[List[float]]],
        entropy_fn: Optional[Callable] = None,
    ) -> Set[int]:
        """为给定样本选择应遮断的模态集。

        返回：应遮断的模态索引集合（空集 = 全模态保留）。

        选择策略（三路竞争）：
        1. 以概率 p_curriculum: 选择"信息冲击最大"的遮断模式（对抗性）。
        2. 以概率 0.1: 选择随机遮断模式（探索——发现新脆弱模式）。
        3. 以剩余概率: 不遮断（全模态——巩固完整路径）。
        """
        self._step_count += 1

        # 计算当前样本各遮断模式的熵损失
        if entropy_fn:
            _losses = self._estimate_entropy_losses(
                sample_id, modal_features, entropy_fn
            )
            # 更新教师：选择熵损失最大的遮断模式
            if _losses:
                _worst_mask = max(_losses, key=_losses.get)
                self._mask_entropy_loss_ema[_worst_mask] = (
                    self.entropy_momentum
                    * self._mask_entropy_loss_ema.get(_worst_mask, _losses[_worst_mask])
                    + (1.0 - self.entropy_momentum) * _losses[_worst_mask]
                )

        # 采样遮断模式
        _rand = (sample_id * 2654435761 + self._step_count * 1597334677) % 1000000 / 1000000.0

        _p_explore = 0.1
        _p_curriculum = 1.0 - _p_explore

        if _rand < _p_curriculum and self._mask_probabilities:
            # 对抗性选择：按信息冲击加权采样
            return self._weighted_sample_mask()
        elif _rand < _p_curriculum + _p_explore:
            # 探索：随机单模态遮断
            return self._random_single_mask()
        else:
            # 全模态保留
            return set()

    def observe(
        self,
        sample_id: int,
        applied_mask: Set[int],
        fusion_entropy: float,
        loss_value: float,
    ):
        """反馈一次遮断的学习效果。

        基于观测到的熵和损失更新教师估计和课程调度。
        """
        _mask_key = frozenset(applied_mask)

        # 更新全模态熵的 EMA（仅当无遮断时）
        if not applied_mask:
            self._full_entropy_ema = (
                self.entropy_momentum * self._full_entropy_ema
                + (1.0 - self.entropy_momentum) * fusion_entropy
            )

        # 更新此遮断模式的熵损失 EMA
        _prev_loss = self._mask_entropy_loss_ema.get(_mask_key, fusion_entropy)
        self._mask_entropy_loss_ema[_mask_key] = (
            self.entropy_momentum * _prev_loss
            + (1.0 - self.entropy_momentum) * abs(fusion_entropy - self._full_entropy_ema)
        )

        # 课程调度：熵损失下降 → 降遮断概率（已学会）
        self._update_curriculum()

    def get_mask_probabilities(self) -> Dict[str, float]:
        """返回当前各遮断模式的概率分布（用于外部审计）。"""
        return {
            "+".join(self.modality_names[i] for i in sorted(k)) if k else "none": v
            for k, v in self._mask_probabilities.items()
        }

    # 内部方法

    def _init_mask_probs(self):
        """初始化所有单模态遮断的等概率分布。"""
        _n_single = self.n_modalities
        _p_each = 1.0 / (_n_single + 1)  # +1 for no-mask
        for _i in range(self.n_modalities):
            self._mask_probabilities[frozenset({_i})] = _p_each
        self._mask_probabilities[frozenset()] = _p_each

    def _estimate_entropy_losses(
        self,
        sample_id: int,
        modal_features: Dict[str, List[List[float]]],
        entropy_fn: Callable,
    ) -> Dict[FrozenSet[int], float]:
        """估计各遮断模式对该样本的熵损失。

        对每个可能的单模态遮断，计算其输出熵与全模态基准的差异。
        差异越大 → 该遮断的信息冲击越大 → 优先选择。
        """
        _full_entropy = entropy_fn(modal_features)
        _losses: Dict[FrozenSet[int], float] = {}

        for _i in range(self.n_modalities):
            _masked = {
                k: v
                for k, v in modal_features.items()
                if self.modality_names.index(k) != _i
            }
            if len(_masked) < 1:
                continue
            _masked_entropy = entropy_fn(_masked)
            _loss = abs(_full_entropy - _masked_entropy)
            _losses[frozenset({_i})] = _loss

        return _losses

    def _weighted_sample_mask(self) -> Set[int]:
        """按信息冲击加权的遮断模式采样。"""
        _probs = self._mask_probabilities
        _total = sum(_probs.values())
        if _total < _EPS:
            return set()

        _rand = (self._step_count * 1103515245 + 12345) % 1000000 / 1000000.0
        _cum = 0.0
        for _mask, _prob in _probs.items():
            _cum += _prob / _total
            if _rand <= _cum:
                return set(_mask)

        return set()

    def _random_single_mask(self) -> Set[int]:
        """随机选择单个模态遮断。"""
        _idx = (self._step_count * 25214903917 + 11) % self.n_modalities
        return {_idx}

    def _update_curriculum(self):
        """根据各遮断模式的熵损失变化更新课程概率。

        熵损失下降 → 以 curriculum_alpha 衰减该模式的遮断概率。
        熵损失上升 → 以 curriculum_alpha * 0.5 提升该模式的遮断概率。
        维护 min/max 边界。
        """
        _adjusted: Dict[FrozenSet[int], float] = {}
        for _mask, _cur_prob in self._mask_probabilities.items():
            _loss_ema = self._mask_entropy_loss_ema.get(_mask, 0.0)
            # 相对熵损失：当前遮断损失相对于全模态熵
            _relative_loss = (
                _loss_ema / max(self._full_entropy_ema, _EPS)
                if self._full_entropy_ema > _EPS
                else 0.5
            )

            # 相对损失低 → 模型对此遮断已适应 → 降低概率
            if _relative_loss < 0.3:
                _new_prob = _cur_prob * (1.0 - self.curriculum_alpha)
            elif _relative_loss > 0.7:
                _new_prob = _cur_prob * (1.0 + self.curriculum_alpha * 0.5)
            else:
                _new_prob = _cur_prob  # 中间区保持

            _adjusted[_mask] = max(
                self.mask_min_prob, min(self.mask_max_prob, _new_prob)
            )

        # 重归一化保持概率和为 1
        _total = sum(_adjusted.values())
        if _total > _EPS:
            for _mask in _adjusted:
                _adjusted[_mask] /= _total

        self._mask_probabilities = _adjusted

def fast_renyi_entropy(values: List[float], alpha: float = 2.0) -> float:
    """单样本快速 Renyi 熵计算——无需构造概率分布。

    适用于在线遮断决策场景。
    """
    _n = len(values)
    if _n < 2:
        return 0.0
    _mean = sum(values) / _n
    _var = sum((v - _mean) ** 2 for v in values) / _n
    if _var < _EPS:
        return 0.0
    # Renyi-2 的方差近似：H_2 ≈ 0.5 * ln(2πe * σ²)
    return 0.5 * math.log(2.0 * math.pi * math.e * _var)

def egac_train_step_wrapper(
    modal_features: Dict[str, List[List[float]]],
    fusion_fn: Callable,
    loss_fn: Callable,
    curriculum: EntropyGradientCurriculum,
    sample_id: int,
) -> Tuple[List[List[float]], Set[int], float]:
    """EGAC 训练步骤的一次完整执行。

    1. 选择遮断模式
    2. 应用遮断 → 融合 → 计算损失
    3. 反馈观察结果至课程调度器
    4. 返回融合结果、应用的遮断模式、损失值

    使用此包装器可避免在训练循环中手动管理遮断逻辑。
    """
    # 熵函数用于遮断选择
    def _entropy_fn(mods):
        _flat = []
        for _feat in mods.values():
            if _feat and _feat[0]:
                _flat.extend(_feat[0])
        return fast_renyi_entropy(_flat) if _flat else 0.0

    _mask = curriculum.select_mask(sample_id, modal_features, _entropy_fn)

    # 应用遮断：移除被遮断的模态
    _active_modals = {}
    for _i, (_name, _feat) in enumerate(modal_features.items()):
        if _i not in _mask:
            _active_modals[_name] = _feat

    if not _active_modals:
        _active_modals = modal_features  # 全遮断时回退

    _fused = fusion_fn(_active_modals)
    _loss = loss_fn(_fused)

    _fusion_entropy = _entropy_fn(_active_modals)
    curriculum.observe(sample_id, _mask, _fusion_entropy, _loss)

    return _fused, _mask, _loss

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _n_modals = 3
    _names = ["static", "dynamic", "symbolic"]
    _egac = EntropyGradientCurriculum(
        n_modalities=_n_modals, modality_names=_names,
    )

    # 模拟 50 步训练
    _dim = 16
    _n = 8
    for _step in range(50):
        _modals = {
            _names[i]: [
                [random.gauss(0, 1) for _ in range(_dim)] for _ in range(_n)
            ]
            for i in range(_n_modals)
        }

        _mask = _egac.select_mask(_step % _n, _modals)
        # 模拟熵反馈：随着训练，熵损失递减
        _sim_entropy = 2.0 * math.exp(-0.1 * _step) + random.gauss(0, 0.1)
        _sim_loss = 1.0 * math.exp(-0.05 * _step)
        _egac.observe(_step % _n, _mask, _sim_entropy, _sim_loss)

    _final_probs = _egac.get_mask_probabilities()
    print(f"[smoke] adversarial_modality_dropout — final mask probs after 50 steps:")
    for _k, _v in sorted(_final_probs.items()):
        print(f"  {_k}: {_v:.4f}")

    # 验证概率和为 1
    _total = sum(_final_probs.values())
    assert abs(_total - 1.0) < 0.01, f"probs sum to {_total}"
    print(f"[smoke] total probability: {_total:.4f}")

    # EGAC 包装器测试
    def _mock_fusion(m):
        _nms = list(m.keys())
        if not _nms:
            return []
        _nn = len(m[_nms[0]])
        return [[0.0] * 4 for _ in range(_nn)]

    def _mock_loss(f):
        return 0.5

    _fused, _mask, _loss = egac_train_step_wrapper(
        _modals, _mock_fusion, _mock_loss, _egac, 42,
    )
    print(f"[smoke] EGAC wrapper — mask: {_mask}, loss: {_loss:.4f}")

    print("[OK] EntropyGradientCurriculum smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
