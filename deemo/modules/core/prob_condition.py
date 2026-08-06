# -*- coding: utf-8 -*-
# 创建: 2026-07-30  修改: 2026-07-31 (Thompson采样+动态阈值)
"""
概率条件执行 — 二值条件 → 贝叶斯信念驱动的软阈值调度.

管道中的 condition 函数是确定性二值谓词, 但 "是否需要执行某钩子" 本身
随上下文变化: 虚表恢复对纯 C 二进制几乎无产出, ARM64 小二进制上密码参数
提取器命中率 < 5%. 每次无条件执行这些低价值钩子浪费资源.

维护 Beta(α, β) 分布作为钩子效用的在线信念:
  α: 正向产出次数 + 先验
  β: 无效执行次数 + 先验
Thompson 采样决定执行/跳过, 自动平衡 explore/exploit.

按 (arch, binary_size_bucket) 条件化信念, 使模型学会上下文相关的跳过策略.
代价不对称设计: 跳过有用钩子的损失 >> 执行无用钩子的浪费, 因此在冷启动
阶段 (精度 < 8 伪样本) 几乎不跳过, 确保模型积累足够数据后才开始优化.
"""

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple


@dataclass
class BetaBelief:
    """Beta(α, β) 分布 — 共轭先验下的信念状态.

    均值 = α / (α + β), 方差 = αβ / ((α+β)²(α+β+1))
    """

    alpha: float = 1.0
    beta: float = 1.0

    @property
    def mean(self) -> float:
        total = self.alpha + self.beta
        return self.alpha / total if total > 0 else 0.5

    @property
    def variance(self) -> float:
        total = self.alpha + self.beta
        if total <= 0:
            return 0.0
        return (self.alpha * self.beta) / (total * total * (total + 1))

    @property
    def precision(self) -> float:
        """精度 = α + β, 等价于等效样本量."""
        return self.alpha + self.beta

    def update(self, reward: float) -> None:
        """以 [0, 1] 的 reward 更新信念. reward > 0.5 视为正向."""
        self.alpha += reward
        self.beta += (1.0 - reward)

    def sample(self) -> float:
        """Thompson 采样: 从 Beta(α, β) 中随机抽取.

        使用 Gamma(α,1) / (Gamma(α,1) + Gamma(β,1)) 的等效变换.
        """
        if self.alpha <= 0 or self.beta <= 0:
            return self.mean
        x = random.gammavariate(self.alpha, 1.0)
        y = random.gammavariate(self.beta, 1.0)
        return x / (x + y) if (x + y) > 0 else self.mean


class ProbConditionModel:
    """特征条件化的概率信念模型.

    为每个 (hook_name, feature_signature) 组合维护独立的 BetaBelief.
    feature_signature 由特征键的子集拼接而成 (如 "arch:x86_64|sz:2^20").

    冷启动策略:
      无历史数据的特征组合回退到该钩子的全局信念 (feature_signature='*'),
      全局信念由该钩子所有历史执行共同更新.

    内存管理:
      每个特征组合的信念对象开销约 80 bytes.
      对于 20 个钩子 × 50 个特征组合, 总内存 < 100KB.
    """

    def __init__(
        self, prior_alpha: float = 1.0, prior_beta: float = 1.0,
        feature_keys: Tuple[str, ...] = ('arch', 'sz'),
    ):
        self._beliefs: Dict[str, Dict[str, BetaBelief]] = defaultdict(dict)
        self._prior_alpha = prior_alpha
        self._prior_beta = prior_beta
        self._feature_keys = feature_keys

    def get_belief(
        self, hook_name: str,
        features: Optional[Dict[str, Any]] = None,
    ) -> BetaBelief:
        """获取特定钩子在给定特征下的信念分布.

        优先级: 精确特征匹配 > 全局回退 > 先验
        """
        sig = self._feature_signature(features) if features else '*'
        belief_map = self._beliefs.get(hook_name, {})

        if sig in belief_map:
            return belief_map[sig]
        if '*' in belief_map:
            return belief_map['*']
        # 完全冷启动: 返回先验
        return BetaBelief(alpha=self._prior_alpha, beta=self._prior_beta)

    def update(
        self, hook_name: str, reward: float,
        features: Optional[Dict[str, Any]] = None,
    ):
        """以此次执行的 reward 更新信念.

        reward ∈ [0, 1]:
          1.0 = 钩子产出有价值结果
          0.0 = 钩子执行但无产出
          0.3 = 钩子有部分产出但质量低 (可用于更精细的反馈)
        """
        sig = self._feature_signature(features) if features else '*'
        belief_map = self._beliefs[hook_name]

        if sig not in belief_map:
            belief_map[sig] = BetaBelief(
                alpha=self._prior_alpha, beta=self._prior_beta,
            )
        belief_map[sig].update(reward)

        # 同时更新全局信念, 作为特征回退的基础
        if sig != '*':
            if '*' not in belief_map:
                belief_map['*'] = BetaBelief(
                    alpha=self._prior_alpha, beta=self._prior_beta,
                )
            belief_map['*'].update(reward)

    def _feature_signature(self, features: Dict[str, Any]) -> str:
        """从特征字典生成可哈希的签名字符串."""
        parts = []
        for k in self._feature_keys:
            v = features.get(k, '')
            parts.append(f'{k}:{v}')
        return '|'.join(parts) if parts else '*'

    def forget(self, hook_name: str, features: Optional[Dict[str, Any]] = None):
        """选择性遗忘: 移除特定钩子的特定特征信念.

        用于概念漂移场景: 环境变化后旧统计数据不再有效.
        """
        if features:
            sig = self._feature_signature(features)
            self._beliefs.get(hook_name, {}).pop(sig, None)
        else:
            self._beliefs.pop(hook_name, None)


class ProbCondition:
    """概率条件包装 — 将传统的二值 condition(context)→bool 升级为概率决策.

    三层决策逻辑:
      1. 若确定性 condition 返回 False → 直接跳过 (保留原始语义)
      2. 否则从信念模型中采样, 按阈值判定:
         - sampled_prob < θ_skip → 跳过 (概率性节省)
         - sampled_prob > θ_force → 执行  (高价值钩子)
         - 中间 → 以 P=sampled_prob 的概率执行 (exploration)

    θ_skip 和 θ_force 随模型的精度动态调整:
      精度低 (等效样本量 < 10) → 缩小跳过区间, 加大探索
      精度高 (等效样本量 > 50) → 扩大跳过区间, 信任模型
    """

    def __init__(
        self,
        hook_name: str,
        model: ProbConditionModel,
        base_condition: Optional[Callable[[Dict[str, Any]], bool]] = None,
        theta_skip: float = 0.15,
        theta_force: float = 0.75,
        feature_extractor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ):
        self.hook_name = hook_name
        self.model = model
        self.base_condition = base_condition
        self._theta_skip = theta_skip
        self._theta_force = theta_force
        self._feature_extractor = feature_extractor or self._default_features

    def __call__(self, context: Dict[str, Any]) -> bool:
        """判定: 此钩子应在当前 context 下执行吗?

        返回 True/False, 可被 HookDAG 的 condition 字段直接消费.
        """
        # 第 1 层: 确定性条件 — 保留程序员意图
        if self.base_condition is not None and not self.base_condition(context):
            return False

        features = self._feature_extractor(context)
        belief = self.model.get_belief(self.hook_name, features)

        # 动态阈值: 根据精度调整
        precision = belief.precision
        skip_adj = self._theta_skip
        force_adj = self._theta_force
        if precision < 8:
            # 冷启动: 几乎不跳过, 让模型积累数据
            skip_adj = self._theta_skip * 0.3
            force_adj = self._theta_force * 0.6
        elif precision > 40:
            # 高置信: 信任模型, 扩大跳过区间
            skip_adj = min(0.35, self._theta_skip * 1.8)
            force_adj = max(0.55, self._theta_force * 0.85)

        sampled = belief.sample()

        if sampled < skip_adj:
            return False
        if sampled > force_adj:
            return True

        # 探索区间: 以 sampled 为概率随机执行
        return random.random() < sampled

    def report_reward(self, context: Dict[str, Any], reward: float):
        """钩子执行完毕后调用, 报告产出质量.

        reward 建议值:
          1.0 — 产出关键发现 (漏洞、重要配置、可利用点)
          0.5 — 产出常规信息
          0.0 — 无产出或纯噪声
        """
        features = self._feature_extractor(context)
        self.model.update(self.hook_name, reward, features)

    @staticmethod
    def _default_features(context: Dict[str, Any]) -> Dict[str, Any]:
        """从 context 中提取默认特征: arch, binary_size, format."""
        info = context.get('binary_info')
        summary = context.get('binary_summary', {})
        return {
            'arch': summary.get('arch', getattr(info, 'arch', 'unknown') if info else 'unknown'),
            'sz': summary.get('size', getattr(info, 'size', 0) if info else 0),
        }


class RewardEstimator:
    """钩子产出质量 → [0, 1] reward 的自动评估器.

    三维加权: 结构性 (非空字段比例) + 新颖性 (新键比例) + 体积 (序列化大小).
    默认权重偏保守, 倾向低分以避免过度乐观.
    """

    def __init__(
        self, struct_weight: float = 0.35, novelty_weight: float = 0.40,
        volume_weight: float = 0.25,
    ):
        self._w_struct = struct_weight
        self._w_novelty = novelty_weight
        self._w_volume = volume_weight
        self._prev_keys: set = set()

    def evaluate(self, output: Any, prev_context_keys: Optional[set] = None) -> float:
        if output is None:
            return 0.0
        if not isinstance(output, dict):
            return 0.25

        # 结构分: 有效键占总键的比例
        total_keys = len(output)
        non_empty = sum(1 for v in output.values() if v is not None and v != [] and v != {})
        struct_score = non_empty / max(1, total_keys)

        # 新颖性分: 引入了多少之前的 context 没有的键
        new_keys = set(output) - (prev_context_keys or set())
        novelty_score = len(new_keys) / max(1, total_keys) if total_keys > 0 else 0.0

        # 体积分: 用序列化长度的 sigmoid 函数 — 10~10000 字符区间线性映射
        try:
            raw_len = len(str(output))
        except Exception:
            raw_len = 0
        if raw_len < 20:
            volume_score = 0.1  # 太短, 几乎无信息
        elif raw_len > 50000:
            volume_score = 0.6  # 过大, 可能有大量冗余
        else:
            volume_score = 0.3 + 0.5 * min(1.0, math.log10(raw_len / 20) / 3.0)

        score = (
            self._w_struct * struct_score
            + self._w_novelty * novelty_score
            + self._w_volume * volume_score
        )
        return max(0.0, min(1.0, score))

    def reset_keys(self):
        self._prev_keys.clear()
