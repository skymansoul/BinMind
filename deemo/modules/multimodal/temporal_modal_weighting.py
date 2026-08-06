"""
时序模态加权 (Temporal Modality Weighting, TMW)
-------------------------------------------------
动态证据随时间衰减, 静态证据保持恒定——时间感知的多模态融合权重.

设计依据:
  二进制分析中的模态具有不同的时效特性:
    - 静态分析 (反汇编/反编译): 时间无关, 权重恒定
    - 动态 trace: 每次执行可能不同, 旧 trace 权重应衰减
    - 符号执行: 基于当前约束求解, 中等时效
    - LLM 分析: 模型版本可能更新, 旧分析可能过时

  现有融合方法对所有模态平等对待, 不考虑时效差异.
  这导致旧动态 trace 可能覆盖当前的静态分析结论——
  例如: 3小时前的 trace 显示某路径不可达, 但新输入已改变状态.

  TMW 为每个模态维护指数衰减权重:
    w_i(t) = w_i(0) * exp(-λ_i * (t - t_observed))
    λ 按模态类型预设: static=0, dynamic=0.5/h, symexec=0.1/h, llm=0.01/h
"""
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# 默认衰减率 (每小时) —— 基于领域知识的预设值
DEFAULT_DECAY_RATES = {
    'disasm': 0.0,       # 静态, 不衰减
    'decompile': 0.0,    # 静态, 不衰减
    'dynamic': 0.5,      # 动态 trace, 半衰期 ~1.4h
    'symexec': 0.1,      # 符号执行, 半衰期 ~7h
    'llm': 0.01,         # LLM 分析, 半衰期 ~69h (模型版本更新)
    'import': 0.0,       # 导入表, 静态
    'checksec': 0.0,     # 保护机制, 静态
}


@dataclass
class ModalWeight:
    """单模态的时序感知权重."""
    modality: str
    base_weight: float       # 初始权重 w_i(0)
    decay_rate: float        # λ (每小时)
    observed_at: float       # 观测时间戳
    current_weight: float    # w_i(t): 当前衰减后权重
    age_hours: float         # 年龄 (小时)
    half_life_hours: float   # 半衰期 (小时)


class TemporalModalWeighting:
    """时序模态加权器.

    用法:
      tmw = TemporalModalWeighting()
      tmw.set_base_weight('dynamic', 0.8)
      tmw.observe('dynamic', timestamp=some_time)
      # ... 时间流逝 ...
      weights = tmw.compute_weights(now=time.time())
      # weights['dynamic'] 已衰减
    """

    def __init__(self, decay_rates: Optional[Dict[str, float]] = None):
        self._decay_rates = dict(decay_rates or DEFAULT_DECAY_RATES)
        self._base_weights: Dict[str, float] = {}
        self._observations: Dict[str, float] = {}  # modality → observed_at
        self._total_observations = 0

    def set_base_weight(self, modality: str, weight: float):
        """设置模态的初始权重 (0-1)."""
        self._base_weights[modality] = max(0.0, min(1.0, weight))

    def observe(self, modality: str, timestamp: Optional[float] = None):
        """记录模态的观测时间."""
        self._observations[modality] = timestamp or time.time()
        self._total_observations += 1
        # 为未见过的模态设置默认基础权重
        if modality not in self._base_weights:
            self._base_weights[modality] = 0.5

    def compute_weights(self, now: Optional[float] = None
                        ) -> Dict[str, float]:
        """计算当前时刻各模态的衰减后权重 (已归一化)."""
        now = now or time.time()
        weights = {}
        for mod, obs_time in self._observations.items():
            base = self._base_weights.get(mod, 0.5)
            lam = self._decay_rates.get(mod, 0.1)
            age_hours = max(0.0, (now - obs_time) / 3600.0)
            # w(t) = w(0) * exp(-λ * age_hours)
            current = base * math.exp(-lam * age_hours)
            weights[mod] = current

        # 归一化
        total = sum(weights.values()) or 1.0
        return {k: round(v / total, 4) for k, v in weights.items()}

    def compute_detailed(self, now: Optional[float] = None
                         ) -> List[ModalWeight]:
        """返回详细的模态权重信息 (含年龄和半衰期)."""
        now = now or time.time()
        result = []
        for mod, obs_time in self._observations.items():
            base = self._base_weights.get(mod, 0.5)
            lam = self._decay_rates.get(mod, 0.1)
            age_hours = max(0.0, (now - obs_time) / 3600.0)
            current = base * math.exp(-lam * age_hours)
            half_life = math.log(2) / lam if lam > 0 else float('inf')
            result.append(ModalWeight(
                modality=mod, base_weight=base, decay_rate=lam,
                observed_at=obs_time, current_weight=round(current, 4),
                age_hours=round(age_hours, 2),
                half_life_hours=round(half_life, 1),
            ))
        result.sort(key=lambda x: x.current_weight, reverse=True)
        return result

    def should_refresh(self, modality: str,
                       threshold: float = 0.5,
                       now: Optional[float] = None) -> bool:
        """判断某模态是否需要刷新 (权重低于基础权重的 threshold 倍)."""
        now = now or time.time()
        if modality not in self._observations:
            return True
        base = self._base_weights.get(modality, 0.5)
        lam = self._decay_rates.get(modality, 0.1)
        age = (now - self._observations[modality]) / 3600.0
        current = base * math.exp(-lam * age)
        return current < base * threshold

    def stale_modalities(self, now: Optional[float] = None) -> List[str]:
        """返回所有需要刷新的模态列表."""
        return [m for m in self._observations
                if self.should_refresh(m, now=now)]

    def decay_rate_for(self, modality: str) -> float:
        return self._decay_rates.get(modality, 0.1)

    def set_decay_rate(self, modality: str, rate: float):
        """自定义某模态的衰减率."""
        self._decay_rates[modality] = max(0.0, rate)


def suggest_decay_rate(
    modality: str,
    volatility: float,       # 0-1, 该模态输出随时间的变异程度
    min_rate: float = 0.001,
    max_rate: float = 2.0,
) -> float:
    """根据模态的观测波动性建议衰减率.
    volatility: 历史观测间的变异系数 (std/mean).
    高波动 → 高衰减率 (旧观测快速失效).
    """
    rate = volatility * max_rate + (1.0 - volatility) * min_rate
    return round(rate, 4)


class AdaptiveTemporalWeighting(TemporalModalWeighting):
    """自适应时序加权 — 从观测数据在线学习各模态的衰减率 λ.

    与父类 TemporalModalWeighting 的区别:
      父类使用预设的 DEFAULT_DECAY_RATES (如 dynamic=0.5/h).
      本类从模态输出的实际波动性中在线估计 λ:
        λ_new = EMA(observed_volatility × max_rate).
      高波动模态自动获得高衰减率, 无需人工预设.

    用法:
      atw = AdaptiveTemporalWeighting()
      atw.observe('dynamic', timestamp=t1)
      atw.record_output_hash('dynamic', hash1)  # 记录本次输出指纹
      # ... 时间流逝, 再次观测 ...
      atw.observe('dynamic', timestamp=t2)
      atw.record_output_hash('dynamic', hash2)  # 若hash不同→波动→λ增加
    """

    def __init__(self, ema_alpha: float = 0.2,
                 min_lambda: float = 0.001, max_lambda: float = 2.0):
        super().__init__()
        self._ema_alpha = ema_alpha
        self._min_lambda = min_lambda
        self._max_lambda = max_lambda
        # 输出指纹历史: modality → [(timestamp, output_hash), ...]
        self._output_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        # 学到的 λ (EMA)
        self._learned_lambda: Dict[str, float] = {}

    def record_output_hash(self, modality: str, output_hash: str):
        """记录某模态在最近一次观测中的输出指纹.
        连续观测的哈希变化用于估计该模态的波动性.
        """
        ts = self._observations.get(modality, time.time())
        hist = self._output_history[modality]
        hist.append((ts, output_hash))
        # 保留最近 20 次记录
        if len(hist) > 20:
            hist.pop(0)
        # 从历史更新 λ
        self._update_lambda(modality)

    def _update_lambda(self, modality: str):
        """从输出哈希变化率估计该模态的 λ."""
        hist = self._output_history[modality]
        if len(hist) < 2:
            return
        # 计算相邻观测间的哈希变化率
        changes = 0
        for i in range(1, len(hist)):
            if hist[i][1] != hist[i-1][1]:
                changes += 1
        volatility = changes / (len(hist) - 1)
        # 时间跨度越大, 变化的意义越小 (可能是正常漂移)
        time_span_h = (hist[-1][0] - hist[0][0]) / 3600.0 if len(hist) >= 2 else 1.0
        # 每小时变化率归一化
        rate_per_hour = volatility / max(0.1, time_span_h)
        raw_lambda = rate_per_hour * self._max_lambda
        raw_lambda = max(self._min_lambda, min(self._max_lambda, raw_lambda))
        # EMA 平滑
        old = self._learned_lambda.get(modality, self._decay_rates.get(modality, 0.1))
        self._learned_lambda[modality] = (
            self._ema_alpha * raw_lambda + (1 - self._ema_alpha) * old
        )

    def compute_weights(self, now: Optional[float] = None) -> Dict[str, float]:
        """使用学到的 λ (若有) 回退预设值."""
        now = now or time.time()
        weights = {}
        for mod, obs_time in self._observations.items():
            base = self._base_weights.get(mod, 0.5)
            lam = self._learned_lambda.get(mod) or self._decay_rates.get(mod, 0.1)
            age_hours = max(0.0, (now - obs_time) / 3600.0)
            current = base * math.exp(-lam * age_hours)
            weights[mod] = current
        total = sum(weights.values()) or 1.0
        return {k: round(v / total, 4) for k, v in weights.items()}

    def learned_lambdas(self) -> Dict[str, float]:
        """返回所有已学到的 λ 值."""
        return dict(self._learned_lambda)
