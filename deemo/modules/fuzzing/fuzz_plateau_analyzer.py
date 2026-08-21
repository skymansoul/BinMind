"""
模糊测试平台期瓶颈分析器 (Plateau Bottleneck Analyzer, PBA)
--------------------------------------------------------------
当覆盖率增长停滞时, 通过因子-效果分组对比诊断最可能的瓶颈——
不仅报告 "覆盖停滞", 还指出 "哪个因子与停滞最相关" 和 "建议调整方向".

注: 本模块进行的是统计相关性分析 (分组均值差异), 不是因果推断.
"因果"一词在变量命名中保留仅因向后兼容.

设计依据:
  现有模糊测试工具 (AFL++, libFuzzer) 仅报告定量指标, 不提供停滞归因.
  PBA 用中位数分割 + 分组均值差异估计每个因子与覆盖率增长的关联强度,
  从而在停滞时给出数据驱动的优化建议.

算法:
  1. 滑动窗口追踪各因子的历史值及对应的覆盖率增量
  2. 中位数分割: 将每个因子分为"高值组"和"低值组"
  3. 计算两组的覆盖率增量均值差作为该因子的关联得分
  4. 停滞时输出得分最低的因子作为优化方向
"""
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PlateauEvent:
    """单次覆盖停滞事件."""
    detected_at_cycle: int
    current_edges: int
    stagnation_cycles: int
    diagnosis: Dict[str, float] = field(default_factory=dict)
    recommendation: str = ""


class FactorTracker:
    """单因子的滑动窗口追踪器 — 追踪因子值与覆盖率增量的关联."""

    def __init__(self, name: str, window_size: int = 50):
        self.name = name
        self._values: deque = deque(maxlen=window_size)
        self._outcomes: deque = deque(maxlen=window_size)  # 对应的覆盖率增量
        self._window = window_size

    def record(self, factor_value: float, outcome: float):
        self._values.append(factor_value)
        self._outcomes.append(outcome)

    def association_score(self) -> float:
        """该因子与覆盖率增量的关联得分.
        中位数分割: 高因子组 vs 低因子组的平均覆盖率增量差异.
        """
        if len(self._values) < 10:
            return 0.0
        median = sorted(self._values)[len(self._values) // 2]
        high_outcomes = [o for v, o in zip(self._values, self._outcomes) if v > median]
        low_outcomes = [o for v, o in zip(self._values, self._outcomes) if v <= median]
        high_avg = sum(high_outcomes) / len(high_outcomes) if high_outcomes else 0.0
        low_avg = sum(low_outcomes) / len(low_outcomes) if low_outcomes else 0.0
        return high_avg - low_avg

    def mean(self) -> float:
        return sum(self._values) / len(self._values) if self._values else 0.0

    def trend(self) -> float:
        """最近 10 个值的线性趋势 (简化: 前后半均值差)."""
        vals = list(self._values)
        if len(vals) < 6:
            return 0.0
        mid = len(vals) // 2
        return sum(vals[mid:]) / len(vals[mid:]) - sum(vals[:mid]) / mid


class PlateauBottleneckAnalyzer:
    """覆盖平台期因果分析器.

    用法:
      pca = PlateauCausalAnalyzer()
      # 每个模糊测试周期:
      pca.record_cycle(seed_diversity=0.7, mutation_hit_rate=0.15,
                       energy_concentration=0.4, new_edges=3)
      # 周期性检查:
      if pca.is_stagnating():
          diag = pca.diagnose()
          print(diag['recommendation'])
    """

    def __init__(self, stagnation_threshold: int = 30):
        self._factors: Dict[str, FactorTracker] = {
            'seed_diversity': FactorTracker('seed_diversity'),
            'mutation_hit_rate': FactorTracker('mutation_hit_rate'),
            'energy_concentration': FactorTracker('energy_concentration'),
            'corpus_size': FactorTracker('corpus_size'),
        }
        self._stagnation_threshold = stagnation_threshold
        self._cycles_without_growth = 0
        self._total_cycles = 0
        self._current_edges = 0
        self._plateau_history: List[PlateauEvent] = []
        # 边缘计数器的 EMA
        self._edge_growth_ema = 0.0

    def record_cycle(
        self,
        seed_diversity: float = 0.0,
        mutation_hit_rate: float = 0.0,
        energy_concentration: float = 0.0,
        corpus_size: int = 0,
        new_edges: int = 0,
    ):
        """记录一个模糊测试周期的观测值."""
        self._total_cycles += 1
        factor_vals = {
            'seed_diversity': seed_diversity,
            'mutation_hit_rate': mutation_hit_rate,
            'energy_concentration': energy_concentration,
            'corpus_size': float(corpus_size),
        }
        for name, tracker in self._factors.items():
            tracker.record(factor_vals.get(name, 0.0), float(new_edges))

        if new_edges > 0:
            self._current_edges += new_edges
            self._cycles_without_growth = 0
        else:
            self._cycles_without_growth += 1

        self._edge_growth_ema = 0.2 * new_edges + 0.8 * self._edge_growth_ema

        # 检测平台期
        if self._cycles_without_growth == self._stagnation_threshold:
            self._record_plateau()

    def is_stagnating(self) -> bool:
        return self._cycles_without_growth >= self._stagnation_threshold

    def stagnation_cycles(self) -> int:
        return self._cycles_without_growth

    def diagnose(self) -> Dict[str, Any]:
        """因果诊断当前停滞的根因.
        返回各因子的因果效应排序 + 推荐干预措施.
        """
        effects = {}
        for name, tracker in self._factors.items():
            effects[name] = tracker.association_score()

        # 找效应最弱的因子 — 这是瓶颈
        sorted_effects = sorted(effects.items(), key=lambda x: x[1])
        bottleneck = sorted_effects[0] if sorted_effects else ('unknown', 0.0)

        recommendations = {
            'seed_diversity': (
                '种子多样性不足——引入新外部种子或增加 splice 变异频率'
            ),
            'mutation_hit_rate': (
                '变异命中率低——增加字典注入、结构感知变异或减少 havoc 比例'
            ),
            'energy_concentration': (
                '能量分配过度集中——提高 explore 策略权重, 扩大种子选择范围'
            ),
            'corpus_size': (
                '语料库规模不足——延长探索阶段或降低最小化频率'
            ),
        }

        return {
            'stagnation_cycles': self._cycles_without_growth,
            'total_cycles': self._total_cycles,
            'current_edges': self._current_edges,
            'edge_growth_ema': round(self._edge_growth_ema, 2),
            'causal_effects': {k: round(v, 4) for k, v in effects.items()},
            'bottleneck_factor': bottleneck[0],
            'bottleneck_effect': round(bottleneck[1], 4),
            'recommendation': recommendations.get(
                bottleneck[0], '需要更细粒度的诊断数据'
            ),
            'factor_trends': {
                k: round(t.trend(), 4) for k, t in self._factors.items()
            },
        }

    def _record_plateau(self):
        diag = self.diagnose()
        event = PlateauEvent(
            detected_at_cycle=self._total_cycles,
            current_edges=self._current_edges,
            stagnation_cycles=self._cycles_without_growth,
            diagnosis=diag.get('causal_effects', {}),
            recommendation=diag.get('recommendation', ''),
        )
        self._plateau_history.append(event)

    def plateau_report(self) -> Dict[str, Any]:
        """所有平台期事件的汇总报告."""
        if not self._plateau_history:
            return {'plateaus_detected': 0}
        return {
            'plateaus_detected': len(self._plateau_history),
            'first_at_cycle': self._plateau_history[0].detected_at_cycle,
            'last_at_cycle': self._plateau_history[-1].detected_at_cycle,
            'common_bottlenecks': self._most_common_bottleneck(),
        }

    def _most_common_bottleneck(self) -> str:
        counts: Dict[str, int] = defaultdict(int)
        for event in self._plateau_history:
            if event.diagnosis:
                sorted_d = sorted(event.diagnosis.items(), key=lambda x: x[1])
                if sorted_d:
                    counts[sorted_d[0][0]] += 1
        return max(counts, key=counts.get) if counts else 'unknown'


def plateau_early_warning(
    pca: PlateauBottleneckAnalyzer,
    patience: int = 15,
) -> Optional[Dict[str, Any]]:
    """平台期提前预警——在完全停滞前 (stagnation < threshold)
    检测增长率衰减趋势, 提前发出警告.
    """
    if pca.stagnation_cycles() < patience:
        return None
    if pca.stagnation_cycles() >= pca._stagnation_threshold:
        return pca.diagnose()
    # 检查趋势
    trends = {k: t.trend() for k, t in pca._factors.items()}
    declining = [k for k, v in trends.items() if v < -0.01]
    if declining:
        return {
            'warning': 'early',
            'stagnation_cycles': pca.stagnation_cycles(),
            'declining_factors': declining,
            'trends': {k: round(v, 4) for k, v in trends.items()},
            'message': f'因子 {", ".join(declining)} 呈下降趋势, 建议提前干预',
        }
    return None


class CounterfactualSimulator:
    """反事实模拟器 — "如果改变因子X, 覆盖率增量会怎样?"

    基于因子→覆盖率增量的历史观测建立线性回归模型,
    模拟对每个因子施加 ±10%/+20% 干预后的预测效果.
    这不是因果推断 (无 do-calculus), 而是基于观测模型的预测模拟.

    用法:
      cfs = CounterfactualSimulator(pba)
      scenarios = cfs.simulate(interventions={'seed_diversity': +0.20})
      for s in scenarios: print(f'{s[\"factor\"]}: +{s[\"predicted_gain\"]:.2f} edges')
    """

    def __init__(self, pba: PlateauBottleneckAnalyzer):
        self._pba = pba
        self._regression_coeffs: Dict[str, float] = {}
        self._intercept: float = 0.0
        self._fitted: bool = False

    def fit(self):
        """从历史观测拟合因子→覆盖率增量的线性模型."""
        factors = list(self._pba._factors.keys())
        X, y_data = [], []
        trackers = self._pba._factors
        n = min(len(trackers[factors[0]]._values) if factors else 0,
                len(trackers[factors[0]]._outcomes) if factors else 0)
        if n < 5:
            return
        for i in range(n):
            row = [1.0]
            for f in factors:
                vals = list(trackers[f]._values)
                row.append(vals[i] if i < len(vals) else 0.0)
            outcomes = list(trackers[factors[0]]._outcomes)
            X.append(row)
            y_data.append(outcomes[i] if i < len(outcomes) else 0.0)
        try:
            coeffs = _ols_solve(X, y_data)
            self._intercept = coeffs[0]
            for j, f in enumerate(factors):
                self._regression_coeffs[f] = coeffs[j + 1] if j + 1 < len(coeffs) else 0.0
            self._fitted = True
        except Exception:
            self._fitted = False

    def simulate(self, interventions: Dict[str, float],
                 n_scenarios: int = 5) -> List[Dict[str, Any]]:
        """模拟干预效果 — 返回各因子的预测增益排序."""
        if not self._fitted:
            self.fit()
        if not self._fitted:
            return [{'error': 'insufficient_data_for_simulation'}]

        scenarios = []
        baseline_factors = {}
        for name, tracker in self._pba._factors.items():
            vals = list(tracker._values)
            baseline_factors[name] = sum(vals[-10:]) / min(10, len(vals)) if vals else 0.5

        for factor, delta_pct in interventions.items():
            if factor not in baseline_factors:
                continue
            current_val = baseline_factors[factor]
            # 生成 n_scenarios 个反事实值: 当前 ± delta
            deltas = [current_val * (1 + delta_pct * k / n_scenarios)
                      for k in range(1, n_scenarios + 1)]
            for d_idx, cf_val in enumerate(deltas):
                cf_factors = dict(baseline_factors)
                cf_factors[factor] = cf_val
                pred = self._intercept
                for f, coeff in self._regression_coeffs.items():
                    pred += coeff * cf_factors.get(f, 0.5)
                scenarios.append({
                    'factor': factor,
                    'current_value': round(current_val, 4),
                    'counterfactual_value': round(cf_val, 4),
                    'delta_pct': round((cf_val / max(0.01, current_val) - 1) * 100, 1),
                    'predicted_edge_gain': round(max(0, pred), 3),
                })
        scenarios.sort(key=lambda s: s['predicted_edge_gain'], reverse=True)
        return scenarios

    def best_intervention(self) -> Dict[str, Any]:
        """返回预期收益最高的单一干预."""
        all_sims = self.simulate(
            {f: 0.20 for f in self._pba._factors.keys()}, n_scenarios=1
        )
        valid = [s for s in all_sims if 'error' not in s]
        return valid[0] if valid else {}


def _ols_solve(X: List[List[float]], y: List[float]) -> List[float]:
    """普通最小二乘: (X^T X)^{-1} X^T y — 小规模直接用高斯消元."""
    n, p = len(X), len(X[0])
    XtX = [[sum(X[k][i] * X[k][j] for k in range(n)) for j in range(p)] for i in range(p)]
    Xty = [sum(X[k][i] * y[k] for k in range(n)) for i in range(p)]
    aug = [XtX[i] + [Xty[i]] for i in range(p)]
    for col in range(p):
        pivot = max(range(col, p), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot][col]) < 1e-9:
            continue
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for row in range(col + 1, p):
            factor = aug[row][col] / aug[col][col]
            for j in range(col, p + 1):
                aug[row][j] -= factor * aug[col][j]
    coeffs = [0.0] * p
    for i in range(p - 1, -1, -1):
        coeffs[i] = (aug[i][p] - sum(aug[i][j] * coeffs[j] for j in range(i + 1, p))) / aug[i][i] if abs(aug[i][i]) > 1e-9 else 0.0
    return coeffs
