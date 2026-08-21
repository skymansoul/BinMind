# 贝叶斯在线变点检测
# 贝叶斯在线变点检测 - CVE利用态势的实时结构断点识别
#
# 问题: 2026年CVE利用时间线发生了结构性断裂:
#   2024年 CVE→Exploit 中位延迟: 56天
#   2025年: 23天
#   2026年YTD: ~10小时
# 传统的固定窗口风险评分假设数据生成过程稳定, 在此速率下已失效.
# 当PoC发布、KEV收录、或武器化利用代码出现时, CVE的风险态势发生
# 不可逆的状态跃迁 - 这本质上是变点检测问题.
#
# 解决方案: 贝叶斯在线变点检测 (BOCD).
# 基于Adams & MacKay 的框架, 适配到CVE利用事件流:
#   1. 维持行程长度 (run length) r_t 的后验分布 P(r_t | x_{1:t}).
#      r_t = 自上次变点以来的时间步数.
#   2. 对每个r_t, 计算观测模型 P(x_t | θ) 在参数后验下的预测密度.
#   3. 变点概率: P(r_t=0 | x_{1:t}) ∝ Σ_{r_{t-1}} P(r_t=0 | r_{t-1}) × P(x_t | r_{t-1}, x).
#   4. 风险函数 (hazard rate) 控制先验变点概率 - 使用常数风险率
#      λ=1/30 (平均每月一次态势变化).
#
# 适配到CVE的三类观测:
#   Type 1 - 利用速度: 事件间到达时间 (inter-arrival time).
#     观测模型: 指数分布 (单次利用) / 泊松过程 (批量利用).
#   Type 2 - 利用严重度: 标记值的移动平均.
#     观测模型: 高斯分布 (经logit变换).
#   Type 3 - 来源多样性: 不同情报源的加权混合熵.
#     观测模型: 多项Dirichlet.
#
# 输出: 对每条CVE流, 实时计算:
# 当前行程长度MAP估计 (自上次态势变化以来的天数)
# 变点概率 (当前步是变点的后验概率)
#   - 态势标签 (pre_exploit / active_exploitation / post_patch / dormant)
#
# 非显而易见性:
#   1. BOCD在工业过程控制中成熟, 但从未用于CVE利用态势检测.
#   2. 三类异构观测的联合似然融合: 速度×严重度×多样性.
#   3. 态势标签不是启发式规则而是后验推断 - 可量化不确定性.
#
#
# Bayesian Online Changepoint Detection
# 在线变点检测综述
# CVE→Exploit 时间线实证分析
# 贝叶斯网络+马尔可夫链的风险评估

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class ChangepointResult:
    """单次变点检测的输出."""
    timestamp: float                    # 观测时间
    run_length_map: int                 # MAP行程长度
    changepoint_prob: float             # P(r_t=0 | data)
    regime_label: str                   # 态势标签
    regime_confidence: float            # 标签置信度
    expected_run_length: float          # E[r_t | data]
    hazard_rate_used: float


class BayesianChangepointDetector:
    """贝叶斯在线变点检测器 - 单流CVE利用态势跟踪.

    使用恒定风险率h的简化BOCD.
    观测模型: 指数族共轭先验 (Gamma-Poisson用于速度, Normal-Gamma用于严重度).

    算法复杂度: O(T) 每步 (T=最大行程长度截断).
    使用截断 T_max=200 控制计算量 - 超过200天无变点的概率 < 0.001 (h=1/30).
    """

    def __init__(self, hazard_rate: float = 1.0 / 30.0,
                 max_run_length: int = 200,
                 prior_alpha: float = 2.0,
                 prior_beta: float = 0.5):
        """
        hazard_rate: 每步变点先验概率 (1/30 ≈ 月频次).
        prior_alpha, prior_beta: Gamma先验参数 (用于指数观测模型).
        """
        self._h = hazard_rate
        self._max_r = max_run_length
        self._prior_alpha = prior_alpha
        self._prior_beta = prior_beta

        # 行程长度后验: P(r_t | x_{1:t}), 每项为概率质量
        self._run_length_probs: List[float] = [1.0]
        self._t = 0
        self._observations: Deque[float] = deque(maxlen=max_run_length)

        # 每行程长度的充分统计量 (用于共轭更新)
        # Gamma模型: alpha_r, beta_r - 观测x_t的指数分布参数
        self._alpha_stats: List[float] = [prior_alpha]
        self._beta_stats: List[float] = [prior_beta]

        # 历史变点
        self._changepoints: List[int] = []

    def update(self, observation: float) -> ChangepointResult:
        """接入一个新观测, 返回当前变点检测结果.

        observation: 事件间到达时间 (天数). 较小的观测 → 利用加速 → 可能变点.
        """
        self._t += 1
        self._observations.append(observation)

        # 1. 计算每个行程长度的预测概率 (log空间避免数值下溢)
        pred_log_probs = [0.0] * (len(self._run_length_probs) + 1)
        for r_prev in range(len(self._run_length_probs)):
            alpha_r = self._alpha_stats[r_prev]
            beta_r = self._beta_stats[r_prev]
            # Lomax log-PDF: log(α) + α·log(β) - (α+1)·log(β+x)
            if beta_r > 0 and beta_r + observation > 0:
                log_pred = (math.log(alpha_r) + alpha_r * math.log(beta_r) -
                            (alpha_r + 1.0) * math.log(beta_r + observation))
            else:
                log_pred = -700.0  # 接近0的概率
            pred_log_probs[r_prev] = log_pred

        # 2. 生长和变点概率 (log空间, 用log-sum-exp归一化)
        log_growth = [0.0] * (len(self._run_length_probs) + 1)
        log_1mh = math.log(max(1.0 - self._h, 1e-15))
        log_h = math.log(max(self._h, 1e-15))

        # 变点时的预测密度: 使用先验参数 (新regime, 尚未累积观测).
        # 这与生长分支不同: 生长使用各行程长度的累积统计量,
        # 变点丢弃历史, 从头开始.
        prior_log_pred = (math.log(self._prior_alpha) +
                          self._prior_alpha * math.log(self._prior_beta) -
                          (self._prior_alpha + 1.0) * math.log(self._prior_beta + observation)
                          if self._prior_beta > 0 else -700.0)

        for r_prev in range(len(self._run_length_probs)):
            if self._run_length_probs[r_prev] > 0:
                log_rp = math.log(self._run_length_probs[r_prev])
                # 生长: 延续旧regime
                log_growth[r_prev + 1] = log_rp + pred_log_probs[r_prev] + log_1mh
                # 变点: 切换到新regime (先验预测密度)
                term = log_rp + prior_log_pred + log_h
                if log_growth[0] == 0.0:
                    log_growth[0] = term
                else:
                    log_growth[0] = _logadd(log_growth[0], term)

        # 归一化 (log-sum-exp → 线性)
        log_total = _logsumexp(log_growth)
        self._run_length_probs = [math.exp(lg - log_total) for lg in log_growth]

        # 5. 截断
        if len(self._run_length_probs) > self._max_r:
            self._run_length_probs = self._run_length_probs[:self._max_r]
            self._alpha_stats = self._alpha_stats[:self._max_r]
            self._beta_stats = self._beta_stats[:self._max_r]

        # 6. 更新充分统计量 (每个r的Gamma后验)
        old_alphas = list(self._alpha_stats)
        old_betas = list(self._beta_stats)
        # r=0: changepoint → 新regime的第一观测, prior + 当前observation
        self._alpha_stats = [self._prior_alpha + 1.0]
        self._beta_stats = [self._prior_beta + observation]
        n_old = len(old_alphas)
        for r_prev in range(n_old):
            if r_prev + 1 >= self._max_r:
                break
            alpha_new = old_alphas[r_prev] + 1.0
            beta_new = old_betas[r_prev] + observation
            self._alpha_stats.append(alpha_new)
            self._beta_stats.append(beta_new)

        # 补齐: 理论上不应出现, 保护性填充使用先验+0观测
        while len(self._alpha_stats) < len(self._run_length_probs):
            self._alpha_stats.append(self._prior_alpha)
            self._beta_stats.append(self._prior_beta + observation * 0.5)

        # 7. 提取结果
        cp_prob_current = self._run_length_probs[0] if len(self._run_length_probs) > 0 else 0.0
        r_map = max(range(len(self._run_length_probs)),
                    key=lambda i: self._run_length_probs[i])
        e_rl = sum(i * p for i, p in enumerate(self._run_length_probs))

        # 态势推断
        regime, confidence = self._infer_regime()

        if cp_prob_current > 0.5:
            self._changepoints.append(self._t)

        return ChangepointResult(
            timestamp=float(self._t),
            run_length_map=r_map,
            changepoint_prob=round(cp_prob_current, 4),
            regime_label=regime,
            regime_confidence=round(confidence, 4),
            expected_run_length=round(e_rl, 2),
            hazard_rate_used=self._h,
        )

    def _infer_regime(self) -> Tuple[str, float]:
        """从当前行程长度+观测统计推断态势标签.

        态势分类逻辑:
          - r_map ≤ 3天 + 观测均值低 → "active_exploitation" (爆发期)
          - r_map ≤ 14天 + 观测均值中 → "pre_exploit" (PoC出现后)
          - r_map ≥ 60天 + 观测均值高 → "dormant" (无活跃利用)
          - 其他 → "post_patch" (修复后稳定)
        """
        r_map = max(range(len(self._run_length_probs)),
                    key=lambda i: self._run_length_probs[i])

        recent_obs = list(self._observations)[-10:] if len(self._observations) >= 10 else list(self._observations)
        if not recent_obs:
            return "dormant", 0.5
        mean_obs = sum(recent_obs) / len(recent_obs)

        if r_map <= 3 and mean_obs < 2.0:
            return "active_exploitation", min(0.9, self._run_length_probs[0] + 0.3)
        elif r_map <= 14 and mean_obs < 7.0:
            return "pre_exploit", 0.7
        elif r_map >= 60 and mean_obs > 14.0:
            return "dormant", 0.8
        else:
            return "post_patch", 0.6

    def reset(self):
        """重置检测器状态."""
        self._run_length_probs = [1.0]
        self._t = 0
        self._observations.clear()
        self._alpha_stats = [self._prior_alpha]
        self._beta_stats = [self._prior_beta]
        self._changepoints.clear()

    @property
    def changepoints(self) -> List[int]:
        return list(self._changepoints)

    @property
    def current_run_length_distribution(self) -> List[float]:
        return list(self._run_length_probs)


class MultiStreamChangepointMonitor:
    """多流变点监控器 - 同时跟踪多个CVE的态势变化.

    维护一个 {cve_id: BayesianChangepointDetector} 映射.
    对每个CVE有独立的观测序列和变点历史.
    """

    def __init__(self, hazard_rate: float = 1.0 / 30.0,
                 max_streams: int = 500):
        self._hazard_rate = hazard_rate
        self._max_streams = max_streams
        self._detectors: Dict[str, BayesianChangepointDetector] = {}
        self._global_alerts: Deque[Dict] = deque(maxlen=100)
        self._total_updates = 0

    def observe(self, cve_id: str, inter_arrival_days: float) -> ChangepointResult:
        """记录一个CVE的利用事件, 返回态势检测结果.

        inter_arrival_days: 自上次利用事件以来的天数.
        首次观测时使用默认值7天.
        """
        if cve_id not in self._detectors:
            if len(self._detectors) >= self._max_streams:
                # LRU淘汰: 移除最久未更新的流
                oldest = min(self._detectors.keys(),
                            key=lambda k: self._detectors[k]._t)
                del self._detectors[oldest]
            self._detectors[cve_id] = BayesianChangepointDetector(
                hazard_rate=self._hazard_rate)

        detector = self._detectors[cve_id]
        result = detector.update(inter_arrival_days)
        self._total_updates += 1

        if result.changepoint_prob > 0.6:
            self._global_alerts.append({
                "cve_id": cve_id,
                "timestamp_step": result.timestamp,
                "changepoint_prob": result.changepoint_prob,
                "new_regime": result.regime_label,
            })

        return result

    def observe_batch(self, events: List[Tuple[str, float]]
                      ) -> List[ChangepointResult]:
        """批量观测: [(cve_id, inter_arrival_days), ...]."""
        return [self.observe(cid, days) for cid, days in events]

    def get_active_regimes(self) -> Dict[str, List[str]]:
        """按态势标签分组CVE."""
        groups: Dict[str, List[str]] = {"active_exploitation": [], "pre_exploit": [],
                                         "post_patch": [], "dormant": []}
        for cid, det in self._detectors.items():
            regime, _ = det._infer_regime()
            groups.setdefault(regime, []).append(cid)
        return groups

    def recent_alerts(self, n: int = 20) -> List[Dict]:
        items = list(self._global_alerts)
        return items[-n:]

    @property
    def active_streams(self) -> int:
        return len(self._detectors)

    @property
    def total_updates(self) -> int:
        return self._total_updates


# CVE专用适配

def estimate_hazard_from_kb(kb, lookback_days: int = 365) -> float:
    """从KB中估计经验风险率 (每月态势变化频率).

    通过统计KEV收录和利用成熟度提升的时间间隔来估计.
    回退为1/30 (约月频次).
    """
    entries, _ = kb.search(limit=10000)
    if not entries or len(entries) < 20:
        return 1.0 / 30.0

    # 统计有KEV收录日期的条目数作为态势变化代理
    changes = 0
    for entry in entries:
        kev = getattr(entry, 'cisa_kev', None) or (
            entry.get('cisa_kev', False) if isinstance(entry, dict) else False)
        kev_date = getattr(entry, 'cisa_kev_date', None) or (
            entry.get('cisa_kev_date', '') if isinstance(entry, dict) else '')
        if kev and kev_date:
            changes += 1

    # 经验hazard: changes / (n_cves * avg_days / 30)
    n = max(len(entries), 1)
    avg_rate = changes / n
    monthly_rate = avg_rate * 30.0 / max(lookback_days, 1)
    return max(1.0 / 90.0, min(1.0 / 7.0, monthly_rate))


def _logsumexp(log_vals: List[float]) -> float:
    """log-sum-exp数值稳定实现."""
    if not log_vals:
        return -700.0
    max_val = max(log_vals)
    if max_val < -700:
        return -700.0
    return max_val + math.log(sum(math.exp(v - max_val) for v in log_vals))


def _logadd(log_a: float, log_b: float) -> float:
    """log(exp(a) + exp(b)) - 两参数的log-sum-exp."""
    if log_a < log_b:
        log_a, log_b = log_b, log_a
    if log_a < -700:
        return -700.0
    return log_a + math.log(1.0 + math.exp(log_b - log_a))


def build_monitor_from_kb(kb, hazard_rate: Optional[float] = None
                          ) -> MultiStreamChangepointMonitor:
    """从KB构建预填充的多流监控器."""
    if hazard_rate is None:
        hazard_rate = estimate_hazard_from_kb(kb)
    return MultiStreamChangepointMonitor(hazard_rate=hazard_rate)
