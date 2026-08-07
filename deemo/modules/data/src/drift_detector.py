# 流式二进制特征漂移检测 (Streaming Binary Profile Drift Detection)
#
# 检测二进制签名流中特征分布的统计漂移, 面向两类场景:
#   a) 编译环境变化检测: 同一项目的 binary 突然改变了编译器特征
#      (节数量、熵分布、导入函数集合), 可能指示供应链攻击.
#   b) 分析结果质量监控: 去重流水线各阶段的输出统计量偏离基线,
#      预警上游数据源变化或工具异常.
#
# 创新点:
#   1. Beta-Bernoulli 共轭在线更新: 对每个 binary 特征维度的 0/1 事件
#      (如"某 section 是否出现")维护 Beta(α,β) 后验. 新观测到来时
#      O(1) 更新后验参数, 无需存储历史数据.
#   2. CUSUM 累积漂移信号: 对连续特征 (熵、大小) 计算标准化残差的
#      累积和, 当 CUSUM 超过动态阈值时宣告漂移. 动态阈值由历史
#      CUSUM 分布的分位数自适应推导, 避免固定阈值对新老数据分布的不适配.
#   3. 多维联合漂移判定: 单维度的轻微漂移可能只是噪声, 但当 >= τ 个维度
#      同时触发信号时, 宣告系统性漂移. τ = ⌈√d⌉ (维度数的平方根),
#      在误报率和检测延迟间取得平衡.
#   4. 漂移归因: 触发后自动列出贡献最大的 Top-k 特征维度 + 它们的方向
#      (均值↑/↓)和幅度 (标准差变化倍数), 辅助分析师定位根因.
#
# 与现有工作的区别:
#   - Domino Drift Effect: 依赖 Pearson 相关矩阵 + 多检测器,
#     对 binary 特征不适用 (Pearson 不适用于 Bernoulli).
# MCD-DD: 需要对比学习嵌入, 计算成本高.
# ADWIN: 单维度滑动窗口, 无联合判定.
#   本方案专为 binary analysis 的多维 Bernoulli+连续混合特征设计,
#   无需训练, O(d) 每观测更新, 内存 O(d).

import math
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from .analysis_types import DriftDimension, DriftReport

class BinaryFeatureProfile:
    """二进制签名的多维特征剖面.

    混合 Bernoulli 特征 (0/1 出现) 和连续特征 (对数/归一化值).
    维度定义:
      Bernoulli: has_code_section, has_data_section, has_debug_info,
                 is_stripped, has_tls, has_imports, has_exports, ...
      Continuous: log(file_size), byte_entropy, section_count,
                  import_count, symbol_count, compression_ratio, ...
    """

    BERNOULLI_DIMS = [
        "has_code_section", "has_data_section", "has_debug_info",
        "is_stripped", "has_tls", "has_relocations",
        "has_imports", "has_exports", "has_dynamic_symbols",
        "has_unwind_info", "is_pie", "is_nx_compatible",
    ]

    CONTINUOUS_DIMS = [
        "log_file_size", "byte_entropy",
        "section_count", "import_count",
        "symbol_count", "compression_ratio",
    ]

    @classmethod
    def dim_count(cls) -> int:
        return len(cls.BERNOULLI_DIMS) + len(cls.CONTINUOUS_DIMS)

class StreamingDriftDetector:
    """流式统计漂移检测器.

    参数:
      warmup_batches: 基线建立所需的最小观测批次数.
      joint_threshold_ratio: 联合漂移判定需触发的维度比例,
        默认 sqrt(|dims|)/|dims|.
      cusum_sensitivity: CUSUM 灵敏度, 值越小对漂移越敏感.
      bernoulli_prior_strength: Beta 先验强度, 越大则基线建立越慢.
      history_window: 保留的最近漂移事件数.
    """

    def __init__(self, warmup_batches: int = 20,
                 joint_threshold_ratio: float = None,
                 cusum_sensitivity: float = 0.5,
                 bernoulli_prior_strength: float = 2.0,
                 history_window: int = 100):
        self.warmup = warmup_batches
        self.cusum_k = cusum_sensitivity
        self.prior_strength = bernoulli_prior_strength
        self.history = deque(maxlen=history_window)

        # Bernoulli 维度: 每维 (α, β) → Beta 后验均值 α/(α+β)
        n_b = len(BinaryFeatureProfile.BERNOULLI_DIMS)
        ps = bernoulli_prior_strength
        self._b_alpha = [ps] * n_b
        self._b_beta = [ps] * n_b

        # 连续维度: 每维的累积统计量
        n_c = len(BinaryFeatureProfile.CONTINUOUS_DIMS)
        self._c_sum = [0.0] * n_c
        self._c_sumsq = [0.0] * n_c
        self._c_count = 0

        # 连续维度的 CUSUM 状态 (正负方向独立跟踪)
        self._cusum_pos = [0.0] * n_c
        self._cusum_neg = [0.0] * n_c
        self._cusum_thresholds = [1.0] * n_c  # 动态阈值, 随基线更新

        # 联合判定阈值
        total_dims = n_b + n_c
        self.joint_threshold = joint_threshold_ratio or max(
            2, int(math.sqrt(total_dims))
        )

        self._batch_count = 0
        self._warmed_up = False
        self._last_drift_at: Optional[float] = None

    @property
    def is_warm(self) -> bool:
        return self._warmed_up

    def observe(self, profile: dict) -> Optional["DriftReport"]:
        """观测一个 binary 的特征剖面, 返回 DriftReport 或 None.

        profile 应包含 BERNOULLI_DIMS 和 CONTINUOUS_DIMS 中的所有键.
        """
        self._batch_count += 1

        # 更新 Bernoulli 后验
        b_signals = []
        for i, dim in enumerate(BinaryFeatureProfile.BERNOULLI_DIMS):
            val = profile.get(dim, 0)
            v = 1 if val else 0
            self._b_alpha[i] += v
            self._b_beta[i] += (1 - v)

            if self._warmed_up:
                # 当前观测相对于基线的异常程度: 用后验预测 p 值的近似
                prior_mean = self._b_alpha[i] / (
                    self._b_alpha[i] + self._b_beta[i])
                # 若当前为 1 但基线均值 < 0.1 → 正向漂移信号
                # 若当前为 0 但基线均值 > 0.9 → 负向漂移信号
                signal = 0.0
                if v == 1 and prior_mean < 0.3:
                    signal = 0.3 - prior_mean
                elif v == 0 and prior_mean > 0.7:
                    signal = prior_mean - 0.7
                b_signals.append(signal)
            else:
                b_signals.append(0.0)

        # 更新连续维度统计 + CUSUM
        c_signals = []
        for i, dim in enumerate(BinaryFeatureProfile.CONTINUOUS_DIMS):
            val = float(profile.get(dim, 0.0))
            self._c_sum[i] += val
            self._c_sumsq[i] += val * val
            self._c_count += 0  # 修复: 在循环外统增

        self._c_count += 1  # 每观测一次所有连续维度计数 +1

        for i, dim in enumerate(BinaryFeatureProfile.CONTINUOUS_DIMS):
            val = float(profile.get(dim, 0.0))
            if self._c_count < 5 or not self._warmed_up:
                c_signals.append(0.0)
                continue

            mean = self._c_sum[i] / self._c_count
            var = self._c_sumsq[i] / self._c_count - mean * mean
            std = math.sqrt(max(var, 1e-9))

            # 标准化残差: (x - μ) / σ
            z = (val - mean) / std if std > 1e-9 else 0.0

            # CUSUM 更新
            self._cusum_pos[i] = max(0, self._cusum_pos[i] + z - self.cusum_k)
            self._cusum_neg[i] = max(0, self._cusum_neg[i] - z - self.cusum_k)

            # 动态阈值: 基于历史 CUSUM 的滚动分位数 (简化: 基线std的倍数)
            if self._batch_count % 10 == 0:
                self._cusum_thresholds[i] = max(3.0, 4.0 * std)

            triggered = (
                self._cusum_pos[i] > self._cusum_thresholds[i] or
                self._cusum_neg[i] > self._cusum_thresholds[i]
            )
            c_signals.append(1.0 if triggered else 0.0)

        # combine all dimension signals
        all_signals = b_signals + c_signals
        # Bernoulli signals are continuous [0, ~0.3], not binary
        # Make them comparable: normalize to [0, 1]
        bern_triggered = sum(1 for s in b_signals if s > 0.05)
        cont_triggered = sum(1 for s in c_signals if s > 0.5)

        total_triggered = bern_triggered + cont_triggered

        # 联合判定
        if not self._warmed_up:
            if self._batch_count >= self.warmup:
                self._warmed_up = True
            return None

        if total_triggered < self.joint_threshold:
            return None

        # 生成漂移报告
        self._last_drift_at = time.time()
        report = self._build_report(profile, b_signals, c_signals,
                                     total_triggered)
        self.history.append(report)
        return report

    def observe_batch(self, profiles: List[dict]) -> List["DriftReport"]:
        """批量观测, 返回所有漂移报告."""
        reports = []
        for p in profiles:
            r = self.observe(p)
            if r is not None:
                reports.append(r)
        return reports

    def _build_report(self, profile: dict,
                       b_signals: List[float], c_signals: List[float],
                       total_triggered: int) -> "DriftReport":
        """构造漂移报告, 归因到 Top-K 贡献维度."""
        # Bernoulli 维度归因
        b_contribs = []
        for i, dim in enumerate(BinaryFeatureProfile.BERNOULLI_DIMS):
            if b_signals[i] > 0.05:
                mean = self._b_alpha[i] / (self._b_alpha[i] + self._b_beta[i])
                direction = "up" if profile.get(dim, 0) else "down"
                b_contribs.append(DriftDimension(
                    name=dim, dim_type="bernoulli",
                    baseline_mean=round(mean, 4),
                    current_value=profile.get(dim, 0),
                    signal_strength=round(b_signals[i], 4),
                    direction=direction,
                ))

        # 连续维度归因
        c_contribs = []
        for i, dim in enumerate(BinaryFeatureProfile.CONTINUOUS_DIMS):
            if c_signals[i] > 0.5:
                mean = self._c_sum[i] / max(self._c_count, 1)
                current = profile.get(dim, 0.0)
                direction = "up" if current > mean else "down"
                c_contribs.append(DriftDimension(
                    name=dim, dim_type="continuous",
                    baseline_mean=round(mean, 4),
                    current_value=round(current, 4),
                    signal_strength=round(
                        max(self._cusum_pos[i], self._cusum_neg[i]), 4),
                    direction=direction,
                ))

        # 合并并按信号强度降序
        all_contribs = b_contribs + c_contribs
        all_contribs.sort(key=lambda x: x.signal_strength, reverse=True)

        return DriftReport(
            timestamp=time.time(),
            triggered_dimensions=total_triggered,
            total_dimensions=len(b_signals) + len(c_signals),
            top_contributors=all_contribs[:8],
            batch_count=self._batch_count,
        )

    def reset_cusum(self):
        """重置 CUSUM 累加器 —— 漂移确认并处理后的恢复操作."""
        n_c = len(BinaryFeatureProfile.CONTINUOUS_DIMS)
        self._cusum_pos = [0.0] * n_c
        self._cusum_neg = [0.0] * n_c

    def baseline_stats(self) -> dict:
        """返回当前基线的统计摘要."""
        b_means = []
        for i in range(len(BinaryFeatureProfile.BERNOULLI_DIMS)):
            m = self._b_alpha[i] / (self._b_alpha[i] + self._b_beta[i])
            b_means.append(round(m, 4))

        c_means = []
        for i in range(len(BinaryFeatureProfile.CONTINUOUS_DIMS)):
            m = self._c_sum[i] / max(self._c_count, 1)
            c_means.append(round(m, 4))

        return {
            "bernoulli_means": dict(zip(
                BinaryFeatureProfile.BERNOULLI_DIMS, b_means)),
            "continuous_means": dict(zip(
                BinaryFeatureProfile.CONTINUOUS_DIMS, c_means)),
            "observations": self._c_count,
            "warmed_up": self._warmed_up,
            "cusum_thresholds": [round(t, 4) for t in self._cusum_thresholds],
        }

__all__ = ["StreamingDriftDetector", "BinaryFeatureProfile"]
