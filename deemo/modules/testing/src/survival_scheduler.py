# 基于事件速率分析的多Fuzzer资源调度器 — 动态分配CPU时间以最大化漏洞发现率
#
# 核心问题:
#   multi_fuzz.py 对多个fuzzer做静态语料同步, drift_calibrator.py 检测
#   单个fuzzer的覆盖停滞, 但两者均不解决资源分配问题:
#   "我有N个fuzzer变体在跑, 每个应得多少CPU时间?"
#
#   现有方案:
#     EnFuzz/Cupid: 静态等分CPU → 浪费资源在低效fuzzer上
#     autofz: 基于覆盖趋势切换fuzzer → 覆盖≠漏洞
#     BandFuzz (2025): 多臂老虎机优化覆盖 → 同上, 且假设平稳奖励分布,
#       但fuzzer的漏洞发现率随时间高度非平稳 (初期快速, 后期枯竭)
#
# 本模块的方法 — 事件速率驱动的动态调度:
#   1. 对每个fuzzer维护加权崩溃计数的时间窗口统计
#   2. 计算各fuzzer的瞬时危险率 (hazard rate) = 窗口内ESA加权崩溃数/窗口时长
#   3. 按危险率比例动态分配CPU份额——危险率高的fuzzer获得更多资源
#   4. 当某fuzzer的危险率持续低于阈值时, 触发策略切换
#   5. 可选协变量调整: 覆盖增长率/输入复杂度/漂移信号作为危险率修正因子
#
# 为什么用事件速率而非多臂老虎机:
#   - 老虎机假设平稳奖励分布; 基于时间窗口的速率估计原生处理时变风险
#   - 不需要参数分布假设 (非参数窗口统计)
#   - 天然支持删失数据 (fuzzer仍在运行但尚未发现下一个崩溃)
#   - 危险率有直观物理解释: "此刻发现新崩溃的瞬时速率"
#
# 注: 本模块使用指数加权时间窗口估计而非Kaplan-Meier乘积限估计。
#     选择窗口法而非KM的原因是:
#     1. 在线场景下窗口法计算O(1) vs KM的O(n)历史遍历
#     2. fuzzer崩溃事件的"风险集"概念不适用(各fuzzer独立运行,无共同删失时间)
#     3. 窗口法天然实现"近期偏好",适合非平稳fuzzer行为
#
# 与现有模块的接合:
#   - drift_calibrator.py: 覆盖停滞信号 → 提升该fuzzer的协变量调整因子
#   - exploit_primitive.py: ESA评分 → 对高ESA崩溃做加权
#   - multi_fuzz.py: 本模块的输出 → CPU份额重分配指令
#
# 参考文献:
#   BandFuzz (Shi et al. 2025, arXiv:2507.10845) — 多臂老虎机协同fuzzing
#   autofz (Fu et al. 2023) — 趋势驱动的动态fuzzer组合
#   Cox 1972, JRSS B 34(2):187-220 — 比例危险模型的形式借鉴

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class FuzzerState(str, Enum):
    """Fuzzer生命周期状态"""
    ACTIVE = "active"        # 正常发现崩溃
    DECLINING = "declining"  # 危险率下降, 疑似枯竭
    STALLED = "stalled"      # 长时间无新崩溃
    RETIRED = "retired"      # 已停止, 资源已回收


@dataclass
class CrashEvent:
    """单次崩溃发现事件"""
    timestamp: float                 # Unix时间戳
    crash_hash: str = ""             # 崩溃栈哈希 (用于去重)
    esa_score: float = 0.0           # 利用性评分 (来自 exploit_primitive)
    is_unique: bool = True           # 是否为新的唯一崩溃
    fuzzer_name: str = ""


@dataclass
class FuzzerProfile:
    """单个fuzzer的运行画像"""
    name: str
    state: FuzzerState = FuzzerState.ACTIVE
    cpu_share: float = 0.0            # 当前CPU份额 [0, 1]
    crash_events: List[CrashEvent] = field(default_factory=list)
    # 生存分析
    hazard_rate: float = 0.0          # 当前瞬时危险率
    median_survival_s: float = 0.0    # 中位生存时间 (秒)
    # 统计
    total_unique_crashes: int = 0
    total_weighted_crashes: float = 0.0  # ESA加权的崩溃总数
    time_since_last_crash: float = 0.0
    started_at: float = 0.0


@dataclass
class ScheduleDecision:
    """资源分配决策"""
    allocations: Dict[str, float]     # fuzzer_name → cpu_share
    retired: List[str]                # 建议停用的fuzzer
    rationale: str = ""


class HazardRateEstimator:
    """基于时间窗口的事件速率估计器。

    对每个fuzzer的事件历史估计瞬时危险率:
    h(t) = 窗口内ESA加权崩溃数 / 窗口时长.
    选择窗口法而非Kaplan-Meier的理由: fuzzer场景中各fuzzer
    独立运行无共同删失时间, 窗口法天然实现近期偏好.
    """

    def __init__(self, window_size: float = 3600.0):
        """
        window_size: 观察窗口 (秒), 超出此窗口的旧事件衰减。
        """
        self._window = window_size

    def estimate_hazard(self, events: List[CrashEvent],
                         now: float) -> Tuple[float, float]:
        """从事件历史估计危险率和中位生存时间。

        危险率 h(t) = 最近ΔT内的崩溃数 / (ΔT内观察到的总时间)
        分子: 最近 window/4 内的唯一崩溃数
        分母: window/4 (秒)

        返回 (hazard_rate, median_survival_s)。
        """
        if not events:
            return 0.0, float('inf')

        recent_window = self._window / 4.0
        cutoff = now - recent_window

        # 筛选窗口内的唯一崩溃
        recent_unique = [
            e for e in events
            if e.timestamp >= cutoff and e.is_unique
        ]

        # 计算 ESA 加权崩溃数——高ESA崩溃权重更高
        weighted_count = sum(
            0.5 + 0.5 * e.esa_score for e in recent_unique
        ) if recent_unique else 0

        if weighted_count == 0:
            return 0.0, float('inf')

        hazard = weighted_count / recent_window

        # 中位生存时间: S(T_median) = 0.5
        # S(t) ≈ exp(-h*t) 在大样本下近似成立
        if hazard > 0:
            median_s = math.log(2) / hazard
        else:
            median_s = float('inf')

        return hazard, median_s

    def survival_probability(self, events: List[CrashEvent],
                              t: float, now: float) -> float:
        """估计在接下来的 t 秒内无新崩溃的概率"""
        hazard, _ = self.estimate_hazard(events, now)
        if hazard <= 0:
            return 1.0
        return math.exp(-hazard * t)


class SurvivalAwareScheduler:
    """基于生存分析的多Fuzzer资源调度器。

    典型用法:
        scheduler = SurvivalAwareScheduler(num_fuzzers=4)
        scheduler.register_fuzzer("afl_default")
        scheduler.register_fuzzer("afl_havoc_heavy")
        # 每个同步周期:
        for fuzzer in fuzzers:
            scheduler.record_crash(fuzzer.name, crash_hash, esa_score)
        decision = scheduler.allocate()
        apply_cpu_shares(decision.allocations)
    """

    def __init__(self,
                 num_fuzzers: int = 4,
                 sync_interval_s: float = 60.0,
                 stall_threshold_s: float = 600.0,
                 decay_threshold_s: float = 300.0):
        """
        sync_interval_s: 资源重分配周期
        stall_threshold_s: 超过此时间无新崩溃 → STALLED
        decay_threshold_s: 危险率低于峰值的10%超过此时间 → DECLINING
        """
        self._sync_interval = sync_interval_s
        self._stall_threshold = stall_threshold_s
        self._decay_threshold = decay_threshold_s
        self._num_fuzzers = num_fuzzers

        self._profiles: Dict[str, FuzzerProfile] = {}
        self._estimator = HazardRateEstimator(window_size=stall_threshold_s * 2)
        self._decisions: List[ScheduleDecision] = []

        # 全局统计
        self._total_crashes_all: int = 0
        self._total_esa_weighted: float = 0.0

    def register_fuzzer(self, name: str) -> None:
        """注册新fuzzer——初始CPU份额等分"""
        self._profiles[name] = FuzzerProfile(
            name=name,
            cpu_share=1.0 / max(1, len(self._profiles) + 1),
            started_at=time.monotonic(),
        )
        self._rebalance_shares()

    def unregister_fuzzer(self, name: str) -> None:
        """移除fuzzer并回收其CPU份额"""
        self._profiles.pop(name, None)
        self._rebalance_shares()

    def record_crash(self, fuzzer_name: str, crash_hash: str = "",
                      esa_score: float = 0.0, is_unique: bool = True) -> None:
        """记录一次崩溃发现——驱动生存函数更新"""
        profile = self._profiles.get(fuzzer_name)
        if profile is None:
            return

        event = CrashEvent(
            timestamp=time.monotonic(),
            crash_hash=crash_hash,
            esa_score=esa_score,
            is_unique=is_unique,
            fuzzer_name=fuzzer_name,
        )
        profile.crash_events.append(event)
        if is_unique:
            profile.total_unique_crashes += 1
            profile.total_weighted_crashes += 0.5 + 0.5 * esa_score
        self._total_crashes_all += 1
        self._total_esa_weighted += 0.5 + 0.5 * esa_score

        # 限制事件历史长度 (保留最近256条)
        if len(profile.crash_events) > 256:
            profile.crash_events = profile.crash_events[-256:]

    def allocate(self) -> ScheduleDecision:
        """主入口: 基于各fuzzer的危险率重新分配CPU份额。

        算法:
          1. 计算每个fuzzer的当前危险率 h_i(t)
          2. 归一化所有活跃fuzzer的危险率 → cpu_share_i ∝ h_i(t)
          3. 对危险率过低的fuzzer标记为 DECLINING 或 STALLED
          4. STALLED fuzzer的CPU份额转移给ACTIVE fuzzer
        """
        now = time.monotonic()
        active_hazards: Dict[str, float] = {}
        retired: List[str] = []
        peak_hazards: Dict[str, float] = {}

        for name, profile in self._profiles.items():
            hazard, median_s = self._estimator.estimate_hazard(
                profile.crash_events, now)
            profile.hazard_rate = hazard
            profile.median_survival_s = median_s
            profile.time_since_last_crash = (
                now - profile.crash_events[-1].timestamp
                if profile.crash_events else now - profile.started_at
            )

            # 追踪峰值危险率 (用于检测衰减)
            peak_hazards[name] = max(
                hazard, peak_hazards.get(name, hazard))

            # 状态更新
            if profile.time_since_last_crash > self._stall_threshold:
                profile.state = FuzzerState.STALLED
                retired.append(name)
            elif (peak_hazards[name] > 0.001
                  and hazard < 0.1 * peak_hazards[name]
                  and profile.time_since_last_crash > self._decay_threshold):
                profile.state = FuzzerState.DECLINING
                active_hazards[name] = hazard * 0.3
            else:
                profile.state = FuzzerState.ACTIVE
                active_hazards[name] = hazard

        # 正常化CPU份额——对ACTIVE/DECLINING的fuzzer
        total_hazard = sum(active_hazards.values())
        allocations: Dict[str, float] = {}

        if total_hazard > 0:
            for name in active_hazards:
                allocations[name] = active_hazards[name] / total_hazard
        else:
            # 所有fuzzer都无产出——回退到等分
            n = max(1, len(active_hazards))
            for name in active_hazards:
                allocations[name] = 1.0 / n

        # STALLED fuzzer: 分配最小保活份额 (2%), 用于检测是否恢复
        for name in retired:
            allocations[name] = 0.02

        # 更新 profile 中的份额
        for name, share in allocations.items():
            if name in self._profiles:
                self._profiles[name].cpu_share = share

        # 重新归一化确保总和=1
        total = sum(allocations.values())
        if total > 0:
            allocations = {k: v / total for k, v in allocations.items()}

        decision = ScheduleDecision(
            allocations=allocations,
            retired=retired,
            rationale=self._build_rationale(retired, active_hazards, now),
        )
        self._decisions.append(decision)
        return decision

    def _rebalance_shares(self) -> None:
        """内部: 重新等分所有fuzzer的CPU份额 (用于初始化和fuzzer增删时)"""
        n = max(1, len(self._profiles))
        for profile in self._profiles.values():
            profile.cpu_share = 1.0 / n

    def _build_rationale(self, retired: List[str],
                          hazards: Dict[str, float], now: float) -> str:
        lines = []
        for name, profile in self._profiles.items():
            lines.append(
                f"{name}: state={profile.state.value}, "
                f"h={profile.hazard_rate:.4f}, "
                f"share={profile.cpu_share:.1%}, "
                f"crashes={profile.total_unique_crashes}")
        if retired:
            lines.append(f"已停用: {', '.join(retired)}")
        return "\n".join(lines)

    # ---- 查询 ----

    def best_fuzzer(self) -> Optional[str]:
        """当前危险率最高的fuzzer"""
        best, best_h = None, -1.0
        for name, p in self._profiles.items():
            if p.hazard_rate > best_h:
                best, best_h = name, p.hazard_rate
        return best

    def should_switch_strategy(self, fuzzer_name: str) -> bool:
        """判断某fuzzer是否应切换策略 (用于对接 drift_calibrator)"""
        p = self._profiles.get(fuzzer_name)
        if p is None:
            return False
        return p.state in (FuzzerState.DECLINING, FuzzerState.STALLED)

    def stats(self) -> Dict[str, Any]:
        return {
            "fuzzers": len(self._profiles),
            "total_crashes": self._total_crashes_all,
            "total_esa_weighted": round(self._total_esa_weighted, 3),
            "profiles": {
                name: {
                    "state": p.state.value,
                    "hazard_rate": round(p.hazard_rate, 6),
                    "cpu_share": round(p.cpu_share, 4),
                    "unique_crashes": p.total_unique_crashes,
                    "weighted_crashes": round(p.total_weighted_crashes, 3),
                    "time_since_last_crash_s": round(
                        p.time_since_last_crash, 1),
                }
                for name, p in self._profiles.items()
            },
        }

    def reset(self) -> None:
        self._profiles.clear()
        self._decisions.clear()
        self._total_crashes_all = 0
        self._total_esa_weighted = 0.0


# ============================================================
# 扩展: Cox比例危险模型 — 协变量感知的危险率预测
# ============================================================

class HeuristicCovariateAdjuster:
    """启发式协变量调整器——使用Cox模型的形式但系数为手动设定。

    不依赖MLE拟合, 系数基于领域经验预设。
    协变量:
      - coverage_growth_rate: 覆盖增长率 (来自 drift_calibrator)
      - input_complexity: 输入复杂度 (平均字节熵)
      - corpus_diversity: 语料库多样性 (唯一种子数/总种子数)

    注: 类名中使用"Cox模型的形式"指 h_adjusted = h_base × exp(Σ β_i·x_i),
    但β_i非通过部分似然最大化拟合——为预设经验值。
    """

    # 协变量系数 (基于领域经验手动设定)
    _COEFFICIENTS = {
        'coverage_growth': 0.8,       # 正相关: 覆盖增长快→更可能发现新崩溃
        'input_complexity': 0.3,      # 弱正相关: 复杂输入发现深层bug
        'corpus_diversity': 0.5,      # 正相关: 多样性高→探索更广
        'drift_indicator': -1.2,      # 负相关: 漂移信号→更不可能发现
    }

    def adjust_hazard(self, base_hazard: float,
                       covariates: Dict[str, float]) -> float:
        """用协变量调整基准危险率。

        h_adjusted = h_base * exp(Σ β_i * x_i)
        """
        log_hr = 0.0
        for cov, value in covariates.items():
            beta = self._COEFFICIENTS.get(cov, 0.0)
            log_hr += beta * value
        # 裁剪调整因子到合理范围 [0.1, 10.0]
        factor = math.exp(max(-2.3, min(2.3, log_hr)))
        return base_hazard * factor


# ============================================================
# 便捷入口
# ============================================================

def quick_schedule(fuzzer_crash_counts: Dict[str, List[float]],
                   stall_s: float = 600.0,
                   ) -> ScheduleDecision:
    """便捷入口: 给定各fuzzer的崩溃时间戳列表, 返回资源分配决策。

    fuzzer_crash_counts: {fuzzer_name: [crash_timestamps]}。
    crash_timestamps 为 time.monotonic() 时间戳列表。
    """
    scheduler = SurvivalAwareScheduler(
        num_fuzzers=len(fuzzer_crash_counts),
        stall_threshold_s=stall_s,
    )
    now = time.monotonic()
    for name, timestamps in fuzzer_crash_counts.items():
        scheduler.register_fuzzer(name)
        for ts in timestamps:
            scheduler.record_crash(
                name, crash_hash=f"{name}_{ts:.0f}", is_unique=True)
    return scheduler.allocate()
