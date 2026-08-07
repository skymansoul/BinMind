# 修改记录:
# 2025-07-19 13:14 - 增加 hysteresis band 防抖机制
# 2025-07-22 10:37 - 引入 integral accumulator，解决稳态误差问题
# 2025-07-26 15:03 - 增加 converg detector，长期稳定后冻结阈值

"""带滞环防抖的自适应阈值控制器

path_diversity_core.py 中的 _auto_adjust_threshold 是比例控制器：
探索速度 < 0.5/s → 降阈值 0.02
探索速度 > 5/s → 升阈值 0.02

比例控制在 23 个离散状态上运作（阈值 0.50-0.95，step 0.02）
当探索速度在 0.4-0.6 间振荡时——交替循环的程序容易触发——
阈值在相邻两值间跳变，导致簇边界反复移动，增加不必要的重聚类开销

本模块提供 PID 风格的阈值控制器，叠加在原有控制器之上：
a. Hysteresis band: 进入新阈值后，只有探索速度持续偏离超过 band 宽度
才允许再次改变，防止阈值在相邻值间跳动
b. Integral accumulator: 累积历史偏差，消除比例控制无法解决的稳态误差
（如探索速度稳定在 0.45/s——比例控制不会调整，积分项会）
c. Dead zone: 速度在 [target_low, target_high] 内时不做任何调整
d. Converg detector: 连续 N 次无需调整后冻结阈值，节省计算
e. Sigmoid 压缩: 将阈值调整量映射到 [-0.04, +0.04]，比固定步长 ±0.02 更精细

ref: KLEE 的启发式搜索策略无阈值自适应
ref: DiversePath 使用固定阈值，未涉及自适应调整
本模块的比例-积分结构受工业 PID 控制器的积分项启发，但应用于符号执行的
路径多样性管理场景是新的——离散阈值空间中的滞环控制
"""

import math
import time
from typing import Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ControllerState:
    current_threshold: float = 0.80
    last_adjustment_time: float = 0.0
    last_adjustment_direction: int = 0      # -1降, 0不变, +1升
    integral_accumulator: float = 0.0
    consecutive_stable: int = 0
    is_frozen: bool = False
    total_adjustments: int = 0
    oscillation_count: int = 0              # 方向翻转次数


class OscillationDampedController:
    """滞环防抖 + 积分项 + 收敛检测的阈值控制器
    
    使用模式：
    controller = OscillationDampedController(initial_threshold=0.80)
    对每个 epoch:
    veloci = measure_exploration_veloci()
    new_threshold = controller.adjust(veloci)
    # controller.threshold_is_frozen → 跳过重聚类
    """

    def __init__(self,
                 initial_threshold: float = 0.80,
                 hysteresis_band: float = 0.06,
                 target_low: float = 0.5,
                 target_high: float = 5.0,
                 integral_limit: float = 0.12,
                 convergence_rounds: int = 20):
        """
        hysteresis_band: 进入新阈值后，速度需偏离 target 区间超过此值
        才允许再次调整。band 越大防抖越强，但响应越慢
        target_low/high: 理想探索速度区间 (条/秒)。区间内不调整
        integral_limit: 积分项累积上限，防止 windup
        convergence_rounds: 连续稳定轮数后冻结阈值
        """
        self._state = ControllerState(current_threshold=initial_threshold)
        self._hysteresis_band = hysteresis_band
        self._target_low = target_low
        self._target_high = target_high
        self._integral_limit = integral_limit
        self._convergence_rounds = convergence_rounds
        self._adjustment_history: list = []  # 最近 32 次调整记录，诊断用

    def adjust(self, exploration_velocity: float) -> float:
        """根据当前探索速度计算新阈值
        
        返回调整后的阈值（可能与输入相同，表示无需调整）
        """
        state = self._state

        if state.is_frozen:
            return state.current_threshold

        now = time.time()
        threshold = state.current_threshold

        # Dead zone: 速度在目标区间内 → 保持阈值不变
        if self._target_low <= exploration_velocity <= self._target_high:
            state.consecutive_stable += 1
            state.integral_accumulator *= 0.9  # 衰减积分项
            if state.consecutive_stable >= self._convergence_rounds:
                state.is_frozen = True
            return threshold

        state.consecutive_stable = 0

        # 计算偏差——用对数缩放避免高低速度区间的不对称
        if exploration_velocity < self._target_low:
            raw_error = exploration_velocity - self._target_low  # 负值
        else:
            raw_error = exploration_velocity - self._target_high  # 正值

        # Sigmoid 压缩误差——大偏差时调整幅度饱和而非线性增长
        compressed_error = 0.04 * (2.0 / (1.0 + math.exp(-raw_error)) - 1.0)

        # 积分项更新——带 anti-windup
        state.integral_accumulator += compressed_error * 0.1
        state.integral_accumulator = max(-self._integral_limit,
                                         min(self._integral_limit,
                                             state.integral_accumulator))

        # 合成调整量 = P 项 + 项
        adjustment = compressed_error + state.integral_accumulator
        new_threshold = threshold + adjustment
        new_threshold = max(0.50, min(0.95, new_threshold))

        # Hysteresis check: 方向翻转需要超出 band 才允许
        direction = 1 if adjustment > 0 else (-1 if adjustment < 0 else 0)
        if state.last_adjustment_direction != 0 and direction != 0:
            if direction != state.last_adjustment_direction:
                # 方向翻转——上一次刚调整完又反向，记录振荡
                state.oscillation_count += 1
                # 连续振荡时扩大 band 以增强阻尼
                effective_band = self._hysteresis_band * (
                    1.0 + 0.5 * min(state.oscillation_count, 6))
                if abs(adjustment) < effective_band * 0.02:
                    # 调整量太小且在振荡——忽略此次调整
                    return threshold

        if abs(adjustment) < 0.005:
            # 调整量可忽略
            return threshold

        # 执行调整
        state.current_threshold = new_threshold
        state.last_adjustment_time = now
        state.last_adjustment_direction = direction
        state.total_adjustments += 1
        state.integral_accumulator *= 0.8  # 调整后衰减积分项

        # 记录历史，保留最近 32 条供诊断
        self._adjustment_history.append((now, threshold, new_threshold, direction))
        if len(self._adjustment_history) > 32:
            self._adjustment_history.pop(0)

        return new_threshold

    def unfreeze(self) -> None:
        """外部信号（如检测到新类型的约束）可解冻控制器"""
        self._state.is_frozen = False
        self._state.consecutive_stable = 0
        self._state.integral_accumulator = 0.0

    @property
    def is_frozen(self) -> bool:
        return self._state.is_frozen

    @property
    def oscillation_count(self) -> int:
        return self._state.oscillation_count

    @property
    def stability_metric(self) -> float:
        """稳定性评分 [0,1]，1 表示完全稳定（冻结）"""
        if self._state.is_frozen:
            return 1.0
        if self._state.total_adjustments == 0:
            return 1.0
        oscillation_ratio = self._state.oscillation_count / max(
            self._state.total_adjustments, 1)
        return max(0.0, 1.0 - oscillation_ratio)

    def get_diagnostics(self) -> dict:
        """返回诊断信息——供外部仪表板或日志"""
        s = self._state
        return {
            'current_threshold': s.current_threshold,
            'is_frozen': s.is_frozen,
            'total_adjustments': s.total_adjustments,
            'oscillation_count': s.oscillation_count,
            'stability_metric': self.stability_metric,
            'integral_accumulator': s.integral_accumulator,
            'consecutive_stable': s.consecutive_stable,
            'recent_history': self._adjustment_history[-8:],
        }
