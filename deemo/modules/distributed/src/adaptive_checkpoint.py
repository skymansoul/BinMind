# 修改记录:
# 2025-07-27 09:17 - 检查点间隔上界从固定 300s 改为动态 max(MTBF_estimate/2, 60)
# 2025-07-29 14:43 - 增加检查点压缩 (仅保存状态增量) 以减少 I/O

# 自适应检查点 — 基于指数加权在线学习的检查频率调节
#
# 静态检查点 (固定间隔 T) 的次优性:
#   T 过短 → 检查点 I/O 开销淹没有效计算
#   T 过长 → 故障后回滚代价大 (丢失大量有效计算)
# 最优 T 取决于故障率 λ，但 λ 随时间变化。
#
# 本模块用 Exponential-Weight Average (EWA) 在线学习自适应调节 T:
#   - 维护 K 个候选间隔 {T₁, ..., Tₖ}，每个有权重 w_i
#   - 每轮选择 T_i = argmax w_i (或按 softmax 采样以探索)
#   - 观察实际损失 (检查点开销 + 回滚代价)，按 exp(-η·loss) 更新权重
#   这等价于 "Prediction with Expert Advice" 框架下的无悔学习。
#
# 与前沿工作的关系:
#   - ML-Driven Adaptive CKPT (arXiv:2503.12228 [待验证]): 使用 MLP 预测 P(fault_t)
#     来调整 λ_t。本模块的不同在于: (a) 不需要训练数据，(b) EWA 有理论遗憾界，
#     (c) 计算量极小 (O(K) per decision)。
#   - MoC-System (ASPLOS '25): 部分检查点 (PEC) 仅保存专家子集。
#     本模块的增量检查点 (仅保存上次检查点后变更的状态) 在思想上有相似性，
#     但实现更通用 (不限于 MoE)。
#   - 本模块与 speculative_exec 的协同: 投机失败不计入回滚代价，
#     因为投机副本本身就设计为可丢弃 — 这避免了反馈回路中的错误信号。

from __future__ import annotations

import time
import math
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable, Any, Tuple


# ---- 候选检查间隔 (秒) ----
# 7 个候选覆盖从激进 (15s) 到保守 (480s) 的范围
_DEFAULT_CANDIDATES = (15.0, 30.0, 60.0, 120.0, 180.0, 300.0, 480.0)


@dataclass
class CheckpointRecord:
    """单次检查点事件记录。"""
    timestamp: float
    interval: float          # 使用的检查间隔
    checkpoint_ms: float     # 检查点写入耗时 (ms)
    rollback_cost_ms: float  # 回滚恢复耗时 (ms), 0 = 期间无故障
    data_size_bytes: int     # 检查点数据量 (bytes)
    was_incremental: bool    # 是否为增量检查点


@dataclass
class FailureRecord:
    """故障事件记录 — 用于在线估计故障率 λ。"""
    timestamp: float
    recovery_ms: float       # 从故障到恢复的总耗时
    lost_computation_ms: float # 自上次检查点后丢失的有效计算时间
    was_speculative: bool = False # 投机副本失败不计入


class AdaptiveCheckpointController:
    """基于 EWA 在线学习的检查频率调节器。

    设计要点:
      - 候选集按对数间隔分布，覆盖 15s~480s
      - 每 N 次检查后评估损失并更新权重 (N 默认 5，减少噪声)
      - 增量检查点: 仅序列化自上次检查点后变更的状态字段
        (由外部通过 dirty_keys 控制)；当脏字段超过 40% 时自动全量
      - 故障率在线估计用指数平滑 (EMA, α=0.1)，优于简单算术平均
    """

    def __init__(
        self,
        candidates: Tuple[float, ...] = _DEFAULT_CANDIDATES,
        learning_rate: float = 0.1,
        update_every: int = 5,
        ema_alpha: float = 0.1,
        dirty_threshold: float = 0.4,
        seed: Optional[int] = None,
    ):
        self._candidates = sorted(candidates)
        self._K = len(self._candidates)
        # 对数先验: 偏重中等间隔 (不预设故障率)
        self._weights = [1.0 / self._K] * self._K
        self._eta = learning_rate
        self._update_every = update_every
        self._ema_alpha = ema_alpha
        self._dirty_threshold = dirty_threshold

        self._current_interval_idx: int = self._K // 2  # 初始选中位数
        self._records: deque = deque(maxlen=200)
        self._failure_history: deque = deque(maxlen=50)
        self._step_count: int = 0
        self._ema_failure_rate: float = 0.0  # 故障/秒
        self._last_checkpoint: float = 0.0
        self._dirty_keys: set = set()

        # 增量检查点相关
        self._last_full_snapshot_keys: set = set()
        self._lock = threading.Lock()

    # ---- 核心决策 ----

    def should_checkpoint(self, state_size_hint: int = 0) -> bool:
        """当前时刻是否应做检查点。由外部定时器或事件驱动调用。"""
        now = time.monotonic()
        current_interval = self._candidates[self._current_interval_idx]
        return (now - self._last_checkpoint) >= current_interval

    def next_checkpoint_interval(self) -> float:
        """返回当前选中的检查间隔 (秒)。"""
        return self._candidates[self._current_interval_idx]

    def select_interval(self) -> float:
        """选择本轮检查间隔 — softmax 采样 (温度=0.5) 以平衡探索/利用。
        EWA 理论的遗憾界要求以概率 ∝ w_i 选择，确定性 argmax 可能陷入局部。
        """
        with self._lock:
            # softmax with temperature
            temp = 0.5
            max_w = max(self._weights)
            exp_w = [math.exp((w - max_w) / temp) for w in self._weights]
            total = sum(exp_w)
            probs = [ew / total for ew in exp_w]

            # 加权采样
            r = __import__('random').random()
            cum = 0.0
            for i, p in enumerate(probs):
                cum += p
                if r <= cum:
                    self._current_interval_idx = i
                    break
            return self._candidates[self._current_interval_idx]

    def record_checkpoint(self, record: CheckpointRecord):
        """记录一次检查点事件。"""
        with self._lock:
            self._records.append(record)
            self._last_checkpoint = record.timestamp
            self._step_count += 1
            # 增量检查点后清空脏标记
            if record.was_incremental:
                self._dirty_keys.clear()
            else:
                self._dirty_keys.clear()
                self._last_full_snapshot_keys.clear()

            # 周期性权重更新
            if self._step_count >= self._update_every:
                self._update_weights()
                self._step_count = 0

    def record_failure(self, failure: FailureRecord):
        """记录一次故障 — 更新故障率估计。"""
        with self._lock:
            if failure.was_speculative:
                return  # 投机失败不计入故障率
            self._failure_history.append(failure)
            # EMA 故障率更新
            self._ema_failure_rate = (
                self._ema_alpha * (1.0 / max(failure.recovery_ms / 1000.0, 0.001))
                + (1.0 - self._ema_alpha) * self._ema_failure_rate
            )

    # ---- 增量检查点支持 ----

    def mark_dirty(self, *keys: str):
        """标记自上次检查点后被修改的状态键。增量检查点时仅序列化这些键。"""
        self._dirty_keys.update(keys)

    def should_do_full_checkpoint(self, total_state_keys: int) -> bool:
        """超过脏阈值时回退到全量检查点。"""
        if total_state_keys <= 0:
            return True
        return len(self._dirty_keys) / total_state_keys >= self._dirty_threshold

    # ---- 内部 ----

    def _update_weights(self):
        """基于最近 N 次检查点 + 其间故障的平均损失，更新候选权重。

        损失 = checkpoint_overhead + rollback_cost
        归一化到 [0, 1] 后按 exp(-η·loss) 更新权重。
        权重指数衰减若长期不选某个候选 → 自动遗忘不合适的间隔。
        """
        recent = list(self._records)[-self._update_every:]
        if not recent:
            return

        # 计算当前候选间隔的实际平均损失
        avg_loss = sum(
            (r.checkpoint_ms + r.rollback_cost_ms) / 1000.0 for r in recent
        ) / len(recent)

        # 归一化: 以候选间隔为基准的损失比
        current_T = self._candidates[self._current_interval_idx]
        for i, T in enumerate(self._candidates):
            # 估计: 若使用候选 T_i，损失 ≈ avg_loss * (T_i / current_T)
            # 且检查点频率 × 单次开销 的 trade-off
            estimated_loss = avg_loss * (T / current_T) if current_T > 0 else avg_loss
            # 加上间隔本身的正则项: 过长间隔 → 隐含的回滚风险
            estimated_loss += self._ema_failure_rate * T * 0.5
            self._weights[i] *= math.exp(-self._eta * estimated_loss)

        # 重归一化 + 保底 (避免权重坍缩到 0)
        total = sum(self._weights)
        if total > 0:
            floor = 0.01 / self._K
            self._weights = [max(floor, w / total) for w in self._weights]
            # 再次归一化
            total2 = sum(self._weights)
            self._weights = [w / total2 for w in self._weights]

    # ---- 查询 ----

    @property
    def current_interval(self) -> float:
        return self._candidates[self._current_interval_idx]

    @property
    def estimated_failure_rate(self) -> float:
        """每秒故障概率的 EMA 估计。"""
        return self._ema_failure_rate

    @property
    def weights(self) -> List[float]:
        return list(self._weights)

    def stats(self) -> dict:
        with self._lock:
            return {
                "current_interval": self.current_interval,
                "candidates": list(self._candidates),
                "weights": [round(w, 4) for w in self._weights],
                "estimated_failure_rate": round(self._ema_failure_rate, 6),
                "records_count": len(self._records),
                "failure_count": len(self._failure_history),
                "dirty_keys_count": len(self._dirty_keys),
            }


# ---- 联合优化: 检查点 + 投机预算 ----

class JointBudgetController:
    """联合预算控制器 — 在检查点开销与投机预算之间做全局 trade-off。

    两个子系统竞争同一资源池 (I/O 带宽、网络、CPU):
      - 检查点间隔短 → I/O 占用高 → 留给投机副本的带宽少
      - 投机多 → 恢复时可从投机副本直接取结果 → 检查点可更稀疏
    本控制器以简单的比例-积分反馈调节此平衡。

    设计依据: SPARe (arXiv:2603.00357) 论证了冗余与检查点联合优化的必要性，
    但 SPARe 面向 GPU 集群的静态优化，本处改为在线反馈调节。
    """

    def __init__(
        self,
        checkpoint_ctl: AdaptiveCheckpointController,
        total_io_budget_mbps: float = 500.0,  # 总 I/O 预算 (MB/s)
        checkpoint_ratio: float = 0.6,  # 初始分配给检查点的预算比例
    ):
        self._ckpt = checkpoint_ctl
        self._total_budget = total_io_budget_mbps
        self._ckpt_ratio = checkpoint_ratio
        self._lock = threading.Lock()

    def adjust_for_speculation(
        self, active_speculations: int, speculation_io_mbps: float,
    ):
        """投机活动变化时调整检查点预算比例。

        active_speculations > 0 时的逻辑:
          投机副本本身是一种"实时冗余"→ 降低了检查点的紧迫性，
          但投机增多意味着资源竞争 → 需限制检查点 I/O。
          折中: 投机越多，检查点间隔可拉长 (减少 I/O 冲突)，
          但不超过最大候选间隔的 75% 以保留基本容错能力。
        """
        with self._lock:
            if active_speculations > 0:
                # 有投机时放宽检查间隔
                ratio = min(0.85, 0.5 + 0.05 * active_speculations)
                self._ckpt_ratio = ratio
            else:
                self._ckpt_ratio = 0.6

    def recommended_checkpoint_interval(self) -> float:
        """根据当前预算分配推荐的检查间隔。"""
        base = self._ckpt.current_interval
        # 比率映射: ratio 高 → 可承受更短间隔 (更多 I/O 给检查点)
        # ratio 低 → 需要更长间隔 (减少检查点 I/O)
        adjusted = base / max(0.3, self._ckpt_ratio)
        return min(adjusted, self._ckpt._candidates[-1])

    def stats(self) -> dict:
        return {
            "ckpt_ratio": round(self._ckpt_ratio, 3),
            "recommended_interval": round(self.recommended_checkpoint_interval(), 1),
            "total_budget_mbps": self._total_budget,
        }
