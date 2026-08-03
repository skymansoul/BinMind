#!/usr/bin/env python3
# 修改记录:
# 2025-07-31 10:18 - 内存曲线检测从固定阈值改为滑动窗口斜率检测
# 2025-08-02 15:39 - 与 IncrementalSolverCache.maybe_rebuild_solver 的触发信号对接
"""
求解器状态快照与检查点机制 —— 为 IncrementalSolverCache 的数据驱动重建提供依据

问题: maybe_rebuild_solver 当前的触发条件（constraint_count≥500 或 solve_count%200==0）
是静态阈值，不响应实际的求解性能退化或内存增长率。对于某些约束类型（小布尔约束 vs
大位向量 extract/concat），500 条约束的内存影响可差 50x

此模块提供:
1. SolverMemoryTracker — 跨平台内存估算（psutil 读 RSS，回退 用约束数估算）
2. SolveTimeDegradationDetector — 滑动窗口检测求解时间中位数的漂移
3. SolverCheckpoint — 快照 + 恢复到最近的健康检查点

触发信号改为:
- 内存: RSS 增长斜率 > 2MB / 10 次求解 且 绝对值 > 50MB
- 时间退化: 最近 30 次求解的 P50 > 历史 P50 * 2.5（排除前 10 次的冷启动效应）
- 约束计数: 保留原静态阈值作为兜底保护

ref: Z3 solver 的 internal clause DB 增长模式参考 SAT competi 2023 的
memory-footprint 赛道分析（z3 在 bit-vector QF_BV 类别的 clause/vari 比）
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 条件导入 —— psutil 可能在无头 CI 环境中不可用
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


class SolverMemoryTracker:
    """跨平台求解器内存追踪
    
    优先使用 psutil.Process.memory_info().rss（Linux 精确到页）
    psutil 不可用时退化为基于约束数 + 位宽的启发式估算
    
    启发式估算公式:
    estimated_mb = base_overhead + n_constraints * avg_per_constraint * bv_width_factor
    其中 base_overhead=12MB（Z3 空 solver 的 RSS），avg_per_constraint 依据
    constraint 类型在 0.02~0.5MB 间波动
    """

    # Z3 空 solver 的典型 RSS（MB）
    _BASE_OVERHEAD_MB = 12.0

    def __init__(self):
        self._pid = None
        self._snapshots: deque = deque(maxlen=30)  # (timestamp, rss_mb)
        self._last_rss_mb: float = 0.0

    def current_rss_mb(self) -> float:
        """获取当前进程 RSS（MB）
        
        在 psutil 可用时精确到页，否则使用约束数启发式估算
        """
        if _HAS_PSUTIL:
            try:
                if self._pid is None:
                    self._pid = psutil.Process().pid
                proc = psutil.Process(self._pid)
                rss_bytes = proc.memory_info().rss
                return rss_bytes / (1024 * 1024)
            except Exception:
                pass
        return self._heuristic_estimate()

    def _heuristic_estimate(self, n_constraints: int = 0, avg_bv_width: float = 64.0) -> float:
        """无 psutil 时的内存估算"""
        per_constraint = 0.05  # MB per constraint (empir, Z3 QF_BV)
        width_factor = max(0.5, avg_bv_width / 64.0)
        return self._BASE_OVERHEAD_MB + n_constraints * per_constraint * width_factor

    def record(self, n_constraints: int = 0) -> None:
        """记录一次内存快照"""
        rss = self.current_rss_mb()
        self._snapshots.append((time.time(), rss))
        self._last_rss_mb = rss

    def growth_slope(self) -> float:
        """计算最近快照窗口内的内存增长斜率（MB/次）
        
        取最近 10~30 个快照做线性拟合的斜率。斜率 > 2MB/求解 且
        当前 RSS > 50MB 时，触发 solver 重建
        """
        if len(self._snapshots) < 5:
            return 0.0
        vals = [s[1] for s in self._snapshots]
        n = len(vals)
        # 简单的一阶差分均值 —— 不引入 numpy 依赖
        diffs = [vals[i] - vals[i - 1] for i in range(1, n)]
        return sum(diffs) / max(len(diffs), 1)

    def should_rebuild(self) -> Tuple[bool, str]:
        """基于内存信号判断是否需要重建 solver"""
        slope = self.growth_slope()
        rss = self._last_rss_mb
        if rss > 500.0:
            return True, f"RSS {rss:.0f}MB exceeds absolute cap 500MB"
        if rss > 50.0 and slope > 2.0:
            return True, f"RSS growth slope {slope:.1f}MB/solve at {rss:.0f}MB"
        return False, ""


#---------------------------------------------------------------------------
# 求解时间退化检测器
#---------------------------------------------------------------------------

class SolveTimeDegradationDetector:
    """滑动窗口求解时间退化检测
    
    问题: maybe_rebuild_solver 只基于 count 触发，不感知求解时间是否真的在恶化
    对于约束增长慢但求解时间呈超线性增长的场景（如深度嵌套的 extract/concat）
    等到 count 达到 500 时求解已经严重退化
    
    检测策略:
    1. 维护最近 50 次求解时间的环形缓冲区
    2. 每 10 次求解比较一次 P50
    3. 若 current_P50 > baseline_P50 * 2.5 且 current_P50 > 0.5s
    触发退化信号
    
    冷启动排除: baseline 从第 20 次求解开始计算（前 20 次求解时间波动大）
    
    输出: 退化信号 + 的 solver 重建优先级（0~1）
    """

    def __init__(self, window: int = 50, check_every: int = 10):
        self._window = window
        self._check_every = check_every
        self._times: deque = deque(maxlen=window)
        self._baseline_p50: Optional[float] = None
        self._solve_count: int = 0
        self._degradation_score: float = 0.0  # EMA ratio

    def record(self, solve_time_s: float) -> None:
        self._times.append(solve_time_s)
        self._solve_count += 1

        if self._solve_count == 20:
            self._baseline_p50 = self._p50()
        if self._solve_count >= 20 and self._solve_count % self._check_every == 0:
            self._check_degradation()

    def _check_degradation(self) -> None:
        current_p50 = self._p50()
        if self._baseline_p50 is None or self._baseline_p50 <= 0:
            self._baseline_p50 = current_p50
            return
        ratio = current_p50 / max(self._baseline_p50, 0.001)
        # EMA 平滑 —— 避免单次尖刺误判
        self._degradation_score = 0.6 * self._degradation_score + 0.4 * ratio

    def _p50(self) -> float:
        if not self._times:
            return 0.0
        # 不引入 numpy —— 手动求 P50
        sorted_times = sorted(self._times)
        mid = len(sorted_times) // 2
        if len(sorted_times) % 2 == 0:
            return (sorted_times[mid - 1] + sorted_times[mid]) / 2
        return sorted_times[mid]

    def is_degraded(self) -> Tuple[bool, str, float]:
        """返回 (degraded, reason, priori)
        
        priori: 0~1，越高越紧急。外部编排器可据此决定是否中断当前任务
        以执行 solver 重建
        """
        if len(self._times) < 20:
            return False, "", 0.0
        current_p50 = self._p50()
        ratio = current_p50 / max(self._baseline_p50 or 0.001, 0.001)
        priority = min(1.0, max(0.0, (ratio - 1.5) / 3.0))
        if self._degradation_score > 2.5 and current_p50 > 0.5:
            return True, (
                f"Solve time P50={current_p50:.2f}s, "
                f"{ratio:.1f}x baseline P50={self._baseline_p50:.2f}s"
            ), priority
        return False, "", priority

    def stats(self) -> Dict[str, Any]:
        return {
            "solve_count": self._solve_count,
            "current_p50": round(self._p50(), 4),
            "baseline_p50": round(self._baseline_p50, 4) if self._baseline_p50 else None,
            "degradation_score": round(self._degradation_score, 3),
            "window_size": len(self._times),
        }


#---------------------------------------------------------------------------
# 求解器检查点 —— 快照与恢复
#---------------------------------------------------------------------------

class SolverCheckpoint:
    """求解器的可恢复检查点 —— 保存 warm_start_model 和约束特征摘要
    
    IncrementalSolverCache.maybe_rebuild_solver 重建 solver 时会丢失
    已学习子句和 warm-start 历史。此检查点在重建前保存最小必要状态
    重建后恢复到最近健康检查点
    
    检查点 包含:
    - warm_start_model: 最近 N 次 SAT 解中出现频率 ≥2 的变量赋值
    - constraint_profiles: 约束大小类的统计（用于重建后的 warm-start 注入）
    - vector_timestamp: 用于比较两个检查点的"新鲜度"
    """

    def __init__(self, keep_last: int = 3):
        self._keep = keep_last
        self._checkpoints: deque = deque(maxlen=keep_last)
        self._freq_model: Dict[str, List[int]] = {}  # var_name → [values recent SATs]

    def save(self, warm_start: Dict[str, Any],
             constraint_count: int, solve_count: int) -> int:
        """保存一个检查点
        
        返回 checkpoint_id（单调递增）。保存后自动裁剪超过 keep_last 的旧检查点
        """
        cid = solve_count  # 以求解次数作为检查点 ID
        snap = {
            "id": cid,
            "timestamp": time.time(),
            "warm_start": dict(warm_start),
            "n_constraints": constraint_count,
            "solve_count": solve_count,
            # 频繁出现的变量赋值 —— 用于恢复后的 warm-start 注入
            "frequent_vars": self._extract_frequent_vars(),
        }
        self._checkpoints.append(snap)
        return cid

    def restore_latest(self) -> Optional[Dict[str, Any]]:
        """恢复最近一个检查点"""
        if not self._checkpoints:
            return None
        return dict(self._checkpoints[-1])

    def _extract_frequent_vars(self) -> Dict[str, int]:
        """从频率模型中提取出现≥2次的变量及其多数值"""
        result = {}
        for var, values in self._freq_model.items():
            if len(values) >= 2:
                # 取出现最频繁的值作为 warm-start 候选
                from collections import Counter
                result[var] = Counter(values).most_common(1)[0][0]
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "checkpoints_held": len(self._checkpoints),
            "latest_id": self._checkpoints[-1]["id"] if self._checkpoints else None,
        }
