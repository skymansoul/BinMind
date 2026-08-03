# ShadowScope: GPU 侧信道监控与内核完整性验证
# 参考:
#   "ShadowScope: GPU Monitoring and Validation via Composable Side Channel Signals"
#     (arXiv 2509.00300, Sep 2025) — Almusaddar et al.
#     NVIDIA V100/RTX4060 上实现 GPU 内核完整性监控, 开销 4.6%
#     检测: 缓冲区溢出, Rowhammer, mind-control 攻击, DoS
#     方法: 从性能计数器 + 时序信号构建 golden model, 运行时比对偏差

import os
import struct
import logging
import math
import hashlib
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ShadowScope 监测的 GPU 性能计数器事件 — 映射到 NVIDIA CUPTI 事件名
# 这些事件在 golden model 建立时采集，运行时用于偏差检测
_SHADOWSCOPE_PMC_EVENTS: dict[str, str] = {
    "l1_cache_hit":       "l1tex__t_sectors_lookup_hit",
    "l1_cache_miss":      "l1tex__t_sectors_lookup_miss",
    "l2_cache_hit":       "lts__t_sectors_lookup_hit",
    "l2_cache_miss":      "lts__t_sectors_lookup_miss",
    "dram_read":          "dram__sectors_read",
    "dram_write":         "dram__sectors_write",
    "inst_executed":      "smsp__inst_executed",
    "global_load":        "smsp__sass_inst_executed_global_load",
    "global_store":       "smsp__sass_inst_executed_global_store",
    "shared_load":        "smsp__sass_inst_executed_shared_load",
    "warp_stall_mem":     "smsp__warp_cycles_per_issue_stall_long_scoreboard",
    "branch_divergence":  "smsp__sass_branch_targets_threads_divergent",
    "atomic_ops":         "smsp__inst_executed_atomic",
}

# 异常检测阈值 — 运行时 PMC 值与 golden model 的偏差超过此倍数视为异常
_DEVIATION_THRESHOLD = 2.5  # 标准差倍数

# Golden model 的缓动平均权重 — α 越高, golden model 越快速适配合法变化
_GOLDEN_EMA_ALPHA = 0.15


@dataclass
class PMCProfile:
    """GPU 性能监控计数器 (PMC) 的一次采样快照。"""
    kernel_name: str
    event_values: dict = field(default_factory=dict)  # event_name → value
    timestamp_us: int = 0
    gpu_id: int = 0
    grid_dim: tuple = (0, 0, 0)
    block_dim: tuple = (0, 0, 0)


@dataclass
class ShadowScopeAnomaly:
    anomaly_type: str           # "buffer_overflow", "rowhammer", "dos", "mind_control"
    severity: str
    kernel_name: str = ""
    event_deviated: str = ""    # 哪个 PMC 事件偏离了 golden model
    expected_range: tuple = (0, 0)
    observed_value: int = 0
    deviation_ratio: float = 0.0
    description: str = ""


class ShadowScopeMonitor:
    """GPU 内核完整性运行时监控器 (arXiv 2509.00300)。

    工作流程:
    1. Profile: 在可信环境中采集各 kernel 的 PMC 特征 → 建立 Golden Model
    2. Monitor: 运行时重复采样 PMC, 与 golden model 比对偏差
    3. Alert: 超出阈值的偏差 → 报告异常

    注意: 这是一个静态/离线分析实现。实际的运行时 PMC 数据
    需通过 CUPTI (NVIDIA) 或 ROCProfiler (AMD) 采集。
    此模块提供分析框架和偏差检测算法。
    """

    def __init__(self, golden_profiles: list[PMCProfile] | None = None):
        self._golden: dict[str, dict[str, tuple[float, float]]] = {}
        #                                 kernel → event → (mean, stddev)
        self._anomalies: list[ShadowScopeAnomaly] = []
        self._profile_history: list[PMCProfile] = []
        if golden_profiles:
            for prof in golden_profiles:
                self.add_golden_profile(prof)

    def add_golden_profile(self, profile: PMCProfile):
        kn = profile.kernel_name
        if kn not in self._golden:
            self._golden[kn] = {}
        for evt, val in profile.event_values.items():
            # EMA 更新: mean_new = α*val + (1-α)*mean_old
            curr_mean, curr_std = self._golden[kn].get(evt, (val, 0.0))
            new_mean = _GOLDEN_EMA_ALPHA * val + (1 - _GOLDEN_EMA_ALPHA) * curr_mean
            # 标准差使用增量 Welford 型更新
            delta = val - curr_mean
            new_std = max(curr_std, abs(delta))
            self._golden[kn][evt] = (new_mean, new_std)

    def validate_profile(self, profile: PMCProfile) -> list[ShadowScopeAnomaly]:
        kn = profile.kernel_name
        if kn not in self._golden:
            logger.warning("No golden model for kernel %s — skipping validation", kn)
            return []
        anomalies = []
        for evt, val in profile.event_values.items():
            if evt not in self._golden[kn]:
                continue
            g_mean, g_std = self._golden[kn][evt]
            if g_std < 1e-9:
                continue
            dev = abs(val - g_mean) / g_std
            if dev > _DEVIATION_THRESHOLD:
                anom_type = self._classify_anomaly(evt, val, g_mean)
                anomalies.append(ShadowScopeAnomaly(
                    anomaly_type=anom_type,
                    severity="High" if dev > 5.0 else "Medium",
                    kernel_name=kn,
                    event_deviated=evt,
                    expected_range=(max(0, g_mean - 2 * g_std),
                                   g_mean + 2 * g_std),
                    observed_value=val,
                    deviation_ratio=round(dev, 2),
                    description=f"PMC {evt}: expected ~{g_mean:.0f}±{g_std:.0f}, observed {val}"
                ))
        self._anomalies.extend(anomalies)
        return anomalies

    def _classify_anomaly(self, event: str, value: int, expected: float) -> str:
        """根据偏离的 PMC 事件类型推断攻击类别。"""
        ratio = value / (expected + 1)
        if event == "dram_read" and ratio > 3:
            return "rowhammer"          # 大量 DRAM 读取暗示 hammering
        if event == "global_store" and ratio > 3:
            return "buffer_overflow"    # 异常多的全局写入暗示溢出
        if event == "inst_executed" and ratio > 5:
            return "dos"                # 指令数爆炸 = DoS
        if event == "atomic_ops" and ratio > 4:
            return "mind_control"       # 异常原子操作来自恶意篡改
        return "unknown_deviation"

    def get_golden_fingerprint(self, kernel_name: str) -> str:
        """计算 golden model 的哈希指纹 — 用于远程验证。"""
        if kernel_name not in self._golden:
            return ""
        parts = []
        for evt in sorted(self._golden[kernel_name].keys()):
            mean, std = self._golden[kernel_name][evt]
            parts.append(f"{evt}:{mean:.1f}:{std:.1f}")
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def export_golden_model(self) -> dict:
        """导出 golden model 为 JSON 兼容的字典。"""
        return {
            kn: {evt: {"mean": m, "std": s} for evt, (m, s) in events.items()}
            for kn, events in self._golden.items()
        }

    @classmethod
    def from_json(cls, data: dict) -> "ShadowScopeMonitor":
        monitor = cls()
        for kn, events in data.items():
            monitor._golden[kn] = {}
            for evt, stats in events.items():
                monitor._golden[kn][evt] = (stats["mean"], stats["std"])
        return monitor


def create_profiler(kernel_name: str) -> PMCProfile:
    """创建空 PMC profile 模板 — 供外部采集工具填充。"""
    return PMCProfile(
        kernel_name=kernel_name,
        event_values={e: 0 for e in _SHADOWSCOPE_PMC_EVENTS},
    )


# 静态偏差检测 — 不依赖运行时 PMC 数据, 从编译期已知信息做启发式分析
def estimate_kernel_risk(kernel_source: str) -> dict:
    """从 GPU kernel 源码估算风险分数 (0-1)。

    基于源码特征: 原子操作密度, 全局内存读写比, 分支复杂度, 共享内存使用。
    """
    lines = kernel_source.split("\n")
    n = max(len(lines), 1)
    atom_count   = sum(1 for l in lines if "atomic" in l.lower())
    global_ld    = sum(1 for l in lines if "ld.global" in l or "global_load" in l)
    global_st    = sum(1 for l in lines if "st.global" in l or "global_store" in l)
    branch_kw    = sum(1 for l in lines if any(k in l for k in ("if", "else", "switch", "case:")))
    shared_mem   = sum(1 for l in lines if "__shared__" in l or "shared" in l)
    risk = (atom_count * 0.3 + (global_ld + global_st) * 0.05 +
            branch_kw * 0.02 + shared_mem * 0.1) / max(n / 100, 1)
    return {
        "risk_score": round(min(risk, 1.0), 2),
        "atomic_density": atom_count / n,
        "global_mem_density": (global_ld + global_st) / n,
        "branch_density": branch_kw / n,
    }
