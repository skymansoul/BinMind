"""
创建: 2025-03-03
修改:
  2025-08-01 - 信号计算委托给 quality_signals.py
Worker 输出质量哨兵 — 多信号异常检测，退化时触发重生成。

问题：并行 worker 调用 LLM API 时，输出质量并非恒定。随着 token 预算消耗、
API 负载波动或 prompt 上下文累积，worker 可能产出退化代码：
  - 重复生成相同函数体（copy-paste 循环）
  - 符号密度骤降（大量空行/注释/占位符）
  - 结构复杂度异常（全是单行函数或全是巨型函数）

当前系统无质量门禁——只要 API 返回非空文本就写入文件。
LettuceDetect-v2 检测代码幻觉但需专用模型；GUARDIAN
建模多 agent 错误传播但关注交互图而非单 worker 输出质量。

方案：四维轻量质量信号，零 API 开销，纯静态计算。
  信号 1（重复度）：滑动窗口内的 N-gram 重复率。阈值 >30% 触发。
  信号 2（符号密度）：每千字节定义的函数/类数量。正常区间 [2, 50]。
  信号 3（结构熵）：AST 节点类型分布的 Shannon 熵。低熵 → 结构单一。
  信号 4（注释比）：注释行数 / 总行数。过高（>40%）→ 可能为占位填充。

每个 worker 维护一个质量画像（EWMA + 标准差），当任两个信号同时超出
2σ 范围时标记为异常。异常输出触发黑板告警，executor 可选择重生成。

与现有工作的差异：
  - LettuceDetect-v2：span 级代码幻觉检测，需专用模型推理
  - GUARDIAN：多 agent 交互图异常检测，忽略单 worker 输出内容质量
  - Sentinel：通用 agent 可观测性，不针对代码生成的特定退化模式
  - 本模块的四维信号 + per-worker 动态画像的组合在文献中未见，
    特别是"注释比"作为占位代码检测信号的应用
"""

from __future__ import annotations

import math
import os
import threading
from dataclasses import dataclass, field


@dataclass
class QualityReport:
    """单次质量评估报告。"""
    filepath: str
    repetition_ratio: float      # 0.0-1.0，越高越重复
    symbol_density: float        # 每 KB 定义的符号数
    structure_entropy: float     # AST 节点类型分布的 Shannon 熵
    comment_ratio: float         # 注释行占比
    is_anomaly: bool             # 是否被标记为异常
    anomaly_reasons: list[str] = field(default_factory=list)


@dataclass
class WorkerProfile:
    """单个 worker 的质量画像——EWMA + 运行标准差（Welford 算法）。"""

    worker_id: str
    # 重复度
    rep_mean: float = 0.15
    rep_m2: float = 0.01       # 用于在线方差计算
    # 符号密度
    sd_mean: float = 8.0
    sd_m2: float = 4.0
    # 结构熵
    se_mean: float = 2.5
    se_m2: float = 0.5
    # 注释比
    cr_mean: float = 0.15
    cr_m2: float = 0.02
    sample_count: int = 0

    def update(self, report: QualityReport) -> None:
        """Welford 在线更新均值和 M2。"""
        self.sample_count += 1

        def _update(val: float, mean: float, m2: float) -> tuple[float, float]:
            delta = val - mean
            new_mean = mean + delta / self.sample_count
            delta2 = val - new_mean
            new_m2 = m2 + delta * delta2
            return new_mean, new_m2

        self.rep_mean, self.rep_m2 = _update(report.repetition_ratio, self.rep_mean, self.rep_m2)
        self.sd_mean, self.sd_m2 = _update(report.symbol_density, self.sd_mean, self.sd_m2)
        self.se_mean, self.se_m2 = _update(report.structure_entropy, self.se_mean, self.se_m2)
        self.cr_mean, self.cr_m2 = _update(report.comment_ratio, self.cr_mean, self.cr_m2)

    def is_anomaly(self, report: QualityReport, sigma: float = 2.0) -> list[str]:
        """检查当前报告是否偏离画像 > sigma 个标准差。返回异常原因列表。"""
        if self.sample_count < 3:
            return []  # 样本不足，不判定

        reasons: list[str] = []
        checks = [
            ("重复度", report.repetition_ratio, self.rep_mean, self.rep_m2, True),
            ("符号密度", report.symbol_density, self.sd_mean, self.sd_m2, False),
            ("结构熵", report.structure_entropy, self.se_mean, self.se_m2, False),
            ("注释比", report.comment_ratio, self.cr_mean, self.cr_m2, True),
        ]

        for name, val, mean, m2, higher_is_bad in checks:
            if self.sample_count > 1:
                std = math.sqrt(m2 / (self.sample_count - 1))
            else:
                std = 0.01
            if std < 1e-8:
                continue

            if higher_is_bad:
                if val > mean + sigma * std:
                    reasons.append(f"{name}偏高({val:.3f} > μ+{sigma}σ={mean + sigma * std:.3f})")
            else:
                if val < mean - sigma * std:
                    reasons.append(f"{name}偏低({val:.3f} < μ-{sigma}σ={mean - sigma * std:.3f})")

        return reasons


class QualitySentinel:
    """多信号输出质量哨兵。线程安全。

    每个 worker 维护独立画像。当同一 worker 连续两个输出被标记为异常时，
    触发"退化确认"——向黑板写入 critical 告警。"""

    def __init__(self):
        self._profiles: dict[str, WorkerProfile] = {}
        self._recent_anomalies: dict[str, int] = {}  # worker → 连续异常计数
        self._lock = threading.Lock()

    def evaluate(
        self,
        worker_id: str,
        filepath: str,
        source: str | None = None,
    ) -> QualityReport:
        """评估单个文件的输出质量。

        若 source 为 None，从 filepath 读取。
        自动更新 worker 画像并检测异常。"""
        if source is None:
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except OSError:
                return QualityReport(
                    filepath=filepath, repetition_ratio=0.0,
                    symbol_density=0.0, structure_entropy=0.0,
                    comment_ratio=1.0, is_anomaly=True,
                    anomaly_reasons=["文件不可读"],
                )

        if not source.strip():
            return QualityReport(
                filepath=filepath, repetition_ratio=0.0,
                symbol_density=0.0, structure_entropy=0.0,
                comment_ratio=1.0, is_anomaly=True,
                anomaly_reasons=["空文件"],
            )

        rep = compute_repetition(source)
        sd = compute_symbol_density(source)
        se = compute_structure_entropy(source)
        cr = compute_comment_ratio(source)

        report = QualityReport(
            filepath=filepath, repetition_ratio=rep,
            symbol_density=sd, structure_entropy=se,
            comment_ratio=cr, is_anomaly=False,
        )

        with self._lock:
            profile = self._profiles.get(worker_id)
            if profile is None:
                profile = WorkerProfile(worker_id=worker_id)
                self._profiles[worker_id] = profile

            reasons = profile.is_anomaly(report)
            # 额外硬阈值检查（不依赖画像）
            if rep > 0.35:
                reasons.append(f"重复度过高({rep:.2f})")
            if cr > 0.45:
                reasons.append(f"注释比异常({cr:.2f})")

            if len(reasons) >= 2:
                report.is_anomaly = True
                report.anomaly_reasons = reasons
                self._recent_anomalies[worker_id] = self._recent_anomalies.get(worker_id, 0) + 1
            else:
                self._recent_anomalies[worker_id] = 0

            profile.update(report)

        return report

    def is_degraded(self, worker_id: str) -> bool:
        """检查 worker 是否处于退化状态（连续 2+ 异常）。"""
        with self._lock:
            return self._recent_anomalies.get(worker_id, 0) >= 2

    def profile_summary(self, worker_id: str) -> dict | None:
        """返回 worker 画像摘要。"""
        with self._lock:
            p = self._profiles.get(worker_id)
            if p is None:
                return None
            return {
                "worker_id": p.worker_id,
                "samples": p.sample_count,
                "rep_mean": round(p.rep_mean, 3),
                "sd_mean": round(p.sd_mean, 1),
                "se_mean": round(p.se_mean, 2),
                "cr_mean": round(p.cr_mean, 2),
            }


# 信号计算委托给 engine/quality_signals.py
from .quality_signals import (
    compute_repetition, compute_symbol_density,
    compute_structure_entropy, compute_comment_ratio,
)


# 便捷集成入口

def sentinel_check_batch(
    sentinel: QualitySentinel,
    worker_id: str,
    filepaths: list[str],
    blackboard=None,
) -> list[QualityReport]:
    """批量检查 worker 产出文件并将异常写入黑板。"""
    reports: list[QualityReport] = []
    for fpath in filepaths:
        if not fpath.endswith(".py"):
            continue
        report = sentinel.evaluate(worker_id, fpath)
        reports.append(report)
        if report.is_anomaly and blackboard is not None:
            blackboard.deposit(
                "warning",
                f"[质量异常] {os.path.basename(fpath)}: "
                + "; ".join(report.anomaly_reasons[:3]),
                source_module="quality_sentinel",
                tags=["quality", "anomaly", worker_id],
            )

    if sentinel.is_degraded(worker_id) and blackboard is not None:
        blackboard.deposit(
            "error",
            f"Worker [{worker_id}] 连续输出质量异常，建议重生成或调整 temperature",
            source_module="quality_sentinel",
            tags=["quality", "degraded", worker_id],
        )

    return reports
