"""
创建: 2026-04-17
修改:
  2025-08-01 - 黑板解析委托给 self_correction_exec.py 避免循环导入
多源验证融合驱动的闭环自校正 — 聚合所有检测器的发现，触发定向重生成。

问题：系统已集成 5 个验证/检测层（语义收敛、架构漂移、质量哨兵、对抗审查、
因果影响），但各层独立运作，发现的问题仅写入黑板供人工查看。
没有一个机制将检测结果反馈给 worker 做自动修复。

现有闭环系统使用单一反馈源
（执行结果或人工审查），而本系统的反馈是多源的——架构违规、质量退化、
语义收敛、对抗审查发现之间可能相互关联（如架构违规导致了质量退化）。

方案：多源发现融合 + 优先级排序 + 定向重生成触发。
  1. 聚合：从黑板收集所有 validation/warning/error 条目
  2. 去重与关联：同一文件的多条发现合并，计算综合修正优先级
  3. 触发：优先级超阈值的发现构建修正 prompt，触发 worker 重生成
  4. 追踪：记录每次重生成的结果，同一发现最多重试 2 次

修正优先级公式：
  priority = Σ(severity_weight × impact_score × freshness_decay)
  freshness_decay = exp(-age_minutes / 30)  ← 30分钟半衰期

与现有工作的差异：
  - Murphy: 单一执行反馈 → GRPO 训练；本系统多源静态分析 → prompt 增强
  - Aggarwal: 人工审查 → 行为规则；本系统自动检测 → 定向重生成
  - AutoOptiCode: 语法/语义验证 → prompt 调整；本系统融合 5 种异构检测源
  - 多源融合 + 关联分析 + 修正优先级排序的组合在文献中未见
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


# 严重级别 → 权重映射
_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "warning": 0.3,
}

# 修正优先级阈值：低于此值的发现不触发重生成
_DEFAULT_PRIORITY_THRESHOLD: float = 0.4
# 单发现最大重试次数
_MAX_RETRIES_PER_FINDING: int = 2
# 新鲜度半衰期（分钟）
_FRESHNESS_HALFLIFE_MIN: float = 30.0


@dataclass
class AggregatedFinding:
    """聚合后的发现——可能合并了多个检测源的关联发现。"""
    finding_id: str            # SHA-256 前12字符
    filepath: str
    sources: list[str]         # 来源检测器列表
    descriptions: list[str]    # 各来源的问题描述
    max_severity: str
    combined_priority: float   # 0.0-1.0
    correction_prompt: str     # 预构建的修正 prompt 片段
    retry_count: int = 0
    last_retry_at: float = 0.0
    resolved: bool = False


@dataclass
class CorrectionResult:
    """单次重生成修正的结果。"""
    finding_id: str
    success: bool
    new_issues: list[str]      # 修正后仍存在的问题
    attempt_number: int


class SelfCorrectionLoop:
    """多源验证融合 + 闭环自校正引擎。线程安全。

    典型用法：
      loop = SelfCorrectionLoop()
      loop.ingest_from_blackboard(blackboard)      # 聚合发现
      triggers = loop.pending_corrections()         # 获取需修正的发现
      for t in triggers:
          prompt = loop.build_correction_prompt(t)  # 构建修正 prompt
          new_code = worker.re_generate(prompt)     # worker 重新生成
          loop.record_result(t.finding_id, new_code) # 记录结果
    """

    def __init__(self, priority_threshold: float = _DEFAULT_PRIORITY_THRESHOLD):
        self._findings: dict[str, AggregatedFinding] = {}
        self._history: list[CorrectionResult] = []
        self._lock = threading.Lock()
        self.priority_threshold = priority_threshold

    # 发现聚合

    def ingest_from_blackboard(self, blackboard) -> int:
        """从黑板拉取所有验证发现并聚合。返回新发现数。

        按 (filepath, 来源) 去重——同一文件的同一来源的多条发现合并。
        不同来源的同一文件发现分别保留，在 priority 计算时加权叠加。"""
        all_entries = blackboard.query("", max_results=200)

        # 延迟导入——避免与 self_correction_exec 的循环依赖
        from parallel_deep_dev.engine.self_correction_exec import (
            infer_source, extract_filepath, infer_severity,
        )

        validation_entries = [
            e for e in all_entries
            if e.entry_type in ("error", "warning")
            and any(
                t in (e.tags or [])
                for t in ("architecture", "quality", "convergence",
                          "review", "impact", "drift", "anomaly")
            )
        ]

        new_count = 0
        for entry in validation_entries:
            source = infer_source(entry)
            filepath = extract_filepath(entry)
            if not filepath:
                continue

            key = f"{filepath}:{source}"
            severity = infer_severity(entry)
            desc = entry.content

            with self._lock:
                if key in self._findings:
                    existing = self._findings[key]
                    if desc not in existing.descriptions:
                        existing.descriptions.append(desc)
                    if _SEVERITY_WEIGHT.get(severity, 0) > _SEVERITY_WEIGHT.get(existing.max_severity, 0):
                        existing.max_severity = severity
                else:
                    fid = hashlib.sha256(key.encode()).hexdigest()[:12]
                    self._findings[key] = AggregatedFinding(
                        finding_id=fid, filepath=filepath,
                        sources=[source], descriptions=[desc],
                        max_severity=severity,
                        combined_priority=self._calc_priority(
                            severity, entry.timestamp,
                        ),
                        correction_prompt="",
                    )
                    new_count += 1

        # 更新所有发现的优先级（考虑多个来源的叠加）
        self._recalc_priorities()
        return new_count

    def pending_corrections(self) -> list[AggregatedFinding]:
        """返回需要触发修正的发现列表。
        过滤条件：优先级 >= 阈值，未解决，重试次数未超限。"""
        with self._lock:
            return sorted(
                [
                    f for f in self._findings.values()
                    if (f.combined_priority >= self.priority_threshold
                        and not f.resolved
                        and f.retry_count < _MAX_RETRIES_PER_FINDING)
                ],
                key=lambda f: f.combined_priority, reverse=True,
            )

    def build_correction_prompt(self, finding: AggregatedFinding) -> str:
        """为聚合发现构建定向修正 prompt。"""
        sources_str = "、".join(finding.sources)
        descs = "\n".join(
            f"  [{i+1}] {d}" for i, d in enumerate(finding.descriptions[:5])
        )

        return (
            f"## 定向修正请求\n"
            f"文件: {finding.filepath}\n"
            f"检测源: {sources_str}\n"
            f"严重级别: {finding.max_severity}\n"
            f"修正优先级: {finding.combined_priority:.2f}\n\n"
            f"### 检测到的问题:\n{descs}\n\n"
            f"### 修正要求:\n"
            f"1. 仅修改必要的代码，保留所有其他功能不变\n"
            f"2. 如果问题是架构违规，确保修改后的代码符合分层规则\n"
            f"3. 如果问题是质量退化，检查是否重复生成了相同逻辑\n"
            f"4. 输出完整的修正后文件内容"
        )

    def record_result(
        self,
        finding_id: str,
        success: bool,
        new_issues: list[str] | None = None,
    ) -> None:
        """记录修正尝试的结果。"""
        with self._lock:
            for f in self._findings.values():
                if f.finding_id == finding_id:
                    f.retry_count += 1
                    f.last_retry_at = time.time()
                    if success:
                        f.resolved = True
                    break

            self._history.append(CorrectionResult(
                finding_id=finding_id,
                success=success,
                new_issues=new_issues or [],
                attempt_number=len([
                    h for h in self._history
                    if h.finding_id == finding_id
                ]) + 1,
            ))

    # 统计

    def stats(self) -> dict:
        with self._lock:
            resolved = sum(1 for f in self._findings.values() if f.resolved)
            pending = sum(
                1 for f in self._findings.values()
                if not f.resolved and f.retry_count < _MAX_RETRIES_PER_FINDING
            )
            exhausted = sum(
                1 for f in self._findings.values()
                if not f.resolved and f.retry_count >= _MAX_RETRIES_PER_FINDING
            )
            return {
                "total_findings": len(self._findings),
                "resolved": resolved,
                "pending": pending,
                "exhausted": exhausted,
                "correction_attempts": len(self._history),
                "success_rate": (
                    sum(1 for h in self._history if h.success) / len(self._history)
                    if self._history else 0.0
                ),
            }

    # 内部

    def _calc_priority(
        self,
        severity: str,
        timestamp: float,
        impact_score: float = 0.0,
    ) -> float:
        sw = _SEVERITY_WEIGHT.get(severity, 0.2)
        age_min = max((time.time() - timestamp) / 60.0, 0.0)
        freshness = math.exp(-age_min / _FRESHNESS_HALFLIFE_MIN)
        impact = max(impact_score, 0.1)
        return sw * impact * freshness

    def _recalc_priorities(self) -> None:
        """重新计算所有发现的优先级，考虑多源叠加。"""
        by_file: dict[str, list[AggregatedFinding]] = defaultdict(list)
        for f in self._findings.values():
            by_file[f.filepath].append(f)

        for filepath, findings in by_file.items():
            if len(findings) >= 2:
                # 多源关联：提升 20% 优先级
                boost = 1.2
            else:
                boost = 1.0

            for f in findings:
                source_bonus = len(f.sources) * 0.1
                f.combined_priority = min(
                    f.combined_priority * boost + source_bonus, 1.0,
                )


# 黑板解析 + 修正周期编排委托给 engine/self_correction_exec.py
# infer_source / extract_filepath / infer_severity / run_correction_cycle
