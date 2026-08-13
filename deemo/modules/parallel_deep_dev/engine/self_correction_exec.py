"""
创建: 2024-11-05
自校正执行器 — 黑板解析 + 修正周期编排。

从 self_correction.py 分离，处理黑板条目解析、修正 prompt 构建、worker 回调编排。
保持核心 SelfCorrectionLoop 类专注于发现聚合和优先级计算。
"""

from __future__ import annotations

import re
from parallel_deep_dev.engine.self_correction import (
    SelfCorrectionLoop, AggregatedFinding,
)


def infer_source(entry) -> str:
    """从黑板条目标签推断检测器来源。"""
    tags = entry.tags or []
    source_map = {
        "drift": "drift_guard", "architecture": "drift_guard",
        "quality": "quality_sentinel", "anomaly": "quality_sentinel",
        "convergence": "semantic_dedup", "dedup": "semantic_dedup",
        "review": "adversarial_review",
        "impact": "causal_graph", "causal": "causal_graph",
    }
    for tag in tags:
        if tag in source_map:
            return source_map[tag]
    return entry.source_module or "unknown"


def extract_filepath(entry) -> str | None:
    """从黑板条目内容或 meta 中提取文件路径。"""
    content = entry.content
    m = re.search(r'([\w/\-\.]+\.py)', content)
    if m:
        return m.group(1)
    meta = getattr(entry, 'meta', {}) or {}
    if isinstance(meta, dict) and 'target' in meta:
        return str(meta['target'])
    return None


def infer_severity(entry) -> str:
    """从黑板条目内容和类型推断严重级别。"""
    content = entry.content.lower() if hasattr(entry, 'content') else ""
    if 'critical' in content:
        return 'critical'
    if 'high' in content or '严重' in str(getattr(entry, 'content', '')):
        return 'high'
    if 'medium' in content:
        return 'medium'
    if getattr(entry, 'entry_type', '') == 'error':
        return 'high'
    return 'warning'


def run_correction_cycle(
    loop: SelfCorrectionLoop,
    blackboard,
    worker_callback=None,
    max_corrections_per_cycle: int = 5,
) -> dict:
    """执行一轮自校正周期：拉取发现 → 筛选 → 构建 prompt → 执行修正。

    worker_callback 签名为 (AggregatedFinding, str) -> bool。
    若为 None，仅返回待修正列表。"""
    new_count = loop.ingest_from_blackboard(blackboard)
    pending = loop.pending_corrections()[:max_corrections_per_cycle]

    corrected = 0
    if worker_callback is not None:
        for finding in pending:
            prompt = loop.build_correction_prompt(finding)
            try:
                success = worker_callback(finding, prompt)
                loop.record_result(finding.finding_id, success)
                if success:
                    corrected += 1
            except Exception:
                loop.record_result(finding.finding_id, False)

    return {
        "new_findings": new_count,
        "pending_corrections": len(pending),
        "corrected": corrected,
        "stats": loop.stats(),
    }
