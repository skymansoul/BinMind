"""
UAF 使用点验证 组合引擎.

串联 事件提取 → 别名分组 → 链构建 → 值流门控核验, 对外提供
detect_uaf_uovf 入口. 输出按裁决分组的证据列表与统计, 供回归
与多工具对比使用.

与既有 UAF 检测器 (uaf_enhanced/uaf_detection_pipeline) 并行,
不修改既有逻辑, 仅作为独立复核通道提供证据.
"""

import time
from typing import List, Tuple

from core.uaf_use_types import (
    PtrEvent, UafChain, UafEvidence, UafVerdict, UovfStats,
)
from core.uaf_use_events import (
    extract_uovf_events, build_chains,
)
from core.uaf_use_verifier import verify_chains


def _drop_filtered(evidence: List[UafEvidence]) -> List[UafEvidence]:
    return [e for e in evidence if e.verdict != UafVerdict.FILTERED]


def analyze_uaf(ir_lines: List[str]) -> Tuple[
        List[PtrEvent], List[UafChain], List[UafEvidence], UovfStats]:
    """完整分析链, 返回各阶段产物供审计."""
    events, aliases, _registry = extract_uovf_events(ir_lines)
    chains = build_chains(events, aliases)
    evidence, stats = verify_chains(ir_lines, chains)
    return events, chains, evidence, stats


def detect_uaf_uovf(ir_lines: List[str]) -> Tuple[
        List[UafEvidence], UovfStats]:
    """UAF 使用点验证 入口: 返回核验证据与统计.

    保留项为 CONFIRMED/UNCERTAIN 证据, FILTERED 已排除.
    """
    t0 = time.perf_counter()
    events, aliases, _registry = extract_uovf_events(ir_lines)
    chains = build_chains(events, aliases)
    evidence, stats = verify_chains(ir_lines, chains)
    stats.elapsed_ms = (time.perf_counter() - t0) * 1000
    kept = _drop_filtered(evidence)
    return kept, stats
