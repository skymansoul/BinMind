"""
回归测试 — 扫描调度模块.

负责: 对每个样本的反汇编文本调度 HFP 检测, 输出原始判定
结果. 调度语义: 单进程顺序扫描, 每样本独立超时保护, 失败
样本标记 error 而非中断整体.

判定口径:
  OVERFLOW/POTENTIAL 视为"检出" (告警)
  SAFE 视为"未检出"
  供 result_collector 按样本 ground truth 归类 TP/FP/FN/TN.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..hfp.hfp_engine import detect_heap_overflow_hfp, suppress_and_report
from ..hfp.hfp_verdict import Verdict

SAFE_SAMPLES = {'safe_01_guard_narrow', 'safe_02_align_slack',
                'safe_03_same_source'}


@dataclass
class ScanResult:
    sample: str
    findings: List[dict] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str = ''
    detected: bool = False


class ScanScheduler:
    """按样本调度 HFP 扫描, 支持 IR 文本与二进制两种输入."""

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def scan_asm_file(self, asm_path: str) -> ScanResult:
        name = Path(asm_path).parent.name
        t0 = time.perf_counter()
        try:
            text = Path(asm_path).read_text(encoding='utf-8',
                                            errors='replace')
            from ..hfp.hfp_scan import asm_to_pseudo_ir
            pseudo_ir = asm_to_pseudo_ir(text)
            findings = detect_heap_overflow_hfp(pseudo_ir)
            kept, stats = suppress_and_report(findings)
            elapsed = (time.perf_counter() - t0) * 1000
            return ScanResult(
                sample=name,
                findings=[f.to_dict() for f in kept],
                stats=stats,
                elapsed_ms=round(elapsed, 2),
                detected=len(kept) > 0,
            )
        except Exception as e:  # 样本级失败不扩散
            elapsed = (time.perf_counter() - t0) * 1000
            return ScanResult(sample=name, error=str(e)[:300],
                              elapsed_ms=round(elapsed, 2))

    def scan_manifest(self, manifest: Dict) -> List[ScanResult]:
        """输入为 sample_compiler 的摘要 dict."""
        results = []
        for asm in manifest.get('asm_files', []):
            results.append(self.scan_asm_file(asm))
        return results


def is_vuln_sample(name: str) -> bool:
    return name not in SAFE_SAMPLES


def summarize(results: List[ScanResult]) -> Dict:
    """按 ground truth 归类, 输出混淆矩阵级统计."""
    tp = fp = fn = tn = 0
    per_sample = []
    for r in results:
        vuln = is_vuln_sample(r.sample)
        if vuln:
            if r.detected:
                tp += 1
            else:
                fn += 1
        else:
            if r.detected:
                fp += 1
            else:
                tn += 1
        per_sample.append({
            'sample': r.sample, 'vuln': vuln, 'detected': r.detected,
            'findings': len(r.findings), 'elapsed_ms': r.elapsed_ms,
            'error': r.error,
        })
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'recall': round(recall, 4), 'precision': round(precision, 4),
        'fpr': round(fpr, 4), 'per_sample': per_sample,
    }
