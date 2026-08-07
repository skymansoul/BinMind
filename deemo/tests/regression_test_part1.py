"""
堆溢出检测回归测试套件 — 自动编译/扫描/收集/比对.

流程:
  1. compile: 编译所有样本为 ELF
  2. scan: 对每个二进制运行堆溢出检测
  3. collect: 收集检测结果, 与预期比对
  4. report: 生成精度/召回/误报率报告

预期定义 (EXPECTED_MAP):
  - should_detect=True: 真阳性, 检测器应报告
  - should_detect=False: 误报测试, 检测器不应报告 (深度过滤目标)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 预期结果映射
# sample_id → {vuln_type, should_detect, cwe, description}
EXPECTED_MAP: Dict[str, Dict[str, Any]] = {
    # True Positives — 检测器必须报告
    "sample_01": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "malloc(64) + memset(256)"},
    "sample_02": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "malloc in loop + memset overflow"},
    "sample_03": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "realloc shrink + overflow"},
    "sample_04": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "calloc + overflow"},
    "sample_05": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "realloc grow + overflow via memset"},
    "sample_06": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "multi buffer overflow"},
    # False Positives — 深度过滤应消除的误报
    "sample_07": {"vuln_type": "heap_overflow", "should_detect": False,
                  "cwe": "CWE-122", "desc": "FP: guard pattern if(n>MAX)n=MAX"},
    "sample_08": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "struct member overflow"},
    "sample_09": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "callback struct + buf overflow"},
    "sample_10": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "indirect pointer overflow"},
    "sample_11": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "dynamic size overflow"},
    "sample_12": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "adjacent buffer overflow"},
    "sample_13": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "loop write overflow"},
    # FP: malloc(0) allocation — 实现定义行为
    "sample_14": {"vuln_type": "heap_overflow", "should_detect": False,
                  "cwe": "CWE-122", "desc": "FP: malloc(0) + overflow"},
    "sample_15": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "strncpy bound bypass"},
    # FP: realloc((size_t)-1) — 分配失败路径
    "sample_16": {"vuln_type": "heap_overflow", "should_detect": False,
                  "cwe": "CWE-122", "desc": "FP: realloc(SIZE_MAX) allocation fail"},
    "sample_17": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "sprintf overflow"},
    "sample_18": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "memmove overflow"},
}


@dataclass
class ScanResult:
    """单个样本的扫描结果."""
    sample_id: str
    binary_path: str
    expected: bool          # should_detect
    detected: bool          # 是否报告了漏洞
    num_findings: int = 0
    findings: List[Dict] = field(default_factory=list)
    compile_ok: bool = False
    scan_ok: bool = False
    error: str = ""


@dataclass
class RegressionReport:
    """回归测试汇总报告."""
    total: int = 0
    compiled: int = 0
    scanned: int = 0
    true_positives: int = 0    # should_detect=True AND detected=True
    false_positives: int = 0   # should_detect=False AND detected=True
    true_negatives: int = 0    # should_detect=False AND detected=False
    false_negatives: int = 0   # should_detect=True AND detected=False
    results: List[ScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        """误报率: FP / (FP + TN)."""
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    def summary(self) -> str:
        return (
            f"Regression Report:\n"
            f"  Compiled: {self.compiled}/{self.total}\n"
            f"  Scanned:  {self.scanned}/{self.compiled}\n"
            f"  TP={self.true_positives} FP={self.false_positives} "
            f"TN={self.true_negatives} FN={self.false_negatives}\n"
            f"  Precision={self.precision:.2%} Recall={self.recall:.2%} "
            f"F1={self.f1:.2%} FP_Rate={self.fp_rate:.2%}\n"
            f"  Errors: {len(self.errors)}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total': self.total, 'compiled': self.compiled,
            'scanned': self.scanned,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'precision': self.precision, 'recall': self.recall,
            'f1': self.f1, 'fp_rate': self.fp_rate,
            'errors': self.errors,
        }


