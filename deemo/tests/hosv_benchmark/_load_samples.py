# coding: utf-8
"""
样本清单加载. 枚举 samples/ 目录, 加载每个样本的 truth.json 与 vuln.c,
输出统一样本清单供扫描模块使用.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE, "samples")


@dataclass
class SampleSpec:
    """单个测试样本的描述."""
    sample_id: str = ""
    cve: str = ""
    mode: str = ""
    label: str = ""          # VULN / SAFE
    verdict: str = ""        # 期望判定
    src_path: str = ""
    truth: Dict = field(default_factory=dict)

    @property
    def is_expected_vuln(self) -> bool:
        return self.verdict == "VULN"


def load_samples(samples_dir: str = SAMPLES_DIR) -> List[SampleSpec]:
    """扫描样本目录, 加载全部样本清单."""
    specs: List[SampleSpec] = []
    if not os.path.isdir(samples_dir):
        return specs
    for entry in sorted(os.listdir(samples_dir)):
        d = os.path.join(samples_dir, entry)
        if not os.path.isdir(d):
            continue
        truth_p = os.path.join(d, "truth.json")
        src_p = os.path.join(d, "vuln.c")
        if not os.path.exists(truth_p) or not os.path.exists(src_p):
            continue
        with open(truth_p, "r", encoding="utf-8") as f:
            truth = json.load(f)
        specs.append(SampleSpec(
            sample_id=truth.get("sample", entry),
            cve=truth.get("cve", ""),
            mode=truth.get("mode", ""),
            label=truth.get("label", ""),
            verdict=truth.get("verdict", ""),
            src_path=src_p,
            truth=truth,
        ))
    return specs


def load_source(spec: SampleSpec) -> str:
    """读取样本源码."""
    with open(spec.src_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


__all__ = ['SampleSpec', 'load_samples', 'load_source', 'SAMPLES_DIR']
