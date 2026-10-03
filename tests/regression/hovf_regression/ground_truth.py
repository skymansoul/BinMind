"""
堆溢出基准样本目录与标签加载.

统一读取 tests/cve_samples/heap_overflow/ground_truth.json 与
samples/cve_heap_overflow 目录, 输出 (样本名, 源码路径, 是否漏洞) 列表.
ground_truth.json 缺失时按目录名回退推断: 含 safe 字样的判为安全.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
_SAMPLE_ROOTS = [
    PROJECT_ROOT / 'tests' / 'cve_samples' / 'heap_overflow',
    PROJECT_ROOT / 'samples' / 'cve_heap_overflow',
    PROJECT_ROOT / 'tests' / 'regression' / 'samples_heap',
]


def load_ground_truth(root: Path) -> Dict[str, bool]:
    """加载单目录 ground_truth.json, 返回 {样本名: 是否漏洞}."""
    gt_file = root / 'ground_truth.json'
    if not gt_file.exists():
        return {}
    try:
        data = json.loads(gt_file.read_text(encoding='utf-8'))
        out = {}
        for name, info in data.get('samples', {}).items():
            if isinstance(info, dict):
                out[name] = bool(info.get('expected_vuln', True))
        return out
    except (json.JSONDecodeError, KeyError, OSError):
        return {}


def _infer_vuln(sample_dir: Path) -> bool:
    name = sample_dir.name.lower()
    if 'safe' in name:
        return False
    return True


def discover_heap_samples() -> List[Tuple[str, Path, Path, bool]]:
    """发现全部堆溢出样本.

    返回 [(样本名, 源码路径, 目录, 是否漏洞)]. 同名目录按根顺序
    去重, 优先取 tests/cve_samples/heap_overflow.
    """
    samples: List[Tuple[str, Path, Path, bool]] = []
    seen = set()
    for root in _SAMPLE_ROOTS:
        if not root.is_dir():
            continue
        gt = load_ground_truth(root)
        for entry in sorted(root.iterdir()):
            if not entry.is_dir() or entry.name in seen:
                continue
            # samples_heap 无 ground_truth.json, 仅收录命名含 CVE 的
            # 真实样本, 排除 GAPSBV-STRESS / LOOP-CUMULATIVE 等
            # 标签不明确的自研压力样本.
            if root.name == 'samples_heap' and not re.match(
                    r'CVE-?\d', entry.name):
                continue
            c_files = sorted(entry.glob('*.c'))
            if not c_files:
                continue
            seen.add(entry.name)
            is_vuln = gt.get(entry.name, _infer_vuln(entry))
            samples.append((entry.name, c_files[0], entry, is_vuln))
    return samples


def cve_id_of(sample_dir: Path) -> str:
    """从目录名或 README 提取 CVE 编号."""
    m = re.search(r'(CVE[-_ ]?\d{4}[-_ ]?\d{4,})',
                  sample_dir.name, re.IGNORECASE)
    if m:
        return m.group(1).upper().replace('_', '-')
    readme = sample_dir / 'README.md'
    if readme.exists():
        text = readme.read_text(encoding='utf-8', errors='replace')
        m = re.search(r'(CVE-\d{4}-\d{4,})', text, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return ''


def load_all() -> List[Dict]:
    """加载全部样本元数据, 供编译/扫描/收集模块复用."""
    out = []
    for name, src, sdir, is_vuln in discover_heap_samples():
        out.append({
            'name': name,
            'source': str(src),
            'dir': str(sdir),
            'is_vuln': is_vuln,
            'cve_id': cve_id_of(sdir),
        })
    return out
