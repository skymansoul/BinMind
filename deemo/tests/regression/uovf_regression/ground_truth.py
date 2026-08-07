"""
UAF 基准样本发现与标签加载.

数据源:
  tests/uaf_benchmark       12 样本, 带 truth.json (expect_uaf)
  tests/regression/samples_uaf  15 真实 CVE 样本, 目录名推断为漏洞
  tests/cve_samples_uaf     TP_*/FP_*/safe_* 挑战样本, 目录名推断

truth.json 优先; 目录名含 safe/FP/tn/free_then_null/realloc_then_use/
refcount/scope_guard 等判为安全.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
_ROOTS = [
    PROJECT_ROOT / 'tests' / 'uaf_benchmark',
    PROJECT_ROOT / 'tests' / 'regression' / 'samples_uaf',
    PROJECT_ROOT / 'tests' / 'cve_samples_uaf',
]

_SAFE_HINTS = ('safe', 'fp_', 'tn_', 'null_after_free',
               'realloc_then_use', 'refcount', 'scope_guard',
               'realloc_self', 'branch_exclusive', 'different_scope',
               'guarded_use', 'reassign_after_free', 'guarded_path')


def _truth_label(sample_dir: Path) -> bool:
    """读取 truth.json 的 expect_uaf; 无则按目录名推断."""
    tf = sample_dir / 'truth.json'
    if tf.exists():
        try:
            return bool(json.loads(tf.read_text(encoding='utf-8'))
                        .get('expect_uaf', True))
        except (json.JSONDecodeError, OSError):
            pass
    name = sample_dir.name.lower()
    return not any(h in name for h in _SAFE_HINTS)


def discover_uaf_samples() -> List[Tuple[str, Path, Path, bool]]:
    """发现全部 UAF 样本.

    返回 [(样本名, 源码路径, 目录, 是否漏洞)].
    """
    out: List[Tuple[str, Path, Path, bool]] = []
    seen = set()
    for root in _ROOTS:
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if not entry.is_dir() or entry.name in seen:
                continue
            if root.name == 'cve_samples_uaf' and not (
                    entry.name.lower().startswith(('tp_', 'fp_', 'safe',
                                                   'tn_'))):
                continue
            c_files = sorted(entry.glob('*.c'))
            if not c_files:
                continue
            seen.add(entry.name)
            out.append((entry.name, c_files[0], entry,
                        _truth_label(entry)))
    return out


def cve_id_of(sample_dir: Path) -> str:
    m = re.search(r'(CVE[-_ ]?\d{4}[-_ ]?\d{4,})',
                  sample_dir.name, re.IGNORECASE)
    if m:
        return m.group(1).upper().replace('_', '-')
    readme = sample_dir / 'README.md'
    if readme.exists():
        m = re.search(r'(CVE-\d{4}-\d{4,})',
                      readme.read_text(encoding='utf-8', errors='replace'),
                      re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return ''


def load_all() -> List[Dict]:
    out = []
    for name, src, sdir, is_vuln in discover_uaf_samples():
        out.append({'name': name, 'source': str(src), 'dir': str(sdir),
                    'is_vuln': is_vuln, 'cve_id': cve_id_of(sdir)})
    return out
