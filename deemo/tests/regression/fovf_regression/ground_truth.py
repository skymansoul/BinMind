"""
格式化字符串基准样本发现与标签加载.

数据源:
  tests/fmt_samples                15 语义命名样本, 'safe' 判安全
  tests/regression/samples_fmt     15 样本, 均漏洞
  tests/format_string_samples      15 CVE 样本, 均漏洞
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
_ROOTS = [
    PROJECT_ROOT / 'tests' / 'fmt_samples',
    PROJECT_ROOT / 'tests' / 'regression' / 'samples_fmt',
    PROJECT_ROOT / 'tests' / 'format_string_samples',
    PROJECT_ROOT / 'samples' / 'format_string',
]

# samples/format_string 的 TP/TN 清单 (取自 tests/regression_format_string.py)
_MANIFEST = {
    'sample_fmt_01': True, 'sample_fmt_02': False,
    'sample_fmt_03': True, 'sample_fmt_04': True,
    'sample_fmt_05': True, 'sample_fmt_06': False,
    'sample_fmt_07': True, 'sample_fmt_08': True,
    'sample_fmt_09': False, 'sample_fmt_10': True,
    'sample_fmt_11': True, 'sample_fmt_12': True,
}


def _infer_vuln(name: str, root: Path) -> bool:
    if name in _MANIFEST:
        return _MANIFEST[name]
    n = name.lower()
    return not ('safe' in n or n.startswith('tn_'))


def discover_fmt_samples() -> List[Tuple[str, Path, Path, bool]]:
    out: List[Tuple[str, Path, Path, bool]] = []
    seen = set()
    for root in _ROOTS:
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if not entry.is_dir() or entry.name in seen:
                continue
            c_files = sorted(entry.glob('*.c'))
            if not c_files:
                continue
            seen.add(entry.name)
            out.append((entry.name, c_files[0], entry,
                        _infer_vuln(entry.name, root)))
    return out


def cve_id_of(sample_dir: Path) -> str:
    m = re.search(r'(CVE[-_ ]?\d{4}[-_ ]?\d{4,})',
                  sample_dir.name, re.IGNORECASE)
    if m:
        return m.group(1).upper().replace('_', '-')
    return ''


def load_all() -> List[Dict]:
    out = []
    for name, src, sdir, is_vuln in discover_fmt_samples():
        out.append({'name': name, 'source': str(src), 'dir': str(sdir),
                    'is_vuln': is_vuln, 'cve_id': cve_id_of(sdir)})
    return out
