"""
生成堆溢出样本目录 doc/heap_sample_catalog.md.

汇总三个样本根目录的全部堆溢出样本: CVE 编号、漏洞模式、触发条件、
预期判定、目录位置. 数据来源: ground_truth.json + README.md.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
_ROOTS = [
    PROJECT_ROOT / 'tests' / 'cve_samples' / 'heap_overflow',
    PROJECT_ROOT / 'samples' / 'cve_heap_overflow',
    PROJECT_ROOT / 'tests' / 'regression' / 'samples_heap',
]


def _gt_map(root: Path) -> dict:
    gt_file = root / 'ground_truth.json'
    if not gt_file.exists():
        return {}
    try:
        return json.loads(gt_file.read_text(encoding='utf-8')).get('samples', {})
    except (json.JSONDecodeError, OSError):
        return {}


def _readme_info(sdir: Path) -> tuple:
    cve, pattern = '', ''
    readme = sdir / 'README.md'
    if readme.exists():
        text = readme.read_text(encoding='utf-8', errors='replace')
        m = re.search(r'CVE-\d{4}-\d{4,}', text)
        if m:
            cve = m.group(0)
        m = re.search(r'## Pattern\s*\n(.+)', text)
        if m:
            pattern = m.group(1).strip()[:70]
    return cve, pattern


def collect() -> list:
    rows = []
    seen = set()
    for root in _ROOTS:
        if not root.is_dir():
            continue
        gt = _gt_map(root)
        for entry in sorted(root.iterdir()):
            if not entry.is_dir() or entry.name in seen:
                continue
            if root.name == 'samples_heap' and not re.match(r'CVE-?\d', entry.name):
                continue
            seen.add(entry.name)
            info = gt.get(entry.name, {})
            is_vuln = bool(info.get('expected_vuln', True)) if info else 'safe' not in entry.name.lower()
            cve, pattern = _readme_info(entry)
            rows.append({
                'name': entry.name,
                'root': root.name,
                'vuln': is_vuln,
                'cve': cve or info.get('cve', ''),
                'pattern': pattern or info.get('pattern', '') or entry.name,
            })
    return rows


def render(rows: list) -> str:
    lines = [
        '# 堆溢出检测基准样本目录',
        '',
        '共收录 %d 个堆溢出相关样本, 分布于三个根目录. 每个样本目录内' % len(rows),
        '包含 C 源码、Makefile 与 README (CVE、触发条件、检测预期).',
        '标签来源: tests/cve_samples/heap_overflow/ground_truth.json 为准,',
        'samples_heap 下仅收录命名含 CVE 的真实样本.',
        '',
        '## 样本总览',
        '',
        '| 样本 | CVE | 模式 / 触发条件 | 预期 |',
        '|------|-----|------------------|------|',
    ]
    for r in sorted(rows, key=lambda x: (x['root'], x['name'])):
        vuln = '漏洞' if r['vuln'] else '安全'
        lines.append(f"| {r['name']} | {r['cve'] or '-'} | {r['pattern']} | {vuln} |")
    return '\n'.join(lines)


def main() -> None:
    rows = collect()
    doc = render(rows)
    out = PROJECT_ROOT / 'doc' / 'heap_sample_catalog.md'
    out.write_text(doc, encoding='utf-8')
    print(f'已生成 {out} ({len(rows)} 样本)')


if __name__ == '__main__':
    main()
