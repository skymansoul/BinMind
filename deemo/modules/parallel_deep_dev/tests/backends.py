"""漏洞类别注册表 — 样本目录与检测器按类别索引。

heap → 容量感知耦合边界验证/基线(堆溢出); uaf → LCV/基线(UAF)。
检测器延迟加载, 避免类别间硬依赖。
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TESTS = Path(__file__).resolve().parent

CLASS_ROOTS = {
    'heap': {
        'vuln_dir': ROOT / 'samples' / 'heap_overflow_cve',
        'safe_dir': ROOT / 'samples' / 'heap_safe_fp',
        'results': TESTS / 'results',
        'tool': 'CACBV',
    },
    'uaf': {
        'vuln_dir': ROOT / 'samples' / 'uaf_cve',
        'safe_dir': ROOT / 'samples' / 'uaf_fp',
        'results': TESTS / 'results_uaf',
        'tool': 'LCV',
    },
    'fmt': {
        'vuln_dir': ROOT / 'samples' / 'fmt_cve',
        'safe_dir': ROOT / 'samples' / 'fmt_fp',
        'results': TESTS / 'results_fmt',
        'tool': 'FSV',
    },
}


def load_detectors(name: str):
    """按类别加载 (detect, baseline, 工具名)。"""
    if name == 'heap':
        from heapov import analyze_source, analyze_baseline
        return analyze_source, analyze_baseline, 'CACBV'
    if name == 'uaf':
        from uafov import analyze_source, analyze_baseline
        return analyze_source, analyze_baseline, 'LCV'
    if name == 'fmt':
        from fmtov import analyze_source, analyze_baseline
        return analyze_source, analyze_baseline, 'FSV'
    raise ValueError(f'unknown sample class: {name}')
