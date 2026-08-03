"""
Crash dump analysis. Parses crash data (ASAN output, GDB backtraces,
coredump summaries) and classifies crash types. Feeds into exploit_gen.
"""

import logging
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

SEVERITY_MAP = {
    'SIGSEGV': 'Critical',
    'SIGABRT': 'High',
    'SIGILL':  'High',
    'SIGBUS':  'Critical',
    'SIGFPE':  'Medium',
    'heap-buffer-overflow': 'Critical',
    'stack-buffer-overflow': 'Critical',
    'use-after-free':        'Critical',
    'double-free':           'Critical',
    'heap-use-after-free':   'Critical',
    'global-buffer-overflow': 'High',
    'stack-use-after-return': 'High',
    'memory-leak':            'Low',
    'unknown-crash':          'Medium',
}


def _guess_crash_type(text: str) -> str:
    """Parse crash data text to identify the crash category."""
    if 'heap-use-after-free' in text or 'use after free' in text.lower():
        return 'use-after-free'
    if 'heap-buffer-overflow' in text:
        return 'heap-buffer-overflow'
    if 'stack-buffer-overflow' in text:
        return 'stack-buffer-overflow'
    if 'double-free' in text or 'double free' in text.lower():
        return 'double-free'
    if 'SIGSEGV' in text:
        return 'SIGSEGV'
    if 'SIGABRT' in text:
        return 'SIGABRT'
    if 'SIGILL' in text:
        return 'SIGILL'
    if 'global-buffer-overflow' in text:
        return 'global-buffer-overflow'
    if 'memory-leak' in text or 'memory leak' in text.lower():
        return 'memory-leak'
    return 'unknown-crash'


def _extract_addresses(text: str) -> List[str]:
    """Pull hex addresses from crash output."""
    pattern = r'(0x[0-9a-fA-F]{6,16})'
    return re.findall(pattern, text)


def parse_crash(raw: str) -> Dict[str, Any]:
    """Parse raw crash output into a structured dict."""
    crash_type = _guess_crash_type(raw)
    addrs = _extract_addresses(raw)

    severity = SEVERITY_MAP.get(crash_type, 'Medium')

    return {
        'crash_type': crash_type,
        'severity': severity,
        'addresses': addrs[:10],
        'raw': raw,
        'exploitable': severity in ('Critical', 'High'),
    }


def load_crash_file(path: str) -> Optional[Dict]:
    """Read a crash log from disk and parse it."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            content = fh.read(65536)  # max 64KB
    except (OSError, IOError) as e:
        _log.error("Cannot read crash file %s: %s", path, e)
        return None

    result = parse_crash(content)
    result['source_file'] = path
    return result


def analyze_crash_for_exploit(crash: Dict) -> Dict:
    """Determine exploitability and suggest primitive types."""
    exploitable = crash.get('exploitable', False)
    crash_type = crash.get('crash_type', 'unknown')

    analysis = {
        'exploitable': exploitable,
        'crash_type': crash_type,
        'primitives': [],
        'notes': [],
    }

    if crash_type in ('heap-buffer-overflow', 'use-after-free'):
        analysis['primitives'].append('arbitrary-read')
        analysis['primitives'].append('arbitrary-write')
        analysis['notes'].append(
            'Heap corruption — check heap allocator version and layout')
    elif crash_type == 'stack-buffer-overflow':
        analysis['primitives'].append('rip-control')
        analysis['notes'].append('Classic stack smash — check for canaries')
    elif crash_type == 'SIGSEGV':
        analysis['primitives'].append('possible-rip-control')
        analysis['notes'].append(
            'Need to determine if the fault address is controllable')
    elif crash_type == 'double-free':
        analysis['primitives'].append('arbitrary-write')
        analysis['notes'].append(
            'Double-free can lead to tcache/fastbin poisoning')

    return analysis


# =============================================================================
# 新增多维原语指纹识别
# 提供比 analyze_crash_for_exploit() 更细粒度的可利用性评估，
# 包含寄存器可控性分析、堆操作序列提取、多维评分和策略推荐。
# 参考: Lancet (USENIX Security 2025), HEXP (IEEE 2025), AutoPwn (2024)
# =============================================================================

def fingerprint_crash_detailed(
    crash_data: dict,
    stack_bounds: tuple = None,
    heap_bounds: list = None,
) -> dict:
    """多维崩溃原语指纹识别——可替代 analyze_crash_for_exploit 的更精细接口。

    返回值包含:
      - registers: 每个寄存器的可控性分析
      - heap_ops: 提取的堆操作序列
      - scores: rip_control / stack_control / heap_control / info_leak / overall
      - recommended_primitives: 推荐的利用原语类型
      - recommended_strategy: 推荐的利用策略文本

    调用方无额外依赖——纯Python标准库实现。
    """
    try:
        from core.crash_primitive_fingerprint import fingerprint_crash
        return fingerprint_crash(crash_data, stack_bounds, heap_bounds)
    except ImportError:
        # 降级到旧接口
        _log.warning("crash_primitive_fingerprint 不可用，降级到 analyze_crash_for_exploit")
        return analyze_crash_for_exploit(crash_data)
