"""
内部共享工具 — 密码学检测模块的通用模式匹配和字节扫描函数。

创建: 2024-11-05 09:15
修改:
  2025-09-20 09:15 — 从 crypto_detector, lwc_detector, whitebox_detector 等模块提取公共模式

目的:
  减少代码重复, 但不强制所有模块迁移 — 各模块可选择直接使用或保留自身实现。
  设计为无依赖纯函数, 仅依赖 Python stdlib。
"""

from typing import List, Optional, Tuple


def scan_all(data: bytes, pattern: bytes, start: int = 0, overlap: bool = False) -> List[int]:
    """
    在字节序列中搜索模式的所有非重叠出现。
    返回偏移列表; overlap=True时允许重叠匹配。
    """
    positions: List[int] = []
    pos = start
    step = 1 if overlap else max(1, len(pattern))
    n = len(data)
    while pos <= n - len(pattern):
        if data[pos:pos + len(pattern)] == pattern:
            positions.append(pos)
            pos += step
        else:
            pos += 1
    return positions


def matches_any(data: bytes, offset: int, patterns: List[Tuple[bytes, str, float]]
                ) -> List[Tuple[str, float]]:
    """
    检查data[offset:]是否匹配patterns中的任何条目。
    返回 [(描述, 置信度), ...] 的匹配列表。
    用于字符串/操作码/API指纹匹配。
    """
    hits: List[Tuple[str, float]] = []
    for pat, desc, conf in patterns:
        if len(pat) <= len(data) - offset:
            if data[offset:offset + len(pat)] == pat:
                hits.append((desc, conf))
    return hits


def count_patterns_in_region(data: bytes, start: int, end: int,
                              patterns: List[bytes]) -> int:
    """统计区域内所有模式的出现总次数。"""
    region = data[start:min(end, len(data))]
    total = 0
    for pat in patterns:
        total += region.count(pat)
    return total


def classify_by_prefix(data: bytes, offset: int,
                        lookup: dict, default=None):
    """
    按单字节前缀分类 — 用于操作码分类。
    lookup: {byte_val: category}
    """
    if offset >= len(data):
        return default
    return lookup.get(data[offset], default)


def sliding_window_check(data: bytes, window_size: int, step: int,
                          check_fn) -> List[Tuple[int, object]]:
    """
    对data做滑动窗口扫描, 每个窗口调用check_fn(window, offset)。
    check_fn返回None表示无发现, 否则返回任意结果。
    返回 [(偏移, check_fn结果), ...]。
    """
    results: List[Tuple[int, object]] = []
    for start in range(0, len(data) - window_size + 1, step):
        window = data[start:start + window_size]
        result = check_fn(window, start)
        if result is not None:
            results.append((start, result))
    return results
