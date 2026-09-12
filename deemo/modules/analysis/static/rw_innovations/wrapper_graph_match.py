"""WrapperGraphMatch - 包装器图匹配 (stage 82).

alloc/copy 包装器识别后构建"包装器调用图", 调用图同构对 -> 跨函数
配对. 与 cross_function_heap_tracker 不同: 图同构而非数据流合成.

设计决策:
  - 识别包装器函数: 函数体内有 malloc/calloc/memcpy 调用
  - 构建调用图: {wrapper -> [被调函数]}
  - 对同构子图对 (边集合相同) 做跨函数配对
  - 配对成功 -> 同构安全
"""

import re
from typing import Dict, List, Optional, Set, Tuple


def _find_wrappers(pseudocode: str) -> Dict[str, List[str]]:
    """识别包装器函数及其被调函数."""
    wrappers: Dict[str, List[str]] = {}
    current = None
    for line in pseudocode.splitlines():
        m_def = re.search(r"\b(\w+)\s*\([^)]*\)\s*\{", line)
        if m_def:
            current = m_def.group(1)
            wrappers.setdefault(current, [])
            continue
        if "}" in line:
            current = None
            continue
        if current:
            m_call = re.search(r"\b(?:malloc|calloc|realloc|memcpy|memmove|strcpy)\s*\(", line)
            if m_call:
                callee = re.search(r"\b(\w+)\s*\(", line).group(1)
                wrappers[current].append(callee)
    return wrappers


def _graph_key(wrappers: Dict[str, List[str]]) -> Dict[str, Tuple[str, ...]]:
    """为每个 wrapper 构造规范签名: 被调函数集合排序元组."""
    return {name: tuple(sorted(set(callees)))
            for name, callees in wrappers.items()}


def run_wrapper_graph_match(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """包装器图匹配. 返回 findings."""
    findings: List[dict] = []
    wrappers = _scan_wrappers(pseudocode)
    keys = _graph_keys(wrappers)
    names = list(keys.keys())
    seen_pairs = set()
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            if keys[a] == keys[b]:
                pair = tuple(sorted((a, b)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": 0.85,
                    "description": f"iso_pair {a}<->{b} "
                                   f"callees={keys[a]}",
                    "verdict": "isomorphic",
                    "source": "wrapper_graph_match",
                })
    return findings


def _graph_keys(wrappers: Dict[str, List[str]]) -> Dict[str, Tuple[str, ...]]:
    return {name: tuple(sorted(callees))
            for name, callees in wrappers.items()}


def _scan_wrappers(pseudocode: str) -> Dict[str, List[str]]:
    return _collect_wrappers(pseudocode)


def _collect_wrappers(pseudocode: str) -> Dict[str, List[str]]:
    wrappers: Dict[str, List[str]] = {}
    current = None
    for line in pseudocode.splitlines():
        m_def = re.search(r"\b(\w+)\s*\([^)]*\)\s*\{", line)
        if m_def:
            current = m_def.group(1)
            wrappers.setdefault(current, [])
            continue
        if "}" in line and current:
            current = None
            continue
        if current:
            m_call = re.search(r"\b(\w+)\s*\(", line)
            if m_call and m_call.group(1) in (
                    "malloc", "calloc", "realloc",
                    "memcpy", "memmove", "strcpy"):
                wrappers[current].append(m_call.group(1))
    return wrappers


if __name__ == "__main__":
    demo = """\
wrap_alloc(n) { p = malloc(n); return p; }
copy_alloc(n) { q = malloc(n); return q; }
"""
    out = run_wrapper_graph_match(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])