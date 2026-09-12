"""JccPolarityMap - 条件跳转极性图 (stage 57).

把每个 jcc 的 taken/fallthrough 边记为 ±极性边, 构建函数内极性图,
对告警写入点做极性可达性传播, 若写入仅在反极性路径可达则过滤.
与 PCFV 支配判定不同: 极性图是图遍历而非支配树.

设计决策:
  - 每行 jcc 生成 taken 边 (+1) 与 fallthrough 边 (-1)
  - 从函数入口沿边做极性可达传播 (BFS)
  - 写入点仅在负极性可达时判为过滤
"""

import re
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple


def _build_graph(lines: List[str]) -> Dict[int, List[Tuple[int, int]]]:
    """构建 {行号: [(后继行号, 极性)]}, 0 基行号."""
    graph: Dict[int, List[Tuple[int, int]]] = defaultdict(list)
    jcc_pat = re.compile(r"\b(j[a-z]{1,2})\s+(\w+)")
    for i, line in enumerate(lines):
        m = jcc_pat.search(line)
        if not m:
            if i + 1 < len(lines):
                graph[i].append((i + 1, 0))
            continue
        target = _resolve_target(m.group(2), lines)
        graph[i].append((target, +1))      # taken 边
        if i + 1 < len(lines):
            graph[i].append((i + 1, -1))   # fallthrough 边
    return graph


def _resolve_target(label: str, lines: List[str]) -> int:
    """把标签解析为行号 (0 基)."""
    for idx, line in enumerate(lines):
        if line.strip().startswith(label + ":"):
            return idx
    return len(lines) - 1


def _reach_polarity(graph: Dict[int, List[Tuple[int, int]]],
                    start: int) -> Dict[int, int]:
    """极性可达性传播: 返回 {行号: 1正 / -1反 / 0双极性}."""
    reach: Dict[int, int] = {}
    dq = deque([(start, 1)])
    while dq:
        node, pol = dq.popleft()
        old = reach.get(node)
        if old is None:
            reach[node] = pol
        elif old != pol and old != 0:
            reach[node] = 0      # 双极性路径均可达
            continue
        for nxt, edge in graph.get(node, []):
            new_pol = pol if edge == 0 else (pol if edge == 1 else -pol)
            dq.append((nxt, new_pol))
    return reach


def run_jcc_polarity_map(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """条件跳转极性图. 返回 findings."""
    lines = pseudocode.splitlines()
    if not lines:
        return []
    graph = _build_polarity_graph(lines)
    reach = _reach_polarity(graph, 0)
    findings: List[dict] = []
    write_pat = re.compile(r"\[[^\]]+\]\s*=")
    for i, line in enumerate(lines):
        if not write_pat.search(line):
            continue
        pol = reach.get(i, 0)
        if pol == 1:
            verdict, conf = "reachable", 1.0
        elif pol == -1:
            verdict, conf = "filtered", 0.2
        else:
            verdict, conf = "ambiguous", 0.5
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"write@line{i + 1} polarity={pol}",
            "verdict": verdict,
            "source": "jcc_polarity_map",
        })
    return findings


def _build_polarity_graph(lines: List[str]) -> Dict[int, List[Tuple[int, int]]]:
    return _build_graph(lines)


if __name__ == "__main__":
    demo = """\
push rbp;
jz skip;
mov [rbx+8], 0x41;
skip:
nop;
"""
    out = run_jcc_polarity_map(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"], item["confidence"])