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
        elif old == 0:
            # 已是双极性，极性不再变化，跳过重复传播
            continue
        elif old != pol:
            # 极性冲突，合并为双极性0并继续向下传播
            reach[node] = 0
            pol = 0
        else:
            # 极性相同，无需重复传播
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

    # C 风格 if 条件块写点可达性判断
    c_findings = _c_if_reachability(lines)
    for cf in c_findings:
        cf["function"] = func_name or "unknown"
        findings.append(cf)
    return findings


def _build_polarity_graph(lines: List[str]) -> Dict[int, List[Tuple[int, int]]]:
    return _build_graph(lines)


# C 风格 if 条件块写点可达性判断
_C_IF_RE = re.compile(r"if\s*\(\s*(.+?)\s*\)\s*\{?")


def _c_if_reachability(lines: List[str]) -> List[dict]:
    """分析 C 风格 if 条件块内写点的可达性.

    if (0) 内的写点不可达 -> filtered;
    if (非零常量/变量) 内的写点可达 -> reachable;
    无 if 包裹的写点 -> reachable.
    """
    findings: List[dict] = []
    write_pat = re.compile(r"\[[^\]]+\]\s*(?:\[[^\]]*\]\s*)?=\s*")
    in_block: Optional[bool] = None  # True=可达块, False=不可达块
    brace_depth = 0
    for i, line in enumerate(lines):
        # 检测 if 条件进入块
        m = _C_IF_RE.search(line)
        if m:
            cond = m.group(1).strip()
            # 条件为常量 0 -> 块不可达
            if cond == "0":
                in_block = False
            else:
                in_block = True
            # 判断同行是否有 {
            if "{" in line:
                brace_depth = line.count("{") - line.count("}")
        # 追踪大括号深度退出块
        if in_block is not None and brace_depth > 0:
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                in_block = None
                brace_depth = 0
        # 单行 if 无大括号: 只影响本行
        if m and "{" not in line:
            # 单行 if: 写点判断只针对本行
            pass
        # 检测写点
        if write_pat.search(line):
            if in_block is False:
                verdict, conf = "filtered", 0.2
            else:
                verdict, conf = "reachable", 0.9
            findings.append({
                "type": "heap_overflow",
                "function": "",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"c_write@line{i + 1} reach={in_block}",
                "verdict": verdict,
                "source": "jcc_polarity_map",
            })
    return findings


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