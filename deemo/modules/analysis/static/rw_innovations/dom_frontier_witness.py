"""DomFrontierWitness - 支配边界见证 (stage 60).

计算函数 CFG 的支配边界, free 块的支配边界若不包含 use 块,
则 use 在所有路径不可达 free 后状态 -> UAF 误报过滤.
与 DRIFT/TOVS 时间序不同: 支配边界集合运算.

设计决策:
  - 从伪代码行构建近似 CFG (顺序 + jcc 分支)
  - 数据流迭代计算支配者集合
  - 支配边界 DF[n] = {x | n 支配 x 的某前驱, 但不支配 x}
  - free 块的 DF 不含 use 块 -> 过滤 UAF 告警
"""

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set


def _build_cfg(lines: List[str]) -> Dict[int, List[int]]:
    """构建 {行号: [后继行号]} (0 基)."""
    cfg: Dict[int, List[int]] = defaultdict(list)
    jcc_pat = re.compile(r"\b(j[a-z]{1,2}|jmp)\s+(\w+)")
    labels: Dict[str, int] = {}
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith(" "):
            labels[stripped[:-1]] = idx
    for i, line in enumerate(lines):
        m = jcc_pat.search(line)
        if m:
            target = labels.get(m.group(2))
            if target is not None:
                cfg[i].append(target)
            if i + 1 < len(lines) and m.group(1) != "jmp":
                cfg[i].append(i + 1)
        else:
            if i + 1 < len(lines):
                cfg[i].append(i + 1)
    return cfg


def _compute_domin(cfg: Dict[int, List[int]], entry: int) -> Dict[int, Set[int]]:
    """数据流迭代计算各节点支配者集合."""
    nodes = set(cfg.keys())
    dom: Dict[int, Set[int]] = {n: set(nodes) for n in nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            preds = [p for p in nodes if n in cfg.get(p, [])]
            if not preds:
                continue
            new_dom = {n}
            if preds:
                new_dom |= set.intersection(*(dom[p] for p in preds))
            if new_dom != dom[n]:
                dom[n] = new_dom
                changed = True
    return dom


def _compute_df(dom: Dict[int, Set[int]], cfg: Dict[int, List[int]]) -> Dict[int, Set[int]]:
    """计算支配边界: DF[b] = {x | b 支配 x 的某前驱, 但不支配 x}."""
    df: Dict[int, Set[int]] = defaultdict(set)
    nodes = set(cfg.keys())
    for n in nodes:
        for succ in cfg.get(n, []):
            if succ not in nodes:
                continue
            for b in nodes:
                if n in dom.get(b, set()) and succ not in dom.get(b, set()):
                    df[b].add(succ)
    return df


def run_dom_frontier_witness(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """支配边界见证. 返回 findings."""
    lines = pseudocode.splitlines()
    if not lines:
        return []
    cfg = _build_cfg(lines)
    dom = _compute_domin(cfg, 0)
    df = _compute_df(dom, cfg)
    findings: List[dict] = []
    free_lines = [i for i, l in enumerate(lines) if re.search(r"\bfree\s*\(", l)]
    use_lines = [i for i, l in enumerate(lines)
                 if re.search(r"\[[^\]]+\]\s*=", l) or re.search(r"\buse\b", l)]
    for fi in free_lines:
        for ui in use_lines:
            if ui == fi:
                continue
            # 若 free 的支配边界不含 use, use 在所有路径上
            # 都不可达 free 之后的状态 -> 误报
            if ui not in df.get(fi, set()):
                findings.append({
                    "type": "use_after_free",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-416",
                    "confidence": 0.8,
                    "description": f"free@line{fi + 1} use@line{ui + 1} "
                                   f"df_not_contains_use",
                    "verdict": "false_positive",
                    "source": "dom_frontier_witness",
                })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(16);
if (x) { free(p); }
use(p);
"""
    out = run_dom_frontier_witness(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])