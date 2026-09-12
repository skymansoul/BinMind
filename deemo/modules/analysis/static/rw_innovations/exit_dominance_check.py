"""ExitDominanceCheck - 出口支配检查 (stage 84).

早退 return 路径若支配 free 块, free 不可达 -> 判 UAF 误报.
与 DomFrontierWitness(60) 不同: 面向 free 可达性 (60 面向 use).

设计决策:
  - 构建 CFG, 计算支配树
  - 若 return 块支配 free 块 -> free 在所有路径上不可达
  - free 不可达 -> UAF 误报
"""

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set


def _build_cfg(lines: List[str]) -> Dict[int, List[int]]:
    """构建 {行号: [后继]} (0 基)."""
    cfg: Dict[int, List[int]] = defaultdict(list)
    jcc_pat = re.compile(r"\b(j[a-z]{1,2}|jmp)\s+(\w+)")
    labels: Dict[str, int] = {}
    for idx, line in enumerate(lines):
        s = line.strip()
        if s.endswith(":") and not s.startswith(" "):
            labels[s[:-1]] = idx
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
    """数据流迭代计算支配者集合."""
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


def run_exit_dominance_check(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """出口支配检查. 返回 findings."""
    lines = pseudocode.splitlines()
    if not lines:
        return []
    cfg = _build_cfg(lines)
    dom = _compute_domin(cfg, 0)
    findings: List[dict] = []
    # return 块
    ret_blocks = [i for i, l in enumerate(lines)
                  if re.search(r"\b(ret|return)\b", l)]
    free_blocks = [i for i, l in enumerate(lines)
                   if re.search(r"\bfree\s*\(", l)]
    for r in ret_blocks:
        for f in free_blocks:
            # 若 return 支配 free -> free 不可达
            if r in dom.get(f, set()):
                findings.append({
                    "type": "use_after_free",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-416",
                    "confidence": 0.85,
                    "description": f"ret@line{r + 1} dominates "
                                   f"free@line{f + 1} -> unreachable",
                    "verdict": "false_positive",
                    "source": "exit_dominance_check",
                })
    return findings


if __name__ == "__main__":
    demo = """\
if (x) { return; }
free(p);
use(p);
"""
    out = run_exit_dominance_check(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])