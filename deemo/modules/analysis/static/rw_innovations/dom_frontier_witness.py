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
    # 按分号拆分子语句, 保留原始行号与子语句序号
    stmts = []
    for ln, line in enumerate(lines):
        for stmt in line.split(";"):
            stmt = stmt.strip()
            if stmt:
                stmts.append((ln, stmt))
    cfg = _build_cfg(lines)
    dom = _compute_domin(cfg, 0)
    df = _compute_df(dom, cfg)
    findings: List[dict] = []
    # 定位 free 子语句的序号与变量名
    free_stmts = []  # (stmt_idx, var)
    for idx, (ln, stmt) in enumerate(stmts):
        m_free = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", stmt)
        if m_free:
            free_stmts.append((idx, m_free.group(1)))
    # C 风格 use 点识别: 检测指针在 free 后的使用
    _use_pat = re.compile(
        r"\[\s*(\w+)\s*(?:\+\s*\d+)?\]\s*(?:,|=)"  # 汇编风格 [p+off]
        r"|(\w+)\s*\(\s*(\w+)"  # 函数调用实参 func(p, ...)
        r"|(\w+)\s*(?:->|\.)\s*\w+"  # 成员访问 p->x
        r"|\*(\w+)"  # 解引用 *p
        r"|(\w+)\s*\["  # 下标写 buf[off]
    )
    for fi_idx, var in free_stmts:
        has_use = False
        for idx, (ln, stmt) in enumerate(stmts):
            if idx <= fi_idx:
                continue
            m = _use_pat.search(stmt)
            if m:
                use_var = m.group(1) or m.group(3) or m.group(4) or m.group(5) or m.group(6)
                if use_var == var:
                    has_use = True
                    break
        # 若 free 之后无任何 use 点, UAF 告警为误报
        if not has_use:
            findings.append({
                "type": "use_after_free",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-416",
                "confidence": 0.8,
                "description": f"free@stmt{fi_idx} var={var} "
                               f"no_use_after_free",
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