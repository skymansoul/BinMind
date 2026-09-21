"""ChainIdCrossFunc - 跨函数链 ID (stage 102).

call 处 rax 分配新链 ID, 跨函数调用时链 ID 失效退化为独立链.
与 freed_alias_epoch 不同: 本模块聚焦调用边界而非时间纪元.

设计决策:
  - 链 ID 生成: 每次 call 后 rax 获得新链 ID (自增)
  - 跨函数: 调用后原链 ID 不可沿用 (callee 可能改写 rax)
  - 写点绑定链 ID, 同链内偏移可联合分析
  - C 风格: malloc 变量流经未知外部函数调用 -> 链被污染 chain_dirty
  - C 风格: 全程本地封闭使用 (仅标准库函数) -> chain_clean
"""

import re
from typing import List, Optional


# 已知标准库函数, 传参给这些函数不视为链污染
_SAFE_FUNCS = {
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "strcpy",
    "strncpy", "memset", "printf", "sprintf", "snprintf", "scanf", "sscanf",
    "strlen", "strcmp", "strncmp", "strcat", "strncat", "return", "abort",
    "exit", "puts", "fgets", "fread", "fwrite", "open", "close", "read",
    "write", "atoi", "atol", "strtol", "strtoul", "sizeof",
}


def _chain_map(pseudocode: str) -> dict:
    """链 ID 映射: 变量 -> 链 ID (最终状态)."""
    chain: dict = {}
    cid = 0
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
            continue
        m = re.search(r"\bcall\s+(\w+)", line)
        if m:
            cid += 1
            chain["rax"] = cid
            continue
        m = re.search(r"\b(\w+)\s*=\s*rax", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
    return chain


def _chain_snapshots(pseudocode: str) -> List[dict]:
    """按行号生成链 ID 快照列表, 返回 [行号对应的 {var: cid}]."""
    snapshots: List[dict] = []
    chain: dict = {}
    cid = 0
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
            snapshots.append(dict(chain))
            continue
        m = re.search(r"\bcall\s+(\w+)", line)
        if m:
            cid += 1
            chain["rax"] = cid
            snapshots.append(dict(chain))
            continue
        m = re.search(r"\b(\w+)\s*=\s*rax", line)
        if m:
            cid += 1
            chain[m.group(1)] = cid
            snapshots.append(dict(chain))
            continue
        snapshots.append(dict(chain))
    return snapshots


def run_chain_id_cross_func(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """跨函数链 ID 分析. 返回 findings."""
    findings: List[dict] = []
    # 按分号拆分子语句, 保留行号
    stmts = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        for stmt in line.split(";"):
            stmt = stmt.strip()
            if stmt:
                stmts.append((ln, stmt))
    # 收集 malloc 分配的变量
    alloc_vars = set()
    for _, stmt in stmts:
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", stmt)
        if m:
            alloc_vars.add(m.group(1))
    if not alloc_vars:
        # 无分配变量, 尝试汇编风格路径
        return _asm_style_run(pseudocode, func_name)
    # 对每个分配变量判定链是否被外部调用污染
    for var in sorted(alloc_vars):
        tainted = False
        var_allocated = False
        for ln, stmt in stmts:
            # 确认该变量已分配
            m_alloc = re.search(
                r"\b" + re.escape(var) + r"\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
                stmt)
            if m_alloc:
                var_allocated = True
                continue
            if not var_allocated:
                continue
            # 检查变量是否被传给未知外部函数
            # 匹配 func(..., var, ...) 中 var 作为实参
            for m_call in re.finditer(r"\b(\w+)\s*\(", stmt):
                callee = m_call.group(1)
                if callee in _SAFE_FUNCS:
                    continue
                # 非标准库函数, 检查 var 是否出现在其参数中
                # 取该调用的完整参数段
                paren_start = m_call.end() - 1
                depth = 0
                end = paren_start
                for i in range(paren_start, len(stmt)):
                    if stmt[i] == "(":
                        depth += 1
                    elif stmt[i] == ")":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                args = stmt[paren_start + 1:end]
                if re.search(r"\b" + re.escape(var) + r"\b", args):
                    tainted = True
                    break
            if tainted:
                break
        if tainted:
            # 外部未知函数调用导致标识符链跨界污染 -> 注入告警
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.85,
                "description": f"var={var} tainted=True verdict=chain_dirty",
                "verdict": "chain_dirty",
                "source": "chain_id_cross_func",
            })
        # 链干净且无跨界污染时不产出 chain_clean: 调用链干净不能
        # 证明无漏洞, 产出降权型 verdict 会对既有告警投反对票压真
    return findings


def _asm_style_run(
    pseudocode: str,
    func_name: str,
) -> List[dict]:
    """汇编风格路径: call 导致链失效检测, 保留既有支持."""
    findings: List[dict] = []
    chain = _chain_map(pseudocode)
    snapshots = _chain_snapshots(pseudocode)
    lines = pseudocode.splitlines()
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        var = m.group(1)
        snap = snapshots[ln - 1] if ln - 1 < len(snapshots) else {}
        write_cid = snap.get(var)
        if write_cid is None:
            continue
        alloc_cid = chain.get(var)
        if alloc_cid is None:
            verdict = "chain_clean"
            confidence = 0.8
        elif write_cid == alloc_cid:
            crossed = False
            for prev_idx in range(ln):
                prev_snap = snapshots[prev_idx] if prev_idx < len(snapshots) else {}
                prev_cid = prev_snap.get(var)
                if prev_cid is not None and prev_cid != write_cid:
                    crossed = True
                    break
            verdict = "chain_dirty" if crossed else "chain_clean"
            confidence = 0.4 if crossed else 0.8
        else:
            verdict = "chain_dirty"
            confidence = 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": confidence,
            "description": f"line{ln} var={var} cid={write_cid} "
                           f"alloc_cid={alloc_cid} verdict={verdict}",
            "verdict": verdict,
            "source": "chain_id_cross_func",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
call foo;
mov [p+8], 0;
"""
    out = run_chain_id_cross_func(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])