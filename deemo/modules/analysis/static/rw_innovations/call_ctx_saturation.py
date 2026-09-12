"""CallCtxSaturation - 调用点饱和度计分 (stage 55).

对每个 alloc 调用点统计指向它的 def 链深度与下游写点数 fanout,
饱和度 = 链深 / (链深 + fanout). 低于阈值的分配点证据被过多写点稀释,
关联告警降权. 与 AWSC 同源判定不同: AWSC 问"是否同源",
本模块问"该分配点证据是否被过多写点稀释".

设计决策:
  - 纯文本伪代码输入, 正则识别 malloc/calloc/realloc 分配点
  - def 链深度: 分配结果变量被后续赋值改写的层数
  - fanout: 指向同一分配结果变量的写指令条数
  - 饱和度 < 阈值(默认0.3) 时对相关 finding 降权
"""

import re
from typing import Dict, List, Optional

_TYPE = "heap_overflow"
_CWE = "CWE-122"
_SEVERITY = "medium"


def _parse_allocs(pseudocode: str) -> Dict[str, List[int]]:
    """识别分配点, 返回 {变量名: [行号,...]}."""
    points: Dict[str, List[int]] = {}
    pat = re.compile(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(")
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = pat.search(line)
        if m:
            points.setdefault(m.group(1), []).append(ln)
    return points


def _def_chain_depth(var: str, lines: List[str]) -> int:
    """从分配行起, 统计 var 沿赋值链被改写的层数."""
    depth = 0
    cur = var
    pat_assign = re.compile(r"\b(\w+)\s*=\s*([^;]+)")
    for line in lines:
        m = pat_assign.search(line)
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if lhs == cur:
            depth += 1
            continue
        if re.search(r"\b" + re.escape(cur) + r"\b", rhs):
            depth += 1
            cur = lhs
    return depth


def _write_fanout(var: str, lines: List[str]) -> int:
    """统计指向 var 的写点数量: var[off]= 或 [var+off]= 形式."""
    pat_write = re.compile(
        r"\[?\s*\b" + re.escape(var) + r"\b\s*(\+\s*\w+)?\]?\s*=")
    return sum(1 for line in lines if pat_write.search(line))


def run_call_ctx_saturation(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    threshold: float = 0.3,
) -> List[dict]:
    """调用点饱和度计分. 返回 findings 列表."""
    lines = pseudocode.splitlines()
    allocs = _parse_allocs(pseudocode)
    findings: List[dict] = []
    sat_map: Dict[str, float] = {}
    for var, alloc_lines in allocs.items():
        chain = _def_chain_depth(var, lines)
        fanout = _write_fanout(var, lines)
        sat = chain / (chain + fanout) if (chain + fanout) else 1.0
        sat_map[var] = sat
        for alloc_ln in alloc_lines:
            verdict = "safe" if sat >= 1.0 - threshold else "downgraded"
            findings.append({
                "type": _TYPE,
                "function": func_name or "unknown",
                "severity": _SEVERITY,
                "cwe": _CWE,
                "confidence": round(min(1.0, sat), 2),
                "description": (
                    f"alloc@{alloc_ln} def_chain={chain} fanout={fanout} "
                    f"saturation={sat:.2f}"
                ),
                "verdict": verdict,
                "source": "call_ctx_saturation",
            })
    if existing_findings:
        for f in existing_findings:
            out = dict(f)
            for var, sat in sat_map.items():
                if var in out.get("description", "") and sat < threshold:
                    out["confidence"] = round(out.get("confidence", 0.5) * 0.6, 2)
                    out["verdict"] = "downgraded"
                    out["source"] = "call_ctx_saturation"
            findings.append(out)
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
q = p;
q = q + 4;
mov [p+8], 0x41414141;
mov [p+16], 0x42424242;
mov [p+24], 0x43434343;
"""
    out = run_call_ctx_saturation(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"], item["confidence"])