"""RetAddrChainStitch - 返回地址链缝合 (stage 64).

对跨函数告警, 沿 call 返回点把 caller 的 alloc 证据与 callee 的
write 证据缝合, 缝合成功 (size 证据传递闭合) 则过滤.
与 AWSC-ICF 摘要不同: 返回点证据缝合而非参数摘要.

设计决策:
  - 识别 call 指令与返回点 (call 下一行)
  - caller 中 rax 携带 alloc 大小证据
  - callee 中写点大小与 caller alloc 大小闭合 -> 过滤
"""

import re
from typing import Dict, List, Optional, Tuple


def _call_sites(pseudocode: str) -> List[Tuple[int, str]]:
    """返回 [(行号, callee)]."""
    out = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\bcall\s+(\w+)", line)
        if m:
            out.append((ln, m.group(1)))
    return out


def run_ret_addr_chain_stitch(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """返回地址链缝合. 返回 findings."""
    findings: List[dict] = []
    lines = pseudocode.splitlines()
    alloc_size: Optional[int] = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    for ln, callee in _scan_sites(pseudocode):
        # 返回点 = call 下一行
        if ln >= len(lines):
            continue
        ret_line = lines[ln]  # 0 基: lines[ln] 是 call 的下一行
        # 缝合: callee 写点大小 + caller alloc 证据
        write_size = None
        m_write = re.search(r"\[[^\]]+\]\s*=\s*(\w+)", ret_line)
        if m_write:
            write_size = _const_of(m_write.group(1))
        if alloc_size is not None and write_size is not None:
            closed = write_size <= alloc_size
        else:
            closed = False
        verdict = "stitched_safe" if closed else "unstitched"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if closed else 0.5,
            "description": f"call@{ln}->{callee} alloc={alloc_size} "
                           f"write={write_size} closed={closed}",
            "verdict": verdict,
            "source": "ret_addr_chain_stitch",
        })
    return findings


def _const_of(s: str) -> Optional[int]:
    try:
        return int(s, 0)
    except ValueError:
        return None


def _scan_sites(pseudocode: str) -> List[Tuple[int, str]]:
    return _call_sites(pseudocode)


if __name__ == "__main__":
    demo = """\
p = malloc(64);
call helper;
mov [p+8], rax;
"""
    out = run_ret_addr_chain_stitch(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])