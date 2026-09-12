"""HeapStackGlobalTri - 堆栈全局三分 (stage 70).

写入基址解析为 heap/stack/global 三域标签, 非堆写入 -> 告警改类型或
降权. 与 BIV-CTC 不同: 地址域三分归类而非跨类型区间.

设计决策:
  - malloc/calloc/realloc 结果标记为 heap
  - 栈指针 (rbp/rsp 相关) 标记为 stack
  - 全局符号 (无来源的命名变量) 标记为 global
  - 写点基址域标签 != heap -> 非堆溢出, 降权/改类型
"""

import re
from typing import Dict, List, Optional, Set


def _classify_vars(pseudocode: str) -> Dict[str, str]:
    """为变量分配域标签 heap/stack/global."""
    domains: Dict[str, str] = {}
    for line in pseudocode.splitlines():
        # 堆分配
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            domains[m.group(1)] = "heap"
            continue
        # 栈相关
        m = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m:
            domains[m.group(1)] = "stack"
            continue
        # 全局命名变量 (未归类且非临时寄存器)
        m = re.search(r"\b([a-z_]\w*)\s*=\s*", line)
        if m and m.group(1) not in domains:
            domains[m.group(1)] = "global"
    return domains


def run_heap_stack_global_tri(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """堆栈全局三分. 返回 findings."""
    findings: List[dict] = []
    domains = _find_vars(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*(\+\s*\d+)?\]\s*(?:,|=)\s*(\w+)", line)
        if not m:
            continue
        base = m.group(1)
        domain = domains.get(base, "unknown")
        if domain == "heap":
            verdict, conf = "heap_write", 0.5
        elif domain == "stack":
            verdict, conf = "stack_write", 0.3
        elif domain == "global":
            verdict, conf = "global_write", 0.3
        else:
            verdict, conf = "unknown_domain", 0.4
        findings.append({
            "type": "heap_overflow" if domain == "heap" else "memory_write",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122" if domain == "heap" else "CWE-787",
            "confidence": conf,
            "description": f"line{ln} base={base} domain={domain}",
            "verdict": verdict,
            "source": "heap_stack_global_tri",
        })
    return findings


def _find_vars(pseudocode: str) -> Dict[str, str]:
    """为变量分配域名 (heap/stack/global)."""
    domains: Dict[str, str] = {}
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(", line)
        if m:
            domains[m.group(1)] = "heap"
            continue
        m = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m:
            domains[m.group(1)] = "stack"
            continue
        m = re.search(r"\b([a-z_]\w*)\s*=\s*", line)
        if m and m.group(1) not in domains:
            domains[m.group(1)] = "global"
    return domains


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 0;
mov [rbp-4], 0;
"""
    out = run_heap_stack_global_tri(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])