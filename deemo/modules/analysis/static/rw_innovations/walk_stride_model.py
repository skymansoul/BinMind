"""WalkStrideModel - 游走步长模型 (stage 78).

p++/p+=k 循环游走写建模 (base + i*stride), stride>1 时按 stride
对齐计算可达上界. 与 PG-WBV-LSA 循环不同: 步长域而非迭代次数.

设计决策:
  - 识别循环游走: p+=k 或 p++ 在循环体内
  - 建模式: 写地址 = base + i*stride
  - stride>1 时上界 = base + (count-1)*stride
  - 上界 <= alloc 大小 -> 安全
"""

import re
from typing import List, Optional, Tuple


def _extract_loop_count(pseudocode: str) -> int:
    """从循环结构提取迭代次数上限, 找不到则保守返回 1."""
    # for (int i = 0; i < N; i++) 模式
    m_for = re.search(
        r"\bfor\s*\(\s*(?:int\s+)?(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+|\d+)",
        pseudocode,
    )
    if m_for:
        bound = m_for.group(2)
        if bound.isdigit():
            return int(bound)
        # 边界为变量时尝试从赋值语句获取值
        m_bound = re.search(rf"\b{re.escape(bound)}\s*=\s*(\d+)", pseudocode)
        if m_bound:
            return int(m_bound.group(1))
    # while (i < N) 或 while (var < N) 模式
    m_while = re.search(r"\bwhile\s*\(\s*(\w+)\s*<\s*(\w+|\d+)", pseudocode)
    if m_while:
        bound = m_while.group(2)
        if bound.isdigit():
            return int(bound)
        m_bound = re.search(rf"\b{re.escape(bound)}\s*=\s*(\d+)", pseudocode)
        if m_bound:
            return int(m_bound.group(1))
    # 无循环结构, 保守单步
    return 1


def _find_stride(pseudocode: str) -> Tuple[str, int, int]:
    """返回 (游走变量, stride, 迭代次数上限)."""
    lines = pseudocode.splitlines()
    stride_var = None
    stride = 1
    for line in lines:
        # 匹配 p += k 模式 (步长为 k)
        m_add = re.search(r"\b(\w+)\s*\+=\s*(\d+)", line)
        if m_add:
            stride_var, stride = m_add.group(1), int(m_add.group(2))
        # 匹配 p++ 模式 (步长为 1)
        m_inc = re.search(r"\b(\w+)\s*\+\+", line)
        if m_inc:
            stride_var = m_inc.group(1)
            stride = 1
    if stride_var is None:
        return "", 1, 0
    # 从循环结构提取迭代次数, 而非从变量赋值
    count = _extract_loop_count(pseudocode)
    return stride_var, stride, count


def run_walk_stride_model(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """游走步长模型. 返回 findings."""
    findings: List[dict] = []
    var, stride, count = _find_stride(pseudocode)
    alloc_size = None
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        base, idx = m.group(1), m.group(2)
        # 游走变量出现在 base 或 idx 任一位置即可建模
        if not var or var not in (base, idx):
            continue
        # 游走可达上界: 起始偏移(0) + (count-1)*stride
        # count 为循环迭代次数; count>=2 时 reach=(count-1)*stride
        if count >= 2:
            reach = (count - 1) * stride
        else:
            # 无循环结构时保守单步, reach=stride
            reach = stride
        if alloc_size is not None and reach < alloc_size:
            verdict, conf = "in_bounds", 0.85
        else:
            verdict, conf = "maybe_overflow", 0.5
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} base={base} stride={stride} "
                           f"count={count} reach={reach} alloc={alloc_size}",
            "verdict": verdict,
            "source": "walk_stride_model",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
for (int i = 0; i < 8; i++) {
    p++;
    mov [p+i], 0;
}
"""
    out = run_walk_stride_model(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])