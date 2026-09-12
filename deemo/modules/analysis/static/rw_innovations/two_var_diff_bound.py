"""TwoVarDiffBound - 双变量差界 (stage 83).

提取 base (基址) 与 index (索引) 两个独立变量的区间, 计算组合差界
d = (base_lo + index_hi * scale + write_width) - alloc_size. 与
seven_dim_weighted 的 const_diff 维度不同: 本模块做"基址+索引"的双变量
组合差界, 而非单变量常量差.

设计决策:
  - base 区间: 从 malloc 大小获得 [0, alloc_size]
  - index 区间: 从守卫或常量获得 [0, N]
  - 写入宽度: 根据源操作数类型确定 (imm=1, qword=8, dword=4, mem=8)
  - 偏移: 从 [base+off] 提取 off (默认 0)
  - 差界 d = (offset + index_hi * scale + write_width) - alloc_size
  - d<=0 -> diff_safe; d>0 -> diff_overflow
"""

import re
from typing import List, Optional, Tuple


def _parse_alloc_size(pseudocode: str) -> Optional[int]:
    """解析分配大小 (常量)."""
    m = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    return int(m.group(1)) if m else None


def _parse_base_var(line: str) -> Optional[str]:
    """从写点 [base+off] 或 [base] 或 [base+index*scale] 提取基址变量."""
    # [base + index * scale] 模式
    m3 = re.search(r"\[\s*(\w+)\s*\+\s*\w+\s*\*\s*\d+\s*\]", line)
    if m3:
        return m3.group(1)
    # [base + index] 模式 (index 为变量名)
    m2 = re.search(r"\[\s*(\w+)\s*\+\s*\w+\s*\]", line)
    if m2:
        return m2.group(1)
    # [base + offset] 模式 (offset 为数字)
    m1 = re.search(r"\[\s*(\w+)\s*(?:\+\s*\d+)?\s*\]", line)
    if m1:
        return m1.group(1)
    return None


def _parse_offset(line: str) -> int:
    """从写点 [base+off] 提取固定偏移量, 默认 0.

    仅提取数字常量偏移; [base+index] 模式无固定偏移返回 0.
    """
    m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
    return int(m.group(1)) if m else 0


def _parse_index_var(line: str) -> Optional[str]:
    """从写点 [base+index] 或 [base+index*scale] 提取索引变量."""
    # [base + index * scale] 模式
    m2 = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\*\s*\d+\s*\]", line)
    if m2:
        return m2.group(1)
    # [base + index] 模式 (index 为变量名, 非数字)
    m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]", line)
    if m:
        var = m.group(1)
        if not var.isdigit():
            return var
    return None


def _parse_index_scale(line: str) -> int:
    """从写点 [base+index*scale] 提取 scale, 默认 1."""
    m = re.search(r"\[\s*\w+\s*\+\s*\w+\s*\*\s*(\d+)\s*\]", line)
    return int(m.group(1)) if m else 1


def _parse_write_width(line: str) -> int:
    """根据写操作的源操作数类型确定写入宽度 (字节).

    立即数 -> 1 字节, qword 寄存器 (rax 等) -> 8 字节,
    dword 寄存器 (eax 等) -> 4 字节, memory 源 -> 8 字节.
    """
    # 写操作的目标操作数 [base+off] 后面的源操作数
    m = re.search(
        r"\]\s*(?:,|=)\s*(0[xX][0-9a-fA-F]+|\d+|"
        r"rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\w+|"
        r"eax|ebx|ecx|edx|esi|edi|"
        r"\[)",
        line,
    )
    if not m:
        return 8
    operand = m.group(1)
    # 立即数: 写入 1 字节 (保守估计)
    if re.match(r"0[xX][0-9a-fA-F]+|\d+$", operand):
        return 1
    # qword 寄存器 (r 系列): 8 字节
    if re.match(r"r\w+", operand):
        return 8
    # dword 寄存器 (e 系列): 4 字节
    if re.match(r"e[a-z]{2}", operand):
        return 4
    # memory 源: 8 字节
    return 8


def _index_bound(pseudocode: str, index_var: str) -> int:
    """获取索引变量的上界 N, 从守卫或常量赋值推断."""
    # 从循环守卫提取: i < N
    m_guard = re.search(
        rf"\b{re.escape(index_var)}\s*<\s*(\d+|\w+)", pseudocode
    )
    if m_guard:
        bound = m_guard.group(1)
        if bound.isdigit():
            return int(bound)
        # 边界为变量时尝试从赋值获取
        m_assign = re.search(rf"\b{re.escape(bound)}\s*=\s*(\d+)", pseudocode)
        if m_assign:
            return int(m_assign.group(1))
    # 从直接赋值提取: index = N
    m_val = re.search(rf"\b{re.escape(index_var)}\s*=\s*(\d+)", pseudocode)
    if m_val:
        return int(m_val.group(1))
    # 无法确定, 保守返回 0
    return 0


def run_two_var_diff_bound(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """双变量差界判定: base + index 组合差界, 非单变量常量差. 返回 findings."""
    findings: List[dict] = []
    alloc_size = _parse_alloc_size(pseudocode)
    if alloc_size is None:
        return findings
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        base = _parse_base_var(line)
        if base is None:
            continue
        # 必须有写操作 (赋值或 mov)
        if not re.search(r"\]\s*(?:,|=)", line):
            continue
        offset = _parse_offset(line)
        write_width = _parse_write_width(line)
        index_var = _parse_index_var(line)
        scale = _parse_index_scale(line)

        if index_var is not None:
            # 双变量组合差界: base + index * scale
            index_hi = _index_bound(pseudocode, index_var)
            # 差界 = (offset + index_hi * scale + write_width) - alloc_size
            d = (offset + index_hi * scale + write_width) - alloc_size
            desc = (f"line{ln} base={base} index={index_var} "
                    f"offset={offset} idx_hi={index_hi} scale={scale} "
                    f"width={write_width} alloc={alloc_size} d={d}")
        else:
            # 无索引变量, 退化为偏移+宽度差界 (仍优于旧版立即数误判)
            d = (offset + write_width) - alloc_size
            desc = (f"line{ln} base={base} offset={offset} "
                    f"width={write_width} alloc={alloc_size} d={d}")

        if d <= 0:
            verdict, conf = "diff_safe", 0.9
        else:
            verdict, conf = "diff_overflow", 0.85
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": desc,
            "verdict": verdict,
            "source": "two_var_diff_bound",
        })
    return findings


def _parse_size(pseudocode: str) -> Optional[int]:
    return _parse_alloc_size(pseudocode)


if __name__ == "__main__":
    demo = """\
p = malloc(32);
for (int i = 0; i < 8; i++) {
    mov [p+i*4], rax;
}
"""
    out = run_two_var_diff_bound(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])