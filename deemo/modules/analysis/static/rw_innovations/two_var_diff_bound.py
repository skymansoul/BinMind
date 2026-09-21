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


def _parse_c_alloc(pseudocode: str) -> Optional[Tuple[str, int, int]]:
    """解析 C 风格 malloc 表达式 -> (var, coeff, const)."""
    m = re.search(r"malloc\s*\(\s*([^)]+)\s*\)", pseudocode)
    if not m:
        return None
    expr = m.group(1).strip()
    if re.fullmatch(r"\d+", expr):
        return ('', 0, int(expr))
    if re.fullmatch(r"\w+", expr):
        return (expr, 1, 0)
    m2 = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", expr)
    if m2:
        return (m2.group(1), int(m2.group(2)), 0)
    m3 = re.fullmatch(r"(\d+)\s*\*\s*(\w+)", expr)
    if m3:
        return (m3.group(2), int(m3.group(1)), 0)
    return None


def _parse_c_index_expr(expr: str) -> Optional[Tuple[str, int, int]]:
    """解析 C 风格索引表达式 -> (idx_var, scale, offset)."""
    expr = expr.strip()
    m = re.fullmatch(r"(\w+)\s*\+\s*(\d+)", expr)
    if m:
        return (m.group(1), 1, int(m.group(2)))
    m = re.fullmatch(r"(\w+)\s*-\s*(\d+)", expr)
    if m:
        return (m.group(1), 1, -int(m.group(2)))
    m = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", expr)
    if m:
        return (m.group(1), int(m.group(2)), 0)
    m = re.fullmatch(r"(\d+)\s*\*\s*(\w+)", expr)
    if m:
        return (m.group(2), int(m.group(1)), 0)
    m = re.fullmatch(r"(\w+)", expr)
    if m:
        return (m.group(1), 1, 0)
    return None


def _c_loop_bound(pseudocode: str, idx: str) -> Optional[str]:
    """解析 for(idx=0; idx<bound; idx++) -> bound."""
    m = re.search(
        r"for\s*\(\s*(?:int\s+)?\w+\s*=\s*\d+\s*;\s*"
        + re.escape(idx) + r"\s*<\s*(\w+)\s*;",
        pseudocode,
    )
    return m.group(1) if m else None


def _c_guard_clamp(pseudocode: str, var: str) -> Optional[int]:
    """解析 if(var > N) var = N 守卫钳位 -> N."""
    m = re.search(
        r"\bif\s*\(\s*" + re.escape(var) + r"\s*>\s*(\d+)\s*\)\s*"
        + re.escape(var) + r"\s*=\s*\1",
        pseudocode,
    )
    return int(m.group(1)) if m else None


def _two_var_diff(
    idx_var: str, scale: int, offset: int,
    pseudocode: str, a_var: str, a_coeff: int, a_const: int,
) -> Optional[Tuple[str, int]]:
    """双变量差界: 返回 (verdict, d_const).
    verdict: diff_overflow / diff_safe / diff_bounded.
    d_const 为差区间常量分量, None 表示无法确定.
    """
    if idx_var == a_var:
        # 同变量: 写偏移 = scale*idx+offset, 分配 = a_coeff*var+a_const
        bound = _c_loop_bound(pseudocode, idx_var)
        if bound is not None and bound == a_var:
            # 循环上界为分配变量: max_idx=var-1
            # 写上界 = scale*(var-1)+offset, 差上界 = (scale-a_coeff)*var + (offset-scale-a_const)
            if scale < a_coeff:
                return ("diff_safe", offset - scale - a_const)
            if scale > a_coeff:
                return ("diff_overflow", offset - scale - a_const)
            return ("diff_safe" if offset - scale <= a_const else "diff_overflow",
                    offset - scale - a_const)
        if bound is not None and re.fullmatch(r"\d+", bound):
            b = int(bound)
            w_hi = scale * (b - 1) + offset
            if a_coeff == 0:
                return ("diff_safe" if w_hi <= a_const else "diff_overflow",
                        w_hi - a_const)
            return ("diff_overflow" if a_coeff > 0 else "diff_safe",
                    w_hi - a_const)
        # 无循环: 单点写 scale*var+offset
        if scale == a_coeff:
            d = offset - a_const
            return ("diff_overflow" if d > 0 else "diff_safe", d)
        if scale > a_coeff:
            return ("diff_overflow", offset - a_const)
        return ("diff_safe", offset - a_const)
    # 双变量: idx_var != a_var, 无法确定变量间关系
    # 但固定正偏移本身意味着越界
    if offset > 0:
        return ("diff_overflow", offset)
    if offset < 0:
        return ("diff_safe", offset)
    return ("diff_bounded", 0)


def run_two_var_diff_bound(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """双变量差界判定: base + index 组合差界, 非单变量常量差. 返回 findings."""
    findings: List[dict] = []
    # 汇编风格: malloc(纯数字)
    alloc_size = _parse_alloc_size(pseudocode)
    # C 风格分配
    c_alloc = _parse_c_alloc(pseudocode)

    # 汇编风格分支 (纯数字分配大小时)
    if alloc_size is not None:
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            base = _parse_base_var(line)
            if base is None:
                continue
            if not re.search(r"\]\s*(?:,|=)", line):
                continue
            offset = _parse_offset(line)
            write_width = _parse_write_width(line)
            index_var = _parse_index_var(line)
            scale = _parse_index_scale(line)
            if index_var is not None:
                index_hi = _index_bound(pseudocode, index_var)
                d = (offset + index_hi * scale + write_width) - alloc_size
                desc = (f"line{ln} base={base} index={index_var} "
                        f"offset={offset} idx_hi={index_hi} scale={scale} "
                        f"width={write_width} alloc={alloc_size} d={d}")
            else:
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

    # C 风格分支
    if c_alloc is None:
        return findings
    a_var, a_coeff, a_const = c_alloc

    # 守卫钳位: if(n > N) n = N -> 分配上界为 N
    clamp = _c_guard_clamp(pseudocode, a_var)
    if clamp is not None:
        a_coeff = 0
        a_const = clamp

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格: buf[expr] = value 写语句
        m_c = re.search(r"(\w+)\s*\[\s*([^\]]+)\s*\]\s*=\s*", line)
        if m_c:
            idx_expr = m_c.group(2).strip()
            cidx = _parse_c_index_expr(idx_expr)
            if cidx is None:
                continue
            idx_var, scale, offset = cidx
            result = _two_var_diff(
                idx_var, scale, offset, pseudocode,
                a_var, a_coeff, a_const)
            if result is None:
                continue
            verdict, d_const = result
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.85 if verdict == "diff_overflow" else 0.9,
                "description": (
                    f"line{ln} buf[{idx_expr}] idx={idx_var} scale={scale} "
                    f"off={offset} alloc_var={a_var} -> {verdict} (d_const={d_const})"),
                "verdict": verdict,
                "source": "two_var_diff_bound",
            })
            continue

        # C 风格: memcpy(buf, src, size) 写语句
        m_mc = re.search(
            r"memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*([^)]+)\s*\)", line)
        if m_mc:
            size_expr = m_mc.group(2).strip()
            if re.fullmatch(r"\d+", size_expr):
                w = int(size_expr)
                if a_coeff == 0:
                    d = w - a_const
                    verdict = "diff_overflow" if d > 0 else "diff_safe"
                else:
                    verdict = "diff_overflow"
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": 0.85 if verdict == "diff_overflow" else 0.9,
                    "description": (
                        f"line{ln} memcpy(buf,src,{w}) "
                        f"alloc={a_coeff}*{a_var}+{a_const} -> {verdict}"),
                    "verdict": verdict,
                    "source": "two_var_diff_bound",
                })
            elif re.fullmatch(r"\w+", size_expr):
                # 变量写入大小
                if size_expr == a_var:
                    # 同变量: 写入大小 = 分配大小 -> diff_safe
                    verdict = "diff_safe"
                else:
                    verdict = "diff_overflow"
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "medium",
                    "cwe": "CWE-122",
                    "confidence": 0.85 if verdict == "diff_overflow" else 0.9,
                    "description": (
                        f"line{ln} memcpy(buf,src,{size_expr}) "
                        f"alloc={a_coeff}*{a_var}+{a_const} -> {verdict}"),
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