"""HeapWriteOperandCap - 堆写操作数容量 (stage 103).

伪代码侧堆写操作数捕获 + 容量判定:
  捕获 mov [dst], src 的写大小 (src 寄存器宽度 / 立即数按默认 4B 或行内宽度前缀)
  并对比分配容量.
与 use_deref_lattice 不同: 本模块专攻堆写操作数宽度.

设计决策:
  - 写大小: src 为寄存器 -> 按寄存器宽度, 立即数 -> 4 (默认 32 位 imm 编码)
  - 容量: 分配大小 - 偏移
  - write_size > capacity -> overflow
  - 偏移含变量名时无法确定, 保守判 unknown 不注入

差异化 (vs write_side_first):
  - 本模块聚焦操作数宽度容量放大: buf[i]=src_var 时 src 宽度决定写宽
  - int 宽 4B vs char 宽 1B, 写宽=4 时容量消耗放大 4 倍
  - 通用常量下标容量比较路径已 DEPRECATED (交由 write_side_first 管写侧可解析性)
"""

import re
from typing import List, Optional


def _write_size(src: str, line: str) -> int:
    """写操作数大小. 依据操作数宽度而非立即数值."""
    # 行内宽度前缀优先
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 内存源
    if src.startswith("["):
        return 8
    # 寄存器源
    src_low = src.lower()
    if re.match(r"^r[a-z0-9]+$", src_low):
        return 8
    if re.match(r"^e[a-z]x$", src_low):
        return 4
    if re.match(r"^[abcd][lh]$", src_low):
        return 1
    if re.match(r"^[abcd]x$", src_low):
        return 2
    # 立即数默认 4 字节
    return 4


def _c_var_width(var_name: str, pseudocode: str) -> int:
    """C 风格变量声明类型推断写宽. int->4, char->1, short->2, long->8."""
    for line in pseudocode.splitlines():
        m = re.search(
            r"\b(?:int|unsigned\s+int|signed\s+int)\b\s+(\w+)\s*[;,=]",
            line,
        )
        if m and m.group(1) == var_name:
            return 4
        m2 = re.search(r"\b(?:char|unsigned\s+char)\b\s+(\w+)\s*[;,=]", line)
        if m2 and m2.group(1) == var_name:
            return 1
        m3 = re.search(r"\b(?:short|unsigned\s+short)\b\s+(\w+)\s*[;,=]", line)
        if m3 and m3.group(1) == var_name:
            return 2
        m4 = re.search(r"\b(?:long|unsigned\s+long)\b\s+(\w+)\s*[;,=]", line)
        if m4 and m4.group(1) == var_name:
            return 8
    # 未找到声明, 默认 int 宽 4 字节
    return 4


def run_heap_write_operand_cap(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """堆写操作数容量判定. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    alloc = int(m_alloc.group(1)) if m_alloc else None
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 支持 [var+常量] 和 [var+变量名] 偏移
        m = re.search(r"\[\s*(\w+)\s*\+\s*(\w+)\s*\]\s*,\s*(\S+)\s*;?", line)
        if not m:
            continue
        var, off_tok, src = m.group(1), m.group(2), m.group(3)
        if alloc is None:
            continue
        # 偏移为变量名时无法确定, 保守判 unknown 不注入
        if not re.fullmatch(r"(0[xX][0-9a-fA-F]+|\d+)", off_tok):
            continue
        off = int(off_tok, 16) if off_tok.lower().startswith("0x") else int(off_tok)
        ws = _write_size(src, line)
        cap = alloc - off
        verdict = "cap_ok" if ws <= cap else "cap_exceed"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9 if verdict == "cap_exceed" else 0.7,
            "description": f"line{ln} off={off} src={src} ws={ws} "
                           f"cap={cap} verdict={verdict}",
            "verdict": verdict,
            "source": "heap_write_operand_cap",
        })

    # C 风格伪代码: 数组写操作数容量判定
    # 收集所有 malloc 容量, 按变量名索引
    alloc_caps: dict = {}
    # 记录 malloc 参数的原始表达式 (用于循环守卫判定)
    alloc_exprs: dict = {}
    for line in pseudocode.splitlines():
        m_a = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)",
            line,
        )
        if m_a:
            alloc_caps[m_a.group(1)] = int(m_a.group(2))
            alloc_exprs[m_a.group(1)] = m_a.group(2)
        # malloc(非纯数字表达式) 容量未知, 记录为 None 和原始表达式
        m_av = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*([^)]+)\s*\)",
            line,
        )
        if m_av and not m_av.group(2).strip().isdigit():
            alloc_caps[m_av.group(1)] = None
            alloc_exprs[m_av.group(1)] = m_av.group(2).strip()

    # 检测 for 循环守卫: for(i=0;i<n;i++) → 循环变量 i 的上界为 n
    loop_bounds: dict = {}
    for line in pseudocode.splitlines():
        m_loop = re.search(
            r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;",
            line,
        )
        if m_loop:
            loop_bounds[m_loop.group(1)] = m_loop.group(2)

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # buf[expr] = val 形式
        m_idx = re.search(r"(\w+)\s*\[([^\]]+)\]\s*=\s*(\S+)", line)
        if not m_idx:
            continue
        buf_var = m_idx.group(1)
        idx_expr = m_idx.group(2).strip()
        if buf_var not in alloc_caps:
            continue
        cap = alloc_caps[buf_var]
        alloc_expr = alloc_exprs.get(buf_var, "")

        # 循环变量索引且有循环守卫: buf[i] 且 for(i=0;i<n;i++)
        # 若 malloc 容量为 n*factor 且索引为 i, 步长为 1 → cap_ok
        m_simple_var = re.fullmatch(r"(\w+)", idx_expr)
        if m_simple_var and m_simple_var.group(1) in loop_bounds:
            loop_var = m_simple_var.group(1)
            bound_var = loop_bounds[loop_var]
            # malloc(n*4) 中 n 是循环上界 → 步长 1 写在容量内
            m_mul = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", alloc_expr)
            if m_mul and m_mul.group(1) == bound_var:
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "low",
                    "cwe": "CWE-122",
                    "confidence": 0.7,
                    "description": f"line{ln} buf[{idx_expr}] within loop guard "
                                   f"alloc={alloc_expr}",
                    "verdict": "cap_ok",
                    "source": "heap_write_operand_cap",
                })
                continue
            # malloc(n) 且循环上界 n, 步长 1 → cap_ok
            if alloc_expr == bound_var:
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "low",
                    "cwe": "CWE-122",
                    "confidence": 0.7,
                    "description": f"line{ln} buf[{idx_expr}] within loop guard "
                                   f"alloc={alloc_expr}",
                    "verdict": "cap_ok",
                    "source": "heap_write_operand_cap",
                })
                continue

        if cap is None:
            # malloc(变量/表达式) 容量未知, 索引含算术超出时判 cap_exceed
            if re.search(r"\w+\s*\+\s*\d+", idx_expr):
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "high",
                    "cwe": "CWE-122",
                    "confidence": 0.85,
                    "description": f"line{ln} buf[{idx_expr}] exceeds dynamic cap",
                    "verdict": "cap_exceed",
                    "source": "heap_write_operand_cap",
                })
            # 步长写 buf[i*8] 无守卫且容量未知 → cap_exceed
            elif re.search(r"\w+\s*\*\s*\d+", idx_expr):
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "high",
                    "cwe": "CWE-122",
                    "confidence": 0.85,
                    "description": f"line{ln} buf[{idx_expr}] stride exceeds dynamic cap",
                    "verdict": "cap_exceed",
                    "source": "heap_write_operand_cap",
                })
            continue
        # #[DEPRECATED] 纯常量索引容量比较路径
        # 与 write_side_first 的常量索引 write_bounded 判定重叠,
        # 差异化后保留旧逻辑但不作为主判定, 仅作兼容回退
        if idx_expr.isdigit():
            off = int(idx_expr, 0)
            ws = 4  # C 风格写默认 4 字节
            verdict = "cap_ok" if off + ws <= cap else "cap_exceed"
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium" if verdict == "cap_ok" else "high",
                "cwe": "CWE-122",
                "confidence": 0.9 if verdict == "cap_exceed" else 0.7,
                "description": f"line{ln} buf[{idx_expr}] ws={ws} "
                               f"cap={cap} verdict={verdict}",
                "verdict": verdict,
                "source": "heap_write_operand_cap",
            })
            continue
        # 差异化: 操作数宽度放大判定 (C 风格独有)
        # buf[idx_expr] = rhs_var 时, rhs_var 的声明类型决定写宽
        # int 型写 4B, char 型写 1B, 写宽放大容量消耗
        m_c_write = re.search(
            r"(\w+)\s*\[([^\]]+)\]\s*=\s*(\w+)\s*;?\s*$", line,
        )
        if m_c_write:
            rhs_var = m_c_write.group(3)
            # 声明类型推断: int/unsigned/long -> 4B, char/short -> 1B/2B
            type_ws = _c_var_width(rhs_var, pseudocode)
            if cap is not None:
                # 写宽放大: 常量索引 + 写宽 > 容量时 cap_exceed
                try:
                    off_val = int(idx_expr, 0) if idx_expr.isdigit() else None
                except ValueError:
                    off_val = None
                if off_val is not None:
                    effective = off_val + type_ws
                    verdict = "cap_ok" if effective <= cap else "cap_exceed"
                    findings.append({
                        "type": "heap_overflow",
                        "function": func_name or "unknown",
                        "severity": "high" if verdict == "cap_exceed" else "low",
                        "cwe": "CWE-122",
                        "confidence": 0.9 if verdict == "cap_exceed" else 0.7,
                        "description": (
                            f"line{ln} buf[{idx_expr}]={rhs_var} "
                            f"type_ws={type_ws} eff={effective} "
                            f"cap={cap} verdict={verdict}"
                        ),
                        "verdict": verdict,
                        "source": "heap_write_operand_cap",
                    })
                    continue
            # 容量未知时操作数宽度审计: 记录写宽但不判定溢出
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.5,
                "description": (
                    f"line{ln} buf[{idx_expr}]={rhs_var} "
                    f"type_ws={type_ws} cap=unknown verdict=unknown"
                ),
                "verdict": "unknown",
                "source": "heap_write_operand_cap",
            })

    # C 风格: memcpy 常量长度 vs malloc 常量容量
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_copy = re.search(
            r"\b(?:memcpy|memmove)\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+)\s*\)",
            line,
        )
        if not m_copy:
            continue
        dst_var = m_copy.group(1)
        copy_len = int(m_copy.group(2))
        if dst_var not in alloc_caps:
            continue
        cap = alloc_caps[dst_var]
        if cap is None:
            continue
        verdict = "cap_exceed" if copy_len > cap else "cap_ok"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "high" if verdict == "cap_exceed" else "low",
            "cwe": "CWE-122",
            "confidence": 0.9 if verdict == "cap_exceed" else 0.7,
            "description": f"line{ln} memcpy len={copy_len} cap={cap} verdict={verdict}",
            "verdict": verdict,
            "source": "heap_write_operand_cap",
        })

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+60], rax;
"""
    out = run_heap_write_operand_cap(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])