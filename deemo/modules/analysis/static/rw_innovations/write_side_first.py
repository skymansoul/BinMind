"""WriteSideFirst - 写侧优先 (stage 101).

先推写侧上界, 写侧不可知时禁止 cannot_overflow 结论.
与 delta_interval_eval 不同: 本模块把"写侧未知"作为保守硬约束.

设计决策:
  - 写侧上界: 索引偏移或守卫上界
  - 写侧不可知 (符号索引无守卫): 只能给 unknown, 不给 safe
  - 分配侧已知与否不影响写侧优先判定

差异化 (vs heap_write_operand_cap):
  - 本模块只判定写侧表达式是否可解析为可比较形式, 不做容量比较
  - 可解析且线性偏差 (var+const) 且无守卫 -> cannot_hold 注入
  - 不可解析 (乘法步长/掩码/无守卫符号) -> write_opaque 审计证据
  - 容量与写宽放大比较交由 heap_write_operand_cap 承担 (其 DEPRECATED 路径保留)
"""

import re
from typing import List, Optional, Tuple


def _write_bound(line: str, pseudocode: str) -> Optional[Tuple[int, int]]:
    """写侧上界: [var+off] 或 [var+idx] 且守卫给上界."""
    m = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
    if m:
        return (int(m.group(1)), int(m.group(1)))
    m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]", line)
    if m:
        idx = m.group(1)
        g = re.search(r"if\s*\(\s*" + re.escape(idx) + r"\s*<\s*(\d+)", pseudocode)
        if g:
            return (0, int(g.group(1)))
    return None


def run_write_side_first(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """写侧优先判定. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 汇编风格: [var+off] 前无变量名 (排除 C 风格 buf[expr])
        m = re.search(r"(?<!\w)\[\s*\w+\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        wu = _write_bound(line, pseudocode)
        if wu is None:
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.2,
                "description": f"line{ln} write_upper=UNKNOWN "
                               f"verdict=cannot_hold",
                "verdict": "cannot_hold",
                "source": "write_side_first",
            })
            continue
        lo, hi = wu
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low",
            "cwe": "CWE-122",
            "confidence": 0.6,
            "description": f"line{ln} write_upper={wu} "
                           "verdict=write_bounded",
            "verdict": "write_bounded",
            "source": "write_side_first",
        })

    # C 风格伪代码: buf[expr]=val 写侧优先判定
    # #[DEPRECATED] 旧容量比较路径: 常量索引 vs 常量容量的判定
    # 已被 heap_write_operand_cap 的 DEPRECATED 常量下标容量路径取代,
    # 本模块不再承担容量比较, 仅判定写侧表达式可解析性
    # 检测 for 循环守卫
    loop_bounds: dict = {}
    for line in pseudocode.splitlines():
        m_loop = re.search(
            r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;",
            line,
        )
        if m_loop:
            loop_bounds[m_loop.group(1)] = m_loop.group(2)

    # 收集 malloc 容量表达式
    alloc_caps: dict = {}
    for line in pseudocode.splitlines():
        m_a = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*([^)]+)\s*\)",
            line,
        )
        if m_a:
            alloc_caps[m_a.group(1)] = m_a.group(2).strip()

    # 收集栈数组声明容量 (如 char local[16];) 用于常量下标越界判定
    stack_caps: dict = {}
    for line in pseudocode.splitlines():
        m_s = re.search(
            r"\b(?:char|int|short|long|float|double)\s+(\w+)\s*\[\s*(\d+)\s*\]\s*;",
            line,
        )
        if m_s:
            stack_caps[m_s.group(1)] = int(m_s.group(2))

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_idx = re.search(r"(\w+)\s*\[([^\]]+)\]\s*=\s*(\S+)", line)
        if not m_idx:
            continue
        buf_var = m_idx.group(1)
        idx_expr = m_idx.group(2).strip()
        # 差异化: 写侧可解析性判定 (不做容量比较)
        # 可解析类别: 纯常量 / 单一循环守卫变量 / 线性变量+常量偏移
        # 不可解析: 乘法步长 / 掩码表达式 / 无守卫符号变量
        m_pure_var = re.fullmatch(r"(\w+)", idx_expr)
        if m_pure_var and m_pure_var.group(1) in loop_bounds:
            # 循环守卫变量 -> 写侧可解析且有界
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "low",
                "cwe": "CWE-122",
                "confidence": 0.6,
                "description": f"line{ln} buf[{idx_expr}] loop-guarded "
                               "verdict=write_bounded",
                "verdict": "write_bounded",
                "source": "write_side_first",
            })
            continue
        if idx_expr.isdigit():
            const_idx = int(idx_expr)
            # 常量下标越界判定: 基址声明容量已知时, 下标超过容量即真漏洞
            # 产 cannot_hold (中性, bridge 不降权) 避免压真; 下标未越界仍产 write_bounded
            base_cap = stack_caps.get(buf_var)
            if base_cap is not None:
                if const_idx >= base_cap:
                    findings.append({
                        "type": "heap_overflow",
                        "function": func_name or "unknown",
                        "severity": "medium",
                        "cwe": "CWE-122",
                        "confidence": 0.2,
                        "description": f"line{ln} {buf_var}[{idx_expr}] "
                                       f"exceeds decl cap={base_cap} "
                                       "verdict=cannot_hold",
                        "verdict": "cannot_hold",
                        "source": "write_side_first",
                    })
                    continue
            # malloc 常量容量同理: 常量下标超过 malloc 常量容量即真漏洞
            mc_cap_str = alloc_caps.get(buf_var)
            if mc_cap_str and mc_cap_str.isdigit():
                if const_idx >= int(mc_cap_str):
                    findings.append({
                        "type": "heap_overflow",
                        "function": func_name or "unknown",
                        "severity": "medium",
                        "cwe": "CWE-122",
                        "confidence": 0.2,
                        "description": f"line{ln} {buf_var}[{idx_expr}] "
                                       f"exceeds malloc cap={mc_cap_str} "
                                       "verdict=cannot_hold",
                        "verdict": "cannot_hold",
                        "source": "write_side_first",
                    })
                    continue
            # 纯常量索引: 写侧本身可解析, 容量比较交给容量模块
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "low",
                "cwe": "CWE-122",
                "confidence": 0.6,
                "description": f"line{ln} buf[{idx_expr}] const-index "
                               "verdict=write_bounded",
                "verdict": "write_bounded",
                "source": "write_side_first",
            })
            continue
        # 乘法步长 (i*8) / 掩码 (&) / 多位运算 -> 写侧不透明审计证据
        if re.search(r"[*/&|^~%]", idx_expr):
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.2,
                "description": f"line{ln} buf[{idx_expr}] write-side opaque "
                               "verdict=write_opaque",
                "verdict": "write_opaque",
                "source": "write_side_first",
            })
            continue
        # 线性偏差 (var+const) 且无守卫: 无法证明有界 -> cannot_hold
        m_lin = re.fullmatch(r"(\w+)([+-]\d+)?", idx_expr)
        if m_lin and m_lin.group(1) not in loop_bounds:
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.2,
                "description": f"line{ln} buf[{idx_expr}] unbounded "
                               "verdict=cannot_hold",
                "verdict": "cannot_hold",
                "source": "write_side_first",
            })
            continue
        # 其余不可解析形式 -> write_opaque 审计证据
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.2,
            "description": f"line{ln} buf[{idx_expr}] write-side opaque "
                           "verdict=write_opaque",
            "verdict": "write_opaque",
            "source": "write_side_first",
        })

    # #[DEPRECATED] memcpy 常量长度 vs 常量容量路径
    # 与 heap_write_operand_cap 的 DEPRECATED 常量下标路径属同类容量比较,
    # 差异化后本模块不再做容量比较, 容量判定交由 heap_write_operand_cap
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_copy = re.search(
            r"\b(?:memcpy|memmove)\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+)\s*\)",
            line,
        )
        if not m_copy:
            continue
        dst_var = m_copy.group(1)
        copy_len = int(m_copy.group(2))
        cap_expr = alloc_caps.get(dst_var)
        if cap_expr and cap_expr.isdigit():
            cap = int(cap_expr)
            if copy_len <= cap:
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "low",
                    "cwe": "CWE-122",
                    "confidence": 0.6,
                    "description": f"line{ln} memcpy len={copy_len} <= cap={cap} "
                                   "verdict=write_bounded",
                    "verdict": "write_bounded",
                    "source": "write_side_first",
                })

    return findings


if __name__ == "__main__":
    demo = """\
mov [p+idx], 0;
"""
    out = run_write_side_first(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])