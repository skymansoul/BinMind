"""MinChunkGeometry - 最小块几何 (stage 74).

request2size 下任何 malloc 可用 >= 32 字节 (MINSIZE), 写入 <= 32 时
无论分配多大必安全. 与 容量感知耦合边界验证 slack 不同: MINSIZE 下界定理直接应用.

设计决策:
  - 采用 glibc request2size 语义: MINSIZE = 32
  - 写大小从操作数宽度推断(非立即数值), 写偏移在 [0, alloc) 内 -> 恒安全
  - 即使 alloc 未知, 写 <= 32 也按最小块几何判安全
  - 本模块产出为几何推理线索 (safe_minsize/beyond_minsize), 一律 rw_weak=True,
    不进入漏洞检出计数; 安全结论与疑似越界均由上层检测器最终裁定.
"""

import re
from typing import List, Optional

_MINSIZE = 32


def _write_width(line: str) -> int:
    """从写操作行推断写入字节数. 依据操作数宽度而非立即数值."""
    line = line.strip()
    # 行内宽度前缀优先
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 寄存器源宽度
    m_reg = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*([A-Za-z][A-Za-z0-9]*)", line)
    if m_reg:
        name = m_reg.group(1).lower()
        if name.startswith("r") and len(name) >= 2:
            return 8
        if name.startswith("e"):
            return 4
        if len(name) == 2 and name[0] in ("a", "b", "c", "d"):
            return 1
    # 立即数默认 4 字节
    return 4


def run_min_chunk_geometry(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """最小块几何判定. 返回 findings."""
    findings: List[dict] = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 汇编风格写点 [ptr+off] (排除 C 风格 var[expr], 前无变量名)
        m = re.search(
            r"(?<!\w)\[\s*(\w+)\s*\+\s*(0[xX][0-9a-fA-F]+|\d+)\s*\]\s*(?:,|=)",
            line,
        )
        if not m:
            m = re.search(r"(?<!\w)\[\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        if len(m.groups()) == 2:
            off_str = m.group(2)
            off = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)
        else:
            off = 0
        # 写宽度从操作数推断
        write_size = _write_width(line)
        # 最小块几何: 任何 malloc 请求可用 >= 32B
        if write_size <= _MINSIZE and off + write_size <= _MINSIZE:
            verdict, conf = "safe_minsize", 0.95
        else:
            verdict, conf = "beyond_minsize", 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low" if verdict == "safe_minsize" else "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} off={off} write={write_size} "
                           f"minsize={_MINSIZE}",
            "verdict": verdict,
            "source": "min_chunk_geometry",
            # 几何推理是线索不是判定: 不进入漏洞检出计数
            "rw_weak": True,
        })

    # C 风格伪代码: buf[expr]=val 和 memcpy 常量长度几何判定
    # 收集 malloc 容量
    alloc_caps: dict = {}
    alloc_exprs: dict = {}
    for line in pseudocode.splitlines():
        m_a = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)",
            line,
        )
        if m_a:
            alloc_caps[m_a.group(1)] = int(m_a.group(2))
            alloc_exprs[m_a.group(1)] = m_a.group(2)
        m_av = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*([^)]+)\s*\)",
            line,
        )
        if m_av and not m_av.group(2).strip().isdigit():
            alloc_exprs[m_av.group(1)] = m_av.group(2).strip()

    # 检测 for 循环守卫
    loop_bounds: dict = {}
    for line in pseudocode.splitlines():
        m_loop = re.search(
            r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;",
            line,
        )
        if m_loop:
            loop_bounds[m_loop.group(1)] = m_loop.group(2)

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_idx = re.search(r"(\w+)\s*\[([^\]]+)\]\s*=\s*(\S+)", line)
        if not m_idx:
            continue
        buf_var = m_idx.group(1)
        idx_expr = m_idx.group(2).strip()
        # 循环变量索引且有循环守卫, 容量含因子 → 写在容量内 → safe_minsize
        m_var = re.fullmatch(r"(\w+)", idx_expr)
        if m_var and m_var.group(1) in loop_bounds:
            bound_var = loop_bounds[m_var.group(1)]
            alloc_expr = alloc_exprs.get(buf_var, "")
            # malloc(n*factor) 中 n 是循环上界 → 有界
            m_mul = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", alloc_expr)
            if (m_mul and m_mul.group(1) == bound_var) or alloc_expr == bound_var:
                findings.append({
                    "type": "heap_overflow",
                    "function": func_name or "unknown",
                    "severity": "low",
                    "cwe": "CWE-122",
                    "confidence": 0.95,
                    "description": f"line{ln} buf[{idx_expr}] loop-guarded "
                                   f"alloc={alloc_expr} minsize={_MINSIZE}",
                    "verdict": "safe_minsize",
                    "source": "min_chunk_geometry",
                    # 几何推理结论(安全)不构成漏洞检出
                    "rw_weak": True,
                })
                continue
        # 索引含变量算术 (n+8, i*8 等) → 无法由几何判定安全 → beyond_minsize
        if not idx_expr.isdigit() and not re.fullmatch(r"0[xX][0-9a-fA-F]+", idx_expr):
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": 0.4,
                "description": f"line{ln} buf[{idx_expr}] beyond geometry "
                               f"minsize={_MINSIZE}",
                "verdict": "beyond_minsize",
                "source": "min_chunk_geometry",
                # 几何推理为线索不是判定: 不进入漏洞检出计数
                "rw_weak": True,
            })
            continue
        # 纯常量索引
        off = int(idx_expr, 0)
        write_size = 4  # C 风格写默认 4 字节
        if write_size <= _MINSIZE and off + write_size <= _MINSIZE:
            verdict, conf = "safe_minsize", 0.95
        else:
            verdict, conf = "beyond_minsize", 0.4
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low" if verdict == "safe_minsize" else "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} off={off} write={write_size} "
                           f"minsize={_MINSIZE}",
            "verdict": verdict,
            "source": "min_chunk_geometry",
            # 几何推理是线索不是判定: 不进入漏洞检出计数
            "rw_weak": True,
        })

    # C 风格: memcpy 常量长度 vs 容量几何判定
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
        if copy_len <= _MINSIZE:
            verdict, conf = "safe_minsize", 0.95
        elif copy_len > cap:
            verdict, conf = "beyond_minsize", 0.4
        else:
            verdict, conf = "safe_minsize", 0.9
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "low" if verdict == "safe_minsize" else "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} memcpy len={copy_len} cap={cap} "
                           f"minsize={_MINSIZE}",
            "verdict": verdict,
            "source": "min_chunk_geometry",
            # 几何推理是线索不是判定: 不进入漏洞检出计数
            "rw_weak": True,
        })

    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(1);
mov [p+8], 0x41;
"""
    out = run_min_chunk_geometry(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])