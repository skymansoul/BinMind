"""SymbolicDiffSign - 符号差符号判定 (stage 69).

write_expr - alloc_expr 化简后若只剩正系数常量项 -> 确定溢出 k 字节.
与 GAPSBV 仿射不同: 不做区间求值, 仅符号化简取符号.

设计决策:
  - 将表达式化简为 (vars, const) 形式: vars 收集变量系数,
    const 为常量部分
  - 求 diff = write - alloc
  - 若 diff 无变量项且 const > 0 -> 确定溢出 const 字节
  - const <= 0 -> 安全; 含变量项 -> 未知
"""

import re
from typing import Dict, List, Optional, Tuple


def _simplify(expr: str) -> Tuple[Dict[str, int], int]:
    """将表达式化简为 (变量系数表, 常量). 支持 + - * 常量 与变量."""
    expr = expr.replace(" ", "")
    # 拆分加减项
    terms = re.findall(r"[+-]?[^+-]+", expr)
    coeff: Dict[str, int] = {}
    const = 0
    for term in terms:
        sign = -1 if term.startswith("-") else 1
        if term.startswith("+") or term.startswith("-"):
            term = term[1:]
        if re.fullmatch(r"\d+", term):
            const += sign * int(term)
        elif re.fullmatch(r"0[xX][0-9a-fA-F]+", term):
            const += sign * int(term, 16)
        else:
            # 变量或 变量*常量
            m = re.fullmatch(r"(\w+)\*(\d+)", term)
            if m:
                coeff[m.group(1)] = coeff.get(m.group(1), 0) + sign * int(m.group(2))
            else:
                coeff[term] = coeff.get(term, 0) + sign
    return coeff, const


def run_symbolic_diff_sign(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """符号差符号判定. 返回 findings."""
    findings: List[dict] = []
    m_alloc = re.search(r"malloc\s*\(\s*([^)]+)\)", pseudocode)
    if not m_alloc:
        return findings
    alloc_expr = m_alloc.group(1)
    alloc_c, alloc_const = _simplify(alloc_expr)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # 写点: [ptr+off], 值 或 [ptr], 值
        m = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*([^;,]+)", line)
        if not m:
            continue
        write_expr = m.group(1).strip()
        wc, wconst = _simplify(write_expr)
        # diff = write - alloc
        diff_c: Dict[str, int] = {}
        for v, c in wc.items():
            diff_c[v] = diff_c.get(v, 0) + c
        for v, c in alloc_c.items():
            diff_c[v] = diff_c.get(v, 0) - c
        diff_const = wconst - alloc_const
        if not diff_c and diff_const > 0:
            verdict = "overflow"
            conf = 0.85
            desc = f"line{ln} diff_const={diff_const} -> overflow {diff_const}B"
        elif not diff_c:
            verdict = "safe"
            conf = 0.9
            desc = f"line{ln} diff_const={diff_const} -> safe"
        else:
            verdict = "unknown"
            conf = 0.4
            desc = f"line{ln} diff_has_vars={sorted(diff_c)} -> unknown"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "high" if verdict == "overflow" else "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": desc,
            "verdict": verdict,
            "source": "symbolic_diff_sign",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(16);
mov [p+8], 0;
"""
    out = run_symbolic_diff_sign(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])