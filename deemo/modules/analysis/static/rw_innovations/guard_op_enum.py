"""GuardOpEnum - 守卫算子枚举 (stage 93).

jcc -> GuardOp 完整枚举表 (ja/jae/jb/jbe/je/jne/jg/jge/jl/jle/js/jns),
守卫查询按算子语义取反/换向, verdict 随守卫语义动态生成.
与 path_guard_collector 不同: 算子语义表完备化 + 动态 verdict.

设计决策:
  - GuardOp 枚举: {jcc: (op, 语义, 取反)}
  - 守卫查询: 给定 jcc 与变量, 得出约束 op(v, imm)
  - verdict 随 jcc 类型和 cmp 操作数动态生成:
    上界守卫 / 下界守卫 / 等值守卫 / 不等守卫 / 未知守卫
"""

import re
from typing import Dict, List, Optional

# jcc -> (比较算子, 取反算子)
_JCC_SEMANTICS = {
    "ja": (">", "<="), "jae": (">=", "<"), "jb": ("<", ">="),
    "jbe": ("<=", ">"), "je": ("==", "!="), "jne": ("!=", "=="),
    "jg": (">", "<="), "jge": (">=", "<"), "jl": ("<", ">="),
    "jle": ("<=", ">"), "js": ("<0", ">=0"), "jns": (">=0", "<0"),
}

# 守卫语义 -> verdict 映射
_GUARD_VERDICT = {
    ">": "guard_upper_bound",
    ">=": "guard_upper_bound",
    "<": "guard_lower_bound",
    "<=": "guard_lower_bound",
    "==": "guard_equality",
    "!=": "guard_inequality",
    "<0": "guard_lower_bound",
    ">=0": "guard_upper_bound",
}


def _guard_verdict(jcc: str) -> str:
    """根据 jcc 算子语义动态生成 verdict."""
    sem = _JCC_SEMANTICS.get(jcc)
    if not sem:
        return "guard_unknown"
    op, _neg = sem
    return _GUARD_VERDICT.get(op, "guard_unknown")


def run_guard_op_enum(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """守卫算子枚举. 返回 findings.

    跨行关联: 第一遍收集 cmp var, imm 站点, 第二遍扫描 jcc 指令,
    将每个 jcc 与最近的在先 cmp 指令配对, 从而兼容 cmp 与分支分行书写.
    verdict 随 jcc 算子语义动态生成, 不再硬编码.
    """
    findings: List[dict] = []
    lines = pseudocode.splitlines()
    cmp_sites: List[tuple] = []
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\bcmp\s+(\w+|\[[^\]]+\])\s*,\s*(\d+)\b", line)
        if m:
            cmp_sites.append((ln, m.group(1), m.group(2)))
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\b(j[a-z]{1,2})\s+(\w+)", line)
        if not m:
            continue
        jcc = m.group(1)
        pair = None
        for cln, var, imm in cmp_sites:
            if cln <= ln:
                pair = (cln, var, imm)
        if pair is None:
            continue
        _, var, imm = pair
        guard = _guard_expr(jcc, var, imm)
        neg = _negate(jcc, var, imm)
        verdict = _guard_verdict(jcc)
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.8,
            "description": f"line{ln} jcc={jcc} guard={guard} neg={neg}",
            "verdict": verdict,
            "source": "guard_op_enum",
        })
    return findings


def _guard_expr(jcc: str, var: str, imm: str = "") -> str:
    sem = _JCC_SEMANTICS.get(jcc)
    if not sem:
        return ""
    op, _ = sem
    if op in ("<0", ">=0"):
        return f"{var} {op}"
    return f"{var} {op} {imm}"


def _negate(jcc: str, var: str, imm: str = "") -> str:
    sem = _JCC_SEMANTICS.get(jcc)
    if not sem:
        return ""
    _, neg_op = sem
    if neg_op in ("<0", ">=0"):
        return f"{var} {neg_op}"
    return f"{var} {neg_op} {imm}"


if __name__ == "__main__":
    demo = """\
cmp rax, 64;
ja skip;
"""
    out = run_guard_op_enum(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])
