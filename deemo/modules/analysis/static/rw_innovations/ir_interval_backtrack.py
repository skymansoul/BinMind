"""IrIntervalBacktrace - IR 区间回溯 (stage 104).

VarRange.at 程序点查询 + 回退最近定义快照:
  维护变量定义快照, 在任意程序点查询变量区间,
  无定义时回退到最近快照.
与 affine_meet_domain 不同: 本模块按程序点回溯而非全局映射.

设计决策:
  - 快照: {var: (区间, 定义行)}
  - at(ln, var): 取 <= ln 的最近定义
  - 无定义 -> UNKNOWN
"""

import re
from typing import Dict, List, Optional, Tuple


class VarRange:
    """变量区间快照表."""

    def __init__(self) -> None:
        self._snap: Dict[str, List[Tuple[int, Tuple[int, int]]]] = {}

    def set(self, var: str, ln: int, r: Tuple[int, int]) -> None:
        self._snap.setdefault(var, []).append((ln, r))

    def at(self, var: str, ln: int) -> Optional[Tuple[int, int]]:
        """查询 <= ln 的最近定义区间."""
        snaps = self._snap.get(var, [])
        best = None
        for sln, r in snaps:
            if sln <= ln:
                best = r
            else:
                break
        return best


def _parse_def(line: str) -> Optional[Tuple[str, int, int, Optional[str]]]:
    m = re.search(r"\b(\w+)\s*=\s*(\d+)\s*;", line)
    if m:
        val = int(m.group(2))
        return m.group(1), val, val, None
    m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)", line)
    if m:
        # 返回 base 变量名供回溯查表，offset 存入 hi 占位
        return m.group(1), 0, int(m.group(3)), m.group(2)
    return None


def _parse_c_loop(pseudocode: str):
    """C 风格循环头解析: for(i=0; i<n; i++) 提取归纳变量与上界变量."""
    m = re.search(r"for\s*\(\s*(\w+)\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
    if m:
        return m.group(1), int(m.group(2)), m.group(3)
    return None


def _parse_c_writes(pseudocode: str):
    """C 风格下标写: 返回 (行号, 索引表达式) 列表."""
    results = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\b(\w+)\[([^\]]+)\]\s*=", line)
        if m:
            results.append((ln, m.group(2).strip()))
    return results


def _parse_c_alloc_coeff(pseudocode: str):
    """解析 C 风格 malloc 表达式中 bound 变量的系数.

    malloc(n) -> (n, 1); malloc(n*4) -> (n, 4); malloc(64) -> ('', 0)
    """
    m = re.search(r"malloc\s*\(\s*([^)]+)\s*\)", pseudocode)
    if not m:
        return None
    expr = m.group(1).strip()
    if re.fullmatch(r"\d+", expr):
        return ('', 0)
    if re.fullmatch(r"\w+", expr):
        return (expr, 1)
    m2 = re.fullmatch(r"(\w+)\s*\*\s*(\d+)", expr)
    if m2:
        return (m2.group(1), int(m2.group(2)))
    m3 = re.fullmatch(r"(\d+)\s*\*\s*(\w+)", expr)
    if m3:
        return (m3.group(2), int(m3.group(1)))
    return None


def run_ir_interval_backtrace(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """区间点回溯. 返回 findings."""
    findings: List[dict] = []
    # C 风格优先: 解析循环头建立归纳变量区间
    c_loop = _parse_c_loop(pseudocode)
    if c_loop is not None:
        loop_var, init_lo, bound_var = c_loop
        # 归纳变量区间 [init_lo, bound_var), bound_var 为符号上界
        # 用 (0, -1) 表示符号上界: lo=init_lo, hi=-1 代表开区间上界为符号变量
        vr_c: Dict[str, Tuple[int, int]] = {loop_var: (init_lo, -1)}
        # 分配上界变量名记录用于后续判断
        bound_vars: Dict[str, str] = {loop_var: bound_var}
        c_writes = _parse_c_writes(pseudocode)
        # 解析分配系数用于步长越界判定
        alloc_info = _parse_c_alloc_coeff(pseudocode)
        alloc_bound_var = alloc_info[0] if alloc_info else ''
        alloc_coeff = alloc_info[1] if alloc_info is not None else 0
        for ln, idx_expr in c_writes:
            # 归纳变量 * 步长: 步长 > 分配系数则越界, 不产 backtraced
            m_mul = re.match(r"(\w+)\s*\*\s*(\d+)$", idx_expr)
            if m_mul and m_mul.group(1) == loop_var:
                stride = int(m_mul.group(2))
                if (alloc_bound_var == bound_var
                        and stride > alloc_coeff and alloc_coeff > 0):
                    verdict, conf = "unknown", 0.2
                    r = None
                else:
                    r = vr_c[loop_var]
                    verdict, conf = "backtraced", 0.8
            elif re.fullmatch(re.escape(loop_var), idx_expr):
                r = vr_c[loop_var]
                verdict, conf = "backtraced", 0.8
            else:
                # 非线性偏移或异名变量: n+8 等, 无法证明界内
                verdict, conf = "unknown", 0.2
                r = None
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"line{ln} idx={idx_expr} range={r} verdict={verdict} mode=c",
                "verdict": verdict,
                "source": "ir_interval_backtrack",
            })
        return findings
    # 汇编风格回退
    vr = VarRange()
    lines = pseudocode.splitlines()
    for ln, line in enumerate(lines, 1):
        d = _parse_def(line)
        if d:
            var, lo, hi, base_var = d
            if base_var is not None:
                # var = base + N: 回溯 base 的已定义区间计算 var 区间
                base_r = vr.at(base_var, ln)
                if base_r is not None:
                    lo = base_r[0] + hi
                    hi = base_r[1] + hi
                    vr.set(var, ln, (lo, hi))
                else:
                    # base 无已知定义，保守标记无法定界
                    vr.set(var, ln, (0, -1))
            else:
                vr.set(var, ln, (lo, hi))
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]\s*(?:,|=)", line)
        if not m:
            continue
        idx = m.group(1)
        r = vr.at(idx, ln)
        if r is None or r[0] > r[1]:
            verdict, conf = "unknown", 0.2
        else:
            verdict, conf = "backtraced", 0.8
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} idx={idx} range={r} verdict={verdict} mode=asm",
            "verdict": verdict,
            "source": "ir_interval_backtrack",
        })
    return findings


if __name__ == "__main__":
    demo = """\
i = 3;
mov [p+i], 0;
"""
    out = run_ir_interval_backtrace(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])