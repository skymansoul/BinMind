"""SymbolicDiffSign - 符号差符号判定 (stage 69).

写范围上界(偏移+写宽度) - alloc_expr 化简后若只剩正系数常量项 -> 确定溢出 k 字节.
与 仿射边界验证 仿射不同: 不做区间求值, 仅符号化简取符号.

设计决策:
  - 将表达式化简为 (vars, const) 形式: vars 收集变量系数,
    const 为常量部分
  - 求 diff = (写偏移 + 写宽度) - alloc
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
            # 变量或 变量*常量 或 常量*变量
            m = re.fullmatch(r"(\w+)\*(\d+)", term)
            if m:
                coeff[m.group(1)] = coeff.get(m.group(1), 0) + sign * int(m.group(2))
            else:
                m2 = re.fullmatch(r"(\d+)\*(\w+)", term)
                if m2:
                    coeff[m2.group(2)] = coeff.get(m2.group(2), 0) + sign * int(m2.group(1))
                else:
                    coeff[term] = coeff.get(term, 0) + sign
    return coeff, const


def _write_width(line: str) -> int:
    """从写操作行推断写入字节数. 依据操作数宽度而非立即数值."""
    line = line.strip()
    # 行内宽度前缀优先: qword/dword/word/byte ptr
    if re.search(r"\bqword\b", line, re.IGNORECASE):
        return 8
    if re.search(r"\bdword\b", line, re.IGNORECASE):
        return 4
    if re.search(r"\bword\b", line, re.IGNORECASE):
        return 2
    if re.search(r"\bbyte\b", line, re.IGNORECASE):
        return 1
    # 寄存器源宽度判断
    # 先找 mov [mem], reg 模式中的 reg
    m_reg = re.search(r"\[[^\]]*\]\s*(?:,|=)\s*([A-Za-z])", line)
    if m_reg:
        reg = m_reg.group(1)
        # 64 位寄存器: rax~r15, r8~r15 (R 开头)
        if re.match(r"r[a-z0-9]+", line[line.index(reg):].split()[0] if " " in line[line.index(reg):] else line[line.index(reg):]):
            # 完整匹配寄存器名
            rest = line[line.index(reg):]
            reg_full = re.match(r"[A-Za-z][A-Za-z0-9]*", rest)
            if reg_full:
                name = reg_full.group(0).lower()
                if name.startswith("r") and len(name) >= 2:
                    return 8
                if name.startswith("e"):
                    return 4
                if len(name) == 2 and name[0] in ("a", "b", "c", "d"):
                    return 1
    # 立即数无其他信息时按 4 字节
    return 4


def _detect_elem_size(pseudocode: str, ptr_name: str) -> int:
    """从 C 风格声明推断指针元素大小. 汇编风格调用方不使用此函数."""
    # 查找指针声明: type *ptr = ...
    m_decl = re.search(
        r"\b(char|short|int|long|unsigned)\s*\*\s*" + re.escape(ptr_name) + r"\s*=",
        pseudocode,
    )
    if m_decl:
        t = m_decl.group(1)
        if t == "char":
            return 1
        if t == "short":
            return 2
        return 4
    # 查找 cast: (type *)malloc
    m_cast = re.search(
        r"\(\s*(char|short|int|long|unsigned)\s*\*\s*\)\s*malloc", pseudocode
    )
    if m_cast:
        t = m_cast.group(1)
        if t == "char":
            return 1
        if t == "short":
            return 2
        return 4
    return 4


def _parse_for_loop_bounds(
    pseudocode: str,
) -> Dict[str, Tuple[Dict[str, int], int, bool]]:
    """解析 for 循环上界. 返回 {var: (upper_coeff, upper_const, is_inclusive)}."""
    bounds: Dict[str, Tuple[Dict[str, int], int, bool]] = {}
    for m in re.finditer(
        r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*(<=|<)\s*([^;]+)\s*;", pseudocode
    ):
        var = m.group(1)
        op = m.group(2)
        upper_expr = m.group(3).strip()
        uc, uconst = _simplify(upper_expr)
        bounds[var] = (uc, uconst, op == "<=")
    return bounds


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
    # C 风格: 从指针 cast 推断元素大小, 用于 buf[i*8] 等步长写
    alloc_ptr = None
    m_ptr = re.search(r"(\w+)\s*=\s*\([^)]*\)?\s*malloc", pseudocode)
    if m_ptr:
        alloc_ptr = m_ptr.group(1)
    elem_size = _detect_elem_size(pseudocode, alloc_ptr) if alloc_ptr else 4
    loop_bounds = _parse_for_loop_bounds(pseudocode)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        # C 风格 memcpy 写操作优先: memcpy(dst, src, len)
        m_mc = re.search(r"memcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*([^)]+)\)", line)
        if m_mc:
            write_expr = m_mc.group(1).strip()
        else:
            # C 风格写点: buf[expr] = ...
            write_expr = None
            m_c = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
            if m_c:
                if alloc_ptr and m_c.group(1) == alloc_ptr:
                    write_expr = m_c.group(2)
                elif not alloc_ptr:
                    write_expr = m_c.group(2)
            if write_expr is None:
                # 汇编风格写点: [ptr+off] ,/= val
                m_asm = re.search(r"\[([^\]]*)\]\s*(?:,|=)", line)
                if m_asm:
                    # 汇编风格: 偏移仅为常量, 指针名不作为变量
                    asm_inner = m_asm.group(1).strip()
                    off_const = 0
                    m_off = re.search(r"\+\s*(\d+|0[xX][0-9a-fA-F]+)", asm_inner)
                    if m_off:
                        off_str = m_off.group(1)
                        off_const = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)
                    wc_asm: Dict[str, int] = {}
                    wconst = off_const
                    wwidth_asm = _write_width(line)
                    wconst += wwidth_asm
                    diff_c_asm: Dict[str, int] = {}
                    diff_const_asm = wconst - alloc_const
                    if diff_const_asm > 0:
                        verdict = "overflow"
                        conf = 0.85
                        desc = f"line{ln} diff_const={diff_const_asm} -> overflow {diff_const_asm}B"
                    elif diff_const_asm == 0:
                        continue
                    else:
                        verdict = "safe"
                        conf = 0.9
                        desc = f"line{ln} diff_const={diff_const_asm} -> safe"
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
                    continue
                else:
                    continue
        # 化简写表达式, 含变量系数
        wc, wconst = _simplify(write_expr)
        # 循环变量消元: 若 write_expr 中含循环变量且有上界, 用上界替换
        for var, (uc, uconst, inclusive) in loop_bounds.items():
            if var in wc:
                coeff = wc.pop(var)
                for uv, uc2 in uc.items():
                    wc[uv] = wc.get(uv, 0) + coeff * uc2
                upper = uconst if inclusive else uconst - 1
                wconst += coeff * upper
        # 写宽度: memcpy 的 len 已是总字节数不叠加; 下标写叠加元素大小
        if not m_mc:
            wwidth = _write_width(line)
            if wwidth == 4 and alloc_ptr:
                wwidth = elem_size
            wconst += wwidth
        # diff = write - alloc
        diff_c: Dict[str, int] = {}
        for v, c in wc.items():
            diff_c[v] = diff_c.get(v, 0) + c
        for v, c in alloc_c.items():
            diff_c[v] = diff_c.get(v, 0) - c
        # 消去零系数变量
        diff_c = {v: c for v, c in diff_c.items() if c != 0}
        diff_const = wconst - alloc_const
        if not diff_c and diff_const > 0:
            verdict = "overflow"
            conf = 0.85
            desc = f"line{ln} diff_const={diff_const} -> overflow {diff_const}B"
        elif not diff_c and diff_const == 0:
            # 差恰好为零, 边界精确, 不注入
            continue
        elif not diff_c:
            verdict = "safe"
            conf = 0.9
            desc = f"line{ln} diff_const={diff_const} -> safe"
        elif all(c < 0 for c in diff_c.values()) and diff_const <= 0:
            # 所有变量系数为负且常量非正, 写上界严格小于分配上界
            verdict = "safe"
            conf = 0.85
            desc = f"line{ln} diff_c={diff_c} diff_const={diff_const} -> safe (neg)"
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