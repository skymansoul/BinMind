"""UseDerefLattice - 解引用格 (stage 79).

use 按解引用深度分层 (传参/取址/解引用/算术), 仅深度>=2 且悬垂才
CONFIRMED. 与 uaf_callee_class 不同: 格深度而非函数白名单.

设计决策:
  - 解引用深度格: 0=直接传参, 1=取址(&x), 2=解引用(*x 或 [x]),
    3=算术组合 (x->f / x+off)
  - use 的深度 >= 2 且对象已 free -> CONFIRMED
  - 深度 < 2 -> 降权
"""

import re
from typing import List, Optional


def _deref_depth(expr: str) -> int:
    """对写操作的完整表达式计算解引用深度, 而非仅匹配到的 use 点字符串.

    深度判定依据表达式中解引用符号的出现层次:
      0: 直接变量名 (如 p), 无解引用
      1: 取地址 &p (一级间接)
      2: 单层数组索引 [p] 或 [p+off] (单层解引用)
      3: 双层解引用 [[p]] 或 [p->field] 或 *(p+off) (两层间接)
    """
    bracket_count = expr.count("[")
    star_count = expr.count("*")
    # 取地址为一级间接, 但不增加解引用深度
    has_addr = "&" in expr
    # 双层解引用: 两个以上 [ 或 [ 与 * 并存
    deref_count = bracket_count + star_count
    if deref_count >= 2:
        return 3
    if deref_count == 1:
        return 2
    if has_addr:
        return 1
    # 结构体成员访问也算一层解引用
    if re.search(r"->|\.", expr):
        return 2
    return 0


def run_use_deref_lattice(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """解引用格判定. 返回 findings."""
    findings: List[dict] = []
    # 按分号拆分子语句, 保留行号映射, 使单行多语句可正确处理时间序
    stmts = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        for stmt in line.split(";"):
            stmt = stmt.strip()
            if stmt:
                stmts.append((ln, stmt))
    # 第一遍: 收集指针变量与全部 freed 变量
    ptr_vars = set()
    freed_all = set()
    for _, stmt in stmts:
        m_free = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", stmt)
        if m_free:
            freed_all.add(m_free.group(1))
            ptr_vars.add(m_free.group(1))
        m_malloc = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(", stmt)
        if m_malloc:
            ptr_vars.add(m_malloc.group(1))
    # 第二遍: 按序检测 use 点, 保留 freed 时间序
    freed_vars = set()
    for ln, stmt in stmts:
        m_free = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", stmt)
        if m_free:
            freed_vars.add(m_free.group(1))
            continue
        # use 点识别: 覆盖汇编风格与 C 风格
        var = None
        match_kind = None
        # 汇编风格: [p+off] => p 在方括号内, 仅当 p 是已知指针变量
        m_asm = re.search(r"\[\s*(\w+)\s*(?:\+\s*\d+)?\]\s*(?:,|=)\s*(\w+)", stmt)
        if m_asm and m_asm.group(1) in ptr_vars:
            var = m_asm.group(1)
            match_kind = "asm_index"
        # C 风格下标写: buf[off] => 指针在方括号左侧
        if var is None:
            m_cidx = re.search(r"\b(\w+)\s*\[", stmt)
            if m_cidx:
                var = m_cidx.group(1)
                match_kind = "c_index"
        # 解引用: *p
        if var is None:
            m_deref = re.search(r"\*(\w+)", stmt)
            if m_deref:
                var = m_deref.group(1)
                match_kind = "deref"
        # 成员访问: p->x 或 p.x
        if var is None:
            m_member = re.search(r"\b(\w+)\s*(?:->|\.)\s*\w+", stmt)
            if m_member:
                var = m_member.group(1)
                match_kind = "member"
        # 函数调用实参: func(p, ...) => 第一个实参为指针变量
        if var is None:
            m_call = re.search(r"\b(\w+)\s*\(\s*(\w+)", stmt)
            if m_call:
                var = m_call.group(2)
                match_kind = "call_arg"
        if var and var in ptr_vars:
            depth = _deref_depth(stmt)
            # 函数调用实参会被函数内部解引用, 最低深度 2
            if match_kind == "call_arg" and depth < 2:
                depth = 2
            dangling = var in freed_vars
            if depth >= 2 and dangling:
                verdict, conf = "confirmed_uaf", 0.9
            elif depth < 2 and dangling:
                verdict, conf = "weak_uaf", 0.4
            elif var not in freed_all:
                # 变量从未被 free, 降权其他模块的 UAF 误报
                verdict, conf = "not_dangling", 0.3
            else:
                # 变量已被 free 但当前语句在 free 之前, 跳过
                continue
            findings.append({
                "type": "use_after_free",
                "function": func_name or "unknown",
                "severity": "high" if verdict == "confirmed_uaf" else "medium",
                "cwe": "CWE-416",
                "confidence": conf,
                "description": f"line{ln} var={var} depth={depth} "
                               f"dangling={dangling}",
                "verdict": verdict,
                "source": "use_deref_lattice",
            })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(16);
free(p);
mov [p+4], 0;
"""
    out = run_use_deref_lattice(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])