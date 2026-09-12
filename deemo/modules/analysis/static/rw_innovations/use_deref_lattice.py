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
    freed_vars = set()
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_free = re.search(r"\bfree\s*\(\s*(\w+)\s*\)", line)
        if m_free:
            freed_vars.add(m_free.group(1))
            continue
        # use 点: 函数调用参数、写点或解引用表达式
        m_use = re.search(r"\[\s*(\w+)\s*(?:\+\s*\d+)?\]\s*(?:,|=)\s*(\w+)", line)
        if not m_use:
            # 也匹配直接解引用 *p 或函数调用 use(p)
            m_use = re.search(r"\*(\w+)", line)
            if not m_use:
                m_use = re.search(r"\b(\w+)\s*\(\s*(\w+)", line)
        if m_use:
            var = m_use.group(1)
            # 对完整行表达式计算深度, 而非仅匹配片段
            depth = _deref_depth(line)
            dangling = var in freed_vars
            if depth >= 2 and dangling:
                verdict, conf = "confirmed_uaf", 0.9
            elif depth < 2 and dangling:
                verdict, conf = "weak_uaf", 0.4
            else:
                verdict, conf = "not_dangling", 0.3
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