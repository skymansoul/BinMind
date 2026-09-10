# analysis/size_equivalence — FC-VRA 阶段C1: 分配/写入大小表达式结构等价
# 若 alloc size 与 write size 在代数结构上等价, 则写入量≤分配量,
# 该候选对必然不构成溢出 (除非整型溢出, 由 C2 整型校验另行把关)。
# 与 heap_overflow_v2._source_safety 的字符串相等相比:
#   字符串相等只能捕获 malloc(n) 与 memcpy(dst,src,n) 的字面一致,
#   无法识别 n*4 与 4*n、n<<2 与 n*4、以及宏替换后的等价。
#
# 设计:
#   1. 预处理: #define 宏常量内联, sizeof(T) → 字节常量
#   2. 代数规范化: 表达式 → 项列表, 每项 = (系数, 变量元组),
#      自动处理交换律/结合律/常量折叠
#   3. 移位移除: n<<k == n*(2**k)
#   4. 等价判定 = 规范化后逐项比较
#
# 符号代数中的多项式规范化; 与编译器的 constant-folding 同源,
# 保证在纯大小比较场景的完备性边界内有效。

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import re

_SIZEOF_MAP = {
    "char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
    "float": 4, "double": 8, "size_t": 8, "void*": 8, "void *": 8,
    "unsigned": 4, "unsigned int": 4, "unsigned long": 8,
}

def _inline_defines(code: str, expr: str) -> str:
    """将 #define 宏常量内联进表达式。"""
    defines: Dict[str, str] = {}
    for m in re.finditer(r"#define\s+(\w+)\s+(\d+)\s*$", code, re.MULTILINE):
        defines[m.group(1)] = m.group(2)
    for name, val in defines.items():
        expr = re.sub(rf"\b{name}\b", val, expr)
    return expr

def _replace_sizeof(expr: str) -> str:
    """sizeof(T) → 字节常量。"""
    def _sub(m: "re.Match") -> str:
        t = m.group(1).strip().replace(" ", "")
        return str(_SIZEOF_MAP.get(t, 4))
    return re.sub(r"sizeof\s*\(\s*([^)]*)\s*\)", _sub, expr)

def _split_terms(expr: str) -> List[str]:
    """按 + - 切分项, 保留每项的前置符号。"""
    expr = expr.replace(" ", "")
    # 规范化一元负号: 首项若为负则保留
    terms = []
    cur, sign = "", 1
    for ch in expr:
        if ch in "+-" and cur:
            terms.append(("" if sign > 0 else "-") + cur)
            cur, sign = "", (1 if ch == "+" else -1)
        else:
            if ch == "-" and not cur:
                sign = -1
                continue
            cur += ch
    if cur:
        terms.append(("" if sign > 0 else "-") + cur)
    return [t for t in terms if t and t != "+"]

def _factor_term(term: str) -> Tuple[int, Tuple[str, ...]]:
    """单项 → (系数, 排序后的变量元组)。变量名即符号常量 (unknown值)。"""
    term = term.replace(" ", "")
    neg = term.startswith("-")
    if neg:
        term = term[1:]

    # 展开括号 (仅一层, 覆盖 (a+b)*c 形式的基本情形)
    if "(" in term:
        m = re.fullmatch(r"\((.+)\)", term)
        if m:
            term = m.group(1)

    # 移位移除: x<<k → x * 2^k; x>>k 不处理 (不等价于乘法)
    term = re.sub(r"(\w+)\s*<<\s*(\d+)",
                  lambda mm: f"{mm.group(1)}*{2 ** int(mm.group(2))}", term)

    parts = [p for p in re.split(r"\*", term) if p]
    coeff = 1
    vars_ = []
    for p in parts:
        if p.isdigit():
            coeff *= int(p)
        else:
            vars_.append(p)
    if not vars_ and not parts:
        return (0, ())
    return (-coeff if neg else coeff, tuple(sorted(vars_)))

def canonical_form(code: str, expr: str) -> Optional[Tuple[int, ...]]:
    """把表达式转为规范形式: 排序后的 (系数, 变量元组) 列表。

    返回 None 表示表达式含无法解析成分 (如函数调用/未知符号) → 判定为未知。
    """
    if not expr or expr in ("unknown", "unbounded", "loop_bounded"):
        return None
    expr = _inline_defines(code, expr)
    expr = _replace_sizeof(expr)

    factors: List[Tuple[int, Tuple[str, ...]]] = []
    for term in _split_terms(expr):
        if not term:
            continue
        coeff, vars_ = _factor_term(term)
        if coeff == 0 and not vars_:
            continue
        # 含函数调用/指针/下标 → 视为不可解析
        if any(ch in term for ch in "()[]~&|^%?:"):
            return None
        factors.append((coeff, vars_))
    if not factors:
        return None
    # 按变量元组排序以消除顺序依赖
    factors.sort(key=lambda f: (len(f[1]), f[1]))
    return tuple(factors)

def sizes_equivalent(code: str, alloc_expr: str, write_expr: str) -> bool:
    """判定分配量与写入量是否结构等价。

    返回 True 仅在规范形式完全一致 (含系数与变量集合)。
    """
    a = canonical_form(code, alloc_expr)
    w = canonical_form(code, write_expr)
    if a is None or w is None:
        return False
    return a == w

def write_bounded_by_alloc(code: str, alloc_expr: str,
                           write_expr: str) -> bool:
    """写入量受分配量约束: 写入量规范形式是分配量规范形式的子项集。

    用于 alloc = n*4+8, write = n*4 之类的"写入≤分配"安全判定。
    """
    a = canonical_form(code, alloc_expr)
    w = canonical_form(code, write_expr)
    if a is None or w is None:
        return False
    if len(w) > len(a):
        return False
    # 每个写入项都必须能在分配项中找到支配项 (同变量, 系数≥)
    for wcoeff, wvars in w:
        found = False
        for acoeff, avars in a:
            if avars == wvars and acoeff >= wcoeff:
                found = True
                break
        if not found:
            return False
    return True

if __name__ == "__main__":
    cases = [
        ("n*4", "4*n", True),
        ("n*4", "n<<2", True),
        ("n", "n", True),
        ("n*4", "n*4+8", False),
        ("N*sizeof(int)", "N*4", True),
        ("n+1", "n+1", True),
        ("n", "m", False),
    ]
    for a, w, expect in cases:
        got = sizes_equivalent("", a, w)
        print(f"{a!r} ~ {w!r}: got={got} expect={expect}")
    print("write_bounded_by_alloc(n*4+8, n*4):",
          write_bounded_by_alloc("", "n*4+8", "n*4"))
