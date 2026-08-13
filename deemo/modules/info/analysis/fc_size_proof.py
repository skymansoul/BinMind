# analysis/fc_size_proof — FC-VRA 尺寸可证性与约束简化
# 集中管理"等量/包含/截断/读源"四类安全证明。
# 设计动机: 真实 CVE 语料暴露两类误抑制 —
#   (a) 运行时尺寸相等 (heartbleed 读溢出) 被当作常量等量安全抑制;
#   (b) 含可控变量的 alloc 尺寸 (len*4 回绕) 被 write⊆alloc 抑制。
# 因此所有"证明安全"必须先回答两个前置问题:
#   P1 尺寸是否编译期常量 (非运行时变量)
#   P2 读源是否为已知本地数组 (决定读溢出候选的成立条件)
# CWE-122 堆写作用域限定: 目标缓冲区有界即为堆写安全;
# 读溢出 (CWE-126) 仅在读源尺寸未知时作为降权候选保留。

from __future__ import annotations
from typing import Dict, Optional
import re

from value_range_analyzer import ValueRange
from size_expr_evaluator import eval_size_expr, resolve_defines
from taint_confirm import _seed_sources, _propagate

_ARRAY_DECL_RE = re.compile(
    r"\b(?:char|unsigned char|signed char|int|unsigned|short|long|size_t)"
    r"\s+(\w+)\s*\[\s*(\d+)\s*\]")


def intra_tainted_vars(code: str) -> set:
    """函数内污染变量集合 (输入源 → 赋值/算术传播)。"""
    return _propagate(code, _seed_sources(code))


def _param_tainted_vars(code: str, intra_tainted) -> set:
    """跨函数参数污染: 函数参数被 tainted 实参传入 → 参数视为可控。

    用于 size 表达式可控性判定 (heartbleed/grub 等 CVE 的 size 均来自
    函数参数, 而参数在调用点被 atoi/recv 等输入驱动)。
    """
    tainted_params = set()
    for m in re.finditer(
        r"(?:static\s+)?(?:void|int|char|size_t|unsigned|long|bool|"
        r"unsigned\s+int)\s+(\w+)\s*\(([^)]*)\)", code):
        fn_name, params = m.group(1), m.group(2)
        # 参数名列表 (按声明顺序, 去掉类型/数组/指针)
        param_names = []
        for part in params.split(","):
            part = part.strip()
            if not part or "..." in part:
                continue
            pn = part.split()[-1].strip("*").strip()
            if pn and pn[0].isalpha():
                param_names.append(pn)
        for call in re.finditer(rf"\b{re.escape(fn_name)}\s*\(\s*([^)]*?)\)",
                                code):
            args = [a.strip() for a in call.group(1).split(",")]
            for i, pn in enumerate(param_names):
                if i >= len(args):
                    break
                arg = args[i]
                if not arg or arg.startswith('"'):
                    continue
                arg_vars = set(re.findall(r"\b(\w+)\b", arg))
                if re.match(r"argv\s*\[", arg) or \
                   re.search(r"argv\s*\[\s*\d+\s*\]", arg) or \
                   any(v in intra_tainted for v in arg_vars):
                    tainted_params.add(pn)
    return tainted_params


def _size_var_tainted(code: str, expr: str, intra_tainted) -> bool:
    """size 表达式是否含攻击者可控变量 (含跨函数参数)。"""
    if not expr:
        return False
    vars_in = [v for v in re.findall(r"\b(\w+)\b", expr)
               if not v.isdigit() and v not in ("int", "char", "short",
                                                "long", "size", "t",
                                                "sizeof")]
    if not vars_in:
        return False
    if any(v in intra_tainted for v in vars_in):
        return True
    return bool(_param_tainted_vars(code, intra_tainted) & set(vars_in))


def size_is_constant(code: str, expr: str, defines: Dict) -> bool:
    """尺寸表达式是否为编译期常量 (字面量/sizeof/#define 宏)。

    运行时变量 (参数/输入/计算值) 即使与写入量相等, 也可能因
    回绕或读源更小而构成溢出 → 不得判定必然安全。
    """
    if not expr:
        return False
    e = expr.strip()
    if not e:
        return False
    if e.isdigit():
        return True
    if re.match(r"sizeof\s*\(", e):
        return True
    # sizeof(T) 为编译期常量, 其内部类型名不参与变量判定
    e = re.sub(r"sizeof\s*\([^)]*\)", "4", e)
    vars_ = [v for v in re.findall(r"\b([a-zA-Z_]\w*)\b", e)
             if v not in ("sizeof", "int", "char", "short", "long", "size",
                          "t")]
    if not vars_:
        return True  # 无变量 (纯运算)
    return all(v in defines for v in vars_)


def resolve_sizeof_var(code: str, expr: str) -> Optional[ValueRange]:
    """sizeof(数组变量) → 数组声明尺寸 (tp_06/tp_09 等 char src[N] 场景)。"""
    m = re.match(r"sizeof\s*\(\s*(\w+)\s*\)", expr.strip())
    if not m:
        return None
    name = m.group(1)
    for dm in _ARRAY_DECL_RE.finditer(code):
        if dm.group(1) == name:
            return ValueRange.const(int(dm.group(2)))
    return None


def write_ternary_capped_by_alloc(code: str, alloc_expr: str,
                                  write_expr: str) -> bool:
    """写入量表达式是否被分配量截断。

    两类截断:
      a) min-style: 写入含分配变量 (NEG-007: len<alloc?len:alloc)
      b) 三目常量截断: X < N ? X : K 或 X < N ? K : X, 且
         max(K, N-1) ≤ 分配常量
    与 grub 类 (write=len, alloc=len*4) 的区别: 后者为纯变量写, 无截断结构。
    """
    if not write_expr or write_expr == alloc_expr:
        return False
    if "?" not in write_expr and "<" not in write_expr and \
       ">" not in write_expr:
        return False
    # a) 写入含分配变量 (min-style)
    if alloc_expr:
        alloc_vars = set(re.findall(r"\b([a-zA-Z_]\w*)\b", alloc_expr))
        alloc_vars -= {"int", "char", "short", "long", "size", "t", "sizeof"}
        if any(v in write_expr for v in alloc_vars):
            return True
    # b) 三目常量截断: X < N ? X : K / X < N ? K : X → 结果上界可计算
    m = re.fullmatch(
        r"(\w+)\s*[<>]\s*(\d+)\s*\?\s*(\w+)\s*:\s*(\w+)",
        write_expr.replace(" ", ""))
    if m:
        var, n_val, b1, b2 = m.group(1), int(m.group(2)), \
            m.group(3), m.group(4)
        upper = []
        ok = True
        for b in (b1, b2):
            if b.isdigit():
                upper.append(int(b))
            elif b == var:
                upper.append(n_val - 1)
            else:
                ok = False
                break
        if ok and alloc_expr and alloc_expr.strip().isdigit():
            return max(upper) <= int(alloc_expr.strip())
    return False


def read_source_is_local_array(code: str, write_func: str) -> bool:
    """memcpy 读源是否为已知尺寸的本地数组。

    等尺寸运行时变量的读溢出候选 (heartbleed 类) 仅在读源尺寸未知
    (指针/参数) 时成立; 读源为已知本地数组时, 目标缓冲区等量安全,
    属于 CWE-122 堆写作用域外, 不告警。
    """
    for m in re.finditer(
        rf"\b{re.escape(write_func)}\s*\(((?:[^()]|\([^()]*\))*)\)", code):
        args = [a.strip() for a in m.group(1).split(",")]
        if len(args) < 2:
            continue
        src = re.sub(r"\s*\+\s*[\w.]+", "", args[1])
        src = re.sub(r"\[[^\]]*\]", "", src).strip()
        if src and re.match(r"^[a-zA-Z_]\w*$", src):
            for dm in _ARRAY_DECL_RE.finditer(code):
                if dm.group(1) == src:
                    return True
    return False
