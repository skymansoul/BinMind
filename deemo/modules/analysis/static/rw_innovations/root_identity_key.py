"""RootIdentityKey - 根身份键 (stage 68).

alloc size 表达式与 write 地址基址表达式分别归一化为四元组
(kind, var, coeff, const) 哈希键, 若两者键相等 (同变量、同系数)
说明写操作目标地址与分配基址同源 -> identity_safe.
与 SI-CTA 链 id 不同: 表达式归一化哈希而非链传播.

设计决策:
  - alloc: 提取 malloc 参数表达式作为 alloc_size_key (保持不变)
  - write: 提取写操作的地址偏移表达式 [var+off] 而非 RHS 值
  - 归一化: 表达式 -> (kind, var, coeff, const)
  - 同根判定: alloc size 键 == write offset 基址键 -> identity_safe
  - 语义: 比较分配大小表达式与写地址基址表达式的根同源性

差异化 (vs chain_equiv_hash):
  - 本模块用符号四元组 (vars_dict, const) 数学比较同根性
  - 合并同类项系数+常量, 差异项=0 即同根
  - n+8 与 n 不同根 (差常量 8); n 与 n 同根 (差异项=0)
  - chain_equiv_hash 改用溯源链滚动哈希比较, 本模块不涉及哈希
"""

import re
from typing import List, Optional, Tuple


def _normalize(expr: str) -> Tuple[str, str, int, int]:
    """归一化表达式 -> (kind, var, coeff, const).
    kind 为 const / var / unknown.
    支持: 纯常量, var, var*coeff, var+const, var*coeff+const, num*var 等变体.
    """
    expr = expr.strip().replace(" ", "")
    if not expr:
        return ("unknown", "", 0, 0)
    # 纯常量
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", expr):
        return ("const", "", 0, int(expr, 0))
    # 通用解析: 将表达式拆成变量系数和常量
    terms = re.findall(r"[+-]?[^+-]+", expr)
    coeff_map: dict = {}
    const_val = 0
    for term in terms:
        sign = -1 if term.startswith("-") else 1
        if term.startswith("+") or term.startswith("-"):
            term = term[1:]
        if re.fullmatch(r"\d+", term):
            const_val += sign * int(term)
        elif re.fullmatch(r"0[xX][0-9a-fA-F]+", term):
            const_val += sign * int(term, 16)
        else:
            m = re.fullmatch(r"(\w+)\*(\d+)", term)
            if m:
                coeff_map[m.group(1)] = coeff_map.get(m.group(1), 0) + sign * int(m.group(2))
                continue
            m2 = re.fullmatch(r"(\d+)\*(\w+)", term)
            if m2:
                coeff_map[m2.group(2)] = coeff_map.get(m2.group(2), 0) + sign * int(m2.group(1))
                continue
            m3 = re.fullmatch(r"(\w+)", term)
            if m3:
                coeff_map[m3.group(1)] = coeff_map.get(m3.group(1), 0) + sign
                continue
            return ("unknown", "", 0, 0)
    if not coeff_map:
        return ("const", "", 0, const_val)
    if len(coeff_map) == 1:
        var, coeff = next(iter(coeff_map.items()))
        return ("var", var, coeff, const_val)
    # 多变量, 取主变量 (第一个)
    var = sorted(coeff_map.keys())[0]
    return ("var", var, coeff_map[var], const_val)


def _key(expr: str) -> Tuple[str, str, int, int]:
    """兼容旧接口, 保留 _key 不删除."""
    return _normalize(expr)


def _root(expr: str) -> Tuple[str, str, int, int]:
    """兼容旧接口, 保留 _root 不删除."""
    return _normalize(expr)


def _extract_write_offset_expr(addr_expr: str) -> str:
    """从写地址表达式 [addr] 中提取偏移表达式.
    [p+8] -> 'p+8'; [p] -> 'p'; [p+idx*4+8] -> 'p+idx*4+8'
    提取的是地址基址+偏移表达式, 而非 RHS 值.
    """
    return addr_expr.strip()


def _same_root_key(
    alloc_key: Tuple[str, str, int, int],
    write_key: Tuple[str, str, int, int],
) -> bool:
    """#[DEPRECATED] 旧四元组精确相等判定.
    与 chain_equiv_hash 的表达式归一化比较重叠, 差异化后改用 _same_root_math.
    保留函数体供汇编分支兼容回退.
    同根条件: kind 相同, var 相同, coeff 相同, const 相同.
    """
    if alloc_key[0] == "unknown" or write_key[0] == "unknown":
        return False
    return alloc_key == write_key


def _normalize_full(expr: str) -> Tuple[dict, int]:
    """全变量系数归一化 -> (vars_coeff_dict, const).
    合并同类项系数+常量, 支持多变量表达式.
    """
    expr = expr.strip().replace(" ", "")
    if not expr:
        return ({}, 0)
    terms = re.findall(r"[+-]?[^+-]+", expr)
    coeff_map: dict = {}
    const_val = 0
    for term in terms:
        sign = -1 if term.startswith("-") else 1
        if term.startswith("+") or term.startswith("-"):
            term = term[1:]
        if re.fullmatch(r"\d+", term):
            const_val += sign * int(term)
        elif re.fullmatch(r"0[xX][0-9a-fA-F]+", term):
            const_val += sign * int(term, 16)
        else:
            m = re.fullmatch(r"(\w+)\*(\d+)", term)
            if m:
                coeff_map[m.group(1)] = coeff_map.get(m.group(1), 0) + sign * int(m.group(2))
                continue
            m2 = re.fullmatch(r"(\d+)\*(\w+)", term)
            if m2:
                coeff_map[m2.group(2)] = coeff_map.get(m2.group(2), 0) + sign * int(m2.group(1))
                continue
            m3 = re.fullmatch(r"(\w+)", term)
            if m3:
                coeff_map[m3.group(1)] = coeff_map.get(m3.group(1), 0) + sign
                continue
            return ({}, 0)
    return (coeff_map, const_val)


def _same_root_math(alloc_expr: str, write_expr: str) -> bool:
    """同根数学归一化判定: 差异项=0 即同根.
    比较分配表达式与写表达式的全变量系数差异, 逐项相减后全为 0 则同根.
    n 与 n 同根 (差异=0); n+8 与 n 不同根 (差常量 8).
    """
    a_vars, a_const = _normalize_full(alloc_expr)
    w_vars, w_const = _normalize_full(write_expr)
    # 常量差异
    if a_const != w_const:
        return False
    # 变量系数差异: 合并键集, 逐项比较
    all_keys = set(a_vars.keys()) | set(w_vars.keys())
    for k in all_keys:
        if a_vars.get(k, 0) != w_vars.get(k, 0):
            return False
    return True


def run_root_identity_key(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """根身份键判定. 返回 findings.
    比较 alloc size 表达式与 write 地址/大小表达式的根同源性.
    """
    findings: List[dict] = []
    # 提取 malloc 参数表达式作为 alloc_size_key
    alloc_expr = None
    m_alloc = re.search(r"malloc\s*\(\s*([^)]+)\)", pseudocode)
    if m_alloc:
        alloc_expr = m_alloc.group(1).strip()
    if not alloc_expr:
        return findings
    alloc_key = _normalize(alloc_expr)
    # 追踪变量赋值用于归一化
    var_map: dict = {}
    for line in pseudocode.splitlines():
        m_assign = re.search(r"\b(\w+)\s*=\s*([^;]+)", line)
        if m_assign:
            lhs = m_assign.group(1)
            rhs = m_assign.group(2).strip()
            if not re.search(r"(?:malloc|calloc|realloc|memcpy|free)\s*\(", rhs):
                # 跳过自引用赋值: rhs 含 lhs 会导致代换死循环
                # (如 rax = qword [rbp + rax*8 - 0x30])
                if not re.search(r"\b" + re.escape(lhs) + r"\b", rhs):
                    var_map[lhs] = rhs
    def _resolve(expr: str) -> str:
        expr = expr.replace(" ", "")
        changed = True
        # 迭代上限: 正常输入 2-3 轮收敛, 50 轮足够且防止死循环
        _max_iters = 50
        # 表达式长度上限: 防止代换膨胀导致内存爆炸
        _max_len = 10000
        while changed and _max_iters > 0 and len(expr) <= _max_len:
            changed = False
            _max_iters -= 1
            for var, val in var_map.items():
                if re.search(r"\b" + re.escape(var) + r"\b", expr) and var != expr:
                    expr = expr.replace(var, val)
                    changed = True
        return expr
    alloc_resolved = _resolve(alloc_expr)
    alloc_key = _normalize(alloc_resolved)
    # 枚举全部写点, 任一写点不同根则不产 identity_safe (避免漏看越界写点)
    write_points = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        write_expr = None
        # C 风格 memcpy: memcpy(dst, src, len) -> 写大小表达式为 len
        m_mc = re.search(r"memcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*([^)]+)\)", line)
        if m_mc:
            write_expr = m_mc.group(1).strip()
        else:
            # C 风格下标写: buf[expr] = val -> 写偏移表达式为 expr
            m_c = re.search(r"(\w+)\[([^\]]*)\]\s*=", line)
            if m_c:
                write_expr = m_c.group(2)
            else:
                # 汇编风格: [addr] ,/= val
                m_asm = re.search(r"\[([^\]]+)\]\s*[,=]", line)
                if m_asm:
                    write_expr = _extract_write_offset_expr(m_asm.group(1))
                else:
                    continue
        if not write_expr or not write_expr.strip():
            write_expr = "0"
        write_resolved = _resolve(write_expr)
        write_key = _normalize(write_resolved)
        # 差异化: 用同根数学归一化判定 (差异项=0 即同根)
        same = _same_root_math(alloc_resolved, write_resolved)
        write_points.append((ln, write_key, same))
    # 全部写点同根才产 identity_safe, 否则不产 (避免压真)
    if not write_points or not all(wp[2] for wp in write_points):
        return findings
    for ln, write_key, same in write_points:
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.9,
            "description": (
                f"line{ln} alloc_key={alloc_key} write_key={write_key} "
                f"same_root={same}"
            ),
            "verdict": "identity_safe",
            "source": "root_identity_key",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(n * 4 + 8);
mov [p+4], n;
"""
    out = run_root_identity_key(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])
