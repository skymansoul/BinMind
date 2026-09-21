"""FiveModalDSTheory - 五模态 D-S 证据理论 (stage 105).

五模态 mass 函数 (safe/overflow/unknown/conflict/filtered)
+ 双源 D-S 组合规则 + 冲突因子 K.
与 four_verdict_scale 不同: 本模块做两源 D-S 组合, four_verdict_scale 做单源概率分级.

设计决策:
  - 五模态: SAFE, OVERFLOW, UNKNOWN, CONFLICT, FILTERED
  - 证据源 A (静态分析证据): malloc/写点/守卫模式匹配
  - 证据源 B (结构证据): 写偏移 vs 分配大小, 守卫证伪
  - D-S 组合: m12(A) = sum_{B∩C=A} m1(B)m2(C) / (1-K)
  - K=冲突因子, K>=1 时证据完全冲突 -> CONFLICT
  - FILTERED: 守卫证伪 (写变量在 if 条件中被约束) 时产出
"""

import re
from typing import Dict, List, Optional

_MODES = ["SAFE", "OVERFLOW", "UNKNOWN", "CONFLICT", "FILTERED"]

# C 风格 if-clamp 守卫: if (x > K) x = K; / if (x >= K) x = K - 1;
# 支持单行/多行/带块写法, re.DOTALL 允许空白跨行
_CLAMP_RE = re.compile(
    r"if\s*\(\s*(\w+)\s*(>|>=)\s*(\d+)\s*\)\s*\{?\s*"
    r"\1\s*=\s*(\d+)(\s*-\s*1)?\s*;?\s*\}?",
    re.DOTALL,
)


def _c_clamp_bounds(pseudocode: str) -> Dict[str, int]:
    """识别 if-clamp 守卫并返回变量上界 {变量: 上界}.

    形如 if (x > K) x = K; 把 x 上界收敛为 K; if (x >= K) x = K - 1;
    上界为 K-1. 返回的上界供长度-分配相容比较使用, 避免把已钳制的
    符号长度误判为越界.
    """
    bounds: Dict[str, int] = {}
    for m in _CLAMP_RE.finditer(pseudocode):
        var, op, imm_str, assign_str, minus1 = (
            m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
        upper = int(imm_str) - 1 if op == ">=" else int(imm_str)
        assign_val = int(assign_str) - 1 if minus1 else int(assign_str)
        bounds[var] = min(upper, assign_val)
    return bounds


def _c_parse_alloc(pseudocode: str):
    """C 风格分配解析: 返回 (变量名, 常量大小或None, (符号变量, 乘数) 或None)."""
    m = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    if m:
        return m.group(1), int(m.group(2)), None
    m = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)", pseudocode)
    if m:
        return m.group(1), None, (m.group(2), int(m.group(3)))
    m = re.search(r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\w+)\s*\)", pseudocode)
    if m:
        return m.group(1), None, (m.group(2), 1)
    return None


def _c_source_a(pseudocode: str, alloc_var) -> Dict[str, float]:
    """C 风格证据源 A: 写模式与分配关系."""
    mass: Dict[str, float] = {}
    has_write = bool(re.search(r"\bmemcpy\s*\(\s*" + re.escape(alloc_var) + r"\b", pseudocode)) or bool(re.search(r"\b" + re.escape(alloc_var) + r"\[", pseudocode))
    if has_write:
        mass["OVERFLOW"] = 0.45
    # 守卫存在
    if re.search(r"if\s*\([^)]*\)", pseudocode):
        mass["SAFE"] = mass.get("SAFE", 0.0) + 0.20
    total = sum(mass.values())
    if total < 1.0:
        mass["UNKNOWN"] = 1.0 - total
    return mass


def _c_source_b(pseudocode: str, alloc_var, alloc_const, alloc_sym,
                clamp_bounds: Dict[str, int] = None) -> Dict[str, float]:
    """C 风格证据源 B: 写偏移/写大小 vs 分配边界.

    clamp_bounds: if-clamp 守卫收敛后的变量上界, 用于把符号长度
    (如 memcpy 第三参为变量) 与分配大小做相容比较.
    """
    mass: Dict[str, float] = {}
    if clamp_bounds is None:
        clamp_bounds = {}
    # memcpy 写大小 vs 常量分配
    m_mc = re.search(r"\bmemcpy\s*\(\s*" + re.escape(alloc_var) + r"\s*,\s*\w+\s*,\s*(\d+)\s*\)", pseudocode)
    if m_mc and alloc_const is not None:
        sz = int(m_mc.group(1))
        if sz <= alloc_const:
            mass["SAFE"] = mass.get("SAFE", 0.0) + 0.55
        else:
            mass["OVERFLOW"] = mass.get("OVERFLOW", 0.0) + 0.55
    # memcpy 写大小为符号变量, 配合 if-clamp 守卫收敛后比较
    m_mc_sym = re.search(
        r"\bmemcpy\s*\(\s*" + re.escape(alloc_var) + r"\s*,\s*\w+\s*,\s*(\w+)\s*\)",
        pseudocode)
    if m_mc_sym and not m_mc:
        size_var = m_mc_sym.group(1)
        # 分配大小也是符号变量 (malloc(var) 形式)
        if alloc_sym is not None and alloc_sym[0] == size_var:
            # 写长度与分配长度同变量, 天然相容
            mass["SAFE"] = mass.get("SAFE", 0.0) + 0.55
        # 写长度被 if-clamp 钳到上界, 分配大小也用同变量或更小上界
        elif size_var in clamp_bounds:
            clamped = clamp_bounds[size_var]
            if alloc_const is not None and clamped <= alloc_const:
                # 钳制后长度 <= 常量分配 => 相容
                mass["SAFE"] = mass.get("SAFE", 0.0) + 0.55
            elif alloc_sym is not None and alloc_sym[0] == size_var:
                mass["SAFE"] = mass.get("SAFE", 0.0) + 0.55
            else:
                mass["OVERFLOW"] = mass.get("OVERFLOW", 0.0) + 0.55
    # 下标写偏移
    m_idx = re.search(r"\b" + re.escape(alloc_var) + r"\[\s*(\w+)\s*\+\s*(\d+)\s*\]\s*=", pseudocode)
    if m_idx and alloc_sym is not None:
        if m_idx.group(1) == alloc_sym[0]:
            mass["OVERFLOW"] = mass.get("OVERFLOW", 0.0) + 0.55
    # 归纳变量直接下标 + n*mul 分配
    m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
    m_direct = re.search(r"\b" + re.escape(alloc_var) + r"\[\s*(\w+)\s*\]\s*=", pseudocode)
    if m_loop and m_direct and alloc_sym is not None:
        if m_loop.group(2) == alloc_sym[0] and m_direct.group(1) == m_loop.group(1):
            mass["SAFE"] = mass.get("SAFE", 0.0) + 0.55
    if not mass:
        mass["UNKNOWN"] = 0.6
    total = sum(mass.values())
    if total < 1.0:
        mass["UNKNOWN"] = mass.get("UNKNOWN", 0.0) + (1.0 - total)
    return mass


def _evidence_source_a(pseudocode: str, line: str) -> Dict[str, float]:
    """证据源 A: 静态分析证据 (模式匹配构建 mass)."""
    mass: Dict[str, float] = {}
    has_malloc = bool(re.search(r"(?:malloc|calloc|realloc)\s*\(", pseudocode))
    has_write = bool(re.search(r"\[\s*\w+\s*(?:\+\s*\w+)?\s*\]\s*(?:,|=)", line))
    has_guard = bool(re.search(r"if\s*\([^)]*\)", pseudocode))

    # malloc 存在 + 写点存在 => OVERFLOW 倾向
    if has_malloc and has_write:
        mass["OVERFLOW"] = 0.45
    # if 守卫存在 => SAFE 倾向
    if has_guard:
        mass["SAFE"] = mass.get("SAFE", 0.0) + 0.35
    # 无危险特征 => SAFE
    if not has_malloc and not has_write:
        mass["SAFE"] = mass.get("SAFE", 0.0) + 0.6
    # 剩余 mass 分配给 UNKNOWN
    total = sum(mass.values())
    if total < 1.0:
        mass["UNKNOWN"] = 1.0 - total
    return mass


def _evidence_source_b(
    pseudocode: str, line: str, alloc_size: Optional[int]
) -> Dict[str, float]:
    """证据源 B: 结构证据 (写偏移 vs 分配大小, 守卫证伪)."""
    mass: Dict[str, float] = {}

    # 守卫证伪: 写变量出现在 if 条件中被约束
    m_write = re.search(r"\[\s*\w+\s*\+\s*(\w+)\s*\]", line)
    idx_var = m_write.group(1) if m_write else None
    if idx_var and re.search(r"if\s*\(\s*" + re.escape(idx_var) +
                            r"\s*[<>=!]", pseudocode):
        mass["FILTERED"] = 0.4

    # 写偏移已知且 < alloc => SAFE
    if alloc_size is not None and idx_var:
        m_const = re.search(r"\[\s*\w+\s*\+\s*(\d+)\s*\]", line)
        if m_const:
            off = int(m_const.group(1))
            if off < alloc_size:
                mass["SAFE"] = mass.get("SAFE", 0.0) + 0.45
            else:
                mass["OVERFLOW"] = mass.get("OVERFLOW", 0.0) + 0.5

    # 写偏移未知 => UNKNOWN
    if not mass:
        mass["UNKNOWN"] = 0.6

    # 补齐剩余 mass
    total = sum(mass.values())
    if total < 1.0:
        mass["UNKNOWN"] = mass.get("UNKNOWN", 0.0) + (1.0 - total)
    return mass


def _combine(m1: Dict[str, float], m2: Dict[str, float]) -> Dict[str, float]:
    """D-S 组合规则: m12(A) = sum_{B∩C=A} m1(B)m2(C) / (1-K).

    K = sum_{B∩C=空} m1(B)m2(C), 不含 UNKNOWN 交集 (UNKNOWN 与任意相交为该集合).
    """
    # 计算冲突因子 K: 不同非 UNKNOWN 模态的交集为空
    k = 0.0
    for a, va in m1.items():
        for b, vb in m2.items():
            # 非相同且都非 UNKNOWN => 交集为空
            if a != b and a != "UNKNOWN" and b != "UNKNOWN":
                k += va * vb

    if k >= 1.0:
        return {"CONFLICT": 1.0}

    denom = 1.0 - k
    out: Dict[str, float] = {}

    for a, va in m1.items():
        for b, vb in m2.items():
            if a == b:
                # 相同模态交集
                out[a] = out.get(a, 0.0) + va * vb / denom
            elif a == "UNKNOWN":
                # UNKNOWN ∩ B = B, B 的 mass 贡献
                out[b] = out.get(b, 0.0) + va * vb / denom
            elif b == "UNKNOWN":
                # A ∩ UNKNOWN = A, A 的 mass 贡献
                out[a] = out.get(a, 0.0) + va * vb / denom
            # a != b 且都非 UNKNOWN => 交集空, 已计入 K, 不产出

    # 确保有输出
    if not out:
        out["UNKNOWN"] = 1.0
    return out


def run_five_modal_ds_theory(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """双源五模态 D-S 证据组合. 返回 findings."""
    findings: List[dict] = []

    # C 风格优先
    c_alloc = _c_parse_alloc(pseudocode)
    if c_alloc is not None:
        alloc_var, alloc_const, alloc_sym = c_alloc
        # 提取 if-clamp 守卫收敛的变量上界, 供 source_b 做长度-分配相容比较
        clamp_bounds = _c_clamp_bounds(pseudocode)
        source_a = _c_source_a(pseudocode, alloc_var)
        source_b = _c_source_b(
            pseudocode, alloc_var, alloc_const, alloc_sym, clamp_bounds)
        if source_a or source_b:
            combined = _combine(source_a, source_b)
            dom = max(combined, key=combined.get)
            conf = round(combined[dom], 2)
            verdict = "ds_" + dom.lower()
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": conf,
                "description": f"source_a={source_a} source_b={source_b} "
                               f"combined={combined} dominant={dom} mode=c",
                "verdict": verdict,
                "source": "five_modal_ds_theory",
            })
            return findings

    # 汇编风格回退
    # 分配大小
    alloc_size = None
    m_alloc = re.search(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)", pseudocode)
    if m_alloc:
        alloc_size = int(m_alloc.group(1))

    lines = pseudocode.splitlines()
    for ln, line in enumerate(lines, 1):
        m = re.search(r"\[\s*\w+\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue

        # 构建两个独立证据源
        source_a = _evidence_source_a(pseudocode, line)
        source_b = _evidence_source_b(pseudocode, line, alloc_size)

        # D-S 组合
        combined = _combine(source_a, source_b)

        # 主导模态
        dom = max(combined, key=combined.get)
        conf = round(combined[dom], 2)
        verdict = "ds_" + dom.lower()

        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": conf,
            "description": f"line{ln} source_a={source_a} source_b={source_b} "
                           f"combined={combined} dominant={dom} mode=asm",
            "verdict": verdict,
            "source": "five_modal_ds_theory",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 0;
"""
    out = run_five_modal_ds_theory(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])