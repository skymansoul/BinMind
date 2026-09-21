"""FourVerdictScale - 四级判定标尺 (stage 98).

CONFIRMED/LIKELY/UNCERTAIN/FILTERED 四级判定, 用概率量化分级:
  0.85-1.0  CONFIRMED   有分配边界且写侧完全解析
  0.6-0.85  LIKELY      写侧部分解析/守卫不完整
  0.3-0.6   UNCERTAIN   信息不足
  <0.3      FILTERED    疑似但被过滤证据降级
与 four_level_adjudicator 区分: 本模块是证据四档刻度尺——消费其他
模块 findings 做后置四维打分; four_level 是四级链逐级 gate 裁决.

设计决策:
  - 消费型打分: 第 3 参收 findings 时按 type/severity/confidence/
    evidence 长度四维打分映射四档
  - 降级轻量审计: 第 3 参为 None 时只统计伪代码 alloc/write/guard
    计数映射四档, 不做逐点特征解析 (与 four_level 的特征正则解耦)
  - FILTERED 特指: 有溢出嫌疑但守卫证伪 (取反路径)
"""

import re
from typing import List, Optional

# 旧 C 风格逐点特征解析分支默认关闭: 特征正则与 four_level 同源,
# 职责解耦后保留函数体供历史参考
_DEPRECATED_C_POINTWISE = False


def _score(line: str, pseudocode: str) -> float:
    """证据加权概率 [0,1]."""
    score = 0.0
    if re.search(r"\b(?:malloc|calloc|realloc)\s*\(", pseudocode):
        score += 0.35
    if re.search(r"\[\s*\w+\s*(\+\s*\d+)?\]", line):
        score += 0.25
    if re.search(r"\bif\s*\([^)]*\)", pseudocode):
        score += 0.30
    return min(score, 1.0)


def _filtered(line: str, pseudocode: str) -> bool:
    """是否有守卫过滤 (if 内含写点变量)."""
    m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
    if not m:
        return False
    var = m.group(1)
    return bool(re.search(r"if\s*\([^)]*" + re.escape(var), pseudocode))


def _grade(p: float, filtered: bool) -> str:
    if filtered and p < 0.6:
        return "FILTERED"
    if p >= 0.85:
        return "CONFIRMED"
    if p >= 0.6:
        return "LIKELY"
    return "UNCERTAIN"


def _consume_score(f: dict) -> float:
    """消费型四维打分: 按 type/severity/confidence/evidence 长度.

    这是本模块的核心刻度尺: 输入是其他模块已产出的 finding,
    输出是该 finding 在四档刻度上的落点概率.
    """
    score = 0.0
    # 维度一: 类型可信度 (heap/uaf 类高危类型权重高)
    ftype = str(f.get("type", ""))
    if ftype in ("heap_overflow", "use_after_free", "format_string"):
        score += 0.3
    elif ftype:
        score += 0.1
    # 维度二: severity 等级
    sev = str(f.get("severity", "")).lower()
    if sev == "high":
        score += 0.25
    elif sev == "medium":
        score += 0.15
    elif sev == "low":
        score += 0.05
    # 维度三: 原始置信度直传
    try:
        conf = float(f.get("confidence", 0))
    except (TypeError, ValueError):
        conf = 0.0
    score += max(0.0, min(1.0, conf)) * 0.3
    # 维度四: evidence 信息量 (每 20 字符 0.05, 封顶 0.15)
    ev = f.get("evidence") or f.get("description") or ""
    score += min(0.15, len(str(ev)) // 20 * 0.05)
    return min(score, 1.0)


def _light_audit(pseudocode: str) -> float:
    """轻量审计概率: 只统计 alloc/write/guard 三类计数映射 [0,1].

    降级路径专用 (第 3 参为 None 时), 与 four_level 的逐点特征
    正则解析完全解耦, 只做全局计数.
    """
    score = 0.0
    if re.search(r"\b(?:malloc|calloc|realloc)\s*\(", pseudocode):
        score += 0.35
    if re.search(r"\bmemcpy\s*\(|\w+\s*\[[^\]]+\]\s*=", pseudocode):
        score += 0.25
    # 守卫证伪: if 约束了 memcpy 大小或下标变量 -> FILTERED 方向
    if re.search(r"\bif\s*\([^)]*\)", pseudocode):
        score += 0.30
    return min(score, 1.0)


def _light_is_filtered(pseudocode: str) -> bool:
    """轻量守卫证伪: 函数级全局检查, 不做逐点解析.

    三条规则 (均与 four_level 的逐点特征正则解耦):
    1. memcpy 常量大小 <= malloc 常量大小 -> 写量在分配内
    2. memcpy 大小为标识符且出现在 if 条件内 -> 守卫钳制写量
    3. 下标写为纯归纳变量且 for 循环上界存在 -> 写点有界
    带 stride 的下标 (i*8) 不在此列: 轻量路径无法核实分配乘数,
    误判会压真, 宁可不下 FILTERED.
    """
    # 规则 1: memcpy 常量 vs malloc 常量
    m_alloc = re.search(r"malloc\s*\(\s*(\d+)\s*\)", pseudocode)
    memcpy_sizes = re.findall(r"memcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*\)", pseudocode)
    if m_alloc and memcpy_sizes and all(s.isdigit() for s in memcpy_sizes):
        alloc_const = int(m_alloc.group(1))
        if all(int(s) <= alloc_const for s in memcpy_sizes):
            return True
    # 规则 2: memcpy 大小标识符被 if 守卫钳制
    for s in memcpy_sizes:
        if not s.isdigit() and re.search(r"if\s*\([^)]*\b" + re.escape(s) + r"\b", pseudocode):
            return True
    # 规则 3: 纯归纳变量下标且 for 上界为分配变量
    # 上界必须与 malloc 参数变量一致 (malloc(n)+for(i<n) 才有界;
    # malloc(m)+for(i<n) 上界与分配无关, 误判会压真)
    m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
    if m_loop:
        loop_var, bound_var = m_loop.group(1), m_loop.group(2)
        m_alloc_sym = re.search(r"malloc\s*\(\s*(\w+)\s*(?:\*\s*\d+\s*)?\)", pseudocode)
        alloc_var_of_bound = m_alloc_sym.group(1) if m_alloc_sym else None
        if alloc_var_of_bound == bound_var and re.search(
            re.escape(loop_var) + r"\s*\]\s*=", pseudocode
        ):
            return True
    return False


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


def _c_write_entries(pseudocode: str, alloc_var: str) -> list:
    """收集 C 风格写操作: (行号, 行内容, 偏移表达式, memcpy大小或None)."""
    entries = []
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_mc = re.search(r"\bmemcpy\s*\(\s*" + re.escape(alloc_var) + r"\s*,\s*\w+\s*,\s*(\w+)\s*\)", line)
        if m_mc:
            sz = m_mc.group(1)
            entries.append((ln, line, None, int(sz) if sz.isdigit() else None))
            continue
        m_idx = re.search(r"\b" + re.escape(alloc_var) + r"\[([^\]]+)\]\s*=", line)
        if m_idx:
            entries.append((ln, line, m_idx.group(1).strip(), None))
    return entries


def _c_score(ln, line, pseudocode, alloc_var, alloc_const, alloc_sym, idx_expr, write_size):
    """C 风格概率评分 [0,1]."""
    score = 0.0
    # 分配存在
    score += 0.35
    # 写点存在
    score += 0.25
    # 写大小 vs 常量分配: 超出 -> 高概率溢出
    if write_size is not None and alloc_const is not None:
        if write_size > alloc_const:
            score += 0.30
    # 偏移 n+const vs 符号分配: 超界 -> 高概率溢出
    elif idx_expr is not None and alloc_sym is not None:
        m_add = re.match(r"(\w+)\s*\+\s*(\d+)$", idx_expr)
        if m_add and m_add.group(1) == alloc_sym[0]:
            score += 0.30
    return min(score, 1.0)


def _c_grade(p: float, filtered: bool) -> str:
    """C 风格分级: 守卫证伪优先 FILTERED, 否则按概率."""
    if filtered:
        return "FILTERED"
    if p >= 0.85:
        return "CONFIRMED"
    if p >= 0.6:
        return "LIKELY"
    return "UNCERTAIN"


def _c_is_filtered(pseudocode, idx_expr, alloc_const, alloc_sym, write_size):
    """C 风格守卫证伪: 写大小在分配内或归纳变量有界 -> FILTERED."""
    # memcpy 写大小精确匹配分配
    if write_size is not None and alloc_const is not None:
        return write_size <= alloc_const
    # 归纳变量直接下标且分配为 n*mul
    if idx_expr is not None and alloc_sym is not None:
        m_loop = re.search(r"for\s*\(\s*(\w+)\s*=\s*\d+\s*;\s*\1\s*<\s*(\w+)\s*;", pseudocode)
        if m_loop and m_loop.group(2) == alloc_sym[0]:
            if re.fullmatch(re.escape(m_loop.group(1)), idx_expr):
                return True
            m_mul = re.match(re.escape(m_loop.group(1)) + r"\s*\*\s*(\d+)$", idx_expr)
            if m_mul and alloc_sym[1] >= int(m_mul.group(1)):
                return True
    return False


def run_four_verdict_scale(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """四级判定标尺. 返回 findings."""
    findings: List[dict] = []
    # 消费型路径: 第 3 参有 findings -> 后置四维打分, 逐条标档
    if existing_findings:
        for f in existing_findings:
            p = _consume_score(f)
            verdict = _grade(p, False)
            findings.append({
                "type": f.get("type", "heap_overflow"),
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": round(p, 2),
                "description": (
                    f"var=None prob={p:.2f} verdict={verdict} "
                    f"mode=consume src_type={f.get('type', '?')}"
                ),
                "verdict": verdict,
                "source": "four_verdict_scale",
            })
        return findings
    # 降级轻量审计路径: 第 3 参为 None -> 只做全局计数映射四档,
    # 不做逐点特征解析 (与 four_level 的特征解析职责解耦)
    light_p = _light_audit(pseudocode)
    light_filtered = _light_is_filtered(pseudocode)
    # 阈值 0.25: 有写点或分配证据即落尺; 纯格式串/纯 free 无写量证据不落尺
    if light_p >= 0.25:
        # 轻量分级: 守卫证伪优先 FILTERED (与旧 _c_grade 同语义),
        # 概率只决定非证伪场景落 CONFIRMED/LIKELY/UNCERTAIN
        if light_filtered:
            verdict = "FILTERED"
        elif light_p >= 0.85:
            verdict = "CONFIRMED"
        elif light_p >= 0.6:
            verdict = "LIKELY"
        else:
            verdict = "UNCERTAIN"
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": round(light_p, 2),
            "description": (
                f"var=None prob={light_p:.2f} verdict={verdict} "
                f"mode=light alloc_write_guard_count"
            ),
            "verdict": verdict,
            "source": "four_verdict_scale",
        })
        return findings
    # #[DEPRECATED] C 风格逐点特征解析分支: 特征正则与
    # four_level_adjudicator 同源, 职责已解耦, 保留函数体供历史参考;
    # 默认关闭不产出
    if _DEPRECATED_C_POINTWISE:
        c_alloc = _c_parse_alloc(pseudocode)
        if c_alloc is not None:
            alloc_var, alloc_const, alloc_sym = c_alloc
            c_writes = _c_write_entries(pseudocode, alloc_var)
            if c_writes:
                for ln, line, idx_expr, write_size in c_writes:
                    p = _c_score(ln, line, pseudocode, alloc_var, alloc_const, alloc_sym, idx_expr, write_size)
                    filtered = _c_is_filtered(pseudocode, idx_expr, alloc_const, alloc_sym, write_size)
                    verdict = _c_grade(p, filtered)
                    findings.append({
                        "type": "heap_overflow",
                        "function": func_name or "unknown",
                        "severity": "medium",
                        "cwe": "CWE-122",
                        "confidence": round(p, 2),
                        "description": f"line{ln} var={alloc_var} prob={p:.2f} "
                                       f"verdict={verdict} mode=c",
                        "verdict": verdict,
                        "source": "four_verdict_scale",
                    })
                return findings
        # 汇编风格回退
        for ln, line in enumerate(pseudocode.splitlines(), 1):
            m = re.search(r"\[\s*(\w+)\s*(\+\s*\w+|\+\s*\d+)?\]\s*(?:,|=)", line)
            if not m:
                continue
            p = _score(line, pseudocode)
            verdict = _grade(p, _filtered(line, pseudocode))
            findings.append({
                "type": "heap_overflow",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-122",
                "confidence": round(p, 2),
                "description": f"line{ln} var={m.group(1)} prob={p:.2f} "
                               f"verdict={verdict} mode=asm",
                "verdict": verdict,
                "source": "four_verdict_scale",
            })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (idx < 64) { mov [p+idx], 0; }
"""
    out = run_four_verdict_scale(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])