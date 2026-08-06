# Created: 2025-07-28 14:30:00
#
# safety_witness_searcher — 安全性见证的反向搜索引擎
# 不同于查找漏洞证据（危险函数、可疑字符串），本模块查找"此处安全"的见证。
# 安全性见证的存在可以大幅降低检测结果的误报率。
#
# 五类安全性见证:
#   W1: 安全变体共存 — strncpy 与 strcpy 同时存在→开发者有边界检查意识
#   W2: 编译器缓解 — canary+fortify+nx 同时启用→即使有 bug 也难以利用
#   W3: 静态检查插入 — 导入 __stack_chk_fail / __chk_fail → 编译器插入运行时检查
#   W4: 输入验证函数 — 导入 is_valid/validate/sanitize/bounds_check → 数据被净化
#   W5: 分配器配对正常 — malloc:free:realloc 比例在正常范围 → 非 UAF 模式
#   W6: 格式字面量存在 — 代码或数据段中存在显式格式串→格式串是开发者的而非用户的

import math
from typing import Dict, List, Set, Tuple, Optional
from collections import Counter


# 编译器插入的运行时检查函数
_COMPILER_CHECK_FUNCTIONS: Set[str] = {
    "__stack_chk_fail", "__stack_chk_fail_local", "__chk_fail",
    "__memcpy_chk", "__memmove_chk", "__memset_chk",
    "__strcpy_chk", "__strcat_chk", "__sprintf_chk", "__snprintf_chk",
    "__vsprintf_chk", "__vsnprintf_chk", "__read_chk",
    "_stack_chk_guard", "stack_chk_fail",
}


def search_safe_alternatives(api_set: Set[str]) -> Dict:
    """W1: 检查危险函数的安全变体是否共存。
    返回 {dangerous_func: safe_alternative_present}。"""
    pairs = {"strcpy": "strncpy", "strcat": "strncat", "sprintf": "snprintf",
             "gets": "fgets", "memcpy": "memcpy_s", "scanf": "scanf_s"}
    found = {}
    for dang, safe in pairs.items():
        if dang in api_set:
            found[dang] = safe in api_set
    return found


def search_compiler_mitigations(checksec: Dict, api_set: Set[str]) -> Dict:
    """W2+W3: 检查编译器缓解措施和运行时检查插入。"""
    evidence = []

    # W2: 三项核心缓解同时存在 → 强安全见证
    mitigations = 0
    if checksec.get("canary"): mitigations += 1
    if checksec.get("nx") or checksec.get("dep"): mitigations += 1
    if checksec.get("pie") or checksec.get("aslr"): mitigations += 1
    has_fortify = checksec.get("fortify", checksec.get("fortify_source", False))

    if mitigations >= 3 and has_fortify:
        evidence.append({"type": "full_compiler_hardening",
                        "strength": 0.90,
                        "detail": "canary+NX+PIE+FORTIFY 全启用 — 即使有 bug 也难以利用"})
    elif mitigations >= 2:
        evidence.append({"type": "partial_compiler_hardening",
                        "strength": 0.50,
                        "detail": f"{mitigations}/3 核心缓解启用"})

    # W3: 编译器插入的 _chk 函数 → 强安全见证
    chk_hits = _COMPILER_CHECK_FUNCTIONS & api_set
    if chk_hits:
        evidence.append({"type": "compiler_inserted_checks",
                        "strength": round(min(len(chk_hits) * 0.15, 0.80), 2),
                        "detail": f"检测到 {len(chk_hits)} 个编译器插入的检查函数"})

    return {"evidence": evidence, "mitigation_count": mitigations,
            "has_fortify": has_fortify, "chk_function_count": len(chk_hits)}


def search_input_validation(api_set: Set[str]) -> Dict:
    """W4: 检查输入验证函数。"""
    patterns = ["is_valid", "validate", "sanitize", "bounds_check", "verify",
                "assert", "range_check", "length_check", "check_"]
    hits = []
    for pat in patterns:
        for api in api_set:
            if pat in api:
                hits.append(api)
                break
    return {"validation_functions_found": list(set(hits)),
            "validation_count": len(set(hits)),
            "strength": min(len(set(hits)) * 0.15, 0.75)}


def search_allocator_pairing(imports: Dict) -> Dict:
    """W5: 检查分配器配对模式。
    正常二进制的 malloc:free 比率约在 1:0.6 到 1:1.5。
    大量 malloc 无对应 free → 可能是分配器不配对→ UAF 风险增高。
    大量 free 无对应 malloc → double-free 风险。"""
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(f.lower().rstrip('aw') for f in funcs)

    has_malloc = "malloc" in api_set or "calloc" in api_set
    has_free = "free" in api_set
    has_realloc = "realloc" in api_set

    if not has_malloc and not has_free:
        return {"pattern": "no_allocator_imports", "uaf_risk": 0.0,
                "detail": "无显式堆分配导入 — 可能使用自定义分配器或仅栈操作"}

    # 分配/释放配对评分
    if has_malloc and has_free:
        pattern = "balanced" if has_realloc else "basic_pair"
        uaf_risk = 0.15 if has_realloc else 0.25
    elif has_malloc and not has_free:
        pattern = "allocate_only"
        uaf_risk = 0.10
    elif not has_malloc and has_free:
        pattern = "free_only"
        uaf_risk = 0.60
    else:
        pattern = "none"
        uaf_risk = 0.0

    return {"pattern": pattern, "uaf_risk": round(uaf_risk, 2),
            "has_malloc": has_malloc, "has_free": has_free,
            "has_realloc": has_realloc,
            "detail": f"分配模式: {pattern} (UAF 基础风险={uaf_risk:.2f})"}


def search_format_literals(strings: List[str]) -> Dict:
    """W6: 检查字符串中是否存在显式格式字面量。
    如果二进制字符串中含有 "%s %d %x" 之类的格式串，
    说明格式化是开发者控制的而非用户输入，降低格式串漏洞风险。"""
    if not strings:
        return {"format_literals_found": 0, "strength": 0.0}

    # 格式串模式: %[flags][width][.precision][length]specifier
    import re
    fmt_pat = re.compile(r'%[-\+0 #]*\d*\.?\d*[hlLqjzt]*[diouxXeEfFgGaAcspn%]')

    text = " ".join(s[1] if isinstance(s, tuple) else str(s) for s in strings)
    matches = fmt_pat.findall(text)
    unique = len(set(matches))

    # 排除单个 %% 的情况 (转义百分号)
    genuine = sum(1 for m in matches if m != "%%")

    strength = min(genuine * 0.08, 0.60) if genuine > 0 else 0.0
    return {"format_literals_found": genuine,
            "unique_patterns": unique,
            "strength": round(strength, 2),
            "detail": (f"发现 {genuine} 个显式格式字面量 → 格式串可能是开发者控制的"
                       if genuine > 0 else "未发现格式字面量 → 格式串可能来自外部输入")}


def aggregate_safety_score(witness_results: Dict) -> Tuple[float, List[str]]:
    """汇总所有安全性见证，给出 0-1 的综合安全性评分。
    高分=更可能是安全的（降低检测置信度），低分=缺乏安全见证（提高检测置信度）。"""
    score = 0.0
    reasons = []

    # W1: 安全变体
    safe_alt = witness_results.get("safe_alternatives", {})
    if safe_alt:
        safe_count = sum(1 for v in safe_alt.values() if v)
        if safe_count > 0:
            score += min(safe_count * 0.10, 0.30)
            reasons.append(f"{safe_count} 个安全变体共存")

    # W2+W3: 编译器缓解
    compiler = witness_results.get("compiler_mitigations", {})
    for ev in compiler.get("evidence", []):
        score += ev.get("strength", 0.0) * 0.30
        reasons.append(ev.get("detail", ""))

    # W4: 输入验证
    validation = witness_results.get("input_validation", {})
    val_strength = validation.get("strength", 0.0)
    if val_strength > 0:
        score += val_strength * 0.20
        reasons.append(f"{validation.get('validation_count', 0)} 个输入验证函数")

    # W5: 分配器配对
    alloc = witness_results.get("allocator_pairing", {})
    uaf_risk = alloc.get("uaf_risk", 0.0)
    score += (1.0 - uaf_risk) * 0.10
    if uaf_risk < 0.20:
        reasons.append("分配器配对正常")

    # W6: 格式字面量
    fmt_lit = witness_results.get("format_literals", {})
    fmt_strength = fmt_lit.get("strength", 0.0)
    if fmt_strength > 0:
        score += fmt_strength * 0.15
        reasons.append(fmt_lit.get("detail", ""))

    return (round(min(score, 0.95), 4), reasons)


def run_full_witness_search(
    api_set: Set[str],
    imports: Dict,
    checksec: Dict,
    strings: List[str],
) -> Dict:
    """执行全部六类安全性见证搜索，返回聚合结果。"""
    results = {
        "safe_alternatives": search_safe_alternatives(api_set),
        "compiler_mitigations": search_compiler_mitigations(checksec or {}, api_set),
        "input_validation": search_input_validation(api_set),
        "allocator_pairing": search_allocator_pairing(imports),
        "format_literals": search_format_literals(strings),
    }
    score, reasons = aggregate_safety_score(results)
    results["aggregate_safety_score"] = score
    results["safety_reasons"] = reasons
    return results
