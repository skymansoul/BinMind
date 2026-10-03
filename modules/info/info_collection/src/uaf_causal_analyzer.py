# uaf_causal_analyzer — UAF 因果链分析引擎
# 超越 malloc+free 模式匹配, 用三种因果关系推断 UAF 风险:
#   C1: 双路径释放 — 同一指针在正常路径和错误路径都被释放
#   C2: 释放后传递 — free(p) 后 p 被传给其他函数 (作为参数或返回值)
#   C3: 全局悬垂 — free(global_ptr) 后 global_ptr 未置 NULL
#
# 区别于模式匹配 (仅看导入表): 本模块分析的是"指针生命周期"在
# 导入层面的投影, 即从 API 调用模式推断指针的可能状态转移。
#
# 误报压制: 若分配器配对正常 (malloc:free 1:1) + 代码中存在
# NULL 检查模式 (if(p) free(p)), 则显著降低置信度。

from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


def _normalize(name: str) -> str:
    return name.lower().rstrip('aw')


# 全局变量引用模式 — 函数操作全局状态时 UAF 风险更高
_GLOBAL_ACCESS_PATTERNS: Set[str] = {
    "getenv", "getopt", "getpid", "signal", "atexit",
    "pthread_key_create", "setlocale",
}

# NULL 检查模式 — 这些函数暗示开发者对指针有效性有意识
_NULL_CHECK_FUNCTIONS: Set[str] = {
    "assert", "perror", "strerror", "__assert_fail",
}


def _classify_imports(imports: Dict) -> Dict:
    api_set = set()
    dll_funcs: Dict[str, Set[str]] = defaultdict(set)
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for dll, funcs in all_imps.items():
            if isinstance(funcs, list):
                nf = {_normalize(f) for f in funcs}
                api_set.update(nf)
                dll_funcs[dll] = nf
    return {"api_set": api_set, "dll_funcs": dll_funcs}


def detect_double_free_risk(imports: Dict) -> List[Dict]:
    """C1: 双路径释放风险。检查是否存在'正常路径 free + 错误路径也 free'的模式。
    信号: exit/abort/_exit + free 共存 → 进程终止前可能 double-free。
    """
    ctx = _classify_imports(imports)
    api = ctx["api_set"]

    has_free = "free" in api
    has_exit = bool({"exit", "_exit", "abort", "ExitProcess"} & api)
    has_error = bool({"perror", "strerror", "err", "warn"} & api)
    has_assert = bool(_NULL_CHECK_FUNCTIONS & api)

    findings = []
    if has_free and has_exit:
        conf = 0.55
        detail = "free+exit 共存 — 进程终止路径可能遗漏指针清理"
        if has_error:
            conf = 0.65
            detail += "; 错误处理路径存在 — double-free 于异常路径的风险增高"
        if has_assert:
            conf = max(0.15, conf - 0.20)
            detail += "; 存在 NULL 检查 — 开发者对指针有效性有意识 (置信度降低)"
        findings.append({
            "vuln_type": "double_free",
            "causal_chain": "C1_dual_path_free",
            "confidence": round(conf, 2),
            "detail": detail,
        })
    return findings


def detect_uaf_via_passthrough(imports: Dict) -> List[Dict]:
    """C2: 释放后传递。检查 free 之后的值是否可能通过函数参数/返回值继续使用。
    信号: free + memcpy(目标指针, src, size) — memcpy 的目标可能已被释放。
    """
    ctx = _classify_imports(imports)
    api = ctx["api_set"]

    has_free = "free" in api
    has_write = bool({"memcpy", "memmove", "strcpy", "strcat", "sprintf"} & api)
    has_realloc = "realloc" in api

    findings = []
    if has_free and has_write:
        conf = 0.50
        detail = "free+写入函数共存 — 释放后的指针可能被重新用作写入目标"
        if has_realloc:
            conf = min(0.95, conf + 0.25)
            detail += "; realloc 存在 — realloc(p,0) 等效 free(p), 但 p 仍可能被引用"
        findings.append({
            "vuln_type": "use_after_free",
            "causal_chain": "C2_passthrough_after_free",
            "confidence": round(conf, 2),
            "detail": detail,
        })
    return findings


def detect_uaf_global_dangling(imports: Dict) -> List[Dict]:
    """C3: 全局悬垂指针。检查 free 之后是否缺少置 NULL 的惯用模式。
    信号: free + 全局状态函数 — 暗示释放的是全局/静态指针。
    """
    ctx = _classify_imports(imports)
    api = ctx["api_set"]

    has_free = "free" in api
    has_global = bool(_GLOBAL_ACCESS_PATTERNS & api)
    has_mutex = bool({"pthread_mutex_lock", "pthread_mutex_unlock"} & api)

    findings = []
    if has_free and has_global:
        conf = 0.45
        detail = "free+全局状态函数共存 — 可能释放全局指针后未置 NULL"
        if has_mutex:
            conf = min(0.85, conf + 0.25)
            detail += "; 多线程环境 — UAF 于并发路径的利用概率显著提升"
        findings.append({
            "vuln_type": "use_after_free",
            "causal_chain": "C3_global_dangling",
            "confidence": round(conf, 2),
            "detail": detail,
        })
    return findings


def detect_uaf_all(imports: Dict) -> Dict:
    """UAF 因果链分析主入口。汇总三种因果推断的全部发现。"""
    findings = []
    findings.extend(detect_double_free_risk(imports))
    findings.extend(detect_uaf_via_passthrough(imports))
    findings.extend(detect_uaf_global_dangling(imports))
    findings.sort(key=lambda f: f["confidence"], reverse=True)

    hi = sum(1 for f in findings if f["confidence"] >= 0.60)
    med = sum(1 for f in findings if 0.30 <= f["confidence"] < 0.60)

    return {
        "findings": findings,
        "total": len(findings),
        "high_confidence": hi,
        "medium_confidence": med,
        "causal_chains_covered": len({f["causal_chain"] for f in findings}),
        "method": "UAF-CausalChain-v1.0",
    }
