# Created: 2025-07-28 17:28:46
#
# bypass_likelihood — 防护机制条件绕过可能性评估
# 超越 checksec 的二元存在/缺失: 估计"已启用但可能被绕过"的概率。
# 对每种保护,基于其他特征推断条件绕过路径 (canary+fmtstr→leak, NX+mprotect→ROP bypass)

from typing import Dict, List, Tuple, Set, Optional


_BYPASS_MODELS = [
    {"protection": "stack_canary", "description": "栈 Canary", "baseline": 0.05,
     "bypass_conditions": [
        ("format_string_vuln", "imports", {"functions": ["printf","fprintf","sprintf","snprintf","dprintf"]}, 0.55),
        ("info_leak_primitive", "imports", {"functions": ["recv","read","fread","fgets","recvfrom"]}, 0.35),
        ("fork_server_pattern", "imports", {"functions": ["fork","accept","select"]}, 0.20),
        ("large_write_primitive", "imports", {"functions": ["memcpy","memmove","read","recv"]}, 0.15)]},
    {"protection": "aslr_pie", "description": "ASLR/PIE", "baseline": 0.03,
     "bypass_conditions": [
        ("info_leak_primitive", "imports", {"functions": ["recv","read","fread","printf","write","send"]}, 0.40),
        ("partial_overwrite_possible", "strings", {"keywords": ["partial","offset","low bits"]}, 0.25),
        ("non_pie_binary", "checksec", {}, 0.50)]},
    {"protection": "nx_dep", "description": "NX/DEP", "baseline": 0.02,
     "bypass_conditions": [
        ("mprotect_available", "imports", {"functions": ["mprotect","VirtualProtect","VirtualAlloc","NtProtectVirtualMemory"]}, 0.45),
        ("rop_gadget_source", "imports", {"functions": ["system","execve","popen","WinExec","CreateProcess"]}, 0.30),
        ("rwx_section_present", "sections", {}, 0.60)]},
    {"protection": "full_relro", "description": "Full RELRO", "baseline": 0.03,
     "bypass_conditions": [
        ("format_string_vuln", "imports", {"functions": ["printf","fprintf","sprintf","snprintf"]}, 0.35),
        ("got_overwrite_alternative", "imports", {"functions": ["dlopen","dlsym","LoadLibrary","GetProcAddress"]}, 0.25),
        ("partial_relro_only", "checksec", {}, 0.40)]},
    {"protection": "cfg_cet", "description": "CFG/CET", "baseline": 0.08,
     "bypass_conditions": [
        ("exception_handler_hijack", "imports", {"functions": ["SetUnhandledExceptionFilter","AddVectoredExceptionHandler"]}, 0.25),
        ("jop_cop_gadgets", "imports", {"functions": ["setjmp","longjmp","swapcontext","setcontext"]}, 0.20)]},
    {"protection": "safeseh", "description": "SafeSEH", "baseline": 0.10,
     "bypass_conditions": [
        ("no_seh_flag", "checksec", {}, 0.30),
        ("exception_overwrite_possible", "imports", {"functions": ["memcpy","strcpy","sprintf","WriteProcessMemory"]}, 0.25)]},
    {"protection": "fortify_source", "description": "FORTIFY_SOURCE", "baseline": 0.05,
     "bypass_conditions": [
        ("unfortified_function_present", "imports", {"functions": ["memcpy","strcpy","sprintf","read","recv"]}, 0.15),
        ("custom_allocator", "imports", {"functions": ["mmap","sbrk","brk","VirtualAlloc"]}, 0.10)]},
]


def _check_import_condition(
    imports: Dict,
    target_functions: Set[str],
) -> bool:
    """检查导入表中是否存在目标函数集合中的任意函数。"""
    _src = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if not isinstance(_src, dict):
        return False
    for _funcs in _src.values():
        if isinstance(_funcs, list):
            for _f in _funcs:
                if _f.lower().rstrip('aw') in target_functions:
                    return True
    # 也检查 dangerous_functions 列表
    for _f in imports.get("dangerous_functions", []):
        if str(_f).lower().rstrip('aw') in target_functions:
            return True
    return False


def _check_string_condition(
    strings: List[str],
    keywords: Set[str],
) -> bool:
    """检查字符串中是否存在任意关键词。"""
    _text = " ".join(
        s[1] if isinstance(s, tuple) else str(s)
        for s in (strings or [])
    ).lower()
    return any(kw.lower() in _text for kw in keywords)


def _check_checksec_condition(
    checksec: Dict,
    condition_name: str,
) -> bool:
    """检查 checksec 条件。"""
    if condition_name == "non_pie_binary":
        return not checksec.get("pie", True)
    if condition_name == "partial_relro_only":
        _relro = str(checksec.get("relro", "")).lower()
        return "partial" in _relro and "full" not in _relro
    if condition_name == "no_seh_flag":
        return not checksec.get("safeseh", True)
    return False


def _check_section_condition(
    sections: List[Dict],
) -> bool:
    """检查是否存在 RWX 段。"""
    for _s in (sections or []):
        if not isinstance(_s, dict):
            continue
        _chars = _s.get("characteristics", [])
        if isinstance(_chars, list):
            if "MEM_WRITE" in _chars and "MEM_EXECUTE" in _chars:
                return True
        _flags = _s.get("flags", 0)
        if isinstance(_flags, int) and (_flags & 0x2) and (_flags & 0x1):
            return True
    return False


def _evaluate_condition(
    cond: Tuple,
    binary_analysis: Dict,
) -> Tuple[bool, float]:
    """评估单个绕过条件。返回 (是否满足, 贡献权重)。"""
    _name, _source, _params, _weight = cond

    if _source == "imports":
        _targets = set(f.lower().rstrip('aw')
                       for f in _params.get("functions", []))
        _met = _check_import_condition(
            binary_analysis.get("imports", {}), _targets)
    elif _source == "strings":
        _keywords = set(_params.get("keywords", []))
        _met = _check_string_condition(
            binary_analysis.get("strings", binary_analysis.get("key_strings", [])),
            _keywords)
    elif _source == "checksec":
        _met = _check_checksec_condition(
            binary_analysis.get("checksec", {}), _name)
    elif _source == "sections":
        _met = _check_section_condition(
            binary_analysis.get("sections", []))
    elif _source == "structural":
        _met = False  # 需要更深的结构分析，此处简化
    else:
        _met = False

    return (_met, _weight if _met else 0.0)


def assess_bypass_likelihood(
    binary_analysis: Dict,
) -> Dict:
    """防护绕过可能性评估主入口。

    binary_analysis: 完整分析结果，至少含 imports/checksec/sections/strings

    返回:
    - protections: 每种防护的绕过评估
    - overall_bypass_score: 综合绕过可能性
    - weak_protections: 绕过可能性 > 0.4 的防护列表
    - effective_protections: 绕过可能性 < 0.15 的防护列表
    - hardening_priority: 加固优先级建议
    """
    _checksec = binary_analysis.get("checksec", {})

    _results = []
    _weak = []
    _effective = []

    for _model in _BYPASS_MODELS:
        _prot_name = _model["protection"]
        _prot_desc = _model["description"]
        _baseline = _model["baseline"]

        # 检查保护是否启用
        _enabled = _check_protection_enabled(_prot_name, _checksec)

        if not _enabled:
            _results.append({
                "protection": _prot_name,
                "description": _prot_desc,
                "enabled": False,
                "bypass_probability": 1.0,
                "status": "NOT_ENABLED",
                "detail": f"{_prot_desc} 未启用 — 无保护",
                "active_bypass_conditions": [],
            })
            _weak.append(_prot_name)
            continue

        # 评估每个绕过条件
        _active_conditions = []
        for _cond in _model["bypass_conditions"]:
            _met, _weight = _evaluate_condition(_cond, binary_analysis)
            if _met:
                _active_conditions.append({
                    "condition": _cond[0], "weight": _weight,
                    "description": _COND_DESCRIPTIONS.get(_cond[0], _cond[0]),
                })

        # logistic 合成: P(bypass) = baseline + contribution from active conditions
        # 使用互补概率: 每个条件独立尝试绕过
        _bypass_prob = _baseline
        for _ac in _active_conditions:
            _w = _ac["weight"]
            _bypass_prob = _bypass_prob + (1.0 - _bypass_prob) * _w

        _bypass_prob = round(min(_bypass_prob, 0.98), 4)

        if _bypass_prob > 0.40:
            _status = "LIKELY_BYPASSABLE"
            _weak.append(_prot_name)
        elif _bypass_prob > 0.15:
            _status = "PARTIALLY_EFFECTIVE"
        else:
            _status = "EFFECTIVE"
            _effective.append(_prot_name)

        _results.append({
            "protection": _prot_name,
            "description": _prot_desc,
            "enabled": True,
            "bypass_probability": _bypass_prob,
            "status": _status,
            "detail": (f"绕过可能性 {_bypass_prob:.1%}: "
                       + ", ".join(a["description"] for a in _active_conditions[:3]))
                       if _active_conditions and _bypass_prob >= 0.10
                       else ("防护有效" if _bypass_prob < 0.10
                             else f"基线绕过可能性 {_bypass_prob:.1%} (无特定条件)"),
            "active_bypass_conditions": _active_conditions,
        })

    _overall = sum(r["bypass_probability"] for r in _results) / max(len(_results), 1)

    # 加固优先级: 绕过可能性高的保护 + 存在被利用条件的 → 优先加固
    _priority = []
    for _r in _results:
        if _r["status"] in ("LIKELY_BYPASSABLE", "NOT_ENABLED"):
            _priority.append({
                "protection": _r["protection"],
                "description": _r["description"],
                "current_bypass_probability": _r["bypass_probability"],
                "recommendation": _BYPASS_RECOMMENDATIONS.get(
                    _r["protection"], "综合加固建议见 OWASP ASVS / CIS Benchmarks"),
            })

    return {
        "protections": _results,
        "overall_bypass_score": round(_overall, 4),
        "overall_assessment": ("HIGH_RISK" if _overall > 0.50 else
                               "MODERATE_RISK" if _overall > 0.30 else
                               "LOW_RISK"),
        "weak_protections": _weak,
        "effective_protections": _effective,
        "hardening_priority": _priority,
    }


def _check_protection_enabled(prot_name: str, checksec: Dict) -> bool:
    _map = {
        "stack_canary": "canary",
        "aslr_pie": "pie",
        "nx_dep": "nx",
        "full_relro": "relro",
        "cfg_cet": "cfg",
        "safeseh": "safeseh",
        "fortify_source": "fortify",
    }
    _key = _map.get(prot_name, "")
    if not _key:
        return True
    _val = checksec.get(_key)
    if _val is None:
        return False
    if isinstance(_val, bool):
        return _val
    if isinstance(_val, str):
        return "none" not in _val.lower()
    return bool(_val)


_COND_DESCRIPTIONS = {
    "format_string_vuln": "格式化字符串函数(可泄露内存)",
    "info_leak_primitive": "信息泄露原语(可读任意内存)",
    "fork_server_pattern": "fork服务器模式(可暴力破解canary)",
    "large_write_primitive": "大块写原语(可连续覆写)",
    "partial_overwrite_possible": "部分覆写(低字节覆盖)",
    "non_pie_binary": "非PIE(地址固定)",
    "mprotect_available": "mprotect/VirtualProtect可用(ROP→可执行内存)",
    "rop_gadget_source": "代码执行汇聚点(ROP跳转目标)",
    "rwx_section_present": "存在静态RWX段",
    "got_overwrite_alternative": "动态符号解析(绕过GOT保护)",
    "partial_relro_only": "仅Partial RELRO",
    "jop_cop_gadgets": "JOP/COP gadget源",
    "exception_handler_hijack": "异常处理函数可劫持",
    "no_seh_flag": "无SEH保护标志",
    "exception_overwrite_possible": "异常处理结构可覆写",
    "unfortified_function_present": "未fortify的函数",
    "custom_allocator": "自定义内存分配器",
}
_BYPASS_RECOMMENDATIONS = {
    "stack_canary": "启用canary+消除格式化字符串漏洞+使用_FORTIFY_SOURCE",
    "aslr_pie": "启用PIE+消除信息泄露+启用HIGHENTROPYVA",
    "nx_dep": "启用NX+消除mprotect/VirtualProtect导入+消除RWX段",
    "full_relro": "启用Full RELRO+消除动态加载依赖",
    "cfg_cet": "启用CFG+CET影子栈+消除异常处理劫持路径",
    "safeseh": "启用SafeSEH+/GS+消除SEH覆写路径",
    "fortify_source": "启用FORTIFY_SOURCE+替换不安全函数为_s变体",
}
