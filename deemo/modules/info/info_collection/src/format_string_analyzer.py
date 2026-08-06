# format_string_analyzer — 数据流感知的格式化字符串漏洞分析
# 超越 "printf 存在+%n 检测" 的模式匹配, 增加三层精化:
#   L1: 格式函数识别+参数计数推断 (format 参数消耗几个栈槽)
#   L2: 格式串来源推断 (常量段 vs 栈变量 vs 堆变量 vs 外部输入)
#   L3: NULL-字节攻击面分析 (%s 在无NULL 内存区读取超长字符串)
#
# 误报压制: 若 snprintf 族安全变体存在且格式串来自常量段→安全, 压制置信度

from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


def _normalize(name: str) -> str:
    return name.lower().rstrip('aw')


# 格式函数元数据: (参数位置0=格式串, 该格式串消耗的最大栈槽数)
_FORMAT_FUNC_PROFILE: Dict[str, Tuple[int, int]] = {
    "printf": (0, 10), "fprintf": (1, 10), "sprintf": (1, 10),
    "snprintf": (2, 8), "dprintf": (1, 10),
    "vprintf": (0, 10), "vfprintf": (1, 10), "vsprintf": (1, 10),
    "vsnprintf": (2, 8), "syslog": (1, 8),
    "err": (1, 5), "warn": (1, 5), "errx": (1, 5), "warnx": (1, 5),
    "scanf": (0, 15), "fscanf": (1, 15), "sscanf": (1, 15),
}

# 安全变体: 危险函数 → 安全替代 (限制输出长度或显式格式)
_SAFE_FORMAT_ALTERNATIVES = {
    "sprintf": "snprintf", "vsprintf": "vsnprintf",
    "printf": "fprintf", "scanf": "fgets",
}


def _format_string_provenance(
    func_name: str,
    strings: List[str],
    api_set: Set[str],
) -> str:
    """推断格式串来源: constant_segment / stack_variable / heap_variable / external_input。"""
    text = " ".join(s[1] if isinstance(s, tuple) else str(s) for s in (strings or []))

    # 外部输入: 如果同时存在 recv/read/fgets 和格式函数 → 格式串可能来自外部
    has_input = bool({"recv", "read", "fgets", "gets", "scanf"} & api_set)
    # 常量段: 字符串中存在 %s %d 等格式控制符
    has_fmt_literal = any(p in text for p in ["%s", "%d", "%x", "%p", "%n"])

    if has_input and not has_fmt_literal:
        return "external_input"
    if has_fmt_literal:
        return "constant_segment"
    return "unknown"


def _count_variadic_args(format_string_hints: List[str]) -> int:
    """从字符串中间接估计格式函数可能消耗的变参数量。
    实际需要反汇编确定, 此处从字符串模式做保守下界估计。
    """
    count = 0
    for s in (format_string_hints or []):
        t = s[1] if isinstance(s, tuple) else str(s)
        # 统计格式控制符 (排除 %%)
        import re
        specs = re.findall(r'%(?!%)[+\-0 #]*\d*\.?\d*[hlLqjzt]*[diouxXeEfFgGaAcspn]', t)
        count += len(specs)
    return count


def analyze_format_string_vulnerabilities(
    imports: Dict,
    strings: List[str] = None,
    checksec: Dict = None,
) -> Dict:
    """数据流感知的格式化字符串漏洞分析主入口。"""
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(_normalize(f) for f in funcs)

    findings = []
    has_safe_alt = False

    for func, (fmt_pos, max_args) in _FORMAT_FUNC_PROFILE.items():
        if func not in api_set:
            continue

        # 检查安全变体
        safe = _SAFE_FORMAT_ALTERNATIVES.get(func)
        if safe and safe in api_set:
            has_safe_alt = True

        # L1: 格式参数位置
        fmt_at_zero = (fmt_pos == 0)
        provenance = _format_string_provenance(func, strings or [], api_set)

        # L2: 来源判定
        if provenance == "external_input" and fmt_at_zero:
            conf = 0.85
            risk = "HIGH"
            detail = f"{func} 格式串为外部输入且位于参数位置0 — 直接可控"
        elif provenance == "external_input":
            conf = 0.65
            risk = "MEDIUM"
            detail = f"{func} 格式串可能来自外部输入(位置{fmt_pos})"
        elif provenance == "unknown" and fmt_at_zero:
            conf = 0.40
            risk = "MEDIUM"
            detail = f"{func} 格式串来源未知但位于参数位置0"
        else:
            conf = 0.18
            risk = "LOW"
            detail = f"{func} 格式串来自常量段 — 低风险"

        # L3: NULL-byte 利用面 — %s 在无 NULL 终止的内存区可无限读取
        strings_text = " ".join(s[1] if isinstance(s, tuple) else str(s) for s in (strings or []))
        if "%s" in strings_text and provenance != "constant_segment":
            conf = min(0.95, conf + 0.15)
            risk = "HIGH"
            detail += "; %s 在非常量内存区 — NULL-byte 注入风险"

        # L4: 变参栈溢出 — 格式串中 %x/%s 数量超过函数预期参数数→越界读栈
        import re
        spec_count = len(re.findall(r'%(?!%)[+\-0 #]*\d*\.?\d*[hlLqjzt]*[diouxXeEfFgGaAcspn]', strings_text))
        if spec_count > max_args:
            conf = min(0.95, conf + 0.12)
            risk = "HIGH" if risk != "HIGH" else risk
            detail += f"; 变参溢出风险 — {spec_count} 个格式控制符超出函数预期的最大 {max_args} 个参数"

        # Fortify 缓解
        if checksec and checksec.get("fortify", checksec.get("fortify_source", False)):
            conf = max(0.05, conf - 0.30)
            detail += " (FORTIFY_SOURCE 启用 — 部分缓解)"

        findings.append({
            "vuln_type": "format_string",
            "function": func,
            "format_arg_position": fmt_pos,
            "format_provenance": provenance,
            "max_variadic_args": max_args,
            "risk": risk,
            "confidence": round(conf, 2),
            "detail": detail,
            "has_safe_alternative": has_safe_alt,
        })

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    return {
        "findings": findings,
        "total": len(findings),
        "high_risk": [f for f in findings if f["risk"] == "HIGH"],
        "safe_alternatives_detected": has_safe_alt,
        "method": "FormatString-DataFlow-v1.0",
    }
