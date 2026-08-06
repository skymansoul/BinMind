# stack_overflow_analyzer — 栈溢出深度分析引擎
# 超越"gets/strcpy 存在→栈溢出"的模式匹配, 做三层精化:
#   L1: 危险函数识别 + 典型栈缓冲区大小推断 (从字符串常量估计)
#   L2: 调用约定感知的参数溢出分析 (system V x86-64 的栈帧结构)
#   L3: canary 交互效应 — 有 canary 时栈溢出利用需要先泄露 canary,
#       若同时存在格式化串或信息泄露→canary 可被绕过→风险升高
#
# 核心创新: L3 的 canary 交互效应建模——传统工具只报告"有 canary=安全",
# 但实际在有信息泄露原语的二进制中, canary 可被绕过。本模块量化此风险。

from typing import Dict, List, Set, Tuple, Optional


_STACK_DANGER_FUNCS = {
    "gets": 0.95, "strcpy": 0.65, "strcat": 0.60,
    "sprintf": 0.70, "vsprintf": 0.65, "scanf": 0.60, "sscanf": 0.45,
    "alloca": 0.30, "getenv": 0.20,
    "CreateProcessA": 0.25, "WinExec": 0.25, "lstrcpyA": 0.65,
}

# 栈缓冲区大小推测: 从字符串中的数字常量推断
_TYPICAL_STACK_BUFFER_SIZES = {32, 64, 128, 256, 512, 1024, 2048, 4096}

# 信息泄露原语 (可泄露 canary 值)
_INFO_LEAK_FUNCS: Set[str] = {"printf", "fprintf", "write", "send", "puts", "fwrite",
                               "recv", "read", "fgets"}

# 格式控制字符 (暗示存在格式化串)
_FORMAT_CHARS: Set[str] = {"%s", "%d", "%x", "%p", "%n", "%lx"}


def _normalize(name: str) -> str:
    return name.lower().rstrip('aw')


def _estimate_min_buffer_size(strings: List[str]) -> int:
    """从字符串常量推断最小的栈缓冲区大小。"""
    sizes = set()
    for s in (strings or []):
        t = s[1] if isinstance(s, tuple) else str(s)
        t = t.strip()
        try:
            v = int(t)
            if v in _TYPICAL_STACK_BUFFER_SIZES:
                sizes.add(v)
        except ValueError:
            pass
    return min(sizes) if sizes else 0


def _has_format_leak(strings: List[str]) -> bool:
    """检查是否存在格式控制字符(暗示格式化串或printf调试)。"""
    text = " ".join(s[1] if isinstance(s, tuple) else str(s) for s in (strings or []))
    return any(fc in text for fc in _FORMAT_CHARS)


def _has_info_leak_primitive(api_set: Set[str]) -> bool:
    """检查是否存在信息泄露原语。"""
    return bool(api_set & _INFO_LEAK_FUNCS)


def analyze_stack_overflow(
    imports: Dict,
    strings: List[str] = None,
    checksec: Dict = None,
    arch: str = "x86_64",
) -> Dict:
    api_set = set()
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if isinstance(all_imps, dict):
        for funcs in all_imps.values():
            if isinstance(funcs, list):
                api_set.update(_normalize(f) for f in funcs)

    has_canary = (checksec or {}).get("canary", False)
    min_buf = _estimate_min_buffer_size(strings or [])
    has_fmt_leak = _has_format_leak(strings or [])
    has_info_leak = _has_info_leak_primitive(api_set)

    findings = []

    for func, base_conf in sorted(_STACK_DANGER_FUNCS.items(), key=lambda x: x[1], reverse=True):
        if func not in api_set:
            continue

        conf = base_conf
        risk = "LOW"

        # L1: 危险函数 + 缓冲区大小推断
        detail = f"{func} 无栈边界检查"
        if min_buf > 0:
            # 若缓冲区 < 512B 且函数是 gets(无限读取)→高风险
            if min_buf < 512 and func == "gets":
                conf = min(1.0, conf + 0.15)
                detail += f" (推测缓冲区仅{min_buf}B, gets可无限写入)"
            if min_buf < 256 and func in ("strcpy", "strcat"):
                conf = min(1.0, conf + 0.10)
                detail += f" (推测缓冲区{min_buf}B, 小于典型输入)"

        # L2: 调用约定感知 — x86-64 栈帧有128B红区
        if "x86" in arch and func in ("gets", "strcpy"):
            conf = min(1.0, conf + 0.05)
            detail += " (x86 cdecl无寄存器保护, 返回地址紧邻栈缓冲区)"

        # L3: canary 交互效应 — 核心创新点
        if has_canary:
            if has_fmt_leak or has_info_leak:
                # canary 存在但可能被泄露→保护被削弱
                conf = min(0.95, conf * 0.85 + 0.15)
                risk = "MEDIUM"
                detail += " — canary 存在但存在信息泄露原语(canary 可被绕过)"
            else:
                # canary 有效→降低风险
                conf = max(0.08, conf * 0.40)
                risk = "LOW"
                detail += " — canary 有效保护(无已知泄露路径)"
            detail += f" [canary_present]"
        else:
            if conf > 0.70: risk = "HIGH"
            elif conf > 0.50: risk = "MEDIUM"
            detail += " [no_canary]"

        findings.append({
            "vuln_type": "stack_overflow",
            "function": func,
            "confidence": round(conf, 2),
            "risk": risk,
            "detail": detail,
            "canary_bypass_possible": has_canary and (has_fmt_leak or has_info_leak),
            "min_buffer_estimate": min_buf,
        })

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    hi = sum(1 for f in findings if f["confidence"] >= 0.60)
    canary_bypass = [f for f in findings if f["canary_bypass_possible"]]

    return {
        "findings": findings,
        "total": len(findings),
        "high_confidence": hi,
        "canary_bypass_risks": canary_bypass,
        "canary_effective": has_canary and not (has_fmt_leak or has_info_leak),
        "method": "StackOverflow-CanaryInteraction-v1.0",
    }
