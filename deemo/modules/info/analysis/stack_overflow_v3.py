# analysis/stack_overflow_v3 — 栈溢出检测 v3.0: 栈帧建模 + 值范围分析 + canary 交互
# 超越 v1 的纯 buffer-size 比较, 升级为三层分析管线:
#   L1: 栈帧建模 (buffer→saved_RIP 距离) — stack_frame_model
#   L2: 写入值范围分析 (复用 ValueRange 区间推导) — value_range_analyzer
#   L3: canary 绕过风险评估 — canary_bypass_risk
# 理论依据: canary 验证语义; 仅靠 canary 不足以防定向溢出; size 值追踪区分真/假溢出。

from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import re
from value_range_analyzer import ValueRange, extract_value_ranges
from stack_frame_model import (estimate_frame_layout, canary_bypass_risk,
                                compute_frame_overflow_risk)

# 危险栈写函数: 无界写入或大块复制
_UNBOUNDED = {"strcpy", "strcat", "gets", "sprintf", "scanf", "sscanf",
              "vsprintf", "wcscpy", "wcscat", "__imp_strcpy", "__imp_gets",
              "_strcpy", "_gets", "strcpy_s"}
_BOUNDED = {"memcpy", "memmove", "strncpy", "strncat", "snprintf", "read",
            "fread", "fgets", "recv", "_read", "_memcpy", "__imp_memcpy"}
# 栈变量暴露 (泄露 canary/RBP/RIP)
_LEAK_FNS = {"printf", "fprintf", "sprintf", "send", "write", "fwrite",
             "puts", "fputs", "__imp_printf"}

def detect_stack_overflow_v3(code: str, func: str = "", arch: str = "x86_64",
                              checksec: Dict = None) -> List[Dict]:
    """栈溢出 v3.0 主检测入口。

    对每个栈缓冲区+写入函数对, 用值范围分析写入量,
    与栈帧模型中的 buffer→saved_RIP 距离比较判定风险。
    """
    frame = estimate_frame_layout(code, arch)
    ranges = extract_value_ranges(code)
    bypass = canary_bypass_risk(code)
    has_canary = frame.get("_meta", {}).get("canary_present", False)
    findings = []

    writes = _extract_writes_with_size(code)
    for w in writes:
        buf_name = w["buffer"]
        if buf_name not in frame:
            continue  # 不在已知栈缓冲区中
        buf_info = frame[buf_name]

        # L2: 值范围分析 — 写入量
        w_range = _resolve_write_range(w, ranges, code)
        buf_sz = buf_info["size"]
        bytes_to_rip = buf_info.get("bytes_to_saved_rip", 12)
        canary_protected = buf_info.get("canary_protected", False) or has_canary

        # L3: canary 交互判定
        risk = compute_frame_overflow_risk(
            buf_sz, w_range.lo if w_range.lo != float('-inf') else 0,
            w_range.hi, bytes_to_rip, canary_protected, bypass["confidence"])

        if not risk["overflow"]:
            continue

        # 附加: 是否存在信息泄露辅助
        leak_risk = _check_leak_risk(code, buf_name)

        conf = risk["confidence"]
        severity = "Critical" if risk["hits_rip"] else ("High" if risk["hits_canary"] else "Medium")

        # canary 绕过增强 → 提高 severity
        if risk["hits_canary"] and bypass["bypassable"]:
            conf = min(0.95, conf + 0.15)
            if bypass["confidence"] > 0.40:
                severity = "Critical"

        # 信息泄露存在 → 提高置信度 (canary 泄露 → 精确溢出成为可能)
        if leak_risk["has_leak"]:
            conf = min(0.98, conf + 0.10)

        findings.append({
            "type": "stack-overflow", "cwe": "CWE-121",
            "function": func, "buffer": buf_name,
            "buffer_size": buf_sz, "is_vla": buf_info["is_vla"],
            "write_func": w["func"], "write_size_expr": w.get("size_expr", "unbounded"),
            "write_range": str(w_range),
            "bytes_to_saved_rip": bytes_to_rip,
            "hits_rip": risk["hits_rip"],
            "hits_canary": risk["hits_canary"],
            "canary_protected": canary_protected,
            "canary_bypass_risk": bypass,
            "info_leak_risk": leak_risk,
            "severity": severity, "confidence": round(conf, 2),
            "description": risk["reason"],
        })

    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings

def _extract_writes_with_size(code: str) -> List[Dict]:
    """提取所有对栈缓冲区的写入操作, 包括 size 表达式。"""
    writes = []
    # 无界写入: strcpy(buf, src) → unbounded
    for fn in _UNBOUNDED:
        for m in re.finditer(rf'\b{re.escape(fn)}\s*\(\s*(\w+)', code):
            writes.append({"buffer": m.group(1), "func": fn,
                          "size_expr": "unbounded", "pos": m.start()})
    # 有界写入: memcpy(buf, src, N) → 提取 N
    for fn in _BOUNDED:
        for m in re.finditer(rf'\b{re.escape(fn)}\s*\(\s*(\w+)\s*,\s*[^,]+,\s*([^,)]+)\s*\)', code):
            writes.append({"buffer": m.group(1), "func": fn,
                          "size_expr": m.group(2).strip(), "pos": m.start()})
    # 格式化写入: sprintf(buf, fmt, ...) → unbounded
    for m in re.finditer(r'(?:sprintf|vsprintf)\s*\(\s*(\w+)', code):
        writes.append({"buffer": m.group(1), "func": "sprintf",
                      "size_expr": "unbounded", "pos": m.start()})
    return writes

def _resolve_write_range(w: Dict, ranges: Dict[str, ValueRange],
                          code: str) -> ValueRange:
    """将写入 size 表达式解析为 ValueRange。"""
    expr = w.get("size_expr", "unbounded")
    if expr == "unbounded":
        return ValueRange.top()
    try:
        return ValueRange.const(int(expr))
    except ValueError:
        pass
    # 尝试从 ranges 查找
    if expr in ranges:
        return ranges[expr]
    # sizeof(T) 模式
    m = re.match(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
    if m:
        smap = {"char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
                "float": 4, "double": 8, "void*": 4, "size_t": 4}
        return ValueRange.const(smap.get(m.group(1).strip(), 4))
    # VAR * N 模式
    m = re.match(r'(\w+)\s*\*\s*(\w+)', expr)
    if m:
        a = ranges.get(m.group(1), ValueRange.top())
        try:
            b = ValueRange.const(int(m.group(2)))
        except ValueError:
            b = ranges.get(m.group(2), ValueRange.top())
        return a.mul(b)
    return ValueRange.top()

def _check_leak_risk(code: str, buf_name: str) -> Dict:
    """检测是否存在可泄露栈内容的代码模式 (辅助 canary 绕过)。"""
    has_leak = False; methods = []
    for fn in _LEAK_FNS:
        if re.search(rf'{re.escape(fn)}\s*\([^)]*{re.escape(buf_name)}', code):
            has_leak = True; methods.append(fn)
    # 格式化字符串泄露: printf(user_input) 可泄露栈内容
    fmt_leak = re.search(r'printf\s*\(\s*(\w+)\s*\)', code)
    if fmt_leak and fmt_leak.group(1) not in ('"', 'format', 'fmt'):
        has_leak = True; methods.append("format_str_leak")
    return {"has_leak": has_leak, "methods": methods,
            "confidence": min(0.30 * len(methods), 0.90)} if has_leak else \
           {"has_leak": False, "methods": [], "confidence": 0.0}
