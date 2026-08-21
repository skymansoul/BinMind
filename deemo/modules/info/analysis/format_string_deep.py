# analysis/format_string_deep.py — 格式化字符串深化检测
# v3 已有污点传播+调用链分析, 本模块补充三个v3缺失的维度:
#
#   维度1: 位置参数追踪 — %n$s / %2$d 等POSIX位置参数,
#          攻击者可跳过参数实现信息泄露 (如 %7$p 读取栈上第7个参数)
#   维度2: 变参计数不匹配 — printf("%s %d", a) 缺少一个参数
#   维度3: 动态宽度字段 — %*s 从参数栈读取宽度
#
#

from __future__ import annotations
import re
from typing import Dict, List, Tuple, Set, Optional
from .format_parser_utils import (
    parse_format_specifiers, split_args, is_string_variable,
)

# printf-family 函数 — 格式字符串参数的位置 (0-indexed)
# printf(fmt, ...):           fmt 在 args[0]
# fprintf(stream, fmt, ...):  fmt 在 args[1]
# sprintf(buf, fmt, ...):     fmt 在 args[1]
_PRINTF_FUNCTIONS = {
    "printf": 0, "fprintf": 1, "dprintf": 1,
    "sprintf": 1, "snprintf": 2, "asprintf": 0,
    "syslog": 0, "vsyslog": 1,
    "err": 0, "warn": 0, "errx": 0, "warnx": 0,
    "__printf_chk": 0, "__fprintf_chk": 1,
    "__sprintf_chk": 1, "__snprintf_chk": 2,
}

def detect_positional_param_abuse(code: str, func: str = "") -> List[Dict]:
    """检测位置参数滥用: %7$p / %7$x 等跳过参数从栈上读取。"""
    findings = []

    for fname, fmt_arg_idx in _PRINTF_FUNCTIONS.items():
        for m in re.finditer(
            rf'{fname}\s*\(\s*((?:[^()]*|\([^()]*\))*)\s*\)', code):
            args_str = m.group(1)
            args = split_args(args_str)
            if len(args) <= fmt_arg_idx:
                continue
            fmt_arg = args[fmt_arg_idx]

            specifiers = parse_format_specifiers(fmt_arg)
            positional = [s for s in specifiers if s["position"] is not None]
            if not positional:
                continue

            max_pos = max(s["position"] for s in positional)
            actual_varargs = len(args) - fmt_arg_idx - 1

            # 位置参数号超过实际参数数量 → 信息泄露
            if max_pos > actual_varargs:
                findings.append({
                    "type": "format-string",
                    "subtype": "positional_param_oob",
                    "function": func, "call": f"{fname}(...)",
                    "max_positional_arg": max_pos,
                    "actual_varargs": actual_varargs,
                    "severity": "High", "cwe": "CWE-134",
                    "confidence": 0.92,
                    "description": (
                        f"位置参数越界: %{max_pos}$ 引用参数超出实际变参"
                        f"({actual_varargs})→栈信息泄露"
                    ),
                })

            # 位置参数跳跃: %1$s 和 %5$d 之间跳过了2,3,4
            if len(positional) >= 2 and actual_varargs > 0:
                positions = sorted(s["position"] for s in positional)
                gaps = []
                for i in range(len(positions) - 1):
                    if positions[i + 1] - positions[i] > 2:
                        gaps.append((positions[i], positions[i + 1]))
                if gaps:
                    findings.append({
                        "type": "format-string",
                        "subtype": "positional_param_gap",
                        "function": func, "call": f"{fname}(...)",
                        "gaps": [f"{a}→{b}" for a, b in gaps],
                        "severity": "Medium", "cwe": "CWE-134",
                        "confidence": 0.65,
                        "description": (
                            f"位置参数跳跃: 未使用位置 {gaps[0][0]+1}-"
                            f"{gaps[0][1]-1}→信息泄露探测"
                        ),
                    })

    return findings

def detect_vararg_count_mismatch(code: str, func: str = "") -> List[Dict]:
    """检测变参数量不匹配: 格式说明符数量 != 提供的参数数量。"""
    findings = []

    for fname, fmt_arg_idx in _PRINTF_FUNCTIONS.items():
        for m in re.finditer(
            rf'{fname}\s*\(\s*((?:[^()]*|\([^()]*\))*)\s*\)', code):
            args_str = m.group(1)
            args = split_args(args_str)
            if len(args) <= fmt_arg_idx:
                continue
            fmt_arg = args[fmt_arg_idx]
            if is_string_variable(fmt_arg):
                continue

            specifiers = parse_format_specifiers(fmt_arg)
            expected_args = len(specifiers)
            actual_args = len(args) - fmt_arg_idx - 1

            if expected_args == 0:
                continue

            if expected_args > actual_args:
                findings.append({
                    "type": "format-string",
                    "subtype": "vararg_undercount",
                    "function": func, "call": f"{fname}(...)",
                    "expected_args": expected_args,
                    "actual_args": actual_args,
                    "specifiers": [s["conversion"] for s in specifiers[:5]],
                    "severity": "High", "cwe": "CWE-134",
                    "confidence": 0.85,
                    "description": (
                        f"变参不足: 格式串要求{expected_args}个参数, "
                        f"实际{actual_args}个→栈未初始化数据泄露"
                    ),
                })
            elif expected_args < actual_args and actual_args > 0:
                findings.append({
                    "type": "format-string",
                    "subtype": "vararg_overcount",
                    "function": func, "call": f"{fname}(...)",
                    "expected_args": expected_args,
                    "actual_args": actual_args,
                    "severity": "Low", "cwe": "CWE-134",
                    "confidence": 0.30,
                    "description": (
                        f"变参过剩: 格式串需{expected_args}个参数, "
                        f"实际{actual_args}个→多余参数被忽略"
                    ),
                })

    return findings

def detect_dynamic_width_risk(code: str, func: str = "") -> List[Dict]:
    """检测动态宽度字段: %*s 从参数栈读取宽度值。"""
    findings = []
    for fname, fmt_arg_idx in _PRINTF_FUNCTIONS.items():
        for m in re.finditer(
            rf'{fname}\s*\(\s*((?:[^()]*|\([^()]*\))*)\s*\)', code):
            args_str = m.group(1)
            args = split_args(args_str)
            if len(args) <= fmt_arg_idx:
                continue
            fmt_arg = args[fmt_arg_idx]
            if is_string_variable(fmt_arg):
                continue

            dynamic_specs = re.findall(r'%\*[diouxXeEfFgGaAcspn]', fmt_arg)
            if dynamic_specs:
                findings.append({
                    "type": "format-string",
                    "subtype": "dynamic_width",
                    "function": func, "call": f"{fname}(...)",
                    "dynamic_specifiers": dynamic_specs,
                    "severity": "Medium", "cwe": "CWE-134",
                    "confidence": 0.55,
                    "description": (
                        f"动态宽度: {dynamic_specs} → "
                        f"宽度由参数栈控制, 若格式串可控→写入风险"
                    ),
                })

    return findings

def detect_format_string_deep(code: str, func: str = "") -> List[Dict]:
    """格式化字符串深度检测主入口。
    整合: 位置参数滥用 + 变参计数 + 动态宽度。
    """
    findings = []
    findings.extend(detect_positional_param_abuse(code, func))
    findings.extend(detect_vararg_count_mismatch(code, func))
    findings.extend(detect_dynamic_width_risk(code, func))
    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings
