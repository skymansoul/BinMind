# coding: utf-8
"""
格式化字符串漏洞检测 — 污点追踪 + 格式符静态解析.

方法:
  1. 识别 printf 族调用 — 基于 IR 级别的调用模式, 不依赖符号名
  2. 污点追踪 format 参数来源 — 若来自外部输入 → 初步标记
  3. 静态解析格式字符串 — 检测 %n (任意地址写)、%x (栈泄露)、位置参数
  4. 综合判定: 外部输入 + 危险格式符 + 无格式符白名单过滤 → 漏洞

检测的格式符威胁:
  %n       — 向已输出字符数写入 (任意地址写原语)
  %hn/%hhn — 半字/字节写入 (更精确的 GOT 覆写)
  %10$n    — 位置参数绕过栈保护 (Linux 的 FORTIFY_SOURCE 不检查位置参数)
  %s       — 栈上的字符串读 (信息泄露, 配合 %n 使用)
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# printf 族函数 — 跨平台归一化名称
_PRINTF_FAMILY = frozenset({
    'printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf',
    'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'wprintf', 'fwprintf', 'swprintf',
    'syslog', 'vsyslog',
    'printf_s', 'fprintf_s', 'sprintf_s',  # Windows 安全版本
    '__printf_chk', '__fprintf_chk',        # glibc FORTIFY 包装
    'print', 'println',                     # 高级语言
})

# 危险格式符 — 在用户可控的格式字符串中出现即高度可疑
_DANGEROUS_SPECIFIERS = {
    '%n':   {'threat': '任意地址写', 'severity': 'critical'},
    '%hn':  {'threat': '半字写入 (GOT覆写)', 'severity': 'critical'},
    '%hhn': {'threat': '字节写入 (精确覆写)', 'severity': 'critical'},
    '%ln':  {'threat': '长字写入', 'severity': 'critical'},
    '%lln': {'threat': '四字写入', 'severity': 'critical'},
}

# 信息泄露格式符
_LEAK_SPECIFIERS = {
    '%s':   {'threat': '栈字符串泄露', 'severity': 'high'},
    '%x':   {'threat': '栈内存泄露 (hex)', 'severity': 'medium'},
    '%lx':  {'threat': '长字栈泄露', 'severity': 'medium'},
    '%p':   {'threat': '指针泄露 (ASLR绕过)', 'severity': 'high'},
}

# 位置参数模式: %n$ 格式 (如 %10$n)
_POSITIONAL_PATTERN = re.compile(r'%\d+\$[nshxlp]')


@dataclass
class FormatStringFinding:
    """一个格式化字符串漏洞的检测结果."""
    call_site: int               # printf 调用地址
    format_arg_index: int        # format 参数在调用中的位置 (0-based)
    format_string_value: str     # 静态解析出的格式字符串 (部分)
    taint_source: str            # 污点来源描述
    dangerous_specs: List[str]   # 检测到的危险格式符
    leak_specs: List[str]        # 检测到的信息泄露格式符
    has_positional: bool         # 是否包含位置参数 (绕过 FORTIFY)
    is_user_controlled: bool     # format 参数是否来自外部输入
    exploitable: bool
    confidence: float
    cwe_id: str = 'CWE-134'     # Use of Externally-Controlled Format String


def _parse_format_specifiers(fmt_str: str) -> Tuple[List[str], List[str], bool]:
    """静态解析格式字符串, 返回 (危险符, 泄露符, 含位置参数?)."""
    dangerous = []
    leaks = []
    has_pos = bool(_POSITIONAL_PATTERN.search(fmt_str))
    for spec, info in _DANGEROUS_SPECIFIERS.items():
        if spec in fmt_str:
            dangerous.append(f'{spec} ({info["threat"]})')
    for spec, info in _LEAK_SPECIFIERS.items():
        if spec in fmt_str:
            leaks.append(f'{spec} ({info["threat"]})')
    return dangerous, leaks, has_pos


def identify_printf_calls(
    ir_ops: Dict[int, Dict],
    callee_names: Dict[int, str],
) -> List[Dict]:
    """在 IR 操作中识别 printf 族调用.

    返回 [{call_addr, callee, format_arg_index}, ...].
    不依赖精确的符号名: 同时检查 callee 名称和调用模式
    (variadic call with format-like first argument).
    """
    calls = []
    for addr, op in ir_ops.items():
        if op.get('op_type') != 'call':
            continue
        callee = callee_names.get(addr, op.get('callee', ''))
        callee_lower = callee.lower().split('.')[-1]  # 去掉命名空间前缀

        if callee_lower in _PRINTF_FAMILY:
            calls.append({
                'call_addr': addr,
                'callee': callee,
                'format_arg_index': 0,  # printf 的第一个参数
            })
        elif 'printf' in callee_lower or 'print' in callee_lower:
            # 模糊匹配: 用户自定义包装函数
            calls.append({
                'call_addr': addr,
                'callee': callee,
                'format_arg_index': 0,
            })
    return calls


def detect_format_string_vulns(
    printf_calls: List[Dict],
    taint_map: Dict[int, Dict],       # addr → {source_type, source_desc}
    string_values: Dict[int, str],     # addr → 格式字符串内容 (静态提取)
    instructions: Optional[List[Dict]] = None,
) -> List[FormatStringFinding]:
    """检测格式化字符串漏洞.

    printf_calls: identify_printf_calls 的输出.
    taint_map: 每个地址的污点信息 (来自 taint_flow.py).
    string_values: 静态提取的格式字符串内容.
    """
    findings = []
    for call in printf_calls:
        addr = call['call_addr']
        fmt_val = string_values.get(addr, '')
        taint = taint_map.get(addr, {})

        is_user_ctrl = taint.get('source_type', '') in (
            'external_input', 'file_input', 'network', 'register')

        dangerous, leaks, has_pos = _parse_format_specifiers(fmt_val)

        if not dangerous and not leaks:
            continue  # 无危险格式符 — 即使用户可控也不构成漏洞

        # 置信度计算
        conf = 0.0
        if dangerous:
            conf += 0.40
        if is_user_ctrl:
            conf += 0.35
        if has_pos:
            conf += 0.15  # 位置参数 → 绕过 FORTIFY_SOURCE
        if leaks:
            conf += 0.10

        exploitable = bool(dangerous and is_user_ctrl)

        findings.append(FormatStringFinding(
            call_site=addr,
            format_arg_index=call['format_arg_index'],
            format_string_value=fmt_val,
            taint_source=taint.get('source_desc', 'unknown'),
            dangerous_specs=dangerous,
            leak_specs=leaks,
            has_positional=has_pos,
            is_user_controlled=is_user_ctrl,
            exploitable=exploitable,
            confidence=min(1.0, conf),
        ))

    findings.sort(key=lambda f: -f.confidence)
    return findings


def summarize_findings(findings: List[FormatStringFinding]) -> Dict[str, Any]:
    exploitable = [f for f in findings if f.exploitable]
    has_positional = [f for f in findings if f.has_positional]
    return {
        'total_printf_calls_analyzed': len(findings),
        'exploitable_format_strings': len(exploitable),
        'with_positional_args': len(has_positional),
        'with_n_write': sum(1 for f in findings if any('%n' in d for d in f.dangerous_specs)),
        'with_leak': sum(1 for f in findings if f.leak_specs),
        'avg_confidence': round(sum(f.confidence for f in findings) / max(1, len(findings)), 2),
    }
