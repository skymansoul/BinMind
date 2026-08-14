# C源码→反编译伪代码归一化 — 按分号将紧凑C源码拆分为每行一条语句,
# 供逐行匹配的检测器使用。不做完整C解析, 仅做语句级拆分+基本预处理。

import re
from typing import List


def normalize_c_source(source: str) -> List[str]:
    """将C源码拆分为每行一条独立语句。

    拆分规则: 在分号处断行, 跳过字符串内的分号。
    移除空行和纯花括号行。
    返回行列表(每行一条语句), 可直接输入检测器。
    """
    # 移除注释
    source = re.sub(r'//[^\n]*', '', source)
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)

    # 在分号处拆分(跳过字符串内的分号)
    lines = []
    current = []
    in_string = False
    string_char = ''
    for ch in source:
        if in_string:
            current.append(ch)
            if ch == string_char:
                in_string = False
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            current.append(ch)
            continue
        if ch == ';':
            line = ''.join(current).strip()
            if line and line not in ('{', '}'):
                lines.append(line)
            current = []
            continue
        current.append(ch)

    # 最后残留的非分号结尾行
    leftover = ''.join(current).strip()
    if leftover and leftover not in ('{', '}'):
        lines.append(leftover)

    return lines


def normalize_and_detect(source: str, func_name: str = "") -> List[dict]:
    """归一化+UAF检测一站式: 拆分源码→喂入两个UAF检测器→合并结果。

    返回与vuln_analyzer兼容的finding列表。
    """
    lines = normalize_c_source(source)
    pseudocode = '\n'.join(lines)

    findings = []

    # UAF FSM
    try:
        from core.heap_lifecycle_fsm import detect_uaf_static, detect_double_free
        findings.extend(detect_uaf_static(pseudocode, func_name))
        findings.extend(detect_double_free(pseudocode, func_name))
    except ImportError:
        pass

    # UAF argument matcher
    try:
        from core.uaf_argument_matcher import detect_uaf_args
        findings.extend(detect_uaf_args(pseudocode, func_name))
    except ImportError:
        pass

    return findings
