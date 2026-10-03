"""双释放检测 — 静态扫描 free 调用点，识别同一指针在重新赋值前的重复释放。

对同一变量名的相邻 free 调用，检查两者之间的代码段是否包含该变量的重新
分配（malloc/realloc/calloc）。存在重新赋值则不属于 double-free；否则按
CWE-415 上报。输入为反编译伪代码或 C 源码文本，逐字符定位，不依赖语法树。
"""
from __future__ import annotations

import re
from typing import Dict, List


def detect_double_free(code: str, func: str = "") -> List[Dict]:
    """在文本中检测 double-free 模式。

    参数:
        code: 目标函数源码或反编译伪代码。
        func: 函数名，用于标注结果来源。
    返回:
        finding 字典列表，字段与现有检测器输出格式一致。
    """
    findings: List[Dict] = []
    free_pat = re.compile(r"free\s*\(\s*(\w+)\s*\)")
    free_calls = [(m.group(1), m.start(), m.end())
                  for m in free_pat.finditer(code)]

    for i in range(len(free_calls)):
        for j in range(i + 1, len(free_calls)):
            if free_calls[i][0] != free_calls[j][0]:
                continue
            v = free_calls[i][0]
            seg = code[free_calls[i][2]:free_calls[j][1]]
            # 两次 free 之间出现重新赋值则不构成 double-free
            reassigned = re.search(
                r'\b' + re.escape(v) + r'\s*=\s*(?:malloc|realloc|calloc)\b', seg)
            if reassigned:
                continue
            findings.append({
                "type": "double-free",
                "function": func,
                "variable": v,
                "severity": "Critical",
                "cwe": "CWE-415",
                "confidence": 0.9,
                "description": "double-free: " + v + " freed twice",
            })
    return findings


__all__ = ["detect_double_free"]
