# [DEPRECATED] — 功能已迁移至 modules/info/analysis/format_string_detector.py 或 src/format_string_detector.py
# 若确认无外部引用, 可安全删除
"""Format string漏洞检测, 支持多参数函数的fmt参数定位."""
import re
from typing import List, Dict

FNS = ["printf","fprintf","sprintf","snprintf","dprintf","syslog","syslog"]
SKIP = {"NULL","nullptr","stderr","stdout","format","fmt"}

def _extract_args(code, pos_after_paren):
    """提取调用参数列表, 处理嵌套括号."""
    depth = 0; args = []; cur = ""
    for i in range(pos_after_paren, len(code)):
        ch = code[i]
        if ch == '(': depth += 1; cur += ch
        elif ch == ')':
            if depth == 0:
                if cur.strip(): args.append(cur.strip())
                return args, i + 1
            depth -= 1; cur += ch
        elif ch == ',' and depth == 0:
            args.append(cur.strip()); cur = ""
        else:
            cur += ch
    return args, len(code)

def detect_format_string(code: str, func: str = "") -> List[Dict]:
    """识别用户可控的format string参数."""
    findings = []
    for fn in FNS:
        needle = fn + "("
        i = 0
        while True:
            i = code.find(needle, i)
            if i < 0: break
            args, end_pos = _extract_args(code, i + len(needle))
            # format参数位置: printf在第1位, fprintf/sprintf/syslog在第2位
            if fn == 'printf':
                target_arg = args[0] if args else None
            elif fn in ('fprintf','dprintf','sprintf','snprintf','syslog'):
                target_arg = args[1] if len(args) > 1 else (args[0] if args else None)
            else:
                target_arg = args[0] if args else None

            if target_arg and target_arg not in SKIP:
                # 检查是否为字面量字符串 (以"或'开头)
                if len(target_arg) > 0 and target_arg[0] not in ('"', "'"):
                    findings.append({
                        "type": "format-string", "function": func,
                        "format_func": fn, "format_arg": target_arg,
                        "severity": "High", "cwe": "CWE-134", "confidence": 0.75,
                        "description": f"{fn}({target_arg}) — user-controlled format string",
                    })
            i = end_pos
    return findings
