# Format string analyzer -- proper arg parsing
from __future__ import annotations
from typing import List

_FMT_FUNCS = ["printf","fprintf","sprintf","snprintf","dprintf","syslog"]
_SOURCES = ["argv","read","fread","recv","recvfrom","fgets","gets","scanf","getenv"]

def _parse_args(call_str):
    depth = 0; args = []; current = []
    for ch in call_str:
        if ch == "(": depth += 1; current.append(ch)
        elif ch == ")": depth -= 1; current.append(ch)
        elif ch == "," and depth == 0: args.append("".join(current).strip()); current = []
        else: current.append(ch)
    if current: args.append("".join(current).strip())
    return args

def detect_format_string(code, func=""):
    findings = []
    for fmt_func in _FMT_FUNCS:
        pos = 0
        while True:
            idx = code.find(fmt_func + "(", pos)
            # 完整函数名匹配, 防止sprintf误匹配printf
            if idx > 0 and (code[idx-1].isalnum() or code[idx-1] == "_"):
                pos = idx + 1; continue
            if idx < 0: break
            paren_start = idx + len(fmt_func)
            paren_end = code.find(")", paren_start)
            if paren_end < 0: pos = idx + 1; continue
            call_str = code[paren_start+1:paren_end]
            args = _parse_args(call_str)
            fmt_idx = 1 if fmt_func in ["sprintf","snprintf"] else 0
            if fmt_idx >= len(args): pos = idx + 1; continue
            arg = args[fmt_idx].strip()
            if arg.startswith(chr(34)) or arg.startswith(chr(39)): pos = idx + 1; continue
            if not arg: pos = idx + 1; continue
            is_ext = any(src in arg for src in _SOURCES)
            findings.append({"type":"format-string","function":func,"fmt_func":fmt_func,
                "arg":arg,"severity":"High" if is_ext else "Low","cwe":"CWE-134",
                "confidence":0.9 if is_ext else 0.4,
                "description":f"{fmt_func}({arg})"})
            pos = paren_end + 1
    return findings