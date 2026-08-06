import re
from typing import List, Dict

FNS = ["printf","fprintf","sprintf","snprintf","dprintf","syslog"]

def detect_format_string(code: str, func: str = "") -> List[Dict]:
    findings = []
    for fn in FNS:
        i = 0
        while True:
            i = code.find(fn + chr(40), i)
            if i < 0: break
            start = i + len(fn) + 1
            end = code.find(chr(44), start)
            if end < 0: end = code.find(chr(41), start)
            if end < 0: i = start; continue
            arg = code[start:end].strip()
            if len(arg) > 0 and arg[0] not in (chr(34),chr(39)):
                if arg not in ("NULL","nullptr","stderr","stdout","format","fmt"):
                    findings.append({"type":"format-string","function":func,"format_func":fn,"format_arg":arg,"severity":"High","cwe":"CWE-134","confidence":0.75,"description":f"{fn}({arg})"})
            i = end + 1
    return findings
