# [DEPRECATED] — 功能已迁移至 modules/info/analysis/uaf_alias_analyzer.py 或 src/uaf_alias_analyzer.py
# 若确认无外部引用, 可安全删除
"""UAF检测 v2 — struct字段追踪."""
from __future__ import annotations
from typing import List
import re

def _extract(code):
    r=[]
    for m in re.finditer(r"free\s*\(\s*([\w\->\.]+)\s*\)", code):
        e=m.group(1);b=re.split(r"[\.\->]",e)[0].strip()
        r.append((e,b,m.start(),m.end()))
    return r

def detect_uaf_with_aliases(code,func=""):
    findings=[]
    for expr,base,fs,fe in _extract(code):
        rem=code[fe:]
        if ">" in expr or "." in expr:
            i=rem.find(expr)
            while i>=0:
                bf=rem[max(0,i-10):i]
                if "free(" not in bf and "free (" not in bf:
                    findings.append({"type":"use-after-free","function":func,"variable":expr,"severity":"Critical","cwe":"CWE-416","confidence":0.85,"description":"UAF: "+expr+" used after free"})
                    break
                i=rem.find(expr,i+1)
        i=rem.find(base)
        while i>=0:
            ok_b=i==0 or not rem[i-1].isalnum()
            ok_a=i+len(base)>=len(rem) or not rem[i+len(base)].isalnum()
            if ok_b and ok_a:
                ctx=rem[max(0,i-8):i]
                if "free(" not in ctx and "free (" not in ctx:
                    findings.append({"type":"use-after-free","function":func,"variable":base,"severity":"Critical","cwe":"CWE-416","confidence":0.75,"description":"UAF: "+base+" used after free("+expr+")"})
                    break
            i=rem.find(base,i+1)
    return findings
