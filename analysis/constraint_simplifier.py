# [DEPRECATED] 功能已合并至 heap_overflow_src_verifier.py, 旧接口保留兼容.
from typing import Dict, List

def extract_constants(code: str) -> Dict[str, int]:
    """提取赋值常量 → 兼容 _init_core.py 导入."""
    import re
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code)}

def filter_false_positives(findings: list, code: str) -> list:
    """按源码存在性去重过滤疑似误报 — 兼容旧调用方."""
    seen = set()
    out = []
    for f in findings:
        var = f.get('var') if isinstance(f, dict) else None
        if var and var not in code:
            continue
        key = (f.get('type'), var, f.get('op'), f.get('val'), f.get('line'))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
