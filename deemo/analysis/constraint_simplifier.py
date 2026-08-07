# [DEPRECATED] 功能已合并至 heap_overflow_src_verifier.py, 旧接口保留兼容.
from typing import Dict, List

def extract_constants(code: str) -> Dict[str, int]:
    """提取赋值常量 → 兼容 _init_core.py 导入."""
    import re
    return {m.group(1): int(m.group(2))
            for m in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code)}

def filter_false_positives(findings: list, code: str) -> list:
    """空实现 — 实际FP过滤由GAPSBV七阶段管线完成."""
    return findings
