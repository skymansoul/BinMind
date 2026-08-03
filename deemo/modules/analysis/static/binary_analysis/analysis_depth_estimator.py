from __future__ import annotations
from typing import Any

def estimate_depth(cfg_size: int, func_count: int, import_count: int) -> dict[str, Any]:
    """估算二进制分析所需深度"""
    depth = "shallow"
    if func_count > 100:
        depth = "deep"
    elif func_count > 30:
        depth = "medium"
    return {"depth": depth, "estimated_time_s": func_count * 2.5}
