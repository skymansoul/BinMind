# analysis/fc_direct_writes — FC-VRA 直接偏移写检测
# 覆盖分配点缓冲区的非函数式写入:
# 直接偏移写与循环定界写不经过 memcpy/strcpy 等函数调用,
# 函数式写入提取对其无效, 需单独检测。
# 覆盖两类:
#   a) buf[CONST] = value              → 写 [CONST, CONST+1)
#   b) for(i=0;i<LIMIT;i++){buf[i]=..} → 写 [0, LIMIT)
#      while(i<LIMIT){buf[i++]=..}     → 写 [0, LIMIT)
# 当 write_end > 对齐后可用空间 → 堆溢出候选。
# `<=` 定界为 LIMIT+1 次迭代 (off-by-one 语义)。

from __future__ import annotations
from typing import Dict, List
import re

from value_range_analyzer import ValueRange
from size_expr_evaluator import eval_size_expr
from heap_layout_model import get_allocator_model
from pointer_tracker import extract_heap_ptrs


def detect_direct_writes(code: str, ranges: Dict, defines: Dict,
                         arch: str) -> List[Dict]:
    """直接偏移写检测主入口。"""
    model = get_allocator_model(arch)
    findings = []
    for hp in extract_heap_ptrs(code):
        alloc_range = eval_size_expr(hp.alloc_size_expr or "unknown",
                                     ranges, defines)
        if not alloc_range.is_const:
            continue
        usable = model.usable_size_min(alloc_range.const_value)
        var = hp.var

        # a) 直接常量偏移写
        for m in re.finditer(rf"\b{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*=", code):
            off = int(m.group(1))
            if off + 1 > usable:
                findings.append({
                    "type": "heap-overflow", "cwe": "CWE-122",
                    "alloc_func": "malloc", "write_func": "direct_offset",
                    "alloc_size_source": hp.alloc_size_expr,
                    "write_size_source": f"offset {off} + 1B",
                    "buffer": var, "alloc_var": var,
                    "binding_conf": 1.0,
                    "confidence": 0.85,
                    "severity": "High",
                    "reason": f"C0:direct offset buf[{off}]+1 > 可用{usable}B",
                })
        # b) 循环全量写 (for/while 定界; <=N 为 N+1 次 → off-by-one)
        # TODO: 循环上界为变量 (i < n) 时无法静态判定, 需接入区间推断
        for lm in re.finditer(
            rf"(?:for\s*\([^;]*;\s*[^;]*(<=|<)\s*(\d+)\s*[^;]*;\s*[^)]*\)|"
            rf"while\s*\(\s*\w+\s*(<=|<)\s*(\d+)\s*\))", code):
            limit = int(lm.group(2) or lm.group(4))
            op = lm.group(1) or lm.group(3)
            total = limit + 1 if op == "<=" else limit
            body_start = lm.end()
            body_end = min(body_start + 400, len(code))
            body = code[body_start:body_end]
            if re.search(rf"\b{re.escape(var)}\s*\[[^\]]*\]\s*=", body):
                if total > usable:
                    findings.append({
                        "type": "heap-overflow", "cwe": "CWE-122",
                        "alloc_func": "malloc", "write_func": "loop_offset",
                        "alloc_size_source": hp.alloc_size_expr,
                        "write_size_source": f"loop {total}B ({op}{limit})",
                        "buffer": var, "alloc_var": var,
                        "binding_conf": 0.9,
                        "confidence": 0.80,
                        "severity": "High",
                        "reason": f"C0:loop write {total}B > 可用{usable}B",
                    })
    return findings
