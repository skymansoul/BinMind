# 抽象解释驱动的误报削减过滤器
#
# 集成 interval_analysis 到检测管线: 对每个漏洞候选,
# 提取涉及的缓冲区变量和写入操作, 用区间分析判定溢出条件是否可行。
#
# Crab (SRI 2024) 和 IKOS 验证了区间抽象削减 50-70% 误报。
# 本模块简化到仅对栈缓冲区做分析——最相关的子问题。

from __future__ import annotations
from typing import List, Dict, Any, Optional
from core.interval_analysis import BufferSizeAnalyzer

def filter_stack_findings(findings, decompiled_code):
    """对栈溢出检测结果做区间分析过滤"""
    import re
    analyzer = BufferSizeAnalyzer()
    # 从反编译代码提取缓冲区声明: char buf[SIZE]
    buf_pattern = re.compile(r"char\s+(\w+)\s*\[\s*(\d+)\s*\]" )
    for m in buf_pattern.finditer(decompiled_code or ""):
        name, size = m.group(1), int(m.group(2))
        analyzer.set_range(name, 1, size)
    filtered = []
    for f_r in findings:
        desc = f_r.get("description", "")
        # 尝试从描述中提取缓冲区名和写入量
        buf_match = re.search(r"(\w+).*?(\d+)\s*bytes", desc)
        if buf_match:
            buf_name, write_sz = buf_match.group(1), int(buf_match.group(2))
            if analyzer.is_safe(buf_name, write_sz):
                continue  # 区间分析判定安全 -> 排除
        filtered.append(f_r)
    return filtered

def filter_all(findings, decompiled_code, cfg=None):
    """对所有类型漏洞候选做误报过滤"""
    stack_findings = [f for f in findings if f.get("type") == "stack-overflow"]
    other_findings = [f for f in findings if f.get("type") != "stack-overflow"]
    # 仅对栈溢出做区间分析 (其他类型需要更复杂的抽象域)
    filtered_stack = filter_stack_findings(stack_findings, decompiled_code or "")
    return filtered_stack + other_findings