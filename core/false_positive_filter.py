# 抽象解释驱动的误报削减过滤器 — 对每个漏洞候选提取缓冲区变量与写入操作,
# 用区间分析判定溢出条件是否可行 (Crab/IKOS 验证可削减 50-70% 误报; 本模块仅分析栈缓冲区)。

import re
from typing import List, Dict, Any, Optional
from core.interval_analysis import BufferSizeAnalyzer


class FalsePositiveFilter:
    """误报过滤器：对漏洞候选执行可选的区间分析过滤。

    封装 filter_stack_findings / filter_all，提供带状态的过滤入口，
    便于在检测管线中复用同一个分析器实例。
    """

    def __init__(self):
        self._analyzer = BufferSizeAnalyzer()

    def filter(self, findings, decompiled_code, cfg=None):
        return filter_all(findings, decompiled_code, cfg)

    def setup(self, ir, scp, taint, interval):
        """注入分析器上下文 — 常量传播 / 污点 / 区间分析结果。

        ir 为逐行 IR; scp/taint/interval 为对应分析器实例。
        """
        self._ir = list(ir or [])
        self._const = scp
        self._taint = taint
        self._interval = interval

    def filter_findings(self, findings):
        """对候选执行过滤, 返回过滤结果对象列表。"""
        results = []
        for finding in findings:
            decision = FilterDecision(finding, filtered_out=False)
            if self._filter_one(finding):
                decision.filtered_out = True
                decision.filter_reason = 'interval-safe'
                decision.filter_layer = 'interval_analysis'
            results.append(decision)
        return results

    def _filter_one(self, finding):
        """区间分析判定写入量不越界则过滤。"""
        interval = getattr(self, '_interval', None)
        if interval is None:
            return False
        buffers = getattr(interval, '_buffers', {})
        if not buffers:
            return False
        desc = finding.get('description', '') or ''
        buf_match = re.search(r'(\w+).*?(\d+)\s*bytes', desc)
        if not buf_match:
            return False
        buf_name, write_sz = buf_match.group(1), int(buf_match.group(2))
        size = buffers.get(buf_name)
        if size is None:
            return False
        return write_sz <= size


class FilterDecision:
    """单条候选的过滤判定结果。"""

    def __init__(self, finding, filtered_out=False,
                 filter_reason='', filter_layer=''):
        self.finding = finding
        self.filtered_out = filtered_out
        self.filter_reason = filter_reason
        self.filter_layer = filter_layer


def filter_stack_findings(findings, decompiled_code):
    """对栈溢出检测结果做区间分析过滤"""
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