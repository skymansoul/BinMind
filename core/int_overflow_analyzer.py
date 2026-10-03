# 整型溢出分析器 — 区间约束检查
# 决策: 对乘/加操作的结果做区间推断, 若结果区间上限超过INT32_MAX或size_t范围则报告溢出
# 与纯模式匹配的区别: 不只看"有没有if检查", 而是推断操作数范围后计算溢出可能性
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class IntRange:
    min_val: int; max_val: int
    def mul(self, o: 'IntRange') -> 'IntRange':
        p = [self.min_val*o.min_val, self.min_val*o.max_val,
             self.max_val*o.min_val, self.max_val*o.max_val]
        return IntRange(min(p), max(p))
    def add(self, o: 'IntRange') -> 'IntRange':
        return IntRange(self.min_val+o.min_val, self.max_val+o.max_val)
    def can_overflow(self, bits: int = 32) -> bool:
        limit = (1 << (bits - 1)) - 1
        return self.max_val > limit or self.min_val < -limit

@dataclass
class IntOverflowReport:
    location: str; operation: str; operands: List[str]
    result_range: IntRange; can_overflow: bool
    used_in_alloc: bool; confidence: float

class IntOverflowAnalyzer:
    _MUL_PAT = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)')
    _ADD_PAT = re.compile(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)')
    _INT_PAT = re.compile(r'\b(\d+)\b')

    def __init__(self):
        self._known_ranges: Dict[str, IntRange] = {}

    def analyze(self, pseudocode: str) -> List[IntOverflowReport]:
        self._known_ranges.clear()
        reports = []
        for line in pseudocode.split('\n'):
            s = line.strip()
            # 从赋值推断变量范围
            self._infer_range(s)
            # 检测乘/加法
            for m in self._MUL_PAT.finditer(s):
                r = self._check_op(m, 'mul', pseudocode)
                if r: reports.append(r)
            for m in self._ADD_PAT.finditer(s):
                r = self._check_op(m, 'add', pseudocode)
                if r and r.can_overflow: reports.append(r)
        reports.sort(key=lambda r: r.confidence, reverse=True)
        return reports

    def _infer_range(self, line: str):
        m = re.search(r'(\w+)\s*=\s*(\d+)\s*;', line)
        if m:
            v = int(m.group(2))
            self._known_ranges[m.group(1)] = IntRange(v, v)
        # 从if条件推断上限: if (x < 4096) → x.max ≤ 4095
        m = re.search(r'if\s*\((\w+)\s*<\s*(\d+)\)', line)
        if m:
            v = int(m.group(2))
            self._known_ranges[m.group(1)] = IntRange(0, v-1)

    def _check_op(self, m, op_type, code):
        lhs, a, b = m.group(1), m.group(2), m.group(3)
        ra = self._get_range(a); rb = self._get_range(b)
        rr = ra.mul(rb) if op_type == 'mul' else ra.add(rb)
        used_in_alloc = bool(re.search(rf'malloc\s*\(\s*{lhs}\s*\)', code))
        can_ov = rr.can_overflow()
        conf = 0.8 if (used_in_alloc and can_ov) else (0.4 if can_ov else 0.1)
        return IntOverflowReport(
            location=f'line_at_{a}_{op_type}_{b}',
            operation=op_type, operands=[a,b],
            result_range=rr, can_overflow=can_ov,
            used_in_alloc=used_in_alloc, confidence=round(conf,2),
        )

    def _get_range(self, var: str) -> IntRange:
        return self._known_ranges.get(var, IntRange(0, 65536))
