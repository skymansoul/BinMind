"""整数溢出检测器 — 改进版: 支持间接乘法分配模式."""
from __future__ import annotations
import re
from typing import Dict, List, Tuple

class ValueRange:
    def __init__(self, lo=None, hi=None):
        if lo is None: self.lo=float('-inf'); self.hi=float('inf'); self.is_top=True; self.is_bottom=False
        else: self.lo=float(lo); self.hi=float(hi); self.is_top=False; self.is_bottom=False
    @staticmethod
    def const(v): return ValueRange(v,v)
    @staticmethod
    def top(): return ValueRange()
    def mul(self,o):
        if self.is_top or o.is_top: return ValueRange.top()
        if self.is_bottom or o.is_bottom: return ValueRange.top()
        p=[self.lo*o.lo,self.lo*o.hi,self.hi*o.lo,self.hi*o.hi]
        return ValueRange(min(p),max(p))
    def add(self,o):
        if self.is_top or o.is_top: return ValueRange.top()
        if self.is_bottom or o.is_bottom: return ValueRange.top()
        return ValueRange(self.lo+o.lo,self.hi+o.hi)
    def overflows(self,bits=32):
        if self.is_top: return False
        lo_val = self.lo if self.lo != float('-inf') else 0
        return self.hi > ((1<<bits)-1) or lo_val < 0
    def __repr__(self):
        if self.is_top: return 'TOP'
        return f'[{self.lo},{self.hi}]'

def _extract_ranges(code: str) -> Dict[str, ValueRange]:
    """从代码中提取变量值范围."""
    r = {}
    # 常量赋值
    for m in re.finditer(r'(\w+)\s*=\s*(\d+)\s*;', code):
        r[m.group(1)] = ValueRange.const(int(m.group(2)))
    # 变量复制
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*;', code):
        if m.group(2) in r: r[m.group(1)] = r[m.group(2)]
    # 乘法
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;', code):
        a = r.get(m.group(2), ValueRange.top())
        b = r.get(m.group(3), ValueRange.top())
        r[m.group(1)] = a.mul(b)
    # sizeof 乘法: x = y * sizeof(type)
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*\w+\s*\)\s*;', code):
        v = r.get(m.group(2), ValueRange.top())
        r[m.group(1)] = v.mul(ValueRange.const(4))  # 假设32位指针
    # ptr = malloc(...) 中的 size 变量
    for m in re.finditer(r'(?:malloc|calloc)\s*\(\s*(\w+)\s*\)', code):
        varname = m.group(1)
        if varname in r:
            sz_range = r[varname]
            if sz_range.overflows(32):
                r['__malloc_size__'] = sz_range
    # atoi(argv[...]) → unknown large range
    for m in re.finditer(r'atoi\s*\(\s*v\[(\d+)\]\)', code):
        r[m.group(0).split('(')[1].split(')')[0]] = ValueRange.top()
    # 减法偏移
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;', code):
        a = r.get(m.group(2), ValueRange.top())
        b = r.get(m.group(3), ValueRange.top())
        r[m.group(1)] = a.add(b)
    return r

def detect_int_overflow(code: str, func: str = '') -> List[Dict]:
    """检测整数溢出."""
    findings = []
    ranges = _extract_ranges(code)

    # 直接模式: malloc(n * m)
    for m in re.finditer(r'(?:malloc|calloc)\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)', code):
        nv, sv = m.group(1), m.group(2)
        rn = ranges.get(nv, ValueRange.top())
        rs = ranges.get(sv, ValueRange.top())
        prod = rn.mul(rs)
        if prod.overflows(32):
            findings.append({
                'type': 'integer-overflow', 'function': func,
                'expr': f'{nv}*{sv}', 'severity': 'High', 'cwe': 'CWE-190',
                'confidence': 0.85,
                'description': f'Integer overflow: {nv}*{sv} (range: {prod}) exceeds uint32',
            })
        elif prod.is_top:
            # 参数来自输入 → 可能溢出
            findings.append({
                'type': 'integer-overflow', 'function': func,
                'expr': f'{nv}*{sv}', 'severity': 'Medium', 'cwe': 'CWE-190',
                'confidence': 0.3,
                'description': f'Possible overflow: {nv}*{sv} range could not be determined',
            })

    # 间接模式: sz = n * m; malloc(sz)
    for m in re.finditer(r'(?:malloc|calloc)\s*\(\s*(\w+)\s*\)', code):
        vn = m.group(1)
        if vn in ranges:
            sz = ranges[vn]
            if sz.overflows(32):
                # 检查是否已报告 (避免重复)
                already = any(f.get('expr','') == vn for f in findings)
                if not already:
                    findings.append({
                        'type': 'integer-overflow', 'function': func,
                        'expr': f'{vn} (derived)', 'severity': 'High',
                        'cwe': 'CWE-190', 'confidence': 0.7,
                        'description': f'Integer overflow: size variable {vn} range {sz} exceeds uint32',
                    })
            elif sz.is_top:
                findings.append({
                    'type': 'integer-overflow', 'function': func,
                    'expr': f'{vn} (unknown)', 'severity': 'Medium',
                    'cwe': 'CWE-190', 'confidence': 0.3,
                    'description': f'Possible overflow: size variable {vn} has unknown range',
                })

    return findings
