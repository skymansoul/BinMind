# coding: utf-8
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class IntOverflowCandidate:
    location: str; operation: str; operands: List[str]
    overflow_type: str; confidence: float
    dst_reg: str = ""  # 溢出指令的目标寄存器, 供FP过滤器追踪sink使用
    evidence: List[str] = field(default_factory=list)

class IntegerOverflowDetector:
    _ARITH_OPS = {'add':'add','sub':'sub','mul':'mul','imul':'mul','shl':'shl','sal':'shl'}

    def detect(self, instructions, func_name='', base_addr=0x400000):
        # Phase 0: 反向追踪-对每寄存器提取最近一次赋值的立即数
        reg_values = {}  # reg -> int value (从最近赋值推断)
        reg_ranges = {}  # reg -> (lo, hi) (从cmp+jcc推断)
        for i, insn in enumerate(instructions):
            mnem, ops = self._parse(insn)
            # cmp约束
            if mnem == 'cmp' and len(ops) >= 2:
                reg = ops[0]
                try: v = int(ops[1], 16) if ops[1].startswith('0x') else int(ops[1])
                except: continue
                if reg not in reg_ranges: reg_ranges[reg] = (0, 2**31-1)
                lo, hi = reg_ranges[reg]
                jcc = self._find_jcc(instructions, i)
                if jcc in ('jle','jl','jbe','jb'): reg_ranges[reg] = (lo, min(hi, v))
                elif jcc in ('jge','jg','jae','ja'): reg_ranges[reg] = (max(lo, v), hi)
            # mov赋值: 追踪常量
            if mnem == 'mov' and len(ops) >= 2:
                dst = ops[0]
                try: v = int(ops[1], 16) if ops[1].startswith('0x') else int(ops[1])
                except: continue
                reg_values[dst] = v

        candidates = []
        for i, insn in enumerate(instructions):
            mnem, ops = self._parse(insn)
            if mnem not in self._ARITH_OPS: continue
            op_type = self._ARITH_OPS[mnem]; addr = self._addr(insn, base_addr, i)
            dst_reg = ops[0] if ops else ""  # 目标寄存器(算术指令的dst)
            # mul/imul单操作数: 隐式eax为第一操作数, 显式操作数为第二
            if mnem in ('mul', 'imul') and len(ops) == 1:
                ops = ['eax', ops[0]]
                dst_reg = 'eax'  # mul结果存入edx:eax, dst为eax
            # 对每个操作数: 优先用追踪到的立即数值, 其次用范围上界
            vals = []
            for op in ops[:2]:
                if op in reg_values: vals.append(reg_values[op])
                elif op in reg_ranges: vals.append(reg_ranges[op][1])
                else: vals.append(None)
            if len(vals) < 2 or vals[0] is None or vals[1] is None: continue
            a, b = vals[0], vals[1]

            if op_type == 'add':
                r = a + b
                if a > 0x40000000 and b > 0 and r < max(a, b):
                    candidates.append(IntOverflowCandidate(
                        location=f'{func_name}@0x{addr:x}', operation=f'add {a}+{b}',
                        operands=[str(a),str(b)], dst_reg=dst_reg, overflow_type='add_overflow',
                        confidence=0.85, evidence=[f'{a}+{b}={r}(wrap at {r.bit_length()}bits)']))
                elif a > 0x40000000 and b > 0 and r > 2**31-1:
                    candidates.append(IntOverflowCandidate(
                        location=f'{func_name}@0x{addr:x}', operation=f'add {a}+{b}={r}',
                        operands=[str(a),str(b)], dst_reg=dst_reg, overflow_type='add_overflow',
                        confidence=0.6, evidence=[f'结果{r}超过INT_MAX(2^31-1)']))
            elif op_type == 'mul':
                r = a * b
                if a > 1 and b > 1 and (r < max(a, b) or r > 2**31-1):
                    candidates.append(IntOverflowCandidate(
                        location=f'{func_name}@0x{addr:x}', operation=f'mul {a}*{b}',
                        operands=[str(a),str(b)], dst_reg=dst_reg, overflow_type='mul_overflow',
                        confidence=0.9, evidence=[f'{a}*{b}={r}(wrap)']))
                elif a > 0x10000 and b > 0x10000 and r > 2**31-1:
                    candidates.append(IntOverflowCandidate(
                        location=f'{func_name}@0x{addr:x}', operation=f'mul {a}*{b}={r}',
                        operands=[str(a),str(b)], dst_reg=dst_reg, overflow_type='mul_overflow',
                        confidence=0.7, evidence=[f'结果{r}超过INT_MAX']))
            elif op_type == 'shl' and b > 0:
                r = a << b
                if r.bit_length() > 32 and a.bit_length() <= 16:
                    candidates.append(IntOverflowCandidate(
                        location=f'{func_name}@0x{addr:x}', operation=f'shl {a}<<{b}',
                        operands=[str(a),str(b)], dst_reg=dst_reg, overflow_type='truncation',
                        confidence=0.7, evidence=[f'{a}<<{b}={r}(可能截断为32位)']))
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def _find_jcc(self, insns, cmp_idx):
        for j in range(cmp_idx+1, min(cmp_idx+4, len(insns))):
            mnem, _ = self._parse(insns[j])
            if mnem in ('jle','jl','jbe','jb','jge','jg','jae','ja','je','jne'): return mnem
        return ''

    def _parse(self, insn):
        s = insn.strip()
        if ':' in s[:20]: s = s.split(':',1)[1].strip()
        p = s.split(None,1)
        if len(p)<2: return (p[0].lower(),[]) if p else ('',[])
        return (p[0].lower(), [o.strip() for o in p[1].split(',')])

    def _addr(self, insn, base, idx):
        s = insn.strip()
        if ':' in s[:20]:
            try: return int(s.split(':')[0],16)
            except ValueError: pass
        return base + idx*4

__all__ = ['IntOverflowCandidate','IntegerOverflowDetector']
