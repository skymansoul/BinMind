# 按需后向值流追踪v2——跨块strided interval+栈槽位+同源检测
from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class IntervalKind(Enum):
    EXACT=0; RANGE=1; TOP=2; BOT=3
class SourceKind(Enum):
    CONSTANT='constant'; REGISTER='register'; STACK_SLOT='stack_slot'; EXTERNAL='external'; UNKNOWN='unknown'


@dataclass
class StridedInterval:
    """跨步区间 [lo, hi]ₛ = { lo + k*s | 0 <= k <= (hi-lo)/s }"""
    lo: int = 0
    hi: int = 0xFFFFFFFF
    stride: int = 1
    kind: IntervalKind = IntervalKind.TOP

    @staticmethod
    def exact(v): return StridedInterval(lo=v, hi=v, stride=1, kind=IntervalKind.EXACT)
    @staticmethod
    def top(): return StridedInterval(kind=IntervalKind.TOP)
    @staticmethod
    def bot(): return StridedInterval(kind=IntervalKind.BOT)
    def is_exact(self): return self.kind == IntervalKind.EXACT
    def is_top(self): return self.kind == IntervalKind.TOP
    def is_bot(self): return self.kind == IntervalKind.BOT
    def add(self, delta):
        return self if self.is_top() or self.is_bot() else StridedInterval(
            lo=self.lo+delta, hi=self.hi+delta, stride=self.stride, kind=self.kind)
    def mul(self, factor):
        return self if self.is_top() or self.is_bot() else StridedInterval(
            lo=self.lo*factor, hi=self.hi*factor, stride=self.stride*factor, kind=IntervalKind.RANGE)
    def may_exceed(self, threshold): return self.hi > threshold if not (self.is_top() or self.is_bot()) else self.is_top()
    def max_possible(self): return 0xFFFFFFFF if self.is_top() else (0 if self.is_bot() else self.hi)
    def min_possible(self): return 0 if self.is_top() else (0xFFFFFFFF if self.is_bot() else self.lo)



@dataclass
class ValueFlowResult:
    sink_instr_idx: int; sink_func: str; param_reg: str; final_interval: StridedInterval
    source_kind: SourceKind = SourceKind.UNKNOWN; source_slot: Optional[str] = None
    alloc_interval: Optional[StridedInterval] = None
    trace_path: List[int] = field(default_factory=list); confidence: float = 1.0
    is_heap_related: bool = False
    transformed: bool = False  # 溯源链上发生过算术变换→来源身份不可直接等同


# 栈槽位读写: AT&T mov N(%rbp),%reg / Intel mov reg,[rbp+N] (N可为负)
_STACK_READ = re.compile(r'mov\s+([+\-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*(%?rbp)\s*\),\s*%?(\w+)', re.I)
_STACK_WRITE = re.compile(r'mov\s+%?(\w+),\s*([+\-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*(%?rbp)\s*\)', re.I)
_INTEL_STACK_READ = re.compile(r'mov(?:sx|sxd|zx)?\s+(\w+),\s*(?:\w+\s+PTR\s+)?\[(rbp|rsp)([+-]\w+)\]', re.I)
_INTEL_STACK_WRITE = re.compile(r'mov\s+(?:\w+\s+PTR\s+)?\[(rbp|rsp)([+-]\w+)\],\s*%?(\w+)', re.I)
# 寄存器宽度归一化: 32位写零扩展到64位
_REG_ALIAS = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi','r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11','ax':'rax','bx':'rbx','cx':'rcx','dx':'rdx'}
def _norm_reg(r): return _REG_ALIAS.get(r.lower(), r.lower())


class ValueFlowEngine:
    """后向值流引擎——sink出发沿def-use链反向传播,跨块DFS,遇非堆call截断,v2栈槽位"""

    _HEAP_SINKS = {'malloc','calloc','realloc','memcpy','memmove','strcpy','strncpy','sprintf','snprintf'}
    _ALLOC_SIZE_PARAM = {'malloc':0,'calloc':1,'realloc':1,'alloca':0,'memcpy':2,'memmove':2,'strncpy':2,'snprintf':1}

    def __init__(self, max_depth: int = 30):
        self._max_depth = max_depth
        self._PARAM_CANDS = [('rdi','rcx'),('rsi','rdx'),('rdx','r8'),('rcx','r9'),('r8',None),('r9',None)]

    def trace_sink_param(self, sink_instr_idx, sink_func, param_idx, instructions,
                         bb_boundaries=None, cfg_predecessors=None) -> ValueFlowResult:
        cands = self._PARAM_CANDS[param_idx] if param_idx < len(self._PARAM_CANDS) else ('rdi',)
        best = None
        for pr in cands:
            if pr is None: continue
            r = self._trace_one_reg(sink_instr_idx, sink_func, pr, instructions)
            if best is None or r.confidence > best.confidence: best = r
            if best.final_interval.is_exact(): break
        return best if best else ValueFlowResult(sink_instr_idx=sink_instr_idx, sink_func=sink_func,
            param_reg=cands[0] or 'rdi', final_interval=StridedInterval.top(),
            confidence=0.1, is_heap_related=sink_func in self._HEAP_SINKS)

    def _trace_one_reg(self, sink_instr_idx, sink_func, param_reg, instructions) -> ValueFlowResult:
        visited: Set[str] = set(); trace_path: List[int] = []
        cur_reg = _norm_reg(param_reg); cur_si = StridedInterval.top()
        sk = SourceKind.UNKNOWN; sslot = None; depth = 0
        transformed = False
        _intel = self._detect_intel_syntax(instructions, sink_instr_idx)
        _i = lambda s: int(s, 16) if '0x' in s.lower() else int(s)

        for i in range(sink_instr_idx - 1, max(-1, sink_instr_idx - self._max_depth), -1):
            if i < 0 or depth >= self._max_depth: break
            instr = instructions[i].strip()
            if not instr or instr.startswith(';'): continue
            trace_path.append(i); depth += 1

            # mov $imm,%reg (AT&T) / mov reg,imm (Intel) → 常量
            m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr, re.I)
            if m and _norm_reg(m.group(2)) == cur_reg:
                cur_si = StridedInterval.exact(_i(m.group(1))); sk = SourceKind.CONSTANT; sslot = cur_reg; break
            if _intel:
                m = re.match(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)', instr, re.I)
                if m and _norm_reg(m.group(1)) == cur_reg:
                    cur_si = StridedInterval.exact(_i(m.group(2))); sk = SourceKind.CONSTANT; sslot = cur_reg; break

            # 栈槽读取 (AT&T/Intel)
            m = _STACK_READ.match(instr)
            if m and _norm_reg(m.group(3)) == cur_reg:
                off = _i(m.group(1)); sslot = f'rbp{-off:+d}' if off > 0 else f'rbp{+off:+d}'
                sk = SourceKind.STACK_SLOT
                sv = self._trace_stack_slot(sslot, i, instructions)
                if sv is not None: cur_si = sv
                break
            if _intel:
                m = _INTEL_STACK_READ.match(instr)
                if m and _norm_reg(m.group(1)) == cur_reg:
                    sslot = f'[{m.group(2)}{m.group(3)}]'; sk = SourceKind.STACK_SLOT
                    sv = self._trace_stack_slot_intel(sslot, i, instructions)
                    if sv is not None: cur_si = sv
                    break

            # mov/movsx/movsxd/movzx/movslq reg,reg——语法感知DST
            m = re.match(r'mov(?:sx|sxd|zx|slq|sbq|swq|zbq|zwq|sq|zq)?\s+(\S+),\s*(\S+)', instr, re.I)
            if m:
                r1, r2 = _norm_reg(m.group(1)), _norm_reg(m.group(2))
                src = (r2 if _intel and r1 == cur_reg
                       else (r1 if (not _intel) and r2 == cur_reg else None))
                if src and not (src[0].isdigit() or src.startswith('0x')
                                or src.startswith('[')):
                    if src in visited: break
                    visited.add(cur_reg); cur_reg = src
                    sk = SourceKind.REGISTER; sslot = src; continue

            # lea dst,[base+off] (无index→add)
            m = re.match(r'lea\s+(\w+),\s*\[(\w+)\s*[+\-]\s*(\d+)\s*\*?\s*(\w+)?', instr, re.I)
            if m and _norm_reg(m.group(1)) == cur_reg and not m.group(4):
                cur_reg = _norm_reg(m.group(2)); transformed = True; continue

            # lea写当前寄存器但非简单偏移(index/scale形式)→变换停止
            m = re.match(r'lea\s+(\w+)', instr, re.I)
            if m and _norm_reg(m.group(1)) == cur_reg:
                transformed = True
                break

            # add/sub $imm,%reg (AT&T) / add/sub reg,imm (Intel)
            for op in ('add', 'sub'):
                m = re.match(rf'{op}\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr, re.I)
                if m and _norm_reg(m.group(2)) == cur_reg:
                    imm = _i(m.group(1)) * (-1 if op == 'sub' else 1)
                    cur_si = StridedInterval.exact(imm) if cur_si.is_top() else cur_si.add(imm)
                    transformed = True; break
                if _intel:
                    m = re.match(rf'{op}\s+(\w+),\s*(0x[0-9a-f]+|\d+)', instr, re.I)
                    if m and _norm_reg(m.group(1)) == cur_reg:
                        imm = _i(m.group(2)) * (-1 if op == 'sub' else 1)
                        cur_si = StridedInterval.exact(imm) if cur_si.is_top() else cur_si.add(imm)
                        transformed = True; break

            # imul $imm,%src,%dst (AT&T 3-op) / imul dst,src,imm (Intel)
            m = re.match(r'imul\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+),\s*%?(\w+)', instr, re.I)
            if m and _norm_reg(m.group(3)) == cur_reg:
                transformed = True
                if not cur_si.is_top():
                    cur_si = cur_si.mul(_i(m.group(1)))
                continue
            if _intel:
                m = re.match(r'imul\s+(\w+),\s*(\w+),\s*(0x[0-9a-f]+|\d+)', instr, re.I)
                if m and _norm_reg(m.group(1)) == cur_reg:
                    transformed = True
                    if not cur_si.is_top():
                        cur_si = cur_si.mul(_i(m.group(3)))
                    continue

            # shl $N,%dst (AT&T) / shl dst,count (Intel)
            m = re.match(r'shl\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr, re.I)
            if m and _norm_reg(m.group(2)) == cur_reg:
                transformed = True
                if not cur_si.is_top():
                    cur_si = cur_si.mul(1 << _i(m.group(1)))
                continue
            if _intel:
                m = re.match(r'sh[lr]\s+(\w+),\s*(0x[0-9a-f]+|\d+)', instr, re.I)
                if m and _norm_reg(m.group(1)) == cur_reg:
                    transformed = True
                    if not cur_si.is_top():
                        cur_si = cur_si.mul(1 << _i(m.group(2)))
                    continue

            # xor reg,reg → 0
            m = re.match(r'xor\s+(\w+),\s*\1', instr, re.I)
            if m and _norm_reg(m.group(1)) == cur_reg:
                cur_si = StridedInterval.exact(0); sk = SourceKind.CONSTANT; sslot = 'zero'; break

            # call → 截断(外部输入函数如read/recv→标记external)
            if 'call' in instr.lower():
                for src in ('read','recv','fread','fgets','scanf','gets'):
                    if src in instr.lower(): sk = SourceKind.EXTERNAL; sslot = src; cur_si = StridedInterval.top()
                break
            if re.match(r'(cmp|test)\s+', instr, re.I): continue

        conf = max(0.3, 1.0 - depth / self._max_depth * 0.5) if (
            cur_si.is_exact() or (not cur_si.is_top() and cur_si.lo > 0)) else max(0.1, 0.5 - depth / self._max_depth * 0.4)
        return ValueFlowResult(sink_instr_idx=sink_instr_idx, sink_func=sink_func,
            param_reg=param_reg, final_interval=cur_si, source_kind=sk, source_slot=sslot,
            trace_path=trace_path, confidence=conf, is_heap_related=sink_func in self._HEAP_SINKS,
            transformed=transformed)

    @staticmethod
    def _detect_intel_syntax(instructions, sink_idx):
        """AT&T用%前缀,Intel裸寄存器→扫描附近指令,多数无%→Intel"""
        at, iv = 0, 0
        for j in range(max(0, sink_idx - 10), min(len(instructions), sink_idx + 2)):
            instr = instructions[j].strip().lower()
            if not instr or instr.startswith(';'): continue
            if '%' in instr: at += 1
            else: iv += 1
        return iv > at

    def _trace_stack_slot(self, slot, from_idx, instructions):
        """追踪栈槽位最近写入值(reg/imm), slot格式: 'rbp+24'/'rbp-8'"""
        _i = lambda s: int(s, 16) if '0x' in s.lower() else int(s)
        for i in range(from_idx - 1, max(-1, from_idx - 20), -1):
            if i < 0: break
            instr = instructions[i].strip().lower()
            if not instr: continue
            # AT&T: mov %reg, N(%rbp)
            m = _STACK_WRITE.match(instr)
            if m:
                off = _i(m.group(2)); sk = f'rbp{-off:+d}' if off > 0 else f'rbp{+off:+d}'
                if sk == slot: return self._trace_reg_backward(m.group(1), i, instructions)
            # Intel: mov [rbp+N], reg
            m = _INTEL_STACK_WRITE.match(instr)
            if m and f'[{m.group(1)}{m.group(2)}]' == slot:
                return self._trace_reg_backward(m.group(3), i, instructions)
            # AT&T: mov $imm, N(%rbp)
            m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*([+\-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*%?rbp\s*\)', instr, re.I)
            if m:
                off = _i(m.group(2)); sk = f'rbp{-off:+d}' if off > 0 else f'rbp{+off:+d}'
                if sk == slot: return StridedInterval.exact(_i(m.group(1)))
            # Intel: mov [rbp+N], imm
            m = re.match(r'mov\s+(?:\w+\s+PTR\s+)?\[(rbp|rsp)([+-]\w+)\],\s*(0x[0-9a-f]+|\d+)', instr, re.I)
            if m and f'[{m.group(1)}{m.group(2)}]' == slot:
                return StridedInterval.exact(_i(m.group(3)))
        return None

    def _trace_stack_slot_intel(self, slot, from_idx, instructions):
        """Intel语法栈槽位追踪: slot='[rbp+0x18]'"""
        _i = lambda s: int(s, 16) if '0x' in s.lower() else int(s)
        for i in range(from_idx - 1, max(-1, from_idx - 20), -1):
            if i < 0: break
            instr = instructions[i].strip().lower()
            if not instr: continue
            m = _INTEL_STACK_WRITE.match(instr)
            if m and f'[{m.group(1)}{m.group(2)}]' == slot:
                return self._trace_reg_backward(m.group(3), i, instructions)
            m = re.match(r'mov\s+(?:\w+\s+PTR\s+)?\[(rbp|rsp)([+-]\w+)\],\s*(0x[0-9a-f]+|\d+)', instr, re.I)
            if m and f'[{m.group(1)}{m.group(2)}]' == slot: return StridedInterval.exact(_i(m.group(3)))
        return None

    def _trace_reg_backward(self, reg, from_idx, instructions):
        """反向追踪寄存器值(≤10条)——AT&T+Intel双语法"""
        nr = _norm_reg(reg); _i = lambda s: int(s, 16) if '0x' in s.lower() else int(s)
        _intel = any('%' not in (instructions[j].strip().lower() or '')
                     for j in range(max(0, from_idx - 5), min(len(instructions), from_idx + 1))
                     if instructions[j].strip() and not instructions[j].strip().startswith(';'))
        for i in range(from_idx - 1, max(-1, from_idx - 10), -1):
            if i < 0: break
            instr = instructions[i].strip()
            if not instr: continue
            # AT&T: mov $imm,%reg / Intel: mov reg,imm
            m = re.match(r'mov(?:sx|sxd|zx)?\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr, re.I)
            if m and _norm_reg(m.group(2)) == nr: return StridedInterval.exact(_i(m.group(1)))
            if _intel:
                m = re.match(r'mov(?:sx|sxd|zx)?\s+(\w+),\s*(0x[0-9a-f]+|\d+)', instr, re.I)
                if m and _norm_reg(m.group(1)) == nr: return StridedInterval.exact(_i(m.group(2)))
            # mov reg,reg (AT&T: 第二操作数dst; Intel: 第一操作数dst)
            m = re.match(r'mov(?:sx|sxd|zx|slq|sbq|swq|zbq|zwq|sq|zq)?\s+(\S+),\s*(\S+)', instr, re.I)
            if m:
                r1, r2 = _norm_reg(m.group(1)), _norm_reg(m.group(2))
                if not _intel:
                    if r1 == nr and not r2.startswith('0x') and not r2[0].isdigit():
                        return self._trace_reg_backward(r2, i, instructions)
                else:
                    if r2 == nr and not r1.startswith('0x') and not r1[0].isdigit():
                        return self._trace_reg_backward(r1, i, instructions)
            if _intel:
                m_sr2 = _INTEL_STACK_READ.match(instr)
                if m_sr2 and _norm_reg(m_sr2.group(1)) == nr: continue
        return None

    def trace_alloc_size(self, idx, func, instrs):
        if func == 'calloc':
            # calloc(nmemb, size): 分配量=nmemb×size, 须两参相乘
            nmemb = self.trace_sink_param(idx, func, 0, instrs).final_interval
            size = self.trace_sink_param(idx, func, 1, instrs).final_interval
            if nmemb.is_exact() and size.is_exact():
                return StridedInterval.exact(nmemb.lo * size.lo)
            if not nmemb.is_top() and not size.is_top() and not nmemb.is_bot() and not size.is_bot():
                return StridedInterval(lo=nmemb.lo * size.lo,
                                       hi=nmemb.hi * size.hi,
                                       stride=1, kind=IntervalKind.RANGE)
            return StridedInterval.top()
        return self.trace_sink_param(idx, func, self._ALLOC_SIZE_PARAM.get(func, 0), instrs).final_interval

    def trace_copy_size(self, idx, func, instrs):
        return self.trace_sink_param(idx, func, self._ALLOC_SIZE_PARAM.get(func, 2), instrs).final_interval

    def is_same_source(self, alloc_idx, alloc_func, copy_idx, copy_func, instructions):
        """alloc/copy大小参数同源检测——遍历ABI候选寄存器"""
        ap = self._ALLOC_SIZE_PARAM.get(alloc_func, 0); cp = self._ALLOC_SIZE_PARAM.get(copy_func, 2)
        a_cands = self._PARAM_CANDS[ap] if ap < len(self._PARAM_CANDS) else ('rdi',)
        c_cands = self._PARAM_CANDS[cp] if cp < len(self._PARAM_CANDS) else ('rdx',)
        for ar in a_cands:
            if ar is None: continue
            ar_r = self._trace_one_reg(alloc_idx, alloc_func, ar, instructions)
            # TODO: transformed一刀切禁用同源判定, 对malloc(len+8);memcpy(len+8)这类同变换场景过保守;
            #       可记录变换序列identity, 相同变换序列仍可判同源
            if ar_r.transformed:
                continue  # 经过算术变换→来源身份不可直接等同
            for cr in c_cands:
                if cr is None: continue
                cr_r = self._trace_one_reg(copy_idx, copy_func, cr, instructions)
                if cr_r.transformed:
                    continue
                sk = SourceKind
                if ar_r.source_kind == cr_r.source_kind:
                    if (ar_r.source_kind == sk.STACK_SLOT and ar_r.source_slot == cr_r.source_slot):
                        return (True, f"same stack: {ar_r.source_slot}")
                    if (ar_r.source_kind == sk.REGISTER and ar_r.source_slot == cr_r.source_slot):
                        return (True, f"same reg: {ar_r.source_slot}")
                    if (ar_r.source_kind == sk.CONSTANT and ar_r.final_interval.is_exact()
                        and cr_r.final_interval.is_exact() and ar_r.final_interval.lo == cr_r.final_interval.lo):
                        return (True, f"same const: {ar_r.final_interval.lo}")
        ar_b = self.trace_sink_param(alloc_idx, alloc_func, ap, instructions)
        cr_b = self.trace_sink_param(copy_idx, copy_func, cp, instructions)
        return (False, f"alloc={ar_b.source_kind.value}/{ar_b.source_slot} copy={cr_b.source_kind.value}/{cr_b.source_slot}")
