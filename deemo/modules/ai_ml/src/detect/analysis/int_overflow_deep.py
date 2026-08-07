# 整数溢出深层分析——值范围传播+分配关联+guard检测
# 核心: 轻量区间追踪(int→size_t转换/符号扩展)+ 守卫(cmp+jcc)识别 + 分配因果链
# 理论: 区间抽象的二进制级简化实现

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class OverflowRisk(Enum):
    NONE = 'none'
    POSSIBLE = 'possible'
    LIKELY = 'likely'
    CONFIRMED = 'confirmed'


@dataclass
class IntOpContext:
    op_idx: int
    operation: str
    src_reg: str = ""
    dst_reg: str = ""
    imm_val: Optional[int] = None
    reg_val_range: Tuple[int, int] = (0, 0)
    has_guard: bool = False
    guard_cond: str = ""
    feeds_malloc: bool = False
    result_reg: str = ""


@dataclass
class DeepOverflowReport:
    func_name: str
    risk: OverflowRisk
    contexts: List[IntOpContext] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0


class IntOverflowDeepAnalyzer:
    """整数溢出深层分析器——区间追踪+守卫检测+分配因果链。

    与integer_overflow_check.py的区别: 引入操作数值范围追踪和守卫检测，
    而非仅检查jo/jc指令是否存在。-O2优化通常消除显式溢出检查但守卫仍在。
    """

    _ARITH_OPS = re.compile(r'\b(add|sub|imul|shl|sal)\b', re.I)
    _JCC_OPS = {'jle', 'jge', 'jbe', 'jae', 'jl', 'jg', 'jb', 'ja',
                'jne', 'je', 'jns', 'js'}
    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}

    def __init__(self, max_scan_dist: int = 15):
        self._max_dist = max_scan_dist

    def analyze_function(self, instructions: List[str],
                         func_name: str = "") -> List[DeepOverflowReport]:
        n = len(instructions)
        if n < 5:
            return []
        reports = []
        for i in range(n):
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith(';'):
                continue
            m = self._ARITH_OPS.search(instr)
            if not m:
                continue
            ctx = self._build_context(instructions, i, m.group(1))
            if ctx is None:
                continue
            risk, evidence = self._assess_overflow_risk(ctx)
            if risk != OverflowRisk.NONE:
                reports.append(DeepOverflowReport(
                    func_name=func_name, risk=risk,
                    contexts=[ctx], evidence=evidence,
                    confidence=self._risk_to_confidence(risk)))
        return reports

    def _build_context(self, instructions: List[str],
                       idx: int, op: str) -> Optional[IntOpContext]:
        instr = instructions[idx].strip().lower()
        ctx = IntOpContext(op_idx=idx, operation=op)
        # 双语法: 按逗号分割操作数, AT&T=op src,dst, Intel=op dst,src
        is_att = '%' in instr
        # 取操作码后的部分
        body = instr[len(op):].strip()
        if ',' not in body:
            return None  # 单操作数无法分析, 排除inc/dec/not/neg
        lhs, rhs = body.split(',', 1)
        lhs_parts = [t for t in lhs.strip().split() if t]
        rhs_parts = [t for t in rhs.strip().split() if t]
        # 立即数: AT&T=$前缀, Intel=裸数字
        for tok in lhs_parts + rhs_parts:
            tc = tok.strip().lstrip('%$')
            if re.match(r'^-?(?:0x[0-9a-f]+|\d+)$', tc):
                ctx.imm_val = int(tc, 16) if '0x' in tc else int(tc)
        # 目标寄存器
        if is_att:
            dst_tokens = rhs_parts      # AT&T: dst在逗号后
            src_tokens = lhs_parts      # AT&T: src在逗号前
        else:
            dst_tokens = lhs_parts      # Intel: dst在逗号前
            src_tokens = rhs_parts      # Intel: src在逗号后
        # dst_reg: 第一个非立即数token
        for t in dst_tokens:
            tc = t.strip().lstrip('%')
            if re.match(r'^[a-z]{2,5}$', tc) and tc not in ('ptr','qword','dword','word','byte'):
                ctx.dst_reg = tc
                ctx.result_reg = tc
                break
        # src_reg
        for t in src_tokens:
            tc = t.strip().lstrip('%')
            if re.match(r'^[a-z]{2,5}$', tc) and tc not in ('ptr','qword','dword','word','byte'):
                ctx.src_reg = tc
                break
        if not ctx.dst_reg:
            return None
        if ctx.dst_reg.lstrip('%') in ('rsp', 'esp', 'rbp', 'ebp'):
            return None
        ctx.reg_val_range = self._trace_value_range(instructions, idx, ctx.dst_reg)
        ctx.has_guard, ctx.guard_cond = self._detect_guard(instructions, idx)
        ctx.feeds_malloc = self._check_feeds_alloc(instructions, idx, ctx.dst_reg)
        return ctx

    def _trace_value_range(self, instructions: List[str],
                           idx: int, reg: str) -> Tuple[int, int]:
        lo, hi = 0, 2**31 - 1
        r = re.escape(reg)
        for j in range(max(0, idx - 8), idx):
            instr = instructions[j].strip().lower()
            # 双ABI: AT&T cmp $imm,%reg 或 Intel cmp reg,imm
            m = re.search(rf'cmp\s+\$?(0x[0-9a-f]+|\d+),\s*%?{r}', instr)
            if not m:
                m = re.search(rf'cmp\s+%?{r},\s*(0x[0-9a-f]+|\d+)', instr)
            if m:
                hi = min(hi, int(m.group(1), 16 if '0x' in m.group(1) else 10))
            # 双ABI: AT&T mov $imm,%reg 或 Intel mov reg,imm
            m = re.search(rf'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?{r}', instr)
            if not m:
                m = re.search(rf'mov\s+%?{r},\s*(0x[0-9a-f]+|\d+)', instr)
            if m:
                lo = hi = int(m.group(1), 16 if '0x' in m.group(1) else 10)
        return lo, hi

    def _detect_guard(self, instructions: List[str],
                      idx: int) -> Tuple[bool, str]:
        for j in range(max(0, idx - 6), idx):
            if re.search(r'(cmp|test)\s+', instructions[j].strip().lower()):
                for k in range(j + 1, min(j + 4, len(instructions))):
                    jcc = instructions[k].strip().lower()
                    m = re.match(r'(j[a-z]+)\s+', jcc)
                    if m and m.group(1) in self._JCC_OPS:
                        return True, m.group(1)
        return False, ""

    def _check_feeds_alloc(self, instructions: List[str],
                           idx: int, dst_reg: str = "") -> bool:
        """算术结果→rdi→alloc参数? 追踪result_reg到rdi的MOV链, 双ABI"""
        result_reg = dst_reg.lstrip('%')
        if result_reg in ('rsp', 'esp', 'rbp', 'ebp'):
            return False
        current = result_reg
        for j in range(idx + 1, min(idx + self._max_dist, len(instructions))):
            instr = instructions[j].strip().lower()
            if 'call' in instr and any(af in instr for af in self._ALLOC_FUNCS):
                if current in ('rdi', 'edi'):
                    return True
                cur2 = result_reg
                for k in range(idx + 1, j):
                    ik = instructions[k].strip().lower()
                    # AT&T: mov %cur2,%rdi 或 Intel: mov rdi,cur2
                    if re.search(rf'mov\s+%?{re.escape(cur2)},\s*%?(?:rdi|edi)', ik):
                        return True
                    if re.search(rf'mov\s+%?(?:rdi|edi),\s*%?{re.escape(cur2)}', ik):
                        return True
                    # AT&T: mov %cur2,%reg
                    m = re.match(rf'mov\s+%?{re.escape(cur2)},\s*%?(\w+)', ik)
                    if not m:
                        m = re.match(rf'mov\s+%?(\w+),\s*%?{re.escape(cur2)}', ik)
                    if m:
                        cur2 = m.group(1)
                return cur2 in ('rdi', 'edi')
            # 双ABI: AT&T mov %cur,%rdi 或 Intel mov rdi,cur
            if re.search(rf'mov\s+%?{re.escape(current)},\s*%?(?:rdi|edi)', instr):
                current = 'rdi'
                continue
            if re.search(rf'mov\s+%?(?:rdi|edi),\s*%?{re.escape(current)}', instr):
                current = 'rdi'
                continue
            # 双ABI: AT&T mov %cur,%reg 或 Intel mov reg,cur
            m = re.match(rf'mov\s+%?{re.escape(current)},\s*%?(\w+)', instr)
            if not m:
                m = re.match(rf'mov\s+%?(\w+),\s*%?{re.escape(current)}', instr)
            if m:
                current = m.group(1)
        return False

    def _assess_overflow_risk(self, ctx: IntOpContext
                              ) -> Tuple[OverflowRisk, List[str]]:
        evidence = []
        lo, hi = ctx.reg_val_range
        # add溢出判定
        if ctx.operation == 'add' and ctx.imm_val is not None:
            max_after = hi + ctx.imm_val
            if max_after <= 2**31 - 1 and ctx.imm_val < 1000:
                return OverflowRisk.NONE, [
                    f"add {ctx.imm_val} to [{lo},{hi}] → max={max_after} < 2^31"]
            if max_after > 2**31 - 1:
                evidence.append(f"add {ctx.imm_val} to hi={hi} → {max_after} > INT_MAX")
        # sub下溢判定
        if ctx.operation == 'sub' and ctx.imm_val is not None:
            min_after = lo - ctx.imm_val
            if min_after < 0:
                evidence.append(f"sub {ctx.imm_val} from lo={lo} → {min_after} 下溢")
        # imul溢出
        if ctx.operation == 'imul':
            if ctx.imm_val and ctx.imm_val > 1:
                if hi * ctx.imm_val > 2**31 - 1:
                    evidence.append(f"imul×{ctx.imm_val}: [{lo},{hi}] → >INT_MAX")
            else:
                evidence.append("imul: 非立即数乘数→可能溢出")
        # shl溢出
        if ctx.operation == 'shl':
            if ctx.imm_val and ctx.imm_val >= 31:
                evidence.append(f"shl by {ctx.imm_val} ≥ 31 → 必然溢出")
            elif ctx.imm_val and ctx.imm_val >= 16:
                evidence.append(f"shl by {ctx.imm_val} ≥ 16 → 高溢出风险")
            elif 'cl' in (ctx.src_reg or ''):
                evidence.append("shl by cl → 移位量可变")
        # 综合评分
        if not evidence:
            return OverflowRisk.NONE, []
        if ctx.feeds_malloc:
            if ctx.operation == 'sub' and ctx.imm_val:
                risk = (OverflowRisk.CONFIRMED if lo < ctx.imm_val
                        else OverflowRisk.LIKELY)
            else:
                risk = (OverflowRisk.CONFIRMED
                        if (ctx.imm_val and ctx.imm_val > 32768)
                        else OverflowRisk.LIKELY)
            evidence.append("溢出→malloc参数→堆溢出前驱")
        elif ctx.has_guard:
            risk = OverflowRisk.POSSIBLE
            evidence.append(f"guard({ctx.guard_cond})→风险降低")
        else:
            risk = OverflowRisk.LIKELY
            evidence.append("无guard+无显式溢出检查")
        return risk, evidence

    def _risk_to_confidence(self, risk: OverflowRisk) -> float:
        return {OverflowRisk.NONE: 0.0, OverflowRisk.POSSIBLE: 0.3,
                OverflowRisk.LIKELY: 0.65, OverflowRisk.CONFIRMED: 0.9
                }.get(risk, 0.0)

    def filter_actionable(self, reports: List[DeepOverflowReport]
                          ) -> List[DeepOverflowReport]:
        return [r for r in reports
                if r.risk in (OverflowRisk.CONFIRMED, OverflowRisk.LIKELY)]
