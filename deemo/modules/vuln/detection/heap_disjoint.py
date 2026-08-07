# coding: utf-8
import re, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
_log = logging.getLogger(__name__)

@dataclass
class AllocSite:
    site_id: int; insn_idx: int; address: int
    alloc_func: str = ""; size_value: int = 0
    size_reg: str = ""; return_reg: str = "rax"

@dataclass
class WriteSite:
    insn_idx: int; address: int; write_func: str = ""
    dst_reg: str = ""; size_value: int = 0; size_reg: str = ""
    linked_alloc_site: int = -1

@dataclass
class DisjointReport:
    alloc_sites: List = field(default_factory=list)
    write_sites: List = field(default_factory=list)
    confirmed_pairs: List = field(default_factory=list)
    filtered_pairs: List = field(default_factory=list)
    fp_reduction_pct: float = 0.0

class HeapDisjointAnalyzer:
    """堆不相交分析——追踪malloc-memcpy指针-分配点关联以滤除FP。
    基于Guo et al. ISSTA 2024堆不相交假设: malloc返回不重叠区域,
    仅同allocation site的(alloc,write)对才可能真实溢出。"""
    _ALLOC_FUNCS = {"malloc","calloc","realloc"}
    _WRITE_FUNCS = {"memcpy","memmove","strcpy","strncpy","memset"}
    _ARG_REGS = ["rdi","rsi","rdx","rcx","r8","r9"]
    _REG32 = {"edi":"rdi","esi":"rsi","edx":"rdx","ecx":"rcx","eax":"rax","ebx":"rbx"}

    def analyze(self, instructions, func_name="", base_addr=0x400000):
        report = DisjointReport()
        if not instructions: return report
        site_id = 0
        for i, insn in enumerate(instructions):
            callee = self._callee(insn)
            if callee and any(a in callee for a in self._ALLOC_FUNCS):
                sz = self._trace_size(instructions, i, 0)
                report.alloc_sites.append(AllocSite(site_id=site_id,insn_idx=i,address=self._addr(insn,base_addr,i),alloc_func=callee,size_value=sz,size_reg="rdi"))
                site_id += 1
        for i, insn in enumerate(instructions):
            callee = self._callee(insn)
            if callee and any(w in callee for w in self._WRITE_FUNCS):
                dr = self._trace_arg(instructions, i, 0)
                sz = self._trace_size(instructions, i, 2)
                ws = WriteSite(insn_idx=i,address=self._addr(insn,base_addr,i),write_func=callee,dst_reg=dr,size_value=sz,size_reg="rdx")
                ws.linked_alloc_site = self._link(instructions, i, dr, report.alloc_sites)
                report.write_sites.append(ws)
        for ws in report.write_sites:
            if ws.linked_alloc_site < 0:
                report.filtered_pairs.append((-1, ws.insn_idx, "dst未追踪到alloc")); continue
            alloc = next((a for a in report.alloc_sites if a.site_id==ws.linked_alloc_site),None)
            if not alloc: report.filtered_pairs.append((ws.linked_alloc_site,ws.insn_idx,"alloc不存在")); continue
            if alloc.size_value>0 and ws.size_value>0:
                if ws.size_value > alloc.size_value: report.confirmed_pairs.append((alloc.site_id,ws.insn_idx))
                else: report.filtered_pairs.append((alloc.site_id,ws.insn_idx,f"写入{ws.size_value}小于等于分配{alloc.size_value}"))
            else: report.confirmed_pairs.append((alloc.site_id,ws.insn_idx))
        t = len(report.confirmed_pairs)+len(report.filtered_pairs)
        report.fp_reduction_pct = round(len(report.filtered_pairs)/max(t,1)*100,1)
        return report

    def _link(self, insns, write_idx, src_of_dst, alloc_sites):
        if not src_of_dst or src_of_dst=="unknown": return -1
        # 直接路径: rdi来自rax(即malloc返回值) → 搜索call malloc
        if src_of_dst == 'rax':
            for k in range(write_idx-1, max(-1,write_idx-25), -1):
                c = self._callee(insns[k])
                if c and any(a in c for a in self._ALLOC_FUNCS):
                    for a in alloc_sites:
                        if a.insn_idx == k: return a.site_id
            return -1
        # 间接路径: rdi来自rbx, rbx来自rax → 搜索mov src_of_dst, rax
        for j in range(write_idx-1, max(-1,write_idx-25), -1):
            insn = insns[j].lower().strip()
            if ":" in insn[:20]: insn = insn.split(":",1)[1].strip()
            if f"mov {src_of_dst}, rax" in insn or f"mov {src_of_dst},rax" in insn:
                for k in range(j-1, max(-1,j-3), -1):
                    c = self._callee(insns[k])
                    if c and any(a in c for a in self._ALLOC_FUNCS):
                        for a in alloc_sites:
                            if a.insn_idx == k: return a.site_id
        return -1

    def _trace_size(self, insns, call_idx, arg_idx):
        if arg_idx>=len(self._ARG_REGS): return 0
        t64 = self._ARG_REGS[arg_idx]
        names = {t64}|{k for k,v in self._REG32.items() if v==t64}
        for j in range(call_idx-1, max(-1,call_idx-10), -1):
            insn = insns[j].lower().strip()
            if ":" in insn[:20]: insn = insn.split(":",1)[1].strip()
            for tgt in names:
                if f"mov {tgt}," in insn or f"mov {tgt}, " in insn:
                    parts = insn.replace(","," ").split()
                    found=False
                    for p in parts:
                        if p==tgt and not found: found=True; continue
                        if found:
                            try: return int(p,16) if p.startswith("0x") else int(p)
                            except ValueError: return 0
        return 0

    def _trace_arg(self, insns, call_idx, arg_idx):
        if arg_idx>=len(self._ARG_REGS): return "unknown"
        t = self._ARG_REGS[arg_idx]
        for j in range(call_idx-1, max(-1,call_idx-6), -1):
            insn = insns[j].lower().strip()
            if ":" in insn[:20]: insn = insn.split(":",1)[1].strip()
            m = re.match(rf"mov\s+{t}\s*,\s*(\w+)", insn)
            if m: return m.group(1)
        return "unknown"

    def _callee(self, insn):
        s=insn.strip()
        if ":" in s[:20]: s=s.split(":",1)[1].strip()
        p=s.split()
        return p[1].lower().split("@")[0] if len(p)>=2 and p[0].lower()=="call" else ""

    def _addr(self, insn, base, idx):
        s=insn.strip()
        if ":" in s[:20]:
            try: return int(s.split(":")[0],16)
            except ValueError: pass
        return base+idx*4

__all__ = ["AllocSite","WriteSite","DisjointReport","HeapDisjointAnalyzer"]
