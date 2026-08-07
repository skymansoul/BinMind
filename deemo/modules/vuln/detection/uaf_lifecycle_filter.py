# coding: utf-8
import re, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

@dataclass
class UafLifecycleResult:
    confirmed: List = field(default_factory=list)  # [(free_idx, deref_idx)]
    filtered: List = field(default_factory=list)   # [(free_idx, deref_idx, reason)]
    fp_reduction_pct: float = 0.0

class UafLifecycleFilter:
    """UAF生命周期过滤器——基于alloc/free配对时序削减误报。

    当前detect_uaf仅检测free后deref模式, 不区分:
    (a) free(ptrA), malloc→复用ptrA, 使用ptrA ← 合法, 当前误报为UAF
    (b) free(ptrA), 无重新分配, 使用ptrA ← 真实UAF

    本过滤器在detect_uaf基础上增加时序验证:
    - 若free和deref之间存在对同一寄存器的重新赋值(mov ptr, new_val)→ 滤除
    - 若free和deref之间存在新的malloc调用且返回值存入同一寄存器→ 滤除
    - 仅保留free后、下次alloc前、无重新赋值的deref → 确认UAF

    方法依据: Lancet 所有权语义——指针在free后失去cell owner,
    新的alloc创建新的cell owner, 旧指针变为dangling。
    """
    _ALLOC_FUNCS = {"malloc", "calloc", "realloc"}
    _FREE_FUNCS = {"free"}

    def filter(self, instructions, uaf_candidates, func_name=""):
        result = UafLifecycleResult()
        if not uaf_candidates: return result

        # 对每个UAF候选做时序验证
        for cand in uaf_candidates:
            free_idx = getattr(cand, 'free_insn_idx', -1)
            use_idx = getattr(cand, 'use_insn_idx', -1)
            ptr_reg = getattr(cand, 'dangling_pointer', '')
            if free_idx < 0 or use_idx < 0:
                result.confirmed.append((free_idx, use_idx)); continue

            # 检查free→use之间是否有重新赋值
            reassigned = False
            new_alloc = False
            for j in range(free_idx + 1, use_idx):
                insn = instructions[j].lower().strip()
                if ":" in insn[:20]: insn = insn.split(":",1)[1].strip()
                # 检测重新赋值: mov ptr_reg, <new_val> 或 lea ptr_reg, <addr>
                if ptr_reg and f"mov {ptr_reg}," in insn:
                    parts = insn.replace(","," ").split()
                    if len(parts)>=3 and parts[1] == ptr_reg:
                        src = parts[2]
                        if src != ptr_reg: reassigned = True; break
                if ptr_reg and f"lea {ptr_reg}," in insn:
                    reassigned = True; break
                # 检测新的malloc并将返回值存入ptr_reg
                callee = self._callee(insn)
                if callee and any(a in callee for a in self._ALLOC_FUNCS):
                    # 检查下一条是否为mov ptr_reg, rax
                    if j+1 < len(instructions):
                        ni = instructions[j+1].lower().strip()
                        if ":" in ni[:20]: ni = ni.split(":",1)[1].strip()
                        if f"mov {ptr_reg}, rax" in ni or f"mov {ptr_reg},rax" in ni:
                            new_alloc = True; break

            if reassigned:
                result.filtered.append((free_idx, use_idx, "free后重新赋值"))
            elif new_alloc:
                result.filtered.append((free_idx, use_idx, "free后新alloc复用指针"))
            else:
                result.confirmed.append((free_idx, use_idx))

        t = len(result.confirmed) + len(result.filtered)
        result.fp_reduction_pct = round(len(result.filtered)/max(t,1)*100, 1)
        return result

    def _callee(self, insn):
        s = insn.strip()
        if ":" in s[:20]: s = s.split(":",1)[1].strip()
        p = s.split()
        return p[1].lower().split("@")[0] if len(p)>=2 and p[0].lower()=="call" else ""

__all__ = ["UafLifecycleResult","UafLifecycleFilter"]
