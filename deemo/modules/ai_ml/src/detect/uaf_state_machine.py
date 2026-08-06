# created: 2026-08-06
# UAF状态机检测——追踪内存分配→释放→使用的完整生命周期
# 与gnn_vulnerability_detector.py的纯函数名匹配不同，
# 此处用状态机建模同一指针对象的状态转移
#
# 状态转移: UNSEEN → ALLOCATED → FREED → USED_AFTER_FREE
# 仅当同一个分配点的内存在free后再次被dereference时才报告
# 排除了: free(NULL), free后立即函数返回(无后续use), free不同指针

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class PtrState(Enum):
    UNSEEN = 0
    ALLOCATED = 1     # malloc/calloc/realloc返回
    FREED = 2         # free已调用
    USED = 3          # 被dereference/作为参数传递给其他函数


@dataclass
class PointerTracker:
    """单个指针对象的生命周期追踪"""
    ptr_name: str                    # 寄存器/变量名(如'rax','rbx')
    alloc_site: int                  # 分配指令地址
    alloc_func: str                  # malloc/calloc/realloc
    free_site: Optional[int] = None  # 释放指令地址
    use_sites: List[int] = field(default_factory=list)  # 使用点地址列表
    state: PtrState = PtrState.UNSEEN
    is_vulnerable: bool = False      # 是否存在free后use


class UAFStateMachine:
    """UAF状态机——在函数CFG内追踪指针生命周期。

    三个关键转移:
      ALLOC→FREE: mov rdi, ptr; call free → ptr状态变为FREED
      FREE→USE: ptr在FREED后被load/store/call引用 → UAF
      ALLOC→USE: 正常使用(不构成漏洞)

    跨函数追踪: 若指针通过参数传递给子函数且在子函数中被释放，
    则在父函数中追踪该指针的后续使用。
    """

    def __init__(self):
        self._alloc_pattern = re.compile(
            r'\b(malloc|calloc|realloc)\b', re.I)
        self._free_pattern = re.compile(
            r'\b(free|kfree|delete)\b', re.I)
        self._ptr_ref_pattern = re.compile(
            r'\[(\w+)\]|mov\s+\w+,\s*\[(\w+)\]|call\s+\w+.*\(.*\)',
            re.I)

    def analyze_function(self,
                          instructions: List[str],
                          bb_boundaries: List[Tuple[int, int]],
                          cfg_edges: List[Tuple[int, int]],
                          func_args: Optional[List[str]] = None
                          ) -> List[PointerTracker]:
        """分析单个函数内的所有指针生命周期。

        Args:
            instructions: 汇编指令列表
            bb_boundaries: 基本块边界 [(start_idx, end_idx), ...]
            cfg_edges: 控制流边 [(from_bb, to_bb), ...]
            func_args: 函数参数(用于追踪外部传入的指针)

        Returns:
            所有被追踪的PointerTracker，其中is_vulnerable=True的为UAF
        """
        trackers: Dict[str, PointerTracker] = {}
        n = len(instructions)

        for i in range(n):
            instr = instructions[i].strip()
            if not instr or instr.startswith(';'):
                continue

            # 分配检测: mov reg, call malloc → reg状态=ALLOCATED
            alloc_m = self._alloc_pattern.search(instr)
            if alloc_m and 'call' in instr:
                # 查找前一条指令——通常将返回值mov到寄存器
                if i > 0:
                    prev = instructions[i-1].strip().lower()
                    m_mov = re.match(r'mov\s+(\w+),\s*rax', prev) if 'call' in instr else None
                    if m_mov:
                        ptr = m_mov.group(1)
                    else:
                        ptr = 'rax'  # 默认返回值在rax
                else:
                    ptr = 'rax'

                trackers[ptr] = PointerTracker(
                    ptr_name=ptr, alloc_site=i,
                    alloc_func=alloc_m.group(1),
                    state=PtrState.ALLOCATED)

            # 释放检测: call free → 追踪传递给free的指针(通常在rdi中)
            free_m = self._free_pattern.search(instr)
            if free_m and 'call' in instr:
                freed_ptr = self._resolve_free_target(
                    instructions, i)
                if freed_ptr and freed_ptr in trackers:
                    t = trackers[freed_ptr]
                    if t.state == PtrState.ALLOCATED:
                        t.state = PtrState.FREED
                        t.free_site = i
                elif freed_ptr:
                    # 跨函数追踪: 指针在外部分配→此处释放→创建追踪器
                    t = PointerTracker(
                        ptr_name=freed_ptr, alloc_site=-1,
                        alloc_func='external',
                        free_site=i, state=PtrState.FREED)
                    trackers[freed_ptr] = t

            # 使用检测: 被FREED的指针出现在load/store/call中
            for ptr_name, tracker in trackers.items():
                if tracker.state != PtrState.FREED:
                    continue
                if self._is_ptr_used(instr, ptr_name):
                    tracker.use_sites.append(i)
                    tracker.state = PtrState.USED
                    tracker.is_vulnerable = True

        return [t for t in trackers.values() if t.state in (PtrState.FREED, PtrState.USED)]

    def _resolve_free_target(self,
                              instructions: List[str],
                              free_idx: int) -> Optional[str]:
        """解析free调用的目标指针——查找free之前的mov rdi, ptr"""
        for j in range(free_idx - 1, max(-1, free_idx - 4), -1):
            instr = instructions[j].strip().lower()
            # mov rdi, reg
            m = re.match(r'mov\s+rdi,\s*(\w+)', instr)
            if m:
                return m.group(1)
            # lea rdi, [reg+offset]
            m = re.match(r'lea\s+rdi,\s*\[(\w+)', instr)
            if m:
                return m.group(1)
        return None

    def _is_ptr_used(self, instr: str, ptr_name: str) -> bool:
        """判断指令是否使用了指定指针"""
        # mov reg, [ptr] — 从指针读
        if re.search(rf'mov\s+\w+,\s*\[{ptr_name}\]', instr, re.I):
            return True
        # mov [ptr], reg — 向指针写
        if re.search(rf'mov\s+\[{ptr_name}\],\s*\w+', instr, re.I):
            return True
        # call — 将ptr作为参数传递
        if 'call' in instr.lower() and re.search(
            rf'\b{ptr_name}\b', instr, re.I):
            return True
        return False

    def cross_function_analysis(self,
                                 caller_instrs: List[str],
                                 callee_trackers: List[PointerTracker],
                                 call_sites: List[int]
                                 ) -> List[PointerTracker]:
        """跨函数扩展——若子函数中有UAF，检查父函数中是否继续使用该指针。

        Args:
            caller_instrs: 父函数指令
            callee_trackers: 子函数中检测到的UAF追踪器
            call_sites: 父函数中调用子函数的指令索引

        Returns:
            父函数层级的新追踪器(若发现cross-function UAF)
        """
        new_trackers = []
        for tracker in callee_trackers:
            if not tracker.is_vulnerable:
                continue
            for call_site in call_sites:
                # 子函数free了ptr→父函数call之后是否还使用ptr?
                for i in range(call_site + 1, len(caller_instrs)):
                    if self._is_ptr_used(caller_instrs[i], tracker.ptr_name):
                        t = PointerTracker(
                            ptr_name=tracker.ptr_name,
                            alloc_site=tracker.alloc_site,
                            alloc_func=tracker.alloc_func,
                            free_site=call_site,
                            use_sites=[i],
                            state=PtrState.USED,
                            is_vulnerable=True)
                        new_trackers.append(t)
                        break
        return new_trackers
