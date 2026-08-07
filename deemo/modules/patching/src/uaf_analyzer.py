# UAF检测深度强化 — 指针生命周期追踪替代计数匹配
"""Use-After-Free 检测器 — 基于指针生命周期的分析。

旧版 memory_safety_cert 通过比较 alloc/free 指令数量来推断 UAF/DF。
此方法的致命缺陷：
  - 无法区分"同一个指针的free在use之后"和"不同指针的正常free"
  - 无法追踪跨基本块的指针传递
  - alloc和free数量相等即判定为安全(漏掉UAF)

本模块升级为：在汇编级别追踪单个指针对象的生命周期。
追踪 alloc 分配的指针值在各寄存器间的移动，在 free 调用点标记
该对象为"已释放"，后续任何对该指针寄存器或派生地址的内存访问
即标记为 UAF。

方法依据: Undangle 的 demand-driven
         指针生命周期分析思想，但操作在汇编而非 LLVM IR。

限制：
  - 不追踪堆内存别名(malloc返回的指针存入内存后又加载到另一寄存器)
  - 保守策略：未追踪到的指针不报告（宁可漏报，不增误报）
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict

_log = logging.getLogger(__name__)


@dataclass
class PointerObject:
    """一个动态分配的指针对象。"""
    obj_id: int = 0
    alloc_line: int = 0          # malloc调用所在行
    alloc_func: str = ""         # malloc / calloc / realloc
    # 此指针在哪些寄存器中存在过
    reg_locations: Dict[int, str] = field(default_factory=dict)
    free_line: int = -1          # -1表示未释放
    is_freed: bool = False
    # use-after-free: 在free之后仍被访问的行
    uaf_lines: List[int] = field(default_factory=list)


@dataclass
class UAFReport:
    """UAF检测报告。"""
    function_name: str = ""
    objects: List[PointerObject] = field(default_factory=list)
    total_allocs: int = 0
    uaf_count: int = 0           # 确认的UAF数量
    false_positive_candidates: int = 0  # alloc+free+无后续使用→可能是安全释放
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'allocs': self.total_allocs,
            'uaf_count': self.uaf_count,
            'fp_candidates': self.false_positive_candidates,
            'findings': self.findings[:10],
        }


# 指针生命周期追踪器

class PointerLifecycleTracker:
    """逐指令追踪指针对象的生命周期。

    流程：
      1. 扫描所有 malloc 调用点 → 创建 PointerObject
      2. 追踪返回值寄存器 rax 在后续指令中的移动
      3. 扫描所有 free 调用点 → 匹配对应的 PointerObject 并标记释放
      4. 在 free 之后若该指针仍被访问 → 标记 UAF
    """

    _ALLOC_FUNCS = re.compile(r'\bcall\s+(malloc|calloc|realloc|_Znwm|_Znam)\b', re.I)
    _FREE_FUNCS = re.compile(r'\bcall\s+(free|delete|_ZdlPv|_ZdaPv)\b', re.I)

    def analyze(self, asm_lines: List[str],
                function_name: str = "") -> UAFReport:
        report = UAFReport(function_name=function_name)
        objects = []
        obj_counter = 0

        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower().replace(',', ' ')

            # malloc → 创建指针对象
            if self._ALLOC_FUNCS.search(stripped):
                obj = PointerObject(obj_id=obj_counter, alloc_line=i,
                                   alloc_func=self._extract_func(stripped))
                obj_counter += 1
                # rax 持有返回的指针
                obj.reg_locations[i] = 'rax'
                objects.append(obj)
                report.total_allocs += 1
                continue

            # free → 标记对应对象为已释放
            free_match = self._FREE_FUNCS.search(stripped)
            if free_match:
                freed_reg = self._find_free_arg(asm_lines, i)
                for obj in objects:
                    if not obj.is_freed and self._matches_pointer(obj, freed_reg, i, asm_lines):
                        obj.is_freed = True
                        obj.free_line = i
                        break
                continue

            # 追踪指针移动 (mov reg, rax 或 mov reg, ptr_reg)
            for obj in objects:
                if obj.is_freed:
                    # 已释放：检查是否有对该指针的访问
                    for reg in list(obj.reg_locations.values()):
                        if self._accesses_pointer(stripped, reg, i, obj):
                            obj.uaf_lines.append(i)
                            report.uaf_count += 1
                            report.findings.append(
                                "UAF @ line %d: 指针在line %d free后仍在line %d被访问" % (
                                    i, obj.free_line, i))
                else:
                    # 未释放：追踪指针移动
                    self._track_pointer_move(stripped, i, obj, asm_lines)

        report.objects = objects
        report.false_positive_candidates = sum(
            1 for o in objects if o.is_freed and len(o.uaf_lines) == 0)
        return report

    def _find_free_arg(self, asm: List[str], free_idx: int) -> str:
        """找 free 调用前设置 rdi 的寄存器。"""
        for j in range(free_idx - 1, max(free_idx - 5, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(r'\bmov\s+rdi,?\s*(\w+)', line)
            if m:
                return m.group(1)
        return 'rdi'

    def _matches_pointer(self, obj: PointerObject, reg: str,
                         free_idx: int, asm: List[str]) -> bool:
        """检查 free(reg) 是否释放了 obj 指向的内存。"""
        for line_idx, loc_reg in obj.reg_locations.items():
            if loc_reg == reg and line_idx < free_idx:
                return True
        return False

    def _track_pointer_move(self, inst: str, idx: int,
                            obj: PointerObject, asm: List[str]):
        """追踪指针在寄存器间的移动。mov dst, ptr_reg → dst也持有指针。"""
        parts = inst.strip().lower().replace(',', ' ').split()
        if len(parts) < 3:
            return
        mnemonic = parts[0]
        if mnemonic not in ('mov', 'movzx', 'movsx', 'lea'):
            return
        dst = parts[1].rstrip(',')
        src = parts[2]
        if not re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3})$', dst):
            return
        for loc_reg in list(obj.reg_locations.values()):
            if src == loc_reg:
                obj.reg_locations[idx] = dst
                break

    def _accesses_pointer(self, inst: str, reg: str, idx: int,
                          obj: PointerObject) -> bool:
        """检查指令是否通过该指针寄存器访问内存。"""
        # mov [reg], ... 或 mov ..., [reg] → 通过指针访问内存
        if re.search(r'\[' + re.escape(reg) + r'[+\]]', inst):
            return True
        # mov reg2, reg (单纯拷贝不算UAF，但保守标记)
        parts = inst.strip().lower().replace(',', ' ').split()
        if len(parts) >= 3 and parts[2] == reg and parts[1].rstrip(',') not in ('rdi',):
            return True
        return False

    @staticmethod
    def _extract_func(inst: str) -> str:
        m = re.search(r'\b(malloc|calloc|realloc|_Znwm|_Znam)\b', inst, re.I)
        return m.group(1) if m else "malloc"
