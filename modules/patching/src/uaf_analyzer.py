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

深度强化(跨函数/ABI/MinGW)：
  - rcx/rdi双ABI的free指针参数识别
  - 全局/栈槽的指针存储追踪(跨函数UAF)
  - free后置NULL识别(安全释放)
  - 函数作用域判定(栈槽仅同函数有效)
  - 待定free机制(函数定义序与执行序相反)
  - CRT库函数过滤

方法依据: Undangle 的 demand-driven 指针生命周期分析思想。
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
    freed_reg: str = ""          # free时的指针参数寄存器
    freed_slot: str = ""         # free指针的来源槽(如rbp-0x8或全局符号)
    alloc_func_name: str = ""    # 分配所在函数名(栈槽作用域判定用)
    slot_locations: List[str] = field(default_factory=list)  # 指针存储的槽位
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


# CRT启动/清理与库内部实现函数(非用户UAF场景)
_CRT_KNOWN = {
    'do_pseudo_reloc', '_ValidateImageBase', 'mark_section_writable',
    'restore_modified_sections', 'register_frame_ctor',
    '_pei386_runtime_relocator', '_gnu_exception_handler',
    '__main', '_tmainCRTStartup', '__mingw_initltsdrot_force',
    '__dyn_tls_init', '_gnu_initial_stk', 'duplicate_ppstrings',
    'check_managed_app', 'dtoa_lock', '_fpreset',
    '___w64_mingwthr_remove_key_dtor', '__mingw_TLScallback',
    '_FindPESection', '_FindPESectionByName',
    '__mingwthr_remove_key_dtor', 'wassert',
    '__mingw_raise_matherr', '__tmainCRTStartup', 'mainCRTStartup',
    # gdtoa/字符串库内部实现 (MinGW浮点转字符串链)
    '__strcp_D2A', 'wcsnlen', 'strnlen', '__s2b_D2A',
    '__d2b_D2A', '__quorem_D2A', '__rv_alloc_D2A',
    '__nrv_alloc_D2A', '__Balloc_D2A', '__Bfree_D2A',
    '__mult_D2A', '__pow5mult_D2A', '__i2b_D2A',
    '__increment_D2A', '__ratio_D2A', '__b2d_D2A',
    '__gethex_D2A', '__hexnan_D2A', '__gdtoa', '__freedtoa',
    'freedtoa', 'gdtoa',
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

    _ALLOC_FUNCS = re.compile(
        r'\bcall\s+(malloc|calloc|realloc|_Znwm|_Znam)\b', re.I)
    _FREE_FUNCS = re.compile(
        r'\bcall\s+(free|delete|_ZdlPv|_ZdaPv)\b', re.I)

    def analyze(self, asm_lines: List[str],
                function_name: str = "") -> UAFReport:
        report = UAFReport(function_name=function_name)
        objects = []
        obj_counter = 0
        func_at = self._map_func_bounds(asm_lines)
        pending_frees = []  # 未匹配到对象的free(函数定义序与执行序相反)

        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower().replace(',', ' ')
            # 跳过CRT启动/清理函数中的alloc/free/use, 避免库代码误报
            cur_func = func_at.get(i, '')
            if self._is_crt_func(cur_func):
                continue

            # malloc → 创建指针对象
            if self._ALLOC_FUNCS.search(stripped):
                obj = PointerObject(
                    obj_id=obj_counter, alloc_line=i,
                    alloc_func=self._extract_func(stripped))
                obj_counter += 1
                obj.alloc_func_name = cur_func
                # rax 持有返回的指针
                obj.reg_locations[i] = 'rax'
                objects.append(obj)
                report.total_allocs += 1
                # re-alloc检测: 若malloc结果写回已释放对象的指针槽,
                # 则旧对象被重新分配, 移出UAF候选(悬空指针已清除)
                realloc_slots = self._find_alloc_store_slots(asm_lines, i)
                if realloc_slots:
                    obj.slot_locations.extend(realloc_slots)
                    for prev in objects:
                        if (prev is not obj and prev.is_freed
                                and prev.freed_slot
                                and prev.freed_slot in realloc_slots):
                            prev.is_freed = False  # 复活: 重新分配
                            break
                # 待定free回溯: 先前出现的free若匹配此对象槽, 标记释放。
                # 同函数内alloc晚于free(行序)是re-alloc场景, 新对象有效;
                # 跨函数(定义序与执行序相反)时按槽匹配。
                for pf in list(pending_frees):
                    pf_reg, pf_slot, pf_idx = pf
                    if pf_slot and pf_slot in obj.slot_locations:
                        same_func = (self._func_of_line(
                            asm_lines, pf_idx) == cur_func)
                        if same_func and i > pf_idx:
                            pending_frees.remove(pf)
                            break
                        obj.is_freed = True
                        obj.free_line = pf_idx
                        obj.freed_reg = pf_reg
                        obj.freed_slot = pf_slot
                        pending_frees.remove(pf)
                        break
                continue

            # free → 标记对应对象为已释放
            free_match = self._FREE_FUNCS.search(stripped)
            if free_match:
                # 库函数内的free(如CRT对全局指针的清理)非用户UAF场景
                if self._is_crt_func(cur_func):
                    continue
                freed_reg = self._find_free_arg(asm_lines, i)
                freed_slot = self._find_free_slot(
                    asm_lines, i, freed_reg)
                matched = False
                for obj in objects:
                    if (not obj.is_freed and self._matches_pointer(
                            obj, freed_reg, i, asm_lines)):
                        obj.is_freed = True
                        obj.free_line = i
                        obj.freed_reg = freed_reg
                        obj.freed_slot = freed_slot
                        matched = True
                        break
                if not matched and freed_slot:
                    # 函数定义序与执行序相反: 挂起, 待malloc创建后匹配
                    pending_frees.append((freed_reg, freed_slot, i))
                continue

            # 追踪指针移动 (mov reg, rax 或 mov reg, ptr_reg)
            for obj in objects:
                if obj.is_freed:
                    # free后置NULL → 指针失效, 后续访问安全(非UAF)
                    if self._is_nullification(stripped, obj):
                        obj.is_freed = False  # 失效化, 移出UAF候选
                        continue
                    # 跨函数: 从对象的全局/栈槽加载指针 → 悬空指针被读取
                    slot_hit = self._loads_from_slot(
                        stripped, obj, cur_func)
                    if slot_hit:
                        obj.uaf_lines.append(i)
                        report.uaf_count += 1
                        report.findings.append(
                            "UAF @ line %d: 从%s加载已free指针(悬空读)" % (
                                i, slot_hit))
                        continue
                    # 已释放：检查是否有对该指针的访问(限定同函数)
                    for reg_line, reg in list(obj.reg_locations.items()):
                        if cur_func:
                            # reg定义位置与当前访问须同函数
                            if self._func_of_line(
                                    asm_lines, reg_line) != cur_func:
                                continue
                        if self._accesses_pointer(
                                stripped, reg, i, obj):
                            obj.uaf_lines.append(i)
                            report.uaf_count += 1
                            report.findings.append(
                                "UAF @ line %d: 指针在line %d free后仍在line %d被访问" % (
                                    i, obj.free_line, i))
                else:
                    # 未释放：追踪指针移动
                    self._track_pointer_move(
                        stripped, i, obj, asm_lines)

        report.objects = objects
        report.false_positive_candidates = sum(
            1 for o in objects if o.is_freed and len(o.uaf_lines) == 0)
        return report

    # ── 槽/寄存器/函数作用域分析 ──────────────────────────────────

    def _map_func_bounds(self, asm: List[str]) -> Dict[int, str]:
        """映射每行所属函数名。"""
        func_at = {}
        cur = ''
        for i, line in enumerate(asm):
            m = re.search(r'<(\w+)>:', line)
            if m:
                cur = m.group(1)
            func_at[i] = cur
        return func_at

    def _func_of_line(self, asm: List[str], line_idx: int) -> str:
        """返回行所在函数名。"""
        for j in range(line_idx, -1, -1):
            m = re.search(r'<(\w+)>:', asm[j])
            if m:
                return m.group(1)
        return ''

    def _is_crt_func(self, name: str) -> bool:
        """判断是否CRT启动/清理函数(库代码, 非用户UAF场景)。
        仅用精确集合, 避免误滤用户函数。
        """
        return name in _CRT_KNOWN if name else False

    def _find_alloc_store_slots(self, asm: List[str], alloc_idx: int
                                ) -> List[str]:
        """malloc返回指针(rax)被存储的所有槽位。
        mov [rbp-N], rax / mov [rip+off], rax → 槽列表。
        只收集malloc后到下一个call前的rax存储链,
        避免其他malloc的存储干扰(不同对象的槽)。
        """
        slots = []
        for j in range(alloc_idx + 1, min(alloc_idx + 15, len(asm))):
            line = asm[j].strip().lower().replace(',', ' ')
            if re.search(r'\bcall\s+', line):
                break
            m = re.search(
                r'\bmov\s+(?:qword\s+ptr\s+)?\[(rbp|rsp|rip)\s*([+\-])\s*'
                r'(0x[0-9a-f]+|\w+)\]\s*,?\s*rax\b', line)
            if m:
                base = m.group(1)
                if base == 'rip':
                    sym = re.search(r'#\s*[0-9a-f]+\s+<([^>]+)>', asm[j])
                    if sym:
                        slots.append(sym.group(1))
                        continue
                slots.append(f'{m.group(1)}{m.group(2)}{m.group(3)}')
        return slots

    def _find_free_arg(self, asm: List[str], free_idx: int) -> str:
        """找 free 调用前设置指针参数的寄存器。
        ABI兼容: SysV=rdi, MS x64=rcx。
        """
        for j in range(free_idx - 1, max(free_idx - 5, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            for fr in ('rdi', 'rcx'):
                m = re.search(r'\bmov\s+' + fr + r',?\s*(\w+)', line)
                if m:
                    return m.group(1)
        return 'rdi'

    def _find_free_slot(self, asm: List[str], free_idx: int,
                        freed_reg: str) -> str:
        """free指针参数寄存器的来源槽(如[rbp-0x8]或全局符号g_msg)。"""
        for j in range(free_idx - 1, max(free_idx - 8, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(
                r'\bmov\s+' + re.escape(freed_reg) + r',?\s*(?:qword\s+ptr\s+)?'
                r'\[(rbp|rsp|rip)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', line)
            if m:
                if m.group(1) == 'rip':
                    sym = re.search(r'#\s*[0-9a-f]+\s+<([^>]+)>', asm[j])
                    if sym:
                        return sym.group(1)
                return f'{m.group(1)}{m.group(2)}{m.group(3)}'
        return ''

    def _matches_pointer(self, obj: PointerObject, reg: str,
                         free_idx: int, asm: List[str]) -> bool:
        """检查 free(reg) 是否释放了 obj 指向的内存。

        栈槽(rbp/rsp)在不同函数中含义不同, 仅同函数内有效;
        全局符号(rip)跨函数有效。不依赖行序。
        """
        for line_idx, loc_reg in obj.reg_locations.items():
            if loc_reg == reg and line_idx < free_idx:
                return True
        freed_slot = self._find_free_slot(asm, free_idx, reg)
        if freed_slot and freed_slot in obj.slot_locations:
            if not freed_slot.startswith(('rbp', 'rsp')):
                return True
            free_func = self._func_of_line(asm, free_idx)
            alloc_func = obj.alloc_func_name
            if free_func and alloc_func and free_func == alloc_func:
                return True
        return False

    def _is_nullification(self, inst: str, obj: PointerObject) -> bool:
        """检查指令是否将指针置NULL(使UAF失效)。
        模式: mov [freed_slot], 0 / xor reg,reg / mov freed_reg, 0
        """
        stripped = inst.strip().lower().replace(',', ' ')
        regs = set(obj.reg_locations.values())
        if obj.freed_reg:
            regs.add(obj.freed_reg)
        for loc_reg in regs:
            if re.search(r'\bmov\s+\[[^\]]*' + re.escape(loc_reg)
                         + r'[^\]]*\]\s*,?\s*(?:0x0|0)\b', stripped):
                return True
            if re.search(r'\bmov\s+' + re.escape(loc_reg) + r',?\s*(?:0x0|0)\b',
                         stripped):
                return True
            if re.search(r'\bxor\s+' + re.escape(loc_reg) + r',?\s*'
                         + re.escape(loc_reg), stripped):
                return True
        if obj.freed_slot:
            m = re.search(r'\bmov\s+(?:qword\s+ptr\s+)?\[([^\]]+)\]'
                          r'\s*,?\s*(?:0x0|0)\b', stripped)
            if m and re.escape(obj.freed_slot) in re.escape(m.group(1)):
                return True
        return False

    def _loads_from_slot(self, inst: str, obj: PointerObject,
                         cur_func: str = "") -> str:
        """检查指令是否从对象的指针槽加载(悬空指针读取)。
        栈槽(rbp/rsp)仅同函数内有效; 全局符号(rip)跨函数有效。
        """
        stripped = inst.strip().lower().replace(',', ' ')
        for slot in obj.slot_locations:
            if slot.startswith(('rbp', 'rsp')):
                if not cur_func:
                    continue
                if obj.alloc_func_name and cur_func != obj.alloc_func_name:
                    continue
            if re.search(r'\bmov\s+\w+\s*,?\s*(?:qword\s+ptr\s+)?'
                         r'\[[^\]]*' + re.escape(slot) + r'[^\]]*\]',
                         stripped):
                return slot
            if re.search(r'<\s*' + re.escape(slot) + r'\s*>', stripped):
                return slot
        return ''

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
        """检查指令是否通过该指针寄存器访问内存。

        仅识别对指针指向内存的实际读写:
          - mov [reg±off], X   → 写
          - mov X, [reg±off]   → 读
        排除纯寄存器拷贝与算术运算, 避免寄存器重用误报。
        """
        stripped = inst.strip().lower().replace(',', ' ')
        m = re.search(r'\bmov\s+\[[^\]]*' + re.escape(reg) + r'[^\]]*\]'
                      r'\s*,?\s*\w+', stripped)
        if m:
            return True
        m = re.search(r'\bmov\s+\w+\s*,?\s*\[[^\]]*' + re.escape(reg)
                      + r'[^\]]*\]', stripped)
        if m:
            return True
        if re.search(r'\b(movzx|movsx|movsxd)\s+\w+\s*,?\s*(?:byte|word|'
                     r'dword|qword)\s+ptr\s*\[[^\]]*' + re.escape(reg)
                     + r'[^\]]*\]', stripped):
            return True
        return False

    @staticmethod
    def _extract_func(inst: str) -> str:
        m = re.search(r'\b(malloc|calloc|realloc|_Znwm|_Znam)\b', inst, re.I)
        return m.group(1) if m else "malloc"
