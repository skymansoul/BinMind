# 循环写检测器 — 逐字节/逐元素循环写导致的堆越界
"""memcpy类sink扫描无法覆盖"循环内逐字节写"模式:
  for (i = 0; i < user_bound && i < cap; i++) buf[i] = v;
该模式在真实CVE中常见。

设计决策:
  - 识别 write-to-heap 的循环写: mov [reg+idx], value 位于loop体内
  - 循环上界来自外部输入 → 上界不可知, 但循环受 cap(如4096)约束时
    可与alloc区间交汇
  - 只对已确认alloc为taint的样本启用, 避免引入新误报
  - 输出LoopWriteFinding: 是否越界、越界依据、置信度
  - 守卫/上界判断委托loop_guard_checker
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

from .loop_guard_checker import LoopGuardChecker


@dataclass
class LoopWriteFinding:
    """循环写检测结果。"""
    alloc_line: int = 0
    loop_start: int = 0
    loop_end: int = 0
    user_bound_reg: str = ""
    cap_value: int = 0
    alloc_lower: int = 0
    alloc_upper: int = 0
    is_tainted: bool = False
    may_overflow: bool = False
    confidence: float = 0.0
    reason: str = ""

    def to_dict(self) -> Dict:
        return {
            'alloc_line': self.alloc_line,
            'loop_range': [self.loop_start, self.loop_end],
            'user_bound_reg': self.user_bound_reg,
            'cap': self.cap_value,
            'alloc_range': [self.alloc_lower, self.alloc_upper],
            'may_overflow': self.may_overflow,
            'confidence': round(self.confidence, 2),
            'reason': self.reason[:150],
        }


# 循环内写指令: mov [reg+idx], value (byte/dword/word/qword ptr)
# 基址排除rbp/rsp(栈变量存储), 只认通用/数据寄存器(堆指针)
_LOOP_WRITE = re.compile(
    r'\bmov\s+(?:byte|word|dword|qword)\s+ptr\s+\[([a-z0-9]+)'
    r'(?:[+\-]\s*\w+)?\]\s*,?\s*\w+', re.I)
# 无类型前缀的裸写: mov [rax], cl
_LOOP_WRITE_RAW = re.compile(
    r'\bmov\s+\[([a-z0-9]+)(?:[+\-]\s*\w+)?\]\s*,?\s*\w+', re.I)

# 栈指针寄存器(排除)
_STACK_PTRS = {'rbp', 'ebp', 'rsp', 'esp'}
# 循环比较指令: cmp reg, imm / cmp reg, [mem] (含 dword/qword ptr 前缀)
_LOOP_CMP = re.compile(
    r'\bcmp\s+(\w+),\s*(?:dword\s+ptr\s+|qword\s+ptr\s+)?'
    r'(0x[0-9a-f]+|\d+|\[[^\]]+\])', re.I)
_LOOP_CMP_MEM = re.compile(
    r'\bcmp\s+(\w+),\s*(?:dword\s+ptr\s+|qword\s+ptr\s+)?'
    r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', re.I)

# 用户输入边界来源
_USER_BOUND_FUNCS = re.compile(
    r'\bcall\s+(read|recv|fgets|scanf|atoi|strtoul|strtol|getenv)\b', re.I)


class LoopWriteDetector:
    """循环写检测器 — 识别tainted alloc后的循环越界写。"""

    # 用户输入边界来源
    _USER_BOUND_FUNCS = re.compile(
        r'\bcall\s+(read|recv|fgets|scanf|atoi|strtoul|strtol|getenv)\b',
        re.I)

    def __init__(self):
        self._guard = LoopGuardChecker()

    def detect(self, asm_lines: List[str], alloc_line: int,
               alloc_lower: int, alloc_upper: int,
               alloc_is_tainted: bool) -> List[LoopWriteFinding]:
        """在alloc之后检测循环写。

        只处理tainted alloc, 避免对常量alloc引入误报。
        搜索窗口: alloc后120行(覆盖循环设置+循环体)。
        """
        if not alloc_is_tainted:
            return []
        findings = []
        end = min(alloc_line + 120, len(asm_lines))
        i = alloc_line + 1
        while i < end:
            line = asm_lines[i].strip().lower()
            if re.search(r'\bcall\s+', line) and not re.search(
                    r'\bcall\s+(memset|memcpy|memmove)\b', line):
                i += 1
                continue
            # 找到循环体起点: 写指令前有循环头
            mw = _LOOP_WRITE.search(line) or _LOOP_WRITE_RAW.search(line)
            if mw and mw.group(1) not in _STACK_PTRS:
                # TODO: 循环写检测窗口120行, 多层嵌套循环的内层写可能漏检
                loop = self._analyze_loop(
                    asm_lines, i, alloc_line, alloc_upper, alloc_lower)
                if loop is not None:
                    loop['alloc_line'] = alloc_line
                    loop['alloc_lower'] = alloc_lower
                    loop['alloc_upper'] = alloc_upper
                    loop['is_tainted'] = True
                    findings.append(LoopWriteFinding(**loop))
                    i += 30  # 跳过已分析区域
                    continue
            i += 1
        return findings

    def _analyze_loop(self, asm_lines: List[str], write_line: int,
                      alloc_line: int, alloc_upper: int,
                      alloc_lower: int = 0
                      ) -> Optional[Dict]:
        """分析写入点所在循环的边界与溢出可能性。"""
        loop_start = write_line
        # 回溯找循环头: cmp可能位于写指令之后(循环头在尾部)
        # 向前找20行 + 向后找15行 (用原始文本, 保留逗号)
        cmp_line = -1
        cmp_mem_slot = ""
        for j in range(write_line - 1, max(write_line - 20, -1), -1):
            m = _LOOP_CMP.search(asm_lines[j].strip().lower())
            if m:
                cmp_line = j
                break
        if cmp_line < 0:
            for j in range(write_line + 1, min(write_line + 15,
                                               len(asm_lines))):
                m = _LOOP_CMP.search(asm_lines[j].strip().lower())
                if m:
                    cmp_line = j
                    break
        if cmp_line < 0:
            return None

        cmp_reg = None
        bound = None
        raw_line = asm_lines[cmp_line].strip().lower()
        m = _LOOP_CMP.search(raw_line)
        if m:
            cmp_reg = m.group(1)
            b = m.group(2)
            # 立即数bound
            if re.match(r'^(?:0x[0-9a-f]+|\d+)$', b):
                bound = int(b, 16) if b.lower().startswith('0x') else int(b)
            else:
                # 内存操作数 → 记录槽位, 后续判断是否用户输入
                mm = _LOOP_CMP_MEM.search(raw_line)
                if mm:
                    cmp_mem_slot = f'{mm.group(2)}{mm.group(3)}{mm.group(4)}'
                    if cmp_reg in ('eax', 'rax'):
                        cmp_reg = mm.group(1)

        # 循环上界来源: 是否由用户输入驱动
        user_controlled = self._bound_is_user_controlled(
            asm_lines, cmp_line, cmp_reg, cmp_mem_slot)
        cap = self._find_loop_cap(asm_lines, cmp_line, write_line)

        # 判定: 循环上界受控且cap > alloc_upper → 可能越界
        may_overflow = False
        conf = 0.0
        reason = ""
        if user_controlled:
            # 守卫推断: 循环上界与alloc大小之间是否有cmp+jcc约束
            guard_safe = self._check_bound_guard(
                asm_lines, alloc_line, write_line, cmp_reg, cmp_mem_slot)
            if guard_safe:
                conf = 0.10
                reason = ('循环上界受alloc大小守卫约束(loop<=alloc) → 安全')
            elif cap > 0:
                # 写侧受cap约束: 仅当alloc下界确定 >= cap 时才安全
                # alloc受控时下界为0, cap越大越可能覆盖小分配
                if alloc_upper < cap:
                    # alloc上界已知且 < cap → 必定越界
                    may_overflow = True
                    conf = 0.70
                    reason = (f'循环上界cap={cap} > alloc上界{alloc_upper}'
                              f' → 必定越界')
                elif alloc_lower >= cap:
                    # alloc下界 >= cap → 安全
                    conf = 0.10
                    reason = (f'alloc下界{alloc_lower} ≥ 循环cap={cap} → 安全')
                else:
                    # alloc区间与cap重叠 → 可能越界
                    may_overflow = True
                    conf = 0.50
                    reason = (f'循环上界受控且cap={cap}, alloc区间'
                              f'[{alloc_lower},{alloc_upper}]与cap重叠'
                              f' → 可能越界')
            else:
                # 无cap → 上界不可知, 与tainted alloc交汇
                may_overflow = True
                conf = 0.45
                reason = ('循环上界受控且无cap约束, alloc受控无界 → 潜在越界')
        return {
            'loop_start': loop_start, 'loop_end': write_line + 1,
            'user_bound_reg': cmp_reg or '', 'cap_value': cap,
            'may_overflow': may_overflow, 'confidence': conf,
            'reason': reason,
        }

    def _check_bound_guard(self, asm_lines: List[str], alloc_line: int,
                           write_line: int, cmp_reg: str,
                           cmp_mem_slot: str = "") -> bool:
        """检查循环上界是否被alloc大小守卫约束(loop_bound <= alloc_size)。

        模式: cmp loop_bound_reg/mem, alloc_size_reg/mem; jle/jbe 进入循环
        若存在该约束, 循环写入不会超过alloc → 安全。
        """
        alloc_slot = self._resolve_alloc_slot(asm_lines, alloc_line)
        if not alloc_slot:
            return False
        for j in range(alloc_line - 1, max(alloc_line - 40, -1), -1):
            line = asm_lines[j].strip().lower()
            m = re.search(
                r'\bcmp\s+\w+,\s*(?:dword\s+ptr\s+)?'
                r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', line)
            if not m:
                continue
            cmp_slot = f'{m.group(1)}{m.group(2)}{m.group(3)}'
            if cmp_slot == alloc_slot:
                # 后续jcc: jle/jbe 进入安全路径(loop<=alloc)
                for k in range(j + 1, min(j + 5, len(asm_lines))):
                    jcc = asm_lines[k].strip().lower()
                    if re.search(r'\b(jle|jbe)\b', jcc):
                        return True
                    if re.search(r'\b(call|jmp|ret)\b', jcc):
                        break
        return False

    def _resolve_alloc_slot(self, asm_lines: List[str],
                            alloc_line: int) -> str:
        """解析alloc size的来源槽位: 追踪 mov size_reg, [rbp-N]。"""
        for j in range(alloc_line - 1, max(alloc_line - 12, -1), -1):
            m = re.search(
                r'\bmov\s+(\w+),?\s*(?:dword\s+ptr\s+)?'
                r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]',
                asm_lines[j].strip().lower())
            if m:
                return f'{m.group(2)}{m.group(3)}{m.group(4)}'
        return ''

    def _bound_is_user_controlled(self, asm_lines: List[str], cmp_line: int,
                                  cmp_reg: str, mem_slot: str = "") -> bool:
        """判断循环比较寄存器是否来自用户输入。
        mem_slot非空时, 检查该栈槽的写入来源是否含用户输入调用。
        """
        if mem_slot:
            for j in range(cmp_line - 1, max(cmp_line - 15, -1), -1):
                line = asm_lines[j].strip().lower()
                if re.search(
                        r'\bmov\s+\[[^\]]*' + re.escape(mem_slot)
                        + r'[^\]]*\]\s*,', line):
                    if _USER_BOUND_FUNCS.search(line):
                        return True
                    break
            for j in range(cmp_line - 1, max(cmp_line - 40, -1), -1):
                line = asm_lines[j].strip().lower()
                if _USER_BOUND_FUNCS.search(line):
                    return True
            return True  # 内存上界保守视为受控

        reg_re = re.compile(r'\b' + re.escape(cmp_reg) + r'\b', re.I)
        for j in range(cmp_line - 1, max(cmp_line - 12, -1), -1):
            line = asm_lines[j].strip().lower()
            if _USER_BOUND_FUNCS.search(line):
                return True
            if re.search(r'\b(movsxd|cdqe|cqo)\b', line) and reg_re.search(line):
                continue
            if re.search(r'\bmov\s+' + re.escape(cmp_reg) + r',?\s*\d', line):
                return False
        return True  # 保守: 无法确认时视为受控

    def _find_loop_cap(self, asm_lines: List[str], cmp_line: int,
                       write_line: int) -> int:
        """查找循环的硬性cap上界(如 i < 4096 && i < user_bound)。"""
        caps = []
        for j in range(cmp_line, min(cmp_line + 15, len(asm_lines))):
            line = asm_lines[j].strip().lower()
            m = _LOOP_CMP.search(line)
            if m:
                b = m.group(2)
                try:
                    v = int(b, 16) if b.lower().startswith('0x') else int(b)
                except ValueError:
                    continue
                if 0 < v <= 65536:
                    caps.append(v)
                continue
            m = re.search(
                r'\bcmp\s+(?:dword\s+ptr\s+|qword\s+ptr\s+)?'
                r'\[[^\]]+\],\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                b = m.group(1)
                try:
                    v = int(b, 16) if b.lower().startswith('0x') else int(b)
                except ValueError:
                    continue
                if 0 < v <= 65536:
                    caps.append(v)
        return min(caps) if caps else 0
