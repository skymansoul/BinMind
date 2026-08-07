# 循环写守卫检查器 — 循环上界与alloc大小关系的守卫推断
"""从循环写检测器拆分出的守卫分析辅助方法。

职责:
  - _check_bound_guard: 判断循环上界是否被alloc大小守卫约束
  - _bound_is_user_controlled: 判断循环上界是否来自用户输入
  - _find_loop_cap: 查找循环的硬性cap上界
"""

import re
from typing import List

# 用户输入边界来源
_USER_BOUND_FUNCS = re.compile(
    r'\bcall\s+(read|recv|fgets|scanf|atoi|strtoul|strtol|getenv)\b', re.I)

# 循环比较指令 (与loop_write_detector共享定义)
_LOOP_CMP = re.compile(
    r'\bcmp\s+(\w+),\s*(?:dword\s+ptr\s+|qword\s+ptr\s+)?'
    r'(0x[0-9a-f]+|\d+|\[[^\]]+\])', re.I)


class LoopGuardChecker:
    """循环守卫分析器 — 提供循环写检测所需的边界/守卫判断。"""

    def check_bound_guard(self, asm_lines: List[str], alloc_line: int,
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

    def bound_is_user_controlled(self, asm_lines: List[str], cmp_line: int,
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

    def find_loop_cap(self, asm_lines: List[str], cmp_line: int,
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
