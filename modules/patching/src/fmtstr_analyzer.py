# 格式化字符串检测深度强化 — 污点感知的fmt参数分析
"""格式化字符串漏洞检测器 — 区分"安全的printf(常量)"和"危险的printf(用户输入)"。

旧方法：看到 printf 调用就报警（极高误报）。
新方法：追踪 printf 的 fmt 参数是否来自用户可控数据。

检测逻辑：
  1. 扫描所有 printf/fprintf/sprintf/syslog 调用点(含__mingw_前缀)
  2. 回溯 fmt 参数来源(第一参数或第二参数, 依函数而定)
  3. 常量格式串 → SAFE; 用户输入 → DANGEROUS; 内存加载 → 可疑
  4. 跨函数/argv/堆拷贝的污点传播

设计依据:
  - MinGW下printf族编译为__mingw_printf等带前缀符号
  - fprintf/sprintf/snprintf的fmt是第二参数
  - CRT内部实现(__report_error等)的格式化调用非用户注入点
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)


@dataclass
class FmtSite:
    """一个格式化函数调用点。"""
    line_index: int = 0
    func_name: str = ""            # printf / sprintf / syslog
    fmt_operand: str = ""          # rdi/rcx 的来源
    fmt_source_type: str = ""      # constant | user_input | memory | unknown
    fmt_value_hint: str = ""       # 常量的具体值提示
    is_dangerous: bool = False
    confidence: float = 0.0


@dataclass
class FmtReport:
    """格式化字符串检测报告。"""
    function_name: str = ""
    sites: List[FmtSite] = field(default_factory=list)
    total_sites: int = 0
    dangerous_count: int = 0
    safe_count: int = 0            # 确认为安全的调用（常量fmt）
    suspicious_count: int = 0      # 无法确定（内存加载等）
    fp_reduction_pct: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total': self.total_sites,
            'dangerous': self.dangerous_count,
            'safe': self.safe_count,
            'suspicious': self.suspicious_count,
            'fp_reduction': round(self.fp_reduction_pct, 1),
        }


# 格式化函数调用点扫描器

class FmtSiteScanner:
    """扫描所有 printf 族函数调用。"""

    # MinGW下printf族编译为__mingw_printf等带前缀符号, 一并匹配
    _FMT_FUNCS = re.compile(
        r'\bcall\s+(?:__mingw_)?(printf|fprintf|dprintf|sprintf|snprintf|'
        r'syslog|__syslog_chk|vsprintf|vsnprintf|vprintf|vfprintf)\b', re.I)

    # 用户输入源
    _SOURCE_PATTERNS = re.compile(
        r'\bcall\s+(read|recv|recvfrom|fgets|scanf|getenv|fread|getc|gets)\b|'
        r'\bargv\b|\bargc\b', re.I)

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

    def _is_crt_func(self, name: str) -> bool:
        """判断是否CRT内部函数(库实现, 非用户fmt注入点)。"""
        if not name:
            return False
        crt_known = {
            '_matherr', '__report_error', '_amsg_exit', '_crt_debugger_hook',
            'wassert', '__mingw_pformat', '__mingw_pformat_begin',
            '__mingw_wformat', 'handle_printf_arg', 'format_arg',
            'safelight', '__acrt_iob_func', '_fpreset',
        }
        return name in crt_known or name.startswith('_')

    def scan(self, asm_lines: List[str]) -> List[FmtSite]:
        sites = []
        func_at = self._map_func_bounds(asm_lines)
        for i, line in enumerate(asm_lines):
            m = self._FMT_FUNCS.search(line)
            if not m:
                continue
            caller = func_at.get(i, '')
            if self._is_crt_func(caller):
                continue
            func = m.group(1)
            fmt_src, src_type, val_hint = self._trace_fmt_source(
                asm_lines, i, func)
            is_dangerous = (src_type == 'user_input' or
                          (src_type == 'memory' and
                           self._has_source_nearby(asm_lines, i)))

            site = FmtSite(
                line_index=i, func_name=func,
                fmt_operand=fmt_src, fmt_source_type=src_type,
                fmt_value_hint=val_hint,
                is_dangerous=is_dangerous,
                confidence=0.9 if src_type == 'user_input' else (
                    0.6 if src_type == 'memory' else
                    0.95 if src_type == 'constant' else 0.3))
            sites.append(site)
        return sites

    def _trace_fmt_source(self, asm: List[str], call_idx: int,
                          func_name: str = ""
                          ) -> Tuple[str, str, str]:
        """回溯 printf 的 fmt 参数来源。

        ABI兼容: SysV第一参数=rdi, MS x64第一参数=rcx。
        fprintf/sprintf/snprintf/vsprintf 的 fmt 是第二参数
          (MS x64=rdx, SysV=rsi)。
        """
        base = (func_name or '').lower().lstrip('__mingw_')
        two_arg = base in ('fprintf', 'dprintf', 'sprintf', 'snprintf',
                           'vsprintf', 'vsnprintf', 'vfprintf')
        fmt_regs = ('rdx', 'rsi') if two_arg else ('rdi', 'rcx')
        for j in range(call_idx - 1, max(call_idx - 10, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')

            for fr in fmt_regs:
                # lea fr, [rip+.Lconst] → compile-time constant → SAFE
                m = re.search(r'\blea\s+' + fr + r',?\s*\[rip\s*[+\-]\s*\w+\]',
                              line)
                if m:
                    return fr, 'constant', 'lea rip-relative (compile-time string)'

                # lea fr, [rbp-N] → stack-local format → possibly safe
                m = re.search(r'\blea\s+' + fr + r',?\s*\[rbp\s*[+\-]\s*\w+\]',
                              line)
                if m:
                    return fr, 'constant', 'lea rbp-relative (stack variable)'

                # mov fr, reg (where reg is tainted)
                m = re.search(r'\bmov\s+' + fr + r',?\s*(\w+)', line)
                if m:
                    reg = m.group(1)
                    if reg not in ('qword', 'dword', 'ptr'):
                        if self._is_reg_tainted(asm, j, reg):
                            return reg, 'user_input', ''
                        # 参数槽 → 跨函数判定
                        slot = self._reg_from_param_slot(asm, j, reg)
                        if slot:
                            if self._cross_function_call_taint(
                                    asm, j, slot):
                                return reg, 'user_input', (
                                    'reg from function arg (user input)')
                        # 堆中格式串: reg指向局部槽, 槽被strcpy写入用户输入
                        local_slot = self._reg_from_local_slot(asm, j, reg)
                        if local_slot and self._slot_filled_by_copy(
                                asm, j, local_slot):
                            return reg, 'user_input', (
                                'fmt from heap buffer filled by strcpy(input)')
                        return reg, 'memory', ''

                # mov fr, [rbp+N] → 函数参数(fmt为入参), 追踪调用点来源
                m = re.search(
                    r'\bmov\s+' + fr + r',?\s*(?:qword\s+ptr\s+)?'
                    r'\[rbp\s*\+\s*(0x[0-9a-f]+|\w+)\]', line)
                if m:
                    arg_tainted = self._arg_is_user_controlled(
                        asm, j, fr, m.group(1))
                    if arg_tainted:
                        return fr, 'user_input', 'function arg from user input'
                    return fr, 'memory', 'function arg (unsure)'

                # mov fr, [mem] → loaded from memory
                if re.search(r'\bmov\s+' + fr + r',?\s*\[', line):
                    return fr, 'memory', 'loaded from memory'

        return 'rdi', 'unknown', ''

    def _arg_is_user_controlled(self, asm: List[str], load_idx: int,
                                reg: str, slot_off: str) -> bool:
        """判断函数参数槽[rbp+N]是否最终来自用户输入。"""
        # 方法1: 窗口内源调用且值流入参数槽
        for j in range(load_idx - 1, max(load_idx - 60, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            if self._SOURCE_PATTERNS.search(line):
                for k in range(j + 1, load_idx):
                    lk = asm[k].strip().lower()
                    if re.search(r'\bmov\s+\[rbp\s*\+\s*'
                                 + re.escape(slot_off) + r'\]\s*,?\s*\w+',
                                 lk):
                        return True
                    if re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*rax',
                                 lk):
                        return True

        # 方法2: argv[i] 取址模式
        argv_ptr_slot = self._find_argv_ptr_slot(asm, load_idx)
        if argv_ptr_slot:
            for j in range(load_idx - 1, max(load_idx - 40, -1), -1):
                line = asm[j].strip().lower().replace(',', ' ')
                if re.search(r'\bmov\s+\[rbp\s*\+\s*' + re.escape(slot_off)
                             + r'\]\s*,?\s*\w+', line):
                    return True
                if re.search(r'\bmov\s+\[rbp\s*\+\s*'
                             + re.escape(argv_ptr_slot) + r'\]\s*,?\s*\w+',
                             line):
                    for k in range(j - 1, max(j - 30, -1), -1):
                        lk = asm[k].strip().lower()
                        if 'argv' in lk:
                            return True
                        if re.search(r'\bmov\s+(rdx|rdi)\b', lk):
                            return True

        # 方法3: 跨函数——参数槽是函数入参
        if self._cross_function_call_taint(asm, load_idx, slot_off):
            return True
        return False

    def _has_source_nearby(self, asm: List[str], call_idx: int) -> bool:
        """检查附近是否存在用户输入源。"""
        for j in range(max(call_idx - 20, 0), call_idx):
            if self._SOURCE_PATTERNS.search(asm[j].strip().lower()):
                return True
        return False

    # ── 污点传播辅助 ──────────────────────────────────────────────

    def _is_reg_tainted(self, asm: List[str], from_idx: int,
                        reg: str) -> bool:
        """寄存器值是否最终来源于用户输入。"""
        for j in range(from_idx - 1, max(from_idx - 15, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            if self._SOURCE_PATTERNS.search(line):
                if reg == 'rax':
                    return True
                for k in range(j + 1, from_idx):
                    if re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*rax',
                                 asm[k].strip().lower()):
                        return True
        return False

    def _reg_from_param_slot(self, asm: List[str], from_idx: int,
                             reg: str) -> str:
        """寄存器来源是否来自[rbp+N]参数槽, 返回槽偏移。"""
        for j in range(from_idx - 1, max(from_idx - 8, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(
                r'\bmov\s+' + re.escape(reg) + r',?\s*(?:qword\s+ptr\s+)?'
                r'\[rbp\s*\+\s*(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return m.group(1)
        return ''

    def _reg_from_local_slot(self, asm: List[str], from_idx: int,
                             reg: str) -> str:
        """寄存器来源是否来自[rbp-N]局部槽, 返回槽标识。"""
        for j in range(from_idx - 1, max(from_idx - 8, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(
                r'\bmov\s+' + re.escape(reg) + r',?\s*(?:qword\s+ptr\s+)?'
                r'\[rbp\s*-\s*(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return f'rbp-{m.group(1)}'
        return ''

    def _slot_filled_by_copy(self, asm: List[str], load_idx: int,
                             slot: str) -> bool:
        """局部槽是否被strcpy/memcpy写入且源为用户输入参数。

        模式: [slot]=malloc; strcpy([slot], input)
        """
        for j in range(load_idx - 1, max(load_idx - 40, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            if re.search(r'\bcall\s+(?:__mingw_)?(strcpy|strncpy|memcpy'
                         r'|strcat|sprintf)\b', line):
                dst_hit = False
                for k in range(j - 1, max(j - 10, -1), -1):
                    lk = asm[k].strip().lower().replace(',', ' ')
                    m = re.search(r'\bmov\s+(rcx|rdi),?\s*(\w+)', lk)
                    if m:
                        dst_reg = m.group(2)
                        if self._reg_from_local_slot(asm, k, dst_reg):
                            dst_hit = True
                            break
                if dst_hit:
                    # 检查src是否用户输入参数 (src设置行可能紧邻call)
                    for q in range(j - 1, max(j - 10, -1), -1):
                        lq = asm[q].strip().lower().replace(',', ' ')
                        m2 = re.search(r'\bmov\s+(rdx|rsi),?\s*(\w+)', lq)
                        if m2:
                            src_reg = m2.group(2)
                            if src_reg not in ('qword', 'dword', 'ptr'):
                                if self._reg_from_param_slot_here(
                                        asm, q, src_reg):
                                    return True
                        m3 = re.search(
                            r'\bmov\s+(rdx|rsi),?\s*(?:qword\s+ptr\s+)?'
                            r'\[rbp\s*\+\s*(0x[0-9a-f]+|\w+)\]', lq)
                        if m3:
                            return True
                    return False
        return False

    def _reg_from_param_slot_here(self, asm: List[str], from_idx: int,
                                  reg: str) -> bool:
        """寄存器在from_idx行或其前是否来自[rbp+N]参数槽。"""
        for j in range(from_idx, max(from_idx - 8, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            m = re.search(
                r'\bmov\s+' + re.escape(reg) + r',?\s*(?:qword\s+ptr\s+)?'
                r'\[rbp\s*\+\s*(0x[0-9a-f]+|\w+)\]', line)
            if m:
                return True
        return False

    def _cross_function_call_taint(self, asm: List[str], load_idx: int,
                                   slot_off: str) -> bool:
        """跨函数判定: 参数槽是函数入参时, 回溯调用点实参来源。

        模式(main调用handler):
          mov rax,[rbp+0x18]   ← argv
          add rax,8            ← argv[1] 索引
          mov rax,[rax]
          mov rcx,rax          ← 第一参数
          call handler
        """
        func_start = load_idx
        for j in range(load_idx, -1, -1):
            if re.search(r'\b\w+>:', asm[j]):
                func_start = j
                break
        func_name = ''
        m = re.search(r'<(\w+)>:', asm[func_start])
        if m:
            func_name = m.group(1)
        if not func_name:
            return False

        search_end = min(func_start + 150, len(asm))
        search_start = max(func_start - 120, 0)
        for j in range(search_start, search_end):
            line = asm[j].strip().lower().replace(',', ' ')
            if re.search(r'\bcall\s+' + re.escape(func_name) + r'\b', line):
                for k in range(j - 1, max(j - 15, -1), -1):
                    lk = asm[k].strip().lower()
                    m2 = re.search(r'\bmov\s+(rcx|rdi|rdx|rsi),?\s*(\w+)',
                                   lk)
                    if m2:
                        src_reg = m2.group(2)
                        for q in range(k - 1, max(k - 20, -1), -1):
                            lq = asm[q].strip().lower().replace(',', ' ')
                            if re.search(r'\bmov\s+' + re.escape(src_reg)
                                         + r',?\s*(?:qword\s+ptr\s+)?\[',
                                         lq):
                                if self._has_argv_nearby(asm, q):
                                    return True
                                if re.search(
                                        r'\[rbp\s*\+\s*(?:0x1[0-9a-f]'
                                        r'|0x2[0-9a-f]|0x3[0-9a-f])\]',
                                        lq):
                                    return True
        return False

    def _has_argv_nearby(self, asm: List[str], idx: int) -> bool:
        """窗口内检查argv引用。"""
        for j in range(max(idx - 30, 0), idx + 1):
            if 'argv' in asm[j].strip().lower():
                return True
        return False

    def _find_argv_ptr_slot(self, asm: List[str], load_idx: int) -> str:
        """定位 argv 指针的存储槽位(若存在)。"""
        for j in range(max(load_idx - 120, 0), load_idx):
            line = asm[j].strip().lower()
            if 'argv' in line:
                m = re.search(r'\bmov\s+\[(rbp|rsp)\s*\+\s*'
                              r'(0x[0-9a-f]+|\w+)\]\s*,?\s*\w+', line)
                if m:
                    return f'{m.group(1)}+{m.group(2)}'
        return ''
