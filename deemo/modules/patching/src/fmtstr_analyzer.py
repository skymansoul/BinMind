# 格式化字符串检测深度强化 — 污点感知的fmt参数分析
"""格式化字符串漏洞检测器 — 区分"安全的printf(常量)"和"危险的printf(用户输入)"。

旧方法：看到 printf 调用就报警（极高误报）。
新方法：追踪 printf 的第一个参数(fmt)是否来自用户可控数据。

误报根源分析：
  约80%的 printf 调用使用字符串常量作为格式参数，属安全调用。
  仅当 fmt 参数通过数据流来自外部输入(read/recv/argv)
  且未经过格式验证时才构成真正的格式化字符串漏洞。

检测逻辑：
  1. 扫描所有 printf/fprintf/sprintf/syslog 调用点
  2. 回溯 rdi 的来源
  3. 若 rdi ← lea [rip+.Lconst] → 常量字符串 → SAFE（过滤）
  4. 若 rdi ← 用户输入寄存器（来自 read/recv/argv） → DANGEROUS
  5. 若 rdi 来自内存加载（mov rdi, [rbp-N]）→ 保守标记为可疑
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
    fmt_operand: str = ""          # rdi 的来源
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


# ── 格式化函数调用点扫描器 ────────────────────────────────────────

class FmtSiteScanner:
    """扫描所有 printf 族函数调用。"""

    _FMT_FUNCS = re.compile(
        r'\bcall\s+(printf|fprintf|dprintf|sprintf|snprintf|'
        r'syslog|__syslog_chk|vsprintf|vsnprintf|vprintf|vfprintf)\b', re.I)

    # 用户输入源
    _SOURCE_PATTERNS = re.compile(
        r'\bcall\s+(read|recv|recvfrom|fgets|scanf|getenv|fread|getc|gets)\b|'
        r'\bargv\b|\bargc\b', re.I)

    def scan(self, asm_lines: List[str]) -> List[FmtSite]:
        sites = []
        for i, line in enumerate(asm_lines):
            m = self._FMT_FUNCS.search(line)
            if not m:
                continue
            func = m.group(1)
            fmt_src, src_type, val_hint = self._trace_fmt_source(asm_lines, i)
            is_dangerous = (src_type == 'user_input' or
                          (src_type == 'memory' and self._has_source_nearby(asm_lines, i)))

            site = FmtSite(
                line_index=i, func_name=func,
                fmt_operand=fmt_src, fmt_source_type=src_type,
                fmt_value_hint=val_hint,
                is_dangerous=is_dangerous,
                confidence=0.9 if src_type == 'user_input' else (
                    0.6 if src_type == 'memory' else 0.95 if src_type == 'constant' else 0.3))
            sites.append(site)
        return sites

    def _trace_fmt_source(self, asm: List[str], call_idx: int
                          ) -> Tuple[str, str, str]:
        """回溯 printf 的 fmt 参数(rdi)来源。"""
        for j in range(call_idx - 1, max(call_idx - 10, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')

            # lea rdi, [rip+.Lconst] → compile-time string constant → SAFE
            m = re.search(r'\blea\s+rdi,?\s*\[rip\s*[+\-]\s*\w+\]', line)
            if m:
                return 'rdi', 'constant', 'lea rip-relative (compile-time string)'

            # lea rdi, [rbp-N] → stack-local format → possibly safe
            m = re.search(r'\blea\s+rdi,?\s*\[rbp\s*[+\-]\s*\w+\]', line)
            if m:
                return 'rdi', 'constant', 'lea rbp-relative (stack variable)'

            # mov rdi, reg (where reg is tainted)
            m = re.search(r'\bmov\s+rdi,?\s*(\w+)', line)
            if m:
                reg = m.group(1)
                if self._is_reg_tainted(asm, j, reg):
                    return reg, 'user_input', ''
                return reg, 'memory', ''

            # mov rdi, [mem] → loaded from memory
            if re.search(r'\bmov\s+rdi,?\s*\[', line):
                return 'rdi', 'memory', 'loaded from memory'

        return 'rdi', 'unknown', ''

    def _is_reg_tainted(self, asm: List[str], from_idx: int, reg: str) -> bool:
        """检查寄存器值是否最终来源于用户输入。"""
        for j in range(from_idx - 1, max(from_idx - 15, -1), -1):
            line = asm[j].strip().lower().replace(',', ' ')
            if self._SOURCE_PATTERNS.search(line):
                # 检查返回值 rax 是否流入了 reg
                if reg == 'rax':
                    return True
                # 检查是否有 mov reg, rax
                for k in range(j + 1, from_idx):
                    if re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*rax', asm[k].strip().lower()):
                        return True
        return False

    def _has_source_nearby(self, asm: List[str], call_idx: int) -> bool:
        """检查附近是否存在用户输入源。"""
        for j in range(max(call_idx - 20, 0), call_idx):
            if self._SOURCE_PATTERNS.search(asm[j].strip().lower()):
                return True
        return False
