# 格式化字符串漏洞静态检测器 — 基于格式参数来源分析
# 核心创新: 在二进制级检测printf/sprintf族调用的格式参数来源
# 方法学:
#   1. 识别所有printf族调用点 (__mingw_printf, printf, sprintf, etc.)
#   2. 追踪格式参数寄存器 (rcx/rdi) 的赋值来源
#   3. lea rcx, [rip+...] → SAFE (常量字符串, 编译器生成的.rodata引用)
#   4. mov rcx, rax/reg → 传播来源追踪
#   5. mov rcx, [rbp-X] → 栈变量, 来源未知 → VULNERABLE标记
# 设计原则: 借鉴PointerProvenance的寄存器追踪机制,
#   追踪格式参数的来源而非追踪堆指针
# 理论来源:
#   - CWE-134: Use of Externally-Controlled Format String
#   - Scut / team teso "Exploiting Format String Vulnerabilities" (2001)
from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .instruction_parser import InstructionParser


class FmtStrSeverity(Enum):
    CRITICAL = auto()   # 格式参数来自用户输入 (读/写任意内存)
    HIGH = auto()       # 格式参数非常量, 可能是攻击者可控
    MEDIUM = auto()     # 长度受限的格式化函数 (snprintf)
    LOW = auto()        # 潜在但被部分保护
    INFO = auto()       # 信息性标注


class FmtStrMode(Enum):
    DIRECT_USER_FMT = auto()   # printf(user_input) — 最危险
    NON_CONST_FMT = auto()     # 格式参数非常量字符串
    STACK_VAR_FMT = auto()     # 格式来自栈变量


@dataclass
class FmtStrFinding:
    finding_id: str
    mode: FmtStrMode
    severity: FmtStrSeverity
    confidence: float
    fmt_func: str
    fmt_reg: str
    fmt_source: str
    instruction_idx: int
    instruction_text: str
    function_name: str
    detail: str
    recommendation: str = ""


class FormatStringDetector:
    """格式化字符串漏洞静态检测器.

    追踪rcx/rdi寄存器中格式参数的来源,
    判断printf/sprintf调用是否存在格式化字符串漏洞.
    """

    # printf族 — Windows x64: rcx=格式参数
    _PRINTF_FAMILY = {
        'printf', '__mingw_printf', '__printf_chk',
        'sprintf', '__mingw_sprintf', '__sprintf_chk',
        'snprintf', '__mingw_snprintf',
        'fprintf', '__mingw_fprintf', '__fprintf_chk',
        'dprintf', 'vdprintf',
        'syslog', 'vsyslog',
    }

    # CRT噪声函数 — 这些函数中的printf调用通常是
    # 启动代码/错误处理的一部分, 不是用户代码漏洞
    _CRT_NOISE_FUNCS = {
        '__tmainCRTStartup', 'WinMainCRTStartup', 'mainCRTStartup',
        '__mingw_invalidParameterHandler', 'safe_flush',
        '__do_global_dtors', '__do_global_ctors',
        '__gcc_register_frame', '__gcc_deregister_frame',
        'check_managed_app', 'atexit',
    }

    def __init__(self):
        self._parser = InstructionParser()
        self._current_func = "_entry_"
        self._call_ctr = 0
        self._findings: List[FmtStrFinding] = []
        # 追踪: {reg64_name: source_type}
        self._reg_source: Dict[str, str] = {}
        # 追踪寄存器来源的详细信息
        self._reg_detail: Dict[str, str] = {}

    def analyze(self, instructions: List[str],
                func_map: Optional[Dict[str, Tuple[int, int]]] = None
                ) -> List[FmtStrFinding]:
        self._current_func = "_entry_"
        self._call_ctr = 0
        self._findings = []
        self._reg_source = {}
        self._reg_detail = {}
        func_map = func_map or {}

        for idx, line in enumerate(instructions):
            result = InstructionParser.parse_line(line)
            if result is None:
                continue
            op, operands = result
            if not op:
                continue

            # 函数边界
            if func_map:
                for fname, (s, e) in func_map.items():
                    if s <= idx <= e and self._current_func != fname:
                        self._reg_source.clear()
                        self._reg_detail.clear()
                        self._current_func = fname
                        break

            # 跳过CRT噪声函数
            if self._current_func in self._CRT_NOISE_FUNCS:
                continue
            if self._current_func.startswith(('__', '_.', '<')):
                continue
            if re.match(r'^func_\d+$', self._current_func):
                continue

# 寄存器来源追踪
            self._track_source(op, operands, line)

# call检测
            if op == 'call':
                self._check_fmt_call(idx, operands, line)

        return self._findings

    def _track_source(self, op: str, operands: List[str], line: str):
        """追踪寄存器的数据来源."""
        if len(operands) < 2:
            return

        dst = InstructionParser.clean_reg(operands[0])
        if not InstructionParser.is_reg(dst):
            return
        dst64 = InstructionParser.normalize_reg64(dst)
        src = operands[1]

        # lea dst, [rip+...] → 常量字符串地址 (安全)
        if op == 'lea':
            if 'rip' in src.lower():
                self._reg_source[dst64] = 'constant_string'
                self._reg_detail[dst64] = f'lea {dst}, [rip+...]'
                return
            # lea dst, [reg+offset] → 从已知寄存器传播
            base, off, idx_reg, scale = InstructionParser.parse_lea_src(src)
            if base:
                base64 = InstructionParser.normalize_reg64(base)
                if base64 in self._reg_source:
                    self._reg_source[dst64] = self._reg_source[base64]
                    self._reg_detail[dst64] = f'lea from {base64}'
                    return
            # lea dst, [rsp/rbp+...] → 栈地址
            if 'rsp' in src.lower() or 'rbp' in src.lower():
                self._reg_source[dst64] = 'stack_addr'
                self._reg_detail[dst64] = f'lea {dst}, [stack]'
                return
            return

        # 仅mov类指令追踪来源, 算术指令(add/sub/xor等)不追踪
        if op not in ('mov', 'movzx', 'movsx', 'movabs'):
            return

        # mov dst, imm → 常量
        imm = InstructionParser.parse_immediate(src)
        if imm is not None:
            self._reg_source[dst64] = 'constant'
            self._reg_detail[dst64] = f'mov {dst}, {imm:#x}'
            return

        # mov dst, reg → 传播来源
        if InstructionParser.is_reg(src):
            src64 = InstructionParser.normalize_reg64(src)
            if src64 in self._reg_source:
                self._reg_source[dst64] = self._reg_source[src64]
                self._reg_detail[dst64] = (
                    f'mov from {src64} ({self._reg_source[src64]})')
            else:
                self._reg_source[dst64] = 'register_unknown'
                self._reg_detail[dst64] = f'mov {dst}, {src64}'
            return

        # mov dst, [mem] → 内存加载
        if '[' in src and ']' in src:
            # 检查是否是栈变量
            if 'rbp' in src.lower() or 'rsp' in src.lower():
                self._reg_source[dst64] = 'stack_var'
                self._reg_detail[dst64] = f'mov {dst}, [stack]'
            else:
                self._reg_source[dst64] = 'memory'
                self._reg_detail[dst64] = f'mov {dst}, [mem]'
            return

    def _check_fmt_call(self, idx: int, operands: List[str], line: str):
        """检查printf族调用, 判断格式参数来源."""
        if not operands:
            return
        callee = operands[0]

        if callee not in self._PRINTF_FAMILY:
            return

        # 确定格式参数寄存器
        # Windows x64 calling convention (rcx, rdx, r8, r9):
        #   printf(fmt, ...)     → rcx=fmt
        #   fprintf(f, fmt, ...) → rdx=fmt
        #   sprintf(out, fmt, ...)  → rdx=fmt
        #   snprintf(out, n, fmt, ...) → r8=fmt
        if callee in ('fprintf', '__mingw_fprintf', '__fprintf_chk',
                      'dprintf', 'vdprintf',
                      'sprintf', '__mingw_sprintf', '__sprintf_chk'):
            fmt_reg = 'rdx'  # Windows x64: rdx=arg2
        elif callee in ('snprintf', '__mingw_snprintf'):
            fmt_reg = 'r8'   # Windows x64: r8=arg3
        else:
            fmt_reg = 'rcx'  # Windows x64: rcx=arg1

        # 检查格式参数寄存器来源
        source = self._reg_source.get(fmt_reg, 'unknown')
        detail = self._reg_detail.get(fmt_reg, '无法追踪')

        # 常量字符串 → 安全
        if source == 'constant_string':
            return

        # 确定严重程度
        if source == 'stack_var' or source == 'stack_addr':
            mode = FmtStrMode.STACK_VAR_FMT
            severity = FmtStrSeverity.HIGH
            confidence = 0.75
        elif source in ('register_unknown', 'memory'):
            mode = FmtStrMode.NON_CONST_FMT
            severity = FmtStrSeverity.HIGH
            confidence = 0.60
        elif source == 'constant':
            # 寄存器含常量数字但不是字符串地址 → 不可能是格式字符串
            return
        else:
            mode = FmtStrMode.DIRECT_USER_FMT
            severity = FmtStrSeverity.CRITICAL
            confidence = 0.85

        # 有限format函数降级
        if callee in ('snprintf', '__mingw_snprintf'):
            severity = FmtStrSeverity.MEDIUM
            confidence -= 0.15

        self._findings.append(FmtStrFinding(
            finding_id=f"FMT-{self._call_ctr}@{idx}",
            mode=mode,
            severity=severity,
            confidence=confidence,
            fmt_func=callee,
            fmt_reg=fmt_reg,
            fmt_source=f'{source}: {detail}',
            instruction_idx=idx,
            instruction_text=line,
            function_name=self._current_func,
            detail=f"{callee} at func={self._current_func}: "
                   f"格式参数({fmt_reg})来源={source}. "
                   f"若攻击者控制此参数, 可用%p/%x泄漏栈数据, "
                   f"或用%n写任意内存.",
            recommendation="将格式参数改为常量字符串, "
                           "e.g. printf(\"%s\", data) 而非 printf(data)"))

        self._call_ctr += 1

    def summary(self) -> Dict:
        modes = {}
        severities = {}
        for f in self._findings:
            m = f.mode.name
            modes[m] = modes.get(m, 0) + 1
            s = f.severity.name
            severities[s] = severities.get(s, 0) + 1
        return {
            'total_fmtstr': len(self._findings),
            'by_mode': modes,
            'by_severity': severities,
        }
