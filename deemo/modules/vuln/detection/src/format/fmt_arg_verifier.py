"""格式化字符串参数验证器 — 格式说明符 vs 参数数量的一致性检查.

创建: 2025-03-03
目的: 消除 taint_format_checker 无法处理的误报场景:
      - printf(const_fmt, a, b) 中 fmt 包含3个 %s 但只传了2个参数 → 栈越界读
      - printf("%d %s", a) 格式串需要2个参数但只传了1个 → 参数不足警告
      同时, 当 fmt 是常量且参数完全匹配时, 可以更有信心地标记为 SAFE.

方法依据:
  - CWE-134 (格式字符串漏洞) 的参数滥用子类
  - printf-family 的 POSIX 规范: 格式说明符数量必须 ≤ 传入的参数数量
  - 本模块只处理格式说明符计数, 不做类型检查 (那是编译器的工作)

决策:
  - 不实现完整的 ABI 分析来数参数 — 用启发式: 检查 call 前 push/mov 的数量
  - 对于可变参数函数, 仅通过格式串分析来做最小参数数需求判定
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple


class ArgMatchVerdict(Enum):
    MATCH = auto()              # 参数数量匹配
    TOO_FEW_ARGS = auto()       # 格式说明符数 > 参数数 → 栈泄露风险
    TOO_MANY_ARGS = auto()      # 参数数 > 格式说明符数 → 浪费但非漏洞
    INDETERMINATE = auto()      # 无法确定 (动态格式串或非标准调用)


@dataclass
class FormatArgCheck:
    """一次格式字符串参数验证结果."""
    call_addr: int
    format_string: str
    expected_args: int           # 格式串中要求的非字面参数数
    actual_args: int             # 调用点实际传入的参数数 (启发式)
    verdict: ArgMatchVerdict
    missing_args: int            # 缺少的参数数 (0=匹配)
    is_vuln: bool                # 参数不足 → 栈泄露 → True


class FormatArgVerifier:
    """格式字符串参数验证器 — 检测格式说明符与参数的匹配情况.

    使用方式:
      verifier = FormatArgVerifier()
      result = verifier.verify('printf("val=%d name=%s", x)', 0x401000)
      if result.verdict == ArgMatchVerdict.TOO_FEW_ARGS:
          print(f'Potential stack leak: missing {result.missing_args} args')
    """

    # 格式说明符的正则 — 匹配 %[flags][width][.precision][length]specifier
    # 排除 %% (字面百分号)
    _FMT_SPEC_RE = re.compile(
        r'%(?:[+\-\s0#])?'          # flags
        r'(?:\d+|\*)?'               # width
        r'(?:\.\d+|\.\*)?'           # precision
        r'(?:hh|h|l|ll|j|z|t|L)?'   # length modifier
        r'[diouxXeEfFgGaAcspn]'      # specifier
    )
    # 百分号字面
    _PCT_LITERAL_RE = re.compile(r'%%')

    # 消耗参数的格式说明符 (大多数说明符消耗1个参数)
    # %n 消耗1个, %s 消耗1个
    _ARG_CONSUMING_SPECS = set('diouxXeEfFgGaAcspn')
    # 不消耗参数的格式说明符 (%m 在 glibc 中打印 errno)
    _NON_CONSUMING = {'m'}

    def count_specifiers(self, fmt_string: str) -> int:
        """统计格式字符串中实际需要的参数数量.

        排除 %% (字面百分号) 和不需要参数的说明符.
        """
        if not fmt_string:
            return 0

        # 移除所有 %% (字面百分号)
        cleaned = self._PCT_LITERAL_RE.sub('', fmt_string)

        count = 0
        for m in self._FMT_SPEC_RE.finditer(cleaned):
            spec = m.group(0)
            # 获取最后一个字符 (格式说明符)
            spec_char = spec[-1]
            if spec_char in self._ARG_CONSUMING_SPECS:
                count += 1
            # %m 不消耗参数
        return count

    def estimate_actual_args(self,
                             instructions_before_call: List[Tuple[str, str, int]],
                             call_target: str = 'printf') -> int:
        """从 call 前指令估算实际传入参数数.

        启发式: x86-64 System V ABI — 前6个参数通过寄存器传递.
        对于 printf-family, 第一个参数总是格式字符串,
        可变参数从第二个位置开始.

        决策: 扫描 call 前指令, 数 mov/call/lea 到参数寄存器 (rdi/rsi/rdx/rcx/r8/r9) 的次数.
        """
        param_regs = {'rdi', 'esi', 'edx', 'ecx', 'r8d', 'r9d',
                      'rsi', 'rdx', 'rcx', 'r8', 'r9'}
        param_count = 0
        seen_regs: Set[str] = set()

        # 从后往前扫描 call 前的指令 (最多16条)
        for mnem, ops, addr in reversed(instructions_before_call[-16:]):
            parts = [p.strip() for p in ops.split(',')]
            if not parts:
                continue
            dst = parts[0].lower()

            if mnem.lower() in ('mov', 'lea', 'xor', 'movabs') and dst in param_regs:
                if dst not in seen_regs:
                    seen_regs.add(dst)
                    param_count += 1

        # printf 的第一个参数是格式字符串 → 剩余可变参数从 rsi 开始
        return max(0, param_count - 1)  # 减去格式字符串本身

    def verify(self, fmt_string: str, call_addr: int = 0,
               instructions_before: List[Tuple[str, str, int]] = None,
               call_target: str = 'printf') -> FormatArgCheck:
        """验证格式字符串参数匹配."""
        expected = self.count_specifiers(fmt_string)
        actual = 0
        if instructions_before:
            actual = self.estimate_actual_args(instructions_before, call_target)

        if expected == 0:
            verdict = ArgMatchVerdict.MATCH
        elif actual == 0 and instructions_before is None:
            verdict = ArgMatchVerdict.INDETERMINATE
        elif actual < expected:
            verdict = ArgMatchVerdict.TOO_FEW_ARGS
        elif actual > expected:
            verdict = ArgMatchVerdict.TOO_MANY_ARGS
        else:
            verdict = ArgMatchVerdict.MATCH

        missing = max(0, expected - actual)
        return FormatArgCheck(
            call_addr=call_addr,
            format_string=fmt_string,
            expected_args=expected,
            actual_args=actual,
            verdict=verdict,
            missing_args=missing,
            is_vuln=(verdict == ArgMatchVerdict.TOO_FEW_ARGS
                    or (expected > 0 and actual == 0)),
        )

    def batch_verify(self,
                     sites: List[Tuple[str, int, List[Tuple[str, str, int]]]],
                     ) -> List[FormatArgCheck]:
        """批量验证多个 printf 调用点."""
        results = []
        for fmt, addr, insns_before in sites:
            results.append(self.verify(fmt, addr, insns_before))
        return results

    def reduction_ratio(self,
                        results: List[FormatArgCheck]) -> float:
        """计算参数验证带来的误报降低率."""
        if not results:
            return 0.0
        confirmed_safe = sum(
            1 for r in results
            if r.verdict == ArgMatchVerdict.MATCH and r.expected_args > 0
        )
        return round(confirmed_safe / len(results), 3)
