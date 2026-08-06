# 整数溢出检测——基于运算结果与操作数关系的静态检查
# 原理: 若 a + b < min(a, b) (无符号) 或符号翻转, 则发生溢出
# 通过模式匹配识别危险算术操作+缺少检查的组合
#
# 检测策略:
#   1. 算术操作识别: add/mul/imul/sub → 提取操作数
#   2. 检查缺失: 操作后是否有jo/jc/jb等溢出/进位检查
#   3. 分配函数关联: 算术结果是否传递给malloc/calloc(size)参数
#   4. 严重度: 传递给分配函数的溢出 > 普通算术溢出

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class IntOverflowSeverity(Enum):
    CRITICAL = 3    # 溢出结果直接用于malloc/calloc——堆缓冲区分配不足
    HIGH = 2        # 溢出结果用于memcpy长度——越界拷贝
    MEDIUM = 1      # 溢出存在但无直接危险使用
    LOW = 0         # 溢出存在但结果未被危险使用


@dataclass
class IntOverflowReport:
    func_name: str
    instr_idx: int
    operation: str           # add/sub/mul/imul
    operands: List[str]
    has_overflow_check: bool
    feeds_alloc_size: bool   # 结果传递给malloc参数
    feeds_copy_size: bool    # 结果传递给memcpy参数
    severity: IntOverflowSeverity
    evidence: List[str] = field(default_factory=list)


class IntegerOverflowChecker:
    """整数溢出检测器。

    在x86-64汇编中检测:
      add reg, imm → 若imm足够大, 可能溢出
      imul reg, reg, imm → 乘法溢出
      操作后缺少 jo/jc 检查 → 漏洞证据

    与分配函数关联时提升严重度:
      add→mov rdi→call malloc → CRITICAL (分配不足)
    """

    # 溢出后应出现的检查指令
    _OVERFLOW_CHECKS = {'jo', 'jno', 'jc', 'jnc', 'jb', 'jnb', 'jbe'}
    # 危险使用——运算结果传递到这些函数
    _DANGEROUS_SINKS = {'malloc', 'calloc', 'realloc', 'memcpy',
                        'memmove', 'strncpy', 'alloca'}

    def __init__(self):
        self._arith_pattern = re.compile(
            r'\b(add|sub|mul|imul|shl|sal)\b', re.I)
        self._imm_pattern = re.compile(
            r'\$?(0x[0-9a-f]+|\d+)', re.I)

    def analyze_function(self,
                          instructions: List[str],
                          func_name: str = ""
                          ) -> List[IntOverflowReport]:
        reports = []
        n = len(instructions)
        if n < 3:
            return reports

        for i in range(n):
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith(';'):
                continue

            m = self._arith_pattern.search(instr)
            if not m:
                continue

            op = m.group(1)
            operands = self._extract_operands(instr)
            if len(operands) < 2:
                continue

            # 检查后续2条指令内是否有溢出检查
            has_check = False
            for j in range(i + 1, min(i + 3, n)):
                next_instr = instructions[j].strip().lower()
                if any(chk in next_instr for chk in self._OVERFLOW_CHECKS):
                    has_check = True
                    break

            # 检查后续5条指令内结果是否传递给危险sink
            feeds_alloc = False
            feeds_copy = False
            for j in range(i + 1, min(i + 6, n)):
                next_instr = instructions[j].strip().lower()
                # 检测: mov rdi/rcx, <result_reg> → call malloc
                for sink in self._DANGEROUS_SINKS:
                    if sink in next_instr and 'call' in next_instr:
                        if sink in ('malloc', 'calloc', 'realloc', 'alloca'):
                            feeds_alloc = True
                        else:
                            feeds_copy = True

            # 严重度判定
            if feeds_alloc:
                sev = IntOverflowSeverity.CRITICAL
            elif feeds_copy:
                sev = IntOverflowSeverity.HIGH
            elif not has_check:
                sev = IntOverflowSeverity.MEDIUM
            else:
                sev = IntOverflowSeverity.LOW

            evidence = [
                f"op={op} at instr[{i}]",
                f"overflow_check={'present' if has_check else 'MISSING'}",
                f"feeds_alloc={feeds_alloc}, feeds_copy={feeds_copy}",
            ]

            reports.append(IntOverflowReport(
                func_name=func_name, instr_idx=i,
                operation=op, operands=operands,
                has_overflow_check=has_check,
                feeds_alloc_size=feeds_alloc,
                feeds_copy_size=feeds_copy,
                severity=sev, evidence=evidence))

        return reports

    def _extract_operands(self, instr: str) -> List[str]:
        """提取操作数——处理AT&T语法: op src, dst"""
        parts = instr.replace('%', '').split()
        operands = []
        for p in parts[1:]:
            p = p.rstrip(',')
            if p and p != ',':
                operands.append(p)
        return operands

    def filter_critical(self, reports: List[IntOverflowReport]
                         ) -> List[IntOverflowReport]:
        """仅返回CRITICAL和HIGH级别的报告"""
        return [r for r in reports
                if r.severity in (IntOverflowSeverity.CRITICAL,
                                  IntOverflowSeverity.HIGH)]
