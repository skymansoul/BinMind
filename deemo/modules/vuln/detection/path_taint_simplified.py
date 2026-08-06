# -*- coding: utf-8 -*-
# 创建: 2026-08-05  |  简化版静态污点传播
#
"""
简化版静态污点传播——从输入源沿指令传播污点至格式化调用点。
解决FormatStringDetector无法追踪多层函数传递的问题。
"""

import re, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

_INPUT_SOURCES = {"recv","read","fread","fgets","gets","scanf","recvfrom","recvmsg","readv","getenv"}
_FORMAT_FUNCS = {"printf","fprintf","sprintf","snprintf","syslog","dprintf","vprintf","vfprintf","vsprintf"}
_PROPAGATE_MNEMONICS = {"mov","movzx","movsx","lea","add","sub","and","or"}

@dataclass
class TaintResult:
    function_name: str
    tainted_at: Dict[int, Set[str]] = field(default_factory=dict)
    format_calls: List = field(default_factory=list)

class SimplifiedTaintTracker:
    """简化版静态污点追踪——面向格式化字符串检测优化。

    从输入源(recv/read/fgets等)标记rax为污点,
    沿mov/lea/算术指令向前传播, 在格式化调用点检查rdi是否被污点。
    """

    def track(self, instructions: List[str], function_name: str = "",
               max_iterations: int = 5) -> TaintResult:
        result = TaintResult(function_name=function_name)
        if not instructions: return result
        n = len(instructions)
        tainted = [set() for _ in range(n)]

        # Phase 1: 标记输入源
        for i, insn in enumerate(instructions):
            callee = self._callee(insn)
            if callee:
                for sf in _INPUT_SOURCES:
                    if sf in callee:
                        tainted[i].add("rax"); break

        # Phase 2: 迭代传播
        for _ in range(max_iterations):
            changed = False
            for i in range(1, n):
                mnem, ops = self._parse(instructions[i])
                if mnem in _PROPAGATE_MNEMONICS and len(ops) >= 2:
                    dr = self._reg(ops[0]); sr = self._reg(ops[1])
                    if sr and sr in tainted[i-1] and dr and dr not in tainted[i]:
                        tainted[i].add(dr); changed = True
                new_t = tainted[i-1] - tainted[i]
                if new_t: tainted[i].update(new_t); changed = True
            if not changed: break

        # Phase 3: 检测格式化调用
        for i, insn in enumerate(instructions):
            callee = self._callee(insn)
            if callee:
                for ff in _FORMAT_FUNCS:
                    if ff in callee:
                        is_tainted = "rdi" in tainted[max(0,i-1)]
                        result.format_calls.append((i, ff, is_tainted))
                        break

        result.tainted_at = {i: tainted[i] for i in range(n) if tainted[i]}
        return result

    def _callee(self, insn: str) -> str:
        s = insn.strip()
        if ":" in s[:20]: s = s.split(":",1)[1].strip()
        p = s.split()
        return p[1].lower().split("@")[0] if len(p)>=2 and p[0].lower()=="call" else ""

    def _parse(self, insn: str):
        s = insn.strip()
        if ":" in s[:20]: s = s.split(":",1)[1].strip()
        p = s.split(None,1)
        if len(p)<2: return (p[0].lower(),[]) if p else ("",[])
        return (p[0].lower(), [o.strip() for o in p[1].split(",")])

    def _reg(self, op: str) -> str:
        op = op.strip().lower()
        if not op or op.startswith("0x") or op.startswith("-") or op.isdigit(): return ""
        if op.startswith("["): return op[1:].split("]")[0].split("+")[0].split("-")[0].strip()
        for sep in ("+","-","*"):
            if sep in op: return op.split(sep)[0].strip()
        return op

__all__ = ["TaintResult","SimplifiedTaintTracker"]
