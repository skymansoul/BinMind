"""
整数溢出下游影响分析器 — 溢出点→危险使用的路径追踪。

与integer_overflow_triage.py(在output模块)的分工:
  triage: 对已发现的溢出做L0-L5分类和exploitability评分
  本模块: 在检测阶段做溢出→危险使用的可达性分析

核心方法:
  1. 定位add/sub/mul/imul等算术指令 → 标记可能溢出点
  2. 追踪溢出结果(mov链)到后续使用点
  3. 若使用点是malloc/memcpy/数组索引 → 高危; 仅cmp → 低危
  4. 结合前序约束: 若溢出前有bounds check → 降危

修改记录:
  创建 2024-12-09
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class IntOverflowPath:
    overflow_insn_idx: int
    overflow_mnemonic: str        # add / sub / imul
    result_reg: str               # 承载溢出结果的寄存器
    downstream_use_idx: int       # 下游使用指令索引
    downstream_func: str          # malloc / memcpy / array_index / cmp
    instruction_gap: int
    has_bounds_check: bool        # 溢出前是否有边界检查
    danger_score: float           # 0-10
    confidence: str


_ARITH_OPS = {'add', 'sub', 'imul', 'mul', 'shl', 'sal', 'inc', 'dec'}
_DANGER_SINKS = {
    'malloc': 9.0, 'calloc': 9.0, 'realloc': 8.5,
    'memcpy': 9.5, 'memmove': 9.0, 'memset': 7.0,
    'strcpy': 8.0, 'strncpy': 7.0, 'read': 7.5, 'recv': 7.5,
    'array_index': 8.0, 'ptr_arith': 7.0,
}
_BOUNDS_CHECK_PATTERNS = {'cmp', 'test', 'je', 'jbe', 'jae', 'jb', 'ja'}


def _parse_regs(insn: str) -> Tuple[Set[str], Set[str]]:
    """提取指令的读写寄存器"""
    parts = insn.lower().replace(',', ' ').split()
    if len(parts) < 2: return set(), set()
    all_regs = {'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
                'r12','r13','r14','r15','eax','ebx','ecx','edx','esi','edi'}
    written, read = set(), set()
    mnemonic = parts[0]
    if mnemonic in _ARITH_OPS:
        for p in parts[1:2]:
            for r in all_regs:
                if r in p:
                    full = 'r' + r[1:] if r.startswith('e') else r
                    written.add(full)
        for p in parts[1:]:
            for r in all_regs:
                if r in p:
                    full = 'r' + r[1:] if r.startswith('e') else r
                    read.add(full)
    return written, read


def _has_bounds_check(instructions: List[str], insn_idx: int,
                      window: int = 5) -> bool:
    """检查溢出指令前window条内是否有边界检查"""
    for j in range(max(0, insn_idx - window), insn_idx):
        insn = instructions[j].lower()
        if any(p in insn for p in _BOUNDS_CHECK_PATTERNS):
            return True
    return False


def analyze_overflow_paths(
    instructions: List[str],
) -> List[IntOverflowPath]:
    """
    分析整数溢出→下游危险使用的路径。
    返回按 danger_score 降序排列。
    """
    reg_values: Dict[str, int] = {}  # 追踪寄存器值的简单传播
    paths: List[IntOverflowPath] = []

    for i, insn in enumerate(instructions):
        parts = insn.lower().replace(',', ' ').split()
        if len(parts) < 2: continue
        mnemonic = parts[0]
        written, read = _parse_regs(insn)

        # 追踪mov/lea的值传播
        if mnemonic in ('mov', 'movzx', 'movsx', 'lea'):
            for w in written:
                for r in read:
                    if r in reg_values:
                        reg_values[w] = reg_values[r]
                        break

        # 标记溢出点
        if mnemonic in _ARITH_OPS and written:
            result_reg = list(written)[0]
            has_bounds = _has_bounds_check(instructions, i)

            # 前向扫描下游使用
            for j in range(i + 1, min(i + 30, len(instructions))):
                fut_insn = instructions[j].lower()
                fut_parts = fut_insn.replace(',', ' ').split()

                if 'call' in fut_insn:
                    callee = fut_parts[-1].lstrip('*').split('@')[0] if len(fut_parts) > 1 else ''
                    base = callee.split('.')[-1]
                    if base in _DANGER_SINKS:
                        danger = _DANGER_SINKS[base]
                        if has_bounds:
                            danger *= 0.6
                        gap = j - i
                        if gap > 15:
                            danger *= 0.7
                        paths.append(IntOverflowPath(
                            overflow_insn_idx=i, overflow_mnemonic=mnemonic,
                            result_reg=result_reg, downstream_use_idx=j,
                            downstream_func=base, instruction_gap=gap,
                            has_bounds_check=has_bounds,
                            danger_score=round(min(10.0, danger), 1),
                            confidence='confirmed' if danger >= 7 else 'likely'))
                        break

                # 检测数组/指针算术使用
                if result_reg in fut_insn:
                    if '[' in fut_insn:
                        danger = _DANGER_SINKS.get('array_index', 7.0)
                        if has_bounds: danger *= 0.6
                        paths.append(IntOverflowPath(
                            overflow_insn_idx=i, overflow_mnemonic=mnemonic,
                            result_reg=result_reg, downstream_use_idx=j,
                            downstream_func='array_index', instruction_gap=j - i,
                            has_bounds_check=has_bounds,
                            danger_score=round(min(10.0, danger), 1),
                            confidence='likely'))
                        break

    paths.sort(key=lambda p: p.danger_score, reverse=True)
    return paths
