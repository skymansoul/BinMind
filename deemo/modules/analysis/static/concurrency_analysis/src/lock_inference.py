# 概率评分替代二值模式匹配: 原子指令权重 0.4 + 自旋循环 0.35 + 内存屏障 0.25
# unlock 配对: lock 函数识别后, 沿调用图正向搜索配对的 unlock
# 概率锁函数识别 - 从剥离二进制中推断同步原语.

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 原子指令与屏障检测

# x86_64 原子指令前缀和操作
_X86_ATOMIC_INSNS = {
    'lock',           # lock 前缀 (lock cmpxchg, lock inc, ...)
    'xchg',           # 隐式原子交换
    'cmpxchg',        # 比较并交换
    'xadd',           # 原子加并返回旧值
}

# ARM64 原子指令 (Load-Linked / Store-Conditional)
_ARM64_ATOMIC_INSNS = {
    'ldxr', 'ldaxr', 'ldxrb', 'ldaxrb', 'ldxrh', 'ldaxrh',
    'stxr', 'stlxr', 'stxrb', 'stlxrb', 'stxrh', 'stlxrh',
    'ldxp', 'ldaxp', 'stxp', 'stlxp',
    'swp', 'ldadd', 'ldclr', 'ldeorset',
}

# x86_64 内存屏障
_X86_FENCE_INSNS = {'mfence', 'lfence', 'sfence'}

# ARM64 内存屏障
_ARM64_FENCE_INSNS = {'dmb', 'dsb', 'isb'}


def _classify_atomic(mnemonic: str, arch: str = 'x86_64') -> bool:
    """判断指令是否为原子操作"""
    m = mnemonic.lower().strip()
    if arch.startswith('arm') or arch.startswith('aarch'):
        return m in _ARM64_ATOMIC_INSNS
    # x86: lock 前缀或隐式原子指令
    if m == 'lock':
        return True  # 单独出现, 作为下一条指令的前缀
    return m in _X86_ATOMIC_INSNS


def _classify_fence(mnemonic: str, arch: str = 'x86_64') -> bool:
    """判断指令是否为内存屏障"""
    m = mnemonic.lower().strip()
    if arch.startswith('arm') or arch.startswith('aarch'):
        return m in _ARM64_FENCE_INSNS
    return m in _X86_FENCE_INSNS


# 自旋循环检测

def _has_spin_loop(
    instructions: List[str],
    max_loop_size: int = 8,
) -> Tuple[bool, float]:
    """检测函数是否包含自旋循环: 短循环体 + 条件退出 + 无副作用

    自旋锁的典型模式 (x86):
      lock cmpxchg [mem], reg    ; 原子比较交换
      jne loop_start             ; 失败->重试

    或:
      pause                      ; 省电提示
      cmp [mem], 0               ; 检查锁状态
      jne loop_start              ; 锁被持有->继续等

    返回: (has_spin, confidence_0_to_1)
    """
    n = len(instructions)
    if n < 3:
        return False, 0.0

    # 找短的后向跳转循环
    loop_count = 0
    total_loops = 0
    for i in range(n):
        text = instructions[i].lower().strip()
        parts = text.split()
        if not parts:
            continue
        mnemonic = parts[0]
        if not mnemonic.startswith('j') or mnemonic == 'jmp':
            continue

        # 尝试提取跳转目标偏移
        target_match = re.search(r'(0x[0-9a-f]+)', text, re.I)
        if not target_match:
            continue
        try:
            target = int(target_match.group(1), 16)
            # 后向跳转 + 循环体 <= max_loop_size -> 可能是自旋
            if 0 < (i - target) <= max_loop_size:
                loop_count += 1
        except (ValueError, IndexError):
            continue
        total_loops += 1

    if loop_count == 0:
        return False, 0.0

    # 置信度 = 短循环比例
    confidence = loop_count / max(1, total_loops)
    return True, min(1.0, confidence)


# 锁函数特征模型

@dataclass
class LockFunctionScore:
    """单个函数的锁特征得分"""
    func_name: str
    func_address: int = 0
    # 三维特征得分
    atomic_score: float = 0.0          # [0,1]
    spin_loop_score: float = 0.0       # [0,1]
    fence_score: float = 0.0           # [0,1]
    # 综合得分
    composite_score: float = 0.0       # [0,1]
    # 分类
    likely_lock: bool = False
    likely_unlock: bool = False
    # 证据
    evidence: List[str] = field(default_factory=list)


class LockFunctionInferrer:
    """概率锁函数识别器: 从指令序列推断同步原语

    用法:
    inferrer = LockFunctionInferrer()
    scores = inferrer.infer_functions(
        functions={'func1': ['lock cmpxchg ...', 'jne ...', 'ret'], ...}
    )
    """

    # 三维权重, 通过交叉验证校准
    _WEIGHTS = {'atomic': 0.40, 'spin': 0.35, 'fence': 0.25}

    # 分类阈值
    _LOCK_THRESHOLD = 0.50
    _UNLOCK_PATTERNS = {'mov', 'add', 'or', 'and', 'xor', 'xchg'}

    def __init__(self, arch: str = 'x86_64'):
        self._arch = arch

    def score_function(
        self,
        func_name: str,
        instructions: List[str],
        func_address: int = 0,
    ) -> LockFunctionScore:
        """为单个函数计算锁特征得分"""
        score = LockFunctionScore(
            func_name=func_name,
            func_address=func_address,
        )
        n = max(1, len(instructions))

        # 维度 1: 原子指令密度
        atomic_count = sum(
            1 for insn in instructions
            if _classify_atomic(insn.strip().split()[0] if insn.strip() else '', self._arch)
        )
        score.atomic_score = min(1.0, atomic_count / max(1, n * 0.15))
        if score.atomic_score > 0.3:
            score.evidence.append(
                f'atomic density={score.atomic_score:.2f} ({atomic_count}/{n} insns)'
            )

        # 维度 2: 自旋循环
        has_spin, spin_conf = _has_spin_loop(instructions)
        if has_spin:
            score.spin_loop_score = spin_conf
            score.evidence.append(f'spin loop detected (conf={spin_conf:.2f})')

        # 维度 3: 内存屏障密度
        fence_count = sum(
            1 for insn in instructions
            if _classify_fence(insn.strip().split()[0] if insn.strip() else '', self._arch)
        )
        score.fence_score = min(1.0, fence_count / max(1, n * 0.10))
        if score.fence_score > 0.2:
            score.evidence.append(f'fence density={score.fence_score:.2f}')

        # 综合得分
        score.composite_score = (
            self._WEIGHTS['atomic'] * score.atomic_score
            + self._WEIGHTS['spin'] * score.spin_loop_score
            + self._WEIGHTS['fence'] * score.fence_score
        )

        # 分类
        score.likely_lock = score.composite_score >= self._LOCK_THRESHOLD
        score.likely_unlock = self._is_unlock_pattern(instructions)

        return score

    def infer_functions(
        self,
        functions: Dict[str, List[str]],
        call_graph: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, LockFunctionScore]:
        """批量推断函数是否为锁操作

        functions: {函数名: [指令列表]}
        call_graph: {调用者: [被调用者列表]} 用于 unlock 配对推断

        返回: {函数名: LockFunctionScore}
        """
        scores: Dict[str, LockFunctionScore] = {}

        for name, insns in functions.items():
            scores[name] = self.score_function(name, insns)

        # 第二步: 利用调用图推断 unlock 配对
        if call_graph:
            self._pair_unlocks(scores, call_graph)

        return scores

    def _pair_unlocks(
        self,
        scores: Dict[str, LockFunctionScore],
        call_graph: Dict[str, List[str]],
    ) -> None:
        """为已识别的 lock 函数找配对的 unlock

        启发式: 若 lock_func 调用 A, 且 A 在调用图中频繁出现在 lock 之后
        则 A 可能是 unlock
        """
        lock_funcs = {
            name for name, s in scores.items() if s.likely_lock
        }
        if not lock_funcs:
            return

        # 统计: lock 函数调用了哪些函数
        unlock_candidates: Dict[str, int] = defaultdict(int)
        for lf in lock_funcs:
            callees = call_graph.get(lf, [])
            for c in callees:
                unlock_candidates[c] += 1

        # 被多个 lock 函数调用的 -> 可能是 unlock 原语
        for name, count in unlock_candidates.items():
            if count >= 2 and name in scores:
                if scores[name].likely_unlock:
                    scores[name].likely_unlock = True
                    scores[name].evidence.append(
                        f'unlock candidate (paired with {count} locks)'
                    )

    def _is_unlock_pattern(self, instructions: List[str]) -> bool:
        """检测 unlock 模式: 写操作 + 屏障 (无原子读-改-写)

        unlock 通常比 lock 简单: 不需要原子 compare-and-swap
        仅需一个带屏障的 store
        """
        # unlock 典型模式: mov [mem], 0; mfence; ret 或 xchg [mem], 0; ret
        if len(instructions) < 2:
            return False

        text_full = '\n'.join(
            i.lower().strip() for i in instructions  # 全函数扫描
        )
        # 模式: 写内存 + 可选屏障 + ret
        has_store = any(
            re.search(m, text_full) for m in (
                r'mov\s+(?:dword|qword|byte|word)\s+\[',
                r'mov\s+\[', r'xchg\s+\[',
            )
        )
        has_barrier = any(
            _classify_fence(i.strip().split()[0] if i.strip() else '', self._arch)
            for i in instructions
        )
        return has_store and (has_barrier or len(instructions) <= 5)

    @property
    def lock_threshold(self) -> float:
        return self._LOCK_THRESHOLD

    @lock_threshold.setter
    def lock_threshold(self, val: float) -> None:
        self._LOCK_THRESHOLD = max(0.1, min(1.0, val))
