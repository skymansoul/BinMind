"""
HOIG Verifier — 将 HOIG 集成到现有 UAF 管线.

作为 GAPSBV-UAF 的补充维度, HOIG 提供:
  1. 对象身份追踪 → 消除指针名不同导致的 FP
  2. realloc 对象延续 → 消除 realloc 后的伪 UAF
  3. 跨函数对象传播 → 发现被调用者内部释放的 UAF

与现有管线的关系:
  PTASM:     状态机追踪 (LIVE/FREED/NULLIFIED/REASSIGNED)
  TARPS:     5阶段级联过滤 (Pattern→Alias→Path→Escape→InterProc)
  Temporal:  BFS 路径验证
  HOIG (NEW): 对象身份图 — 补充别名分析和 realloc 追踪

HOIG 聚焦于 Temporal Path Verifier 的 2 个误报和 1 个漏报:
  - FP (refcount): 对象身份不同, 但因指针别名被误判 UAF
  - FP (cross-func): 跨函数 free 后的 use 被误判 (因为不知道跨函数)
  - FN (sample25): 链表释放 - 需要对象身份追踪
"""


import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .uaf_hoig_types import (
    ObjState, ObjectID, ObjStateAtPoint,
    IdentityEdge, FuncObjSummary, UafHoigVerdict,
)
from .uaf_hoig_builder import HoigBuilder
from .uaf_hoig_cross_func import HoigCrossFuncVerifier


class HoigVerifier:
    """HOIG 集成验证器.

    在现有 UAF 管线判定基础上, 用 HOIG 进行二次验证:
      - HOIG 判定 SAFE → 过滤 PTASM 的 CONFIRMED (减少 FP)
      - HOIG 判定 CONFIRMED → 补充 PTASM 的 UNCERTAIN (减少 FN)
    """

    def __init__(self):
        self.hdb: Dict[str, Dict[str, Any]] = {}  # sample → hoig_data

    def verify_single(self, pseudocode: str, func_name: str = "",
                      entry_bindings: Optional[Dict[str, ObjectID]] = None
                      ) -> UafHoigVerdict:
        """单个函数的 HOIG 验证.

        返回最严重的 UAF 判定 (CONFIRMED > UNCERTAIN > SAFE).
        """
        builder = HoigBuilder()
        _, _, verdicts = builder.build(pseudocode, func_name, entry_bindings)

        confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
        if confirmed:
            return max(confirmed, key=lambda v: v.confidence)

        return UafHoigVerdict(
            verdict='SAFE', confidence=0.80,
            reason='No UAF detected by HOIG',
        )

    def verify_multi_func(self,
                          func_bodies: Dict[str, str],
                          calls: List[Tuple[str, str]]
                          ) -> List[UafHoigVerdict]:
        """多函数 HOIG 验证 (含跨函数分析).

        Args:
            func_bodies: {func_name: pseudocode}
            calls: [(caller, callee), ...]

        Returns:
            HOIG verdicts (intra + cross-function)
        """
        all_verdicts: List[UafHoigVerdict] = []

        # Phase 1: 单函数内验证
        for fname, body in func_bodies.items():
            v = self.verify_single(body, fname)
            if v.verdict == 'CONFIRMED':
                all_verdicts.append(v)

        # Phase 2: 跨函数验证
        cross_verifier = HoigCrossFuncVerifier()
        for fname, body in func_bodies.items():
            cross_verifier.register(fname, body)
        for caller, callee in calls:
            cross_verifier.register_call(caller, callee)

        cross_verdicts = cross_verifier.verify_all()
        all_verdicts.extend(cross_verdicts)

        return all_verdicts

    def refine_ptasm(self, ptasm_verdict: str, hoig_verdict: str
                     ) -> Tuple[str, str]:
        """HOIG 精化 PTASM 判定.

        HOIG SAFE → 过滤 PTASM 的误报.
        HOIG CONFIRMED → 补充 PTASM 的漏报.
        HOIG UNCERTAIN → 保持 PTASM 判定.
        """
        if hoig_verdict == 'SAFE' and ptasm_verdict in ('CONFIRMED', 'LIKELY'):
            return ('SAFE',
                    'HOIG: object identity proves no UAF (different ObjectIDs)')
        if hoig_verdict == 'CONFIRMED' and ptasm_verdict in ('SAFE', 'UNCERTAIN'):
            return ('CONFIRMED',
                    'HOIG: cross-function object lifetime tracking reveals UAF')
        return (ptasm_verdict, 'HOIG: no refinement needed')


class HoigReallocTracker:
    """realloc 对象身份延续追踪器.

    解决 realloc 的特殊语义:
      - realloc(ptr, size): 若成功, 返回新指针, 旧指针悬垂
      - 但对象身份延续 (同一逻辑对象)
      - 旧指针不应再被使用 (但如果通过新指针访问, 则不是 UAF)

    关键检测:
      1. realloc 后使用旧指针 → UAF (旧指针是悬垂的)
      2. 通过 struct->field 的 realloc 传播 → 需要字段敏感的追踪
    """

    def __init__(self):
        self.realloc_chains: Dict[str, List[str]] = {}  # old → [new, new2, ...]

    def analyze(self, pseudocode: str) -> List[UafHoigVerdict]:
        """分析 realloc 后的指针使用."""
        verdicts: List[UafHoigVerdict] = []
        lines = pseudocode.split('\n')

        realloc_map: Dict[str, Tuple[str, int]] = {}  # old → (new, line)
        freed_at_line: Dict[str, int] = {}  # ptr → realloc_line

        for lineno, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # 检测 realloc
            realloc_m = re.search(
                r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(\s*(\w[\w]*)\s*,',
                line)
            if realloc_m:
                new_ptr = realloc_m.group(1)
                old_ptr = realloc_m.group(2)
                realloc_map[old_ptr] = (new_ptr, lineno)
                freed_at_line[old_ptr] = lineno
                continue

            # 检测 realloc 后使用旧指针
            for old_ptr, (new_ptr, rl) in realloc_map.items():
                # 跳过同一行 (realloc 自己的行)
                if lineno == rl:
                    continue
                # 旧指针是否被解引用
                if (f'*{old_ptr}' in line or f'{old_ptr}->' in line
                        or f'{old_ptr}[' in line):
                    # 检查旧指针是否被 NULL check (安全模式)
                    if f'if ({old_ptr})' in line or f'if({old_ptr})' in line:
                        continue
                    verdicts.append(UafHoigVerdict(
                        verdict='CONFIRMED',
                        confidence=0.92,
                        free_line=rl,
                        use_line=lineno,
                        use_var=old_ptr,
                        free_var=old_ptr,
                        reason=f'realloc frees old ptr {old_ptr} at L{rl}, '
                               f'use of {old_ptr} at L{lineno}',
                    ))

        return verdicts


__all__ = ['HoigVerifier', 'HoigReallocTracker']
