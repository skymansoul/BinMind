# 语义保持的汇编指令变换器
# 用于 adversarial_variant_gen.py 的二进制变体生成

import re
import random
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class TransformKind(Enum):
    REG_RENAME = 'reg_rename'
    INST_REORDER = 'inst_reorder'
    INST_REPLACE = 'inst_replace'
    NOP_PAD = 'nop_pad'
    CONST_ENCODE = 'const_encode'
    BRANCH_INVERT = 'branch_invert'
    PUSH_POP_SUBST = 'push_pop_subst'


@dataclass
class TransformResult:
    original_instr: str
    transformed_instr: str
    kind: TransformKind
    perturbation_radius: float
    address: int = 0


class SemanticPreservingTransform:
    """语义保持的汇编指令变换器。

    等价寄存器分组（x86_64）——排除rsp/rbp:
      G0: {rax, rbx, rcx, rdx, rsi, rdi}
      G1: {r8, r9, r10, r11, r12, r13, r14, r15}

    等价指令对:
      xor reg,reg ↔ mov reg,0
      add reg,1 ↔ inc reg
      test reg,reg ↔ cmp reg,0
    """

    _REG_GROUPS = [
        {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi'},
        {'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'},
    ]

    _EQUIV_INST = [
        (r'\bxor\s+(\w+),\s*\1\b', lambda m: f'mov {m.group(1)}, 0'),
        (r'\bmov\s+(\w+),\s*0\b', lambda m: f'xor {m.group(1)}, {m.group(1)}'),
        (r'\badd\s+(\w+),\s*1\b', lambda m: f'inc {m.group(1)}'),
        (r'\bsub\s+(\w+),\s*1\b', lambda m: f'dec {m.group(1)}'),
        (r'\btest\s+(\w+),\s*\1\b', lambda m: f'cmp {m.group(1)}, 0'),
        (r'\bcmp\s+(\w+),\s*0\b', lambda m: f'test {m.group(1)}, {m.group(1)}'),
    ]

    _PERTURBATION_COST = {
        TransformKind.NOP_PAD: 0.01,
        TransformKind.REG_RENAME: 0.02,
        TransformKind.CONST_ENCODE: 0.01,
        TransformKind.INST_REORDER: 0.03,
        TransformKind.INST_REPLACE: 0.05,
        TransformKind.BRANCH_INVERT: 0.08,
        TransformKind.PUSH_POP_SUBST: 0.04,
    }

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)

    @classmethod
    def perturbation_cost(cls, kind: TransformKind) -> float:
        return cls._PERTURBATION_COST.get(kind, 0.02)

    def apply_transform(self, instructions: List[str],
                        allowed_kinds: Optional[List[TransformKind]] = None,
                        max_perturbation: float = 0.3
                        ) -> List[TransformResult]:
        if allowed_kinds is None:
            allowed_kinds = list(TransformKind)

        results = []
        cumulative = 0.0
        dep_graph = self._analyze_dependencies(instructions)

        for idx, instr in enumerate(instructions):
            if cumulative >= max_perturbation:
                break
            available = [k for k in allowed_kinds
                        if self.perturbation_cost(k) <= max_perturbation - cumulative]
            if not available:
                continue
            kind = self._rng.choice(available)
            result = self._try_transform(instr, kind, idx, instructions, dep_graph)
            if result is not None:
                results.append(result)
                cumulative += result.perturbation_radius
        return results

    def _try_transform(self, instr: str, kind: TransformKind, idx: int,
                       all_instrs: List[str],
                       dep_graph: Dict[int, Set[int]]) -> Optional[TransformResult]:
        stripped = instr.strip()
        if not stripped or stripped.startswith(';') or stripped.startswith('#'):
            return None
        if kind == TransformKind.REG_RENAME:
            return self._reg_rename(stripped)
        elif kind == TransformKind.INST_REPLACE:
            return self._inst_replace(stripped)
        elif kind == TransformKind.NOP_PAD:
            return self._nop_pad(stripped)
        elif kind == TransformKind.INST_REORDER:
            return self._inst_reorder(idx, all_instrs, dep_graph)
        elif kind == TransformKind.CONST_ENCODE:
            return self._const_encode(stripped)
        return None

    def _reg_rename(self, instr: str) -> Optional[TransformResult]:
        used_regs = set(re.findall(r'\b(r[a-z0-9]+)\b', instr.lower()))
        for group in self._REG_GROUPS:
            inter = used_regs & group
            if not inter:
                continue
            candidates = group - inter
            if not candidates:
                continue
            old_reg = self._rng.choice(list(inter))
            new_reg = self._rng.choice(list(candidates))
            new_instr = re.sub(rf'\b{old_reg}\b', new_reg, instr)
            if new_instr == instr:
                return None
            return TransformResult(original_instr=instr, transformed_instr=new_instr,
                                  kind=TransformKind.REG_RENAME, perturbation_radius=0.02)
        return None

    def _inst_replace(self, instr: str) -> Optional[TransformResult]:
        plist = list(self._EQUIV_INST)
        self._rng.shuffle(plist)
        for pattern, repl_fn in plist:
            m = re.search(pattern, instr, re.I)
            if m:
                ni = repl_fn(m)
                if ni != instr:
                    return TransformResult(original_instr=instr, transformed_instr=ni,
                                          kind=TransformKind.INST_REPLACE,
                                          perturbation_radius=0.05)
        return None

    def _nop_pad(self, instr: str) -> Optional[TransformResult]:
        if self._rng.random() < 0.3:
            return TransformResult(original_instr=instr,
                                  transformed_instr=f"nop\n{instr}",
                                  kind=TransformKind.NOP_PAD,
                                  perturbation_radius=0.01)
        return None

    def _inst_reorder(self, idx: int, all_instrs: List[str],
                      dep_graph: Dict[int, Set[int]]) -> Optional[TransformResult]:
        if idx >= len(all_instrs) - 1:
            return None
        deps = dep_graph.get(idx, set())
        if idx + 1 in deps or idx in dep_graph.get(idx + 1, set()):
            return None
        a, b = all_instrs[idx], all_instrs[idx + 1]
        if not a.strip() or not b.strip():
            return None
        return TransformResult(original_instr=f"{a}\n{b}",
                              transformed_instr=f"{b}\n{a}",
                              kind=TransformKind.INST_REORDER,
                              perturbation_radius=0.03)

    def _const_encode(self, instr: str) -> Optional[TransformResult]:
        m = re.search(r'\b(0x[0-9a-fA-F]+|\d+)\b', instr)
        if not m:
            return None
        return TransformResult(original_instr=instr, transformed_instr=instr,
                              kind=TransformKind.CONST_ENCODE,
                              perturbation_radius=0.01)

    @staticmethod
    def _analyze_dependencies(instructions: List[str]) -> Dict[int, Set[int]]:
        deps = defaultdict(set)
        last_writer = {}
        for idx, instr in enumerate(instructions):
            tokens = re.findall(r'\b(r[a-z0-9]+|[a-z]{2,})\b', instr.lower())
            for r in set(tokens):
                if r in last_writer:
                    deps[last_writer[r]].add(idx)
            parts = instr.split(',')
            if parts:
                writers = set(re.findall(r'\b(r[a-z0-9]+)\b', parts[0].lower()))
                for w in writers:
                    last_writer[w] = idx
        return dict(deps)
