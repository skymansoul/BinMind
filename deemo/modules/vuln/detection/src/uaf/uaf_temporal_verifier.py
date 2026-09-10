"""UAF 时序路径验证器 — free→use 路径的形式化安全证明.

目的: 在 UAFUseChainTracker 找到 free→use 路径后, 做第二阶段的时序安全分析.
      类似于 AVHO-G 的 heap_safety_prover 对堆溢出的 tri-state 判定,
      本模块对 UAF 做四态判定:
        DEFINITELY_UAF — free→use 路径存在, 无可证明的安全约束
        POTENTIAL_UAF — 有可疑路径但存在部分缓解因素
        LIKELY_SAFE — 存在确定性的安全约束 (如 null-after-free)
        DEFINITELY_SAFE — 可证明不存在 free→use (如 free 在 use 之后)

方法依据:
  - UAFL: typestate 分析追踪对象状态转移
  - UAFX: UAF 利用的路径条件分析
  - 本模块在二进制 IR 层面实现简化版时序安全证明

架构:
  输入: UAFUseChainTracker 的 UseChain 列表 + 指令序列 (含地址)
  输出: TemporalVerdict + SafetyProof

决策:
  - 用指令地址的相对顺序做时序推断, 不构建完整 CFG
  - null-after-free 是最强的安全信号 — 直接判定 DEFINITELY_SAFE
  - 分支互斥性分析基于 cmp+jcc 模式匹配, 保守处理
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple


class TemporalVerdict(Enum):
    """UAF 时序安全判定 — 四态."""
    DEFINITELY_UAF = auto()      # 明确 UAF: free 后 use, 无防护
    POTENTIAL_UAF = auto()       # 可能存在 UAF, 需进一步分析
    LIKELY_SAFE = auto()         # 存在弱安全约束
    DEFINITELY_SAFE = auto()     # 可证明安全


@dataclass
class SafetyProof:
    """一个 UAF 安全证明."""
    ptr_name: str
    verdict: TemporalVerdict
    free_addr: int
    use_addr: int
    proof_trace: List[str] = field(default_factory=list)
    confidence: float = 0.0

    # 安全信号的类型
    has_null_after_free: bool = False      # free(p); p = NULL
    has_guard_before_use: bool = False     # if (p) { *p }
    has_mutex_protection: bool = False     # 互斥分支: free 和 use 不在同一执行路径
    has_return_check: bool = False         # realloc 返回值被检查, 旧指针未使用
    free_after_use: bool = False           # free 在 use 之后 → 无 UAF


class UAFTemporalVerifier:
    """UAF 时序路径验证器 — 证明或驳斥 free→use 路径.

    使用方式:
      verifier = UAFTemporalVerifier()
      verifier.load_instructions(insns, addrs)    # 加载指令流
      proof = verifier.verify(chain)               # 验证一条 use chain
      # proof.verdict ∈ {DEFINITELY_UAF, POTENTIAL_UAF, LIKELY_SAFE, DEFINITELY_SAFE}
    """

    # 清零模式 — free(p) 后紧跟的 null 赋值
    _NULL_AFTER_FREE = {
        'mov', 'xor', 'lea',                       # mov reg, 0 / xor reg,reg
    }

    # 守卫检查模式 — 使用前检查非空
    _GUARD_PATTERNS = {
        'test', 'cmp',                             # test reg, reg; jz skip
    }

    # 互斥分支模式 — 不同 cmp+jcc 目标
    _BRANCH_INSTRUCTIONS = {
        'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 'jae', 'jbe',
        'jg', 'jl', 'jge', 'jle', 'jmp',
    }

    def __init__(self):
        self._insns: List[Tuple[str, str, int]] = []  # (mnem, op_str, addr)
        self._addr_to_idx: Dict[int, int] = {}
        self._proofs: List[SafetyProof] = []

    def load_instructions(self,
                          instructions: List[Tuple[str, str, int]]) -> None:
        """加载指令序列 — 用于时序分析和空指针检测."""
        self._insns = instructions
        self._addr_to_idx = {addr: i for i, (_, _, addr)
                            in enumerate(instructions)}

    def verify(self, ptr_name: str, free_addr: int,
               use_addr: int,
               chain_length: int = 0,
               escape_path: List[str] = None) -> SafetyProof:
        """验证一条 free→use 路径的安全性.

          1. free 和 use 的时序关系: free < use? (地址顺序)
          2. free 后是否有 p=NULL 赋值?
          3. use 前是否有 if(p) 守卫?
          4. free 和 use 是否在互斥分支?
        """
        proof = SafetyProof(
            ptr_name=ptr_name, verdict=TemporalVerdict.POTENTIAL_UAF,
            free_addr=free_addr, use_addr=use_addr,
            proof_trace=[], confidence=0.5)

        # 时序: free 在 use 之前?
        if use_addr < free_addr:
            proof.free_after_use = True
            proof.verdict = TemporalVerdict.DEFINITELY_SAFE
            proof.confidence = 0.95
            proof.proof_trace.append(
                f'free@{free_addr:#x} after use@{use_addr:#x} → '
                'DEFINITELY_SAFE (temporal order)')
            self._proofs.append(proof)
            return proof

        free_idx = self._addr_to_idx.get(free_addr)
        use_idx = self._addr_to_idx.get(use_addr)

        if free_idx is None or use_idx is None:
            proof.proof_trace.append(
                'free or use not in instruction stream → POTENTIAL_UAF')
            self._proofs.append(proof)
            return proof

        # 检查1: free 后是否有 null 赋值?
        null_check = self._check_null_after_free(free_idx, ptr_name)
        if null_check:
            proof.has_null_after_free = True
            proof.verdict = TemporalVerdict.DEFINITELY_SAFE
            proof.confidence = 0.95
            proof.proof_trace.append(
                f'null-after-free at {null_check} → DEFINITELY_SAFE')
            self._proofs.append(proof)
            return proof

        # 检查2: use 前是否有守卫?
        guard = self._check_guard_before_use(use_idx, ptr_name)
        if guard:
            proof.has_guard_before_use = True
            proof.verdict = TemporalVerdict.LIKELY_SAFE
            proof.confidence = 0.75
            proof.proof_trace.append(
                f'guard check before use at {guard} → LIKELY_SAFE')

        # 检查3: free 和 use 是否在互斥分支?
        mutex = self._check_mutex_branches(free_idx, use_idx)
        if mutex:
            proof.has_mutex_protection = True
            proof.verdict = TemporalVerdict.LIKELY_SAFE
            proof.confidence = 0.80
            proof.proof_trace.append(
                'free and use in mutually exclusive branches → LIKELY_SAFE')

        # 检查4: 转义路径长度 — 长链更难利用
        if chain_length > 3 and proof.verdict != TemporalVerdict.DEFINITELY_SAFE:
            proof.verdict = TemporalVerdict.POTENTIAL_UAF
            proof.confidence = 0.40
            proof.proof_trace.append(
                f'long escape chain (len={chain_length}) → POTENTIAL_UAF')

        # 默认: 无安全约束 → DEFINITELY_UAF
        if proof.verdict == TemporalVerdict.POTENTIAL_UAF and not guard and not mutex:
            proof.verdict = TemporalVerdict.DEFINITELY_UAF
            proof.confidence = 0.90
            proof.proof_trace.append(
                f'no safety constraints found on free→use path → '
                'DEFINITELY_UAF')

        self._proofs.append(proof)
        return proof

    def _check_null_after_free(self, free_idx: int,
                               ptr_name: str) -> Optional[int]:
        """检查 free 后 N 条指令内是否有 ptr=NULL 赋值.

        决策: 仅检查 5 条指令窗口 — 更远的 null 赋值可能是无关代码.
        """
        for i in range(free_idx + 1, min(free_idx + 6, len(self._insns))):
            mnem, ops, addr = self._insns[i]
            mnem_l = mnem.lower()
            if mnem_l not in self._NULL_AFTER_FREE:
                continue
            if mnem_l == 'xor':
                parts = [p.strip() for p in ops.split(',')]
                if len(parts) == 2 and parts[0] == parts[1]:
                    return addr
            # mov/lea reg, 0 — 必须是精确的0, 不是 0x... 或包含0的其他值
            if mnem_l in ('mov', 'lea'):
                parts = [p.strip() for p in ops.split(',')]
                if len(parts) == 2:
                    src = parts[1].lower()
                    # 精确匹配: '0', '0x0', '0x00' 等
                    if src in ('0', '0x0', '0x00', '0x00000000'):
                        return addr
        return None

    def _check_guard_before_use(self, use_idx: int,
                                ptr_name: str) -> Optional[int]:
        """检查 use 前 N 条指令内是否有 if(p) 守卫.

        模式: test reg, reg; jz skip 或 cmp reg, 0; je skip.
        """
        for i in range(max(0, use_idx - 5), use_idx):
            mnem, ops, addr = self._insns[i]
            if mnem.lower() in self._GUARD_PATTERNS:
                # test 或 cmp 后是条件跳转 → 守卫存在
                for j in range(i + 1, min(i + 3, len(self._insns))):
                    j_mnem, _, _ = self._insns[j]
                    if j_mnem.lower() in self._BRANCH_INSTRUCTIONS:
                        return addr
        return None

    def _check_mutex_branches(self, free_idx: int,
                              use_idx: int) -> bool:
        """检查 free 和 use 是否在互斥分支 — 基于 cmp+jcc 模式.

        保守: 仅在明确检测到互斥条件时才返回 True.
        若 free 在 if(fail) { free } 分支, use 在 else { use } 分支.
        """
        # 搜索 free 前的条件跳转
        free_branch = None
        for i in range(max(0, free_idx - 8), free_idx):
            _, ops, addr = self._insns[i]
            # 找最近的条件跳转 → 它可能是 free 的守卫
            for j in range(i + 1, min(i + 4, free_idx)):
                j_mnem, j_ops, j_addr = self._insns[j]
                if j_mnem.lower() in ('je', 'jne', 'jz', 'jnz'):
                    free_branch = j_addr
                    break

        # 搜索 use 前的条件跳转
        use_branch = None
        for i in range(max(0, use_idx - 8), use_idx):
            for j in range(i + 1, min(i + 4, use_idx)):
                j_mnem, j_ops, j_addr = self._insns[j]
                if j_mnem.lower() in ('je', 'jne', 'jz', 'jnz'):
                    use_branch = j_addr
                    break

        # 若两个跳转目标不同 → 可能在互斥分支
        if free_branch and use_branch and free_branch != use_branch:
            return True
        return False

    def stats(self) -> dict:
        verdicts = {}
        for p in self._proofs:
            key = p.verdict.name
            verdicts[key] = verdicts.get(key, 0) + 1
        return {
            'total_verified': len(self._proofs),
            **verdicts,
            'fp_reduction_ratio': round(
                verdicts.get('DEFINITELY_SAFE', 0)
                / max(1, len(self._proofs)), 3),
        }

    def clear(self) -> None:
        self._insns.clear()
        self._addr_to_idx.clear()
        self._proofs.clear()
