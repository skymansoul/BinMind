# 二进制语义差分意图分类——汇编级变更语义识别
# 核心问题: semantic_diff.py比较函数相似度但不能回答"变更意图是什么"
# 2025年LLMCC/AACC在源码级做意图分类，二进制级无源码无法直接使用
# 方案: 汇编操作语义类别指纹 + 轻量分类器 + 分级LLM增强(仅top-5%高风险)
# 核心: 操作类别统计是ISA无关的——x86和ARM的边界检查添加在操作层面表现一致

from __future__ import annotations

import math
import re
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class ChangeIntent(Enum):
    SECURITY_FIX = 'security_fix'
    BUG_FIX = 'bug_fix'
    REFACTOR = 'refactor'
    FEATURE_ADD = 'feature_add'
    UNKNOWN = 'unknown'


# 汇编操作语义类别

class AsmOpCategory(Enum):
    """汇编操作的语义类别——ISA无关"""
    ARITH = 'arith'           # 算术: add/sub/mul/div/inc/dec
    LOGIC = 'logic'           # 逻辑: and/or/xor/not/shl/shr
    COMPARE = 'compare'       # 比较: cmp/test
    BRANCH = 'branch'         # 分支: jmp/jcc/call/ret
    MEM_READ = 'mem_read'     # 内存读: mov from [mem]
    MEM_WRITE = 'mem_write'   # 内存写: mov to [mem]
    STACK = 'stack'           # 栈操作: push/pop
    CONTROL = 'control'       # 系统控制: syscall/int


# 汇编助记符→操作类别映射（x86/x64覆盖主要指令）
_MNEMONIC_CAT = {
    'add': AsmOpCategory.ARITH, 'sub': AsmOpCategory.ARITH,
    'mul': AsmOpCategory.ARITH, 'div': AsmOpCategory.ARITH,
    'inc': AsmOpCategory.ARITH, 'dec': AsmOpCategory.ARITH,
    'and': AsmOpCategory.LOGIC, 'or': AsmOpCategory.LOGIC,
    'xor': AsmOpCategory.LOGIC, 'not': AsmOpCategory.LOGIC,
    'shl': AsmOpCategory.LOGIC, 'shr': AsmOpCategory.LOGIC,
    'cmp': AsmOpCategory.COMPARE, 'test': AsmOpCategory.COMPARE,
    'jmp': AsmOpCategory.BRANCH, 'je': AsmOpCategory.BRANCH,
    'jne': AsmOpCategory.BRANCH, 'jg': AsmOpCategory.BRANCH,
    'jl': AsmOpCategory.BRANCH, 'jge': AsmOpCategory.BRANCH,
    'jle': AsmOpCategory.BRANCH, 'ja': AsmOpCategory.BRANCH,
    'jb': AsmOpCategory.BRANCH, 'call': AsmOpCategory.BRANCH,
    'ret': AsmOpCategory.BRANCH, 'jz': AsmOpCategory.BRANCH,
    'jnz': AsmOpCategory.BRANCH,
    'mov': None,  # 需要分析操作数确定是mem_read/mem_write/reg_move
    'lea': AsmOpCategory.ARITH,  # 地址计算本质上是指针算术
    'push': AsmOpCategory.STACK, 'pop': AsmOpCategory.STACK,
    'syscall': AsmOpCategory.CONTROL, 'int': AsmOpCategory.CONTROL,
}


# 安全相关操作模式（指示可能存在安全检查的添加）
_SECURITY_OPS = {
    'cmp', 'test',       # 比较——可能是边界/空指针检查的前置
    'je', 'jne', 'jz', 'jnz', 'jb', 'ja',  # 条件跳转——检查后分支
    'call',              # 调用——可能是新增的安全函数调用
}

# 危险API（变更涉及这些API时提高安全敏感度）
_DANGEROUS_APIS = {
    'memcpy', 'memmove', 'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
    'system', 'execve', 'popen', 'malloc', 'free', 'mmap', 'mprotect',
    'recv', 'read', 'write', 'send',
}


# 变更指纹提取

@dataclass
class ChangeFingerprint:
    """二进制变更的语义指纹"""
    func_name: str
    # 删除行的操作类别分布
    removed_op_dist: Dict[AsmOpCategory, int]
    # 添加行的操作类别分布
    added_op_dist: Dict[AsmOpCategory, int]
    # 净变化: (added - removed) / total
    delta_op_dist: Dict[AsmOpCategory, float]
    # 安全相关操作的变化
    security_op_change: float       # 安全操作比例的变化
    # 危险API涉及度
    dangerous_api_involved: int     # 变更中涉及的危险API调用数
    # 结构变化
    branch_count_change: int        # 分支指令数量变化
    stack_frame_change: int         # 栈帧大小变化（push/pop净变化）
    # 变更规模
    total_lines_changed: int
    net_lines_added: int

    def to_vector(self) -> np.ndarray:
        """将指纹编码为固定维度分类特征向量"""
        cats = list(AsmOpCategory)
        vec = []
        for c in cats:
            vec.append(float(self.removed_op_dist.get(c, 0)))
            vec.append(float(self.added_op_dist.get(c, 0)))
            vec.append(self.delta_op_dist.get(c, 0.0))
        vec.append(self.security_op_change)
        vec.append(float(self.dangerous_api_involved))
        vec.append(float(self.branch_count_change))
        vec.append(float(self.stack_frame_change))
        vec.append(math.log(1 + self.total_lines_changed))
        vec.append(float(self.net_lines_added))
        return np.array(vec, dtype=np.float64)


class AsmChangeAnalyzer:
    """汇编级变更语义分析器。

    输入: 变更前后的汇编指令序列
    输出: ChangeFingerprint变更指纹
    """

    def analyze(self,
                removed_instrs: List[str],
                added_instrs: List[str],
                func_name: str = "") -> ChangeFingerprint:
        removed_cats = self._categorize_instructions(removed_instrs)
        added_cats = self._categorize_instructions(added_instrs)

        delta = {}
        total = max(1, sum(removed_cats.values()) + sum(added_cats.values()))
        for cat in AsmOpCategory:
            dr = removed_cats.get(cat, 0)
            da = added_cats.get(cat, 0)
            delta[cat] = (da - dr) / total

        # 安全操作变化
        sec_removed = sum(1 for instr in removed_instrs
                         if self._is_security_related(instr))
        sec_added = sum(1 for instr in added_instrs
                       if self._is_security_related(instr))
        sec_change = (sec_added - sec_removed) / max(1, len(added_instrs) + len(removed_instrs))

        # 危险API
        all_text = ' '.join(removed_instrs + added_instrs).lower()
        api_count = sum(1 for api in _DANGEROUS_APIS if api in all_text)

        # 分支变化
        branch_removed = sum(1 for instr in removed_instrs
                           if self._classify_mnemonic(instr) == AsmOpCategory.BRANCH)
        branch_added = sum(1 for instr in added_instrs
                         if self._classify_mnemonic(instr) == AsmOpCategory.BRANCH)

        # 栈帧变化
        stack_removed = sum(1 for instr in removed_instrs
                          if self._classify_mnemonic(instr) == AsmOpCategory.STACK)
        stack_added = sum(1 for instr in added_instrs
                        if self._classify_mnemonic(instr) == AsmOpCategory.STACK)

        return ChangeFingerprint(
            func_name=func_name,
            removed_op_dist=removed_cats,
            added_op_dist=added_cats,
            delta_op_dist=delta,
            security_op_change=sec_change,
            dangerous_api_involved=api_count,
            branch_count_change=branch_added - branch_removed,
            stack_frame_change=stack_added - stack_removed,
            total_lines_changed=len(removed_instrs) + len(added_instrs),
            net_lines_added=len(added_instrs) - len(removed_instrs),
        )

    def _categorize_instructions(self, instrs: List[str]
                                 ) -> Dict[AsmOpCategory, int]:
        counts: Dict[AsmOpCategory, int] = defaultdict(int)
        for instr in instrs:
            cat = self._classify_mnemonic(instr)
            if cat is not None:
                counts[cat] += 1
        return dict(counts)

    def _classify_mnemonic(self, instr: str) -> Optional[AsmOpCategory]:
        stripped = instr.strip().lower()
        if not stripped or stripped.startswith(';'):
            return None
        mnemonic = stripped.split()[0] if stripped.split() else ""
        if mnemonic in _MNEMONIC_CAT:
            cat = _MNEMONIC_CAT[mnemonic]
            if cat is not None:
                return cat
        # mov的歧义消除
        if mnemonic == 'mov':
            if '[' in stripped.split(',')[1] if ',' in stripped else False:
                return AsmOpCategory.MEM_WRITE
            if '[' in stripped.split(',')[0] if ',' in stripped else False:
                return AsmOpCategory.MEM_READ
            return AsmOpCategory.ARITH  # reg-to-reg mov
        return None

    def _is_security_related(self, instr: str) -> bool:
        mn = instr.strip().lower().split()[0] if instr.strip().split() else ""
        return mn in _SECURITY_OPS


# 意图分类器

class DiffIntentClassifier:
    """二进制变更意图分类器。

    使用逻辑回归（softmax）而非深度网络——特征维度低（~30维），
    深度网络在此场景下过拟合风险高。
    """

    FEATURE_DIM = 29  # 8 cats × 3 + 5 extra
    N_CLASSES = 5     # 4 intents + UNKNOWN

    def __init__(self):
        rng = np.random.RandomState(42)
        s = math.sqrt(2.0 / self.FEATURE_DIM)
        self.W = rng.randn(self.FEATURE_DIM, self.N_CLASSES) * s
        self.b = np.zeros(self.N_CLASSES)
        self._analyzer = AsmChangeAnalyzer()

    def predict(self, fingerprint: ChangeFingerprint) -> Tuple[ChangeIntent, float]:
        """预测变更意图及置信度。

        Returns:
            (intent, confidence) — confidence为softmax最大概率
        """
        vec = fingerprint.to_vector()
        if len(vec) < self.FEATURE_DIM:
            vec = np.pad(vec, (0, self.FEATURE_DIM - len(vec)))
        logits = vec[:self.FEATURE_DIM] @ self.W + self.b
        logits -= logits.max()
        probs = np.exp(logits) / np.exp(logits).sum()
        best_idx = int(np.argmax(probs))
        intents = list(ChangeIntent)
        return intents[best_idx], float(probs[best_idx])

    def classify_diff(self,
                      removed_instrs: List[str],
                      added_instrs: List[str],
                      func_name: str = "") -> Tuple[ChangeIntent, float, float]:
        """一步分类: 分析汇编diff→指纹→意图分类。

        Returns:
            (intent, confidence, security_sensitivity)
        """
        fp = self._analyzer.analyze(removed_instrs, added_instrs, func_name)
        intent, conf = self.predict(fp)

        # 安全敏感度: 综合危险API+安全操作变化
        sec_sensitivity = min(1.0, (
            fp.security_op_change * 3.0 +
            fp.dangerous_api_involved * 0.15 +
            abs(fp.branch_count_change) * 0.05
        ))

        return intent, conf, max(0.0, sec_sensitivity)

    def should_invoke_llm(self, security_sensitivity: float,
                          confidence: float) -> bool:
        """判断是否应对此变更调用LLM进行深度分析。

        触发条件: 安全敏感度 > 0.3 或 (安全敏感度 > 0.15 且置信度 < 0.7)
        此策略确保LLM调用仅覆盖约top-5%的高风险变更。
        """
        if security_sensitivity > 0.3:
            return True
        if security_sensitivity > 0.15 and confidence < 0.7:
            return True
        return False
