# UAF路径敏感分析器——区分条件free和无条件free
# uaf_state_machine.py的核心缺陷2: 假设每个free都必然执行
# 实际代码中: if(err) { free(ptr); return; } — free是条件执行的
# 若条件不成立，后续use(ptr)是安全的——不是UAF
#
# 改进:
#   1. 识别free所在基本块的前驱条件(cmp/test + jcc)
#   2. 若free在条件分支内，降低置信度(conservative downgrade)
#   3. 若free在无条件路径(直行代码)，保持高置信度
#   4. 识别return/exit后的free——这些是清理代码，后续use不可达
#
# 理论: 基于路径敏感的污点分析思想，在二进制层面做轻量级条件推理
#       不执行完整符号执行，仅利用cmp/jcc的局部约束

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class FreeCertainty(Enum):
    UNCONDITIONAL = 'unconditional'   # 必然执行——最高风险
    CONDITIONAL = 'conditional'       # 条件执行——中等风险
    UNREACHABLE_AFTER = 'unreachable_after'  # free后立即返回——低风险
    UNKNOWN = 'unknown'


@dataclass
class PathContext:
    """free点的路径上下文"""
    free_idx: int
    bb_id: int                     # 所在基本块
    has_preceding_cond: bool = False  # 前面是否有条件跳转
    cond_type: str = ""            # 'je','jne','jg','jl'等
    has_return_after: bool = False # free后是否有return
    has_call_after: bool = False   # free后是否有其他call
    certainty: FreeCertainty = FreeCertainty.UNKNOWN
    evidence: List[str] = field(default_factory=list)


class UafPathAnalyzer:
    """路径敏感的UAF分析器。

    分析流程:
      1. 识别函数中所有free点
      2. 对每个free，向上查找到达free的路径条件
      3. 向下查找free后的控制流(是否return/exit)
      4. 综合判定free的确定性
    """

    # 条件跳转指令
    _JCC_PATTERN = re.compile(
        r'\b(j[eznglabcpos]|jn?[abceglopsz]|jmp)\b', re.I)
    _RET_PATTERN = re.compile(r'\b(ret|retn|hlt)\b', re.I)
    _CMP_TEST_PATTERN = re.compile(
        r'\b(cmp|test|or)\s+', re.I)

    def analyze_free_sites(self,
                           instructions: List[str],
                           bb_boundaries: List[Tuple[int, int]],
                           free_sites: List[int]
                           ) -> Dict[int, PathContext]:
        """分析所有free站点的路径上下文"""
        n = len(instructions)
        results: Dict[int, PathContext] = {}

        # 构建索引→基本块映射
        idx_to_bb: Dict[int, int] = {}
        for bb_id, (start, end) in enumerate(bb_boundaries):
            for i in range(start, min(end, n)):
                idx_to_bb[i] = bb_id

        for free_idx in free_sites:
            bb_id = idx_to_bb.get(free_idx, -1)
            ctx = PathContext(free_idx=free_idx, bb_id=bb_id)

            # 向上查找: 此基本块是否有前驱条件跳转
            ctx.has_preceding_cond, ctx.cond_type = (
                self._find_preceding_condition(
                    instructions, free_idx, bb_boundaries))

            # 向下查找: free后是否有return
            ctx.has_return_after = self._has_return_after(
                instructions, free_idx)

            # 向下查找: free后是否还有其他call(排除noreturn函数)
            ctx.has_call_after = self._has_call_after(
                instructions, free_idx)

            # 综合判定
            ctx.certainty = self._determine_certainty(ctx)
            ctx.evidence = self._build_evidence(ctx)

            results[free_idx] = ctx

        return results

    def is_safe_conditional_free(self,
                                  free_idx: int,
                                  path_ctx: Dict[int, PathContext]
                                  ) -> bool:
        """判断某个free是否是安全的条件释放——即不构成UAF的条件"""
        ctx = path_ctx.get(free_idx)
        if ctx is None:
            return False
        # 条件free + 之后无危险use → 可能安全
        if ctx.certainty == FreeCertainty.CONDITIONAL:
            return True
        # free后立即返回 → 不可能有use → 安全
        if ctx.certainty == FreeCertainty.UNREACHABLE_AFTER:
            return True
        return False

    def downgrade_confidence(self,
                              free_idx: int,
                              path_ctx: Dict[int, PathContext],
                              base_confidence: float
                              ) -> float:
        """根据路径上下文调整UAF检测置信度"""
        ctx = path_ctx.get(free_idx)
        if ctx is None:
            return base_confidence
        if ctx.certainty == FreeCertainty.UNCONDITIONAL:
            return base_confidence  # 无调整
        elif ctx.certainty == FreeCertainty.CONDITIONAL:
            return base_confidence * 0.5  # 条件释放→置信度减半
        elif ctx.certainty == FreeCertainty.UNREACHABLE_AFTER:
            return base_confidence * 0.15  # 清理代码→几乎确定是FP
        return base_confidence * 0.3

    def _find_preceding_condition(self,
                                   instructions: List[str],
                                   free_idx: int,
                                   bb_boundaries: List[Tuple[int, int]]
                                   ) -> Tuple[bool, str]:
        """查找free前是否有条件跳转指向此free所在的基本块"""
        bb_id = -1
        for bid, (s, e) in enumerate(bb_boundaries):
            if s <= free_idx < e:
                bb_id = bid
                break

        if bb_id < 0:
            return False, ""

        # 查找跳转到此BB的条件跳转
        cond_type = ""
        for i in range(max(0, free_idx - 20), free_idx):
            instr = instructions[i].strip().lower()
            if not instr:
                continue
            # cmp/test → 记录可能的条件类型
            if self._CMP_TEST_PATTERN.search(instr):
                # 找紧随其后的jcc
                for j in range(i + 1, min(i + 5, len(instructions))):
                    j_instr = instructions[j].strip().lower()
                    jm = self._JCC_PATTERN.search(j_instr)
                    if jm:
                        cond_type = jm.group(1)
                        return True, cond_type

        return False, cond_type

    def _has_return_after(self,
                          instructions: List[str],
                          free_idx: int) -> bool:
        """free指令后8条指令内是否有return"""
        end = min(free_idx + 8, len(instructions))
        for i in range(free_idx + 1, end):
            instr = instructions[i].strip().lower()
            if self._RET_PATTERN.search(instr):
                return True
            # call exit/abort → 等同于noreturn
            if 'call' in instr and any(
                nf in instr for nf in ('exit', 'abort', '_Exit')):
                return True
        return False

    def _has_call_after(self,
                        instructions: List[str],
                        free_idx: int) -> bool:
        """free后是否有非清理类的函数调用"""
        # 跳过return检测的范围，继续向后查找
        start = free_idx + 1
        end = min(start + 15, len(instructions))
        for i in range(start, end):
            instr = instructions[i].strip().lower()
            if 'call' in instr:
                # 排除free本身和noreturn函数
                if not any(nf in instr for nf in (
                    'free', 'kfree', 'delete', 'exit', 'abort')):
                    return True
            # 碰到ret则停止
            if self._RET_PATTERN.search(instr):
                break
        return False

    def _determine_certainty(self, ctx: PathContext) -> FreeCertainty:
        """综合判定free的确定性"""
        if ctx.has_return_after and not ctx.has_call_after:
            return FreeCertainty.UNREACHABLE_AFTER
        if ctx.has_preceding_cond:
            return FreeCertainty.CONDITIONAL
        return FreeCertainty.UNCONDITIONAL

    def _build_evidence(self, ctx: PathContext) -> List[str]:
        """生成路径证据"""
        e = []
        if ctx.has_preceding_cond:
            e.append(f"条件跳转({ctx.cond_type})在free前→free可能不执行")
        if ctx.has_return_after:
            e.append("free后立即返回→后续使用不可达")
        if ctx.has_call_after:
            e.append("free后还有其他函数调用→路径上可能继续执行")
        if not e:
            e.append("无条件free——路径上必然执行")
        return e
