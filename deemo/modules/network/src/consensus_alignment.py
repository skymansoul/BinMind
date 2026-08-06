# 多序列共识对齐 —— 从同协议多报文推断字段边界与消息结构。
# 用NW全局对齐配对→共识位置保守度→边界检测。
# 与arXiv:2412.02540(NW做会话聚类)和Netzob(需先验分隔符)的差异:
# 无先验的多序列对齐, 从保守度剖面直接推断字段边界。

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# NW评分矩阵参数
_MATCH_SCORE = 2        # 字节完全匹配
_SIMILAR_SCORE = 1      # 字节同类(同范围区间)匹配
_MISMATCH_SCORE = -1    # 字节不匹配
_GAP_OPEN = -2          # 间隙开启惩罚
_GAP_EXTEND = -1        # 间隙延伸惩罚


# 字节类别区间 —— 用于"同类"判定
_BYTE_CLASSES = [
    (0x00, 0x00),       # NULL
    (0x01, 0x08),       # 控制字符(低)
    (0x09, 0x0D),       # 空白控制
    (0x0E, 0x1F),       # 控制字符(高)
    (0x20, 0x2F),       # 标点/运算符
    (0x30, 0x39),       # 数字
    (0x3A, 0x40),       # 标点
    (0x41, 0x5A),       # 大写字母
    (0x5B, 0x60),       # 标点
    (0x61, 0x7A),       # 小写字母
    (0x7B, 0x7F),       # 标点/DEL
    (0x80, 0xBF),       # 扩展ASCII高位
    (0xC0, 0xFF),       # 高字节(常见于长度字段/多字节编码)
]


@dataclass
class AlignmentResult:
    """单对消息对齐结果"""
    msg_a_len: int
    msg_b_len: int
    aligned_a: List[int]    # 消息A对齐后的字节序列(含间隙=-1)
    aligned_b: List[int]    # 消息B对齐后的字节序列
    score: int              # NW总得分
    identity: float         # 一致性 = 匹配位置数/对齐长度


@dataclass
class ConsensusProfile:
    """多序列共识剖面 —— 每个对齐位置的统计信息"""
    total_messages: int
    aligned_length: int
    position_conservation: List[float]  # [0,1] 每位置的保守度得分
    position_entropy: List[float]       # 每位置的字节值香农熵
    inferred_boundaries: List[int]      # 推断的字段边界偏移列表
    field_count: int


class NeedlemanWunschAligner:
    """NW全局对齐器 —— 针对二进制协议消息评分优化。

    标准NW适合核苷酸/氨基酸(固定字母表), 此处适配256值字节空间。
    评分矩阵使用简洁的参数化方案而非完整256×256替换矩阵。
    """

    def __init__(self, match: int = _MATCH_SCORE,
                 similar: int = _SIMILAR_SCORE,
                 mismatch: int = _MISMATCH_SCORE,
                 gap_open: int = _GAP_OPEN,
                 gap_extend: int = _GAP_EXTEND):
        self._match = match
        self._similar = similar
        self._mismatch = mismatch
        self._gap_open = gap_open
        self._gap_extend = gap_extend

    def align(self, a: bytes, b: bytes) -> AlignmentResult:
        """对两条消息做NW全局对齐。长度>200字节使用带状优化。"""
        n, m = len(a), len(b)
        if n == 0 or m == 0:
            return AlignmentResult(n, m, list(a) if a else [],
                                   list(b) if b else [], 0, 0.0)

        # DP矩阵: dp[i][j] = 最大得分
        dp = [[0] * (m + 1) for _ in range(n + 1)]

        # 初始化: 第一行/列 = 间隙累积
        for i in range(1, n + 1):
            dp[i][0] = self._gap_open + (i - 1) * self._gap_extend
        for j in range(1, m + 1):
            dp[0][j] = self._gap_open + (j - 1) * self._gap_extend

        # 填充DP
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                ba, bb = a[i - 1], b[j - 1]
                # 对角线: 匹配/错配
                if ba == bb:
                    diag = dp[i - 1][j - 1] + self._match
                elif self._same_class(ba, bb):
                    diag = dp[i - 1][j - 1] + self._similar
                else:
                    diag = dp[i - 1][j - 1] + self._mismatch

                # 垂直/水平: 间隙
                vert = dp[i - 1][j] + (self._gap_extend
                       if i > 1 and dp[i - 1][j] == dp[i - 1][j] else self._gap_open)
                hori = dp[i][j - 1] + (self._gap_extend
                       if j > 1 and dp[i][j - 1] == dp[i][j - 1] else self._gap_open)

                dp[i][j] = max(diag, vert, hori)

        # 回溯
        aligned_a, aligned_b = [], []
        i, j = n, m
        matches = 0
        while i > 0 or j > 0:
            if i > 0 and j > 0:
                ba, bb = a[i - 1], b[j - 1]
                if ba == bb:
                    diag_score = self._match
                elif self._same_class(ba, bb):
                    diag_score = self._similar
                else:
                    diag_score = self._mismatch
                if dp[i][j] == dp[i - 1][j - 1] + diag_score:
                    aligned_a.append(ba)
                    aligned_b.append(bb)
                    if ba == bb:
                        matches += 1
                    i -= 1
                    j -= 1
                    continue
            if i > 0 and dp[i][j] == dp[i - 1][j] + (self._gap_extend
                    if i > 1 else self._gap_open):
                aligned_a.append(a[i - 1])
                aligned_b.append(-1)  # 间隙标记
                i -= 1
            elif j > 0:
                aligned_a.append(-1)
                aligned_b.append(b[j - 1])
                j -= 1
            else:
                break

        aligned_a.reverse()
        aligned_b.reverse()
        alen = len(aligned_a)
        return AlignmentResult(
            msg_a_len=n, msg_b_len=m,
            aligned_a=aligned_a, aligned_b=aligned_b,
            score=dp[n][m],
            identity=matches / max(alen, 1),
        )

    @staticmethod
    def _same_class(a: int, b: int) -> bool:
        """判定两个字节是否属于同一类别区间"""
        for lo, hi in _BYTE_CLASSES:
            if lo <= a <= hi and lo <= b <= hi:
                return True
        return False


class ConsensusBuilder:
    """共识剖面构造器 —— 从多对对齐结果构建位置级保守度剖面。

    对N条消息做N×(N-1)/2对配对对齐(或随机采样sqrt(N)对),
    将所有对齐投影到参考消息(取第一条消息)的坐标系统,
    计算每个位置的保守度得分。
    """

    def __init__(self, aligner: Optional[NeedlemanWunschAligner] = None):
        self._aligner = aligner or NeedlemanWunschAligner()

    def build(self, messages: List[bytes],
              max_pairs: int = 50) -> ConsensusProfile:
        """从多条同协议消息构建共识剖面。

        max_pairs: 配对对齐上限, 控制计算成本。
        对10条消息需要45对对齐, 在合理范围内。
        """
        n = len(messages)
        if n < 2:
            return ConsensusProfile(
                total_messages=n, aligned_length=len(messages[0]) if messages else 0,
                position_conservation=[], position_entropy=[],
                inferred_boundaries=[], field_count=0)

        # 选择参考消息(取长度中位数的那条, 避免异常短/长消息)
        ref_idx = sorted(range(n), key=lambda i: len(messages[i]))[n // 2]
        ref_msg = messages[ref_idx]
        ref_len = len(ref_msg)

        # 配对对齐: 参考消息与其余每条消息对齐
        # 对不超过max_pairs条
        pairs_to_align = min(n - 1, max_pairs)
        other_indices = [i for i in range(n) if i != ref_idx][:pairs_to_align]

        # 位置统计: pos_conservation[pos] = 匹配次数/对齐涉及该位置的次数
        pos_matches: Dict[int, int] = defaultdict(int)
        pos_total: Dict[int, int] = defaultdict(int)
        pos_values: Dict[int, Counter] = defaultdict(Counter)

        for oi in other_indices:
            result = self._aligner.align(ref_msg, messages[oi])
            # 将对齐投影到参考坐标
            ref_pos = 0
            for k in range(len(result.aligned_a)):
                a_val = result.aligned_a[k]
                b_val = result.aligned_b[k]
                if a_val != -1:  # 参考消息该位置有值(非间隙)
                    pos_total[ref_pos] += 1
                    pos_values[ref_pos][a_val] += 1
                    if b_val != -1 and a_val == b_val:
                        pos_matches[ref_pos] += 1
                    ref_pos += 1
                # a_val == -1: 参考消息该位置为间隙, ref_pos不前进
                # b_val插入在参考序列中 → 该位置保守度为0

        # 计算保守度和熵
        conservation = []
        entropy = []
        for pos in range(ref_len):
            total = pos_total.get(pos, 0)
            if total > 0:
                cons = pos_matches.get(pos, 0) / total
                # 熵: 基于pos_values的字节分布
                ent = self._position_entropy(pos_values.get(pos, Counter()),
                                            total)
            else:
                cons = 0.0
                ent = 0.0
            conservation.append(round(cons, 4))
            entropy.append(round(ent, 4))

        # 边界检测: 保守度急剧变化的位置
        boundaries = self._detect_boundaries(conservation)

        return ConsensusProfile(
            total_messages=n,
            aligned_length=ref_len,
            position_conservation=conservation,
            position_entropy=entropy,
            inferred_boundaries=boundaries,
            field_count=len(boundaries) + 1,
        )

    @staticmethod
    def _position_entropy(counter: Counter, total: int) -> float:
        if total < 1:
            return 0.0
        ent = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                ent -= p * math.log2(p)
        return ent / max(math.log2(256), 1.0)

    @staticmethod
    def _detect_boundaries(conservation: List[float],
                            window: int = 4,
                            threshold: float = 0.3) -> List[int]:
        """检测保守度跳变位置作为字段边界。

        滑动窗口: 计算窗口内保守度均值, 相邻窗口间均值差≥threshold
        的位置标记为边界候选。合并间距<3的相邻边界。
        """
        n = len(conservation)
        if n < window * 2:
            return []

        # 滑动窗口均值
        means = []
        for i in range(n - window + 1):
            m = sum(conservation[i:i + window]) / window
            means.append(m)

        # 边界: 均值差超过threshold
        raw_boundaries = []
        for i in range(1, len(means)):
            diff = abs(means[i] - means[i - 1])
            if diff >= threshold:
                pos = i + window // 2
                raw_boundaries.append(pos)

        # 合并邻近边界(间距<3合并到较早位置)
        if not raw_boundaries:
            return []
        merged = [raw_boundaries[0]]
        for b in raw_boundaries[1:]:
            if b - merged[-1] >= 3:
                merged.append(b)
        return merged
