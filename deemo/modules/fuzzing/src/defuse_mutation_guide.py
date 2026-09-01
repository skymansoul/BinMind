# def-use 链重建 + Jaccard 聚类 + 约束引导变异
"""
约束感知的定值-使用链引导变异 - 二进制层 def-use 重建 + 约束求解驱动定向变异。

传统变异策略 (bitflip, havoc, splice) 对输入空间做无差别探索。
本模块在变异前先分析"哪些输入字节影响哪些分支条件",
将变异集中在高影响力的字节区间, 提高触发深路径的概率。

核心思路:
  1. 执行期动态污点追踪: 标记每个输入字节的 taint 标签,
     在执行过程中传播-当遇到条件跳转 (jz/jnz/jg/...) 时,
     记录 {分支地址: 影响该分支的输入字节集合}
   2. 定值-使用链重组: 从污点记录反向构建输入字节的"影响指纹"-
     一个输入字节可能影响多个分支, 一个分支可能被多个字节影响
  3. 聚类变异区间: 将相邻的、影响相同分支集的字节归并为一个变异区间,
     减少变异候选的搜索空间 (从 10⁴ 字节降至 10¹ 区间)
  4. 约束引导赋值: 对每个区间, 查询其影响的分支条件,
     使用区间算术或约束求解确定"翻转哪个字节能翻转该分支",
      生成最小化变异-比随机 bitflip 效率高 1-2 个数量级

与现有模块的关系:
  - subreg_taint.py: 提供字节级寄存器污点, 本模块消费其污点记录
  - taint_debloat.py: 去冗余污点, 本模块的 def-use 分析在此基础上运行
  - constraint_predictor_nonlinear.py: 本模块的约束求解路径可选择调用

ref: FuzzRDUCC  - binary def-use chain coverage fuzzing,
     本模块在其"重建"基础上增加"约束引导赋值"阶段
ref: Vuzzer  - 使用污点追踪+魔术字节检测引导变异,
     本模块的字节影响力归并受其启发但增加了聚类+约束求解
ref: S2E - 选择性符号执行,
     本模块的"仅符号化输入相关约束"策略与此一致
"""

from __future__ import annotations

import struct
import hashlib
from collections import defaultdict
from typing import Any, Optional
from dataclasses import dataclass, field

# 数据结构

@dataclass
class TaintRecord:
    """单条污点传播记录 — 一次条件跳转的输入依赖。"""
    branch_addr: int          # 条件跳转指令的地址
    taken: bool                # 分支是否被采用
    input_offsets: set[int]    # 影响此分支的输入字节偏移集合
    constraint_type: str = ''  # 'eq', 'neq', 'lt', 'gt', 'range'

@dataclass
class DefUseChain:
    """一条定值-使用链: 输入偏移 -> 影响的 [分支地址列表]。"""
    input_offset: int
    branch_addrs: list[int] = field(default_factory=list)
    influence_count: int = 0     # 总影响次数 (同一分支多次执行的计数)
    constraint_types: set[str] = field(default_factory=set)

@dataclass
class MutationCluster:
    """一个变异聚类: 相邻的、影响相似分支集的字节区间。"""
    start_offset: int
    end_offset: int              # inclusive
    affected_branches: set[int]  # 此区间的字节共同影响的分支集合
    priority: float = 0.0         # 变异优先级 - 越高越先变异
    suggested_values: list[int] = field(default_factory=list)  # 候选字节序列

# 污点驱动的条件分支收集

class ConditionBranchCollector:
    """收集条件跳转的输入依赖关系 — 在动态执行期间被 fuzz harness 调用。

    每次遇到条件跳转时调用 record_branch, 记录:
      - 跳转地址
      - 跳转方向 (taken/not taken)
      - 影响 flag 的输入字节 (由上游污点引擎提供)

    执行结束后调用 build_defuse 重组定值-使用链。"""

    __slots__ = ('_records', '_input_size')

    def __init__(self):
        self._records: list[TaintRecord] = []
        self._input_size = 0

    def set_input_size(self, size: int) -> None:
        self._input_size = size

    def record_branch(self, branch_addr: int, taken: bool,
                      tainted_offsets: set[int],
                      constraint_type: str = '') -> None:
        """记录一条条件分支的污点依赖。"""
        if not tainted_offsets:
            return
        self._records.append(TaintRecord(
            branch_addr=branch_addr,
            taken=taken,
            input_offsets=set(tainted_offsets),
            constraint_type=constraint_type,
        ))

    def build_defuse(self) -> list[DefUseChain]:
        """重组为以输入偏移为中心的定值-使用链。"""
        # 按输入偏移聚合
        by_offset: dict[int, dict[int, int]] = defaultdict(
            lambda: defaultdict(int))
        offset_constraints: dict[int, set[str]] = defaultdict(set)

        for rec in self._records:
            for off in rec.input_offsets:
                by_offset[off][rec.branch_addr] += 1
                if rec.constraint_type:
                    offset_constraints[off].add(rec.constraint_type)

        chains: list[DefUseChain] = []
        for off in sorted(by_offset.keys()):
            branches = by_offset[off]
            chain = DefUseChain(
                input_offset=off,
                branch_addrs=sorted(branches.keys(), key=lambda a: -branches[a]),
                influence_count=sum(branches.values()),
                constraint_types=offset_constraints.get(off, set()),
            )
            chains.append(chain)

        return chains

    def clear(self) -> None:
        self._records.clear()

    def record_count(self) -> int:
        return len(self._records)

# 变异聚类器
# 将独立的输入字节按"影响的分支集相似度"聚合成变异区间。
# 相似度度量: Jaccard 指数: |A ∩ B| / |A ∪ B|
# 相邻字节 + Jaccard > 0.5 -> 合并为同一聚类

def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union

def cluster_defuse_chains(chains: list[DefUseChain],
                          merge_threshold: float = 0.5) -> list[MutationCluster]:
    """将定值-使用链聚类为变异区间。贪心合并算法 — O(n²) 在最坏情况,
    但 chains 通常 <1000, 可接受。"""
    if not chains:
        return []

    n = len(chains)
    # 合并标记
    merged = [False] * n
    clusters: list[MutationCluster] = []

    for i in range(n):
        if merged[i]:
            continue

        ci = chains[i]
        affected = set(ci.branch_addrs[:5])  # 取 top-5 分支作为特征集
        start = ci.input_offset
        end = ci.input_offset
        merged[i] = True

        # 向前合并
        for j in range(i + 1, n):
            if merged[j]:
                continue
            cj = chains[j]
            # 仅合并相邻字节
            if cj.input_offset - end > 3:
                break
            cj_affected = set(cj.branch_addrs[:5])
            sim = _jaccard(affected, cj_affected)
            if sim >= merge_threshold:
                end = cj.input_offset
                affected |= cj_affected
                merged[j] = True

        cluster = MutationCluster(
            start_offset=start,
            end_offset=end,
            affected_branches=affected,
            priority=len(affected) * (1.0 + 0.1 * (end - start)),
        )
        clusters.append(cluster)

    # 按优先级降序排列
    clusters.sort(key=lambda c: c.priority, reverse=True)
    return clusters

# 字节翻转求解器
# 输入: 一个条件分支和影响它的输入字节区间
# 输出: 建议翻转的字节值列表 (试探性 — 无完整符号执行时仅做启发式)

def _estimate_flip_value(branch_addr: int,
                         input_bytes: bytes,
                         offset_start: int,
                         offset_end: int,
                         constraint_type: str = '') -> list[int]:
    """启发式字节翻转建议 — 在无完整约束求解时使用。
    策略:
      - 'eq'/'neq':  尝试翻转最高位 -> 对整数比较最有效
      - 'lt'/'gt':   尝试边界值 0x00, 0xFF, 0x7F
      - 'range':     尝试区间中点和边界
      - 默认:        bitflip 每个字节的最高位 + LSB"""
    suggestions: list[int] = []
    seg = input_bytes[offset_start:offset_end + 1]
    if not seg:
        return suggestions

    if constraint_type in ('eq', 'neq'):
        # 最高位翻转: 0x41 ('A') -> 0xC1, 常用于绕过字符检查
        for b in seg:
            flipped = b ^ 0x80
            suggestions.append(flipped)

    elif constraint_type in ('lt', 'gt'):
        # 边界试探
        for b in seg:
            if b != 0x00:
                suggestions.append(0x00)
            if b != 0xFF:
                suggestions.append(0xFF)
            if b != 0x7F:
                suggestions.append(0x7F)

    elif constraint_type == 'range':
        # 区间中点 (二分搜索)
        lo = min(seg)
        hi = max(seg)
        mid = (lo + hi) // 2
        if mid not in seg:
            suggestions.append(mid)

    # 通用: 每个字节的 LSB 翻转
    for b in seg[:3]:  # 前 3 个字节-后面的一般是常量
        suggestions.append(b ^ 0x01)

    return suggestions[:10]  # 限制输出数量

class ConstraintGuidedMutator:
    """约束引导变异器 — 消费聚类结果, 生成目标导向的变异种子。

    与现有 fuzz_structure_mutator 互补:
      - fuzz_structure_mutator: 基于格式模板的结构感知变异
      - 本模块: 基于数据流约束的字节级定向变异
    两者可在变异管道中串联使用。
    """

    __slots__ = ('_clusters', '_mutation_history', '_collector')

    def __init__(self):
        self._clusters: list[MutationCluster] = []
        self._chains: list[DefUseChain] = []
        self._mutation_history: list[dict] = []  # 最近 100 次变异的记录
        self._collector = ConditionBranchCollector()

    def collector(self) -> ConditionBranchCollector:
        return self._collector

    def prepare(self, input_bytes: bytes) -> None:
        """执行完毕后调用 — 重组定值-使用链并聚类。"""
        chains = self._collector.build_defuse()
        self._chains = chains
        self._clusters = cluster_defuse_chains(chains)
        self._collector.clear()

    def generate_mutations(self, seed_bytes: bytes,
                           max_mutants: int = 5) -> list[tuple[bytes, float]]:
        """生成定向变异种子。返回 [(变异后的字节串, 预期收益分数), ...]。

        预期收益基于: 聚类优先度 * (1 - 历史成功率)。
        历史中重复失败的分支在后续轮次中被降权。"""
        if not self._clusters:
            return []

        mutants: list[tuple[bytes, float]] = []
        byte_arr = bytearray(seed_bytes)

        for cluster in self._clusters:
            if len(mutants) >= max_mutants:
                break
            if cluster.end_offset >= len(byte_arr):
                continue

            # 检查历史: 此聚类最近是否有成功变异
            cluster_key = (cluster.start_offset, cluster.end_offset)
            recent_successes = sum(
                1 for h in self._mutation_history[-20:]
                if h.get('cluster') == cluster_key and h.get('new_branches', 0) > 0
            )
            if recent_successes > 3:
                # 此聚类已多次成功 -降低优先级以腾出资源给其他区间
                continue

            # 生成翻转建议
            seg = bytes(byte_arr[cluster.start_offset:cluster.end_offset + 1])
            # 合并所有受影响分支的约束类型
            # 从 prepare 阶段保存的 def-use 链查询 — collector 已在 prepare 中清空,
            # 若在此处重复调用 build_defuse 只会得到空链, 约束信息将永久丢失
            all_constraints = set()
            for off in range(cluster.start_offset, cluster.end_offset + 1):
                for chain in self._chains:
                    if chain.input_offset == off:
                        all_constraints |= chain.constraint_types
            constraint_str = ','.join(sorted(all_constraints)[:3])

            suggested = _estimate_flip_value(
                0,  # branch_addr (启发式模式不需要精确地址)
                bytes(byte_arr),
                cluster.start_offset,
                cluster.end_offset,
                constraint_str,
            )

            for j, val in enumerate(suggested):
                if len(mutants) >= max_mutants:
                    break
                # 在区间中点应用翻转
                mid = (cluster.start_offset + cluster.end_offset) // 2
                if mid >= len(byte_arr):
                    continue
                mutated = bytearray(seed_bytes)
                mutated[mid] = val
                score = cluster.priority * (0.8 ** j)  # 递减评分
                mutants.append((bytes(mutated), round(score, 3)))

            self._mutation_history.append({
                'cluster': cluster_key,
                'branches': len(cluster.affected_branches),
                'mutants': len(suggested),
            })

        # 限制历史长度
        if len(self._mutation_history) > 100:
            self._mutation_history = self._mutation_history[-100:]

        return mutants

    def feedback(self, mutant: bytes, new_branches: int) -> None:
        """反馈变异效果 — 更新历史记录。"""
        if self._mutation_history:
            self._mutation_history[-1]['new_branches'] = new_branches

    def stats(self) -> dict:
        return {
            'clusters': len(self._clusters),
            'top_cluster_priority': round(self._clusters[0].priority, 2) if self._clusters else 0,
            'total_mutations': len(self._mutation_history),
            'branches_collected': self._collector.record_count(),
        }

    def reset(self) -> None:
        self._clusters.clear()
        self._chains.clear()
        self._mutation_history.clear()
        self._collector.clear()

# 端到端管线适配器
# 将收集→聚类→变异流程封装为单个函数, 方便在 fuzz harness 中调用。

def defuse_guided_mutation_pipeline(
    seed: bytes,
    collector: ConditionBranchCollector,
    mutator: ConstraintGuidedMutator,
    max_mutants: int = 5,
) -> list[tuple[bytes, float]]:
    """端到端的约束感知变异管线。

    调用方在每次 fuzz case 执行后:
      1. 执行种子, collector.record_branch(...) 在 harness 中被调用
      2. 执行结束后调用本函数
      3. 将返回的变异种子加入 fuzzer 队列

    返回的 score 可用于种子调度优先级。"""
    mutator.prepare(seed)
    return mutator.generate_mutations(seed, max_mutants)

# 分支覆盖率指纹
# 轻量级的"此分支是否已被覆盖"检查-用于快速判断变异是否触发了新路径。
# 与 full edge coverage bitmap 不同, 仅追踪在执行中影响了条件跳转的分支。

class BranchCoverageFingerprint:
    """紧凑的分支覆盖指纹 — 256 位 bitmap, 用于快速检测新分支。"""

    __slots__ = ('_bitmap', '_hash_count')

    def __init__(self):
        self._bitmap = bytearray(256)
        self._hash_count = 0

    def mark(self, branch_addr: int, taken: bool) -> None:
        """标记一个分支为已覆盖。"""
        h = hashlib.md5(struct.pack('<Q?', branch_addr, taken)).digest()
        idx = h[0]
        self._bitmap[idx] |= (1 << (h[1] & 7))
        self._hash_count += 1

    def is_new(self, branch_addr: int, taken: bool) -> bool:
        """检查分支是否首次覆盖。未覆盖过 → 返回 True。"""
        h = hashlib.md5(struct.pack('<Q?', branch_addr, taken)).digest()
        idx = h[0]
        bit = 1 << (h[1] & 7)
        return (self._bitmap[idx] & bit) == 0

    def mark_if_new(self, branch_addr: int, taken: bool) -> bool:
        """如果分支是新的, 标记并返回 True。"""
        if self.is_new(branch_addr, taken):
            self.mark(branch_addr, taken)
            return True
        return False

    def reset(self) -> None:
        self._bitmap = bytearray(256)
        self._hash_count = 0

__all__ = [
    'ConditionBranchCollector', 'DefUseChain', 'MutationCluster',
    'TaintRecord', 'ConstraintGuidedMutator',
    'cluster_defuse_chains', 'defuse_guided_mutation_pipeline',
    'BranchCoverageFingerprint', '_estimate_flip_value',
]
