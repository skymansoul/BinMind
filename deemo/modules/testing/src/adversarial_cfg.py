# 对抗性 CFG 伪装生成器 — 语义保持的 CFG 变换以规避二进制相似性检测
#
# 设计动机:
#   现有二进制相似性检测 (BinDiff, Diaphora, 以及本项目的 cfg_entropy_fingerprint.py)
#   基于 CFG 结构特征做函数匹配。Kelpie (Sauger et al. 2025) 证明:
#   通过对代码做语义保持变换, 可系统性规避此类检测器的嵌入空间分类。
#
#   本模块提供面向防御的CFG鲁棒性评估: 生成对抗性变换后的CFG,
#   计算变换前后的嵌入距离, 量化相似性检测器的脆弱性。
#
#   三个关键技术决策:
#     1. 双重约束优化: 在语义保持和嵌入距离最大化之间做帕累托搜索。
#        变换后功能等价 (等价指令替换+死代码注入), 同时最大化熵指纹余弦距离。
#     2. 逐块熵预算: 按基本块对整体CFG熵特征的贡献度分配变换配额,
#        避免在低价值块上浪费体积膨胀预算。
#     3. 多目标可迁移性: 生成的对抗样本对其他相似性检测器也有效
#        (变换步长≤0.15时对多模型具有泛化攻击性)。
#
# 文件结构:
#   本文件包含核心类型定义和变换引擎的主逻辑。
#   具体的变换操作 (split/merge/nop/reorder等) 在 adversarial_cfg_ops.py,
#   CFGRobustnessEvaluator 也在 ops 文件中, 通过本文件的便捷入口访问。
#
# 参考文献:
#   Kelpie (Sauger et al. 2025) — 零查询目标模仿攻击, 语义保持变换规避
#     六种二进制函数分类器; 本项目取其变换思想但用于防御评估而非攻击
#   Capozzi et al. (IEEE Access 2024) — 黑盒攻击可达 93.81% 成功率;
#     本项目参考其贪心搜索策略, 以熵预算约束替代无界变异

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class TransformOp(str, Enum):
    """CFG 变换操作——全部语义保持"""
    SPLIT_BLOCK = "split_block"
    MERGE_BLOCKS = "merge_blocks"
    INSERT_NOP_BLOCK = "insert_nop_block"
    REORDER_BLOCKS = "reorder_blocks"
    DUPLICATE_BLOCK = "duplicate_block"
    EQUIVALENT_INSTR = "equivalent_instr"
    CLONE_THEN_GUARD = "clone_then_guard"


@dataclass
class BasicBlock:
    """基本块——CFG节点"""
    block_id: int
    start_addr: int = 0
    end_addr: int = 0
    instruction_count: int = 1
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    entropy_contribution: float = 0.0


@dataclass
class CFGSpec:
    """CFG规格——供变换引擎操作"""
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    entry_id: int = 0
    adjacency: Dict[int, List[int]] = field(default_factory=dict)
    block_sizes: Dict[int, int] = field(default_factory=dict)


@dataclass
class TransformStep:
    """单步变换记录——可追踪可回滚"""
    op: TransformOp
    target_block: int
    description: str
    entropy_delta: float = 0.0
    size_delta: int = 0


@dataclass
class AdversarialCFGResult:
    """对抗性CFG变换结果"""
    original_cfg: CFGSpec
    transformed_cfg: CFGSpec
    transform_steps: List[TransformStep] = field(default_factory=list)
    cosine_distance: float = 0.0
    l2_distance: float = 0.0
    size_increase_pct: float = 0.0
    functional_equivalence_score: float = 1.0
    robustness_score: float = 0.0
    execution_time_s: float = 0.0
    summary: str = ""


class EntropyBudget:
    """逐块熵预算——按基本块对CFG熵的贡献度分配变换资源

    total_budget=0.15 表示允许熵偏离最多15%, 用于限制变换的激进程度。
    """

    def __init__(self, total_budget: float = 0.15):
        self._total_budget = total_budget
        self._spent: float = 0.0
        self._block_allocations: Dict[int, float] = defaultdict(float)

    @property
    def remaining(self) -> float:
        return max(0.0, self._total_budget - self._spent)

    def allocate(self, block_id: int, requested: float) -> float:
        granted = min(requested, self.remaining)
        self._spent += granted
        self._block_allocations[block_id] += granted
        return granted

    def spent_for(self, block_id: int) -> float:
        return self._block_allocations.get(block_id, 0.0)


class AdversarialCFGTransformer:
    """对抗性CFG变换引擎。

    变换操作委托给 adversarial_cfg_ops.py 中的独立函数,
    本类负责策略选择、预算管理和特征提取。
    """

    def __init__(self,
                 entropy_budget: float = 0.15,
                 max_size_increase_pct: float = 30.0,
                 seed: Optional[int] = None):
        self._budget = EntropyBudget(entropy_budget)
        self._max_size_pct = max_size_increase_pct
        self._rng = random.Random(seed)
        self._op_priority: List[TransformOp] = [
            TransformOp.SPLIT_BLOCK,
            TransformOp.EQUIVALENT_INSTR,
            TransformOp.INSERT_NOP_BLOCK,
            TransformOp.MERGE_BLOCKS,
            TransformOp.REORDER_BLOCKS,
            TransformOp.DUPLICATE_BLOCK,
            TransformOp.CLONE_THEN_GUARD,
        ]
        # 延迟导入, 避免循环依赖
        self._ops_loaded = False

    def _ensure_ops(self):
        if self._ops_loaded:
            return
        from . import adversarial_cfg_ops as _ops
        self._sim_dispatch = _ops._SIM_DISPATCH
        self._ops_loaded = True

    def transform(self,
                  cfg: CFGSpec,
                  target_distance: float = 0.25,
                  max_steps: int = 12,
                  ) -> AdversarialCFGResult:
        """主入口: 在熵预算内最大化CFG嵌入距离。"""
        self._ensure_ops()
        t0 = time.perf_counter()

        original_features = self._cfg_to_features(cfg)
        working_cfg = self._deep_copy_cfg(cfg)
        steps: List[TransformStep] = []
        total_size_delta = 0

        block_contributions = self._compute_entropy_contributions(cfg)
        ranked_blocks = sorted(block_contributions.items(),
                               key=lambda x: -x[1])

        for step_idx in range(max_steps):
            if self._budget.remaining <= 0:
                break
            if (total_size_delta / max(1, self._estimate_total_size(cfg))
                    > self._max_size_pct / 100):
                break

            best_step = self._select_best_transform(
                working_cfg, original_features, ranked_blocks, step_idx)
            if best_step is None:
                break

            self._apply_transform(working_cfg, best_step)
            steps.append(best_step)
            total_size_delta += best_step.size_delta

            current_features = self._cfg_to_features(working_cfg)
            current_dist = self._cosine_distance(
                original_features, current_features)
            if current_dist >= target_distance:
                break

        transformed_features = self._cfg_to_features(working_cfg)
        cos_dist = self._cosine_distance(original_features, transformed_features)
        l2_dist = self._l2_distance(original_features, transformed_features)
        size_pct = (total_size_delta / max(1, self._estimate_total_size(cfg))) * 100
        equiv_score = self._estimate_equivalence(cfg, working_cfg, steps)
        robustness = cos_dist * equiv_score / (1.0 + math.log1p(size_pct))

        elapsed = time.perf_counter() - t0
        return AdversarialCFGResult(
            original_cfg=cfg,
            transformed_cfg=working_cfg,
            transform_steps=steps,
            cosine_distance=cos_dist,
            l2_distance=l2_dist,
            size_increase_pct=size_pct,
            functional_equivalence_score=equiv_score,
            robustness_score=robustness,
            execution_time_s=elapsed,
            summary=self._build_summary(steps, cos_dist, robustness),
        )

    def _select_best_transform(self,
                                cfg: CFGSpec,
                                original_features: List[float],
                                ranked_blocks: List[Tuple[int, float]],
                                step_idx: int,
                                ) -> Optional[TransformStep]:
        """贪心搜索: 在前5个高贡献块上尝试当前步骤的变换操作。"""
        best_step: Optional[TransformStep] = None
        best_gain: float = -1.0

        candidate_blocks = [bid for bid, _ in ranked_blocks[:5]
                            if bid in cfg.blocks]
        candidate_ops = [self._op_priority[step_idx % len(self._op_priority)]]

        for block_id in candidate_blocks:
            for op in candidate_ops:
                sim_cfg = self._deep_copy_cfg(cfg)
                sim_step = self._simulate_transform(sim_cfg, block_id, op)
                if sim_step is None:
                    continue

                sim_features = self._cfg_to_features(sim_cfg)
                gain = self._cosine_distance(original_features, sim_features)

                budget_request = abs(sim_step.entropy_delta) * 0.5
                if self._budget.allocate(block_id, budget_request) < budget_request:
                    continue

                if gain > best_gain:
                    best_gain = gain
                    best_step = sim_step

        return best_step

    def _simulate_transform(self, cfg: CFGSpec,
                             block_id: int, op: TransformOp,
                             ) -> Optional[TransformStep]:
        block = cfg.blocks.get(block_id)
        if block is None:
            return None
        handler = self._sim_dispatch.get(op)
        if handler is None:
            return None
        return handler(cfg, block, self._rng)

    def _apply_transform(self, cfg: CFGSpec, step: TransformStep) -> None:
        """对working_cfg执行已评估的变换操作。"""
        block = cfg.blocks.get(step.target_block)
        if block is None:
            return
        handler = self._sim_dispatch.get(step.op)
        if handler:
            handler(cfg, block, self._rng)

    # ---- CFG → 9维熵特征向量 ----

    def _cfg_to_features(self, cfg: CFGSpec) -> List[float]:
        """将CFG转化为9维熵特征——与cfg_entropy_fingerprint.py对齐。

        维度: F1出度熵 F2入度熵 F3块大小熵 F4循环块比率
              F5分支块比率 F6平均出度 F7最大出度 F8出口比率 F9孤立块比率
        """
        if not cfg.blocks:
            return [0.0] * 9

        blocks = list(cfg.blocks.values())
        n = len(blocks)
        sizes = cfg.block_sizes or {
            b.block_id: b.instruction_count for b in blocks}

        outdeg: Dict[int, int] = defaultdict(int)
        indeg: Dict[int, int] = defaultdict(int)
        for b in blocks:
            outdeg[len(b.successors)] += 1
            indeg[len(b.predecessors)] += 1

        ot = sum(outdeg.values()) or 1
        it = sum(indeg.values()) or 1
        sz = [sizes.get(b.block_id, b.instruction_count) for b in blocks]
        st = sum(sz) or 1

        f1 = self._shannon([c / ot for c in outdeg.values()])
        f2 = self._shannon([c / it for c in indeg.values()])
        f3 = self._shannon([s / st for s in sz])
        f4 = sum(1 for b in blocks
                 if len(b.successors) >= 2 or len(b.predecessors) >= 2) / n
        f5 = sum(1 for b in blocks if len(b.successors) >= 2) / n
        f6 = sum(len(b.successors) for b in blocks) / n
        f7 = float(max((len(b.successors) for b in blocks), default=0))
        f8 = sum(1 for b in blocks if len(b.successors) == 0) / max(1, n)
        f9 = sum(1 for b in blocks
                 if len(b.predecessors) == 0 and len(b.successors) == 0
                 and not b.is_entry) / max(1, n)

        return [f1, f2, f3, f4, f5, f6, f7, f8, f9]

    @staticmethod
    def _shannon(probs: List[float]) -> float:
        ent = 0.0
        for p in probs:
            if p > 0:
                ent -= p * math.log2(p)
        return ent

    @staticmethod
    def _cosine_distance(a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return 1.0 - max(-1.0, min(1.0, dot / (na * nb)))

    @staticmethod
    def _l2_distance(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    def _compute_entropy_contributions(self,
                                        cfg: CFGSpec) -> Dict[int, float]:
        """逐块熵贡献度: 移除该块后的余弦距离"""
        baseline = self._cfg_to_features(cfg)
        contributions: Dict[int, float] = {}
        for bid in cfg.blocks:
            reduced = self._deep_copy_cfg(cfg)
            reduced.blocks.pop(bid, None)
            reduced.adjacency.pop(bid, None)
            reduced.block_sizes.pop(bid, None)
            for b in reduced.blocks.values():
                b.predecessors = [p for p in b.predecessors if p != bid]
                b.successors = [s for s in b.successors if s != bid]
            reduced_feat = self._cfg_to_features(reduced)
            contributions[bid] = self._cosine_distance(baseline, reduced_feat)
        return contributions

    @staticmethod
    def _estimate_total_size(cfg: CFGSpec) -> int:
        return sum(cfg.block_sizes.values()) if cfg.block_sizes else len(cfg.blocks)

    @staticmethod
    def _estimate_equivalence(original: CFGSpec, transformed: CFGSpec,
                               steps: List[TransformStep]) -> float:
        """功能等价性估计: 基于变换类型加权。

        SPLIT_BLOCK / EQUIVALENT_INSTR / REORDER_BLOCKS → 1.0
        INSERT_NOP_BLOCK / MERGE_BLOCKS → 0.99
        DUPLICATE_BLOCK / CLONE_THEN_GUARD → 0.95
        """
        if not steps:
            return 1.0
        op_weights = {
            TransformOp.SPLIT_BLOCK: 1.0,
            TransformOp.EQUIVALENT_INSTR: 1.0,
            TransformOp.REORDER_BLOCKS: 1.0,
            TransformOp.INSERT_NOP_BLOCK: 0.99,
            TransformOp.MERGE_BLOCKS: 0.99,
            TransformOp.DUPLICATE_BLOCK: 0.95,
            TransformOp.CLONE_THEN_GUARD: 0.95,
        }
        total = sum(op_weights.get(s.op, 0.9) for s in steps)
        return total / len(steps)

    @staticmethod
    def _deep_copy_cfg(cfg: CFGSpec) -> CFGSpec:
        new_cfg = CFGSpec(entry_id=cfg.entry_id)
        for bid, block in cfg.blocks.items():
            new_cfg.blocks[bid] = BasicBlock(
                block_id=block.block_id,
                start_addr=block.start_addr,
                end_addr=block.end_addr,
                instruction_count=block.instruction_count,
                successors=list(block.successors),
                predecessors=list(block.predecessors),
                is_entry=block.is_entry,
                is_exit=block.is_exit,
                entropy_contribution=block.entropy_contribution,
            )
        new_cfg.adjacency = {k: list(v) for k, v in cfg.adjacency.items()}
        new_cfg.block_sizes = dict(cfg.block_sizes)
        return new_cfg

    @staticmethod
    def _build_summary(steps: List[TransformStep],
                        cos_dist: float, robustness: float) -> str:
        op_summary = defaultdict(int)
        for s in steps:
            op_summary[s.op.value] += 1
        ops_str = ", ".join(f"{k}×{v}" for k, v in op_summary.items())
        return (f"对抗变换: {len(steps)} 步 ({ops_str}), "
                f"余弦距离={cos_dist:.4f}, 鲁棒性={robustness:.3f}")


def quick_adversarial_cfg(cfg_spec: CFGSpec,
                           target_distance: float = 0.25,
                           ) -> AdversarialCFGResult:
    """便捷入口: 对单个CFG快速生成对抗变体"""
    transformer = AdversarialCFGTransformer()
    return transformer.transform(cfg_spec, target_distance=target_distance)
