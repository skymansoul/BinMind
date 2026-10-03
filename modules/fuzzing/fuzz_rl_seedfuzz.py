"""RL-SeedFuzz 集成门面 --- RL 后训练变异调度 + LLM 初始种子语料增强。

设计意图:
  RL-SeedFuzz 为 BinMind fuzzing 模块的深度方案，由三个可独立使用、
  亦可组合的组件构成:

    [组件 1] fuzz_rl_sequence_scheduler.RLSequenceScheduler
             策略梯度变异序列建模: 将"长度 L 的变异算子序列"作为整体动作，
             以覆盖率增益为奖励，GRPO 式组内相对优势在线更新可学习序列
             打分器，显式建模算子间的时序依赖。可与 Bandit 种子调度叠加。

    [组件 2] fuzz_llm_seed_gen.HybridSeedGenerator
             LLM 初始种子语料增强: 对定向目标用 LLM 构建贴近目标语义的
             初始种子，提升冷启动命中概率；LLM 未配置时回退内置语法结构。

    [组件 3] fuzz_corpus_prior.SemanticPrior
             语料感知语义先验: 从种子语料提取 token 频率与结构模式，
             为字典与结构感知变异提供先验权重，提升结构变异有效性。

  本模块为三者的组合门面，提供冷启动 + 变异调度的一体化入口。

与论文的对应关系:
  R1-Fuzz   -- 组件 1 的 GRPO 组相对优势奖励建模
  ISC4DGF   -- 组件 2 的 LLM 定向初始种子语料构建
  LLAMAFUZZ -- 组件 3 的语料感知变异先验
  DeepGo    -- 定向灰盒模糊测试的预测性目标引导 (选读)

使用示例 (见函数 rl_seedfuzz_example):
  from modules.fuzzing.fuzz_rl_seedfuzz import RLSeedFuzz
  fz = RLSeedFuzz(llm_config=None)          # 无 LLM 时自动用结构化种子
  seeds = fz.run_cold_start([target1, target2], per_target=8)
  seq = fz.select_mutation_sequence(ctx)
  summary = fz.notify_mutation_reward(new_edges, seq, ctx)
"""

from typing import Any, Dict, List, Optional, Sequence

import logging

_log = logging.getLogger(__name__)

class RLSeedFuzz:
    """RL-SeedFuzz 一体化门面。

    组成:
      _seed_gen : LLM/结构化混合种子构造器 (组件 2)
      _prior    : 语料感知语义先验 (组件 3)
      _hybrid   : Bandit 种子调度 + RL 变异序列调度叠加 (组件 1)

    生命周期:
      1. run_cold_start(targets)  构建初始语料并纳入语料先验
      2. ingest_corpus(seeds)     运行中持续补充语料统计
      3. select_seed / select_mutation_sequence  调度
      4. notify_seed_reward / notify_mutation_reward  反馈更新
    """

    def __init__(self, llm_config=None, per_target: int = 8,
                 bandit_strategy: str = "linucb",
                 bandit_kwargs: Optional[dict] = None,
                 rl_kwargs: Optional[dict] = None,
                 context_dim: int = 5):
        try:
            from .fuzz_llm_seed_gen import build_seed_generator
            self._seed_gen = build_seed_generator(llm_config)
        except ImportError:
            _log.warning("fuzz_llm_seed_gen 不可用, 冷启动依赖外部种子")
            self._seed_gen = None
        try:
            from .fuzz_corpus_prior import CorpusTokenModel, SemanticPrior
            self._prior = SemanticPrior(CorpusTokenModel())
        except ImportError:
            _log.warning("fuzz_corpus_prior 不可用, 语义先验降级为空")
            self._prior = None
        try:
            from .fuzz_rl_sequence_scheduler import (
                HybridSeedMutationScheduler, seed_context_features)
            self._hybrid = HybridSeedMutationScheduler(
                bandit_strategy=bandit_strategy,
                bandit_kwargs=bandit_kwargs,
                rl_kwargs=rl_kwargs,
                context_dim=context_dim,
            )
            self._seed_context_extractor = seed_context_features
        except ImportError:
            _log.error("fuzz_rl_sequence_scheduler 不可用, RL 调度降级为 None")
            self._hybrid = None
            self._seed_context_extractor = None
        self._per_target = max(1, int(per_target))
        self._cold_start_count = 0
        self._corpus = []

    # 冷启动与语料

    def run_cold_start(self, target_sites: Sequence[Any],
                       per_target: Optional[int] = None) -> List[bytes]:
        """为定向目标列表构建初始种子语料 (LLM 增强 + 结构化兜底)。

        产出结果同时纳入语料先验，供后续变异调度使用。
        """
        n = per_target or self._per_target
        seeds: List[bytes] = []
        if self._seed_gen is not None:
            try:
                from .fuzz_llm_seed_gen import generate_initial_seed_corpus
                seeds = generate_initial_seed_corpus(
                    list(target_sites), self._seed_gen, per_target=n)
            except Exception as e:
                _log.warning("冷启动种子生成失败: %s", e)
        self.ingest_corpus(seeds)
        self._cold_start_count += 1
        return seeds

    def ingest_corpus(self, seeds: Sequence[bytes]) -> None:
        """将种子纳入语料先验统计 (运行中可增量调用)。"""
        if not seeds:
            return
        self._corpus.extend(bytes(s) for s in seeds)
        if self._prior is not None:
            self._prior.ingest(seeds)

    def corpus(self) -> List[bytes]:
        """返回累计语料的只读副本。"""
        return list(self._corpus)

    # 调度 (种子 + 变异序列)

    def select_seed(self, seed_queue: list,
                    contexts: Optional[List[List[float]]] = None):
        """委托 Bandit 调度器选择种子；返回 (索引, 分数) 或 None。"""
        if self._hybrid is None:
            return (0, 0.0) if seed_queue else None
        return self._hybrid.select_seed(seed_queue, contexts)

    def select_mutation_sequence(self,
                                 seed_meta: Optional[dict] = None,
                                 seed_data: bytes = b"") -> List[str]:
        """从 RL 策略中采样一条变异算子序列。

        传入种子元数据或数据时自动提取上下文特征供策略条件调制；
        否则使用无上下文策略。边界: _hybrid 为 None 时返回空列表。
        """
        if self._hybrid is None:
            return []
        ctx = None
        if self._seed_context_extractor is not None and seed_meta is not None:
            ctx = self._seed_context_extractor(
                seed_meta, len(seed_data),
                edge_count=seed_meta.get("edge_count", 0))
        return self._hybrid.select_mutation_sequence(ctx)

    # 反馈

    def notify_seed_reward(self, seed_id: str, is_new_find: bool,
                           crash_found: bool = False,
                           context: Optional[List[float]] = None) -> None:
        if self._hybrid is not None:
            self._hybrid.notify_seed_reward(seed_id, context, is_new_find,
                                            crash_found)

    def notify_mutation_reward(self, new_edges: int, seq: Sequence[str],
                               total_edges_before: int = 0,
                               crash_found: bool = False,
                               hang_found: bool = False,
                               exec_time_ms: float = 1.0,
                               context: Optional[List[float]] = None) -> Optional[dict]:
        """将覆盖率增益折算为奖励并反馈给 RL 调度器。

        折算细节见 fuzz_rl_sequence_scheduler.compute_sequence_reward。
        返回组更新摘要 dict，未满组时返回 None。
        """
        if self._hybrid is None:
            return None
        try:
            from .fuzz_rl_sequence_scheduler import compute_sequence_reward
            reward = compute_sequence_reward(
                new_edges, total_edges_before,
                crash_found=crash_found, hang_found=hang_found,
                exec_time_ms=exec_time_ms)
        except ImportError:
            reward = float(new_edges)
        return self._hybrid.notify_mutation_reward(reward, seq, context)

    # 统计

    def get_stats(self) -> dict:
        stats = {
            "cold_start_rounds": self._cold_start_count,
            "corpus_seeds": len(self._corpus),
            "prior_format": (self._prior._model.dominant_format()
                             if self._prior is not None else "unknown"),
        }
        if self._hybrid is not None:
            try:
                stats["hybrid"] = self._hybrid.get_stats()
            except Exception as e:
                stats["hybrid_error"] = str(e)
        return stats

    def reset(self) -> None:
        """重置调度器状态 (保留语料统计)。"""
        if self._hybrid is not None:
            self._hybrid.reset()
        self._cold_start_count = 0

# 快捷构造入口

def create_rl_seedfuzz(llm_config=None, **kw) -> RLSeedFuzz:
    """构造 RL-SeedFuzz 门面实例。"""
    return RLSeedFuzz(llm_config=llm_config, **kw)

def rl_seedfuzz_example() -> dict:
    """RL-SeedFuzz 标准使用流程示例 (含全部三组件)。

    该例程不依赖外部 LLM (llm_config=None)，验证无配置时程序照常运行。
    """
    from .fuzz_llm_seed_gen import _LabelTarget

    targets = [_LabelTarget("CVE-2024-XXXX patch json_parse"),
               _LabelTarget("http header length check")]
    fz = RLSeedFuzz(llm_config=None, bandit_strategy="linucb")
    seeds = fz.run_cold_start(targets, per_target=6)
    seq = fz.select_mutation_sequence(
        {"exec_time_ms": 5.0, "generation": 0, "edge_count": 42}, b"A" * 64)
    summary = fz.notify_mutation_reward(
        new_edges=3, seq=seq, total_edges_before=100)
    return {
        "cold_start_seeds": len(seeds),
        "sample_seq": seq,
        "group_update": summary,
        "stats": fz.get_stats(),
    }

__all__ = ["RLSeedFuzz", "create_rl_seedfuzz", "rl_seedfuzz_example"]
