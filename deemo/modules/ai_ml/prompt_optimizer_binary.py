# 测试时提示优化——为LLM二进制分析动态选择最优few-shot示例
#
# 核心问题: llm_agent_binary.py使用固定的prompt模板+随机few-shot示例，
# 但不同分析任务（函数命名/漏洞检测/反混淆）需要不同类型的示例。
# 更关键的——与目标函数最相似的示例比随机示例能显著提升LLM输出质量。
# 2025年研究表明提示工程对代码LLM的性能影响可达20-40%。
#
# 技术方案:
#   1. 示例池: 维护标注好的(functions, analysis)示例池
#   2. 嵌入匹配: 对目标函数计算嵌入→从池中检索最相似的K个示例
#   3. 多样性选择: MMR(Maximal Marginal Relevance)平衡相似性和多样性——
#      选出的K个示例既要与目标相关，又要彼此不同（覆盖不同模式）
#   4. 性能反馈: 记录每个示例在历史任务中的"贡献度"——
#      帮助产生正确输出的示例得分+1，低质量示例逐渐被淘汰

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class FewShotExample:
    """标注的few-shot示例"""
    example_id: str
    task_type: str              # function_naming / vuln_detect / deobfuscate
    function_embedding: np.ndarray
    input_code: str             # 函数反汇编
    output_analysis: str        # 标注的分析结果
    contribution_score: float = 0.0  # 历史贡献度(越高越好)
    usage_count: int = 0
    success_count: int = 0


@dataclass
class OptimizedPrompt:
    """优化后的prompt"""
    task_description: str
    selected_examples: List[FewShotExample]
    target_code: str
    final_prompt: str
    estimated_quality: float    # 预估的LLM输出质量


class PromptOptimizer:
    """测试时提示优化器——MMR选择+贡献度追踪。

    MMR (Maximal Marginal Relevance):
      选择第i个示例时最大化: λ·sim(example, target) - (1-λ)·max_j(sim(example, selected[j]))
      第一项确保相关性，第二项确保多样性。
    """

    def __init__(self, example_pool: List[FewShotExample],
                 lambda_diversity: float = 0.7,
                 max_examples: int = 5):
        self._pool = example_pool
        self._lambda = lambda_diversity
        self._max_examples = max_examples
        self._usage_log: Dict[str, List[float]] = defaultdict(list)

    def optimize(self, target_embedding: np.ndarray,
                 target_code: str, task_type: str,
                 task_description: str = "") -> OptimizedPrompt:
        """为给定目标函数优化few-shot示例选择。"""
        # 筛选任务类型匹配的示例
        candidates = [e for e in self._pool if e.task_type == task_type]
        if not candidates:
            candidates = self._pool[:self._max_examples * 2]

        # MMR选择
        selected = self._mmr_select(candidates, target_embedding,
                                     self._max_examples)

        # 构建prompt
        prompt_parts = [task_description or f"Task: {task_type} analysis"]
        prompt_parts.append("\nExamples:\n")
        for i, ex in enumerate(selected):
            prompt_parts.append(f"--- Example {i+1} ---")
            prompt_parts.append(f"Input:\n{ex.input_code[:800]}")
            prompt_parts.append(f"Analysis:\n{ex.output_analysis[:500]}")
            prompt_parts.append("")

        prompt_parts.append("--- Target ---")
        prompt_parts.append(f"Input:\n{target_code[:1500]}")
        prompt_parts.append("Analysis:")

        final_prompt = "\n".join(prompt_parts)

        # 质量估计: 基于所选示例的平均贡献度+与目标的平均相似度
        avg_contrib = float(np.mean([e.contribution_score for e in selected])) if selected else 0.0
        avg_sim = float(np.mean([
            self._cosine_sim(e.function_embedding, target_embedding)
            for e in selected])) if selected else 0.0
        est_quality = 0.4 * avg_contrib + 0.6 * avg_sim

        return OptimizedPrompt(
            task_description=task_description,
            selected_examples=selected,
            target_code=target_code,
            final_prompt=final_prompt,
            estimated_quality=est_quality)

    def _mmr_select(self, candidates: List[FewShotExample],
                    target_emb: np.ndarray, K: int) -> List[FewShotExample]:
        selected = []
        remaining = list(candidates)

        # 第一个: 选最相似的
        if remaining:
            best = max(remaining, key=lambda e:
                      self._cosine_sim(e.function_embedding, target_emb))
            selected.append(best)
            remaining.remove(best)

        # 后续: MMR
        for _ in range(K - 1):
            if not remaining:
                break
            best_ex, best_score = None, -float('inf')
            for ex in remaining:
                relevance = self._cosine_sim(ex.function_embedding, target_emb)
                max_redundancy = max(
                    (self._cosine_sim(ex.function_embedding, s.function_embedding)
                     for s in selected), default=0.0)
                mmr = self._lambda * relevance - (1 - self._lambda) * max_redundancy
                # 贡献度bonus
                mmr += 0.1 * ex.contribution_score
                if mmr > best_score:
                    best_score, best_ex = mmr, ex
            if best_ex:
                selected.append(best_ex)
                remaining.remove(best_ex)

        return selected

    def record_feedback(self, example_id: str, was_helpful: bool):
        """记录示例的反馈——用于贡献度追踪"""
        if example_id in {e.example_id for e in self._pool}:
            for ex in self._pool:
                if ex.example_id == example_id:
                    ex.usage_count += 1
                    ex.success_count += int(was_helpful)
                    ex.contribution_score = (
                        ex.success_count / max(1, ex.usage_count))

    def prune_low_quality(self, min_uses: int = 5,
                          min_score: float = 0.3):
        """剪枝低质量示例——长期表现不佳的示例被移除"""
        self._pool = [e for e in self._pool
                     if e.usage_count < min_uses or
                     e.contribution_score >= min_score]

    @staticmethod
    def _cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
        na = float(np.linalg.norm(a))
        nb = float(np.linalg.norm(b))
        if na < 1e-8 or nb < 1e-8:
            return 0.0
        return float(np.dot(a, b)) / (na * nb)
