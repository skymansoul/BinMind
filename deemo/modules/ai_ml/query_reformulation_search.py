# created: 2026-08-18
# 查询重写——自动将模糊查询重构为更精确的二进制函数搜索
#
# 核心问题: 用户的自然语言查询与二进制指令之间存在词汇鸿沟——
# "网络包处理函数"不会直接出现在汇编代码中。
#
# 技术方案:
#   1. 伪相关反馈(PRF): 从top-K结果中提取扩展词
#   2. 多策略重写: expand/abstract/specialize三种方向
#   3. 质量评估: 基于检索分数分布的分离度估计重写质量
#   4. 迭代改进: 多轮重写直到质量不再提升
#
# 注: abstract/specialize的映射表是可扩展的——通过register_mapping()
# 添加领域特定的术语映射。当前内置映射覆盖常见二进制分析场景。

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class QueryCandidate:
    """查询候选——原始查询的一个重写版本"""
    query_text: str
    query_embedding: np.ndarray
    reformulation_strategy: str       # 使用的重写策略
    retrieval_results: List[Tuple[str, float]]  # [(func_id, score), ...]
    quality_score: float              # 检索质量估计
    round_number: int                 # 重写轮数


@dataclass
class ReformulationReport:
    """查询重写完整报告"""
    original_query: str
    final_query: str
    n_reformulations: int
    n_total_results: int
    quality_improvement: float
    candidate_history: List[QueryCandidate]


class QueryReformulator:
    """查询重写器——自动优化二进制函数搜索查询。

    四种重写策略:
      EXPAND: 从top检索结果中提取共同特征→扩展查询
      ABSTRACT: 将具体操作提升为抽象类别（mov→内存操作→数据处理）
      SPECIALIZE: 将抽象描述细化为具体操作（"加密"→aesenc/pxor/sha256）
      SPLIT: 将复合查询拆分为独立子查询→分别检索→合并
    """

    def __init__(self,
                 embed_fn: Callable[[str], np.ndarray],
                 search_fn: Callable[[np.ndarray, int], List[Tuple[str, float]]],
                 embed_dim: int = 128):
        self._embed = embed_fn
        self._search = search_fn
        self.embed_dim = embed_dim
        # 可扩展的术语映射——通过register_mapping()添加领域特定映射
        self._abstract_map = {
            'memcpy': 'memory_copy', 'strcpy': 'memory_copy',
            'memmove': 'memory_copy', 'strncpy': 'memory_copy',
            'malloc': 'memory_allocate', 'calloc': 'memory_allocate',
            'realloc': 'memory_allocate',
            'send': 'data_output', 'write': 'data_output',
            'recv': 'data_input', 'read': 'data_input',
            'encrypt': 'crypto_operation', 'decrypt': 'crypto_operation',
            'compress': 'data_transform', 'decompress': 'data_transform',
            'parse': 'data_parsing', 'serialize': 'data_serialization',
            'connect': 'network_operation', 'bind': 'network_operation',
            'fork': 'process_control', 'exec': 'process_control',
        }
        self._specialize_map = {
            'memory_copy': 'memcpy OR memmove OR strncpy',
            'memory_allocate': 'malloc OR calloc OR realloc',
            'crypto': 'aesenc OR pxor OR sha256 OR ror OR xor',
            'network': 'recv OR send OR socket OR connect OR bind',
            'parsing': 'strcmp OR strstr OR strtok OR sscanf OR atoi',
            'compression': 'inflate OR deflate OR lzma OR zlib',
            'process_control': 'fork OR execve OR clone OR waitpid',
            'file_io': 'open OR read OR write OR close OR lseek OR mmap',
        }

    def register_mapping(self, direction: str,
                         concrete: str, abstract: str):
        """注册领域特定的术语映射——扩展内置映射表。

        Args:
            direction: 'abstract' 或 'specialize'
            concrete: 具体术语
            abstract: 抽象术语
        """
        if direction == 'abstract':
            self._abstract_map[concrete.lower()] = abstract
        elif direction == 'specialize':
            self._specialize_map[abstract.lower()] = concrete

    def reformulate(self,
                    query_text: str,
                    max_rounds: int = 3,
                    top_k: int = 10
                    ) -> ReformulationReport:
        """多轮查询重写——逐步改进检索质量。

        Returns:
            ReformulationReport with history
        """
        candidates = []
        current_query = query_text

        for round_num in range(max_rounds):
            round_candidates = []

            # 对当前查询尝试所有策略
            for strategy in ['expand', 'abstract', 'specialize']:
                rewritten = self._apply_strategy(
                    current_query, strategy, candidates)
                if rewritten == current_query:
                    continue

                q_emb = self._embed(rewritten)
                results = self._search(q_emb, top_k)
                quality = self._estimate_quality(results)

                round_candidates.append(QueryCandidate(
                    query_text=rewritten,
                    query_embedding=q_emb,
                    reformulation_strategy=strategy,
                    retrieval_results=results,
                    quality_score=quality,
                    round_number=round_num + 1))

            candidates.extend(round_candidates)

            # 选择本轮最佳重写作为下一轮的起点
            if round_candidates:
                best = max(round_candidates, key=lambda c: c.quality_score)
                if best.quality_score > self._estimate_quality(
                    self._search(self._embed(current_query), top_k)):
                    current_query = best.query_text
                else:
                    break  # 质量未提升，停止重写
            else:
                break

        all_results = {}
        for c in candidates:
            for fid, score in c.retrieval_results:
                if fid not in all_results or score > all_results[fid]:
                    all_results[fid] = score

        initial_quality = 0.0
        if candidates:
            first_round = [c for c in candidates if c.round_number == 1]
            if first_round:
                initial_quality = max(c.quality_score for c in first_round)

        final_quality = 0.0
        if candidates:
            final_quality = max(c.quality_score for c in candidates)

        return ReformulationReport(
            original_query=query_text,
            final_query=current_query,
            n_reformulations=len(candidates),
            n_total_results=len(all_results),
            quality_improvement=final_quality - initial_quality,
            candidate_history=candidates)

    def _apply_strategy(self, query: str, strategy: str,
                        history: List[QueryCandidate]) -> str:
        """应用重写策略"""
        if strategy == 'expand':
            return self._expand_query(query, history)
        elif strategy == 'abstract':
            return self._abstract_query(query)
        elif strategy == 'specialize':
            return self._specialize_query(query)
        return query

    def _expand_query(self, query: str,
                      history: List[QueryCandidate]) -> str:
        """伪相关反馈: 从历史最佳结果中提取扩展词"""
        if not history:
            return query
        recent = [c for c in history if c.retrieval_results]
        if not recent:
            return query
        best_results = recent[-1].retrieval_results[:3]
        # 提取函数名中的关键词作为扩展
        extra_terms = []
        for fid, score in best_results:
            if score > 0.7:
                terms = fid.replace('_', ' ').split()[:3]
                extra_terms.extend(terms)
        if extra_terms:
            unique = list(dict.fromkeys(extra_terms))[:5]
            return query + " " + " ".join(unique)
        return query

    def _abstract_query(self, query: str) -> str:
        """提升抽象层次: 具体操作→功能类别"""
        q_lower = query.lower()
        for concrete, abstract in self._abstract_map.items():
            if concrete in q_lower:
                return abstract
        return query

    def _specialize_query(self, query: str) -> str:
        """细化抽象描述: 功能类别→具体指令序列"""
        q_lower = query.lower()
        for abstract, concrete in self._specialize_map.items():
            if abstract in q_lower:
                return concrete
        return query

    def _estimate_quality(self,
                          results: List[Tuple[str, float]]) -> float:
        """估计检索质量——基于结果分数的统计特征。

        高质量检索的特征: 分数分布有明显的"头"（top分数远高于平均值）。
        """
        if not results:
            return 0.0
        scores = [s for _, s in results]
        if len(scores) < 2:
            return float(scores[0]) if scores else 0.0
        top_score = max(scores)
        mean_score = float(np.mean(scores))
        std_score = float(np.std(scores))
        # 质量 = top分数 × (top偏离均值的程度)
        separation = (top_score - mean_score) / max(0.01, std_score)
        return top_score * min(1.0, separation / 3.0)
