# 图检索增强生成——为LLM二进制分析注入相似函数的上下文
#
# 核心问题: LLM分析二进制函数时仅看到当前函数的反汇编代码，
# 缺乏项目内其他函数的上下文。同项目的相似函数往往共享命名约定、
# 数据结构和错误处理模式——这些上下文能显著提升LLM的分析质量。
# 2025年RAG广泛应用于源码和文档领域，但二进制代码RAG尚未被探索。
#
# 技术方案:
#   1. 函数嵌入索引: 将项目中所有函数编码为嵌入向量并建索引
#   2. 相似函数检索: 对目标函数，检索top-K个嵌入最相似的函数
#   3. 上下文增强: 将检索到的相似函数的反汇编+元数据注入LLM prompt
#   4. 相关性筛选: 仅注入与目标函数共享调用链/数据引用的函数——
#      避免"表面相似但语义无关"的噪声污染prompt
#   5. Token预算感知: 根据剩余token预算动态调整K

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class RetrievedFunction:
    func_id: str
    func_name: str
    similarity: float
    disassembly: str
    call_chain_distance: int     # 调用图中到目标函数的距离
    shared_data_refs: List[str]  # 与目标函数共享的数据引用
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AugmentedPrompt:
    target_function: str         # 目标函数的反汇编
    retrieved_contexts: List[RetrievedFunction]
    prompt_template: str
    final_prompt: str
    token_count: int
    relevance_score: float


class BinaryFunctionIndex:
    """二进制函数嵌入索引——为RAG检索提供后端。

    索引结构: 嵌入向量 + 调用图邻接 + 数据引用映射
    相似度: 嵌入余弦相似度(0.6) + 调用图邻近度(0.25) + 数据引用重叠(0.15)
    """

    def __init__(self, embed_dim: int = 128):
        self.embed_dim = embed_dim
        self._embeddings: Dict[str, np.ndarray] = {}
        self._disasm: Dict[str, str] = {}
        self._call_graph: Dict[str, List[str]] = defaultdict(list)
        self._callers: Dict[str, List[str]] = defaultdict(list)
        self._data_refs: Dict[str, Set[str]] = defaultdict(set)
        self._metadata: Dict[str, Dict] = {}

    def index_function(self, func_id: str, embedding: np.ndarray,
                       disassembly: str = "",
                       callees: List[str] = None,
                       data_refs: List[str] = None,
                       metadata: Dict = None):
        self._embeddings[func_id] = embedding
        self._disasm[func_id] = disassembly
        if callees:
            self._call_graph[func_id] = list(callees)
            for c in callees:
                self._callers[c].append(func_id)
        if data_refs:
            self._data_refs[func_id] = set(data_refs)
        if metadata:
            self._metadata[func_id] = metadata

    def retrieve(self, query_embedding: np.ndarray,
                 target_func_id: str,
                 top_k: int = 5,
                 max_call_distance: int = 3) -> List[RetrievedFunction]:
        """检索与目标函数相关的相似函数。

        三步筛选:
          1. 嵌入余弦相似度top-2K
          2. 调用图距离过滤(≤max_call_distance)
          3. 数据引用重叠加分→重排序
        """
        if not self._embeddings:
            return []

        q_norm = float(np.linalg.norm(query_embedding))
        if q_norm < 1e-8:
            return []

        # 嵌入相似度
        candidates = []
        for fid, emb in self._embeddings.items():
            if fid == target_func_id:
                continue
            e_norm = float(np.linalg.norm(emb))
            if e_norm < 1e-8:
                continue
            sim = float(np.dot(query_embedding, emb)) / (q_norm * e_norm)
            if sim > 0.5:  # 仅保留有意义的相似度
                candidates.append((fid, sim))

        candidates.sort(key=lambda x: -x[1])
        candidates = candidates[:top_k * 2]

        # 调用图距离
        call_distances = self._compute_call_distances(target_func_id)
        filtered = []
        for fid, sim in candidates:
            dist = call_distances.get(fid, max_call_distance + 1)
            if dist <= max_call_distance:
                # 距离越近→额外加分
                proximity_bonus = 1.0 / (1.0 + dist)
                filtered.append((fid, sim + 0.1 * proximity_bonus, dist))

        # 数据引用重叠
        target_refs = self._data_refs.get(target_func_id, set())
        scored = []
        for fid, combined_sim, dist in filtered:
            shared_refs = list(target_refs & self._data_refs.get(fid, set()))
            if target_refs:
                ref_overlap = len(shared_refs) / max(1, len(target_refs))
                combined_sim += 0.15 * ref_overlap
            scored.append((fid, combined_sim, dist, shared_refs))

        scored.sort(key=lambda x: -x[1])
        results = []
        for fid, sim, dist, shared_refs in scored[:top_k]:
            results.append(RetrievedFunction(
                func_id=fid,
                func_name=self._metadata.get(fid, {}).get("name", fid),
                similarity=sim,
                disassembly=self._disasm.get(fid, "")[:2000],
                call_chain_distance=dist,
                shared_data_refs=shared_refs[:10],
                metadata=self._metadata.get(fid, {})))
        return results

    def _compute_call_distances(self, source: str) -> Dict[str, int]:
        """BFS计算调用图中source到各函数的距离"""
        distances = {source: 0}
        q = deque([source])
        while q:
            u = q.popleft()
            for v in self._call_graph.get(u, []):
                if v not in distances:
                    distances[v] = distances[u] + 1
                    q.append(v)
            for v in self._callers.get(u, []):
                if v not in distances:
                    distances[v] = distances[u] + 1
                    q.append(v)
        return distances


class GraphRAGAugmenter:
    """图RAG增强器——为LLM二进制分析构建增强prompt。

    Prompt模板注入策略:
      将检索到的相似函数以"参考上下文"的形式注入prompt，
      包含: 函数名、反汇编摘要、与目标的调用关系。
      格式化为结构化JSON以避免与主prompt混淆。
    """

    def __init__(self, function_index: BinaryFunctionIndex,
                 max_context_tokens: int = 2000):
        self._index = function_index
        self._max_tokens = max_context_tokens

    def augment(self, target_func_id: str,
                query_embedding: np.ndarray,
                base_prompt: str,
                top_k: int = 3) -> AugmentedPrompt:
        """构建RAG增强的LLM prompt。"""
        retrieved = self._index.retrieve(
            query_embedding, target_func_id, top_k=top_k)

        if not retrieved:
            return AugmentedPrompt(
                target_function=self._index._disasm.get(target_func_id, ""),
                retrieved_contexts=[],
                prompt_template=base_prompt,
                final_prompt=base_prompt,
                token_count=len(base_prompt.split()),
                relevance_score=0.0)

        # 构建上下文注入块
        context_parts = ["[RETRIEVED CONTEXT - Similar functions in this binary:]\n"]
        token_budget = self._max_tokens
        relevance_sum = 0.0

        for i, rf in enumerate(retrieved):
            ctx = (f"--- Similar Function {i+1}: {rf.func_name} "
                   f"(similarity={rf.similarity:.2f}, "
                   f"call_distance={rf.call_chain_distance}) ---\n"
                   f"Disassembly:\n{rf.disassembly[:500]}\n")
            if rf.shared_data_refs:
                ctx += f"Shared data refs: {', '.join(rf.shared_data_refs[:5])}\n"
            ctx_tokens = len(ctx.split())
            if token_budget - ctx_tokens < 0:
                break
            context_parts.append(ctx)
            token_budget -= ctx_tokens
            relevance_sum += rf.similarity

        context_parts.append("[END CONTEXT]\n\n")

        context_block = "\n".join(context_parts)
        final = context_block + base_prompt
        token_count = len(final.split())
        avg_relevance = relevance_sum / max(1, len(retrieved))

        return AugmentedPrompt(
            target_function=self._index._disasm.get(target_func_id, ""),
            retrieved_contexts=retrieved,
            prompt_template=base_prompt,
            final_prompt=final,
            token_count=token_count,
            relevance_score=avg_relevance)

    def estimate_improvement(self, augmented: AugmentedPrompt,
                             baseline_quality: float = 0.5) -> float:
        """估计RAG增强后的质量提升。

        模型: improvement = relevance_score × context_diversity × log(1+K)
        相关性越高、检索结果越多样、K越多→提升越大（边际递减）。
        """
        if not augmented.retrieved_contexts:
            return 0.0
        K = len(augmented.retrieved_contexts)
        # 上下文多样性: 调用距离的方差
        distances = [rf.call_chain_distance
                    for rf in augmented.retrieved_contexts]
        diversity = float(np.std(distances)) / max(1.0, float(np.mean(distances)))
        improvement = (augmented.relevance_score *
                      min(1.0, diversity * 0.5) *
                      math.log(1 + K) / math.log(4))
        return improvement
