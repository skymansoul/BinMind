# 基于离散图编辑的反事实解释器，面向二进制漏洞检测GNN模型
# 核心问题: 给定一个被判定为"漏洞"的二进制函数图，找出最小的一组图编辑操作
# 使模型预测翻转为"非漏洞"
#
# 离散搜索由 src/explain/counterfactual_search.py 的 MCTS 引擎执行
# 本文件提供 CounterfactualExplainer 便捷入口和 CounterfactualResult 包装

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field

import numpy as np

from .src.explain.cf_constraints import GraphEdit, GraphEditOp, BinarySemanticConstraints
from .src.explain.counterfactual_search import (
    CounterfactualSearchEngine, MCTSNode, SearchResult,
)

logger = logging.getLogger(__name__)


@dataclass
class CounterfactualResult:
    """反事实解释的完整结果-对SearchResult的用户友好包装"""
    original_pred: float
    counterfactual_pred: float
    flip_achieved: bool
    edits: List[GraphEdit]
    total_cost: float
    search_steps: int
    alternative_edits: List[List[GraphEdit]] = field(default_factory=list)
    constraints_violated: List[str] = field(default_factory=list)

    @staticmethod
    def from_search_result(sr: SearchResult) -> CounterfactualResult:
        return CounterfactualResult(
            original_pred=sr.original_pred,
            counterfactual_pred=sr.counterfactual_pred,
            flip_achieved=sr.flip_achieved,
            edits=sr.edits,
            total_cost=sr.total_cost,
            search_steps=sr.search_steps,
        )

    def to_dict(self) -> dict:
        return {
            'original_pred': self.original_pred,
            'counterfactual_pred': self.counterfactual_pred,
            'flip_achieved': self.flip_achieved,
            'n_edits': len(self.edits),
            'total_cost': self.total_cost,
            'search_steps': self.search_steps,
            'edits': [
                {'op': e.op.value, 'src': e.src_node, 'dst': e.dst_node, 'cost': e.cost}
                for e in self.edits
            ],
        }

    def summarize(self) -> str:
        if self.flip_achieved:
            return (
                f"反事实成功: pred {self.original_pred:.3f}→{self.counterfactual_pred:.3f}, "
                f"{len(self.edits)}次编辑, cost={self.total_cost:.2f}"
            )
        return (
            f"反事实未找到: best pred={self.counterfactual_pred:.3f}, "
            f"steps={self.search_steps}"
        )


class CounterfactualExplainer:
    """面向二进制漏洞GNN模型的反事实解释器。

    使用场景:
      - 理解为何某个函数被判定为有漏洞
      - 生成最小程序变换方案使GNN预测翻转
      - 验证模型是否学到了正确的漏洞模式（而非伪相关）

    输出可直接映射到二进制修改建议: 删除某分支、重排某条指令。
    """

    def __init__(self,
                 model_fn: Callable,
                 constraints: Optional[BinarySemanticConstraints] = None,
                 flip_threshold: float = 0.5,
                 mcts_iterations: int = 200,
                 max_edits: int = 20):
        self._model = model_fn
        self._constraints = constraints or BinarySemanticConstraints()
        self._threshold = flip_threshold
        self._mcts_iters = mcts_iterations
        self._max_edits = max_edits

    def explain(self,
                node_features: List[List[float]],
                adjacency: List[List[int]],
                target_node: int,
                node_types: Optional[List[str]] = None,
                loop_edges: Optional[List[Tuple[int, int]]] = None) -> CounterfactualResult:
        """为指定节点生成反事实解释。"""
        self._constraints.load_from_cfg(adjacency, node_types, loop_edges)

        engine = CounterfactualSearchEngine(
            model_fn=self._model,
            adjacency=adjacency,
            node_features=node_features,
            constraints=self._constraints,
            target_node=target_node,
            flip_threshold=self._threshold,
            max_edits=self._max_edits,
            mcts_iterations=self._mcts_iters,
        )
        sr = engine.search()
        return CounterfactualResult.from_search_result(sr)

    def batch_explain(self,
                      graphs: List[Tuple[List[List[float]], List[List[int]], int]],
                      node_types_list: Optional[List[List[str]]] = None) -> List[CounterfactualResult]:
        """批量反事实解释（顺序执行）"""
        results = []
        for idx, (feats, adj, target) in enumerate(graphs):
            ntypes = node_types_list[idx] if node_types_list else None
            result = self.explain(feats, adj, target, node_types=ntypes)
            results.append(result)
            if result.flip_achieved:
                logger.info(
                    f"graph {idx}: flipped with {len(result.edits)} edits, cost={result.total_cost:.2f}"
                )
            else:
                logger.info(
                    f"graph {idx}: no flip found, best pred={result.counterfactual_pred:.4f}"
                )
        return results
