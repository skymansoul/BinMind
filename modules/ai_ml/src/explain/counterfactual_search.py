# MCTS引导的离散图编辑反事实搜索
# 搜索目标: 最小编辑代价使GNN预测从vulnerable翻转为benign
# 约束由 cf_constraints.py 定义
# 编辑操作池动态生成(O(N)而非O(N²)) + 状态哈希缓存 + UCT代价融入
from __future__ import annotations

import math
import random
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque
from dataclasses import dataclass, field
import numpy as np

from .cf_constraints import GraphEditOp, GraphEdit, BinarySemanticConstraints

logger = logging.getLogger(__name__)


# 搜索结果-避免与上层explainer的循环导入
@dataclass
class SearchResult:
    original_pred: float
    counterfactual_pred: float
    flip_achieved: bool
    edits: List[GraphEdit] = field(default_factory=list)
    total_cost: float = 0.0
    search_steps: int = 0


class MCTSNode:
    """MCTS节点-代表部分编辑序列。UCT融入编辑代价偏向低成本路径。"""

    __slots__ = ('edits', 'parent', 'children', 'visits', 'value',
                 'pred_score', 'untried_ops')

    def __init__(self, edits: List[GraphEdit], parent=None):
        self.edits = edits
        self.parent = parent
        self.children: List[MCTSNode] = []
        self.visits = 0
        self.value = 0.0
        self.pred_score = 0.0
        self.untried_ops: List[GraphEdit] = []

    def is_fully_expanded(self) -> bool:
        return len(self.untried_ops) == 0

    def best_child(self, explore_weight: float = 1.414) -> MCTSNode:
        if not self.children:
            return self
        log_n = math.log(max(1, self.visits))
        def uct(child):
            exploit = child.value / max(1, child.visits)
            explore = explore_weight * math.sqrt(log_n / max(1, child.visits))
            cost_penalty = 1.0 / (1.0 + sum(e.cost for e in child.edits))
            return exploit * cost_penalty + explore
        return max(self.children, key=uct)


# MCTS搜索引擎
class CounterfactualSearchEngine:
    """MCTS反事实搜索: 最小编辑代价使GNN预测翻转。"""

    def __init__(self,
                 model_fn: Callable,
                 adjacency: List[List[int]],
                 node_features: List[List[float]],
                 constraints: BinarySemanticConstraints,
                 target_node: int,
                 flip_threshold: float = 0.5,
                 max_edits: int = 20,
                 mcts_iterations: int = 200,
                 mcts_depth: int = 3,
                 explore_weight: float = 1.414):
        self._model = model_fn
        self._adj = [row[:] for row in adjacency]
        self._features = [row[:] for row in node_features]
        self._constraints = constraints
        self._target = target_node
        self._threshold = flip_threshold
        self._max_edits = max_edits
        self._mcts_iters = mcts_iterations
        self._mcts_depth = mcts_depth
        self._c = explore_weight
        self._eval_cache: Dict[str, float] = {}
        self._n_nodes = len(adjacency)

    def _model_predict(self, adj, feats) -> float:
        cache_key = self._hash_state(adj, feats, self._target)
        if cache_key in self._eval_cache:
            return self._eval_cache[cache_key]
        try:
            out = self._model(feats, adj)
            if hasattr(out, '__len__') and len(out) > self._target:
                score = float(out[self._target])
            elif hasattr(out, 'flatten'):
                score = float(np.asarray(out).flatten()[0])
            else:
                score = float(out)
        except (TypeError, ValueError, IndexError, AttributeError) as e:
            logger.debug(f"model predict failed at target={self._target}: {e}")
            score = 1.0  # 保守假设: 评估失败→高漏洞概率
        self._eval_cache[cache_key] = score
        return score

    @staticmethod
    def _hash_state(adj, feats, target) -> str:
        n = min(len(adj), 16)
        rows = []
        for i in range(n):
            row_sum = sum(adj[i][:n]) if i < len(adj) else 0
            feat_mean = (sum(feats[i][:4]) / max(1, len(feats[i][:4]))
                        if i < len(feats) else 0)
            rows.append(f"{row_sum:.1f}:{feat_mean:.2f}")
        return f"t{target}_" + "|".join(rows)

    def _generate_candidate_edits(self, adj, feats, max_candidates=30) -> List[GraphEdit]:
        candidates = []
        n = len(adj)
        distances = self._compute_distances(adj, self._target)

        # 边删除: 近邻边优先
        drop_cands = []
        for i in range(n):
            for j in range(n):
                if adj[i][j]:
                    dw = 1.0 / (1.0 + min(distances[i], distances[j]))
                    drop_cands.append((dw, i, j))
        drop_cands.sort(key=lambda x: -x[0])
        for _, i, j in drop_cands[:max_candidates // 3]:
            edit = GraphEdit(op=GraphEditOp.EDGE_DROP, src_node=i, dst_node=j, cost=1.0)
            allowed, _ = self._constraints.is_edit_allowed(edit, adj, feats)
            if allowed:
                candidates.append(edit)

        # 边添加: 近邻非相邻节点
        add_count = 0
        for i in range(n):
            if add_count >= max_candidates // 4:
                break
            for j in range(n):
                if i == j or adj[i][j]:
                    continue
                if abs(distances[i] - distances[j]) <= 2:
                    edit = GraphEdit(op=GraphEditOp.EDGE_ADD, src_node=i, dst_node=j, cost=1.5)
                    allowed, _ = self._constraints.is_edit_allowed(edit, adj, feats)
                    if allowed:
                        candidates.append(edit)
                        add_count += 1
                        if add_count >= max_candidates // 4:
                            break

        # 特征扰动: 高方差维度
        if feats and len(feats) > 0 and len(feats[0]) > 0:
            dim = len(feats[0])
            variances = []
            for d in range(dim):
                vals = [feats[i][d] for i in range(n) if i < len(feats) and d < len(feats[i])]
                if len(vals) > 1:
                    variances.append((d, np.var(vals)))
            variances.sort(key=lambda x: -x[1])
            top_dims = [d for d, _ in variances[:min(4, len(variances))]]
            for node in range(min(n, max_candidates // 4)):
                if node in self._constraints._entry_nodes:
                    continue
                for d in top_dims:
                    if d < len(feats[node]):
                        ov = feats[node][d]
                        perturb = ov * random.uniform(-0.3, 0.3)
                        edit = GraphEdit(op=GraphEditOp.FEATURE_PERTURB,
                                        src_node=node, feature_idx=d,
                                        old_value=ov, new_value=ov + perturb, cost=0.5)
                        candidates.append(edit)

        return candidates

    def _compute_distances(self, adj, source) -> List[int]:
        n = len(adj)
        dist = [n * 2] * n
        if source >= n:
            return [0] * n
        dist[source] = 0
        q = deque([source])
        while q:
            u = q.popleft()
            for v in range(n):
                if adj[u][v] and dist[v] > dist[u] + 1:
                    dist[v] = dist[u] + 1
                    q.append(v)
        return dist

    def _apply_edits(self, adj, feats, edits):
        new_adj = [row[:] for row in adj]
        new_feats = [row[:] for row in feats]
        for edit in edits:
            if edit.op == GraphEditOp.EDGE_DROP:
                if 0 <= edit.src_node < len(new_adj) and 0 <= edit.dst_node < len(new_adj):
                    new_adj[edit.src_node][edit.dst_node] = 0
            elif edit.op == GraphEditOp.EDGE_ADD:
                if 0 <= edit.src_node < len(new_adj) and 0 <= edit.dst_node < len(new_adj):
                    new_adj[edit.src_node][edit.dst_node] = 1
            elif edit.op == GraphEditOp.FEATURE_PERTURB:
                if (0 <= edit.src_node < len(new_feats) and
                    0 <= edit.feature_idx < len(new_feats[edit.src_node])):
                    new_feats[edit.src_node][edit.feature_idx] = edit.new_value
            elif edit.op == GraphEditOp.NODE_MASK:
                if 0 <= edit.src_node < len(new_feats):
                    new_feats[edit.src_node] = [0.0] * len(new_feats[edit.src_node])
        return new_adj, new_feats

    def _rollout(self, adj, feats, depth):
        cur_adj = [row[:] for row in adj]
        cur_feat = [row[:] for row in feats]
        applied = []
        for _ in range(depth):
            score = self._model_predict(cur_adj, cur_feat)
            if score < self._threshold:
                return 1.0, applied
            cands = self._generate_candidate_edits(cur_adj, cur_feat, max_candidates=15)
            if not cands:
                break
            best_edit, best_drop = None, -float('inf')
            for edit in cands[:8]:
                try:
                    ta, tf = self._apply_edits(cur_adj, cur_feat, [edit])
                    drop = score - self._model_predict(ta, tf)
                    if drop > best_drop:
                        best_drop, best_edit = drop, edit
                except Exception:
                    continue
            if best_edit is None:
                best_edit = random.choice(cands)
            cur_adj, cur_feat = self._apply_edits(cur_adj, cur_feat, [best_edit])
            applied.append(best_edit)
        final = self._model_predict(cur_adj, cur_feat)
        return (1.0 if final < self._threshold else 0.0), applied

    def search(self) -> SearchResult:
        original_score = self._model_predict(self._adj, self._features)

        root = MCTSNode(edits=[])
        root.pred_score = original_score
        root.untried_ops = self._generate_candidate_edits(
            self._adj, self._features, max_candidates=30)
        root.visits = 1
        root.value = 0.0
        best_result: Optional[SearchResult] = None

        for iteration in range(self._mcts_iters):
            node = root
            depth = 0
            while node.is_fully_expanded() and node.children and depth < self._max_edits:
                node = node.best_child(self._c)
                depth += 1

            if node.untried_ops and len(node.edits) < self._max_edits:
                chosen = node.untried_ops.pop()
                new_edits = node.edits + [chosen]
                child = MCTSNode(edits=new_edits, parent=node)
                na, nf = self._apply_edits(self._adj, self._features, new_edits)
                child.pred_score = self._model_predict(na, nf)
                child.untried_ops = self._generate_candidate_edits(na, nf, max_candidates=20)
                node.children.append(child)
                node = child

            ra, rf = self._apply_edits(self._adj, self._features, node.edits)
            reward, _ = self._rollout(ra, rf, self._mcts_depth)

            if node.pred_score < self._threshold:
                tc = sum(e.cost for e in node.edits)
                if best_result is None or tc < best_result.total_cost:
                    best_result = SearchResult(
                        original_pred=original_score,
                        counterfactual_pred=node.pred_score,
                        flip_achieved=True, edits=node.edits,
                        total_cost=tc, search_steps=iteration + 1)

            while node is not None:
                node.visits += 1
                node.value += reward
                node = node.parent

        if best_result is None:
            all_nodes = self._collect_all_nodes(root)
            best_node = min(all_nodes, key=lambda n: n.pred_score) if all_nodes else root
            best_result = SearchResult(
                original_pred=original_score,
                counterfactual_pred=best_node.pred_score,
                flip_achieved=best_node.pred_score < self._threshold,
                edits=best_node.edits,
                total_cost=sum(e.cost for e in best_node.edits),
                search_steps=self._mcts_iters)

        return best_result

    @staticmethod
    def _collect_all_nodes(root: MCTSNode) -> List[MCTSNode]:
        nodes = [root]
        for child in root.children:
            nodes.extend(CounterfactualSearchEngine._collect_all_nodes(child))
        return nodes
