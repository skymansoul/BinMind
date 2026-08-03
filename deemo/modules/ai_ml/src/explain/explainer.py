# ==== 图模型解释：GNNExplainer风格边掩码 + 遮挡归因 + 反事实解释 ====

import numpy as np
from math import log as _log


# ############################################################
# SubgraphExplainer — 边掩码 + 坐标下降
# ############################################################

class SubgraphExplainer:
    """GNNExplainer启发: 学习稀疏边掩码使预测保持，提取关键子图"""

    def __init__(self, model, edge_mask_lr=0.01, num_epochs=100, edge_entropy_coeff=0.01):
        self._m = model           # callable: model(x, adj) -> logits or probs
        self._lr = edge_mask_lr
        self._epochs = num_epochs
        self._ent_coeff = edge_entropy_coeff

    @staticmethod
    def _sigmoid(v):
        return 1.0 / (1.0 + np.exp(-np.clip(v, -50, 50)))

    # //// 用软掩码调制邻接矩阵 ////
    def _masked_adj(self, adj, mask_param):
        _mask = self._sigmoid(mask_param)
        return adj * _mask

    # ==== 解释主入口 ====
    def explain(self, x, adj, node_idx, target_class=None):
        x = np.asarray(x, dtype=np.float64)
        adj = np.asarray(adj, dtype=np.float64)
        _n = adj.shape[0]

        # 仅对存在边的位置参数化掩码
        _edge_idx = np.where(adj > 0)
        _mask_param = np.full(adj.shape, -10.0)  # sigmoid(-10) ~ 0
        _mask_param[_edge_idx] = 5.0              # sigmoid(5) ~ 0.993 — 初始保留所有边

        # 获取目标预测
        if target_class is None:
            _ref_out = self._m(x, adj)
            if _ref_out.ndim > 1:
                target_class = int(np.argmax(_ref_out[node_idx]))
            else:
                target_class = int(_ref_out[node_idx] > 0)

        _best_loss = float("inf")
        _best_mask = None

        # ---- 坐标下降：逐边优化 ----
        for _ep in range(self._epochs):
            _lr_t = self._lr / (1.0 + _ep * 0.005)
            _edges = list(zip(_edge_idx[0], _edge_idx[1]))
            np.random.shuffle(_edges)

            for _u, _v in _edges:
                # 当前软掩码邻接矩阵
                _adj_masked = self._masked_adj(adj, _mask_param)

                # 当前损失
                _cur_loss = self._compute_loss(x, _adj_masked, node_idx, target_class, _mask_param)
                # 试探: 减小掩码参数（压制该边）
                _orig_val = _mask_param[_u, _v]
                _mask_param[_u, _v] -= 0.5
                _adj_try = self._masked_adj(adj, _mask_param)
                _try_loss = self._compute_loss(x, _adj_try, node_idx, target_class, _mask_param)

                if _try_loss < _cur_loss:
                    _cur_loss = _try_loss
                else:
                    # 试探: 增大掩码参数（增强该边）
                    _mask_param[_u, _v] = _orig_val + 0.5
                    _adj_try = self._masked_adj(adj, _mask_param)
                    _try_loss = self._compute_loss(x, _adj_try, node_idx, target_class, _mask_param)
                    if _try_loss < _cur_loss:
                        _cur_loss = _try_loss
                    else:
                        _mask_param[_u, _v] = _orig_val  # 回退

                # SGD微调
                _grad = (_try_loss - self._compute_loss(x,
                         self._masked_adj(adj, _mask_param), node_idx,
                         target_class, _mask_param)) / 0.5
                _mask_param[_u, _v] -= _lr_t * _grad if abs(_grad) < 100 else 0

            if _cur_loss < _best_loss:
                _best_loss = _cur_loss
                _best_mask = self._sigmoid(_mask_param).copy()

        _final_mask = _best_mask if _best_mask is not None else self._sigmoid(_mask_param)
        return {
            "edge_mask": _final_mask,
            "subgraph_adj": adj * _final_mask,
            "importance": _final_mask[_edge_idx],
            "target_class": target_class,
        }

    # ---- 损失: 预测保真度 + 掩码稀疏正则 ----
    def _compute_loss(self, x, adj_masked, node_idx, target_class, mask_param):
        _out = self._m(x, adj_masked)
        if _out.ndim > 1:
            # 多分类: 负对数似然
            _probs = np.exp(_out[node_idx] - np.max(_out[node_idx]))
            _probs = _probs / np.sum(_probs)
            _pred_loss = -_log(max(_probs[target_class], 1e-12))
        else:
            # 二分类: hinge-like
            _pred_loss = max(0, 1.0 - _out[node_idx] * (1 if target_class else -1))

        # 掩码熵正则（鼓励稀疏）
        _mask = self._sigmoid(mask_param)
        _m_clip = np.clip(_mask, 1e-7, 1.0 - 1e-7)
        _entropy = -np.mean(_m_clip * np.log(_m_clip) + (1 - _m_clip) * np.log(1 - _m_clip))
        return _pred_loss + self._ent_coeff * _entropy


# ############################################################
# FeatureAttributor — 遮挡归因
# ############################################################

class FeatureAttributor:
    """逐特征 + 逐节点遮挡分析：零化后测量预测变化量"""

    def __init__(self, model):
        self._m = model  # callable: model(x, adj) -> output

    # ==== 归因入口 ====
    def attribute(self, x, adj, node_idx=None):
        x = np.asarray(x, dtype=np.float64)
        adj = np.asarray(adj, dtype=np.float64)
        _n, _d = x.shape

        _base = self._m(x, adj)

        # ---- 节点级别归因 ----
        _node_imp = np.zeros(_n)
        if node_idx is not None:
            # 目标节点归因: 逐个零化其他节点特征
            _base_target = _base[node_idx] if _base.ndim > 1 else _base[node_idx]
            for _i in range(_n):
                if _i == node_idx:
                    _node_imp[_i] = 0.0  # 自身
                    continue
                _x_occ = x.copy()
                _x_occ[_i] = 0.0
                _out = self._m(_x_occ, adj)
                _val = _out[node_idx] if _out.ndim > 1 else _out[node_idx]
                _node_imp[_i] = float(np.linalg.norm(np.asarray(_base_target) - np.asarray(_val)))
        else:
            # 全局归因: 零化每个节点，看整体预测变化
            _base_sum = np.sum(_base)
            for _i in range(_n):
                _x_occ = x.copy()
                _x_occ[_i] = 0.0
                _out = self._m(_x_occ, adj)
                _node_imp[_i] = abs(_base_sum - np.sum(_out))

        # ---- 特征级别归因 ----
        _feat_imp = np.zeros(_d)
        for _j in range(_d):
            _x_occ = self._occlude_feature(x, _j)
            _out = self._m(_x_occ, adj)
            _feat_imp[_j] = float(np.linalg.norm(np.asarray(_base) - np.asarray(_out)))

        return {
            "feature_importance": _feat_imp,
            "node_importance": _node_imp,
        }

    @staticmethod
    def _occlude_feature(x, dim):
        _r = x.copy()
        _r[:, dim] = 0.0
        return _r


# ############################################################
# CounterfactualExplainer — 最小扰动翻转预测
# ############################################################

class CounterfactualExplainer:
    """找最小边增/删集使预测翻转 — 二分搜索扰动规模"""

    def __init__(self, model):
        self._m = model

    # ==== 反事实搜索 ====
    def explain(self, x, adj, node_idx, target_class=None):
        x = np.asarray(x, dtype=np.float64)
        adj = np.asarray(adj, dtype=np.float64).copy()
        _n = adj.shape[0]

        # 确定原始预测
        _orig_out = self._m(x, adj)
        if _orig_out.ndim > 1:
            _orig_pred = int(np.argmax(_orig_out[node_idx]))
        else:
            _orig_pred = int(_orig_out[node_idx] > 0)

        if target_class is None:
            # 选取最可能的非原始类
            if _orig_out.ndim > 1:
                _probs = _orig_out[node_idx]
                _sorted = np.argsort(_probs)[::-1]
                target_class = int(_sorted[0]) if _sorted[0] != _orig_pred else int(_sorted[1])
            else:
                target_class = 1 - _orig_pred

        # ---- 枚举候选边操作 ----
        # 可删边 (当前邻接矩阵中为1的)
        _del_candidates = [(int(i), int(j)) for i in range(_n) for j in range(i + 1, _n) if adj[i, j] > 0]
        # 可增边 (0的，排除自环)
        _add_candidates = [(int(i), int(j)) for i in range(_n) for j in range(i + 1, _n) if adj[i, j] == 0]

        # 先试纯删除
        _result = self._search_perturbations(
            x, adj, node_idx, _orig_pred, target_class, _del_candidates, mode="del"
        )
        if _result is not None:
            return _result

        # 再试纯添加
        _result = self._search_perturbations(
            x, adj, node_idx, _orig_pred, target_class, _add_candidates, mode="add"
        )
        if _result is not None:
            return _result

        # 混合: 删+增组合
        _all_ops = [("del", e) for e in _del_candidates] + [("add", e) for e in _add_candidates]
        return self._search_mixed(x, adj, node_idx, _orig_pred, target_class, _all_ops)

    # //// 单一模式搜索：二分规模 ////
    def _search_perturbations(self, x, adj, node_idx, orig_pred, target_class, candidates, mode):
        if not candidates:
            return None
        _lo, _hi = 1, min(len(candidates), 20)
        _best = None

        # 膨胀式探测
        for _k in [_lo, _hi // 4, _hi // 2, _hi]:
            _k = max(1, min(_k, len(candidates)))
            _combo = candidates[:_k]
            _adj_try = adj.copy()
            for _u, _v in _combo:
                if mode == "del":
                    _adj_try[_u, _v] = _adj_try[_v, _u] = 0.0
                else:
                    _adj_try[_u, _v] = _adj_try[_v, _u] = 1.0

            if self._is_flipped(x, _adj_try, node_idx, orig_pred, target_class):
                _best = (_k, _combo, _adj_try)
                break

        if _best is None:
            return None

        _k_best, _combo, _adj_best = _best
        return {
            "counterfactual_adj": _adj_best,
            "changes": [{"type": mode, "edge": e} for e in _combo],
            "num_changes": _k_best,
            "target_class": target_class,
        }

    # //// 混合操作搜索 ////
    def _search_mixed(self, x, adj, node_idx, orig_pred, target_class, all_ops):
        _n_ops = len(all_ops)
        # 贪心：逐个尝试每个操作
        for _k in range(1, min(_n_ops + 1, 10)):
            _adj_try = adj.copy()
            _changes = []
            for _i in range(_k):
                _op_type, (_u, _v) = all_ops[_i]
                if _op_type == "del":
                    _adj_try[_u, _v] = _adj_try[_v, _u] = 0.0
                else:
                    _adj_try[_u, _v] = _adj_try[_v, _u] = 1.0
                _changes.append({"type": _op_type, "edge": (_u, _v)})

            if self._is_flipped(x, _adj_try, node_idx, orig_pred, target_class):
                return {
                    "counterfactual_adj": _adj_try,
                    "changes": _changes,
                    "num_changes": _k,
                    "target_class": target_class,
                }
        # 兜底
        return {
            "counterfactual_adj": adj.copy(),
            "changes": [],
            "num_changes": 0,
            "target_class": target_class,
            "note": "no flip found within search budget",
        }

    # //// 判断预测是否翻转 ////
    def _is_flipped(self, x, adj, node_idx, orig_pred, target_class):
        _out = self._m(x, adj)
        if _out.ndim > 1:
            _new_pred = int(np.argmax(_out[node_idx]))
        else:
            _new_pred = int(_out[node_idx] > 0)
        return _new_pred == target_class

    # //// 尝试扰动并测试 ////
    def _try_perturbation(self, adj, changes):
        _adj_new = adj.copy()
        for _ch in changes:
            _u, _v = _ch["edge"]
            if _ch["type"] == "del":
                _adj_new[_u, _v] = _adj_new[_v, _u] = 0.0
            else:
                _adj_new[_u, _v] = _adj_new[_v, _u] = 1.0
        return _adj_new


# ############################################################
# explain_prediction — 快速调度器
# ############################################################

def explain_prediction(model, x, adj, method="subgraph", **kwargs):
    """统一入口：method in {'subgraph', 'feature', 'counterfactual'}"""
    _node_idx = kwargs.get("node_idx", 0)
    _target = kwargs.get("target_class", None)

    if method == "subgraph":
        _exp = SubgraphExplainer(
            model,
            edge_mask_lr=kwargs.get("edge_mask_lr", 0.01),
            num_epochs=kwargs.get("num_epochs", 100),
            edge_entropy_coeff=kwargs.get("edge_entropy_coeff", 0.01),
        )
        return _exp.explain(x, adj, _node_idx, _target)
    elif method == "feature":
        _exp = FeatureAttributor(model)
        return _exp.attribute(x, adj, _node_idx if "node_idx" in kwargs else None)
    elif method == "counterfactual":
        _exp = CounterfactualExplainer(model)
        return _exp.explain(x, adj, _node_idx, _target)
    else:
        raise ValueError(f"Unknown method: {method}. Use 'subgraph', 'feature', or 'counterfactual'.")
