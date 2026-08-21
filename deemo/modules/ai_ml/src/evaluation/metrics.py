# 排序指标核心 -- 所有实现纯numpy，零依赖，简洁风格
# 设计哲学：每个函数独立可测，输入shape自推断，Multi-label原生支持

import numpy as np


def _rank_scores(scores):
# 分数转排名：越大排越前（descending）
    # scores: (N,) 或 (N, C)，返回同shape的rank (1-based)
    _s = np.asarray(scores, dtype=np.float64)
    if _s.ndim == 1:
        _o = np.argsort(-_s)
        _r = np.empty_like(_o, dtype=np.int64)
        _r[_o] = np.arange(1, len(_s) + 1)
        return _r
    # //// 多维：逐行排序
    _r = np.zeros_like(_s, dtype=np.int64)
    for _i in range(_s.shape[0]):
        _o = np.argsort(-_s[_i])
        _r[_i, _o] = np.arange(1, _s.shape[1] + 1)
    return _r


def mrr_score(y_true, y_pred_scores):
    """Mean Reciprocal Rank: 对每个查询，找到首个相关项的排名倒数，取均值。
    y_true: (N,) 整型label 或 (N, C) binary matrix
    y_pred_scores: (N,) 或 (N, C) 每个类的预测分数
    """
    _t = np.asarray(y_true)
    _p = np.asarray(y_pred_scores, dtype=np.float64)

    if _t.ndim == 1:
# 单标签场景
        _ranks = _rank_scores(_p)
        _n = len(_t)
        _rr = np.zeros(_n, dtype=np.float64)
        for _i in range(_n):
            _rel_rank = _ranks[_i][_t[_i] == (_t[_i] if _t.ndim == 1 else None)]
            # 单标签简化：找预测排名最高的那个相关项
            # 实际上单标签场景下，每个query只有一个正确答案
            # 正确定义：按分数排序后，第一个相关项的位置
        # 重新实现：对单label做更精确的MRR
        _rr = np.zeros(_n, dtype=np.float64)
        for _i in range(_n):
            _order = np.argsort(-_p[_i])
            _pos = np.where(_order == _t[_i])[0][0] + 1
            _rr[_i] = 1.0 / _pos
        return float(np.mean(_rr))

    # //// 多标签场景：每行是一个样本的binary 相关性 向量
    _n, _c = _t.shape
    _rr = np.zeros(_n, dtype=np.float64)
    for _i in range(_n):
        _order = np.argsort(-_p[_i])
        _found = False
        for _pos, _idx in enumerate(_order, 1):
            if _t[_i, _idx] > 0:
                _rr[_i] = 1.0 / _pos
                _found = True
                break
        if not _found:
            _rr[_i] = 0.0
    return float(np.mean(_rr[_rr > 0])) if np.any(_rr > 0) else 0.0


def recall_at_k(y_true, y_pred_scores, k=10):
    """Recall@K: top-k中相关项数 / 总相关项数。
    支持 multi-label: y_true shape (N, C)
    """
    _t = np.asarray(y_true)
    _p = np.asarray(y_pred_scores, dtype=np.float64)

    if _t.ndim == 1:
# 单标签：每个query一个正确答案
        _n = len(_t)
        _hits = 0
        for _i in range(_n):
            _topk = np.argpartition(-_p[_i], min(k, len(_p[_i])) - 1)[:k]
            if _t[_i] in _topk:
                _hits += 1
        return float(_hits) / _n if _n > 0 else 0.0

    # //// 多标签：每行多个正类
    _n, _c = _t.shape
    _recalls = np.zeros(_n, dtype=np.float64)
    for _i in range(_n):
        _topk = np.argpartition(-_p[_i], min(k, _c) - 1)[:k]
        _rel_total = int(np.sum(_t[_i]))
        if _rel_total == 0:
            _recalls[_i] = 0.0
            continue
        _rel_retrieved = int(np.sum(_t[_i, _topk]))
        _recalls[_i] = _rel_retrieved / _rel_total
    return float(np.mean(_recalls))


def precision_at_k(y_true, y_pred_scores, k=10):
    """Precision@K: top-k中相关项数 / k"""
    _t = np.asarray(y_true)
    _p = np.asarray(y_pred_scores, dtype=np.float64)

    if _t.ndim == 1:
        _n = len(_t)
        _prec_sum = 0.0
        for _i in range(_n):
            _topk = np.argpartition(-_p[_i], min(k, len(_p[_i])) - 1)[:k]
            _prec_sum += float(np.sum(_t[_i] == _topk)) / k if k > 0 else 0.0
        return _prec_sum / _n if _n > 0 else 0.0

# 多标签
    _n, _c = _t.shape
    _precs = np.zeros(_n, dtype=np.float64)
    for _i in range(_n):
        _topk = np.argpartition(-_p[_i], min(k, _c) - 1)[:k]
        if k > 0:
            _precs[_i] = float(np.sum(_t[_i, _topk])) / k
    return float(np.mean(_precs))


def ndcg_at_k(y_true, y_pred_scores, k=10):
    """Normalized Discounted Cumulative Gain@K.
    DCG = sum_i (2^rel_i - 1) / log2(i+2), i从0开始
    NDCG = DCG / IDCG，其中IDCG用真实相关性降序排列计算
    """
    _t = np.asarray(y_true, dtype=np.float64)
    _p = np.asarray(y_pred_scores, dtype=np.float64)

    _discounts = 1.0 / np.log2(np.arange(2, k + 2))  # i=0 -> log2(2), i=1 -> log2(3)...

    def _dcg(_rels):
        _gains = np.power(2.0, _rels) - 1.0
        return np.sum(_gains * _discounts[:len(_gains)])

    if _t.ndim == 1:
        _n = len(_t)
        _ndcg_vals = np.zeros(_n, dtype=np.float64)
        for _i in range(_n):
            _topk_idx = np.argsort(-_p[_i])[:k]
            _rels_pred = np.zeros(k, dtype=np.float64)
            _rels_ideal_arr = np.zeros(k, dtype=np.float64)
            for _j, _idx in enumerate(_topk_idx):
                _rels_pred[_j] = 1.0 if _t[_i] == _idx else 0.0
            # ideal: 1 at first position
            _rels_ideal_arr[0] = 1.0
            _dcg_val = _dcg(_rels_pred)
            _idcg_val = _dcg(_rels_ideal_arr)
            _ndcg_vals[_i] = _dcg_val / _idcg_val if _idcg_val > 0 else 0.0
        return float(np.mean(_ndcg_vals))

    # //// 多标签 NDCG
    _n, _c = _t.shape
    _ndcg_vals = np.zeros(_n, dtype=np.float64)
    for _i in range(_n):
        _topk_idx = np.argsort(-_p[_i])[:k]
        _actual_k = min(k, _c)
        _rels_pred = np.array([_t[_i, _idx] for _idx in _topk_idx], dtype=np.float64)
        _rels_ideal = -np.sort(-_t[_i])[:_actual_k]  # 降序取top-k真实值
        _disc_used = _discounts[:_actual_k]
        _dcg_val = np.sum((np.power(2.0, _rels_pred) - 1.0) * _disc_used)
        _idcg_val = np.sum((np.power(2.0, _rels_ideal) - 1.0) * _disc_used)
        _ndcg_vals[_i] = _dcg_val / _idcg_val if _idcg_val > 0 else 0.0
    return float(np.mean(_ndcg_vals[_ndcg_vals > 0])) if np.any(_ndcg_vals > 0) else 0.0


def average_precision(y_true, y_pred_scores):
    """Average Precision: AP = sum_k(P@k * rel_k) / total_relevant。
    当无相关项时返回0。
    """
    _t = np.asarray(y_true)
    _p = np.asarray(y_pred_scores, dtype=np.float64)

    if _t.ndim == 1:
        _n = len(_t)
        _ap_sum = 0.0
        for _i in range(_n):
            _order = np.argsort(-_p[_i])
            _hits = 0.0
            _prec_at_k = 0.0
            for _pos, _idx in enumerate(_order, 1):
                if _t[_i] == _idx:
                    _hits += 1.0
                    _prec_at_k += _hits / _pos
            _ap_sum += _prec_at_k / _hits if _hits > 0 else 0.0
        return _ap_sum / _n if _n > 0 else 0.0

# 多标签 AP
    _n, _c = _t.shape
    _ap_sum = 0.0
    for _i in range(_n):
        _rel_total = float(np.sum(_t[_i]))
        if _rel_total == 0:
            continue
        _order = np.argsort(-_p[_i])
        _hits = 0.0
        _prec_sum = 0.0
        for _pos, _idx in enumerate(_order, 1):
            if _t[_i, _idx] > 0:
                _hits += 1.0
                _prec_sum += _hits / _pos
        _ap_sum += _prec_sum / _rel_total
    return _ap_sum / _n if _n > 0 else 0.0
