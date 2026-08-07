# active/sampler.py
# 主动学习采样策略：不确定性、委员会投票、多样性采样
# 设计权衡：保留原始概率分布的面貌，不在query阶段修改probs

import numpy as np
from collections import Counter

# UncertaintySampler
# 基于单个模型的预测不确定性选样
# entropy适合类别多且分布均匀的场景，margin适合二分类边界模糊的情况
# least_confidence最简单但可能忽略次要类别的信息

class UncertaintySampler:
    def __init__(self, strategy='entropy'):
        _valid = {'entropy', 'margin', 'least_confidence'}
        if strategy not in _valid:
            raise ValueError(f"无效策略: {strategy}, 支持: {_valid}")
        self._s = strategy

    def query(self, probs, n=10):
        """probs: (n_samples, n_classes), 返回不确定度最高的n个样本索引"""
        if self._s == 'entropy':
            _h = self._entropy(probs)
            _idx = np.argsort(_h)[::-1][:n]
        elif self._s == 'margin':
            _sorted = np.sort(probs, axis=1)
            _m = 1.0 - (_sorted[:, -1] - _sorted[:, -2])
            _idx = np.argsort(_m)[:n]  # 边界越小越不确定
        elif self._s == 'least_confidence':
            _lc = 1.0 - np.max(probs, axis=1)
            _idx = np.argsort(_lc)[::-1][:n]
        else:
            _idx = np.arange(n)
        return np.asarray(_idx)

    # ////
    @staticmethod
    def _entropy(probs):
        _eps = 1e-12
        _p = np.clip(probs, _eps, 1.0 - _eps)
        return -np.sum(_p * np.log(_p), axis=1)

    def query_class_balanced(self, probs, labels, n=10):
        """按类别比例平衡采样，每类选最不确定的，避免偏移"""
        _n_classes = probs.shape[1]
        _uncertainty = self._entropy(probs) if self._s == 'entropy' else (
            1.0 - np.max(probs, axis=1))
        _labels = np.asarray(labels)
        _per_class = max(1, n // _n_classes)
        _selected = []
        _class_counts = Counter(_labels)
        # 根据各类占比分配配额，保证少数类至少1个
        _total = len(labels)
        for _c in range(_n_classes):
            _mask = _labels == _c
            _c_indices = np.where(_mask)[0]
            if len(_c_indices) == 0:
                continue
            _quota = max(1, int(n * _class_counts.get(_c, 0) / _total + 0.5))
            _quota = min(_quota, len(_c_indices))
            _c_uncertain = _uncertainty[_c_indices]
            _top_n = np.argsort(_c_uncertain)[::-1][:_quota]
            _selected.extend(_c_indices[_top_n].tolist())
        # 如果有余量，用全局不确定度补
        _remaining = n - len(_selected)
        if _remaining > 0:
            _used = set(_selected)
            _rest = [i for i in np.argsort(_uncertainty)[::-1] if i not in _used]
            _selected.extend(_rest[:_remaining])
        return np.asarray(_selected[:n])


# CommitteeSampler
# 多模型委员会投票，用模型间分歧衡量不确定度
# vote_entropy：直接计算投票分布的熵，计算量小
# kl_divergence：衡量每个成员与共识的KL散度，对方向性分歧敏感

class CommitteeSampler:
    def __init__(self, models, strategy='vote_entropy'):
        if not models or len(models) < 2:
            raise ValueError("委员会至少需要2个模型")
        _valid = {'vote_entropy', 'kl_divergence'}
        if strategy not in _valid:
            raise ValueError(f"无效策略: {strategy}")
        self._models = models
        self._s = strategy

    def _committee_probas(self, X):
        """(n_models, n_samples, n_classes)"""
        _all = [m.predict_proba(X) if hasattr(m, 'predict_proba') else m(X)
                for m in self._models]
        return np.stack(_all, axis=0)

    # ////
    def _vote_entropy(self, _votes):
        """_votes: (n_models, n_samples, n_classes)"""
        _n_models = _votes.shape[0]
        _avg = np.mean(_votes, axis=0)
        _eps = 1e-12
        _avg = np.clip(_avg, _eps, 1 - _eps)
        return -np.sum(_avg * np.log(_avg), axis=1)

    def query(self, X, n=10):
        """X: 特征矩阵, 返回分歧最大的n个样本索引"""
        _v = self._committee_probas(X)
        if self._s == 'vote_entropy':
            _scores = self._vote_entropy(_v)
            _idx = np.argsort(_scores)[::-1][:n]
        elif self._s == 'kl_divergence':
            _eps = 1e-12
            _avg = np.mean(_v, axis=0)
            _avg = np.clip(_avg, _eps, 1 - _eps)
            _kl_all = np.zeros(_v.shape[1])
            for _m in range(_v.shape[0]):
                _p = np.clip(_v[_m], _eps, 1 - _eps)
                _kl_all += np.sum(_p * (np.log(_p) - np.log(_avg)), axis=1)
            _scores = _kl_all / _v.shape[0]
            _idx = np.argsort(_scores)[::-1][:n]
        return np.asarray(_idx)


# DiversitySampler
# 多样性采样：避免选到信息冗余的相近样本
# kmeans_pp：概率正比于到已选集合的最小距离平方，理论保证O(log k)近似
# farthest_first：贪心选最远点，确定性更强但可能被离群点劫持

class DiversitySampler:
    def __init__(self, strategy='kmeans_pp'):
        _valid = {'kmeans_pp', 'farthest_first'}
        if strategy not in _valid:
            raise ValueError(f"无效策略: {strategy}, 支持: {_valid}")
        self._s = strategy

    def query(self, X, n=10, seed_indices=None):
        """X_emb: 嵌入/特征矩阵, 返回n个最具多样性的索引"""
        _x = np.asarray(X, dtype=np.float64)
        if seed_indices is not None and len(seed_indices) > 0:
            _selected = list(seed_indices)
        else:
            # 随机选第一个
            _selected = [np.random.randint(0, len(_x))]
        if self._s == 'kmeans_pp':
            _result = self._kmeans_plus_plus(_x, n, _selected)
        else:  # farthest_first
            _result = self._farthest_first(_x, n, _selected)
        return np.asarray(_result)

    # ////
    def _kmeans_plus_plus(self, _x, n, _selected):
        _n_samples = len(_x)
        _selected = list(_selected)
        # 空种子集：随机初始化第一个点
        if not _selected:
            _selected.append(np.random.randint(0, _n_samples))
        while len(_selected) < n:
            # 每个点到最近已选点的最小平方距离
            _d2 = np.full(_n_samples, np.inf)
            for _s in _selected:
                _dist = np.sum((_x - _x[_s]) ** 2, axis=1)
                _d2 = np.minimum(_d2, _dist)
            _total = _d2.sum()
            if _total < 1e-15:
                # 剩余点全重合，均匀随机选
                _probs = np.ones(_n_samples) / _n_samples
            else:
                _probs = _d2 / _total
            # NaN安全：替换非法值为均匀分布
            _nan_mask = ~np.isfinite(_probs)
            if _nan_mask.any():
                _probs[_nan_mask] = 1.0 / _n_samples
                _probs /= _probs.sum()
            _new = np.random.choice(_n_samples, p=_probs)
            _selected.append(_new)
        return _selected

    def _farthest_first(self, _x, n, _selected):
        _n_samples = len(_x)
        _selected = list(_selected)
        _remaining = set(range(_n_samples)) - set(_selected)
        while len(_selected) < n and _remaining:
            _best_d = -1.0
            _best_i = None
            for _i in _remaining:
                _min_d = min(np.sum((_x[_i] - _x[_s]) ** 2) for _s in _selected)
                if _min_d > _best_d:
                    _best_d = _min_d
                    _best_i = _i
            _selected.append(_best_i)
            _remaining.discard(_best_i)
        return _selected


# combined_query
# alpha混合：不确定性 + 多样性线性加权
# alpha=0.5 两者等权，alpha>0.5偏向不确定度，alpha<0.5偏向多样性
# 用z-score标准化后合并，避免量纲差异

def combined_query(probs, X_emb, models, n=10, alpha=0.5):
    """alpha=0.5: 等权混合; probs和X_emb应对应同一样本集"""
    _us = UncertaintySampler('entropy')
    _ds = DiversitySampler('kmeans_pp')

    _x = np.asarray(X_emb, dtype=np.float64)
    # 确保probs和X_emb维度一致，取较小者
    _n = min(len(probs), len(_x))
    _p = probs[:_n] if len(probs) > _n else probs
    _x = _x[:_n] if len(_x) > _n else _x

    # 不确定度评分 (entropy)
    _u_scores = _us._entropy(_p)
    # 多样性评分: k-means++初始化序列，前n*3个点
    _d_scores = _ds._kmeans_plus_plus(_x, min(n * 3, _n), [])

    # 多样性分: 被选中的顺序越靠前（越具多样性）得分越高
    _d_arr = np.zeros(_n)
    for _i, _rank in enumerate(_d_scores):
        if _rank < _n:
            _d_arr[_rank] = 1.0 - _i / max(1, len(_d_scores))

    # min-max标准化到[0,1]
    _u_norm = (_u_scores - _u_scores.min()) / (_u_scores.max() - _u_scores.min() + 1e-12)
    _d_norm = (_d_arr - _d_arr.min()) / (_d_arr.max() - _d_arr.min() + 1e-12)

    _combined = alpha * _u_norm + (1.0 - alpha) * _d_norm

    # tie-breaking: 分数相同时按索引升序
    _order = np.lexsort((np.arange(len(_combined)), -_combined))
    _idx = _order[:n]
    return np.asarray(_idx)
