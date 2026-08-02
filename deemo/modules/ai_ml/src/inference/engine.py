# 2026-07-18
# 推理引擎 —— LRU缓存 + 多任务推理 + Platt/Temperature校准
# 战略设计：模型注册表驱动路由，特征提取就地流水线，缓存减少重复encode开销

import time
import hashlib
import struct
from collections import OrderedDict
import numpy as np


# ==================== 特征提取辅助 ====================

def _extract_features_from_bytes(data):
    """从二进制字节中提取轻量特征：byte直方图 + 可打印字符串统计"""
    _h = np.zeros(256, dtype=np.float64)  # byte histogram
    _str_len = 0
    _str_count = 0
    _current = []

    for _b in data:
        _h[_b] += 1
        if 0x20 <= _b < 0x7f:
            _current.append(chr(_b))
        else:
            if len(_current) >= 4:
                _str_len += len(_current)
                _str_count += 1
            _current = []

    # //// 尾部残留字符串
    if len(_current) >= 4:
        _str_len += len(_current)
        _str_count += 1

    _total = max(len(data), 1)
    _h = _h / _total  # 归一化

    return {
        "byte_hist": _h,
        "num_strings": _str_count,
        "avg_string_len": _str_len / max(_str_count, 1),
        "size": len(data),
    }


# ==================== LRU 嵌入缓存 ====================

class LRUEmbeddingCache:
    """LRU缓存 + TTL过期，用于embedding结果缓存。
    最大条目数max_size，超时秒数ttl。
    """

    def __init__(self, max_size=10000, ttl=3600):
        self._m = max_size
        self._ttl = ttl
        self._store = OrderedDict()   # key -> (value, timestamp)

    def _evict_lru(self):
        # ---- 驱逐最久未访问的条目（OrderedDict头部） ----
        if self._store:
            self._store.popitem(last=False)

    def _make_key(self, key):
        # key规范化：bytes -> hex digest，其他用repr
        if isinstance(key, bytes):
            return hashlib.sha256(key).hexdigest()
        return hashlib.sha256(repr(key).encode()).hexdigest()

    def get(self, key):
        """获取缓存值，过期返回None"""
        _k = self._make_key(key)
        if _k not in self._store:
            return None
        _val, _ts = self._store[_k]
        # ===== TTL 检查 =====
        if time.time() - _ts > self._ttl:
            del self._store[_k]
            return None
        # 访问后移到末尾（标记为最近使用）
        self._store.move_to_end(_k)
        return _val

    def put(self, key, value):
        """插入缓存，超过max_size时驱逐LRU"""
        _k = self._make_key(key)
        # 如果key已存在，先删除再插入（更新位置）
        if _k in self._store:
            del self._store[_k]
        elif len(self._store) >= self._m:
            self._evict_lru()
        self._store[_k] = (value, time.time())


# ==================== Platt / Temperature 校准 ====================

def platt_scaling(scores, labels, num_bins=10):
    """Platt Scaling: 用sigmoid calibrate scores -> probabilities.
    scores: (N,) raw scores
    labels: (N,) binary {0,1}
    返回 (A, B): P(y=1|s) = 1 / (1 + exp(A*s + B))
    """
    _s = np.asarray(scores, dtype=np.float64)
    _l = np.asarray(labels, dtype=np.float64)
    _n = len(_s)

    if _n == 0:
        return 0.0, 0.0

    # //// Binning + EM-style fitting
    # 分箱计算每个bin内正样本比例
    _min_s, _max_s = np.min(_s), np.max(_s)
    if _min_s == _max_s:
        return 0.0, -np.log((np.sum(_l) + 0.5) / (_n + 1.0)) if np.sum(_l) > 0 else 0.0

    _bins = np.linspace(_min_s - 1e-9, _max_s + 1e-9, num_bins + 1)
    _bin_idx = np.digitize(_s, _bins) - 1
    _bin_idx = np.clip(_bin_idx, 0, num_bins - 1)

    _bin_prior = np.zeros(num_bins, dtype=np.float64)
    _bin_count = np.zeros(num_bins, dtype=np.float64)

    for _i in range(_n):
        _b = _bin_idx[_i]
        _bin_count[_b] += 1.0
        if _l[_i] > 0:
            _bin_prior[_b] += 1.0

    # Laplace smoothing
    _bin_prior = (_bin_prior + 0.5) / (_bin_count + 1.0)
    _bin_centers = (_bins[:-1] + _bins[1:]) / 2.0

    # 仅用有样本的bin拟合
    _valid = _bin_count > 0
    if np.sum(_valid) < 2:
        # 退化情况：直接用全量
        _pos_ratio = max(np.sum(_l) / _n, 1e-9)
        return 0.0, -np.log(_pos_ratio / (1.0 - _pos_ratio))

    _sc = _bin_centers[_valid]
    _pr = np.clip(_bin_prior[_valid], 1e-9, 1.0 - 1e-9)

    # ---- 对数几率线性回归: log(p/(1-p)) = -(A*s + B) ----
    _y = -np.log(_pr / (1.0 - _pr))
    # fit y = A * _sc + B via least squares
    _X = np.column_stack([_sc, np.ones(len(_sc))])
    _coeff, _residuals, _rank, _sv = np.linalg.lstsq(_X, _y, rcond=None)
    _A, _B = _coeff[0], _coeff[1]

    return float(_A), float(_B)


def temperature_scaling(logits, labels):
    """Temperature Scaling: 找最优T最小化 NLL。
    logits: (N, C) 或 (N,) raw logits
    labels: (N,) integer labels
    返回最优温度 T。
    网格搜索 log-spaced [0.01, 10.0]
    """
    _logits = np.asarray(logits, dtype=np.float64)
    _lbls = np.asarray(labels, dtype=np.int64)

    if _logits.ndim == 1:
        _logits = np.column_stack([-_logits, _logits])

    _n, _c = _logits.shape
    if _n == 0:
        return 1.0

    # ===== 网格搜索：log-spaced 50点 =====
    _Ts = np.logspace(-2, 1, 50)  # 0.01 .. 10.0
    _best_T = 1.0
    _best_nll = float("inf")

    for _T in _Ts:
        _scaled = _logits / _T
        _scaled -= np.max(_scaled, axis=1, keepdims=True)  # 数值稳定
        _exp = np.exp(_scaled)
        _probs = _exp / np.sum(_exp, axis=1, keepdims=True)

        _nll = 0.0
        for _i in range(_n):
            _p = max(_probs[_i, _lbls[_i]], 1e-15)
            _nll -= np.log(_p)
        _nll /= _n

        if _nll < _best_nll:
            _best_nll = _nll
            _best_T = _T

    return float(_best_T)


# ==================== 推理引擎 ====================

class InferenceEngine:
    """多任务推理引擎。model_registry = {"classifier": ..., "detector": ..., "matcher": ...}
    支持单样本和批量推理，内建特征缓存。
    """

    def __init__(self, model_registry):
        self._models = model_registry
        self._cache = LRUEmbeddingCache(max_size=5000, ttl=1800)
        # //// 校验必要模型是否存在
        for _task in ("classifier", "detector", "matcher"):
            if _task not in self._models:
                self._models[_task] = None

    def _preprocess(self, binary_data):
        """特征提取流水线：byte直方图 + 字符串统计 -> 特征dict"""
        _feat = _extract_features_from_bytes(binary_data)
        # ---- 追加熵估计 ----
        _h = _feat["byte_hist"]
        _entropy = 0.0
        for _v in _h:
            if _v > 0:
                _entropy -= _v * np.log2(_v)
        _feat["entropy"] = _entropy
        return _feat

    def _build_graph(self, features):
        """从特征构建图结构特征 (node features, adjacency)。
        返回 (x, adj) 或 (x, None) 若无需图结构。
        """
        _h = features.get("byte_hist", np.zeros(256))
        # ===== 简化CFG模拟：byte transition matrix作为adjacency =====
        # 在实际使用中会从CFG解析得到，这里用单位阵做fallback
        _x = _h.reshape(1, -1).astype(np.float64)
        _adj = np.eye(1, dtype=np.float64)
        return _x, _adj

    def encode(self, binary_data):
        """获取样本的embedding向量（通过matcher模型）"""
        _cached = self._cache.get(binary_data)
        if _cached is not None:
            return _cached

        _model = self._models.get("matcher")
        if _model is None:
            # //// 无matcher模型时用特征直方图作为embedding
            _feat = self._preprocess(binary_data)
            _emb = _feat["byte_hist"].copy()
        else:
            _feat = self._preprocess(binary_data)
            _x, _adj = self._build_graph(_feat)
            try:
                _emb = _model.encode(_x, _adj)
            except (AttributeError, TypeError):
                _emb = _model(_x) if hasattr(_model, '__call__') else _feat["byte_hist"]

        _result = np.asarray(_emb, dtype=np.float64).flatten()
        self._cache.put(binary_data, _result)
        return _result

    def encode_batch(self, data_list):
        """批量编码，利用缓存减少重复计算"""
        _results = []
        for _d in data_list:
            _results.append(self.encode(_d))
        return _results

    def predict(self, binary_data, task="classifier"):
        """单样本推理。task: classifier/detector/matcher"""
        _model = self._models.get(task)
        if _model is None:
            return {"task": task, "error": f"Model for '{task}' not registered"}

        _feat = self._preprocess(binary_data)

        # ===== 任务路由 =====
        if task == "classifier":
            _x, _adj = self._build_graph(_feat)
            try:
                _pred = _model.predict(_x, _adj)
            except (AttributeError, TypeError):
                _pred = _model(_x) if hasattr(_model, '__call__') else np.zeros(1)
            _result = np.asarray(_pred).flatten()
            return {
                "task": task,
                "prediction": _result.tolist(),
                "label": int(np.argmax(_result)) if len(_result) > 1 else int(_result[0] > 0.5),
                "confidence": float(np.max(_result)) if len(_result) > 0 else 0.0,
            }

        elif task == "detector":
            _x, _adj = self._build_graph(_feat)
            try:
                _pred = _model.detect(_x, _adj)
            except (AttributeError, TypeError):
                _pred = _model(_x) if hasattr(_model, '__call__') else np.array([0.0])
            _result = np.asarray(_pred).flatten()
            # //// 检测结果：分数 + 二元判定
            _threshold = getattr(_model, "threshold", 0.5)
            return {
                "task": task,
                "score": float(_result[0]) if len(_result) > 0 else 0.0,
                "is_malicious": bool(_result[0] > _threshold) if len(_result) > 0 else False,
                "raw": _result.tolist(),
            }

        elif task == "matcher":
            _emb = self.encode(binary_data)
            return {
                "task": task,
                "embedding": _emb.tolist(),
                "embedding_shape": list(_emb.shape),
            }

        else:
            return {"task": task, "error": f"Unknown task: {task}"}

    def predict_batch(self, data_list, task="classifier"):
        """批量推理，返回list of dicts"""
        return [self.predict(_d, task=task) for _d in data_list]
