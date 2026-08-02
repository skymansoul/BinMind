# 2026-07-19
# ==== 异常检测引擎：VAE重构 + 孤立森林 + OC-SVM（纯numpy，零依赖sklearn） ====

import numpy as np
from math import log as _log, sqrt as _sqrt


# ############################################################
# BinaryFuncVAE — Beta-VAE for binary function embeddings
# ############################################################

class BinaryFuncVAE:
    """Beta-VAE: 3层encoder/decoder，均纯numpy前向 + Xavier初始化"""

    def __init__(self, input_dim=12, hidden_dims=None, latent_dim=8, beta=4.0):
        if hidden_dims is None:
            hidden_dims = [32, 16]
        self._d = input_dim
        self._h = hidden_dims
        self._z = latent_dim
        self._b = beta

        # ---- 构建层维度链 ----
        _enc_dims = [self._d] + self._h + [self._z]
        _dec_dims = [self._z] + list(reversed(self._h)) + [self._d]

        self._enc_w = {}
        self._enc_b = {}
        self._dec_w = {}
        self._dec_b = {}

        for _i in range(len(_enc_dims) - 1):
            _w, _bias = self._init_weights([_enc_dims[_i], _enc_dims[_i + 1]])
            self._enc_w[_i] = _w
            self._enc_b[_i] = _bias

        # 最后一层encoder输出mu和logvar各一份
        _last_w_mu, _last_b_mu = self._init_weights([_enc_dims[-2], self._z])
        _last_w_lv, _last_b_lv = self._init_weights([_enc_dims[-2], self._z])
        _idx_last = len(_enc_dims) - 2
        self._enc_w[_idx_last] = _last_w_mu
        self._enc_b[_idx_last] = _last_b_mu
        # logvar分支: 复用bias索引，单独存w
        self._enc_w_lv = _last_w_lv
        self._enc_b_lv = _last_b_lv

        # decoder
        for _j in range(len(_dec_dims) - 1):
            _w, _bias = self._init_weights([_dec_dims[_j], _dec_dims[_j + 1]])
            self._dec_w[_j] = _w
            self._dec_b[_j] = _bias

    # //// 权重初始化：Xavier uniform ////
    @staticmethod
    def _init_weights(dims):
        _fan_in, _fan_out = dims[0], dims[1]
        _limit = _sqrt(6.0 / (_fan_in + _fan_out))
        _w = np.random.uniform(-_limit, _limit, (_fan_in, _fan_out))
        _b = np.zeros(_fan_out)
        return _w, _b

    @staticmethod
    def _relu(x):
        return np.maximum(0, x)

    @staticmethod
    def _sigmoid(x):
        # clip防溢出
        return 1.0 / (1.0 + np.exp(-np.clip(x, -50, 50)))

    # ==== Encoder: x -> mu, logvar ====
    def encode(self, x):
        _h = x  # (N, input_dim)
        _enc_layers = len(self._h) + 1  # hidden + output layer
        for _i in range(_enc_layers - 1):
            _h = self._relu(np.dot(_h, self._enc_w[_i]) + self._enc_b[_i])
        # 最后一层分叉
        _mu = np.dot(_h, self._enc_w[_enc_layers - 1]) + self._enc_b[_enc_layers - 1]
        _logvar = np.dot(_h, self._enc_w_lv) + self._enc_b_lv
        return _mu, _logvar

    # ==== Decoder: z -> x_recon ====
    def decode(self, z):
        _h = z
        _n_layers = len(self._dec_w)
        for _j in range(_n_layers - 1):
            _h = self._relu(np.dot(_h, self._dec_w[_j]) + self._dec_b[_j])
        # 输出层用sigmoid（假设输入归一化到[0,1]）
        _h = self._sigmoid(np.dot(_h, self._dec_w[_n_layers - 1]) + self._dec_b[_n_layers - 1])
        return _h

    # ==== Reparameterization trick ====
    @staticmethod
    def _reparam(mu, logvar):
        _eps = np.random.randn(*mu.shape)
        return mu + _eps * np.exp(0.5 * logvar)

    # ==== 完整前向 ====
    def forward(self, x):
        _mu, _logvar = self.encode(x)
        _z = self._reparam(_mu, _logvar)
        _x_recon = self.decode(_z)
        return _x_recon, _mu, _logvar

    # ==== Beta-VAE损失 ====
    def loss(self, x):
        _x_recon, _mu, _logvar = self.forward(x)
        # MSE重建损失
        _mse = np.mean(np.square(x - _x_recon))
        # KL散度: -0.5 * sum(1 + logvar - mu^2 - exp(logvar))
        _kl = -0.5 * np.sum(1 + _logvar - np.square(_mu) - np.exp(_logvar), axis=1)
        _kl = np.mean(_kl)
        return _mse + self._b * _kl

    # ==== 简易SGD训练一步 ====
    def train_step(self, x, lr=0.001):
        """单步梯度下降（数值梯度近似，兼容numpy-only）"""
        # 用有限差分做梯度估计 — 生产环境可替换为autograd
        _eps = 1e-5
        _loss0 = self.loss(x)
        _grads = {}

        def _perturb_and_grad(w_dict, b_dict, prefix_w, prefix_b):
            _g = {}
            for _k in w_dict:
                _w_orig = w_dict[_k].copy()
                _flat = _w_orig.ravel()
                _g_flat = np.zeros_like(_flat)
                for _t in range(len(_flat)):
                    _flat[_t] += _eps
                    w_dict[_k] = _flat.reshape(_w_orig.shape)
                    _lp = self.loss(x)
                    _flat[_t] -= 2 * _eps
                    w_dict[_k] = _flat.reshape(_w_orig.shape)
                    _ln = self.loss(x)
                    _g_flat[_t] = (_lp - _ln) / (2 * _eps)
                    _flat[_t] += _eps  # 恢复
                w_dict[_k] = _w_orig
                _g[f"{prefix_w}{_k}"] = _g_flat.reshape(_w_orig.shape)
            for _k in b_dict:
                _b_orig = b_dict[_k].copy()
                _g_b = np.zeros_like(_b_orig)
                for _t in range(len(_b_orig)):
                    _b_orig[_t] += _eps
                    b_dict[_k] = _b_orig
                    _lp = self.loss(x)
                    _b_orig[_t] -= 2 * _eps
                    b_dict[_k] = _b_orig
                    _ln = self.loss(x)
                    _g_b[_t] = (_lp - _ln) / (2 * _eps)
                    _b_orig[_t] += _eps
                b_dict[_k] = _b_orig
                _g[f"{prefix_b}{_k}"] = _g_b
            return _g

        # 收集encoder梯度
        _grads.update(_perturb_and_grad(self._enc_w, self._enc_b, "ew", "eb"))
        # logvar分支
        _w_lv_orig = self._enc_w_lv.copy()
        _b_lv_orig = self._enc_b_lv.copy()
        # gradient for _enc_w_lv
        _flat_w = _w_lv_orig.ravel()
        _g_wlv = np.zeros_like(_flat_w)
        for _t in range(len(_flat_w)):
            _flat_w[_t] += _eps
            self._enc_w_lv = _flat_w.reshape(_w_lv_orig.shape)
            _lp = self.loss(x)
            _flat_w[_t] -= 2 * _eps
            self._enc_w_lv = _flat_w.reshape(_w_lv_orig.shape)
            _ln = self.loss(x)
            _g_wlv[_t] = (_lp - _ln) / (2 * _eps)
            _flat_w[_t] += _eps
        self._enc_w_lv = _w_lv_orig
        # gradient for _enc_b_lv
        _g_blv = np.zeros_like(_b_lv_orig)
        for _t in range(len(_b_lv_orig)):
            _b_lv_orig[_t] += _eps
            self._enc_b_lv = _b_lv_orig
            _lp = self.loss(x)
            _b_lv_orig[_t] -= 2 * _eps
            self._enc_b_lv = _b_lv_orig
            _ln = self.loss(x)
            _g_blv[_t] = (_lp - _ln) / (2 * _eps)
            _b_lv_orig[_t] += _eps
        self._enc_b_lv = _b_lv_orig
        _grads["ew_lv"] = _g_wlv.reshape(_w_lv_orig.shape)
        _grads["eb_lv"] = _g_blv

        # 收集decoder梯度
        _grads.update(_perturb_and_grad(self._dec_w, self._dec_b, "dw", "db"))

        # 应用梯度
        for _k in self._enc_w:
            self._enc_w[_k] -= lr * _grads[f"ew{_k}"]
            self._enc_b[_k] -= lr * _grads[f"eb{_k}"]
        self._enc_w_lv -= lr * _grads["ew_lv"]
        self._enc_b_lv -= lr * _grads["eb_lv"]
        for _k in self._dec_w:
            self._dec_w[_k] -= lr * _grads[f"dw{_k}"]
            self._dec_b[_k] -= lr * _grads[f"db{_k}"]

        return _loss0


# ############################################################
# VAEScorer — 基于重建误差的异常打分
# ############################################################

class VAEScorer:
    """重构误差做异常得分，percentile阈值切分inlier/outlier"""

    def __init__(self, model, percentile=95):
        self._m = model  # BinaryFuncVAE实例
        self._pct = percentile
        self._threshold = None

    # //// 用训练集计算重构误差分布 ////
    def fit(self, X):
        _mu, _logvar = self._m.encode(X)
        _z = self._m._reparam(_mu, _logvar)
        _recon = self._m.decode(_z)
        _errs = np.mean(np.square(X - _recon), axis=1)
        self._threshold = self._compute_threshold(_errs, self._pct)
        return self

    def score(self, X):
        """逐样本重构误差 — 越高越异常"""
        _mu, _logvar = self._m.encode(X)
        _z = self._m._reparam(_mu, _logvar)
        _recon = self._m.decode(_z)
        return np.mean(np.square(X - _recon), axis=1)

    def predict(self, X):
        if self._threshold is None:
            raise RuntimeError("Call fit() first")
        _s = self.score(X)
        return (_s > self._threshold).astype(np.int32)

    @staticmethod
    def _compute_threshold(errors, pct):
        return float(np.percentile(errors, pct))


# ############################################################
# FunctionEmbeddingIForest — 手写Isolation Forest
# ############################################################

class FunctionEmbeddingIForest:
    """纯二叉树递归分区，不依赖sklearn — 经典iForest算法"""

    def __init__(self, n_trees=100, sample_size=256, max_depth=None):
        self._n = n_trees
        self._s = sample_size  # 子采样大小
        self._md = max_depth  # None则自动: ceil(log2(sample_size))
        self._trees = []  # [{feature, split_value, left, right, size}...]

    # ---- 构建森林 ----
    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        _n_samples = X.shape[0]
        self._trees = []
        _max_d = self._md if self._md is not None else int(np.ceil(np.log2(max(self._s, 2))))

        for _ in range(self._n):
            _idx = np.random.choice(_n_samples, min(self._s, _n_samples), replace=False)
            _sub = X[_idx]
            _tree = self._build_tree(_sub, 0, _max_d)
            self._trees.append(_tree)

        # 预计算c(n)调整因子
        self._cn = self._c_factor(self._s if self._s <= _n_samples else _n_samples)
        return self

    # //// 递归建树 ////
    def _build_tree(self, X, depth, max_depth):
        _n = X.shape[0]
        if depth >= max_depth or _n <= 1:
            return {"size": _n, "left": None, "right": None,
                    "feature": None, "split_value": None}

        _n_feat = X.shape[1]
        # 随机选特征和分割点
        _feat = np.random.randint(0, _n_feat)
        _fmin, _fmax = X[:, _feat].min(), X[:, _feat].max()

        if _fmin >= _fmax:
            return {"size": _n, "left": None, "right": None,
                    "feature": None, "split_value": None}

        _split = np.random.uniform(_fmin, _fmax)
        _left_mask = X[:, _feat] < _split
        _right_mask = ~_left_mask

        _node = {
            "feature": _feat,
            "split_value": _split,
            "size": _n,
        }
        _node["left"] = self._build_tree(X[_left_mask], depth + 1, max_depth)
        _node["right"] = self._build_tree(X[_right_mask], depth + 1, max_depth)
        return _node

    # //// 路径长度 ////
    def _path_length(self, x, tree, depth=0):
        if tree["feature"] is None:
            # 叶子节点 — 用c(size)调整
            return depth + self._c_factor(tree["size"]) if tree["size"] > 1 else depth
        if x[tree["feature"]] < tree["split_value"]:
            return self._path_length(x, tree["left"], depth + 1)
        else:
            return self._path_length(x, tree["right"], depth + 1)

    # //// c(n): 二叉搜索树平均路径长度 ////
    @staticmethod
    def _c_factor(n):
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        _h = _log(n - 1) + 0.5772156649  # Euler-Mascheroni
        return 2.0 * _h - 2.0 * (n - 1) / n

    # ==== 异常分数（原始论文公式）====
    def _anomaly_score(self, path_len, n_samples):
        return 2.0 ** (-path_len / self._c_factor(n_samples))

    # ==== 评分接口 ====
    def score(self, X):
        X = np.asarray(X, dtype=np.float64)
        _n = X.shape[0]
        _scores = np.zeros(_n)
        _c = self._cn

        for _i in range(_n):
            _pl_sum = 0.0
            for _t in self._trees:
                _pl_sum += self._path_length(X[_i], _t, 0)
            _avg_pl = _pl_sum / len(self._trees)
            _scores[_i] = 2.0 ** (-_avg_pl / _c)
        return _scores

    # ==== 预测（contamination-based cutoff）====
    def predict(self, X, threshold=None):
        _s = self.score(X)
        if threshold is not None:
            return (_s > threshold).astype(np.int32)
        # 默认：分数高于训练时中位数+2*MAD的标记为异常
        # 无法访问训练数据时，用0.5作为启发式阈值
        _cut = np.percentile(_s, 95)  # contamination heuristic = 5%
        return (_s > _cut).astype(np.int32)


# ############################################################
# OneClassSVMDetector — RFF核近似 + SGD
# ############################################################

class OneClassSVMDetector:
    """RFF近似RBF核 + SGD hinge OC-SVM — 零sklearn依赖"""

    def __init__(self, n_components=200, gamma=1.0, nu=0.1, lr=0.01):
        self._n_comp = n_components
        self._gamma = gamma  # RBF kernel bandwidth
        self._nu = nu        # 异常比例上限
        self._lr = lr
        self._w = None       # RFF空间的权重
        self._b = None       # 偏置
        self._rff_w = None   # 随机频率
        self._rff_b = None   # 随机相位

    # //// RFF变换: X -> [cos(X@W+b), sin(X@W+b)] ////
    def _rff_transform(self, X):
        X = np.asarray(X, dtype=np.float64)
        _proj = np.dot(X, self._rff_w) + self._rff_b
        return np.hstack([np.cos(_proj), np.sin(_proj)]) * _sqrt(1.0 / self._n_comp)

    # //// SGD一步: hinge-style OC-SVM更新 ////
    def _sgd_step(self, w, b, x_feat):
        _score = np.dot(w, x_feat) + b
        # OC-SVM hinge: 想让score >= margin (设为1)，否则惩罚
        _margin = 1.0
        if _score < _margin:
            _w_grad = w - self._nu * x_feat  # L2 reg + hinge grad
            _b_grad = -self._nu * 1.0
        else:
            _w_grad = w  # 仅L2正则项
            _b_grad = 0.0
        return _w_grad, _b_grad

    # ==== 训练 ====
    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        _d = X.shape[1]

        # 随机频率: N(0, 2*gamma)
        self._rff_w = np.random.randn(_d, self._n_comp) * _sqrt(2.0 * self._gamma)
        self._rff_b = np.random.uniform(0, 2 * np.pi, self._n_comp)

        # 特征变换
        _phi = self._rff_transform(X)
        _n, _feat_dim = _phi.shape

        # 初始化权重
        _w = np.zeros(_feat_dim)
        _b = 0.0

        _n_epochs = 50
        for _ep in range(_n_epochs):
            _lr_t = self._lr / (1.0 + _ep * 0.01)
            _perm = np.random.permutation(_n)
            for _j in _perm:
                _gw, _gb = self._sgd_step(_w, _b, _phi[_j])
                _w -= _lr_t * _gw
                _b -= _lr_t * _gb

        self._w = _w
        self._b = _b
        return self

    # ==== 决策函数 ====
    def decision_function(self, X):
        X = np.asarray(X, dtype=np.float64)
        _phi = self._rff_transform(X)
        return np.dot(_phi, self._w) + self._b

    # ==== 预测: 1=inlier, -1=outlier ====
    def predict(self, X):
        _scores = self.decision_function(X)
        # 0为分界线: >=0 -> inlier(1), <0 -> outlier(-1)
        _preds = np.where(_scores >= 0, 1, -1)
        return _preds
