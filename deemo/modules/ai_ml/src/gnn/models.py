# 2026-07-15
# GNN下游模型 — 二分类/漏洞检测/孪生匹配，全部纯NumPy
# 战略思路：GNN模型本身不存储训练状态（无optimizer），推理接口即forward+归一化后处理；
# 训练逻辑由外部编排器负责，模型只管前向传播

import numpy as np
from .layers import GraphConv, GATConv, normalize_adj

# ---- 初始化工具 ----

def _xavier(fi, fo):
    _l = np.sqrt(6.0 / (fi + fo))
    return np.random.uniform(-_l, _l, (fi, fo))


def _sigmoid(_h):
    _h = np.clip(_h, -50, 50)
    return 1.0 / (1.0 + np.exp(-_h))


# ===== GCNBinaryClassifier =====


class GCNBinaryClassifier:
    """堆叠GraphConv的节点级二分类器
    中间层ReLU激活，输出层sigmoid — 适合函数相似度/漏洞存在性判定"""

    def __init__(self, in_dim=12, hidden_dim=64, num_layers=2):
        _stack = []
        for _i in range(num_layers):
            _di = in_dim if _i == 0 else hidden_dim
            _do = 1 if _i == num_layers - 1 else hidden_dim
            _act = 'sigmoid' if _i == num_layers - 1 else 'relu'
            _stack.append(GraphConv(_di, _do, activation=_act))
        self._layers = _stack
        self._n = num_layers

    def forward(self, _x, _a):
        _h = _x
        for _l in self._layers:
            _h = _l.forward(_h, _a)
        return _h

    def predict(self, _x, _a, threshold=0.5):
        _p = self.forward(_x, _a)
        return (_p > threshold).astype(np.int32)


# ===== GATVulnDetector =====


class GATVulnDetector:
    """GAT + 全局平均池化的图级二分类
    适用场景：判断整个二进制函数是否含漏洞
    池化策略选择mean pooling而非max — 更平滑的梯度，对小样本友好"""

    def __init__(self, in_dim=12, hidden_dim=64, heads=4):
        self._gat = GATConv(in_dim, hidden_dim, heads=heads)
        self._dense_w = _xavier(hidden_dim, 1)
        self._dense_b = np.zeros(1)

    def _global_mean_pool(self, _h):
        return _h.mean(axis=0)

    def forward(self, _x, _a):
        """返回标量漏洞分数 ∈ [0, 1]"""
        _h = self._gat.forward(_x, _a)           # (N, hidden_dim)
        _pooled = self._global_mean_pool(_h)      # (hidden_dim,)
        _pooled = np.maximum(0, _pooled)           # ReLU
        _logit = np.dot(_pooled, self._dense_w.flatten()) + self._dense_b[0]
        return float(_sigmoid(_logit))

    def predict(self, _x, _a, threshold=0.5):
        return self.forward(_x, _a) >= threshold


# ===== SiameseBinaryMatcher =====


class SiameseBinaryMatcher:
    """双塔GCN孪生网络，用于二进制函数相似度匹配
    共享权重的两层GCN编码器 → global mean pool → 余弦相似度
    选择余弦而非欧氏距离：归一化到[-1,1]后线性映射至[0,1]，对嵌入模长不敏感"""

    def __init__(self, in_dim=12, hidden_dim=64):
        self._gcn1 = GraphConv(in_dim, hidden_dim, activation='relu')
        self._gcn2 = GraphConv(hidden_dim, hidden_dim, activation='relu')

    def compute_embedding(self, _x, _a):
        """将图映射为固定维度的嵌入向量"""
        _h = self._gcn1.forward(_x, _a)
        _h = self._gcn2.forward(_h, _a)
        # 全局均值池化 → (hidden_dim,)
        return _h.mean(axis=0)

    def forward(self, _x1, _a1, _x2, _a2):
        """计算两个函数CFG的相似度分数 ∈ [0, 1]"""
        _e1 = self.compute_embedding(_x1, _a1)
        _e2 = self.compute_embedding(_x2, _a2)

        # 余弦相似度
        _dot = np.dot(_e1, _e2)
        _n1 = np.linalg.norm(_e1) + 1e-10
        _n2 = np.linalg.norm(_e2) + 1e-10
        _cos = _dot / (_n1 * _n2)

        # 映射到 [0, 1]
        return float((_cos + 1.0) / 2.0)

    def predict(self, _x1, _a1, _x2, _a2, threshold=0.5):
        return self.forward(_x1, _a1, _x2, _a2) >= threshold


# ===== Batch inference convenience =====


def batch_predict_matches(_matcher, _pairs):
    """批量孪生匹配推理
    _pairs: list of (x1, a1, x2, a2) tuples
    返回: list of float scores"""
    return [_matcher.forward(*_p) for _p in _pairs]


def _demo():
    """轻量冒烟测试 — 验证各模块前向通路不崩溃"""
    np.random.seed(42)
    _n = 8
    _d = 12
    _x = np.random.randn(_n, _d).astype(np.float32)
    # 构造简单链式邻接
    _a = np.zeros((_n, _n))
    for _i in range(_n - 1):
        _a[_i, _i + 1] = 1.0
        _a[_i + 1, _i] = 1.0

    # GCNBinaryClassifier
    _gcn = GCNBinaryClassifier(in_dim=_d, hidden_dim=32, num_layers=2)
    _p = _gcn.forward(_x, _a)
    assert _p.shape == (_n, 1), f"GCN shape mismatch: {_p.shape}"
    print(f"[OK] GCNBinaryClassifier output shape: {_p.shape}")

    # GATVulnDetector
    _gat = GATVulnDetector(in_dim=_d, hidden_dim=32, heads=4)
    _s = _gat.forward(_x, _a)
    assert isinstance(_s, float), f"GAT score not float: {type(_s)}"
    print(f"[OK] GATVulnDetector score: {_s:.4f}")

    # SiameseBinaryMatcher
    _matcher = SiameseBinaryMatcher(in_dim=_d, hidden_dim=32)
    _sim = _matcher.forward(_x, _a, _x, _a)
    assert 0.0 <= _sim <= 1.0, f"Similarity out of bounds: {_sim}"
    print(f"[OK] SiameseBinaryMatcher self-sim: {_sim:.4f}")

    # SAGPool
    from .layers import SAGPool
    _pool = SAGPool(in_dim=_d, ratio=0.5)
    _px, _pa, _idx = _pool.forward(_x, _a)
    assert len(_px) <= _n, f"Pool didn't reduce nodes: {len(_px)}"
    print(f"[OK] SAGPool: {_n} -> {len(_px)} nodes")

    # LaplacianPE
    from .layers import LaplacianPE
    _lpe = LaplacianPE(k=3)
    _pe = _lpe.compute(_a)
    assert _pe.shape == (_n, 3), f"LPE shape mismatch: {_pe.shape}"
    print(f"[OK] LaplacianPE shape: {_pe.shape}")

    print("\nAll smoke tests passed.")


if __name__ == "__main__":
    _demo()
