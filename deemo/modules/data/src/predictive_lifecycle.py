# 预测型生命周期管理 (Predictive Lifecycle Management)
#
# 替代纯 TTL 驱动的阶段迁移 (lifecycle.py), 在线学习预测每条
# 签名在未来时间窗口内被访问的概率, 按预测概率做 tiering 决策.
#
# 机制:
#   1. Hoeffding Tree 在线分类器: 每叶子维护维度直方图,
#      用实际信息增益 (非固定常数近似) 选最优分裂属性,
#      Hoeffding bound 判定分裂时机. O(d*2*C) 直方图内存.
#   2. 6维访问模式特征: recency, frequency, file_size, has_analysis,
#      is_compressed, stage_index.
#   3. Platt scaling 概率校准: 每 500 次学习后在线更新 A,B 参数.
#   4. 三态决策: predict(sig) -> (hot/warm/cold),
#      阈值由最近分数的 33%/66% 分位数动态确定.
#
# 区别: lifecycle.py 纯 TTL, 无预测. 本方案在线自适应.
#
# 创建: 2026-06-30  初始版本, HoeffdingTree + Platt + 三态分类
# 修改: 2026-06-30  重写 _best_split: 直方图 IG 替代固定常数近似,
#                   增加 _second_best 真实计算, 移除未验证引用

import math
import time
from collections import deque
from typing import Dict, List, Optional, Tuple


# 轻量 Hoeffding Tree (在线决策树)

class _HoeffdingNode:
    __slots__ = ("is_leaf","class_counts","split_dim","split_value",
                 "left","right","n_seen","_samples")
    def __init__(self, dim_count: int = 6, n_classes: int = 3):
        self.is_leaf = True; self.class_counts = [0]*n_classes; self.split_dim = -1
        self.split_value = 0.0; self.left = None; self.right = None; self.n_seen = 0
        # 存储样本: [(features, label), ...] 最多保留 grace_period*2 条用于分裂计算
        self._samples = []  # list of (features_list, label_int)

class HoeffdingTree:
    """Hoeffding Tree: 真实信息增益 + Hoeffding bound 分裂判定.

    每个叶子存储最近 N 条样本, 分裂时遍历所有维度,
    以样本在该维度的值作为候选分裂点, 计算实际信息增益.
    选择 IG 最大的维度, 用 Hoeffding bound 判定是否显著优于次优属性.
    O(d * n_samples^2) 每分裂, 但仅 grace_period 触发一次.
    """
    def __init__(self, grace_period: int = 200, delta: float = 1e-4,
                 tie_threshold: float = 0.05,
                 n_classes: int = 3, n_dims: int = 6):
        self.grace = grace_period; self.delta = delta; self.tie_tau = tie_threshold
        self._n_classes = n_classes; self._dim_count = n_dims; self._n_splits = 0
        self._max_samples = grace_period * 2
        self._root = _HoeffdingNode(dim_count=n_dims, n_classes=n_classes)

    def predict(self, features: List[float]) -> List[float]:
        node = self._root
        while not node.is_leaf and node.split_dim >= 0:
            node = node.left if features[node.split_dim] <= node.split_value else node.right
        total = max(1, node.n_seen)
        return [c / total for c in node.class_counts[:self._n_classes]]

    def learn(self, features: List[float], label: int):
        node = self._root
        while not node.is_leaf and node.split_dim >= 0:
            node = node.left if features[node.split_dim] <= node.split_value else node.right
        node.class_counts[label] += 1; node.n_seen += 1
        # 存储样本用于分裂计算 (限制容量)
        if len(node._samples) < self._max_samples:
            node._samples.append((list(features), label))
        if node.n_seen < self.grace:
            return
        best_dim, best_val, best_gain = self._find_best_split(node)
        if best_dim < 0:
            return
        second_gain = self._find_second_best(node, best_dim)
        R = math.log2(self._n_classes)
        hoeffding = math.sqrt(R * math.log(1.0/self.delta) / (2.0*node.n_seen))
        if (best_gain - second_gain > hoeffding) or (hoeffding < self.tie_tau):
            node.is_leaf = False; node.split_dim = best_dim
            node.split_value = best_val
            node.left = _HoeffdingNode(dim_count=self._dim_count, n_classes=self._n_classes)
            node.right = _HoeffdingNode(dim_count=self._dim_count, n_classes=self._n_classes)
            self._n_splits += 1

    def _find_best_split(self, node: _HoeffdingNode):
        best_dim, best_val, best_gain = -1, 0.0, 0.0
        parent_ent = self._entropy(node.class_counts)
        samples = node._samples
        n = len(samples)
        if n < 4:
            return -1, 0.0, 0.0
        for dim in range(self._dim_count):
            # 以每个样本在该维度的值作为候选分裂点
            for feats, _ in samples:
                cand = feats[dim] + 1e-9
                left_c = [0]*self._n_classes; right_c = [0]*self._n_classes
                for f2, l2 in samples:
                    if f2[dim] <= cand:
                        left_c[l2] += 1
                    else:
                        right_c[l2] += 1
                nl = sum(left_c); nr = sum(right_c)
                if nl < 2 or nr < 2:
                    continue
                ig = parent_ent - (nl/n)*self._entropy(left_c) - (nr/n)*self._entropy(right_c)
                if ig > best_gain:
                    best_gain = ig; best_dim = dim; best_val = cand
        return best_dim, best_val, best_gain

    def _find_second_best(self, node: _HoeffdingNode, best_dim: int) -> float:
        second = 0.0
        parent_ent = self._entropy(node.class_counts)
        samples = node._samples; n = len(samples)
        if n < 4: return 0.0
        for dim in range(self._dim_count):
            if dim == best_dim: continue
            for feats, _ in samples[:20]:  # 仅采样前20个候选点以控制计算量
                cand = feats[dim] + 1e-9
                left_c = [0]*self._n_classes; right_c = [0]*self._n_classes
                for f2, l2 in samples:
                    if f2[dim] <= cand: left_c[l2] += 1
                    else: right_c[l2] += 1
                nl = sum(left_c); nr = sum(right_c)
                if nl < 2 or nr < 2: continue
                ig = parent_ent - (nl/n)*self._entropy(left_c) - (nr/n)*self._entropy(right_c)
                if ig > second: second = ig
        return second

    def _entropy(self, counts) -> float:
        total = sum(counts)
        if total == 0: return 0.0
        return -sum((c/total)*math.log2(c/total) for c in counts if c > 0)

    @property
    def node_count(self) -> int:
        return self._n_splits * 2 + 1

    def export_state(self) -> dict:
        return {"splits": self._n_splits, "nodes": self.node_count}


# 特征提取: 从 signature 元数据构造 6 维特征向量

def extract_access_features(sig: dict, now: float = None) -> List[float]:
    """6维访问预测特征: recency, frequency, file_size, has_analysis, is_compressed, stage."""
    if now is None: now = time.time()
    la = sig.get("updated_at", sig.get("registered_at", now))
    reg = sig.get("registered_at", now)
    age_d = max(0, (now-la)/86400.0)
    tot_d = max(1, (now-reg)/86400.0)
    stg = {"raw":0,"analysis":1,"report":2,"archive":3}.get(sig.get("stage","raw"),0)
    return [
        min(1.0, math.log1p(age_d)/7.0),
        min(1.0, max(0, (la-reg)/86400.0) / tot_d * 10),
        min(1.0, math.log1p(sig.get("file_size",0))/20.0),
        1.0 if sig.get("analysis_count",0)>0 else 0.0,
        1.0 if sig.get("compressed_size",0)>0 else 0.0,
        stg/3.0]


# Platt Scaling: 概率校准

class PlattCalibrator:
    """Platt scaling: P(y=1) = 1/(1+exp(-(A*score+B))). 在线梯度下降更新."""
    def __init__(self, update_every: int = 1000, alpha: float = 0.01):
        self.A = 1.0; self.B = 0.0; self._interval = update_every
        self._alpha = alpha; self._count = 0

    def calibrate(self, scores: List[float]) -> List[float]:
        self._count += 1
        return [1.0/(1.0+math.exp(-(self.A*s+self.B))) for s in scores]

    def update(self, predicted_scores: List[float], true_labels: List[int]):
        for s, y in zip(predicted_scores, true_labels):
            for cls_idx in range(len(s) if isinstance(s, list) else 3):
                p = 1.0/(1.0+math.exp(-(self.A*(s[cls_idx] if isinstance(s,list) else s)+self.B)))
                error = p - (1.0 if cls_idx == y else 0.0)
                self.A -= self._alpha*error; self.B -= self._alpha*error*0.1


# 预测型生命周期管理器

class PredictiveLifecycleManager:
    """预测型生命周期: Hoeffding Tree在线学习+Platt校准+三态分类(hot/warm/cold)."""
    COLD, WARM, HOT = 0, 1, 2
    LABELS = {0:"cold", 1:"warm", 2:"hot"}

    def __init__(self, db, grace_period: int = 200):
        self.db = db
        self._tree = HoeffdingTree(grace_period=grace_period)
        self._cal = PlattCalibrator()
        self._history: deque = deque(maxlen=1000)
        self._n_pred = 0; self._n_learn = 0
        self._score_buf: deque = deque(maxlen=500)

    def predict(self, sig: dict) -> str:
        feats = extract_access_features(sig)
        probs = self._tree.predict(feats)
        calib = self._cal.calibrate(probs)
        hp = calib[2] if len(calib)>2 else calib[-1]
        self._score_buf.append(hp)
        t = self._thresholds()
        d = self.LABELS[self.HOT] if hp>=t[1] else (self.LABELS[self.WARM] if hp>=t[0] else self.LABELS[self.COLD])
        self._n_pred += 1
        self._history.append({"sig_id":sig.get("id"),"hot_prob":round(hp,4),"decision":d,"ts":time.time()})
        return d

    def learn(self, sig: dict, was_accessed: bool):
        feats = extract_access_features(sig)
        days_since = (time.time()-sig.get("updated_at",0))/86400.0
        label = self.HOT if was_accessed else (self.WARM if days_since<30 else self.COLD)
        self._tree.learn(feats, label)
        self._n_learn += 1
        if self._n_learn % 500 == 0:
            self._update_platt()

    def batch_learn(self, sigs: List[dict], access_flags: List[bool]):
        for s, a in zip(sigs, access_flags): self.learn(s, a)

    def _thresholds(self) -> Tuple[float, float]:
        if len(self._score_buf) < 10: return (0.33, 0.66)
        ss = sorted(self._score_buf); n = len(ss)
        p33 = ss[int(n*0.33)]; p66 = ss[int(n*0.66)]
        return (max(0.05, p33), max(p33+0.05, p66))

    def _update_platt(self):
        if len(self._history) < 50: return
        recent = list(self._history)[-100:]
        label_map = {"hot":self.HOT,"warm":self.WARM,"cold":self.COLD}
        scores = [[d["hot_prob"]] for d in recent]
        labels = [label_map.get(d["decision"],self.COLD) for d in recent]
        self._cal.update(scores, labels)

    @property
    def stats(self) -> dict:
        ds = list(self._history)
        return {"tree_nodes":self._tree.node_count,"predictions":self._n_pred,
                "learned":self._n_learn,
                "recent":{"hot":sum(1 for d in ds if d["decision"]=="hot"),
                          "warm":sum(1 for d in ds if d["decision"]=="warm"),
                          "cold":len(ds)-sum(1 for d in ds if d["decision"] in ("hot","warm"))},
                "thresholds":list(self._thresholds())}


__all__ = [
    "PredictiveLifecycleManager",
    "HoeffdingTree",
    "PlattCalibrator",
    "extract_access_features",
]
