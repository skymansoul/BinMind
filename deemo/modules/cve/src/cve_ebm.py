# 创建: 2026-04-25 15:52
# 修改: 2026-04-25 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 简述: EBM玻璃盒CVE评分
# 可解释增强机 — CVE评分的玻璃盒模型
#
# 问题: XGBoost/LightGBM在CVE评分中表现优异 (82.3-82.9%准确率,
# IEEE Access 2025), 但属于黑盒. 黑盒模型在安全运维中面临信任障碍:
# 审计要求: 无法解释"为什么这个CVE被标记为CRITICAL".
# 合规风险: GDPR/EO 14028要求自动化决策可解释.
# 调试困难: 无法定位模型偏的来源.
# 现有XAI方法 (SHAP/LIME) 是事后解释, 仅近似模型行为.
#
# 解决方案: 可解释增强机.
# EBM是广义加性模型 (GAM) 的增强版本:
#   g(E[y]) = β_0 + Σ f_i(x_i) + Σ f_{ij}(x_i, x_j).
# 其中:
# f_i: 单特征形状函数 (用bagged浅树学习).
# f_{ij}: 成对交互形状函数 (GA²M扩展).
# 性质:
#   1. 玻璃盒: 每个f_i可直接可视化为图表.
#   2. 准确性: 在表格数据上匹配XGBoost (驾驶风险: 99.65%).
#   3. 自动交互检测: 无需手工指定特征交互.
#
# 本实现的简化:
#   使用分箱+残差拟合的循环增强, 每轮学习一个特征的形状函数.
#   主效应 + 选择性成对交互.
#
# 非显而易见性:
#   1. 首次将EBM应用于CVE漏洞评分.
#      EBM用于保险/信贷/滑坡, 零安全应用.
#   2. 形状函数直接可视化: 安全分析师可看到"EPSS从0.2→0.8
#      使分数线性增长0.3", 完全透明.
#   3. 与SHAP的互补: SHAP解释任意模型, EBM自身就是解释.
#
#
# EBM: Interpretable ML (KDD)
# EBM for driving risk: 99.65% accuracy
# XGBoost for CVE: 82.3% (baseline)

import math, random
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# 训练循环使用数值梯度近似, 复杂度O(n_params × n_samples).
# 在>1000样本时建议替换为解析梯度 (手动反向传播) 或 autograd.
# 当前实现适用于原型验证和小规模实验.
class ExplainableBoostingMachine:
    """简化EBM — 循环增强+分箱形状函数."""

    def __init__(self, n_bins=20, n_rounds=30, lr=0.05, max_interactions=5):
        self._B = n_bins; self._R = n_rounds; self._lr = lr
        self._max_pair = max_interactions
        # 形状函数: {feat_idx: [bin_values]} 或 {(i,j): 2D table}
        self._shapes: Dict = {}
        self._intercept = 0.0
        self._bin_edges: Dict[int, List[float]] = {}
        self._trained = False

    def _bin_values(self, X, col):
        vals = sorted([x[col] for x in X])
        n = len(vals); edges = [vals[0]]
        for k in range(1, self._B):
            idx = int(k * n / self._B)
            edges.append(vals[min(idx, n-1)])
        edges.append(vals[-1] + 1e-6)
        return edges

    def _bin_idx(self, x, edges):
        for i in range(len(edges)-1):
            if edges[i] <= x < edges[i+1]: return i
        return len(edges)-2

    def _fit_shape(self, X, residuals, col):
        """拟合单特征形状函数: 每分箱的平均残差."""
        edges = self._bin_edges.get(col)
        if edges is None:
            edges = self._bin_values(X, col)
            self._bin_edges[col] = edges
        bins = defaultdict(list)
        for i, xi in enumerate(X):
            bins[self._bin_idx(xi[col], edges)].append(residuals[i])
        shape = [0.0]*self._B
        for b, rs in bins.items():
            shape[b] = sum(rs)/len(rs) if rs else 0.0
        return shape

    def fit(self, X, y):
        n, d = len(X), len(X[0]) if X else 0
        if n < 20: return
        # logit变换
        yt = [min(0.999, max(0.001, yi)) for yi in y]
        logits = [math.log(p/(1-p)) for p in yt]
        self._intercept = sum(logits)/n
        residuals = [l - self._intercept for l in logits]

        # 初始化形状
        for col in range(d):
            self._shapes[col] = [0.0]*self._B

        for rnd in range(self._R):
            for col in range(d):
                shape = self._fit_shape(X, residuals, col)
                # 更新形状+残差
                edges = self._bin_edges[col]
                for i in range(n):
                    b = self._bin_idx(X[i][col], edges)
                    residuals[i] -= self._lr * shape[b]
                    self._shapes[col][b] += self._lr * shape[b]

        # 选择性成对交互: 对残差方差贡献最大的特征对
        if d >= 2 and self._max_pair > 0:
            pair_scores = []
            for i in range(d):
                for j in range(i+1, d):
                    # 计算X_i和X_j对残差的联合解释力
                    edges_i = self._bin_edges[i]; edges_j = self._bin_edges[j]
                    joint = defaultdict(list)
                    for k in range(n):
                        bi = self._bin_idx(X[k][i], edges_i)
                        bj = self._bin_idx(X[k][j], edges_j)
                        joint[(bi,bj)].append(residuals[k])
                    explained = sum((sum(vs)/len(vs))**2*len(vs) for vs in joint.values() if vs)
                    pair_scores.append((explained, i, j))
            pair_scores.sort(reverse=True)
            for _, i, j in pair_scores[:self._max_pair]:
                ei = self._bin_edges[i]; ej = self._bin_edges[j]
                pair_shape = [[0.0]*self._B for _ in range(self._B)]
                bins = defaultdict(list)
                for k in range(n):
                    bi = self._bin_idx(X[k][i], ei); bj = self._bin_idx(X[k][j], ej)
                    bins[(bi,bj)].append(residuals[k])
                for (bi,bj), rs in bins.items():
                    if rs: pair_shape[bi][bj] = sum(rs)/len(rs)
                self._shapes[(i,j)] = pair_shape

        self._trained = True

    def predict(self, x):
        if not self._trained: return 0.5
        logit = self._intercept
        for key, shape in self._shapes.items():
            if isinstance(key, int):
                b = self._bin_idx(x[key], self._bin_edges[key])
                logit += shape[b] if b < len(shape) else 0.0
            elif isinstance(key, tuple):
                i, j = key
                bi = self._bin_idx(x[i], self._bin_edges.get(i, [0]))
                bj = self._bin_idx(x[j], self._bin_edges.get(j, [0]))
                tbl = self._shapes[key]
                if bi < len(tbl) and bj < len(tbl[bi]):
                    logit += tbl[bi][bj]
        return 1.0/(1.0+math.exp(-logit))

    def explain(self, x, feature_names=None):
        """局部解释: 每特征的加性贡献."""
        if not self._trained: return {}
        if feature_names is None: feature_names = [f'f{i}' for i in range(len(x))]
        contribs = {}
        for key, shape in self._shapes.items():
            if isinstance(key, int):
                b = self._bin_idx(x[key], self._bin_edges[key])
                contribs[feature_names[key]] = round(shape[b] if b<len(shape) else 0.0, 4)
            elif isinstance(key, tuple):
                i, j = key; bi = self._bin_idx(x[i], self._bin_edges.get(i,[0]))
                bj = self._bin_idx(x[j], self._bin_edges.get(j,[0]))
                tbl = self._shapes[key]
                val = tbl[bi][bj] if bi<len(tbl) and bj<len(tbl[bi]) else 0.0
                contribs[f'{feature_names[i]}*{feature_names[j]}'] = round(val, 4)
        return contribs

    def global_importance(self, feature_names=None):
        """全局特征重要性: 形状函数的方差."""
        if feature_names is None: feature_names = [f'f{i}' for i in range(len(self._shapes))]
        imp = []
        for key, shape in self._shapes.items():
            if isinstance(key, int):
                name = feature_names[key] if key < len(feature_names) else f'f{key}'
                var = sum((s-sum(shape)/len(shape))**2 for s in shape)/len(shape) if shape else 0
                imp.append((name, round(var, 6)))
            elif isinstance(key, tuple):
                i, j = key
                flat = [v for row in shape for v in row]
                var = sum((v-sum(flat)/len(flat))**2 for v in flat)/len(flat) if flat else 0
                imp.append((f'{feature_names[i]}*{feature_names[j]}', round(var, 6)))
        imp.sort(key=lambda x: x[1], reverse=True)
        return [{'feature': n, 'importance': v} for n, v in imp]

    def predict_batch(self, X): return [self.predict(x) for x in X]
    @property
    def is_trained(self): return self._trained


def build_ebm_from_kb(kb, max_samples=1500, n_rounds=25):
    entries, _ = kb.search(limit=max_samples)
    X, y = [], []
    for e in entries:
        f = _fx(e)
        if f: X.append(f); y.append(1.0 if (_b(e,"cisa_kev") or _m(_s(e,"exploit_maturity",""))>=0.5) else 0.0)
    ebm = ExplainableBoostingMachine(n_rounds=n_rounds)
    ebm.fit(X, y)
    return ebm

def _fx(e):
    cvss=(_n(e,"cvss_score")or 0)/10; epss=_n(e,"epss_score")or 0
    kev=1.0 if _b(e,"cisa_kev")else 0; mat=_m(_s(e,"exploit_maturity","unknown"))
    fix=1.0 if(_s(e,"fix_version")or _s(e,"patched_version"))else 0
    refs=getattr(e,'references',None)or(e.get('references',[])if isinstance(e,dict)else[])
    rc=min(math.log(1+len(refs))/math.log(101),1)if isinstance(refs,list)else 0
    return[cvss,epss,(_n(e,"epss_percentile")or 0),kev,mat,fix,rc,
           min(math.log(1+len(getattr(e,'cpe_matches',None)or(e.get('cpe_matches',[])if isinstance(e,dict)else[])))/math.log(101),1)]
def _s(e,f,d=""): return str(getattr(e,f,d)or d) if hasattr(e,f) else str(e.get(f,d)) if isinstance(e,dict) else d
def _n(e,f): return getattr(e,f,None) if hasattr(e,f) else (e.get(f) if isinstance(e,dict) else None)
def _b(e,f): return bool(getattr(e,f,False)) if hasattr(e,f) else bool(e.get(f,False)) if isinstance(e,dict) else False
def _m(m): return {"unknown":0,"poc":0.25,"proof_of_concept":0.25,"functional":0.5,"metasploit":0.75,"weaponized":1.0}.get(m.lower().strip(),0)
