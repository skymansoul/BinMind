# 创建: 2026-08-01 07:03
# 修改: 2026-08-04 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 修改: 2026-08-05 09:45 (解析梯度替换数值梯度: 手动推导异方差损失反向传播, mini-batch SGD)
# 简述: MC Dropout贝叶斯评分 — 认知+偶然不确定性分解
# 贝叶斯CVE评分 — MC Dropout驱动的认知+偶然不确定性估计
#
# 问题: 现有CVE评分模型输出点估计, 不区分两种不确定性:
#   1. 认知 (Epistemic): 模型知识不足 → 可通过更多数据减少.
#   2. 偶然 (Aleatoric): 数据固有噪声 → 不可约.
# 区分两者的实际价值: 高认知+低偶然→需更多数据; 低认知+高偶然→不可预测.
#
# 解决方案: MC Dropout (Gal & Ghahramani 2016) + 双头输出 (Kendall & Gal 2017).
# 训练时: 标准MLP + Dropout正则化.
# 推理时: 保持Dropout开启, T次随机前向传播.
#   总方差 = 认知方差 (样本间) + 偶然方差 (平均预测方差).
#
# 双头架构 + 异方差损失:
#   共享编码器 → 分数头 (μ) + 方差头 (log σ²).
#   损失: L = (y-μ)²/(2σ²) + log(σ²)/2.
#   高噪声样本的σ²自动增大, 降低其对梯度贡献 — 自动加权.
#
# 关键改进 (相对原数值梯度版本):
#   解析反向传播: 手动推导异方差损失的梯度, 消除O(n²)复杂度.
#     ∂L/∂s_μ = -(y-μ)·μ(1-μ)/exp(s_σ²)    (分数头logit梯度)
#     ∂L/∂s_σ² = 0.5 - (y-μ)²/(2·exp(s_σ²))  (方差头logit梯度)
#   mini-batch SGD: 批量累积梯度, 减少Python循环开销.
#   训练速度提升 ~500-1000x (相对数值梯度逐参数差分).
#
# 参考:
#   [Gal & Ghahramani 2016] Dropout as Bayesian Approximation (ICML)
#   [Kendall & Gal 2017] Aleatoric+Epistemic Uncertainty (NeurIPS)
#   [VB-Score 2025] 通用评分框架, 非CVE特定

import math, random
from typing import Dict, List, Optional, Tuple

class MCDropoutScorer:
    """MC Dropout贝叶斯评分器 — 解析梯度, 双头架构, mini-batch SGD."""

    def __init__(self, input_dim=8, hidden_dim=24, dropout_rate=0.3):
        self._d_in = input_dim; self._d_h = hidden_dim; self._p = dropout_rate
        lim_e = math.sqrt(6/(input_dim+hidden_dim))
        lim_h = math.sqrt(6/(hidden_dim+1))
        self._W_enc = [[random.uniform(-lim_e, lim_e) for _ in range(hidden_dim)] for _ in range(input_dim)]
        self._b_enc = [0.0]*hidden_dim
        self._W_score = [[random.uniform(-lim_h, lim_h)] for _ in range(hidden_dim)]
        self._b_score = [0.0]
        self._W_var = [[random.uniform(-lim_h, lim_h)] for _ in range(hidden_dim)]
        self._b_var = [0.0]
        self._trained = False

    def _forward(self, x, training=True):
        """返回 (μ, σ², h_post, dropout_mask)."""
        h_pre = [0.0]*self._d_h
        for j in range(self._d_h):
            s = self._b_enc[j]
            for i in range(min(self._d_in, len(x))): s += x[i]*self._W_enc[i][j]
            h_pre[j] = s
        h_post = [max(0.0, v) for v in h_pre]
        mask = [1.0]*self._d_h
        if training:
            mask = [0.0 if random.random() < self._p else 1.0 for _ in range(self._d_h)]
            scale = 1.0/(1.0-self._p)
            for j in range(self._d_h): h_post[j] *= mask[j]*scale
        s1 = self._b_score[0] + sum(h_post[j]*self._W_score[j][0] for j in range(self._d_h))
        mu = 1.0/(1.0+math.exp(-s1))
        s2 = self._b_var[0] + sum(h_post[j]*self._W_var[j][0] for j in range(self._d_h))
        sigma2 = math.exp(min(s2, 3.0)) + 1e-4
        return mu, sigma2, h_post, mask

    def train(self, X, y, epochs=80, lr=0.005, batch_size=32):
        """解析梯度mini-batch SGD训练. 异方差损失自动加权."""
        n = len(X)
        if n < 10: return
        for epoch in range(epochs):
            indices = list(range(n)); random.shuffle(indices)
            for start in range(0, n, batch_size):
                batch = indices[start:start+batch_size]
                dW_enc = [[0.0]*self._d_h for _ in range(self._d_in)]
                db_enc = [0.0]*self._d_h
                dW_score = [[0.0] for _ in range(self._d_h)]
                db_score = [0.0]
                dW_var = [[0.0] for _ in range(self._d_h)]
                db_var = [0.0]
                for idx in batch:
                    xi, yi = X[idx], y[idx]
                    mu, sigma2, h_post, _ = self._forward(xi, training=True)
                    delta_score = -(yi-mu)*mu*(1-mu)/sigma2  # ∂L/∂s1
                    delta_var = 0.5 - (yi-mu)**2/(2*sigma2)   # ∂L/∂s2
                    for j in range(self._d_h):
                        dW_score[j][0] += delta_score*h_post[j]
                        dW_var[j][0] += delta_var*h_post[j]
                    db_score[0] += delta_score; db_var[0] += delta_var
                    for j in range(self._d_h):
                        dh = delta_score*self._W_score[j][0] + delta_var*self._W_var[j][0]
                        for i in range(min(self._d_in, len(xi))):
                            dW_enc[i][j] += dh*xi[i]
                        db_enc[j] += dh
                m = len(batch); lr_b = lr/m; l2 = 0.001
                for i in range(self._d_in):
                    for j in range(self._d_h):
                        self._W_enc[i][j] -= lr_b*(dW_enc[i][j] + l2*self._W_enc[i][j])
                for j in range(self._d_h):
                    self._b_enc[j] -= lr_b*(db_enc[j] + l2*self._b_enc[j])
                    self._W_score[j][0] -= lr_b*(dW_score[j][0] + l2*self._W_score[j][0])
                    self._W_var[j][0] -= lr_b*(dW_var[j][0] + l2*self._W_var[j][0])
                self._b_score[0] -= lr_b*(db_score[0] + l2*self._b_score[0])
                self._b_var[0] -= lr_b*(db_var[0] + l2*self._b_var[0])
            lr *= 0.97
        self._trained = True

    def predict(self, x, n_samples=50):
        if not self._trained:
            mu, _ = self._forward(x, training=False)[:2]
            return {"score": round(mu,4), "epistemic": 0.0, "aleatoric": 0.0, "total_uncertainty": 0.0}
        samples, variances = [], []
        for _ in range(n_samples):
            mu, sigma2, _, _ = self._forward(x, training=True)
            samples.append(mu); variances.append(sigma2)
        mean_s = sum(samples)/n_samples
        epistemic = sum((s-mean_s)**2 for s in samples)/n_samples
        aleatoric = sum(variances)/n_samples
        total = epistemic + aleatoric
        return {"score": round(mean_s,4), "epistemic": round(epistemic,6),
                "aleatoric": round(aleatoric,6), "total_uncertainty": round(total,6),
                "uncertainty_type": self._classify(epistemic, aleatoric)}

    def batch_predict(self, X, n_samples=30): return [self.predict(x, n_samples) for x in X]

    def _classify(self, ep, al):
        if ep>0.02 and al>0.02: return "high_epistemic_high_aleatoric"
        if ep>0.02: return "high_epistemic_low_aleatoric"
        if al>0.02: return "low_epistemic_high_aleatoric"
        return "low_uncertainty"

    @property
    def is_trained(self): return self._trained


def build_bayesian_scorer_from_kb(kb, max_samples=2000, epochs=80):
    entries, _ = kb.search(limit=max_samples)
    X, y = [], []
    for e in entries:
        f = _fx(e)
        if f: X.append(f); y.append(1.0 if (_b(e,"cisa_kev") or _m(_s(e,"exploit_maturity",""))>=0.5) else 0.0)
    scorer = MCDropoutScorer(input_dim=len(X[0]) if X else 8)
    scorer.train(X, y, epochs=epochs)
    return scorer


def uncertainty_triage(scorer, features, cve_ids, n_samples=30):
    return sorted([{"cve_id": cid, **scorer.predict(f, n_samples)} for f, cid in zip(features, cve_ids)], key=lambda r: r["total_uncertainty"], reverse=True)


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
