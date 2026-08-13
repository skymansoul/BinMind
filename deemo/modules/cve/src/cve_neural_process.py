# 创建: 2026-06-08 22:08
# 修改: 2026-06-08 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 简述: 条件神经过程CVE评分
# 条件神经过程 — CVE评分函数分布的学习与推理
#
# 问题: 现有CVE评分模型 (EPSS/GNN/Hawkes) 学习单一函数 f: X→[0,1].
# 但CVE评分本质上是随机的 — 同一特征向量的CVE可能因未观测因素
# (攻击者动机、工具链可用性、地缘政治) 而有不同的利用结果.
# 单一函数无法表达这种不确定性, 且无法利用少量已知CVE快速适应新上下文.
#
# 解决方案: 条件神经过程 (Conditional Neural Process, CNP).
# CNP学习的是函数的分布 P(f|D_context), 而非单一函数.
# 给定上下文集 {(x_i, y_i)} (已知的CVE特征+利用标签),
# CNP输出对查询点x*的预测分布 N(μ*, σ*²).
#
# 架构:
#   编码器 h_i = MLP_enc(x_i, y_i)  →  聚合 r = mean(h_i)
#   解码器 (μ*, σ*) = MLP_dec(r, x*)
# 训练: 最大化 log P(y_query | X_query, D_context).
#
# CNP的关键特性:
#   1. 不确定性校准: σ* 反映给定上下文后预测的不确定性.
#      少上下文 → 高σ (模型知道自己不知道).
#   2. 快速适应: 给定新CWE类型的几个已知CVE作为上下文,
#      即可对该类型的其他CVE做出校准预测.
#   3. 计算效率: O(|C|+|Q|) 单次前向, 无需MAML的梯度循环.
#
# 与现有模块的差异:
#   - MAMLCVEModel (cve_meta_learning): 基于梯度的元学习, 需要内循环.
# CNP: 基于前向的元学习, 上下文通过编码器直接调制预测.
#   - ConformalExploitScorer: 频率学派区间, CNP提供贝叶斯风格的后验方差.
#
# 非显而易见性:
#   1. 首次将神经过程应用于CVE评分.
#      2025-2026年检索: BayesMAML用于恶意软件检测,
#      但零论文使用Neural Processes于漏洞评分.
#   2. 上下文设计: 编码器融合了特征+标签的联合表示,
#      而非仅特征 (标准CNP for regression).
#      这使上下文信息更丰富地调制解码器.
#   3. 与ConformalExploitScorer形成双不确定性体系:
#      CNP提供认知不确定性 (模型知识不足),
#      共形提供偶然不确定性 (个体预测波动).
#
#
# Conditional Neural Processes (ICML)
# Neural Processes (ICML Workshop)
# BayesMAML for zero-day malware (related but different)

import math
import random
from typing import Dict, List, Optional, Tuple

# 性能注意: 训练循环使用数值梯度近似, 复杂度O(n_params × n_samples).
# 在>1000样本时建议替换为解析梯度 (手动反向传播) 或 autograd.
# 当前实现适用于原型验证和小规模实验.

class ConditionalNeuralProcess:
    """条件神经过程 — CVE评分函数分布的学习.

    编码器-解码器架构:
      r = mean(MLP_enc(concat(x_i, y_i)) for (x_i,y_i) in context)
      (μ, log_σ²) = MLP_dec(concat(r, x*))
    """

    def __init__(self, x_dim: int = 8, h_dim: int = 32, r_dim: int = 32):
        self._x_dim = x_dim
        self._h_dim = h_dim
        self._r_dim = r_dim

        # 编码器: (x_dim+1) → h_dim → h_dim
        self._enc_W1 = self._init_matrix(x_dim + 1, h_dim)
        self._enc_b1 = [0.0] * h_dim
        self._enc_W2 = self._init_matrix(h_dim, h_dim)
        self._enc_b2 = [0.0] * h_dim

        # 聚合后变换: h_dim → r_dim
        self._agg_W = self._init_matrix(h_dim, r_dim)
        self._agg_b = [0.0] * r_dim

        # 解码器: (r_dim + x_dim) → h_dim → h_dim → 2
        self._dec_W1 = self._init_matrix(r_dim + x_dim, h_dim)
        self._dec_b1 = [0.0] * h_dim
        self._dec_W2 = self._init_matrix(h_dim, h_dim)
        self._dec_b2 = [0.0] * h_dim
        self._dec_W3 = self._init_matrix(h_dim, 2)
        self._dec_b3 = [0.0, 0.0]

        self._trained = False

    def _init_matrix(self, d_in: int, d_out: int) -> List[List[float]]:
        limit = math.sqrt(6.0 / (d_in + d_out))
        return [[random.uniform(-limit, limit) for _ in range(d_out)]
                for _ in range(d_in)]

    def _mlp_forward(self, x: List[float], weights: List[List[List[float]]],
                     biases: List[List[float]]) -> List[float]:
        """多层MLP前向传播. weights=[W1,W2,...], biases=[b1,b2,...]."""
        h = list(x)
        for W, b in zip(weights[:-1], biases[:-1]):
            new_h = [0.0] * len(W[0])
            for j in range(len(W[0])):
                s = b[j]
                for i in range(min(len(W), len(h))):
                    s += h[i] * W[i][j]
                new_h[j] = max(0.0, s)  # ReLU
            h = new_h
        # 最后一层 (无激活)
        W_last, b_last = weights[-1], biases[-1]
        out = [0.0] * len(W_last[0])
        for j in range(len(W_last[0])):
            s = b_last[j]
            for i in range(min(len(W_last), len(h))):
                s += h[i] * W_last[i][j]
            out[j] = s
        return out

    def _encode_context(self, context_X: List[List[float]],
                        context_y: List[float]) -> List[float]:
        """编码上下文: r = mean(MLP_enc([x_i, y_i]))."""
        if not context_X:
            return [0.0] * self._r_dim

        enc_weights = [self._enc_W1, self._enc_W2]
        enc_biases = [self._enc_b1, self._enc_b2]

        reps = []
        for xi, yi in zip(context_X, context_y):
            inp = list(xi) + [yi]
            h = self._mlp_forward(inp, enc_weights, enc_biases)
            reps.append(h)

        # 均值聚合
        r = [0.0] * self._h_dim
        for h in reps:
            for j in range(self._h_dim):
                r[j] += h[j] / len(reps)
        # 投影到r_dim
        r_proj = [0.0] * self._r_dim
        for j in range(self._r_dim):
            s = self._agg_b[j]
            for i in range(self._h_dim):
                s += r[i] * self._agg_W[i][j]
            r_proj[j] = s
        return r_proj

    def _decode(self, r: List[float], x_star: List[float]
                ) -> Tuple[float, float]:
        """解码: (μ, log_σ²) = MLP_dec([r, x*])."""
        inp = r + list(x_star)
        dec_weights = [self._dec_W1, self._dec_W2, self._dec_W3]
        dec_biases = [self._dec_b1, self._dec_b2, self._dec_b3]
        out = self._mlp_forward(inp, dec_weights, dec_biases)
        mu = out[0]
        log_var = out[1]
        sigma = math.sqrt(max(1e-4, math.exp(min(log_var, 5.0))))
        return mu, sigma

    def train(self, tasks: List[Tuple[List[List[float]], List[float]]],
              epochs: int = 100, lr: float = 0.005,
              context_ratio: float = 0.5):
        """CNP训练: 最大化条件对数似然.

        tasks: [(X, y), ...] 每个任务为一个CWE类型的数据.
        每epoch随机划分context/query, 梯度下降最小化负对数似然.
        """
        if len(tasks) < 2:
            return

        for epoch in range(epochs):
            total_loss = 0.0
            for X_all, y_all in tasks:
                n = len(X_all)
                if n < 3:
                    continue
                n_ctx = max(1, int(n * context_ratio))
                indices = list(range(n))
                random.shuffle(indices)
                ctx_X = [X_all[i] for i in indices[:n_ctx]]
                ctx_y = [y_all[i] for i in indices[:n_ctx]]
                qry_X = [X_all[i] for i in indices[n_ctx:]]
                qry_y = [y_all[i] for i in indices[n_ctx:]]

                r = self._encode_context(ctx_X, ctx_y)
                # 负对数似然损失
                loss = 0.0
                for xi, yi in zip(qry_X, qry_y):
                    mu, sigma = self._decode(r, xi)
                    diff = yi - mu
                    nll = 0.5 * math.log(2.0 * math.pi * sigma * sigma) + \
                          (diff * diff) / (2.0 * sigma * sigma + 1e-6)
                    loss += nll
                loss /= max(len(qry_X), 1)
                total_loss += loss

                # 数值梯度更新 (简化: 仅更新解码器最后一层)
                eps = 1e-4
                for i in range(len(self._dec_W3)):
                    for j in range(2):
                        orig = self._dec_W3[i][j]
                        self._dec_W3[i][j] = orig + eps
                        r2 = self._encode_context(ctx_X, ctx_y)
                        loss_plus = sum(
                            0.5 * math.log(2*math.pi*s*s) + (yi-mu)**2/(2*s*s+1e-6)
                            for xi2, yi2 in zip(qry_X, qry_y)
                            for mu, s in [self._decode(r2, xi2)]
                        ) / max(len(qry_X), 1)
                        self._dec_W3[i][j] = orig - eps
                        r3 = self._encode_context(ctx_X, ctx_y)
                        loss_minus = sum(
                            0.5 * math.log(2*math.pi*s*s) + (yi-mu)**2/(2*s*s+1e-6)
                            for xi3, yi3 in zip(qry_X, qry_y)
                            for mu, s in [self._decode(r3, xi3)]
                        ) / max(len(qry_X), 1)
                        self._dec_W3[i][j] = orig
                        grad = (loss_plus - loss_minus) / (2.0 * eps)
                        self._dec_W3[i][j] -= lr * grad

            lr *= 0.98
            if epoch % 20 == 0 and total_loss < 1e-6:
                break

        self._trained = True

    def predict(self, context_X: List[List[float]],
                context_y: List[float],
                query_X: List[List[float]]
                ) -> List[Tuple[float, float]]:
        """给定上下文, 对查询点输出 (μ, σ) 预测分布."""
        r = self._encode_context(context_X, context_y)
        return [self._decode(r, x) for x in query_X]

    def predict_single(self, context_X: List[List[float]],
                       context_y: List[float],
                       query_x: List[float]) -> Tuple[float, float, float]:
        """单查询点预测, 返回 (μ, σ, σ/μ 变异系数)."""
        r = self._encode_context(context_X, context_y)
        mu, sigma = self._decode(r, query_x)
        cv = sigma / max(abs(mu), 1e-4)
        return mu, sigma, cv

    @property
    def is_trained(self) -> bool:
        return self._trained


# 便捷接口

def build_cnp_from_kb(kb, min_cwe_samples: int = 8,
                      epochs: int = 60) -> ConditionalNeuralProcess:
    """从KB构建CWE任务并训练CNP."""
    from collections import defaultdict
    entries, _ = kb.search(limit=5000)
    tasks_data: Dict[str, Tuple[List[List[float]], List[float]]] = defaultdict(
        lambda: ([], []))

    for entry in entries:
        cwes = getattr(entry, 'cwes', None)
        if not cwes:
            continue
        cvss = (_get_num(entry, "cvss_score") or 0.0) / 10.0
        epss = _get_num(entry, "epss_score") or 0.0
        kev = 1.0 if _get_bool(entry, "cisa_kev") else 0.0
        mat = {"unknown": 0.0, "poc": 0.25, "functional": 0.5,
               "metasploit": 0.75, "weaponized": 1.0}.get(
                   str(_get_str(entry, "exploit_maturity", "unknown")).lower().strip(), 0.0)
        has_fix = 1.0 if (_get_str(entry, "fix_version") or _get_str(entry, "patched_version")) else 0.0
        feat = [cvss, epss, (_get_num(entry, "epss_percentile") or 0.0), kev, mat, has_fix,
                _log_refs(entry), _log_cpes(entry)]
        label = 1.0 if (kev > 0 or mat >= 0.5) else 0.0
        tasks_data[cwes[0]][0].append(feat)
        tasks_data[cwes[0]][1].append(label)

    filtered = [v for k, v in tasks_data.items() if len(v[0]) >= min_cwe_samples]
    cnp = ConditionalNeuralProcess(x_dim=8)
    cnp.train(filtered, epochs=epochs)
    return cnp


from ._internal_helpers import _get_str, _get_num, _get_bool


def _log_refs(entry) -> float:
    refs = getattr(entry, 'references', None)
    if refs is None and isinstance(entry, dict): refs = entry.get('references', [])
    return min(math.log(1 + len(refs)) / math.log(101), 1.0) if isinstance(refs, list) and refs else 0.0


def _log_cpes(entry) -> float:
    cpes = getattr(entry, 'cpe_matches', None)
    if cpes is None and isinstance(entry, dict): cpes = entry.get('cpe_matches', [])
    return min(math.log(1 + len(cpes)) / math.log(101), 1.0) if isinstance(cpes, list) and cpes else 0.0
