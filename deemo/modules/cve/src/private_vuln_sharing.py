# 创建: 2025-08-14 20:55
# 修改: 2025-08-14 — Local DP (Laplace+随机化响应) + SimHash + 联邦聚合
"""
隐私保护的漏洞情报共享 — 本地差分隐私 + 相似性保持哈希。

问题: 组织间共享漏洞数据有价值 (发现攻击模式、优先修补),
但直接共享暴露内部资产信息——攻击面、受影响版本、内部网络拓扑。
GDPR/CCPA 等法规进一步限制了原始数据的跨组织传输。

本模块提供隐私保护的双向漏洞情报共享协议:
  1. 本地差分隐私 (Local DP): 在数据离开组织前加噪——不需要可信中心服务器
  2. 相似性保持哈希 (SimHash): 对漏洞描述做降维哈希, 保持相似度可计算
  3. 随机化响应: 对敏感字段 (CVE是否存在于内部资产中) 用随机化响应保护
  4. 联邦聚合: 多方数据聚合时, Laplace 噪声相互抵消, 聚合统计保持准确

为什么选择 Local DP 而非 Central DP:
  漏洞情报的共享方互不信任——不存在一个"完全可信的聚合服务器"。
  Local DP 让每个组织在本地加噪, 不依赖第三方。

隐私预算 (ε) 分配策略:
  总预算 ε = 1.0, 分配:
    - 漏洞存在性字段: ε/3 (随机化响应)
    - 影响版本: ε/3 (Laplace 加噪)
    - CVSS 评分: ε/3 (Laplace 加噪)

ref: Dwork & Roth (2014) "The Algorithmic Foundations of Differential Privacy"
     — ε-DP 的形式定义与 Laplace 机制
ref: Erlingsson et al. (2014) "RAPPOR: Randomized Aggregatable
     Privacy-Preserving Ordinal Response" (CCS) — 随机化响应协议,
     本项目借鉴其 Bloom filter + PRR 设计
ref: arXiv:2604.07125 (2026) — DDP-SA 分布式差分隐私安全聚合,
     本项目取其"先本地加噪再聚合"的架构
ref: Shokri et al. (2012) "Quantifying Location Privacy" (IEEE S&P) —
     差分隐私在安全领域的应用范式
"""

from __future__ import annotations

import math
import random
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional


# --- 本地差分隐私原语 ---

@dataclass
class PrivacyBudget:
    """隐私预算跟踪器。ε 越小 → 隐私保护越强, 数据效用越低。
    典型值: ε=1.0 (中等隐私), ε=0.1 (强隐私)。"""
    total: float = 1.0
    spent: float = 0.0

    def consume(self, amount: float) -> bool:
        if self.spent + amount > self.total:
            return False
        self.spent += amount
        return True

    def remaining(self) -> float:
        return max(0.0, self.total - self.spent)


def laplace_noise(scale: float) -> float:
    """拉普拉斯分布噪声 — 敏感度/ε 为 scale 参数。
    Laplace(0, b): pdf = 1/(2b) * exp(-|x|/b)。"""
    u = random.random() - 0.5
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


def randomized_response(true_value: bool, epsilon: float) -> bool:
    """随机化响应 — 对二值敏感字段的 ε-本地差分隐私保护。

    以概率 p = e^ε/(1+e^ε) 返回真实值, 1-p 返回翻转值。
    ε→∞ → p→1 (不保护), ε→0 → p→0.5 (完全随机)。"""
    p = math.exp(epsilon) / (1.0 + math.exp(epsilon))
    if random.random() < p:
        return true_value
    return not true_value


def privatize_count(true_count: int, sensitivity: float,
                    epsilon: float) -> int:
    """对计数值加 Laplace 噪声 (ε-差分隐私)。
    sensitivity: 单条数据对计数的影响上限 (通常=1)。"""
    scale = sensitivity / max(epsilon, 0.01)
    noise = laplace_noise(scale)
    return max(0, int(round(true_count + noise)))


# --- 漏洞情报记录 ---

@dataclass
class VulnerabilityRecord:
    """单条漏洞情报 — 共享前的内部视图。"""
    cve_id: str = ''
    cvss_score: float = 0.0
    affected: bool = False       # 此 CVE 是否影响本组织 (敏感!)
    patch_applied: bool = False
    exploited_in_wild: bool = False
    detection_method: str = ''   # 'static_analysis' | 'fuzzing' | 'external_feed'
    internal_impact_count: int = 0  # 受影响内部资产数 (敏感!)
    description_hash: str = ''   # SimHash 64-bit for similarity search


@dataclass
class PrivatizedRecord:
    """差分隐私保护后的共享记录。"""
    cve_id: str = ''
    cvss_score: float = 0.0       # +Laplace noise
    affected_rr: bool = False     # 随机化响应
    exploited_in_wild: bool = False
    detection_method: str = ''
    internal_impact_count: int = 0 # +Laplace noise
    simhash: int = 0              # 64-bit 相似性保持哈希
    privacy_budget_consumed: float = 0.0


# --- 相似性保持哈希 (SimHash) ---
# Charikar (STOC 2002): 随机超平面投影 → 保持余弦相似度的二值哈希。
# 64-bit 哈希: 汉明距离 ≤ 3 → 原始描述相似度 ≥ 0.9 (高概率)。

def simhash_64(text: str) -> int:
    """计算文本的 64-bit SimHash。"""
    if not text:
        return 0
    vec = [0] * 64
    tokens = text.lower().split()
    for token in tokens:
        h = hashlib.sha256(token.encode()).digest()
        for i in range(64):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(h) and (h[byte_idx] >> bit_idx) & 1:
                vec[i] += 1
            else:
                vec[i] -= 1
    result = 0
    for i in range(64):
        if vec[i] > 0:
            result |= (1 << i)
    return result


def simhash_distance(a: int, b: int) -> int:
    """两个 SimHash 的汉明距离——距离越小越相似。"""
    return (a ^ b).bit_count()


# --- 私有化引擎 ---

class VulnerabilityPrivatizer:
    """漏洞情报的本地差分隐私引擎。

    每个组织在自己的数据边界内调用此引擎——加噪后的数据才能离开
    组织网络参与共享聚合。"""

    __slots__ = ('_budget', '_epsilon_total')

    def __init__(self, epsilon: float = 1.0):
        self._epsilon_total = epsilon

    def privatize(self, record: VulnerabilityRecord) -> PrivatizedRecord:
        budget = PrivacyBudget(total=self._epsilon_total)
        eps_per_field = self._epsilon_total / 3.0

        # 字段1: 漏洞存在性 (随机化响应)
        budget.consume(eps_per_field)
        affected_rr = randomized_response(record.affected, eps_per_field)

        # 字段2: CVSS 评分 (Laplace 加噪, 敏感度=10/ε)
        budget.consume(eps_per_field)
        noisy_cvss = record.cvss_score + laplace_noise(10.0 / max(eps_per_field, 0.01))
        noisy_cvss = max(0.0, min(10.0, noisy_cvss))

        # 字段3: 影响资产数 (Laplace 加噪, 敏感度=1)
        budget.consume(eps_per_field)
        noisy_impact = privatize_count(
            record.internal_impact_count, sensitivity=1.0,
            epsilon=eps_per_field)

        # SimHash (不消耗隐私预算——description 是公开信息)
        sh = simhash_64(record.description_hash or record.cve_id)

        return PrivatizedRecord(
            cve_id=record.cve_id,
            cvss_score=round(noisy_cvss, 1),
            affected_rr=affected_rr,
            exploited_in_wild=record.exploited_in_wild,
            detection_method=record.detection_method,
            internal_impact_count=noisy_impact,
            simhash=sh,
            privacy_budget_consumed=round(budget.spent, 3),
        )


# --- 联邦聚合器 ---
# 从多个组织的私有化记录中恢复人口级统计。
# Laplace 噪声的均值为 0 → 多方聚合时噪声相互抵消。
# 聚合方差 = m * (scale²), 其中 m 为参与方数量。
# 聚合标准误差 = scale * sqrt(m) / m = scale / sqrt(m)。

class FederatedAggregator:
    """跨组织漏洞情报的隐私保护联邦聚合。

    聚合结果包含:
      - 受影响组织数的无偏估计 (随机化响应可逆)
      - 聚合 CVSS 评分 (均值)
      - 基于 SimHash 的相似漏洞聚类
    """

    __slots__ = ('_records', '_org_count')

    def __init__(self):
        self._records: list[PrivatizedRecord] = []
        self._org_count = 0

    def add_org_records(self, records: list[PrivatizedRecord]) -> None:
        self._records.extend(records)
        self._org_count += 1

    def estimate_affected_orgs(self) -> float:
        """从随机化响应恢复受影响组织数的无偏估计。

        若 p = e^ε/(1+e^ε) 是保留真实值的概率:
        E[observed_true] = p * n_true + (1-p) * n_false
        由此解得 n_true 的无偏估计。"""
        if not self._records:
            return 0.0
        eps_per_field = 1.0 / 3.0  # 假设各组织使用相同 ε
        p = math.exp(eps_per_field) / (1.0 + math.exp(eps_per_field))
        if abs(p - 0.5) < 1e-9:
            return float(len(self._records)) * 0.5

        n_yes = sum(1 for r in self._records if r.affected_rr)
        n_total = len(self._records)
        # n_yes = p * n_true + (1-p) * (n_total - n_true)
        # n_yes = p*n_true + (1-p)*n_total - (1-p)*n_true
        # n_yes = (2p-1)*n_true + (1-p)*n_total
        # n_true = (n_yes - (1-p)*n_total) / (2p-1)
        n_true = (n_yes - (1.0 - p) * n_total) / (2.0 * p - 1.0)
        return max(0.0, min(float(n_total), n_true))

    def aggregate_cvss(self) -> dict:
        """聚合 CVSS 评分统计。Laplace 噪声均值 0 → 均值无偏。"""
        if not self._records:
            return {'mean': 0.0, 'count': 0}
        scores = [r.cvss_score for r in self._records]
        return {
            'mean': round(sum(scores) / len(scores), 2),
            'min': round(min(scores), 1),
            'max': round(max(scores), 1),
            'count': len(scores),
            'noise_std_error': round(10.0 / 0.33 / math.sqrt(len(self._records)), 2),
        }

    def cluster_by_simhash(self, max_distance: int = 6) -> list[list[str]]:
        """基于 SimHash 汉明距离的相似漏洞聚类。
        max_distance=6 → 相似度约 0.9 (64-bit SimHash)。"""
        recs = self._records
        n = len(recs)
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for i in range(n):
            for j in range(i + 1, n):
                if simhash_distance(recs[i].simhash, recs[j].simhash) <= max_distance:
                    union(i, j)

        clusters: dict[int, list[str]] = defaultdict(list)
        for i, r in enumerate(recs):
            clusters[find(i)].append(r.cve_id)

        return [cves for cves in clusters.values() if len(cves) >= 2]

    def stats(self) -> dict:
        return {
            'organizations': self._org_count,
            'total_records': len(self._records),
            'estimated_affected_orgs': round(self.estimate_affected_orgs(), 0),
        }


__all__ = [
    'VulnerabilityRecord', 'PrivatizedRecord', 'PrivacyBudget',
    'VulnerabilityPrivatizer', 'FederatedAggregator',
    'simhash_64', 'simhash_distance', 'randomized_response',
    'laplace_noise',
]
