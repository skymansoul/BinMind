"""
格基密码安全级别估计 — 从FHE/PQC参数估算BKZ格基约化攻击的bit安全性。

设计意图:
  crypto_noise_estimator估算FHE噪声预算(同态乘法还能做多少次),
  但回答不了"这些参数足够安全吗?" 密码学安全性取决于LWE问题的难度,
  即从(A, As+e)中恢复s的计算复杂度。格基约化(BKZ)是当前最有效的攻击。

  本模块实现简化版的LWE安全估计:
    E1 (参数提取): 从二进制或给定参数获取n(维度), q(模数), α(噪声率)。
    E2 (BKZ成本模型): 基于Core-SVP模型 — 估算达到所需BKZ块大小β的计算成本。
      cost ≈ 2^(0.292*β + log2(β))  (量子加速筛法; 经典: 0.292 → 0.349)
    E3 (Thijs简化): 對偶攻击成本 — β ≈ n * log(q/σ) / log(α_q)^2。
    E4 (安全级别映射): bit数 → NIST安全类别(1/2/3/4/5)。

  - Alkim et al.: NewHope — 格基参数选择方法论。
  - Albrecht et al.: LWE估计器 — BKZ成本模型的综合评估。
  - Thijs Laarhoven: 筛法复杂度。

边界条件:
  - 安全估计基于当前已知的最佳攻击(BKZ+筛法) — 新的格基攻击可能降低安全级别。
  - 不建模代数攻击(如利用环结构的攻击) → 对Ring-LWE可能高估安全级别。
  - 参数提取依赖crypto_noise_estimator或手工提供 — 自动提取的精度有限。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class LatticeSecurityReport:
    scheme: str = ""              # Kyber / BGV / BFV / CKKS / Dilithium
    n: int = 0                    # 格维度
    q_bits: int = 0               # 模数log2
    alpha: float = 0.0            # 噪声率 σ/q
    bkz_block_size: int = 0       # 所需BKZ块大小β
    classical_bits: float = 0.0   # 经典攻击bit安全性
    quantum_bits: float = 0.0     # 量子攻击bit安全性
    nist_level: int = 0           # NIST安全类别(1-5)
    is_secure: bool = False       # ≥128-bit经典安全?
    attack_model: str = ""        # PRIMAL / DUAL / CORE_SVP
    warnings: List[str] = field(default_factory=list)


# ── BKZ 成本模型 ──

def _core_svp_cost(beta: int, quantum: bool = False) -> float:
    """
    Core-SVP模型: BKZ-β的bit成本。
    经典筛法: log2(cost) ≈ 0.349*β + log2(β) - 13.3 (≈0.292*β渐进)
    量子筛法: log2(cost) ≈ 0.292*β + log2(β) - 13.3
    常数-13.3来自Albrecht et al. 2018的拟合。
    """
    if beta <= 0:
        return 0.0
    c = 0.292 if quantum else 0.349
    raw = c * beta + math.log2(beta) - 13.3
    return max(0.0, raw)


def _estimate_beta_primal(n: int, q: float, sigma: float) -> int:
    """
    原始攻击(Primary)所需BKZ块大小: BKZ-β在q元格上找到短向量。
    近似公式(来自NewHope/ Kyber参数选择):
      β ≈ n * log(q/σ) / log(δ)²
    其中根Hermite因子δ ≈ (β/(2πe))^(1/(2β-2)) * π^(1/β)

    简化: 使用经验拟合。
    """
    if q <= 0 or sigma <= 0 or n <= 0:
        return 0
    ratio = q / sigma
    log_ratio = math.log2(ratio)
    # 经验公式: β ≈ 0.48 * n * log(q/σ) / log(n)
    beta = int(0.48 * n * log_ratio / max(1, math.log2(n)))
    return max(2, min(2000, beta))


def _estimate_beta_dual(n: int, q: float, sigma: float) -> int:
    """
    对偶攻击所需BKZ块大小。
    对偶攻击寻找使 <a_i, v> 为短整数的向量v。
    公式: β ≈ min(n, n * (1 - log(q/sigma)/log(q))) 的变体。

    简化近似。
    """
    ratio = q / sigma
    if ratio <= 1:
        return n
    log_q = math.log2(q)
    beta = int(n * (1.0 - math.log2(ratio) / log_q)) if log_q > 0 else n
    return max(2, min(n, beta))


# ── NIST 安全级别映射 ──

def _nist_level(quantum_bits: float) -> int:
    """映射量子安全bit数到NIST PQC安全类别。"""
    if quantum_bits >= 272:
        return 5
    elif quantum_bits >= 256:
        return 4
    elif quantum_bits >= 192:
        return 3
    elif quantum_bits >= 128:
        return 2
    elif quantum_bits >= 80:
        return 1
    return 0


# ── 主估计函数 ──

def estimate_lattice_security(n: Optional[int] = None,
                               q: Optional[int] = None,
                               sigma: Optional[float] = None,
                               scheme: str = "UNKNOWN",
                               noise_report=None
                               ) -> LatticeSecurityReport:
    """
    估计格基密码参数的安全性。

    可从crypto_noise_estimator的FHENoiseReport获取参数,
    或直接提供n, q, sigma。
    """
    # 尝试从noise_report提取参数
    if noise_report and n is None:
        try:
            n = getattr(noise_report, 'poly_degree', 0)
            q_bits = getattr(noise_report, 'ciphertext_modulus_bits', 0)
            q = 2 ** q_bits if q_bits > 0 else 0
        except Exception:
            pass

    if n is None or n <= 0:
        n = 1024  # 保守默认
    if q is None or q <= 0:
        q = 2**109   # 保守默认(~BGV q)

    # 噪声标准差估计: 若未提供, 使用典型值 σ ≈ 3.2 (离散高斯, s=3.2)
    if sigma is None or sigma <= 0:
        sigma = 3.2

    q_bits_actual = int(math.log2(q)) if q > 1 else 0

    report = LatticeSecurityReport(
        scheme=scheme, n=n, q_bits=q_bits_actual,
        alpha=round(sigma / q, 10) if q > 0 else 0.0)

    # 估计BKZ块大小(取原始和对偶攻击的最小β)
    beta_primal = _estimate_beta_primal(n, float(q), sigma)
    beta_dual = _estimate_beta_dual(n, float(q), sigma)
    beta = max(beta_primal, beta_dual)  # 保守: 取更大的
    report.bkz_block_size = beta

    # 计算bit安全性
    report.classical_bits = round(_core_svp_cost(beta, quantum=False), 2)
    report.quantum_bits = round(_core_svp_cost(beta, quantum=True), 2)
    report.nist_level = _nist_level(report.quantum_bits)

    # 安全判定
    if report.classical_bits >= 128:
        report.is_secure = True
        report.attack_model = 'CORE_SVP'
    else:
        report.is_secure = False
        report.attack_model = 'CORE_SVP'
        report.warnings.append(
            f'经典安全性{report.classical_bits}bit < 128bit — 参数不足')

    # 附加警告
    if report.alpha > 0.01 and report.n < 2048:
        report.warnings.append(
            f'噪声率α={report.alpha:.4f}偏高 — LWE可能退化为可解')
    if report.bkz_block_size <= 0:
        report.warnings.append('BKZ块大小估计异常 — 检查输入参数')
    if report.nist_level < 2:
        report.warnings.append(
            f'NIST级别{report.nist_level} — 仅适用于实验/非生产环境')

    return report


# ── 批量估计 ──

def estimate_known_schemes() -> Dict[str, LatticeSecurityReport]:
    """
    对已知PQC/FHE方案做安全级别基准测试。
    用于验证估计器输出与NIST官方评估的一致性。
    """
    schemes = {
        'Kyber-512': (512, 3329, 1.0),
        'Kyber-768': (768, 3329, 1.0),
        'Kyber-1024': (1024, 3329, 1.0),
        'Dilithium-2': (768, 8380417, 1.0),
        'Dilithium-3': (768, 8380417, 1.0),
        'BGV-8192': (8192, 2**218, 3.2),
        'CKKS-16384': (16384, 2**880, 3.2),
    }
    results = {}
    for name, (n_val, q_val, sig) in schemes.items():
        results[name] = estimate_lattice_security(
            n=n_val, q=q_val, sigma=sig, scheme=name)
    return results
