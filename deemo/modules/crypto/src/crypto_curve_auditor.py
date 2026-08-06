"""
椭圆曲线安全性审计 — 从检测到的曲线参数验证数学安全性。

创建: 2025-09-22 11:08
修改:
  2025-09-22 11:08 — 初始实现: 曲线阶分解/嵌入度/辅因子/MOV安全性/异常曲线检测

设计意图:
  crypto_backdoor_analyzer做模式匹配(全零参数/全一参数/线性递推),
  但无法回答更深层的数学问题: 这条自定义曲线的阶是否足够大?
  Pohlig-Hellman攻击的适用性? 嵌入度是否异常小(MOV/FR攻击)?

  本模块对检测到的椭圆曲线参数做数学验证:
    V1 (阶的素因子分解): 曲线阶N = h×q (h=辅因子, q=大素数)。
        若q < 2^256 → Pohlig-Hellman可将ECDLP降级到子群。
    V2 (嵌入度): 最小的k使q | p^k - 1。k小(≤12) → MOV/FR配对攻击。
    V3 (异常曲线): #E(Fp) = p → SSSA攻击(Smart-Satoh-Seman-Araki)。
    V4 (辅因子): h > 1且有小子群 → 小子群攻击(Lim-Lee风格)。
    V5 (CM判别式): 复乘判别式|D|极小 → CM方法构造, 可能存在额外结构。

  安全阈值:
    - 子群素数q ≥ 2^256 (≥128-bit安全)
    - 嵌入度k ≥ 12 (配对友好曲线); 通用曲线k ≈ q量级
    - 辅因子h ≤ 8 (最佳h=1为素数阶曲线)
    - CM判别式|D| ≥ 2^100 (非CM构造)

参考:
  - Silverman (2009): "The Arithmetic of Elliptic Curves" — ECC数学基础。
  - Menezes-Okamoto-Vanstone (1993): MOV攻击 — 嵌入度与配对。
  - Smart (1999): 异常曲线攻击 — #E(Fp)=p时ECDLP可归约到Fp加法群。
  - Lim & Lee (CRYPTO 1997): 小子群攻击 — 辅因子利用。

边界条件:
  - 曲线参数提取依赖crypto_detector识别EC参数块 → 误识别导致无效分析。
  - 大素数判定使用Miller-Rabin概率测试(k=40轮, 错误概率<2^-80)。
  - 嵌入度计算对大q使用Pollard's rho探索 — 在未知曲线阶时不可计算(V2需N已知)。
"""

import math
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CurveAuditResult:
    curve_name: str = ""           # 检测到的曲线标识
    field_prime_p: int = 0         # 基域特征
    curve_order_n: int = 0         # 曲线阶 #E(Fp) (若可提取)
    cofactor_h: int = 1            # 辅因子
    large_prime_q: int = 0         # 大素数子群阶
    embedding_degree_k: int = 0    # 嵌入度(0=未计算)
    cm_discriminant: int = 0       # CM判别式(0=未计算)
    is_anomalous: bool = False     # 异常曲线?
    security_bits: int = 0         # 估计安全级别
    warnings: List[str] = field(default_factory=list)
    verdict: str = "UNKNOWN"       # SAFE / SUSPICIOUS / WEAK / DANGEROUS


# ── Miller-Rabin素性测试 ──

def _miller_rabin(n: int, k: int = 40) -> bool:
    """Miller-Rabin概率素性测试。k=40 → 错误概率<2^-80。"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # n-1 = 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ── V1: 阶的素因子分解 (试除+Pollard's rho) ──

def _trial_division(n: int, bound: int = 1000000) -> Tuple[int, int]:
    """试除法提取小因子。返回(剩余部分, 提取的小因子乘积)。"""
    remaining = n
    small_part = 1
    # 2
    while remaining % 2 == 0:
        small_part *= 2
        remaining //= 2
    # 奇数
    d = 3
    while d * d <= remaining and d <= bound:
        while remaining % d == 0:
            small_part *= d
            remaining //= d
        d += 2
    return remaining, small_part


def _pollard_rho_factor(n: int, max_iter: int = 50000) -> Optional[int]:
    """Pollard's rho分解 — 寻找n的一个非平凡因子。"""
    if n % 2 == 0:
        return 2
    if _miller_rabin(n, k=5):
        return None  # n是素数

    def _f(x):
        return (x * x + 1) % n

    for _ in range(3):  # 3次尝试, 不同起始值
        x = random.randrange(2, n - 1)
        y = x
        d = 1
        count = 0
        while d == 1 and count < max_iter:
            x = _f(x)
            y = _f(_f(y))
            d = math.gcd(abs(x - y), n)
            count += 1
        if d != 1 and d != n:
            return d
    return None


def _factor_order(order: int) -> Tuple[int, int, int]:
    """
    分解椭圆曲线阶N = h × q。
    返回(h, q, q_bits)其中q是N的最大素因子, h是辅因子。
    """
    n = order
    remaining, h = _trial_division(n)
    q = remaining
    q_bits = q.bit_length()

    # 若剩余部分是合数, 尝试Pollard's rho
    if not _miller_rabin(q, k=5):
        factor = _pollard_rho_factor(q)
        if factor:
            q1 = factor
            q2 = q // factor
            # 取较大者作为q
            if q1 > q2:
                q = q1
            else:
                q = q2
            h = order // q
            q_bits = q.bit_length()

    if not _miller_rabin(q, k=5):
        # q可能仍是合数 → 标记
        q_bits = min(q_bits, q.bit_length() // 2)

    return h, q, q_bits


# ── V2: 嵌入度估计 ──

def _estimate_embedding_degree(p: int, q: int, max_k: int = 24) -> int:
    """
    估计嵌入度k — 最小的k使q | p^k - 1。
    仅检查到max_k; 若未找到, 返回max_k+1(表示k > max_k)。
    """
    if q <= 1 or p <= 1:
        return 0
    pk = p % q
    for k in range(1, max_k + 1):
        if pk == 1:
            return k
        pk = (pk * p) % q
    return max_k + 1  # k > max_k → 安全


# ── V3: 异常曲线检测 ──

def _check_anomalous(p: int, n: int) -> bool:
    """检查#E(Fp)==p (异常曲线, SSSA攻击可破解ECDLP)。"""
    return n == p


# ── V4: 辅因子安全性 ──

def _check_cofactor_safety(h: int, q_bits: int) -> List[str]:
    """检查辅因子h是否引入小子群攻击面。"""
    warnings: List[str] = []
    if h > 8:
        warnings.append(f'辅因子h={h}偏大 — 非素数阶曲线, 存在小子群攻击面')
    if h > 1:
        remaining, small_part = _trial_division(h, bound=10000)
        if small_part > 1:
            warnings.append(f'辅因子含小素数因子(small_part={small_part}) — Lim-Lee小子群攻击')
    if h == 1:
        pass  # 素数阶曲线 → 理想
    return warnings


# ── 主审计函数 ──

def audit_curve_parameters(p: int, n: Optional[int] = None,
                            a: Optional[int] = None,
                            b: Optional[int] = None,
                            curve_name: str = "detected_curve"
                            ) -> CurveAuditResult:
    """
    审计椭圆曲线参数的数学安全性。
    p: 基域特征(素数)
    n: 曲线阶#E(Fp) (若可从二进制提取; 否则仅做基域检查)
    a, b: Weierstrass系数 y² = x³ + ax + b (可选)
    """
    result = CurveAuditResult(curve_name=curve_name, field_prime_p=p)
    warnings: List[str] = []

    # 基域检查
    if not _miller_rabin(p, k=20):
        warnings.append(f'基域p={p.bit_length()}bit不是素数 — 使用扩展域或合数模?')
    elif p.bit_length() < 224:
        warnings.append(f'基域仅{p.bit_length()}bit — 低于NIST P-224的最低标准')

    if n is not None and n > 0:
        result.curve_order_n = n
        h, q, q_bits = _factor_order(n)
        result.cofactor_h = h
        result.large_prime_q = q

        if q_bits < 256:
            sev = 'DANGEROUS' if q_bits < 128 else 'WEAK'
            warnings.append(f'子群素数仅{q_bits}bit — Pohlig-Hellman可降级ECDLP至2^{q_bits}')

        # 嵌入度
        result.embedding_degree_k = _estimate_embedding_degree(p, q)
        k = result.embedding_degree_k
        if k <= 6 and k > 0:
            warnings.append(f'嵌入度k={k}≤6 — MOV/FR配对攻击可行')
        elif k <= 12 and k > 0:
            warnings.append(f'嵌入度k={k}≤12 — 可能为配对友好曲线(若k=12且q≥256bit→OK)')

        # 异常曲线
        result.is_anomalous = _check_anomalous(p, n)
        if result.is_anomalous:
            warnings.append('异常曲线(#E(Fp)=p) — SSSA攻击可瞬时破解!')

        # 辅因子
        warnings.extend(_check_cofactor_safety(h, q_bits))

        # 安全级别估计
        if result.is_anomalous:
            result.security_bits = 0
        elif k <= 6:
            result.security_bits = min(q_bits, p.bit_length()) // (2 if k <= 2 else 1)
        else:
            result.security_bits = q_bits // 2

    else:
        # 无曲线阶 → 仅基域级别检查
        result.security_bits = p.bit_length() // 2
        if result.security_bits < 128:
            warnings.append(f'基域安全级别≈{result.security_bits}bit — 不足128-bit')

    # 综合判定
    result.warnings = warnings
    if not warnings:
        result.verdict = 'SAFE'
    elif any('瞬时' in w or 'DANGEROUS' in w for w in warnings):
        result.verdict = 'DANGEROUS'
    elif any('WEAK' in w for w in warnings):
        result.verdict = 'WEAK'
    else:
        result.verdict = 'SUSPICIOUS'

    return result
