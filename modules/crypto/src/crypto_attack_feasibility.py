"""
密码学攻击可行性估计 — 从二进制检测到的弱点估算实际攻击复杂度和可利用性。

设计意图:
  既有crypto_misuse报告"此实现使用了硬编码密钥", crypto_aging报告"SHA-1已禁止"。
  但审计者需要的不是缺陷列表, 而是可操作的攻击可行性评估:
    "此弱点能否被实际利用? 需要多少资源? 攻击收益是否值得?"

  CryptAttackTester 在算法设计层做高保证的攻击成本分析 —
  但对二进制实现的审计者而言, 需要的是"从二进制检测到的弱点→攻击路径→
  复杂度→可行性"的快速评估, 而非CAT的严格形式化证明。

  本模块将弱点映射到已知攻击类别:
    - 暴力破解(密钥熵不足): 复杂度=2^(有效熵)。aes-256+time()种子=~31-bit熵。
    - 碰撞攻击(弱哈希): MD5碰撞≈2^18操作; SHA-1≈2^63操作。
    - 数学攻击(小因子/弱曲线): Pohlig-Hellman复杂度=Σ2^(子群bit)。
    - 侧信道(时序/缓存): 所需trace数量≈2倍密钥字节数的统计显著性。
    - 后门利用(Dual_EC_DRBG/陷门): 瞬时(O(1)) — 若持有陷门密钥。

  输出三相可行性:
    - 学术可行(理论界限, 可能在超算/集群上)
    - 实际可行(商用硬件AWS/GCP, 预算$10K-$1M)
    - 即时可利用(笔记本电脑, <24小时, <$100)

  - CryptAttackTester: 高保证攻击成本量化 — 本模块做近似估计。
  - NIST SP 800-57 Pt.1 Rev.5: 密钥管理 — 安全强度与攻击成本对照。
  - ATT&CK for ICS: 攻击可行性分类方法论。

边界条件:
  - 攻击复杂度估算为数量级近似 — 不精确到常数因子。
  - 某些攻击的实际可行性取决于对实现的额外假设(如物理访问需求)。
  - 组合攻击(如侧信道+数学攻击)的复杂度未建模 — 取最低者。
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class FeasibilityLevel(Enum):
    TRIVIAL = 0       # 笔记本电脑, <1小时, <$10
    PRACTICAL = 1     # 商用硬件, <1周, <$10K
    ACADEMIC = 2      # 需要集群/超算, <1年, <$1M
    THEORETICAL = 3   # 计算上不可行(>2^100), 但数学上存在攻击路径
    NOT_FEASIBLE = 4  # 无已知攻击路径

@dataclass
class AttackEstimate:
    attack_name: str = ""
    attack_category: str = ""        # BRUTE_FORCE / COLLISION / SIDE_CHANNEL / MATH / TRAPDOOR
    target_algorithm: str = ""
    weakness_exploited: str = ""     # 被利用的弱点描述
    complexity_bits: float = 0.0     # log2(所需操作/查询/trace数量)
    estimated_time: str = ""         # "1 hour" / "3 days" / "2 years" / "infeasible"
    estimated_cost: str = ""         # "$10" / "$5K" / "$500K" / "N/A"
    feasibility: FeasibilityLevel = FeasibilityLevel.THEORETICAL
    prerequisites: List[str] = field(default_factory=list)
    mitigation: str = ""

# 攻击复杂度参考表
# 硬件假设: 1台AWS p4d.24xlarge ≈ 2^40 ops/s; 1台普通笔记本 ≈ 2^30 ops/s
# 成本: $1/小时的GPU ≈ 2^40 ops; 1年集群=$10M ≈ 2^90 ops
# 时间边界: 1天=2^16秒, 1周=2^19秒, 1年=2^25秒

_OPS_PER_SECOND_LAPTOP = 2**30     # ~10亿op/s
_OPS_PER_SECOND_CLUSTER = 2**50    # ~1e15 op/s (大规模GPU集群)
_OPS_PER_SECOND_SUPERCOMPUTER = 2**60  # ~1e18 op/s

def _estimate_from_complexity(bits: float) -> Tuple[FeasibilityLevel, str, str]:
    """从攻击复杂度(bits)估算时间/成本/可行性。"""
    if bits <= 20:
        ops = 2**bits
        sec = ops / _OPS_PER_SECOND_LAPTOP
        return (FeasibilityLevel.TRIVIAL,
                '<1 second' if sec < 1 else f'{sec:.0f} seconds',
                '<$1')
    elif bits <= 40:
        ops = 2**bits
        sec = ops / _OPS_PER_SECOND_LAPTOP
        hours = sec / 3600
        cost = hours * 0.5  # 笔记本电费
        return (FeasibilityLevel.TRIVIAL,
                f'{hours:.1f} hours' if hours < 24 else f'{hours/24:.1f} days',
                f'~${cost:.0f}')
    elif bits <= 60:
        ops = 2**bits
        sec = ops / _OPS_PER_SECOND_CLUSTER
        days = sec / 86400
        cost_per_day = 500  # GPU集群≈$500/天
        return (FeasibilityLevel.PRACTICAL,
                f'{days:.1f} days' if days < 30 else f'{days/30:.1f} months',
                f'~${days * cost_per_day:,.0f}')
    elif bits <= 90:
        ops = 2**bits
        sec = ops / _OPS_PER_SECOND_CLUSTER
        days = sec / 86400
        return (FeasibilityLevel.ACADEMIC,
                f'{days:.1f} days' if days < 365 else f'{days/365:.1f} years',
                '~$100K–$1M')
    elif bits <= 112:
        return (FeasibilityLevel.THEORETICAL,
                '>10 years on current hardware', '>$10M')
    else:
        return (FeasibilityLevel.NOT_FEASIBLE,
                '>100 years', '>$1B (economically irrational)')

def _estimate_brute_force(algo: str, details: str = '') -> AttackEstimate:
    """估算暴力破解攻击的可行性。"""
    key_bits = 128  # 默认
    if '256' in algo:
        key_bits = 256
    elif '128' in algo:
        key_bits = 128
    elif 'DES' in algo:
        key_bits = 56
    elif '3DES' in algo:
        key_bits = 112

    # 弱熵源退化的有效密钥熵
    if '弱熵源' in details or 'time' in details.lower():
        effective_bits = 31  # time(NULL) ≈ 31-bit熵
    elif '弱密码' in details or 'password' in details.lower():
        effective_bits = 20  # 典型密码≈20-bit熵
    else:
        effective_bits = key_bits

    level, time_str, cost_str = _estimate_from_complexity(effective_bits)
    return AttackEstimate(
        attack_name=f'{algo} brute-force',
        attack_category='BRUTE_FORCE',
        target_algorithm=algo,
        weakness_exploited=f'密钥有效熵≈{effective_bits}bit' if effective_bits < key_bits
        else f'{key_bits}bit穷举搜索',
        complexity_bits=float(effective_bits),
        estimated_time=time_str, estimated_cost=cost_str,
        feasibility=level,
        prerequisites=['已知密文+对应的明文块(已知明文攻击)'],
        mitigation='使用256-bit密钥; 使用硬件TRNG生成密钥')

def _estimate_collision(algo: str) -> AttackEstimate:
    """估算哈希碰撞攻击的可行性。"""
    collision_bits = {'MD5': 18, 'SHA-1': 63, 'SHA-256': 128, 'SHA-512': 256}
    bits = collision_bits.get(algo, 128)
    level, time_str, cost_str = _estimate_from_complexity(float(bits))
    return AttackEstimate(
        attack_name=f'{algo} collision attack',
        attack_category='COLLISION',
        target_algorithm=algo,
        weakness_exploited=f'碰撞复杂度≈2^{bits}',
        complexity_bits=float(bits),
        estimated_time=time_str, estimated_cost=cost_str,
        feasibility=level,
        prerequisites=['选择前缀碰撞能力'],
        mitigation=f'替换为SHA-384/SHA-512/BLAKE2b')

def _estimate_side_channel(leakage_report=None) -> Optional[AttackEstimate]:
    """估算侧信道攻击的可行性。"""
    if leakage_report is None:
        return None

    try:
        score = getattr(leakage_report, 'composite_score', 0.5)
    except Exception:
        return None

    if score < 0.3:
        # 泄漏潜力低 → 需要大量trace
        traces_needed = 2**20
    elif score < 0.5:
        traces_needed = 2**14
    elif score < 0.7:
        traces_needed = 2**10
    else:
        traces_needed = 2**5

    bits = math.log2(traces_needed)
    level, time_str, cost_str = _estimate_from_complexity(bits + 6)
    return AttackEstimate(
        attack_name='Side-channel key extraction',
        attack_category='SIDE_CHANNEL',
        target_algorithm='DETECTED',
        weakness_exploited=f'{traces_needed}次trace测量可恢复密钥(泄漏评分{score:.2f})',
        complexity_bits=bits + 6,
        estimated_time=time_str, estimated_cost=cost_str,
        feasibility=level,
        prerequisites=['目标设备的物理/远程侧信道访问', '已知明文/密文对'],
        mitigation='实现常量时间代码; 添加随机延迟/掩码; 使用硬件侧信道对策')

def assess_attack_feasibility(
        algo_names: Optional[List[str]] = None,
        crypto_findings: Optional[List] = None,
        leakage_report=None,
        backdoor_findings: Optional[List] = None,
        entropy_reports: Optional[List] = None,
) -> List[AttackEstimate]:
    """综合评估检测到的弱点对应的攻击可行性。"""
    estimates: List[AttackEstimate] = []
    algos = algo_names or []

    if crypto_findings:
        for f in crypto_findings:
            try:
                algos.append(getattr(f, 'algorithm', ''))
            except Exception:
                pass

    for algo in algos:
        # 暴力破解评估
        if any(kw in algo for kw in ('AES', 'DES', '3DES', 'ChaCha', 'SM4')):
            has_weak_entropy = False
            if entropy_reports:
                for er in entropy_reports:
                    try:
                        if getattr(er, 'grade', None):
                            if er.grade.name in ('LOW', 'CRITICAL'):
                                has_weak_entropy = True
                    except Exception:
                        pass
            detail = '弱熵源(time/pid)' if has_weak_entropy else ''
            estimates.append(_estimate_brute_force(algo, detail))

        # 碰撞评估
        if any(kw in algo for kw in ('MD5', 'SHA-1')):
            estimates.append(_estimate_collision(algo))

    # 侧信道评估
    if leakage_report:
        sc_est = _estimate_side_channel(leakage_report)
        if sc_est:
            estimates.append(sc_est)

    # 后门利用(若检测到)
    for bf in backdoor_findings or []:
        try:
            sev = getattr(bf, 'severity', 'MEDIUM')
            if sev in ('CRITICAL', 'HIGH'):
                estimates.append(AttackEstimate(
                    attack_name='Cryptographic backdoor exploitation',
                    attack_category='TRAPDOOR',
                    target_algorithm=getattr(bf, 'algorithm', 'UNKNOWN'),
                    weakness_exploited=getattr(bf, 'detail', 'dual EC or trapdoor structure'),
                    complexity_bits=0, estimated_time='instantaneous',
                    estimated_cost='$0 (if trapdoor known)',
                    feasibility=FeasibilityLevel.TRIVIAL,
                    prerequisites=['陷门知识(Dual_EC_DRBG: e使得Q=e*P)'],
                    mitigation='立即替换实现; 审计供应链来源'))
        except Exception:
            pass

    estimates.sort(key=lambda e: e.complexity_bits)
    return estimates
