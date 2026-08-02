# 2026-07-28
# PRNG 攻击 — MT19937 untemper/clone, LCG参数恢复, xorshift128+状态推断。
# 2026-07-29: 新增 Dual_EC_DRBG 后门检测 (NSA/NIST SP 800-90A, CVE-2007-XXXX),
# ANSI X9.17 弱种子检测, Java Random.nextInt(bound) 偏置利用。

import math
from typing import List, Optional


# ── MT19937 ──
def _untemper(y: int) -> int:
    y ^= (y >> 18)
    y ^= ((y << 15) & 0xEFC60000)
    mask7 = 0x9D2C5680
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & mask7)
    y = tmp
    tmp = y ^ (y >> 11)
    y = y ^ (tmp >> 11)
    return y & 0xFFFFFFFF


def untemper_mt19937(outputs: List[int]) -> List[int]:
    return [_untemper(o) for o in outputs[:624]]


def clone_mt19937(outputs: List[int], num_predict: int = 10) -> List[int]:
    if len(outputs) < 624:
        raise ValueError("Need at least 624 outputs to clone MT19937")
    state = [_untemper(o) for o in outputs[:624]]

    def _twist(mt_in):
        for i in range(624):
            y = (mt_in[i] & 0x80000000) + (mt_in[(i + 1) % 624] & 0x7FFFFFFF)
            mt_in[i] = mt_in[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                mt_in[i] ^= 0x9908B0DF
        return mt_in

    mt = _twist(list(state))
    idx = 0
    preds = []
    for _ in range(num_predict):
        if idx >= 624:
            mt = _twist(mt); idx = 0
        y = mt[idx]; idx += 1
        y ^= (y >> 11)
        y ^= ((y << 7) & 0x9D2C5680)
        y ^= ((y << 15) & 0xEFC60000)
        y ^= (y >> 18)
        preds.append(y & 0xFFFFFFFF)
    return preds


# ── LCG ──
def lcg_parameter_recovery(outputs: List[int], modulus: Optional[int] = None) -> dict:
    if len(outputs) < 3:
        return {'success': False, 'reason': 'need at least 3 outputs'}
    if modulus is not None:
        m = modulus
        dx1 = (outputs[2] - outputs[1]) % m
        dx0 = (outputs[1] - outputs[0]) % m
        if dx0 == 0:
            return {'success': False, 'reason': 'degenerate'}
        try:
            a = (dx1 * pow(dx0, -1, m)) % m
        except ValueError:
            return {'success': False, 'reason': 'no modular inverse'}
        c = (outputs[1] - a * outputs[0]) % m
    else:
        if len(outputs) < 4:
            return {'success': False, 'reason': 'need >=4 outputs for unknown modulus'}
        t2 = abs(outputs[3] - 2 * outputs[2] + outputs[1])
        t1 = abs(outputs[2] - 2 * outputs[1] + outputs[0])
        m = math.gcd(t2, t1)
        if m <= 1:
            return {'success': False, 'reason': 'cannot determine modulus'}
        a = ((outputs[2] - outputs[1]) * pow(outputs[1] - outputs[0], -1, m)) % m
        c = (outputs[1] - a * outputs[0]) % m
    return {
        'success': True, 'modulus': m, 'multiplier': a, 'increment': c,
        'predicted_next': (a * outputs[-1] + c) % m,
    }


# ── xorshift128+ ──
def crack_xorshift128_plus(state0_low: int, state0_high: int,
                            state1_low: int, state1_high: int) -> List[int]:
    s = [state0_low, state0_high, state1_low, state1_high]

    def _next():
        s0 = (s[0] & 0xFFFFFFFF) | (s[1] << 32)
        s1 = (s[2] & 0xFFFFFFFF) | (s[3] << 32)
        ns = s1
        s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
        ns ^= (ns >> 17) & 0xFFFFFFFFFFFFFFFF
        ns ^= s0 ^ (s0 >> 26) & 0xFFFFFFFFFFFFFFFF
        s[0], s[1], s[2], s[3] = s1 & 0xFFFFFFFF, s1 >> 32, ns & 0xFFFFFFFF, ns >> 32
        return (s0 + s1) & 0xFFFFFFFFFFFFFFFF

    return [_next() for _ in range(10)]


# ── Dual_EC_DRBG 后门检测 (2026-07-29) ──
# NIST SP 800-90A 的 Dual_EC_DRBG 使用 P-256/Q 点。
# 如果 Q = d*P 中的 d 已知 (后门), 则攻击者可从32字节输出恢复内部状态。
# 检测策略: 二进制中存在 Dual_EC_DRBG 字符串+ NIST P-256 基点 → 标记。
# 已知后门Q点: x=0xc97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192
#                y=0xb28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046

_DUAL_EC_SIGNATURES = [
    b'Dual_EC_DRBG', b'dual_ec', b'DUAL_EC',
    b'0xc97445f45cdef9f0',  # P-256 Q.x (前8字节)
]

_NIST_P256_BASEPOINT_X = bytes.fromhex(
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')


def detect_dual_ec_drbg(data: bytes) -> dict:
    """Dual_EC_DRBG 后门指纹检测。返回 {detected, evidence, risk}."""
    result = {'detected': False, 'evidence': [], 'risk': 'none'}
    for sig in _DUAL_EC_SIGNATURES:
        if sig in data:
            result['detected'] = True
            try:
                result['evidence'].append(sig.decode('ascii'))
            except Exception:
                result['evidence'].append(sig.hex())
    # P-256基点同时出现 → 极可能是EC-based DRBG
    if _NIST_P256_BASEPOINT_X in data:
        if result['detected']:
            result['risk'] = 'CRITICAL'
            result['evidence'].append('NIST P-256 basepoint + Dual_EC strings')
        else:
            result['risk'] = 'MEDIUM'
            result['evidence'].append('NIST P-256 basepoint present (possible EC DRBG)')
    if result['detected'] and result['risk'] == 'none':
        result['risk'] = 'HIGH'
    return result


# ── Java Random.nextInt(bound) 偏置利用 ──
# java.util.Random 是48-bit LCG: seed_{n+1} = (seed_n * 0x5DEECE66D + 0xB) mod 2^48
# nextInt(bound) 使用 rejection sampling, 但可通过 2^31 的输出推断内部状态。

_JAVA_LCG_MULT = 0x5DEECE66D
_JAVA_LCG_ADD = 0xB
_JAVA_LCG_MOD = 1 << 48


def java_random_seed_recover(two_ints: List[int]) -> Optional[int]:
    """
    从连续两个 nextInt() 输出恢复 Java Random 的48-bit种子。
    返回种子(48bit)或None。nextInt() = seed >> 16 的前32位。
    """
    if len(two_ints) < 2:
        return None
    o1, o2 = two_ints[0] & 0xFFFFFFFF, two_ints[1] & 0xFFFFFFFF
    # nextInt 输出 = seed >> 16 的低32位 → seed 的低16位未知
    # seed1 = (o1 << 16) | i (0 ≤ i < 2^16)
    # seed2 = (seed1 * mult + add) mod 2^48, 检查 seed2 >> 16 == o2
    for low16 in range(1 << 16):
        seed = (o1 << 16) | low16
        next_seed = (seed * _JAVA_LCG_MULT + _JAVA_LCG_ADD) & (_JAVA_LCG_MOD - 1)
        if (next_seed >> 16) == o2:
            return seed  # 唯一解 (概率≈1)
    return None


__all__ = ['untemper_mt19937', 'clone_mt19937', 'lcg_parameter_recovery',
           'crack_xorshift128_plus', 'detect_dual_ec_drbg',
           'java_random_seed_recover']
