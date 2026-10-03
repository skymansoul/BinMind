# 椭圆曲线攻击 — ECDSA nonce重用/偏置, invalid curve, twist攻击, small-subgroup。
# SEC 1/2, Bernstein "How to Design an ECDSA System", Bitcoin nonce-reuse corpus,
# Biehl-Meyer-Muller "Differential Fault Attacks on ECC" (2000), Bos-Halderman et al. (2014).

import hashlib
from io import StringIO
from typing import List, Tuple, Optional


# ---- ECDSA nonce重用 (k-reuse) 私钥恢复 ----
# 同一私钥对两条不同消息使用相同k(nonce):
#   s1 = k^-1 * (z1 + r*d),  s2 = k^-1 * (z2 + r*d)
#   k = (z1 - z2) / (s1 - s2) mod n
#   d = (s1*k - z1) / r mod n
# 已知r/s/z, 私钥d可直接计算。
# 注: z = hash(message)的前L_n位(n = curve order bit-length)。

def ecdsa_recover_private_key_from_k_reuse(
    r: int, s1: int, s2: int,
    z1: int, z2: int, curve_order: int
) -> Optional[int]:
    """
    从nonce重用的两条ECDSA签名恢复私钥d。
    返回私钥d或None (签名格式错误或nonce确实不同)。
    """
    if r <= 0 or r >= curve_order:
        return None
    try:
        # k = (z1 - z2) * (s1 - s2)^(-1) mod n
        z_diff = (z1 - z2) % curve_order
        s_diff = (s1 - s2) % curve_order
        if s_diff == 0:
            return None  # nonce确实不同, 无法恢复
        k = (z_diff * pow(s_diff, -1, curve_order)) % curve_order
        # d = (s1 * k - z1) / r mod n
        d = ((s1 * k - z1) % curve_order) * pow(r, -1, curve_order) % curve_order
        return d
    except (ValueError, ZeroDivisionError):
        return None


# ---- ECDSA nonce偏置 (partial k leakage) ----
# nonce k的高位或低位已知(如硬件RNG仅31-bit有效), 可用格归约(LLL/BKZ)恢复。
# 简化版: 给定k高位known_hi和低位零长度zero_low_bits, 枚举中间未知比特。
# 复杂度O(2^(k_bits - known_hi - zero_low_bits)), 实际用lattice — 此处为骨架。

def ecdsa_partial_nonce_recover(
    r: int, s: int, z: int, curve_order: int,
    known_hi: int, zero_low_bits: int, k_total_bits: int = 256
) -> Optional[int]:
    """
    已知nonce k部分位信息, 蛮力搜索恢复私钥d。
    known_hi = k最高位(已知), zero_low_bits = k最低位已知为0的位数。
    k中间unknown_bits位需爆破。适用: unknown_bits ≤ 32 (2^32 = 4B枚举)。
    返回私钥d或None。
    """
    unknown_bits = k_total_bits - zero_low_bits - known_hi.bit_length()
    if unknown_bits > 32:
        return None  # 爆破空间过大, 需lattice方法
    if unknown_bits < 0:
        return None

    k_base = (known_hi << (k_total_bits - known_hi.bit_length())) | 0
    k_mask = (1 << zero_low_bits) - 1
    k_base &= ~k_mask

    for mid in range(1 << unknown_bits):
        k = k_base | (mid << zero_low_bits)
        if k <= 0 or k >= curve_order:
            continue
        try:
            d = ((s * k - z) % curve_order) * pow(r, -1, curve_order) % curve_order
            # 快速验证: 检查公钥Q = d*G与已知公钥匹配(调用方提供检查函数)
            # 返回候选d, 由调用方验证
            return d
        except (ValueError, ZeroDivisionError):
            continue
    return None


# ---- Invalid Curve攻击 ----
# 实现不检查点是否在curve上时, 攻击者可提供不在curve上的点(低阶点)
# 通过中国剩余定理(CRT)恢复私钥d。每次交互泄露d mod small_order。
# Biehl-Meyer-Muller (2000), Antipa et al. (2002).

def invalid_curve_attack_crt(partial_keys: List[Tuple[int, int]]) -> Optional[int]:
    """
    从多个(d mod small_order, small_order)对中通过CRT恢复完整私钥d。
    partial_keys: [(d_mod_p1, p1), (d_mod_p2, p2), ...]
    返回完整d或None (模数互质条件不满足)。
    """
    if not partial_keys:
        return None

    # Garner's algorithm for CRT reconstruction
    d = 0
    modulus = 1
    for residue, prime in partial_keys:
        # d ≡ residue (mod prime)
        # d = current_d + modulus * t, solve: current_d + modulus*t ≡ residue (mod prime)
        target = (residue - d) % prime
        try:
            inv = pow(modulus % prime, -1, prime)
        except ValueError:
            return None  # modulus与prime不互质
        t = (target * inv) % prime
        d = d + modulus * t
        modulus = modulus * prime
    return d % modulus


# ---- Twist Security检测 ----
# 曲线twist(二次扭曲)阶的质因数大小决定twist攻击难度。
# twist阶主要由小质数组成→可执行Pohlig-Hellman→曲线twist-insecure。
# 以下为NIST P-256和Curve25519的twist阶已知质因数分解。

# secp256r1 twist: y^2 = x^3 + a*x*d^2 + b*d^3 (同构于twisted curve)
# twist order = 2*p + 2 - n (Hasse bound)
# secp256r1: twist_order含大质因数 (曲线本身secure)
# Curve25519: twist阶 = 2^2 * p2 (p2为~253-bit质数) → twist-secure

_TWIST_ORDERS = {
    'secp256r1': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    'secp256k1': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    'Curve25519': 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3EC,
}


def twist_security_check(curve_name: str) -> dict:
    """检查曲线twist安全性。返回{secure, twist_order, largest_prime_factor_bits}。"""
    twist_order = _TWIST_ORDERS.get(curve_name)
    if twist_order is None:
        return {'secure': 'unknown', 'reason': f'curve {curve_name} not in database'}
    # 快速质因数分解 (试除小质数, 检测大质因数)
    n = twist_order
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                    53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    remaining = n
    max_small_factor = 1
    for p in small_primes:
        while remaining % p == 0:
            remaining //= p
            max_small_factor = p
    remaining_bits = remaining.bit_length() if remaining > 1 else 0
    return {
        'secure': remaining_bits >= 200,
        'twist_order_hex': hex(twist_order),
        'largest_small_factor': max_small_factor,
        'remaining_factor_bits': remaining_bits,
    }


# ---- ECDSA公钥恢复 (从签名+消息) ----
# SEC 1 §4.1.6: 给定(r, s, message), 恢复可能的公钥Q (最多2个候选)。
# Q = r^-1 * (s*R - z*G), 其中R从r和parity(recid)恢复。

def ecdsa_recover_public_key(
    r: int, s: int, z: int,
    curve_order: int,
    recover_compress_odd: int = 0
) -> Optional[Tuple[int, int]]:
    """
    SEC1公钥恢复: Q = r^-1 * (s*R - z*G).
    R的y坐标由r, recover_compress_odd(0或1)确定。
    返回(Qx, Qy)或None。
    注: 完整实现需底层曲线运算(点乘/点加), 此处为接口骨架。
    实际使用时集成ecdsa Python library或coincurve。
    """
    if r <= 0 or r >= curve_order or s <= 0 or s >= curve_order:
        return None
    try:
        r_inv = pow(r, -1, curve_order)
    except ValueError:
        return None
    # 恢复点R: x = r + (recover_compress_odd ? curve_order + ... : 0)
    # 完整实现需解y^2 = x^3 + ax + b mod p → 两条候选R
    # 以下返回占位值 — 调用方应使用coincurve或ecdsa库完成实际计算
    return None  # placeholder — integrate with coincurve for full recovery


__all__ = ['ecdsa_recover_private_key_from_k_reuse', 'ecdsa_partial_nonce_recover',
           'invalid_curve_attack_crt', 'twist_security_check',
           'ecdsa_recover_public_key']


def _debug_print(*args, **kwargs):
    pass  # 内部调试输出桩
