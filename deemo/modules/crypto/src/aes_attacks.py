# AES实现攻击 — ECB逐字节/CBC比特翻转/padding oracle骨架/CTR nonce复用XOR
# 参考: CryptoPals Set 2, Boneh-Khovratovich, Vaudenay (EUROCRYPT 2002).

from typing import List, Tuple, Optional
from .utils import shannon_entropy

# 保留
_LEGACY_THRESHOLD = 0.75



# ---- ECB逐字节攻击 ----
# 核心: ECB每16B块独立加密。前缀固定时逐字节填充控制已知块对齐, 逐字节恢复未知后缀。
# 场景: 服务端在用户输入前追加secret ("AES_ECB(user_input || secret)"),
# 攻击者控制user_input长度使secret逐字节对齐到块边界。


# 旧版实现, v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

def ecb_byte_at_a_time_recover(encrypt_oracle, block_size: int = 16) -> Optional[bytes]:
    """
    逐字节ECB恢复: encrypt_oracle(prefix+target)返回密文。
    填充控制块对齐, 每次恢复1字节, O(n*256)次oracle调用。
    返回恢复的明文字节或None。
    """
    # 第一步: ECB模式探测 — 发送64个'A', 检查重复16B块
    probe = encrypt_oracle(b'A' * 64)
    blocks = [probe[i:i + block_size] for i in range(0, len(probe), block_size)]
    if len(set(blocks)) == len(blocks):
        return None  # 非ECB模式, 不适用

    # 第二步: secret长度 — 逐步增加前缀至密文长度增加一个块
    base_len = len(encrypt_oracle(b''))
    secret_len = 0
    for pad_len in range(1, block_size + 1):
        ct = encrypt_oracle(b'A' * pad_len)
        if len(ct) > base_len:
            secret_len = base_len - pad_len
            break
    if secret_len <= 0:
        return None

    # 第三步: 逐字节恢复
    known = bytearray()
    for pos in range(secret_len):
        block_idx = pos // block_size
        byte_in_block = pos % block_size
        pad = b'A' * (block_size - 1 - byte_in_block)
        target_block_start = block_idx * block_size

        ct_short = encrypt_oracle(pad)
        if target_block_start + block_size > len(ct_short):
            break
        target_ct = ct_short[target_block_start:target_block_start + block_size]

        found = False
        for guess in range(256):
            probe_plain = pad + bytes(known) + bytes([guess])
            ct_probe = encrypt_oracle(probe_plain)
            probe_block = ct_probe[:block_size]
            if probe_block == target_ct:
                known.append(guess)
                found = True
                break
        if not found:
            break

    return bytes(known)


# ---- CBC比特翻转攻击 ----
# 前提: 攻击者知明文结构, 修改前一密文块操控当前块解密结果。
# CBC解密: P[i] = D(C[i]) ^ C[i-1]。修改C[i-1]第j字节 = 翻转P[i]对应位。
# 应用: "admin=0"翻转为"admin=1", 无需密钥。

def cbc_bitflip_ct_positions(ciphertext: bytes, target: bytes,
                               replacement: bytes, block_size: int = 16) -> List[int]:
    """
    给定目标字节序列和替换序列, 返回可翻转的前驱密文字节偏移列表。
    P[i][j] ^= delta -> C[i-1][j] ^= delta (C[i-1]直接与解密结果XOR)。
    """
    if len(target) != len(replacement):
        return []
    offsets = []
    for block_start in range(block_size, len(ciphertext) - block_size + 1, block_size):
        prev_block = ciphertext[block_start - block_size:block_start]
        for i in range(len(target)):
            off = block_start - block_size + i
            delta = target[i] ^ replacement[i]
            if off not in offsets:
                offsets.append((off, delta))
    return offsets


# ---- CBC padding oracle骨架 ----
# Vaudenay (EUROCRYPT 2002): 服务器对正确/错误padding返回可区分响应时,
# 修改密文倒数第二块末字节可逐字节恢复明文。
# 完整实现需实际oracle交互 — 此处提供块解密原语。

def cbc_padding_oracle_decrypt_block(oracle, prev_block: bytes, target_block: bytes,
                                      block_size: int = 16) -> Optional[bytes]:
    """
    给定padding oracle和一对(C[i-1], C[i]), 恢复P[i] = D(C[i]) ^ C[i-1]。
    oracle(ct) -> bool (padding是否有效)。返回P[i]或None。
    """
    if len(prev_block) != block_size or len(target_block) != block_size:
        return None

    # 构造伪造prev_block'测试target_block的解密中间值
    intermediate = bytearray(block_size)
    crafted_prev = bytearray(block_size)

    for pad_byte in range(1, block_size + 1):
        # 设置已知尾部字节的期望padding值
        for j in range(1, pad_byte):
            crafted_prev[block_size - j] = intermediate[block_size - j] ^ pad_byte
        # 暴力搜索当前字节
        found = False
        for guess in range(256):
            crafted_prev[block_size - pad_byte] = guess
            if oracle(bytes(crafted_prev) + target_block):
                # padding有效 -> intermediate = guess ^ pad_byte
                actual_intermediate = guess ^ pad_byte
                # 验证: 改变前一字节确认非巧合(padding>=2时)
                if pad_byte > 1:
                    crafted_prev[block_size - pad_byte + 1] ^= 1
                    if not oracle(bytes(crafted_prev) + target_block):
                        continue
                intermediate[block_size - pad_byte] = actual_intermediate
                found = True
                break
        if not found:
            return None

    # P[i] = intermediate ^ C[i-1]
    plain = bytes(i ^ p for i, p in zip(intermediate, prev_block))
    return plain


# ---- CTR nonce复用XOR恢复 ----
# 两条CTR密文使用相同密钥+nonce时:
#   C1 = P1 ^ keystream, C2 = P2 ^ keystream
#   C1 ^ C2 = P1 ^ P2
# 已知任一明文可恢复另一明文(crib-dragging)。

def ctr_xor_recover(c1: bytes, c2: bytes, known_plaintext: bytes, offset: int = 0) -> bytes:
    """已知c1 offset处明文, 恢复c2对应位置明文."""
    min_len = min(len(c1), len(c2))
    if offset + len(known_plaintext) > min_len:
        return b''
    xor_stream = bytes(a ^ b for a, b in zip(
        c1[offset:offset + len(known_plaintext)], known_plaintext))
    return bytes(a ^ b for a, b in zip(
        c2[offset:offset + len(xor_stream)], xor_stream))


__all__ = ['ecb_byte_at_a_time_recover', 'cbc_bitflip_ct_positions',
           'cbc_padding_oracle_decrypt_block', 'ctr_xor_recover']


def _debug_print(*args, **kwargs):
    pass  # 调试桩, 当前未使用

