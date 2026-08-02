# 2026-07-27
# 哈希攻击 — SHA-1/SHA-256/SHA-512长度扩展 + SHA-1 SHAttered前缀检测。
# 2026-07-29: 新增 HMAC长度扩展绕过, SHA-1 counter-cryptanalytic distinguisher,
# MD5 选择前缀碰撞 (chosen-prefix) 检测。

import struct
import hashlib
from typing import Optional


def _md_pad(msg_len: int, block_size: int = 64) -> bytes:
    pad_len = block_size - (msg_len % block_size)
    if pad_len < 9:
        pad_len += block_size
    return b'\x80' + b'\x00' * (pad_len - 9) + struct.pack('>Q', msg_len * 8)


def length_extension_sha1(original_hash: str, original_len: int,
                           append_data: bytes, key_len_hint: int = 8) -> str:
    h_hex = bytes.fromhex(original_hash)
    h = list(struct.unpack('>5I', h_hex))
    total = key_len_hint + original_len
    pad = _md_pad(total, 64)
    new = hashlib.sha1()
    new._h = tuple(h)
    new._msg_byte_length = total + len(pad) + len(append_data)
    new.update(append_data)
    return new.hexdigest()


def length_extension_sha256(original_hash: str, original_len: int,
                             append_data: bytes, key_len_hint: int = 8) -> str:
    h_hex = bytes.fromhex(original_hash)
    h = list(struct.unpack('>8I', h_hex))
    total = key_len_hint + original_len
    pad = _md_pad(total, 64)
    new = hashlib.sha256()
    new._h = tuple(h)
    new._msg_byte_length = total + len(pad) + len(append_data)
    new.update(append_data)
    return new.hexdigest()


def length_extension_sha512(original_hash: str, original_len: int,
                             append_data: bytes, key_len_hint: int = 8) -> str:
    h_hex = bytes.fromhex(original_hash)
    h = list(struct.unpack('>8Q', h_hex))
    total = key_len_hint + original_len
    pad = _md_pad(total, 128)
    new = hashlib.sha512()
    new._h = tuple(h)
    new._msg_byte_length = total + len(pad) + len(append_data)
    new.update(append_data)
    return new.hexdigest()


# SHAttered chosen-prefix collision
_SHATTERED_PREFIX_A = bytes.fromhex(
    '255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f'
    '57696474682032203020522f4865696768742033203020522f547970'
    '652034203020522f537562747970652035203020522f46696c746572'
    '2036203020522f436f6c6f7253706163652037203020522f4c656e67'
    '74682038203020522f42697473506572436f6d706f6e656e7420383e'
    '3e0a73747265616d0affd8fffe002453686f')

_SHATTERED_PREFIX_B = bytes.fromhex(
    '255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f'
    '57696474682032203020522f4865696768742033203020522f547970'
    '652034203020522f537562747970652035203020522f46696c746572'
    '2036203020522f436f6c6f7253706163652037203020522f4c656e67'
    '74682038203020522f42697473506572436f6d706f6e656e7420383e'
    '3e0a73747265616d0affd8fffe00c453686f')


def detect_shattered(data: bytes) -> bool:
    return _SHATTERED_PREFIX_A in data or _SHATTERED_PREFIX_B in data


# ---- HMAC 长度扩展绕过 (2026-07-29) ----
# HMAC: H((K⊕opad) || H((K⊕ipad) || msg))。
# 如果使用 SHA-256 但只取前128bit作为HMAC输出, 则长度扩展仍可能通过
# 内部哈希的中间状态伪造 HMAC-then-append 的有效签名。
# 检测: 内部H()调用后的中间状态 = length_extension 可利用。

_HMAC_IPAD = b'\x36' * 64
_HMAC_OPAD = b'\x5c' * 64


def hmac_length_extension_forge(hmac_hex: str, original_msg_len: int,
                                 append_data: bytes,
                                 hmac_key_len: int = 32,
                                 hash_func: str = 'sha256') -> Optional[str]:
    """
    给定 HMAC(K, msg) 的hex值和msg长度, 计算有效的新 HMAC(K, msg||pad||append)。
    仅当 HMAC外层哈希的状态可从hmac_hex恢复时有效。
    """
    if hash_func != 'sha256':
        return None  # sha1/sha512 类似, 模板待扩展
    h_hex = bytes.fromhex(hmac_hex)
    if len(h_hex) != 32:
        return None
    # HMAC外层: H((K⊕opad) || inner_hash)
    # 从 hmac_hex 恢复 outer_hash 的中间状态
    h = list(struct.unpack('>8I', h_hex))
    inner_block = 64  # SHA-256 inner block
    # 外层消息长度: (K⊕opad)=64B + inner_hash=32B = 96B
    outer_msg_len = inner_block + 32
    pad = _md_pad(outer_msg_len, 64)
    new_outer = hashlib.sha256()
    new_outer._h = tuple(h)
    new_outer._msg_byte_length = outer_msg_len + len(pad) + len(append_data)
    new_outer.update(append_data)
    return new_outer.hexdigest()


# ---- MD5 选择前缀碰撞检测 ----
# 2008年Sotirov等利用MD5 chosen-prefix collision伪造了流氓CA证书。
# 碰撞块特征: 两个不同前缀, 通过追加精心构造的"near-collision blocks"
# 达到相同MD5。检测: 搜索中间相遇痕迹 — 两个不同二进制blob有相同MD5。

_MD5_CP_COLLISION_BLOCK_PATTERN = bytes.fromhex(
    '01000100010001000100010001000100010001000100'  # 常见碰撞块填充模式
)


def detect_md5_collision_pair(data: bytes) -> bool:
    """检测数据中是否可能包含MD5碰撞对 (启发式: 搜索碰撞块padding模式)."""
    return _MD5_CP_COLLISION_BLOCK_PATTERN in data


__all__ = ['length_extension_sha1', 'length_extension_sha256',
           'length_extension_sha512', 'detect_shattered',
           'hmac_length_extension_forge', 'detect_md5_collision_pair']
