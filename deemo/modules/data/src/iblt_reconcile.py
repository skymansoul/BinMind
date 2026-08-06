# IBLT 键值集合对账: 计数Bloom估算差异→IBLT或KeyList自适应选择
# 扩展标准IBLT为KV对账(keySum⊕valueSum⊕count), 解码失败自动1.5x重试.
# 区别于 Rateless IBLT(SIGCOMM 2024), CertainSync(2025): 面向签名库KV对账.
import hashlib, math, random, struct, time
from typing import Any, Dict, List, Optional, Set, Tuple


class KVIBLT:
    """键值 IBLT: cell=(count, keySum⊕, valSum⊕), n_cells≥1.5×预期差异."""
    def __init__(self, n_cells: int = 1024, n_hashes: int = 3,
                 value_bytes: int = 32):
        self.m = n_cells; self.k = n_hashes; self.vb = value_bytes
        self._counts = [0]*n_cells; self._key_sums = [0]*n_cells
        self._val_sums = [bytearray(value_bytes) for _ in range(n_cells)]

    def insert(self, key: int, value: bytes):
        for i in range(self.k):
            idx = self._hash_idx(key, i)
            self._counts[idx] += 1; self._key_sums[idx] ^= key; self._xor_val(idx, value)

    def remove(self, key: int, value: bytes):
        for i in range(self.k):
            idx = self._hash_idx(key, i)
            self._counts[idx] -= 1; self._key_sums[idx] ^= key; self._xor_val(idx, value)

    def decode(self, max_iterations: int = None) -> Tuple[List[Tuple[int, bytes]], List[Tuple[int, bytes]]]:
        """解码 IBLT → (本地独有, 远端独有).

        剥离算法: 找到 |count|=1 的 cell → 提取 key → 从所有 cell 中移除.
        重复至无更多 singleton. 剩余 cell 中 |count|>1 的是不可解码环.
        count>0 → 本地独有 (多插入), count<0 → 远端独有 (多删除).
        """
        if max_iterations is None:
            max_iterations = self.m * 2

        local_only = []
        remote_only = []
        remaining = set(range(self.m))

        for _ in range(max_iterations):
            singleton = None
            for idx in list(remaining):
                if abs(self._counts[idx]) == 1:
                    singleton = idx
                    break
            if singleton is None:
                break

            remaining.discard(singleton)
            cnt = self._counts[singleton]
            key = self._key_sums[singleton]
            val = bytes(self._val_sums[singleton])

            if cnt > 0:
                local_only.append((key, val))
            else:
                remote_only.append((key, val))

            # 从其他 cell 中剥离
            for i in range(self.k):
                idx2 = self._hash_idx(key, i)
                if idx2 in remaining or idx2 == singleton:
                    self._counts[idx2] -= cnt
                    self._key_sums[idx2] ^= key
                    self._xor_val(idx2, val)

        return local_only, remote_only

    def is_empty(self) -> bool:
        return all(c == 0 for c in self._counts)

    def serialize(self) -> bytes:
        """序列化为紧凑字节流用于网络传输."""
        buf = bytearray()
        buf.extend(struct.pack('<II', self.m, self.k))
        for i in range(self.m):
            buf.extend(struct.pack('<iQ', self._counts[i], self._key_sums[i]))
            buf.extend(self._val_sums[i])
        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes) -> "KVIBLT":
        m_val, k_val = struct.unpack('<II', data[:8])
        vb = (len(data) - 8) // m_val - 12  # 4B count + 8B key + vb val
        iblt = cls(n_cells=m_val, n_hashes=k_val, value_bytes=vb)
        off = 8
        for i in range(m_val):
            iblt._counts[i] = struct.unpack('<i', data[off:off+4])[0]
            iblt._key_sums[i] = struct.unpack('<Q', data[off+4:off+12])[0]
            iblt._val_sums[i] = bytearray(data[off+12:off+12+vb])
            off += 12 + vb
        return iblt

    def _hash_idx(self, key: int, i: int) -> int:
        h = key ^ (i * 0x9e3779b97f4a7c15 + 0xbf58476d1ce4e5b9)
        h = (h ^ (h >> 33)) * 0xff51afd7ed558ccd
        h = (h ^ (h >> 33)) & 0x7FFFFFFFFFFFFFFF
        return h % self.m

    def _xor_val(self, idx: int, value: bytes):
        vs = self._val_sums[idx]
        limit = min(len(vs), len(value))
        for j in range(limit):
            vs[j] ^= value[j]


# ---------------------------------------------------------------------------
# 混合自适应对账协调器
# ---------------------------------------------------------------------------

class HybridReconciler:
    """混合对账: 计数Bloom估差异→IBLT/KeyList自适应. hr.reconcile(local_kv, remote_kv)."""

    # 计数 Bloom: 当 d_est < 此阈值时用精确 key 列表代替 IBLT
    KEYLIST_THRESHOLD = 100
    # IBLT 大小乘数: n_cells = max(1.5 × d_est, 64)
    IBLT_MULTIPLIER = 1.5
    MAX_RETRIES = 3

    def __init__(self, bloom_bytes: int = 4096):
        self.bloom_bytes = bloom_bytes

    def reconcile(self, local_kv: Dict[int, bytes],
                   remote_kv: Dict[int, bytes]
                   ) -> "ReconciliationResult":
        """执行对账: 返回两端的差异.

        local_kv, remote_kv: {key_int → value_bytes} 映射.
        """
        t0 = time.time()
        local_keys = set(local_kv.keys())
        remote_keys = set(remote_kv.keys())

        # Step 1: 计数 Bloom 估算差异大小
        d_est = self._estimate_diff(local_keys, remote_keys)

        # Step 2: 根据 d_est 选择策略
        if d_est <= self.KEYLIST_THRESHOLD:
            return self._keylist_reconcile(local_kv, remote_kv, t0)

        # Step 3: IBLT 对账 (含重试)
        return self._iblt_reconcile(local_kv, remote_kv, d_est, t0)

    def _estimate_diff(self, set_a: Set[int],
                        set_b: Set[int]) -> int:
        """用计数 Bloom 过滤器估算对称差大小.

        构建两个 4-bit 计数 Bloom: 对 set_a 加 1, 对 set_b 减 1.
        |diff| ≈ sum(|counts_i|) / k (k=hash_count, 取整).
        """
        k = 3
        m = self.bloom_bytes * 2  # 4-bit counters → m/2 cells
        n_cells = m // 2
        counts = [0] * n_cells

        for key in set_a:
            for i in range(k):
                idx = self._bhash(key, i, n_cells)
                counts[idx] = min(15, counts[idx] + 1)
        for key in set_b:
            for i in range(k):
                idx = self._bhash(key, i, n_cells)
                counts[idx] = max(-15, counts[idx] - 1)

        abs_sum = sum(abs(c) for c in counts)
        est = abs_sum // k  # 每元素贡献 k 次计数
        return max(0, est)

    def _iblt_reconcile(self, local_kv: Dict[int, bytes],
                          remote_kv: Dict[int, bytes],
                          d_est: int, t0: float
                          ) -> "ReconciliationResult":
        """IBLT 对账主循环 (含自动重试)."""
        n_cells = max(64, int(d_est * self.IBLT_MULTIPLIER))

        for attempt in range(self.MAX_RETRIES):
            iblt = KVIBLT(n_cells=n_cells)
            # 插入本地所有条目
            for key, val in local_kv.items():
                iblt.insert(key, val)
            # 从远端移除 (减法)
            for key, val in remote_kv.items():
                iblt.remove(key, val)

            local_diff, remote_diff = iblt.decode()

            # 检查是否有未解码的残留
            unresolvable = sum(1 for c in iblt._counts if c != 0)
            if unresolvable == 0:
                elapsed = time.time() - t0
                return ReconciliationResult(
                    local_only=dict(local_diff),
                    remote_only=dict(remote_diff),
                    method="iblt",
                    cells_used=n_cells,
                    retries=attempt,
                    diff_estimate=d_est,
                    elapsed_s=round(elapsed, 3),
                    success=True,
                )
            # 重试: 增大 cell 数
            n_cells = int(n_cells * 1.5)

        # 所有重试失败: 回退到 keylist
        elapsed = time.time() - t0
        local_only = {k: local_kv[k] for k in local_kv if k not in remote_kv}
        remote_only = {k: remote_kv[k] for k in remote_kv if k not in local_kv}
        return ReconciliationResult(
            local_only=local_only, remote_only=remote_only,
            method="keylist_fallback",
            cells_used=n_cells,
            retries=self.MAX_RETRIES,
            diff_estimate=d_est,
            elapsed_s=round(elapsed, 3),
            success=False,
        )

    def _keylist_reconcile(self, local_kv: Dict[int, bytes],
                            remote_kv: Dict[int, bytes],
                            t0: float) -> "ReconciliationResult":
        """精确键列表交换 (差异小时更高效)."""
        local_only = {k: local_kv[k] for k in local_kv if k not in remote_kv}
        remote_only = {k: remote_kv[k] for k in remote_kv if k not in local_kv}
        elapsed = time.time() - t0
        return ReconciliationResult(
            local_only=local_only, remote_only=remote_only,
            method="keylist",
            cells_used=0, retries=0,
            diff_estimate=len(local_only)+len(remote_only),
            elapsed_s=round(elapsed, 3), success=True,
        )

    @staticmethod
    def _bhash(key: int, seed: int, n_cells: int) -> int:
        h = key ^ (seed * 0x9e3779b97f4a7c15)
        h = (h ^ (h >> 33)) * 0xff51afd7ed558ccd
        return (h ^ (h >> 33)) % n_cells


class ReconciliationResult:
    """对账结果."""
    __slots__ = ("local_only","remote_only","method","cells_used",
                 "retries","diff_estimate","elapsed_s","success")
    def __init__(self, local_only: dict, remote_only: dict, method: str,
                 cells_used: int, retries: int, diff_estimate: int,
                 elapsed_s: float, success: bool):
        self.local_only = local_only
        self.remote_only = remote_only
        self.method = method
        self.cells_used = cells_used
        self.retries = retries
        self.diff_estimate = diff_estimate
        self.elapsed_s = elapsed_s
        self.success = success

    @property
    def total_diff(self) -> int:
        return len(self.local_only) + len(self.remote_only)

    def to_dict(self) -> dict:
        return {
            "method": self.method, "success": self.success,
            "local_only": len(self.local_only),
            "remote_only": len(self.remote_only),
            "diff_estimated": self.diff_estimate,
            "cells": self.cells_used, "retries": self.retries,
            "elapsed_s": self.elapsed_s,
        }


# 便捷函数: 从两个 sha256 列表快速对账
def reconcile_sha256_sets(local_hashes: List[str],
                           remote_hashes: List[str],
                           value_size: int = 16) -> ReconciliationResult:
    """从两个 SHA256 十六进制字符串列表对账.

    value = sha256 的前 value_size 字节 (作为元数据代理).
    """
    def _kv_from_hashes(h_list):
        kv = {}
        for h in h_list:
            raw = bytes.fromhex(h) if len(h) == 64 else hashlib.sha256(h.encode()).digest()
            key_int = int.from_bytes(raw[:8], 'little')
            kv[key_int] = raw[:value_size]
        return kv

    hr = HybridReconciler()
    return hr.reconcile(_kv_from_hashes(local_hashes),
                         _kv_from_hashes(remote_hashes))


__all__ = [
    "KVIBLT",
    "HybridReconciler",
    "ReconciliationResult",
    "reconcile_sha256_sets",
]
