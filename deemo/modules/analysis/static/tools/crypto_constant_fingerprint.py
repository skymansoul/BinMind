# 常量池熵剖面: 不同加密算法的常量表产生独特熵签名
# 字节级滑动窗口扫描: 不依赖函数边界
# 放宽签名容差
# 卡方 S-box 置换检验: 区分256字节排列与随机数据, 消除对AES的假阳性

from __future__ import annotations

import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 已知加密算法的常量熵签名, (均值, 标准差, 块大小)

_CRYPTO_SIGNATURES: Dict[str, Tuple[float, float, int]] = {
    # AES: 256 字节全排列 S-box, 全窗熵 8.0 (理论最大)
    'AES':        (7.95, 0.05, 256),
    # DES: 8 个 S-box, 每 64 字节->熵≈5.5
    'DES':        (5.50, 0.15, 64),
    # SHA-256: 64 个 32-bit K 常量 (256 字节)->熵≈5.5
    'SHA256':     (5.45, 0.20, 256),
    # SHA-512: 80 个 64-bit K 常量->熵更大
    'SHA512':     (6.10, 0.18, 640),
    # MD5: 64 字节 T 表 + S 表
    'MD5':        (4.80, 0.30, 64),
    # ChaCha20: "expand 32-byte k" (16 字节 ASCII) + 轮常量
    'ChaCha20':   (3.20, 1.50, 16),
    # Salsa20: 类似 ChaCha20
    'Salsa20':    (3.15, 1.55, 16),
    # RC4: 256 字节初始 S-box (与 AES 不同, RC4 的 S-box 是 identity)
    'RC4':        (6.50, 0.80, 256),
    # Blowfish: 4KB S-box->高熵区域
    'Blowfish':   (7.50, 0.25, 4096),
    # RSA: 大整数常量->熵≈4-5
    'RSA':        (4.50, 0.40, 128),
    # ECC: 曲线参数->熵≈4-5
    'ECC':        (4.30, 0.45, 64),
}


@dataclass
class CryptoDetection:
    # 单个加密算法检测结果
    algorithm: str
    confidence: float
    offset: int                 # 常量表在二进制中的偏移
    size_hint: int              # 估算的常量表大小
    entropy_mean: float
    entropy_std: float


@dataclass
class CryptoFingerprintReport:
    # 加密常量指纹检测报告
    detections: List[CryptoDetection]
    total_bytes_scanned: int
    scan_time_ms: float = 0.0


class CryptoConstantFingerprinter:
    # 加密算法常量熵指纹提取器

    _WINDOW_SIZE = 256
    _STEP_SIZE = 64

    def scan(self, data: bytes) -> CryptoFingerprintReport:
        # 扫描二进制数据中的加密常量表
        import time
        t0 = time.perf_counter()

        detections: List[CryptoDetection] = []
        n = len(data)

        if n < self._WINDOW_SIZE:
            return CryptoFingerprintReport(
                detections=[], total_bytes_scanned=n,
                scan_time_ms=(time.perf_counter() - t0) * 1000,
            )

        # 滑动窗口扫描
        for offset in range(0, n - self._WINDOW_SIZE, self._STEP_SIZE):
            window = data[offset:offset + self._WINDOW_SIZE]
            h_mean, h_std = self._window_entropy_stats(window)

            # 与每已知算法签名匹配
            for algo, (sig_mean, sig_std, sig_size) in _CRYPTO_SIGNATURES.items():
                # 均值匹配: 放宽容差, 编译器数据对齐和常量合并改变熵剖面
                mean_match = abs(h_mean - sig_mean) < max(0.45, sig_std * 3.0)
                if not mean_match:
                    continue

                # 标准差匹配: 同样放宽
                std_match = abs(h_std - sig_std) < max(0.50, sig_std * 2.0)
                if not std_match:
                    continue

                # 置信度: 基于均值和标准差的归一化偏差
                z_mean = abs(h_mean - sig_mean) / max(0.01, sig_std)
                z_std = abs(h_std - sig_std) / max(0.01, sig_std)
                confidence = math.exp(-0.5 * (z_mean + z_std))

                if confidence > 0.35:
                    # S-box 算法额外验证: 卡方置换检验
                    if algo in ('AES', 'DES', 'RC4', 'Blowfish'):
                        chi2, is_perm = self._chi_squared_permutation_test(window)
                    if not is_perm:
                        continue  # 非真排列 -> 不是 S-box, 跳过
                        # 卡方值越低置信度越高
                        chi2_bonus = max(0, 0.15 * (1.0 - min(1.0, chi2 / 100.0)))
                        confidence = min(1.0, confidence + chi2_bonus)
                    detections.append(CryptoDetection(
                        algorithm=algo,
                        confidence=round(min(1.0, confidence), 4),
                        offset=offset,
                        size_hint=sig_size,
                        entropy_mean=round(h_mean, 4),
                        entropy_std=round(h_std, 4),
                    ))

        # 后处理: 合并重叠检测 (同算法, 相邻窗口 -> 同一常量表)
        detections = self._merge_overlapping(detections)

        return CryptoFingerprintReport(
            detections=sorted(detections, key=lambda d: -d.confidence),
            total_bytes_scanned=n,
            scan_time_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    def _window_entropy_stats(self, data: bytes) -> Tuple[float, float]:
        # 计算窗口字节熵: 全窗Shannon熵(均值) + 8个32字节子块熵散布(标准差)
        if len(data) < 32:
            return 0.0, 0.0

        # 全窗熵 (256 字节, 区分度更高)
        full_counts = [0] * 256
        window = data[:256]
        for b in window:
            full_counts[b] += 1
        full_h = 0.0
        for c in full_counts:
            if c > 0:
                p = c / 256.0
                full_h -= p * math.log2(p)

        # 子块熵的散布作为标准差 (捕获常量表内部的非均匀性)
        chunk_entropies = []
        for i in range(0, min(len(data), 256), 32):
            chunk = data[i:i + 32]
            counts = [0] * 256
            for b in chunk:
                counts[b] += 1
            h = 0.0
            for c in counts:
                if c > 0:
                    p = c / 32.0
                    h -= p * math.log2(p)
            chunk_entropies.append(h)

        if not chunk_entropies:
            return full_h, 0.0

        mean_chunk = sum(chunk_entropies) / len(chunk_entropies)
        variance = sum(
            (h - mean_chunk) ** 2 for h in chunk_entropies
        ) / len(chunk_entropies)

        return full_h, math.sqrt(variance)

    @staticmethod
    def _chi_squared_permutation_test(data: bytes) -> Tuple[float, bool]:
        # 卡方置换检验: 判断256字节是否构成0..255的排列
        # 真 S-box 每字节值恰好出现一次, χ²=Σ(O_i-1)², 自由度255
        # 真排列χ²≈0, 随机χ²≈255±22, 重复χ²>>10³; 阈值50允许少量填充噪声
        if len(data) < 256:
            return float('inf'), False
        window = data[:256]
        counts = [0] * 256
        for b in window:
            counts[b] += 1
        chi2 = sum((c - 1) ** 2 for c in counts)
        # χ² < 50 → 极可能为真排列 (允许少量编译器填充噪声)
        is_permutation = chi2 < 50
        return chi2, is_permutation

    def _merge_overlapping(
        self, detections: List[CryptoDetection]
    ) -> List[CryptoDetection]:
        # 合并重叠检测: 相邻窗口同算法视为同一常量表
        if len(detections) < 2:
            return detections

        detections.sort(key=lambda d: (d.algorithm, d.offset))
        merged: List[CryptoDetection] = []
        current = detections[0]

        for d in detections[1:]:
            if (
                d.algorithm == current.algorithm
                and d.offset <= current.offset + self._WINDOW_SIZE
            ):
                # 合并: 取置信度最高的
                if d.confidence > current.confidence:
                    current = d
                # 扩展 size_hint 到覆盖范围
                current.size_hint = max(
                    current.size_hint,
                    d.offset - current.offset + d.size_hint,
                )
            else:
                merged.append(current)
                current = d

        merged.append(current)
        return merged
