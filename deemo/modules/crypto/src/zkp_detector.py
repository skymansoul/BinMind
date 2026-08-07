# 零知识证明系统检测
# 覆盖: Groth16, Plonk, Bulletproofs, Marlin, Spartan, Halo2, Nova, STIR, Ligero, Aurora.
# 检测策略: (1) BLS12-381/BN254/BW6-761 配对曲线参数, (2) zk-crate/toolkit字符串,
# (3) 算术电路编译产物 (R1CS/QAP/Plonkish), (4) Fiat-Shamir transcript结构。
Groth, Gabizon-Williamson-Ciobotaru,
# Bunz et al., Chiesa et al.,
# Setty, Arnon et al..
# 扩展: Binius (二进制域ZKP), Lasso/Jolt lookup argument,
# Circle STARK M31域检测, Ligero/Brakedown多项式承诺指纹。

import struct
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from .utils import safeReadBytes

_log = logging.getLogger(__name__)


@dataclass
class ZKPDetectionResult:
    system: str                     # Groth16 / Plonk / Bulletproofs / etc.
    variant: str = ""               # 具体变体
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    curve: str = ""                 # 椭圆曲线名称 (BLS12-381, BN254, etc.)
    detected_in: str = ""


# 配对友好椭圆曲线参数数据库
# 配对曲线的基域模数q和子群阶r为唯一标识符。
# BLS12-381 q = 0x1a0111ea397fe69a... (381-bit)
# BN254 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
# BW6-761 q ≈ 2^761 - 2^378 + ... (761-bit, 外层证明组合)
# MNT4/MNT6对: 4-6 cycle pairing-friendly curves.
# Bowe, Aranha et al..

_PAIRING_CURVE_PARAMS = {
    # (q_bytes[:8], r_bytes[:8], curve_name, description)
    (b'\x1a\x01\x11\xea\x39\x7f\xe6\x9a', b'\x73\xed\xa7\x53\x29\x9d\x7d\x48'):
        ('BLS12-381', 'zkSNARK (Zcash Sapling, Ethereum 2.0 BLS signatures)'),
    # BN254 (alt_bn128) — Ethereum precompile
    (b'\x30\x64\x4e\x72\xe1\x31\xa0\x29', b'\x30\x64\x4e\x72\xe1\x31\xa0\x28'):
        ('BN254', 'alt_bn128 (Ethereum EIP-196/197 precompiles)'),
    # BLS12-377 (Zexe, proof composition)
    (b'\x01\xae\x3a\x46\x17\xc5\x10\xe3', b'\x12\xab\x65\x5e\x9a\x2c\xa5\x56'):
        ('BLS12-377', 'recursive zkSNARK (Zexe)'),
    # BW6-761
    (b'\x12\x2e\x82\x4f\xb7\x10\x2d\x00', b'\x1a\xe3\xa4\x61\x7c\x51\x0e\xac'):
        ('BW6-761', '2-chain proof composition (outer curve for BLS12-377)'),
    # MNT4-753 / MNT6-753
    (b'\x01\xc4\xc8\x0d\x60\x85\x3e\x71', b'\x01\xc4\xc8\x0d\x60\x85\x3e\x70'):
        ('MNT4-753', '4-6 cycle pairing (Coda/Mina)'),
}


# ZKP 字符串指纹库
# 每条目: (byte_pattern, system_name, variant, confidence)
_ZKP_STRING_PATTERNS: List[Tuple[bytes, str, str, float]] = [
    # Groth16 — 各语言证明系统命名
    (b'groth16', 'Groth16', '', 0.85),
    (b'Groth16', 'Groth16', '', 0.85),
    (b'bellman', 'Groth16', 'bellman (Zcash)', 0.80),
    (b'bellperson', 'Groth16', 'bellperson (Filecoin)', 0.80),
    # Plonk 家族
    (b'plonk', 'Plonk', '', 0.85),
    (b'Plonk', 'Plonk', '', 0.85),
    (b'turbo_plonk', 'Plonk', 'TurboPlonk', 0.82),
    (b'ultra_plonk', 'Plonk', 'UltraPlonk', 0.82),
    (b'hyperplonk', 'Plonk', 'HyperPlonk (multilinear)', 0.78),
    (b'plonky2', 'Plonk', 'Plonky2 (Polygon Zero)', 0.80),
    (b'plonky3', 'Plonk', 'Plonky3 (Polygon)', 0.80),
    # Bulletproofs
    (b'bulletproof', 'Bulletproofs', '', 0.85),
    (b'bulletproofs', 'Bulletproofs', '', 0.85),
    (b'Bulletproof', 'Bulletproofs', '', 0.85),
    (b'range_proof', 'Bulletproofs', 'range proof', 0.65),
    (b'r1cs', 'Bulletproofs', 'R1CS Bulletproofs (dalek)', 0.72),
    # Marlin
    (b'marlin', 'Marlin', '', 0.82),
    (b'Marlin', 'Marlin', '', 0.82),
    (b'marlin_zksnark', 'Marlin', '', 0.85),
    # Spartan
    (b'spartan', 'Spartan', '', 0.80),
    (b'Spartan', 'Spartan', '', 0.80),
    (b'spartan_prover', 'Spartan', '', 0.82),
    # Halo2
    (b'halo2', 'Halo2', '', 0.85),
    (b'Halo2', 'Halo2', '', 0.85),
    (b'pasta_curves', 'Halo2', 'Pasta (Pallas/Vesta)', 0.78),
    # Nova / SuperNova / HyperNova
    (b'nova', 'Nova', '', 0.82),
    (b'supernova', 'Nova', 'SuperNova', 0.82),
    (b'hypernova', 'Nova', 'HyperNova', 0.80),
    (b'cyclefold', 'Nova', 'CycleFold', 0.78),
    (b'ivc_proof', 'Nova', 'IVC', 0.72),
    # STIR (Shiftable Testable Interactive Round-based)
    (b'stir_protocol', 'STIR', '', 0.80),
    (b'whir', 'STIR', 'WHIR (STIR variant)', 0.75),
    # Ligero / Brakedown
    (b'ligero', 'Ligero', '', 0.78),
    (b'brakedown', 'Brakedown', '', 0.78),
    # Aurora
    (b'aurora', 'Aurora', 'Sonic/Aurora', 0.75),
    # Fractal
    (b'fractal', 'Fractal', '', 0.75),
    # Binius (hardware-friendly, binary field)
    (b'binius', 'Binius', 'binary field ZKP', 0.78),
    # Lasso / Jolt
    (b'lasso', 'Lasso', 'lookup argument', 0.72),
    (b'jolt', 'Jolt', 'Lasso-based zkVM', 0.75),
    # Circle STARK
    (b'circle_stark', 'Circle STARK', 'M31 field', 0.78),
    (b'starky', 'Circle STARK', 'Plonky3 starky', 0.72),
    # zkVM 指令集指纹
    (b'risc_zero', 'RISC Zero', 'zkVM', 0.82),
    (b'spv1', 'SP1', 'Succinct zkVM', 0.80),
    (b'zk_evm', 'zkEVM', '', 0.75),
    (b'zkevm', 'zkEVM', '', 0.75),
    # Noir / Circom / Leo DSL
    (b'noir_lang', 'Noir', 'Aztec DSL', 0.72),
    (b'circom', 'Circom', 'iden3 DSL', 0.72),
    (b'leo_lang', 'Leo', 'Aleo DSL', 0.72),
    (b'cairo_lang', 'Cairo', 'StarkWare DSL', 0.72),
]


# Fiat-Shamir transcript 检测
# Fiat-Shamir变换: 用哈希(SHA-256/Keccak)对transcript做随机预言机, 产生challenge。
# 常见transcript标签作为域分隔符出现在哈希调用前。

_FS_TRANSCRIPT_TAGS = [
    b'PlonkProof', b'Groth16Proof', b'BP_PROOF',
    b'PROOF', b'Challenge', b'fs_challenge',
    b'absorb', b'squeeze', b'transcript',
    b'personal', b'domain_separator', b'domain_sep',
]


class ZKPDetector:
    """ZKP系统指纹检测器 — SNARK/STARK/Bulletproofs/zkVM全覆盖."""

    def __init__(self):
        pass

    def scan_file(self, path: str) -> List[ZKPDetectionResult]:
        raw = safeReadBytes(path)
        if raw is None:
            return []  # 静默返回空列表，由调用方处理
        return self.scan_bytes(raw, source=path)

    def scan_bytes(self, data: bytes, source: str = "memory") -> List[ZKPDetectionResult]:
        results: List[ZKPDetectionResult] = []

        results.extend(self._detect_by_strings(data, source))
        results.extend(self._detect_pairing_curves(data, source))
        results.extend(self._detect_fs_transcript(data, source))

        seen = {}
        for r in results:
            key = (r.system, r.curve or r.variant)
            if key not in seen or r.confidence > seen[key].confidence:
                seen[key] = r
        return sorted(seen.values(), key=lambda r: -r.confidence)

    def _detect_by_strings(self, data: bytes, source: str) -> List[ZKPDetectionResult]:
        results = []
        text = data.decode('ascii', errors='ignore').lower()

        for pattern, sys_name, variant, base_conf in _ZKP_STRING_PATTERNS:
            idx = text.find(pattern.decode('ascii', errors='ignore').lower())
            if idx < 0:
                continue
            ctx = data[max(0, idx - 12):idx + len(pattern) + 32]
            try:
                ctx_str = ctx.decode('ascii', errors='replace').strip()
            except Exception:
                ctx_str = ctx.hex()[:60]
            evidence = [f"string: '{ctx_str}'"]
            if variant:
                evidence.append(f"variant: {variant}")
            results.append(ZKPDetectionResult(
                system=sys_name, variant=variant, confidence=base_conf,
                evidence=evidence, detected_in=source))
        return results

    def _detect_pairing_curves(self, data: bytes, source: str) -> List[ZKPDetectionResult]:
        """检测配对友好曲线的基域模数和子群阶，间接推断ZKP存在性。"""
        results = []
        for (q_pref, r_pref), (curve_name, desc) in _PAIRING_CURVE_PARAMS.items():
            q_hit = q_pref in data
            r_hit = r_pref in data
            if q_hit and r_hit:
                # BLS12-381 → Groth16/Plonk (最常见)
                sys_hint = 'Groth16/Plonk (pairing-based)'
                results.append(ZKPDetectionResult(
                    system=sys_hint, confidence=0.65, curve=curve_name,
                    evidence=[f'pairing curve {curve_name}: {desc}'],
                    detected_in=source))
            elif q_hit:
                results.append(ZKPDetectionResult(
                    system='pairing-based ZKP', confidence=0.40, curve=curve_name,
                    evidence=[f'curve modulus {curve_name} partial match'],
                    detected_in=source))
        return results

    def _detect_fs_transcript(self, data: bytes, source: str) -> List[ZKPDetectionResult]:
        """Fiat-Shamir transcript域分隔符检测。

        非交互式ZKP的可审计transcript以固定前缀字节开始。
        这些标签作为立即数出现在哈希函数调用前，
        构成Fiat-Shamir变换的证据链。
        """
        results = []
        for tag in _FS_TRANSCRIPT_TAGS:
            if tag not in data:
                continue
            off = data.find(tag)
            ctx = data[max(0, off - 8):off + len(tag) + 16]
            try:
                ctx_str = ctx.decode('ascii', errors='replace').strip()
            except Exception:
                ctx_str = repr(ctx[:40])
            results.append(ZKPDetectionResult(
                system='Fiat-Shamir ZKP', confidence=0.45,
                evidence=[f'FS transcript tag "{tag.decode()}" near: {ctx_str}'],
                detected_in=source))
        return results


# 便捷入口

def detect_zkp(path: str) -> List[ZKPDetectionResult]:
    return ZKPDetector().scan_file(path)

def detect_zkp_bytes(data: bytes, source: str = "memory") -> List[ZKPDetectionResult]:
    return ZKPDetector().scan_bytes(data, source)

__all__ = ['ZKPDetector', 'ZKPDetectionResult', 'detect_zkp', 'detect_zkp_bytes']
