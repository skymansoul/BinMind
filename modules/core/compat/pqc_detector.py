"""后量子密码检测器 —— 字节级签名扫描与熵分析。

检测二进制数据中的 PQC 算法字符串签名，输出标准化检测结果。
对外暴露 PQCAlgorithm / PQCDetectionResult / PQCAnalysisResult
数据模型与 analyze_binary 分析入口。
"""

import math
import os
from dataclasses import dataclass, field
from typing import List

# 已知 PQC 算法族——用于签名扫描与常量判定
PQC_CONSTANTS = {
    'Kyber': {
        'family': 'lattice', 'algorithm_type': 'KEM',
        'nist_status': 'standardized', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': True,
        'description': 'CRYSTALS-Kyber: Module-LWE 密钥封装',
    },
    'Dilithium': {
        'family': 'lattice', 'algorithm_type': 'SIG',
        'nist_status': 'standardized', 'key_size': 256,
        'security_level': 'NIST-L2', 'recommended': True,
        'description': 'CRYSTALS-Dilithium: Module-LWE 数字签名',
    },
    'Falcon': {
        'family': 'lattice', 'algorithm_type': 'SIG',
        'nist_status': 'standardized', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': True,
        'description': 'Falcon: NTRU 格数字签名',
    },
    'NTRU': {
        'family': 'lattice', 'algorithm_type': 'KEM',
        'nist_status': 'round4', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': False,
        'description': 'NTRU: 循环格密钥封装',
    },
    'SPHINCS+': {
        'family': 'hash', 'algorithm_type': 'SIG',
        'nist_status': 'standardized', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': False,
        'description': 'SPHINCS+: 无状态哈希签名',
    },
    'FrodoKEM': {
        'family': 'lattice', 'algorithm_type': 'KEM',
        'nist_status': 'alternate', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': False,
        'description': 'FrodoKEM: 基于 LWE 的保守 KEM',
    },
    'BIKE': {
        'family': 'code', 'algorithm_type': 'KEM',
        'nist_status': 'round4', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': False,
        'description': 'BIKE: QC-MDPC 码密钥封装',
    },
    'HQC': {
        'family': 'code', 'algorithm_type': 'KEM',
        'nist_status': 'round4', 'key_size': 128,
        'security_level': 'NIST-L1', 'recommended': False,
        'description': 'HQC: 张量码密钥封装',
    },
    'Classic McEliece': {
        'family': 'code', 'algorithm_type': 'KEM',
        'nist_status': 'round4', 'key_size': 256,
        'security_level': 'NIST-L3', 'recommended': False,
        'description': 'Classic McEliece: Goppa 码密钥封装',
    },
}

# 字符串签名 → 算法名
_SIGNATURES = {
    b'KYBER': 'Kyber',
    b'DILITHIUM': 'Dilithium',
    b'FALCON': 'Falcon',
    b'SPHINCS': 'SPHINCS+',
    b'FRODOKEM': 'FrodoKEM',
    b'NTRU': 'NTRU',
    b'BIKE': 'BIKE',
    b'MCELIECE': 'Classic McEliece',
    b'HQC': 'HQC',
}


@dataclass
class PQCAlgorithm:
    """PQC 算法元数据。"""
    name: str
    family: str
    algorithm_type: str
    nist_status: str
    key_size: int
    security_level: str
    recommended: bool
    description: str = ''


@dataclass
class PQCDetectionResult:
    """单次签名命中结果。"""
    algorithm: PQCAlgorithm
    confidence: float = 0.0
    offset: int = 0
    evidence: List[str] = field(default_factory=list)


@dataclass
class PQCAnalysisResult:
    """单次二进制分析的完整结果。"""
    pqc_algorithms_found: List[PQCDetectionResult] = field(default_factory=list)
    classical_algorithms_found: List[str] = field(default_factory=list)
    migration_warnings: List[object] = field(default_factory=list)
    summary: str = ''


@dataclass
class MigrationWarning:
    """经典算法迁移警告——针对未迁移算法的降级提示。"""
    algorithm_name: str
    message: str = ''


class PQCDetector:
    """扫描二进制数据中的 PQC 签名，评估迁移风险。"""

    _CLASSICAL_ALGORITHMS = ['RSA', 'ECDSA', 'DSA', 'DH', 'AES-GCM', 'SHA-2']

    def _calculate_entropy(self, data: bytes) -> float:
        """计算字节级 Shannon 熵。"""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def _scan_for_constant(self, data: bytes, signature: bytes) -> List[int]:
        """返回 signature 在 data 中的所有字节偏移。"""
        offsets = []
        start = 0
        while True:
            idx = data.find(signature, start)
            if idx < 0:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    def _detect_pqc_algorithms(self, data: bytes) -> List[PQCDetectionResult]:
        """按字符串签名扫描数据，返回算法命中列表。"""
        results = []
        for signature, alg_name in _SIGNATURES.items():
            for offset in self._scan_for_constant(data, signature):
                params = PQC_CONSTANTS.get(alg_name)
                if params is None:
                    continue
                algorithm = PQCAlgorithm(
                    name=alg_name,
                    family=params['family'],
                    algorithm_type=params['algorithm_type'],
                    nist_status=params['nist_status'],
                    key_size=params['key_size'],
                    security_level=params['security_level'],
                    recommended=params['recommended'],
                    description=params['description'],
                )
                results.append(PQCDetectionResult(
                    algorithm=algorithm,
                    confidence=0.9,
                    offset=offset,
                    evidence=[f'String signature {signature!r} at offset {offset}'],
                ))
        return results

    def _generate_migration_warnings(self, classical_algorithms: List[str]) -> List[MigrationWarning]:
        """为仍在使用经典算法的组件生成迁移提示。"""
        warnings = []
        for alg in classical_algorithms:
            warnings.append(MigrationWarning(
                algorithm_name=alg,
                message=f'{alg} 不满足后量子安全要求，建议迁移至 NIST 标准 PQC 算法',
            ))
        return warnings

    def analyze_binary(self, path: str) -> PQCAnalysisResult:
        """分析二进制文件，返回检测结果。"""
        if not os.path.isfile(path):
            return PQCAnalysisResult(summary='文件不存在')

        with open(path, 'rb') as f:
            data = f.read()

        if not data:
            return PQCAnalysisResult(summary='空文件')

        found = self._detect_pqc_algorithms(data)
        classical = [a for a in self._CLASSICAL_ALGORITHMS if a.encode() in data]
        warnings = self._generate_migration_warnings(classical)

        summary = f'检测到 {len(found)} 个 PQC 算法'
        return PQCAnalysisResult(
            pqc_algorithms_found=found,
            classical_algorithms_found=classical,
            migration_warnings=warnings,
            summary=summary,
        )

    def format_report(self, result: PQCAnalysisResult) -> str:
        """将分析结果格式化为可读文本。"""
        lines = [f'PQC 分析报告: {result.summary}']
        for finding in result.pqc_algorithms_found:
            alg = finding.algorithm
            lines.append(
                f'- {alg.name} ({alg.family}/{alg.algorithm_type}) '
                f'confidence={finding.confidence:.2f} offset={finding.offset}'
            )
        for warning in result.migration_warnings:
            lines.append(f'- 迁移提示: {warning.algorithm_name}')
        return '\n'.join(lines)
