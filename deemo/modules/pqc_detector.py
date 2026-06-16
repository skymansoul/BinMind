import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

@dataclass
class PQCAlgorithm:
    """
    后量子密码算法信息
    """
    name: str
    family: str
    algorithm_type: str
    nist_status: str
    key_size: int
    security_level: str
    recommended: bool
    description: str
    references: List[str] = field(default_factory=list)

@dataclass
class PQCDetectionResult:
    """
    PQC检测结果
    """
    algorithm: PQCAlgorithm
    confidence: float
    offset: int
    context: str = ""

@dataclass
class MigrationWarning:
    """
    迁移警告信息
    """
    algorithm_name: str
    risk_level: str
    description: str
    recommended_replacement: str
    affected_functions: List[str] = field(default_factory=list)

@dataclass
class PQCAnalysisResult:
    """
    PQC分析结果汇总
    """
    pqc_algorithms_found: List[PQCDetectionResult]
    classical_algorithms_found: List[str]
    migration_warnings: List[MigrationWarning]
    summary: str

# NIST 标准化的后量子密码算法特征库
PQC_CONSTANTS = {
    'Kyber': {
        'family': 'lattice',
        'type': 'KEM',
        'nist_status': 'standardized',
        'key_sizes': [128, 192, 256],
        'security_levels': ['NIST-L1', 'NIST-L3', 'NIST-L5'],
        'description': 'CRYSTALS-Kyber: 基于模格的密钥封装机制',
        'recommended': True,
        'constants': {
            'q': 3329,
            'n': 256,
            'k': [2, 3, 4],
            'poly_mod': b'\x80\x01\x00\x00',
            'signature': b'KYBER'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2024']
    },
    'NTRU': {
        'family': 'lattice',
        'type': 'KEM',
        'nist_status': 'standardized',
        'key_sizes': [128, 192, 256],
        'security_levels': ['NIST-L1', 'NIST-L3', 'NIST-L5'],
        'description': 'NTRU Prime: 基于NTRU格的密钥封装机制',
        'recommended': True,
        'constants': {
            'q': 8192,
            'n': [509, 677, 821],
            'signature': b'NTRU'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2024']
    },
    'Sphincs+': {
        'family': 'hash-based',
        'type': 'signature',
        'nist_status': 'standardized',
        'key_sizes': [32, 48, 64],
        'security_levels': ['NIST-L1', 'NIST-L3', 'NIST-L5'],
        'description': 'SPHINCS+: 基于哈希的数字签名方案',
        'recommended': True,
        'constants': {
            'signature': b'SPHINCS'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2024']
    },
    'Dilithium': {
        'family': 'lattice',
        'type': 'signature',
        'nist_status': 'standardized',
        'key_sizes': [256, 384, 512],
        'security_levels': ['NIST-L2', 'NIST-L3', 'NIST-L5'],
        'description': 'CRYSTALS-Dilithium: 基于模格的数字签名方案',
        'recommended': True,
        'constants': {
            'q': 8380417,
            'n': 256,
            'k': [4, 6, 8],
            'l': [4, 5, 7],
            'signature': b'DILITHIUM'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2024']
    },
    'Falcon': {
        'family': 'lattice',
        'type': 'signature',
        'nist_status': 'standardized',
        'key_sizes': [512, 1024],
        'security_levels': ['NIST-L1', 'NIST-L5'],
        'description': 'Falcon: 基于NTRU格的数字签名方案',
        'recommended': True,
        'constants': {
            'n': [512, 1024],
            'q': [12289, 12289],
            'signature': b'FALCON'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2024']
    },
    'Rainbow': {
        'family': 'multivariate',
        'type': 'signature',
        'nist_status': 'alternate',
        'key_sizes': [32, 48],
        'security_levels': ['NIST-L1', 'NIST-L3'],
        'description': 'Rainbow: 基于多元二次方程组的签名方案',
        'recommended': False,
        'constants': {
            'signature': b'RAINBOW'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/round-3-submissions']
    },
    'McEliece': {
        'family': 'code-based',
        'type': 'KEM',
        'nist_status': 'alternate',
        'key_sizes': [256],
        'security_levels': ['NIST-L1'],
        'description': 'Classic McEliece: 基于二元Goppa码的KEM',
        'recommended': False,
        'constants': {
            'signature': b'MCELIECE'
        },
        'references': ['https://csrc.nist.gov/projects/post-quantum-cryptography/round-3-submissions']
    }
}

# 经典密码算法（易受量子攻击）
CLASSICAL_ALGORITHMS = {
    'RSA': {
        'type': 'asymmetric',
        'quantum_vulnerable': True,
        'risk_level': 'high',
        'replacement': 'Kyber/NTRU',
        'description': 'RSA公钥加密算法',
        'function_names': ['RSA_', 'rsa_', 'OPENSSL_rsa']
    },
    'EC': {
        'type': 'asymmetric',
        'quantum_vulnerable': True,
        'risk_level': 'high',
        'replacement': 'Dilithium/Falcon',
        'description': '椭圆曲线密码算法',
        'function_names': ['EC_', 'ec_', 'ECC_', 'ecc_', 'secp', 'nistp', 'brainpool']
    },
    'DSA': {
        'type': 'signature',
        'quantum_vulnerable': True,
        'risk_level': 'high',
        'replacement': 'Dilithium/Falcon',
        'description': '数字签名算法',
        'function_names': ['DSA_', 'dsa_']
    },
    'ECDSA': {
        'type': 'signature',
        'quantum_vulnerable': True,
        'risk_level': 'high',
        'replacement': 'Dilithium/Falcon',
        'description': '椭圆曲线数字签名算法',
        'function_names': ['ECDSA_', 'ecdsa_']
    }
}

class PQCDetector:
    """
    抗量子密码算法检测与评估模块
    
    核心功能：
    1. 识别二进制中使用的后量子密码算法（NTRU、Kyber等）
    2. 检测经典密码算法的使用（RSA、EC等）
    3. 评估参数安全性（密钥长度等）
    4. 为迁移提供预警
    """
    
    def __init__(self):
        """初始化PQC检测器"""
        logger.info("PQCDetector 初始化完成")
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的熵值
        
        Args:
            data: 要计算熵的数据
        
        Returns:
            熵值（0-8之间）
        """
        if not data:
            return 0.0
        
        import math
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _scan_for_constant(self, data: bytes, constant: bytes, min_match: int = 4) -> List[int]:
        """
        在数据中搜索常量序列
        
        Args:
            data: 要扫描的数据
            constant: 要搜索的常量
            min_match: 最小匹配长度
        
        Returns:
            匹配位置列表
        """
        positions = []
        constant_len = len(constant)
        data_len = len(data)
        
        if constant_len < min_match or data_len < min_match:
            return positions
        
        for i in range(data_len - constant_len + 1):
            if data[i:i+constant_len] == constant:
                positions.append(i)
        
        return positions
    
    def _detect_pqc_algorithms(self, data: bytes) -> List[PQCDetectionResult]:
        """
        检测二进制数据中的后量子密码算法
        
        Args:
            data: 二进制数据
        
        Returns:
            PQC算法检测结果列表
        """
        results = []
        
        for alg_name, alg_info in PQC_CONSTANTS.items():
            constants = alg_info.get('constants', {})
            
            for const_name, const_value in constants.items():
                if isinstance(const_value, bytes):
                    positions = self._scan_for_constant(data, const_value)
                    
                    for offset in positions:
                        pqc_alg = PQCAlgorithm(
                            name=alg_name,
                            family=alg_info['family'],
                            algorithm_type=alg_info['type'],
                            nist_status=alg_info['nist_status'],
                            key_size=alg_info['key_sizes'][0],
                            security_level=alg_info['security_levels'][0],
                            recommended=alg_info['recommended'],
                            description=alg_info['description'],
                            references=alg_info.get('references', [])
                        )
                        
                        results.append(PQCDetectionResult(
                            algorithm=pqc_alg,
                            confidence=1.0,
                            offset=offset,
                            context=f"Found {const_name} constant"
                        ))
        
        return results
    
    def _detect_classical_algorithms(self, binary_path: str) -> List[str]:
        """
        检测二进制中使用的经典密码算法（易受量子攻击）
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            检测到的经典算法名称列表
        """
        found_algs = []
        
        try:
            import subprocess
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'is', binary_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout
                for alg_name, alg_info in CLASSICAL_ALGORITHMS.items():
                    for func_pattern in alg_info['function_names']:
                        if func_pattern.lower() in output.lower():
                            if alg_name not in found_algs:
                                found_algs.append(alg_name)
                            break
            
            # 检查字符串
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'iz', binary_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout
                for alg_name, alg_info in CLASSICAL_ALGORITHMS.items():
                    if alg_name.lower() in output.lower() and alg_name not in found_algs:
                        found_algs.append(alg_name)
        
        except Exception as e:
            logger.debug(f"检测经典算法失败: {e}")
        
        return found_algs
    
    def _generate_migration_warnings(self, classical_algs: List[str]) -> List[MigrationWarning]:
        """
        根据检测到的经典算法生成迁移警告
        
        Args:
            classical_algs: 检测到的经典算法列表
        
        Returns:
            迁移警告列表
        """
        warnings = []
        
        for alg_name in classical_algs:
            alg_info = CLASSICAL_ALGORITHMS.get(alg_name)
            if alg_info and alg_info.get('quantum_vulnerable'):
                warnings.append(MigrationWarning(
                    algorithm_name=alg_name,
                    risk_level=alg_info['risk_level'],
                    description=f"{alg_info['description']}易受量子计算机攻击",
                    recommended_replacement=alg_info['replacement'],
                    affected_functions=alg_info['function_names']
                ))
        
        return warnings
    
    def analyze_binary(self, binary_path: str) -> PQCAnalysisResult:
        """
        分析二进制文件中的PQC算法使用情况
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            PQCAnalysisResult 对象
        """
        logger.info(f"开始分析二进制文件的PQC特征: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return PQCAnalysisResult(
                pqc_algorithms_found=[],
                classical_algorithms_found=[],
                migration_warnings=[],
                summary="文件不存在"
            )
        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # 检测PQC算法
            pqc_results = self._detect_pqc_algorithms(data)
            
            # 检测经典算法
            classical_algs = self._detect_classical_algorithms(binary_path)
            
            # 生成迁移警告
            migration_warnings = self._generate_migration_warnings(classical_algs)
            
            # 生成摘要
            summary_parts = []
            if pqc_results:
                pqc_names = set(r.algorithm.name for r in pqc_results)
                summary_parts.append(f"发现 {len(pqc_names)} 种后量子算法: {', '.join(pqc_names)}")
            else:
                summary_parts.append("未发现后量子密码算法")
            
            if classical_algs:
                summary_parts.append(f"发现 {len(classical_algs)} 种经典算法: {', '.join(classical_algs)}")
            
            if migration_warnings:
                summary_parts.append(f"生成 {len(migration_warnings)} 条迁移警告")
            
            summary = "; ".join(summary_parts)
            logger.info(f"PQC分析完成: {summary}")
            
            return PQCAnalysisResult(
                pqc_algorithms_found=pqc_results,
                classical_algorithms_found=classical_algs,
                migration_warnings=migration_warnings,
                summary=summary
            )
            
        except Exception as e:
            logger.error(f"分析二进制文件失败: {e}")
            return PQCAnalysisResult(
                pqc_algorithms_found=[],
                classical_algorithms_found=[],
                migration_warnings=[],
                summary=f"分析失败: {e}"
            )
    
    def format_report(self, result: PQCAnalysisResult) -> str:
        """
        格式化分析报告为Markdown格式
        
        Args:
            result: 分析结果
        
        Returns:
            Markdown格式的报告字符串
        """
        output = []
        
        output.append("## 抗量子密码算法分析报告")
        output.append(f"\n**摘要**: {result.summary}\n")
        
        if result.pqc_algorithms_found:
            output.append("### 发现的后量子密码算法")
            output.append("| 算法 | 类型 | NIST状态 | 安全级别 | 推荐 |")
            output.append("|------|------|----------|----------|------|")
            
            seen_algs = set()
            for detection in result.pqc_algorithms_found:
                if detection.algorithm.name not in seen_algs:
                    seen_algs.add(detection.algorithm.name)
                    rec_icon = '✅' if detection.algorithm.recommended else '⚠️'
                    nist_badge = '📋' if detection.algorithm.nist_status == 'standardized' else '📝'
                    output.append(f"| {detection.algorithm.name} | {detection.algorithm.algorithm_type} | {nist_badge} {detection.algorithm.nist_status} | {detection.algorithm.security_level} | {rec_icon} |")
            
            output.append("")
        
        if result.classical_algorithms_found:
            output.append("### 使用的经典密码算法")
            output.append("| 算法 | 风险等级 | 状态 |")
            output.append("|------|----------|------|")
            
            for alg_name in result.classical_algorithms_found:
                alg_info = CLASSICAL_ALGORITHMS.get(alg_name, {})
                risk_color = '🔴' if alg_info.get('risk_level') == 'high' else '🟡'
                output.append(f"| {alg_name} | {risk_color} {alg_info.get('risk_level', 'unknown')} | 量子脆弱 |")
            
            output.append("")
        
        if result.migration_warnings:
            output.append("### ⚠️ 量子迁移警告")
            
            for warning in result.migration_warnings:
                output.append(f"#### {warning.algorithm_name}")
                output.append(f"- **风险等级**: **{warning.risk_level}**")
                output.append(f"- **描述**: {warning.description}")
                output.append(f"- **推荐替换**: {warning.recommended_replacement}")
                output.append("")
        
        output.append("### 📌 迁移建议")
        output.append("1. 评估当前使用的经典算法的安全需求")
        output.append("2. 优先考虑NIST标准化的后量子算法（Kyber、Dilithium、Falcon、Sphincs+）")
        output.append("3. 制定过渡计划，逐步替换脆弱的密码基础设施")
        output.append("4. 关注NIST后量子密码标准的更新")
        
        return '\n'.join(output)


def get_pqc_detector() -> PQCDetector:
    """
    获取全局PQC检测器实例
    
    Returns:
        PQCDetector 实例
    """
    global _pqc_detector
    if _pqc_detector is None:
        _pqc_detector = PQCDetector()
    return _pqc_detector


# 全局PQC检测器实例
_pqc_detector = None
