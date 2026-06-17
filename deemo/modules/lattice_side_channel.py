import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class SideChannelVulnerability:
    """
    侧信道漏洞信息
    """
    name: str
    vulnerability_type: str
    severity: str
    confidence: float
    location: int
    description: str
    mitigation: str
    affected_code: str = ""

@dataclass
class TimingAnalysisResult:
    """
    计时分析结果
    """
    vulnerabilities: List[SideChannelVulnerability]
    suspicious_functions: List[str]
    timing_anomalies: int
    summary: str

@dataclass
class PolynomialOperation:
    """
    多项式操作信息
    """
    function_name: str
    operation_type: str
    coefficient_handling: str
    has_conditional_branching: bool
    has_memory_access_patterns: bool
    complexity: str

# 格密码算法特征模式
LATTICE_PATTERNS = {
    'polynomial_mult': {
        'description': '多项式乘法操作',
        'patterns': [
            r'poly_mul', r'poly_mult', r'polymul',
            r'ntru_mul', r'kyber_mul', r'dilithium_mul',
            r'mul_poly', r'mult_poly'
        ],
        'risk_level': 'high'
    },
    'polynomial_add': {
        'description': '多项式加法操作',
        'patterns': [
            r'poly_add', r'poly_addmod', r'poly_sub',
            r'ntru_add', r'kyber_add'
        ],
        'risk_level': 'low'
    },
    'polynomial_shift': {
        'description': '多项式移位操作',
        'patterns': [
            r'poly_shift', r'poly_rotate', r'poly_roll'
        ],
        'risk_level': 'medium'
    },
    'modular_reduction': {
        'description': '模约简操作',
        'patterns': [
            r'mod_reduce', r'poly_mod', r'reduce_mod',
            r'barrett', r'montgomery', r'ntt_reduce'
        ],
        'risk_level': 'high'
    },
    'ntt_transform': {
        'description': 'NTT变换操作',
        'patterns': [
            r'ntt_', r'_ntt', r'number_theoretic_transform'
        ],
        'risk_level': 'high'
    },
    'coefficient_extract': {
        'description': '系数提取操作',
        'patterns': [
            r'coeff_', r'_coeff', r'get_coeff', r'extract_coeff'
        ],
        'risk_level': 'medium'
    }
}

# 侧信道漏洞模式
SIDE_CHANNEL_PATTERNS = {
    'conditional_on_secret': {
        'name': '基于秘密的条件分支',
        'description': '代码中存在基于秘密值的条件分支，可能导致计时泄露',
        'severity': 'critical',
        'patterns': [
            r'if.*secret', r'if.*key', r'if.*coeff',
            r'cmp.*secret', r'test.*secret', r'bne.*key'
        ]
    },
    'memory_access_pattern': {
        'name': '数据依赖的内存访问模式',
        'description': '内存访问模式依赖于秘密数据，可能导致缓存攻击',
        'severity': 'high',
        'patterns': [
            r'\[.*secret.*\]', r'\[.*key.*\]', r'\[.*coeff.*\]',
            r'ldr.*\[.*key', r'str.*\[.*key', r'mov.*\[.*secret'
        ]
    },
    'table_lookup': {
        'name': '基于秘密的查表操作',
        'description': '查表操作的索引依赖于秘密数据',
        'severity': 'high',
        'patterns': [
            r'table\[.*key', r'lookup.*secret', r'sbox.*secret'
        ]
    },
    'variable_time_comparison': {
        'name': '变长比较操作',
        'description': '字符串或数据比较的时间依赖于数据内容',
        'severity': 'medium',
        'patterns': [
            r'memcmp.*secret', r'strcmp.*key', r'cmpstr.*secret'
        ]
    },
    'division_modulo': {
        'name': '变长除法/模运算',
        'description': '除法或模运算的执行时间依赖于操作数',
        'severity': 'medium',
        'patterns': [
            r'div.*secret', r'mod.*secret', r'rem.*secret'
        ]
    }
}

class LatticeSideChannelAnalyzer:
    """
    格密码时间侧信道检测模块
    
    核心功能：
    1. 识别格密码算法中的多项式运算
    2. 检测基于秘密数据的条件分支
    3. 识别数据依赖的内存访问模式
    4. 分析计时泄露风险并提供修复建议
    """
    
    def __init__(self):
        """初始化格密码侧信道分析器"""
        logger.info("LatticeSideChannelAnalyzer 初始化完成")
    
    def _extract_function_names(self, binary_path: str) -> List[str]:
        """
        从二进制文件中提取函数名称
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            函数名称列表
        """
        functions = []
        
        try:
            import subprocess
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'is', binary_path]
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) > 0:
                            func_name = parts[-1]
                            if func_name:
                                functions.append(func_name)
        
        except Exception as e:
            logger.debug(f"提取函数名失败: {e}")
        
        return functions
    
    def _extract_strings(self, binary_path: str) -> List[str]:
        """
        从二进制文件中提取字符串
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            字符串列表
        """
        strings = []
        
        try:
            import subprocess
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'iz', binary_path]
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split(' ')
                        if len(parts) > 4:
                            string_content = ' '.join(parts[4:])
                            strings.append(string_content)
        
        except Exception as e:
            logger.debug(f"提取字符串失败: {e}")
        
        return strings
    
    def _detect_lattice_operations(self, functions: List[str]) -> List[PolynomialOperation]:
        """
        检测格密码相关的多项式操作
        
        Args:
            functions: 函数名称列表
        
        Returns:
            多项式操作列表
        """
        operations = []
        
        for func_name in functions:
            for pattern_name, pattern_info in LATTICE_PATTERNS.items():
                for pattern in pattern_info['patterns']:
                    if pattern.lower() in func_name.lower():
                        operations.append(PolynomialOperation(
                            function_name=func_name,
                            operation_type=pattern_info['description'],
                            coefficient_handling='unknown',
                            has_conditional_branching=True,
                            has_memory_access_patterns=True,
                            complexity=pattern_info['risk_level']
                        

                        break
        
        return operations
    
    def _detect_side_channel_vulnerabilities(, self)
        functions: List[str], 
        strings: List[str]
    ) -> List[SideChannelVulnerability]:
        """
        检测侧信道漏洞
        
        Args:
            functions: 函数名称列表
            strings: 字符串列表
        
        Returns:
            侧信道漏洞列表
        """
        vulnerabilities = []
        location_counter = 0
        
        for vuln_type, vuln_info in SIDE_CHANNEL_PATTERNS.items():
            for pattern in vuln_info['patterns']:
                for func_name in functions:
                    if pattern.lower() in func_name.lower():
                        vulnerabilities.append(SideChannelVulnerability(
                            name=vuln_info['name'],
                            vulnerability_type=vuln_type,
                            severity=vuln_info['severity'],
                            confidence=0.85,
                            location=location_counter,
                            description=vuln_info['description'],
                            mitigation=self._get_mitigation(vuln_type),
                            affected_code=func_name
                        

                        location_counter += 1
                
                for string in strings:
                    if pattern.lower() in string.lower():
                        vulnerabilities.append(SideChannelVulnerability(
                            name=vuln_info['name'],
                            vulnerability_type=vuln_type,
                            severity=vuln_info['severity'],
                            confidence=0.7,
                            location=location_counter,
                            description=vuln_info['description'],
                            mitigation=self._get_mitigation(vuln_type),
                            affected_code=string
                        

                        location_counter += 1
        
        return vulnerabilities
    
    def _get_mitigation(self, vuln_type: str) -> str:
        """
        根据漏洞类型获取缓解建议
        
        Args:
            vuln_type: 漏洞类型
        
        Returns:
            缓解建议字符串
        """
        mitigations = {
            'conditional_on_secret': '使用常量时间比较操作，避免基于秘密的条件分支',
            'memory_access_pattern': '使用常量时间内存访问模式，考虑使用位切片技术',
            'table_lookup': '使用预计算表或常量时间查表方法',
            'variable_time_comparison': '使用常量时间比较函数（如 CRYPTO_memcmp）',
            'division_modulo': '使用常量时间除法实现或预计算结果'
        }
        return mitigations.get(vuln_type, '需要进一步分析以确定缓解措施')
    
    def _identify_suspicious_functions(self, operations: List[PolynomialOperation]) -> List[str]:
        """
        识别可疑函数
        
        Args:
            operations: 多项式操作列表
        
        Returns:
            可疑函数名称列表
        """
        suspicious = []
        for op in operations:
            if op.has_conditional_branching or op.has_memory_access_patterns:
                if op.function_name not in suspicious:
                    suspicious.append(op.function_name)
        return suspicious
    
    def analyze_binary(self, binary_path: str) -> TimingAnalysisResult:
        """
        分析二进制文件中的格密码侧信道漏洞
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            TimingAnalysisResult 对象
        """
        logger.info(f"开始分析二进制文件的格密码侧信道特征: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return TimingAnalysisResult(
                vulnerabilities=[],
                suspicious_functions=[],
                timing_anomalies=0,
                summary="文件不存在")
            

        
        try:
            # 提取函数名和字符串
            functions = self._extract_function_names(binary_path)
            strings = self._extract_strings(binary_path)
            
            # 检测格密码操作
            lattice_ops = self._detect_lattice_operations(functions)
            
            # 检测侧信道漏洞
            vulnerabilities = self._detect_side_channel_vulnerabilities(functions, strings)
            
            # 识别可疑函数
            suspicious_funcs = self._identify_suspicious_functions(lattice_ops)
            
            # 统计计时异常
            timing_anomalies = len([v for v in vulnerabilities if v.severity in ['critical', 'high']])
            
            # 生成摘要
            summary_parts = []
            if lattice_ops:
                summary_parts.append(f"发现 {len(lattice_ops)} 个格密码多项式操作")
            if vulnerabilities:
                summary_parts.append(f"发现 {len(vulnerabilities)} 个侧信道漏洞")
            if suspicious_funcs:
                summary_parts.append(f"发现 {len(suspicious_funcs)} 个可疑函数")
            if timing_anomalies > 0:
                summary_parts.append(f"发现 {timing_anomalies} 个高危计时异常")
            
            summary = "; ".join(summary_parts) if summary_parts else "未发现格密码侧信道特征"
            logger.info(f"格密码侧信道分析完成: {summary}")
            
            return TimingAnalysisResult(
                vulnerabilities=vulnerabilities,
                suspicious_functions=suspicious_funcs,
                timing_anomalies=timing_anomalies,
                summary=summary)
            

            
        except Exception as e:
            logger.error(f"分析二进制文件失败: {e}")
            return TimingAnalysisResult(
                vulnerabilities=[],
                suspicious_functions=[],
                timing_anomalies=0,
                summary=f"分析失败: {e}")
            

    
    def format_report(self, result: TimingAnalysisResult) -> str:
        """
        格式化分析报告为Markdown格式
        
        Args:
            result: 分析结果
        
        Returns:
            Markdown格式的报告字符串
        """
        output = []
        
        output.append("## 格密码时间侧信道分析报告")
        output.append(f"\n**摘要**: {result.summary}\n")
        
        if result.vulnerabilities:
            output.append("### 检测到的侧信道漏洞")
            output.append("| 漏洞名称 | 类型 | 严重程度 | 置信度 | 影响代码 |")
            output.append("|----------|------|----------|--------|----------|")
            
            severity_colors = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            for vuln in sorted(result.vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low'].index(x.severity)):
                color = severity_colors.get(vuln.severity, '⚪')
                output.append(f"| {vuln.name} | {vuln.vulnerability_type} | {color} {vuln.severity} | {vuln.confidence:.2f} | {vuln.affected_code} |")
            
            output.append("")
        
        if result.suspicious_functions:
            output.append("### 可疑函数列表")
            output.append("<details>")
            output.append("<summary>点击展开</summary>")
            output.append("")
            for func in result.suspicious_functions:
                output.append(f"- `{func}`")
            output.append("")
            output.append("</details>")
            output.append("")
        
        if result.vulnerabilities:
            output.append("### 🛡️ 缓解建议")
            
            for vuln in result.vulnerabilities:
                output.append(f"#### {vuln.name}")
                output.append(f"- **问题**: {vuln.description}")
                output.append(f"- **缓解**: {vuln.mitigation}")
                output.append("")
        
        output.append("### 📌 通用防护建议")
        output.append("1. 使用常量时间实现所有密码学操作")
        output.append("2. 避免基于秘密数据的分支和查表")
        output.append("3. 使用位切片技术消除数据依赖的内存访问")
        output.append("4. 对敏感操作进行常量时间比较")
        output.append("5. 使用经过验证的密码学库（如 OpenSSL、wolfSSL 的常量时间实现）")
        
        return '\n'.join(output)


def get_lattice_side_channel_analyzer() -> LatticeSideChannelAnalyzer:
    """
    获取全局格密码侧信道分析器实例
    
    Returns:
        LatticeSideChannelAnalyzer 实例
    """
    global _lattice_analyzer
    if _lattice_analyzer is None:
        _lattice_analyzer = LatticeSideChannelAnalyzer()
    return _lattice_analyzer


# 全局格密码侧信道分析器实例
_lattice_analyzer = None)))))