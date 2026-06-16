#!/usr/bin/env python3
"""
逻辑漏洞检测模块

检测常见的逻辑漏洞类型：
- TOCTOU (Time-of-check to time-of-use) 竞态条件
- 权限绕过漏洞
- 认证绕过漏洞
- 访问控制缺陷

支持结合符号执行和规则引擎进行检测。
"""

import logging
import os
import re
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """逻辑漏洞类型枚举"""
    TOCTOU = "toctou"
    PERMISSION_BYPASS = "permission_bypass"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    ACCESS_CONTROL = "access_control"
    RACE_CONDITION = "race_condition"
    SYMLINK_ATTACK = "symlink_attack"
    PATH_TRAVERSAL = "path_traversal"


class VulnerabilitySeverity(Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class VulnerabilityFinding:
    """
    逻辑漏洞检测结果
    """
    vuln_type: VulnerabilityType
    severity: VulnerabilitySeverity
    function_name: str
    address: int
    description: str
    evidence: List[str] = field(default_factory=list)
    affected_code: List[str] = field(default_factory=list)
    recommendation: str = ""
    confidence: float = 0.0


@dataclass
class TOCTOUMatch:
    """
    TOCTOU模式匹配结果
    """
    check_address: int
    use_address: int
    check_function: str
    use_function: str
    vulnerable_path: List[int] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class PermissionCheck:
    """
    权限检查信息
    """
    function_name: str
    address: int
    check_type: str  # 'access', 'stat', 'lstat', 'open'
    path_argument: int  # 参数位置
    permission_flags: int
    conditional_jump: Optional[int] = None


class LogicVulnDetector(ABC):
    """
    逻辑漏洞检测器抽象基类
    """
    
    def __init__(self, binary_path: str):
        """
        初始化检测器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        self.binary_path = binary_path
        self.findings: List[VulnerabilityFinding] = []
    
    @abstractmethod
    def analyze(self) -> List[VulnerabilityFinding]:
        """
        执行分析
        
        Returns:
            漏洞检测结果列表
        """
        pass
    
    @abstractmethod
    def detect_toctou(self) -> List[VulnerabilityFinding]:
        """
        检测TOCTOU漏洞
        
        Returns:
            TOCTOU漏洞检测结果
        """
        pass
    
    @abstractmethod
    def detect_permission_bypass(self) -> List[VulnerabilityFinding]:
        """
        检测权限绕过漏洞
        
        Returns:
            权限绕过漏洞检测结果
        """
        pass


class TOCTORuleEngine:
    """
    TOCTOU规则引擎
    
    识别常见的TOCTOU模式：
    1. access() + open() 组合
    2. stat() + open() 组合
    3. lstat() + open() 组合（lstat可以防止符号链接攻击）
    4. chown() + open() 组合
    """
    
    # TOCTOU检测规则
    TOCTOU_PATTERNS = [
        # (检查函数, 使用函数, 是否安全, 描述)
        ('access', 'open', False, 'access()后直接open()，存在TOCTOU风险'),
        ('access', 'openat', False, 'access()后直接openat()，存在TOCTOU风险'),
        ('stat', 'open', False, 'stat()后直接open()，存在TOCTOU风险'),
        ('stat', 'openat', False, 'stat()后直接openat()，存在TOCTOU风险'),
        ('stat', 'chmod', False, 'stat()后直接chmod()，存在TOCTOU风险'),
        ('stat', 'chown', False, 'stat()后直接chown()，存在TOCTOU风险'),
        ('lstat', 'open', True, 'lstat()后open()，相对安全（防止符号链接攻击）'),
        ('lstat', 'openat', True, 'lstat()后openat()，相对安全'),
        ('fstat', 'open', True, 'fstat()后open()，相对安全（已打开文件描述符）'),
    ]
    
    # 危险的文件操作序列
    DANGEROUS_SEQUENCES = [
        ['access', 'open'],
        ['access', 'chmod'],
        ['access', 'chown'],
        ['stat', 'open'],
        ['stat', 'chmod'],
        ['stat', 'chown'],
        ['stat', 'unlink'],
    ]
    
    def __init__(self):
        self.matches: List[TOCTOUMatch] = []
    
    def analyze_call_sequence(self, call_sequence: List[Tuple[str, int]]) -> List[TOCTOUMatch]:
        """
        分析调用序列，检测TOCTOU模式
        
        Args:
            call_sequence: 调用序列列表，格式为 [(函数名, 地址), ...]
            
        Returns:
            TOCTOU匹配结果列表
        """
        matches = []
        
        for i in range(len(call_sequence) - 1):
            check_func, check_addr = call_sequence[i]
            use_func, use_addr = call_sequence[i + 1]
            
            for pattern_check, pattern_use, is_safe, desc in self.TOCTOU_PATTERNS:
                if check_func == pattern_check and use_func == pattern_use:
                    confidence = 0.8 if not is_safe else 0.2
                    if not is_safe:
                        matches.append(TOCTOUMatch(
                            check_address=check_addr,
                            use_address=use_addr,
                            check_function=check_func,
                            use_function=use_func,
                            confidence=confidence
                        ))
        
        return matches
    
    def detect_dangerous_sequences(self, call_graph: Dict[str, List[str]]) -> List[str]:
        """
        检测危险的函数调用序列
        
        Args:
            call_graph: 调用图，键为函数名，值为被调用的函数列表
            
        Returns:
            危险序列描述列表
        """
        dangerous = []
        
        for func_name, called_funcs in call_graph.items():
            for sequence in self.DANGEROUS_SEQUENCES:
                if all(f in called_funcs for f in sequence):
                    dangerous.append(f"函数 {func_name} 包含危险序列: {' -> '.join(sequence)}")
        
        return dangerous


class PermissionAnalysisEngine:
    """
    权限分析引擎
    
    检测权限检查相关漏洞：
    1. 缺失的权限检查
    2. 不安全的权限比较
    3. 硬编码的权限值
    4. 权限检查后未使用结果
    """
    
    # 需要权限检查的危险操作
    DANGEROUS_OPS_REQUIRING_CHECK = [
        'open', 'openat', 'chmod', 'chown', 'unlink', 'rmdir',
        'rename', 'link', 'symlink', 'mount', 'umount'
    ]
    
    # 权限检查函数
    PERMISSION_CHECK_FUNCS = [
        'access', 'stat', 'lstat', 'fstat', 'getuid', 'getgid',
        'geteuid', 'getegid', 'setuid', 'setgid', 'cap_get_proc'
    ]
    
    # 权限标志位
    PERMISSION_FLAGS = {
        'R_OK': 4,
        'W_OK': 2,
        'X_OK': 1,
        'F_OK': 0
    }
    
    def __init__(self):
        self.permission_checks: List[PermissionCheck] = []
    
    def find_permission_checks(self, functions: Dict[str, Any]) -> List[PermissionCheck]:
        """
        查找权限检查点
        
        Args:
            functions: 函数分析结果字典
            
        Returns:
            权限检查列表
        """
        checks = []
        
        for func_name, func_info in functions.items():
            calls = func_info.get('calls', [])
            for call in calls:
                if call['name'] in ['access', 'stat', 'lstat']:
                    checks.append(PermissionCheck(
                        function_name=func_name,
                        address=call['address'],
                        check_type=call['name'],
                        path_argument=0,  # 第一个参数通常是路径
                        permission_flags=call.get('args', {}).get('mode', 0)
                    ))
        
        return checks
    
    def detect_missing_checks(self, call_graph: Dict[str, List[str]]) -> List[str]:
        """
        检测缺失权限检查的危险操作
        
        Args:
            call_graph: 调用图
            
        Returns:
            缺失检查的危险操作列表
        """
        missing_checks = []
        
        for func_name, called_funcs in call_graph.items():
            has_permission_check = any(f in self.PERMISSION_CHECK_FUNCS for f in called_funcs)
            
            for dangerous_op in self.DANGEROUS_OPS_REQUIRING_CHECK:
                if dangerous_op in called_funcs and not has_permission_check:
                    missing_checks.append({
                        'function': func_name,
                        'dangerous_op': dangerous_op,
                        'description': f"函数 {func_name} 调用 {dangerous_op} 前未进行权限检查"
                    })
        
        return missing_checks
    
    def detect_insecure_comparisons(self, instructions: List[Dict[str, Any]]) -> List[str]:
        """
        检测不安全的权限比较
        
        Args:
            instructions: 指令列表
            
        Returns:
            不安全比较列表
        """
        insecure = []
        
        # 查找硬编码的UID/GID比较
        hardcoded_patterns = [
            (0, 'root'),
            (1000, '普通用户'),
        ]
        
        for instr in instructions:
            for uid, desc in hardcoded_patterns:
                if str(uid) in instr.get('disassembly', ''):
                    insecure.append(f"检测到硬编码UID {uid} ({desc}) 比较")
        
        return insecure


class SimpleLogicVulnDetector(LogicVulnDetector):
    """
    简单逻辑漏洞检测器
    
    使用字符串匹配和规则引擎检测逻辑漏洞，无需依赖复杂的二进制分析框架。
    """
    
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        self.toctou_engine = TOCTORuleEngine()
        self.permission_engine = PermissionAnalysisEngine()
        self._binary_content = b""
        self._disassembly = ""
    
    def _load_binary(self):
        """加载二进制文件内容"""
        if os.path.exists(self.binary_path):
            with open(self.binary_path, 'rb') as f:
                self._binary_content = f.read()
    
    def _get_disassembly(self) -> str:
        """获取二进制文件的反汇编（简化实现）"""
        try:
            import subprocess
            result = subprocess.run(
                ['objdump', '-d', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except Exception:
            return ""
    
    def _parse_function_calls(self) -> Dict[str, List[str]]:
        """
        解析函数调用（简化实现）
        
        Returns:
            函数调用图字典
        """
        call_graph = defaultdict(list)
        
        disasm = self._get_disassembly()
        current_func = None
        
        for line in disasm.split('\n'):
            # 查找函数定义
            func_match = re.match(r'^([0-9a-f]+)\s+<(\w+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue
            
            # 查找函数调用
            if current_func:
                call_match = re.search(r'call\s+q?word\s+ptr\s*\[[^]]*\]\s*<(\w+)>', line)
                if not call_match:
                    call_match = re.search(r'bl?\s+[0-9a-f]+\s*<(\w+)>', line)
                
                if call_match:
                    called_func = call_match.group(1)
                    if called_func not in call_graph[current_func]:
                        call_graph[current_func].append(called_func)
        
        return dict(call_graph)
    
    def _find_string_constants(self) -> List[str]:
        """查找二进制中的字符串常量"""
        strings = []
        
        # 简单的字符串提取
        pattern = rb'[ -~]{4,}'
        for match in re.finditer(pattern, self._binary_content):
            try:
                strings.append(match.group().decode('utf-8'))
            except:
                pass
        
        return strings
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """执行完整分析"""
        logger.info(f"[LogicVuln] 开始分析逻辑漏洞: {self.binary_path}")
        
        self._load_binary()
        
        # 检测TOCTOU漏洞
        toctou_findings = self.detect_toctou()
        self.findings.extend(toctou_findings)
        
        # 检测权限绕过漏洞
        permission_findings = self.detect_permission_bypass()
        self.findings.extend(permission_findings)
        
        # 检测路径遍历漏洞
        path_findings = self.detect_path_traversal()
        self.findings.extend(path_findings)
        
        logger.info(f"[LogicVuln] 分析完成，发现 {len(self.findings)} 个逻辑漏洞")
        return self.findings
    
    def detect_toctou(self) -> List[VulnerabilityFinding]:
        """检测TOCTOU漏洞"""
        findings = []
        
        try:
            call_graph = self._parse_function_calls()
            dangerous_sequences = self.toctou_engine.detect_dangerous_sequences(call_graph)
            
            for seq_desc in dangerous_sequences:
                # 提取函数名
                func_match = re.search(r'函数 (\w+) 包含危险序列', seq_desc)
                func_name = func_match.group(1) if func_match else 'unknown'
                
                findings.append(VulnerabilityFinding(
                    vuln_type=VulnerabilityType.TOCTOU,
                    severity=VulnerabilitySeverity.HIGH,
                    function_name=func_name,
                    address=0,
                    description=seq_desc,
                    evidence=[seq_desc],
                    recommendation="考虑使用openat()配合O_NOFOLLOW标志，或使用lstat()代替stat()",
                    confidence=0.7
                ))
        
        except Exception as e:
            logger.debug(f"[LogicVuln] TOCTOU检测失败: {e}")
        
        return findings
    
    def detect_permission_bypass(self) -> List[VulnerabilityFinding]:
        """检测权限绕过漏洞"""
        findings = []
        
        try:
            call_graph = self._parse_function_calls()
            missing_checks = self.permission_engine.detect_missing_checks(call_graph)
            
            for check in missing_checks:
                findings.append(VulnerabilityFinding(
                    vuln_type=VulnerabilityType.PERMISSION_BYPASS,
                    severity=VulnerabilitySeverity.HIGH,
                    function_name=check['function'],
                    address=0,
                    description=check['description'],
                    evidence=[f"危险操作: {check['dangerous_op']}"],
                    recommendation=f"在调用 {check['dangerous_op']} 前添加适当的权限检查",
                    confidence=0.6
                ))
        
        except Exception as e:
            logger.debug(f"[LogicVuln] 权限绕过检测失败: {e}")
        
        return findings
    
    def detect_path_traversal(self) -> List[VulnerabilityFinding]:
        """检测路径遍历漏洞"""
        findings = []
        
        try:
            strings = self._find_string_constants()
            
            path_traversal_patterns = [
                '../', '..\\', '/etc/passwd', '/etc/shadow',
                '~', '/root/', '/home/', '..%2f', '..%5c'
            ]
            
            for pattern in path_traversal_patterns:
                if pattern in ' '.join(strings):
                    findings.append(VulnerabilityFinding(
                        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
                        severity=VulnerabilitySeverity.HIGH,
                        function_name='unknown',
                        address=0,
                        description=f"检测到路径遍历模式: {pattern}",
                        evidence=[f"字符串常量中包含: {pattern}"],
                        recommendation="对用户输入路径进行规范化处理，使用realpath()或pathlib进行安全解析",
                        confidence=0.5
                    ))
        
        except Exception as e:
            logger.debug(f"[LogicVuln] 路径遍历检测失败: {e}")
        
        return findings
    
    def generate_report(self) -> Dict[str, Any]:
        """生成分析报告"""
        report = {
            'binary_path': self.binary_path,
            'analysis_type': 'logic_vulnerability',
            'findings': [],
            'summary': {
                'total_findings': len(self.findings),
                'critical': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.CRITICAL),
                'high': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.HIGH),
                'medium': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.MEDIUM),
                'low': sum(1 for f in self.findings if f.severity == VulnerabilitySeverity.LOW)
            }
        }
        
        for finding in self.findings:
            report['findings'].append({
                'type': finding.vuln_type.value,
                'severity': finding.severity.value,
                'function_name': finding.function_name,
                'address': hex(finding.address),
                'description': finding.description,
                'evidence': finding.evidence,
                'recommendation': finding.recommendation,
                'confidence': finding.confidence
            })
        
        return report


class AngrLogicVulnDetector(LogicVulnDetector):
    """
    基于Angr的高级逻辑漏洞检测器
    
    使用符号执行增强TOCTOU和权限绕过检测的准确性。
    """
    
    ANGR_AVAILABLE = False
    
    def __init__(self, binary_path: str):
        super().__init__(binary_path)
        
        try:
            import angr
            self.ANGR_AVAILABLE = True
            self.project = angr.Project(binary_path, auto_load_libs=False)
        except ImportError:
            logger.warning("angr 未安装，将使用简单检测器")
            self.project = None
    
    def is_available(self) -> bool:
        """检查检测器是否可用"""
        return self.ANGR_AVAILABLE and self.project is not None
    
    def analyze(self) -> List[VulnerabilityFinding]:
        """执行分析"""
        if not self.is_available():
            # 回退到简单检测器
            simple_detector = SimpleLogicVulnDetector(self.binary_path)
            return simple_detector.analyze()
        
        logger.info(f"[AngrLogicVuln] 使用angr分析逻辑漏洞: {self.binary_path}")
        
        findings = []
        
        # 使用符号执行检测TOCTOU
        toctou_findings = self.detect_toctou()
        findings.extend(toctou_findings)
        
        # 检测权限绕过
        permission_findings = self.detect_permission_bypass()
        findings.extend(permission_findings)
        
        self.findings = findings
        return findings
    
    def detect_toctou(self) -> List[VulnerabilityFinding]:
        """检测TOCTOU漏洞"""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            # 找到所有包含危险序列的函数
            cfg = self.project.analyses.CFGEmulated()
            
            for func in cfg.kb.functions.values():
                if not func.is_simprocedure:
                    called_funcs = set()
                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            if instr.insn_name() in ['call', 'bl', 'jal', 'jalr']:
                                # 尝试获取调用目标
                                try:
                                    op_str = instr.op_str
                                    called_funcs.add(op_str)
                                except:
                                    pass
                    
                    # 检查TOCTOU模式
                    if 'access' in called_funcs and 'open' in called_funcs:
                        findings.append(VulnerabilityFinding(
                            vuln_type=VulnerabilityType.TOCTOU,
                            severity=VulnerabilitySeverity.HIGH,
                            function_name=func.name,
                            address=func.addr,
                            description=f"函数 {func.name} 包含 access() + open() 序列，存在TOCTOU竞态条件风险",
                            evidence=[f"函数地址: {hex(func.addr)}"],
                            recommendation="考虑使用openat()配合O_NOFOLLOW标志",
                            confidence=0.8
                        ))
        
        except Exception as e:
            logger.debug(f"[AngrLogicVuln] TOCTOU检测失败: {e}")
        
        return findings
    
    def detect_permission_bypass(self) -> List[VulnerabilityFinding]:
        """检测权限绕过漏洞"""
        findings = []
        
        if not self.is_available():
            return findings
        
        try:
            cfg = self.project.analyses.CFGEmulated()
            
            for func in cfg.kb.functions.values():
                if not func.is_simprocedure:
                    called_funcs = set()
                    has_permission_check = False
                    has_dangerous_op = False
                    
                    for block in func.blocks:
                        for instr in block.capstone.insns:
                            op_str = instr.op_str.lower()
                            if any(check in op_str for check in ['access', 'stat', 'lstat', 'getuid', 'getgid']):
                                has_permission_check = True
                            if any(op in op_str for op in ['open', 'chmod', 'chown', 'unlink']):
                                has_dangerous_op = True
                    
                    if has_dangerous_op and not has_permission_check:
                        findings.append(VulnerabilityFinding(
                            vuln_type=VulnerabilityType.PERMISSION_BYPASS,
                            severity=VulnerabilitySeverity.HIGH,
                            function_name=func.name,
                            address=func.addr,
                            description=f"函数 {func.name} 执行危险操作但缺少权限检查",
                            evidence=[f"函数地址: {hex(func.addr)}"],
                            recommendation="添加适当的权限验证逻辑",
                            confidence=0.7
                        ))
        
        except Exception as e:
            logger.debug(f"[AngrLogicVuln] 权限绕过检测失败: {e}")
        
        return findings


def create_logic_vuln_detector(
    binary_path: str,
    use_angr: bool = True
) -> LogicVulnDetector:
    """
    创建逻辑漏洞检测器实例
    
    Args:
        binary_path: 目标二进制文件路径
        use_angr: 是否使用angr进行增强分析
        
    Returns:
        逻辑漏洞检测器实例
    """
    if use_angr:
        detector = AngrLogicVulnDetector(binary_path)
        if detector.is_available():
            return detector
    
    return SimpleLogicVulnDetector(binary_path)


def analyze_logic_vulnerabilities(
    binary_path: str,
    use_angr: bool = True
) -> Dict[str, Any]:
    """
    便捷函数：分析逻辑漏洞
    
    Args:
        binary_path: 目标二进制文件路径
        use_angr: 是否使用angr进行增强分析
        
    Returns:
        分析结果字典
    """
    detector = create_logic_vuln_detector(binary_path, use_angr)
    findings = detector.analyze()
    
    return {
        'success': True,
        'binary_path': binary_path,
        'detector_type': type(detector).__name__,
        'findings': [
            {
                'type': f.vuln_type.value,
                'severity': f.severity.value,
                'function_name': f.function_name,
                'address': hex(f.address),
                'description': f.description,
                'evidence': f.evidence,
                'recommendation': f.recommendation,
                'confidence': f.confidence
            }
            for f in findings
        ],
        'total_findings': len(findings),
        'report': detector.generate_report()
    }