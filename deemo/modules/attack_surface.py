#!/usr/bin/env python3
"""
攻击面识别与风险排序模块

从二进制文件中识别所有对外暴露的接口，构建攻击面图并进行风险排序。
支持提取：
- 导出函数（PE/ELF符号表）
- 网络监听函数（bind, listen, accept等）
- 文件解析入口（open/fopen等）
- IPC接口（shmget, mq_open等）
- RPC接口（Microsoft RPC, gRPC等）
"""

import logging
import os
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AttackSurfaceType(Enum):
    """攻击面类型枚举"""
    EXPORTED_FUNCTION = "exported_function"
    NETWORK_INTERFACE = "network_interface"
    FILE_OPERATION = "file_operation"
    IPC_ENDPOINT = "ipc_endpoint"
    RPC_INTERFACE = "rpc_interface"
    COMMAND_LINE = "command_line"
    CONFIGURATION = "configuration"


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class AttackSurfacePoint:
    """
    攻击面点定义
    """
    name: str
    address: int
    surface_type: AttackSurfaceType
    description: str = ""
    parameters: List[str] = field(default_factory=list)
    buffer_size: Optional[int] = None
    requires_auth: bool = False
    is_remote: bool = False
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    evidence: List[str] = field(default_factory=list)
    related_vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class AttackSurfaceReport:
    """
    攻击面分析报告
    """
    binary_path: str
    surface_points: List[AttackSurfacePoint] = field(default_factory=list)
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    analysis_success: bool = False
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'binary_path': self.binary_path,
            'surface_points': [
                {
                    'name': point.name,
                    'address': hex(point.address),
                    'surface_type': point.surface_type.value,
                    'description': point.description,
                    'parameters': point.parameters,
                    'buffer_size': point.buffer_size,
                    'requires_auth': point.requires_auth,
                    'is_remote': point.is_remote,
                    'risk_score': point.risk_score,
                    'risk_level': point.risk_level.value,
                    'evidence': point.evidence,
                    'related_vulnerabilities': point.related_vulnerabilities
                }
                for point in self.surface_points
            ],
            'high_risk_count': self.high_risk_count,
            'medium_risk_count': self.medium_risk_count,
            'low_risk_count': self.low_risk_count,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message
        }


class AttackSurfaceMapper:
    """
    攻击面映射器
    
    从二进制文件中识别所有对外暴露的接口，构建攻击面图并进行风险排序。
    """

    # 网络相关函数
    NETWORK_FUNCTIONS = {
        'bind', 'listen', 'accept', 'accept4',
        'recv', 'recvfrom', 'recvmsg',
        'send', 'sendto', 'sendmsg',
        'socket', 'connect',
        'getaddrinfo', 'gethostbyname', 'gethostbyname2'
    }

    # 文件操作函数
    FILE_FUNCTIONS = {
        'open', 'openat', 'creat',
        'fopen', 'fopen64', 'freopen',
        'read', 'write', 'pread', 'pwrite',
        'fread', 'fwrite', 'fgets', 'fputs',
        'stat', 'lstat', 'fstat',
        'access', 'chmod', 'chown'
    }

    # IPC相关函数
    IPC_FUNCTIONS = {
        'shmget', 'shmat', 'shmdt', 'shmctl',
        'mq_open', 'mq_close', 'mq_send', 'mq_receive',
        'semget', 'semop', 'semctl',
        'socketpair', 'pipe', 'pipe2',
        'msgget', 'msgsnd', 'msgrcv', 'msgctl'
    }

    # RPC相关函数模式
    RPC_PATTERNS = [
        r'RpcServerRegister',
        r'RpcServerListen',
        r'RpcBinding',
        r'grpc_',
        r'__rpc_'
    ]

    # 危险函数特征
    DANGEROUS_FUNCTIONS = {
        'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
        'system', 'execve', 'popen', 'fork'
    }

    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        """
        初始化攻击面映射器
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制信息字典（可选）
        """
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.surface_points: List[AttackSurfacePoint] = []
        self._strings: List[Tuple[int, str]] = []

    def _validate_path(self) -> bool:
        """验证文件路径"""
        if not os.path.exists(self.binary_path):
            logger.error(f"文件不存在: {self.binary_path}")
            return False
        if not os.path.isfile(self.binary_path):
            logger.error(f"不是有效文件: {self.binary_path}")
            return False
        return True

    def _extract_strings(self) -> List[Tuple[int, str]]:
        """提取二进制中的可打印字符串"""
        if self._strings:
            return self._strings

        strings = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            current_offset = 0
            
            for i, byte in enumerate(data):
                if 0x20 <= byte <= 0x7E or byte in [0x09, 0x0A, 0x0D]:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append((current_offset, ''.join(current_string)))
                    current_string = []
                    current_offset = i + 1
            
            if len(current_string) >= 4:
                strings.append((current_offset, ''.join(current_string)))
            
            self._strings = strings
            logger.debug(f"提取到 {len(strings)} 个字符串")
            
        except Exception as e:
            logger.error(f"提取字符串失败: {e}")
        
        return strings

    def _extract_exported_functions(self, report: AttackSurfaceReport) -> None:
        """提取导出函数"""
        logger.debug("提取导出函数")
        
        try:
            import subprocess
            
            cmd = ['readelf', '-s', self.binary_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 8 and parts[2] == 'FUNC' and parts[6] == 'Global':
                        addr = int(parts[1], 16)
                        name = parts[-1]
                        
                        if not name.startswith('_') and not name.startswith('.'):
                            point = AttackSurfacePoint(
                                name=name,
                                address=addr,
                                surface_type=AttackSurfaceType.EXPORTED_FUNCTION,
                                description=f"导出函数: {name}",
                                requires_auth=False
                            )
                            self._calculate_risk(point)
                            report.surface_points.append(point)
            
            # 尝试使用nm作为后备
            else:
                cmd = ['nm', '-D', self.binary_path]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == 'T':
                            addr = int(parts[0], 16)
                            name = parts[-1]
                            
                            point = AttackSurfacePoint(
                                name=name,
                                address=addr,
                                surface_type=AttackSurfaceType.EXPORTED_FUNCTION,
                                description=f"导出函数: {name}",
                                requires_auth=False
                            )
                            self._calculate_risk(point)
                            report.surface_points.append(point)
        
        except Exception as e:
            logger.debug(f"提取导出函数失败: {e}")
            self._extract_exported_functions_from_strings(report)

    def _extract_exported_functions_from_strings(self, report: AttackSurfaceReport) -> None:
        """从字符串中提取潜在的导出函数名称"""
        strings = self._extract_strings()
        func_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
        
        seen = set()
        for offset, string in strings:
            if func_pattern.match(string) and len(string) > 3:
                if string not in seen:
                    seen.add(string)
                    point = AttackSurfacePoint(
                        name=string,
                        address=offset,
                        surface_type=AttackSurfaceType.EXPORTED_FUNCTION,
                        description=f"潜在导出函数: {string}",
                        requires_auth=False,
                        evidence=[f"字符串匹配: {string}"]
                    )
                    self._calculate_risk(point)
                    report.surface_points.append(point)

    def _extract_network_interfaces(self, report: AttackSurfaceReport) -> None:
        """提取网络接口"""
        logger.debug("提取网络接口")
        
        strings = self._extract_strings()
        port_pattern = re.compile(r':(\d{1,5})\b')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        url_pattern = re.compile(r'https?://[\w.-]+(?::\d+)?')
        
        for offset, string in strings:
            # 检测端口号
            port_matches = port_pattern.findall(string)
            for port in port_matches:
                port_int = int(port)
                if 1 <= port_int <= 65535:
                    protocol = self._infer_protocol(port_int)
                    point = AttackSurfacePoint(
                        name=f"network_port_{port}",
                        address=offset,
                        surface_type=AttackSurfaceType.NETWORK_INTERFACE,
                        description=f"网络端口监听: {port} ({protocol})",
                        is_remote=True,
                        evidence=[f"字符串: {string}"]
                    )
                    self._calculate_risk(point)
                    report.surface_points.append(point)
            
            # 检测IP地址
            if ip_pattern.search(string):
                point = AttackSurfacePoint(
                    name=f"network_ip_{string[:20]}",
                    address=offset,
                    surface_type=AttackSurfaceType.NETWORK_INTERFACE,
                    description=f"网络地址: {string}",
                    is_remote=True,
                    evidence=[f"字符串: {string}"]
                )
                self._calculate_risk(point)
                report.surface_points.append(point)
            
            # 检测URL
            if url_pattern.search(string):
                point = AttackSurfacePoint(
                    name=f"network_url_{string[:20]}",
                    address=offset,
                    surface_type=AttackSurfaceType.NETWORK_INTERFACE,
                    description=f"网络URL: {string}",
                    is_remote=True,
                    evidence=[f"字符串: {string}"]
                )
                self._calculate_risk(point)
                report.surface_points.append(point)

    def _infer_protocol(self, port: int) -> str:
        """根据端口号推断协议类型"""
        protocol_map = {
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            1521: 'Oracle',
            389: 'LDAP',
            445: 'SMB',
            139: 'NetBIOS'
        }
        return protocol_map.get(port, 'TCP/UDP')

    def _extract_file_operations(self, report: AttackSurfaceReport) -> None:
        """提取文件操作入口"""
        logger.debug("提取文件操作入口")
        
        strings = self._extract_strings()
        file_ext_patterns = [
            r'\.(txt|log|conf|cfg|dat|json|xml|bin|exe|dll|so)$',
            r'/etc/', r'/var/', r'/home/', r'/tmp/',
            r'C:\\', r'D:\\'
        ]
        
        for offset, string in strings:
            for pattern in file_ext_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    point = AttackSurfacePoint(
                        name=f"file_path_{string[:20]}",
                        address=offset,
                        surface_type=AttackSurfaceType.FILE_OPERATION,
                        description=f"文件路径引用: {string}",
                        is_remote=False,
                        evidence=[f"字符串: {string}"]
                    )
                    self._calculate_risk(point)
                    report.surface_points.append(point)
                    break

    def _extract_ipc_endpoints(self, report: AttackSurfaceReport) -> None:
        """提取IPC端点"""
        logger.debug("提取IPC端点")
        
        strings = self._extract_strings()
        ipc_patterns = [
            r'/tmp/',
            r'/run/',
            r'shm_',
            r'mq_',
            r'sem_',
            r'pipe_',
            r'^IPC_',
            r'^MSG_'
        ]
        
        for offset, string in strings:
            for pattern in ipc_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    point = AttackSurfacePoint(
                        name=f"ipc_{string[:20]}",
                        address=offset,
                        surface_type=AttackSurfaceType.IPC_ENDPOINT,
                        description=f"IPC端点: {string}",
                        is_remote=False,
                        evidence=[f"字符串: {string}"]
                    )
                    self._calculate_risk(point)
                    report.surface_points.append(point)
                    break

    def _extract_rpc_interfaces(self, report: AttackSurfaceReport) -> None:
        """提取RPC接口"""
        logger.debug("提取RPC接口")
        
        strings = self._extract_strings()
        
        for offset, string in strings:
            for pattern in self.RPC_PATTERNS:
                if re.search(pattern, string):
                    point = AttackSurfacePoint(
                        name=f"rpc_{string[:20]}",
                        address=offset,
                        surface_type=AttackSurfaceType.RPC_INTERFACE,
                        description=f"RPC接口: {string}",
                        is_remote=True,
                        evidence=[f"字符串: {string}"]
                    )
                    self._calculate_risk(point)
                    report.surface_points.append(point)
                    break

    def _extract_command_line_interfaces(self, report: AttackSurfaceReport) -> None:
        """提取命令行接口"""
        logger.debug("提取命令行接口")
        
        strings = self._extract_strings()
        cli_patterns = [
            r'^--\w+',
            r'^-\w',
            r'^/\w+',
            r'^-h$', r'^--help$',
            r'^-v$', r'^--version$',
            r'^--config=', r'^-c='
        ]
        
        for offset, string in strings:
            for pattern in cli_patterns:
                if re.match(pattern, string):
                    point = AttackSurfacePoint(
                        name=f"cli_option_{string[:20]}",
                        address=offset,
                        surface_type=AttackSurfaceType.COMMAND_LINE,
                        description=f"命令行选项: {string}",
                        is_remote=False,
                        evidence=[f"字符串: {string}"]
                    )
                    self._calculate_risk(point)
                    report.surface_points.append(point)
                    break

    def _calculate_risk(self, point: AttackSurfacePoint) -> None:
        """计算风险评分"""
        score = 0.0
        
        # 远程访问权重
        if point.is_remote:
            score += 30
        
        # 认证要求权重
        if not point.requires_auth:
            score += 20
        
        # 参数数量权重
        if len(point.parameters) > 3:
            score += 15
        
        # 缓冲区大小权重
        if point.buffer_size and point.buffer_size > 1024:
            score += 10
        
        # 危险函数检查
        if point.name.lower() in self.DANGEROUS_FUNCTIONS:
            score += 25
        
        # 基于类型的权重
        type_weights = {
            AttackSurfaceType.NETWORK_INTERFACE: 20,
            AttackSurfaceType.RPC_INTERFACE: 15,
            AttackSurfaceType.EXPORTED_FUNCTION: 10,
            AttackSurfaceType.FILE_OPERATION: 10,
            AttackSurfaceType.IPC_ENDPOINT: 5,
            AttackSurfaceType.COMMAND_LINE: 5
        }
        score += type_weights.get(point.surface_type, 0)
        
        # 归一化评分
        score = min(score / 1.2, 100)
        point.risk_score = round(score, 2)
        
        # 确定风险等级
        if score >= 80:
            point.risk_level = RiskLevel.CRITICAL
        elif score >= 60:
            point.risk_level = RiskLevel.HIGH
        elif score >= 40:
            point.risk_level = RiskLevel.MEDIUM
        elif score >= 20:
            point.risk_level = RiskLevel.LOW
        else:
            point.risk_level = RiskLevel.INFO

    def _categorize_by_risk(self, report: AttackSurfaceReport) -> None:
        """按风险等级分类"""
        report.high_risk_count = sum(1 for p in report.surface_points 
                                      if p.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH])
        report.medium_risk_count = sum(1 for p in report.surface_points 
                                        if p.risk_level == RiskLevel.MEDIUM)
        report.low_risk_count = sum(1 for p in report.surface_points 
                                     if p.risk_level in [RiskLevel.LOW, RiskLevel.INFO])

    def analyze(self) -> AttackSurfaceReport:
        """
        执行攻击面分析
        
        Returns:
            AttackSurfaceReport 分析报告
        """
        logger.info(f"开始攻击面分析: {self.binary_path}")
        
        report = AttackSurfaceReport(binary_path=self.binary_path)
        
        if not self._validate_path():
            report.error_message = f"无效的文件路径: {self.binary_path}"
            return report
        
        try:
            self._extract_exported_functions(report)
            self._extract_network_interfaces(report)
            self._extract_file_operations(report)
            self._extract_ipc_endpoints(report)
            self._extract_rpc_interfaces(report)
            self._extract_command_line_interfaces(report)
            
            # 去重
            seen = set()
            unique_points = []
            for point in report.surface_points:
                key = (point.name, point.surface_type)
                if key not in seen:
                    seen.add(key)
                    unique_points.append(point)
            report.surface_points = unique_points
            
            self._categorize_by_risk(report)
            
            # 按风险评分排序
            report.surface_points.sort(key=lambda p: p.risk_score, reverse=True)
            
            report.analysis_success = True
            logger.info(f"攻击面分析完成，发现 {len(report.surface_points)} 个攻击面点")
            
        except Exception as e:
            logger.error(f"攻击面分析失败: {e}")
            report.error_message = str(e)
        
        return report

    def generate_report(self, output_path: str = None) -> Optional[str]:
        """
        生成攻击面报告
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            报告内容或保存路径
        """
        report = self.analyze()
        
        if not report.analysis_success:
            return None
        
        lines = []
        lines.append("# 攻击面分析报告")
        lines.append("")
        lines.append(f"**目标文件**: `{report.binary_path}`")
        lines.append(f"**分析时间**: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("## 概览")
        lines.append("")
        lines.append(f"- 高危攻击面: {report.high_risk_count}")
        lines.append(f"- 中危攻击面: {report.medium_risk_count}")
        lines.append(f"- 低危攻击面: {report.low_risk_count}")
        lines.append(f"- 总计: {len(report.surface_points)}")
        lines.append("")
        lines.append("## 攻击面详细列表")
        lines.append("")
        lines.append("| 名称 | 类型 | 风险等级 | 评分 | 远程 | 认证 |")
        lines.append("|------|------|----------|------|------|------|")
        
        for point in report.surface_points:
            lines.append(f"| `{point.name}` | {point.surface_type.value} | {point.risk_level.value} | {point.risk_score} | {'是' if point.is_remote else '否'} | {'是' if point.requires_auth else '否'} |")
        
        report_content = '\n'.join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return output_path
        
        return report_content
