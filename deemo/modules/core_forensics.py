"""
Core Dump 自动取证与敏感数据提取模块

扩展崩溃分析能力，当分析 core dump 文件时，不仅分析崩溃原因，
还进行内存取证：提取进程内存映射、栈/堆内容、环境变量、文件描述符、
可能存在的密钥、证书、内部凭据等敏感信息，为事件响应和漏洞利用后分析提供情报。

依赖: pyelftools (用于解析 ELF core dump 格式)
"""

import os
import re
import struct
import logging
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# 敏感信息模式
SENSITIVE_PATTERNS = {
    'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'aws_secret_key': re.compile(r'[A-Za-z0-9/+=]{40}'),
    'rsa_private_key': re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    'jwt_token': re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
    'github_token': re.compile(r'ghp_[A-Za-z0-9]{36}'),
    'gitlab_token': re.compile(r'glpat-[A-Za-z0-9\-_]{20}'),
    'slack_token': re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
    'discord_token': re.compile(r'[MN][A-Za-z\d]{23,24}\.[A-Za-z\d]{6}\.[A-Za-z\d_-]{27,}'),
    'google_api_key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'azure_key': re.compile(r'[a-zA-Z0-9+/]{86}=='),
    'base64_certificate': re.compile(r'-----BEGIN CERTIFICATE-----'),
    'password_in_url': re.compile(r'[a-zA-Z]+://[^:]+:[^@]+@'),
    'connection_string': re.compile(r'(Server=.*?;|Data Source=.*?;|Database=.*?;)'),
    'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    'mac_address': re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'),
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
}

# 高熵字符串检测阈值
HIGH_ENTROPY_THRESHOLD = 4.5


class SeverityLevel(Enum):
    """严重程度等级"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class ForensicFinding:
    """取证发现项"""
    category: str
    description: str
    severity: SeverityLevel
    location: str
    content_preview: str
    raw_content: str = ""
    offset: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'category': self.category,
            'description': self.description,
            'severity': self.severity.value,
            'location': self.location,
            'content_preview': self.content_preview,
            'offset': self.offset
        }


@dataclass
class CoreForensicsReport:
    """Core Dump 取证分析报告"""
    core_file_path: str
    process_info: Dict[str, Any] = field(default_factory=dict)
    memory_mappings: List[Dict[str, Any]] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    file_descriptors: List[Dict[str, Any]] = field(default_factory=list)
    threads: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[ForensicFinding] = field(default_factory=list)
    strings_found: List[str] = field(default_factory=list)
    is_elf_core: bool = False
    analysis_success: bool = False
    error_message: str = ""
    severity_score: int = 0
    
    def get_findings_by_severity(self, severity: SeverityLevel) -> List[ForensicFinding]:
        return [f for f in self.findings if f.severity == severity]
    
    def get_critical_findings(self) -> List[ForensicFinding]:
        return self.get_findings_by_severity(SeverityLevel.CRITICAL)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'core_file_path': self.core_file_path,
            'process_info': self.process_info,
            'memory_mappings': self.memory_mappings,
            'environment_variables': self.environment_variables,
            'file_descriptors': self.file_descriptors,
            'threads': self.threads,
            'findings': [f.to_dict() for f in self.findings],
            'strings_found': self.strings_found[:100],
            'is_elf_core': self.is_elf_core,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message,
            'severity_score': self.severity_score
        }


def is_elf_core_file(file_path: str) -> bool:
    """
    检测文件是否为 ELF core dump 格式
    
    Args:
        file_path: 文件路径
        
    Returns:
        True 如果是 ELF core dump
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
            if len(header) < 16:
                return False
            if header[:4] != b'\x7fELF':
                return False
            e_type = struct.unpack('<H', header[16:18])[0]
            return e_type == 4
    except Exception as e:
        logger.debug(f"检测 ELF core 格式失败: {e}")
        return False


def calculate_entropy(data: bytes) -> float:
    """
    计算数据熵值
    
    Args:
        data: 字节数据
        
    Returns:
        熵值 (0-8)
    """
    if not data:
        return 0.0
    
    import math
    
    entropy = 0.0
    byte_counts = [0] * 256
    
    for byte in data:
        byte_counts[byte] += 1
    
    data_len = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        p = count / data_len
        entropy -= p * math.log2(p)
    
    return entropy


def mask_sensitive_content(content: str, pattern_name: str = "") -> str:
    """
    脱敏敏感内容
    
    Args:
        content: 原始内容
        pattern_name: 模式名称
        
    Returns:
        脱敏后的内容
    """
    if not content:
        return content
    
    if len(content) <= 8:
        return '*' * len(content)
    
    return content[:4] + '*' * (len(content) - 8) + content[-4:]


class CoreForensicsAnalyzer:
    """
    Core Dump 取证分析器
    
    利用 pyelftools 解析 ELF core dump 文件，提取进程信息、内存映射、
    栈/堆内容、环境变量、敏感数据等。
    """
    
    def __init__(self, timeout: int = 300):
        """
        初始化取证分析器
        
        Args:
            timeout: 分析超时时间（秒）
        """
        self.timeout = timeout
        self.pyelftools_available = self._check_pyelftools()
        
    def _check_pyelftools(self) -> bool:
        """检查 pyelftools 是否可用"""
        try:
            import elftools
            return True
        except ImportError:
            logger.warning("pyelftools 未安装，将使用备用方法解析 core dump")
            return False
    
    def analyze(self, core_file_path: str, crash_data: Dict[str, Any] = None) -> CoreForensicsReport:
        """
        分析 core dump 文件
        
        Args:
            core_file_path: core dump 文件路径
            crash_data: 可选的崩溃数据（用于关联分析）
            
        Returns:
            CoreForensicsReport 取证分析报告
        """
        logger.info(f"开始分析 core dump: {core_file_path}")
        
        report = CoreForensicsReport(core_file_path=core_file_path)
        
        try:
            if not os.path.exists(core_file_path):
                report.error_message = f"文件不存在: {core_file_path}",
                return report
            
            report.is_elf_core = is_elf_core_file(core_file_path)
            logger.info(f"ELF Core 格式检测: {report.is_elf_core}")
            
            if report.is_elf_core and self.pyelftools_available:
                self._analyze_elf_core(core_file_path, report)
            else:
                self._analyze_generic_core(core_file_path, report)
            
            self._search_sensitive_data(report)
            self._calculate_severity_score(report)
            
            report.analysis_success = True
            logger.info(f"Core dump 分析完成，发现 {len(report.findings)} 个取证项")
            
        except Exception as e:
            logger.error(f"Core dump 分析失败: {e}")
            report.error_message = str(e)
        
        return report
    
    def _analyze_elf_core(self, core_path: str, report: CoreForensicsReport) -> None:
        """
        使用 pyelftools 分析 ELF core dump
        
        Args:
            core_path: core dump 文件路径
            report: 取证报告对象
        """
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.descriptions import describe_p_flags
            
            with open(core_path, 'rb') as f:
                elf = ELFFile(f)
                
                if not elf.header['e_type'] == 'ET_CORE':
                    logger.warning("文件不是 core dump 类型")
                    return
                
                report.process_info = {
                    'e_type': 'ET_CORE',
                    'e_machine': elf.header['e_machine'],
                    'e_entry': hex(elf.header['e_entry']) if 'e_entry' in elf.header else 'N/A',
                    'e_phnum': elf.header['e_phnum'],
                    'e_phentsize': elf.header['e_phentsize'],
                }
                
                for section in elf.iter_sections():
                    section_name = section.name
                    
                    if section_name == '.note.prstatus':
                        self._parse_prstatus(section, report)
                    elif section_name == '.note.elf.note':
                        self._parse_elf_note(section, report)
                
                for program_header in elf.iter_phdrs():
                    if program_header['p_type'] == 'PT_LOAD':
                        self._parse_pt_load(program_header, report, elf)
                    elif program_header['p_type'] == 'PT_NOTE':
                        self._parse_pt_note(program_header, report, elf)
                
                for segment in elf.iter_segments():
                    if segment['p_type'] == 'PT_LOAD':
                        try:
                            data = segment.data()
                            strings = self._extract_strings(data)
                            report.strings_found.extend(strings[:50])
                        except Exception as e:
                            logger.debug(f"提取字符串失败: {e}")
                            
        except Exception as e:
            logger.error(f"ELF core 分析失败: {e}")
            raise
    
    def _parse_prstatus(self, section, report: CoreForensicsReport) -> None:
        """解析 .note.prstatus 段获取进程状态"""
        try:
            data = section.data()
            if len(data) < 148:
                return
            
            pr_info = {
                'signal': struct.unpack('<I', data[12:16])[0],
                'registers': {}
            }
            
            arch = report.process_info.get('e_machine', '')
            
            if 'x86' in arch or arch == 'EM_386':
                reg_names = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'xds', 'xes', 'xfs', 'xgs', 'orig_eax', 'eip', 'xcs', 'efl', 'uesp', 'xss']
                for i, name in enumerate(reg_names[:17]):
                    offset = 24 + i * 4,
                    if offset + 4 <= len(data):
                        pr_info['registers'][name] = hex(struct.unpack('<I', data[offset:offset + 4])[0])
            elif 'x86-64' in arch or arch == 'EM_X86_64':
                reg_names = ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'xcs', 'efl', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs']
                for i, name in enumerate(reg_names[:27]):
                    offset = 24 + i * 8,
                    if offset + 8 <= len(data):
                        pr_info['registers'][name] = hex(struct.unpack('<Q', data[offset:offset + 8])[0])
            
            report.threads.append(pr_info)
            
        except Exception as e:
            logger.debug(f"解析 prstatus 失败: {e}")
    
    def _parse_elf_note(self, section, report: CoreForensicsReport) -> None:
        """解析 ELF note 段"""
        try:
            data = section.data()
            offset = 0
            
            while offset < len(data) - 12:
                namesz = struct.unpack('<I', data[offset:offset + 4])[0]
                descsz = struct.unpack('<I', data[offset + 4:offset + 8])[0]
                n_type = struct.unpack('<I', data[offset + 8:offset + 12])[0]
                
                name = data[offset + 12:offset + 12 + namesz].rstrip(b'\x00').decode('utf-8', errors='ignore')
                
                if name == 'CORE' or name == 'LINUX':
                    if n_type == 1:
                        report.process_info['siginfo_type'] = 'NT_PRSTATUS'
                    elif n_type == 3:
                        report.process_info['siginfo_type'] = 'NT_PRPSINFO'
                    elif n_type == 4:
                        report.process_info['siginfo_type'] = 'NT_FPREGSET'
                
                offset += 12 + namesz + descsz,
                if namesz % 4:
                    offset += 4 - (namesz % 4)
                    
        except Exception as e:
            logger.debug(f"解析 ELF note 失败: {e}")
    
    def _parse_pt_load(self, phdr, report: CoreForensicsReport, elf) -> None:
        """解析 PT_LOAD 段获取内存映射"""
        try:
            mapping = {
                'start': hex(phdr['p_vaddr']),
                'end': hex(phdr['p_vaddr'] + phdr['p_filesz']),
                'offset': hex(phdr['p_offset']),
                'size': phdr['p_filesz'],
                'flags': describe_p_flags(phdr['p_flags']) if hasattr(phdr, 'p_flags') else 'N/A'
            }
            
            mapping['readable'] = 'r' in mapping.get('flags', '')
            mapping['writable'] = 'w' in mapping.get('flags', '')
            mapping['executable'] = 'x' in mapping.get('flags', '')
            
            report.memory_mappings.append(mapping)
            
        except Exception as e:
            logger.debug(f"解析 PT_LOAD 失败: {e}")
    
    def _parse_pt_note(self, phdr, report: CoreForensicsReport, elf) -> None:
        """解析 PT_NOTE 段"""
        pass
    
    def _analyze_generic_core(self, core_path: str, report: CoreForensicsReport) -> None:
        """
        使用通用方法分析 core dump
        
        Args:
            core_path: core dump 文件路径
            report: 取证报告对象
        """
        try:
            result = subprocess.run()
                ['file', core_path],
                capture_output=True,
                text=True,
                timeout=10
            
            report.process_info['file_type'] = result.stdout.strip()
            
        except Exception as e:
            logger.debug(f"获取文件类型失败: {e}")
        
        try:
            strings_output = subprocess.run()
                ['strings', '-n', '8', core_path],
                capture_output=True,
                text=True,
                timeout=60
            
            if strings_output.returncode == 0:
                report.strings_found = strings_output.stdout.split('\n')
                
        except Exception as e:
            logger.debug(f"提取字符串失败: {e}")
        
        try:
            size = os.path.getsize(core_path)
            report.process_info['file_size'] = size
            
            with open(core_path, 'rb') as f:
                f.seek(0)
                header = f.read(4096)
                
                strings_in_header = self._extract_strings(header)
                report.strings_found.extend(strings_in_header)
                
        except Exception as e:
            logger.debug(f"读取文件头失败: {e}")
    
    def _extract_strings(self, data: bytes, min_length: int = 6) -> List[str]:
        """
        从二进制数据中提取可打印字符串
        
        Args:
            data: 二进制数据
            min_length: 最小字符串长度
            
        Returns:
            字符串列表
        """
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte

            else:
                if len(current) >= min_length:
                    strings.append(''.join(current

                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current

        
        return strings
    
    def _search_sensitive_data(self, report: CoreForensicsReport) -> None:
        """
        在 core dump 中搜索敏感数据
        
        Args:
            report: 取证报告对象
        """
        logger.info("开始搜索敏感数据...")
        
        all_strings = ' '.join(report.strings_found)
        
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            for match in pattern.finditer(all_strings):
                content = match.group(0)
                
                if pattern_name == 'rsa_private_key':
                    finding = ForensicFinding()
                        category='CRYPTO_KEY',
                        description='发现 RSA/EC/DSA 私钥',
                        severity=SeverityLevel.CRITICAL,
                        location='memory',
                        content_preview=mask_sensitive_content(content, pattern_name),
                        raw_content=content,
                        offset=match.start()
                    
                    report.findings.append(finding)
                    
                elif pattern_name == 'jwt_token':
                    finding = ForensicFinding()
                        category='AUTH_TOKEN',
                        description='发现 JWT Token',
                        severity=SeverityLevel.HIGH,
                        location='memory',
                        content_preview=mask_sensitive_content(content, pattern_name),
                        raw_content=content,
                        offset=match.start()
                    
                    report.findings.append(finding)
                    
                elif pattern_name in ['aws_access_key', 'aws_secret_key']:
                    finding = ForensicFinding()
                        category='CLOUD_CREDENTIAL',
                        description='发现 AWS 凭证',
                        severity=SeverityLevel.CRITICAL,
                        location='memory',
                        content_preview=mask_sensitive_content(content, pattern_name),
                        raw_content=content,
                        offset=match.start()
                    
                    report.findings.append(finding)
                    
                elif pattern_name in ['github_token', 'gitlab_token', 'slack_token', 'discord_token']:
                    finding = ForensicFinding()
                        category='API_TOKEN',
                        description=f'发现 {pattern_name.replace("_", " ").title()}',
                        severity=SeverityLevel.HIGH,
                        location='memory',
                        content_preview=mask_sensitive_content(content, pattern_name),
                        raw_content=content,
                        offset=match.start()
                    
                    report.findings.append(finding)
                    
                elif pattern_name == 'password_in_url':
                    finding = ForensicFinding()
                        category='CREDENTIAL',
                        description='发现 URL 中的密码凭据',
                        severity=SeverityLevel.CRITICAL,
                        location='memory',
                        content_preview=mask_sensitive_content(content, pattern_name),
                        raw_content=content,
                        offset=match.start()
                    
                    report.findings.append(finding)
                    
                elif pattern_name == 'google_api_key':
                    finding = ForensicFinding()
                        category='API_KEY',
                        description='发现 Google API 密钥',
                        severity=SeverityLevel.HIGH,
                        location='memory',
                        content_preview=mask_sensitive_content(content, pattern_name),
                        raw_content=content,
                        offset=match.start()
                    
                    report.findings.append(finding)
        
        self._search_high_entropy_strings(report)
        self._search_environment_variables(report)
        self._search_file_paths(report)
    
    def _search_high_entropy_strings(self, report: CoreForensicsReport) -> None:
        """搜索高熵字符串（可能的密钥）"""
        for s in report.strings_found:
            if len(s) < 20:
                continue
            
            try:
                entropy = calculate_entropy(s.encode('utf-8'

                
                if entropy >= HIGH_ENTROPY_THRESHOLD:
                    if not any(p.match(s) for p in SENSITIVE_PATTERNS.values()):
                        finding = ForensicFinding()
                            category='HIGH_ENTROPY',
                            description='发现高熵字符串（可能是加密密钥或随机token）',
                            severity=SeverityLevel.MEDIUM,
                            location='memory',
                            content_preview=mask_sensitive_content(s),
                            raw_content=s,
                            offset=0
                        
                        report.findings.append(finding)
                        
            except Exception:
                continue
    
    def _search_environment_variables(self, report: CoreForensicsReport) -> None:
        """搜索环境变量"""
        env_pattern = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=([^\x00-\x1f\x7f]+)')
        
        all_text = ' '.join(report.strings_found)
        
        for match in env_pattern.finditer(all_text):
            key = match.group(1)
            value = match.group(2)
            
            sensitive_keys = [
                'PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'LOGNAME',
                'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'DATABASE_URL', 'DB_HOST', 'DB_PASSWORD', 'DB_USER',
                'REDIS_URL', 'REDIS_PASSWORD',
                'SECRET_KEY', 'API_KEY', 'APISECRET', 'AUTH_TOKEN',
                'GITHUB_TOKEN', 'GITLAB_TOKEN', 'DOCKER_TLS_CERTDIR',
                'MYSQL_PASSWORD', 'POSTGRES_PASSWORD', 'MONGODB_PASSWORD',
                'STRIPE_SECRET_KEY', 'SENDGRID_API_KEY', 'TWILIO_AUTH_TOKEN',
                'GOOGLE_APPLICATION_CREDENTIALS', 'VAULT_ADDR', 'VAULT_TOKEN'
            ]
            
            if key in sensitive_keys or any(k in key.upper() for k in ['SECRET', 'KEY', 'PASSWORD', 'TOKEN', 'CREDENTIAL']):
                report.environment_variables[key] = mask_sensitive_content(value, key)
                
                if any(k in key.upper() for k in ['SECRET', 'KEY', 'PASSWORD', 'TOKEN', 'CREDENTIAL', 'AWS', 'VAULT']):
                    severity = SeverityLevel.HIGH if 'PASSWORD' in key.upper() or 'SECRET' in key.upper() or 'KEY' in key.upper() else SeverityLevel.MEDIUM
                    
                    finding = ForensicFinding()
                        category='ENVIRONMENT_VARIABLE',
                        description=f'发现敏感环境变量: {key}',
                        severity=severity,
                        location='environ',
                        content_preview=f'{key}=***',
                        raw_content=f'{key}={value}',
                        offset=match.start()
                    
                    report.findings.append(finding)
    
    def _search_file_paths(self, report: CoreForensicsReport) -> None:
        """搜索文件路径"""
        path_pattern = re.compile(r'(?:/[a-zA-Z0-9_.~-]+)+/?')
        
        all_text = ' '.join(report.strings_found)
        
        sensitive_paths = []
        for match in path_pattern.finditer(all_text):
            path = match.group(0)
            
            if len(path) < 5:
                continue
            
            if any(s in path for s in ['/etc/', '/var/', '/home/', '/root/', '/tmp/', '/proc/', '/sys/']):
                sensitive_paths.append(path)
                
                if any(s in path for s in ['/etc/shadow', '/etc/passwd', '/root/.ssh/', '/home/']):
                    finding = ForensicFinding()
                        category='FILE_PATH',
                        description=f'发现敏感文件路径',
                        severity=SeverityLevel.MEDIUM,
                        location='memory',
                        content_preview=path[:50] + '...' if len(path) > 50 else path,
                        raw_content=path,
                        offset=match.start()
                    
                    report.findings.append(finding)
    
    def _calculate_severity_score(self, report: CoreForensicsReport) -> None:
        """计算严重程度评分"""
        score = 0
        
        for finding in report.findings:
            if finding.severity == SeverityLevel.CRITICAL:
                score += 10
            elif finding.severity == SeverityLevel.HIGH:
                score += 5
            elif finding.severity == SeverityLevel.MEDIUM:
                score += 2
            elif finding.severity == SeverityLevel.LOW:
                score += 1
        
        if report.memory_mappings:
            for mapping in report.memory_mappings:
                if mapping.get('executable') and mapping.get('writable'):
                    score += 3
                    break
        
        report.severity_score = min(score, 100)
        
        logger.info(f"取证严重程度评分: {report.severity_score}")


def analyze_core_dump(, core_file_path: str, crash_data: Dict[str, Any] = None, timeout: int = 300) -> CoreForensicsReport:
    """
    分析 core dump 文件的便捷函数
    
    Args:
        core_file_path: core dump 文件路径
        crash_data: 可选的崩溃数据
        timeout: 分析超时时间
        
    Returns:
        CoreForensicsReport 取证分析报告
    """
    analyzer = CoreForensicsAnalyzer(timeout=timeout)
    return analyzer.analyze(core_file_path, crash_data)


def format_forensics_report(report: CoreForensicsReport) -> str:
    """
    将取证报告格式化为可读字符串
    
    Args:
        report: CoreForensicsReport 对象
        
    Returns:
        格式化的报告字符串
    """
    lines = []
    lines.append("=" * 70)
    lines.append("Core Dump 取证分析报告")
    lines.append("=" * 70)
    
    lines.append(f"\n文件: {report.core_file_path}")
    lines.append(f"ELF Core 格式: {report.is_elf_core}")
    lines.append(f"分析成功: {report.analysis_success}")
    lines.append(f"严重程度评分: {report.severity_score}/100")
    
    if report.process_info:
        lines.append("\n--- 进程信息 ---")
        for key, value in report.process_info.items():
            lines.append(f"  {key}: {value}")
    
    if report.memory_mappings:
        lines.append("\n--- 内存映射 ---")
        for mapping in report.memory_mappings[:10]:
            flags = ''.join([)
                'r' if mapping.get('readable') else '-',
                'w' if mapping.get('writable') else '-',
                'x' if mapping.get('executable') else '-'
            ]
            lines.append(f"  {mapping['start']} - {mapping['end']} [{flags}]")
    
    if report.environment_variables:
        lines.append("\n--- 环境变量 ---")
        for key, value in list(report.environment_variables.items())[:20]:
            lines.append(f"  {key}={value}")
        if len(report.environment_variables) > 20:
            lines.append(f"  ... 还有 {len(report.environment_variables) - 20} 个变量")
    
    if report.findings:
        lines.append("\n--- 取证发现 ---")
        
        critical = report.get_critical_findings()
        if critical:
            lines.append(f"\n  [严重] {len(critical)} 个关键发现:")
            for f in critical[:5]:
                lines.append(f"    - {f.description} ({f.category})")
        
        all_findings = report.findings
        lines.append(f"\n  总计: {len(all_findings)} 个发现")
        
        by_category = {}
        for f in all_findings:
            if f.category not in by_category:
                by_category[f.category] = 0
            by_category[f.category] += 1
        
        for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"    {cat}: {count}")
    
    if report.error_message:
        lines.append(f"\n错误: {report.error_message}")
    
    lines.append("\n" + "=" * 70)
    
    return '\n'.join(lines))))))))