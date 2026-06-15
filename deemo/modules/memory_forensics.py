"""
内存快照取证与敏感信息恢复模块

支持对运行时进程进行内存快照采集，分析Windows/Linux内存镜像，
提取密钥、明文数据、数据库连接串等敏感信息，辅助事件响应。
"""

import os
import re
import json
import struct
import logging
import subprocess
import platform
import tempfile
import hashlib
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union, Tuple
from pathlib import Path
from collections import defaultdict

try:
    from config import Config
except ImportError:
    # 允许独立运行时的基本配置
    class Config:
        MEMORY_FORENSICS_OUTPUT_DIR = "data/memory_forensics"
        LOG_LEVEL = "INFO"
        VOLATILITY_PATH = "volatility3"
        MAX_STRING_LENGTH = 10000
        SENSITIVE_DATA_MASK = True


# 配置日志
log_level_str = getattr(Config, 'LOG_LEVEL', 'INFO')
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
logger = logging.getLogger(__name__)


class MemoryType(Enum):
    """内存类型枚举"""
    LIVE_PROCESS = "live_process"      # 运行时进程
    MEMORY_DUMP = "memory_dump"        # 内存镜像文件
    MINIDUMP = "minidump"              # Windows minidump
    CORE_DUMP = "core_dump"            # Linux core dump
    ELF_DUMP = "elf_dump"              # ELF格式dump
    RAW_DUMP = "raw_dump"              # 原始内存dump


class OSType(Enum):
    """操作系统类型枚举"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class SensitiveDataType(Enum):
    """敏感数据类型枚举"""
    RSA_PRIVATE_KEY = "rsa_private_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    DATABASE_CONNECTION = "database_connection"
    PASSWORD_HASH = "password_hash"
    PLAIN_PASSWORD = "plain_password"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"                        # 社会安全号码
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    SESSION_ID = "session_id"
    COOKIE = "cookie"
    AUTH_TOKEN = "auth_token"
    ENCRYPTION_KEY = "encryption_key"
    IP_ADDRESS = "ip_address"
    URL_WITH_Creds = "url_with_creds"
    EMAIL = "email"
    PHONE = "phone_number"
    OTHER = "other"


@dataclass
class ProcessInfo:
    """进程信息"""
    pid: int
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    start_time: Optional[str] = None
    parent_pid: Optional[int] = None
    threads: int = 0
    handles: int = 0
    memory_usage: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "command_line": self.command_line,
            "user": self.user,
            "start_time": self.start_time,
            "parent_pid": self.parent_pid,
            "threads": self.threads,
            "handles": self.handles,
            "memory_usage": self.memory_usage
        }


@dataclass
class NetworkConnection:
    """网络连接信息"""
    protocol: str                     # TCP/UDP
    local_addr: str                   # 本地地址
    local_port: int                   # 本地端口
    remote_addr: Optional[str] = None # 远程地址
    remote_port: Optional[int] = None # 远程端口
    state: Optional[str] = None       # 连接状态
    pid: Optional[int] = None         # 关联进程PID
    process_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "protocol": self.protocol,
            "local_addr": self.local_addr,
            "local_port": self.local_port,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "state": self.state,
            "pid": self.pid,
            "process_name": self.process_name
        }


@dataclass
class FileHandle:
    """文件句柄信息"""
    file_path: str
    handle_value: Optional[int] = None
    access_mode: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "handle_value": self.handle_value,
            "file_path": self.file_path,
            "access_mode": self.access_mode,
            "pid": self.pid,
            "process_name": self.process_name
        }


@dataclass
class RegistryKey:
    """Windows注册表键信息"""
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    value_type: Optional[str] = None
    last_write_time: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "key_path": self.key_path,
            "value_name": self.value_name,
            "value_data": self._mask_sensitive() if Config.SENSITIVE_DATA_MASK else self.value_data,
            "value_type": self.value_type,
            "last_write_time": self.last_write_time
        }
    
    def _mask_sensitive(self) -> Optional[str]:
        """脱敏处理"""
        if not self.value_data:
            return None
        # 检查是否包含敏感信息
        sensitive_patterns = [
            r'password', r'passwd', r'pwd', r'secret', r'key',
            r'token', r'credential', r'api_key'
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, self.key_path.lower() + self.value_name.lower() if self.value_name else ''):
                return "***REDACTED***"
        return self.value_data


@dataclass
class MemoryString:
    """内存字符串"""
    address: int
    content: str
    length: int
    encoding: str = "utf-8"
    context: Optional[str] = None     # 前后文
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "address": hex(self.address),
            "content": self.content[:Config.MAX_STRING_LENGTH] if len(self.content) > Config.MAX_STRING_LENGTH else self.content,
            "length": self.length,
            "encoding": self.encoding,
            "context": self.context
        }


@dataclass
class SensitiveData:
    """敏感数据"""
    data_type: SensitiveDataType
    value: str
    location: str                     # 发现位置
    address: Optional[int] = None     # 内存地址
    process: Optional[str] = None     # 关联进程
    confidence: float = 0.0           # 置信度
    context: Optional[str] = None     # 上下文
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "data_type": self.data_type.value,
            "value": self._mask_value(),
            "location": self.location,
            "address": hex(self.address) if self.address else None,
            "process": self.process,
            "confidence": self.confidence,
            "context": self.context
        }
    
    def _mask_value(self) -> str:
        """脱敏处理"""
        if not Config.SENSITIVE_DATA_MASK:
            return self.value
        
        # 根据类型进行不同程度的脱敏
        if self.data_type in [SensitiveDataType.PLAIN_PASSWORD, 
                              SensitiveDataType.AWS_SECRET_KEY,
                              SensitiveDataType.ENCRYPTION_KEY]:
            return "***REDACTED***"
        
        # 保留部分信息用于识别
        if len(self.value) > 8:
            return self.value[:4] + "****" + self.value[-4:]
        return "***REDACTED***"


@dataclass
class ForensicsResult:
    """取证分析结果"""
    source: str                       # 分析源（文件路径或PID）
    memory_type: MemoryType
    os_type: OSType
    timestamp: str
    
    # 分析结果
    processes: List[ProcessInfo] = field(default_factory=list)
    network_connections: List[NetworkConnection] = field(default_factory=list)
    file_handles: List[FileHandle] = field(default_factory=list)
    registry_keys: List[RegistryKey] = field(default_factory=list)
    memory_strings: List[MemoryString] = field(default_factory=list)
    sensitive_data: List[SensitiveData] = field(default_factory=list)
    
    # 统计信息
    total_processes: int = 0
    total_connections: int = 0
    total_handles: int = 0
    total_sensitive_items: int = 0
    
    # 元数据
    analysis_duration: Optional[float] = None
    volatility_version: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "source": self.source,
            "memory_type": self.memory_type.value,
            "os_type": self.os_type.value,
            "timestamp": self.timestamp,
            "summary": {
                "total_processes": self.total_processes,
                "total_connections": self.total_connections,
                "total_handles": self.total_handles,
                "total_sensitive_items": self.total_sensitive_items
            },
            "processes": [p.to_dict() for p in self.processes],
            "network_connections": [n.to_dict() for n in self.network_connections],
            "file_handles": [f.to_dict() for f in self.file_handles],
            "registry_keys": [r.to_dict() for r in self.registry_keys],
            "memory_strings": [m.to_dict() for m in self.memory_strings[:100]],  # 限制输出数量
            "sensitive_data": [s.to_dict() for s in self.sensitive_data],
            "analysis_duration": self.analysis_duration,
            "volatility_version": self.volatility_version,
            "errors": self.errors
        }


class MemoryForensicsAnalyzer:
    """
    内存取证分析器
    
    支持对运行时进程和内存镜像进行取证分析，
    提取进程信息、网络连接、敏感数据等。
    """
    
    # 敏感数据检测模式
    SENSITIVE_PATTERNS = {
        SensitiveDataType.RSA_PRIVATE_KEY: [
            r'-----BEGIN RSA PRIVATE KEY-----',
            r'-----BEGIN PRIVATE KEY-----',
        ],
        SensitiveDataType.AWS_ACCESS_KEY: [
            r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        ],
        SensitiveDataType.AWS_SECRET_KEY: [
            r'[A-Za-z0-9/+=]{40}',
        ],
        SensitiveDataType.API_KEY: [
            r'api[_-]?key\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
            r'apikey\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
        ],
        SensitiveDataType.JWT_TOKEN: [
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        ],
        SensitiveDataType.DATABASE_CONNECTION: [
            r'(?:mysql|postgres|mongodb|redis|oracle|sqlserver)://[^\s]+',
            r'(?:jdbc:)[^\s]+',
        ],
        SensitiveDataType.PLAIN_PASSWORD: [
            r'password\s*[=:]\s*[\'"]?[^\s\'"]{8,}[\'"]?',
            r'passwd\s*[=:]\s*[\'"]?[^\s\'"]{8,}[\'"]?',
            r'pwd\s*[=:]\s*[\'"]?[^\s\'"]{8,}[\'"]?',
        ],
        SensitiveDataType.CREDIT_CARD: [
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
        ],
        SensitiveDataType.SSN: [
            r'\b\d{3}-\d{2}-\d{4}\b',
        ],
        SensitiveDataType.PRIVATE_KEY: [
            r'-----BEGIN (?:DSA |EC |OPENSSH )?PRIVATE KEY-----',
        ],
        SensitiveDataType.CERTIFICATE: [
            r'-----BEGIN CERTIFICATE-----',
        ],
        SensitiveDataType.SESSION_ID: [
            r'session[_-]?id\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
            r'sessionid\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
        ],
        SensitiveDataType.AUTH_TOKEN: [
            r'auth[_-]?token\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
            r'token\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}[\'"]?',
        ],
        SensitiveDataType.ENCRYPTION_KEY: [
            r'encryption[_-]?key\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{16,}[\'"]?',
            r'secret[_-]?key\s*[=:]\s*[\'"]?[a-zA-Z0-9_-]{16,}[\'"]?',
        ],
        SensitiveDataType.IP_ADDRESS: [
            r'\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b',
        ],
        SensitiveDataType.URL_WITH_Creds: [
            r'https?://[^\s:]+:[^\s@]+@[^\s]+',
        ],
        SensitiveDataType.EMAIL: [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
    }
    
    # 可打印字符串的最小长度
    MIN_STRING_LENGTH = 8
    
    def __init__(self, output_dir: Optional[str] = None, volatility_path: Optional[str] = None):
        """
        初始化内存取证分析器
        
        Args:
            output_dir: 输出目录
            volatility_path: volatility3路径
        """
        self.output_dir = Path(output_dir or Config.MEMORY_FORENSICS_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.volatility_path = volatility_path or Config.VOLATILITY_PATH
        self.platform = platform.system().lower()
        
        # 检查volatility是否可用
        self.volatility_available = self._check_volatility()
        
        logger.info(f"内存取证分析器初始化，平台: {self.platform}")
        logger.info(f"Volatility可用: {self.volatility_available}")
    
    def _check_volatility(self) -> bool:
        """检查volatility是否可用"""
        try:
            result = subprocess.run(
                [self.volatility_path, "-h"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Volatility检查失败: {e}")
            return False
    
    def analyze(self, source: Union[str, int], memory_type: Optional[MemoryType] = None) -> ForensicsResult:
        """
        分析内存
        
        Args:
            source: 分析源（PID或文件路径）
            memory_type: 内存类型
            
        Returns:
            ForensicsResult对象
        """
        start_time = datetime.now()
        
        # 确定内存类型
        if memory_type is None:
            memory_type = self._detect_memory_type(source)
        
        # 确定操作系统类型
        os_type = self._detect_os_type(source, memory_type)
        
        # 创建结果对象
        result = ForensicsResult(
            source=str(source),
            memory_type=memory_type,
            os_type=os_type,
            timestamp=start_time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        logger.info(f"开始分析: {source}, 类型: {memory_type.value}, OS: {os_type.value}")
        
        try:
            # 根据类型选择分析方法
            if memory_type == MemoryType.LIVE_PROCESS:
                self._analyze_live_process(source, result)
            elif memory_type == MemoryType.MEMORY_DUMP:
                self._analyze_memory_dump(source, result)
            elif memory_type == MemoryType.MINIDUMP:
                self._analyze_minidump(source, result)
            elif memory_type == MemoryType.CORE_DUMP:
                self._analyze_core_dump(source, result)
            else:
                # 尝试通用分析
                self._analyze_generic(source, result)
            
            # 提取敏感数据
            self._extract_sensitive_data(result)
            
        except Exception as e:
            logger.error(f"分析失败: {e}")
            result.errors.append(str(e))
        
        # 计算分析时长
        end_time = datetime.now()
        result.analysis_duration = (end_time - start_time).total_seconds()
        
        # 更新统计
        result.total_processes = len(result.processes)
        result.total_connections = len(result.network_connections)
        result.total_handles = len(result.file_handles)
        result.total_sensitive_items = len(result.sensitive_data)
        
        logger.info(f"分析完成，耗时: {result.analysis_duration:.2f}s")
        return result
    
    def _detect_memory_type(self, source: Union[str, int]) -> MemoryType:
        """检测内存类型"""
        if isinstance(source, int):
            return MemoryType.LIVE_PROCESS
        
        source_str = str(source)
        
        # 检查文件扩展名
        if source_str.endswith('.dmp') or source_str.endswith('.mdmp'):
            return MemoryType.MINIDUMP
        elif source_str.endswith('.core') or 'core' in source_str.lower():
            return MemoryType.CORE_DUMP
        elif source_str.endswith('.raw') or source_str.endswith('.mem'):
            return MemoryType.RAW_DUMP
        elif source_str.endswith('.elf'):
            return MemoryType.ELF_DUMP
        
        # 尝试读取文件头判断
        try:
            with open(source_str, 'rb') as f:
                header = f.read(4)
                # Windows minidump签名
                if header == b'MDMP':
                    return MemoryType.MINIDUMP
                # ELF文件
                if header[:4] == b'\x7fELF':
                    return MemoryType.ELF_DUMP
        except Exception:
            pass
        
        return MemoryType.MEMORY_DUMP
    
    def _detect_os_type(self, source: Union[str, int], memory_type: MemoryType) -> OSType:
        """检测操作系统类型"""
        if memory_type == MemoryType.LIVE_PROCESS:
            if self.platform == 'windows':
                return OSType.WINDOWS
            elif self.platform == 'linux':
                return OSType.LINUX
            elif self.platform == 'darwin':
                return OSType.MACOS
        
        # 对于dump文件，尝试通过volatility检测
        if self.volatility_available and isinstance(source, str):
            try:
                result = subprocess.run(
                    [self.volatility_path, "-f", source, "imageinfo"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if "Windows" in result.stdout:
                    return OSType.WINDOWS
                if "Linux" in result.stdout:
                    return OSType.LINUX
            except Exception:
                pass
        
        return OSType.UNKNOWN
    
    def _analyze_live_process(self, pid: Union[str, int], result: ForensicsResult) -> None:
        """分析运行时进程"""
        pid_int = int(pid)
        
        # 检查权限
        if self.platform == 'linux' and os.geteuid() != 0:
            logger.warning("分析运行时进程需要root权限")
            result.errors.append("需要root权限才能分析运行时进程")
            return
        
        if self.platform == 'windows':
            self._analyze_windows_process(pid_int, result)
        elif self.platform == 'linux':
            self._analyze_linux_process(pid_int, result)
        else:
            logger.warning(f"不支持的平台: {self.platform}")
    
    def _analyze_linux_process(self, pid: int, result: ForensicsResult) -> None:
        """分析Linux进程"""
        proc_path = Path(f"/proc/{pid}")
        
        if not proc_path.exists():
            result.errors.append(f"进程 {pid} 不存在")
            return
        
        # 获取进程基本信息
        try:
            # 读取cmdline
            cmdline_path = proc_path / "cmdline"
            if cmdline_path.exists():
                cmdline = cmdline_path.read_text().replace('\x00', ' ').strip()
            
            # 读取status
            status_path = proc_path / "status"
            if status_path.exists():
                status_content = status_path.read_text()
                name_match = re.search(r'Name:\s*(.+)', status_content)
                uid_match = re.search(r'Uid:\s*(\d+)', status_content)
                threads_match = re.search(r'Threads:\s*(\d+)', status_content)
                
                name = name_match.group(1) if name_match else "unknown"
                uid = uid_match.group(1) if uid_match else "0"
                threads = int(threads_match.group(1)) if threads_match else 0
            
            # 读取exe路径
            exe_path = proc_path / "exe"
            exe = str(exe_path.resolve()) if exe_path.exists() else None
            
            process_info = ProcessInfo(
                pid=pid,
                name=name,
                path=exe,
                command_line=cmdline,
                user=uid,
                threads=threads
            )
            result.processes.append(process_info)
            
        except Exception as e:
            logger.warning(f"读取进程信息失败: {e}")
        
        # 读取内存映射
        try:
            maps_path = proc_path / "maps"
            if maps_path.exists():
                maps_content = maps_path.read_text()
                # 解析内存映射区域
                for line in maps_content.split('\n')[:50]:  # 限制数量
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_range = parts[0]
                        perms = parts[1]
                        # 可以进一步解析内存区域
        except Exception as e:
            logger.warning(f"读取内存映射失败: {e}")
        
        # 读取内存内容（提取字符串）
        try:
            mem_path = proc_path / "mem"
            if mem_path.exists():
                self._extract_strings_from_mem(mem_path, result)
        except PermissionError:
            logger.warning("无权限读取进程内存")
            result.errors.append("无权限读取进程内存")
        except Exception as e:
            logger.warning(f"读取内存失败: {e}")
        
        # 获取网络连接
        self._get_linux_network_connections(pid, result)
        
        # 获取文件句柄
        self._get_linux_file_handles(pid, result)
    
    def _extract_strings_from_mem(self, mem_path: Path, result: ForensicsResult) -> None:
        """从进程内存提取字符串"""
        try:
            with open(mem_path, 'rb') as f:
                # 读取部分内存（避免读取全部）
                chunk_size = 1024 * 1024  # 1MB
                max_chunks = 100  # 最多读取100MB
                
                buffer = b''
                for i in range(max_chunks):
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    buffer += chunk
                    
                    # 提取可打印字符串
                    strings = self._extract_printable_strings(buffer)
                    for addr, content in strings:
                        mem_string = MemoryString(
                            address=addr,
                            content=content,
                            length=len(content)
                        )
                        result.memory_strings.append(mem_string)
                    
                    # 保留部分buffer用于跨chunk字符串
                    buffer = buffer[-1000:] if len(buffer) > 1000 else buffer
                    
        except Exception as e:
            logger.warning(f"提取字符串失败: {e}")
    
    def _extract_printable_strings(self, data: bytes, min_length: int = 8) -> List[Tuple[int, str]]:
        """提取可打印字符串"""
        strings = []
        
        # ASCII字符串
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            try:
                content = match.group().decode('ascii')
                strings.append((match.start(), content))
            except Exception:
                pass
        
        # UTF-8字符串（尝试解码）
        utf8_pattern = rb'[\x00-\xff]{' + str(min_length * 2).encode() + rb',}'
        for match in re.finditer(utf8_pattern, data):
            try:
                content = match.group().decode('utf-8', errors='ignore')
                if content.strip() and len(content) >= min_length:
                    strings.append((match.start(), content.strip()))
            except Exception:
                pass
        
        return strings
    
    def _get_linux_network_connections(self, pid: int, result: ForensicsResult) -> None:
        """获取Linux进程网络连接"""
        try:
            # 使用netstat或ss命令
            cmd = f"netstat -tulnp 2>/dev/null | grep {pid} || ss -tulnp 2>/dev/null | grep {pid}"
            output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            for line in output.stdout.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 5:
                    protocol = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4] if len(parts) > 4 else None
                    state = parts[5] if len(parts) > 5 else None
                    
                    # 解析地址和端口
                    if ':' in local_addr:
                        addr, port = local_addr.rsplit(':', 1)
                        conn = NetworkConnection(
                            protocol=protocol,
                            local_addr=addr,
                            local_port=int(port),
                            remote_addr=remote_addr.split(':')[0] if remote_addr and ':' in remote_addr else None,
                            remote_port=int(remote_addr.rsplit(':', 1)[1]) if remote_addr and ':' in remote_addr else None,
                            state=state,
                            pid=pid
                        )
                        result.network_connections.append(conn)
                        
        except Exception as e:
            logger.warning(f"获取网络连接失败: {e}")
    
    def _get_linux_file_handles(self, pid: int, result: ForensicsResult) -> None:
        """获取Linux进程文件句柄"""
        fd_path = Path(f"/proc/{pid}/fd")
        
        if not fd_path.exists():
            return
        
        try:
            for fd in fd_path.iterdir():
                try:
                    file_path = str(fd.resolve())
                    handle = FileHandle(
                        handle_value=int(fd.name),
                        file_path=file_path,
                        pid=pid
                    )
                    result.file_handles.append(handle)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"获取文件句柄失败: {e}")
    
    def _analyze_windows_process(self, pid: int, result: ForensicsResult) -> None:
        """分析Windows进程"""
        # 使用Windows API或命令行工具
        try:
            # 使用tasklist获取进程信息
            output = subprocess.run(
                ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = output.stdout.strip().split('\n')
            if len(lines) > 1:
                # 解析CSV输出
                parts = lines[1].split(',')
                if len(parts) >= 2:
                    name = parts[0].strip('"')
                    mem_usage = parts[4].strip('"') if len(parts) > 4 else None
                    
                    process_info = ProcessInfo(
                        pid=pid,
                        name=name,
                        memory_usage=int(mem_usage.replace(' K', '').replace(',', '')) * 1024 if mem_usage else None
                    )
                    result.processes.append(process_info)
                    
        except Exception as e:
            logger.warning(f"获取Windows进程信息失败: {e}")
        
        # 使用netstat获取网络连接
        try:
            output = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for line in output.stdout.split('\n'):
                if str(pid) in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        protocol = parts[0]
                        local_addr = parts[1]
                        remote_addr = parts[2] if len(parts) > 2 else None
                        state = parts[3] if len(parts) > 3 else None
                        
                        if ':' in local_addr:
                            addr, port = local_addr.rsplit(':', 1)
                            conn = NetworkConnection(
                                protocol=protocol,
                                local_addr=addr,
                                local_port=int(port),
                                remote_addr=remote_addr.rsplit(':', 1)[0] if remote_addr and ':' in remote_addr else None,
                                remote_port=int(remote_addr.rsplit(':', 1)[1]) if remote_addr and ':' in remote_addr else None,
                                state=state,
                                pid=pid
                            )
                            result.network_connections.append(conn)
                            
        except Exception as e:
            logger.warning(f"获取Windows网络连接失败: {e}")
    
    def _analyze_memory_dump(self, source: str, result: ForensicsResult) -> None:
        """分析内存镜像文件"""
        if self.volatility_available:
            self._analyze_with_volatility(source, result)
        else:
            # 直接分析文件内容
            self._analyze_dump_file_direct(source, result)
    
    def _analyze_with_volatility(self, source: str, result: ForensicsResult) -> None:
        """使用Volatility分析"""
        # 获取volatility版本
        try:
            version_output = subprocess.run(
                [self.volatility_path, "-h"],
                capture_output=True,
                text=True,
                timeout=10
            )
            version_match = re.search(r'Volatility\s+(\d+\.\d+)', version_output.stdout)
            result.volatility_version = version_match.group(1) if version_match else "unknown"
        except Exception:
            pass
        
        # 获取进程列表
        try:
            output = subprocess.run(
                [self.volatility_path, "-f", source, "pslist"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            for line in output.stdout.split('\n'):
                if line.strip() and not line.startswith('|') and not line.startswith('-'):
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            process_info = ProcessInfo(
                                pid=int(parts[2]),
                                name=parts[0],
                                parent_pid=int(parts[3]) if len(parts) > 3 else None,
                                threads=int(parts[4]) if len(parts) > 4 else 0,
                                handles=int(parts[5]) if len(parts) > 5 else 0
                            )
                            result.processes.append(process_info)
                        except ValueError:
                            pass
                            
        except Exception as e:
            logger.warning(f"Volatility pslist失败: {e}")
            result.errors.append(f"pslist分析失败: {e}")
        
        # 获取网络连接
        try:
            output = subprocess.run(
                [self.volatility_path, "-f", source, "netscan"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            for line in output.stdout.split('\n'):
                if line.strip() and not line.startswith('|') and not line.startswith('-'):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            conn = NetworkConnection(
                                protocol=parts[0] if parts[0] else "TCP",
                                local_addr=parts[1] if len(parts) > 1 else "",
                                local_port=int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                                remote_addr=parts[3] if len(parts) > 3 else None,
                                remote_port=int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None,
                                state=parts[5] if len(parts) > 5 else None,
                                pid=int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else None
                            )
                            result.network_connections.append(conn)
                        except ValueError:
                            pass
                            
        except Exception as e:
            logger.warning(f"Volatility netscan失败: {e}")
        
        # 提取字符串
        try:
            output = subprocess.run(
                [self.volatility_path, "-f", source, "strings"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            for line in output.stdout.split('\n')[:1000]:  # 限制数量
                if len(line.strip()) >= self.MIN_STRING_LENGTH:
                    # 解析地址和内容
                    match = re.match(r'([a-fA-F0-9]+)\s*:\s*(.+)', line)
                    if match:
                        addr = int(match.group(1), 16)
                        content = match.group(2)
                        mem_string = MemoryString(
                            address=addr,
                            content=content,
                            length=len(content)
                        )
                        result.memory_strings.append(mem_string)
                        
        except Exception as e:
            logger.warning(f"Volatility strings失败: {e}")
    
    def _analyze_dump_file_direct(self, source: str, result: ForensicsResult) -> None:
        """直接分析dump文件内容"""
        try:
            with open(source, 'rb') as f:
                # 读取文件大小
                file_size = f.seek(0, 2)
                f.seek(0)
                
                logger.info(f"分析文件: {source}, 大小: {file_size}")
                
                # 分块读取提取字符串
                chunk_size = 10 * 1024 * 1024  # 10MB
                offset = 0
                
                while offset < file_size:
                    f.seek(offset)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # 提取字符串
                    strings = self._extract_printable_strings(chunk)
                    for addr, content in strings:
                        mem_string = MemoryString(
                            address=offset + addr,
                            content=content,
                            length=len(content)
                        )
                        result.memory_strings.append(mem_string)
                    
                    offset += chunk_size
                    
                    # 限制处理数量
                    if len(result.memory_strings) > 10000:
                        break
                        
        except Exception as e:
            logger.error(f"直接分析失败: {e}")
            result.errors.append(str(e))
    
    def _analyze_minidump(self, source: str, result: ForensicsResult) -> None:
        """分析Windows minidump"""
        # minidump有特定格式，尝试解析基本信息
        try:
            with open(source, 'rb') as f:
                header = f.read(4)
                if header != b'MDMP':
                    result.errors.append("无效的minidump文件")
                    return
                
                # 读取minidump目录
                # 这里简化处理，主要提取字符串
                f.seek(0)
                content = f.read()
                
                strings = self._extract_printable_strings(content)
                for addr, content in strings:
                    mem_string = MemoryString(
                        address=addr,
                        content=content,
                        length=len(content)
                    )
                    result.memory_strings.append(mem_string)
                    
        except Exception as e:
            logger.error(f"分析minidump失败: {e}")
            result.errors.append(str(e))
    
    def _analyze_core_dump(self, source: str, result: ForensicsResult) -> None:
        """分析Linux core dump"""
        # ELF格式的core dump
        try:
            with open(source, 'rb') as f:
                header = f.read(4)
                if header[:4] != b'\x7fELF':
                    result.errors.append("无效的core dump文件")
                    return
                
                # 提取字符串
                f.seek(0)
                content = f.read()
                
                strings = self._extract_printable_strings(content)
                for addr, content in strings:
                    mem_string = MemoryString(
                        address=addr,
                        content=content,
                        length=len(content)
                    )
                    result.memory_strings.append(mem_string)
                    
        except Exception as e:
            logger.error(f"分析core dump失败: {e}")
            result.errors.append(str(e))
    
    def _analyze_generic(self, source: str, result: ForensicsResult) -> None:
        """通用分析方法"""
        self._analyze_dump_file_direct(source, result)
    
    def _extract_sensitive_data(self, result: ForensicsResult) -> None:
        """从内存字符串中提取敏感数据"""
        for mem_string in result.memory_strings:
            content = mem_string.content
            
            for data_type, patterns in self.SENSITIVE_PATTERNS.items():
                for pattern in patterns:
                    try:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            sensitive = SensitiveData(
                                data_type=data_type,
                                value=match.group(),
                                location=f"内存地址 {hex(mem_string.address)}",
                                address=mem_string.address + match.start(),
                                confidence=0.8,
                                context=content[max(0, match.start()-50):match.end()+50]
                            )
                            result.sensitive_data.append(sensitive)
                    except Exception:
                        pass
        
        # 去重（基于值）
        seen_values = set()
        unique_sensitive = []
        for item in result.sensitive_data:
            value_hash = hashlib.md5(item.value.encode()).hexdigest()
            if value_hash not in seen_values:
                seen_values.add(value_hash)
                unique_sensitive.append(item)
        
        result.sensitive_data = unique_sensitive
        logger.info(f"发现 {len(result.sensitive_data)} 个敏感数据项")
    
    def dump_process_memory(self, pid: int, output_path: Optional[str] = None) -> str:
        """
        导出进程内存
        
        Args:
            pid: 进程ID
            output_path: 输出路径
            
        Returns:
            dump文件路径
        """
        if output_path is None:
            output_path = str(self.output_dir / f"process_{pid}_dump.bin")
        
        if self.platform == 'linux':
            # 使用gcore或直接读取/proc/pid/mem
            try:
                # 尝试使用gcore
                result = subprocess.run(
                    ["gcore", "-o", output_path, str(pid)],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode == 0:
                    return output_path
            except Exception:
                pass
            
            # 直接读取内存映射
            proc_path = Path(f"/proc/{pid}")
            maps_path = proc_path / "maps"
            mem_path = proc_path / "mem"
            
            if maps_path.exists() and mem_path.exists():
                with open(output_path, 'wb') as out_file:
                    with open(maps_path, 'r') as maps_file:
                        for line in maps_file:
                            parts = line.split()
                            if len(parts) >= 1:
                                addr_range = parts[0]
                                start, end = addr_range.split('-')
                                start_addr = int(start, 16)
                                end_addr = int(end, 16)
                                
                                # 只读取可读区域
                                perms = parts[1] if len(parts) > 1 else ''
                                if 'r' in perms:
                                    try:
                                        with open(mem_path, 'rb') as mem_file:
                                            mem_file.seek(start_addr)
                                            data = mem_file.read(end_addr - start_addr)
                                            out_file.write(data)
                                    except Exception:
                                        pass
                
                return output_path
                
        elif self.platform == 'windows':
            # 使用procdump或其他工具
            try:
                result = subprocess.run(
                    ["procdump", "-ma", str(pid), output_path],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if result.returncode == 0:
                    return output_path
            except Exception as e:
                logger.warning(f"procdump不可用: {e}")
        
        raise RuntimeError(f"无法导出进程 {pid} 的内存")
    
    def generate_report(self, result: ForensicsResult) -> str:
        """
       生成取证报告
        
        Args:
            result: 分析结果
            
        Returns:
            Markdown格式报告
        """
        report_lines = [
            "# 内存取证分析报告",
            "",
            f"**分析时间**: {result.timestamp}",
            f"**分析源**: {result.source}",
            f"**内存类型**: {result.memory_type.value}",
            f"**操作系统**: {result.os_type.value}",
            f"**分析耗时**: {result.analysis_duration:.2f}s",
            "",
            "## 统计摘要",
            "",
            "| 项目 | 数量 |",
            "|------|------|",
            f"| 进程数 | {result.total_processes} |",
            f"| 网络连接数 | {result.total_connections} |",
            f"| 文件句柄数 | {result.total_handles} |",
            f"| 敏感数据项 | {result.total_sensitive_items} |",
            f"| 内存字符串数 | {len(result.memory_strings)} |",
            "",
        ]
        
        # 进程列表
        if result.processes:
            report_lines.extend([
                "## 进程列表",
                "",
                "| PID | 名称 | 路径 | 用户 | 线程数 |",
                "|-----|------|------|------|--------|",
            ])
            for proc in result.processes[:20]:  # 限制显示数量
                report_lines.append(
                    f"| {proc.pid} | {proc.name} | {proc.path or 'N/A'} | {proc.user or 'N/A'} | {proc.threads} |"
                )
            report_lines.append("")
        
        # 网络连接
        if result.network_connections:
            report_lines.extend([
                "## 网络连接",
                "",
                "| 协议 | 本地地址 | 本地端口 | 远程地址 | 远程端口 | 状态 |",
                "|------|----------|----------|----------|----------|------|",
            ])
            for conn in result.network_connections[:20]:
                report_lines.append(
                    f"| {conn.protocol} | {conn.local_addr} | {conn.local_port} | "
                    f"{conn.remote_addr or 'N/A'} | {conn.remote_port or 'N/A'} | {conn.state or 'N/A'} |"
                )
            report_lines.append("")
        
        # 文件句柄
        if result.file_handles:
            report_lines.extend([
                "## 文件句柄",
                "",
                "| FD | 文件路径 |",
                "|----|----------|",
            ])
            for handle in result.file_handles[:20]:
                report_lines.append(f"| {handle.handle_value or 'N/A'} | {handle.file_path} |")
            report_lines.append("")
        
        # 敏感数据
        if result.sensitive_data:
            report_lines.extend([
                "## 发现的敏感数据",
                "",
                "| 类型 | 位置 | 置信度 |",
                "|------|------|--------|",
            ])
            for item in result.sensitive_data[:50]:
                report_lines.append(
                    f"| {item.data_type.value} | {item.location} | {item.confidence:.2f} |"
                )
            report_lines.append("")
            
            # 添加警告
            report_lines.extend([
                "### ⚠️ 安全警告",
                "",
                "以下类型的敏感数据被发现:",
                "",
            ])
            type_counts = defaultdict(int)
            for item in result.sensitive_data:
                type_counts[item.data_type.value] += 1
            
            for data_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                report_lines.append(f"- **{data_type}**: {count} 个")
            report_lines.append("")
        
        # 错误信息
        if result.errors:
            report_lines.extend([
                "## 分析错误",
                "",
            ])
            for error in result.errors:
                report_lines.append(f"- {error}")
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    def save_result(self, result: ForensicsResult, filename: Optional[str] = None) -> str:
        """
        保存分析结果
        
        Args:
            result: 分析结果
            filename: 文件名
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensics_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        # 保存JSON格式结果
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        # 同时保存报告
        report_path = filepath.with_suffix('.md')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(result))
        
        logger.info(f"结果已保存: {filepath}")
        return str(filepath)


# 便捷函数
def analyze_memory(source: Union[str, int], output_dir: Optional[str] = None) -> ForensicsResult:
    """
    便捷函数：分析内存
    
    Args:
        source: PID或文件路径
        output_dir: 输出目录
        
    Returns:
        ForensicsResult对象
    """
    analyzer = MemoryForensicsAnalyzer(output_dir)
    result = analyzer.analyze(source)
    analyzer.save_result(result)
    return result


if __name__ == "__main__":
    # 示例用法
    import sys
    
    analyzer = MemoryForensicsAnalyzer()
    
    if len(sys.argv) > 1:
        source = sys.argv[1]
        try:
            pid = int(source)
            print(f"分析进程: {pid}")
        except ValueError:
            print(f"分析文件: {source}")
        
        result = analyzer.analyze(source)
        analyzer.save_result(result)
        
        print("\n分析完成!")
        print(f"发现进程: {result.total_processes}")
        print(f"发现连接: {result.total_connections}")
        print(f"敏感数据: {result.total_sensitive_items}")
    else:
        print("用法: python memory_forensics.py <pid或文件路径>")
        print("\n示例:")
        print("  python memory_forensics.py 1234        # 分析进程1234")
        print("  python memory_forensics.py dump.raw    # 分析内存镜像")