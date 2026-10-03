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
from typing import Optional, List, Dict, Any, Union, Tuple
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

# 独立运行时的回退配置
class Config:
    MEMORY_FORENSICS_OUTPUT_DIR = "data/memory_forensics"
    LOG_LEVEL = "INFO"
    VOLATILITY_PATH = "volatility3"
    MAX_STRING_LENGTH = 10000
    SENSITIVE_DATA_MASK = True


# 按配置级别初始化日志管道
log_level_str = getattr(Config, 'LOG_LEVEL', 'INFO')
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
logger = logging.getLogger(__name__)


class MemoryType(Enum):
    # 内存来源工件类型分类
    LIVE_PROCESS = "live_process"      # 运行中进程内存快照
    MEMORY_DUMP = "memory_dump"        # 完整物理内存镜像
    MINIDUMP = "minidump"              # Windows minidump 格式 (MDMP)
    CORE_DUMP = "core_dump"            # Linux ELF core dump 工件
    ELF_DUMP = "elf_dump"              # ELF 结构化内存转储
    RAW_DUMP = "raw_dump"              # 非结构化二进制内存快照


class OSType(Enum):
    # 操作系统平台标识
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"

class SensitiveDataType(Enum):
    # 敏感数据分类体系，用于内存模式匹配
    RSA_PRIVATE_KEY = "rsa_private_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    DATABASE_CONNECTION = "database_connection"
    PASSWORD_HASH = "password_hash"
    PLAIN_PASSWORD = "plain_password"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"                        # 美国社会安全号 (###-##-####)
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
    # 从活动或快照内存中提取的进程元数据记录
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
    # 从进程或内存镜像捕获的网络套接字状态描述符
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    state: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
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
    # 从进程状态枚举的打开文件描述符记录
    file_path: str
    handle_value: Optional[int] = None
    access_mode: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle_value": self.handle_value,
            "file_path": self.file_path,
            "access_mode": self.access_mode,
            "pid": self.pid,
            "process_name": self.process_name
        }


@dataclass
class RegistryKey:
    # 从内存恢复的 Windows 注册表蜂巢条目
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    value_type: Optional[str] = None
    last_write_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_path": self.key_path,
            "value_name": self.value_name,
            "value_data": self._mask_sensitive() if Config.SENSITIVE_DATA_MASK else self.value_data,
            "value_type": self.value_type,
            "last_write_time": self.last_write_time
        }

    def _mask_sensitive(self) -> Optional[str]:
        # 对键名匹配敏感词的注册表值进行脱敏
        if not self.value_data:
            return None
        # 按敏感词目录匹配键路径和值名
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
    # 从内存区域恢复的可打印字符串工件
    address: int
    content: str
    length: int
    encoding: str = "utf-8"
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "content": self.content[:Config.MAX_STRING_LENGTH] if len(self.content) > Config.MAX_STRING_LENGTH else self.content,
            "length": self.length,
            "encoding": self.encoding,
            "context": self.context
        }


@dataclass
class SensitiveData:
    # 带来源位置和置信度的敏感数据发现
    data_type: SensitiveDataType
    value: str
    location: str
    address: Optional[int] = None
    process: Optional[str] = None
    confidence: float = 0.0
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
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
        # 按类型分级对敏感字段值脱敏以安全导出
        if not Config.SENSITIVE_DATA_MASK:
            return self.value

        # 认证关键类别完全遮蔽
        if self.data_type in [SensitiveDataType.PLAIN_PASSWORD,
                              SensitiveDataType.AWS_SECRET_KEY,
                              SensitiveDataType.ENCRYPTION_KEY]:
            return "***REDACTED***"

        # 前后缀保留以支持取证可追溯性
        if len(self.value) > 8:
            return self.value[:4] + "****" + self.value[-4:]
        return "***REDACTED***"


@dataclass
class ForensicsResult:
    # 单次内存取证实况的完整结果集
    source: str
    memory_type: MemoryType
    os_type: OSType
    timestamp: str
    processes: List[ProcessInfo] = field(default_factory=list)
    network_connections: List[NetworkConnection] = field(default_factory=list)
    file_handles: List[FileHandle] = field(default_factory=list)
    registry_keys: List[RegistryKey] = field(default_factory=list)
    memory_strings: List[MemoryString] = field(default_factory=list)
    sensitive_data: List[SensitiveData] = field(default_factory=list)
    total_processes: int = 0
    total_connections: int = 0
    total_handles: int = 0
    total_sensitive_items: int = 0
    analysis_duration: Optional[float] = None
    volatility_version: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
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
            "memory_strings": [m.to_dict() for m in self.memory_strings[:100]],  # 截断字符串列表至前 100 条
            "sensitive_data": [s.to_dict() for s in self.sensitive_data],
            "analysis_duration": self.analysis_duration,
            "volatility_version": self.volatility_version,
            "errors": self.errors
        }


class MemoryForensicsAnalyzer:
    # 内存取证分析引擎：从进程快照和离线镜像提取进程、网络套接字、文件描述符、嵌入字符串和敏感数据

    # 敏感数据分类正则模式库
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
            r'(?:jdbc:[^\s]+',
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

    # 可识别可打印字符串的最小码点数
    MIN_STRING_LENGTH = 8

    def __init__(self, output_dir: Optional[str] = None, volatility_path: Optional[str] = None):
        # 初始化输出目录和工具路径配置
        self.output_dir = Path(output_dir or Config.MEMORY_FORENSICS_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.volatility_path = volatility_path or Config.VOLATILITY_PATH
        self.platform = platform.system().lower()

        # 检查 Volatility CLI 在本机是否可用
        self.volatility_available = self._check_volatility()

        logger.info(f"Memory forensics engine started, platform: {self.platform}")
        logger.info(f"Volatility framework detected: {self.volatility_available}")

    def _check_volatility(self) -> bool:
        # 测试 Volatility 二进制是否可调用
        try:
            result = subprocess.run(
                [self.volatility_path, "-h"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Volatility probe rejected: {e}")
            return False

    def analyze(self, source: Union[str, int], memory_type: Optional[MemoryType] = None) -> ForensicsResult:
        # 对来源工件执行完整取证分析流水线
        start_time = datetime.now()

        # 从来源标识推断内存工件类型
        if memory_type is None:
            memory_type = self._detect_memory_type(source)

        # 确定目标操作系统
        os_type = self._detect_os_type(source, memory_type)

        # 用会话元数据初始化结果聚合器
        result = ForensicsResult(
            source=str(source),
            memory_type=memory_type,
            os_type=os_type,
            timestamp=start_time.strftime("%Y-%m-%d %H:%M:%S")
        )

        logger.info(f"Analysis initiated: source={source}, memory_type={memory_type.value}, os={os_type.value}")

        try:
            # 按类型分发到对应分析处理器
            if memory_type == MemoryType.LIVE_PROCESS:
                self._analyze_live_process(source, result)
            elif memory_type == MemoryType.MEMORY_DUMP:
                self._analyze_memory_dump(source, result)
            elif memory_type == MemoryType.MINIDUMP:
                self._analyze_minidump(source, result)
            elif memory_type == MemoryType.CORE_DUMP:
                self._analyze_core_dump(source, result)
            else:
                # 默认路径：当作非结构化二进制块处理
                self._analyze_generic(source, result)

            # 用敏感数据模式库扫描恢复的字符串
            self._extract_sensitive_data(result)

        except Exception as e:
            logger.error(f"Analysis pipeline aborted: {e}")
            result.errors.append(str(e))


        # 记录挂钟耗时
        end_time = datetime.now()
        result.analysis_duration = (end_time - start_time).total_seconds()

        # 从结果容器汇总统计
        result.total_processes = len(result.processes)
        result.total_connections = len(result.network_connections)
        result.total_handles = len(result.file_handles)
        result.total_sensitive_items = len(result.sensitive_data)

        logger.info(f"Analysis finished, wall-clock: {result.analysis_duration:.2f}s")
        return result

    def _detect_memory_type(self, source: Union[str, int]) -> MemoryType:
        # 从来源句柄分类内存工件类型
        if isinstance(source, int):
            return MemoryType.LIVE_PROCESS

        source_str = str(source)

        # 基于扩展名的启发式分类层
        if source_str.endswith('.dmp') or source_str.endswith('.mdmp'):
            return MemoryType.MINIDUMP
        elif source_str.endswith('.core') or 'core' in source_str.lower():
            return MemoryType.CORE_DUMP
        elif source_str.endswith('.raw') or source_str.endswith('.mem'):
            return MemoryType.RAW_DUMP
        elif source_str.endswith('.elf'):
            return MemoryType.ELF_DUMP

        # 魔数签名验证层
        try:
            with open(source_str, 'rb') as f:
                header = f.read(4)
                # MDMP FourCC：Windows minidump 签名
                if header == b'MDMP':
                    return MemoryType.MINIDUMP
                # 0x7F E L F：ELF 格式魔数
                if header[:4] == b'\x7fELF':
                    return MemoryType.ELF_DUMP
        except Exception:
            logger.debug("suppressed", exc_info=True)

        return MemoryType.MEMORY_DUMP

    def _detect_os_type(self, source: Union[str, int], memory_type: MemoryType) -> OSType:
        # 确定产生此工件的操作系统
        if memory_type == MemoryType.LIVE_PROCESS:
            if self.platform == 'windows':
                return OSType.WINDOWS
            elif self.platform == 'linux':
                return OSType.LINUX
            elif self.platform == 'darwin':
                return OSType.MACOS

        # 查询 Volatility imageinfo 插件识别转储文件 OS 指纹
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
                logger.debug("suppressed", exc_info=True)

        return OSType.UNKNOWN

    def _analyze_live_process(self, pid: Union[str, int], result: ForensicsResult) -> None:
        # 对给定 PID 执行实时进程分析
        pid_int = int(pid)

        # Linux 上访问 /proc/<pid>/mem 需要 root
        if self.platform == 'linux' and os.geteuid() != 0:
            logger.warning("Insufficient privileges: root required for live process memory access")
            result.errors.append("Root privileges required for live process analysis")
            return

        if self.platform == 'windows':
            self._analyze_windows_process(pid_int, result)
        elif self.platform == 'linux':
            self._analyze_linux_process(pid_int, result)
        else:
            logger.warning(f"Platform unsupported for live analysis: {self.platform}")

    def _analyze_linux_process(self, pid: int, result: ForensicsResult) -> None:
        # 通过 /proc 文件系统从 Linux 进程提取工件
        proc_path = Path(f"/proc/{pid}")

        if not proc_path.exists():
            result.errors.append(f"Process {pid} does not exist")
            return

        # 从 /proc 条目采集进程身份元数据
        try:
            # 从 /proc/<pid>/cmdline 读取命令行参数
            cmdline_path = proc_path / "cmdline"
            if cmdline_path.exists():
                cmdline = cmdline_path.read_text().replace('\x00', ' ').strip()

            # 从 /proc/<pid>/status 提取名称、UID 和线程数
            status_path = proc_path / "status"
            if status_path.exists():
                status_content = status_path.read_text()
                name_match = re.search(r'Name:\s*(.+)', status_content)
                uid_match = re.search(r'Uid:\s*(\d+)', status_content)
                threads_match = re.search(r'Threads:\s*(\d+)', status_content)

                name = name_match.group(1) if name_match else "unknown"
                uid = uid_match.group(1) if uid_match else "0"
                threads = int(threads_match.group(1)) if threads_match else 0

            # 跟随 /proc/<pid>/exe 符号链接获取二进制路径
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
            logger.warning(f"Process metadata read failed: {e}")

        # 遍历 /proc/<pid>/maps 获取虚拟内存区域布局
        try:
            maps_path = proc_path / "maps"
            if maps_path.exists():
                maps_content = maps_path.read_text()
                # 按映射区域解码地址范围和权限位
                for line in maps_content.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 5:
                        addr_range = parts[0]
                        perms = parts[1]
                        # 预留：未来按区域做详细检查
        except Exception as e:
            logger.warning(f"Memory maps read failed: {e}")

        # 扫描进程虚拟内存中的可打印字符串工件
        try:
            mem_path = proc_path / "mem"
            if mem_path.exists():
                self._extract_strings_from_mem(mem_path, result)
        except PermissionError:
            logger.warning("Permission denied accessing process virtual memory")
            result.errors.append("Insufficient permission to read process memory")
        except Exception as e:
            logger.warning(f"Process memory access failed: {e}")

        # 枚举活动网络套接字描述符
        self._get_linux_network_connections(pid, result)

        # 枚举打开文件描述符表
        self._get_linux_file_handles(pid, result)

    def _extract_strings_from_mem(self, mem_path: Path, result: ForensicsResult) -> None:
        # 分块读取进程内存，提取可打印字符串
        try:
            with open(mem_path, 'rb') as f:
                # 限制读取大小防止资源耗尽
                chunk_size = 1024 * 1024  # 1 MB
                max_chunks = 100  # 总处理上限 100 MB

                buffer = b''
                for i in range(max_chunks):
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    buffer += chunk

                    # 从当前块提取可打印字符串序列
                    strings = self._extract_printable_strings(buffer)
                    for addr, content in strings:
                        mem_string = MemoryString(
                            address=addr,
                            content=content,
                            length=len(content)
                        )
                        result.memory_strings.append(mem_string)

                    # 保留尾部窗口以捕获跨块边界的碎片
                    buffer = buffer[-1000:] if len(buffer) > 1000 else buffer

        except Exception as e:
            logger.warning(f"String extraction aborted: {e}")

    def _extract_printable_strings(self, data: bytes, min_length: int = 8) -> List[Tuple[int, str]]:
        # 从字节缓冲区提取可打印 ASCII 和 UTF-8 序列
        strings = []

        # 匹配连续可打印 ASCII 字节 (0x20-0x7E)
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            try:
                content = match.group().decode('ascii')
                strings.append((match.start(), content))

            except Exception:
                logger.debug("suppressed", exc_info=True)

        # 宽扫描潜在 UTF-8 序列，丢弃解码失败
        utf8_pattern = rb'[\x00-\xff]{' + str(min_length * 2).encode() + rb',}'
        for match in re.finditer(utf8_pattern, data):
            try:
                content = match.group().decode('utf-8', errors='ignore')
                if content.strip() and len(content) >= min_length:
                    strings.append((match.start(), content))

            except Exception:
                logger.debug("suppressed", exc_info=True)

        return strings

    def _get_linux_network_connections(self, pid: int, result: ForensicsResult) -> None:
        # 通过 netstat(8) 采集网络套接字状态，ss(8) 作为回退
        try:
            # netstat 优先，ss 作为回退工具
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

                    # 分解地址:端口复合字段
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
            logger.warning(f"Network connection enumeration failed: {e}")

    def _get_linux_file_handles(self, pid: int, result: ForensicsResult) -> None:
        # 遍历 /proc/<pid>/fd 枚举打开文件描述符
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
                    logger.debug("suppressed", exc_info=True)
        except Exception as e:
            logger.warning(f"File descriptor enumeration failed: {e}")

    def _analyze_windows_process(self, pid: int, result: ForensicsResult) -> None:
        # 通过原生 OS 命令行工具分析 Windows 进程
        # 查询 tasklist.exe 获取进程身份元数据
        try:
            # 请求 tasklist 输出详细 CSV
            output = subprocess.run(
                ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/v"],
                capture_output=True,
                text=True,
                timeout=10
            )
            lines = output.stdout.strip().split('\n')
            if len(lines) > 1:
                # 从第一行数据行提取字段
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
            logger.warning(f"Windows process info query failed: {e}")

        # 通过 netstat -ano 枚举套接字状态
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
            logger.warning(f"Windows socket enumeration failed: {e}")

    def _analyze_memory_dump(self, source: str, result: ForensicsResult) -> None:
        # 分析内存镜像文件，有 Volatility 时路由到 Volatility
        if self.volatility_available:
            self._analyze_with_volatility(source, result)
        else:
            # 无 Volatility 时降级为原始二进制分析
            self._analyze_dump_file_direct(source, result)

    def _analyze_with_volatility(self, source: str, result: ForensicsResult) -> None:
        # 通过 Volatility 3 框架插件执行结构化工件提取
        # 从帮助输出捕获 Volatility 版本字符串
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
            logger.debug("suppressed", exc_info=True)

        # 通过 pslist 插件枚举进程
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
            logger.warning(f"Volatility pslist plugin failed: {e}")
            result.errors.append(f"pslist analysis failed: {e}")

        # 通过 netscan 插件枚举网络连接
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
            logger.warning(f"Volatility netscan plugin failed: {e}")

        # 通过 strings 插件提取嵌入字符串
        try:
            output = subprocess.run(
                [self.volatility_path, "-f", source, "strings"],
                capture_output=True,
                text=True,
                timeout=300
            )

            for line in output.stdout.split('\n'):
                if len(line.strip()) >= self.MIN_STRING_LENGTH:
                    # 从 Volatility strings 输出解析十六进制地址和内容
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
            logger.warning(f"Volatility strings plugin failed: {e}")

    def _analyze_dump_file_direct(self, source: str, result: ForensicsResult) -> None:
        # 无 Volatility 依赖时执行原始二进制分析
        try:
            with open(source, 'rb') as f:
                # 获取文件总大小用于进度跟踪
                file_size = f.seek(0, 2)
                f.seek(0)

                logger.info(f"Direct analysis: file={source}, size={file_size} bytes")

                # 以固定大小块流式遍历文件
                chunk_size = 10 * 1024 * 1024  # 10 MB
                offset = 0

                while offset < file_size:
                    f.seek(offset)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # 扫描块中的可打印字符串序列
                    strings = self._extract_printable_strings(chunk)
                    for addr, content in strings:
                        mem_string = MemoryString(
                            address=offset + addr,
                            content=content,
                            length=len(content)
                        )
                        result.memory_strings.append(mem_string)

                    offset += chunk_size

                    # 强制限制提取字符串数上限
                    if len(result.memory_strings) > 10000:
                        break

        except Exception as e:
            logger.error(f"Direct binary analysis failed: {e}")
            result.errors.append(str(e))


    def _analyze_minidump(self, source: str, result: ForensicsResult) -> None:
        # 分析 Windows minidump 文件，先验证 MDMP 头
        # 验证 MDMP 签名后提取内容
        try:
            with open(source, 'rb') as f:
                header = f.read(4)
                if header != b'MDMP':
                    result.errors.append("Invalid minidump file")
                    return

                # 从完整转储载荷提取字符串
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
            logger.error(f"Minidump analysis failed: {e}")
            result.errors.append(str(e))

    def _analyze_core_dump(self, source: str, result: ForensicsResult) -> None:
        # 分析 Linux ELF core dump，确认 ELF 魔数头
        # core dump 是 ELF 文件，先验证魔数
        try:
            with open(source, 'rb') as f:
                header = f.read(4)
                if header[:4] != b'\x7fELF':
                    result.errors.append("Invalid core dump file")
                    return

                # 扫描完整内容查找可打印字符串工件
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
            logger.error(f"Core dump analysis failed: {e}")
            result.errors.append(str(e))


    def _analyze_generic(self, source: str, result: ForensicsResult) -> None:
        # 兜底处理器：将来源作为无类型二进制块处理
        self._analyze_dump_file_direct(source, result)

    def _extract_sensitive_data(self, result: ForensicsResult) -> None:
        # 将提取的内存字符串与敏感数据模式目录匹配
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
                                location=f"memoryaddress {hex(mem_string.address)}",
                                address=mem_string.address + match.start(),
                                confidence=0.8,
                                context=content[max(0, match.start()-50):match.end()+50]
                            )

                            result.sensitive_data.append(sensitive)
                    except Exception:
                        logger.debug("suppressed", exc_info=True)

        # 按匹配值的 MD5 哈希去重
        seen_values = set()
        unique_sensitive = []
        for item in result.sensitive_data:
            value_hash = hashlib.md5(item.value.encode()).hexdigest()
            if value_hash not in seen_values:
                seen_values.add(value_hash)
                unique_sensitive.append(item)

        result.sensitive_data = unique_sensitive
        logger.info(f"Sensitive data items detected: {len(result.sensitive_data)}")

    def dump_process_memory(self, pid: int, output_path: Optional[str] = None) -> str:
        # 将进程虚拟内存导出为二进制转储文件，Linux 用 gcore 或 /proc/<pid>/mem，Windows 用 procdump
        if output_path is None:
            output_path = str(self.output_dir / f"process_{pid}_dump.bin")

        if self.platform == 'linux':
            # 先尝试 gcore，失败则回退直接读 /proc/<pid>/mem
            try:
                # 优先 gcore 生成结构化 ELF core
                result = subprocess.run(
                    ["gcore", "-o", output_path, str(pid)],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                if result.returncode == 0:
                    return output_path
            except Exception:
                logger.debug("suppressed", exc_info=True)

            # 通过 /proc/<pid>/maps + /proc/<pid>/mem 手动提取
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

                                # 仅提取可读映射区域
                                perms = parts[1] if len(parts) > 1 else ''
                                if 'r' in perms:
                                    try:
                                        with open(mem_path, 'rb') as mem_file:
                                            mem_file.seek(start_addr)
                                            data = mem_file.read(end_addr - start_addr)
                                            out_file.write(data)
                                    except Exception:
                                        logger.debug("suppressed", exc_info=True)

                return output_path

        elif self.platform == 'windows':
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
                logger.warning(f"procdump invocation failed: {e}")

        raise RuntimeError(f"Cannot export memory for process {pid}")

    def generate_report(self, result: ForensicsResult) -> str:
        # 将取证发现渲染为结构化 Markdown 报告
        report_lines = [
            "# Memory Forensics Analysis Report",
            "",
            f"**Analysis Time**: {result.timestamp}",
            f"**Source**: {result.source}",
            f"**Memory Type**: {result.memory_type.value}",
            f"**Operating System**: {result.os_type.value}",
            f"**Duration**: {result.analysis_duration:.2f}s",
            "",
            "## Summary Statistics",
            "",
            "| Metric | Count |",
            "|------|------|",
            f"| Processes | {result.total_processes} |",
            f"| Network Connections | {result.total_connections} |",
            f"| File Handles | {result.total_handles} |",
            f"| Sensitive Data Items | {result.total_sensitive_items} |",
            f"| Memory Strings | {len(result.memory_strings)} |",
            "",
        ]

        # 进程列表区
        if result.processes:
            report_lines.extend([
                "## Process List",
                "",
                "| PID | Name | Path | User | Threads |",
                "|-----|------|------|------|--------|",
            ])
            for proc in result.processes[:20]:  # 显示上限 20 条
                report_lines.append(
                    f"| {proc.pid} | {proc.name} | {proc.path or 'N/A'} | {proc.user or 'N/A'} | {proc.threads} |"
                )
            report_lines.append("")

        # 网络连接区
        if result.network_connections:
            report_lines.extend([
                "## Network Connections",
                "",
                "| Protocol | Local Address | Local Port | Remote Address | Remote Port | State |",
                "|------|----------|----------|----------|----------|------|",
            ])
            for conn in result.network_connections[:20]:  # 显示上限 20 条
                report_lines.append(
                    f"| {conn.protocol} | {conn.local_addr} | {conn.local_port} | "
                    f"{conn.remote_addr or 'N/A'} | {conn.remote_port or 'N/A'} | {conn.state or 'N/A'} |"
                )

            report_lines.append("")

        # 文件句柄区
        if result.file_handles:
            report_lines.extend([
                "## File Handles",
                "",
                "| FD | File Path |",
                "|----|----------|",
            ])
            for handle in result.file_handles[:20]:  # 显示上限 20 条
                report_lines.append(f"| {handle.handle_value or 'N/A'} | {handle.file_path} |")
            report_lines.append("")

        # 敏感数据发现区
        if result.sensitive_data:
            report_lines.extend([
                "## Detected Sensitive Data",
                "",
                "| Type | Location | Confidence |",
                "|------|------|--------|",
            ])
            for item in result.sensitive_data[:50]:  # 显示上限 50 条
                report_lines.append(
                    f"| {item.data_type.value} | {item.location} | {item.confidence:.2f} |"
                )

            report_lines.append("")

            # 安全告警摘要块
            report_lines.extend([
                "### Security Warning",
                "",
                "The following sensitive data types were detected in memory:",
                "",
            ])
            type_counts = defaultdict(int)
            for item in result.sensitive_data:
                type_counts[item.data_type.value] += 1

            for data_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                report_lines.append(f"- **{data_type}**: {count} item(s)")
            report_lines.append("")

        # 错误区
        if result.errors:
            report_lines.extend([
                "## Analysis Errors",
                "",
            ])
            for error in result.errors:
                report_lines.append(f"- {error}")
            report_lines.append("")

        return "\n".join(report_lines)

    def save_result(self, result: ForensicsResult, filename: Optional[str] = None) -> str:
        # 将取证结果以 JSON 和 Markdown 报告持久化到磁盘
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"forensics_{timestamp}.json"

        filepath = self.output_dir / filename

        # 写入结构化 JSON 输出
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        # 生成并保存配套 Markdown 报告
        report_path = filepath.with_suffix('.md')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(result))

        logger.info(f"Forensic results persisted to: {filepath}")
        return str(filepath)


# 单次调用入口，快速取证分析
def analyze_memory(source: Union[str, int], output_dir: Optional[str] = None) -> ForensicsResult:
    # 一次性便捷封装：分析来源并持久化结果
    analyzer = MemoryForensicsAnalyzer(output_dir)
    result = analyzer.analyze(source)
    analyzer.save_result(result)
    return result


if __name__ == "__main__":
    # 独立运行的 CLI 入口
    import sys

    analyzer = MemoryForensicsAnalyzer()

    if len(sys.argv) > 1:
        source = sys.argv[1]
        try:
            pid = int(source)
            print(f"Analyzing process: {pid}")
        except ValueError:
            print(f"Analyzing file: {source}")

        result = analyzer.analyze(source)
        analyzer.save_result(result)

        print("\nAnalysis complete!")
        print(f"Processes found: {result.total_processes}")
        print(f"Connections found: {result.total_connections}")
        print(f"Sensitive data items: {result.total_sensitive_items}")
    else:
        print("Usage: python memory_forensics.py <pid or filepath>")
        print("\nExamples:")
        print("  python memory_forensics.py 1234        # Analyze process 1234")
        print("  python memory_forensics.py dump.raw    # Analyze memory image")
