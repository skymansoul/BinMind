"""
实时API调用追踪与恶意行为序列分析模块

该模块用于动态追踪二进制程序的API调用序列，识别潜在的恶意行为模式，
如文件操作、网络通信、进程创建、注册表修改等，辅助恶意软件分析和行为检测。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import os
import re
import json
import time
import subprocess
import threading
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class BehaviorCategory(Enum):
    """
    行为类别枚举
    """
    FILE_OPERATION = 'file_operation'
    NETWORK = 'network'
    PROCESS = 'process'
    MEMORY = 'memory'
    REGISTRY = 'registry'
    PRIVILEGE = 'privilege'
    CRYPTO = 'crypto'
    PERSISTENCE = 'persistence'
    EVASION = 'evasion'
    DATA_EXFIL = 'data_exfiltration'
    UNKNOWN = 'unknown'


@dataclass
class ApiCall:
    """
    API 调用记录
    
    Attributes:
        timestamp: 调用时间戳
        api_name: API 函数名
        category: 行为类别
        arguments: 调用参数
        return_value: 返回值
        success: 是否成功
        process_id: 进程ID
        thread_id: 线程ID
        context: 上下文信息
    """
    timestamp: float
    api_name: str
    category: BehaviorCategory
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Any = None
    success: bool = True
    process_id: int = 0
    thread_id: int = 0
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorSequence:
    """
    行为序列
    
    Attributes:
        sequence_id: 序列ID
        start_time: 开始时间
        end_time: 结束时间
        api_calls: API调用列表
        pattern_type: 检测到的模式类型
        risk_level: 风险等级
        description: 描述
        indicators: 指标列表
    """
    sequence_id: str
    start_time: float
    end_time: float
    api_calls: List[ApiCall] = field(default_factory=list)
    pattern_type: str = ''
    risk_level: str = 'low'
    description: str = ''
    indicators: List[str] = field(default_factory=list)


@dataclass
class TraceResult:
    """
    追踪结果
    
    Attributes:
        success: 是否成功
        binary_path: 二进制路径
        duration: 追踪时长
        total_calls: 总调用数
        api_calls: API调用列表
        behavior_sequences: 行为序列列表
        risk_summary: 风险摘要
        warnings: 警告列表
        trace_log: 追踪日志路径
    """
    success: bool
    binary_path: str = ''
    duration: float = 0.0
    total_calls: int = 0
    api_calls: List[ApiCall] = field(default_factory=list)
    behavior_sequences: List[BehaviorSequence] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    trace_log: str = ''


# API 函数分类映射
API_CATEGORY_MAP = {
    # 文件操作
    'CreateFile': BehaviorCategory.FILE_OPERATION,
    'ReadFile': BehaviorCategory.FILE_OPERATION,
    'WriteFile': BehaviorCategory.FILE_OPERATION,
    'DeleteFile': BehaviorCategory.FILE_OPERATION,
    'MoveFile': BehaviorCategory.FILE_OPERATION,
    'CopyFile': BehaviorCategory.FILE_OPERATION,
    'open': BehaviorCategory.FILE_OPERATION,
    'read': BehaviorCategory.FILE_OPERATION,
    'write': BehaviorCategory.FILE_OPERATION,
    'fopen': BehaviorCategory.FILE_OPERATION,
    'fread': BehaviorCategory.FILE_OPERATION,
    'fwrite': BehaviorCategory.FILE_OPERATION,
    
    # 网络操作
    'socket': BehaviorCategory.NETWORK,
    'connect': BehaviorCategory.NETWORK,
    'send': BehaviorCategory.NETWORK,
    'recv': BehaviorCategory.NETWORK,
    'WSAConnect': BehaviorCategory.NETWORK,
    'InternetConnect': BehaviorCategory.NETWORK,
    'HttpSendRequest': BehaviorCategory.NETWORK,
    'URLDownloadToFile': BehaviorCategory.NETWORK,
    'getaddrinfo': BehaviorCategory.NETWORK,
    
    # 进程操作
    'CreateProcess': BehaviorCategory.PROCESS,
    'OpenProcess': BehaviorCategory.PROCESS,
    'TerminateProcess': BehaviorCategory.PROCESS,
    'VirtualAllocEx': BehaviorCategory.PROCESS,
    'WriteProcessMemory': BehaviorCategory.PROCESS,
    'ReadProcessMemory': BehaviorCategory.PROCESS,
    'fork': BehaviorCategory.PROCESS,
    'exec': BehaviorCategory.PROCESS,
    'execve': BehaviorCategory.PROCESS,
    'system': BehaviorCategory.PROCESS,
    'popen': BehaviorCategory.PROCESS,
    
    # 内存操作
    'VirtualAlloc': BehaviorCategory.MEMORY,
    'VirtualProtect': BehaviorCategory.MEMORY,
    'VirtualFree': BehaviorCategory.MEMORY,
    'malloc': BehaviorCategory.MEMORY,
    'free': BehaviorCategory.MEMORY,
    'mmap': BehaviorCategory.MEMORY,
    'munmap': BehaviorCategory.MEMORY,
    
    # 注册表操作
    'RegOpenKey': BehaviorCategory.REGISTRY,
    'RegSetValue': BehaviorCategory.REGISTRY,
    'RegDeleteKey': BehaviorCategory.REGISTRY,
    'RegCreateKey': BehaviorCategory.REGISTRY,
    
    # 权限操作
    'AdjustTokenPrivileges': BehaviorCategory.PRIVILEGE,
    'OpenProcessToken': BehaviorCategory.PRIVILEGE,
    'LookupPrivilegeValue': BehaviorCategory.PRIVILEGE,
    'setuid': BehaviorCategory.PRIVILEGE,
    'setgid': BehaviorCategory.PRIVILEGE,
    'chmod': BehaviorCategory.PRIVILEGE,
    
    # 加密操作
    'CryptAcquireContext': BehaviorCategory.CRYPTO,
    'CryptEncrypt': BehaviorCategory.CRYPTO,
    'CryptDecrypt': BehaviorCategory.CRYPTO,
    'CryptGenKey': BehaviorCategory.CRYPTO,
    
    # 持久化
    'SetWindowsHookEx': BehaviorCategory.PERSISTENCE,
    'RegisterClassEx': BehaviorCategory.PERSISTENCE,
    'CreateService': BehaviorCategory.PERSISTENCE,
    'StartService': BehaviorCategory.PERSISTENCE,
    'SchRegisterTask': BehaviorCategory.PERSISTENCE,
}

# 恶意行为模式定义
MALICIOUS_BEHAVIOR_PATTERNS = [
    {
        'name': 'file_exfiltration',
        'description': '文件窃取行为',
        'risk': 'high',
        'sequence': [
            {'category': BehaviorCategory.FILE_OPERATION, 'apis': ['CreateFile', 'ReadFile', 'open', 'read']},
            {'category': BehaviorCategory.NETWORK, 'apis': ['connect', 'send', 'InternetConnect', 'HttpSendRequest']},
        ],
        'indicators': ['读取敏感文件后发送网络数据']
    },
    {
        'name': 'process_injection',
        'description': '进程注入行为',
        'risk': 'critical',
        'sequence': [
            {'category': BehaviorCategory.PROCESS, 'apis': ['OpenProcess', 'CreateProcess']},
            {'category': BehaviorCategory.MEMORY, 'apis': ['VirtualAllocEx', 'WriteProcessMemory']},
            {'category': BehaviorCategory.PROCESS, 'apis': ['CreateRemoteThread']},
        ],
        'indicators': ['向其他进程写入代码']
    },
    {
        'name': 'privilege_escalation',
        'description': '权限提升行为',
        'risk': 'high',
        'sequence': [
            {'category': BehaviorCategory.PRIVILEGE, 'apis': ['OpenProcessToken', 'LookupPrivilegeValue']},
            {'category': BehaviorCategory.PRIVILEGE, 'apis': ['AdjustTokenPrivileges']},
        ],
        'indicators': ['尝试获取更高权限']
    },
    {
        'name': 'registry_persistence',
        'description': '注册表持久化',
        'risk': 'medium',
        'sequence': [
            {'category': BehaviorCategory.REGISTRY, 'apis': ['RegOpenKey', 'RegCreateKey']},
            {'category': BehaviorCategory.REGISTRY, 'apis': ['RegSetValue']},
        ],
        'indicators': ['写入注册表自启动项']
    },
    {
        'name': 'anti_debug',
        'description': '反调试行为',
        'risk': 'medium',
        'sequence': [
            {'apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess']},
        ],
        'indicators': ['检测调试器存在']
    },
    {
        'name': 'code_injection',
        'description': '代码注入',
        'risk': 'critical',
        'sequence': [
            {'category': BehaviorCategory.MEMORY, 'apis': ['VirtualAlloc']},
            {'category': BehaviorCategory.MEMORY, 'apis': ['VirtualProtect']},
            {'apis': ['WriteProcessMemory', 'memcpy']},
        ],
        'indicators': ['分配可执行内存并写入代码']
    },
    {
        'name': 'network_c2',
        'description': 'C2通信行为',
        'risk': 'high',
        'sequence': [
            {'category': BehaviorCategory.NETWORK, 'apis': ['socket', 'connect', 'InternetConnect']},
            {'category': BehaviorCategory.NETWORK, 'apis': ['recv', 'HttpSendRequest']},
            {'category': BehaviorCategory.PROCESS, 'apis': ['CreateProcess', 'system']},
        ],
        'indicators': ['接收网络命令并执行']
    },
    {
        'name': 'credential_dumping',
        'description': '凭证窃取',
        'risk': 'critical',
        'sequence': [
            {'category': BehaviorCategory.FILE_OPERATION, 'apis': ['CreateFile']},
            {'apis': ['LSASecrets', 'SamIConnect']},
        ],
        'indicators': ['读取敏感凭证文件']
    },
]


class BehaviorTracer:
    """
    实时API调用追踪与恶意行为序列分析器
    
    用于动态追踪二进制程序的API调用，识别恶意行为模式。
    """
    
    def __init__(self, timeout: int = 300):
        """
        初始化追踪器
        
        Args:
            timeout: 追踪超时时间（秒）
        """
        from config import Config
        
        self.timeout = timeout
        self.trace_output_dir = os.path.join(Config.DATA_DIR, 'traces')
        os.makedirs(self.trace_output_dir, exist_ok=True)
        
        # 检查追踪工具可用性
        self._strace_available = self._check_strace()
        self._frida_available = self._check_frida()
        
        # 追踪状态
        self._running = False
        self._api_calls: List[ApiCall] = []
        self._lock = threading.Lock()
        
    def _check_strace(self) -> bool:
        """检查 strace 是否可用（Linux）"""
        try:
            result = subprocess.run(
                ['strace', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
            
    def _check_frida(self) -> bool:
        """检查 Frida 是否可用"""
        try:
            import frida
            return True
        except ImportError:
            return False
            
    def trace_binary(
        self,
        binary_path: str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        use_frida: bool = False
    ) -> TraceResult:
        """
        追踪二进制程序的API调用
        
        Args:
            binary_path: 二进制文件路径
            args: 程序参数
            timeout: 追踪超时时间
            use_frida: 是否使用 Frida
            
        Returns:
            TraceResult: 追踪结果
        """
        if not os.path.exists(binary_path):
            logger.error(f"二进制文件不存在: {binary_path}")
            return TraceResult(
                success=False,
                binary_path=binary_path,
                warnings=['文件不存在']
            )
            
        timeout = timeout or self.timeout
        start_time = time.time()
        
        result = TraceResult(
            success=False,
            binary_path=binary_path
        )
        
        try:
            # 选择追踪方法
            if use_frida and self._frida_available:
                logger.info("使用 Frida 进行动态追踪")
                trace_data = self._trace_with_frida(binary_path, args, timeout)
            elif self._strace_available:
                logger.info("使用 strace 进行系统调用追踪")
                trace_data = self._trace_with_strace(binary_path, args, timeout)
            else:
                logger.warning("没有可用的追踪工具")
                result.warnings.append('没有可用的追踪工具（strace 或 Frida）')
                return result
                
            # 解析追踪数据
            if trace_data:
                result.api_calls = self._parse_trace_data(trace_data)
                result.total_calls = len(result.api_calls)
                
                # 分析行为序列
                result.behavior_sequences = self._analyze_behavior_sequences(result.api_calls)
                
                # 计算风险摘要
                result.risk_summary = self._calculate_risk_summary(result.behavior_sequences)
                
                result.success = True
                
        except subprocess.TimeoutExpired:
            logger.warning(f"追踪超时 ({timeout}s)")
            result.warnings.append(f'追踪超时')
        except Exception as e:
            logger.error(f"追踪失败: {e}")
            result.warnings.append(f'追踪异常: {str(e)}')
            
        result.duration = time.time() - start_time
        
        # 保存追踪日志
        if result.api_calls:
            result.trace_log = self._save_trace_log(result)
            
        return result
        
    def _trace_with_strace(
        self,
        binary_path: str,
        args: Optional[List[str]],
        timeout: int
    ) -> Optional[str]:
        """
        使用 strace 追踪系统调用
        
        Args:
            binary_path: 二进制路径
            args: 参数
            timeout: 超时
            
        Returns:
            strace 输出或 None
        """
        try:
            cmd = ['strace', '-f', '-e', 'trace=file,process,network,memory', '-s', '256']
            cmd.append(binary_path)
            if args:
                cmd.extend(args)
                
            logger.info(f"执行追踪命令: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            return result.stderr  # strace 输出到 stderr
            
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            logger.error(f"strace 执行失败: {e}")
            return None
            
    def _trace_with_frida(
        self,
        binary_path: str,
        args: Optional[List[str]],
        timeout: int
    ) -> Optional[List[Dict]]:
        """
        使用 Frida 进行动态追踪
        
        Args:
            binary_path: 二进制路径
            args: 参数
            timeout: 超时
            
        Returns:
            Frida 追踪数据或 None
        """
        try:
            import frida
            
            trace_data = []
            
            # Frida 脚本
            frida_script = """
            // 监控关键 API 调用
            var api_calls = [];
            
            // 监控文件操作
            Interceptor.attach(Module.findExportByName(null, 'open'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'open',
                        args: {path: Memory.readUtf8String(args[0])},
                        timestamp: Date.now()
                    });
                }
            });
            
            Interceptor.attach(Module.findExportByName(null, 'read'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'read',
                        args: {fd: args[0].toInt32(), size: args[2].toInt32()},
                        timestamp: Date.now()
                    });
                }
            });
            
            Interceptor.attach(Module.findExportByName(null, 'write'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'write',
                        args: {fd: args[0].toInt32(), size: args[2].toInt32()},
                        timestamp: Date.now()
                    });
                }
            });
            
            // 监控网络操作
            Interceptor.attach(Module.findExportByName(null, 'connect'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'connect',
                        args: {sockfd: args[0].toInt32()},
                        timestamp: Date.now()
                    });
                }
            });
            
            Interceptor.attach(Module.findExportByName(null, 'send'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'send',
                        args: {sockfd: args[0].toInt32(), size: args[2].toInt32()},
                        timestamp: Date.now()
                    });
                }
            });
            
            // 监控进程操作
            Interceptor.attach(Module.findExportByName(null, 'fork'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'fork',
                        args: {},
                        timestamp: Date.now()
                    });
                }
            });
            
            Interceptor.attach(Module.findExportByName(null, 'execve'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'execve',
                        args: {path: Memory.readUtf8String(args[0])},
                        timestamp: Date.now()
                    });
                }
            });
            
            // 监控内存操作
            Interceptor.attach(Module.findExportByName(null, 'mmap'), {
                onEnter: function(args) {
                    api_calls.push({
                        api: 'mmap',
                        args: {size: args[1].toInt32(), prot: args[2].toInt32()},
                        timestamp: Date.now()
                    });
                }
            });
            
            // 定期发送数据
            setInterval(function() {
                send({type: 'api_calls', data: api_calls});
                api_calls = [];
            }, 1000);
            
            // 进程退出时发送
            Process.setExceptionHandler(function(details) {
                send({type: 'exit', data: api_calls});
                return false;
            });
            """
            
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload['type'] == 'api_calls':
                        trace_data.extend(payload['data'])
                        
            # 启动进程
            pid = frida.spawn([binary_path] + (args or []))
            session = frida.attach(pid)
            script = session.create_script(frida_script)
            script.on('message', on_message)
            script.load()
            
            # 恢复进程执行
            frida.resume(pid)
            
            # 等待追踪完成
            time.sleep(min(timeout, 30))
            
            # 清理
            session.detach()
            
            return trace_data
            
        except ImportError:
            logger.warning("Frida 未安装")
            return None
        except Exception as e:
            logger.error(f"Frida 追踪失败: {e}")
            return None
            
    def _parse_trace_data(self, trace_data: Any) -> List[ApiCall]:
        """
        解析追踪数据
        
        Args:
            trace_data: 原始追踪数据
            
        Returns:
            API调用列表
        """
        api_calls = []
        
        if isinstance(trace_data, str):
            # strace 输出解析
            api_calls = self._parse_strace_output(trace_data)
        elif isinstance(trace_data, list):
            # Frida 输出解析
            api_calls = self._parse_frida_output(trace_data)
            
        return api_calls
        
    def _parse_strace_output(self, output: str) -> List[ApiCall]:
        """
        解析 strace 输出
        
        Args:
            output: strace 输出字符串
            
        Returns:
            API调用列表
        """
        api_calls = []
        
        # strace 输出格式: PID syscall(args) = return
        pattern = r'^(\d+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)'
        
        for line in output.split('\n'):
            match = re.match(pattern, line.strip())
            if match:
                pid = int(match.group(1))
                api_name = match.group(2)
                args_str = match.group(3)
                return_val = match.group(4)
                
                # 解析参数
                arguments = self._parse_strace_args(args_str)
                
                # 判断成功
                success = return_val not in ['-1', '0xffffffff', '0xffffffffffffffff']
                
                # 分类
                category = self._classify_api(api_name)
                
                api_call = ApiCall(
                    timestamp=time.time(),
                    api_name=api_name,
                    category=category,
                    arguments=arguments,
                    return_value=return_val,
                    success=success,
                    process_id=pid
                )
                
                api_calls.append(api_call)
                
        return api_calls
        
    def _parse_strace_args(self, args_str: str) -> Dict[str, Any]:
        """
        解析 strace 参数字符串
        
        Args:
            args_str: 参数字符串
            
        Returns:
            参数字典
        """
        arguments = {}
        
        try:
            # 简化解析，提取关键信息
            parts = args_str.split(',')
            for i, part in enumerate(parts):
                part = part.strip()
                
                # 尝试解析字符串参数
                if '"' in part:
                    match = re.search(r'"([^"]*)"', part)
                    if match:
                        arguments[f'arg{i}'] = match.group(1)
                # 尝试解析数字参数
                elif part.startswith('0x'):
                    arguments[f'arg{i}'] = int(part, 16)
                elif part.isdigit() or (part.startswith('-') and part[1:].isdigit()):
                    arguments[f'arg{i}'] = int(part)
                else:
                    arguments[f'arg{i}'] = part
                    
        except Exception as e:
            logger.debug(f"解析参数失败: {e}")
            
        return arguments
        
    def _parse_frida_output(self, output: List[Dict]) -> List[ApiCall]:
        """
        解析 Frida 输出
        
        Args:
            output: Frida 输出列表
            
        Returns:
            API调用列表
        """
        api_calls = []
        
        for item in output:
            api_name = item.get('api', 'unknown')
            category = self._classify_api(api_name)
            
            api_call = ApiCall(
                timestamp=item.get('timestamp', time.time() * 1000) / 1000,
                api_name=api_name,
                category=category,
                arguments=item.get('args', {}),
                success=True
            )
            
            api_calls.append(api_call)
            
        return api_calls
        
    def _classify_api(self, api_name: str) -> BehaviorCategory:
        """
        分类 API 调用
        
        Args:
            api_name: API 名称
            
        Returns:
            行为类别
        """
        # 直接匹配
        if api_name in API_CATEGORY_MAP:
            return API_CATEGORY_MAP[api_name]
            
        # 模糊匹配
        api_lower = api_name.lower()
        
        if any(kw in api_lower for kw in ['file', 'open', 'read', 'write', 'delete', 'move', 'copy']):
            return BehaviorCategory.FILE_OPERATION
        if any(kw in api_lower for kw in ['socket', 'connect', 'send', 'recv', 'http', 'internet', 'url', 'net']):
            return BehaviorCategory.NETWORK
        if any(kw in api_lower for kw in ['process', 'thread', 'fork', 'exec', 'spawn', 'create']):
            return BehaviorCategory.PROCESS
        if any(kw in api_lower for kw in ['mem', 'alloc', 'map', 'virtual', 'heap']):
            return BehaviorCategory.MEMORY
        if any(kw in api_lower for kw in ['reg', 'registry', 'key']):
            return BehaviorCategory.REGISTRY
        if any(kw in api_lower for kw in ['token', 'priv', 'uid', 'gid', 'perm', 'chmod']):
            return BehaviorCategory.PRIVILEGE
        if any(kw in api_lower for kw in ['crypt', 'encrypt', 'decrypt', 'hash', 'key']):
            return BehaviorCategory.CRYPTO
            
        return BehaviorCategory.UNKNOWN
        
    def _analyze_behavior_sequences(
        self,
        api_calls: List[ApiCall]
    ) -> List[BehaviorSequence]:
        """
        分析行为序列，识别恶意模式
        
        Args:
            api_calls: API调用列表
            
        Returns:
            行为序列列表
        """
        sequences = []
        
        # 按时间窗口分组
        window_size = 60  # 60秒窗口
        windows = defaultdict(list)
        
        for call in api_calls:
            window_key = int(call.timestamp / window_size)
            windows[window_key].append(call)
            
        # 在每个窗口中检测模式
        for window_key, calls in windows.items():
            window_sequences = self._detect_patterns_in_window(calls, window_key)
            sequences.extend(window_sequences)
            
        return sequences
        
    def _detect_patterns_in_window(
        self,
        calls: List[ApiCall],
        window_key: int
    ) -> List[BehaviorSequence]:
        """
        在时间窗口中检测恶意模式
        
        Args:
            calls: API调用列表
            window_key: 窗口键
            
        Returns:
            检测到的行为序列
        """
        sequences = []
        
        for pattern in MALICIOUS_BEHAVIOR_PATTERNS:
            if self._match_pattern(calls, pattern):
                sequence = BehaviorSequence(
                    sequence_id=f"{window_key}_{pattern['name']}",
                    start_time=calls[0].timestamp if calls else time.time(),
                    end_time=calls[-1].timestamp if calls else time.time(),
                    api_calls=calls,
                    pattern_type=pattern['name'],
                    risk_level=pattern['risk'],
                    description=pattern['description'],
                    indicators=pattern['indicators']
                )
                sequences.append(sequence)
                
        return sequences
        
    def _match_pattern(
        self,
        calls: List[ApiCall],
        pattern: Dict
    ) -> bool:
        """
        匹配恶意行为模式
        
        Args:
            calls: API调用列表
            pattern: 模式定义
            
        Returns:
            是否匹配
        """
        sequence = pattern['sequence']
        
        # 检查序列中的每个步骤
        matched_steps = 0
        
        for step in sequence:
            # 检查类别匹配
            if 'category' in step:
                category_calls = [c for c in calls if c.category == step['category']]
                if not category_calls:
                    continue
                    
            # 检查 API 名称匹配
            if 'apis' in step:
                api_matched = any(c.api_name in step['apis'] for c in calls)
                if api_matched:
                    matched_steps += 1
                    
        # 如果匹配了大部分步骤，认为模式匹配
        return matched_steps >= len(sequence) * 0.5
        
    def _calculate_risk_summary(
        self,
        sequences: List[BehaviorSequence]
    ) -> Dict[str, int]:
        """
        计算风险摘要
        
        Args:
            sequences: 行为序列列表
            
        Returns:
            风险等级计数
        """
        summary = defaultdict(int)
        
        for seq in sequences:
            summary[seq.risk_level] += 1
            
        return dict(summary)
        
    def _save_trace_log(self, result: TraceResult) -> str:
        """
        保存追踪日志
        
        Args:
            result: 追踪结果
            
        Returns:
            日志文件路径
        """
        binary_name = os.path.splitext(os.path.basename(result.binary_path))[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_path = os.path.join(self.trace_output_dir, f'{binary_name}_{timestamp}.json')
        
        try:
            log_data = {
                'binary_path': result.binary_path,
                'duration': result.duration,
                'total_calls': result.total_calls,
                'api_calls': [
                    {
                        'timestamp': c.timestamp,
                        'api_name': c.api_name,
                        'category': c.category.value,
                        'arguments': c.arguments,
                        'return_value': str(c.return_value),
                        'success': c.success,
                        'process_id': c.process_id
                    }
                    for c in result.api_calls[:1000]  # 限制数量
                ],
                'behavior_sequences': [
                    {
                        'sequence_id': s.sequence_id,
                        'pattern_type': s.pattern_type,
                        'risk_level': s.risk_level,
                        'description': s.description,
                        'indicators': s.indicators
                    }
                    for s in result.behavior_sequences
                ],
                'risk_summary': result.risk_summary
            }
            
            with open(log_path, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"追踪日志已保存: {log_path}")
            
        except Exception as e:
            logger.error(f"保存追踪日志失败: {e}")
            
        return log_path
        
    def generate_report(self, result: TraceResult) -> str:
        """
        生成追踪分析报告
        
        Args:
            result: 追踪结果
            
        Returns:
            Markdown 格式报告
        """
        report = []
        report.append("## API 调用追踪分析报告\n")
        
        report.append("### 基本信息")
        report.append(f"- 二进制路径: `{result.binary_path}`")
        report.append(f"- 追踪时长: {result.duration:.2f} 秒")
        report.append(f"- 总调用数: {result.total_calls}")
        report.append(f"- 追踪状态: {'成功' if result.success else '失败'}")
        report.append("")
        
        # API 调用统计
        if result.api_calls:
            report.append("### API 调用统计")
            
            # 按类别统计
            category_stats = defaultdict(int)
            for call in result.api_calls:
                category_stats[call.category.value] += 1
                
            report.append("| 类别 | 调用次数 |")
            report.append("|------|----------|")
            for category, count in sorted(category_stats.items(), key=lambda x: -x[1]):
                report.append(f"| {category} | {count} |")
            report.append("")
            
            # 最近的 API 调用
            report.append("### 最近 API 调用 (前20个)")
            report.append("| 时间 | API | 类别 | 参数 |")
            report.append("|------|-----|------|------|")
            for call in result.api_calls[:20]:
                args_str = str(call.arguments)[:50]
                report.append(f"| {call.timestamp:.3f} | `{call.api_name}` | {call.category.value} | {args_str} |")
            report.append("")
            
        # 行为序列分析
        if result.behavior_sequences:
            report.append("### 检测到的行为模式")
            
            for seq in result.behavior_sequences:
                risk_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(seq.risk_level, '⚪')
                
                report.append(f"\n#### {risk_icon} {seq.description}")
                report.append(f"- 模式类型: `{seq.pattern_type}`")
                report.append(f"- 风险等级: **{seq.risk_level}**")
                
                if seq.indicators:
                    report.append("- 指标:")
                    for indicator in seq.indicators:
                        report.append(f"  - {indicator}")
                        
        # 风险摘要
        if result.risk_summary:
            report.append("\n### 风险摘要")
            for level, count in sorted(result.risk_summary.items()):
                report.append(f"- {level}: {count} 个")
                
        # 警告
        if result.warnings:
            report.append("\n### 警告")
            for warning in result.warnings:
                report.append(f"- ⚠️ {warning}")
                
        return '\n'.join(report)


def trace_and_analyze(
    binary_path: str,
    args: Optional[List[str]] = None,
    timeout: int = 300,
    use_frida: bool = False
) -> TraceResult:
    """
    追踪并分析二进制程序
    
    Args:
        binary_path: 二进制路径
        args: 程序参数
        timeout: 超时时间
        use_frida: 是否使用 Frida
        
    Returns:
        TraceResult: 追踪结果
    """
    tracer = BehaviorTracer(timeout=timeout)
    return tracer.trace_binary(binary_path, args, timeout, use_frida)