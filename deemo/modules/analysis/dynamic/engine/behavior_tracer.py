"""
实时 API 调用追踪与恶意行为序列分析。

动态追踪二进制程序的 API 调用，按行为类别聚合，并在时间窗口内匹配
已知恶意模式（进程注入、权限提升、C2 通信、数据外传）。strace 与
Frida 二选一作为采集后端，均不可用时结果标记失败并保留错误信息。
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BehaviorCategory(Enum):
    """行为类别枚举。"""

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
    # 旧版 __slots__ 残留与 dataclass 字段不一致，导致无 __dict__ 且 api_name 赋值失败；移除
    timestamp: float
    api_name: str
    category: BehaviorCategory
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Any = None
    success: bool = True
    process_id: int = 0
    thread_id: int = 0
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化字典。"""
        return {
            'timestamp': self.timestamp,
            'api_name': self.api_name,
            'category': self.category.value,
            'arguments': self.arguments,
            'return_value': str(self.return_value),
            'success': self.success,
            'process_id': self.process_id,
            'thread_id': self.thread_id,
        }


@dataclass
class BehaviorSequence:
    """检测到的行为序列。"""

    name: str
    pattern_type: str
    severity: str
    description: str
    api_calls: List[str] = field(default_factory=list)
    confidence: float = 0.0
    sequence_id: str = ''
    start_time: float = 0.0
    end_time: float = 0.0
    is_malicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化字典。"""
        return {
            'name': self.name,
            'pattern_type': self.pattern_type,
            'severity': self.severity,
            'description': self.description,
            'api_calls': self.api_calls,
            'confidence': self.confidence,
        }


@dataclass
class TraceResult:
    """一次完整追踪的结果容器。"""

    binary_path: str = ''
    trace_duration: float = 0.0
    total_calls: int = 0
    api_calls: List[ApiCall] = field(default_factory=list)
    behavior_sequences: List[BehaviorSequence] = field(default_factory=list)
    suspicious_behaviors: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    success: bool = False
    risk_summary: Dict[str, int] = field(default_factory=dict)
    trace_log: str = ''
    name: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化字典。"""
        return {
            'binary_path': self.binary_path,
            'trace_duration': self.trace_duration,
            'total_calls': self.total_calls,
            'api_calls': [c.to_dict() for c in self.api_calls],
            'behavior_sequences': [s.to_dict() for s in self.behavior_sequences],
            'suspicious_behaviors': self.suspicious_behaviors,
            'errors': self.errors,
            'success': self.success,
            'risk_summary': self.risk_summary,
        }


# API 名称到行为类别的映射表
API_CATEGORY_MAP: Dict[str, BehaviorCategory] = {
    # 文件操作
    'CreateFile': BehaviorCategory.FILE_OPERATION,
    'OpenFile': BehaviorCategory.FILE_OPERATION,
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
    'sendto': BehaviorCategory.NETWORK,
    'recvfrom': BehaviorCategory.NETWORK,
    'WSAConnect': BehaviorCategory.NETWORK,
    'InternetConnect': BehaviorCategory.NETWORK,
    'HttpSendRequest': BehaviorCategory.NETWORK,
    'HttpOpenRequest': BehaviorCategory.NETWORK,
    'URLDownloadToFile': BehaviorCategory.NETWORK,
    'getaddrinfo': BehaviorCategory.NETWORK,
    # 进程操作
    'CreateProcess': BehaviorCategory.PROCESS,
    'OpenProcess': BehaviorCategory.PROCESS,
    'TerminateProcess': BehaviorCategory.PROCESS,
    'VirtualAllocEx': BehaviorCategory.PROCESS,
    'WriteProcessMemory': BehaviorCategory.PROCESS,
    'ReadProcessMemory': BehaviorCategory.PROCESS,
    'CreateRemoteThread': BehaviorCategory.PROCESS,
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
    'RegQueryValue': BehaviorCategory.REGISTRY,
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
    'RegSetValueEx': BehaviorCategory.PERSISTENCE,
}


# 恶意行为模式库 — 按模式名索引，每条含 name/severity/api_sequence
MALICIOUS_BEHAVIOR_PATTERNS: Dict[str, Dict[str, Any]] = {
    'process_injection': {
        'name': 'process_injection',
        'description': '进程注入行为',
        'severity': 'critical',
        'risk': 'critical',
        'api_sequence': [
            {'category': BehaviorCategory.PROCESS, 'apis': ['OpenProcess', 'CreateProcess']},
            {'category': BehaviorCategory.MEMORY, 'apis': ['VirtualAllocEx', 'VirtualAlloc']},
            {'category': BehaviorCategory.PROCESS, 'apis': ['WriteProcessMemory', 'CreateRemoteThread']},
        ],
        'indicators': ['向其他进程写入代码'],
    },
    'privilege_escalation': {
        'name': 'privilege_escalation',
        'description': '权限提升行为',
        'severity': 'high',
        'risk': 'high',
        'api_sequence': [
            {'category': BehaviorCategory.PRIVILEGE, 'apis': ['OpenProcessToken', 'LookupPrivilegeValue']},
            {'category': BehaviorCategory.PRIVILEGE, 'apis': ['AdjustTokenPrivileges']},
        ],
        'indicators': ['尝试获取更高权限'],
    },
    'c2_communication': {
        'name': 'c2_communication',
        'description': 'C2 通信行为',
        'severity': 'high',
        'risk': 'high',
        'api_sequence': [
            {'category': BehaviorCategory.NETWORK, 'apis': ['socket', 'connect', 'InternetConnect']},
            {'category': BehaviorCategory.NETWORK, 'apis': ['recv', 'HttpSendRequest', 'send']},
            {'category': BehaviorCategory.PROCESS, 'apis': ['CreateProcess', 'system']},
        ],
        'indicators': ['接收网络命令并执行'],
    },
    'data_exfiltration': {
        'name': 'data_exfiltration',
        'description': '数据外传行为',
        'severity': 'high',
        'risk': 'high',
        'api_sequence': [
            {'category': BehaviorCategory.FILE_OPERATION, 'apis': ['CreateFile', 'ReadFile', 'open', 'read']},
            {'category': BehaviorCategory.NETWORK, 'apis': ['connect', 'send', 'InternetConnect', 'HttpSendRequest']},
        ],
        'indicators': ['读取敏感文件后发送网络数据'],
    },
    'file_exfiltration': {
        'name': 'file_exfiltration',
        'description': '文件窃取行为',
        'severity': 'high',
        'risk': 'high',
        'api_sequence': [
            {'category': BehaviorCategory.FILE_OPERATION, 'apis': ['CreateFile', 'ReadFile', 'open', 'read']},
            {'category': BehaviorCategory.NETWORK, 'apis': ['connect', 'send', 'InternetConnect', 'HttpSendRequest']},
        ],
        'indicators': ['读取敏感文件后发送网络数据'],
    },
    'registry_persistence': {
        'name': 'registry_persistence',
        'description': '注册表持久化',
        'severity': 'medium',
        'risk': 'medium',
        'api_sequence': [
            {'category': BehaviorCategory.REGISTRY, 'apis': ['RegOpenKey', 'RegCreateKey']},
            {'category': BehaviorCategory.REGISTRY, 'apis': ['RegSetValue', 'RegSetValueEx']},
        ],
        'indicators': ['写入注册表自启动项'],
    },
    'anti_debug': {
        'name': 'anti_debug',
        'description': '反调试行为',
        'severity': 'medium',
        'risk': 'medium',
        'api_sequence': [
            {'apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess']},
        ],
        'indicators': ['检测调试器存在'],
    },
    'code_injection': {
        'name': 'code_injection',
        'description': '代码注入',
        'severity': 'critical',
        'risk': 'critical',
        'api_sequence': [
            {'category': BehaviorCategory.MEMORY, 'apis': ['VirtualAlloc']},
            {'category': BehaviorCategory.MEMORY, 'apis': ['VirtualProtect']},
            {'apis': ['WriteProcessMemory', 'memcpy']},
        ],
        'indicators': ['分配可执行内存并写入代码'],
    },
    'credential_dumping': {
        'name': 'credential_dumping',
        'description': '凭证窃取',
        'severity': 'critical',
        'risk': 'critical',
        'api_sequence': [
            {'category': BehaviorCategory.FILE_OPERATION, 'apis': ['CreateFile']},
            {'apis': ['LSASecrets', 'SamIConnect']},
        ],
        'indicators': ['读取敏感凭证文件'],
    },
}


class BehaviorTracer:
    """实时 API 调用追踪与恶意行为序列分析器。"""

    def __init__(self, timeout: int = 300, output_dir: Optional[str] = None):
        """初始化追踪器。

        timeout: 单次追踪超时（秒）。
        output_dir: 追踪日志输出目录；未指定时使用默认 traces 目录。
        """
        self.timeout = timeout
        if output_dir:
            self.trace_output_dir = output_dir
        else:
            base = os.environ.get('BINMIND_DATA_DIR', 'data')
            self.trace_output_dir = os.path.join(base, 'traces')
        os.makedirs(self.trace_output_dir, exist_ok=True)

        self._strace_available = self._check_strace()
        self._frida_available = self._check_frida()

        self._running = False
        self._api_calls: List[ApiCall] = []
        self._lock = threading.Lock()

    def _check_strace(self) -> bool:
        """检查 strace 是否可用（Linux 平台）。"""
        try:
            result = subprocess.run(
                ['strace', '--version'],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_frida(self) -> bool:
        """检查 Frida 是否可用。"""
        try:
            import frida  # noqa: F401
            return True
        except ImportError:
            return False

    def trace_binary(
        self,
        binary_path: str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        use_frida: bool = False,
    ) -> TraceResult:
        """追踪二进制程序的 API 调用序列。

        目标不存在时返回 errors 非空的失败结果；采集后端缺失时
        同样在 errors 中记录，不抛出异常。
        """
        result = TraceResult(binary_path=binary_path)
        if not os.path.exists(binary_path):
            result.errors.append(f'文件不存在: {binary_path}')
            logger.error('二进制文件不存在: %s', binary_path)
            return result

        timeout = timeout or self.timeout
        start_time = time.time()

        try:
            if use_frida and self._frida_available:
                trace_data = self._trace_with_frida(binary_path, args, timeout)
            elif self._strace_available:
                trace_data = self._trace_with_strace(binary_path, args, timeout)
            else:
                result.errors.append('没有可用的追踪工具（strace 或 Frida）')
                return result

            if trace_data:
                result.api_calls = self._parse_trace_data(trace_data)
                result.total_calls = len(result.api_calls)
                result.behavior_sequences = self._analyze_behavior_sequences(result.api_calls)
                result.risk_summary = self._calculate_risk_summary(result.behavior_sequences)
                result.success = True
        except subprocess.TimeoutExpired:
            result.errors.append(f'追踪超时 ({timeout}s)')
        except Exception as exc:
            result.errors.append(f'追踪异常: {exc}')

        result.trace_duration = time.time() - start_time
        if result.api_calls:
            result.trace_log = self._save_trace_log(result)
        return result

    def _trace_with_strace(self, binary_path: str, args: Optional[List[str]],
                           timeout: int) -> Optional[str]:
        """使用 strace 采集系统调用，返回 stderr 文本。"""
        try:
            cmd = ['strace', '-f', '-e', 'trace=file,process,network,memory', '-s', '256']
            cmd.append(binary_path)
            if args:
                cmd.extend(args)
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                encoding='utf-8', errors='replace',
            )
            return result.stderr
        except subprocess.TimeoutExpired:
            raise
        except Exception as exc:
            logger.error('strace 执行失败: %s', exc)
            return None

    def _trace_with_frida(self, binary_path: str, args: Optional[List[str]],
                          timeout: int) -> Optional[List[Dict]]:
        """使用 Frida 采集 API 调用，返回调用记录列表。"""
        try:
            import frida
        except ImportError:
            return None

        trace_data: List[Dict] = []

        def on_message(message, data):  # noqa: ARG001
            if message.get('type') == 'send':
                payload = message.get('payload', {})
                if payload.get('type') == 'api_calls':
                    trace_data.extend(payload.get('data', []))

        script_source = """
        var api_calls = [];
        function watch(name, fn) {
            var ptr = Module.findExportByName(null, name);
            if (!ptr) return;
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    api_calls.push({api: name, args: {}, timestamp: Date.now()});
                }
            });
        }
        ['open','read','write','connect','send','recv','fork','execve','mmap'].forEach(watch);
        setInterval(function() { send({type: 'api_calls', data: api_calls}); api_calls = []; }, 1000);
        """
        try:
            pid = frida.spawn([binary_path] + (args or []))
            session = frida.attach(pid)
            script = session.create_script(script_source)
            script.on('message', on_message)
            script.load()
            frida.resume(pid)
            time.sleep(min(timeout, 30))
            session.detach()
        except Exception as exc:
            logger.error('Frida 追踪失败: %s', exc)
            return None
        return trace_data

    def _parse_trace_data(self, trace_data: Any) -> List[ApiCall]:
        """按采集后端类型分发解析。"""
        if isinstance(trace_data, str):
            return self._parse_strace_output(trace_data)
        if isinstance(trace_data, list):
            return self._parse_frida_output(trace_data)
        return []

    def _parse_strace_output(self, output: str) -> List[ApiCall]:
        """解析 strace 行：PID syscall(args) = ret。"""
        api_calls: List[ApiCall] = []
        pattern = re.compile(
            r'^(\d+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)'
        )
        for line in output.split('\n'):
            match = pattern.match(line.strip())
            if not match:
                continue
            pid = int(match.group(1))
            api_name = match.group(2)
            args_str = match.group(3)
            return_val = match.group(4)
            arguments = self._parse_strace_args(args_str)
            success = return_val not in ('-1', '0xffffffff', '0xffffffffffffffff')
            api_calls.append(ApiCall(
                timestamp=time.time(),
                api_name=api_name,
                category=self._categorize_api_call(api_name, arguments),
                arguments=arguments,
                return_value=return_val,
                success=success,
                process_id=pid,
            ))
        return api_calls

    def _parse_strace_args(self, args_str: str) -> Dict[str, Any]:
        """从 strace 参数字符串提取键值。"""
        arguments: Dict[str, Any] = {}
        for i, part in enumerate(args_str.split(',')):
            part = part.strip()
            if not part:
                continue
            quoted = re.search(r'"([^"]*)"', part)
            if quoted:
                arguments[f'arg{i}'] = quoted.group(1)
            elif part.startswith('0x'):
                try:
                    arguments[f'arg{i}'] = int(part, 16)
                except ValueError:
                    arguments[f'arg{i}'] = part
            elif part.lstrip('-').isdigit():
                arguments[f'arg{i}'] = int(part)
            else:
                arguments[f'arg{i}'] = part
        return arguments

    def _parse_frida_output(self, output: List[Dict]) -> List[ApiCall]:
        """解析 Frida 采集的调用记录。"""
        api_calls: List[ApiCall] = []
        for item in output:
            api_name = item.get('api', 'unknown')
            arguments = item.get('args', {})
            ts = item.get('timestamp', time.time() * 1000)
            api_calls.append(ApiCall(
                timestamp=ts / 1000.0,
                api_name=api_name,
                category=self._categorize_api_call(api_name, arguments),
                arguments=arguments,
                success=True,
            ))
        return api_calls

    def _categorize_api_call(self, api_name: str, arguments: Dict[str, Any]) -> BehaviorCategory:
        """将 API 名称归类为行为类别。

        先查精确映射表，再按名称关键词模糊归类，均未命中返回 UNKNOWN。
        """
        if api_name in API_CATEGORY_MAP:
            return API_CATEGORY_MAP[api_name]

        api_lower = api_name.lower()
        keyword_map = [
            (['file', 'open', 'read', 'write', 'delete', 'move', 'copy'], BehaviorCategory.FILE_OPERATION),
            (['socket', 'connect', 'send', 'recv', 'http', 'internet', 'url', 'net'], BehaviorCategory.NETWORK),
            (['process', 'thread', 'fork', 'exec', 'spawn', 'create'], BehaviorCategory.PROCESS),
            (['mem', 'alloc', 'map', 'virtual', 'heap'], BehaviorCategory.MEMORY),
            (['reg', 'registry', 'key'], BehaviorCategory.REGISTRY),
            (['token', 'priv', 'uid', 'gid', 'perm', 'chmod'], BehaviorCategory.PRIVILEGE),
            (['crypt', 'encrypt', 'decrypt', 'hash'], BehaviorCategory.CRYPTO),
        ]
        for keywords, category in keyword_map:
            if any(kw in api_lower for kw in keywords):
                return category
        return BehaviorCategory.UNKNOWN

    def _analyze_behavior_sequences(self, api_calls: List[ApiCall]) -> List[BehaviorSequence]:
        """按时间窗口分组，逐模式匹配，返回命中的行为序列。"""
        sequences: List[BehaviorSequence] = []
        if not api_calls:
            return sequences

        window_size = 60.0
        windows: Dict[int, List[ApiCall]] = defaultdict(list)
        for call in api_calls:
            ts = call.timestamp
            if isinstance(ts, datetime):
                ts = ts.timestamp()
            window_key = int(ts / window_size)
            windows[window_key].append(call)

        for window_key, calls in windows.items():
            for pattern_name, pattern in MALICIOUS_BEHAVIOR_PATTERNS.items():
                if not self._match_pattern(calls, pattern):
                    continue
                start_ts = []
                end_ts = []
                for c in calls:
                    t = c.timestamp
                    if isinstance(t, datetime):
                        t = t.timestamp()
                    start_ts.append(t)
                    end_ts.append(t)
                sequences.append(BehaviorSequence(
                    name=pattern_name,
                    pattern_type=pattern['name'],
                    severity=pattern['severity'],
                    description=pattern['description'],
                    api_calls=[c.api_name for c in calls],
                    confidence=self._match_confidence(calls, pattern),
                    sequence_id=f"{window_key}_{pattern['name']}",
                    start_time=min(start_ts),
                    end_time=max(end_ts),
                ))
        return sequences

    def _match_pattern(self, calls: List[ApiCall], pattern: Dict[str, Any]) -> bool:
        """判断调用列表是否命中模式的 api_sequence。

        每个步骤中只要有一个 API 出现在调用集中即视为该步骤命中，
        命中步骤占比不低于一半时判定模式成立。
        """
        steps = pattern.get('api_sequence', [])
        if not steps:
            return False
        call_names = {c.api_name for c in calls}
        call_categories = {c.category for c in calls}
        matched = 0
        for step in steps:
            step_apis = set(step.get('apis', []))
            step_categories = set(step.get('category', [])) if isinstance(step.get('category'), list) else (
                {step['category']} if 'category' in step else set()
            )
            api_hit = bool(step_apis & call_names) if step_apis else False
            cat_hit = bool(step_categories & call_categories) if step_categories else False
            if api_hit or cat_hit:
                matched += 1
        return matched >= max(1, len(steps) / 2)

    def _match_confidence(self, calls: List[ApiCall], pattern: Dict[str, Any]) -> float:
        """计算模式匹配置信度：命中步骤数占全部步骤的比例。"""
        steps = pattern.get('api_sequence', [])
        if not steps:
            return 0.0
        call_names = {c.api_name for c in calls}
        call_categories = {c.category for c in calls}
        matched = 0
        for step in steps:
            step_apis = set(step.get('apis', []))
            step_categories = set(step.get('category', [])) if isinstance(step.get('category'), list) else (
                {step['category']} if 'category' in step else set()
            )
            if (step_apis & call_names) or (step_categories & call_categories):
                matched += 1
        return round(matched / len(steps), 3)

    def _calculate_risk_summary(self, sequences: List[BehaviorSequence]) -> Dict[str, int]:
        """按风险等级统计行为序列数量。"""
        summary: Dict[str, int] = defaultdict(int)
        for seq in sequences:
            summary[seq.severity] += 1
        return dict(summary)

    def _save_trace_log(self, result: TraceResult) -> str:
        """将追踪结果落盘为 JSON，返回文件路径。"""
        binary_name = os.path.splitext(os.path.basename(result.binary_path))[0]
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_path = os.path.join(self.trace_output_dir, f'{binary_name}_{stamp}.json')
        try:
            with open(log_path, 'w', encoding='utf-8') as fh:
                json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.error('保存追踪日志失败: %s', exc)
        return log_path

    def save_result(self, result: TraceResult, name: str) -> str:
        """将追踪结果写入输出目录，返回保存路径。"""
        if not name.endswith('.json'):
            name += '.json'
        path = os.path.join(self.trace_output_dir, name)
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
        return path

    def generate_report(self, result: TraceResult) -> str:
        """生成 Markdown 格式的追踪分析报告。"""
        lines: List[str] = []
        lines.append('## API 调用追踪分析报告\n')
        lines.append('### 基本信息')
        lines.append(f'- 二进制路径: `{result.binary_path}`')
        lines.append(f'- 追踪时长: {result.trace_duration:.2f} 秒')
        lines.append(f'- 总调用数: {result.total_calls}')
        lines.append('')

        if result.api_calls:
            lines.append('### API调用统计')
            category_stats: Dict[str, int] = defaultdict(int)
            for call in result.api_calls:
                category_stats[call.category.value] += 1
            lines.append('| 类别 | 调用次数 |')
            lines.append('|------|----------|')
            for category, count in sorted(category_stats.items(), key=lambda x: -x[1]):
                lines.append(f'| {category} | {count} |')
            lines.append('')

        if result.behavior_sequences:
            lines.append('### 检测到的行为模式')
            for seq in result.behavior_sequences:
                lines.append(f'- **{seq.name}**（{seq.severity}）: {seq.description}')

        if result.risk_summary:
            lines.append('### 风险摘要')
            for level, count in sorted(result.risk_summary.items()):
                lines.append(f'- {level}: {count} 个')

        if result.errors:
            lines.append('### 错误')
            for error in result.errors:
                lines.append(f'- {error}')

        return '\n'.join(lines)


def trace_and_analyze(
    binary_path: str,
    args: Optional[List[str]] = None,
    timeout: int = 300,
    use_frida: bool = False,
) -> TraceResult:
    """便捷入口：追踪并分析单个二进制。"""
    tracer = BehaviorTracer(timeout=timeout)
    return tracer.trace_binary(binary_path, args, timeout, use_frida)
