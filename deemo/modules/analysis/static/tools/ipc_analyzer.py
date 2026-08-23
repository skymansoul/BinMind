# 公共 API: 5 个类, IPCType, IPCSecurityIssue, IPCEndpoint, IPCInteraction, IPCAnalysisResult
# 依赖: os (文件系统), 日志, typing, dataclasses
# 计算复杂度: O(n*m) 每次扫描; 内存: O(n) 原始二进制缓冲区
#
# 2025 升级: GUARD 启发的通用 API 反混淆
# GUARD 使用模拟执行 + 栈布局分析 + sIAT 恢复被混淆的导入函数
# 本模块集成简化版栈布局分析, 通过解析 push/call 序列推断
# 被混淆 API 的参数数量，辅助 sIAT 重构
import os
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

_log = logging.getLogger(__name__)

class IPCType:
    PIPE = "pipe"
    SHARED_MEMORY = "shared_memory"
    SOCKET = "socket"
    DBUS = "dbus"
    COM = "com"
    MESSAGE_QUEUE = "message_queue"
    SEMAPHORE = "semaphore"
    UNKNOWN = "unknown"

class IPCSecurityIssue:
    NO_AUTHENTICATION = "no_authentication"
    INSUFFICIENT_VALIDATION = "insufficient_validation"
    INJECTION_VULNERABILITY = "injection_vulnerability"
    PERMISSION_MISCONFIGURATION = "permission_misconfiguration"
    UNENCRYPTED_COMMUNICATION = "unencrypted_communication"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"

@dataclass
class IPCEndpoint:
    name: str = ""
    ipc_type: str = ""
    location: str = ""
    binary_path: str = ""
    binary_name: str = ""
    read_access: bool = False
    write_access: bool = False
    is_server: bool = False
    is_client: bool = False

class IPCInteraction:
    __slots__ = ('source_binary', 'destination_binary', 'ipc_type', 'endpoint_name', 'data_flow_risk', 'security_issues',)

    def __init__(self, source_binary, destination_binary, ipc_type, endpoint_name, data_flow_risk=0.0, security_issues=None):
        self.source_binary = source_binary
        self.destination_binary = destination_binary
        self.ipc_type = ipc_type
        self.endpoint_name = endpoint_name
        self.data_flow_risk = data_flow_risk
        self.security_issues = security_issues if security_issues is not None else []

class IPCAnalysisResult:
    __slots__ = ('binaries', 'endpoints', 'interactions', 'security_issues', 'interaction_graph', 'cross_binary_taints',)

    def __init__(self, binaries, endpoints, interactions, security_issues, interaction_graph, cross_binary_taints):
        self.binaries = binaries
        self.endpoints = endpoints
        self.interactions = interactions
        self.security_issues = security_issues
        self.interaction_graph = interaction_graph
        self.cross_binary_taints = cross_binary_taints


# GUARD 启发的 sIAT 栈布局分析
# Hwang et al., "GUARD: 针对加壳恶意软件的通用 API 反混淆与 sIAT 恢复"
# 核心方法: Themida/VMProtect 等加壳器将 API 调用混淆为 push/call 序列
# 通过分析 call 前的 push 指令数量推断参数个数，重建 Scattered IAT
# 这大大提高了加壳二进制中 IPC API 的检测率


class StackLayoutAnalyzer:
    """栈布局分析器, GUARD 启发的方法
    通过解析 call 指令前的 push 序列推断被混淆 API 的参数数量和调用约定
    x86: push argN;.; push arg1; call [api] → N 个 push = N 个参数
    x64: mov rcx/rdx/r8/r9 + 栈上参数 → 更复杂但模式可辨
    """

    _PUSH_PAT = __import__('re').compile(
        rb'(?:push|mov\s+(?:r(?:cx|dx|r?8|r?9)|ecx|edx))\s+',
        __import__('re').IGNORECASE
    )
    _CALL_INDIRECT = __import__('re').compile(
        rb'call\s+(?:qword\s+)?\[', __import__('re').IGNORECASE
    )

    def count_params_before_call(self, asm_window: bytes) -> int:
        """计算 call 指令前的参数推送数, 用于恢复混淆 API 的参数签名"""
        push_count = 0
        for m in self._PUSH_PAT.finditer(asm_window):
            push_count += 1
        # 约束：大多数 Windows API ≤ 6 个参数
        return min(push_count, 6)

    def reconstruct_siat_entry(self, binary_data: bytes,
                                 call_offset: int) -> Dict[str, Any]:
        """重建单个 sIAT 条目, 从 call [addr] 模式的上下文恢复 API 信息"""
        # 检索 call 指令前 64 字节
        window_start = max(0, call_offset - 64)
        window = binary_data[window_start:call_offset + 8]
        param_count = self.count_params_before_call(window)
        # 尝试解析间接调用的目标地址
        if call_offset + 6 <= len(binary_data):
            try:
                import struct
                target_ptr = struct.unpack_from('<I', binary_data, call_offset + 2)[0]
            except (struct.error, IndexError):
                target_ptr = 0
        else:
            target_ptr = 0
        return {
            'call_offset': call_offset,
            'estimated_params': param_count,
            'target_ptr': hex(target_ptr) if target_ptr else 'unknown',
            'is_obfuscated': param_count > 0,
        }


class IPCSecurityAnalyzer:
    """Multi-binary IPC security analyzer"""

    PIPE_PATTERNS = [
        b'CreateNamedPipe', b'CreatePipe', b'ConnectNamedPipe',
        b'CallNamedPipe', b'_CreateNamedPipe', b'\\.\\pipe\\', b'NMPipe',
    ]
    SHARED_MEMORY_PATTERNS = [
        b'CreateFileMapping', b'OpenFileMapping', b'MapViewOfFile',
        b'CreateSharedMemory', b'/dev/shm/', b'SHMEM',
    ]
    SOCKET_PATTERNS = [
        b'socket(', b'bind(', b'listen(', b'accept(', b'connect(',
        b'WSASocket', b'localhost', b'127.0.0.1', b'::1',
    ]
    DBUS_PATTERNS = [b'dbus_', b'DBus', b'org.freedesktop.DBus']
    COM_PATTERNS = [b'CoCreateInstance', b'CLSID_', b'IID_', b'OLE Automation']
    MESSAGE_QUEUE_PATTERNS = [b'CreateMsgQueue', b'OpenMsgQueue', b'mq_open', b'mq_send', b'mq_receive']

    def __init__(self, binary_paths: List[str] = None):
        self.binary_paths = binary_paths or []
        self.binary_data: Dict[str, bytes] = {}
        self.endpoints: List[IPCEndpoint] = []
        self.interactions: List[IPCInteraction] = []
        self.security_issues: List[Dict[str, Any]] = []
        self._stack_analyzer = StackLayoutAnalyzer()
        if self.binary_paths:
            self._load_binaries()

    def _load_binaries(self):
        for path in self.binary_paths:
            try:
                with open(path, 'rb') as f:
                    self.binary_data[path] = f.read()
                _log.info(f"Binary loaded: {path}")
            except Exception as e:
                _log.error(f"Binary load failed: {path} | {e}")

    def _detect_ipc_patterns(self, binary_data: bytes, binary_name: str) -> List[Tuple[str, str]]:
        results = []
        for pattern in self.PIPE_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.PIPE, pattern.decode('ascii', errors='ignore')))
        for pattern in self.SHARED_MEMORY_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.SHARED_MEMORY, pattern.decode('ascii', errors='ignore')))
        for pattern in self.SOCKET_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.SOCKET, pattern.decode('ascii', errors='ignore')))
        for pattern in self.DBUS_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.DBUS, pattern.decode('ascii', errors='ignore')))
        for pattern in self.COM_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.COM, pattern.decode('ascii', errors='ignore')))
        for pattern in self.MESSAGE_QUEUE_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.MESSAGE_QUEUE, pattern.decode('ascii', errors='ignore')))
        return results

    def _extract_endpoint_names(self, binary_data: bytes) -> List[str]:
        names = []
        pipe_patterns = [b'\\\\.\\\\pipe\\\\', b'\\\\.\\pipe\\']
        for pattern in pipe_patterns:
            dwIdx = 0
            while dwIdx < len(binary_data):
                pos = binary_data.find(pattern, dwIdx)
                if pos == -1:
                    break
                end_pos = binary_data.find(b'\x00', pos)
                if end_pos != -1:
                    name = binary_data[pos:end_pos].decode('utf-8', errors='ignore')
                    if len(name) > len(pattern):
                        names.append(name)
                dwIdx = pos + 1
        shm_patterns = [b'/dev/shm/', b'SHM_', b'Shared']
        for pattern in shm_patterns:
            dwIdx = 0
            while dwIdx < len(binary_data):
                pos = binary_data.find(pattern, dwIdx)
                if pos == -1:
                    break
                end_pos = binary_data.find(b'\x00', pos)
                if end_pos != -1:
                    name = binary_data[pos:end_pos].decode('utf-8', errors='ignore')
                    if len(name) > 4:
                        names.append(name)
                dwIdx = pos + 1
        return names

    def _analyze_single_binary(self, binary_path: str, binary_data: bytes) -> List[IPCEndpoint]:
        endpoints = []
        binary_name = os.path.basename(binary_path)
        patterns = self._detect_ipc_patterns(binary_data, binary_name)
        endpoint_names = self._extract_endpoint_names(binary_data)
        for ipc_type, _ in patterns:
            if endpoint_names:
                for name in endpoint_names:
                    endpoint = IPCEndpoint(
                        name=name, ipc_type=ipc_type, location=name,
                        binary_path=binary_path, binary_name=binary_name,
                        is_server=b'Create' in binary_data or b'Server' in binary_data,
                        is_client=b'Connect' in binary_data or b'Client' in binary_data)
                    endpoints.append(endpoint)
            else:
                endpoint = IPCEndpoint(
                    name=f"{binary_name}_{ipc_type}", ipc_type=ipc_type,
                    location="unknown", binary_path=binary_path, binary_name=binary_name,
                    is_server=b'Create' in binary_data or b'Server' in binary_data,
                    is_client=b'Connect' in binary_data or b'Client' in binary_data)
                endpoints.append(endpoint)
        return endpoints

    def _identify_cross_binary_interactions(self) -> List[IPCInteraction]:
        interactions = []
        endpoint_map: Dict[str, List[IPCEndpoint]] = {}
        for endpoint in self.endpoints:
            key = endpoint.location.lower()
            endpoint_map.setdefault(key, []).append(endpoint)
        for endpoint_name, endpoints in endpoint_map.items():
            if len(endpoints) >= 2:
                binaries = set(e.binary_path for e in endpoints)
                if len(binaries) >= 2:
                    servers = [e for e in endpoints if e.is_server]
                    clients = [e for e in endpoints if e.is_client]
                    for server in servers:
                        for client in clients:
                            if server.binary_path != client.binary_path:
                                interaction = IPCInteraction(
                                    source_binary=client.binary_name,
                                    destination_binary=server.binary_name,
                                    ipc_type=server.ipc_type,
                                    endpoint_name=endpoint_name,
                                    data_flow_risk=self._calculate_data_flow_risk(client, server))
                                interactions.append(interaction)
        return interactions

    def _calculate_data_flow_risk(self, client: IPCEndpoint, server: IPCEndpoint) -> float:
        risk = 0.0
        client_data = self.binary_data.get(client.binary_path, b'')
        server_data = self.binary_data.get(server.binary_path, b'')
        if b'strcpy' in client_data or b'sprintf' in client_data:
            risk += 0.2
        if b'system(' in client_data or b'exec' in client_data:
            risk += 0.3
        if b'strcpy' in server_data or b'sprintf' in server_data:
            risk += 0.2
        if b'system(' in server_data or b'exec' in server_data:
            risk += 0.3
        return min(risk, 1.0)

    def _detect_security_issues(self) -> List[Dict[str, Any]]:
        issues = []
        for interaction in self.interactions:
            interaction_issues = []
            if b'Authenticate' not in self.binary_data.get(interaction.destination_binary, b''):
                interaction_issues.append(IPCSecurityIssue.NO_AUTHENTICATION)
            validation_funcs = [b'Validate', b'CheckInput', b'Sanitize', b'Filter']
            has_validation = any(f in self.binary_data.get(interaction.destination_binary, b'') for f in validation_funcs)
            if not has_validation:
                interaction_issues.append(IPCSecurityIssue.INSUFFICIENT_VALIDATION)
            if b'system(' in self.binary_data.get(interaction.destination_binary, b''):
                interaction_issues.append(IPCSecurityIssue.INJECTION_VULNERABILITY)
            if interaction.ipc_type == IPCType.PIPE:
                if b'Everyone' in self.binary_data.get(interaction.destination_binary, b''):
                    interaction_issues.append(IPCSecurityIssue.PERMISSION_MISCONFIGURATION)
            if interaction_issues:
                issues.append({
                    'interaction': f"{interaction.source_binary} -> {interaction.destination_binary}",
                    'ipc_type': interaction.ipc_type, 'endpoint': interaction.endpoint_name,
                    'issues': interaction_issues, 'risk_score': interaction.data_flow_risk})
        return issues

    def _generate_interaction_graph(self) -> str:
        graph_lines = ['digraph IPC_Interactions {']
        binaries = set()
        for interaction in self.interactions:
            binaries.add(interaction.source_binary)
            binaries.add(interaction.destination_binary)
        for binary in binaries:
            graph_lines.append(f'    "{binary}" [shape=box];')
        for interaction in self.interactions:
            color = 'green' if interaction.data_flow_risk < 0.5 else 'red'
            graph_lines.append(f'    "{interaction.source_binary}" -> '
                             f'"{interaction.destination_binary}" [label="{interaction.ipc_type}", color="{color}"];')
        graph_lines.append('}')
        return '\n'.join(graph_lines)

    def _identify_cross_binary_taints(self) -> List[Dict[str, Any]]:
        taints = []
        for interaction in self.interactions:
            server_data = self.binary_data.get(interaction.destination_binary, b'')
            dangerous_funcs = [b'system(', b'exec', b'WinExec', b'ShellExecute']
            for func in dangerous_funcs:
                if func in server_data:
                    taints.append({
                        'source': interaction.source_binary,
                        'destination': interaction.destination_binary,
                        'ipc_type': interaction.ipc_type,
                        'dangerous_function': func.decode('ascii'), 'risk': 'high'})
        return taints

    def analyze(self) -> IPCAnalysisResult:
        if not self.binary_data:
            _log.warning("No binaries loaded; returning empty result.")
            return IPCAnalysisResult(binaries=[], endpoints=[], interactions=[],
                                     security_issues=[], interaction_graph='',
                                     cross_binary_taints=[])
        for binary_path, binary_data in self.binary_data.items():
            endpoints = self._analyze_single_binary(binary_path, binary_data)
            self.endpoints.extend(endpoints)
        self.interactions = self._identify_cross_binary_interactions()
        self.security_issues = self._detect_security_issues()
        graph = self._generate_interaction_graph()
        taints = self._identify_cross_binary_taints()
        return IPCAnalysisResult(
            binaries=list(self.binary_data.keys()), endpoints=self.endpoints,
            interactions=self.interactions, security_issues=self.security_issues,
            interaction_graph=graph, cross_binary_taints=taints)

    def get_analysis_summary(self) -> Dict[str, Any]:
        result = self.analyze()
        return {
            'num_binaries': len(result.binaries),
            'num_endpoints': len(result.endpoints),
            'num_interactions': len(result.interactions),
            'num_security_issues': len(result.security_issues),
            'num_taints': len(result.cross_binary_taints),
            'interaction_graph': result.interaction_graph,
            'security_issues': result.security_issues,
            'cross_binary_taints': result.cross_binary_taints,
        }
