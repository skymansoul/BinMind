import os
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class IPCType(Enum):
    """IPC类型枚举"""
    PIPE = 'pipe'
    SHARED_MEMORY = 'shared_memory'
    SOCKET = 'socket'
    DBUS = 'dbus'
    COM = 'com'
    MESSAGE_QUEUE = 'message_queue'
    SEMAPHORE = 'semaphore'
    UNKNOWN = 'unknown'

class IPCSecurityIssue(Enum):
    """IPC安全问题类型"""
    NO_AUTHENTICATION = 'no_authentication'
    INSUFFICIENT_VALIDATION = 'insufficient_validation'
    INJECTION_VULNERABILITY = 'injection_vulnerability'
    PERMISSION_MISCONFIGURATION = 'permission_misconfiguration'
    UNENCRYPTED_COMMUNICATION = 'unencrypted_communication'
    PATH_TRAVERSAL = 'path_traversal'
    BUFFER_OVERFLOW = 'buffer_overflow'
    RACE_CONDITION = 'race_condition'

@dataclass
class IPCEndpoint:
    """IPC端点信息"""
    name: str
    ipc_type: IPCType
    location: str  # 管道名、socket路径、共享内存名等
    binary_path: str
    binary_name: str
    read_access: bool = True
    write_access: bool = True
    is_server: bool = False
    is_client: bool = False

@dataclass
class IPCInteraction:
    """IPC交互信息"""
    source_binary: str
    destination_binary: str
    ipc_type: IPCType
    endpoint_name: str
    data_flow_risk: float = 0.0
    security_issues: List[IPCSecurityIssue] = None
    
    def __post_init__(self):
        if self.security_issues is None:
            self.security_issues = []

@dataclass
class IPCAnalysisResult:
    """IPC分析结果"""
    binaries: List[str]
    endpoints: List[IPCEndpoint]
    interactions: List[IPCInteraction]
    security_issues: List[Dict[str, Any]]
    interaction_graph: str
    cross_binary_taints: List[Dict[str, Any]]

class IPCSecurityAnalyzer:
    """多二进制IPC安全分析器"""
    
    # IPC相关的特征模式
    PIPE_PATTERNS = [
        b'CreateNamedPipe',
        b'CreatePipe',
        b'ConnectNamedPipe',
        b'CallNamedPipe',
        b'_CreateNamedPipe',
        b'\\.\\pipe\\',
        b'\\\\.\\pipe\\',
        b'NMPipe',
    ]
    
    SHARED_MEMORY_PATTERNS = [
        b'CreateFileMapping',
        b'OpenFileMapping',
        b'MapViewOfFile',
        b'CreateSharedMemory',
        b'SharedMemory',
        b'MemMap',
        b'/dev/shm/',
        b'SHMEM',
    ]
    
    SOCKET_PATTERNS = [
        b'socket(',
        b'bind(',
        b'listen(',
        b'accept(',
        b'connect(',
        b'WSASocket',
        b'InetAddr',
        b'localhost',
        b'127.0.0.1',
        b'::1',
    ]
    
    DBUS_PATTERNS = [
        b'dbus_',
        b'DBus',
        b'org.freedesktop.DBus',
    ]
    
    COM_PATTERNS = [
        b'CoCreateInstance',
        b'CLSID_',
        b'IID_',
        b'COMObject',
        b'OLE Automation',
    ]
    
    MESSAGE_QUEUE_PATTERNS = [
        b'CreateMsgQueue',
        b'OpenMsgQueue',
        b'MsgQueue',
        b'mq_open',
        b'mq_send',
        b'mq_receive',
    ]
    
    def __init__(self, binary_paths: List[str] = None):
        """初始化IPC安全分析器"""
        self.binary_paths = binary_paths or []
        self.binary_data: Dict[str, bytes] = {}
        self.endpoints: List[IPCEndpoint] = []
        self.interactions: List[IPCInteraction] = []
        self.security_issues: List[Dict[str, Any]] = []
        
        if self.binary_paths:
            self._load_binaries()
    
    def _load_binaries(self):
        """加载所有二进制文件"""
        for path in self.binary_paths:
            try:
                with open(path, 'rb') as f:
                    self.binary_data[path] = f.read()
                logger.info(f"已加载二进制文件: {path}")
            except Exception as e:
                logger.error(f"加载二进制文件失败 {path}: {e}")
    
    def _detect_ipc_patterns(self, binary_data: bytes, binary_name: str) -> List[Tuple[IPCType, str]]:
        """检测二进制中的IPC模式"""
        results = []
        
        # 检测管道
        for pattern in self.PIPE_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.PIPE, pattern.decode('ascii', errors='ignore')))
        
        # 检测共享内存
        for pattern in self.SHARED_MEMORY_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.SHARED_MEMORY, pattern.decode('ascii', errors='ignore')))
        
        # 检测Socket
        for pattern in self.SOCKET_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.SOCKET, pattern.decode('ascii', errors='ignore')))
        
        # 检测D-Bus
        for pattern in self.DBUS_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.DBUS, pattern.decode('ascii', errors='ignore')))
        
        # 检测COM
        for pattern in self.COM_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.COM, pattern.decode('ascii', errors='ignore')))
        
        # 检测消息队列
        for pattern in self.MESSAGE_QUEUE_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.MESSAGE_QUEUE, pattern.decode('ascii', errors='ignore')))
        
        return results
    
    def _extract_endpoint_names(self, binary_data: bytes) -> List[str]:
        """提取IPC端点名称"""
        names = []
        
        # 尝试提取管道名称
        pipe_patterns = [b'\\\\.\\\\pipe\\\\', b'\\\\.\\pipe\\']
        for pattern in pipe_patterns:
            idx = 0
            while idx < len(binary_data):
                pos = binary_data.find(pattern, idx)
                if pos == -1:
                    break
                # 查找字符串结束
                end_pos = binary_data.find(b'\x00', pos)
                if end_pos != -1:
                    name = binary_data[pos:end_pos].decode('utf-8', errors='ignore')
                    if len(name) > len(pattern):
                        names.append(name)
                idx = pos + 1
        
        # 提取共享内存名称
        shm_patterns = [b'/dev/shm/', b'SHM_', b'Shared']
        for pattern in shm_patterns:
            idx = 0
            while idx < len(binary_data):
                pos = binary_data.find(pattern, idx)
                if pos == -1:
                    break
                end_pos = binary_data.find(b'\x00', pos)
                if end_pos != -1:
                    name = binary_data[pos:end_pos].decode('utf-8', errors='ignore')
                    if len(name) > 4:
                        names.append(name)
                idx = pos + 1
        
        return names
    
    def _analyze_single_binary(self, binary_path: str, binary_data: bytes) -> List[IPCEndpoint]:
        """分析单个二进制的IPC端点"""
        endpoints = []
        binary_name = os.path.basename(binary_path)
        
        patterns = self._detect_ipc_patterns(binary_data, binary_name)
        endpoint_names = self._extract_endpoint_names(binary_data)
        
        for ipc_type, _ in patterns:
            if endpoint_names:
                for name in endpoint_names[:3]:  # 限制数量
                    endpoint = IPCEndpoint(
                        name=name,
                        ipc_type=ipc_type,
                        location=name,
                        binary_path=binary_path,
                        binary_name=binary_name,
                        is_server=b'Create' in binary_data or b'Server' in binary_data,
                        is_client=b'Connect' in binary_data or b'Client' in binary_data
                    )
                    endpoints.append(endpoint)
            else:
                endpoint = IPCEndpoint(
                    name=f"{binary_name}_{ipc_type.value}",
                    ipc_type=ipc_type,
                    location="unknown",
                    binary_path=binary_path,
                    binary_name=binary_name,
                    is_server=b'Create' in binary_data or b'Server' in binary_data,
                    is_client=b'Connect' in binary_data or b'Client' in binary_data
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    def _identify_cross_binary_interactions(self) -> List[IPCInteraction]:
        """识别跨二进制交互"""
        interactions = []
        endpoint_map: Dict[str, List[IPCEndpoint]] = {}
        
        # 按端点名称分组
        for endpoint in self.endpoints:
            key = endpoint.location.lower()
            if key not in endpoint_map:
                endpoint_map[key] = []
            endpoint_map[key].append(endpoint)
        
        # 识别跨二进制交互
        for endpoint_name, endpoints in endpoint_map.items():
            if len(endpoints) >= 2:
                binaries = set(e.binary_path for e in endpoints)
                if len(binaries) >= 2:
                    # 找到服务器和客户端
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
                                    data_flow_risk=self._calculate_data_flow_risk(client, server)
                                )
                                interactions.append(interaction)
        
        return interactions
    
    def _calculate_data_flow_risk(self, client: IPCEndpoint, server: IPCEndpoint) -> float:
        """计算数据流风险评分"""
        risk = 0.0
        
        # 检查是否存在危险函数
        client_data = self.binary_data.get(client.binary_path, b'')
        server_data = self.binary_data.get(server.binary_path, b'')
        
        # 客户端风险因素
        if b'strcpy' in client_data or b'sprintf' in client_data:
            risk += 0.2
        if b'system(' in client_data or b'exec' in client_data:
            risk += 0.3
        
        # 服务端风险因素
        if b'strcpy' in server_data or b'sprintf' in server_data:
            risk += 0.2
        if b'system(' in server_data or b'exec' in server_data:
            risk += 0.3
        
        return min(risk, 1.0)
    
    def _detect_security_issues(self) -> List[Dict[str, Any]]:
        """检测安全问题"""
        issues = []
        
        for interaction in self.interactions:
            interaction_issues = []
            
            # 检查认证问题
            if b'Authenticate' not in self.binary_data.get(interaction.destination_binary, b''):
                interaction_issues.append(IPCSecurityIssue.NO_AUTHENTICATION)
            
            # 检查输入验证
            validation_funcs = [b'Validate', b'CheckInput', b'Sanitize', b'Filter']
            has_validation = any(f in self.binary_data.get(interaction.destination_binary, b'') for f in validation_funcs)
            if not has_validation:
                interaction_issues.append(IPCSecurityIssue.INSUFFICIENT_VALIDATION)
            
            # 检查注入风险
            if b'system(' in self.binary_data.get(interaction.destination_binary, b''):
                interaction_issues.append(IPCSecurityIssue.INJECTION_VULNERABILITY)
            
            # 检查权限配置
            if interaction.ipc_type == IPCType.PIPE:
                if b'Everyone' in self.binary_data.get(interaction.destination_binary, b''):
                    interaction_issues.append(IPCSecurityIssue.PERMISSION_MISCONFIGURATION)
            
            if interaction_issues:
                issues.append({
                    'interaction': f"{interaction.source_binary} -> {interaction.destination_binary}",
                    'ipc_type': interaction.ipc_type.value,
                    'endpoint': interaction.endpoint_name,
                    'issues': [i.value for i in interaction_issues],
                    'risk_score': interaction.data_flow_risk
                })
        
        return issues
    
    def _generate_interaction_graph(self) -> str:
        """生成交互图（Graphviz格式）"""
        graph_lines = ['digraph IPC_Interactions {']
        
        # 添加节点
        binaries = set()
        for interaction in self.interactions:
            binaries.add(interaction.source_binary)
            binaries.add(interaction.destination_binary)
        
        for binary in binaries:
            graph_lines.append(f'    "{binary}" [shape=box];')
        
        # 添加边
        for interaction in self.interactions:
            color = 'green' if interaction.data_flow_risk < 0.5 else 'red'
            label = f"{interaction.ipc_type.value}"
            graph_lines.append(f'    "{interaction.source_binary}" -> "{interaction.destination_binary}" [label="{label}", color="{color}"];')
        
        graph_lines.append('}')
        
        return '\n'.join(graph_lines)
    
    def _identify_cross_binary_taints(self) -> List[Dict[str, Any]]:
        """识别跨二进制污点"""
        taints = []
        
        for interaction in self.interactions:
            server_data = self.binary_data.get(interaction.destination_binary, b'')
            
            # 检查是否存在从IPC读取后直接传递给危险函数的模式
            dangerous_funcs = [b'system(', b'exec', b'WinExec', b'ShellExecute']
            
            for func in dangerous_funcs:
                if func in server_data:
                    taints.append({
                        'source': interaction.source_binary,
                        'destination': interaction.destination_binary,
                        'ipc_type': interaction.ipc_type.value,
                        'dangerous_function': func.decode('ascii'),
                        'risk': 'high'
                    })
        
        return taints
    
    def analyze(self) -> IPCAnalysisResult:
        """执行完整的IPC安全分析"""
        if not self.binary_data:
            logger.warning("未加载任何二进制文件")
            return IPCAnalysisResult(
                binaries=[],
                endpoints=[],
                interactions=[],
                security_issues=[],
                interaction_graph='',
                cross_binary_taints=[]
            )
        
        # 分析每个二进制的IPC端点
        for binary_path, binary_data in self.binary_data.items():
            endpoints = self._analyze_single_binary(binary_path, binary_data)
            self.endpoints.extend(endpoints)
        
        # 识别跨二进制交互
        self.interactions = self._identify_cross_binary_interactions()
        
        # 检测安全问题
        self.security_issues = self._detect_security_issues()
        
        # 生成交互图
        graph = self._generate_interaction_graph()
        
        # 识别跨二进制污点
        taints = self._identify_cross_binary_taints()
        
        return IPCAnalysisResult(
            binaries=list(self.binary_data.keys()),
            endpoints=self.endpoints,
            interactions=self.interactions,
            security_issues=self.security_issues,
            interaction_graph=graph,
            cross_binary_taints=taints
        )
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
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
