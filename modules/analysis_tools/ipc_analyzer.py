# Public API: 5 classes — IPCType, IPCSecurityIssue, IPCEndpoint, IPCInteraction, IPCAnalysisResult.
# Dependency: os (filesystem), logging, typing, dataclasses.
# Computational bound: O(n*m) per scan pass; memory: O(n) for raw binary buffers.
import os
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class IPCType:
    # Enumerated IPC transport variants.
    PIPE = 'pipe'
    SHARED_MEMORY = 'shared_memory'
    SOCKET = 'socket'
    DBUS = 'dbus'
    COM = 'com'
    MESSAGE_QUEUE = 'message_queue'
    SEMAPHORE = 'semaphore'
    UNKNOWN = 'unknown'

class IPCSecurityIssue:
    """Taxonomy of IPC security vulnerability classes."""
    NO_AUTHENTICATION = 'no_authentication'
    INSUFFICIENT_VALIDATION = 'insufficient_validation'
    INJECTION_VULNERABILITY = 'injection_vulnerability'
    PERMISSION_MISCONFIGURATION = 'permission_misconfiguration'
    UNENCRYPTED_COMMUNICATION = 'unencrypted_communication'
    PATH_TRAVERSAL = 'path_traversal'
    BUFFER_OVERFLOW = 'buffer_overflow'
    RACE_CONDITION = 'race_condition'

# Field defaults declared inline; @dataclass generates constructor.
@dataclass
class IPCEndpoint:
    name: str = ""
    ipc_type: Any = None
    location: Any = None
    binary_path: Any = None
    binary_name: Any = None
    read_access: Any = None
    write_access: Any = None
    is_server: Any = None
    is_client: Any = None

class IPCInteraction:
    __slots__ = ('source_binary', 'destination_binary', 'ipc_type', 'endpoint_name', 'data_flow_risk', 'security_issues',)

    def __init__(self, source_binary, destination_binary, ipc_type, endpoint_name, data_flow_risk=0.0, security_issues=None):
        self.source_binary = source_binary
        self.destination_binary = destination_binary
        self.ipc_type = ipc_type
        self.endpoint_name = endpoint_name
        self.data_flow_risk = data_flow_risk
        self.security_issues = security_issues

    def __post_init__(self):
        if self.security_issues is None:
            self.security_issues = []

# Hand-written constructor; __slots__ enforces fixed attribute layout.
class IPCAnalysisResult:
    __slots__ = ('binaries', 'endpoints', 'interactions', 'security_issues', 'interaction_graph', 'cross_binary_taints',)

    def __init__(self, binaries, endpoints, interactions, security_issues, interaction_graph, cross_binary_taints):
        self.binaries = binaries
        self.endpoints = endpoints
        self.interactions = interactions
        self.security_issues = security_issues
        self.interaction_graph = interaction_graph
        self.cross_binary_taints = cross_binary_taints

class IPCSecurityAnalyzer:
    """Multi-binary IPC security analyzer."""

    # Byte-pattern signatures for IPC mechanism detection.
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
        # Instantiate analyzer state; optionally preload binaries.
        self.binary_paths = binary_paths or []
        self.binary_data: Dict[str, bytes] = {}
        self.endpoints: List[IPCEndpoint] = []
        self.interactions: List[IPCInteraction] = []
        self.security_issues: List[Dict[str, Any]] = []

        if self.binary_paths:
            self._load_binaries()

    def _load_binaries(self):
        # Read each binary into memory for byte-level scanning.
        for path in self.binary_paths:
            try:
                with open(path, 'rb') as f:
                    self.binary_data[path] = f.read()
                logger.info(f"Binary loaded: {path}")
            except Exception as e:
                logger.error(f"Binary load failed: {path} | {e}")

    def _detect_ipc_patterns(self, binary_data: bytes, binary_name: str) -> List[Tuple[IPCType, str]]:
        """Match known IPC patterns against raw binary bytes."""
        results = []

        # Scan for named/anonymous pipe APIs.
        for pattern in self.PIPE_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.PIPE, pattern.decode('ascii', errors='ignore')))

        # Probe shared memory mapping primitives.
        for pattern in self.SHARED_MEMORY_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.SHARED_MEMORY, pattern.decode('ascii', errors='ignore')))

        # Identify socket-level network IPC.
        for pattern in self.SOCKET_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.SOCKET, pattern.decode('ascii', errors='ignore')))

        # Search for D-Bus transport references.
        for pattern in self.DBUS_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.DBUS, pattern.decode('ascii', errors='ignore')))

        # Detect COM/OLE instantiation calls.
        for pattern in self.COM_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.COM, pattern.decode('ascii', errors='ignore')))

        # Match POSIX/Win32 message queue APIs.
        for pattern in self.MESSAGE_QUEUE_PATTERNS:
            if pattern in binary_data:
                results.append((IPCType.MESSAGE_QUEUE, pattern.decode('ascii', errors='ignore')))

        return results

    def _extract_endpoint_names(self, binary_data: bytes) -> List[str]:
        # Recover IPC endpoint names from binary strings.
        names = []

        # Extract named pipe paths (\\\\.\\pipe\\ prefix).
        pipe_patterns = [b'\\\\.\\\\pipe\\\\', b'\\\\.\\pipe\\']
        for pattern in pipe_patterns:
            dwIdx = 0
            while dwIdx < len(binary_data):
                pos = binary_data.find(pattern, dwIdx)
                if pos == -1:
                    break
                # Locate null terminator bounding the string.
                end_pos = binary_data.find(b'\x00', pos)
                if end_pos != -1:
                    name = binary_data[pos:end_pos].decode('utf-8', errors='ignore')
                    if len(name) > len(pattern):
                        names.append(name)
                dwIdx = pos + 1

        # Recover shared memory segment identifiers.
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
        # Enumerate IPC endpoints within one binary.
        endpoints = []
        binary_name = os.path.basename(binary_path)

        patterns = self._detect_ipc_patterns(binary_data, binary_name)
        endpoint_names = self._extract_endpoint_names(binary_data)

        for ipc_type, _ in patterns:
            if endpoint_names:
                for name in endpoint_names:
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
                    name=f"{binary_name}_{ipc_type}",
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
        # Map cross-binary IPC producer-consumer pairs.
        interactions = []
        endpoint_map: Dict[str, List[IPCEndpoint]] = {}

        # Cluster endpoints by normalized location key.
        for endpoint in self.endpoints:
            key = endpoint.location.lower()
            if key not in endpoint_map:
                endpoint_map[key] = []
            endpoint_map[key].append(endpoint)

        # Resolve interactions where 2+ binaries share an endpoint.
        for endpoint_name, endpoints in endpoint_map.items():
            if len(endpoints) >= 2:
                binaries = set(e.binary_path for e in endpoints)
                if len(binaries) >= 2:
                    # Partition endpoints into server and client roles.
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
        # Compute risk score for data flow between client and server.
        risk = 0.0

        # Inspect binary data for unsafe C runtime calls.
        client_data = self.binary_data.get(client.binary_path, b'')
        server_data = self.binary_data.get(server.binary_path, b'')

        # Client-side risk: unsafe string ops and command execution.
        if b'strcpy' in client_data or b'sprintf' in client_data:
            risk += 0.2
        if b'system(' in client_data or b'exec' in client_data:
            risk += 0.3

        # Server-side risk: identical unsafe-call heuristics.
        if b'strcpy' in server_data or b'sprintf' in server_data:
            risk += 0.2
        if b'system(' in server_data or b'exec' in server_data:
            risk += 0.3

        return min(risk, 1.0)

    def _detect_security_issues(self) -> List[Dict[str, Any]]:
        """Identify security issues from interaction data and binary contents."""
        issues = []

        for interaction in self.interactions:
            interaction_issues = []

            # Verify presence of authentication mechanisms.
            if b'Authenticate' not in self.binary_data.get(interaction.destination_binary, b''):
                interaction_issues.append(IPCSecurityIssue.NO_AUTHENTICATION)

            # Confirm input sanitization routines exist.
            validation_funcs = [b'Validate', b'CheckInput', b'Sanitize', b'Filter']
            has_validation = any(f in self.binary_data.get(interaction.destination_binary, b'') for f in validation_funcs)
            if not has_validation:
                interaction_issues.append(IPCSecurityIssue.INSUFFICIENT_VALIDATION)

            # Flag command injection via system() or exec().
            if b'system(' in self.binary_data.get(interaction.destination_binary, b''):
                interaction_issues.append(IPCSecurityIssue.INJECTION_VULNERABILITY)

            # Audit pipe permission scope (Everyone SID).
            if interaction.ipc_type == IPCType.PIPE:
                if b'Everyone' in self.binary_data.get(interaction.destination_binary, b''):
                    interaction_issues.append(IPCSecurityIssue.PERMISSION_MISCONFIGURATION)

            if interaction_issues:
                issues.append({
                    'interaction': f"{interaction.source_binary} -> {interaction.destination_binary}",
                    'ipc_type': interaction.ipc_type,
                    'endpoint': interaction.endpoint_name,
                    'issues': [i for i in interaction_issues],
                    'risk_score': interaction.data_flow_risk
                })

        return issues

    def _generate_interaction_graph(self) -> str:
        # Render interaction topology as a Graphviz digraph.
        graph_lines = ['digraph IPC_Interactions {']

        # Declare graph nodes — one per binary.
        binaries = set()
        for interaction in self.interactions:
            binaries.add(interaction.source_binary)
            binaries.add(interaction.destination_binary)

        for binary in binaries:
            graph_lines.append(f'    "{binary}" [shape=box];')

        # Declare directed edges with risk-colored labels.
        for interaction in self.interactions:
            color = 'green' if interaction.data_flow_risk < 0.5 else 'red'
            label = f"{interaction.ipc_type}"
            graph_lines.append(f'    "{interaction.source_binary}" -> "{interaction.destination_binary}" [label="{label}", color="{color}"];')

        graph_lines.append('}')

        return '\n'.join(graph_lines)

    def _identify_cross_binary_taints(self) -> List[Dict[str, Any]]:
        # Trace taint paths from IPC source to dangerous sink.
        taints = []

        for interaction in self.interactions:
            server_data = self.binary_data.get(interaction.destination_binary, b'')

            # Flag taint when IPC data reaches a dangerous sink without sanitization.
            dangerous_funcs = [b'system(', b'exec', b'WinExec', b'ShellExecute']

            for func in dangerous_funcs:
                if func in server_data:
                    taints.append({
                        'source': interaction.source_binary,
                        'destination': interaction.destination_binary,
                        'ipc_type': interaction.ipc_type,
                        'dangerous_function': func.decode('ascii'),
                        'risk': 'high'
                    })

        return taints

    def analyze(self) -> IPCAnalysisResult:
        """Run the full IPC security analysis pipeline."""
        if not self.binary_data:
            logger.warning("No binaries loaded; returning empty result.")
            return IPCAnalysisResult(
                binaries=[],
                endpoints=[],
                interactions=[],
                security_issues=[],
                interaction_graph='',
                cross_binary_taints=[])

        # Step 1: Scan each binary for IPC endpoints.
        for binary_path, binary_data in self.binary_data.items():
            endpoints = self._analyze_single_binary(binary_path, binary_data)
            self.endpoints.extend(endpoints)

        # Step 2: Derive cross-binary interactions.
        self.interactions = self._identify_cross_binary_interactions()

        # Step 3: Detect security issues.
        self.security_issues = self._detect_security_issues()

        # Step 4: Generate Graphviz topology.
        graph = self._generate_interaction_graph()

        # Step 5: Identify cross-binary taint flows.
        taints = self._identify_cross_binary_taints()

        return IPCAnalysisResult(
            binaries=list(self.binary_data.keys()),
            endpoints=self.endpoints,
            interactions=self.interactions,
            security_issues=self.security_issues,
            interaction_graph=graph,
            cross_binary_taints=taints)

    def get_analysis_summary(self) -> Dict[str, Any]:
        # Return aggregated analysis metrics and findings.
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
