import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入模块，避免触发 __init__.py 的导入
import importlib.util
spec = importlib.util.spec_from_file_location("ipc_analyzer", 
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'ipc_analyzer.py'))
ipc_analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ipc_analyzer)

IPCSecurityAnalyzer = ipc_analyzer.IPCSecurityAnalyzer
IPCAnalysisResult = ipc_analyzer.IPCAnalysisResult
IPCEndpoint = ipc_analyzer.IPCEndpoint
IPCInteraction = ipc_analyzer.IPCInteraction
IPCType = ipc_analyzer.IPCType
IPCSecurityIssue = ipc_analyzer.IPCSecurityIssue


class TestIPCAnalyzer(unittest.TestCase):

    def test_init_with_paths(self):
        analyzer = IPCSecurityAnalyzer(binary_paths=['test1.exe', 'test2.exe'])
        self.assertIsNotNone(analyzer)
        self.assertEqual(len(analyzer.binary_paths), 2)

    def test_init_empty(self):
        analyzer = IPCSecurityAnalyzer()
        self.assertIsNotNone(analyzer)
        self.assertEqual(len(analyzer.binary_paths), 0)

    def test_detect_ipc_patterns_pipe(self):
        data = b'CreateNamedPipe'
        analyzer = IPCSecurityAnalyzer()
        analyzer.binary_data['test.exe'] = data
        patterns = analyzer._detect_ipc_patterns(data, 'test.exe')
        self.assertTrue(len(patterns) > 0)
        self.assertTrue(any(p[0] == IPCType.PIPE for p in patterns))

    def test_detect_ipc_patterns_shared_memory(self):
        data = b'CreateFileMapping'
        analyzer = IPCSecurityAnalyzer()
        analyzer.binary_data['test.exe'] = data
        patterns = analyzer._detect_ipc_patterns(data, 'test.exe')
        self.assertTrue(len(patterns) > 0)
        self.assertTrue(any(p[0] == IPCType.SHARED_MEMORY for p in patterns))

    def test_detect_ipc_patterns_socket(self):
        data = b'socket(AF_INET'
        analyzer = IPCSecurityAnalyzer()
        analyzer.binary_data['test.exe'] = data
        patterns = analyzer._detect_ipc_patterns(data, 'test.exe')
        self.assertTrue(len(patterns) > 0)
        self.assertTrue(any(p[0] == IPCType.SOCKET for p in patterns))

    def test_extract_endpoint_names_pipe(self):
        data = b'\\\\.\\pipe\\test_pipe\x00'
        analyzer = IPCSecurityAnalyzer()
        names = analyzer._extract_endpoint_names(data)
        self.assertTrue(len(names) > 0)

    def test_analyze_no_binaries(self):
        analyzer = IPCSecurityAnalyzer()
        result = analyzer.analyze()
        self.assertEqual(len(result.binaries), 0)
        self.assertEqual(len(result.endpoints), 0)

    def test_analyze_single_binary(self):
        data = b'CreateNamedPipe'
        analyzer = IPCSecurityAnalyzer()
        analyzer.binary_data['test.exe'] = data
        endpoints = analyzer._analyze_single_binary('test.exe', data)
        self.assertTrue(len(endpoints) > 0)

    def test_identify_cross_binary_interactions(self):
        analyzer = IPCSecurityAnalyzer()
        analyzer.binary_data['server.exe'] = b'CreateNamedPipe Server'
        analyzer.binary_data['client.exe'] = b'ConnectNamedPipe Client'
        
        server_endpoint = IPCEndpoint(
            name='test_pipe',
            ipc_type=IPCType.PIPE,
            location='test_pipe',
            binary_path='server.exe',
            binary_name='server.exe',
            is_server=True
        )
        client_endpoint = IPCEndpoint(
            name='test_pipe',
            ipc_type=IPCType.PIPE,
            location='test_pipe',
            binary_path='client.exe',
            binary_name='client.exe',
            is_client=True
        )
        analyzer.endpoints = [server_endpoint, client_endpoint]
        
        interactions = analyzer._identify_cross_binary_interactions()
        self.assertTrue(len(interactions) > 0)

    def test_generate_interaction_graph(self):
        analyzer = IPCSecurityAnalyzer()
        interaction = IPCInteraction(
            source_binary='client.exe',
            destination_binary='server.exe',
            ipc_type=IPCType.PIPE,
            endpoint_name='test_pipe',
            data_flow_risk=0.5
        )
        analyzer.interactions = [interaction]
        graph = analyzer._generate_interaction_graph()
        self.assertIn('digraph', graph)
        self.assertIn('client.exe', graph)
        self.assertIn('server.exe', graph)

    def test_calculate_data_flow_risk(self):
        analyzer = IPCSecurityAnalyzer()
        analyzer.binary_data['client.exe'] = b'strcpy'
        analyzer.binary_data['server.exe'] = b'system('
        
        client = IPCEndpoint(
            name='test',
            ipc_type=IPCType.PIPE,
            location='test',
            binary_path='client.exe',
            binary_name='client.exe'
        )
        server = IPCEndpoint(
            name='test',
            ipc_type=IPCType.PIPE,
            location='test',
            binary_path='server.exe',
            binary_name='server.exe'
        )
        
        risk = analyzer._calculate_data_flow_risk(client, server)
        self.assertGreater(risk, 0)

    def test_get_analysis_summary(self):
        analyzer = IPCSecurityAnalyzer()
        summary = analyzer.get_analysis_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('num_binaries', summary)
        self.assertIn('num_endpoints', summary)
        self.assertIn('num_interactions', summary)

    def test_ipc_type_enum(self):
        self.assertEqual(IPCType.PIPE.value, 'pipe')
        self.assertEqual(IPCType.SHARED_MEMORY.value, 'shared_memory')
        self.assertEqual(IPCType.SOCKET.value, 'socket')
        self.assertEqual(IPCType.DBUS.value, 'dbus')
        self.assertEqual(IPCType.COM.value, 'com')

    def test_ipc_security_issue_enum(self):
        self.assertEqual(IPCSecurityIssue.NO_AUTHENTICATION.value, 'no_authentication')
        self.assertEqual(IPCSecurityIssue.INSUFFICIENT_VALIDATION.value, 'insufficient_validation')
        self.assertEqual(IPCSecurityIssue.INJECTION_VULNERABILITY.value, 'injection_vulnerability')

    def test_ipc_endpoint_dataclass(self):
        endpoint = IPCEndpoint(
            name='test',
            ipc_type=IPCType.PIPE,
            location='test_loc',
            binary_path='test.exe',
            binary_name='test.exe',
            read_access=True,
            write_access=False,
            is_server=True,
            is_client=False
        )
        self.assertEqual(endpoint.name, 'test')
        self.assertTrue(endpoint.is_server)
        self.assertFalse(endpoint.is_client)

    def test_ipc_interaction_dataclass(self):
        interaction = IPCInteraction(
            source_binary='client',
            destination_binary='server',
            ipc_type=IPCType.PIPE,
            endpoint_name='test',
            data_flow_risk=0.8,
            security_issues=[IPCSecurityIssue.NO_AUTHENTICATION]
        )
        self.assertEqual(interaction.source_binary, 'client')
        self.assertEqual(interaction.data_flow_risk, 0.8)


class TestIPCAnalysisResult(unittest.TestCase):

    def test_result_dataclass(self):
        result = IPCAnalysisResult(
            binaries=['test1.exe', 'test2.exe'],
            endpoints=[],
            interactions=[],
            security_issues=[],
            interaction_graph='',
            cross_binary_taints=[]
        )
        self.assertIsInstance(result.binaries, list)
        self.assertEqual(len(result.binaries), 2)


if __name__ == '__main__':
    unittest.main()