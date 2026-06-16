#!/usr/bin/env python3
"""
Kubernetes集群扫描模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.k8s_scanner import (
    K8sClusterScanner, ContainerInfo, BinaryRisk, ClusterScanResult,
    ScanScope
)


class TestK8sClusterScanner(unittest.TestCase):
    """Kubernetes集群扫描器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        # 不连接真实集群，仅测试数据结构和逻辑
        self.scanner = K8sClusterScanner(output_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_scan_scope_enum(self):
        """测试扫描范围枚举"""
        self.assertEqual(ScanScope.ALL.value, 'all')
        self.assertEqual(ScanScope.SPECIFIC.value, 'specific')
        self.assertEqual(ScanScope.LABEL.value, 'label')
        self.assertEqual(ScanScope.IMAGE.value, 'image')

    def test_risk_level_enum(self):
        """测试风险等级枚举"""
        self.assertEqual(RiskLevel.LOW.value, 'low')
        self.assertEqual(RiskLevel.MEDIUM.value, 'medium')
        self.assertEqual(RiskLevel.HIGH.value, 'high')
        self.assertEqual(RiskLevel.CRITICAL.value, 'critical')

    def test_container_info_dataclass(self):
        """测试 ContainerInfo 数据类"""
        container = ContainerInfo(
            name='test-container',
            image='nginx:latest',
            namespace='default',
            pod_name='test-pod',
            container_id='container123',
            status='running',
            ports=[80, 443],
            env_vars={'ENV': 'test'}
        )
        
        self.assertEqual(container.name, 'test-container')
        self.assertEqual(container.image, 'nginx:latest')
        self.assertEqual(container.namespace, 'default')
        self.assertEqual(len(container.ports), 2)

    def test_container_info_to_dict(self):
        """测试 ContainerInfo 转换为字典"""
        container = ContainerInfo(
            name='web',
            image='web:v1',
            namespace='production',
            pod_name='web-pod',
            container_id='abc123',
            status='running',
            ports=[8080],
            env_vars={'DEBUG': 'false'}
        )
        
        result = container.to_dict()
        
        self.assertIn('name', result)
        self.assertIn('image', result)
        self.assertIn('namespace', result)
        self.assertEqual(result['name'], 'web')

    def test_binary_risk_dataclass(self):
        """测试 BinaryRisk 数据类"""
        risk = BinaryRisk(
            binary_name='vulnerable-binary',
            binary_path='/usr/bin/vulnerable',
            risk_level=RiskLevel.HIGH,
            vulnerability_type='buffer_overflow',
            description='存在缓冲区溢出漏洞',
            cve_id='CVE-2024-12345',
            remediation='升级到新版本',
            container_name='app-container',
            pod_name='app-pod',
            namespace='default'
        )
        
        self.assertEqual(risk.binary_name, 'vulnerable-binary')
        self.assertEqual(risk.risk_level, RiskLevel.HIGH)
        self.assertEqual(risk.cve_id, 'CVE-2024-12345')

    def test_binary_risk_to_dict(self):
        """测试 BinaryRisk 转换为字典"""
        risk = BinaryRisk(
            binary_name='test-bin',
            binary_path='/bin/test',
            risk_level=RiskLevel.MEDIUM,
            vulnerability_type='info_disclosure',
            description='信息泄露',
            cve_id=None,
            remediation='修复配置',
            container_name='test',
            pod_name='test-pod',
            namespace='test-ns'
        )
        
        result = risk.to_dict()
        
        self.assertIn('binary_name', result)
        self.assertIn('risk_level', result)
        self.assertEqual(result['risk_level'], 'medium')

    def test_cluster_scan_result_dataclass(self):
        """测试 ClusterScanResult 数据类"""
        result = ClusterScanResult(
            cluster_name='test-cluster',
            scan_scope=ScanScope.ALL,
            namespaces=['default', 'production'],
            containers=[],
            binary_risks=[],
            risk_summary={'high': 0, 'medium': 0, 'low': 0},
            scan_duration=10.5,
            errors=[]
        )
        
        self.assertEqual(result.cluster_name, 'test-cluster')
        self.assertEqual(result.scan_scope, ScanScope.ALL)
        self.assertEqual(len(result.namespaces), 2)

    def test_cluster_scan_result_to_dict(self):
        """测试 ClusterScanResult 转换为字典"""
        container = ContainerInfo(
            name='test',
            image='test:v1',
            namespace='default',
            pod_name='test-pod',
            container_id='123',
            status='running',
            ports=[],
            env_vars={}
        )
        
        result = ClusterScanResult(
            cluster_name='prod-cluster',
            scan_scope=ScanScope.SPECIFIC,
            namespaces=['production'],
            containers=[container],
            binary_risks=[],
            risk_summary={'high': 1, 'medium': 2, 'low': 3},
            scan_duration=15.0,
            errors=[]
        )
        
        data = result.to_dict()
        
        self.assertIn('cluster_name', data)
        self.assertIn('containers', data)
        self.assertEqual(data['scan_duration'], 15.0)

    def test_generate_report(self):
        """测试生成报告"""
        risk = BinaryRisk(
            binary_name='vuln-bin',
            binary_path='/bin/vuln',
            risk_level=RiskLevel.HIGH,
            vulnerability_type='rce',
            description='远程代码执行',
            cve_id='CVE-2024-11111',
            remediation='升级',
            container_name='app',
            pod_name='app-pod',
            namespace='default'
        )
        
        result = ClusterScanResult(
            cluster_name='test-cluster',
            scan_scope=ScanScope.ALL,
            namespaces=['default'],
            containers=[],
            binary_risks=[risk],
            risk_summary={'high': 1, 'medium': 0, 'low': 0},
            scan_duration=5.0,
            errors=[]
        )
        
        report = self.scanner.generate_report(result)
        
        self.assertIn('test-cluster', report)
        self.assertIn('CVE-2024-11111', report)

    def test_save_result(self):
        """测试保存结果"""
        result = ClusterScanResult(
            cluster_name='test-cluster',
            scan_scope=ScanScope.ALL,
            namespaces=['default'],
            containers=[],
            binary_risks=[],
            risk_summary={'high': 0, 'medium': 0, 'low': 0},
            scan_duration=5.0,
            errors=[]
        )
        
        saved_path = self.scanner.save_result(result, 'test_scan')
        
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))

    def test_risk_summary_calculation(self):
        """测试风险摘要计算"""
        risks = [
            BinaryRisk(
                binary_name='bin1',
                binary_path='/bin1',
                risk_level=RiskLevel.HIGH,
                vulnerability_type='vuln1',
                description='desc1',
                cve_id=None,
                remediation='fix1',
                container_name='c1',
                pod_name='p1',
                namespace='ns1'
            ),
            BinaryRisk(
                binary_name='bin2',
                binary_path='/bin2',
                risk_level=RiskLevel.MEDIUM,
                vulnerability_type='vuln2',
                description='desc2',
                cve_id=None,
                remediation='fix2',
                container_name='c2',
                pod_name='p2',
                namespace='ns2'
            ),
            BinaryRisk(
                binary_name='bin3',
                binary_path='/bin3',
                risk_level=RiskLevel.LOW,
                vulnerability_type='vuln3',
                description='desc3',
                cve_id=None,
                remediation='fix3',
                container_name='c3',
                pod_name='p3',
                namespace='ns3'
            )
        ]
        
        summary = self.scanner._calculate_risk_summary(risks)
        
        self.assertEqual(summary['high'], 1)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['low'], 1)


class TestContainerInfo(unittest.TestCase):
    """ContainerInfo 数据类测试"""

    def test_ports_list(self):
        """测试端口列表"""
        container = ContainerInfo(
            name='web',
            image='web:v1',
            namespace='default',
            pod_name='web-pod',
            container_id='123',
            status='running',
            ports=[80, 443, 8080],
            env_vars={}
        )
        
        self.assertEqual(len(container.ports), 3)
        self.assertIn(80, container.ports)

    def test_env_vars_dict(self):
        """测试环境变量字典"""
        container = ContainerInfo(
            name='app',
            image='app:v1',
            namespace='default',
            pod_name='app-pod',
            container_id='456',
            status='running',
            ports=[],
            env_vars={'API_KEY': 'secret', 'DEBUG': 'true'}
        )
        
        self.assertIn('API_KEY', container.env_vars)
        self.assertIn('DEBUG', container.env_vars)


class TestBinaryRisk(unittest.TestCase):
    """BinaryRisk 数据类测试"""

    def test_risk_level_order(self):
        """测试风险等级顺序"""
        self.assertEqual(RiskLevel.CRITICAL.value, 'critical')
        self.assertEqual(RiskLevel.HIGH.value, 'high')
        self.assertEqual(RiskLevel.MEDIUM.value, 'medium')
        self.assertEqual(RiskLevel.LOW.value, 'low')

    def test_cve_id_optional(self):
        """测试 CVE ID 可选"""
        risk_with_cve = BinaryRisk(
            binary_name='bin1',
            binary_path='/bin1',
            risk_level=RiskLevel.HIGH,
            vulnerability_type='vuln',
            description='desc',
            cve_id='CVE-2024-12345',
            remediation='fix',
            container_name='c',
            pod_name='p',
            namespace='ns'
        )
        
        risk_without_cve = BinaryRisk(
            binary_name='bin2',
            binary_path='/bin2',
            risk_level=RiskLevel.LOW,
            vulnerability_type='vuln',
            description='desc',
            cve_id=None,
            remediation='fix',
            container_name='c',
            pod_name='p',
            namespace='ns'
        )
        
        self.assertIsNotNone(risk_with_cve.cve_id)
        self.assertIsNone(risk_without_cve.cve_id)


if __name__ == '__main__':
    unittest.main()