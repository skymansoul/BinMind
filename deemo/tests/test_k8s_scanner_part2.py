

class TestContainerInfo(unittest.TestCase):
    """ContainerInfo 数据类测试"""

    def test_ports_list(self):
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
            cve_id='CVE-2026-12345',
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


