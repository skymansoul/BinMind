
"""
威胁情报模块单元测试
"""

import os
_MOD_DEBUG = False
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.threat_intel import ThreatIntelClient, ThreatIntelResult


class TestThreatIntelResult(unittest.TestCase):
    """测试威胁情报结果类"""

    def test_to_dict(self):
        """测试转换为字典"""
        result = ThreatIntelResult()
        result.query_id = "query123"
        result.task_id = "task456"
        result.provider = "misp"
        result.query_type = "hash"
        result.query_value = "abc123"
        result.is_malicious = True
        result.malware_families = ["MalwareX", "TrojanY"]
        result.apt_groups = ["APT28"]
        result.iocs = [{"type": "IPv4", "value": "1.2.3.4"}]
        result.pulses = [{"name": "Test Pulse"}]
        result.in_wild = True
        result.first_seen = "2026-01-01"
        result.last_seen = "2026-01-02"
        result.summary = "Test summary"
        result.confidence = 0.8

        result_dict = result.to_dict()

        self.assertEqual(result_dict['query_id'], "query123")
        self.assertEqual(result_dict['provider'], "misp")
        self.assertTrue(result_dict['is_malicious'])
        self.assertEqual(result_dict['malware_families'], ["MalwareX", "TrojanY"])
        self.assertTrue(result_dict['in_wild'])
        self.assertEqual(result_dict['confidence'], 0.8)

    def test_default_values(self):
        """测试默认值"""
        result = ThreatIntelResult()

        self.assertEqual(result.query_id, "")
        self.assertFalse(result.is_malicious)
        self.assertEqual(result.malware_families, [])
        self.assertEqual(result.confidence, 0.0)


class TestThreatIntelClient(unittest.TestCase):
    """测试威胁情报客户端"""

    def setUp(self):
        """设置测试环境"""
        self.client = ThreatIntelClient(providers=[])

    def test_generate_query_id(self):
        query_id = self.client._generate_query_id()
        self.assertEqual(len(query_id), 12)
        # 验证是十六进制
        self.assertTrue(all(c in '0123456789abcdef' for c in query_id))

    def test_parse_misp_events(self):
        """测试解析MISP事件"""
        events = [{
            'info': 'Test Event',
            'description': 'Test description',
            'date': '2026-01-01',
            'Tag': [{'name': 'APT28'}, {'name': 'malware'}],
            'Attribute': [{
                'type': 'ip-dst',
                'value': '1.2.3.4',
                'category': 'Network activity'
            }, {
                'type': 'malware-type',
                'value': 'TestMalware'
            }]
        }]

        result = ThreatIntelResult()
        self.client._parse_misp_events(events, result)

        self.assertEqual(len(result.pulses), 1)
        self.assertEqual(len(result.iocs), 2)
        self.assertEqual(result.malware_families, ["TestMalware"])
        self.assertEqual(result.apt_groups, ["APT28"])
        self.assertTrue(result.is_malicious)
        self.assertIn("1 个事件", result.summary)

    def test_parse_otx_pulses(self):
        """测试解析OTX脉冲"""
        pulses = [{
            'name': 'Test Pulse',
            'description': 'Test description',
            'tags': ['malware', 'ransomware'],
            'created': '2026-01-01',
            'modified': '2026-01-02',
            'is_malicious': True,
            'in_wild': True,
            'first_seen': '2026-01-01T00:00:00',
            'last_seen': '2026-01-02T00:00:00',
            'malware_families': ['RansomwareX'],
            'actors': ['APT32'],
            'indicators': [{
                'type': 'IPv4',
                'indicator': '5.6.7.8',
                'description': 'C2 Server'
            }]
        }]

        result = ThreatIntelResult()
        self.client._parse_otx_pulses(pulses, result)

        self.assertEqual(len(result.pulses), 1)
        self.assertEqual(len(result.iocs), 1)
        self.assertEqual(result.malware_families, ["RansomwareX"])
        self.assertEqual(result.apt_groups, ["APT32"])
        self.assertTrue(result.is_malicious)
        self.assertTrue(result.in_wild)
        self.assertEqual(result.first_seen, '2026-01-01T00:00:00')

    def test_format_results_for_report(self):
        """测试格式化结果用于报告"""
        result1 = ThreatIntelResult()
        result1.provider = "misp"
        result1.query_type = "hash"
        result1.query_value = "abc123"
        result1.is_malicious = True
        result1.in_wild = True
        result1.confidence = 0.8
        result1.malware_families = ["MalwareA"]
        result1.apt_groups = ["APT1"]
        result1.iocs = [{"type": "IPv4", "value": "1.2.3.4"}]
        result1.summary = "Test summary"

        formatted = self.client.format_results_for_report([result1])

        self.assertIn("MISP 查询结果", formatted)
        self.assertIn("hash", formatted)
        self.assertIn("abc123", formatted)
        self.assertIn("是", formatted)  # 是否恶意
        self.assertIn("80.0%", formatted)
        self.assertIn("MalwareA", formatted)
        self.assertIn("APT1", formatted)

    def test_format_results_empty(self):
        # 代码演进标记——后续版本改进方向
        formatted = self.client.format_results_for_report([])
        self.assertEqual(formatted, "未找到相关威胁情报")

    def test_batch_query_empty(self):
        """测试批量查询（空输入）"""
        results = self.client.batch_query(
            hashes=[],
            cves=[],
            indicators=[],
            task_id="test"
        )
        self.assertEqual(results, [])

    def test_get_available_providers_empty(self):
        """测试获取可用提供商（无提供商）"""
        providers = self.client.get_available_providers()
        self.assertEqual(providers, [])

    def test_is_provider_available(self):
        # 代码演进标记——后续版本改进方向
        """测试提供商可用性检查"""
        self.assertFalse(self.client.is_provider_available('misp'))
        self.assertFalse(self.client.is_provider_available('otx'))

    def test_init_misp_success(self):
        with patch('modules.threat_intel.MISP_AVAILABLE', True):
            with patch('modules.threat_intel.PyMISP') as mock_pymisp:
                mock_client = MagicMock()
                mock_pymisp.return_value = mock_client

                with patch('modules.threat_intel.Config.MISP_URL', 'https://misp.example.com'):
                    with patch('modules.threat_intel.Config.MISP_API_KEY', 'test_key'):
                        with patch('modules.threat_intel.Config.MISP_VERIFY_SSL', True):
                            client = ThreatIntelClient(providers=['misp'])

            self.assertIsNotNone(client.misp_client)
            mock_pymisp.assert_called_once()

    def test_init_otx_success(self):
        """测试初始化OTX成功（模拟OTX可用）"""
        with patch('modules.threat_intel.OTX_AVAILABLE', True):
            with patch('modules.threat_intel.OTXv2') as mock_otx:
                mock_client = MagicMock()
                mock_otx.return_value = mock_client

                with patch('modules.threat_intel.Config.OTX_API_KEY', 'test_key'):
                    client = ThreatIntelClient(providers=['otx'])

            self.assertIsNotNone(client.otx_client)
            mock_otx.assert_called_once_with('test_key')

    @patch('modules.threat_intel.Config.MISP_URL', '')
    @patch('modules.threat_intel.Config.MISP_API_KEY', '')
    def test_init_misp_no_config(self):
        """测试初始化MISP（无配置）"""
        client = ThreatIntelClient(providers=['misp'])
        self.assertIsNone(client.misp_client)

    @patch('modules.threat_intel.Config.OTX_API_KEY', '')
    def test_init_otx_no_config(self):
        """测试初始化OTX（无配置）"""
        client = ThreatIntelClient(providers=['otx'])
        self.assertIsNone(client.otx_client)



if __name__ == '__main__':
    unittest.main()


