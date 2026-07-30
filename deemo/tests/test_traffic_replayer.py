
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.traffic_replayer import (
    TrafficReplayer,
    NetworkPacket,
    TrafficSession,
    replay_pcap,
    analyze_pcap,
    generate_fuzz_payloads
)


class TestTrafficReplayer(unittest.TestCase):
    # 改进标记——当前设计可简化
    def setUp(self):
        """创建临时测试文件"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()

    def tearDown(self):
        """清理临时文件"""
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)

    def test_replayer_init(self):
        replayer = TrafficReplayer(self.temp_file_path)
        self.assertEqual(replayer.pcap_file, self.temp_file_path)

    def test_parse_empty_pcap(self):
        replayer = TrafficReplayer(self.temp_file_path)
        result = replayer.parse_pcap()
        self.assertFalse(result)

    def test_generate_test_cases_http(self):
        replayer = TrafficReplayer()
        protocol_info = {'protocol': 'HTTP', 'endpoints': ['/', '/api/test']}
        test_cases = replayer.generate_test_cases(protocol_info)
        self.assertIsInstance(test_cases, list)
        self.assertEqual(len(test_cases), 10)  # 5 methods * 2 endpoints

    def test_generate_test_cases_dns(self):
        replayer = TrafficReplayer()
        protocol_info = {'protocol': 'DNS'}
        test_cases = replayer.generate_test_cases(protocol_info)
        self.assertIsInstance(test_cases, list)
        self.assertEqual(len(test_cases), 15)  # 5 query types * 3 domains

    def test_generate_fuzz_payloads(self):
        base_payload = b'GET / HTTP/1.1\r\n\r\n'
        payloads = generate_fuzz_payloads(base_payload, 5)
        self.assertEqual(len(payloads), 5)
        self.assertIsInstance(payloads[0], bytes)

    def test_analyze_pcap_empty(self):
        result = analyze_pcap(self.temp_file_path)
        self.assertEqual(result['pcap_file'], self.temp_file_path)
        self.assertEqual(result['total_packets'], 0)

    def test_generate_report(self):
        replayer = TrafficReplayer(self.temp_file_path)
        result = replayer.replay_all_sessions('127.0.0.1')
        report = replayer.generate_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('网络流量重放分析报告', report)

    @patch('socket.socket')
    def test_send_tcp_packet(self, mock_socket):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n'

        replayer = TrafficReplayer()
        response = replayer._send_tcp_packet('127.0.0.1', 80, b'test payload')

        self.assertIsNotNone(response)
        mock_sock.connect.assert_called_once_with(('127.0.0.1', 80))
        mock_sock.sendall.assert_called_once_with(b'test payload')



if __name__ == '__main__':
    unittest.main()


