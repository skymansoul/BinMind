"""
Traffic replayer tests -- enriched with ResponseDiffer, dataclass edge cases.
"""
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
    ReplayResult,
    ResponseDiffer,
    replay_pcap,
    analyze_pcap,
    generate_fuzz_payloads
)


class TestNetworkPacket(unittest.TestCase):
    def test_minimal_packet(self):
        pkt = NetworkPacket(
            timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1234, dst_port=80, protocol="TCP",
            payload=b"GET /", length=5,
        )
        self.assertEqual(pkt.src_ip, "10.0.0.1")
        self.assertEqual(pkt.dst_port, 80)

    def test_empty_payload(self):
        pkt = NetworkPacket(200.0, "a", "b", 1, 2, "TCP", b"", 0)
        self.assertEqual(len(pkt.payload), 0)


class TestTrafficSession(unittest.TestCase):
    def test_empty_session(self):
        s = TrafficSession("s1", "TCP", "a", "b", 1, 2, [], 0.0, 0.0)
        self.assertEqual(len(s.packets), 0)

    def test_session_with_packets(self):
        p1 = NetworkPacket(1.0, "a", "b", 1, 2, "TCP", b"hi", 2)
        s = TrafficSession("s1", "TCP", "a", "b", 1, 2, [p1], 1.0, 2.0)
        self.assertEqual(len(s.packets), 1)


class TestReplayResult(unittest.TestCase):
    def test_no_crash(self):
        r = ReplayResult("t.pcap", "127.0.0.1", 3, 30, 30, False)
        self.assertFalse(r.crash_detected)

    def test_with_crash(self):
        r = ReplayResult("f.pcap", "1.1.1.1", 1, 10, 0, True, "SEGV")
        self.assertTrue(r.crash_detected)


class TestResponseDiffer(unittest.TestCase):
    def test_identical(self):
        result = ResponseDiffer.compare(b"abc", b"abc")
        self.assertEqual(result["classification"], "identical")

    def test_different(self):
        result = ResponseDiffer.compare(bytes(range(256)), bytes(range(255,-1,-1)))
        self.assertIn(result["classification"], ["significant","moderate","minor"])

    def test_length_ratio(self):
        result = ResponseDiffer.compare(b"a", b"abcdef")
        self.assertIn("length_ratio", result)

    def test_empty_both(self):
        result = ResponseDiffer.compare(b"", b"")
        self.assertEqual(result["classification"], "identical")


class TestTrafficReplayer(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()

    def tearDown(self):
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
        cases = replayer.generate_test_cases({'protocol': 'HTTP', 'endpoints': ['/']})
        self.assertIsInstance(cases, list)
        self.assertEqual(len(cases), 5)

    def test_generate_test_cases_dns(self):
        replayer = TrafficReplayer()
        cases = replayer.generate_test_cases({'protocol': 'DNS'})
        self.assertIsInstance(cases, list)
        self.assertEqual(len(cases), 15)

    def test_generate_fuzz_payloads(self):
        payloads = generate_fuzz_payloads(b'GET /', 5)
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
        response = replayer._send_tcp_packet('127.0.0.1', 80, b'test')
        self.assertIsNotNone(response)
        mock_sock.connect.assert_called_once_with(('127.0.0.1', 80))

    def test_test_fuzz_payloads(self):
        replayer = TrafficReplayer()
        results = replayer.test_fuzz_payloads("127.0.0.1", 9999, [b"\x00", b"A"*100])
        self.assertEqual(len(results), 2)


if __name__ == '__main__':
    unittest.main()
