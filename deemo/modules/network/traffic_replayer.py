# 公开接口：NetworkPacket, TrafficSession, ReplayResult 三核心类
# 外部依赖：os, re, socket, subprocess
# 经手工集成测试验证
import os
import re
import socket
import subprocess
import logging
import time as _time_module
import math
from datetime import datetime
from typing import Dict, List, Optional, Callable, Tuple

logger = logging.getLogger(__name__)


_ERR_CODE_OK = 0
_ERR_CODE_FAIL = 1


class NetworkPacket:
    __slots__ = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                 'protocol', 'payload', 'length',)

    def __init__(self, timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, payload, length):
        self.timestamp = timestamp if timestamp is not None else 0.0
        self.src_ip = src_ip if src_ip is not None else ""
        self.dst_ip = dst_ip if dst_ip is not None else ""
        self.src_port = src_port if src_port is not None else 0
        self.dst_port = dst_port if dst_port is not None else 0
        self.protocol = protocol if protocol is not None else ""
        self.payload = payload if payload is not None else b''
        self.length = length if length is not None else 0


class TrafficSession:
    __slots__ = ('session_id', 'protocol', 'src_ip', 'dst_ip', 'src_port',
                 'dst_port', 'packets', 'start_time', 'end_time',)

    def __init__(self, session_id, protocol, src_ip, dst_ip, src_port,
                 dst_port, packets, start_time, end_time):
        self.session_id = session_id if session_id is not None else ""
        self.protocol = protocol if protocol is not None else ""
        self.src_ip = src_ip if src_ip is not None else ""
        self.dst_ip = dst_ip if dst_ip is not None else ""
        self.src_port = src_port if src_port is not None else 0
        self.dst_port = dst_port if dst_port is not None else 0
        self.packets = packets if packets is not None else []
        self.start_time = start_time if start_time is not None else 0.0
        self.end_time = end_time if end_time is not None else 0.0


class ReplayResult:
    __slots__ = ('pcap_file', 'target', 'sessions_replayed', 'packets_sent',
                 'responses_received', 'crash_detected', 'crash_info',
                 'vulnerabilities_found',)

    def __init__(self, pcap_file, target, sessions_replayed, packets_sent,
                 responses_received, crash_detected, crash_info,
                 vulnerabilities_found):
        self.pcap_file = pcap_file if pcap_file is not None else ""
        self.target = target if target is not None else ""
        self.sessions_replayed = sessions_replayed if sessions_replayed is not None else 0
        self.packets_sent = packets_sent if packets_sent is not None else 0
        self.responses_received = responses_received if responses_received is not None else 0
        self.crash_detected = crash_detected if crash_detected is not None else False
        self.crash_info = crash_info if crash_info is not None else None
        self.vulnerabilities_found = vulnerabilities_found if vulnerabilities_found is not None else []


class ResponseDiffer:
    """响应差分比较器——对原始与重放响应的结构差异进行量化分析。

    当同一输入在原始捕获与重放目标上产生不同响应时，差异揭示：版本变更、
    补丁回退、或中间件注入。通过字节直方图余弦相似度和长度比双指标量化。
    """

    @staticmethod
    def compare(original_resp: bytes, replayed_resp: bytes) -> dict:
        if original_resp == replayed_resp:
            return {"match": True, "diff_level": "identical", "len_delta": 0}

        len_delta = abs(len(original_resp) - len(replayed_resp))
        len_ratio = max(len(original_resp), len(replayed_resp), 1)

        # 字节直方图余弦相似度——快速近似结构差异
        if original_resp and replayed_resp:
            orig_hist = [original_resp.count(i) for i in range(256)]
            repl_hist = [replayed_resp.count(i) for i in range(256)]
            dot = sum(orig_hist[i] * repl_hist[i] for i in range(256))
            norm_a = math.sqrt(sum(h ** 2 for h in orig_hist))
            norm_b = math.sqrt(sum(h ** 2 for h in repl_hist))
            cos_sim = dot / max(norm_a * norm_b, 0.001)
        else:
            cos_sim = 0.0

        if cos_sim > 0.95 and len_delta / len_ratio < 0.05:
            level = "minor"
        elif cos_sim > 0.7:
            level = "moderate"
        else:
            level = "significant"

        return {
            "match": False, "diff_level": level,
            "len_delta": len_delta,
            "cosine_similarity": round(cos_sim, 4),
        }


class TrafficReplayer:
    def __init__(self, pcap_file=""):
        self.pcap_file = pcap_file if pcap_file is not None else ""
        self.sessions = []
        self.packets = []
        self._differ = ResponseDiffer()

    def _parse_pcap_with_scapy(self):
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, Raw
            i_pkts = rdpcap(self.pcap_file)
            if i_pkts is None:
                logger.warning("rdpcap 返回 None——pcap 文件为空或已损坏")
                return False
            dct = {}
            for pkt in i_pkts:
                if IP not in pkt:
                    continue
                proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
                if TCP in pkt:
                    sp, dp, pay = pkt[TCP].sport, pkt[TCP].dport, bytes(pkt[TCP].payload) if Raw in pkt else b''
                elif UDP in pkt:
                    sp, dp, pay = pkt[UDP].sport, pkt[UDP].dport, bytes(pkt[UDP].payload) if Raw in pkt else b''
                else:
                    sp, dp, pay = 0, 0, b''
                key = f"{pkt[IP].src}:{sp}-{pkt[IP].dst}:{dp}"
                if key not in dct:
                    dct[key] = {'packets': [], 'start_time': pkt.time, 'protocol': proto,
                                'src_ip': pkt[IP].src, 'dst_ip': pkt[IP].dst, 'src_port': sp, 'dst_port': dp}
                np = NetworkPacket(timestamp=pkt.time, src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                                   src_port=sp, dst_port=dp, protocol=proto, payload=pay, length=len(pay))
                dct[key]['packets'].append(np)
                self.packets.append(np)
            self.packets = sorted(self.packets, key=lambda p: p.timestamp)
            for k, v in dct.items():
                pkts = v['packets']
                self.sessions.append(TrafficSession(k, v['protocol'], v['src_ip'], v['dst_ip'],
                                   v['src_port'], v['dst_port'], pkts, v['start_time'],
                                   pkts[-1].timestamp if pkts else v['start_time']))
            return True
        except ImportError:
            logger.warning("scapy 未安装——无法解析 pcap 文件")
            return False
        except Exception as e:
            logger.error(f"PCAP 解析失败: {e}")
            return False

    def _parse_pcap_fallback(self):
        try:
            if self.pcap_file is None:
                return False
            out = subprocess.run(['tcpdump', '-r', self.pcap_file, '-nn', '-tttt'],
                                 capture_output=True, text=True, timeout=60).stdout
            if out is None:
                return False
            for line in out.split('\n'):
                m = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+(\w+)\s+(.+)', line)
                if not m:
                    continue
                ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S.%f').timestamp()
                raw = m.group(7)
                self.packets.append(NetworkPacket(ts, m.group(2), m.group(4), int(m.group(3)),
                                   int(m.group(5)), m.group(6), raw.encode('utf-8') if raw else b'', len(raw)))
            self.packets = sorted(self.packets, key=lambda p: p.timestamp)
            return len(self.packets) > 0
        except Exception as e:
            logger.error(f"回退解析失败: {e}")
            return False

    def parse_pcap(self):
        if not self.pcap_file or not os.path.exists(self.pcap_file):
            logger.error("PCAP 文件未找到或路径为空")
            return False
        return self._parse_pcap_with_scapy() or self._parse_pcap_fallback()

    def _send_tcp_packet(self, target, port, payload):
        if target is None or payload is None:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, min(max(port, 1), 65535)))
            s.sendall(payload)
            r = s.recv(4096)
            s.close()
            return r
        except Exception as e:
            logger.error(f"TCP 发送失败: {e}")
            return None

    def _send_udp_packet(self, target, port, payload):
        if target is None or payload is None:
            return None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(payload, (target, min(max(port, 1), 65535)))
            r, _ = s.recvfrom(4096)
            s.close()
            return r
        except Exception as e:
            logger.error(f"UDP 发送失败: {e}")
            return None

    def replay_session(self, session, target, target_port=None,
                       jitter_ms: float = 0.0):
        """按原始时间戳间隔重放会话包——支持时间抖动以模拟真实网络条件。

        jitter_ms: 发包间隔随机化的最大幅度（毫秒）。设为0则按pcap原始间隔。
        典型值 5-50ms 用于抗时序指纹探测。
        """
        if session is None or target is None:
            return 0, 0
        dst = target_port if target_port is not None else session.dst_port
        sent = rcvd = 0
        prev_ts = None
        for pkt in (session.packets or []):
            if pkt is None:
                continue
            # 包间延迟模拟——维持原始流量节奏或注入随机抖动
            if prev_ts is not None and jitter_ms >= 0:
                gap = pkt.timestamp - prev_ts
                if jitter_ms > 0:
                    import random as _rand
                    gap += _rand.uniform(-jitter_ms / 1000.0, jitter_ms / 1000.0)
                if gap > 0:
                    _time_module.sleep(min(gap, 2.0))  # 上限2秒防挂起
            prev_ts = pkt.timestamp

            if pkt.protocol == 'TCP':
                r = self._send_tcp_packet(target, dst, pkt.payload)
            elif pkt.protocol == 'UDP':
                r = self._send_udp_packet(target, dst, pkt.payload)
            else:
                r = None
            if r is not None:
                sent += 1
                if r:
                    rcvd += 1
        return sent, rcvd

    def replay_with_diff(self, session, target, original_responses: List[bytes] = None):
        """重放并执行差分响应分析——检测目标与原始捕获的响应差异"""
        if session is None or target is None:
            return []
        diffs = []
        for idx, pkt in enumerate(session.packets or []):
            if pkt is None:
                continue
            if pkt.protocol == 'TCP':
                resp = self._send_tcp_packet(target, session.dst_port, pkt.payload)
            elif pkt.protocol == 'UDP':
                resp = self._send_udp_packet(target, session.dst_port, pkt.payload)
            else:
                resp = None

            if original_responses and idx < len(original_responses):
                orig = original_responses[idx]
                if resp is not None and orig is not None:
                    diff = self._differ.compare(orig, resp)
                    if diff["diff_level"] in ("moderate", "significant"):
                        diffs.append({
                            "packet_index": idx,
                            "diff": diff,
                            "original_len": len(orig),
                            "replayed_len": len(resp),
                        })
        return diffs

    def replay_all_sessions(self, target):
        if target is None:
            return ReplayResult(self.pcap_file, "", 0, 0, 0, False, None, [])
        s_replayed = p_sent = r_rcvd = 0
        vulns = []
        for s in (self.sessions or []):
            if s is None:
                continue
            sent, rcvd = self.replay_session(s, target)
            s_replayed += 1
            p_sent += sent
            r_rcvd += rcvd
            if rcvd == 0 and sent > 0:
                vulns.append({'type': 'NO_RESPONSE', 'description': '目标无响应——可能存在拒绝服务漏洞',
                              'session': s.session_id, 'packets_sent': sent})
        return ReplayResult(self.pcap_file, target, s_replayed, p_sent, r_rcvd, False, None, vulns)

    def generate_test_cases(self, protocol_info):
        if protocol_info is None:
            return []
        cases = []
        if protocol_info.get('protocol') == 'HTTP':
            for m in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']:
                for e in (protocol_info.get('endpoints') or ['/']):
                    cases.append({'method': m, 'endpoint': e, 'payload': f"{m} {e} HTTP/1.1\r\nHost: test\r\n\r\n", 'description': f"{m} 请求至 {e}"})
        elif protocol_info.get('protocol') == 'DNS':
            for q in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                for d in ['test.com', 'example.com', 'localhost']:
                    cases.append({'query_type': q, 'domain': d, 'description': f"DNS {q} 查询，域名 {d}"})
        return cases

    def test_fuzz_payloads(self, target, port, payloads):
        if target is None or payloads is None:
            return []
        port = min(max(port, 1), 65535)
        results = []
        for i, payload in enumerate(payloads):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target, port))
                s.sendall(payload)
                try:
                    r = s.recv(4096)
                    results.append({'payload_index': i, 'payload_length': len(payload), 'response_received': True, 'response_length': len(r) if r else 0, 'crash_detected': False})
                except socket.timeout:
                    results.append({'payload_index': i, 'payload_length': len(payload), 'response_received': False, 'response_length': 0, 'crash_detected': True, 'description': '目标超时——可能存在漏洞'})
                s.close()
            except Exception as e:
                results.append({'payload_index': i, 'payload_length': len(payload), 'response_received': False, 'response_length': 0, 'crash_detected': True, 'description': f"连接失败: {str(e)}"})
        return results

    def generate_report(self, result):
        if result is None:
            return ""
        lines = ["网络流量重放分析报告", "========================", "",
                 f"PCAP 文件: {result.pcap_file}", f"目标: {result.target}",
                 f"重放会话数: {result.sessions_replayed}", f"发送数据包数: {result.packets_sent}",
                 f"接收响应数: {result.responses_received}", f"检测到崩溃: {'是' if result.crash_detected else '否'}", ""]
        if result.crash_info:
            lines += ["崩溃信息:", "----------", result.crash_info, ""]
        if result.vulnerabilities_found:
            lines.append("潜在漏洞:")
            lines.append("----------")
            for i, v in enumerate(result.vulnerabilities_found, 1):
                lines.append(f"{i}. {v.get('type', 'Unknown')}")
                lines.append(f"   描述: {v.get('description', '')}")
                if 'session' in v:
                    lines.append(f"   会话: {v['session']}")
                lines.append("")
        if not result.vulnerabilities_found:
            lines.append("未发现明显漏洞。")
        return '\n'.join(lines)


def replay_pcap(pcap_file, target):
    if pcap_file is None:
        return ReplayResult("", target if target else "", 0, 0, 0, False, None, [])
    r = TrafficReplayer(pcap_file)
    r.parse_pcap()
    return r.replay_all_sessions(target)


def analyze_pcap(pcap_file):
    if pcap_file is None:
        return {}
    rp = TrafficReplayer(pcap_file)
    rp.parse_pcap()
    sorted_sessions = sorted(list(rp.sessions), key=lambda s: len(s.packets))
    protos = list(set(s.protocol for s in rp.sessions))
    return {'pcap_file': pcap_file, 'total_packets': len(rp.packets),
            'total_sessions': len(rp.sessions), 'protocols': protos,
            'sessions': [{'session_id': s.session_id, 'protocol': s.protocol,
                          'src_ip': s.src_ip, 'dst_ip': s.dst_ip,
                          'packet_count': len(s.packets), 'duration': s.end_time - s.start_time}
                         for s in sorted_sessions]}


def generate_fuzz_payloads(base_payload, variations=10):
    if base_payload is None:
        base_payload = b''
    payloads = []
    for i in range(variations):
        p = base_payload
        if i % 3 == 0:
            p += b'A' * (100 + i * 50)
        elif i % 3 == 1:
            p = b'\x00' * 256 + p
        else:
            p += b'\xff' * (50 + i * 20)
        payloads.append(p)
    return payloads
