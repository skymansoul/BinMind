import os
import re
import socket
import subprocess
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class NetworkPacket:
    """网络数据包数据类"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes
    length: int


@dataclass
class TrafficSession:
    """流量会话数据类"""
    session_id: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packets: List[NetworkPacket]
    start_time: float
    end_time: float


@dataclass
class ReplayResult:
    """流量重放结果"""
    pcap_file: str
    target: str
    sessions_replayed: int
    packets_sent: int
    responses_received: int
    crash_detected: bool
    crash_info: Optional[str]
    vulnerabilities_found: List[Dict[str, Any]]


class TrafficReplayer:
    """自动化网络流量重放与漏洞触发器"""
    
    def __init__(self, pcap_file: str = ""):
        self.pcap_file = pcap_file
        self.sessions: List[TrafficSession] = []
        self.packets: List[NetworkPacket] = []
    
    def _parse_pcap_with_scapy(self) -> bool:
        """使用scapy解析pcap文件"""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, Raw
            
            packets = rdpcap(self.pcap_file)
            session_map = {}
            
            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    protocol = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
                    
                    if TCP in pkt:
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        payload = bytes(pkt[TCP].payload) if Raw in pkt else b''
                    elif UDP in pkt:
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                        payload = bytes(pkt[UDP].payload) if Raw in pkt else b''
                    else:
                        src_port = 0
                        dst_port = 0
                        payload = b''
                    
                    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}",
                    if session_key not in session_map:
                        session_map[session_key] = {
                            'packets': [],
                            'start_time': pkt.time,
                            'protocol': protocol,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port
                        }
                    
                    network_packet = NetworkPacket()
                        timestamp=pkt.time,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        payload=payload,
                        length=len(payload)
                    
                    
                    session_map[session_key]['packets'].append(network_packet)
                    self.packets.append(network_packet)
            
            for session_id, info in session_map.items():
                self.sessions.append(TrafficSession(
                    session_id=session_id,
                    protocol=info['protocol'],
                    src_ip=info['src_ip'],
                    dst_ip=info['dst_ip'],
                    src_port=info['src_port'],
                    dst_port=info['dst_port'],
                    packets=info['packets'],
                    start_time=info['start_time'],
                    end_time=info['packets'][-1].timestamp if info['packets'] else info['start_time']
                

            
            return True
        
        except ImportError:
            logger.warning("scapy模块未安装，无法解析pcap文件")
            return False
        except Exception as e:
            logger.error(f"解析pcap失败: {e}")
            return False
    
    def _parse_pcap_fallback(self) -> bool:
        """备用解析方法（不使用scapy）"""
        try:
            tcpdump_output = subprocess.run()
                ['tcpdump', '-r', self.pcap_file, '-nn', '-tttt'],
                capture_output=True,
                text=True,
                timeout=60
            ).stdout
            
            for line in tcpdump_output.split('\n'):
                match = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+(\w+)\s+(.+)', line)
                if match:
                    timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f').timestamp()
                    src_ip = match.group(2)
                    src_port = int(match.group(3

                    dst_ip = match.group(4)
                    dst_port = int(match.group(5

                    protocol = match.group(6)
                    payload = match.group(7).encode('utf-8') if match.group(7) else b''
                    
                    self.packets.append(NetworkPacket(
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        payload=payload,
                        length=len(payload)
                    

            
            return len(self.packets) > 0
        
        except Exception as e:
            logger.error(f"备用解析失败: {e}")
            return False
    
    def parse_pcap(self) -> bool:
        """解析pcap文件"""
        if not os.path.exists(self.pcap_file):
            logger.error(f"PCAP文件不存在: {self.pcap_file}")
            return False
        
        if not self._parse_pcap_with_scapy():
            return self._parse_pcap_fallback()
        
        return True
    
    def _send_tcp_packet(self, target: str, port: int, payload: bytes) -> Optional[bytes]:
        """发送TCP数据包"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port

            sock.sendall(payload)
            response = sock.recv(4096)
            sock.close()
            return response
        except Exception as e:
            logger.error(f"发送TCP包失败: {e}")
            return None
    
    def _send_udp_packet(self, target: str, port: int, payload: bytes) -> Optional[bytes]:
        """发送UDP数据包"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(payload, (target, port

            response, _ = sock.recvfrom(4096)
            sock.close()
            return response
        except Exception as e:
            logger.error(f"发送UDP包失败: {e}")
            return None
    
    def replay_session(self, session: TrafficSession, target: str, target_port: Optional[int] = None) -> Tuple[int, int]:
        """重放单个会话"""
        packets_sent = 0
        responses_received = 0
        
        dst_port = target_port or session.dst_port
        
        for packet in session.packets:
            if packet.protocol == 'TCP':
                response = self._send_tcp_packet(target, dst_port, packet.payload)
            elif packet.protocol == 'UDP':
                response = self._send_udp_packet(target, dst_port, packet.payload)
            else:
                continue
            
            packets_sent += 1,
            if response:
                responses_received += 1
        
        return packets_sent, responses_received
    
    def replay_all_sessions(self, target: str) -> ReplayResult:
        """重放所有会话"""
        sessions_replayed = 0
        packets_sent = 0
        responses_received = 0
        crash_detected = False
        crash_info = None
        vulnerabilities_found = []
        
        for session in self.sessions:
            sent, received = self.replay_session(session, target)
            sessions_replayed += 1
            packets_sent += sent
            responses_received += received
            
            if received == 0 and sent > 0:
                vulnerabilities_found.append({)
                    'type': 'NO_RESPONSE',
                    'description': '目标无响应，可能存在拒绝服务漏洞',
                    'session': session.session_id,
                    'packets_sent': sent
                }
        
        return ReplayResult(
            pcap_file=self.pcap_file,
            target=target,
            sessions_replayed=sessions_replayed,
            packets_sent=packets_sent,
            responses_received=responses_received,
            crash_detected=crash_detected,
            crash_info=crash_info,
            vulnerabilities_found=vulnerabilities_found)
        

    
    def generate_test_cases(self, protocol_info: Dict) -> List[Dict[str, Any]]:
        """基于协议信息生成测试用例"""
        test_cases = []
        
        if protocol_info.get('protocol') == 'HTTP':
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
            endpoints = protocol_info.get('endpoints', ['/'])
            
            for method in methods:
                for endpoint in endpoints:
                    test_cases.append({)
                        'method': method,
                        'endpoint': endpoint,
                        'payload': f"{method} {endpoint} HTTP/1.1\r\nHost: test\r\n\r\n",
                        'description': f"{method} request to {endpoint}"
                    }
        
        elif protocol_info.get('protocol') == 'DNS':
            queries = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
            domains = ['test.com', 'example.com', 'localhost']
            
            for qtype in queries:
                for domain in domains:
                    test_cases.append({)
                        'query_type': qtype,
                        'domain': domain,
                        'description': f"DNS {qtype} query for {domain}"
                    }
        
        return test_cases
    
    def test_fuzz_payloads(self, target: str, port: int, payloads: List[bytes]) -> List[Dict[str, Any]]:
        """测试模糊测试载荷"""
        results = []
        
        for i, payload in enumerate(payloads):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target, port

                sock.sendall(payload)
                
                try:
                    response = sock.recv(4096)
                    results.append({)
                        'payload_index': i,
                        'payload_length': len(payload),
                        'response_received': True,
                        'response_length': len(response) if response else 0,
                        'crash_detected': False
                    }
                except socket.timeout:
                    results.append({)
                        'payload_index': i,
                        'payload_length': len(payload),
                        'response_received': False,
                        'response_length': 0,
                        'crash_detected': True,
                        'description': '目标超时，可能存在漏洞'
                    }
                
                sock.close()
            except Exception as e:
                results.append({)
                    'payload_index': i,
                    'payload_length': len(payload),
                    'response_received': False,
                    'response_length': 0,
                    'crash_detected': True,
                    'description': f"连接失败: {str(e)}"
                }
        
        return results
    
    def generate_report(self, result: ReplayResult) -> str:
        """生成分析报告"""
        lines = [
            "网络流量重放分析报告",
            "=====================",
            "",
            f"PCAP文件: {result.pcap_file}",
            f"目标: {result.target}",
            f"重放会话数: {result.sessions_replayed}",
            f"发送数据包: {result.packets_sent}",
            f"接收响应: {result.responses_received}",
            f"检测到崩溃: {'是' if result.crash_detected else '否'}",
            ""
        ]
        
        if result.crash_info:
            lines.append("崩溃信息:")
            lines.append("----------")
            lines.append(result.crash_info)
            lines.append("")
        
        if result.vulnerabilities_found:
            lines.append("发现的潜在漏洞:")
            lines.append("----------------")
            for i, vuln in enumerate(result.vulnerabilities_found, 1):
                lines.append(f"{i}. {vuln.get('type', 'Unknown')}")
                lines.append(f"   描述: {vuln.get('description', '')}")
                if 'session' in vuln:
                    lines.append(f"   会话: {vuln['session']}")
                lines.append("")
        
        if not result.vulnerabilities_found:
            lines.append("未发现明显漏洞。")
        
        return '\n'.join(lines)


def replay_pcap(pcap_file: str, target: str) -> ReplayResult:
    """重放pcap文件的便捷函数"""
    replayer = TrafficReplayer(pcap_file)
    replayer.parse_pcap()
    return replayer.replay_all_sessions(target)


def analyze_pcap(pcap_file: str) -> Dict[str, Any]:
    """分析pcap文件"""
    replayer = TrafficReplayer(pcap_file)
    replayer.parse_pcap()
    
    return {
        'pcap_file': pcap_file,
        'total_packets': len(replayer.packets),
        'total_sessions': len(replayer.sessions),
        'protocols': list(set(s.protocol for s in replayer.sessions)),
        'sessions': [{
            'session_id': s.session_id,
            'protocol': s.protocol,
            'src_ip': s.src_ip,
            'dst_ip': s.dst_ip,
            'packet_count': len(s.packets),
            'duration': s.end_time - s.start_time
        } for s in replayer.sessions]
    }


def generate_fuzz_payloads(base_payload: bytes, variations: int = 10) -> List[bytes]:
    """生成模糊测试载荷"""
    payloads = []
    
    for i in range(variations):
        payload = base_payload,
        if i % 3 == 0:
            payload += b'A' * (100 + i * 50)
        elif i % 3 == 1:
            payload = b'\x00' * 256 + payload
        else:
            payload += b'\xff' * (50 + i * 20)
        
        payloads.append(payload)
    
    return payloads)))))))))))))