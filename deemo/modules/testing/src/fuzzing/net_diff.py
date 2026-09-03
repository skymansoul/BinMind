"""网络差分分析——多实例请求比对——同请求不同响应差异检测"""
import time
import socket
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from collections import defaultdict


@dataclass
class NetDiffResult:
    diff_type: str = ""
    location: str = ""
    server_a_response: bytes = b""
    server_b_response: bytes = b""
    server_a_name: str = "A"
    server_b_name: str = "B"
    offset: int = 0


def capture_responses(targets: Dict[str, Tuple[str, int]],
                      request: bytes,
                      timeout: float = 5.0) -> Dict[str, bytes]:
    """向多服务器发送相同请求收集响应"""
    _responses = {}
    for _name, (_host, _port) in targets.items():
        try:
            _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _sock.settimeout(timeout)
            _sock.connect((_host, _port))
            _sock.sendall(request)
            _data = b""
            while True:
                try:
                    _chunk = _sock.recv(4096)
                    if not _chunk:
                        break
                    _data += _chunk
                except socket.timeout:
                    break
            _sock.close()
            _responses[_name] = _data
        except Exception as _e:
            _responses[_name] = f"ERROR: {_e}".encode()
    return _responses


def diff_responses(responses: Dict[str, bytes]) -> List[NetDiffResult]:
    """比较所有响应对之间的差异"""
    _diffs = []
    _names = list(responses.keys())

    for _i in range(len(_names)):
        for _j in range(_i + 1, len(_names)):
            _a = _names[_i]
            _b = _names[_j]
            _ra = responses.get(_a, b"")
            _rb = responses.get(_b, b"")

            if _ra == _rb:
                _diffs.append(NetDiffResult(
                    diff_type="NONE",
                    server_a_name=_a, server_b_name=_b,
                    server_a_response=_ra, server_b_response=_rb,
                ))
                continue

            if len(_ra) != len(_rb):
                _diffs.append(NetDiffResult(
                    diff_type="SIZE",
                    location="response_body",
                    server_a_name=_a, server_b_name=_b,
                    server_a_response=_ra, server_b_response=_rb,
                    offset=min(len(_ra), len(_rb)),
                ))

            _min_len = min(len(_ra), len(_rb))
            for _k in range(_min_len):
                if _ra[_k] != _rb[_k]:
                    _diffs.append(NetDiffResult(
                        diff_type="BODY",
                        location=f"offset_{_k}",
                        server_a_name=_a, server_b_name=_b,
                        server_a_response=_ra, server_b_response=_rb,
                        offset=_k,
                    ))
                    break

    return _diffs


def identify_implementation_diffs(responses_a: Dict[str, bytes],
                                  responses_b: Dict[str, bytes]) -> List[NetDiffResult]:
    """识别两个服务实现的差异——区分规范差异与潜在 bug"""
    _diffs = []
    _common_keys = set(responses_a.keys()) & set(responses_b.keys())

    for _name in _common_keys:
        _ra = responses_a[_name]
        _rb = responses_b[_name]

        if _ra == _rb:
            continue

        _ha, _ba = _split_http(_ra)
        _hb, _bb = _split_http(_rb)

        _hdiffs = _compare_headers(_ha, _hb)
        if _hdiffs:
            _diffs.append(NetDiffResult(
                diff_type="HEADER",
                location=f"header:{'+'.join(_hdiffs)}",
                server_a_name=_name, server_b_name=_name,
                server_a_response=_ra, server_b_response=_rb,
            ))

        if _ba != _bb:
            _diffs.append(NetDiffResult(
                diff_type="BODY",
                location="body",
                server_a_name=_name, server_b_name=_name,
                server_a_response=_ra, server_b_response=_rb,
                offset=_first_diff_offset(_ba, _bb),
            ))

    return _diffs


def _split_http(response: bytes) -> Tuple[Dict[str, str], bytes]:
    """分离 HTTP 响应的 header 和 body"""
    _sep = response.find(b"\r\n\r\n")
    if _sep < 0:
        _sep = response.find(b"\n\n")
    if _sep < 0:
        return {}, response

    _header_block = response[:_sep].decode(errors="replace")
    _body = response[_sep + 4:] if response[_sep:_sep + 2] == b"\r\n" else response[_sep + 2:]

    _headers = {}
    for _line in _header_block.split("\n"):
        _line = _line.strip()
        if ":" in _line:
            _key, _, _val = _line.partition(":")
            _headers[_key.strip().lower()] = _val.strip()

    return _headers, _body


def _compare_headers(a: Dict[str, str], b: Dict[str, str]) -> List[str]:
    """比较两个 header dict——忽略时间戳和服务器标识"""
    _diffs = []
    _all_keys = set(a.keys()) | set(b.keys())
    _ignore = {"date", "server", "x-powered-by", "set-cookie", "expires",
               "last-modified", "etag", "x-request-id", "x-trace-id"}

    for _k in sorted(_all_keys):
        if _k in _ignore:
            continue
        _va = a.get(_k, "<missing>")
        _vb = b.get(_k, "<missing>")
        if _va != _vb:
            _diffs.append(_k)
    return _diffs


def _first_diff_offset(a: bytes, b: bytes) -> int:
    _min = min(len(a), len(b))
    for _i in range(_min):
        if a[_i] != b[_i]:
            return _i
    return _min


class NetworkServiceResponseDiffAnalyzer:
    """网络服务响应差分分析——近似请求对 -> 响应差异 -> 信息泄露/异常检测"""

    def __init__(self):
        self.request_pairs: List[Dict[str, Any]] = []
        self.response_diffs: List[Dict[str, Any]] = []
        self.detected_issues: List[Dict[str, Any]] = []
        self._timing_baseline: Dict[str, List[float]] = defaultdict(list)

    def generate_request_pairs(self, base_request: bytes) -> List[Dict[str, bytes]]:
        """生成请求变体对——空字段/长值/特殊字符/null 注入"""
        pairs = []

        variations = [
            {'name': 'empty_field', 'request': base_request.replace(b'value', b'')},
            {'name': 'long_value', 'request': base_request.replace(b'value', b'value' * 100)},
            {'name': 'special_chars', 'request': base_request.replace(b'value', b'<script>')},
            {'name': 'null_bytes', 'request': base_request.replace(b'value', b'\x00\x00')},
        ]

        for variation in variations:
            pairs.append({
                'name': variation['name'],
                'request1': base_request,
                'request2': variation['request']
            })

        self.request_pairs = pairs
        return pairs

    def compare_responses(self, response1: bytes, response2: bytes) -> Dict[str, Any]:
        """比较两个响应——尺寸差异、内容差异、错误消息泄露"""
        diff = {
            'size_diff': len(response2) - len(response1),
            'content_diff': [],
            'status_diff': False,
            'potential_leak': False
        }

        if abs(diff['size_diff']) > 100:
            diff['potential_leak'] = True
            diff['content_diff'].append('响应尺寸异常')

        if response1 != response2:
            for i, (c1, c2) in enumerate(zip(response1, response2)):
                if c1 != c2:
                    diff['content_diff'].append(f'字节差异于偏移 {i}')

        error_patterns = [b'error', b'exception', b'failed', b'invalid']
        for pattern in error_patterns:
            if pattern in response2 and pattern not in response1:
                diff['potential_leak'] = True
                diff['content_diff'].append('错误字符串泄露')

        return diff

    def analyze_service_responses(self, target: str, port: int) -> List[Dict[str, Any]]:
        """分析服务响应——对每个请求对收发并比较"""
        results = []

        for pair in self.request_pairs:
            try:
                sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock1.settimeout(5)
                sock1.connect((target, port))
                t1_start = time.perf_counter()
                sock1.send(pair['request1'])
                response1 = sock1.recv(4096)
                t1 = time.perf_counter() - t1_start
                sock1.close()

                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(5)
                sock2.connect((target, port))
                t2_start = time.perf_counter()
                sock2.send(pair['request2'])
                response2 = sock2.recv(4096)
                t2 = time.perf_counter() - t2_start
                sock2.close()

                diff = self.compare_responses(response1, response2)

                results.append({
                    'pair_name': pair['name'],
                    'diff': diff,
                    'timing': {'req1_ms': round(t1 * 1000, 2),
                               'req2_ms': round(t2 * 1000, 2)},
                })

                if diff['potential_leak']:
                    self.detected_issues.append({
                        'type': 'information_leak',
                        'pair_name': pair['name'],
                        'description': '响应差分存在潜在信息泄露'
                    })

                if t1 > 0 and (t2 / t1 > 10 or t1 / t2 > 10):
                    self.detected_issues.append({
                        'type': 'timing_anomaly',
                        'pair_name': pair['name'],
                        'description': f'响应时序比 {max(t1,t2)/min(t1,t2):.1f}x',
                    })

            except Exception as e:
                results.append({
                    'pair_name': pair['name'],
                    'error': str(e)
                })

        self.response_diffs = results
        return results

    def fingerprint_service(self, target: str, port: int,
                            probe: bytes, samples: int = 10) -> Dict[str, Any]:
        """服务指纹收集——多次采样建立响应特征基线"""
        times = []
        sizes = []
        for _ in range(samples):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                t0 = time.perf_counter()
                sock.send(probe)
                resp = sock.recv(4096)
                elapsed = time.perf_counter() - t0
                times.append(elapsed)
                sizes.append(len(resp))
                sock.close()
            except Exception:
                pass
        if not times:
            return {'error': '无成功探测'}
        return {
            'avg_response_ms': round(sum(times) / len(times) * 1000, 2),
            'std_response_ms': round(
                (sum((t - sum(times) / len(times)) ** 2
                     for t in times) / len(times)) ** 0.5 * 1000, 2),
            'avg_size': sum(sizes) // len(sizes),
            'samples': len(times),
        }

    def generate_diff_report(self) -> str:
        """差分分析报告"""
        report = '# 网络服务响应差分分析报告\n\n'

        report += '## 响应差异\n'
        for diff in self.response_diffs:
            report += f'- {diff["pair_name"]}: 尺寸差 {diff["diff"]["size_diff"]}\n'

        if self.detected_issues:
            report += '\n## 检测到的问题\n'
            for issue in self.detected_issues:
                report += f'- {issue["type"]}: {issue["description"]}\n'

        return report
