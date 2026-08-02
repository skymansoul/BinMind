# 2026-07-30
# Network differential analysis — 多实例请求比对
# 对相同的请求，不同服务器实现返回不同响应 → 发现实现差异/bug。
# 策略：发请求 → 收响应 → header + body 逐字段比对 → 分类差异。
import time
import socket
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set


@dataclass
class NetDiffResult:
    diff_type: str = ""          # HEADER | BODY | TIMING | STATUS | NONE
    location: str = ""           # which field/offset
    server_a_response: bytes = b""
    server_b_response: bytes = b""
    server_a_name: str = "A"
    server_b_name: str = "B"
    offset: int = 0


# ================================================
def capture_responses(targets: Dict[str, Tuple[str, int]],
                      request: bytes,
                      timeout: float = 5.0) -> Dict[str, bytes]:
    """向多个服务器发送相同请求，收集响应。

    targets: {instance_name: (host, port), ...}
    返回: {instance_name: response_bytes, ...}
    """
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


# ================================================
def diff_responses(responses: Dict[str, bytes]) -> List[NetDiffResult]:
    """比较所有响应对之间的差异。"""
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

            # Size diff
            if len(_ra) != len(_rb):
                _diffs.append(NetDiffResult(
                    diff_type="SIZE",
                    location="response_body",
                    server_a_name=_a, server_b_name=_b,
                    server_a_response=_ra, server_b_response=_rb,
                    offset=min(len(_ra), len(_rb)),
                ))

            # Content diff
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


# ================================================
def identify_implementation_diffs(responses_a: Dict[str, bytes],
                                  responses_b: Dict[str, bytes]) -> List[NetDiffResult]:
    """识别两个服务器实现之间的差异。

    区分：
    - spec-compliant 差异（如 header 顺序、空白）
    - potential bugs（语义差异）
    """
    _diffs = []
    _common_keys = set(responses_a.keys()) & set(responses_b.keys())

    for _name in _common_keys:
        _ra = responses_a[_name]
        _rb = responses_b[_name]

        if _ra == _rb:
            continue

        # 分离 header 和 body
        _ha, _ba = _split_http(_ra)
        _hb, _bb = _split_http(_rb)

        # Header 差异检查
        _hdiffs = _compare_headers(_ha, _hb)
        if _hdiffs:
            _diffs.append(NetDiffResult(
                diff_type="HEADER",
                location=f"header:{'+'.join(_hdiffs)}",
                server_a_name=_name, server_b_name=_name,
                server_a_response=_ra, server_b_response=_rb,
            ))

        # Body 差异
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
    """分离 HTTP 响应的 header 和 body。"""
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
    """比较两个 header dict，找出有意义的差异。"""
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
