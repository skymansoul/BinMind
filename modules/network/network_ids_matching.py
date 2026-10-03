"""IDS规则引擎——数据包匹配工具函数。"""
import re
from typing import Set

from .network_ids_types import SuricataRule


def rule_matches_packet(rule: SuricataRule, payload: bytes, proto: str, dport: int) -> bool:
    """对单条规则执行完整匹配：端口→content→pcre。"""
    # 端口过滤
    if rule.dst_port != "any":
        if not _port_matches(rule.dst_port, dport):
            return False

    # content匹配
    if rule.content_patterns:
        for _cp in rule.content_patterns:
            _pat = _decode_content_pattern(_cp)
            if _pat and _pat not in payload:
                return False

    # pcre匹配
    if rule.pcre_patterns:
        for _pcre in rule.pcre_patterns:
            try:
                _m = re.search(_pcre.encode() if isinstance(_pcre, str) else _pcre, payload)
            except Exception:
                try:
                    _m = re.search(_pcre, payload.decode("latin-1", errors="replace"))
                except Exception:
                    _m = None
            if not _m:
                return False

    return True


def _port_matches(rule_port: str, actual_port: int) -> bool:
    if rule_port == "any":
        return True
    # 处理端口组 [80,443,8080]
    if rule_port.startswith("[") and rule_port.endswith("]"):
        _inner = rule_port[1:-1]
        _ports = _parse_port_list(_inner)
        return actual_port in _ports
    # 处理排除端口 ![22]
    if rule_port.startswith("![") and rule_port.endswith("]"):
        _inner = rule_port[2:-1]
        _ports = _parse_port_list(_inner)
        return actual_port not in _ports
    # 范围 8000:8100
    if ":" in rule_port and not rule_port.startswith("!"):
        _parts = rule_port.split(":")
        try:
            _lo = int(_parts[0])
            _hi = int(_parts[1])
            return _lo <= actual_port <= _hi
        except ValueError:
            return True
    # 单个端口
    try:
        return int(rule_port) == actual_port
    except ValueError:
        return True


def _parse_port_list(s: str) -> Set[int]:
    _ports: Set[int] = set()
    for _p in s.split(","):
        _p = _p.strip()
        try:
            _ports.add(int(_p))
        except ValueError:
            pass
    return _ports


def _decode_content_pattern(pat: str) -> bytes:
    """解码content模式，支持|XX XX|十六进制和普通ASCII混合"""
    _result = bytearray()
    _i = 0
    while _i < len(pat):
        if pat[_i] == "|":
            _end = pat.find("|", _i + 1)
            if _end == -1:
                _result.extend(pat[_i:].encode("latin-1"))
                break
            _hex = pat[_i+1:_end]
            for _b in _hex.split():
                try:
                    _result.append(int(_b.strip(), 16))
                except ValueError:
                    pass
            _i = _end + 1
        else:
            _result.append(ord(pat[_i]))
            _i += 1
    return bytes(_result)
