"""IDS规则引擎——Suricata规则语法解析。"""
import re
from typing import List, Tuple, Optional

from .network_ids_types import SuricataRule


def parse_suricata_rule(line: str) -> Optional[SuricataRule]:
    """分析Suricata规则语法行到结构化对象。

    格式：action proto src_ip src_port direction dst_ip dst_port (options;)
    options中以分号分隔，支持content、pcre、dsize、threshold、flow等关键字。
    """
    _line = line.strip()
    if not _line or _line.startswith("#"):
        return None

    _rule = SuricataRule(raw=_line)

    # 匹配规则头部: action proto src src_port -> dst dst_port
    _head_pattern = re.compile(
        r'^(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+'
        r'(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$',
        re.DOTALL
    )
    _m = _head_pattern.match(_line)
    if not _m:
        return None

    _rule.action = _m.group(1)
    _rule.proto = _m.group(2)
    _rule.src_ip = _m.group(3)
    _rule.src_port = _m.group(4)
    _rule.direction = _m.group(5)
    _rule.dst_ip = _m.group(6)
    _rule.dst_port = _m.group(7)
    _options_str = _m.group(8)

    # 解析options
    _parse_options(_options_str, _rule)
    return _rule


def _parse_options(opts: str, rule: SuricataRule) -> None:
    # 处理引号内容避免分号拆分错误
    _parts = _split_options(opts)
    for _part in _parts:
        _part = _part.strip()
        if not _part:
            continue
        _kv = _part.split(":", 1)
        if len(_kv) < 2:
            continue
        _key = _kv[0].strip()
        _val = _kv[1].strip()

        if _key == "msg":
            rule.msg = _val.strip('"')
        elif _key == "sid":
            try:
                rule.sid = int(_val)
            except ValueError:
                pass
        elif _key == "content":
            rule.content_patterns.append(_val.strip('"'))
        elif _key == "pcre":
            rule.pcre_patterns.append(_val.strip('"'))
        elif _key == "flow":
            rule.flow_direction = _val.strip('"')
        elif _key == "dsize":
            _parsed = _parse_dsize(_val)
            rule.dsize_min, rule.dsize_max = _parsed
        elif _key == "threshold":
            _parsed = _parse_threshold(_val)
            rule.threshold_count, rule.threshold_seconds = _parsed
        elif _key == "reference":
            rule.reference_urls.append(_val.strip('"'))
        elif _key == "classtype":
            rule.classtype = _val.strip('"')
        elif _key == "metadata":
            for _pair in _val.strip('"').split(","):
                _pair = _pair.strip()
                if " " in _pair:
                    _mk, _mv = _pair.split(" ", 1)
                    rule.metadata[_mk.strip()] = _mv.strip()
                else:
                    rule.metadata[_pair] = ""


def _split_options(s: str) -> List[str]:
    _parts = []
    _current = ""
    _in_quotes = False
    _quote_char = ""
    for _ch in s:
        if _ch in ('"', "'") and not _in_quotes:
            _in_quotes = True
            _quote_char = _ch
            _current += _ch
        elif _ch == _quote_char and _in_quotes:
            _in_quotes = False
            _quote_char = ""
            _current += _ch
        elif _ch == ";" and not _in_quotes:
            _parts.append(_current)
            _current = ""
        else:
            _current += _ch
    if _current:
        _parts.append(_current)
    return _parts


def _parse_dsize(val: str) -> Tuple[int, int]:
    _m = re.match(r'^(\d+)$', val)
    if _m:
        _v = int(_m.group(1))
        return (_v, _v)
    _range = re.match(r'^(\d+)\s*<>\s*(\d+)$', val)
    if _range:
        return (int(_range.group(1)), int(_range.group(2)))
    _gt = re.match(r'^>(\d+)$', val)
    if _gt:
        return (int(_gt.group(1)), 0xFFFFFFFF)
    _lt = re.match(r'^<(\d+)$', val)
    if _lt:
        return (0, int(_lt.group(1)))
    return (0, 0)


def _parse_threshold(val: str) -> Tuple[int, int]:
    _count = 0
    _sec = 0
    _parts = val.strip('"').split(",")
    for _p in _parts:
        _p = _p.strip()
        if "count" in _p:
            try:
                _count = int(_p.split("count")[-1].strip())
            except ValueError:
                pass
        elif "seconds" in _p:
            try:
                _sec = int(_p.split("seconds")[-1].strip())
            except ValueError:
                pass
    return (_count, _sec)
