"""IDS规则引擎——Suricata风格规则解析与匹配。"""
import logging, re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Set
import uuid

_log = logging.getLogger(__name__)

# ---- 内置规则SID范围 ----
SID_RANGE = (9000001, 9000100)

# ===== 数据结构 =====
@dataclass
class SuricataRule:
    sid: int = 0
    msg: str = ""
    action: str = "alert"
    proto: str = "any"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"
    content_patterns: List[str] = field(default_factory=list)
    pcre_patterns: List[str] = field(default_factory=list)
    flow_direction: str = ""  # to_server, to_client, established
    dsize_min: int = 0
    dsize_max: int = 0
    threshold_count: int = 0
    threshold_seconds: int = 0
    reference_urls: List[str] = field(default_factory=list)
    classtype: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    raw: str = ""


# Suricata规则解析
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


# ===== 内置检测规则 =====
BUILT_IN_RULES: List[SuricataRule] = []

def _build_builtin_rules() -> List[SuricataRule]:
    """构建7条内置检测规则，SID范围9000001-9000007。

    规则覆盖ICMP隧道、DNS隧道、非标SSH、C2端口、PE下载、
    DNS外泄、Heartbleed攻击等典型威胁场景。
    """
    _rules_raw = [
        # SID 9000001: ICMP隧道检测
        'alert icmp any any -> any any (msg:"ICMP TUNNEL DETECTED - large payload"; '
        'dsize:>512; sid:9000001; classtype:"trojan-activity"; '
        'reference:url,attack.mitre.org/techniques/T1095/; '
        'metadata:detection icmp_tunnel;)',

        # SID 9000002: DNS长查询
        'alert udp any any -> any 53 (msg:"DNS TUNNEL - long query"; '
        'dsize:>253; sid:9000002; classtype:"trojan-activity"; '
        'reference:url,attack.mitre.org/techniques/T1048/; '
        'metadata:detection dns_tunnel;)',

        # SID 9000003: 非标SSH
        'alert tcp any any -> any ![22,2222,22222] (msg:"SSH ON NON-STANDARD PORT"; '
        'content:"SSH-"; sid:9000003; classtype:"policy-violation"; '
        'threshold:type limit,track by_src,count 1,seconds 60; '
        'metadata:detection non_standard_ssh;)',

        # SID 9000004: 已知C2默认端口
        'alert tcp any any -> any [4444,1337,5555,6666,7777,8888,9999,31337,12345,54321,4782,1177,8282,8443] '
        '(msg:"C2 DEFAULT PORT"; sid:9000004; classtype:"trojan-activity"; '
        'reference:url,attack.mitre.org/techniques/T1571/; '
        'metadata:detection c2_default_port;)',

        # SID 9000005: PE文件下载
        'alert tcp any any -> any any (msg:"PE FILE DOWNLOAD - MZ header"; '
        'content:"MZ"; content:"This program cannot be run in DOS mode"; '
        'flow:to_client,established; sid:9000005; classtype:"trojan-activity"; '
        'reference:url,attack.mitre.org/techniques/T1105/; '
        'metadata:detection pe_download;)',

        # SID 9000006: DNS数据外泄
        'alert udp any any -> any 53 (msg:"DNS DATA EXFILTRATION - large TXT"; '
        'dsize:>256; sid:9000006; classtype:"attempted-recon"; '
        'reference:url,attack.mitre.org/techniques/T1048/; '
        'metadata:detection dns_exfil;)',

        # SID 9000007: Heartbleed攻击
        'alert tcp any any -> any 443 (msg:"HEARTBLEED TLS HEARTBEAT ATTACK"; '
        'content:"|18 03|"; dsize:>40; sid:9000007; classtype:"attempted-admin"; '
        'reference:url,cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160; '
        'metadata:detection heartbleed;)',
    ]
    _rules = []
    for _raw in _rules_raw:
        _r = parse_suricata_rule(_raw)
        if _r:
            _rules.append(_r)
    return _rules


BUILT_IN_RULES = _build_builtin_rules()


# 规则引擎
class RuleEngine:
    """Suricata风格规则引擎：加载规则、匹配包和流。

    匹配策略：先检查协议和端口（快速过滤），再逐条匹配content和pcre模式。
    流级别规则需在match_flow中基于FlowRecord统计特征匹配。
    """

    def __init__(self):
        self._rules: List[SuricataRule] = []
        self._rules_by_proto: Dict[str, List[SuricataRule]] = {
            "tcp": [], "udp": [], "icmp": [], "any": [],
        }
        self._rules_by_sid: Dict[int, SuricataRule] = {}

    def load_rules(self, rules_source: Any) -> int:
        """从文件或列表加载规则。

        参数可以是文件路径(str)或SuricataRule列表。自动按协议索引以提高
        匹配效率。返回加载的规则数量。
        """
        _rules: List[SuricataRule] = []
        if isinstance(rules_source, str):
            # 文件路径
            try:
                with open(rules_source, "r", encoding="utf-8", errors="replace") as _f:
                    for _line in _f:
                        _r = parse_suricata_rule(_line)
                        if _r:
                            _rules.append(_r)
            except Exception as e:
                _log.error("加载规则文件失败 %s: %s", rules_source, e)
                return 0
        elif isinstance(rules_source, list):
            for _item in rules_source:
                if isinstance(_item, SuricataRule):
                    _rules.append(_item)
                elif isinstance(_item, str):
                    _r = parse_suricata_rule(_item)
                    if _r:
                        _rules.append(_r)
        else:
            _log.warning("不支持的规则源类型: %s", type(rules_source))
            return 0

        self._rules.extend(_rules)
        # 建立索引
        for _r in _rules:
            _proto = _r.proto.lower()
            if _proto in self._rules_by_proto:
                self._rules_by_proto[_proto].append(_r)
            else:
                self._rules_by_proto["any"].append(_r)
            self._rules_by_sid[_r.sid] = _r

        return len(_rules)

    def match_packet(self, packet_data: Any) -> List[SuricataRule]:
        """对数据包匹配所有规则，返回触发的规则列表。

        packet_data可以是字节串(bytes)或包含protocol/ports等属性的对象。
        匹配流程：协议过滤 → 端口过滤 → content/pcre匹配。
        """
        _triggered: List[SuricataRule] = []

        # 提取协议和端口
        _proto_str = "any"
        _dport = 0
        _payload = b""

        if isinstance(packet_data, bytes):
            _payload = packet_data
            _candidates = self._rules_by_proto.get("any", [])
        elif isinstance(packet_data, dict):
            _payload = packet_data.get("payload", b"")
            _p = packet_data.get("protocol", 6)
            if _p == 6:
                _proto_str = "tcp"
            elif _p == 17:
                _proto_str = "udp"
            elif _p == 1:
                _proto_str = "icmp"
            _dport = packet_data.get("dst_port", 0)
        else:
            _payload = getattr(packet_data, "payload", b"")
            _p = getattr(packet_data, "protocol", 6)
            if _p == 6:
                _proto_str = "tcp"
            elif _p == 17:
                _proto_str = "udp"
            elif _p == 1:
                _proto_str = "icmp"
            _dport = getattr(packet_data, "dst_port", 0)

        _candidates = list(self._rules_by_proto.get(_proto_str, []))
        _candidates.extend(self._rules_by_proto.get("any", []))

        for _rule in _candidates:
            if _rule_matches_packet(_rule, _payload, _proto_str, _dport):
                _triggered.append(_rule)

        return _triggered

    def match_flow(self, flow: Any) -> List[SuricataRule]:
        """对流记录匹配基于流特征的规则（阈值、字节数等）。

        主要匹配dsize约束和threshold阈值规则。flow需提供bytes_sum、
        packets、src_port、dst_port等属性。
        """
        _triggered: List[SuricataRule] = []
        _bytes = getattr(flow, "bytes_sum", 0)
        _packets = getattr(flow, "packets", 0)
        _dport = getattr(flow, "dst_port", 0)

        for _rule in self._rules:
            # dsize匹配
            if _rule.dsize_min > 0 and _bytes < _rule.dsize_min:
                continue
            if _rule.dsize_max > 0 and _rule.dsize_max < 0xFFFFFFFF and _bytes > _rule.dsize_max:
                continue
            # threshold匹配
            if _rule.threshold_count > 0 and _packets < _rule.threshold_count:
                continue
            _triggered.append(_rule)

        return _triggered

    def get_rule(self, sid: int) -> Optional[SuricataRule]:
        return self._rules_by_sid.get(sid)

    def list_rules(self) -> List[SuricataRule]:
        return list(self._rules)

    def rule_count(self) -> int:
        return len(self._rules)


def _rule_matches_packet(rule: SuricataRule, payload: bytes, proto: str, dport: int) -> bool:
    # 端口过滤
    if rule.dst_port != "any":
        if not _port_matches(rule.dst_port, dport):
            return False

    # content匹配
    if rule.content_patterns:
        for _cp in rule.content_patterns:
            # 处理十六进制转义 |XX XX|
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
