"""IDS规则引擎——内置检测规则定义。"""
from typing import List

from .network_ids_types import SuricataRule
from .network_ids_parser import parse_suricata_rule

# 模块级缓存，首次访问时构建
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
