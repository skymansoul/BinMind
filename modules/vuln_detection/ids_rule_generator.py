#!/usr/bin/env python3
from typing import Dict, List, Optional, Any
"""IDS/IPS规则编译器——将捕获的exploit流量特征转换为Snort 3和Suricata规则语法。
覆盖TCP、UDP、HTTP、DNS、TLS模板，支持可配置告警优先级、flow语义及PCRE链式匹配。
"""

import hashlib
import json
import logging
import re
import uuid
from enum import Enum

logger = logging.getLogger(__name__)

# 协议、动作、优先级枚举——约束规则字段的值空间

class RuleProtocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    ICMP = "icmp"

class RuleAction(Enum):
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    PASS = "pass"

class RulePriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


# 协议专属模板片段——生成时拼装为完整规则语法

_SID_TRACKER: Dict[str, int] = {}

_SERVICE_TEMPLATES: Dict[str, str] = {
    "http": "flow:to_server,established; http.uri; content:\"{pattern}\"; "
             "http.method; content:\"{method}\";",
    "dns":  "flow:to_server; dns.query; content:\"{pattern}\";",
    "tls":  "flow:to_server,established; tls.sni; content:\"{pattern}\";",
}

_PROTOCOL_PORTS: Dict[str, str] = {
    "tcp": "$EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS",
    "udp": "$EXTERNAL_NET any -> $HOME_NET 53",
    "http": "$EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS",
    "dns": "$EXTERNAL_NET any -> $HOME_NET 53",
    "tls": "$EXTERNAL_NET any -> $HOME_NET 443",
    "icmp": "$EXTERNAL_NET any -> $HOME_NET any",
}


# 核心数据结构——签名对象与规则内容容器

class AttackSignature:
    """单条攻击签名——可序列化为Suricata和Snort两种规则方言。"""

    def __init__(self, name: str = "", pattern: str = "",
                 protocol: RuleProtocol = RuleProtocol.TCP,
                 src_ip: str = "any", src_port: str = "any",
                 dst_ip: str = "any", dst_port: str = "any",
                 action: RuleAction = RuleAction.ALERT,
                 priority: RulePriority = RulePriority.MEDIUM,
                 classtype: str = "trojan-activity",
                 reference: str = "",
                 pcre: str = "",
                 flow: str = "to_server,established",
                 sid: Optional[int] = None):
        self.name = name
        self.pattern = pattern
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.action = action
        self.priority = priority
        self.classtype = classtype
        self.reference = reference
        self.pcre = pcre
        self.flow = flow
        self.sid = sid or self._allocate_sid(name)

    @staticmethod
    def _allocate_sid(name: str) -> int:
        h = hashlib.md5(name.encode()).hexdigest()
        sid = int(h[:8], 16) % 9000000 + 1000000
        while sid in _SID_TRACKER:
            sid = (sid + 1) % 9000000 + 1000000
        _SID_TRACKER[str(sid)] = sid
        return sid

    def _msg(self) -> str:
        return f'msg:"{self.name}"; '

    def _content(self) -> str:
        parts: List[str] = []
        # HTTP内容匹配——注入URI与方法检测指令
        if self.protocol == RuleProtocol.HTTP:
            parts.append("flow:to_server,established; ")
            enc = _escape(self.pattern)
            parts.append(f'http.uri; content:"{enc}"; ')
        elif self.protocol == RuleProtocol.DNS:
            parts.append("flow:to_server; ")
            enc = _escape(self.pattern)
            parts.append(f'dns.query; content:"{enc}"; ')
        elif self.protocol == RuleProtocol.TLS:
            parts.append("flow:to_server,established; ")
            enc = _escape(self.pattern)
            parts.append(f'tls.sni; content:"{enc}"; ')
        else:
            enc = _escape(self.pattern)
            parts.append(f'content:"{enc}"; ')
        if self.pcre:
            parts.append(f'pcre:"{_escape(self.pcre)}"; ')
        return "".join(parts)

    def _header(self) -> str:
        return (f"{self.action.value} {self.protocol.value} "
                f"{self.src_ip} {self.src_port} -> "
                f"{self.dst_ip} {self.dst_port} ")

    def to_suricata(self) -> str:
        return (
            f"{self._header()}"
            f"({self._msg()}"
            f"{self._content()}"
            f"flow:{self.flow}; "
            f"classtype:{self.classtype}; "
            f"priority:{self.priority.value}; "
            f"sid:{self.sid}; "
            f"rev:1;)"
        )

    def to_snort(self) -> str:
        return (
            f"{self._header()}"
            f"({self._msg()}"
            f"{self._content()}"
            f"classtype:{self.classtype}; "
            f"priority:{self.priority.value}; "
            f"sid:{self.sid}; "
            f"rev:1;)"
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "pattern": self.pattern,
            "protocol": self.protocol.value,
            "action": self.action.value,
            "sid": self.sid,
            "suricata": self.to_suricata(),
            "snort": self.to_snort(),
        }


# 字符转义工具——中和内容字符串中的定界符

def _escape(s: str) -> str:
    return s.replace('"', '\\"').replace(";", "\\;").replace("|", "\\|")


# 规则内容聚合体——有序签名列表及元数据键值存储

class IDSRuleContent:
    """AttackSignature有序集合——附带元数据键值字典。"""

    def __init__(self):
        self.rules: List[AttackSignature] = []
        self.meta: Dict[str, str] = {}

    def add(self, sig: AttackSignature) -> None:
        self.rules.append(sig)

    def to_suricata_ruleset(self) -> str:
        return "\n".join(r.to_suricata() for r in self.rules)

    def to_snort_ruleset(self) -> str:
        return "\n".join(r.to_snort() for r in self.rules)


# 规则生成引擎——漏洞描述符→AttackSignature→序列化规则

class IDSRuleGenerator:
    """将漏洞描述符或原始字节模式编译为Suricata/Snort规则语法。"""

    def __init__(self):
        self.rules: IDSRuleContent = IDSRuleContent()

    def generate_from_vuln(self, vuln: Dict[str, Any]) -> AttackSignature:
        """从漏洞描述符字典构造单条AttackSignature。

        可识别键：name, pattern, protocol, action, priority, classtype,
        reference, pcre, src_ip, src_port, dst_ip, dst_port, flow。
        """
        proto_str = vuln.get("protocol", "tcp").lower()
        try:
            protocol = RuleProtocol(proto_str)
        except ValueError:
            protocol = RuleProtocol.TCP

        action_str = vuln.get("action", "alert").lower()
        try:
            action = RuleAction(action_str)
        except ValueError:
            action = RuleAction.ALERT

        sig = AttackSignature(
            name=vuln.get("name", f"GEN_{uuid.uuid4().hex[:8]}"),
            pattern=vuln.get("pattern", ""),
            protocol=protocol,
            action=action,
            priority=RulePriority(vuln.get("priority", 3)),
            classtype=vuln.get("classtype", "trojan-activity"),
            reference=vuln.get("reference", ""),
            pcre=vuln.get("pcre", ""),
            src_ip=vuln.get("src_ip", "$EXTERNAL_NET"),
            src_port=vuln.get("src_port", "any"),
            dst_ip=vuln.get("dst_ip", "$HOME_NET"),
            dst_port=vuln.get("dst_port", "any"),
            flow=vuln.get("flow", "to_server,established"),
        )
        self.rules.add(sig)
        return sig

    def generate_from_pcap(self, patterns: Sequence[str],
                           protocol: RuleProtocol = RuleProtocol.TCP,
                           name_prefix: str = "PCAP") -> List[AttackSignature]:
        """从模式字符串序列批量生成规则——共享同一协议与命名前缀。"""
        sigs = []
        for i, pat in enumerate(patterns):
            if not pat.strip():
                continue
            sig = AttackSignature(
                name=f"{name_prefix}_{i + 1}",
                pattern=pat,
                protocol=protocol,
            )
            self.rules.add(sig)
            sigs.append(sig)
        return sigs

    def export_rules(self, fmt: str = "suricata") -> List[str]:
        if fmt == "suricata":
            rule_str = self.rules.to_suricata_ruleset()
        elif fmt == "snort":
            rule_str = self.rules.to_snort_ruleset()
        else:
            raise ValueError(f"Unknown format: {fmt}")
        return rule_str.splitlines() if rule_str else []


class NetworkFunctionInfo:
    """二进制分析中识别的网络相关函数元数据记录。"""
    def __init__(self, name: str = "", protocol: str = "tcp",
                 address: int = 0):
        self.name = name
        self.protocol = protocol
        self.address = address


# 便捷入口——单次调用完成漏洞列表到序列化规则字符串的管道转换

def generate_ids_rules(vulns: Sequence[Dict[str, Any]],
                       fmt: str = "suricata") -> List[str]:
    gen = IDSRuleGenerator()
    for v in vulns:
        gen.generate_from_vuln(v)
    return gen.export_rules(fmt)


name = "ids_rule_generator"
module = "ids_rule_generator"
