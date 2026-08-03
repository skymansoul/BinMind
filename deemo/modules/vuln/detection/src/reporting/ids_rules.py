# IDS规则生成器
# Snort 3与Suricata规则生成，基于CVE/攻击模式生成网络检测规则
# FIXME: 端口和流向目前硬编码为any→any，应从CVE描述中提取

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import json as _json
import os
import re
import hashlib

json = _json


class RuleProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    ANY = "any"


class RuleAction(str, Enum):
    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    PASS = "pass"
    LOG = "log"


@dataclass
class SuricataRule:
    sid: int
    msg: str
    action: str = "alert"
    protocol: str = "any"
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    content: str = ""
    pcre: str = ""
    classtype: str = ""
    reference: str = ""
    metadata: List[str] = field(default_factory=list)

    def to_rule_string(self) -> str:
        """生成Suricata规则字符串。"""
        parts = [
            f'{self.action} {self.protocol} {self.src_ip} {self.src_port}',
            f'-> {self.dst_ip} {self.dst_port}',
        ]
        opts = [f'msg:"{self.msg}";', f'sid:{self.sid};']
        if self.content:
            opts.append(f'content:"{self.content}";')
        if self.pcre:
            opts.append(f'pcre:"{self.pcre}";')
        if self.classtype:
            opts.append(f'classtype:{self.classtype};')
        if self.reference:
            opts.append(f'reference:{self.reference};')
        for m in self.metadata:
            opts.append(f'metadata:{m};')
        return f"{' '.join(parts)} ({' '.join(opts)})"


@dataclass
class SnortRule:
    gid: int = 1
    sid: int = 0
    rev: int = 1
    msg: str = ""
    action: str = "alert"
    protocol: str = "tcp"
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    content: str = ""
    pcre: str = ""
    classtype: str = ""
    reference: str = ""

    def to_rule_string(self) -> str:
        parts = [
            f'{self.action} {self.protocol} {self.src_ip} {self.src_port}',
            f'-> {self.dst_ip} {self.dst_port}',
        ]
        opts = [f'msg:"{self.msg}";', f'gid:{self.gid};',
                f'sid:{self.sid};', f'rev:{self.rev};']
        if self.content:
            opts.append(f'content:"{self.content}";')
        if self.pcre:
            opts.append(f'pcre:"{self.pcre}";')
        if self.classtype:
            opts.append(f'classtype:{self.classtype};')
        if self.reference:
            opts.append(f'reference:{self.reference};')
        return f"{' '.join(parts)} ({' '.join(opts)})"

    @property
    def rule_id(self) -> str:
        return f"{self.gid}:{self.sid}:{self.rev}"


class IDSRuleGenerator:
    """IDS/IPS规则生成器。

    从CVE编号和漏洞描述生成Snort 3与Suricata兼容的检测规则。
    支持HTTP/TCP/UDP/DNS/TLS协议层签名。

    规则SID自1000001起按hash派生，保持确定性。
    """

    BASE_SID = 1000001

    # 按CWE/CVE类型映射的检测模式
    _VULN_PATTERNS = {
        "CWE-89": {  # SQL注入
            "contents": ["UNION SELECT", "OR 1=1", "--"],
            "pcre": r"/(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:.*\s)?(?:FROM|INTO|SET)/i",
        },
        "CWE-79": {  # 跨站脚本
            "contents": ["<script>", "javascript:", "onerror=", "onload="],
        },
        "CWE-78": {  # 命令注入
            "contents": [";cat ", "|/bin/sh", "`id`", "$(whoami)"],
            "pcre": r"/(?:\||;|\x60|\$\().*(?:cat|id|whoami|ls|wget|curl)/i",
        },
        "CWE-22": {  # 路径遍历
            "contents": ["../", "..\\", "/etc/passwd", "boot.ini"],
            "pcre": r"/(?:\.\.\/|\.\.\\){2,}/",
        },
        "CWE-434": {  # 文件上传
            "contents": [".php", ".jsp", ".asp", ".war"],
        },
        "CWE-502": {  # 反序列化
            "contents": ["O:", "ac ed 00 05"],
        },
    }

    def __init__(self):
        self._sid_counter = self.BASE_SID
        self._rules: List[SuricataRule] = []

    def _next_sid(self, seed: str = "") -> int:
        if seed:
            return self.BASE_SID + int(hashlib.md5(seed.encode()).hexdigest()[:8], 16) % 900000
        sid = self._sid_counter
        self._sid_counter += 1
        return sid

    def generate_from_cve(self, cve_id: str, cwe_id: str = "",
                          description: str = "",
                          protocol: str = "http") -> List[SuricataRule]:
        rules = []
        base_msg = f"BinMind: {cve_id} exploitation attempt"
        cwe_patterns = self._VULN_PATTERNS.get(cwe_id, {})

        content_patterns = cwe_patterns.get("contents", [])
        pcre_pattern = cwe_patterns.get("pcre", "")

        if content_patterns:
            for i, content in enumerate(content_patterns):
                sid = self._next_sid(f"{cve_id}:{i}")
                rules.append(SuricataRule(
                    sid=sid,
                    msg=f"{base_msg} ({content[:30]})",
                    action="alert",
                    protocol=protocol,
                    content=content,
                    classtype="attempted-admin",
                    reference=f"cve,{cve_id}",
                ))

        if pcre_pattern:
            sid = self._next_sid(f"{cve_id}:pcre")
            rules.append(SuricataRule(
                sid=sid, msg=f"{base_msg} (PCRE match)",
                action="alert", protocol=protocol,
                pcre=pcre_pattern,
                classtype="attempted-admin",
                reference=f"cve,{cve_id}",
            ))

        if not rules:
            sid = self._next_sid(cve_id)
            rules.append(SuricataRule(
                sid=sid, msg=base_msg,
                action="alert", protocol=protocol,
                reference=f"cve,{cve_id}",
                classtype="attempted-user",
            ))

        self._rules.extend(rules)
        return rules

    def generate_drop_rule(self, src_ip: str, dst_ip: str,
                           src_port: str = "any", dst_port: str = "any",
                           protocol: str = "tcp", msg: str = "") -> SuricataRule:
        sid = self._next_sid()
        return SuricataRule(
            sid=sid, msg=msg or f"Drop traffic {src_ip}->{dst_ip}:{dst_port}",
            action="drop", protocol=protocol,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
        )

    def to_snort_rules(self) -> List[SnortRule]:
        snort = []
        for r in self._rules:
            snort.append(SnortRule(
                sid=r.sid, msg=r.msg,
                action=r.action, protocol=r.protocol,
                src_ip=r.src_ip, src_port=r.src_port,
                dst_ip=r.dst_ip, dst_port=r.dst_port,
                content=r.content, pcre=r.pcre,
                classtype=r.classtype, reference=r.reference,
            ))
        return snort

    def export(self, path: str, format: str = "suricata") -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if format == "suricata":
            lines = [f"# BinMind Suricata rules — {os.path.basename(path)}"]
            lines.extend(r.to_rule_string() for r in self._rules)
        elif format == "snort":
            lines = [f"# BinMind Snort3 rules — {os.path.basename(path)}"]
            lines.extend(r.to_rule_string() for r in self.to_snort_rules())
        elif format == "json":
            data = [{"sid": r.sid, "msg": r.msg, "rule": r.to_rule_string()}
                    for r in self._rules]
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            return os.path.abspath(path)
        else:
            raise ValueError(f"unknown format: {format}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return os.path.abspath(path)

    rule_count = property(lambda self: len(self._rules))

    def _debug_print_rules(self) -> str:
        return "\n".join(r.to_rule_string() for r in self._rules[:5])


def generate_suricata_rules(cve_list: List[Dict]) -> str:
    gen = IDSRuleGenerator()
    for cve in cve_list:
        gen.generate_from_cve(
            cve_id=cve.get("cve_id", ""),
            cwe_id=cve.get("cwe_id", ""),
            description=cve.get("description", ""),
            protocol=cve.get("protocol", "http"),
        )
    return "\n".join(r.to_rule_string() for r in gen._rules)


def generate_snort_rules(cve_list: List[Dict]) -> str:
    gen = IDSRuleGenerator()
    for cve in cve_list:
        gen.generate_from_cve(
            cve_id=cve.get("cve_id", ""),
            cwe_id=cve.get("cwe_id", ""),
            description=cve.get("description", ""),
        )
    return "\n".join(r.to_rule_string() for r in gen.to_snort_rules())
