"""RFC 协议合规性校验器 —— 基于 RFC 文本的协议实现验证。

核心理念（参考可追溯RFC文档解释的协议解析器验证方法）：
将 RFC 中的 MUST/SHOULD/MAY 约束提取为可自动执行的规则，
对协议实现进行合规性断言。

RFC 2119 关键词分级：
- MUST / REQUIRED / SHALL → CRITICAL 违规（协议破坏性缺陷）
- SHOULD / RECOMMENDED → HIGH 违规（非最佳实践，存在安全风险）
- MAY / OPTIONAL → INFO（信息性，非强制）

本模块不解析完整 RFC 文本 —— 而是内置常见协议的关键规则模板，
可扩展为从 RFC XML 自动提取。
"""
import re, logging, struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any

_log = logging.getLogger(__name__)


class RfcSeverity(Enum):
    MUST = "must"         # RFC 2119 MUST → 违反即 CRITICAL
    SHOULD = "should"     # RFC 2119 SHOULD → 违反即 HIGH
    MAY = "may"           # RFC 2119 MAY → INFO
    CUSTOM = "custom"     # 自定义规则


@dataclass
class RfcRule:
    rule_id: str = ""
    rfc_number: int = 0
    section: str = ""              # RFC 章节号
    keyword: RfcSeverity = RfcSeverity.MUST
    description: str = ""          # 规则的自然语言描述
    check_field: str = ""          # 要检查的协议字段名
    expected: Any = None           # 期望值或范围 (min, max) 或 callable
    violation_message: str = ""


@dataclass
class RfcViolation:
    rule: RfcRule
    observed_value: Any = None
    packet_offset: int = 0
    detail: str = ""


class RfcRuleLibrary:
    """RFC 规则库 —— 常见协议的关键 RFC 约束模板。

    每条规则来自对应 RFC 的 MUST/SHOULD 语句。
    规则按协议分组，支持精确值匹配、范围检查、自定义函数断言。
    """

    # TCP (RFC 793, 9293)
    TCP_RULES: List[RfcRule] = [
        RfcRule("TCP-001", 9293, "§3.1", RfcSeverity.MUST,
                "SYN 包的数据偏移字段必须 >=5 (20字节最小头部)",
                "data_offset", (5, 15),
                "数据偏移 <5 表示 TCP 头部被截断"),
        RfcRule("TCP-002", 9293, "§3.1", RfcSeverity.MUST,
                "SYN+ACK 必须同时置位 SYN 和 ACK 标志",
                "flags", lambda f: (f & 0x12) == 0x12,
                "SYN+ACK 缺少 SYN 或 ACK 标志位"),
        RfcRule("TCP-003", 9293, "§3.4", RfcSeverity.SHOULD,
                "RST 包不应携带 TCP 选项",
                "data_offset", lambda d: d == 5,
                "RST 包的数据偏移 !=5 —— 存在 TCP 选项异常"),
        RfcRule("TCP-004", 9293, "§3.8", RfcSeverity.MUST,
                "窗口大小字段不能为零（零窗口探测除外）",
                "window", (1, 65535),
                "窗口大小为 0 —— 可能为拒绝服务"),
    ]

    # DNS (RFC 1035, 6891)
    DNS_RULES: List[RfcRule] = [
        RfcRule("DNS-001", 1035, "§4.1.1", RfcSeverity.MUST,
                "DNS 头部的 QR 位在查询时必须为 0",
                "qr_flag", 0,
                "DNS 查询的 QR 位非 0"),
        RfcRule("DNS-002", 1035, "§4.1.1", RfcSeverity.MUST,
                "DNS 头部的 TC 位在 UDP 上表示截断，TCP 应忽略",
                "tc_flag", lambda f, proto="udp": proto != "udp" or f <= 1,
                "UDP DNS 的 TC 位异常"),
        RfcRule("DNS-003", 1035, "§2.3.4", RfcSeverity.MUST,
                "DNS 域名标签长度不得超过 63 字节",
                "label_len", (1, 63),
                "标签长度超出 RFC 1035 限制 —— 可触发缓冲区溢出"),
        RfcRule("DNS-004", 6891, "§6.1.2", RfcSeverity.SHOULD,
                "EDNS0 的 UDP payload size 应 >= 512",
                "edns_udp_size", (512, 65535),
                "EDNS0 缓冲区大小 <512 —— 不支持 EDNS0 扩展"),
    ]

    # TLS (RFC 8446)
    TLS_RULES: List[RfcRule] = [
        RfcRule("TLS-001", 8446, "§4.1.2", RfcSeverity.MUST,
                "ClientHello.legacy_version 必须为 0x0303 (TLS 1.2)",
                "legacy_version", 0x0303,
                "ClientHello 版本字段非 0x0303"),
        RfcRule("TLS-002", 8446, "§4.2.1", RfcSeverity.MUST,
                "TLS 1.3 ClientHello 必须包含 supported_versions 扩展",
                "supported_versions_present", True,
                "缺少 supported_versions 扩展 —— 无法协商 TLS 1.3"),
        RfcRule("TLS-003", 8446, "§4.1.3", RfcSeverity.SHOULD,
                "ServerHello.random 的最后 8 字节不应为全零或特殊值（降级信号）",
                "random_last8", lambda r: r != b'\x00' * 8 and r != b'\x44\x4f\x57\x4e\x47\x52\x44\x01',
                "ServerHello.random 包含降级信号 —— 可能存在降级攻击"),
    ]

    # QUIC (RFC 9000)
    QUIC_RULES: List[RfcRule] = [
        RfcRule("QUIC-001", 9000, "§17.2", RfcSeverity.MUST,
                "QUIC 长包头的版本字段不能为 0",
                "version", lambda v: v != 0,
                "QUIC 版本为 0 —— 版本协商包与数据包混淆"),
        RfcRule("QUIC-002", 9000, "§17.2", RfcSeverity.MUST,
                "QUIC 连接 ID 长度必须在 0-20 字节之间",
                "cid_len", (0, 20),
                "连接 ID 长度超出 RFC 9000 限制"),
    ]

    # HTTP (RFC 9110, 9112)
    HTTP_RULES: List[RfcRule] = [
        RfcRule("HTTP-001", 9112, "§3", RfcSeverity.MUST,
                "HTTP/1.1 请求行必须以 CRLF 结尾",
                "request_line", lambda r: r.endswith(b"\r\n"),
                "请求行不以 CRLF 结尾"),
        RfcRule("HTTP-002", 9110, "§7.1", RfcSeverity.SHOULD,
                "HTTP 响应应包含 Date 头部",
                "has_date_header", True,
                "HTTP 响应缺少 Date 头部"),
    ]

    @classmethod
    def get_rules(cls, protocol: str) -> List[RfcRule]:
        """按协议名获取规则列表"""
        mapping = {
            "tcp": cls.TCP_RULES, "dns": cls.DNS_RULES,
            "tls": cls.TLS_RULES, "quic": cls.QUIC_RULES,
            "http": cls.HTTP_RULES,
        }
        return mapping.get(protocol.lower(), [])


class RfcComplianceChecker:
    """RFC 合规性校验器 —— 对协议包执行规则库中所有适用规则。

    使用方式：对每个捕获的协议包调用 check()，累积违规列表。
    支持自定义规则扩展 —— 通过 add_rule() 注入领域特定规则。
    """

    def __init__(self):
        self._violations: List[RfcViolation] = []
        self._custom_rules: Dict[str, List[RfcRule]] = defaultdict(list)
        self._stats: Dict[str, int] = Counter()

    def add_rule(self, protocol: str, rule: RfcRule) -> None:
        """注册自定义合规性规则"""
        self._custom_rules[protocol].append(rule)

    def check(self, protocol: str, fields: Dict[str, Any],
              offset: int = 0) -> List[RfcViolation]:
        """对协议字段字典执行合规性检查。返回新违规列表。

        fields 示例: {"data_offset": 7, "flags": 0x02, "window": 8192}
        """
        new_violations = []
        rules = RfcRuleLibrary.get_rules(protocol)
        rules.extend(self._custom_rules.get(protocol, []))

        for rule in rules:
            if rule.check_field not in fields:
                continue

            observed = fields[rule.check_field]
            passed = True

            if rule.expected is None:
                passed = True
            elif isinstance(rule.expected, tuple) and len(rule.expected) == 2:
                lo, hi = rule.expected
                if isinstance(observed, (int, float)):
                    passed = lo <= observed <= hi
                else:
                    passed = True  # 跳过非数值的元组检查
            elif callable(rule.expected):
                try:    passed = rule.expected(observed)
                except Exception: passed = False
            else:
                passed = observed == rule.expected

            if not passed:
                violation = RfcViolation(
                    rule=rule,
                    observed_value=observed,
                    packet_offset=offset,
                    detail=f"期望={rule.expected}, 实际={observed}",
                )
                new_violations.append(violation)
                self._violations.append(violation)
                self._stats[rule.keyword.value] += 1

        return new_violations

    def severity_distribution(self) -> Dict[str, int]:
        """按 RFC 2119 关键词分组的违规统计"""
        dist: Dict[str, int] = defaultdict(int)
        for v in self._violations:
            dist[v.rule.keyword.value] += 1
        return dict(dist)

    def summary(self) -> Dict[str, Any]:
        dist = self.severity_distribution()
        total = len(self._violations)
        critical_violations = [
            v for v in self._violations
            if v.rule.keyword == RfcSeverity.MUST
        ]
        return {
            "total_violations": total,
            "by_severity": dist,
            "critical_count": len(critical_violations),
            "rules_violated": len(set(v.rule.rule_id for v in self._violations)),
            "overall_compliance": "noncompliant" if critical_violations else (
                "partial" if total > 0 else "compliant"
            ),
            "top_violations": [
                {
                    "rule_id": v.rule.rule_id,
                    "rfc": f"RFC {v.rule.rfc_number}",
                    "section": v.rule.section,
                    "severity": v.rule.keyword.value,
                    "observed": str(v.observed_value)[:60],
                    "description": v.rule.description[:120],
                }
                for v in sorted(
                    self._violations,
                    key=lambda x: 0 if x.rule.keyword == RfcSeverity.MUST else 1,
                )[:20]
            ],
        }


def check_rfc_compliance(protocol: str,
                         packet_fields: List[Dict[str, Any]]) -> Dict[str, Any]:
    """批量 RFC 合规性检查入口

    packet_fields: [{"data_offset": 5, "flags": 0x02, ...}, ...]
    """
    checker = RfcComplianceChecker()
    for i, fields in enumerate(packet_fields):
        checker.check(protocol, fields, offset=i)
    return checker.summary()


__all__ = ["RfcComplianceChecker", "RfcRuleLibrary", "RfcRule",
           "RfcViolation", "RfcSeverity", "check_rfc_compliance"]
