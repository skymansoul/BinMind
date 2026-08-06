# 跨层MAC/IP绑定一致性验证 —— 多源ARP/DHCP/NDP/CAM交叉检验。
#
# ARP欺骗攻击在L2注入虚假MAC-IP映射, 传统检测仅监控ARP流量
# 的异常模式(如无故ARP)。攻击者可模拟正常ARP流量绕过。
#
# 本模块从OSI四层独立收集MAC-IP绑定证据:
#   L2 CAM表: 交换机端口↔MAC地址
#   L2 ARP表: MAC↔IPv4
#   L2 NDP表: MAC↔IPv6
#   L3 DHCP绑定: MAC↔IPv4+租约
#   L4 TCP连接: (MAC,IP,Port) 元组持续存在→证实绑定有效
#
# 一致性模型: 对每个IP, 从四个源收集其声称的MAC, 投票判定
# 不一致的源标记为潜在ARP欺骗。多源交叉验证的核心假设:
# 攻击者无法同时控制CAM/DHCP/NDP/TCP四个观测平面。
#
# 未见2024-2025文献涉及四层交叉验证用于ARP欺骗检测。

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class MacIpBinding:
    """单源的MAC-IP绑定证据"""
    ip_address: str
    mac_address: str
    source: str          # "arp"/"dhcp"/"ndp"/"cam"/"tcp_flow"
    timestamp: float
    confidence: float    # [0,1] 该源自身的可信度
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsistencyVerdict:
    """单个IP的一致性判定"""
    ip_address: str
    claimed_macs: Dict[str, str]  # {source → mac}
    consensus_mac: str            # 多数投票结果
    inconsistent_sources: List[str]
    is_spoofed: bool
    spoof_confidence: float       # [0,1]
    evidence_summary: str = ""


@dataclass
class CrossLayerReport:
    """跨层验证完整报告"""
    total_ips_checked: int
    consistent_ips: int
    spoofed_ips: int
    verdicts: List[ConsistencyVerdict]
    # 全局统计
    source_reliability: Dict[str, float]  # {source → 与其他源一致的比率}


class CrossLayerVerifier:
    """跨层MAC-IP绑定一致性验证器。

    对每个IP收集来自arp/dhcp/ndp/cam/tcp_flow的MAC绑定,
    多数投票(≥2源同意)确定共识MAC。单个源与共识不一致→
    标记为不一致(可能被欺骗或该源的数据过期)。
    """

    def __init__(self, min_sources_for_consensus: int = 2):
        self._min_consensus = min_sources_for_consensus
        self._bindings: Dict[str, Dict[str, MacIpBinding]] = defaultdict(dict)
        # {ip → {source → binding}}
        self._source_stats: Dict[str, Tuple[int, int]] = defaultdict(
            lambda: (0, 0))  # {source: (agree_count, total_count)}

    def add_binding(self, ip: str, mac: str, source: str,
                     confidence: float = 0.8,
                     metadata: Dict[str, Any] = None) -> None:
        """添加一条MAC-IP绑定证据。

        source: "arp"/"dhcp"/"ndp"/"cam"/"tcp_flow"
        confidence: 该源的观测可信度(TCP流>DHCP>ARP>CAM)
        """
        binding = MacIpBinding(
            ip_address=ip, mac_address=mac.upper(),
            source=source, timestamp=time.time(),
            confidence=confidence,
            metadata=metadata or {},
        )
        self._bindings[ip][source] = binding

    def verify(self) -> CrossLayerReport:
        """对所有IP执行跨层一致性验证。"""
        verdicts: List[ConsistencyVerdict] = []
        consistent = 0
        spoofed = 0

        for ip, sources in self._bindings.items():
            if len(sources) < 2:
                continue  # 单源无法做交叉验证

            verdict = self._verify_ip(ip, sources)
            verdicts.append(verdict)
            if verdict.is_spoofed:
                spoofed += 1
            else:
                consistent += 1

        # 源可靠性统计
        reliability = {}
        for src, (agree, total) in self._source_stats.items():
            reliability[src] = round(agree / max(total, 1), 3)

        return CrossLayerReport(
            total_ips_checked=len(verdicts),
            consistent_ips=consistent,
            spoofed_ips=spoofed,
            verdicts=verdicts,
            source_reliability=reliability,
        )

    def _verify_ip(self, ip: str,
                    sources: Dict[str, MacIpBinding]
                    ) -> ConsistencyVerdict:
        mac_votes: Dict[str, List[str]] = defaultdict(list)
        source_to_mac: Dict[str, str] = {}

        for src, binding in sources.items():
            mac = binding.mac_address
            source_to_mac[src] = mac
            mac_votes[mac].append(src)

        # 多数投票: 得票最多的MAC=共识
        sorted_macs = sorted(mac_votes.items(),
                            key=lambda x: (-len(x[1]), x[0]))
        consensus_mac = sorted_macs[0][0]
        consensus_sources = sorted_macs[0][1]
        consensus_count = len(consensus_sources)

        # 不一致源
        inconsistent = []
        for src, mac in source_to_mac.items():
            if mac != consensus_mac:
                inconsistent.append(src)

        # 判定欺骗: 多数≥min_consensus且至少1个不一致源
        is_spoofed = (consensus_count >= self._min_consensus and
                      len(inconsistent) > 0)

        # 置信度: 基于共识比例和不一致源的置信度
        conf = 0.0
        if is_spoofed:
            agree_ratio = consensus_count / len(sources)
            # 若不一致源是TCP/DHCP(高可信源), 置信度更高
            high_conf_sources = {"tcp_flow", "dhcp"}
            inconsistent_conf = sum(
                sources[s].confidence for s in inconsistent
                if s in high_conf_sources
            ) / max(len(inconsistent), 1)
            conf = agree_ratio * 0.5 + inconsistent_conf * 0.5

        # 更新全局源统计
        for src, mac in source_to_mac.items():
            agree_count, total_count = self._source_stats[src]
            if mac == consensus_mac:
                agree_count += 1
            total_count += 1
            self._source_stats[src] = (agree_count, total_count)

        evidence = ""
        if is_spoofed:
            evidence = (f"IP {ip}: 共识MAC={consensus_mac} "
                       f"({', '.join(consensus_sources)}), "
                       f"歧义源: {', '.join(inconsistent)}")

        return ConsistencyVerdict(
            ip_address=ip,
            claimed_macs=source_to_mac,
            consensus_mac=consensus_mac,
            inconsistent_sources=inconsistent,
            is_spoofed=is_spoofed,
            spoof_confidence=round(conf, 3),
            evidence_summary=evidence,
        )


def verify_arp_consistency(
    arp_table: Dict[str, str],
    dhcp_bindings: Dict[str, str],
    tcp_flows: Dict[str, str],
    ndp_table: Dict[str, str] = None,
    cam_table: Dict[str, str] = None,
) -> CrossLayerReport:
    """便捷入口: 多源表→跨层验证→CrossLayerReport。

    各表格式: {ip → mac}, 来源依次为arp/dhcp/tcp_flow/ndp/cam。
    """
    verifier = CrossLayerVerifier()

    for ip, mac in arp_table.items():
        verifier.add_binding(ip, mac, "arp", 0.6)
    for ip, mac in dhcp_bindings.items():
        verifier.add_binding(ip, mac, "dhcp", 0.9)
    for ip, mac in tcp_flows.items():
        verifier.add_binding(ip, mac, "tcp_flow", 0.95)
    for ip, mac in (ndp_table or {}).items():
        verifier.add_binding(ip, mac, "ndp", 0.7)
    for ip, mac in (cam_table or {}).items():
        verifier.add_binding(ip, mac, "cam", 0.5)

    return verifier.verify()


__all__ = [
    "MacIpBinding", "ConsistencyVerdict", "CrossLayerReport",
    "CrossLayerVerifier", "verify_arp_consistency",
]
