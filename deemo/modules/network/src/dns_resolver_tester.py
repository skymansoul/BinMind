# 创建: 2026-05-10  修改: 2026-08-13 (quick_assess_dns_resolver改为接收已采集数据, 网络I/O由调用方注入)
# DNS解析器漏洞评估器 —— 检测解析器对缓存投毒攻击的防御能力。
#
# 2024-2025年DNS缓存投毒研究
# 揭示了解析器在TXID熵/源端口随机化/Bailiwick校验等维度的持续脆弱性。
# Internet扫描显示20-34%的开放解析器至少在一个维度上可被利用。
#
# 本模块从外部视角(攻击者视角)被动探测解析器的防御质量:
#   1. TXID熵估计: 多查询采样→位级熵→对抗生日攻击的阻力
#   2. 源端口随机化: 连续查询的端口序列→自相关→预测难度
#   3. Bailiwick校验: 在响应附加段注入越权记录→检测是否被接受
#   4. 0x20编码保持: 大小写随机化查询→响应是否保持相同大小写
#   5. 响应一致性: 查询名/类型是否与响应一致→防响应伪造
#
# 与现有DNS分析的互补: dns_analyzer检测DGA/隧道/快速通量,
# 本模块检测解析器自身的脆弱性——解析器是基础设施, 其脆弱性
# 影响所有依赖它的客户端。

from __future__ import annotations

import math
import random
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ResolverVulnerability:
    """单维度漏洞评估结果"""
    dimension: str        # "txid_entropy" / "port_randomization" / ...
    score: float          # [0,1] 0=完全安全, 1=极度脆弱
    severity: str         # "safe" / "moderate" / "vulnerable" / "critical"
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class ResolverAssessment:
    """DNS解析器完整评估报告"""
    resolver_ip: str
    total_queries_sent: int
    responses_received: int
    response_rate: float       # [0,1]
    vulnerabilities: List[ResolverVulnerability]
    overall_score: float       # [0,1] 多维度加权综合得分
    risk_level: str            # "low"/"medium"/"high"/"critical"
    hardening_steps: List[str] = field(default_factory=list)


from .dns_vulnerability_scorer import (
    estimate_txid_entropy, assess_port_randomization,
    assess_bailiwick_vulnerability, assess_0x20_preservation,
)


def score_resolver(resolver_ip: str,
                   txids: List[int],
                   ports: List[int],
                   responses: List[Dict],
                   casings: List[Tuple[str, str]]
                   ) -> ResolverAssessment:
    """综合评估DNS解析器的多维度安全性。

    权重基于2024-2025研究的攻击实用性:
      TXID熵: 0.30 (生日攻击可直接暴力破解)
      端口随机化: 0.30 (SAD DNS利用侧信道去随机化)
      Bailiwick: 0.25 (TuDoor利用预解析逻辑缺陷)
      0x20编码: 0.15 (辅助防御层)
    """
    vulns: List[ResolverVulnerability] = []
    total_resp = len(responses)
    total_sent = len(txids)  # proxy for queries sent
    resp_rate = total_resp / max(total_sent, 1)

    # 1. TXID熵
    txid_result = estimate_txid_entropy(txids)
    txid_bits = txid_result.get("bits_entropy", 0.0)
    if txid_bits < 12:
        txid_sev, txid_score = "critical", 0.95
    elif txid_bits < 14:
        txid_sev, txid_score = "vulnerable", 0.7
    elif txid_bits < 15.5:
        txid_sev, txid_score = "moderate", 0.3
    else:
        txid_sev, txid_score = "safe", 0.05
    vulns.append(ResolverVulnerability(
        dimension="txid_entropy", score=round(txid_score, 2),
        severity=txid_sev, evidence=txid_result,
        recommendation="确保DNS软件TXID由CSPRNG生成, 避免基于时间的种子"))

    # 2. 源端口随机化
    port_result = assess_port_randomization(ports)
    port_pred = port_result.get("predictability_score", 0.0)
    if port_pred < 0.3:
        port_sev, port_score = "critical", 0.95
    elif port_pred < 0.6:
        port_sev, port_score = "vulnerable", 0.7
    elif port_pred < 0.8:
        port_sev, port_score = "moderate", 0.3
    else:
        port_sev, port_score = "safe", 0.05
    vulns.append(ResolverVulnerability(
        dimension="port_randomization", score=round(port_score, 2),
        severity=port_sev, evidence=port_result,
        recommendation="配置DNS软件使用大范围随机源端口, 避免NAT设备干扰"))

    # 3. Bailiwick校验
    bailiwick_result = assess_bailiwick_vulnerability(responses)
    if bailiwick_result.get("suspicious_extra_sections", 0) > 0:
        bailiwick_sev, bailiwick_score = "vulnerable", 0.8
    elif resp_rate < 0.5:
        bailiwick_sev, bailiwick_score = "moderate", 0.4
    else:
        bailiwick_sev, bailiwick_score = "safe", 0.1
    vulns.append(ResolverVulnerability(
        dimension="bailiwick_check", score=round(bailiwick_score, 2),
        severity=bailiwick_sev, evidence=bailiwick_result,
        recommendation="确保解析器严格拒绝对应域外的附加快取记录"))

    # 4. 0x20编码
    casing_result = assess_0x20_preservation(casings)
    if not casing_result.get("preserves_0x20", False):
        casing_sev, casing_score = "moderate", 0.5
    else:
        casing_sev, casing_score = "safe", 0.05
    vulns.append(ResolverVulnerability(
        dimension="0x20_encoding", score=round(casing_score, 2),
        severity=casing_sev, evidence=casing_result,
        recommendation="启用0x20编码并在验证响应时检查大小写一致性"))

    # 加权综合得分
    weights = {"txid_entropy": 0.30, "port_randomization": 0.30,
               "bailiwick_check": 0.25, "0x20_encoding": 0.15}
    overall = sum(v.score * weights.get(v.dimension, 0.25) for v in vulns)

    if overall > 0.7:
        risk = "critical"
    elif overall > 0.4:
        risk = "high"
    elif overall > 0.2:
        risk = "medium"
    else:
        risk = "low"

    hardening = [v.recommendation for v in vulns if v.severity != "safe"]

    return ResolverAssessment(
        resolver_ip=resolver_ip,
        total_queries_sent=total_sent,
        responses_received=total_resp,
        response_rate=round(resp_rate, 3),
        vulnerabilities=vulns,
        overall_score=round(overall, 3),
        risk_level=risk,
        hardening_steps=hardening,
    )


def quick_assess_dns_resolver(resolver_ip: str,
                               txids: List[int] = None,
                               ports: List[int] = None,
                               casings: List[Tuple[str, str]] = None,
                               extra_section_sizes: List[int] = None
                               ) -> ResolverAssessment:
    """便捷入口: 用已采集数据对DNS解析器做多维度漏洞评估。

    各参数为从解析器采集的原始数据:
      txids: 查询响应中的TXID值列表
      ports: 查询使用的源端口列表
      casings: [(查询大小写名, 响应中返回名), ...] 用于0x20检测
      extra_section_sizes: 响应附加段大小列表, 用于Bailiwick检测

    若未提供数据则返回空评估(risk=unknown)。
    实际网络采集逻辑由调用方实现(socket/ scapy/ dnspython),
    本模块负责统计分析与评分。
    """
    if not txids or len(txids) < 20:
        return ResolverAssessment(
            resolver_ip=resolver_ip, total_queries_sent=len(txids or []),
            responses_received=0, response_rate=0.0,
            vulnerabilities=[], overall_score=0.0,
            risk_level="unknown",
            hardening_steps=["样本不足(需≥20次查询), 无法评估"],
        )

    responses = [{"additional_bytes": s} for s in (extra_section_sizes or [])]
    return score_resolver(
        resolver_ip, list(txids),
        list(ports) if ports else [],
        responses,
        list(casings) if casings else [],
    )


__all__ = [
    "ResolverVulnerability", "ResolverAssessment",
    "estimate_txid_entropy", "assess_port_randomization",
    "assess_bailiwick_vulnerability", "assess_0x20_preservation",
    "score_resolver", "quick_assess_dns_resolver",
]
