# 创建: 2026-06-07 18:10
# 漏洞点三维排序 — 路径可达性 × sink危险度 × 净化强度

"""Vuln Ranker — 基于三维评分的漏洞点优先级排序。

借鉴 Mango 的 TruPoCs 排名思想：
  不是对每个检测结果给出"是/否"的二元判定，
  而是输出有序列表——审查者从排名最高的开始验证。

三维评分：
  R = w1 × reachability_score + w2 × sink_risk_score + w3 × (1 - sanitization_score)

  reachability_score (0..1):
    基于 source→sink 路径的置信度和长度。短路径 + 无净化 → 高分。

  sink_risk_score (0..1):
    基于 sink 类型的基础风险。system()=0.95, printf()=0.6。

  sanitization_score (0..1):
    基于路径上净化操作的组合强度。强净化 → 降低风险分。

权重：w1=0.40, w2=0.35, w3=0.25
  可达性最高权重——"漏洞是否真实可达"比"sink多危险"更重要。
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class VulnCandidate:
    """单个漏洞候选。"""
    patch_id: str = ""
    sink_function: str = ""
    sink_category: str = ""
    sink_address: int = 0
    # 三维评分
    reachability: float = 0.0
    sink_risk: float = 0.0
    sanitization_strength: float = 0.0
    composite_score: float = 0.0
    # 元数据
    source_description: str = ""
    path_length: int = 0
    confidence: float = 0.0
    # 判定
    severity: str = "info"           # critical | high | medium | low | info

    def to_dict(self) -> Dict:
        return {
            'sink': self.sink_function, 'category': self.sink_category,
            'score': round(self.composite_score, 3),
            'reachability': round(self.reachability, 2),
            'sink_risk': round(self.sink_risk, 2),
            'sanitization': round(self.sanitization_strength, 2),
            'severity': self.severity,
            'path_len': self.path_length,
            'source': self.source_description,
        }


@dataclass
class RankReport:
    """漏洞排名报告。"""
    function_name: str = ""
    candidates: List[VulnCandidate] = field(default_factory=list)
    total_detected: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'total': self.total_detected,
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'top_candidates': [c.to_dict() for c in self.candidates[:10]],
        }


class VulnRanker:
    """三维漏洞评分与排序引擎。

    权重可由用户通过构造函数自定义。
    默认权重基于 Mango 论文的发现：reachability 是误报减少的最大贡献者。
    """

    def __init__(self, w_reach: float = 0.40,
                 w_risk: float = 0.35,
                 w_san: float = 0.25):
        self.w_reach = w_reach
        self.w_risk = w_risk
        self.w_san = w_san

    def rank(self, dangerous_paths: List,
             sink_risks: Dict[str, float] = None,
             sanitization_scores: Dict[str, float] = None) -> RankReport:
        """对检测结果排序并输出结构化报告。"""
        sink_risks = sink_risks or {}
        sanitization_scores = sanitization_scores or {}

        report = RankReport()
        candidates = []

        for path in dangerous_paths:
            # reachability: 路径越短、置信越高 → 分数越大
            reach = path.confidence * (1.0 - min(path.length / 30.0, 0.8))

            # sink_risk: 从映射表获取，默认 0.5
            risk = sink_risks.get(path.sink_function, 0.5)

            # sanitization: 从映射表获取，默认 0
            san = sanitization_scores.get(path.sink_function, 0.0)

            composite = (self.w_reach * reach +
                        self.w_risk * risk +
                        self.w_san * (1.0 - san))

            # 严重级别
            if composite >= 0.80:
                severity = "critical"
            elif composite >= 0.60:
                severity = "high"
            elif composite >= 0.35:
                severity = "medium"
            elif composite >= 0.15:
                severity = "low"
            else:
                severity = "info"

            candidates.append(VulnCandidate(
                sink_function=path.sink_function,
                sink_category="unknown",
                reachability=reach, sink_risk=risk,
                sanitization_strength=san,
                composite_score=composite,
                source_description=path.source_location,
                path_length=path.length,
                confidence=path.confidence,
                severity=severity))

        # 按 composite_score 降序排列
        candidates.sort(key=lambda c: -c.composite_score)
        report.candidates = candidates
        report.total_detected = len(candidates)
        report.critical_count = sum(1 for c in candidates if c.severity == 'critical')
        report.high_count = sum(1 for c in candidates if c.severity == 'high')
        report.medium_count = sum(1 for c in candidates if c.severity == 'medium')
        report.low_count = sum(1 for c in candidates if c.severity == 'low')

        return report

    @staticmethod
    def default_sink_risks() -> Dict[str, float]:
        """sink 类型的基础风险分。基于 CWE/CVSS 和 Mango 论文。"""
        return {
            'system': 0.95, 'popen': 0.90, 'execve': 0.95, 'execvp': 0.95,
            'strcpy': 0.90, 'strcat': 0.85, 'wcscpy': 0.85,
            'sprintf': 0.85, 'vsprintf': 0.85,
            'memcpy': 0.70, 'memmove': 0.65,
            'printf': 0.60, 'fprintf': 0.55, 'syslog': 0.55,
            'malloc': 0.30, 'calloc': 0.25, 'realloc': 0.40,
            'free': 0.50, 'delete': 0.50,
            'strncpy': 0.40, 'strncat': 0.35,
        }
