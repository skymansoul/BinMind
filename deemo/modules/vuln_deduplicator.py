"""
多维漏洞归并与去重模块

对不同分析模块发现的漏洞进行聚类和去重，生成统一的风险条目：
- 基于位置、类型、约束的多维聚类
- 共识评分计算
- 优先级排序
- 报告生成

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                     VulnDeduplicator                         │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
    │  │ Normalizer   │  │ Clusterer    │  │  Scorer      │     │
    │  │ (标准化)      │  │ (聚类)        │  │  (评分)       │     │
    │  └──────────────┘  └──────────────┘  └──────────────┘     │
    │          │                │                │              │
    │          └────────────────┼────────────────┘              │
    │                           ▼                               │
    │                  ┌────────────────┐                        │
    │                  │ Unified Report │                        │
    │                  └────────────────┘                        │
    └─────────────────────────────────────────────────────────────┘

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import hashlib
import json
import re
import os
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod
import math

logger = logging.getLogger(__name__)


class Severity(Enum):
    """严重程度枚举"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    UNKNOWN = "Unknown"


class LocationType(Enum):
    """位置类型枚举"""
    FUNCTION = "function"
    FILE = "file"
    ADDRESS = "address"
    LINE = "line"
    CALLGRAPH = "callgraph"


@dataclass
class Vulnerability:
    """漏洞数据"""
    vuln_id: str
    source_module: str  # 来源模块
    vuln_type: str  # 漏洞类型
    
    # 位置信息
    location: str  # 位置描述
    file_path: Optional[str] = None
    function_name: Optional[str] = None
    line_number: Optional[int] = None
    address: Optional[int] = None
    
    # 严重程度
    severity: str = "Unknown"
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    
    # 描述
    title: str = ""
    description: str = ""
    remediation: Optional[str] = None
    
    # 上下文
    constraints: List[str] = field(default_factory=list)
    call_chain: List[str] = field(default_factory=list)
    taint_sources: List[str] = field(default_factory=list)
    sink_points: List[str] = field(default_factory=list)
    
    # 置信度
    confidence: float = 1.0
    evidence: List[str] = field(default_factory=list)
    
    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    
    # 指纹（用于去重）
    fingerprint: Optional[str] = None
    
    def normalize(self) -> 'NormalizedVulnerability':
        """标准化漏洞"""
        return NormalizedVulnerability.from_vulnerability(self)


@dataclass
class NormalizedVulnerability:
    """标准化漏洞"""
    # 指纹
    fingerprint: str
    
    # 类型标准化
    normalized_type: str
    
    # 位置标准化
    normalized_location: str
    location_type: LocationType
    file_pattern: str  # 文件名模式（去除路径差异）
    function_pattern: str  # 函数名模式（去除差异）
    
    # 严重程度
    severity: Severity
    cvss_score: Optional[float]
    
    # 来源
    source_modules: Set[str] = field(default_factory=set)
    original_count: int = 1
    
    # 原始数据引用
    original_vulns: List[str] = field(default_factory=list)
    
    # 类型变体
    type_variants: List[str] = field(default_factory=list)
    
    @classmethod
    def from_vulnerability(cls, vuln: Vulnerability) -> 'NormalizedVulnerability':
        """从漏洞创建标准化漏洞"""
        # 生成指纹
        fp_parts = [
            vuln.vuln_type.lower(),
            cls._normalize_location(vuln.location),
            cls._normalize_function(vuln.function_name) if vuln.function_name else ""
        ]
        fingerprint = hashlib.sha256(
            "|".join(fp_parts).encode()
        ).hexdigest()[:16]
        
        return cls(
            fingerprint=fingerprint,
            normalized_type=cls._normalize_type(vuln.vuln_type),
            normalized_location=cls._normalize_location(vuln.location),
            location_type=cls._infer_location_type(vuln),
            file_pattern=cls._normalize_path(vuln.file_path) if vuln.file_path else "",
            function_pattern=cls._normalize_function(vuln.function_name) if vuln.function_name else "",
            severity=cls._parse_severity(vuln.severity),
            cvss_score=vuln.cvss_score,
            source_modules={vuln.source_module},
            original_vulns=[]
        )
    
    @classmethod
    def _parse_severity(cls, severity_str: str) -> Severity:
        """解析严重程度（大小写不敏感）"""
        try:
            return Severity(severity_str)
        except ValueError:
            # 大小写不敏感匹配
            for s in Severity:
                if s.value.lower() == severity_str.lower():
                    return s
            return Severity.UNKNOWN
    
    @staticmethod
    def _normalize_type(vuln_type: str) -> str:
        """标准化漏洞类型"""
        type_mapping = {
            'buffer_overflow': 'buffer_overflow',
            'buffer overflow': 'buffer_overflow',
            'bof': 'buffer_overflow',
            'heap overflow': 'heap_overflow',
            'stack overflow': 'stack_overflow',
            'use after free': 'use_after_free',
            'uaf': 'use_after_free',
            'double free': 'double_free',
            'format string': 'format_string',
            'format string vuln': 'format_string',
            'sql injection': 'sql_injection',
            'sqli': 'sql_injection',
            'xss': 'xss',
            'cross site scripting': 'xss',
            'command injection': 'command_injection',
            'rce': 'command_injection',
            'path traversal': 'path_traversal',
            'directory traversal': 'path_traversal',
            'race condition': 'race_condition',
            'toctou': 'race_condition',
            'integer overflow': 'integer_overflow',
            'heap spray': 'heap_spray',
            'null pointer': 'null_pointer_dereference',
            'npe': 'null_pointer_dereference',
            'type confusion': 'type_confusion',
            'information leak': 'information_disclosure',
            'infoleak': 'information_disclosure',
        }
        
        normalized = vuln_type.lower().strip()
        for pattern, standard in type_mapping.items():
            if pattern in normalized:
                return standard
        
        return normalized.replace(' ', '_').replace('-', '_')
    
    @staticmethod
    def _normalize_location(location: str) -> str:
        """标准化位置"""
        # 移除地址和行号的具体值，保留结构
        # 先替换行号，再替换地址，最后处理残留数字
        normalized = re.sub(r':\d+', ':LINE', location)
        normalized = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', normalized)
        normalized = re.sub(r'\b\d+\b', 'N', normalized)
        return normalized.strip()
    
    @staticmethod
    def _normalize_function(func_name: Optional[str]) -> str:
        """标准化函数名"""
        if not func_name:
            return ""
        
        # 移除命名空间、类前缀等
        normalized = func_name
        
        # 移除常见前缀
        for prefix in ['_ZN', '_Z', 'impl::', 'class.', 'struct.']:
            normalized = normalized.replace(prefix, '')
        
        # 移除模板参数
        normalized = re.sub(r'<[^>]+>', '', normalized)
        
        # 移除参数类型
        if '(' in normalized:
            normalized = normalized.split('(')[0]
        
        return normalized.lower().strip()
    
    @staticmethod
    def _normalize_path(path: Optional[str]) -> str:
        """标准化路径"""
        if not path:
            return ""
        
        # 只保留文件名
        return os.path.basename(path)
    
    @staticmethod
    def _infer_location_type(vuln: Vulnerability) -> LocationType:
        """推断位置类型"""
        if vuln.function_name:
            return LocationType.FUNCTION
        elif vuln.file_path and vuln.line_number:
            return LocationType.LINE
        elif vuln.file_path:
            return LocationType.FILE
        elif vuln.address:
            return LocationType.ADDRESS
        else:
            return LocationType.CALLGRAPH


@dataclass
class VulnCluster:
    """漏洞聚类"""
    cluster_id: str
    normalized_vuln: NormalizedVulnerability
    
    # 成员漏洞
    members: List[Vulnerability] = field(default_factory=list)
    member_count: int = 0
    
    # 共识评分
    consensus_severity: Severity = Severity.UNKNOWN
    consensus_score: float = 0.0
    consensus_confidence: float = 0.0
    
    # 来源统计
    source_distribution: Dict[str, int] = field(default_factory=dict)
    
    # 聚合信息
    aggregated_description: str = ""
    aggregated_remediation: List[str] = field(default_factory=list)
    
    def add_member(self, vuln: Vulnerability) -> None:
        """添加成员"""
        self.members.append(vuln)
        self.member_count = len(self.members)
        
        # 更新来源分布
        self.source_distribution[vuln.source_module] = \
            self.source_distribution.get(vuln.source_module, 0) + 1
        
        # 更新标准化漏洞
        self.normalized_vuln.source_modules.add(vuln.source_module)
        self.normalized_vuln.original_vulns.append(vuln.vuln_id)
        self.normalized_vuln.original_count = self.member_count
    
    def calculate_consensus(self) -> None:
        """计算共识评分"""
        if not self.members:
            return
        
        # 严重程度投票（大小写不敏感）
        severity_votes = defaultdict(int)
        for vuln in self.members:
            # 尝试直接匹配，否则做大小写不敏感匹配
            try:
                sev = Severity(vuln.severity)
            except ValueError:
                # 大小写不敏感匹配
                matched = False
                for s in Severity:
                    if s.value.lower() == vuln.severity.lower():
                        sev = s
                        matched = True
                        break
                if not matched:
                    sev = Severity.UNKNOWN
            severity_votes[sev] += 1
        
        # 选择票数最多的
        max_votes = 0
        for sev, votes in severity_votes.items():
            if votes > max_votes:
                self.consensus_severity = sev
                max_votes = votes
        
        # 计算共识分数
        confidence_sum = sum(v.confidence for v in self.members)
        self.consensus_confidence = confidence_sum / self.member_count
        
        # 计算综合评分
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0,
            Severity.UNKNOWN: 0.0
        }
        
        severity_score = severity_weights.get(self.consensus_severity, 0)
        self.consensus_score = severity_score * self.consensus_confidence


@dataclass
class DeduplicationConfig:
    """去重配置"""
    # 相似度阈值
    fingerprint_threshold: float = 0.85  # 指纹相似度
    location_threshold: float = 0.90  # 位置相似度
    type_threshold: float = 0.80  # 类型相似度
    
    # 权重
    fingerprint_weight: float = 0.5
    location_weight: float = 0.3
    type_weight: float = 0.2
    
    # 最小共识要求
    min_source_count: int = 1  # 最少来源数
    min_confidence: float = 0.5  # 最小置信度


class SimilarityCalculator:
    """相似度计算器"""
    
    def __init__(self, config: DeduplicationConfig):
        self.config = config
    
    def calculate_fingerprint_similarity(
        self, 
        fp1: str, 
        fp2: str
    ) -> float:
        """计算指纹相似度"""
        if fp1 == fp2:
            return 1.0
        
        # 使用编辑距离
        distance = self._levenshtein_distance(fp1, fp2)
        max_len = max(len(fp1), len(fp2))
        
        return 1.0 - (distance / max_len) if max_len > 0 else 0.0
    
    def calculate_location_similarity(
        self,
        loc1: str,
        loc2: str,
        func1: Optional[str] = None,
        func2: Optional[str] = None
    ) -> float:
        """计算位置相似度"""
        # 函数名相似度
        func_sim = 0.0
        has_func = bool(func1 and func2)
        if has_func:
            func_sim = self._token_similarity(
                NormalizedVulnerability._normalize_function(func1),
                NormalizedVulnerability._normalize_function(func2)
            )
        
        # 位置描述相似度
        loc_sim = self._token_similarity(
            NormalizedVulnerability._normalize_location(loc1),
            NormalizedVulnerability._normalize_location(loc2)
        )
        
        # 如果没有函数信息，仅使用位置相似度
        if not has_func:
            return loc_sim
        
        return 0.7 * func_sim + 0.3 * loc_sim
    
    def calculate_type_similarity(
        self,
        type1: str,
        type2: str
    ) -> float:
        """计算类型相似度"""
        norm_type1 = NormalizedVulnerability._normalize_type(type1)
        norm_type2 = NormalizedVulnerability._normalize_type(type2)
        
        if norm_type1 == norm_type2:
            return 1.0
        
        # 部分匹配
        if norm_type1 in norm_type2 or norm_type2 in norm_type1:
            return 0.7
        
        # Token 相似度
        return self._token_similarity(norm_type1, norm_type2)
    
    def calculate_overall_similarity(
        self,
        norm1: NormalizedVulnerability,
        norm2: NormalizedVulnerability
    ) -> float:
        """计算综合相似度"""
        fp_sim = self.calculate_fingerprint_similarity(
            norm1.fingerprint, norm2.fingerprint
        )
        
        loc_sim = self.calculate_location_similarity(
            norm1.normalized_location,
            norm2.normalized_location,
            norm1.function_pattern,
            norm2.function_pattern
        )
        
        type_sim = self.calculate_type_similarity(
            norm1.normalized_type,
            norm2.normalized_type
        )
        
        score = (
            fp_sim * self.config.fingerprint_weight +
            loc_sim * self.config.location_weight +
            type_sim * self.config.type_weight
        )
        
        return score
    
    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """编辑距离"""
        if len(s1) < len(s2):
            return SimilarityCalculator._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        return prev_row[-1]
    
    @staticmethod
    def _token_similarity(s1: str, s2: str) -> float:
        """Token 相似度"""
        tokens1 = set(s1.split('_'))
        tokens2 = set(s2.split('_'))
        
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        
        return intersection / union if union > 0 else 0.0


class VulnDeduplicator:
    """
    多维漏洞归并与去重器
    
    核心功能：
    1. 漏洞标准化
    2. 多维聚类
    3. 共识评分
    4. 优先级排序
    5. 统一报告生成
    """
    
    def __init__(self, config: Optional[DeduplicationConfig] = None):
        """
        初始化去重器
        
        Args:
            config: 去重配置
        """
        self.config = config or DeduplicationConfig()
        self.similarity_calc = SimilarityCalculator(self.config)
        self.clusters: Dict[str, VulnCluster] = {}
        self.unified_report: Optional[Dict[str, Any]] = None
    
    def add_vulnerabilities(self, vulns: List[Vulnerability]) -> int:
        """
        添加漏洞进行去重
        
        Args:
            vulns: 漏洞列表
        
        Returns:
            添加的漏洞数量
        """
        added_count = 0
        
        for vuln in vulns:
            # 标准化
            normalized = vuln.normalize()
            
            # 查找匹配的聚类
            matched_cluster = self._find_matching_cluster(normalized)
            
            if matched_cluster:
                matched_cluster.add_member(vuln)
            else:
                # 创建新聚类
                cluster = VulnCluster(
                    cluster_id=f"cluster_{len(self.clusters)}",
                    normalized_vuln=normalized
                )
                cluster.add_member(vuln)
                cluster.calculate_consensus()
                self.clusters[cluster.cluster_id] = cluster
                added_count += 1
        
        return added_count
    
    def _find_matching_cluster(
        self, 
        normalized: NormalizedVulnerability
    ) -> Optional[VulnCluster]:
        """查找匹配的聚类"""
        best_match = None
        best_similarity = 0.0
        
        for cluster in self.clusters.values():
            similarity = self.similarity_calc.calculate_overall_similarity(
                normalized, cluster.normalized_vuln
            )
            
            if similarity > self.config.fingerprint_threshold:
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = cluster
        
        return best_match
    
    def merge_clusters(self) -> List[VulnCluster]:
        """
        合并所有聚类并计算共识评分
        
        Returns:
            合并后的聚类列表
        """
        for cluster in self.clusters.values():
            cluster.calculate_consensus()
        
        return list(self.clusters.values())
    
    def get_filtered_clusters(
        self,
        min_severity: Optional[Severity] = None,
        min_confidence: Optional[float] = None,
        min_sources: Optional[int] = None,
        category: Optional[str] = None
    ) -> List[VulnCluster]:
        """
        获取过滤后的聚类
        
        Args:
            min_severity: 最小严重程度
            min_confidence: 最小置信度
            min_sources: 最少来源数
            category: 类别过滤
        
        Returns:
            过滤后的聚类列表
        """
        clusters = list(self.clusters.values())
        
        if min_severity:
            severity_order = [Severity.UNKNOWN, Severity.INFO, Severity.LOW, Severity.MEDIUM, 
                            Severity.HIGH, Severity.CRITICAL]
            min_idx = severity_order.index(min_severity)
            clusters = [
                c for c in clusters 
                if severity_order.index(c.consensus_severity) >= min_idx
            ]
        
        if min_confidence is not None:
            clusters = [
                c for c in clusters 
                if c.consensus_confidence >= min_confidence
            ]
        
        if min_sources is not None:
            clusters = [
                c for c in clusters 
                if c.member_count >= min_sources
            ]
        
        if category:
            clusters = [
                c for c in clusters 
                if c.normalized_vuln.normalized_type == category
            ]
        
        return clusters
    
    def get_prioritized_report(
        self,
        min_severity: Optional[Severity] = Severity.MEDIUM
    ) -> Dict[str, Any]:
        """
        生成优先级排序的报告
        
        Args:
            min_severity: 最小严重程度
        
        Returns:
            统一报告字典
        """
        # 合并并过滤
        clusters = self.merge_clusters()
        
        severity_filter = min_severity or Severity.INFO
        filtered = self.get_filtered_clusters(min_severity=severity_filter)
        
        # 按优先级排序
        def priority_key(cluster: VulnCluster) -> Tuple[int, float, int]:
            severity_order = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.INFO: 0,
                Severity.UNKNOWN: -1
            }
            return (
                severity_order.get(cluster.consensus_severity, 0),
                cluster.consensus_score,
                -cluster.member_count  # 多数量优先
            )
        
        sorted_clusters = sorted(filtered, key=priority_key, reverse=True)
        
        # 生成报告
        report = {
            'summary': self._generate_summary(sorted_clusters),
            'vulnerabilities': [
                self._cluster_to_report_entry(cluster, idx + 1)
                for idx, cluster in enumerate(sorted_clusters)
            ],
            'statistics': self._generate_statistics(sorted_clusters),
            'timeline': self._generate_timeline(),
            'recommendations': self._generate_recommendations(sorted_clusters)
        }
        
        self.unified_report = report
        return report
    
    def _generate_summary(self, clusters: List[VulnCluster]) -> Dict[str, Any]:
        """生成摘要"""
        severity_counts = defaultdict(int)
        total_vulns = 0
        
        for cluster in clusters:
            severity_counts[cluster.consensus_severity.value] += 1
            total_vulns += cluster.member_count
        
        return {
            'total_unique_vulnerabilities': len(clusters),
            'total_original_vulnerabilities': total_vulns,
            'deduplication_ratio': 1.0 - len(clusters) / total_vulns if total_vulns > 0 else 0,
            'by_severity': dict(severity_counts),
            'high_priority_count': sum(
                1 for c in clusters 
                if c.consensus_severity in [Severity.CRITICAL, Severity.HIGH]
            )
        }
    
    def _cluster_to_report_entry(
        self, 
        cluster: VulnCluster,
        index: int
    ) -> Dict[str, Any]:
        """聚类转报告条目"""
        primary = cluster.members[0]
        
        return {
            'id': f"VULN-{index:04d}",
            'cluster_id': cluster.cluster_id,
            'fingerprint': cluster.normalized_vuln.fingerprint,
            
            # 类型和描述
            'type': cluster.normalized_vuln.normalized_type,
            'title': primary.title or f"{cluster.normalized_vuln.normalized_type.replace('_', ' ').title()} Vulnerability",
            'description': primary.description or cluster.aggregated_description,
            'remediation': cluster.aggregated_remediation or [primary.remediation] if primary.remediation else [],
            
            # 严重程度
            'severity': cluster.consensus_severity.value,
            'cvss_score': cluster.consensus_score,
            'confidence': cluster.consensus_confidence,
            
            # 位置
            'location': {
                'file': primary.file_path,
                'function': primary.function_name,
                'line': primary.line_number,
                'address': hex(primary.address) if primary.address else None
            },
            
            # 来源统计
            'sources': {
                'count': cluster.member_count,
                'modules': list(cluster.source_distribution.keys()),
                'distribution': cluster.source_distribution
            },
            
            # 原始漏洞
            'original_ids': cluster.normalized_vuln.original_vulns,
            
            # 元数据
            'cve_id': primary.cve_id,
            'cwe_id': primary.cwe_id,
            'constraints': primary.constraints,
            'call_chain': primary.call_chain,
            'evidence': primary.evidence
        }
    
    def _generate_statistics(self, clusters: List[VulnCluster]) -> Dict[str, Any]:
        """生成统计信息"""
        if not clusters:
            return {}
        
        # 类型分布
        type_dist = defaultdict(int)
        for c in clusters:
            type_dist[c.normalized_vuln.normalized_type] += 1
        
        # 来源分布
        source_dist = defaultdict(int)
        for c in clusters:
            for src in c.source_distribution:
                source_dist[src] += c.source_distribution[src]
        
        return {
            'type_distribution': dict(type_dist),
            'source_distribution': dict(source_dist),
            'confidence_stats': {
                'avg': sum(c.consensus_confidence for c in clusters) / len(clusters),
                'max': max(c.consensus_confidence for c in clusters),
                'min': min(c.consensus_confidence for c in clusters)
            },
            'consensus_stats': {
                'avg_score': sum(c.consensus_score for c in clusters) / len(clusters)
            }
        }
    
    def _generate_timeline(self) -> List[Dict[str, Any]]:
        """生成时间线"""
        # 简化实现
        return [
            {
                'timestamp': vuln.timestamp,
                'type': 'discovery',
                'description': f"发现 {vuln.vuln_type}"
            }
            for vuln in self._get_all_members()[:100]  # 限制数量
        ]
    
    def _generate_recommendations(self, clusters: List[VulnCluster]) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        critical_count = sum(
            1 for c in clusters 
            if c.consensus_severity == Severity.CRITICAL
        )
        
        if critical_count > 0:
            recommendations.append(
                f"立即修复 {critical_count} 个严重漏洞，这些漏洞可能导致代码执行"
            )
        
        high_count = sum(
            1 for c in clusters 
            if c.consensus_severity == Severity.HIGH
        )
        
        if high_count > 0:
            recommendations.append(
                f"优先修复 {high_count} 个高危漏洞"
            )
        
        # 基于类型的建议
        type_counts = defaultdict(int)
        for c in clusters:
            type_counts[c.normalized_vuln.normalized_type] += 1
        
        most_common = max(type_counts.items(), key=lambda x: x[1], default=(None, 0))
        if most_common[0]:
            recommendations.append(
                f"考虑对 {most_common[1]} 个 {most_common[0].replace('_', ' ')} 类型漏洞进行系统性修复"
            )
        
        return recommendations
    
    def _get_all_members(self) -> List[Vulnerability]:
        """获取所有成员漏洞"""
        members = []
        for cluster in self.clusters.values():
            members.extend(cluster.members)
        return sorted(members, key=lambda v: v.timestamp, reverse=True)
    
    def export_json(self, output_path: str) -> bool:
        """导出为 JSON"""
        if not self.unified_report:
            self.get_prioritized_report()
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.unified_report, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"导出失败: {e}")
            return False
    
    def export_sarif(self, output_path: str) -> bool:
        """导出为 SARIF 格式"""
        if not self.unified_report:
            self.get_prioritized_report()
        
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BinaryAnalysisPlatform",
                        "version": "1.0.0"
                    }
                },
                "results": [
                    {
                        "id": v["id"],
                        "ruleId": v["type"],
                        "level": self._severity_to_sarif_level(v["severity"]),
                        "message": {"text": v["description"]},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": v["location"]["file"] or "unknown"},
                                "region": {"startLine": v["location"]["line"]}
                            }
                        }]
                    }
                    for v in self.unified_report.get("vulnerabilities", [])
                ]
            }]
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"SARIF 导出失败: {e}")
            return False
    
    @staticmethod
    def _severity_to_sarif_level(severity: str) -> str:
        """严重程度转 SARIF 级别"""
        mapping = {
            "Critical": "error",
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Info": "note"
        }
        return mapping.get(severity, "note")


# 辅助函数

def create_deduplicator(config: Optional[DeduplicationConfig] = None) -> VulnDeduplicator:
    """创建去重器"""
    return VulnDeduplicator(config)


def batch_add_vulnerabilities(
    deduplicator: VulnDeduplicator,
    vuln_sources: Dict[str, List[Dict]]
) -> int:
    """
    批量添加漏洞
    
    Args:
        deduplicator: 去重器
        vuln_sources: 漏洞源字典 {module_name: [vuln_dicts]}
    
    Returns:
        添加的漏洞数量
    """
    total_added = 0
    
    for module_name, vulns in vuln_sources.items():
        for vuln_dict in vulns:
            vuln = Vulnerability(
                vuln_id=vuln_dict.get('id', f"{module_name}_{total_added}"),
                source_module=module_name,
                vuln_type=vuln_dict.get('type', 'unknown'),
                location=vuln_dict.get('location', ''),
                file_path=vuln_dict.get('file'),
                function_name=vuln_dict.get('function'),
                line_number=vuln_dict.get('line'),
                severity=vuln_dict.get('severity', 'Unknown'),
                description=vuln_dict.get('description', ''),
                remediation=vuln_dict.get('remediation'),
                confidence=vuln_dict.get('confidence', 1.0)
            )
            total_added += 1
    
    return total_added
