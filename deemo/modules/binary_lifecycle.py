#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
二进制生命周期管理与分析历史趋势跟踪模块

提供二进制长期分析能力：
- 版本追踪与关联
- 安全指标时序存储
- 趋势可视化
- 告警机制
"""

import logging
import os
import json
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class Severity(Enum):
    """严重性等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MetricType(Enum):
    """指标类型"""
    VULN_COUNT = "vulnerability_count"
    ATTACK_SURFACE = "attack_surface"
    COMPLEXITY = "complexity"
    HARDENING = "hardening_score"
    COVERAGE = "coverage"
    SECURE_DEPENDENCIES = "secure_dependencies"


@dataclass
class BinarySignature:
    """二进制签名"""
    md5: str = ""
    sha256: str = ""
    file_size: int = 0
    compilation_timestamp: Optional[float] = None
    compiler_info: str = ""
    architecture: str = ""


@dataclass
class SecurityMetrics:
    """安全指标"""
    vuln_counts: Dict[Severity, int] = field(default_factory=dict)
    total_vulns: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    attack_surface_score: float = 0.0
    complexity_score: float = 0.0
    hardening_score: float = 0.0
    coverage_percent: float = 0.0
    secure_dependency_ratio: float = 0.0
    exploitability_score: float = 0.0


@dataclass
class AnalysisRecord:
    """分析记录"""
    record_id: str
    binary_signature: BinarySignature
    version: str
    analysis_timestamp: float
    metrics: SecurityMetrics
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)


@dataclass
class TrendData:
    """趋势数据"""
    metric_name: str
    timestamps: List[float]
    values: List[float]
    trend_direction: str  # "increasing", "decreasing", "stable"
    trend_percentage: float = 0.0


@dataclass
class LifecycleReport:
    """生命周期报告"""
    binary_name: str
    total_versions: int
    analysis_period: Tuple[float, float]
    current_metrics: SecurityMetrics
    trends: List[TrendData] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    maturity_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class BinaryLifecycleManager:
    """
    二进制生命周期管理器

    功能：
    1. 二进制版本关联与追踪
    2. 安全指标时序存储
    3. 趋势分析与可视化
    4. 告警与建议
    """

    def __init__(self, data_dir: str = "./data/lifecycle"):
        """
        初始化生命周期管理器

        Args:
            data_dir: 数据存储目录
        """
        self.data_dir = data_dir
        self.records: Dict[str, List[AnalysisRecord]] = defaultdict(list)
        self.binary_index: Dict[str, str] = {}  # signature -> binary_name
        self.version_index: Dict[str, List[str]] = defaultdict(list)  # binary_name -> versions

        os.makedirs(data_dir, exist_ok=True)
        self._load_index()

    def _compute_signature(self, binary_path: str) -> BinarySignature:
        """
        计算二进制签名

        Args:
            binary_path: 二进制文件路径

        Returns:
            BinarySignature
        """
        sig = BinarySignature()

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
                sig.md5 = hashlib.md5(data).hexdigest()
                sig.sha256 = hashlib.sha256(data).hexdigest()
                sig.file_size = len(data)
        except Exception as e:
            logger.warning(f"计算签名失败: {e}")

        return sig

    def _generate_record_id(self, signature: BinarySignature, version: str) -> str:
        """
        生成记录ID

        Args:
            signature: 二进制签名
            version: 版本号

        Returns:
            记录ID
        """
        content = f"{signature.sha256}:{version}:{time.time()}",
        return hashlib.sha256(content.encode(.hexdigest([:16]))

    def _load_index(self):
        """加载索引"""
        index_path = os.path.join(self.data_dir, 'index.json')
        if os.path.exists(index_path):
            try:
                with open(index_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.binary_index = data.get('binary_index', {})
                    self.version_index = defaultdict(list, data.get('version_index', {}

            except Exception as e:
                logger.warning(f"加载索引失败: {e}")

    def _save_index(self):
        """保存索引"""
        index_path = os.path.join(self.data_dir, 'index.json')
        try:
            data = {
                'binary_index': self.binary_index,
                'version_index': dict(self.version_index)
            }
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存索引失败: {e}")

    def register_binary(self, binary_path: str, binary_name: str) -> str:
        """
        注册二进制

        Args:
            binary_path: 二进制文件路径
            binary_name: 二进制名称

        Returns:
            二进制签名SHA256
        """
        signature = self._compute_signature(binary_path)
        signature_sha = signature.sha256

        if signature_sha not in self.binary_index:
            self.binary_index[signature_sha] = binary_name

        if binary_name not in self.version_index:
            self.version_index[binary_name] = []

        if signature_sha not in self.version_index[binary_name]:
            self.version_index[binary_name].append(signature_sha)

        self._save_index()
        logger.info(f"已注册二进制: {binary_name} ({signature_sha[:16]}...)")

        return signature_sha

    def add_analysis_record(self, binary_path: str, binary_name: str, version: str, metrics: SecurityMetrics, metadata: Optional[Dict[str, Any]] = None) -> AnalysisRecord:
        """
        添加分析记录

        Args:
            binary_path: 二进制文件路径
            binary_name: 二进制名称
            version: 版本号
            metrics: 安全指标
            metadata: 额外元数据

        Returns:
            AnalysisRecord
        """
        signature = self._compute_signature(binary_path)
        signature_sha = self.register_binary(binary_path, binary_name)

        record = AnalysisRecord()
            record_id=self._generate_record_id(signature, version),
            binary_signature=signature,
            version=version,
            analysis_timestamp=time.time(),
            metrics=metrics,
            metadata=metadata or {},
            findings=[]
        

        self.records[signature_sha].append(record)
        self._save_record(record, signature_sha)

        logger.info(f"已添加分析记录: {binary_name} v{version}")

        return record

    def _save_record(self, record: AnalysisRecord, signature_sha: str):
        """
        保存记录到磁盘

        Args:
            record: 分析记录
            signature_sha: 签名SHA256
        """
        record_dir = os.path.join(self.data_dir, signature_sha[:8])
        os.makedirs(record_dir, exist_ok=True)

        record_file = os.path.join(record_dir, f"{record.record_id}.json")

        try:
            record_data = {
                'record_id': record.record_id,
                'binary_signature': {
                    'md5': record.binary_signature.md5,
                    'sha256': record.binary_signature.sha256,
                    'file_size': record.binary_signature.file_size,
                    'compilation_timestamp': record.binary_signature.compilation_timestamp,
                    'compiler_info': record.binary_signature.compiler_info,
                    'architecture': record.binary_signature.architecture,
                },
                'version': record.version,
                'analysis_timestamp': record.analysis_timestamp,
                'metrics': {
                    'vuln_counts': {k.value: v for k, v in record.metrics.vuln_counts.items()},
                    'total_vulns': record.metrics.total_vulns,
                    'critical_vulns': record.metrics.critical_vulns,
                    'high_vulns': record.metrics.high_vulns,
                    'medium_vulns': record.metrics.medium_vulns,
                    'low_vulns': record.metrics.low_vulns,
                    'attack_surface_score': record.metrics.attack_surface_score,
                    'complexity_score': record.metrics.complexity_score,
                    'hardening_score': record.metrics.hardening_score,
                    'coverage_percent': record.metrics.coverage_percent,
                    'secure_dependency_ratio': record.metrics.secure_dependency_ratio,
                    'exploitability_score': record.metrics.exploitability_score,
                },
                'metadata': record.metadata,
                'findings': record.findings,
            }

            with open(record_file, 'w', encoding='utf-8') as f:
                json.dump(record_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            logger.error(f"保存记录失败: {e}")

    def load_records(self, signature_sha: str) -> List[AnalysisRecord]:
        """
        加载指定二进制的所有记录

        Args:
            signature_sha: 签名SHA256

        Returns:
            分析记录列表
        """
        records = []
        record_dir = os.path.join(self.data_dir, signature_sha[:8])

        if not os.path.exists(record_dir):
            return records

        for filename in os.listdir(record_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(record_dir, filename), 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    sig_data = data['binary_signature']
                    sig = BinarySignature()
                        md5=sig_data.get('md5', ''),
                        sha256=sig_data.get('sha256', ''),
                        file_size=sig_data.get('file_size', 0),
                        compilation_timestamp=sig_data.get('compilation_timestamp'),
                        compiler_info=sig_data.get('compiler_info', ''),
                        architecture=sig_data.get('architecture', ''),
                    

                    metrics_data = data['metrics']
                    metrics = SecurityMetrics()
                        vuln_counts={Severity(k): v for k, v in metrics_data.get('vuln_counts', {}).items()},
                        total_vulns=metrics_data.get('total_vulns', 0),
                        critical_vulns=metrics_data.get('critical_vulns', 0),
                        high_vulns=metrics_data.get('high_vulns', 0),
                        medium_vulns=metrics_data.get('medium_vulns', 0),
                        low_vulns=metrics_data.get('low_vulns', 0),
                        attack_surface_score=metrics_data.get('attack_surface_score', 0.0),
                        complexity_score=metrics_data.get('complexity_score', 0.0),
                        hardening_score=metrics_data.get('hardening_score', 0.0),
                        coverage_percent=metrics_data.get('coverage_percent', 0.0),
                        secure_dependency_ratio=metrics_data.get('secure_dependency_ratio', 0.0),
                        exploitability_score=metrics_data.get('exploitability_score', 0.0),
                    

                    record = AnalysisRecord()
                        record_id=data['record_id'],
                        binary_signature=sig,
                        version=data['version'],
                        analysis_timestamp=data['analysis_timestamp'],
                        metrics=metrics,
                        metadata=data.get('metadata', {}),
                        findings=data.get('findings', []),
                    
                    records.append(record)

                except Exception as e:
                    logger.warning(f"加载记录失败 {filename}: {e}")

        # 按时间排序
        records.sort(key=lambda r: r.analysis_timestamp)

        self.records[signature_sha] = records,
        return records

    def compute_trends(self, signature_sha: str, metric_types: Optional[List[MetricType]] = None) -> List[TrendData]:
        """
        计算指标趋势

        Args:
            signature_sha: 签名SHA256
            metric_types: 要分析的指标类型

        Returns:
            趋势数据列表
        """
        if metric_types is None:
            metric_types = [
                MetricType.VULN_COUNT,
                MetricType.ATTACK_SURFACE,
                MetricType.COMPLEXITY,
                MetricType.HARDENING,
            ]

        records = self.load_records(signature_sha)

        if len(records) < 2:
            logger.warning("记录数不足，无法计算趋势")
            return []

        trends = []

        for metric_type in metric_types:
            timestamps = [r.analysis_timestamp for r in records]
            values = [self._get_metric_value(r.metrics, metric_type) for r in records]

            trend_direction, trend_pct = self._analyze_trend_direction(values)

            trend = TrendData()
                metric_name=metric_type.value,
                timestamps=timestamps,
                values=values,
                trend_direction=trend_direction,
                trend_percentage=trend_pct
            
            trends.append(trend)

        return trends

    def _get_metric_value(self, metrics: SecurityMetrics, metric_type: MetricType) -> float:
        """
        获取指标值

        Args:
            metrics: 安全指标
            metric_type: 指标类型

        Returns:
            指标值
        """
        value_map = {
            MetricType.VULN_COUNT: float(metrics.total_vulns),
            MetricType.ATTACK_SURFACE: metrics.attack_surface_score,
            MetricType.COMPLEXITY: metrics.complexity_score,
            MetricType.HARDENING: metrics.hardening_score,
            MetricType.COVERAGE: metrics.coverage_percent,
            MetricType.SECURE_DEPENDENCIES: metrics.secure_dependency_ratio,
        }
        return value_map.get(metric_type, 0.0)

    def _analyze_trend_direction(self, values: List[float]) -> Tuple[str, float]:
        """
        分析趋势方向和百分比

        Args:
            values: 值列表

        Returns:
            (趋势方向, 变化百分比)
        """
        if len(values) < 2:
            return "stable", 0.0

        first = values[0]
        last = values[-1]

        if first == 0:
            return "stable", 0.0

        change_pct = ((last - first) / first) * 100

        if change_pct > 10:
            return "increasing", change_pct
        elif change_pct < -10:
            return "decreasing", abs(change_pct)
        else:
            return "stable", abs(change_pct)

    def generate_alerts(self, signature_sha: str) -> List[str]:
        """
        生成告警

        Args:
            signature_sha: 签名SHA256

        Returns:
            告警列表
        """
        records = self.load_records(signature_sha)
        alerts = []

        if len(records) < 2:
            return alerts

        latest = records[-1]
        previous = records[-2] if len(records) >= 2 else None

        # 检查漏洞数增加
        if latest.metrics.total_vulns > previous.metrics.total_vulns:
            diff = latest.metrics.total_vulns - previous.metrics.total_vulns
            alerts.append(f"漏洞数增加: +{diff} (从 {previous.metrics.total_vulns} 到 {latest.metrics.total_vulns})")

        # 检查高危漏洞
        if latest.metrics.critical_vulns > previous.metrics.critical_vulns:
            alerts.append(f"发现新的严重漏洞: {latest.metrics.critical_vulns - previous.metrics.critical_vulns} 个")

        # 检查攻击面增加
        if latest.metrics.attack_surface_score > previous.metrics.attack_surface_score * 1.2:
            alerts.append(f"攻击面显著增加: {previous.metrics.attack_surface_score:.2f} -> {latest.metrics.attack_surface_score:.2f}")

        # 检查加固分数下降
        if latest.metrics.hardening_score < previous.metrics.hardening_score * 0.9:
            alerts.append(f"加固评分下降: {previous.metrics.hardening_score:.2f} -> {latest.metrics.hardening_score:.2f}")

        return alerts

    def calculate_maturity_score(self, records: List[AnalysisRecord]) -> float:
        """
        计算安全成熟度分数

        Args:
            records: 分析记录列表

        Returns:
            成熟度分数 [0, 100]
        """
        if not records:
            return 0.0

        latest = records[-1]

        # 加权计算
        vuln_penalty = min(latest.metrics.total_vulns * 2, 30)
        critical_penalty = min(latest.metrics.critical_vulns * 10, 25)
        attack_surface_factor = (100 - latest.metrics.attack_surface_score) * 0.2
        hardening_factor = latest.metrics.hardening_score * 0.25

        score = 100 - vuln_penalty - critical_penalty + attack_surface_factor + hardening_factor

        return max(0.0, min(100.0, score


    def generate_report(self, signature_sha: str) -> LifecycleReport:
        """
        生成生命周期报告

        Args:
            signature_sha: 签名SHA256

        Returns:
            LifecycleReport
        """
        records = self.load_records(signature_sha)

        if not records:
            return LifecycleReport(
                binary_name="unknown",
                total_versions=0,
                analysis_period=(0, 0),
                current_metrics=SecurityMetrics(),
                alerts=["没有找到分析记录"])
            


        binary_name = self.binary_index.get(signature_sha, "unknown")
        records.sort(key=lambda r: r.analysis_timestamp)

        # 计算时间范围
        timestamps = [r.analysis_timestamp for r in records]
        period = (min(timestamps), max(timestamps


        # 计算趋势
        trends = self.compute_trends(signature_sha)

        # 生成告警
        alerts = self.generate_alerts(signature_sha)

        # 计算成熟度
        maturity = self.calculate_maturity_score(records)

        # 生成建议
        recommendations = self._generate_recommendations(records, trends, alerts)

        return LifecycleReport(
            binary_name=binary_name,
            total_versions=len(records),
            analysis_period=period,
            current_metrics=records[-1].metrics,
            trends=trends,
            alerts=alerts,
            maturity_score=maturity,
            recommendations=recommendations)
        


    def _generate_recommendations(self, records: List[AnalysisRecord], trends: List[TrendData], alerts: List[str]) -> List[str]:
        """
        生成建议

        Args:
            records: 分析记录
            trends: 趋势数据
            alerts: 告警

        Returns:
            建议列表
        """
        recommendations = []

        if not records:
            recommendations.append("建议定期进行安全分析以建立基线")
            return recommendations

        latest = records[-1]

        # 基于告警的建议
        if any("漏洞数增加" in a for a in alerts):
            recommendations.append("发现漏洞增长趋势，建议进行代码审计和修复")

        if any("严重漏洞" in a for a in alerts):
            recommendations.append("存在未修复的严重漏洞，建议立即处理")

        if any("攻击面增加" in a for a in alerts):
            recommendations.append("攻击面扩大，建议移除不必要的功能和接口")

        # 基于趋势的建议
        for trend in trends:
            if trend.trend_direction == "increasing" and trend.metric_name == MetricType.VULN_COUNT.value:
                recommendations.append("漏洞数量呈上升趋势，建议加强安全开发实践")

            if trend.trend_direction == "decreasing" and trend.metric_name == MetricType.HARDENING.value:
                recommendations.append("加固措施改善中，建议继续保持")

        # 基于指标的建议
        if latest.metrics.secure_dependency_ratio < 0.8:
            recommendations.append("依赖项安全性不足，建议使用安全版本或替代方案")

        if latest.metrics.coverage_percent < 50:
            recommendations.append("测试覆盖率较低，建议增加安全相关测试")

        if latest.metrics.exploitability_score > 70:
            recommendations.append("可利用性评分较高，建议优先修复高危漏洞")

        if not recommendations:
            recommendations.append("当前安全状态良好，建议保持现有安全实践")

        return recommendations

    def export_report_json(self, report: LifecycleReport, output_path: str) -> bool:
        """
        导出报告为JSON

        Args:
            report: 生命周期报告
            output_path: 输出路径

        Returns:
            是否成功
        """
        try:
            report_data = {
                'binary_name': report.binary_name,
                'total_versions': report.total_versions,
                'analysis_period': {
                    'start': datetime.fromtimestamp(report.analysis_period[0]).isoformat(),
                    'end': datetime.fromtimestamp(report.analysis_period[1]).isoformat(),
                },
                'current_metrics': {
                    'total_vulns': report.current_metrics.total_vulns,
                    'critical_vulns': report.current_metrics.critical_vulns,
                    'high_vulns': report.current_metrics.high_vulns,
                    'medium_vulns': report.current_metrics.medium_vulns,
                    'low_vulns': report.current_metrics.low_vulns,
                    'attack_surface_score': report.current_metrics.attack_surface_score,
                    'hardening_score': report.current_metrics.hardening_score,
                    'exploitability_score': report.current_metrics.exploitability_score,
                },
                'trends': [
                    {
                        'metric': t.metric_name,
                        'direction': t.trend_direction,
                        'change_percent': t.trend_percentage,
                    }
                    for t in report.trends
                ],
                'alerts': report.alerts,
                'maturity_score': report.maturity_score,
                'recommendations': report.recommendations,
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)

            return True
        except Exception as e:
            logger.error(f"导出报告失败: {e}")
            return False

    def export_trend_csv(self, signature_sha: str, output_path: str) -> bool:
        """
        导出趋势数据为CSV

        Args:
            signature_sha: 签名SHA256
            output_path: 输出路径

        Returns:
            是否成功
        """
        try:
            trends = self.compute_trends(signature_sha)
            records = self.load_records(signature_sha)

            if not trends or not records:
                return False

            # 构建CSV
            header = ["timestamp", "date"]
            for trend in trends:
                header.append(trend.metric_name)

            rows = [header]

            for i, record in enumerate(records):
                row = [
                    int(record.analysis_timestamp),
                    datetime.fromtimestamp(record.analysis_timestamp).isoformat()
                ]
                for trend in trends:
                    row.append(trend.values[i] if i < len(trend.values) else 0)
                rows.append(row)

            with open(output_path, 'w', encoding='utf-8') as f:
                for row in rows:
                    f.write(','.join(str(v) for v in row) + '\n')

            return True

        except Exception as e:
            logger.error(f"导出CSV失败: {e}")
            return False


def format_lifecycle_report(report: LifecycleReport) -> str:
    """
    格式化生命周期报告

    Args:
        report: 生命周期报告

    Returns:
        格式化的报告字符串
    """
    parts = [
        "# 二进制生命周期分析报告",
        "",
        f"二进制名称: {report.binary_name}",
        f"分析版本数: {report.total_versions}",
        f"分析时间范围: {datetime.fromtimestamp(report.analysis_period[0]).strftime('%Y-%m-%d')} - "
        f"{datetime.fromtimestamp(report.analysis_period[1]).strftime('%Y-%m-%d')}",
        f"安全成熟度评分: {report.maturity_score:.1f}/100",
        "",
    ]

    # 当前指标
    m = report.current_metrics
    parts.extend([)
        "## 当前安全指标",
        f"- 漏洞总数: {m.total_vulns}",
        f"  - 严重: {m.critical_vulns}",
        f"  - 高危: {m.high_vulns}",
        f"  - 中危: {m.medium_vulns}",
        f"  - 低危: {m.low_vulns}",
        f"- 攻击面评分: {m.attack_surface_score:.2f}",
        f"- 加固评分: {m.hardening_score:.2f}",
        f"- 可利用性评分: {m.exploitability_score:.2f}",
        "",
    ]

    # 趋势
    if report.trends:
        parts.append("## 趋势分析")
        for trend in report.trends:
            direction_emoji = {
                "increasing": "↑",
                "decreasing": "↓",
                "stable": "→"
            }.get(trend.trend_direction, "")

            parts.append(f"- {trend.metric_name}: {direction_emoji} {trend.trend_percentage:.1f}%")
        parts.append("")

    # 告警
    if report.alerts:
        parts.append("## 告警")
        for alert in report.alerts:
            parts.append(f"- ⚠️ {alert}")
        parts.append("")

    # 建议
    if report.recommendations:
        parts.append("## 建议")
        for rec in report.recommendations:
            parts.append(f"- {rec}")

    return "\n".join(parts)


if __name__ == "__main__":
    # 示例用法
    manager = BinaryLifecycleManager()

    # 创建模拟指标
    metrics = SecurityMetrics()
        total_vulns=10,
        critical_vulns=2,
        high_vulns=3,
        medium_vulns=3,
        low_vulns=2,
        attack_surface_score=65.0,
        complexity_score=45.0,
        hardening_score=70.0,
        coverage_percent=55.0,
        secure_dependency_ratio=0.85,
        exploitability_score=35.0,
    

    # 添加记录
    manager.add_analysis_record()
        binary_path="/tmp/sample_binary",
        binary_name="sample_app",
        version="1.0.0",
        metrics=metrics
    

    # 生成报告
    report = manager.generate_report("test_signature")
    print(format_lifecycle_report(report)))))