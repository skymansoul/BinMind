#!/usr/bin/env python3
import logging
import os
import json
import sqlite3
import math as _math
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from enum import Enum

logger = logging.getLogger(__name__)

class TrendPeriod(str, Enum):
    """Time period enumeration"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"

class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class VulnerabilityTrend:
    timestamp: datetime = field(default_factory=datetime.now)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    binary_count: int = 0
    avg_severity: float = 0.0

@dataclass
class TrendAnalysisResult:
    period: TrendPeriod = TrendPeriod.WEEKLY
    trends: List[VulnerabilityTrend] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    archetype: str = "unknown"  # GHP 启发的行为——cold_start/early_burst/oscillator/taper

@dataclass
class AnalysisRecord:
    record_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    binary_path: str = ""
    binary_hash: str = ""
    binary_version: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    vulnerability_count: int = 0
    severity_distribution: Dict[str, int] = field(default_factory=dict)


# GHP 启发的趋势预测
# "GitHub PoC Activity an Early Warning System for 漏洞 Risk"
# 核心发现: 前 5-7 天的交互模式足以预测 90 天内的关注度 (Spearman >0.91)
# 将这一方法论应用到漏洞趋势追踪：使用短期窗口（最近 N 个周期）
# 的特征预测未来趋势方向，识别"front-loaded burst"等异常模式


class EngagementArchetype:
    """行为模式原型分类器——识别趋势序列所属的聚类原型
    Leiden 论文识别了五种模式：cold_start, early_burst, oscillator
    steady_taper, front_loaded
    """
    COLD_START = "cold_start"
    EARLY_BURST = "early_burst"
    OSCILLATOR = "oscillator"
    STEADY_TAPER = "steady_taper"
    FRONT_LOADED = "front_loaded"

    @classmethod
    def classify(cls, trends: List[VulnerabilityTrend]) -> str:
        """基于前几个周期的变化率对趋势序列进行原型分类"""
        if len(trends) < 3:
            return cls.COLD_START
        values = [t.total_vulnerabilities for t in trends]
        # 计算变化率序列
        deltas: List[float] = []
        for i in range(1, len(values)):
            if values[i - 1] > 0:
                deltas.append((values[i] - values[i - 1]) / values[i - 1])
        if not deltas:
            return cls.COLD_START
        # 前 30% 周期的变化率 vs 后 70%
        split = max(1, len(deltas) // 3)
        early_delta = sum(abs(d) for d in deltas[:split]) / split
        late_delta = sum(abs(d) for d in deltas[split:]) / max(1, len(deltas) - split)
        # 振荡器：全序列方差高
        variance = sum((d - (sum(deltas) / len(deltas))) ** 2 for d in deltas) / len(deltas)
        if variance > 2.0:
            return cls.OSCILLATOR
        if early_delta > late_delta * 3.0:
            return cls.FRONT_LOADED
        if early_delta > late_delta * 1.5:
            return cls.EARLY_BURST
        if late_delta < 0.1:
            return cls.STEADY_TAPER
        return cls.COLD_START

    @classmethod
    def risk_baseline(cls, archetype: str) -> float:
        """每种原型的基线风险乘数——front_loaded 最高，cold_start 最低
        数值来源于 Leiden 论文的 漏洞利用ation signal 对齐 数据
        """
        return {
            cls.FRONT_LOADED: 3.0,
            cls.EARLY_BURST: 2.0,
            cls.OSCILLATOR: 1.5,
            cls.STEADY_TAPER: 1.0,
            cls.COLD_START: 0.5,
        }.get(archetype, 1.0)


class ShortWindowPredictor:
    """短期窗口预测器——使用最近 N 个周期的特征预测趋势方向
    方法论移植自 Leiden 2025 的 GitHub PoC 预测框架
    发现 5-7 个周期的观测窗口足以产生可靠预测（Spearman >0.91）
    """

    def __init__(self, window_size: int = 6):
        self._window = window_size

    def predict_direction(self, trends: List[VulnerabilityTrend]) -> Tuple[str, float]:
        """预测未来趋势方向及置信度"""
        if len(trends) < self._window:
            return "stable", 0.5
        # 取最近 window 个周期
        recent = trends[-self._window:]
        values = [t.total_vulnerabilities for t in recent]
        # 加权线性趋势——越近的周期权重越大
        n = len(values)
        sum_x, sum_y, sum_xy, sum_x2 = 0.0, 0.0, 0.0, 0.0
        for i in range(n):
            w = (i + 1) / n  # 线性递增权重
            sum_x += i * w
            sum_y += values[i] * w
            sum_xy += i * values[i] * w
            sum_x2 += i * i * w
        denominator = n * sum_x2 - sum_x * sum_x
        if abs(denominator) < 1e-10:
            return "stable", 0.5
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        avg_val = sum(values) / n if n > 0 else 1.0
        norm_slope = slope / avg_val if avg_val > 0 else 0.0
        if norm_slope > 0.15:
            return "increasing", min(abs(norm_slope), 1.0)
        elif norm_slope < -0.15:
            return "decreasing", min(abs(norm_slope), 1.0)
        return "stable", 1.0 - min(abs(norm_slope) / 0.15, 1.0)


# 主类

class TrendTracker(BaseAnalyzer):
    """
    Analysis results time-series tracker
    
    存储 historical analysis results, 计算 漏洞 trends
    构造 trend 报告. 2025 升级: GHP 启发的短期预测+原型分类
    """

    def __init__(self, database_path: str = "data/trend_tracker.db"):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._predictor = ShortWindowPredictor(window_size=6)
        self._archetype_classifier = EngagementArchetype()
        self._init_database()

    def _init_database(self):
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT UNIQUE,
                timestamp TEXT,
                binary_path TEXT,
                binary_hash TEXT,
                binary_version TEXT,
                results TEXT,
                vulnerability_count INTEGER,
                severity_distribution TEXT,
                created_at TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trend_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                period TEXT,
                period_start TEXT,
                total_vulnerabilities INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                info_count INTEGER,
                binary_count INTEGER,
                avg_severity REAL,
                archetype TEXT,
                created_at TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_records_timestamp ON analysis_records(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_records_hash ON analysis_records(binary_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_trend_period ON trend_data(period, period_start)')
        conn.commit()
        conn.close()

    def analyze(self, **kwargs) -> Dict[str, Any]:
        period = kwargs.get('period', 'weekly')
        start_date = kwargs.get('start_date')
        end_date = kwargs.get('end_date')
        binary_hash = kwargs.get('binary_hash')
        try:
            trend_period = TrendPeriod(period.lower())
        except ValueError:
            return {'success': False, 'error': f"Invalid time period: {period}"}

        result = self.get_trend_analysis(trend_period, start_date, end_date, binary_hash)
        # 短期预测
        direction, conf = self._predictor.predict_direction(result.trends)
        archetype = EngagementArchetype.classify(result.trends)
        risk_mult = EngagementArchetype.risk_baseline(archetype)

        return {
            'success': True, 'period': period,
            'start_date': start_date, 'end_date': end_date,
            'trends': [t.__dict__ for t in result.trends],
            'summary': result.summary,
            'anomalies': result.anomalies,
            'prediction': {'direction': direction, 'confidence': conf},
            'archetype': archetype,
            'risk_multiplier': risk_mult,
        }

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="TrendTracker", type=AnalyzerType.OTHER, version="1.0.0",
            description="Time-series tracker for analysis results. Plots vulnerability density and severity trends.",
            author="BinaryAnalysisPlatform", supported_platforms=["all"])

    def store_analysis_result(self, binary_path: str, binary_hash: str,
                               results: Dict[str, Any], binary_version: str = None) -> str:
        record_id = self._generate_record_id()
        timestamp = datetime.now().isoformat()
        vuln_count = 0
        severity_dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        if 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                vuln_count += 1
                severity = vuln.get('severity', 'medium').lower()
                if severity in severity_dist:
                    severity_dist[severity] += 1
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO analysis_records
                (record_id, timestamp, binary_path, binary_hash, binary_version,
                 results, vulnerability_count, severity_distribution, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (record_id, timestamp, binary_path, binary_hash, binary_version or '',
                  json.dumps(results, ensure_ascii=False), vuln_count,
                  json.dumps(severity_dist), timestamp))
            conn.commit()
            logger.info(f"[TrendTracker] Analysis record stored: {record_id}")
            self._update_trend_data()
            return record_id
        except sqlite3.IntegrityError:
            return record_id
        except Exception as e:
            logger.error(f"[TrendTracker] Record storage failed: {e}")
            raise
        finally:
            conn.close()

    def get_record_by_id(self, record_id: str) -> Optional[AnalysisRecord]:
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        cursor.execute('''
            SELECT record_id, timestamp, binary_path, binary_hash, binary_version,
                   results, vulnerability_count, severity_distribution
            FROM analysis_records WHERE record_id = ?
        ''', (record_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return AnalysisRecord(
            record_id=row[0], timestamp=datetime.fromisoformat(row[1]),
            binary_path=row[2], binary_hash=row[3],
            binary_version=row[4] if row[4] else None,
            results=json.loads(row[5]), vulnerability_count=row[6],
            severity_distribution=json.loads(row[7]))

    def get_trend_analysis(self, period: TrendPeriod,
                            start_date: Optional[str] = None,
                            end_date: Optional[str] = None,
                            binary_hash: Optional[str] = None) -> TrendAnalysisResult:
        trends = self._fetch_trend_data(period, start_date, end_date, binary_hash)
        summary = self._calculate_summary(trends)
        anomalies = self._detect_anomalies(trends)
        archetype = EngagementArchetype.classify(trends)
        return TrendAnalysisResult(period=period, trends=trends,
                                   summary=summary, anomalies=anomalies,
                                   archetype=archetype)

    def _fetch_trend_data(self, period: TrendPeriod,
                           start_date: Optional[str] = None,
                           end_date: Optional[str] = None,
                           binary_hash: Optional[str] = None) -> List[VulnerabilityTrend]:
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        query = '''
            SELECT timestamp, vulnerability_count, severity_distribution
            FROM analysis_records WHERE 1=1
        '''
        params = []
        if binary_hash:
            query += ' AND binary_hash = ?'; params.append(binary_hash)
        if start_date:
            query += ' AND timestamp >= ?'; params.append(start_date)
        if end_date:
            query += ' AND timestamp <= ?'; params.append(end_date)
        query += ' ORDER BY timestamp ASC'
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        period_groups = {}
        for row in rows:
            timestamp = datetime.fromisoformat(row[0])
            vuln_count = row[1]
            severity_dist = json.loads(row[2])
            period_key = self._get_period_key(timestamp, period)
            if period_key not in period_groups:
                period_groups[period_key] = {'timestamps': [], 'vuln_counts': [], 'severity_dists': []}
            period_groups[period_key]['timestamps'].append(timestamp)
            period_groups[period_key]['vuln_counts'].append(vuln_count)
            period_groups[period_key]['severity_dists'].append(severity_dist)
        trends = []
        for period_key, data in sorted(period_groups.items()):
            avg_timestamp = data['timestamps'][len(data['timestamps']) // 2]
            total_vulns = sum(data['vuln_counts'])
            binary_count = len(data['timestamps'])
            agg_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for dist in data['severity_dists']:
                for key in agg_severity:
                    agg_severity[key] += dist.get(key, 0)
            total_weight = agg_severity['critical'] * 4 + agg_severity['high'] * 3 + \
                          agg_severity['medium'] * 2 + agg_severity['low'] * 1
            avg_severity = total_weight / total_vulns if total_vulns > 0 else 0.0
            trends.append(VulnerabilityTrend(
                timestamp=avg_timestamp, total_vulnerabilities=total_vulns,
                critical_count=agg_severity['critical'], high_count=agg_severity['high'],
                medium_count=agg_severity['medium'], low_count=agg_severity['low'],
                info_count=agg_severity['info'], binary_count=binary_count,
                avg_severity=avg_severity))
        return trends

    def _get_period_key(self, timestamp: datetime, period: TrendPeriod) -> str:
        if period == TrendPeriod.DAILY:
            return timestamp.strftime('%Y-%m-%d')
        elif period == TrendPeriod.WEEKLY:
            year, week, _ = timestamp.isocalendar()
            return f'{year}-W{week:02d}'
        elif period == TrendPeriod.MONTHLY:
            return timestamp.strftime('%Y-%m')
        elif period == TrendPeriod.YEARLY:
            return str(timestamp.year)
        return timestamp.strftime('%Y-%m-%d')

    def _calculate_summary(self, trends: List[VulnerabilityTrend]) -> Dict[str, Any]:
        if not trends:
            return {'total_periods': 0, 'total_vulnerabilities': 0,
                    'avg_vulnerabilities_per_period': 0, 'max_vulnerabilities': 0,
                    'min_vulnerabilities': 0, 'avg_severity': 0.0,
                    'trend_direction': 'stable', 'change_percentage': 0.0}
        total_vulns = sum(t.total_vulnerabilities for t in trends)
        avg_vulns = total_vulns / len(trends)
        max_vulns = max(t.total_vulnerabilities for t in trends)
        min_vulns = min(t.total_vulnerabilities for t in trends)
        avg_severity = sum(t.avg_severity for t in trends) / len(trends)
        trend_direction = 'stable'; change_percentage = 0.0
        if len(trends) >= 2:
            first = trends[0].total_vulnerabilities
            last = trends[-1].total_vulnerabilities
            if first > 0:
                change_percentage = ((last - first) / first) * 100
                if change_percentage > 10: trend_direction = 'increasing'
                elif change_percentage < -10: trend_direction = 'decreasing'
        return {
            'total_periods': len(trends), 'total_vulnerabilities': total_vulns,
            'avg_vulnerabilities_per_period': avg_vulns, 'max_vulnerabilities': max_vulns,
            'min_vulnerabilities': min_vulns, 'avg_severity': avg_severity,
            'trend_direction': trend_direction, 'change_percentage': change_percentage,
            'critical_count': sum(t.critical_count for t in trends),
            'high_count': sum(t.high_count for t in trends),
            'medium_count': sum(t.medium_count for t in trends),
            'low_count': sum(t.low_count for t in trends),
            'info_count': sum(t.info_count for t in trends),
            'total_binaries': sum(t.binary_count for t in trends)}

    def _detect_anomalies(self, trends: List[VulnerabilityTrend]) -> List[Dict[str, Any]]:
        anomalies = []
        if len(trends) < 5:
            return anomalies
        vuln_counts = [t.total_vulnerabilities for t in trends]
        mean = sum(vuln_counts) / len(vuln_counts)
        variance = sum((x - mean) ** 2 for x in vuln_counts) / len(vuln_counts)
        std_dev = variance ** 0.5
        threshold = 3 * std_dev
        for trend in trends:
            if abs(trend.total_vulnerabilities - mean) > threshold:
                anomalies.append({
                    'timestamp': trend.timestamp.isoformat(),
                    'value': trend.total_vulnerabilities, 'mean': mean,
                    'deviation': abs(trend.total_vulnerabilities - mean),
                    'type': 'spike' if trend.total_vulnerabilities > mean else 'drop',
                    'severity': 'high' if abs(trend.total_vulnerabilities - mean) > 5 * std_dev else 'medium'})
        return anomalies

    def _update_trend_data(self):
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        cursor.execute('DELETE FROM trend_data')
        for period in TrendPeriod:
            cursor.execute('''
                SELECT timestamp, vulnerability_count, severity_distribution
                FROM analysis_records ORDER BY timestamp ASC
            ''')
            rows = cursor.fetchall()
            period_groups = {}
            for row in rows:
                timestamp = datetime.fromisoformat(row[0])
                vuln_count = row[1]; severity_dist = json.loads(row[2])
                period_key = self._get_period_key(timestamp, period)
                if period_key not in period_groups:
                    period_groups[period_key] = {'timestamps': [], 'vuln_counts': [], 'severity_dists': []}
                period_groups[period_key]['timestamps'].append(timestamp)
                period_groups[period_key]['vuln_counts'].append(vuln_count)
                period_groups[period_key]['severity_dists'].append(severity_dist)
            for period_key, data in period_groups.items():
                avg_timestamp = data['timestamps'][len(data['timestamps']) // 2]
                total_vulns = sum(data['vuln_counts'])
                binary_count = len(data['timestamps'])
                agg_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                for dist in data['severity_dists']:
                    for key in agg_severity:
                        agg_severity[key] += dist.get(key, 0)
                total_weight = agg_severity['critical'] * 4 + agg_severity['high'] * 3 + \
                              agg_severity['medium'] * 2 + agg_severity['low'] * 1
                avg_severity = total_weight / total_vulns if total_vulns > 0 else 0.0
                cursor.execute('''
                    INSERT INTO trend_data
                    (period, period_start, total_vulnerabilities, critical_count,
                     high_count, medium_count, low_count, info_count, binary_count,
                     avg_severity, archetype, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (period.value, period_key, total_vulns,
                      agg_severity['critical'], agg_severity['high'],
                      agg_severity['medium'], agg_severity['low'],
                      agg_severity['info'], binary_count, avg_severity,
                      'unknown', datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def _generate_record_id(self) -> str:
        import hashlib
        return hashlib.sha256(datetime.now().isoformat().encode()).hexdigest()[:16]

    def get_all_records(self) -> List[AnalysisRecord]:
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        cursor.execute('''
            SELECT record_id, timestamp, binary_path, binary_hash, binary_version,
                   results, vulnerability_count, severity_distribution
            FROM analysis_records ORDER BY timestamp DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        records = []
        for row in rows:
            records.append(AnalysisRecord(
                record_id=row[0], timestamp=datetime.fromisoformat(row[1]),
                binary_path=row[2], binary_hash=row[3],
                binary_version=row[4] if row[4] else None,
                results=json.loads(row[5]), vulnerability_count=row[6],
                severity_distribution=json.loads(row[7])))
        return records

    def generate_trend_report(self, period: TrendPeriod = TrendPeriod.WEEKLY) -> str:
        result = self.get_trend_analysis(period)
        direction, conf = self._predictor.predict_direction(result.trends)
        archetype = EngagementArchetype.classify(result.trends)
        lines = [
            f"# Vulnerability Trend Analysis Report", "",
            f"**Generated at**: {datetime.now().isoformat()}",
            f"**Archetype**: {archetype} "
            f"(risk multiplier: {EngagementArchetype.risk_baseline(archetype):.1f}x)",
            f"**Prediction**: {direction} (confidence: {conf:.1%})",
        ]
        if result.trends:
            lines.extend([
                "", "## Trend Overview", "",
                f"- Analysis period: {period.value}",
                f"- Total periods: {result.summary['total_periods']}",
                f"- Total binaries: {result.summary['total_binaries']}",
                f"- Total vulnerabilities: {result.summary['total_vulnerabilities']}",
                f"- Avg per period: {result.summary['avg_vulnerabilities_per_period']:.1f}",
                f"- Direction: {result.summary['trend_direction']}",
                "", "## Distribution by Severity", "",
                "| Severity | Count |",
                "|------|------|",
                f"| Critical | {result.summary['critical_count']} |",
                f"| High | {result.summary['high_count']} |",
                f"| Medium | {result.summary['medium_count']} |",
                f"| Low | {result.summary['low_count']} |",
                f"| Info | {result.summary['info_count']} |",
            ])
            if result.anomalies:
                lines.extend(["", "## Anomalies", "",
                    "| Timestamp | Type | Deviation | Severity |",
                    "|------|----------|--------|----------|"])
                for a in result.anomalies:
                    lines.append(f"| {a['timestamp']} | {a['type']} | {a['deviation']:.1f} | {a['severity']} |")
        else:
            lines.append("\nNo trend data available.")
        return "\n".join(lines)
