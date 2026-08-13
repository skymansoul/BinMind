avg_severity=None
binary_count=None
info_count=None
low_count=None
medium_count=None
high_count=None
critical_count=None
total_vulnerabilities=None
timestamp: str = ""
import os
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass, field

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from enum import Enum

logger = logging.getLogger(__name__)

class TrendPeriod:
    """Time period enumeration."""
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
    timestamp
    total_vulnerabilities
    critical_count
    high_count
    medium_count
    low_count
    info_count
    binary_count
    avg_severity
    
@dataclass
class TrendAnalysisResult:
    period
    trends
    summary
    anomalies

@dataclass
class AnalysisRecord:
    record_id
    timestamp
    binary_path
    binary_hash
    binary_version
    results
    vulnerability_count
    severity_distribution

class TrendTracker(BaseAnalyzer):
    """
    Analysis results time-series tracker.

    Stores historical analysis results, computes vulnerability trends,
    generates trend reports.
    """

    def __init__(self, database_path: str = "data/trend_tracker.db"):
        """
        Initialize trend tracker with database at the given path.
        """
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_database()

    def _init_database(self):
        """Initialize database schema and indexes."""
        conn = sqlite3.connect(str(self.database_path))

        cursor = conn.cursor()

        # Create analysis records table
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

        # Create aggregated trend data table
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
                created_at TEXT
            )
        ''')

        # Create indexes for efficient queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_records_timestamp ON analysis_records(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_records_hash ON analysis_records(binary_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_trend_period ON trend_data(period, period_start)')

        conn.commit()
        conn.close()

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        Execute trend analysis for the given period and filters.
        """
        period = kwargs.get('period', 'weekly')
        start_date = kwargs.get('start_date')
        end_date = kwargs.get('end_date')
        binary_hash = kwargs.get('binary_hash')

        try:
            trend_period = TrendPeriod(period.lower())

        except ValueError:
            return {'success': False, 'error': f"Invalid time period: {period}"}

        result = self.get_trend_analysis(trend_period, start_date, end_date, binary_hash)

        return {
            'success': True,
            'period': period,
            'start_date': start_date,
            'end_date': end_date,
            'trends': [t.__dict__ for t in result.trends],
            'summary': result.summary,
            'anomalies': result.anomalies
        }

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="TrendTracker",
            type=AnalyzerType.OTHER,
            version="1.0.0",
            description="Time-series tracker for analysis results. Plots vulnerability density and severity trends.",
            author="BinaryAnalysisPlatform",
            supported_platforms=["all"])

    def store_analysis_result(self,
        binary_path: str,
        binary_hash: str,
        results: Dict[str, Any],
        binary_version: str = None
    ) -> str:
        """
        Persist analysis results and update trend data.
        Returns the generated record ID.
        """
        record_id = self._generate_record_id()
        timestamp = datetime.now().isoformat()

        # Count vulnerabilities and aggregate severity distribution
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
            ''', (
                record_id,
                timestamp,
                binary_path,
                binary_hash,
                binary_version or '',
                json.dumps(results, ensure_ascii=False),
                vuln_count,
                json.dumps(severity_dist),
                timestamp
            ))

            conn.commit()
            logger.info(f"[TrendTracker] Analysis record stored: {record_id}")

            # Refresh trend data aggregates
            self._update_trend_data()

            return record_id

        except sqlite3.IntegrityError:
            logger.warning(f"[TrendTracker] Record already exists: {record_id}")
            return record_id
        except Exception as e:
            logger.error(f"[TrendTracker] Record storage failed: {e}")
            raise
        finally:
            conn.close()

    def get_record_by_id(self, record_id: str) -> Optional[AnalysisRecord]:
        """
        Retrieve a single analysis record by its unique record ID.
        Returns None if not found.
        """
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
            record_id=row[0],
            timestamp=datetime.fromisoformat(row[1]),
            binary_path=row[2],
            binary_hash=row[3],
            binary_version=row[4] if row[4] else None,
            results=json.loads(row[5]),
            vulnerability_count=row[6],
            severity_distribution=json.loads(row[7]))

    def get_trend_analysis(self,
        period: TrendPeriod,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        binary_hash: Optional[str] = None
    ) -> TrendAnalysisResult:
        """
        Compute trend analysis: fetches data, calculates summary, detects anomalies.
        """
        trends = self._fetch_trend_data(period, start_date, end_date, binary_hash)
        summary = self._calculate_summary(trends)
        anomalies = self._detect_anomalies(trends)

        return TrendAnalysisResult(
            period=period,
            trends=trends,
            summary=summary,
            anomalies=anomalies)

    def _fetch_trend_data(self,
        period: TrendPeriod,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        binary_hash: Optional[str] = None
    ) -> List[VulnerabilityTrend]:
        """
        Query trend data from database, group by period, return aggregated VulnerabilityTrends.
        """
        conn = sqlite3.connect(str(self.database_path))

        cursor = conn.cursor()

        query = '''
            SELECT timestamp, vulnerability_count, severity_distribution
            FROM analysis_records
            WHERE 1=1
        '''
        params = []

        if binary_hash:
            query += ' AND binary_hash = ?'
            params.append(binary_hash)

        if start_date:
            query += ' AND timestamp >= ?'
            params.append(start_date)

        if end_date:
            query += ' AND timestamp <= ?'
            params.append(end_date)

        query += ' ORDER BY timestamp ASC'

        cursor.execute(query, params)

        rows = cursor.fetchall()
        conn.close()

        # Group records by period key
        period_groups = {}

        for row in rows:
            timestamp = datetime.fromisoformat(row[0])
            vuln_count = row[1]
            severity_dist = json.loads(row[2])

            period_key = self._get_period_key(timestamp, period)

            if period_key not in period_groups:
                period_groups[period_key] = {
                    'timestamps': [],
                    'vuln_counts': [],
                    'severity_dists': []
                }

            period_groups[period_key]['timestamps'].append(timestamp)
            period_groups[period_key]['vuln_counts'].append(vuln_count)
            period_groups[period_key]['severity_dists'].append(severity_dist)

        # Compute aggregate values per period group
        trends = []
        for period_key, data in sorted(period_groups.items()):
            avg_timestamp = data['timestamps'][len(data['timestamps']) // 2]

            total_vulns = sum(data['vuln_counts'])
            binary_count = len(data['timestamps'])

            # Aggregate severity distribution across records
            agg_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for dist in data['severity_dists']:
                for key in agg_severity:
                    agg_severity[key] += dist.get(key, 0)

            # Weighted average severity (critical=4, high=3, medium=2, low=1, info=0)
            total_weight = agg_severity['critical'] * 4 + agg_severity['high'] * 3 + \
                          agg_severity['medium'] * 2 + agg_severity['low'] * 1
            avg_severity = total_weight / total_vulns if total_vulns > 0 else 0.0

            trends.append(VulnerabilityTrend(
                timestamp=avg_timestamp,
                total_vulnerabilities=total_vulns,
                critical_count=agg_severity['critical'],
                high_count=agg_severity['high'],
                medium_count=agg_severity['medium'],
                low_count=agg_severity['low'],
                info_count=agg_severity['info'],
                binary_count=binary_count,
                avg_severity=avg_severity
            ))

        return trends

    def _get_period_key(self, timestamp: datetime, period: TrendPeriod) -> str:
        """
        Map a timestamp to its period key string based on the trend period.
        """
        if period == TrendPeriod.DAILY:
            return timestamp.strftime('%Y-%m-%d')
        elif period == TrendPeriod.WEEKLY:
            year, week, _ = timestamp.isocalendar()
            return f'{year}-W{week:02d}'
        elif period == TrendPeriod.MONTHLY:
            return timestamp.strftime('%Y-%m')
        elif period == TrendPeriod.YEARLY:
            return str(timestamp.year)
        else:
            return timestamp.strftime('%Y-%m-%d')

    def _calculate_summary(self, trends: List[VulnerabilityTrend]) -> Dict[str, Any]:
        """
        Compute summary statistics from trend data points.
        """
        if not trends:
            return {
                'total_periods': 0,
                'total_vulnerabilities': 0,
                'avg_vulnerabilities_per_period': 0,
                'max_vulnerabilities': 0,
                'min_vulnerabilities': 0,
                'avg_severity': 0.0,
                'trend_direction': 'stable',
                'change_percentage': 0.0
            }

        total_vulns = sum(t.total_vulnerabilities for t in trends)
        avg_vulns = total_vulns / len(trends)
        max_vulns = max(t.total_vulnerabilities for t in trends)
        min_vulns = min(t.total_vulnerabilities for t in trends)
        avg_severity = sum(t.avg_severity for t in trends) / len(trends)

        # Determine trend direction (increasing/decreasing/stable)
        trend_direction = 'stable'
        change_percentage = 0.0

        if len(trends) >= 2:
            first = trends[0].total_vulnerabilities
            last = trends[-1].total_vulnerabilities

            if first > 0:
                change_percentage = ((last - first) / first) * 100

                if change_percentage > 10:
                    trend_direction = 'increasing'
                elif change_percentage < -10:
                    trend_direction = 'decreasing'

        return {
            'total_periods': len(trends),
            'total_vulnerabilities': total_vulns,
            'avg_vulnerabilities_per_period': avg_vulns,
            'max_vulnerabilities': max_vulns,
            'min_vulnerabilities': min_vulns,
            'avg_severity': avg_severity,
            'trend_direction': trend_direction,
            'change_percentage': change_percentage,
            'critical_count': sum(t.critical_count for t in trends),
            'high_count': sum(t.high_count for t in trends),
            'medium_count': sum(t.medium_count for t in trends),
            'low_count': sum(t.low_count for t in trends),
            'info_count': sum(t.info_count for t in trends),
            'total_binaries': sum(t.binary_count for t in trends)
        }

    def _detect_anomalies(self, trends: List[VulnerabilityTrend]) -> List[Dict[str, Any]]:
        """
        Detect anomalous data points using statistical deviation analysis.
        """
        anomalies = []

        if len(trends) < 5:
            return anomalies

        # Compute mean and standard deviation of vulnerability counts
        vuln_counts = [t.total_vulnerabilities for t in trends]
        mean = sum(vuln_counts) / len(vuln_counts)
        variance = sum((x - mean) ** 2 for x in vuln_counts) / len(vuln_counts)
        std_dev = variance ** 0.5

        # Flag points exceeding 3 sigma from the mean
        threshold = 3 * std_dev

        for trend in trends:
            if abs(trend.total_vulnerabilities - mean) > threshold:
                anomalies.append({
                    'timestamp': trend.timestamp.isoformat(),
                    'value': trend.total_vulnerabilities,
                    'mean': mean,
                    'deviation': abs(trend.total_vulnerabilities - mean),
                    'type': 'spike' if trend.total_vulnerabilities > mean else 'drop',
                    'severity': 'high' if abs(trend.total_vulnerabilities - mean) > 5 * std_dev else 'medium'
                })

        return anomalies

    def _update_trend_data(self):
        """Rebuild aggregated trend data from all analysis records."""
        conn = sqlite3.connect(str(self.database_path))

        cursor = conn.cursor()

        # Clear stale aggregate data
        cursor.execute('DELETE FROM trend_data')

        # Recompute aggregates across all periods
        for period in TrendPeriod:
            cursor.execute('''
                SELECT timestamp, vulnerability_count, severity_distribution
                FROM analysis_records
                ORDER BY timestamp ASC
            ''')

            rows = cursor.fetchall()
            period_groups = {}

            for row in rows:
                timestamp = datetime.fromisoformat(row[0])
                vuln_count = row[1]
                severity_dist = json.loads(row[2])

                period_key = self._get_period_key(timestamp, period)

                if period_key not in period_groups:
                    period_groups[period_key] = {
                        'timestamps': [],
                        'vuln_counts': [],
                        'severity_dists': []
                    }

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
                     avg_severity, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    period.value,
                    period_key,
                    total_vulns,
                    agg_severity['critical'],
                    agg_severity['high'],
                    agg_severity['medium'],
                    agg_severity['low'],
                    agg_severity['info'],
                    binary_count,
                    avg_severity,
                    datetime.now().isoformat()
                ))

        conn.commit()
        conn.close()

    def _generate_record_id(self) -> str:
        """Generate a unique record ID from the current timestamp."""
        timestamp = datetime.now().isoformat()
        import hashlib
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]

    def get_all_records(self) -> List[AnalysisRecord]:
        # Retrieve all analysis records ordered by timestamp descending
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
                record_id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                binary_path=row[2],
                binary_hash=row[3],
                binary_version=row[4] if row[4] else None,
                results=json.loads(row[5]),
                vulnerability_count=row[6],
                severity_distribution=json.loads(row[7])
            ))

        return records

    def generate_trend_report(self, period: TrendPeriod = TrendPeriod.WEEKLY) -> str:
        """
        Generate a markdown-formatted trend report for the given period.
        """
        result = self.get_trend_analysis(period)

        lines = [
            f"# Vulnerability Trend Analysis Report",
            "",
            f"**Generated at**: {datetime.now().isoformat()}"
        ]

        if result.trends:
            lines.extend([
                "",
                "## Trend Overview",
                "",
                f"- Analysis period: {period.value}",
                f"- Total periods: {result.summary['total_periods']}",
                f"- Total binaries: {result.summary['total_binaries']}",
                f"- Total vulnerabilities: {result.summary['total_vulnerabilities']}",
                f"- Avg vulnerabilities per period: {result.summary['avg_vulnerabilities_per_period']:.1f}",
                f"- Trend direction: {result.summary['trend_direction']} ({result.summary['change_percentage']:.1f}%)",
                "",
                "## Distribution by Severity",
                "",
                "| Severity | Count |",
                "|------|------|",
                f"| Critical | {result.summary['critical_count']} |",
                f"| High | {result.summary['high_count']} |",
                f"| Medium | {result.summary['medium_count']} |",
                f"| Low | {result.summary['low_count']} |",
                f"| Info | {result.summary['info_count']} |",
                "",
                "## Trend Data",
                "",
                "| Timestamp | Total | Critical | High | Medium | Low | Info | Binaries |",
                "|------|----------|------|-----|-----|-----|------|----------|"
            ])

            for trend in result.trends:
                lines.append(
                    f"| {trend.timestamp.strftime('%Y-%m-%d')} | {trend.total_vulnerabilities} | "
                    f"{trend.critical_count} | {trend.high_count} | {trend.medium_count} | "
                    f"{trend.low_count} | {trend.info_count} | {trend.binary_count} |")

            if result.anomalies:
                lines.extend([
                    "",
                    "## Anomaly Detection",
                    "",
                    "| Timestamp | Type | Deviation | Severity |",
                    "|------|----------|--------|----------|"
                ])

                for anomaly in result.anomalies:
                    lines.append(
                        f"| {anomaly['timestamp']} | {anomaly['type']} | "
                        f"{anomaly['deviation']:.1f} | {anomaly['severity']} |")

        else:
            lines.append("\nNo trend data available.")

        return "\n".join(lines)
