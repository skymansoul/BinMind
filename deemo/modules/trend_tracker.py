"""
分析结果时间序列追踪模块

存储不同版本分析结果，绘制漏洞密度、严重性趋势图。

核心功能：
1. 时间序列存储：使用 SQLite/TimescaleDB 存储历史分析结果
2. 趋势分析：计算漏洞密度、严重性随时间的变化趋势
3. 可视化：生成趋势图表数据
4. 异常检测：识别分析结果的异常波动
5. 报告生成：生成趋势分析报告
"""

import os
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class TrendPeriod(Enum):
    """时间周期枚举"""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"


class SeverityLevel(Enum):
    """漏洞严重性级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnerabilityTrend:
    """漏洞趋势数据点"""
    timestamp: datetime
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    binary_count: int
    avg_severity: float


@dataclass
class TrendAnalysisResult:
    """趋势分析结果"""
    period: TrendPeriod
    trends: List[VulnerabilityTrend]
    summary: Dict[str, Any]
    anomalies: List[Dict[str, Any]]


@dataclass
class AnalysisRecord:
    """单次分析记录"""
    record_id: str
    timestamp: datetime
    binary_path: str
    binary_hash: str
    binary_version: Optional[str]
    results: Dict[str, Any]
    vulnerability_count: int
    severity_distribution: Dict[str, int]


class TrendTracker(BaseAnalyzer):
    """
    分析结果时间序列追踪器
    
    负责存储历史分析结果，分析漏洞趋势，生成趋势报告。
    """
    
    def __init__(self, database_path: str = "data/trend_tracker.db"):
        """
        初始化趋势追踪器
        
        Args:
            database_path: 数据库文件路径
        """
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_database()
    
    def _init_database(self):
        """初始化数据库表"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        # 创建分析记录表
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
        
        # 创建聚合趋势表
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
        
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_records_timestamp ON analysis_records(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_records_hash ON analysis_records(binary_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_trend_period ON trend_data(period, period_start)')
        
        conn.commit()
        conn.close()
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行趋势分析
        
        Args:
            **kwargs: 分析参数
                - period: 时间周期 (daily/weekly/monthly/yearly)
                - start_date: 开始日期 (ISO格式)
                - end_date: 结束日期 (ISO格式)
                - binary_hash: 可选，特定二进制文件的hash
        
        Returns:
            趋势分析结果
        """
        period = kwargs.get('period', 'weekly')
        start_date = kwargs.get('start_date')
        end_date = kwargs.get('end_date')
        binary_hash = kwargs.get('binary_hash')
        
        try:
            trend_period = TrendPeriod(period.lower())
        except ValueError:
            return {'success': False, 'error': f"无效的时间周期: {period}"}
        
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
            description="分析结果时间序列追踪器，绘制漏洞密度、严重性趋势图",
            author="BinaryAnalysisPlatform",
            supported_platforms=["all"]
        )
    
    def store_analysis_result(
        self,
        binary_path: str,
        binary_hash: str,
        results: Dict[str, Any],
        binary_version: str = None
    ) -> str:
        """
        存储分析结果
        
        Args:
            binary_path: 二进制文件路径
            binary_hash: 二进制文件哈希
            results: 分析结果
            binary_version: 二进制版本（可选）
        
        Returns:
            记录ID
        """
        record_id = self._generate_record_id()
        timestamp = datetime.now().isoformat()
        
        # 统计漏洞数量和严重性分布
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
            logger.info(f"[TrendTracker] 分析记录已存储: {record_id}")
            
            # 更新趋势数据
            self._update_trend_data()
            
            return record_id
            
        except sqlite3.IntegrityError:
            logger.warning(f"[TrendTracker] 记录已存在: {record_id}")
            return record_id
        except Exception as e:
            logger.error(f"[TrendTracker] 存储记录失败: {e}")
            raise
        finally:
            conn.close()
    
    def get_record_by_id(self, record_id: str) -> Optional[AnalysisRecord]:
        """
        根据记录ID获取分析记录
        
        Args:
            record_id: 记录ID
        
        Returns:
            AnalysisRecord 对象，不存在返回 None
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
            severity_distribution=json.loads(row[7])
        )
    
    def get_trend_analysis(
        self,
        period: TrendPeriod,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        binary_hash: Optional[str] = None
    ) -> TrendAnalysisResult:
        """
        获取趋势分析结果
        
        Args:
            period: 时间周期
            start_date: 开始日期
            end_date: 结束日期
            binary_hash: 可选，特定二进制文件的hash
        
        Returns:
            TrendAnalysisResult 对象
        """
        trends = self._fetch_trend_data(period, start_date, end_date, binary_hash)
        summary = self._calculate_summary(trends)
        anomalies = self._detect_anomalies(trends)
        
        return TrendAnalysisResult(
            period=period,
            trends=trends,
            summary=summary,
            anomalies=anomalies
        )
    
    def _fetch_trend_data(
        self,
        period: TrendPeriod,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        binary_hash: Optional[str] = None
    ) -> List[VulnerabilityTrend]:
        """
        从数据库获取趋势数据
        
        Args:
            period: 时间周期
            start_date: 开始日期
            end_date: 结束日期
            binary_hash: 可选，特定二进制文件的hash
        
        Returns:
            趋势数据列表
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
        
        # 按周期聚合
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
        
        # 计算聚合值
        trends = []
        for period_key, data in sorted(period_groups.items()):
            avg_timestamp = data['timestamps'][len(data['timestamps']) // 2]
            
            total_vulns = sum(data['vuln_counts'])
            binary_count = len(data['timestamps'])
            
            # 聚合严重性分布
            agg_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for dist in data['severity_dists']:
                for key in agg_severity:
                    agg_severity[key] += dist.get(key, 0)
            
            # 计算平均严重性 (critical=4, high=3, medium=2, low=1, info=0)
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
        获取周期键
        
        Args:
            timestamp: 时间戳
            period: 周期类型
        
        Returns:
            周期键字符串
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
        计算趋势摘要
        
        Args:
            trends: 趋势数据列表
        
        Returns:
            摘要统计信息
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
        
        # 计算趋势方向
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
        检测异常数据点
        
        Args:
            trends: 趋势数据列表
        
        Returns:
            异常点列表
        """
        anomalies = []
        
        if len(trends) < 5:
            return anomalies
        
        # 计算平均漏洞数量和标准差
        vuln_counts = [t.total_vulnerabilities for t in trends]
        mean = sum(vuln_counts) / len(vuln_counts)
        variance = sum((x - mean) ** 2 for x in vuln_counts) / len(vuln_counts)
        std_dev = variance ** 0.5
        
        # 检测超过3倍标准差的异常点
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
        """更新聚合趋势数据"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        # 清空旧的聚合数据
        cursor.execute('DELETE FROM trend_data')
        
        # 重新计算聚合
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
        """生成唯一记录ID"""
        timestamp = datetime.now().isoformat()
        import hashlib
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]
    
    def get_all_records(self) -> List[AnalysisRecord]:
        """获取所有分析记录"""
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
        生成趋势报告
        
        Args:
            period: 时间周期
        
        Returns:
            Markdown格式的报告
        """
        result = self.get_trend_analysis(period)
        
        lines = [
            f"# 漏洞趋势分析报告",
            "",
            f"**生成时间**: {datetime.now().isoformat()}"
        ]
        
        if result.trends:
            lines.extend([
                "",
                "## 趋势概览",
                "",
                f"- 分析周期: {period.value}",
                f"- 总周期数: {result.summary['total_periods']}",
                f"- 分析二进制数: {result.summary['total_binaries']}",
                f"- 总漏洞数: {result.summary['total_vulnerabilities']}",
                f"- 平均每个周期漏洞数: {result.summary['avg_vulnerabilities_per_period']:.1f}",
                f"- 趋势方向: {result.summary['trend_direction']} ({result.summary['change_percentage']:.1f}%)",
                "",
                "## 严重性分布",
                "",
                "| 级别 | 数量 |",
                "|------|------|",
                f"| 严重(Critical) | {result.summary['critical_count']} |",
                f"| 高(High) | {result.summary['high_count']} |",
                f"| 中(Medium) | {result.summary['medium_count']} |",
                f"| 低(Low) | {result.summary['low_count']} |",
                f"| 信息(Info) | {result.summary['info_count']} |",
                "",
                "## 趋势数据",
                "",
                "| 时间 | 漏洞总数 | 严重 | 高 | 中 | 低 | 信息 | 二进制数 |",
                "|------|----------|------|-----|-----|-----|------|----------|"
            ])
            
            for trend in result.trends:
                lines.append(f"| {trend.timestamp.strftime('%Y-%m-%d')} | {trend.total_vulnerabilities} | "
                            f"{trend.critical_count} | {trend.high_count} | {trend.medium_count} | "
                            f"{trend.low_count} | {trend.info_count} | {trend.binary_count} |")
            
            if result.anomalies:
                lines.extend([
                    "",
                    "## 异常检测",
                    "",
                    "| 时间 | 异常类型 | 偏差值 | 严重程度 |",
                    "|------|----------|--------|----------|"
                ])
                
                for anomaly in result.anomalies:
                    lines.append(f"| {anomaly['timestamp']} | {anomaly['type']} | "
                                f"{anomaly['deviation']:.1f} | {anomaly['severity']} |")
        
        else:
            lines.append("\n暂无趋势数据")
        
        return "\n".join(lines)
