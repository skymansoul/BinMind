import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class StatisticType(Enum):
    VULNERABILITY_DISTRIBUTION = "vulnerability_distribution"
    HIGH_RISK_FUNCTIONS = "high_risk_functions"
    SEVERITY_TREND = "severity_trend"
    ANALYSIS_METRICS = "analysis_metrics"
    EXPLOITABILITY_SCORES = "exploitability_scores"


@dataclass
class VulnerabilityDistribution:
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    by_architecture: Dict[str, int]
    total_vulnerabilities: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'by_type': self.by_type,
            'by_severity': self.by_severity,
            'by_architecture': self.by_architecture,
            'total_vulnerabilities': self.total_vulnerabilities
        }


@dataclass
class HighRiskFunction:
    function_name: str
    vulnerability_count: int
    severity_score: int
    exploitability_score: int
    address: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'vulnerability_count': self.vulnerability_count,
            'severity_score': self.severity_score,
            'exploitability_score': self.exploitability_score,
            'address': hex(self.address)
        }


@dataclass
class SeverityTrend:
    dates: List[str]
    critical: List[int]
    high: List[int]
    medium: List[int]
    low: List[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'dates': self.dates,
            'critical': self.critical,
            'high': self.high,
            'medium': self.medium,
            'low': self.low
        }


@dataclass
class AnalysisMetrics:
    total_analyses: int
    successful_analyses: int
    failed_analyses: int
    average_time: float
    coverage_rate: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_analyses': self.total_analyses,
            'successful_analyses': self.successful_analyses,
            'failed_analyses': self.failed_analyses,
            'average_time': self.average_time,
            'coverage_rate': self.coverage_rate
        }


@dataclass
class APIResponse:
    statistic_type: StatisticType
    data: Dict[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'statistic_type': self.statistic_type.value,
            'data': self.data,
            'timestamp': self.timestamp
        }


class MultiDimensionStatsAPI:
    
    def __init__(self):
        self.vulnerability_types = [
            'buffer_overflow', 'use_after_free', 'format_string',
            'integer_overflow', 'null_deref', 'double_free',
            'stack_overflow', 'heap_overflow', 'race_condition'
        ]
        
        self.severity_levels = ['critical', 'high', 'medium', 'low']
    
    def get_vulnerability_distribution(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        by_type = {vt: 0 for vt in self.vulnerability_types}
        by_severity = {sl: 0 for sl in self.severity_levels}
        by_architecture = {}
        total = 0
        
        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                vuln_type = vuln.get('type', 'unknown')
                severity = vuln.get('severity', 'low')
                arch = analysis.get('architecture', 'unknown')
                
                if vuln_type in by_type:
                    by_type[vuln_type] += 1
                else:
                    by_type[vuln_type] = 1
                
                if severity in by_severity:
                    by_severity[severity] += 1
                
                by_architecture[arch] = by_architecture.get(arch, 0) + 1
                total += 1
        
        distribution = VulnerabilityDistribution()
            by_type=by_type,
            by_severity=by_severity,
            by_architecture=by_architecture,
            total_vulnerabilities=total
        
        
        return APIResponse(
            statistic_type=StatisticType.VULNERABILITY_DISTRIBUTION,
            data=distribution.to_dict(),
            timestamp=self._get_timestamp())
        

    
    def get_high_risk_functions(self, analysis_history: List[Dict[str, Any]], limit: int = 10) -> APIResponse:
        functions = {}
        
        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                func_name = vuln.get('function_name', 'unknown')
                
                if func_name not in functions:
                    functions[func_name] = {
                        'count': 0,
                        'severity_score': 0,
                        'exploitability_score': 0,
                        'address': vuln.get('address', 0)
                    }
                
                functions[func_name]['count'] += 1
                
                severity_map = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
                functions[func_name]['severity_score'] += severity_map.get(vuln.get('severity', 'low'), 1)
                
                functions[func_name]['exploitability_score'] += vuln.get('exploitability_score', 0)
        
        sorted_funcs = sorted(functions.items(), key=lambda x: x[1]['severity_score'], reverse=True)
        
        high_risk = []
        for name, data in sorted_funcs[:limit]:
            high_risk.append(HighRiskFunction(
                function_name=name,
                vulnerability_count=data['count'],
                severity_score=data['severity_score'],
                exploitability_score=data['exploitability_score'],
                address=data['address']
            

        
        return APIResponse(
            statistic_type=StatisticType.HIGH_RISK_FUNCTIONS,
            data=[h.to_dict() for h in high_risk],
            timestamp=self._get_timestamp())
        

    
    def get_severity_trend(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        dates = []
        critical = []
        high = []
        medium = []
        low = []
        
        date_counts = {}
        
        for analysis in analysis_history:
            date = analysis.get('date', 'unknown')
            
            if date not in date_counts:
                date_counts[date] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in analysis.get('vulnerabilities', []):
                severity = vuln.get('severity', 'low')
                date_counts[date][severity] += 1
        
        for date in sorted(date_counts.keys()):
            dates.append(date)
            counts = date_counts[date]
            critical.append(counts['critical'])
            high.append(counts['high'])
            medium.append(counts['medium'])
            low.append(counts['low'])
        
        trend = SeverityTrend()
            dates=dates,
            critical=critical,
            high=high,
            medium=medium,
            low=low
        
        
        return APIResponse(
            statistic_type=StatisticType.SEVERITY_TREND,
            data=trend.to_dict(),
            timestamp=self._get_timestamp())
        

    
    def get_analysis_metrics(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        total = len(analysis_history)
        successful = sum(1 for a in analysis_history if a.get('success', False

        failed = total - successful
        
        times = [a.get('analysis_time', 0) for a in analysis_history if a.get('analysis_time')]
        avg_time = sum(times) / len(times) if times else 0.0
        
        coverage = [a.get('coverage_rate', 0) for a in analysis_history if a.get('coverage_rate')]
        avg_coverage = sum(coverage) / len(coverage) if coverage else 0.0
        
        metrics = AnalysisMetrics()
            total_analyses=total,
            successful_analyses=successful,
            failed_analyses=failed,
            average_time=avg_time,
            coverage_rate=avg_coverage
        
        
        return APIResponse(
            statistic_type=StatisticType.ANALYSIS_METRICS,
            data=metrics.to_dict(),
            timestamp=self._get_timestamp())
        

    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now(.isoformat()


def get_statistics(statistic_type: str, analysis_history: List[Dict[str, Any]]) -> APIResponse:
    api = MultiDimensionStatsAPI()
    
    try:
        stat_type = StatisticType[statistic_type.upper()]
        
        if stat_type == StatisticType.VULNERABILITY_DISTRIBUTION:
            return api.get_vulnerability_distribution(analysis_history)
        elif stat_type == StatisticType.HIGH_RISK_FUNCTIONS:
            return api.get_high_risk_functions(analysis_history)
        elif stat_type == StatisticType.SEVERITY_TREND:
            return api.get_severity_trend(analysis_history)
        elif stat_type == StatisticType.ANALYSIS_METRICS:
            return api.get_analysis_metrics(analysis_history)
    except KeyError:
        pass
    
    return APIResponse(
        statistic_type=StatisticType.ANALYSIS_METRICS,
        data={},
        timestamp=api._get_timestamp())))))