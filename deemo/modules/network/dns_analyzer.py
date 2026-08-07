"""DNS流量分析——综合分析入口，整合所有检测模块并重导出完整公共API。"""

import logging
from typing import List, Dict, Tuple

from .dns_analyzer_types import (
    DnsQuery, DnsLabelAnalysis, DnsAnalysisReport,
    TLD_SUSPICIOUS, ENTROPY_THRESHOLD, FAST_FLUX_IP_THRESHOLD,
    TXT_EXFIL_THRESHOLD, BEACON_JITTER_RATIO,
    DGA_LABEL_LEN_MIN, DGA_LABEL_LEN_MAX,
    BIGRAM_FREQ, BIGRAM_MAX,
)
from .dns_analyzer_features import (
    shannon_entropy, label_entropies, bigram_frequency_score,
    vowel_consonant_ratio, length_penalty,
)
from .dns_analyzer_detectors import (
    DgaAssessor, check_suspicious_tld, FastFluxDetector,
    analyze_txt_records, QuerySpikeDetector,
)

_log = logging.getLogger(__name__)


# 综合分析入口
def analyze(queries: List[DnsQuery]) -> DnsAnalysisReport:
    """DNS流量分析，整合DGA检测、外泄分析、通量检测等所有模块。

    处理流程：统计基本指标 → 逐域名DGA评估 → 快速通量检测 → TXT外泄 →
    频率尖峰 → 综合风险评分。TXT和DNS隧道是最高危信号，权重最高。
    """
    _r = DnsAnalysisReport()
    if not queries:
        return _r

    _r.total_queries = len(queries)
    _unique = set(q.domain for q in queries)
    _r.unique_domains = len(_unique)

    # DGA评估
    assessed: Dict[str, Tuple[float, bool, List[DnsLabelAnalysis]]] = {}
    for domain in _unique:
        _score, _verdict, _analyses = DgaAssessor.assess_domain(domain)
        assessed[domain] = (_score, _verdict, _analyses)
        if _verdict:
            _r.dga_detected += 1
            _r.dga_domains.append(domain)
        _r.label_analyses.extend(_analyses)

    # 快速通量
    _ff_results = FastFluxDetector.detect(queries)
    _r.fast_flux_domains = [d for d, _, _ in _ff_results]

    # TXT外泄
    _r.txt_exfil_alerts = analyze_txt_records(queries)

    # 频率尖峰
    _r.query_spike_alerts = QuerySpikeDetector.detect_spikes(queries)

    # 综合风险评分（0-100）
    _risk = 0.0
    if _r.unique_domains > 0:
        _risk += min(_r.dga_detected / _r.unique_domains * 40, 40)
    if _r.fast_flux_domains:
        _risk += min(len(_r.fast_flux_domains) * 10, 25)
    if _r.txt_exfil_alerts:
        _risk += min(len(_r.txt_exfil_alerts) * 15, 25)
    if _r.query_spike_alerts:
        _risk += min(len(_r.query_spike_alerts) * 3, 10)
    _r.risk_score = min(_risk, 100.0)

    return _r


# 保持原文件公共API完全不变
__all__ = [
    "shannon_entropy", "label_entropies", "bigram_frequency_score",
    "vowel_consonant_ratio", "length_penalty",
    "DnsQuery", "DnsLabelAnalysis", "DnsAnalysisReport",
    "DgaAssessor", "check_suspicious_tld", "FastFluxDetector",
    "analyze_txt_records", "QuerySpikeDetector", "analyze",
    "TLD_SUSPICIOUS", "ENTROPY_THRESHOLD", "FAST_FLUX_IP_THRESHOLD",
    "TXT_EXFIL_THRESHOLD", "BEACON_JITTER_RATIO",
    "DGA_LABEL_LEN_MIN", "DGA_LABEL_LEN_MAX",
]
