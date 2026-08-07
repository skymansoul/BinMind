"""DNS分析——DGA评估、快速通量检测、TXT外泄、频率尖峰检测。"""

import logging
from collections import defaultdict
from statistics import mean
from typing import List, Dict, Tuple, Set

from .dns_analyzer_types import (
    DnsQuery, DnsLabelAnalysis,
    FAST_FLUX_IP_THRESHOLD, TXT_EXFIL_THRESHOLD, TLD_SUSPICIOUS,
    DGA_LABEL_LEN_MIN, DGA_LABEL_LEN_MAX,
)
from .dns_analyzer_features import (
    shannon_entropy, bigram_frequency_score, vowel_consonant_ratio, length_penalty,
)

_log = logging.getLogger(__name__)


# DGA域名综合评估
class DgaAssessor:
    @staticmethod
    def assess_domain(domain: str) -> Tuple[float, bool, List[DnsLabelAnalysis]]:
        """综合评估域名是否为DGA产品。

        评估策略：先分标签计算各项指标（熵、双字母频率、元辅音比），
        再加权融合。单高熵标签不足以判断DGA，需结合多特征。
        """
        labels = domain.lower().rstrip(".").split(".")
        # 取去除TLD后的标签
        _core = labels[:-1] if len(labels) > 1 else labels
        analyses: List[DnsLabelAnalysis] = []
        high_risk_count = 0

        for lb in _core:
            if not lb:
                continue
            _ent = shannon_entropy(lb)
            _pen = length_penalty(lb)
            _ent += _pen
            _bg = bigram_frequency_score(lb)
            _vc = vowel_consonant_ratio(lb)

            # DGA评分：多特征加权融合
            # 高熵+低双字母频率+极端元辅音比 → DGA可能性高
            _dga = 0.0
            if _ent > 2.5:
                _dga += min((_ent - 2.5) / 2.0, 1.0) * 0.45  # 熵贡献最高权重
            if _bg < 0.25:
                _dga += (0.25 - _bg) / 0.25 * 0.30
            else:
                _dga += 0.0
            if _vc < 0.15 or _vc > 0.85:
                _dga += min(abs(_vc - 0.45) / 0.45, 1.0) * 0.25
            # 标签长度一致性加分（DGA常见特征）
            _l = len(lb)
            if DGA_LABEL_LEN_MIN <= _l <= DGA_LABEL_LEN_MAX:
                _dga += 0.05

            _dga = min(_dga, 1.0)
            _suspicious = _dga > 0.55
            if _suspicious:
                high_risk_count += 1

            analyses.append(DnsLabelAnalysis(
                label=lb, entropy=_ent, length=_l,
                bigram_score=_bg, vc_ratio=_vc,
                dga_score=_dga, is_suspicious=_suspicious,
            ))

        # 域名级综合评分
        if analyses:
            _avg = sum(a.dga_score for a in analyses) / len(analyses)
        else:
            _avg = 0.0
        # 多个标签同时可疑则提高评分
        if high_risk_count >= 2:
            _avg = min(_avg + 0.15, 1.0)

        _verdict = _avg > 0.52
        return _avg, _verdict, analyses


# TLD可疑性检查
def check_suspicious_tld(domain: str) -> bool:
    _dom = domain.lower().rstrip(".")
    for tld in TLD_SUSPICIOUS:
        if _dom.endswith(tld):
            return True
    return False


# 快速通量检测
class FastFluxDetector:
    """检测快速通量：同一域名在不同时间窗口解析到大量IP。

    快速通量僵尸网络通过频繁更换IP躲避封锁。检测方法：时间窗口内
    同域名解析IP数超阈值（默认5），跨ASN则置信度更高。
    """

    @staticmethod
    def detect(queries: List[DnsQuery], ip_threshold: int = FAST_FLUX_IP_THRESHOLD,
               time_window: float = 300.0) -> List[Tuple[str, int, float]]:
        if not queries:
            return []
        # 按域名聚合IP
        _domain_ips: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        for q in queries:
            if q.resolved_ips and q.qtype in ("A", "AAAA"):
                for ip in q.resolved_ips:
                    _domain_ips[q.domain][ip].append(q.timestamp)

        results: List[Tuple[str, int, float]] = []
        for domain, ip_ts in _domain_ips.items():
            # 检测时间窗口内IP数量
            _all_ts = [ts for ts_list in ip_ts.values() for ts in ts_list]
            _all_ts.sort()
            if not _all_ts:
                continue

            _window_ips: Dict[float, Set[str]] = {}
            for ip, ts_list in ip_ts.items():
                for ts in ts_list:
                    # 找到该时间戳所属窗口起始点
                    _win_start = (ts // time_window) * time_window
                    if _win_start not in _window_ips:
                        _window_ips[_win_start] = set()
                    _window_ips[_win_start].add(ip)

            for _win, _ips in _window_ips.items():
                _count = len(_ips)
                if _count >= ip_threshold:
                    # 粗略跨ASN检测（基于IP前缀）
                    _subnets = set(ip.rsplit(".", 1)[0] for ip in _ips if ip.count(".") == 3)
                    _confidence = min(_count / ip_threshold, 2.0)
                    if len(_subnets) >= 2:
                        _confidence += 0.3
                    results.append((domain, _count, _confidence))

        return results


# TXT记录外泄分析
def analyze_txt_records(queries: List[DnsQuery]) -> List[Tuple[str, int]]:
    """分析TXT记录作为数据外泄通道"""
    alerts: List[Tuple[str, int]] = []
    _txt_queries = [q for q in queries if q.qtype.upper() == "TXT"]
    for q in _txt_queries:
        if q.response_size > TXT_EXFIL_THRESHOLD:
            alerts.append((q.domain, q.response_size))
    return alerts


# 查询频率尖峰检测
class QuerySpikeDetector:
    @staticmethod
    def detect_spikes(queries: List[DnsQuery], window_sec: float = 60.0,
                      spike_factor: float = 3.0) -> List[str]:
        """基于滑动窗口QPS检测查询频率异常尖峰。

        计算每窗口查询次数，与基线（移动平均）比较。尖峰因子默认3倍。
        """
        if len(queries) < 10:
            return []
        _sorted = sorted(queries, key=lambda q: q.timestamp)
        _start = _sorted[0].timestamp
        _end = _sorted[-1].timestamp
        if _end <= _start:
            return []

        # 构建时间桶
        _num_windows = int((_end - _start) / window_sec) + 1
        _buckets = [0] * _num_windows
        for q in _sorted:
            _idx = int((q.timestamp - _start) / window_sec)
            if 0 <= _idx < _num_windows:
                _buckets[_idx] += 1

        # 计算移动平均基线
        _baseline_window = 10
        _baselines = []
        for i in range(_num_windows):
            _prev = _buckets[max(0, i - _baseline_window):i]
            if _prev:
                _baselines.append(mean(_prev))
            else:
                _baselines.append(_buckets[i] if _buckets[i] > 0 else 1.0)

        alerts: List[str] = []
        for i in range(_num_windows):
            if _buckets[i] > _baselines[i] * spike_factor and _buckets[i] >= 5:
                _ts = _start + i * window_sec
                alerts.append(f"QPS spike at {_ts:.0f}: {_buckets[i]} queries (baseline {_baselines[i]:.1f})")

        return alerts
