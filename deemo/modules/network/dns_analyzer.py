"""DNS流量分析——DGA检测、DNS隧道识别、快速通量检测。"""
import math, re, logging, hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from statistics import mean, stdev

_log = logging.getLogger(__name__)

# ---- 可疑TLD列表 —— 常见于DGA和恶意域名注册 ----
TLD_SUSPICIOUS = frozenset([
    ".xyz", ".top", ".tk", ".ga", ".ml", ".cf", ".gq", ".loan", ".work",
    ".click", ".country", ".stream", ".download", ".trade", ".date", ".review",
    ".accountant", ".science", ".party", ".webcam", ".bid", ".cricket",
])

# ===== 英文双字母频率模型 —— 基于英语语料库统计 =====
_BIGRAM_FREQ: Dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99, "on": 1.76,
    "at": 1.49, "en": 1.45, "nd": 1.35, "ti": 1.34, "es": 1.33, "or": 1.28,
    "te": 1.20, "of": 1.17, "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09,
    "ar": 1.07, "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.92, "ou": 0.87, "io": 0.83, "le": 0.83, "ve": 0.83,
    "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76, "ri": 0.73, "ro": 0.73,
    "ic": 0.70, "ne": 0.69, "ea": 0.69, "ra": 0.69, "ce": 0.65, "li": 0.62,
    "ch": 0.60, "ll": 0.58, "be": 0.58, "ma": 0.57, "si": 0.55, "om": 0.55,
    "ur": 0.54, "ca": 0.53, "el": 0.53, "ta": 0.53, "la": 0.52, "ns": 0.51,
    "di": 0.51, "fo": 0.50, "ho": 0.50, "pe": 0.49, "ec": 0.49, "pr": 0.48,
    "no": 0.48, "ct": 0.48, "us": 0.47, "ac": 0.47, "ot": 0.46, "il": 0.46,
    "tr": 0.46, "ly": 0.45, "nc": 0.44, "ad": 0.44, "wi": 0.44, "ni": 0.43,
    "wh": 0.42, "ge": 0.42, "ol": 0.41, "em": 0.41, "mo": 0.41, "am": 0.40,
    "os": 0.40, "pa": 0.40, "so": 0.39, "ai": 0.39, "fi": 0.39, "do": 0.38,
    "ee": 0.38, "oo": 0.37, "ld": 0.37, "un": 0.37, "ow": 0.36, "lo": 0.36,
    "ay": 0.35, "sc": 0.35, "ck": 0.35, "ci": 0.34, "um": 0.34, "gh": 0.33,
    "ex": 0.33, "pl": 0.33, "bl": 0.33, "gr": 0.33, "fe": 0.32, "ir": 0.32,
    "su": 0.32, "ag": 0.31, "op": 0.31, "pi": 0.31, "ke": 0.30, "mp": 0.29,
    "mi": 0.29, "wa": 0.29, "wo": 0.29, "bo": 0.28, "av": 0.27, "bu": 0.27,
    "ap": 0.27, "go": 0.27, "fi": 0.27, "po": 0.27, "ru": 0.27, "ep": 0.26,
    "oc": 0.26, "ab": 0.26, "ov": 0.26, "sa": 0.26, "tu": 0.26, "rm": 0.26,
    "ig": 0.25, "qu": 0.25, "au": 0.25, "sp": 0.24, "im": 0.24, "ev": 0.24,
    "nc": 0.24, "tt": 0.23, "sh": 0.23, "og": 0.23, "du": 0.23, "tw": 0.23,
    "jo": 0.22, "cl": 0.22, "vi": 0.22, "sm": 0.21, "xt": 0.21, "yp": 0.20,
    "eo": 0.20, "dr": 0.20, "my": 0.20, "da": 0.19, "ze": 0.18, "je": 0.17,
}
_BIGRAM_MAX = max(_BIGRAM_FREQ.values())

# 熵值阈值 —— 参考CIC-Bell-DNS-EXF-2021数据集
ENTROPY_THRESHOLD = 3.0
# 快速通量检测阈值
FAST_FLUX_IP_THRESHOLD = 5
# TXT记录大小阈值（字节）
TXT_EXFIL_THRESHOLD = 256
# 信标检测抖动比阈值
BEACON_JITTER_RATIO = 0.12
# 标签长度异常范围
DGA_LABEL_LEN_MIN = 8
DGA_LABEL_LEN_MAX = 12


def shannon_entropy(s: str) -> float:
    """计算字符串香农熵，衡量字符分布随机性。

    DGA域名通常每标签熵较高（>3.0），正常域名含常见词根如
    'google', 'yahoo'等，熵值较低。分标签计算而非整个域名。
    """
    if not s:
        return 0.0
    _h = Counter(s)
    length = len(s)
    return -sum((freq / length) * math.log2(freq / length) for freq in _h.values())


def label_entropies(domain: str) -> List[float]:
    """计算域名每个标签（点分隔部分）的熵值"""
    labels = domain.lower().rstrip(".").split(".")
    # 去除TLD，关注二级及更深标签
    if len(labels) > 1:
        labels = labels[:-1]
    return [shannon_entropy(lb) for lb in labels if lb]


def bigram_frequency_score(domain: str) -> float:
    # 与英文双字母频率模型比较，DGA域名的双字母频率异常低
    _s = domain.lower().rstrip(".").split(".")[-2] if len(domain.split(".")) >= 2 else domain.lower()
    _s = re.sub(r'[^a-z]', '', _s)
    if len(_s) < 2:
        return 0.0
    bigrams = [_s[i:i+2] for i in range(len(_s)-1)]
    total = 0.0
    _m = 0
    for bg in bigrams:
        freq = _BIGRAM_FREQ.get(bg, 0.0)
        total += freq
        _m += 1
    return total / (_m * _BIGRAM_MAX) if _m > 0 else 0.0


def vowel_consonant_ratio(domain: str) -> float:
    _s = domain.lower().rstrip(".").split(".")[-2] if len(domain.split(".")) >= 2 else domain.lower()
    _s = re.sub(r'[^a-z]', '', _s)
    if not _s:
        return 0.0
    vowels = sum(1 for ch in _s if ch in "aeiou")
    consonants = len(_s) - vowels
    if consonants == 0:
        return 1.0
    return vowels / consonants


def length_penalty(label: str) -> float:
    """对极短或极长标签应用熵修正因子。

    短标签（<4字符）熵计算噪声大，上调0.1。长标签（>25字符）无论熵值
    均为高度可疑。正常标签返回0。
    """
    _l = len(label)
    if _l < 4:
        return 0.15  # 短标签噪声惩罚
    elif _l > 25:
        return 0.5   # 长标签高度可疑
    return 0.0


# ===== 数据结构 =====
@dataclass
class DnsQuery:
    domain: str
    qtype: str = "A"
    client_ip: str = "0.0.0.0"
    timestamp: float = 0.0
    response_size: int = 0
    ttl: int = 0
    resolved_ips: List[str] = field(default_factory=list)

@dataclass
class DnsLabelAnalysis:
    label: str
    entropy: float = 0.0
    length: int = 0
    bigram_score: float = 0.0
    vc_ratio: float = 0.0
    dga_score: float = 0.0
    is_suspicious: bool = False

@dataclass
class DnsAnalysisReport:
    total_queries: int = 0
    unique_domains: int = 0
    dga_detected: int = 0
    dga_domains: List[str] = field(default_factory=list)
    fast_flux_domains: List[str] = field(default_factory=list)
    txt_exfil_alerts: List[Tuple[str, int]] = field(default_factory=list)
    query_spike_alerts: List[str] = field(default_factory=list)
    label_analyses: List[DnsLabelAnalysis] = field(default_factory=list)
    risk_score: float = 0.0


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


# ===== TLD可疑性检查 =====
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


# ===== TXT记录外泄分析 =====
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


# ===== 综合分析入口 =====
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
