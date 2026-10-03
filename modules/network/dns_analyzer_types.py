"""DNS分析——数据结构定义与常量。"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

_log = logging.getLogger(__name__)

# 可疑TLD列表 —— 常见于DGA和恶意域名注册
TLD_SUSPICIOUS = frozenset([
    ".xyz", ".top", ".tk", ".ga", ".ml", ".cf", ".gq", ".loan", ".work",
    ".click", ".country", ".stream", ".download", ".trade", ".date", ".review",
    ".accountant", ".science", ".party", ".webcam", ".bid", ".cricket",
])

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

# 英文双字母频率模型 —— 基于英语语料库统计
BIGRAM_FREQ: Dict[str, float] = {
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
BIGRAM_MAX = max(BIGRAM_FREQ.values())


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
