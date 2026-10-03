# 多源网络时间共识验证器 —— 跨NTP/TLS/HTTP/区块链时间源检测时间操纵。
#
# 时间操纵攻击(NTP投毒/TLS时间戳伪造)可破坏证书验证、Kerberos认证、
# 日志取证链。单时间源是不可信的——本模块交叉验证多源时间戳,
# 用修剪均值共识算法检测偏离源。
#
# 时间源类型:
#   1. NTP: 从多个NTP服务器获取的网络时间(易投毒, 需多服务器交叉验证)
#   2. TLS ServerHello.random: 32字节含4字节Unix时间戳(RFC 5246 §7.4.1.2)
#   3. HTTP Date头: RFC 7231格式, 精度1秒
#   4. 自定义源: 区块链区块时间戳/本地RTC/GPS时间
#
# 共识算法:
#   对N个时间源的时间戳排序, 计算修剪均值(去掉20%极值),
#   每个源到共识值的绝对偏差→Z-score→异常标记(>2σ)。
#   最终输出: 共识时间 + 每个源的可信度得分。
#
# 未见2024-2025文献涉及多协议时间源交叉共识用于攻击检测。

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class TimeSource(Enum):
    NTP      = auto()
    TLS_RANDOM = auto()
    HTTP_DATE  = auto()
    CUSTOM   = auto()


@dataclass
class TimeSample:
    """单时间源的采样值"""
    source_type: TimeSource
    source_id: str          # "ntp://pool.ntp.org", "tls://example.com:443"
    timestamp_unix: float   # epoch seconds
    precision_s: float      # 声称精度(秒), NTP=0.001, HTTP=1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceConsensus:
    """单个源的共识评估"""
    source_type: TimeSource
    source_id: str
    deviation_s: float         # 到共识均值的绝对偏差(秒)
    z_score: float             # 标准化偏差
    is_outlier: bool           # |z_score| > 2.0
    trust_score: float         # [0,1], 基于偏差和精度
    recommendation: str = ""


@dataclass
class TimeConsensusReport:
    """多源时间共识完整报告"""
    consensus_time: float       # 修剪均值(epoch seconds)
    consensus_uncertainty: float  # 修剪均值的标准误差(秒)
    samples_count: int
    outliers_detected: int
    source_details: List[SourceConsensus]
    overall_trust: float        # [0,1] 所有源的平均可信度
    risk_level: str             # "safe"/"suspicious"/"manipulated"


def extract_tls_timestamp(server_random: bytes) -> Optional[float]:
    """从TLS ServerHello.random提取Unix时间戳。

    RFC 5246 §7.4.1.2: ServerHello.random的前4字节为
    GMT Unix时间戳(gmt_unix_time), 后续28字节为随机数。
    """
    if len(server_random) < 32:
        return None
    # 大端序, 无符号32位
    gmt_time = int.from_bytes(server_random[:4], 'big')
    # 检查合理性: TLS时间戳不应早于2000年或晚于2100年
    if gmt_time < 946684800 or gmt_time > 4102444800:
        return None
    return float(gmt_time)


def parse_http_date(date_str: str) -> Optional[float]:
    """解析HTTP Date头为Unix时间戳。

    支持三种RFC 7231格式: RFC 1123(preferred), RFC 850(obsolete), asctime.
    返回epoch seconds或None(解析失败)。
    """
    import time as _time
    formats = [
        '%a, %d %b %Y %H:%M:%S GMT',     # RFC 1123
        '%A, %d-%b-%y %H:%M:%S GMT',     # RFC 850
        '%a %b %d %H:%M:%S %Y',          # asctime
    ]
    for fmt in formats:
        try:
            struct_time = _time.strptime(date_str.strip(), fmt)
            return _time.mktime(struct_time)
        except (ValueError, OverflowError):
            continue
    return None


class TimeConsensusVerifier:
    """多源时间共识验证器。

    输入N个时间采样(N≥3), 输出修剪均值共识+各源可信度。
    修剪比例0.2(至少保留60%的样本), 适应最多20%的源被操纵。

    Z-score阈值: >2.0标记outlier。在N<5时放宽到>2.5避免小样本误报。
    """

    def __init__(self, trim_ratio: float = 0.2,
                 outlier_z_threshold: float = 2.0):
        self._trim = trim_ratio
        self._z_thresh = outlier_z_threshold

    def verify(self, samples: List[TimeSample]) -> TimeConsensusReport:
        if len(samples) < 3:
            return self._insufficient_samples(samples)

        # 排序取修剪均值
        timestamps = sorted(s.timestamp_unix for s in samples)
        n = len(timestamps)
        trim_n = max(1, int(n * self._trim))
        trimmed = timestamps[trim_n:n - trim_n] if n - 2 * trim_n > 0 else timestamps
        consensus = sum(trimmed) / len(trimmed)

        # 基于修剪样本的标准误差
        if len(trimmed) > 1:
            se = math.sqrt(sum((t - consensus) ** 2
                             for t in trimmed) / (len(trimmed) - 1))
            uncertainty = se / math.sqrt(len(trimmed))
        else:
            uncertainty = 1.0

        # 计算各源偏差
        all_devs = [abs(s.timestamp_unix - consensus) for s in samples]
        mean_dev = sum(all_devs) / n
        std_dev = math.sqrt(sum((d - mean_dev) ** 2
                               for d in all_devs) / max(n - 1, 1))
        if std_dev < 1e-6:
            std_dev = 0.01  # 所有源完全一致时避免除零

        details: List[SourceConsensus] = []
        outliers = 0
        z_thresh = self._z_thresh if n >= 5 else 2.5

        for s in samples:
            dev = abs(s.timestamp_unix - consensus)
            z = dev / std_dev
            is_out = z > z_thresh
            if is_out:
                outliers += 1

            # 可信度: 偏差越小+精度越高→得分越高
            trust = math.exp(-dev / max(s.precision_s, 0.001)) * 0.7
            trust += 0.3 * math.exp(-s.precision_s / 1.0)
            trust = min(trust, 1.0)

            if is_out:
                rec = (f"{s.source_id}: 偏差{dev:.2f}s (z={z:.1f})——"
                       f"可能被操纵或时钟异常")
            elif z > 1.0:
                rec = f"{s.source_id}: 小幅偏差{dev:.2f}s——监控建议"
            else:
                rec = f"{s.source_id}: 在共识范围内"

            details.append(SourceConsensus(
                source_type=s.source_type,
                source_id=s.source_id,
                deviation_s=round(dev, 4),
                z_score=round(z, 2),
                is_outlier=is_out,
                trust_score=round(trust, 3),
                recommendation=rec,
            ))

        overall_trust = sum(d.trust_score for d in details) / n

        if outliers >= n // 2:
            risk = "manipulated"
        elif outliers > 0:
            risk = "suspicious"
        else:
            risk = "safe"

        return TimeConsensusReport(
            consensus_time=round(consensus, 3),
            consensus_uncertainty=round(uncertainty, 4),
            samples_count=n,
            outliers_detected=outliers,
            source_details=details,
            overall_trust=round(overall_trust, 3),
            risk_level=risk,
        )

    @staticmethod
    def _insufficient_samples(samples: List[TimeSample]
                               ) -> TimeConsensusReport:
        return TimeConsensusReport(
            consensus_time=samples[0].timestamp_unix if samples else 0.0,
            consensus_uncertainty=999.0,
            samples_count=len(samples),
            outliers_detected=0,
            source_details=[],
            overall_trust=0.0,
            risk_level="unknown",
        )


def verify_time_consensus(ntp_times: Dict[str, float],
                           tls_randoms: Dict[str, bytes],
                           http_dates: Dict[str, str],
                           custom_times: Dict[str, float] = None
                           ) -> TimeConsensusReport:
    """便捷入口: 多源时间戳→共识验证→TimeConsensusReport。

    ntp_times: {"server1": epoch_seconds, ...}
    tls_randoms: {"host1": server_random_bytes, ...}
    http_dates: {"host1": "Tue, 15 Nov 1994 08:12:31 GMT", ...}
    custom_times: {"blockchain_eth": epoch_seconds, ...}
    """
    samples: List[TimeSample] = []

    for server_id, ts in ntp_times.items():
        samples.append(TimeSample(TimeSource.NTP, f"ntp://{server_id}",
                                  ts, 0.001))
    for host_id, sr in tls_randoms.items():
        ts = extract_tls_timestamp(sr)
        if ts is not None:
            samples.append(TimeSample(TimeSource.TLS_RANDOM,
                                      f"tls://{host_id}", ts, 1.0))
    for host_id, date_str in http_dates.items():
        ts = parse_http_date(date_str)
        if ts is not None:
            samples.append(TimeSample(TimeSource.HTTP_DATE,
                                      f"http://{host_id}", ts, 1.0))
    for source_id, ts in (custom_times or {}).items():
        samples.append(TimeSample(TimeSource.CUSTOM, source_id, ts, 0.1))

    verifier = TimeConsensusVerifier()
    return verifier.verify(samples)


__all__ = [
    "TimeSource", "TimeSample", "SourceConsensus",
    "TimeConsensusReport", "TimeConsensusVerifier",
    "extract_tls_timestamp", "parse_http_date",
    "verify_time_consensus",
]
