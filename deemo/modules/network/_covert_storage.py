"""存储式隐蔽信道检测器 —— 检查协议字段中的异常数据。

TCP保留位、IP ID、负载熵三类检测器；检测逻辑见各方法。
"""
import math
from collections import Counter
from statistics import mean
from typing import List

from ._covert_types import (
    CovertChannelAlert,
    _HIGH_ENTROPY_THRESHOLD,
)


class StorageChannelDetector:
    """存储式隐蔽信道检测器 —— 检查协议字段中的异常数据。

    检测位置：
    - TCP 保留字段 (6bit) —— 正常情况下恒为0，非0即异常
    - IP ID字段 —— 连续递增正常，随机/恒定异常
    - DNS QNAME标签熵 —— 隧道数据编码在DNS子域名中
    - ICMP payload熵 —— ping -p 可携带任意payload
    """

    @staticmethod
    def _byte_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        ctr = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in ctr.values())

    def detect_tcp_reserved(self, tcp_flags_list: List[int]) -> List[CovertChannelAlert]:
        """检测TCP保留位异常使用 —— 3bit reserved应恒为0"""
        # TCP标志位：bit 0-3 = 保留, bit 4-7 = CWR/ECE/URG/ACK
        anomalies = [f for f in tcp_flags_list if (f & 0x0E) != 0]
        if len(anomalies) > len(tcp_flags_list) * 0.1 and len(anomalies) >= 3:
            return [CovertChannelAlert(
                channel_type="header_field",
                description=f"TCP保留位非零: {len(anomalies)}/{len(tcp_flags_list)}包 —— "
                            f"存储信道数据嵌入嫌疑",
                severity="high",
                confidence=0.75,
            )]
        return []

    def detect_ip_id_anomaly(self, ip_ids: List[int]) -> List[CovertChannelAlert]:
        """IP ID字段异常 —— 正常应为单调递增(每包+1)"""
        if len(ip_ids) < 10:
            return []
        # 增量为1的比例
        deltas = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids) - 1)]
        normal = sum(1 for d in deltas if d == 1)
        ratio = normal / len(deltas)
        if ratio < 0.3:
            return [CovertChannelAlert(
                channel_type="header_field",
                description=f"IP ID增量=1的比例仅{ratio:.0%} —— 非正常单调递增，"
                            f"存储信道复用嫌疑",
                severity="medium",
                confidence=0.7 - ratio,
                evidence={"ip_id_deltas": deltas[:20]},
            )]
        return []

    def detect_payload_entropy(self, payloads: List[bytes],
                                threshold: float = _HIGH_ENTROPY_THRESHOLD) -> List[CovertChannelAlert]:
        """检测负载高熵（加密/编码数据特征）"""
        if not payloads:
            return []
        entropies = [self._byte_entropy(p) for p in payloads if len(p) > 16]
        if not entropies:
            return []
        high_ent_count = sum(1 for e in entropies if e > threshold)
        if high_ent_count > len(entropies) * 0.5:
            return [CovertChannelAlert(
                channel_type="storage",
                description=f"高熵负载: {high_ent_count}/{len(entropies)}包熵>{threshold} —— "
                            f"疑似加密隧道或编码数据",
                severity="medium",
                confidence=min(high_ent_count / max(len(entropies), 1), 1.0),
                evidence={"mean_entropy": round(mean(entropies), 2)},
            )]
        return []
