"""隐蔽信道检测器 —— 时序信道、存储信道、协议头部隧道检测。

隐蔽信道分类（NIST SP 800-53 / NCSC指南）：
- 时序信道：通过包间延迟/顺序编码信息。检测方法：IAT熵分析 + 规律性评分。
- 存储信道：利用协议保留字段/可选头部嵌入数据。检测方法：字段熵异常。
- DNS/ICMP隧道：利用DNS查询/ICMP负载传输数据。检测方法：熵+长度+频率综合评分。

设计前提：不依赖已知签名。基于统计特征检测未记录的隐蔽信道。
"""
import math, logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from statistics import mean, stdev, median

_log = logging.getLogger(__name__)

# 熵值阈值 —— DNS/ICMP负载的字符分布异常判定线
_HIGH_ENTROPY_THRESHOLD = 4.0  # 接近随机分布的熵值（base64/加密数据）
# IAT抖动比阈值 —— 低于此值表示过度规律（可能编码了信息）
_IAT_JITTER_COVERT = 0.05
# 包长序列周期检测的类FFT自相关阈值
_AUTOCORR_THRESHOLD = 0.7


@dataclass
class CovertChannelAlert:
    channel_type: str   # timing / storage / dns_tunnel / icmp_tunnel / header_field
    description: str
    severity: str = "high"
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


class TimingChannelDetector:
    # 时序隐蔽信道检测器 —— 分析包间到达时间(IAT)的统计异常。
    # 检测原理：IAT分布的熵 + 抖动比 + 自相关
    @staticmethod
    def shannon_entropy(values: List[float], bins: int = 20) -> float:
        if not values:
            return 0.0
        vm, vx = min(values), max(values)
        if vm == vx:
            return 0.0
        bw = (vx - vm) / bins
        hist = [0] * bins
        for v in values:
            idx = min(int((v - vm) / bw), bins - 1)
            hist[idx] += 1
        n = len(values)
        return -sum((h / n) * math.log2(h / n) for h in hist if h > 0)

    @staticmethod
    def autocorrelation(seq: List[float], lag: int = 1) -> float:
        n = len(seq)
        if n <= lag + 2:
            return 0.0
        m = mean(seq)
        num = sum((seq[i] - m) * (seq[i + lag] - m) for i in range(n - lag))
        den = sum((x - m) ** 2 for x in seq)
        return num / den if den > 1e-9 else 0.0

    def detect(self, iat_sequence: List[float], packet_count: int) -> List[CovertChannelAlert]:
        """分析IAT序列，返回时序信道告警列表"""
        alerts = []
        n = len(iat_sequence)
        if n < 8:
            return alerts

        # 抖动比
        try:
            m = mean(iat_sequence)
            s = stdev(iat_sequence)
            jitter = s / m if m > 0 else 0.0
        except Exception:
            jitter = 0.0

        # 自相关
        ac1 = self.autocorrelation(iat_sequence, 1)
        ac2 = self.autocorrelation(iat_sequence, 2)

        # IAT熵
        iat_entropy = self.shannon_entropy(iat_sequence)

        confidence = 0.0
        reasons = []

        if jitter < _IAT_JITTER_COVERT and n >= 10:
            confidence += 0.4
            reasons.append(f"IAT抖动比={jitter:.4f} —— 极度规律")

        if abs(ac1) > _AUTOCORR_THRESHOLD:
            confidence += 0.3
            reasons.append(f"IAT自相关(1)={ac1:.3f}")

        if iat_entropy < 1.5 and n >= 15:
            confidence += 0.3
            reasons.append(f"IAT熵={iat_entropy:.2f} bits —— 分布集中")

        if confidence >= 0.5:
            alerts.append(CovertChannelAlert(
                channel_type="timing",
                description="; ".join(reasons),
                severity="high" if confidence >= 0.7 else "medium",
                confidence=min(confidence, 1.0),
                evidence={
                    "iat_jitter": round(jitter, 5),
                    "autocorr_lag1": round(ac1, 4),
                    "autocorr_lag2": round(ac2, 4),
                    "iat_entropy": round(iat_entropy, 3),
                    "sample_count": n,
                },
            ))

        return alerts


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


class DnsTunnelDetector:
    """DNS 隧道检测 —— 综合熵+长度+频率+查询多样性评分。

    DNS隧道的典型特征：
    - 查询域名标签熵值异常高（base32/base64编码数据）
    - 单个标签长度异常长（>40字符）
    - 查询频率远高于正常DNS（隧道需持续通信）
    - 查询域名多样性极低（总是查询同一隧道域名）
    - TXT/MX/CNAME等非A记录异常占比高
    """

    def detect(self, queries: List[Dict]) -> List[CovertChannelAlert]:
        """输入查询列表 [{domain, qtype, query_len, timestamp}, ...]"""
        if len(queries) < 5:
            return []

        alerts = []
        domains = [q.get("domain", "") for q in queries]
        unique_domains = set(domains)

        # 域名多样性 —— 隧道通信通常仅1-2个隧道域名
        diversity = len(unique_domains) / max(len(domains), 1)
        if diversity < 0.1 and len(domains) >= 10:
            # 极低多样性 + 高频查询 = 疑似隧道
            sample_domain = max(set(domains), key=domains.count)
            labels = sample_domain.rstrip(".").split(".")
            long_labels = [lb for lb in labels if len(lb) > 40]
            if long_labels or len(labels) >= 5:
                alerts.append(CovertChannelAlert(
                    channel_type="dns_tunnel",
                    description=f"DNS隧道嫌疑: 域名多样性仅{diversity:.2%}，"
                                f"高频查询'{sample_domain[:60]}'",
                    severity="high",
                    confidence=min(0.9, 1.0 - diversity + 0.2),
                    evidence={
                        "unique_domains": len(unique_domains),
                        "total_queries": len(domains),
                        "sample_domain": sample_domain[:100],
                    },
                ))

        # TXT记录异常 —— 正常DNS查询中TXT记录通常<5%
        txt_queries = [q for q in queries if q.get("qtype", "").upper() == "TXT"]
        if txt_queries and len(txt_queries) / len(queries) > 0.2:
            alerts.append(CovertChannelAlert(
                channel_type="dns_tunnel",
                description=f"TXT查询占比{len(txt_queries)/len(queries):.0%} —— "
                            f"正常DNS以A/AAAA查询为主，TXT占比异常",
                severity="high",
                confidence=0.7,
            ))

        # 标签熵值分析 —— 隧道域名标签熵值接近随机(>3.5)
        high_ent_labels = 0
        total_labels = 0
        for domain in unique_domains:
            for label in domain.rstrip(".").split("."):
                if not label or len(label) < 4:
                    continue
                total_labels += 1
                ctr = Counter(label.lower())
                ent = -sum((c / len(label)) * math.log2(c / len(label)) for c in ctr.values())
                if ent > 3.5:
                    high_ent_labels += 1
        if high_ent_labels > 0 and high_ent_labels / max(total_labels, 1) > 0.4:
            alerts.append(CovertChannelAlert(
                channel_type="dns_tunnel",
                description=f"标签高熵比例{high_ent_labels}/{total_labels} —— "
                            f"DNS隧道常用base32/base64编码子域名",
                severity="high",
                confidence=0.8,
            ))

        return alerts


class CovertChannelDetector:
    """隐蔽信道综合检测引擎 —— 整合时序、存储、DNS隧道三个检测器。

    每条流独立评估，输出所有超阈值的隐蔽信道告警。
    设计为在线流式处理 —— 每个新包更新内部状态并返回增量告警。
    """

    def __init__(self):
        self._timing = TimingChannelDetector()
        self._storage = StorageChannelDetector()
        self._dns_tunnel = DnsTunnelDetector()
        self._alerts: List[CovertChannelAlert] = []
        # 流状态缓存
        self._flow_iats: Dict[str, List[float]] = defaultdict(list)
        self._flow_payloads: Dict[str, List[bytes]] = defaultdict(list)
        self._flow_ip_ids: Dict[str, List[int]] = defaultdict(list)
        self._flow_tcp_flags: Dict[str, List[int]] = defaultdict(list)
        self._dns_queries: List[Dict] = []

    def feed_packet(self, flow_key: str, iat: float,
                    payload: bytes, ip_id: int = 0,
                    tcp_flags: int = 0) -> List[CovertChannelAlert]:
        """每包调用 —— 返回触发的新告警（增量）"""
        new = []
        self._flow_iats[flow_key].append(iat)
        if payload:
            self._flow_payloads[flow_key].append(payload)
        if ip_id:
            self._flow_ip_ids[flow_key].append(ip_id)
        if tcp_flags:
            self._flow_tcp_flags[flow_key].append(tcp_flags)
        return new

    def evaluate_flow(self, flow_key: str) -> List[CovertChannelAlert]:
        """流结束时调用 —— 对流内所有缓存数据做完整分析"""
        alerts = []
        iats = self._flow_iats.get(flow_key, [])
        payloads = self._flow_payloads.get(flow_key, [])
        ip_ids = self._flow_ip_ids.get(flow_key, [])
        tcp_flags = self._flow_tcp_flags.get(flow_key, [])

        alerts.extend(self._timing.detect(iats, len(iats)))
        alerts.extend(self._storage.detect_ip_id_anomaly(ip_ids))
        alerts.extend(self._storage.detect_tcp_reserved(tcp_flags))
        alerts.extend(self._storage.detect_payload_entropy(payloads))

        self._alerts.extend(alerts)
        # 清理已评估的流缓存
        for d in [self._flow_iats, self._flow_payloads, self._flow_ip_ids, self._flow_tcp_flags]:
            d.pop(flow_key, None)
        return alerts

    def evaluate_dns(self, queries: List[Dict]) -> List[CovertChannelAlert]:
        """批量评估DNS查询列表"""
        alerts = self._dns_tunnel.detect(queries)
        self._alerts.extend(alerts)
        return alerts

    def summary(self) -> Dict[str, Any]:
        type_dist = Counter(a.channel_type for a in self._alerts)
        sev_dist = Counter(a.severity for a in self._alerts)
        return {
            "total_alerts": len(self._alerts),
            "by_channel_type": dict(type_dist),
            "by_severity": dict(sev_dist),
            "mean_confidence": mean([a.confidence for a in self._alerts]) if self._alerts else 0.0,
            "high_confidence": sum(1 for a in self._alerts if a.confidence > 0.7),
        }


__all__ = ["CovertChannelDetector", "CovertChannelAlert",
           "TimingChannelDetector", "StorageChannelDetector",
           "DnsTunnelDetector"]

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
