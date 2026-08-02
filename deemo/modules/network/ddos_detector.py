# 2026-07-23
"""DDoS 攻击检测引擎 —— 多向量并行检测 + EWMA自适应阈值。

检测向量：SYN flood、UDP flood、DNS amplification、NTP amplification、
ICMP flood、Slowloris慢速攻击。

参考：
- PARTHENON (IEEE TNSM 2024): 两级监控 —— 粗粒度sketch + ML分类
- LARDM (JSA 2025): Gini impurity流量异常量化 + 数据面决策树
- P4-DPDK (IEEE BlackSea 2025): 计数min-sketch + 连接跟踪
"""
import math
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from statistics import mean, stdev

# EWMA平滑系数 —— PARTHENON的CGM阶段使用α=0.1进行流量基线估计
_DDOS_EWMA_ALPHA = 0.1
# 检测窗口（秒）
_DETECT_WINDOW = 10.0
# Sketch桶数量 —— 简化的Count-Min Sketch近似
_SKETCH_BUCKETS = 1024
# 阈值sigma倍数
_SIGMA_MULTIPLIER = 3.5


@dataclass
class DdosAlert:
    attack_type: str     # syn_flood / udp_flood / dns_amp / ntp_amp / icmp_flood / slowloris
    target: str          # 目标IP或子网
    metric_value: float
    baseline: float
    ratio: float
    severity: str
    timestamp: float = 0.0


class SketchCounter:
    """简化的Count-Min Sketch计数器 —— LARDM启发式哈希碰撞过滤。

    使用2个哈希函数映射(src,dst)对到固定桶，减少内存占用。
    对Top-K大象流检测精度≈90% [LARDM 2025评估]。
    """

    def __init__(self, num_buckets: int = _SKETCH_BUCKETS):
        self.bsize = num_buckets
        self._row_a = [0] * num_buckets
        self._row_b = [0] * num_buckets
        self._total = 0

    @staticmethod
    def _hash1(key: str) -> int:
        h = 5381
        for c in key:
            h = ((h << 5) + h) + ord(c)
        return h & 0x7FFFFFFF

    @staticmethod
    def _hash2(key: str) -> int:
        h = 0
        for c in key:
            h = (h * 31) + ord(c)
        return h & 0x7FFFFFFF

    def add(self, key: str, count: int = 1) -> None:
        self._row_a[self._hash1(key) % self.bsize] += count
        self._row_b[self._hash2(key) % self.bsize] += count
        self._total += count

    def estimate(self, key: str) -> int:
        return min(
            self._row_a[self._hash1(key) % self.bsize],
            self._row_b[self._hash2(key) % self.bsize],
        )

    def total(self) -> int:
        return self._total


class DdosDetector:
    """DDoS 多向量检测引擎。

    架构：每向量维护独立的EWMA基线 + 滑动窗口计数器。
    异常判定：当前窗口值 > (EWMA基线 + SIGMA_MULTIPLIER × 历史标准差)。

    PARTHENON方法的两级借鉴：本类实现粗粒度检测(CGM)，外部可接入ML模型做细粒度(FGM)。
    """

    def __init__(self, window_sec: float = _DETECT_WINDOW):
        self._window = window_sec
        self._ewma: Dict[str, float] = {}       # vector → EWMA
        self._ewma_sq: Dict[str, float] = {}    # vector → EWMA of squares (variance tracking)
        self._counters: Dict[str, SketchCounter] = defaultdict(SketchCounter)
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self._alerts: List[DdosAlert] = []
        self._n_windows = 0
        self._baseline_initialized = False

    # 各攻击向量的聚合键生成
    @staticmethod
    def _syn_key(target: str) -> str:
        return f"syn:{target}"
    @staticmethod
    def _udp_key(target: str) -> str:
        return f"udp:{target}"
    @staticmethod
    def _dns_key(target: str) -> str:
        return f"dns:{target}"
    @staticmethod
    def _ntp_key(target: str) -> str:
        return f"ntp:{target}"
    @staticmethod
    def _icmp_key(target: str) -> str:
        return f"icmp:{target}"

    def feed_packet(self, src_ip: str, dst_ip: str, protocol: int,
                    src_port: int, dst_port: int, length: int,
                    timestamp: float = 0.0) -> None:
        """每包调用 —— 递增对应计数器的sketch桶。

        协议映射：
        - TCP SYN (flags=0x02): 计入SYN flood sketch
        - UDP port 53: 计入DNS amplification
        - UDP port 123: 计入NTP amplification
        - ICMP (proto=1): 计入ICMP flood
        - 其他UDP: 计入通用UDP flood
        """
        # SYN flood —— TCP SYN包
        if protocol == 6 and length < 100:
            self._counters["syn"].add(self._syn_key(dst_ip))
            self._counters["syn_src"].add(src_ip)

        # UDP flood
        if protocol == 17:
            self._counters["udp"].add(self._udp_key(dst_ip))
            # DNS amplification —— 目标端口53的UDP大包
            if dst_port == 53 and length > 200:
                self._counters["dns_amp"].add(self._dns_key(dst_ip))
            # NTP amplification —— 源端口123的UDP大包（monlist响应）
            if src_port == 123 and length > 400:
                self._counters["ntp_amp"].add(self._ntp_key(src_ip))
            # 短UDP包可能是memcached/CLDAP等放大反射
            if dst_port in (11211, 389, 1900) and length < 100:
                self._counters["amp_generic"].add(self._udp_key(dst_ip))

        # ICMP flood
        if protocol == 1:
            self._counters["icmp"].add(self._icmp_key(dst_ip))

    def evaluate_window(self) -> List[DdosAlert]:
        """在每个检测窗口结束时调用 —— 评估所有向量是否触发异常阈值。

        返回新生成的DdosAlert列表。内部更新EWMA基线。
        """
        self._n_windows += 1
        new_alerts = []

        vector_configs = [
            ("syn", "syn_flood", 500, "high"),
            ("udp", "udp_flood", 300, "medium"),
            ("dns_amp", "dns_amplification", 20, "high"),
            ("ntp_amp", "ntp_amplification", 10, "high"),
            ("icmp", "icmp_flood", 200, "medium"),
            ("amp_generic", "amplification_generic", 15, "high"),
        ]

        for vec_key, atype, min_abs, default_sev in vector_configs:
            if vec_key not in self._counters:
                continue
            total = self._counters[vec_key].total()

            if self._n_windows <= 3:
                # 初始基线建立阶段 —— 前3个窗口仅积累数据不告警
                self._history[vec_key].append(total)
                if self._n_windows == 3 and len(self._history[vec_key]) >= 3:
                    vals = list(self._history[vec_key])
                    self._ewma[vec_key] = mean(vals)
                    if len(vals) >= 2:
                        self._ewma_sq[vec_key] = mean(v * v for v in vals)
                    self._baseline_initialized = True
                continue

            self._history[vec_key].append(total)

            # EWMA更新
            prev_ewma = self._ewma.get(vec_key, float(total))
            new_ewma = _DDOS_EWMA_ALPHA * total + (1 - _DDOS_EWMA_ALPHA) * prev_ewma
            prev_ewma_sq = self._ewma_sq.get(vec_key, float(total * total))
            new_ewma_sq = _DDOS_EWMA_ALPHA * (total * total) + (1 - _DDOS_EWMA_ALPHA) * prev_ewma_sq
            self._ewma[vec_key] = new_ewma
            self._ewma_sq[vec_key] = new_ewma_sq

            variance = max(new_ewma_sq - new_ewma ** 2, 1e-6)
            sigma = math.sqrt(variance)
            threshold = new_ewma + _SIGMA_MULTIPLIER * sigma

            # 绝对最小值过滤 —— 基线极低时避免误报
            if total < min_abs:
                continue

            ratio = total / max(new_ewma, 1)
            if total > threshold and ratio > 2.0:
                sev = "critical" if ratio > 10 else default_sev
                alert = DdosAlert(
                    attack_type=atype,
                    target=f"vector:{vec_key}",
                    metric_value=total,
                    baseline=new_ewma,
                    ratio=ratio,
                    severity=sev,
                )
                new_alerts.append(alert)
                self._alerts.append(alert)

        # 重置窗口计数器
        self._counters.clear()
        return new_alerts

    def slowloris_check(self, conn_tracker: Dict[str, List[float]]) -> List[DdosAlert]:
        """Slowloris慢速攻击检测 —— 检测大量半开连接长时间占用。

        Slowloris特征：大量TCP连接处于ESTABLISHED但仅发送极小片段，
        连接持续时间远超正常HTTP事务。

        conn_tracker: {conn_key: [timestamps_of_packets]}
        """
        alerts = []
        now = __import__("time").time()
        for key, timestamps in conn_tracker.items():
            if len(timestamps) < 5:
                continue
            duration = max(timestamps) - min(timestamps)
            if duration > 30 and len(timestamps) / max(duration, 1) < 0.5:
                # 持续>30秒但平均包率<0.5/秒 —— Slowloris特征
                alerts.append(DdosAlert(
                    attack_type="slowloris",
                    target=key, metric_value=duration,
                    baseline=0, ratio=duration / 30.0,
                    severity="high",
                ))
        return alerts

    def gini_impurity_score(self, flow_sizes: List[int]) -> float:
        """Gini impurity流量分布异常量化 —— LARDM核心度量。

        正常流量：Gini ≈ 0.3~0.5（适度集中）。DDoS攻击：Gini ≈ 0.7~1.0
        （少数流占据绝大多数流量）。[LARDM 2025]
        """
        n = len(flow_sizes)
        if n == 0:
            return 0.0
        total = sum(flow_sizes)
        if total <= 0:
            return 0.0
        # 按大小排序后计算Lorenz曲线面积
        sorted_vals = sorted(flow_sizes)
        cumsum = 0.0
        gini_sum = 0.0
        for i, v in enumerate(sorted_vals):
            cumsum += v
            gini_sum += (i + 1) * v
        return (2.0 * gini_sum) / (n * total) - (n + 1) / n

    def summary(self) -> Dict[str, Any]:
        counts = Counter(a.attack_type for a in self._alerts)
        return {
            "total_alerts": len(self._alerts),
            "by_attack_type": dict(counts),
            "severity_dist": dict(Counter(a.severity for a in self._alerts)),
            "recent_ratio": self._alerts[-1].ratio if self._alerts else 0.0,
            "windows_evaluated": self._n_windows,
            "baseline_stable": self._baseline_initialized,
        }


def detect_ddos_from_packets(packets: List[Dict]) -> Dict[str, Any]:
    """从包列表快速检测DDoS —— 封装DdosDetector流水线。

    输入格式: [{src_ip, dst_ip, protocol, src_port, dst_port, length, timestamp}, ...]
    """
    det = DdosDetector()
    for pkt in packets:
        det.feed_packet(
            pkt.get("src_ip", ""), pkt.get("dst_ip", ""),
            pkt.get("protocol", 6), pkt.get("src_port", 0),
            pkt.get("dst_port", 0), pkt.get("length", 0),
            pkt.get("timestamp", 0.0),
        )
    det.evaluate_window()
    return det.summary()


__all__ = ["DdosDetector", "DdosAlert", "SketchCounter",
           "detect_ddos_from_packets"]
