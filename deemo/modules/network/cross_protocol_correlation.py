"""
跨协议因果关联引擎 (Cross-Protocol Causal Correlation Engine, CPCE)
----------------------------------------------------------------------
自动发现 DNS/TLS/HTTP/ICMP 间的时序因果关系,
检测多协议协同的 APT/C2 行为模式.

设计依据:
  SmartNIC 方案 和 P4 交换机方案
  均针对单一 TLS 流做 ML 分类 — 无法捕获跨协议协同.
  ZetaSwitch 案例 展示真实 C2 使用 DNS (心跳/信令) + HTTP (数据外传),
  但需人工分析关联.
  Murakami et al. 关联 sinkhole + ISP 流数据,
  但依赖已知恶意服务器列表而非行为模式.

  CPCE 自动发现协议间的 Granger 因果关系:
    DNS 查询频率异常 → 数秒后 TLS 连接建立 → HTTP POST 突发
  这种时序因果链是 APT/C2 的行为指纹, 不依赖域名/IP 黑名单.

算法:
  1. 按时间窗聚合各协议的统计特征 (频率/熵/包大小)
  2. 滑动窗口 Granger 因果检验 — 发现协议间的时间领先-滞后关系
  3. 因果链构建: 将显著的成对因果关系链成多跳路径
  4. 匹配已知 APT 行为模板 (信标 → C2 → 外传 等模式)
"""
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ProtocolWindow:
    """单协议的时间窗口统计."""
    proto: str
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    unique_destinations: int = 0
    entropy: float = 0.0
    avg_packet_size: float = 0.0
    burst_count: int = 0       # 突发次数 (包间延迟 < 10ms)


@dataclass
class CausalLink:
    """协议间因果关联 — A Granger-causes B."""
    source_proto: str
    target_proto: str
    lag_windows: int           # 领先窗口数
    f_statistic: float         # Granger F 统计量
    p_value: float
    confidence: float          # 0-1
    avg_effect_size: float     # Cohen's f²


class CrossProtocolCorrelationEngine:
    """跨协议因果关联引擎.

    用法:
      cpce = CrossProtocolCorrelationEngine(window_s=5.0, max_lag=6)
      for packet in pcap_stream:
          cpce.ingest(proto='dns', ts=packet.ts, size=len(packet), dest=packet.dst)
      links = cpce.detect_causal_links(min_confidence=0.7)
      chains = cpce.build_causal_chains(links)
    """

    def __init__(self, window_s: float = 5.0, max_lag: int = 6,
                 min_windows_for_test: int = 20):
        self._window_s = window_s
        self._max_lag = max_lag
        self._min_windows = min_windows_for_test
        # proto → deque of ProtocolWindow
        self._history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._current_windows: Dict[str, ProtocolWindow] = {}
        self._window_start: float = 0.0
        self._detected_links: List[CausalLink] = []

    def ingest(self, proto: str, ts: float, size: int = 0,
               dest: str = "", entropy_sample: float = 0.0):
        """摄入单个数据包的观测值."""
        if self._window_start == 0.0:
            self._window_start = ts

        if proto not in self._current_windows:
            self._current_windows[proto] = ProtocolWindow(
                proto=proto, start_time=ts,
                end_time=ts + self._window_s,
            )

        w = self._current_windows[proto]
        if ts > w.start_time + self._window_s:
            self._flush_window(proto)
            self._current_windows[proto] = ProtocolWindow(
                proto=proto, start_time=ts,
                end_time=ts + self._window_s,
            )
            w = self._current_windows[proto]

        w.packet_count += 1
        w.byte_count += size
        if dest:
            # 用集合近似 unique destinations
            if not hasattr(w, '_dests'):
                w._dests: Set[str] = set()
            w._dests.add(dest)
            w.unique_destinations = len(w._dests)
        w.avg_packet_size = w.byte_count / w.packet_count if w.packet_count > 0 else 0

    def _flush_window(self, proto: str):
        w = self._current_windows.get(proto)
        if w is None or w.packet_count == 0:
            return
        w.end_time = w.start_time + self._window_s
        self._history[proto].append(w)

    def detect_causal_links(self, min_confidence: float = 0.7) -> List[CausalLink]:
        """检测所有显著协议对间的 Granger 因果关系."""
        self._flush_all()
        protos = [p for p, h in self._history.items() if len(h) >= self._min_windows]
        links = []
        for src in protos:
            for tgt in protos:
                if src == tgt:
                    continue
                link = self._granger_test(src, tgt)
                if link is not None and link.confidence >= min_confidence:
                    links.append(link)
        links.sort(key=lambda x: x.confidence, reverse=True)
        self._detected_links = links
        return links

    def _flush_all(self):
        for proto in list(self._current_windows):
            self._flush_window(proto)

    def _granger_test(self, src: str, tgt: str) -> Optional[CausalLink]:
        """简化 Granger 因果检验 — 基于交叉相关 + F 近似."""
        src_wins = list(self._history[src])
        tgt_wins = list(self._history[tgt])
        n = min(len(src_wins), len(tgt_wins))
        if n < self._min_windows:
            return None

        # 特征: 包计数 — 最直接的活动指标
        src_series = [w.packet_count for w in src_wins[-n:]]
        tgt_series = [w.packet_count for w in tgt_wins[-n:]]

        best_lag = 0
        best_corr = 0.0
        for lag in range(1, min(self._max_lag + 1, n // 3)):
            corr = _pearson_r(src_series[:-lag], tgt_series[lag:])
            if abs(corr) > abs(best_corr):
                best_corr = corr
                best_lag = lag

        if abs(best_corr) < 0.3:
            return None

        # F 统计量近似: F = (r² / (k)) / ((1-r²) / (n-k-1))
        r2 = best_corr ** 2
        k = 1
        if n - k - 1 <= 0:
            return None
        f_stat = (r2 / k) / ((1 - r2) / (n - k - 1))
        # p-value 简化 (F(1, n-2) 的尾部概率用 Wilson-Hilferty 近似)
        p_val = _f_survival_approx(f_stat, k, n - k - 1)

        confidence = 1.0 - min(1.0, p_val * 2)
        effect_size = r2 / (1 - r2) if r2 < 1 else 1.0

        return CausalLink(
            source_proto=src, target_proto=tgt,
            lag_windows=best_lag,
            f_statistic=round(f_stat, 3),
            p_value=round(p_val, 4),
            confidence=round(confidence, 3),
            avg_effect_size=round(effect_size, 3),
        )

    def build_causal_chains(self, links: Optional[List[CausalLink]] = None,
                            min_chain_len: int = 2) -> List[List[CausalLink]]:
        """将成对因果关系链接为多跳因果链.
        例如: DNS → TLS → HTTP 构成完整 C2 行为链.
        """
        if links is None:
            links = self._detected_links
        adj: Dict[str, List[CausalLink]] = defaultdict(list)
        for link in links:
            adj[link.source_proto].append(link)

        chains = []
        visited_chains: Set[Tuple[str, ...]] = set()

        def dfs(current: str, path: List[str], path_links: List[CausalLink]):
            if len(path) >= min_chain_len:
                chain_key = tuple(path)
                if chain_key not in visited_chains:
                    visited_chains.add(chain_key)
                    chains.append(list(path_links))
            if len(path) >= 5:
                return
            for link in adj.get(current, []):
                if link.target_proto not in path:
                    dfs(link.target_proto, path + [link.target_proto],
                        path_links + [link])

        for proto in adj:
            dfs(proto, [proto], [])
        # 按链长度和总置信度排序
        chains.sort(key=lambda c: (len(c), sum(l.confidence for l in c)), reverse=True)
        return chains

    def match_apt_patterns(self, chains: List[List[CausalLink]]) -> List[Dict[str, Any]]:
        """匹配已知 APT 行为模板."""
        templates = [
            {
                'name': 'C2 Beacon + Exfil',
                'pattern': ['dns', 'tls', 'http'],
                'description': 'DNS心跳→TLS C2→HTTP数据外传 (ZetaSwitch模式)',
            },
            {
                'name': 'DNS Tunneling',
                'pattern': ['dns'],
                'min_confidence': 0.8,
                'description': '单一DNS协议高频大包隧道',
            },
            {
                'name': 'HTTPS C2 Only',
                'pattern': ['tls', 'http'],
                'description': 'HTTPS加密信道内完成信令+外传',
            },
        ]
        matches = []
        for tmpl in templates:
            for chain in chains:
                chain_protos = [chain[0].source_proto] + [l.target_proto for l in chain]
                if _sequence_match(tmpl['pattern'], chain_protos):
                    avg_conf = sum(l.confidence for l in chain) / len(chain)
                    if avg_conf >= tmpl.get('min_confidence', 0.5):
                        matches.append({
                            'template': tmpl['name'],
                            'chain': chain_protos,
                            'confidence': round(avg_conf, 3),
                            'description': tmpl['description'],
                        })
        return matches


def _pearson_r(x: List[float], y: List[float]) -> float:
    n = len(x)
    if n < 3:
        return 0.0
    mx = sum(x) / n; my = sum(y) / n
    num = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    dx = math.sqrt(sum((v - mx) ** 2 for v in x))
    dy = math.sqrt(sum((v - my) ** 2 for v in y))
    return num / (dx * dy) if dx > 0 and dy > 0 else 0.0


def _f_survival_approx(f: float, df1: int, df2: int) -> float:
    """F 分布生存函数近似 — Wilson-Hilferty 变换."""
    if f <= 0:
        return 1.0
    z = ((f ** (1/3)) * (1 - 2/(9*df2)) - (1 - 2/(9*df1))) / \
        math.sqrt(2/(9*df1) + 2/(9*df2))
    return max(0.0, min(1.0, 0.5 * math.erfc(z / math.sqrt(2))))


def _sequence_match(pattern: List[str], chain: List[str]) -> bool:
    """检查 pattern 是否为 chain 的子序列 (保持顺序, 不要求连续)."""
    pi = 0
    for item in chain:
        if pi < len(pattern) and item == pattern[pi]:
            pi += 1
    return pi == len(pattern)
