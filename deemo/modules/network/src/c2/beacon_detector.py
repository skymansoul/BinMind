"""C2信标检测 — 统计周期分析+熵差判定——识别恶意软件命令控制信道。

恶意软件C2通信的核心特征——周期性信标(beaconing)：
受控端定期向C2服务器发送心跳(HTTP GET / DNS TXT / ICMP echo)，
间隔通常在 30s-24h 之间。与正常流量的区别在于：
1. 周期性极度规律（抖动<5% vs 正常流量的非周期突发）。
2. 载荷熵低（加密/编码后的固定格式数据 vs 正常流量的可变内容）。
3. 请求目标集极小（1-3个IP vs 浏览器的数十个域名）。

本模块的三维判定：
D1-Lomb-Scargle周期图→检测非均匀采样下的隐含周期（处理丢包/重传的间隔抖动）。
D2-滑动窗载荷熵差→信标帧载荷熵显著低于同流其他帧。
D3-目标集聚集度→通信对端IP/域名的香农熵。

三维得分加权融合→信标概率。与既有IDS(基于已知IOC匹配)不同，
本方案不需要已知C2签名——纯统计判定。

- Lomb: 非均匀采样周期图——处理真实网络中不规则的包到达间隔。
- "Detecting Malware C2 Channels": 信标检测的统计方法综述。
"""

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

@dataclass
class FlowRecord:
    """一条通信流的概要。"""
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    timestamps: List[float] = field(default_factory=list)  # 发包时间戳
    payload_sizes: List[int] = field(default_factory=list)
    payload_entropies: List[float] = field(default_factory=list)

    @property
    def interval_mean(self) -> float:
        if len(self.timestamps) < 2:
            return 0.0
        _ints = [self.timestamps[i] - self.timestamps[i-1]
                 for i in range(1, len(self.timestamps))]
        return sum(_ints) / len(_ints)

    @property
    def interval_jitter(self) -> float:
        """间隔变异系数——规律性度量。低值=高度规律。"""
        if len(self.timestamps) < 3:
            return 1.0
        _ints = [self.timestamps[i] - self.timestamps[i-1]
                 for i in range(1, len(self.timestamps))]
        _mean = sum(_ints) / len(_ints)
        if _mean < _EPS:
            return 1.0
        _var = sum((x - _mean) ** 2 for x in _ints) / len(_ints)
        return math.sqrt(_var) / _mean

@dataclass
class BeaconScore:
    """一条流的信标评分。"""
    flow_id: str
    periodicity_score: float    # D1: Lomb-Scargle周期显著性
    entropy_drop_score: float   # D2: 载荷熵异常降低
    target_concentration: float # D3: 目标聚集度
    composite_score: float
    is_beacon: bool
    estimated_interval: float = 0.0

class C2BeaconDetector:
    """C2信标检测器——三维统计判定。

    使用范式：
      detector = C2BeaconDetector()
      for flow in flows:
          detector.ingest_flow(flow)
      scores = detector.score_all()
    """

    def __init__(
        self,
        periodicity_weight: float = 0.45,
        entropy_weight: float = 0.35,
        target_weight: float = 0.20,
        beacon_threshold: float = 0.65,
        min_observations: int = 10,
    ):
        self.periodicity_weight = periodicity_weight
        self.entropy_weight = entropy_weight
        self.target_weight = target_weight
        self.beacon_threshold = beacon_threshold
        self.min_observations = min_observations

        self._flows: Dict[str, FlowRecord] = {}
        # 全局目标聚集度——跨流统计
        self._global_destinations: Dict[str, int] = defaultdict(int)

    def ingest_flow(self, flow: FlowRecord):
        """摄入一条通信流记录。"""
        self._flows[flow.flow_id] = flow
        self._global_destinations[flow.dst_ip] += 1

    def score_all(self) -> List[BeaconScore]:
        """对所有已摄入流进行信标评分。"""
        _scores: List[BeaconScore] = []
        _total_flows = max(len(self._flows), 1)

        for _fid, _flow in self._flows.items():
            if len(_flow.timestamps) < self.min_observations:
                continue

            _d1 = self._score_periodicity(_flow)
            _d2 = self._score_entropy_drop(_flow)
            _d3 = self._score_target_concentration(_flow, _total_flows)

            _composite = (
                _d1 * self.periodicity_weight
                + _d2 * self.entropy_weight
                + _d3 * self.target_weight
            )
            _scores.append(BeaconScore(
                flow_id=_fid,
                periodicity_score=_d1,
                entropy_drop_score=_d2,
                target_concentration=_d3,
                composite_score=round(_composite, 4),
                is_beacon=_composite >= self.beacon_threshold,
                estimated_interval=_flow.interval_mean,
            ))

        # 降序排列——最高信标概率的流排在最前
        _scores.sort(key=lambda s: s.composite_score, reverse=True)
        return _scores

    def detect_c2_clusters(self) -> List[Dict[str, Any]]:
        """检测C2集群——共享目标IP的高信标概率流组。"""
        _scores = self.score_all()
        _beacons = [s for s in _scores if s.is_beacon]

        _by_dst: Dict[str, List[str]] = defaultdict(list)
        for _b in _beacons:
            _flow = self._flows.get(_b.flow_id)
            if _flow:
                _by_dst[_flow.dst_ip].append(_b.flow_id)

        _clusters = []
        for _ip, _flow_ids in _by_dst.items():
            if len(_flow_ids) >= 2:
                _clusters.append({
                    "c2_ip": _ip,
                    "infected_hosts": list(set(
                        self._flows[fid].src_ip for fid in _flow_ids
                    )),
                    "flow_count": len(_flow_ids),
                    "avg_beacon_score": round(
                        sum(s.composite_score for s in _beacons
                            if s.flow_id in _flow_ids) / len(_flow_ids), 4
                    ),
                })

        return _clusters

    # 三维得分计算

    @staticmethod
    def _score_periodicity(flow: FlowRecord) -> float:
        """D1: 周期显著性——简化自相关近似（完整 Lomb-Scargle 需要 FFT）。

        对非均匀采样使用自相关替代完整 LS 周期图，
        计算时延τ下的自相关系数峰值作为周期性强度的代理指标。
        精度低于完整 LS 但对检测目的足够——C2信标周期通常极规则。
        """
        _n = len(flow.timestamps)
        if _n < 5:
            return 0.0

        _ints = [flow.timestamps[i] - flow.timestamps[i-1]
                 for i in range(1, _n)]
        _mean = sum(_ints) / len(_ints)

        # 归一化自相关——找最高峰值
        _max_acf = 0.0
        _best_lag = 0
        for _lag in range(1, min(_n // 2, 20)):
            _num = 0.0
            _den = 0.0
            for _i in range(_n - _lag - 1):
                _num += (_ints[_i] - _mean) * (_ints[_i + _lag] - _mean)
                _den += (_ints[_i] - _mean) ** 2
            _acf = _num / max(_den, _EPS)
            if _acf > _max_acf:
                _max_acf = _acf

        # 抖动惩罚——变异系数越高，周期越不可信
        _jitter = flow.interval_jitter
        _jitter_penalty = max(0.0, 1.0 - _jitter * 2.0)

        return min(1.0, max(0.0, _max_acf * _jitter_penalty))

    @staticmethod
    def _score_entropy_drop(flow: FlowRecord) -> float:
        """D2: 载荷熵异常降低——信标帧通常编码固定格式数据。

        比较当前帧与滑动窗口内历史帧的熵差异。
        """
        if len(flow.payload_entropies) < 4:
            return 0.0

        _window = min(10, len(flow.payload_entropies))
        _recent = flow.payload_entropies[-_window:]
        _earlier = flow.payload_entropies[:-_window] if len(flow.payload_entropies) > _window else _recent

        _recent_mean = sum(_recent) / len(_recent)
        _earlier_mean = sum(_earlier) / max(len(_earlier), 1)

        # 近期熵显著低于历史 → 可能是信标模式（周期性低熵帧）
        _drop = _earlier_mean - _recent_mean
        return max(0.0, min(1.0, _drop / max(_earlier_mean, _EPS)))

    def _score_target_concentration(
        self, flow: FlowRecord, total_flows: int,
    ) -> float:
        """D3: 目标聚集度——通信对端的稀缺性。

        若该流的 dst_ip 在整个捕获中仅少量流使用→高信标概率。
        正常流量（如DNS）会与大量不同IP通信。
        """
        _dst_count = self._global_destinations.get(flow.dst_ip, 1)
        # 目标越稀有→分数越高
        _rarity = 1.0 / max(_dst_count, 1)
        # 但单次通信不足以判定→需要流的重复度
        _repetition = len(flow.timestamps) / max(total_flows, 1)
        return min(1.0, _rarity + _repetition * 0.5)

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _detector = C2BeaconDetector()

    # 模拟一条C2信标流——间隔120s，抖动<3%
    _beacon_ts = [0.0]
    for _i in range(1, 20):
        _beacon_ts.append(_beacon_ts[-1] + 120.0 + random.gauss(0, 2.0))
    _beacon_flow = FlowRecord(
        flow_id="f_beacon", src_ip="10.0.0.5", dst_ip="45.33.32.156",
        dst_port=443, protocol="tls",
        timestamps=_beacon_ts,
        payload_sizes=[64]*20,
        payload_entropies=[2.1 + random.gauss(0, 0.05) for _ in range(20)],
    )
    _detector.ingest_flow(_beacon_flow)

    # 模拟一条正常浏览流——无规律间隔
    _normal_ts = [0.0]
    for _i in range(1, 20):
        _normal_ts.append(_normal_ts[-1] + random.expovariate(0.1))
    _normal_flow = FlowRecord(
        flow_id="f_normal", src_ip="10.0.0.5", dst_ip="142.250.80.46",
        dst_port=443, protocol="tls",
        timestamps=_normal_ts,
        payload_sizes=[random.randint(100, 1500) for _ in range(20)],
        payload_entropies=[4.5 + random.gauss(0, 0.5) for _ in range(20)],
    )
    _detector.ingest_flow(_normal_flow)

    _scores = _detector.score_all()
    for _s in _scores:
        print(f"[c2] {_s.flow_id}: composite={_s.composite_score:.3f} "
              f"period={_s.periodicity_score:.3f} "
              f"entropy={_s.entropy_drop_score:.3f} "
              f"target={_s.target_concentration:.3f} "
              f"beacon={_s.is_beacon}")

    assert _scores[0].flow_id == "f_beacon", "beacon flow should score highest"
    assert _scores[0].composite_score > _scores[1].composite_score
    print("[OK] C2BeaconDetector smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
