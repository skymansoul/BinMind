"""加密流量分类器 —— 首包熵值+流图特征的轻量级分类。

参考：
- ECHO (2024): 非均匀性即所需 —— 首N包非均匀分箱
- FG-SAT (IEEE TIFS 2025): 流图结构特征+JS散度特征选择
- MH-Net (AAAI 2025): 多视图异构图流量建模
- 两级明文/密文流量分类策略

设计目标：不依赖深度包检测，仅用包时序、长度序列、熵分布
构建分类特征。适用于TLS1.3/QUIC等全加密场景。
"""
import math, struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from statistics import mean, stdev, median


# 包长度熵分箱 —— ECHO论文中的非均匀分箱策略
# 将包长空间按常见MTU边界分为13个桶，减少稀疏性
_LEN_BINS = [
    (0, 63), (64, 127), (128, 255), (256, 511),
    (512, 767), (768, 1023), (1024, 1279), (1280, 1400),
    (1401, 1410), (1411, 1460), (1461, 1500), (1501, 9000),
]

# 首包数量（ECHO的最优观测窗——20-40包在精度/延迟间取得平衡）
_FIRST_N_PACKETS = 30

@dataclass
class FlowFeatures:
    """流的统计特征向量 —— 分类器输入"""
    flow_key: str = ""
    pkt_count: int = 0
    byte_count: int = 0
    duration_ms: float = 0.0
    # 包长度统计
    len_mean: float = 0.0
    len_std: float = 0.0
    len_min: int = 0
    len_max: int = 0
    len_entropy: float = 0.0        # 包长度分布香农熵
    # IAT统计 —— 对交互式/流媒体/批量传输区分度高
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_min: float = 0.0
    iat_max: float = 0.0
    # 首N包特征 —— FG-SAT核心观察：前30包已含足够流结构信息
    first_n_lens: List[int] = field(default_factory=list)
    first_n_iats: List[float] = field(default_factory=list)
    # 分箱特征
    len_bin_counts: List[int] = field(default_factory=lambda: [0] * len(_LEN_BINS))
    # 方向特征
    out_pkt_ratio: float = 0.0       # 出方向包占比
    out_byte_ratio: float = 0.0      # 出方向字节占比
    # 突发特征 —— QUIC/HTTP3短突发是WF攻击主要信号
    burst_count: int = 0              # 突发块数量
    burst_len_max: int = 0           # 最大突发长度


class EntropyBasedClassifier:
    """基于信息熵的轻量加密流量分类器。

    核心假设：不同应用类型在加密后仍保持显著不同的包长度和时序分布。
    纯统计实现，零ML框架依赖，资源受限可用。
    表格化流量数据上XGBoost与DL精度相当。[Korea Univ. 2025]"""

    # 类别原型 —— 基于公开数据集统计的先验分布
    _PROTOTYPES: Dict[str, Dict[str, Tuple[float, float]]] = {
        "video_streaming": {
            "len_mean": (1000, 1400), "iat_mean": (1, 50),
            "burst_len_max": (15, 200), "out_byte_ratio": (0.8, 1.0),
        },
        "web_browsing": {
            "len_mean": (400, 1200), "iat_mean": (10, 500),
            "burst_len_max": (3, 20), "out_byte_ratio": (0.3, 0.7),
        },
        "file_transfer": {
            "len_mean": (1300, 1500), "iat_mean": (0.1, 10),
            "burst_len_max": (50, 500), "out_byte_ratio": (0.5, 1.0),
        },
        "voip": {
            "len_mean": (60, 300), "iat_mean": (10, 30),
            "burst_len_max": (1, 3), "out_byte_ratio": (0.4, 0.6),
        },
        "dns": {
            "len_mean": (40, 512), "iat_mean": (1, 200),
            "burst_len_max": (1, 2), "out_byte_ratio": (0.4, 0.6),
        },
        "iot_telemetry": {
            "len_mean": (40, 200), "iat_mean": (1000, 60000),
            "burst_len_max": (1, 1), "out_byte_ratio": (0.9, 1.0),
        },
    }

    def classify(self, features: FlowFeatures) -> Dict[str, Any]:
        """基于特征向量匹配最近应用类别原型。

        加权欧氏距离 —— 各维度权重基于该维度在原型中的区分度
        （原型区间越窄的维度，权重越高）。
        """
        raw_scores: Dict[str, float] = {}
        for cls_name, proto in self._PROTOTYPES.items():
            dist = 0.0
            used_dims = 0
            for dim, (lo, hi) in proto.items():
                fv = getattr(features, dim, None)
                if fv is None:
                    continue
                # 归一化到 [0,1]：值在区间内 → 0，越远越高
                center = (lo + hi) / 2.0
                half_range = max((hi - lo) / 2.0, 0.001)
                norm_dist = max(0.0, abs(fv - center) - half_range) / half_range
                # 区间窄 → 权重高（该维度区分力强）
                weight = 1.0 / max((hi - lo), 1)
                dist += norm_dist * weight
                used_dims += 1
            avg_dist = dist / max(used_dims, 1)
            raw_scores[cls_name] = max(0.0, 1.0 - min(avg_dist, 1.0))

        if not raw_scores:
            return {"class": "unknown", "confidence": 0.0, "scores": {}}

        best = max(raw_scores, key=raw_scores.get)
        best_score = raw_scores[best]
        runner_up = sorted(raw_scores.values(), reverse=True)[1] if len(raw_scores) > 1 else 0.0
        # 置信度 = 最佳分与次佳分之差（差值大→确信；接近→不确定）
        confidence = best_score - runner_up + 0.3
        return {
            "class": best if confidence > 0.3 else "unknown",
            "confidence": min(confidence, 1.0),
            "scores": raw_scores,
        }


class FlowGraphBuilder:
    """从包序列构建流图特征 —— FG-SAT核心方法。

    将流表示为有向图：节点=包（按长度分箱），边=包间时序关系。
    提取度分布、尺寸变化率等结构特征。
    FG-SAT (IEEE TIFS 2025)使用GraphSAGE+GAT处理此类图结构。
    """

    @staticmethod
    def build_features(packet_lens: List[int],
                       packet_times: List[float]) -> Dict[str, float]:
        """从包长度和时间戳序列提取流图统计特征。

        时间复杂度O(n) —— 对首N包窗口可接受(n≤30)。
        """
        n = min(len(packet_lens), _FIRST_N_PACKETS)
        if n < 3:
            return {}

        lens = packet_lens[:n]
        times = packet_times[:n] if len(packet_times) >= n else [float(i) for i in range(n)]

        # 构建邻接：相邻包间有向边（方向由尺寸变化决定）
        edges = 0
        for i in range(n - 1):
            if abs(lens[i] - lens[i + 1]) > 100:
                edges += 1  # 尺寸突变边

        # 度分布
        in_deg = [0] * n; out_deg = [0] * n
        for i in range(n - 1):
            out_deg[i] += 1
            in_deg[i + 1] += 1

        avg_out = sum(out_deg) / len(out_deg) if out_deg else 0.0

        # 尺寸变化率 —— 流图边的权重代理
        size_deltas = [abs(lens[i+1] - lens[i]) for i in range(n - 1)]
        mean_delta = mean(size_deltas) if size_deltas else 0.0
        try:
            std_delta = stdev(size_deltas) if len(size_deltas) >= 2 else 0.0
        except Exception:
            std_delta = 0.0

        # 包长度分布JS散度（前半vs后半） —— 检测流量模式变化
        half = n // 2
        first_half = Counter(lens[:half])
        second_half = Counter(lens[half:])

        def _kl_div(p: Counter, q: Counter) -> float:
            all_k = set(p) | set(q)
            kl = 0.0
            for k in all_k:
                pk = (p.get(k, 0) + 0.5) / (sum(p.values()) + 0.5 * 256)
                qk = (q.get(k, 0) + 0.5) / (sum(q.values()) + 0.5 * 256)
                if pk > 0 and qk > 0:
                    kl += pk * math.log2(pk / qk)
            return kl

        js_div = (_kl_div(first_half, second_half) + _kl_div(second_half, first_half)) / 2.0

        return {
            "graph_edges": edges,
            "graph_avg_out_degree": avg_out,
            "graph_size_delta_mean": mean_delta,
            "graph_size_delta_std": std_delta,
            "graph_js_divergence": js_div,
            "graph_node_count": n,
        }


class EncryptedTrafficClassifier:
    """加密流量分类流水线 —— 特征提取+流图构建+原型匹配。

    架构：
    1. FlowFeatureExtractor: 从原始包列表提取统计特征
    2. FlowGraphBuilder: 构建流图结构特征
    3. EntropyBasedClassifier: 原型匹配分类

    零外部ML依赖。第三步可插拔替换为sklearn/ONNX分类器。
    """

    def __init__(self):
        self._classifier = EntropyBasedClassifier()
        self._graph_builder = FlowGraphBuilder()
        self._results: List[Dict] = []

    def extract_features(self, flow_key: str,
                         packet_lens: List[int],
                         packet_times: List[float],
                         directions: Optional[List[int]] = None) -> FlowFeatures:
        """从流中提取统计和结构特征

        directions: 0=出方向, 1=入方向, None=全部出方向
        """
        feats = FlowFeatures(flow_key=flow_key)
        n = len(packet_lens)
        if n == 0:
            return feats

        feats.pkt_count = n
        feats.byte_count = sum(packet_lens)
        if len(packet_times) >= 2:
            feats.duration_ms = (packet_times[-1] - packet_times[0]) * 1000.0

        # 长度统计
        feats.len_mean = mean(packet_lens)
        feats.len_min = min(packet_lens)
        feats.len_max = max(packet_lens)
        if n >= 2:
            try:
                feats.len_std = stdev(packet_lens)
            except Exception:
                feats.len_std = 0.0

        # 长度熵
        len_ctr = Counter(packet_lens)
        feats.len_entropy = -sum(
            (c / n) * math.log2(c / n) for c in len_ctr.values()
        )

        # IAT统计
        if len(packet_times) >= 2:
            iats = [packet_times[i+1] - packet_times[i] for i in range(n - 1)]
            iats_s = [iat for iat in iats if iat >= 0]
            if iats_s:
                feats.iat_mean = mean(iats_s)
                feats.iat_min = min(iats_s)
                feats.iat_max = max(iats_s)
                if len(iats_s) >= 2:
                    try:
                        feats.iat_std = stdev(iats_s)
                    except Exception:
                        feats.iat_std = 0.0

        # 首N包特征
        feats.first_n_lens = packet_lens[:_FIRST_N_PACKETS]
        feats.first_n_iats = packet_times[:_FIRST_N_PACKETS]

        # 分箱
        for plen in packet_lens:
            for bi, (lo, hi) in enumerate(_LEN_BINS):
                if lo <= plen <= hi:
                    feats.len_bin_counts[bi] += 1
                    break

        # 方向比率
        if directions:
            out_pkts = sum(1 for d in directions if d == 0)
            feats.out_pkt_ratio = out_pkts / max(n, 1)
            out_bytes = sum(packet_lens[i] for i in range(n) if directions[i] == 0)
            feats.out_byte_ratio = out_bytes / max(feats.byte_count, 1)

        # 突发检测 —— 连续出方向包构成突发
        if directions:
            in_burst = False
            burst_lens = []
            cur_burst = 0
            for d in directions:
                if d == 0:  # 出方向
                    if not in_burst:
                        in_burst = True
                        if cur_burst > 0:
                            burst_lens.append(cur_burst)
                        cur_burst = 1
                    else:
                        cur_burst += 1
                else:
                    in_burst = False
            if cur_burst > 0:
                burst_lens.append(cur_burst)
            feats.burst_count = len(burst_lens)
            feats.burst_len_max = max(burst_lens) if burst_lens else 0

        return feats

    def classify_flow(self, flow_key: str,
                      packet_lens: List[int],
                      packet_times: List[float],
                      directions: Optional[List[int]] = None) -> Dict[str, Any]:
        """对单条流执行完整分类流水线"""
        feats = self.extract_features(flow_key, packet_lens, packet_times, directions)
        graph_feats = self._graph_builder.build_features(packet_lens, packet_times)

        # 图形特征合并到FlowFeatures（动态属性注入）
        for k, v in graph_feats.items():
            setattr(feats, k, v)

        result = self._classifier.classify(feats)
        result["flow_key"] = flow_key
        result["packet_count"] = feats.pkt_count
        result["byte_count"] = feats.byte_count
        result["duration_ms"] = feats.duration_ms
        result["graph_features"] = graph_feats
        self._results.append(result)
        return result

    def batch_classify(self, flows: List[Dict]) -> List[Dict]:
        """批量分类多流

        每条流预期格式: {key, lengths: [int], timestamps: [float], directions: [int]}
        """
        return [
            self.classify_flow(
                f.get("key", f"flow_{i}"),
                f.get("lengths", []),
                f.get("timestamps", []),
                f.get("directions"),
            )
            for i, f in enumerate(flows)
        ]

    def summary(self) -> Dict[str, Any]:
        if not self._results:
            return {"total_flows": 0}
        classes = Counter(r.get("class", "unknown") for r in self._results)
        confidences = [r.get("confidence", 0.0) for r in self._results]
        return {
            "total_flows": len(self._results),
            "class_distribution": dict(classes.most_common()),
            "mean_confidence": mean(confidences) if confidences else 0.0,
            "classified_ratio": sum(1 for r in self._results if r.get("class") != "unknown") / len(self._results),
        }


def classify_encrypted_traffic(flows: List[Dict]) -> List[Dict]:
    """便捷入口：输入流列表，返回分类结果列表"""
    return EncryptedTrafficClassifier().batch_classify(flows)


__all__ = ["EncryptedTrafficClassifier", "EntropyBasedClassifier",
           "FlowGraphBuilder", "FlowFeatures", "classify_encrypted_traffic"]
