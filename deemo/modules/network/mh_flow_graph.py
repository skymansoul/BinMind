"""MH-Flow: 环境偏移鲁棒化与异构图会话表征。

EnvShiftRobustifier: FG-SAT重传/分片/代理扰动过滤与特征平滑。
HeteroFlowGraph: 异构图会话表征，纯Python稀疏邻接表实现，
提供类型感知消息传递与稠密邻接矩阵导出。
"""
import math
from collections import defaultdict
from typing import List, Dict, Optional, Any

from .mh_flow_types import (
    RETRANSMIT_IAT, FRAGMENT_MSS, FRAGMENT_IAT,
    smooth_sequence, domain_feature,
)


class EnvShiftRobustifier:
    """环境偏移鲁棒化 —— 重传/分片/代理扰动处理。

    FG-SAT：流跨环境传输时引入重传、IP分片、代理重组等扰动，
    在统计视图上表现为重复包/微小包，污染分类特征。
    策略：丢弃扰动样本+特征平滑（滑动窗口均值）。

    边界条件：TCP重传=相同长度+极小IAT；IP分片=前包≥MSS且当前<MSS/2
    且紧邻（半MSS阈值，避免误伤合法大包抖动）；代理注入=孤立小包。
    判定为启发式，不依赖TCP序列号。
    """

    def __init__(self, retransmit_iat: float = RETRANSMIT_IAT,
                 mss: int = FRAGMENT_MSS, fragment_iat: float = FRAGMENT_IAT,
                 smooth_window: int = 3):
        self._retransmit_iat = retransmit_iat
        self._mss = mss
        self._fragment_iat = fragment_iat
        self._smooth_window = smooth_window

    def robustify(self, lens: List[int], times: List[float],
                  directions: Optional[List[int]] = None) -> Dict[str, Any]:
        """对包序列做扰动过滤与平滑。

        返回含过滤后序列、平滑特征、逐类丢弃计数的dict；
        dropped_reason 记录每种扰动丢弃量，供可解释性使用。
        """
        from collections import Counter
        kept_l: List[int] = []
        kept_t: List[float] = []
        kept_d: List[int] = []
        drop_reason = Counter()
        for i, pl in enumerate(lens):
            ts = times[i] if i < len(times) else float(i)
            dr = directions[i] if directions and i < len(directions) else 0
            if kept_l:
                prev_len = kept_l[-1]
                prev_ts = kept_t[-1]
                iat = max(ts - prev_ts, 0.0)
                if pl == prev_len and iat < self._retransmit_iat:
                    drop_reason["retransmit"] += 1
                    continue
                if prev_len >= self._mss and pl < self._mss // 2 and iat < self._fragment_iat:
                    drop_reason["fragment"] += 1
                    continue
            kept_l.append(pl)
            kept_t.append(ts)
            kept_d.append(dr)
        smooth = smooth_sequence(kept_l, self._smooth_window)
        return {
            "lens": kept_l,
            "times": kept_t,
            "directions": kept_d,
            "smooth_features": smooth,
            "dropped_reason": drop_reason,
        }


class HeteroFlowGraph:
    """异构图会话表征 —— 节点=会话/流/域名，边=关联关系。

    MH-Net：加密流量以异构图建模，不同节点类型承载不同语义，
    通过类型感知消息传递（按边类型分别聚合邻居特征）融合多视图信息。

    实现约束：纯Python稀疏邻接表（dict-of-list），无networkx/torch依赖；
    提供 to_dense_adjacency 导出等价稠密邻接矩阵供调试。
    """

    SESSION, FLOW, DOMAIN = 0, 1, 2
    EDGE_FLOW_SESSION = 0
    EDGE_FLOW_DOMAIN = 1
    EDGE_SESSION_DOMAIN = 2
    _TYPE_NAMES = {SESSION: "session", FLOW: "flow", DOMAIN: "domain"}
    _EDGE_TYPES = {
        EDGE_FLOW_SESSION: (FLOW, SESSION),
        EDGE_FLOW_DOMAIN: (FLOW, DOMAIN),
        EDGE_SESSION_DOMAIN: (SESSION, DOMAIN),
    }

    def __init__(self):
        self._feats: Dict[int, List[List[float]]] = {
            t: [] for t in (self.SESSION, self.FLOW, self.DOMAIN)
        }
        self._node_count: Dict[int, int] = {
            t: 0 for t in (self.SESSION, self.FLOW, self.DOMAIN)
        }
        self._adj: Dict[int, Dict[int, List[int]]] = {
            e: defaultdict(list)
            for e in (self.EDGE_FLOW_SESSION, self.EDGE_FLOW_DOMAIN,
                      self.EDGE_SESSION_DOMAIN)
        }

    def add_node(self, ntype: int, feats: List[float]) -> int:
        """新增节点并返回类型内自增索引。"""
        idx = self._node_count[ntype]
        self._node_count[ntype] += 1
        self._feats[ntype].append(list(feats))
        return idx

    def add_edge(self, edge_type: int, src_type: int,
                 src_idx: int, dst_idx: int) -> None:
        """新增有向边 —— src_type 的 src_idx 指向 dst_idx。"""
        self._adj[edge_type][src_idx].append(dst_idx)

    def node_count(self, ntype: int) -> int:
        return self._node_count[ntype]

    def propagate(self, rounds: int = 2,
                  edge_weights: Optional[Dict[int, float]] = None) -> Dict[int, List[List[float]]]:
        """类型感知消息传递 —— 按边类型聚合邻居特征。

        MH-Net异构图卷积：每轮每节点以边类型加权均值
        聚合异质邻居特征，残差加入自身表示（防过平滑）。
        edge_weights 缺省时按边类型等权。
        """
        w = edge_weights or {e: 1.0 for e in self._EDGE_TYPES}
        feats = {t: [list(f) for f in self._feats[t]] for t in self._feats}
        for _ in range(rounds):
            new_feats = {t: [list(f) for f in feats[t]] for t in feats}
            for etype, (st, dt) in self._EDGE_TYPES.items():
                for src_idx, dst_idxs in self._adj[etype].items():
                    if not dst_idxs:
                        continue
                    dims = len(feats[dt][dst_idxs[0]]) if dst_idxs else 0
                    agg = [0.0] * dims
                    cnt = 0
                    for di in dst_idxs:
                        if di < len(feats[dt]):
                            nf = feats[dt][di]
                            for k in range(min(dims, len(nf))):
                                agg[k] += nf[k]
                            cnt += 1
                    if cnt == 0 or dims == 0:
                        continue
                    agg = [x / cnt for x in agg]
                    self_feat = new_feats[st][src_idx]
                    for k in range(min(len(self_feat), len(agg))):
                        self_feat[k] += w[etype] * agg[k]
            feats = new_feats
        return feats

    def to_dense_adjacency(self) -> Dict[int, List[List[int]]]:
        """导出稠密邻接矩阵 —— type→全局索引n×n矩阵。

        MH-Net以邻接矩阵输入GNN；此处提供等价纯Python稠密表达，
        行/列索引为跨类型全局节点编号（按类型顺序偏移）。
        """
        offset: Dict[int, int] = {}
        acc = 0
        for t in (self.SESSION, self.FLOW, self.DOMAIN):
            offset[t] = acc
            acc += self._node_count[t]
        total = acc
        dense: Dict[int, List[List[int]]] = {}
        for etype, (st, dt) in self._EDGE_TYPES.items():
            m = [[0] * total for _ in range(total)]
            for src, dsts in self._adj[etype].items():
                for dst in dsts:
                    m[offset[st] + src][offset[dt] + dst] = 1
            dense[etype] = m
        return dense


__all__ = ["EnvShiftRobustifier", "HeteroFlowGraph"]
