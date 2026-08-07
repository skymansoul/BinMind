"""MH-Flow: 多视图异构图加密流量分类 + 环境偏移鲁棒流图。

设计创新点（相对模块内既有单一统计视图方法）：
1. 多视图特征抽取 —— TLS指纹视图/报文大小序列视图/时序视图/可读明文段视图；
2. 异构图会话表征 —— 节点=会话/流/域名，边=关联关系，纯Python邻接矩阵实现；
3. 环境偏移鲁棒表示 —— 丢弃重传/分片扰动样本+特征平滑；
4. 明文预筛两阶段 —— 含可读明文段的会话先做明文规则分类，其余进入异构图分类。

模块拆分：
- mh_flow_types: 常量/数据结构/工具函数
- mh_flow_views: 多视图特征抽取器
- mh_flow_graph: 环境偏移鲁棒化+异构图会话表征
- mh_flow_classify: 多视图融合分类器
- mh_flow: 两阶段流水线+便捷入口（本文件）
"""
import logging
from collections import Counter, defaultdict
from typing import List, Dict, Optional, Tuple, Any, Set

from .mh_flow_types import (
    SessionRecord, MultiViewFeatures, PLAINTEXT_MARKERS, TLS_DIM, SIZE_DIM,
)
from .mh_flow_views import MultiViewExtractor
from .mh_flow_graph import EnvShiftRobustifier, HeteroFlowGraph
from .mh_flow_classify import MhFlowClassifier, split_view_vector
from .mh_flow_types import domain_feature

_log = logging.getLogger(__name__)


class TwoStagePipeline:
    """两阶段明文/密文分类流水线。

    对含可读明文段会话先用廉价规则分类（明文视图协议标记判别），
    置信度高直接返回；其余进入异构图分类（图消息传递+多视图原型匹配）。
    避免对明文流量做无谓的密文建模。
    """

    def __init__(self, robustifier: Optional[EnvShiftRobustifier] = None,
                 extractor: Optional[MultiViewExtractor] = None,
                 classifier: Optional[MhFlowClassifier] = None):
        self._robust = robustifier or EnvShiftRobustifier()
        self._extractor = extractor or MultiViewExtractor()
        self._classifier = classifier or MhFlowClassifier()
        self._results: List[Dict[str, Any]] = []

    def _robust_session(self, s: SessionRecord) -> Tuple[SessionRecord, Dict[str, Any]]:
        """应用环境偏移鲁棒化 —— 返回过滤后会话与鲁棒化元信息。"""
        rob = self._robust.robustify(s.packet_lens, s.packet_times, s.directions)
        rs = SessionRecord(
            session_key=s.session_key,
            packet_lens=rob["lens"], packet_times=rob["times"],
            directions=rob["directions"],
            payloads=s.payloads, domains=s.domains,
            tls_ciphers=s.tls_ciphers, tls_extensions=s.tls_extensions,
        )
        return rs, rob

    @staticmethod
    def _session_id(s: SessionRecord) -> str:
        """会话分组ID —— 取五元组键中的源端前缀，缺省回退整条流。"""
        key = s.session_key or ""
        for sep in ("|", "-"):
            if sep in key:
                return key.split(sep)[0]
        return key

    def build_graph(self, sessions: List[SessionRecord]) -> HeteroFlowGraph:
        """从会话批构建异构图 —— 流/会话/域名三类节点。"""
        g = HeteroFlowGraph()
        session_node: Dict[str, int] = {}
        domain_node: Dict[str, int] = {}
        session_fv: Dict[str, List[float]] = {}
        session_flows: Dict[str, List[int]] = defaultdict(list)
        session_domains: Dict[str, Set[str]] = defaultdict(set)

        for s in sessions:
            feats = self._extractor.extract(s)
            fv = feats.tls_view + feats.size_view + feats.timing_view + feats.plaintext_view
            fi = g.add_node(HeteroFlowGraph.FLOW, fv)
            sid = self._session_id(s)
            session_flows[sid].append(fi)
            if sid not in session_fv:
                session_fv[sid] = [float(x) for x in fv]
            else:
                cur = session_fv[sid]
                for k in range(min(len(cur), len(fv))):
                    cur[k] = (cur[k] + fv[k]) / 2.0
            for dom in (s.domains or []):
                if not dom:
                    continue
                session_domains[sid].add(dom)
                if dom not in domain_node:
                    domain_node[dom] = g.add_node(HeteroFlowGraph.DOMAIN,
                                                   domain_feature(dom))
                g.add_edge(HeteroFlowGraph.EDGE_FLOW_DOMAIN,
                           HeteroFlowGraph.FLOW, fi, domain_node[dom])

        for sid, fv in session_fv.items():
            snode = g.add_node(HeteroFlowGraph.SESSION, fv)
            session_node[sid] = snode
            for fi in session_flows[sid]:
                g.add_edge(HeteroFlowGraph.EDGE_FLOW_SESSION,
                           HeteroFlowGraph.FLOW, fi, snode)
            for dom in session_domains[sid]:
                if dom in domain_node:
                    g.add_edge(HeteroFlowGraph.EDGE_SESSION_DOMAIN,
                               HeteroFlowGraph.SESSION, snode, domain_node[dom])
        return g

    def classify_batch(self, sessions: List[SessionRecord]) -> List[Dict[str, Any]]:
        """对会话批执行两阶段分类。"""
        results: List[Dict[str, Any]] = []
        robust_sessions = []
        for s in sessions:
            rs, _rob = self._robust_session(s)
            robust_sessions.append((s, rs, _rob))
        graph = self.build_graph([rs for _, rs, _ in robust_sessions])
        refined = graph.propagate(rounds=2)
        for i, (s, rs, rob) in enumerate(robust_sessions):
            rvec = refined[HeteroFlowGraph.FLOW][i] if i < len(refined[HeteroFlowGraph.FLOW]) else []
            res = self._classify_one(rs, rvec)
            res["session_key"] = s.session_key
            res["dropped"] = dict(rob["dropped_reason"])
            res["smooth_mean"] = rob["smooth_features"].get("mean", 0.0)
            res["smooth_residual"] = rob["smooth_features"].get("residual", 0.0)
            self._results.append(res)
            results.append(res)
        return results

    def _classify_one(self, s: SessionRecord,
                      refined_vec: Optional[List[float]] = None) -> Dict[str, Any]:
        """单会话两阶段分类 —— 明文预筛优先，未命中走图分类。"""
        feats = self._extractor.extract(s)
        plain = feats.plaintext_view
        # 阶段一：明文预筛
        if plain and len(plain) >= 4 and plain[0] > 0.3 and plain[3] > 0.0:
            cls = self._plaintext_rule_classify(feats.raw_plaintext)
            if cls != "unknown":
                return {"class": cls,
                        "confidence": min(0.6 + plain[0] * 0.4, 1.0),
                        "stage": "plaintext"}
        # 阶段二：图分类
        if refined_vec and len(refined_vec) >= TLS_DIM + SIZE_DIM:
            feats2 = split_view_vector(refined_vec)
        else:
            feats2 = feats
        res = self._classifier.predict(feats2)
        res["stage"] = "graph"
        return res

    @staticmethod
    def _plaintext_rule_classify(segs: List[bytes]) -> str:
        """明文协议标记判别 —— 两阶段中明文阶段规则分类。"""
        if not segs:
            return "unknown"
        joined = b" ".join(segs[:8])
        for cls_name, markers in PLAINTEXT_MARKERS.items():
            for mk in markers:
                if mk in joined:
                    return cls_name
        return "unknown"

    def summary(self) -> Dict[str, Any]:
        if not self._results:
            return {"total_sessions": 0}
        classes = Counter(r.get("class", "unknown") for r in self._results)
        stages = Counter(r.get("stage", "graph") for r in self._results)
        dropped = Counter()
        for r in self._results:
            dropped.update(r.get("dropped", {}))
        return {
            "total_sessions": len(self._results),
            "class_distribution": dict(classes.most_common()),
            "stage_distribution": dict(stages.most_common()),
            "perturbation_dropped": dict(dropped),
        }


# 便捷入口
def session_from_flow_dict(flow: Dict[str, Any]) -> SessionRecord:
    """从流字典构造会话记录 —— 兼容 encrypted_traffic_classifier 的流格式。"""
    return SessionRecord(
        session_key=str(flow.get("key", "flow")),
        packet_lens=[int(x) for x in (flow.get("lengths") or [])],
        packet_times=[float(x) for x in (flow.get("timestamps") or [])],
        directions=[int(x) for x in (flow.get("directions") or [])],
        payloads=list(flow.get("payloads") or []),
        domains=[str(d) for d in (flow.get("domains") or [])],
        tls_ciphers=[int(x) for x in (flow.get("tls_ciphers") or [])],
        tls_extensions=[int(x) for x in (flow.get("tls_extensions") or [])],
    )


def classify_mh_flow(flows: List[Dict[str, Any]],
                     fit_samples: Optional[List[Tuple[str, MultiViewFeatures]]] = None,
                     use_default_prototypes: bool = True) -> List[Dict[str, Any]]:
    """便捷入口 —— 输入流字典列表，返回两阶段分类结果。"""
    pipe = TwoStagePipeline(classifier=MhFlowClassifier(
        use_default_prototypes=use_default_prototypes))
    if fit_samples:
        pipe._classifier.fit(fit_samples)
    sessions = [session_from_flow_dict(f) for f in flows]
    return pipe.classify_batch(sessions)


__all__ = [
    "SessionRecord", "MultiViewFeatures", "MultiViewExtractor",
    "EnvShiftRobustifier", "HeteroFlowGraph", "MhFlowClassifier",
    "TwoStagePipeline", "classify_mh_flow", "session_from_flow_dict",
]
