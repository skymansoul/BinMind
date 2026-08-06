# 分析结果共享数据类型 — 多个分析模块的轻量结果容器
# 独立文件避免跨模块导入循环, 符合渐进式抽象

from typing import Dict, List, Set


class CausalNodeScore:
    __slots__ = ("node_id","node_type","name","katz_centrality","counterfactual_impact","is_confounder")
    def __init__(self, node_id: str, node_type: str, name: str,
                 katz_centrality: float, counterfactual_impact: int,
                 is_confounder: bool):
        self.node_id = node_id; self.node_type = node_type; self.name = name
        self.katz_centrality = katz_centrality
        self.counterfactual_impact = counterfactual_impact
        self.is_confounder = is_confounder
    def to_dict(self) -> dict:
        return {"node_id":self.node_id,"type":self.node_type,"name":self.name,
                "katz":self.katz_centrality,"impact":self.counterfactual_impact,
                "confounder":self.is_confounder}


class ChainStep:
    __slots__ = ("node_id","node_type","name","causal_score","impact","position")
    def __init__(self, node_id: str, node_type: str, name: str,
                 causal_score: float, impact: int, position: str):
        self.node_id = node_id; self.node_type = node_type; self.name = name
        self.causal_score = causal_score; self.impact = impact
        self.position = position
    def to_dict(self) -> dict:
        return {"node_id":self.node_id,"type":self.node_type,"name":self.name,
                "causal_score":self.causal_score,"impact":self.impact,
                "position":self.position}


class CausalAnalysis:
    __slots__ = ("node_scores","attack_chain","confounders","graph_summary")
    def __init__(self, node_scores=None, attack_chain=None,
                 confounders=None, graph_summary=None):
        self.node_scores = node_scores or []
        self.attack_chain = attack_chain or []
        self.confounders = confounders or set()
        self.graph_summary = graph_summary or {}
    def top_nodes(self, k: int = 5): return self.node_scores[:k]
    def root_causes(self, min_impact: int = 1):
        return [ns for ns in self.node_scores
                if ns.counterfactual_impact >= min_impact]
    def to_dict(self) -> dict:
        return {"nodes":[ns.to_dict() for ns in self.node_scores],
                "chain":[cs.to_dict() for cs in self.attack_chain],
                "confounders":sorted(self.confounders),"summary":self.graph_summary}


class DriftDimension:
    __slots__ = ("name","dim_type","baseline_mean","current_value","signal_strength","direction")
    def __init__(self, name: str, dim_type: str, baseline_mean: float,
                 current_value: float, signal_strength: float, direction: str):
        self.name = name; self.dim_type = dim_type
        self.baseline_mean = baseline_mean; self.current_value = current_value
        self.signal_strength = signal_strength; self.direction = direction
    def to_dict(self) -> dict:
        return {"dimension":self.name,"type":self.dim_type,
                "baseline":self.baseline_mean,"current":self.current_value,
                "signal":self.signal_strength,"direction":self.direction}


class DriftReport:
    __slots__ = ("timestamp","triggered_dimensions","total_dimensions",
                 "top_contributors","batch_count")
    def __init__(self, timestamp: float, triggered_dimensions: int,
                 total_dimensions: int, top_contributors,
                 batch_count: int):
        self.timestamp = timestamp
        self.triggered_dimensions = triggered_dimensions
        self.total_dimensions = total_dimensions
        self.top_contributors = top_contributors
        self.batch_count = batch_count
    @property
    def severity(self) -> str:
        r = self.triggered_dimensions / max(self.total_dimensions,1)
        if r > 0.5: return "critical"
        elif r > 0.3: return "high"
        elif r > 0.15: return "medium"
        return "low"
    def to_dict(self) -> dict:
        return {"timestamp":self.timestamp,"severity":self.severity,
                "triggered":self.triggered_dimensions,"total_dims":self.total_dimensions,
                "contributors":[c.to_dict() for c in self.top_contributors],
                "batch":self.batch_count}


__all__ = ["CausalNodeScore","ChainStep","CausalAnalysis","DriftDimension","DriftReport"]
