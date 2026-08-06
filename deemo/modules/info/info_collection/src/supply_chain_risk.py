# Created: 2025-07-29 11:50:44
#
# supply_chain_risk — 二进制级供应链风险传播模型
# 以 SBOM 依赖图 + 每节点的二进制静态分析结果作为输入，
# 沿依赖边传播风险：下游继承上游的 exploitability/保护缺口/危险导入。
#
# 与现有研究的本质差异:
#   - VPSS (ASE 2025): package 级调用图分析，Maven 生态
#   - 本模块: 不依赖 CVE 数据库或 ML 模型，直接从二进制属性计算风险
#     传播。适用于无 CVE 的闭源/内部二进制。
#
# 传播模型:
#   每个节点有三维风险向量 (exploitability, protection_gap, import_surface)
#   传播规则: child_risk = max(child_own_risk, sum(parent_risk * edge_weight))
#   使用 PageRank 式迭代直至收敛 (≤50 轮，容忍度 1e-6)

from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import math


def _normalize_vector(vec: Tuple[float, float, float]) -> Tuple[float, float, float]:
    """L2 归一化三维风险向量。"""
    _norm = math.sqrt(vec[0]**2 + vec[1]**2 + vec[2]**2)
    if _norm < 1e-9:
        return (0.0, 0.0, 0.0)
    return (round(vec[0] / _norm, 6), round(vec[1] / _norm, 6), round(vec[2] / _norm, 6))


def _extract_risk_vector(binary_analysis: Dict) -> Tuple[float, float, float]:
    """从单二进制分析结果中提取三维风险向量。
    - exploitability: exploitability_index / 100
    - protection_gap: 1 - posture_score (保护缺失程度)
    - import_surface: dangerous_import_ratio
    """
    _exploit = 0.0
    _prot_gap = 0.0
    _import_surf = 0.0

    # exploitability — 来自 exploit_chain_inference 或 posture_pipeline 扩展分析
    _ec = binary_analysis.get("exploit_chain", {})
    if "exploitability_index" in _ec:
        _exploit = _ec["exploitability_index"] / 100.0
    elif "error" not in _ec:
        _exploit = _ec.get("exploitability_index", 0.0) / 100.0

    # protection gap — 来自 security_posture 或 checksec
    _sp = binary_analysis.get("security_posture", {})
    if "posture_score" in _sp:
        _prot_gap = 1.0 - _sp["posture_score"]
    else:
        _cs = binary_analysis.get("checksec", {})
        if _cs:
            _score = sum(1 for k in ["nx", "pie", "canary", "relro"]
                        if _cs.get(k)) / 4.0
            _prot_gap = 1.0 - _score

    # import surface — 危险导入占总导入的比例
    _imps = binary_analysis.get("imports", {})
    if isinstance(_imps, dict):
        _all_imps = _imps.get("all_imports", _imps)
        _total = sum(len(v) for v in _all_imps.values()) if isinstance(_all_imps, dict) else 0
        _danger = len(_imps.get("dangerous_functions", []))
        _import_surf = _danger / max(_total, 1)

    return (_exploit, _prot_gap, _import_surf)


def _compute_edge_weight(
    parent_analysis: Dict,
    child_analysis: Dict,
    dependency_type: str = "runtime",
) -> float:
    """计算依赖边的风险传播权重。
    - runtime 依赖: 权重 0.85（父节点代码在子进程空间中执行）
    - build 依赖: 权重 0.35（仅影响构建产物，不直接执行）
    - test 依赖: 权重 0.10
    - optional 依赖: 权重 0.20
    权重可被段布局相似度微调（相似度高 → 传播概率高）
    """
    _base = {"runtime": 0.85, "build": 0.35, "test": 0.10,
             "optional": 0.20, "provided": 0.30}.get(dependency_type, 0.50)

    # 段布局相似度微调: 相同格式 + 相同架构 → +0.05
    if parent_analysis.get("format") == child_analysis.get("format"):
        if parent_analysis.get("arch") == child_analysis.get("arch"):
            _base += 0.05

    return min(_base, 0.95)


def propagate_risks(
    dependency_graph: Dict[str, Dict],
    binary_analyses: Dict[str, Dict],
    max_iterations: int = 50,
    tolerance: float = 1e-6,
) -> Dict:
    """供应链风险传播主入口。

    dependency_graph: {node_name: {deps: [{name, type}], ...}}
      每个节点可包含 'deps' 列表，每项有 'name' (依赖名) 和 'type' (依赖类型)
    binary_analyses: {node_name: binary_analysis_dict}
      每个节点的二进制分析结果，至少包含 format/arch/checksec/imports

    输出:
    - node_risks: {node: {own_risk, propagated_risk, total_risk, risk_vector}}
    - propagation_graph: 有向边列表 (parent→child, weight, risk_contribution)
    - critical_nodes: 按总风险降序排列的节点
    - risk_concentration: 风险集中度 (Gini 式度量)
    """
    _nodes = list(dependency_graph.keys())
    if not _nodes:
        return {"node_risks": {}, "propagation_graph": [],
                "critical_nodes": [], "risk_concentration": 0.0}

    # 每个节点的自身风险向量
    _own_vectors: Dict[str, Tuple[float, float, float]] = {}
    for _name in _nodes:
        _analysis = binary_analyses.get(_name, {})
        _own_vectors[_name] = _extract_risk_vector(_analysis)

    # 构建邻接表: parent → [(child, weight)]
    _adj: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    for _child_name, _node_data in dependency_graph.items():
        _deps = _node_data.get("deps", [])
        for _dep in _deps:
            _parent_name = _dep.get("name", "")
            if _parent_name in _nodes and _parent_name != _child_name:
                _dep_type = _dep.get("type", "runtime")
                _parent_analysis = binary_analyses.get(_parent_name, {})
                _child_analysis = binary_analyses.get(_child_name, {})
                _weight = _compute_edge_weight(
                    _parent_analysis, _child_analysis, _dep_type)
                _adj[_parent_name].append((_child_name, _weight))

    # PageRank 式迭代传播
    _current = dict(_own_vectors)
    _prev = {}

    for _iter in range(max_iterations):
        _next: Dict[str, List[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])

        # 每个节点从所有父节点接收风险
        for _parent, _children in _adj.items():
            _p_vec = _current[_parent]
            for _child, _weight in _children:
                for _d in range(3):
                    _next[_child][_d] += _p_vec[_d] * _weight

        # 合并: max(自身, 传播) 确保风险不会因传播而降低
        _changed = False
        for _name in _nodes:
            _own = _own_vectors[_name]
            _prop = tuple(_next[_name])
            _merged = tuple(
                max(_own[d], min(_prop[d], 1.0))
                for d in range(3)
            )
            _prev = _current.get(_name, (0, 0, 0))
            _current[_name] = _merged
            if any(abs(_merged[d] - _prev[d]) > tolerance for d in range(3)):
                _changed = True

        if not _changed:
            break

    # 汇总结果
    _node_risks = {}
    _critical = []
    for _name in _nodes:
        _own = _own_vectors[_name]
        _curr = _current[_name]
        _prop = tuple(
            round(max(0.0, _curr[d] - _own[d]), 6)
            for d in range(3)
        )
        _total = sum(_curr)
        _node_risks[_name] = {
            "own_risk_vector": list(_own),
            "propagated_risk_vector": list(_prop),
            "total_risk_vector": list(_curr),
            "total_risk_score": round(_total / 3.0, 6),
            "own_risk_score": round(sum(_own) / 3.0, 6),
        }
        _critical.append((_name, _total / 3.0))

    _critical.sort(key=lambda x: x[1], reverse=True)

    # 传播图
    _prop_graph = []
    for _parent, _children in _adj.items():
        _p_vec = _current[_parent]
        for _child, _weight in _children:
            _contribution = sum(_p_vec[d] * _weight for d in range(3)) / 3.0
            _prop_graph.append({
                "from": _parent, "to": _child,
                "weight": round(_weight, 4),
                "risk_contribution": round(_contribution, 6),
            })

    # 风险集中度 (简化 Gini)
    _scores = sorted([s for _, s in _critical])
    if _scores and _scores[-1] > 0:
        _n = len(_scores)
        _gini = sum((2 * i - _n - 1) * _scores[i] for i in range(_n))
        _gini /= _n * sum(_scores)
        _gini = abs(_gini)
    else:
        _gini = 0.0

    return {
        "node_risks": _node_risks,
        "propagation_graph": _prop_graph,
        "critical_nodes": [
            {"name": n, "total_risk": round(s, 6)}
            for n, s in _critical[:10]
        ],
        "risk_concentration": round(_gini, 4),
    }


def quick_chain_risk(
    binary_analyses: Dict[str, Dict],
    dependency_chain: List[str],
) -> Dict:
    """快速单链风险传播：给定一条依赖链 [root, dep1, dep2, ..., leaf]，
    计算风险沿链累积效应。适合 CI/CD 中检查单个构建路径。
    """
    if len(dependency_chain) < 2:
        return {"chain_risk": 0.0, "amplification_factor": 1.0, "steps": []}

    _accum = list(_extract_risk_vector(binary_analyses.get(dependency_chain[0], {})))
    _steps = [{"node": dependency_chain[0], "accumulated_risk": list(_accum)}]

    for _i in range(1, len(dependency_chain)):
        _child = dependency_chain[_i]
        _child_own = _extract_risk_vector(binary_analyses.get(_child, {}))
        _parent_analysis = binary_analyses.get(dependency_chain[_i - 1], {})
        _child_analysis = binary_analyses.get(_child, {})
        _weight = _compute_edge_weight(_parent_analysis, _child_analysis)

        for _d in range(3):
            _accum[_d] = max(_child_own[_d], _accum[_d] * _weight)

        _steps.append({"node": _child, "accumulated_risk": list(_accum)})

    _chain_risk = sum(_accum) / 3.0
    _initial = sum(_extract_risk_vector(
        binary_analyses.get(dependency_chain[-1], {}))) / 3.0
    _amp = _chain_risk / max(_initial, 0.001)

    return {
        "chain_risk": round(_chain_risk, 6),
        "amplification_factor": round(min(_amp, 100.0), 2),
        "steps": _steps,
    }
