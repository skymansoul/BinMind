#!/usr/bin/env python3
# 智能驱动执行路径优先级排序 — 按可利用性评分代码路径
# (内存操作/用户控制数据流/可达性).
# 污点源接近度评分+循环深度惩罚乘数.
# sigmoid距离衰减/操作邻接乘数/Jaccard多样性惩罚.

import logging as _logging
import re as _re
import math as _math
from collections import defaultdict as _defaultdict

_dbg = _logging.getLogger(__name__)


# 风险加权操作模式
_RISK_PATTERNS = [
    (_re.compile(r'\b(memcpy|memmove|strcpy|strcat|sprintf|gets|scanf)\s*\('), 0.8, "unbounded_copy"),
    (_re.compile(r'\b(malloc|calloc|realloc|new\s)\s*[\[(]'), 0.3, "allocation"),
    (_re.compile(r'\b(free|delete\s)\s*[\[(]'), 0.3, "deallocation"),
    (_re.compile(r'\b(VirtualAlloc|VirtualProtect|mprotect|mmap)\s*\('), 0.7, "memory_protect"),
    (_re.compile(r'\b(recv|read|fread|ReadFile)\s*\('), 0.6, "external_input"),
    (_re.compile(r'\b(strlen|wcslen)\s*\('), 0.2, "length_check"),
    (_re.compile(r'\b(system|exec|popen|CreateProcess|WinExec)\s*\('), 0.9, "command_exec"),
    (_re.compile(r'\b(atoi|atol|strtol|sscanf)\s*\('), 0.4, "parsing"),
    (_re.compile(r'\b(xor\s*=|^\s*\w+\s*\^=\s*)'), 0.3, "xor_operation"),
    (_re.compile(r'\b(base64|decode|decrypt|decompress|inflate)\s*\('), 0.5, "decode"),
    (_re.compile(r'\b(send|write|fwrite|WriteFile)\s*\('), 0.4, "output"),
    (_re.compile(r'\b(CreateMutex|WaitForSingleObject|EnterCriticalSection)\s*\('), 0.2, "sync"),
]

# 增强常量
# 邻接窗口：两个危险操作在此距离内触发耦合乘数
_ADJACENCY_WINDOW = 3  # 节点跨度
# sigmoid陡峭度：值越大，衰减越急剧（尾部风险集中在前半段）
_SIGMOID_STEEPNESS = 0.75
# sigmoid中点：距离超过此值后衰减加速
_SIGMOID_MIDPOINT = 2.0
# Jaccard多样性惩罚强度：重复操作集的路径被降权
_DIVERSITY_PENALTY_STRENGTH = 0.18
# 邻接乘数上限
_ADJACENCY_MULTIPLIER_CAP = 2.5

# 已知危险操作链：前驱操作 + 后继操作 → 乘数
# 策略意图：特定操作对在短距离内共现时，单独评分低估了耦合风险
_CHAIN_PATTERNS = [
    ({"external_input", "unbounded_copy"}, 1.8),
    ({"external_input", "command_exec"}, 2.0),
    ({"unbounded_copy", "decode"}, 1.5),
    ({"memory_protect", "command_exec"}, 2.2),
    ({"external_input", "parsing"}, 1.4),
    ({"allocation", "unbounded_copy"}, 1.6),
    ({"deallocation", "unbounded_copy"}, 1.5),  # use-after-free路径
    ({"external_input", "memory_protect"}, 1.7),
]


def _sigmoid_decay(distance, midpoint=_SIGMOID_MIDPOINT, steepness=_SIGMOID_STEEPNESS):
    # sigmoid距离衰减: taint-to-sink距离对可利用性影响呈S形
    if distance <= 0:
        return 1.0
    exponent = (distance - midpoint) / steepness
    # 钳制指数范围防止溢出
    exponent = max(-20.0, min(20.0, exponent))
    return 1.0 / (1.0 + _math.exp(exponent))


class PathNode:

    __slots__ = ('m_addr', 'm_code', 'm_score', 'm_taint_sources', 'm_loop_depth',
                 'm_ops', 'm_op_names')

    def __init__(self, addr, code=''):
        self.m_addr = addr
        self.m_code = code if code else ''
        self.m_score = 0.0
        self.m_taint_sources = []
        self.m_loop_depth = 0
        self.m_ops = []
        self.m_op_names = set()  # 操作名集合，供邻接匹配和多样性计算

    def compute_risk_pn(self):
        if not self.m_code:
            self.m_score = 0.0
            self.m_op_names = set()
            return

        score = 0.0
        ops = []
        op_names = set()
        pi = 0
        while pi < len(_RISK_PATTERNS):
            pat, weight, name = _RISK_PATTERNS[pi]
            matches = pat.findall(self.m_code)
            if matches:
                match_score = weight * min(len(matches), 5)
                score += match_score
                ops.append((name, len(matches), match_score))
                op_names.add(name)
            pi += 1

        # 循环深度惩罚: 深层循环评分更高
        loop_mult = 1.0 + self.m_loop_depth * 0.15
        score *= loop_mult

        # 分数上限
        self.m_score = min(score, 10.0)
        self.m_ops = ops
        self.m_op_names = op_names


class ExecutionPath:

    __slots__ = ('m_nodes', 'm_total_score', 'm_length', 'm_has_taint',
                 'm_dominator_score', 'm_adjacency_bonus', 'm_diversity_penalty',
                 'm_op_signature', 'm_final_score')

    def __init__(self, nodes=None):
        self.m_nodes = nodes if nodes else []
        self.m_total_score = 0.0
        self.m_length = len(self.m_nodes)
        self.m_has_taint = False
        self.m_dominator_score = 0.0
        self.m_adjacency_bonus = 0.0
        self.m_diversity_penalty = 0.0
        self.m_op_signature = frozenset()
        self.m_final_score = 0.0

    def compute_score_ep(self):
        if not self.m_nodes:
            self.m_final_score = 0.0
            return

        total = 0.0
        max_node = 0.0
        has_taint_source = False
        ni = 0
        while ni < len(self.m_nodes):
            n = self.m_nodes[ni]
            n.compute_risk_pn()
            total += n.m_score
            if n.m_score > max_node:
                max_node = n.m_score
            if n.m_taint_sources:
                has_taint_source = True
            ni += 1

        self.m_total_score = total
        self.m_has_taint = has_taint_source
        # 支配分: 最高单节点风险 × (1 + 均值)
        avg = total / max(len(self.m_nodes), 1)
        self.m_dominator_score = max_node * (1.0 + avg * 0.5)

        # 邻接加成分量
        self.m_dominator_score += self.m_adjacency_bonus * 0.5

        # 最终分：支配分 * (1 - 多样性惩罚)
        penalty_factor = 1.0 - self.m_diversity_penalty
        self.m_final_score = self.m_dominator_score * max(penalty_factor, 0.35)

    def get_risk_summary_ep(self):
        if not self.m_nodes:
            return {'risk': 'none', 'score': 0.0, 'nodes': 0}
        # 使用最终分判定风险级别
        effective = self.m_final_score if self.m_final_score > 0 else self.m_dominator_score
        if effective >= 8.0:
            risk = 'critical'
        elif effective >= 5.0:
            risk = 'high'
        elif effective >= 2.5:
            risk = 'medium'
        elif effective >= 1.0:
            risk = 'low'
        else:
            risk = 'info'
        return {'risk': risk, 'score': self.m_dominator_score,
                'final_score': self.m_final_score, 'nodes': self.m_length,
                'has_taint': self.m_has_taint, 'total_score': self.m_total_score,
                'adjacency_bonus': self.m_adjacency_bonus,
                'diversity_penalty': self.m_diversity_penalty}

    def collect_op_signature_ep(self):
        # 收集路径级操作签名, 用于Jaccard相似度和邻接链检测
        all_ops = set()
        for node in self.m_nodes:
            all_ops.update(node.m_op_names)
        self.m_op_signature = frozenset(all_ops)


def _jaccard_similarity(set_a, set_b):
    # 空集对空集定义为0
    if not set_a and not set_b:
        return 0.0
    union_size = len(set_a | set_b)
    if union_size == 0:
        return 0.0
    return len(set_a & set_b) / union_size


class PathPrioritizer:
    # 轻量启发式排序路径: 节点风险评分 + taint源接近度 + 路径长度归一化 + 邻接链加成 + 多样性重排序

    __slots__ = ('m_taint_sources', 'm_sinks', 'm_taint_distance_max',
                 'm_adjacency_window', 'm_diversity_strength')

    def __init__(self, taint_distance_max=5):
        self.m_taint_sources = set()
        self.m_sinks = set()
        self.m_taint_distance_max = taint_distance_max
        self.m_adjacency_window = _ADJACENCY_WINDOW
        self.m_diversity_strength = _DIVERSITY_PENALTY_STRENGTH

    def set_taint_config_pp(self, sources, sinks):
        if sources:
            si = 0
            while si < len(sources):
                self.m_taint_sources.add(sources[si])
                si += 1
        if sinks:
            si = 0
            while si < len(sinks):
                self.m_sinks.add(sinks[si])
                si += 1

    def build_path_pp(self, nodes_data):
        nodes = []
        ni = 0
        while ni < len(nodes_data):
            nd = nodes_data[ni]
            node = PathNode(addr=nd.get('addr', ni), code=nd.get('code', ''))
            node.m_loop_depth = nd.get('loop_depth', 0)
            nodes.append(node)
            ni += 1
        path = ExecutionPath(nodes)
        path.compute_score_ep()
        return path

    def prioritize_paths_pp(self, paths):
        # 邻接检测 + taint标注 + 多样性重排序
        built = []
        pi = 0
        while pi < len(paths):
            ep = self.build_path_pp(paths[pi])
            # 邻接链检测在taint标注之前，利用原始操作名
            self._compute_adjacency_bonus_pp(ep)
            self._annotate_taint_pp(ep)
            ep.collect_op_signature_ep()
            # 重新计算以融合邻接加成
            ep.compute_score_ep()
            built.append(ep)
            pi += 1

        # 多样性重排序：贪心选取-每次取剩余中（原始分 * 多样性折扣）最高的
        ranked = self._diversity_rerank(built)
        return ranked

    def _compute_adjacency_bonus_pp(self, path):
        # 窗口内检测已知危险操作链, 加成与两节点风险分乘积成正比
        if path is None or not path.m_nodes or len(path.m_nodes) < 2:
            return

        # 各节点先计算自身风险并填充op_names
        node_count = len(path.m_nodes)
        ni = 0
        while ni < node_count:
            path.m_nodes[ni].compute_risk_pn()
            ni += 1

        adjacency_total = 0.0
        applied_pairs = set()  # 防止同一节点对重复加成
        for window_start in range(node_count - 1):
            window_end = min(window_start + self.m_adjacency_window, node_count)
            for j in range(window_start + 1, window_end):
                node_a = path.m_nodes[window_start]
                node_b = path.m_nodes[j]
                ops_a = node_a.m_op_names
                ops_b = node_b.m_op_names

                if not ops_a or not ops_b:
                    continue

                # 已知危险链匹配
                for chain_ops, multiplier in _CHAIN_PATTERNS:
                    pair_key = (window_start, j, frozenset(chain_ops))
                    if pair_key in applied_pairs:
                        continue
                    # 链匹配: 窗口内存在chain_ops中的两个操作
                    if (chain_ops & ops_a) and (chain_ops & ops_b) and (chain_ops & ops_a) != (chain_ops & ops_b):
                        # 两个节点各贡献chain中的一个操作
                        pair_score = (node_a.m_score + node_b.m_score) * 0.5
                        bonus = pair_score * (multiplier - 1.0)
                        # 距离折扣: 窗口内越近越危险
                        distance_discount = 1.0 / (1.0 + 0.3 * (j - window_start - 1))
                        adjacency_total += bonus * distance_discount
                        applied_pairs.add(pair_key)
                        _dbg.debug("邻接链命中: %s ↔ %s @dist=%d, bonus=%.3f",
                                    chain_ops & ops_a, chain_ops & ops_b,
                                    j - window_start, bonus * distance_discount)

        # 同节点内多操作耦合: 单节点含互补操作对时也加分
        for ni in range(node_count):
            node_ops = path.m_nodes[ni].m_op_names
            if len(node_ops) < 2:
                continue
            for chain_ops, multiplier in _CHAIN_PATTERNS:
                if chain_ops.issubset(node_ops):
                    bonus = path.m_nodes[ni].m_score * (multiplier - 1.0) * 0.3
                    adjacency_total += bonus
                    _dbg.debug("同节点链命中: %s @node=%d, bonus=%.3f",
                                chain_ops, ni, bonus)

        path.m_adjacency_bonus = min(adjacency_total, _ADJACENCY_MULTIPLIER_CAP)

    def _annotate_taint_pp(self, path):
        if path is None or not path.m_nodes:
            return

        # 前向扫描: 标记taint引入点
        active_taint = []
        ni = 0
        while ni < len(path.m_nodes):
            node = path.m_nodes[ni]
            code_lower = node.m_code.lower()

            # 检查节点是否引入taint
            si = 0
            src_list = list(self.m_taint_sources)
            while si < len(src_list):
                if src_list[si].lower() in code_lower:
                    node.m_taint_sources.append(src_list[si])
                    active_taint.append((src_list[si], ni))
                si += 1

            # taint-to-sink接近度: sigmoid衰减替代线性
            si = 0
            sink_list = list(self.m_sinks)
            while si < len(sink_list):
                if sink_list[si].lower() in code_lower:
                    ti = len(active_taint) - 1
                    while ti >= 0:
                        taint_src, taint_pos = active_taint[ti]
                        distance = ni - taint_pos
                        if distance <= self.m_taint_distance_max:
                            # sigmoid衰减: 短距离保持高分, 中段急剧下降
                            decay = _sigmoid_decay(distance,
                                                   midpoint=self.m_taint_distance_max * 0.4,
                                                   steepness=_SIGMOID_STEEPNESS)
                            node.m_score += 1.5 * decay
                        ti -= 1
                si += 1
            ni += 1

        path.compute_score_ep()

    def _diversity_rerank(self, paths):
        # 贪心选取 + 滚动Jaccard相似度惩罚, 优先选操作签名差异大的路径
        if not paths:
            return []

        # 确保每条路径已构建操作签名
        for p in paths:
            if not p.m_op_signature:
                p.collect_op_signature_ep()

        remaining = [p for p in paths]
        selected = []
        covered_op_sets = []

        while remaining:
            best_idx = 0
            best_score = -1.0

            for ri in range(len(remaining)):
                cand = remaining[ri]
                base_score = cand.m_dominator_score + cand.m_adjacency_bonus

                # 计算与已选路径的最大Jaccard相似度
                max_sim = 0.0
                for cov_set in covered_op_sets:
                    sim = _jaccard_similarity(cand.m_op_signature, cov_set)
                    if sim > max_sim:
                        max_sim = sim

                diversity_discount = 1.0 - self.m_diversity_strength * max_sim
                adjusted_score = base_score * diversity_discount

                cand.m_diversity_penalty = self.m_diversity_strength * max_sim
                cand.m_final_score = adjusted_score

                if adjusted_score > best_score:
                    best_score = adjusted_score
                    best_idx = ri

            chosen = remaining.pop(best_idx)
            selected.append(chosen)
            covered_op_sets.append(chosen.m_op_signature)

        # 构建带排名的结果
        ranked = []
        pi = 0
        while pi < len(selected):
            ranked.append((selected[pi], pi + 1))
            pi += 1
        return ranked

    def get_top_paths_pp(self, paths, top_n=10):
        ranked = self.prioritize_paths_pp(paths)
        top_n = min(top_n, len(ranked))
        results = []
        pi = 0
        while pi < top_n:
            path, rank = ranked[pi]
            summary = path.get_risk_summary_ep()
            summary['rank'] = rank
            results.append(summary)
            pi += 1
        return results


def create_path_prioritizer(taint_distance_max=5):
    return PathPrioritizer(taint_distance_max=taint_distance_max)


# AI 辅助路径优先级排序 API
# 面向符号执行产出的路径对象排序: 按危险函数可达性、路径深度、覆盖率与
# 特征权重综合打分, 输出 CRITICAL/HIGH/MEDIUM/LOW 四级优先级。
# 与 PathPrioritizer 的区别: 本组接口直接消费 SymbolicPath 结构,
# 供符号执行引擎在每轮探索结束后对候选路径做排序。

from enum import Enum as _Enum
from dataclasses import dataclass as _dc, field as _field
from typing import Any as _Any, Dict as _Dict, List as _List, Optional as _Optional


class PathFeature(_Enum):
    USER_INPUT = "user_input"
    MEMORY_ACCESS = "memory_access"
    SYSTEM_CALL = "system_call"
    PRIVILEGE_CHANGE = "privilege_change"


class PathPriority(_Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@_dc
class SymbolicPath:
    path_id: str = ""
    constraints: _List[str] = _field(default_factory=list)
    instructions: _List[str] = _field(default_factory=list)
    registers: _Dict[str, _Any] = _field(default_factory=dict)
    memory_access: _List[_Dict[str, _Any]] = _field(default_factory=list)
    reached_functions: _List[str] = _field(default_factory=list)
    depth: int = 0
    coverage_ratio: float = 0.0
    features: _List[PathFeature] = _field(default_factory=list)


@_dc
class PathAnalysis:
    path_id: str = ""
    priority_score: float = 0.0
    priority_level: PathPriority = PathPriority.LOW
    reasoning: str = ""


@_dc
class PrioritizationResult:
    paths: _List[PathAnalysis] = _field(default_factory=list)
    total_paths: int = 0
    prioritized_paths: int = 0
    analysis_time: float = 0.0
    summary: _Dict[str, _Any] = _field(default_factory=dict)


# 危险函数权重 - 高影响函数直接抬高路径得分
_PATH_FUNC_WEIGHTS = {
    'strcpy': 0.10, 'strcat': 0.10, 'sprintf': 0.10, 'gets': 0.15,
    'scanf': 0.10, 'memcpy': 0.10, 'memmove': 0.08, 'system': 0.20,
    'popen': 0.20, 'exec': 0.15, 'recv': 0.05, 'read': 0.05,
    'printf': 0.02, 'snprintf': 0.02, 'strncpy': 0.02, 'strncat': 0.02,
}
_PATH_FEATURE_WEIGHTS = {
    PathFeature.USER_INPUT: 0.10,
    PathFeature.MEMORY_ACCESS: 0.05,
    PathFeature.SYSTEM_CALL: 0.15,
    PathFeature.PRIVILEGE_CHANGE: 0.15,
}


def _score_symbolic_path(path: SymbolicPath) -> float:
    # 路径优先级得分 [0, 0.98]
    score = 0.0
    score += min(max(path.depth, 0) * 0.01, 0.30)
    score += max(0.0, min(path.coverage_ratio, 1.0)) * 0.30
    for feat in path.features:
        score += _PATH_FEATURE_WEIGHTS.get(feat, 0.0)
    for fn in path.reached_functions:
        score += _PATH_FUNC_WEIGHTS.get(fn, 0.0)
    return round(min(0.98, max(0.0, score)), 4)


def _priority_level(score: float) -> PathPriority:
    if score >= 0.9:
        return PathPriority.CRITICAL
    if score >= 0.7:
        return PathPriority.HIGH
    if score >= 0.5:
        return PathPriority.MEDIUM
    return PathPriority.LOW


class AIPathPrioritizer:
    # 三策略: heuristic(静态打分) / llm(预留) / hybrid(启发式+人工修正)

    def __init__(self, strategy: str = "hybrid"):
        self.strategy = strategy
        self._analyses: _Dict[str, PathAnalysis] = {}

    def prioritize(self, paths: _List[SymbolicPath],
                   top_k: _Optional[int] = None) -> PrioritizationResult:
        scored: _List[PathAnalysis] = []
        for p in paths:
            score = _score_symbolic_path(p)
            analysis = PathAnalysis(
                path_id=p.path_id,
                priority_score=score,
                priority_level=_priority_level(score),
                reasoning=self._reason(p),
            )
            self._analyses[p.path_id] = analysis
            scored.append(analysis)
        scored.sort(key=lambda a: a.priority_score, reverse=True)
        if top_k is not None and top_k < len(scored):
            scored = scored[:top_k]
        summary = self._summarize(scored)
        return PrioritizationResult(
            paths=scored,
            total_paths=len(paths),
            prioritized_paths=len(scored),
            analysis_time=0.0,
            summary=summary,
        )

    def get_path_analysis(self, path_id: str) -> _Optional[PathAnalysis]:
        return self._analyses.get(path_id)

    def update_path_priority(self, path_id: str, score: float,
                             reason: str = "") -> PathAnalysis:
        analysis = self._analyses.get(path_id)
        if analysis is None:
            analysis = PathAnalysis(path_id=path_id)
            self._analyses[path_id] = analysis
        analysis.priority_score = score
        analysis.priority_level = _priority_level(score)
        analysis.reasoning = f"{reason}（人工评分 {score}）"
        return analysis

    def _reason(self, path: SymbolicPath) -> str:
        parts = []
        if path.reached_functions:
            parts.append("危险函数:" + ",".join(path.reached_functions))
        if path.features:
            parts.append("特征:" + ",".join(f.value for f in path.features))
        if path.depth > 0:
            parts.append(f"深度:{path.depth}")
        return ";".join(parts) if parts else "无显著特征"

    def _summarize(self, analyses: _List[PathAnalysis]) -> _Dict[str, _Any]:
        counts = {lv.value: 0 for lv in PathPriority}
        for a in analyses:
            counts[a.priority_level.value] += 1
        scores = [a.priority_score for a in analyses]
        return {
            'critical_paths': counts['critical'],
            'high_paths': counts['high'],
            'avg_vulnerability_likelihood': round(
                sum(scores) / max(1, len(scores)) * 100, 1),
            'avg_exploration_value': 60.0,
            'priority_distribution': counts,
        }


def prioritize_paths(paths: _List[_Any], strategy: str = "heuristic",
                     top_k: _Optional[int] = None) -> PrioritizationResult:
    normalized: _List[SymbolicPath] = []
    for item in paths:
        if isinstance(item, SymbolicPath):
            normalized.append(item)
        elif isinstance(item, _Dict):
            feats = []
            for f in item.get('features', []):
                try:
                    feats.append(PathFeature(f))
                except ValueError:
                    pass
            normalized.append(SymbolicPath(
                path_id=item.get('path_id', ''),
                constraints=list(item.get('constraints', [])),
                instructions=list(item.get('instructions', [])),
                registers=dict(item.get('registers', {})),
                memory_access=list(item.get('memory_access', [])),
                reached_functions=list(item.get('reached_functions', [])),
                depth=int(item.get('depth', 0)),
                coverage_ratio=float(item.get('coverage_ratio', 0.0)),
                features=feats,
            ))
    return AIPathPrioritizer(strategy=strategy).prioritize(normalized, top_k=top_k)


def format_prioritization_report(result: PrioritizationResult) -> str:
    summary = result.summary or {}
    lines = [
        "路径优先级分析报告",
        f"分析路径总数: {result.total_paths}",
        f"已排序路径数: {result.prioritized_paths}",
        f"关键路径数: {summary.get('critical_paths', 0)}",
        f"高优先级路径数: {summary.get('high_paths', 0)}",
        f"平均漏洞可能性: {summary.get('avg_vulnerability_likelihood', 0)}%",
        "",
        "排序结果:",
    ]
    for a in result.paths:
        lines.append(
            f"  - {a.path_id}: {a.priority_score:.3f} "
            f"[{a.priority_level.value}] {a.reasoning}")
    return "\n".join(lines)

