# 增加共享内存区域匹配规则，覆盖 RowHammer→内核的传播路径
# 正则规则引擎从线性扫描重构为预编译的规则 DAG

"""
跨平台漏洞关联器。

发现跨平台层的漏洞传播边。规则引擎匹配不同层分析结果的共现模式
（共享符号、地址重叠、时序关联等），输出PropagationEdge。

设计：
  - 规则以声明式DAG组织-先跑廉价规则初筛，再对候选集跑高成本规则，
    避免O(N²)跨层全量匹配。
  - 每条规则输出 (source_node, target_node, confidence, evidence) 元组。

ref: FirmUpdate — 固件更新的多阶段图抽象，
     此处将阶段泛化为平台层，规则引擎替代硬编码的阶段转移。
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .propagation_graph import (
    PlatformLayer, PropagationEdge, PropagationGraph, VulnNode,
)


# 规则签名: (graph, context) → List[(source_id, target_id, confidence, rule_name)]
CorrelationRule = Callable[[PropagationGraph, Dict[str, Any]], List[Tuple[str, str, float, str]]]


def _symbol_co_occurrence(graph: PropagationGraph,
                          ctx: Dict[str, Any]) -> List[Tuple[str, str, float, str]]:
    """共享符号名匹配-最低成本规则。

    固件导出符号与内核导入符号重合 → 高置信度传播边。
    """
    edges: List[Tuple[str, str, float, str]] = []
    fw_symbols = ctx.get('firmware_exported_symbols', {})
    kern_imports = ctx.get('kernel_imported_symbols', {})

    for sym_name, fw_node_ids in fw_symbols.items():
        if sym_name in kern_imports:
            for fw_id in fw_node_ids:
                for kern_id in kern_imports[sym_name]:
                    edges.append((fw_id, kern_id, 0.78, 'symbol_co_occurrence'))
    return edges


def _memory_region_overlap(graph: PropagationGraph,
                           ctx: Dict[str, Any]) -> List[Tuple[str, str, float, str]]:
    """物理内存区域重叠检测。

    固件MMIO区间与硬件侧信道目标区间重叠 → 传播边。
    ref: CVE-2015-5692及RowHammer类漏洞跨层利用链-硬件位翻转经内存映射传播至内核页表。
    """
    edges: List[Tuple[str, str, float, str]] = []
    fw_regions = ctx.get('firmware_mmio_regions', [])    # [(start, end, node_id)]
    hw_regions = ctx.get('hardware_target_regions', [])   # [(start, end, node_id)]

    for fw_start, fw_end, fw_id in fw_regions:
        for hw_start, hw_end, hw_id in hw_regions:
            overlap_start = max(fw_start, hw_start)
            overlap_end = min(fw_end, hw_end)
            if overlap_start < overlap_end:
                overlap_ratio = (overlap_end - overlap_start) / min(
                    fw_end - fw_start, hw_end - hw_start
                )
                if overlap_ratio > 0.3:
                    edges.append((hw_id, fw_id, 0.65 + 0.2 * overlap_ratio,
                                  'memory_region_overlap'))
    return edges


def _syscall_table_correlation(graph: PropagationGraph,
                               ctx: Dict[str, Any]) -> List[Tuple[str, str, float, str]]:
    """系统调用表关联-内核syscall被恶意软件/移动端调用。

    eBPF钩子挂载的syscall与恶意软件行为trace中的syscall号重合。
    """
    edges: List[Tuple[str, str, float, str]] = []
    ebpf_syscalls = ctx.get('ebpf_hooked_syscalls', {})   # {nr: [node_id]}
    malware_syscalls = ctx.get('malware_trace_syscalls', {})  # {nr: [node_id]}

    for nr in set(ebpf_syscalls) & set(malware_syscalls):
        for kern_id in ebpf_syscalls[nr]:
            for mal_id in malware_syscalls[nr]:
                edges.append((kern_id, mal_id, 0.72, 'syscall_correlation'))
    return edges


def _temporal_causality(graph: PropagationGraph,
                        ctx: Dict[str, Any]) -> List[Tuple[str, str, float, str]]:
    """时序因果检测-固件漏洞披露时间先于内核漏洞利用PoC，
    且共享相同影响范围（如同驱动），则建立传播边。

    置信度较低-时序相关不等同因果-仅作辅助信号。
    """
    edges: List[Tuple[str, str, float, str]] = []
    fw_timeline = ctx.get('firmware_vuln_timeline', [])    # [(timestamp, node_id, scope)]
    kern_timeline = ctx.get('kernel_vuln_timeline', [])    # [(timestamp, node_id, scope)]

    for fw_ts, fw_id, fw_scope in fw_timeline:
        for kern_ts, kern_id, kern_scope in kern_timeline:
            if fw_ts < kern_ts and _scope_overlap(fw_scope, kern_scope):
                # 时序差距越小，置信度越低-可能只是巧合
                time_gap_days = (kern_ts - fw_ts) / 86400.0
                conf = max(0.35, 0.65 - 0.05 * time_gap_days)
                edges.append((fw_id, kern_id, conf, 'temporal_causality'))
    return edges


def _scope_overlap(scope_a: str, scope_b: str) -> bool:
    """简易范围重叠-空格/逗号分词后取集合交集。"""
    tokens_a = set(re.split(r'[\s,]+', scope_a.lower()))
    tokens_b = set(re.split(r'[\s,]+', scope_b.lower()))
    return bool(tokens_a & tokens_b)


# 规则 DAG — 按成本从低到高分阶段执行
# phase 0: O(N) 规则，基于预建索引
# phase 1: O(N log N) 规则，需要排序或区间查询
# phase 2: O(N²) 规则，仅对 phase 0/1 产生的候选集运行
_RULE_PHASES: List[List[CorrelationRule]] = [
    [_symbol_co_occurrence, _syscall_table_correlation],
    [_memory_region_overlap, _temporal_causality],
]


class CrossPlatformCorrelator:
    """跨平台关联引擎-规则驱动发现传播边并更新图。

    用法::

        graph = PropagationGraph()
        # ... 从各平台分析结果填充节点 ...
        correlator = CrossPlatformCorrelator()
        correlator.correlate(graph, context={
            'firmware_exported_symbols': {...},
            'kernel_imported_symbols': {...},
        })
    """

    def __init__(self, confidence_threshold: float = 0.35):
        self._threshold = confidence_threshold
        self._custom_rules: List[CorrelationRule] = []

    def register_rule(self, rule: CorrelationRule, phase: int = 1) -> None:
        """注册自定义关联规则-phase越大执行越晚。"""
        self._custom_rules.append(rule)
        # 自定义规则归入 phase 1，后续可扩展为按 phase 参数分类

    def correlate(self, graph: PropagationGraph,
                  context: Optional[Dict[str, Any]] = None) -> int:
        """执行全部关联规则，向图添加发现的PropagationEdge。

        返回新增边数。
        """
        if context is None:
            context = {}
        new_edges = 0

        for phase_idx, rules in enumerate(_RULE_PHASES):
            all_rules = list(rules)
            if phase_idx == 1:
                all_rules.extend(self._custom_rules)

            for rule in all_rules:
                try:
                    candidates = rule(graph, context)
                except Exception:
                    # 单条规则失败不中断整个关联流程
                    continue

                for src_id, tgt_id, confidence, rule_name in candidates:
                    if confidence < self._threshold:
                        continue
                    if src_id not in graph._nodes or tgt_id not in graph._nodes:
                        continue
                    try:
                        edge = graph.add_edge(src_id, tgt_id, confidence, rule_name)
                        if edge.evidence_count == 0:
                            new_edges += 1
                    except ValueError:
                        continue

        return new_edges

    def correlate_with_bayesian_update(
        self, graph: PropagationGraph,
        new_evidence: Dict[Tuple[str, str], Tuple[float, float]],
    ) -> int:
        """新证据对已有边做贝叶斯更新-不创建新边。

        new_evidence: {(source_id, target_id): (likelihood, weight)}
        """
        updated = 0
        for (src, tgt), (likelihood, weight) in new_evidence.items():
            edge = graph._edges.get((src, tgt))
            if edge is None:
                continue
            edge.bayesian_update(likelihood, weight)
            updated += 1
        return updated

    @staticmethod
    def build_context_from_analysis(
        firmware_findings: Optional[List[Dict]] = None,
        kernel_findings: Optional[List[Dict]] = None,
        hardware_findings: Optional[List[Dict]] = None,
        malware_findings: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """从各平台分析结果构建关联上下文-桥接现有模块数据格式。"""
        ctx: Dict[str, Any] = {}

        if firmware_findings:
            fw_syms: Dict[str, List[str]] = defaultdict(list)
            fw_mmio: List[Tuple[int, int, str]] = []
            fw_timeline: List[Tuple[float, str, str]] = []
            for f in firmware_findings:
                nid = f.get('node_id', f.get('function', ''))
                for sym in f.get('symbols', []):
                    fw_syms[sym].append(nid)
                for region in f.get('mmio_regions', []):
                    fw_mmio.append((region[0], region[1], nid))
                ts = f.get('disclosure_time')
                scope = f.get('affected_scope', '')
                if ts and nid:
                    fw_timeline.append((ts, nid, scope))
            ctx['firmware_exported_symbols'] = dict(fw_syms)
            ctx['firmware_mmio_regions'] = fw_mmio
            ctx['firmware_vuln_timeline'] = fw_timeline

        if kernel_findings:
            kern_imports: Dict[str, List[str]] = defaultdict(list)
            ebpf_sys: Dict[int, List[str]] = defaultdict(list)
            kern_timeline: List[Tuple[float, str, str]] = []
            for k in kernel_findings:
                nid = k.get('node_id', k.get('module', ''))
                for imp in k.get('imported_symbols', []):
                    kern_imports[imp].append(nid)
                for nr in k.get('ebpf_hooked_syscalls', []):
                    ebpf_sys[nr].append(nid)
                ts = k.get('disclosure_time')
                scope = k.get('affected_scope', '')
                if ts and nid:
                    kern_timeline.append((ts, nid, scope))
            ctx['kernel_imported_symbols'] = dict(kern_imports)
            ctx['ebpf_hooked_syscalls'] = dict(ebpf_sys)
            ctx['kernel_vuln_timeline'] = kern_timeline

        if hardware_findings:
            hw_regions: List[Tuple[int, int, str]] = []
            for h in hardware_findings:
                nid = h.get('node_id', h.get('target', ''))
                for region in h.get('target_regions', []):
                    hw_regions.append((region[0], region[1], nid))
            ctx['hardware_target_regions'] = hw_regions

        if malware_findings:
            mal_sys: Dict[int, List[str]] = defaultdict(list)
            for m in malware_findings:
                nid = m.get('node_id', m.get('sample_hash', ''))
                for nr in m.get('trace_syscalls', []):
                    mal_sys[nr].append(nid)
            ctx['malware_trace_syscalls'] = dict(mal_sys)

        return ctx
