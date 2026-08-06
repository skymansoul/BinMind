# -*- coding: utf-8 -*-
# 创建: 2026-08-01 — HookSignature + SchemaModel + DAGVerifier
# 修改: 2026-08-02 — 四维检查完善, 传递依赖边建议
"""
钩子模式推断与 DAG 完备性验证 — 从执行轨迹学习钩子的 I/O 键签名, 静态检查 DAG 正确性.

APEX-DAG (VLDB 2025) 从 AST 提取数据管道模式, 依赖 GNN; SLiCE (arXiv:2508.07179) 用 LLM.
本模块的不同: 模式从运行时执行轨迹学习 (适用任意可调用对象), 检查对象是钩子 DAG
的结构完备性而非列级谱系, 产出可操作的修复建议.

检查维度: 缺失输入 / 死输出 / 键冲突 / 缺失依赖边.
"""

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class HookSignature:
    """钩子的 I/O 键签名 — 从执行轨迹推断."""
    hook_name: str
    required_reads: Set[str] = field(default_factory=set)   # 每次必读
    optional_reads: Set[str] = field(default_factory=set)   # 条件读取
    written_keys: Set[str] = field(default_factory=set)
    sample_count: int = 0

    @property
    def all_reads(self) -> Set[str]:
        return self.required_reads | self.optional_reads

    def update(self, reads: Set[str], writes: Set[str]) -> None:
        if self.sample_count == 0:
            self.required_reads = set(reads); self.written_keys = set(writes)
        else:
            old_req = set(self.required_reads)
            self.required_reads &= reads
            # 新出现的键 + 从 required 降级的旧键 → optional
            self.optional_reads |= (reads - self.required_reads)
            self.optional_reads |= (old_req - self.required_reads)
            self.written_keys |= writes
        self.sample_count += 1

    def merge(self, other: 'HookSignature') -> 'HookSignature':
        merged = HookSignature(hook_name=self.hook_name)
        merged.required_reads = self.required_reads & other.required_reads
        merged.optional_reads = (self.optional_reads | other.optional_reads
                                | (self.required_reads - merged.required_reads)
                                | (other.required_reads - merged.required_reads))
        merged.written_keys = self.written_keys | other.written_keys
        merged.sample_count = self.sample_count + other.sample_count
        return merged

    def to_dict(self) -> Dict[str, Any]:
        return {
            'hook': self.hook_name,
            'required_reads': sorted(self.required_reads),
            'optional_reads': sorted(self.optional_reads),
            'written_keys': sorted(self.written_keys),
            'samples': self.sample_count,
        }


@dataclass
class VerificationIssue:
    """DAG 完备性检查发现的一个问题."""
    severity: str        # 'error' | 'warning' | 'info'
    category: str        # 'missing_input' | 'dead_output' | 'key_collision' | 'missing_dep'
    hook_name: str
    detail: str
    suggestion: str = ''


class SchemaModel:
    """钩子模式模型 — 从 ProvenanceGraph 执行轨迹学习 I/O 签名."""

    def __init__(self):
        self._signatures: Dict[str, HookSignature] = {}

    def learn_from_provenance(self, prov_graph) -> int:
        if not hasattr(prov_graph, 'edges'):
            return 0
        for edge in (prov_graph.edges() if callable(prov_graph.edges) else []):
            name = edge.hook_name
            if name.startswith('__'): continue
            reads = set(getattr(edge, 'read_keys', []))
            writes = set(getattr(edge, 'written_keys', []))
            if name not in self._signatures:
                self._signatures[name] = HookSignature(hook_name=name)
            self._signatures[name].update(reads, writes)
        return len(self._signatures)

    def learn_from_telemetry(self, telemetry: List[Dict[str, Any]]) -> int:
        for entry in telemetry:
            name = entry.get('name', '')
            if not name or name.startswith('_'): continue
            reads = set(entry.get('read_keys', []))
            writes = set(entry.get('written_keys', []))
            if not reads and not writes: continue
            if name not in self._signatures:
                self._signatures[name] = HookSignature(hook_name=name)
            self._signatures[name].update(reads, writes)
        return len(self._signatures)

    def signature(self, hook_name: str) -> Optional[HookSignature]:
        return self._signatures.get(hook_name)

    def all_signatures(self) -> Dict[str, HookSignature]:
        return dict(self._signatures)

    def merge(self, other: 'SchemaModel') -> 'SchemaModel':
        for name, sig in other._signatures.items():
            if name in self._signatures:
                self._signatures[name] = self._signatures[name].merge(sig)
            else:
                self._signatures[name] = sig
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {n: s.to_dict() for n, s in self._signatures.items()}

    def save(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> 'SchemaModel':
        model = cls()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return model
        for name, sd in data.items():
            sig = HookSignature(hook_name=name)
            sig.required_reads = set(sd.get('required_reads', []))
            sig.optional_reads = set(sd.get('optional_reads', []))
            sig.written_keys = set(sd.get('written_keys', []))
            sig.sample_count = sd.get('samples', 0)
            model._signatures[name] = sig
        return model


class DAGVerifier:
    """DAG 完备性验证 — 基于 SchemaModel 做静态正确性检查. 空列表 = 通过."""

    def __init__(self, model: SchemaModel):
        self._model = model

    def verify(
        self, edges: Dict[str, List[str]],
        initial_context_keys: Optional[Set[str]] = None,
        final_output_keys: Optional[Set[str]] = None,
    ) -> List[VerificationIssue]:
        ickeys = initial_context_keys or set()
        okeys = final_output_keys or set()
        issues: List[VerificationIssue] = []

        all_nodes: Set[str] = set(edges)
        for dsts in edges.values():
            all_nodes.update(dsts)
        rev_edges: Dict[str, List[str]] = defaultdict(list)
        for src, dsts in edges.items():
            for d in dsts:
                rev_edges[d].append(src)

        # 拓扑排序 + 环检测
        in_deg = {n: 0 for n in all_nodes}
        for src, dsts in edges.items():
            in_deg[src] = in_deg.get(src, 0)
            for d in dsts:
                in_deg[d] = in_deg.get(d, 0) + 1
        from collections import deque
        queue = deque([n for n, d in in_deg.items() if d == 0])
        topo: List[str] = []
        while queue:
            n = queue.popleft(); topo.append(n)
            for d in edges.get(n, []):
                in_deg[d] -= 1
                if in_deg[d] == 0: queue.append(d)
        if len(topo) != len(all_nodes):
            return [VerificationIssue('error', 'cycle', '', 'DAG 中存在循环依赖')]

        produced: Dict[str, Set[str]] = {}
        all_consumed: Set[str] = set(okeys)

        for node in topo:
            avail = set(ickeys)
            for pred in rev_edges.get(node, []):
                avail.update(produced.get(pred, set()))
            sig = self._model.signature(node)
            if sig is None:
                produced[node] = set(); continue

            # 缺失输入
            for rk in sig.required_reads:
                if rk not in avail:
                    issues.append(VerificationIssue('error', 'missing_input', node,
                        f'必需输入 "{rk}" 未被任何上游产出, 也不在初始 context',
                        f'需添加产出 "{rk}" 的钩子为 {node} 的前驱'))
            for rk in sig.optional_reads:
                if rk not in avail:
                    issues.append(VerificationIssue('warning', 'missing_input', node,
                        f'可选输入 "{rk}" 不可用, 钩子可能降级'))

            produced[node] = set(sig.written_keys)

        # 死输出
        for node in topo:
            sig = self._model.signature(node)
            if sig is None: continue
            for d in edges.get(node, []):
                dsig = self._model.signature(d)
                if dsig: all_consumed.update(dsig.all_reads)
        for node in topo:
            sig = self._model.signature(node)
            if sig is None: continue
            dead = sig.written_keys - all_consumed
            if dead:
                issues.append(VerificationIssue('info', 'dead_output', node,
                    f'产出 {sorted(dead)} 无下游消费'))

        # 键冲突: 无依赖关系的节点对可能并行, 检查写入键重叠
        for i, ni in enumerate(topo):
            for j in range(i + 1, len(topo)):
                nj = topo[j]
                if nj not in edges.get(ni, []) and ni not in edges.get(nj, []):
                    si, sj = self._model.signature(ni), self._model.signature(nj)
                    if si and sj:
                        overlap = si.written_keys & sj.written_keys
                        if overlap:
                            issues.append(VerificationIssue('warning', 'key_collision',
                                f'{ni}/{nj}', f'并行写入 {sorted(overlap)}',
                                '添加依赖边或重构键名'))

        # 缺失依赖: A→K→B 数据流但无边
        for node in topo:
            sig = self._model.signature(node)
            if sig is None: continue
            for rk in sig.required_reads:
                prods = [p for p in topo if p != node and rk in produced.get(p, set())]
                for prod in prods:
                    if prod not in rev_edges.get(node, []) and not self._path_exists(prod, node, edges):
                        issues.append(VerificationIssue('warning', 'missing_dep', node,
                            f'读 "{rk}" 来自 {prod} 但缺 {prod}→{node} 边',
                            f'添加 "{prod}" 到 {node} 的 deps'))

        return issues

    @staticmethod
    def _path_exists(src: str, dst: str, edges: Dict[str, List[str]]) -> bool:
        """BFS 检测 src 到 dst 是否存在有向路径."""
        visited: Set[str] = {src}
        queue = [src]
        while queue:
            cur = queue.pop(0)
            if cur == dst:
                return True
            for nxt in edges.get(cur, []):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        return False

    def verify_from_scheduler(
        self, scheduler,
        initial_context_keys: Optional[Set[str]] = None,
        final_output_keys: Optional[Set[str]] = None,
    ) -> List[VerificationIssue]:
        """直接从调度器实例验证."""
        if hasattr(scheduler, 'graph_edges'):
            edges = scheduler.graph_edges()
        elif hasattr(scheduler, '_succ'):
            edges = dict(scheduler._succ)
        else:
            return [VerificationIssue(severity='error', category='internal',
                     hook_name='', detail='无法从调度器提取 DAG 结构')]
        return self.verify(edges, initial_context_keys, final_output_keys)
