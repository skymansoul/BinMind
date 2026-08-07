# coding: utf-8
"""
管道产出语义比对 — 对比两次执行的 context, 通过溯源图将每个变更归因到具体钩子.

BinDiff/Diaphora 比对二进制本身, 本模块比对分析管道产出.
结合 provenance graph 实现变更溯源: 不仅报告 "vulns 键的值变了",
还指出 "vulns 由 vuln_scan 钩子产出, 其输入 info 来自 loader, loader 的
输入 binary_path 不同导致整条链的产出变化".
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


def _stable_hash(obj: Any) -> str:
    try:
        raw = json.dumps(obj, sort_keys=True, default=repr).encode('utf-8')
    except (TypeError, ValueError):
        raw = repr(obj).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass
class KeyChange:
    """单个 context 键的变更记录."""
    key: str
    change_type: str          # 'added' | 'removed' | 'modified' | 'unchanged'
    old_hash: str = ''
    new_hash: str = ''
    old_preview: str = ''     # 旧值截断预览
    new_preview: str = ''     # 新值截断预览
    attributed_hooks: List[str] = field(default_factory=list)
    attribution_chain: str = ''  # 人类可读的因果链


@dataclass
class DiffReport:
    """一次管道比对的结构化报告."""
    keys_added: List[str]
    keys_removed: List[str]
    keys_modified: List[str]
    keys_unchanged: List[str]
    changes: List[KeyChange]
    summary: str = ''


class PipelineDiffer:
    """管道产出比对器 — 比较两次执行的 context 差异, 溯源变更原因.

    用法:
      differ = PipelineDiffer()
      report = differ.compare(ctx_v1, ctx_v2, prov_v1, prov_v2)
      # report.keys_modified → ['vulns', 'report']
      # report.changes[0].attribution_chain → 'loader→vuln_scan'
    """

    def __init__(self, max_preview_len: int = 120):
        self._max_preview = max_preview_len

    def compare(
        self, ctx_a: Dict[str, Any], ctx_b: Dict[str, Any],
        prov_a=None, prov_b=None,
    ) -> DiffReport:
        """比对两个 context, 产出带溯源的变更报告."""
        all_keys = set(ctx_a) | set(ctx_b)
        changes: List[KeyChange] = []
        added, removed, modified, unchanged = [], [], [], []

        for key in sorted(all_keys):
            va, vb = ctx_a.get(key), ctx_b.get(key)
            ha, hb = _stable_hash(va), _stable_hash(vb)

            if key not in ctx_a:
                kc = KeyChange(key=key, change_type='added',
                              new_hash=hb, new_preview=self._preview(vb))
                added.append(key)
            elif key not in ctx_b:
                kc = KeyChange(key=key, change_type='removed',
                              old_hash=ha, old_preview=self._preview(va))
                removed.append(key)
            elif ha != hb:
                kc = KeyChange(key=key, change_type='modified',
                              old_hash=ha, new_hash=hb,
                              old_preview=self._preview(va),
                              new_preview=self._preview(vb))
                modified.append(key)
            else:
                kc = KeyChange(key=key, change_type='unchanged',
                              old_hash=ha, new_hash=hb)
                unchanged.append(key)

            # 溯源归因
            if kc.change_type in ('modified', 'added', 'removed'):
                self._attribute(kc, prov_a, prov_b)
            changes.append(kc)

        summary = (f'{len(added)} added, {len(removed)} removed, '
                  f'{len(modified)} modified, {len(unchanged)} unchanged')
        return DiffReport(
            keys_added=added, keys_removed=removed,
            keys_modified=modified, keys_unchanged=unchanged,
            changes=changes, summary=summary)

    def _attribute(self, kc: KeyChange, prov_a, prov_b) -> None:
        """通过溯源图追溯变更的因果链."""
        # 查找产出该键的钩子
        producers_a = self._find_producers(kc.key, prov_a)
        producers_b = self._find_producers(kc.key, prov_b)

        if producers_a and producers_b and producers_a != producers_b:
            kc.attributed_hooks = list(set(producers_a) | set(producers_b))
            kc.attribution_chain = (
                f'产出钩子变更: {producers_a} → {producers_b}')
        elif producers_a:
            kc.attributed_hooks = producers_a
            # 沿溯源链向上追溯: 找到输入差异的根源
            chain = self._trace_upstream(kc.key, producers_a[0], prov_a, prov_b)
            kc.attribution_chain = chain if chain else f'由 {producers_a[0]} 产出'
        elif producers_b:
            kc.attributed_hooks = producers_b
            kc.attribution_chain = f'由 {producers_b[0]} 新增产出'
        else:
            kc.attribution_chain = '外部注入 (初始 context 差异)'

    def _find_producers(self, key: str, prov) -> List[str]:
        """在溯源图中查找产出指定键的钩子."""
        if prov is None or not hasattr(prov, 'graph'):
            return []
        producers = set()
        for edge in (prov.graph.edges() if callable(prov.graph.edges) else []):
            if hasattr(edge, 'written_keys') and key in (edge.written_keys or []):
                producers.add(edge.hook_name)
        return sorted(producers)

    def _trace_upstream(
        self, key: str, producer: str, prov_a, prov_b,
    ) -> str:
        """沿溯源链向上追溯, 找到输入差异的根因钩子."""
        if prov_a is None or prov_b is None:
            return ''
        # 找到 producer 的输入边
        edges_a = self._edges_for(prov_a)
        edges_b = self._edges_for(prov_b)

        # 查找 producer 的输入键
        input_keys_a = set()
        input_keys_b = set()
        for e in edges_a:
            if e.hook_name == producer:
                input_keys_a.update(getattr(e, 'read_keys', []))
        for e in edges_b:
            if e.hook_name == producer:
                input_keys_b.update(getattr(e, 'read_keys', []))

        # 找到有差异的输入键
        diff_inputs = set()
        for ik in input_keys_a | input_keys_b:
            # 粗略比对: 看是否有同名输入来自不同的上游钩子
            upstream_a = self._producer_of(ik, edges_a)
            upstream_b = self._producer_of(ik, edges_b)
            if upstream_a != upstream_b:
                diff_inputs.add(ik)

        if diff_inputs:
            chain_parts = [f'{producer} 的输入 {sorted(diff_inputs)} 有差异']
            # 递归追溯一层
            for ik in sorted(diff_inputs)[:2]:
                up = self._producer_of(ik, edges_a) or self._producer_of(ik, edges_b)
                if up:
                    chain_parts.append(f'← {up} 产出 {ik} 不同')
            return '; '.join(chain_parts)

        return f'{producer} 输入相同但产出不同 (非确定性或外部状态)'

    @staticmethod
    def _edges_for(prov) -> List[Any]:
        if prov is None or not hasattr(prov, 'graph'):
            return []
        return list(prov.graph.edges()) if callable(prov.graph.edges) else []

    @staticmethod
    def _producer_of(key: str, edges: List[Any]) -> str:
        for e in edges:
            if hasattr(e, 'written_keys') and key in (e.written_keys or []):
                return e.hook_name
        return ''

    def _preview(self, val: Any) -> str:
        if val is None:
            return '<None>'
        s = str(val)
        if len(s) > self._max_preview:
            return s[:self._max_preview] + '...'
        return s


class BatchDiffer:
    """批量比对 — 对多组 (binary_v1, binary_v2) 产出做统计.

    用于回归测试: 检测管道升级后哪些钩子的产出发生了系统性变化.
    """

    def __init__(self):
        self._stats: Dict[str, Dict[str, int]] = {}  # hook_name → {added/removed/modified: count}

    def add_report(self, report: DiffReport) -> None:
        for kc in report.changes:
            for hook in kc.attributed_hooks:
                if hook not in self._stats:
                    self._stats[hook] = {'added': 0, 'removed': 0, 'modified': 0}
                self._stats[hook][kc.change_type] = self._stats[hook].get(kc.change_type, 0) + 1

    def volatile_hooks(self, threshold: int = 3) -> List[str]:
        """返回频繁产出变更的钩子 (变更次数 ≥ threshold)."""
        return sorted(
            [h for h, s in self._stats.items()
             if sum(s.values()) >= threshold],
            key=lambda h: sum(self._stats[h].values()), reverse=True)

    def summary(self) -> Dict[str, Any]:
        return {'hook_stats': self._stats, 'volatile': self.volatile_hooks()}
