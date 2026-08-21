# coding: utf-8
"""
因果溯源追踪 - 钩子管道的每次状态变迁以有向溯源图记录.

现有 DAG 调度器的遥测是统计型 (count/latency/success_rate) —
能回答 "某钩子是否成功/耗时多少", 但回答不了 "钩子 B 的输出异常是否由
钩子 A 的错误写入所致". 这对复杂分析管道的事后诊断是致命缺陷.

借鉴 SPARSE 的溯源图思想, 将其从审计日志域迁移到
钩子管道执行域: 每个钩子执行 → 一条溯源边 (input_version → output_version).
引入读键集/写键集记录, 刻画数据流以支持裁剪式传播路径查询.

溯源图使管道从 "可观测" 升级为 "可解释" -
类似数据库的 provenance (why + where) 但面向动态管道执行.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from modules.core.context_versioning import ContextVersion, ContextVersionStore


@dataclass
class ProvenanceEdge:
    """溯源图中的一条有向边: 钩子执行 f(input_version) -> output_version.

    read_keys / written_keys 记录该钩子实际触碰的 context 键集,
    用于 impact_analysis 时的精准传播路径裁剪.
    """

    edge_id: str
    hook_name: str
    input_version_id: str
    output_version_id: str
    read_keys: Tuple[str, ...]
    written_keys: Tuple[str, ...]
    wall_ms: float
    success: bool
    error_msg: str = ''
    extra: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        status = 'OK' if self.success else 'FAIL'
        return (f'Edge({self.hook_name}: '
                f'{self.input_version_id[:8]}→{self.output_version_id[:8]} '
                f'{self.wall_ms:.1f}ms {status})')


class ProvenanceGraph:
    """钩子管道的因果溯源 DAG.

    内部维护:
      - _edges: edge_id → ProvenanceEdge
      - _adj_fwd: version_id → [edge_id]   (正向: 从该版本出发的边)
      - _adj_rev: version_id → [edge_id]   (逆向: 到达该版本的边)
      - _hook_edges: hook_name → [edge_id] (按钩子名索引)

    双向邻接使正向影响分析与逆向根因分析均为 O(reachable_edges).
    """

    def __init__(self):
        self._edges: Dict[str, ProvenanceEdge] = {}
        self._adj_fwd: Dict[str, List[str]] = defaultdict(list)
        self._adj_rev: Dict[str, List[str]] = defaultdict(list)
        self._hook_edges: Dict[str, List[str]] = defaultdict(list)
        self._execution_count = 0

    def record(
        self, hook_name: str,
        input_version: ContextVersion,
        output_version: ContextVersion,
        read_keys: Tuple[str, ...],
        written_keys: Tuple[str, ...],
        wall_ms: float,
        success: bool,
        error_msg: str = '',
        **extra,
    ) -> ProvenanceEdge:
        """记录一次钩子执行的溯源边."""
        self._execution_count += 1
        edge_id = f'{hook_name}:{self._execution_count}'
        edge = ProvenanceEdge(
            edge_id=edge_id, hook_name=hook_name,
            input_version_id=input_version.version_id,
            output_version_id=output_version.version_id,
            read_keys=read_keys, written_keys=written_keys,
            wall_ms=wall_ms, success=success,
            error_msg=error_msg, extra=extra,
        )
        self._edges[edge_id] = edge
        self._adj_fwd[input_version.version_id].append(edge_id)
        self._adj_rev[output_version.version_id].append(edge_id)
        self._hook_edges[hook_name].append(edge_id)
        return edge

    def impact_analysis(
        self, start_version_id: str, max_depth: int = 50,
    ) -> List[ProvenanceEdge]:
        """正向追溯: 从 start_version 沿数据流找所有受影响的边.

        仅遍历 written_keys 与下游 read_keys 有交集的边, 无数据依赖的分支被裁掉.
        """
        visited: Set[str] = set()
        result: List[ProvenanceEdge] = []
        stack: List[Tuple[str, int, Set[str]]] = [(start_version_id, 0, set())]
        while stack:
            vid, depth, keys_of_interest = stack.pop()
            if depth >= max_depth:
                continue
            for eid in self._adj_fwd.get(vid, []):
                if eid in visited:
                    continue
                edge = self._edges[eid]
                visited.add(eid)
                if not keys_of_interest or (set(edge.read_keys) & keys_of_interest):
                    result.append(edge)
                    next_keys = keys_of_interest | set(edge.written_keys) if keys_of_interest else set(edge.written_keys)
                    stack.append((edge.output_version_id, depth + 1, next_keys))
                elif set(edge.written_keys) & keys_of_interest:
                    result.append(edge)
                    stack.append((edge.output_version_id, depth + 1, keys_of_interest))
        return result

    def root_cause(
        self, target_version_id: str, max_depth: int = 50,
    ) -> List[ProvenanceEdge]:
        """逆向追溯: 从 target_version 回溯前序边链."""
        visited: Set[str] = set()
        result: List[ProvenanceEdge] = []
        stack: List[Tuple[str, int]] = [(target_version_id, 0)]
        while stack:
            vid, depth = stack.pop()
            if depth >= max_depth:
                continue
            for eid in self._adj_rev.get(vid, []):
                if eid in visited:
                    continue
                edge = self._edges[eid]
                visited.add(eid)
                result.append(edge)
                stack.append((edge.input_version_id, depth + 1))
        return result

    def blame(
        self, target_version_id: str, max_depth: int = 50,
    ) -> Optional[ProvenanceEdge]:
        """故障根因定位: 逆向追溯中最深的 success=False 边."""
        chain = self.root_cause(target_version_id, max_depth=max_depth)
        failed = [e for e in chain if not e.success]
        if not failed:
            return None
        failed.sort(key=lambda e: e.input_version_id)
        return failed[0]

    def hook_statistics(self, hook_name: str) -> Dict[str, Any]:
        """单钩子的溯源统计: 成功率、平均读写键数、数据流影响范围."""
        edges = self._hook_edges.get(hook_name, [])
        if not edges:
            return {'count': 0}
        recs = [self._edges[eid] for eid in edges]
        success_rate = sum(1 for r in recs if r.success) / len(recs)
        avg_reads = sum(len(r.read_keys) for r in recs) / len(recs)
        avg_writes = sum(len(r.written_keys) for r in recs) / len(recs)
        downstream = set()
        for r in recs:
            for eid in self._adj_fwd.get(r.output_version_id, []):
                downstream.add(self._edges[eid].hook_name)
        return {
            'count': len(recs), 'success_rate': round(success_rate, 4),
            'avg_read_keys': round(avg_reads, 2),
            'avg_written_keys': round(avg_writes, 2),
            'downstream_hooks': sorted(downstream),
        }

    def edges(self) -> List[ProvenanceEdge]:
        return list(self._edges.values())

    def edge_count(self) -> int:
        return len(self._edges)


class ProvenanceScheduler:
    """溯源感知的调度器包装 - 包裹 HookDAGScheduler 并在每次钩子执行前后
    自动记录溯源边, 对既有调度器零侵入.

    用法:
      base_sched = HookDAGScheduler()
      base_sched.register(...).build()
      prov = ProvenanceScheduler(base_sched)
      ctx = prov.execute(context)
      prov.graph.impact_analysis(prov.version_store.latest().version_id)
    """

    def __init__(self, scheduler):
        """scheduler: 任意实现了 execute(context) 和 get_telemetry() 的对象.

        通过依赖注入而非继承设计: 避免侵入既有调度器的内部状态管理,
        且可对任意 DAG 调度器实现复用.
        """
        self._sched = scheduler
        self.version_store = ContextVersionStore()
        self.graph = ProvenanceGraph()
        # 钩子执行前 context 的版本映射: hook_name → (pre_version, read_keys_probe)
        self._pending: Dict[str, Tuple[ContextVersion, Tuple[str, ...]]] = {}

    def execute(
        self, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None, parallel: bool = True,
    ) -> Dict[str, Any]:
        """执行管道, 与 HookDAGScheduler.execute 签名兼容, 额外产生溯源图."""
        if context is None:
            context = {}
        root_version = self.version_store.commit(context, hook_name='__root__')
        self._pending.clear()

        # 注入探头: 猴子补丁拦截 _execute_one.
        # 不修改原始调度器: 保持与未来版本的兼容性.
        original_exec_one = self._sched._execute_one
        original_run_level = self._sched._run_level
        provenance_graph = self.graph
        version_store = self.version_store
        pending_map = self._pending

        def _wrapped_exec_one(name: str, ctx: dict, failed: set, skipped: set) -> None:
            # 读键探测: 用闭包钩子截获 context 的读取
            reads: Set[str] = set()
            ctx_before = dict(ctx)

            class _ReadProbe(dict):
                # 拦截 __getitem__ 记录被读取的键 — 仅用于溯源
                _reads: Set[str]

                def __getitem__(self, k):
                    self._reads.add(k)
                    return super().__getitem__(k)

            probe = _ReadProbe(ctx)
            probe._reads = reads
            probe.update(ctx)

            t0 = time.perf_counter()
            # 对原始调度器: 临时替换 context 为探测版本
            original_exec_one(name, probe, failed, skipped)
            elapsed = (time.perf_counter() - t0) * 1000

            # 写键推断: 对比探测前后的差异
            written = tuple(sorted(
                k for k in set(ctx_before) | set(probe)
                if k not in ctx_before or k in probe and ctx_before.get(k) != probe.get(k)
            ))

            # 提交版本并记录溯源边
            pre_ver = pending_map.get(name, (root_version, ()))[0]
            try:
                post_ver = version_store.commit(
                    probe, parent=pre_ver, hook_name=name,
                )
            except Exception:
                post_ver = pre_ver  # 提交失败时退化为不变

            success = name not in failed
            provenance_graph.record(
                hook_name=name,
                input_version=pre_ver,
                output_version=post_ver,
                read_keys=tuple(sorted(reads)),
                written_keys=written,
                wall_ms=elapsed,
                success=success,
                error_msg='' if success else f'任务 {name} 执行失败',
            )

            # 更新 context (原始调度器期望 side-effect 写回)
            ctx.clear()
            ctx.update(probe)

            # 缓存此钩子的输出版本, 供下游溯源
            pending_map[name] = (post_ver, written)

        self._sched._execute_one = _wrapped_exec_one

        try:
            result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
        finally:
            # 恢复原始方法, 确保无持久副作用
            self._sched._execute_one = original_exec_one
            self._sched._run_level = original_run_level

        # 最终版本
        self.version_store.commit(result, hook_name='__final__')
        return result

    def telemetry(self) -> Any:
        """代理原始调度器的遥测."""
        if hasattr(self._sched, 'get_telemetry'):
            return self._sched.get_telemetry()
        return None
