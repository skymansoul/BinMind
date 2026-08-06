# 创建: 2026-07-28
# 修改: 2026-08-02 — PAVA 保序回归替换为块合并实现
#
# 死锁自由调度验证 — 资源分配图约简 + 环检测
#
# DAG 调度中任务对共享资源 (锁、GPU 内存、文件句柄) 的获取顺序
# 若在机器分配后形成环，则调度必然死锁。静态依赖分析无法发现此类问题——
# 它来自运行时资源获取顺序与机器分配的组合，而非编译期依赖。
#
# 本模块: 从 DAG + 机器分配 + 资源需求规格构建资源分配图 (RAG)，
# 通过约简规则判定死锁自由，或输出死锁环作为证据。
#
# 方法:
#   1. 构造 RAG: 节点=任务+资源，边=分配+等待
#   2. 若 RAG 含环 → 潜在死锁。但并非所有环都可达:
#      DAG 的拓扑约束使某些边在调度执行中不可同时存在。
#   3. 基于 DAG 偏序的环过滤: 环中等待边需对应"可能并发"的任务对，
#      即两任务在 DAG 中不可比较 (既非祖先也非后代)。
#   4. 约简规则: 若某资源仅被一个未完成任务持有 → 删除其出边
#      (无竞争 → 无等待 → 不参与死锁)
#
# 与 Event-B (ICECCS 2024) / SAG 框架的区别:
#   两者用重型形式化方法验证调度性。本模块是轻量工程工具——
#   无需定理证明器，纯图算法，在提交调度前做最终检查。

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple

from .grl_graph import TaskDependencyGraph


@dataclass
class ResourceSpec:
    """任务对共享资源的需求规格。"""
    resource_id: str
    hold_duration: float = 1.0    # 持有时长 (归一化)
    mode: str = "exclusive"       # exclusive | shared


@dataclass
class DeadlockReport:
    """死锁验证报告。"""
    is_deadlock_free: bool
    cycles_found: List[List[str]]            # 每条环 = [task_id, resource, task_id, ...]
    reduction_steps: int                     # 约简步数
    unreachable_cycles_eliminated: int       # 被 DAG 偏序过滤的环数
    critical_resources: List[str]            # 参与潜在死锁环的资源


def _tarjan_scc(adj: Dict[str, List[str]]) -> List[List[str]]:
    """Tarjan 强连通分量 → 返回大小 ≥2 的 SCC (即环的节点集)。"""
    index = 0
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    onstack: Set[str] = set()
    stack: List[str] = []
    sccs: List[List[str]] = []

    def strongconnect(v: str):
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        onstack.add(v)
        for w in adj.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in onstack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            scc: List[str] = []
            while True:
                w = stack.pop()
                onstack.discard(w)
                scc.append(w)
                if w == v:
                    break
            if len(scc) >= 2:
                sccs.append(scc)

    for v in adj:
        if v not in indices:
            strongconnect(v)
    return sccs


def _are_concurrent(dag: TaskDependencyGraph, a: str, b: str) -> bool:
    """a 和 b 在 DAG 的偏序中是否不可比较。

    不可比较 = a 既不是 b 的祖先也不是 b 的后代 → 两者可能并发执行。
    这是死锁的必要条件之一: 等待环中的任务必须可能同时活跃。
    """
    if a == b:
        return False
    # 祖先检查: a 是 b 的祖先?
    anc_a = dag.ancestors(b)
    if a in anc_a:
        return False
    # 后代检查: b 是 a 的祖先? (即 a 是 b 的后代)
    anc_b = dag.ancestors(a)
    if b in anc_b:
        return False
    return True


class DeadlockVerifier:
    """死锁自由调度验证器。

    使用方式:
      verifier = DeadlockVerifier()
      report = verifier.verify(dag, assignment, resource_specs)
      if not report.is_deadlock_free:
          print(f"Deadlock risk: {report.cycles_found}")
    """

    def verify(
        self,
        dag: TaskDependencyGraph,
        assignment: Dict[str, int],           # task_id → machine_id
        resource_specs: Dict[str, List[ResourceSpec]],  # task_id → 需要的资源列表
    ) -> DeadlockReport:
        """验证给定调度方案是否死锁自由。"""
        ids = set(dag.node_ids)
        all_resources: Set[str] = set()
        task_resources: Dict[str, List[str]] = {}   # task → 它需要的资源

        for tid, specs in resource_specs.items():
            if tid not in ids:
                continue
            task_resources[tid] = [spec.resource_id for spec in specs]
            for spec in specs:
                all_resources.add(spec.resource_id)

        if not all_resources:
            return DeadlockReport(
                is_deadlock_free=True, cycles_found=[],
                reduction_steps=0, unreachable_cycles_eliminated=0,
                critical_resources=[],
            )

        # Step 1: 构造 RAG — 二部图 (任务 ∪ 资源)
        # 边: task → resource (等待) / resource → task (持有)
        rag: Dict[str, List[str]] = {}
        for tid in ids:
            rag[tid] = []
        for rid in all_resources:
            rag[rid] = []

        # 同一机器上的任务按 DAG 的拓扑序串行化假设:
        # 若任务 A 和 B 在同一机器上且 A 在 B 之前 → A 持有资源时 B 在等机器
        # 死锁的核心关注点在跨机器的资源等待关系。
        machine_tasks: Dict[int, List[str]] = {}
        for tid, mid in assignment.items():
            if tid in ids:
                machine_tasks.setdefault(mid, []).append(tid)

        # 持有边: resource → task (该任务正在使用此资源)
        for tid, specs in resource_specs.items():
            if tid not in ids:
                continue
            for spec in specs:
                rag[spec.resource_id].append(tid)

        # 等待边: task → resource (该任务等待此资源)
        for tid, specs in resource_specs.items():
            if tid not in ids:
                continue
            for spec in specs:
                rag[tid].append(spec.resource_id)

        # Step 2: 约简 — 无竞争的持有边按规则消去
        reduction_steps = 0
        changed = True
        while changed:
            changed = False
            for rid in list(all_resources):
                holders = [t for t in rag.get(rid, []) if t in ids]
                # 规则1: 资源仅一个持有者 → 无竞争 → 删除此资源的所有边
                if len(holders) <= 1:
                    for t in rag:
                        if rid in rag[t]:
                            rag[t].remove(rid)
                    rag[rid] = []
                    all_resources.discard(rid)
                    changed = True
                    reduction_steps += 1
                    continue
                # 规则2: 所有持有者互不并发 → 实际上无竞争
                if len(holders) >= 2:
                    all_sequential = True
                    for i in range(len(holders)):
                        for j in range(i + 1, len(holders)):
                            if _are_concurrent(dag, holders[i], holders[j]):
                                all_sequential = False
                                break
                        if not all_sequential:
                            break
                    if all_sequential:
                        for t in rag:
                            if rid in rag[t]:
                                rag[t].remove(rid)
                        rag[rid] = []
                        all_resources.discard(rid)
                        changed = True
                        reduction_steps += 1

        # Step 3: 在约简后的 RAG 上检测环
        raw_cycles = _tarjan_scc(rag)
        unreachable_eliminated = 0
        real_cycles: List[List[str]] = []

        for scc in raw_cycles:
            # 在 SCC 中提取有向环 — 从任务节点出发，交替经过资源
            cycle = self._extract_cycle(scc, rag)
            if not cycle:
                continue
            # 过滤: 环中相邻任务对必须可并发
            valid = self._is_valid_cycle(cycle, dag)
            if valid:
                real_cycles.append(cycle)
            else:
                unreachable_eliminated += 1

        critical = list(set(
            node for cycle in real_cycles for node in cycle
            if node in all_resources
        ))

        return DeadlockReport(
            is_deadlock_free=len(real_cycles) == 0,
            cycles_found=real_cycles,
            reduction_steps=reduction_steps,
            unreachable_cycles_eliminated=unreachable_eliminated,
            critical_resources=critical,
        )

    def _extract_cycle(
        self, scc: List[str], rag: Dict[str, List[str]],
    ) -> List[str]:
        """从 SCC 中提取一条有向环。SCC 大小 ≥ 2 保证了环的存在。"""
        scc_set = set(scc)
        visited: Set[str] = set()
        path: List[str] = []

        def dfs(u: str) -> bool:
            if u in visited:
                if u in path:
                    # 找到环 — 截取 path 中从 u 开始的部分
                    idx = path.index(u)
                    nonlocal cycle_found
                    cycle_found = path[idx:]
                    return True
                return False
            visited.add(u)
            path.append(u)
            for v in rag.get(u, []):
                if v in scc_set:
                    if dfs(v):
                        return True
            path.pop()
            return False

        cycle_found: List[str] = []
        for start in scc:
            if start in visited:
                continue
            if dfs(start):
                return cycle_found
        return []

    def _is_valid_cycle(
        self, cycle: List[str], dag: TaskDependencyGraph,
    ) -> bool:
        """验证环中的等待关系在 DAG 偏序下可达。

        环的形式: T0 → R1 → T1 → R2 → T2 → ... → T0
        每对 (Ti waiting for R → held by Tj) 要求 Ti 和 Tj 可并发。
        """
        task_nodes = [n for n in cycle if n in dag]
        for i in range(len(task_nodes)):
            ti = task_nodes[i]
            tj = task_nodes[(i + 1) % len(task_nodes)]
            if ti != tj and not _are_concurrent(dag, ti, tj):
                return False
        return True
