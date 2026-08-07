# 能力感知调度 — 任务需求与节点能力的双层匹配
#
# 安全分析任务对执行环境有异构需求:
# GPU 内存 ≥ 8GB (符号执行加速)
# 特定工具链 (Ghidra v11, IDA Pro)
# OS 版本 (某些二进制仅特定系统可运行)
# 网络隔离 (恶意样本需沙箱)
#
# 传统调度将节点视为同质计算单元——忽略能力差异。
# 导致: GPU 任务被分配到纯 CPU 节点 (慢 10×)、工具链版本不匹配
# (任务失败)、恶意样本在无隔离环境执行 (安全风险)。
#
# 本模块:
#   1. 能力向量: 每个节点声明其能力 (CapabilityVector)
#   2. 任务需求: 每个任务声明其需求 (TaskRequirement)
#   3. 匹配: 二部图匹配——需求 ⊆ 能力 → 节点合格
#   4. 软约束: 可选能力 (偏好加分) vs 硬约束 (必须满足)
#   5. 降级: 硬约束不满足 → 标记为 UNPLACEABLE + 通知用户

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional, List, Dict, Set, Tuple


@dataclass
class CapabilityVector:
    """节点的能力声明。"""
    node_id: str
    cpu_cores: int = 4
    memory_gb: float = 16.0
    gpu_memory_gb: float = 0.0
    has_gpu: bool = False
    tools: Set[str] = field(default_factory=set)
    os_type: str = "linux"
    is_isolated: bool = False          # 沙箱隔离
    labels: Dict[str, str] = field(default_factory=dict)

    def satisfies(self, req: "TaskRequirement") -> Tuple[bool, float]:
        """检查是否满足任务需求。

        返回 (硬约束全满足, 匹配分数 0-1)。
        匹配分数 = 软约束满足比例——用于候选节点排序。
        """
        hard_ok = True
        soft_score = 0.0
        n_checks = 0

        # 硬约束
        if req.min_cpu_cores > 0:
            n_checks += 1
            if self.cpu_cores >= req.min_cpu_cores:
                soft_score += 1.0
            else:
                hard_ok = False

        if req.min_memory_gb > 0:
            n_checks += 1
            if self.memory_gb >= req.min_memory_gb:
                soft_score += 1.0
            else:
                hard_ok = False

        if req.requires_gpu and not self.has_gpu:
            hard_ok = False

        if req.min_gpu_memory_gb > 0:
            n_checks += 1
            if self.gpu_memory_gb >= req.min_gpu_memory_gb:
                soft_score += 1.0
            else:
                hard_ok = False

        # 工具链 (硬)
        if req.required_tools:
            n_checks += 1
            missing = req.required_tools - self.tools
            if missing:
                hard_ok = False
            else:
                soft_score += 1.0

        # OS (硬)
        if req.os_type and req.os_type != "*":
            n_checks += 1
            if self.os_type == req.os_type:
                soft_score += 1.0
            else:
                hard_ok = False

        # 隔离 (硬)
        if req.requires_isolation and not self.is_isolated:
            hard_ok = False

        # 软约束: 偏好标签匹配
        if req.preferred_labels:
            n_checks += 0.5
            overlap = set(req.preferred_labels.keys()) & set(self.labels.keys())
            if overlap:
                matches = sum(
                    1 for k in overlap
                    if self.labels.get(k) == req.preferred_labels.get(k)
                )
                soft_score += 0.5 * matches / max(len(overlap), 1)

        # 偏好工具 (软)
        if req.preferred_tools:
            n_checks += 0.5
            overlap = req.preferred_tools & self.tools
            soft_score += 0.5 * len(overlap) / max(len(req.preferred_tools), 1)

        score = soft_score / max(n_checks, 1) if n_checks > 0 else 1.0
        return hard_ok, min(1.0, score)


@dataclass
class TaskRequirement:
    task_id: str
    min_cpu_cores: int = 1
    min_memory_gb: float = 1.0
    requires_gpu: bool = False
    min_gpu_memory_gb: float = 0.0
    required_tools: Set[str] = field(default_factory=set)
    preferred_tools: Set[str] = field(default_factory=set)
    os_type: str = "*"
    requires_isolation: bool = False
    preferred_labels: Dict[str, str] = field(default_factory=dict)


class CapabilityAwareScheduler:
    """能力感知调度器 — 任务需求与节点能力的双层匹配。

    匹配流程:
      1. 硬约束过滤 → 合格的节点集
      2. 软约束评分 → 排序 (分数高者优先)
      3. 负载均衡 → 在 top-K 候选中选负载最轻的
      4. 若无可匹配节点 → 返回 UNPLACEABLE
    """

    def __init__(self):
        self._nodes: Dict[str, CapabilityVector] = {}
        self._node_loads: Dict[str, float] = defaultdict(float)

    def register_node(self, cap: CapabilityVector):
        self._nodes[cap.node_id] = cap

    def remove_node(self, node_id: str):
        self._nodes.pop(node_id, None)
        self._node_loads.pop(node_id, None)

    def select_best(self, req: TaskRequirement,
                    top_k: int = 3) -> Optional[str]:
        """为任务需求选择最佳节点。返回 node_id 或 None (不可放置)。"""
        candidates = []
        for nid, cap in self._nodes.items():
            hard_ok, score = cap.satisfies(req)
            if hard_ok:
                candidates.append((score, self._node_loads.get(nid, 0.0), nid))

        if not candidates:
            return None

        # 排序: 匹配分高 + 负载低的优先
        candidates.sort(key=lambda x: (-x[0], x[1]))
        best = candidates[0][2]
        self._node_loads[best] += 1.0
        return best

    def complete_task(self, node_id: str):
        self._node_loads[node_id] = max(
            0.0, self._node_loads.get(node_id, 0.0) - 1.0
        )

    def unplaceable_reason(self, req: TaskRequirement) -> List[str]:
        """诊断不可放置的原因。"""
        reasons = []
        for nid, cap in self._nodes.items():
            hard_ok, _ = cap.satisfies(req)
            if not hard_ok:
                if req.requires_gpu and not cap.has_gpu:
                    reasons.append(f"{nid}: no GPU")
                if req.required_tools - cap.tools:
                    reasons.append(
                        f"{nid}: missing {req.required_tools - cap.tools}"
                    )
        return reasons[:5]

    def eligible_count(self, req: TaskRequirement) -> int:
        return sum(
            1 for cap in self._nodes.values()
            if cap.satisfies(req)[0]
        )

    def stats(self) -> dict:
        return {
            "registered_nodes": len(self._nodes),
            "nodes_with_gpu": sum(1 for c in self._nodes.values() if c.has_gpu),
            "nodes_isolated": sum(1 for c in self._nodes.values() if c.is_isolated),
            "avg_load": round(
                sum(self._node_loads.values()) / max(len(self._nodes), 1), 2
            ),
        }
