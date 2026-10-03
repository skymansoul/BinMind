# 工作窃取协调器 — 分布式符号执行节点的自适应负载均衡
#
# 分布式符号执行中节点负载天然不均。部分节点分配含密集循环的函数，路径数
# 迅速膨胀；另一些节点分配短小工具函数，快速进入空闲。传统固定分片
# （按函数名哈希分配）无法应对这种动态差异。
#
# 本模块在每个节点上运行轻量级协调器：
#   (a) 每 5 秒向其他节点广播自身负载快照（活跃路径数 + 求解器利用率）
#   (b) 自身空闲（活跃路径 < 阈值）时，按 least_loaded 顺序向其他节点
#       请求窃取任务
#   (c) 被窃取节点从工作列表中选择"最可分割"路径——选择标准为该路径
#       挂起的 fork 点最多（拆分为独立子任务的潜力最大）
#   (d) 被窃取子任务携带完整符号状态（约束集 + 内存快照），
#       通过 pickle 序列化传输
#
# 与 SolverBudgetManager 协同：
#   被窃取方在转移子任务前扣减自身预算，窃取方在接收后申请新预算。
#   防止"预算套利"：通过频繁窃取绕过单节点预算限制。
#
# 降低空窃取率。

import time
import threading
import random
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import deque


@dataclass
class NodeState:
    """节点实时负载快照。"""
    node_id: str
    active_paths: int
    solver_utilization: float  # 求解器线程池利用率，归一化至 [0, 1]
    pending_fork_points: int   # 所有活跃路径中待探索分支点总数
    last_heartbeat: float = 0.0


class WorkStealingCoordinator:
    """单节点工作窃取协调器。

    每个节点运行一个实例。通过 heartbeat（消息队列 / Redis pubsub）
    交换 NodeState。传输层由调用方注入，不绑定特定实现。
    """

    IDLE_THRESHOLD = 5       # 活跃路径低于此值触发窃取
    HEARTBEAT_INTERVAL = 5.0  # 心跳广播间隔（秒）
    STATE_TTL = 15.0          # 节点状态过期时限（秒），超时视为离线

    def __init__(self, node_id: str):
        self._node_id = node_id
        self._local_state = NodeState(
            node_id=node_id, active_paths=0,
            solver_utilization=0.0, pending_fork_points=0,
            last_heartbeat=time.time(),
        )
        self._peer_states: Dict[str, NodeState] = {}
        self._stolen_task_count: int = 0
        self._donated_task_count: int = 0
        self._lock = threading.Lock()

    def update_local(self, active_paths: int, solver_utilization: float,
                     pending_fork_points: int):
        """更新本节点负载状态，由主事件循环每轮调用。"""
        with self._lock:
            self._local_state.active_paths = active_paths
            self._local_state.solver_utilization = solver_utilization
            self._local_state.pending_fork_points = pending_fork_points
            self._local_state.last_heartbeat = time.time()

    def receive_heartbeat(self, peer_state: NodeState):
        """接收对等节点心跳，由消息层回调。"""
        with self._lock:
            self._peer_states[peer_state.node_id] = peer_state

    def get_local_state(self) -> NodeState:
        return self._local_state

    def should_steal(self) -> bool:
        """判断本节点是否应发起工作窃取。"""
        with self._lock:
            return self._local_state.active_paths < self.IDLE_THRESHOLD

    def select_victim(self) -> Optional[str]:
        """选择窃取目标节点 — least_loaded 优先。

        活跃路径最少且 pending_fork_points 最多的节点：
        即"最空闲但持有最多可分拆任务"的节点。
        仅考虑心跳未过期且 pending_fork_points ≥ 2 的节点。
        """
        now = time.time()
        candidates = []
        with self._lock:
            for nid, state in self._peer_states.items():
                if nid == self._node_id:
                    continue
                if now - state.last_heartbeat > self.STATE_TTL:
                    continue
                if state.pending_fork_points < 2:
                    continue  # 无可分割任务，窃取无收益
                candidates.append(state)

        if not candidates:
            return None

        # least_loaded: 按 (active_paths, -pending_fork_points) 升序排列
        candidates.sort(key=lambda s: (s.active_paths, -s.pending_fork_points))
        return candidates[0].node_id

    def select_donation_task(self, max_count: int = 3) -> List[Any]:
        """从本地工作列表中选择最适合转移的子任务。

        选择 pending_fork_points 最大的路径：未探索分支最多，
        拆分为独立子任务后并行潜力最大。
        调用方负责从本地工作列表移除返回的任务。
        """
        # 占位实现：实际任务选择依赖本地符号执行引擎 API，
        # 由调用方按 fork 点排序后注入
        return []

    def record_steal(self):
        self._stolen_task_count += 1

    def record_donation(self):
        self._donated_task_count += 1

    def stats(self) -> Dict:
        with self._lock:
            online_peers = sum(
                1 for s in self._peer_states.values()
                if time.time() - s.last_heartbeat <= self.STATE_TTL
            )
            return {
                'node_id': self._node_id,
                'active_paths': self._local_state.active_paths,
                'solver_utilization': self._local_state.solver_utilization,
                'online_peers': online_peers,
                'stolen_tasks': self._stolen_task_count,
                'donated_tasks': self._donated_task_count,
            }
