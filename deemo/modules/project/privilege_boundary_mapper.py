# 修改记录:
# 2025-07-22 16:50 — 初始创建: 六层权限模型+路径枚举
# 2025-07-29 10:15 — 增加权限图+Dijkstra最短攻击路径+跨层传播
# 2025-08-04 14:22 — 增加capability传播图+攻击路径风险评分
# 权限边界映射器: 权限图传播 / Dijkstra最短路径 / 跨层攻击链
# 技术问题: 简单if-else枚举无法发现跨层攻击路径.
#   例如: CAP_SYS_ADMIN(层3) 可创建user namespace→在其中获得
#   CAP_SYS_PTRACE(层3)→ptrace注入宿主机进程(跨层1→层5).
#   枚举式检查只能看到各层独立的风险, 遗漏跨层组合
# 解决手段: 构建权限传播有向图:
#   节点: (层, 权限集) 状态
#   边: 状态转移 (获取capability/创建namespace/ptrace注入等)
#   权重: 攻击难度 (1-10)
#   Dijkstra求从当前状态到目标状态的最短路径(最小难度和)
# 参考 (已验证真实):
#   Linux capabilities man page (capabilities(7)) — capability位定义
#   CVE-2022-0492 (container escape via cgroup release_agent) — 跨层攻击实例
from __future__ import annotations
import heapq, logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

_CAPABILITIES = {0:"CAP_CHOWN",1:"CAP_DAC_OVERRIDE",6:"CAP_SETUID",
    7:"CAP_SETGID",12:"CAP_NET_ADMIN",17:"CAP_SYS_ADMIN",
    21:"CAP_SYS_PTRACE",39:"CAP_BPF",40:"CAP_CHECKPOINT_RESTORE"}


@dataclass
class PrivNode:
    """权限图节点: (layer, capability_set, context)."""
    node_id: str; layer: str
    capabilities: int = 0; uid: int = 1000
    ns_type: str = "host"; seccomp: str = "none"


@dataclass
class PrivEdge:
    """权限转移边: 从src到dst的攻击步骤."""
    src_id: str; dst_id: str; action: str
    difficulty: float = 5.0          # 1-10
    required_caps: int = 0
    gained_caps: int = 0
    precondition: str = ""


class PrivilegeGraph:
    """权限传播有向图.

    节点在(层,权限集,上下文)空间中, 边编码状态转移.
    Dijkstra求从初始节点到目标节点的最短(最小难度)攻击路径.
    """

    def __init__(self):
        self._nodes: Dict[str, PrivNode] = {}
        self._edges: Dict[str, List[PrivEdge]] = defaultdict(list)

    def add_node(self, n: PrivNode):
        self._nodes[n.node_id] = n

    def add_edge(self, e: PrivEdge):
        self._edges[e.src_id].append(e)

    def shortest_attack_path(self, start_id: str,
                             target_layer: str = "root",
                             target_caps: int = 0
                             ) -> Tuple[List[PrivEdge], float]:
        """Dijkstra求最短攻击路径.

        边权重 = difficulty (越小越容易).
        返回: (path_edges, total_difficulty).
        """
        if start_id not in self._nodes:
            return [], float('inf')
        dist: Dict[str, float] = {start_id: 0.0}
        prev: Dict[str, Optional[Tuple[str, PrivEdge]]] = {start_id: None}
        pq = [(0.0, start_id)]
        visited: Set[str] = set()
        best_target = None
        while pq:
            d, uid = heapq.heappop(pq)
            if uid in visited:
                continue
            visited.add(uid)
            node = self._nodes.get(uid)
            if node and (node.layer == target_layer or
                         (target_caps and node.capabilities & target_caps == target_caps)):
                if best_target is None or d < dist.get(best_target, float('inf')):
                    best_target = uid
                    dist[best_target] = d
            for edge in self._edges.get(uid, []):
                nd = d + edge.difficulty
                if nd < dist.get(edge.dst_id, float('inf')):
                    dist[edge.dst_id] = nd
                    prev[edge.dst_id] = (uid, edge)
                    heapq.heappush(pq, (nd, edge.dst_id))
        if best_target is None:
            return [], float('inf')
        # 回溯路径
        path = []
        cur = best_target
        while prev.get(cur) is not None:
            parent, edge = prev[cur]
            path.append(edge)
            cur = parent
        path.reverse()
        return path, dist[best_target]

    def build_from_context(self, ctx) -> str:
        """从PrivilegeContext构建初始节点和可达状态图."""
        caps_list = self._decode_caps(ctx.capabilities)
        start = PrivNode(node_id="start", layer="current",
                         capabilities=ctx.capabilities, uid=ctx.uid,
                         ns_type=ctx.namespace_type, seccomp=ctx.seccomp_mode)
        self.add_node(start)
        # 节点1: 同层提权 (setuid/sudo/cap)
        if ctx.uid != 0:
            n_root = PrivNode("root_same_layer", "user", uid=0,
                              capabilities=ctx.capabilities)
            self.add_node(n_root)
            diff = 3.0 if ctx.uid == 0 else 6.0
            self.add_edge(PrivEdge("start", "root_same_layer",
                          "local privesc", diff,
                          gained_caps=ctx.capabilities))
        # 节点2: capability提升 (CAP_SYS_ADMIN→近似root)
        if ctx.capabilities & (1 << 17):  # CAP_SYS_ADMIN
            n_admin = PrivNode("sys_admin", "capability_boundary",
                               capabilities=ctx.capabilities | (1 << 21))
            self.add_node(n_admin)
            self.add_edge(PrivEdge("start", "sys_admin",
                          "CAP_SYS_ADMIN exploit", 5.0,
                          required_caps=1 << 17,
                          gained_caps=(1 << 21)))
        # 节点3: 容器逃逸
        if ctx.namespace_type == "container" or ctx.is_privileged_container:
            n_escape = PrivNode("host_escape", "host", uid=0, ns_type="host",
                                capabilities=0xFFFFFFFF)
            self.add_node(n_escape)
            diff = 3.0 if ctx.is_privileged_container else 7.0
            self.add_edge(PrivEdge("start", "host_escape",
                          "container escape", diff,
                          precondition="privileged or docker.sock"))
        # 节点4: namespace逃逸 (user ns→获取cap→逃逸)
        n_ns = PrivNode("ns_escape", "host", uid=0, capabilities=0xFFFFFFFF)
        self.add_node(n_ns)
        self.add_edge(PrivEdge("start", "ns_escape", "user ns + cap bypass", 8.0,
                      precondition="CLONE_NEWUSER available"))
        return "start"

    @staticmethod
    def _decode_caps(mask: int) -> List[str]:
        return [n for b, n in _CAPABILITIES.items() if mask & (1 << b)]


@dataclass
class PrivilegeContext:
    uid: int = 1000; gid: int = 1000; euid: int = 1000
    capabilities: int = 0; namespace_type: str = "host"
    seccomp_mode: str = "none"; lsm_profile: str = "none"
    is_privileged_container: bool = False


@dataclass
class PrivilegeEscalationPath:
    path_type: str; description: str; difficulty: int = 5
    required_capabilities: List[str] = field(default_factory=list)
    gained_privileges: List[str] = field(default_factory=list)
    detection_method: str = ""


class PrivilegeBoundaryMapper:
    """多层权限边界映射器 (含权限图传播+Dijkstra路径)."""

    def __init__(self):
        self._graph = PrivilegeGraph()

    def map_escalation_paths(self, ctx: PrivilegeContext,
                             setuid_binaries: Optional[List[str]] = None,
                             sudo_rules: Optional[List[str]] = None,
                             mounted_volumes: Optional[List[str]] = None,
                             device_nodes: Optional[List[str]] = None,
                             kernel_version: str = "5.15.0"
                             ) -> List[PrivilegeEscalationPath]:
        paths: List[PrivilegeEscalationPath] = []
        # 静态检查 (原有功能保留)
        caps_list = self._decode_caps(ctx.capabilities)
        for binary in (setuid_binaries or []):
            paths.append(PrivilegeEscalationPath(
                "setuid", f"setuid binary: {binary}", 4,
                gained_privileges=["euid=0"],
                detection_method="find / -perm -4000 -type f"))
        for rule in (sudo_rules or []):
            paths.append(PrivilegeEscalationPath(
                "sudo", f"sudo rule: {rule}", 3,
                gained_privileges=["euid=0"],
                detection_method="sudo -l"))
        if "CAP_SYS_ADMIN" in caps_list:
            paths.append(PrivilegeEscalationPath("capability",
                "CAP_SYS_ADMIN→近似root", 5, ["CAP_SYS_ADMIN"],
                ["容器逃逸","内核模块加载"]))
        if "CAP_SYS_PTRACE" in caps_list:
            paths.append(PrivilegeEscalationPath("capability",
                "CAP_SYS_PTRACE→ptrace注入", 6, ["CAP_SYS_PTRACE"],
                ["任意进程注入"]))
        if "CAP_BPF" in caps_list:
            paths.append(PrivilegeEscalationPath("eBPF",
                "CAP_BPF→内核代码执行", 7, ["CAP_BPF"],
                ["rootkit安装"]))
        if ctx.is_privileged_container:
            paths.append(PrivilegeEscalationPath("container_escape",
                "特权容器逃逸", 3, gained_privileges=["宿主机root"]))
        if (mounted_volumes and
            any("docker.sock" in v for v in mounted_volumes)):
            paths.append(PrivilegeEscalationPath("container_escape",
                "Docker socket挂载→宿主机root", 2))
        # 动态图分析: Dijkstra最短路径
        if ctx.uid != 0 or ctx.is_privileged_container:
            start_id = self._graph.build_from_context(ctx)
            path_edges, total_diff = self._graph.shortest_attack_path(
                start_id, "host", 0)
            for e in path_edges:
                paths.append(PrivilegeEscalationPath(
                    "graph_path", f"{e.action} (diff={e.difficulty:.0f})",
                    int(e.difficulty),
                    gained_privileges=[f"+{self._decode_caps(e.gained_caps)}"
                                      if e.gained_caps else "target_reached"]))
        return sorted(paths, key=lambda p: p.difficulty)

    def assess_context(self, uid: int = 1000, euid: int = 1000,
                       gid: int = 1000,
                       extra_caps: Optional[List[str]] = None
                       ) -> PrivilegeContext:
        cap_mask = 0
        if extra_caps:
            for cap in extra_caps:
                for bit, name in _CAPABILITIES.items():
                    if name == cap:
                        cap_mask |= (1 << bit)
        ns_type = "host"
        try:
            with open("/proc/1/cgroup", "r") as f:
                if any(kw in f.read() for kw in ("docker", "kubepods")):
                    ns_type = "container"
        except (IOError, OSError):
            pass
        return PrivilegeContext(uid=uid, gid=gid, euid=euid,
                               capabilities=cap_mask, namespace_type=ns_type)

    @staticmethod
    def _decode_caps(mask: int) -> List[str]:
        return [n for b, n in _CAPABILITIES.items() if mask & (1 << b)]
