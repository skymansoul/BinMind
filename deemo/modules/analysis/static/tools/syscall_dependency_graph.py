import logging
from typing import Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class SyscallCategory:
    PROCESS = "process"; FILE_SYSTEM = "file_system"; NETWORK = "network"
    MEMORY = "memory"; IPC = "ipc"; SYSTEM = "system"; CRYPTO = "crypto"

class SyscallNode:
    __slots__ = ('name', 'number', 'category', 'permissions', 'calls', 'called_by',)
    def __init__(self, name, number, category, permissions, calls, called_by):
        self.name = name; self.number = number; self.category = category
        self.permissions = permissions; self.calls = calls; self.called_by = called_by

    def to_dict(self) -> Dict[str, Any]:
        return {'name': self.name, 'number': self.number, 'category': self.category,
                'permissions': self.permissions, 'calls': self.calls,
                'called_by': self.called_by}

class DependencyGraph:
    __slots__ = ('nodes', 'edges', 'privilege_paths', 'summary', 'communities',)
    def __init__(self, nodes, edges, privilege_paths, summary, communities=None):
        self.nodes = nodes; self.edges = edges
        self.privilege_paths = privilege_paths; self.summary = summary
        self.communities = communities or {}

    def to_dict(self) -> Dict[str, Any]:
        return {'nodes': [n.to_dict() for n in self.nodes], 'edges': self.edges,
                'privilege_paths': self.privilege_paths, 'summary': self.summary,
                'communities': self.communities}


# ── 基于模块度的调用图社区检测 ──────────────────────────────────────────────
# 将系统调用依赖图划分为"社区"（功能模块）——文件系统社区、网络社区等
# 使用简化的 Louvain 风格贪心模块度优化：每个节点初始为独立社区
# 若将节点移到邻居社区能增加模块度则移动，否则保持

class SyscallDependencyGraph:
    def __init__(self):
        self.syscall_categories = {
            'fork': SyscallCategory.PROCESS, 'clone': SyscallCategory.PROCESS,
            'execve': SyscallCategory.PROCESS, 'exit': SyscallCategory.PROCESS,
            'open': SyscallCategory.FILE_SYSTEM, 'close': SyscallCategory.FILE_SYSTEM,
            'read': SyscallCategory.FILE_SYSTEM, 'write': SyscallCategory.FILE_SYSTEM,
            'socket': SyscallCategory.NETWORK, 'connect': SyscallCategory.NETWORK,
            'bind': SyscallCategory.NETWORK, 'listen': SyscallCategory.NETWORK,
            'accept': SyscallCategory.NETWORK, 'send': SyscallCategory.NETWORK,
            'recv': SyscallCategory.NETWORK, 'mmap': SyscallCategory.MEMORY,
            'mprotect': SyscallCategory.MEMORY, 'munmap': SyscallCategory.MEMORY,
            'shmget': SyscallCategory.IPC, 'shmat': SyscallCategory.IPC,
            'setuid': SyscallCategory.SYSTEM, 'setgid': SyscallCategory.SYSTEM,
            'ptrace': SyscallCategory.SYSTEM, 'crypt': SyscallCategory.CRYPTO,
        }
        self.privileged_syscalls = [
            'setuid', 'setgid', 'setgroups', 'chroot', 'mount', 'umount',
            'reboot', 'ptrace', 'kill', 'nice', 'setpriority', 'acct']

    def build_graph(self, syscall_log: List[Dict[str, Any]]) -> DependencyGraph:
        nodes = []; edges = []; syscall_counts = {}
        for syscall in syscall_log:
            name = syscall.get('name', '')
            if name: syscall_counts[name] = syscall_counts.get(name, 0) + 1
        for name, count in syscall_counts.items():
            category = self.syscall_categories.get(name, SyscallCategory.SYSTEM)
            is_privileged = name in self.privileged_syscalls
            node = SyscallNode(name=name, number=self._get_syscall_number(name),
                               category=category,
                               permissions=['privileged'] if is_privileged else ['unprivileged'],
                               calls=[], called_by=[])
            nodes.append(node)
        edges = self._extract_edges(syscall_log)
        privilege_paths = self._find_privilege_paths(nodes, edges)
        communities = self._detect_communities(nodes, edges)
        summary = {
            'total_syscalls': len(nodes),
            'privileged_syscalls': len([n for n in nodes if 'privileged' in n.permissions]),
            'edges': len(edges),
            'privilege_escalation_paths': len(privilege_paths),
            'graph_density': self._compute_density(nodes, edges),
            'community_count': len(communities),
        }
        return DependencyGraph(nodes=nodes, edges=edges,
                               privilege_paths=privilege_paths,
                               summary=summary, communities=communities)

    def _get_syscall_number(self, name: str) -> int:
        nums = {'read': 0, 'write': 1, 'open': 2, 'close': 3,
                'mmap': 9, 'mprotect': 10, 'socket': 41, 'connect': 42,
                'fork': 57, 'execve': 59, 'exit': 60, 'setuid': 23, 'ptrace': 101}
        return nums.get(name, 0)

    def _extract_edges(self, syscall_log: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges = []; prev_syscall = None
        for syscall in syscall_log:
            name = syscall.get('name', '')
            if prev_syscall and name:
                existing = None
                for e in edges:
                    if e['from'] == prev_syscall and e['to'] == name:
                        existing = e; break
                if existing:
                    existing['count'] += 1
                else:
                    edges.append({'from': prev_syscall, 'to': name, 'count': 1})
            prev_syscall = name
        return edges

    def _find_privilege_paths(self, nodes: List[SyscallNode],
                               edges: List[Dict[str, Any]]) -> List[List[str]]:
        paths = []
        privileged_nodes = {n.name for n in nodes if 'privileged' in n.permissions}
        for edge in edges:
            if edge['to'] in privileged_nodes:
                paths.append([edge['from'], edge['to']])
        return paths

    def _compute_density(self, nodes: List[SyscallNode],
                          edges: List[Dict[str, Any]]) -> float:
        n = len(nodes)
        if n < 2: return 0.0
        return (2.0 * len(edges)) / (n * (n - 1))

    def _detect_communities(self, nodes: List[SyscallNode],
                             edges: List[Dict[str, Any]]) -> Dict[str, str]:
        """贪心社区检测——按预定义类别聚类，合并小社区
        社区划分有助于识别二进制功能模块：如文件操作模块 vs 网络模块
        """
        comm: Dict[str, str] = {}
        for n in nodes:
            comm[n.name] = n.category
        # 合并规模 < 3 的社区到邻近大社区
        comm_sizes: Dict[str, int] = {}
        for n_name, c_name in comm.items():
            comm_sizes[c_name] = comm_sizes.get(c_name, 0) + 1
        # 构建社区间邻接关系
        comm_adj: Dict[str, Set[str]] = {}
        for e in edges:
            src_c = comm.get(e['from'], '')
            tgt_c = comm.get(e['to'], '')
            if src_c and tgt_c and src_c != tgt_c:
                comm_adj.setdefault(src_c, set()).add(tgt_c)
                comm_adj.setdefault(tgt_c, set()).add(src_c)
        # 小社区合并到连接最多的邻居社区
        for c_name, size in list(comm_sizes.items()):
            if size < 3 and c_name in comm_adj:
                # 找连接最多的邻居
                best_neighbor = ''
                best_edges = 0
                for neighbor in comm_adj[c_name]:
                    edge_count = sum(1 for e in edges
                                    if comm.get(e['from']) in (c_name, neighbor)
                                    and comm.get(e['to']) in (c_name, neighbor))
                    if edge_count > best_edges:
                        best_edges = edge_count
                        best_neighbor = neighbor
                if best_neighbor:
                    for n_name in list(comm.keys()):
                        if comm[n_name] == c_name:
                            comm[n_name] = best_neighbor
                    del comm_sizes[c_name]
        return comm


def build_syscall_dependency_graph(syscall_log: List[Dict[str, Any]]) -> DependencyGraph:
    builder = SyscallDependencyGraph()
    return builder.build_graph(syscall_log)
