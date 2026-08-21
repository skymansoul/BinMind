import logging
from typing import Dict, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class SyscallCategory:
    PROCESS = "process"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    MEMORY = "memory"
    IPC = "ipc"
    SYSTEM = "system"
    CRYPTO = "crypto"
class SyscallNode:
    __slots__ = ('name', 'number', 'category', 'permissions', 'calls', 'called_by',)

    def __init__(self, name, number, category, permissions, calls, called_by):
        self.name = name
        self.number = number
        self.category = category
        self.permissions = permissions
        self.calls = calls
        self.called_by = called_by

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'number': self.number,
            'category': self.category.value,
            'permissions': self.permissions,
            'calls': self.calls,
            'called_by': self.called_by
        }

class DependencyGraph:
    __slots__ = ('nodes', 'edges', 'privilege_paths', 'summary',)

    def __init__(self, nodes, edges, privilege_paths, summary):
        self.nodes = nodes
        self.edges = edges
        self.privilege_paths = privilege_paths
        self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            'nodes': [n.to_dict() for n in self.nodes],
            'edges': self.edges,
            'privilege_paths': self.privilege_paths,
            'summary': self.summary
        }

class SyscallDependencyGraph:
    def __init__(self):
        self.syscall_categories = {
            'fork': SyscallCategory.PROCESS,
            'clone': SyscallCategory.PROCESS,
            'execve': SyscallCategory.PROCESS,
            'exit': SyscallCategory.PROCESS,
            'wait': SyscallCategory.PROCESS,
            'open': SyscallCategory.FILE_SYSTEM,
            'close': SyscallCategory.FILE_SYSTEM,
            'read': SyscallCategory.FILE_SYSTEM,
            'write': SyscallCategory.FILE_SYSTEM,
            'stat': SyscallCategory.FILE_SYSTEM,
            'chmod': SyscallCategory.FILE_SYSTEM,
            'chown': SyscallCategory.FILE_SYSTEM,
            'socket': SyscallCategory.NETWORK,
            'connect': SyscallCategory.NETWORK,
            'bind': SyscallCategory.NETWORK,
            'listen': SyscallCategory.NETWORK,
            'accept': SyscallCategory.NETWORK,
            'send': SyscallCategory.NETWORK,
            'recv': SyscallCategory.NETWORK,
            'mmap': SyscallCategory.MEMORY,
            'mprotect': SyscallCategory.MEMORY,
            'munmap': SyscallCategory.MEMORY,
            'shmget': SyscallCategory.IPC,
            'shmat': SyscallCategory.IPC,
            'semget': SyscallCategory.IPC,
            'msgget': SyscallCategory.IPC,
            'setuid': SyscallCategory.SYSTEM,
            'setgid': SyscallCategory.SYSTEM,
            'reboot': SyscallCategory.SYSTEM,
            'ptrace': SyscallCategory.SYSTEM,
            'crypt': SyscallCategory.CRYPTO
        }

        self.privileged_syscalls = [
            'setuid', 'setgid', 'setgroups', 'chroot', 'mount', 'umount',
            'reboot', 'ptrace', 'kill', 'nice', 'setpriority', 'acct'
        ]

    def build_graph(self, syscall_log: List[Dict[str, Any]]) -> DependencyGraph:
        nodes = []
        edges = []
        syscall_counts = {}

        for syscall in syscall_log:
            name = syscall.get('name', '')
            if name:
                syscall_counts[name] = syscall_counts.get(name, 0) + 1

        for name, count in syscall_counts.items():
            category = self.syscall_categories.get(name, SyscallCategory.SYSTEM)
            is_privileged = name in self.privileged_syscalls

            node = SyscallNode(
                name=name,
                number=self._get_syscall_number(name),
                category=category,
                permissions=['privileged'] if is_privileged else ['unprivileged'],
                calls=[],
                called_by=[]
            )
            nodes.append(node)

        edges = self._extract_edges(syscall_log)
        privilege_paths = self._find_privilege_paths(nodes, edges)

        summary = {
            'total_syscalls': len(nodes),
            'privileged_syscalls': len([n for n in nodes if 'privileged' in n.permissions]),
            'edges': len(edges),
            'privilege_escalation_paths': len(privilege_paths)
        }

        return DependencyGraph(
            nodes=nodes,
            edges=edges,
            privilege_paths=privilege_paths,
            summary=summary)

    def _get_syscall_number(self, name: str) -> int:
        syscall_numbers = {
            'read': 0, 'write': 1, 'open': 2, 'close': 3,
            'stat': 4, 'fstat': 5, 'lstat': 6, 'poll': 7,
            'lseek': 8, 'mmap': 9, 'mprotect': 10, 'munmap': 11,
            'ioctl': 16, 'pread64': 17, 'pwrite64': 18,
            'readv': 19, 'writev': 20, 'access': 21,
            'pipe': 22, 'select': 23, 'sched_yield': 24,
            'mremap': 25, 'msync': 26, 'mincore': 27,
            'madvise': 28, 'shmget': 29, 'shmat': 30,
            'shmctl': 31, 'dup': 32, 'dup2': 33,
            'pause': 34, 'nanosleep': 35, 'getitimer': 36,
            'alarm': 37, 'setitimer': 38, 'getpid': 39,
            'sendfile': 40, 'socket': 41, 'connect': 42,
            'accept': 43, 'sendto': 44, 'recvfrom': 45,
            'sendmsg': 46, 'recvmsg': 47, 'shutdown': 48,
            'bind': 49, 'listen': 50, 'getsockname': 51,
            'fork': 57, 'vfork': 58, 'execve': 59,
            'exit': 60, 'wait4': 61, 'kill': 62,
            'uname': 63, 'semget': 64, 'semop': 65,
            'semctl': 66, 'shmdt': 67, 'msgget': 68,
            'msgsnd': 69, 'msgrcv': 70, 'msgctl': 71,
            'fcntl': 72, 'flock': 73, 'fsync': 74,
            'setuid': 23, 'setgid': 24, 'setgroups': 115,
            'chroot': 161, 'mount': 165, 'umount2': 166,
            'reboot': 168, 'ptrace': 101
        }
        return syscall_numbers.get(name, 0)

    def _extract_edges(self, syscall_log: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges = []
        prev_syscall = None
        for syscall in syscall_log:
            name = syscall.get('name', '')
            if prev_syscall and name:
                edges.append({
                    'from': prev_syscall,
                    'to': name,
                    'count': 1
                })
            prev_syscall = name
        return edges

    def _find_privilege_paths(self, nodes: List[SyscallNode], edges: List[Dict[str, Any]]) -> List[List[str]]:
        paths = []
        privileged_nodes = {n.name for n in nodes if 'privileged' in n.permissions}
        for edge in edges:
            if edge['to'] in privileged_nodes:
                paths.append([edge['from'], edge['to']])
        return paths

def build_syscall_dependency_graph(syscall_log: List[Dict[str, Any]]) -> DependencyGraph:
    builder = SyscallDependencyGraph()
    return builder.build_graph(syscall_log)
