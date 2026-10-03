# 轻量级污点追踪引擎——漏洞分析数据流溯源，不依赖重量级符号执行

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, deque


class TaintSource(Enum):
    """污点源类型枚举"""
    USER_INPUT = auto()
    NETWORK = auto()
    FILE_READ = auto()
    ENVIRONMENT = auto()
    ARGUMENT = auto()
    MEMORY_ALLOC = auto()
    UNKNOWN = auto()


class TaintSink(Enum):
    """危险汇点类型枚举"""
    MEMCPY = auto()
    STRCPY = auto()
    SPRINTF = auto()
    SYSTEM = auto()
    EXEC = auto()
    MEMORY_WRITE = auto()
    NETWORK_SEND = auto()
    FORMAT_STRING = auto()


@dataclass
class TaintNode:
    """污点传播图节点"""
    addr: int
    source: Optional[TaintSource] = None
    sink: Optional[TaintSink] = None
    label: str = ""
    tainted: bool = False


@dataclass
class TaintPath:
    """源到汇完整污点传播路径"""
    source_addr: int
    sink_addr: int
    path: List[int]
    confidence: float = 1.0


class TaintTracker:
    """轻量级污点追踪——跟踪数据从源到危险汇的流动。

    方法:
        mark_source(addr, source_type) -- 标记污点源
        mark_sink(addr, sink_type) -- 标记危险汇点
        add_data_flow(src_addr, dst_addr) -- 添加数据流边
        find_paths() -- 查找全部污点路径
        is_sink_tainted(addr) -- 检查汇点是否被污染
    """

    def __init__(self):
        self.nodes: Dict[int, TaintNode] = {}
        self.edges: Dict[int, List[int]] = defaultdict(list)
        self._reverse_edges: Dict[int, List[int]] = defaultdict(list)
        self._tainted: Set[int] = set()

    def mark_source(self, addr: int, source_type: TaintSource,
                    label: str = "") -> TaintNode:
        node = TaintNode(addr=addr, source=source_type, label=label, tainted=True)
        self.nodes[addr] = node
        self._tainted.add(addr)
        return node

    def mark_sink(self, addr: int, sink_type: TaintSink,
                  label: str = "") -> TaintNode:
        node = TaintNode(addr=addr, sink=sink_type, label=label)
        self.nodes[addr] = node
        return node

    def add_data_flow(self, src_addr: int, dst_addr: int) -> None:
        """添加src→dst数据流边——污点自动沿边传播"""
        self.edges[src_addr].append(dst_addr)
        self._reverse_edges[dst_addr].append(src_addr)
        # 前向污点传播
        if src_addr in self._tainted:
            self._propagate_taint(src_addr)

    def _propagate_taint(self, start: int) -> None:
        """BFS前向传播污点标记"""
        q = deque([start])
        while q:
            cur = q.popleft()
            for nxt in self.edges.get(cur, []):
                if nxt not in self._tainted:
                    self._tainted.add(nxt)
                    if nxt in self.nodes:
                        self.nodes[nxt].tainted = True
                    q.append(nxt)

    def find_paths(self, max_depth: int = 20) -> List[TaintPath]:
        """查找所有污点源到危险汇的路径"""
        results = []
        for src_addr in self._tainted:
            src_node = self.nodes.get(src_addr)
            if src_node is None or src_node.source is None:
                continue
            # BFS到所有汇点
            visited = {src_addr: [src_addr]}
            q = deque([src_addr])
            while q:
                cur = q.popleft()
                path = visited[cur]
                if len(path) > max_depth:
                    continue
                for nxt in self.edges.get(cur, []):
                    if nxt not in visited:
                        new_path = path + [nxt]
                        visited[nxt] = new_path
                        q.append(nxt)
                        nxt_node = self.nodes.get(nxt)
                        if nxt_node and nxt_node.sink is not None:
                            results.append(TaintPath(
                                source_addr=src_addr, sink_addr=nxt,
                                path=new_path, confidence=1.0 / len(new_path)))
        results.sort(key=lambda p: p.confidence, reverse=True)
        return results

    def is_sink_tainted(self, addr: int) -> bool:
        return addr in self._tainted and addr in self.nodes and self.nodes[addr].sink is not None

    def get_tainted_sinks(self) -> List[TaintNode]:
        return [n for n in self.nodes.values() if n.sink and n.addr in self._tainted]

    def get_all_sources(self) -> List[TaintNode]:
        return [n for n in self.nodes.values() if n.source]

    def stats(self) -> Dict:
        return {
            "nodes": len(self.nodes),
            "edges": sum(len(v) for v in self.edges.values()),
            "sources": sum(1 for n in self.nodes.values() if n.source),
            "sinks": sum(1 for n in self.nodes.values() if n.sink),
            "tainted_sinks": len(self.get_tainted_sinks()),
        }

    def reset(self) -> None:
        self.nodes.clear()
        self.edges.clear()
        self._reverse_edges.clear()
        self._tainted.clear()


# disasm辅助——从objdump行推断数据流

_DEF_MNEMONICS = {"mov", "lea", "add", "sub", "xor", "and", "or",
                  "shl", "shr", "pop", "call", "xchg"}
_USE_MNEMONICS = {"mov", "cmp", "test", "add", "sub", "xor", "push",
                  "call", "jmp", "je", "jne", "ret", "xchg"}
_TAINT_CALLS = {"read", "fread", "recv", "scanf", "gets", "fgets",
                "recvfrom", "recvmsg", "getenv", "argv"}
_SINK_CALLS = {"strcpy", "strncpy", "memcpy", "sprintf", "snprintf",
               "system", "execve", "execl", "execvp", "popen",
               "printf", "fprintf"}


def extract_data_flow_from_disasm(disasm_text: str) -> TaintTracker:
    """从objdump反汇编文本提取数据流至轻量级TaintTracker。

    启发式逻辑:
    - 调用read/recv等函数标记为USER_INPUT源
    - 调用strcpy/system等标记为对应汇点
    - call指令后的mov/lea在16字节内视为数据传播

    非精确寄存器污点分析，为快速可达性估算。
    """
    import re
    tracker = TaintTracker()
    addr_re = re.compile(r'^\s*([0-9a-fA-F]+):')
    call_re = re.compile(r'call\s+.*<?(\w+)')

    lines = []
    for ln in disasm_text.split("\n"):
        m = addr_re.match(ln)
        if m:
            lines.append((int(m.group(1), 16), ln.strip()))

    # 第一遍——标记源与汇
    last_call = 0
    last_call_target = ""
    for addr, text in lines:
        cm = call_re.search(text.lower())
        if cm:
            last_call = addr
            last_call_target = cm.group(1).lower()
            for taint_call in _TAINT_CALLS:
                if taint_call in last_call_target:
                    tracker.mark_source(addr, TaintSource.USER_INPUT,
                                        label=last_call_target)
            for sink_call in _SINK_CALLS:
                if sink_call in last_call_target:
                    if sink_call in ("strcpy", "strncpy", "memcpy"):
                        tracker.mark_sink(addr, TaintSink.STRCPY, label=sink_call)
                    elif sink_call in ("sprintf", "snprintf", "printf", "fprintf"):
                        tracker.mark_sink(addr, TaintSink.FORMAT_STRING, label=sink_call)
                    elif sink_call in ("system", "execve", "execl", "execvp", "popen"):
                        tracker.mark_sink(addr, TaintSink.SYSTEM, label=sink_call)

    # 第二遍——连接相邻def-use对
    for i, (addr_a, _) in enumerate(lines):
        for j in range(i + 1, min(i + 8, len(lines))):
            addr_b = lines[j][0]
            if abs(addr_a - addr_b) <= 0x20:
                tracker.add_data_flow(addr_a, addr_b)
                break

    return tracker
