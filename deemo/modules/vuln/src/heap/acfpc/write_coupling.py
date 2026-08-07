"""写-分配参数耦合判定 — 同源共变安全关系的可判定化.

  - 误报主根因之一: p=malloc(len); memcpy(p, q, len) 型代码. 写入
    量与分配量同源 (同一变量), 二者共变, 除非算术缺陷否则不可能
    越界. 启发式过滤器对此无能为力, 需要定义链身份比较.
  - 同源判定: 写 size 参数与分配 size 参数的定义链根身份一致
    (同一栈槽/同一内存位置/同一函数参数寄存器). 常量相等不构成
    耦合, 常量必须走数值精确比较.
  - DERIVED 节点一律不耦合: 任何算术变换都可能破坏共变关系,
    耦合成立仅限直通 (mov/lea) 传播, 保证判定可证伪.
  - 保守性: 判定为 COUPLED 时才压制; INDEPENDENT/UNKNOWN 均保留
    原 finding, 召回不受损.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional

from .def_chain import DefChainTracker, DefKind, DefNode
from .alloc_contract import AllocContract

WRITE_FUNCS = {
    'memcpy': {'win64': 'r8', 'sysv': 'rdx'},
    'memset': {'win64': 'r8', 'sysv': 'rdx'},
    'strncpy': {'win64': 'r8', 'sysv': 'rdx'},
    'strcpy': {'win64': 'rdx', 'sysv': 'rsi'},
    'sprintf': {'win64': 'rdx', 'sysv': 'rsi'},
}


class Coupling(Enum):
    COUPLED = auto()        # 同源共变 → 不可能越界 (可压制)
    INDEPENDENT = auto()    # 独立来源 (含双常量) → 需数值判定
    UNKNOWN = auto()        # 无法判定 → 保留


@dataclass
class CouplingVerdict:
    verdict: Coupling
    reason: str = ''
    alloc_root: Optional[DefNode] = None
    write_root: Optional[DefNode] = None


def coupling_verdict(alloc_identity: str, write_identity: str,
                     alloc_root: DefNode, write_root: DefNode) -> CouplingVerdict:
    """判定分配 size 与写 size 是否同源 (身份键比较).

    身份键来自 DefChainTracker.identity: SLOT/MEM/ARG 是锚点.
    DERIVED 与 IMM 均无身份, 前者表示共变断裂, 后者走数值比较."""
    if alloc_identity and alloc_identity == write_identity:
        return CouplingVerdict(
            Coupling.COUPLED,
            f'同源 {alloc_identity}: 分配与写入共享同一数据源, 共变无越界',
            alloc_root, write_root)

    if alloc_root.kind == DefKind.IMM and write_root.kind == DefKind.IMM:
        return CouplingVerdict(
            Coupling.INDEPENDENT,
            f'双常量 {alloc_root.imm:#x} vs {write_root.imm:#x}: 走数值比较',
            alloc_root, write_root)

    if write_root.kind == DefKind.DERIVED or alloc_root.kind == DefKind.DERIVED:
        return CouplingVerdict(
            Coupling.INDEPENDENT,
            '存在算术变换: 共变关系断裂, 按独立处理',
            alloc_root, write_root)

    return CouplingVerdict(
        Coupling.UNKNOWN,
        f'来源不可判定 ({alloc_root.describe()} vs {write_root.describe()})',
        alloc_root, write_root)


class WriteCouplingAnalyzer:
    """对全部写调用快照执行耦合判定."""

    def __init__(self, tracker: DefChainTracker, abi: str = 'win64'):
        self._tracker = tracker
        self._abi = abi

    def write_size_node(self, snap) -> Optional[DefNode]:
        """取写调用的 size/源参数节点."""
        reg_map = WRITE_FUNCS.get(snap.callee.lower())
        if not reg_map:
            return None
        reg = reg_map[self._abi]
        if reg not in snap.args:
            return None
        return snap.args[reg]

    def write_size_imm(self, snap) -> Optional[int]:
        """写调用 size 的解析后立即数值 (仅直通链)."""
        node = self.write_size_node(snap)
        if node is None:
            return None
        root = self._tracker.resolve(node)
        if root.kind == DefKind.IMM:
            return root.imm
        return None

    def judge(self, contract: AllocContract, snap) -> CouplingVerdict:
        """对一次写调用给出耦合判决."""
        wnode = self.write_size_node(snap)
        if wnode is None:
            return CouplingVerdict(Coupling.UNKNOWN, '写 size 参数不可定位')
        wroot = self._tracker.resolve(wnode)
        widentity = self._tracker.identity(wnode)
        return coupling_verdict(contract.size_identity, widentity,
                                contract.size_root, wroot)

    def judge_all(self, contract: AllocContract) -> List[tuple]:
        """对所有写调用批量判定, 返回 (snap, verdict) 列表."""
        out = []
        for snap in self._tracker.calls():
            if snap.callee.lower() not in WRITE_FUNCS:
                continue
            if snap.insn_idx < contract.insn_idx:
                continue
            out.append((snap, self.judge(contract, snap)))
        return out
