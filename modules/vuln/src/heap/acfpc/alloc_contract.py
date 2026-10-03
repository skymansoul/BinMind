"""分配契约提取 — malloc/calloc/realloc 的 size 参数来源分类.

  - 契约 = (分配函数, size 参数的定义链根). 分类目的是区分
    "size 受控于输入" 与 "size 为编译期常量", 前者可参与写-分配
    耦合判定 (同源时写入随分配缩放, 不可能越界).
  - 分类规则 (保守):
      IMM     → 编译期常量, 契约确定
      SLOT    → 局部变量 (可能来自输入), 契约不确定但可耦合
      REG     → 直接来自寄存器直通, 视为与源同源
      MEM     → 全局/间接读取, 视为外部输入
      ARG     → 函数参数, 视为外部输入
      DERIVED → 算术变换产物, 视为独立来源
  - calloc 的 size 为乘积 nmemb*size, 两个参数均记录.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .def_chain import DefChainTracker, DefKind, DefNode, CallSnapshot

ALLOC_FUNCS = ('malloc', 'calloc', 'realloc')
WIN64_PARAM_REGS = ('rcx', 'rdx', 'r8', 'r9')
SYSV_PARAM_REGS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')


def _kind_from_identity(identity: str) -> str:
    """身份键 → 类型: 身份锚点决定来源类别, 优先于解析值."""
    if identity.startswith('slot:'):
        return DefKind.SLOT
    if identity == 'mem':
        return DefKind.MEM
    if identity.startswith('arg:'):
        return DefKind.ARG
    return ''


def _result_identity(instructions: List[str], call_idx: int,
                     tracker: Optional[DefChainTracker] = None,
                     window: int = 4) -> str:
    """解析 malloc 返回值落点: 紧跟 call 的 'mov slot/reg, rax'.

    寄存器落点经定义链解析: 若 rax 为 call 返回值 (RETURN), 落点
    身份即 'ret:函数名', 与后续写目标寄存器身份可对齐."""
    import re as _re
    from .def_chain import slot_name, DefKind
    pat = _re.compile(
        r'mov\s+(?:QWORD\s+PTR\s+)?\[([^\]\s]+)\]'
        r'|mov\s+(rax|rbx|rcx|rdx|r8|r9|rsi|rdi)',
        _re.IGNORECASE)
    for i in range(call_idx + 1, min(len(instructions), call_idx + 1 + window)):
        line = instructions[i]
        if 'rax' not in line and 'eax' not in line:
            continue
        m = pat.search(line)
        if m:
            if m.group(1):
                sl = slot_name(f'[{m.group(1)}]')
                if sl:
                    return f'slot:{sl}'
                return ''
            reg = m.group(2)
            if tracker is not None:
                node = tracker.def_of_reg(reg)
                if node.kind == DefKind.RETURN and node.ret_name:
                    return f'ret:{node.ret_name}'
            return f'arg:{reg}'
    return ''


@dataclass
class AllocContract:
    """一次堆分配的契约."""
    insn_idx: int
    func: str
    size_root: DefNode              # size 参数的定义链根
    size_kind: str = DefKind.UNKNOWN
    size_imm: int = 0               # IMM 时的值
    size_identity: str = ''         # 同源判定的身份键
    result_identity: str = ''       # 返回值落点身份 (写目标配对用)
    nmemb_root: Optional[DefNode] = None  # calloc 第一参数
    same_abi_win64: bool = True     # 参数寄存器命名假设

    def usable_base(self) -> int:
        if self.size_kind == DefKind.IMM:
            return self.size_imm
        return 0

    def describe(self) -> str:
        return (f'{self.func} size={self.size_root.describe()}'
                f' (imm={self.size_imm:#x})')


def _param_regs_for(func: str, tracker: DefChainTracker,
                    abi: str) -> Dict[str, DefNode]:
    regs = WIN64_PARAM_REGS if abi == 'win64' else SYSV_PARAM_REGS
    args: Dict[str, DefNode] = {}
    for i, reg in enumerate(regs):
        if i >= 2 and func == 'malloc':
            break
        if i >= 3 and func == 'calloc':
            break
        args[reg] = tracker.def_of_reg(reg)
    return args


def _root_slot_ref(node: DefNode) -> DefNode:
    """REG 节点先解析到根, 再标注 ARG/外部来源."""
    if node.kind == DefKind.REG:
        return DefNode(DefKind.ARG, reg=node.reg, insn_idx=node.insn_idx)
    return node


class AllocContractExtractor:
    """从调用快照中提取分配契约."""

    def __init__(self, tracker: DefChainTracker, abi: str = 'win64'):
        self._tracker = tracker
        self._abi = abi

    def extract(self, instructions: Optional[List[str]] = None) -> List[AllocContract]:
        contracts: List[AllocContract] = []
        for snap in self._tracker.calls_named(ALLOC_FUNCS):
            func = snap.callee.lower()
            args = snap.args
            if not args:
                continue
            size_node = self._pick_size_node(func, args)
            if size_node is None:
                continue
            root = self._tracker.resolve(size_node)
            identity = self._tracker.identity(size_node)
            kind = _kind_from_identity(identity) or root.kind
            contracts.append(AllocContract(
                insn_idx=snap.insn_idx, func=func,
                size_root=root,
                size_kind=kind,
                size_imm=root.imm if root.kind == DefKind.IMM else 0,
                size_identity=identity,
                result_identity=_result_identity(
                    instructions or [], snap.insn_idx, self._tracker),
                nmemb_root=self._nmemb(args) if func == 'calloc' else None,
                same_abi_win64=(self._abi == 'win64'),
            ))
        return contracts

    def _pick_size_node(self, func: str, args: Dict[str, DefNode]) -> Optional[DefNode]:
        if func in ('malloc', 'realloc'):
            for reg in ('rcx', 'rdi'):
                if reg in args:
                    return args[reg]
            return None
        if func == 'calloc':
            for reg in ('rdx', 'rsi'):
                if reg in args:
                    return args[reg]
            return None
        return None

    def _nmemb(self, args: Dict[str, DefNode]) -> Optional[DefNode]:
        for reg in ('rcx', 'rdi'):
            if reg in args:
                return args[reg]
        return None


def contract_at(contracts: List[AllocContract], insn_idx: int,
                tolerance: int = 4) -> Optional[AllocContract]:
    """在指令位置附近 (含容忍窗口) 查找最近的分配契约."""
    best, best_d = None, None
    for c in contracts:
        d = c.insn_idx - insn_idx
        if d <= 0 and -d <= tolerance:
            if best_d is None or -d < best_d:
                best, best_d = c, -d
    return best
