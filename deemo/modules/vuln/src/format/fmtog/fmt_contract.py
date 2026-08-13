"""printf 族调用点提取 — 格式串溯源与实参数收集.

复用 heap.acfpc.def_chain 的定义链: 调用点快照给出参数寄存器来源,
lea 解析给出 .rodata 常量串身份. 本模块输出:
  - 每个 printf 族调用的 fmt 参数定义链根 (IMM 常量 / lea 常量 /
    SLOT / RETURN(输入 API) / ARG / UNKNOWN)
  - 实参数数量: 参数寄存器快照 + 后续栈槽写入计数
  - 常量格式串内容: 从 objdump -s 的 .rdata 字符串表按地址查
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ...heap.acfpc.def_chain import DefChainTracker, DefKind, DefNode

PRINTF_FAMILY = ('printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf',
                 'vsprintf', 'vsnprintf', 'vfwprintf', 'fwprintf',
                 'swprintf', 'vswprintf', '__mingw_printf', '__mingw_fprintf',
                 '__mingw_sprintf', '__mingw_snprintf', '__mingw_vfprintf',
                 '__mingw_vprintf')
INPUT_SOURCES = ('gets', 'scanf', 'fscanf', 'sscanf', 'recv', 'read',
                 'fgets', 'getchar', 'getc', 'getline')

# fmt 参数寄存器: 带 FILE* 首参的函数族 fmt 在 rdx, 其余在 rcx
_FMT_RDX_FAMILY = ('fprintf', 'vfprintf', 'fwprintf', 'vfwprintf',
                   'swprintf', 'vswprintf', 'vsprintf', 'vsnprintf',
                   '__mingw_fprintf', '__mingw_vfprintf', '__mingw_vsprintf',
                   '__mingw_vsnprintf')


def fmt_reg_for(func: str) -> str:
    return 'rdx' if func in _FMT_RDX_FAMILY else 'rcx'


@dataclass
class FmtCall:
    insn_idx: int
    addr: int
    func: str
    fmt_node: Optional[DefNode] = None
    fmt_kind: str = ''
    fmt_const: str = ''          # 常量格式串内容 (若可解析)
    fmt_identity: str = ''       # 身份键 (SLOT/RETURN/ARG/...)
    return_src: str = ''         # resolve 根的输入源 (RETURN 链)
    args_available: int = 0      # 可确认的实参数
    reason: str = ''


def _lea_const_addr(instructions: List[str], at: int) -> str:
    """调用点前 lea [rip+disp] 的注释绝对地址 (常量格式串).

    目标寄存器不限 (fmt 可经 rax→rdx 传递); 仅匹配带绝对地址
    注释的 lea 行, 栈槽 lea 无注释自然跳过."""
    import re
    for i in range(max(0, at - 8), at):
        line = instructions[i]
        if 'lea' not in line or 'rip' not in line:
            continue
        m = re.search(r'#\s+(?:0x)?([0-9a-fA-F]{6,16})\b', line)
        if m:
            return m.group(1).lower()
    return ''


def _lea_slot_identity(derived_op: str) -> str:
    """lea [rbp±N] 派生 → 槽身份 (buf 经 lea 传递的场景)."""
    import re
    from ...heap.acfpc.def_node import slot_name
    m = re.search(r'lea\s*\[(rbp[-+]0x[0-9a-fA-F]+)\]', derived_op, re.I)
    if m:
        sl = slot_name(f'[{m.group(1)}]')
        if sl:
            return f'slot:{sl}'
    return ''


class FmtCallExtractor:
    """从指令流提取 printf 族调用与 fmt 参数定义链."""

    def __init__(self, tracker: DefChainTracker,
                 rdata_strings: Optional[Dict[int, str]] = None):
        self._tracker = tracker
        self._rdata = rdata_strings or {}

    def extract(self, instructions: List[str],
                addrs: Optional[List[int]] = None) -> List[FmtCall]:
        calls = []
        for snap in self._tracker.calls():
            if snap.callee not in PRINTF_FAMILY:
                continue
            fmt_reg = fmt_reg_for(snap.callee)
            fmt_node = snap.args.get(fmt_reg)
            root = self._tracker.resolve(fmt_node) if fmt_node else None
            ident = self._tracker.identity(fmt_node) if fmt_node else ''
            if not ident and fmt_node is not None and \
                    fmt_node.kind == DefKind.DERIVED:
                ident = _lea_slot_identity(fmt_node.derived_op)
            const = ''
            # 常量格式串仅当 fmt 派生自 lea [rip+disp] (rdata 引用);
            # 其他 lea (栈槽) 的注释地址不适用
            if fmt_node is not None and fmt_node.kind == DefKind.DERIVED \
                    and '[rip' in fmt_node.derived_op.lower():
                const_addr = _lea_const_addr(instructions, snap.insn_idx)
                if const_addr:
                    const = self._rdata.get(int(const_addr, 16), '')
            if not const and root is not None and \
                    root.kind == DefKind.IMM and root.imm:
                const = self._rdata.get(root.imm, '')
            return_src = ''
            if root is not None and root.kind == DefKind.RETURN:
                return_src = root.ret_name
            calls.append(FmtCall(
                insn_idx=snap.insn_idx,
                addr=addrs[snap.insn_idx] if addrs else 0,
                func=snap.callee,
                fmt_node=fmt_node,
                fmt_kind=root.kind if root else '',
                fmt_const=const,
                fmt_identity=ident,
                return_src=return_src,
                args_available=self._count_args(snap.args, snap.insn_idx,
                                        instructions),
            ))
        return calls

    def _count_args(self, args: Dict[str, DefNode],
                    call_idx: int = -1,
                    instructions: Optional[List[str]] = None) -> int:
        """可确认实参: 寄存器参数 (邻近定义) + 栈参数.

        跨函数残留定义 (CRT 段的 r8/r9 旧值) 不计数; 第 5+ 参数
        落在栈上 (mov [rsp+0x20+8k], reg), 按调用点前写入计数."""
        n = 0
        for reg in ('rdx', 'r8', 'r9', 'xmm1', 'xmm2', 'xmm3'):
            node = args.get(reg)
            if node is None or node.kind == DefKind.UNKNOWN:
                continue
            if call_idx >= 0 and 0 <= node.insn_idx < call_idx - 8:
                continue
            n += 1
        if instructions and call_idx >= 0:
            import re as _re
            for i in range(max(0, call_idx - 12), call_idx):
                line = instructions[i]
                if _re.search(r'mov\s+QWORD PTR \[rsp\+0x(?:20|28|30|38|40|48|50|58|60|68)\]',
                              line, _re.I):
                    n += 1
        return n
