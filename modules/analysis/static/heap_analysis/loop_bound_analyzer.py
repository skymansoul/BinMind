"""循环界分析 - 识别有界计数循环, 判定循环内堆写入是否越界.

误报根源: absint_adjudicator.handle_memory_write 对未知偏移的堆写入
(循环写 p[i]) 一律报告. 本模块识别 back-edge 计数循环, 支持两类
计数器: 寄存器计数器 (cmp reg, imm / inc reg) 与栈槽计数器
(add QWORD PTR [rbp-0x10], 1 - MinGW -O0 默认代码生成形态).
循环次数上界 + 元素宽度 → 写入字节上界, 上界 ≤ 可用大小 → 安全过滤.

设计决策:
  - 只识别"计数器 vs 立即数"的比较循环 — 数据依赖循环不可界定
  - 栈槽计数器的界不可得 (bound 在内存) → trips=None, 由判定器
    保守处理, 绝不凭"有循环"就过滤
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction

_JCC_BACK = {
    "jb", "jbe", "jl", "jle", "jnae", "jnbe", "jng", "jna",
    "jne", "jnz", "jge", "jg", "ja", "jae",
}


@dataclass
class LoopInfo:
    """一个计数循环的信息."""
    start_addr: int                 # back-edge 目标 (循环体首)
    end_addr: int                   # back-edge 指令地址
    counter_reg: Optional[str]      # 寄存器计数器 (无则 None)
    counter_slot: Optional[Tuple[str, int]]  # 栈槽计数器 (base, offset)
    bound_imm: Optional[int]        # cmp counter, imm (独占上界)
    bound_inclusive: bool = False   # jle/jbe 等含等号比较
    step: int = 1
    init: Optional[int] = None
    trips: Optional[int] = None     # 循环次数上界


class LoopBoundAnalyzer:
    """循环界分析器 - 一次分析, 多次查询."""

    def __init__(self, insns: List[ParsedInstruction],
                 addr_to_idx: Dict[int, int]):
        self._insns = insns
        self._addr_to_idx = addr_to_idx
        self._loops: List[LoopInfo] = []

    # 分析入口

    def analyze(self) -> List[LoopInfo]:
        """扫描全部 back-edge, 提取计数循环."""
        self._loops = []
        for i, ins in enumerate(self._insns):
            mn = ins.mnemonic.lower()
            if mn not in _JCC_BACK:
                continue
            target = self._jmp_target(ins)
            if target is None or target >= ins.address:
                continue
            info = self._extract_loop(i, target, mn)
            if info:
                self._loops.append(info)
        return self._loops

    # 查询

    def containing_loop(self, insn_addr: int) -> Optional[LoopInfo]:
        """返回包含指令地址的最内层循环."""
        best = None
        for info in self._loops:
            if info.start_addr <= insn_addr <= info.end_addr:
                if best is None or info.end_addr - info.start_addr < \
                        best.end_addr - best.start_addr:
                    best = info
        return best

    def loop_chain(self, insn_addr: int) -> List[LoopInfo]:
        """包含指令地址的全部循环, 按跨度从小到大 (内层在前)."""
        chain = [l for l in self._loops
                 if l.start_addr <= insn_addr <= l.end_addr]
        chain.sort(key=lambda l: l.end_addr - l.start_addr)
        return chain

    def write_bytes_bound(self, insn_addr: int,
                          index_reg: Optional[str]) -> Optional[int]:
        """显式索引写入的字节上界: trips * 元素宽度."""
        info = self.containing_loop(insn_addr)
        if info is None or info.trips is None or index_reg is None:
            return None
        if InstructionParser.normalize_reg(index_reg) != info.counter_reg:
            return None
        return info.trips

    # 内部

    def _jmp_target(self, ins: ParsedInstruction) -> Optional[int]:
        if not ins.operands:
            return None
        op = ins.operands[0].strip()
        addr_part = op.split()[0] if op else ""
        # objdump 跳转目标一律为十六进制地址
        try:
            return int(addr_part, 16)
        except ValueError:
            return None

    def _extract_loop(self, back_idx: int, target: int,
                      jcc_mn: str) -> Optional[LoopInfo]:
        """提取 back-edge 处的计数器/上界/步长/初值."""
        counter_reg, counter_slot, bound_imm = \
            self._find_counter(back_idx)
        if counter_reg is None and counter_slot is None:
            return None
        inclusive = jcc_mn in ("jle", "jbe", "jge", "jae", "jz", "je")
        step = self._find_step(back_idx, target, counter_reg, counter_slot)
        if step <= 0:
            return None
        init = self._find_init(back_idx, target, counter_reg, counter_slot)
        trips = None
        if bound_imm is not None and init is not None:
            upper = bound_imm + (1 if inclusive else 0)
            if upper > init:
                trips = (upper - init + step - 1) // step
        # TODO: 数据依赖上界 (bound 为运行时值) 暂不推导, trips=None 保守报告
        return LoopInfo(start_addr=target,
                        end_addr=self._insns[back_idx].address,
                        counter_reg=counter_reg,
                        counter_slot=counter_slot,
                        bound_imm=bound_imm,
                        bound_inclusive=inclusive, step=step,
                        init=init, trips=trips)

    def _find_counter(self, back_idx: int
                      ) -> Tuple[Optional[str], Optional[Tuple[str, int]],
                                 Optional[int]]:
        """检测计数器: 栈槽增量 + cmp 上界 两遍联合判定."""
        slot: Optional[Tuple[str, int]] = None
        for j in range(back_idx - 1, -1, -1):
            if j < max(0, back_idx - 12):
                break
            ins = self._insns[j]
            if ins.mnemonic in ("add", "inc") and ins.operands:
                if "[" in ins.operands[0]:
                    base, _, _, off = \
                        InstructionParser.parse_memory_operand_full(
                            ins.operands[0])
                    if base in ("rbp", "rsp"):
                        step = 1 if ins.mnemonic == "inc" else \
                            (InstructionParser._try_parse_int(
                                ins.operands[1]) or 1)
                        if step > 0:
                            # 取最靠近 back-edge 的增量 — 内层循环
                            # 的增量在后扫描时不得覆盖外层槽
                            slot = (base, off)
                            break
        for j in range(back_idx - 1, -1, -1):
            if j < max(0, back_idx - 8):
                break
            ins = self._insns[j]
            if ins.mnemonic != "cmp" or len(ins.operands) < 2:
                continue
            reg = InstructionParser.normalize_reg(ins.operands[0])
            if reg:
                imm = InstructionParser._try_parse_int(ins.operands[1])
                if imm is not None:
                    return reg, None, imm
            base, _, _, off = \
                InstructionParser.parse_memory_operand_full(ins.operands[0])
            if base in ("rbp", "rsp"):
                imm = InstructionParser._try_parse_int(ins.operands[1])
                if imm is not None:
                    if slot is None or (base, off) == slot:
                        return None, (base, off), imm
        if slot is not None:
            return None, slot, None
        return None, None, None

    def _find_step(self, back_idx: int, target: int,
                   counter_reg: Optional[str],
                   counter_slot: Optional[Tuple[str, int]]) -> int:
        """在循环体内找计数器增量."""
        for j in range(back_idx - 1, -1, -1):
            if j < max(0, back_idx - 12):
                break
            ins = self._insns[j]
            if ins.address < target:
                break
            if counter_reg and ins.mnemonic == "inc" and ins.operands:
                if InstructionParser.normalize_reg(
                        ins.operands[0]) == counter_reg:
                    return 1
            if counter_reg and ins.mnemonic == "add" \
                    and len(ins.operands) >= 2:
                if InstructionParser.normalize_reg(
                        ins.operands[0]) == counter_reg:
                    imm = InstructionParser._try_parse_int(ins.operands[1])
                    if imm is not None and imm > 0:
                        return imm
            if counter_slot and ins.mnemonic == "add" \
                    and len(ins.operands) >= 2:
                base, _, _, off = \
                    InstructionParser.parse_memory_operand_full(
                        ins.operands[0])
                if (base, off) == counter_slot:
                    imm = InstructionParser._try_parse_int(ins.operands[1])
                    if imm is not None and imm > 0:
                        return imm
        return 0

    def _find_init(self, back_idx: int, target: int,
                   counter_reg: Optional[str],
                   counter_slot: Optional[Tuple[str, int]]
                   ) -> Optional[int]:
        """在循环入口前找初值定义 (窗口: 入口前30条)."""
        for j in range(back_idx - 1, -1, -1):
            if j < max(0, back_idx - 30):
                break
            ins = self._insns[j]
            if ins.address >= target:
                continue  # 循环体内不算初值定义
            if counter_reg and ins.mnemonic in ("xor", "mov") \
                    and len(ins.operands) >= 2:
                if ins.mnemonic == "xor" and \
                        ins.operands[0].strip() == ins.operands[1].strip():
                    if InstructionParser.normalize_reg(
                            ins.operands[0]) == counter_reg:
                        return 0
                if ins.mnemonic == "mov" and \
                        InstructionParser.normalize_reg(
                            ins.operands[0]) == counter_reg:
                    imm = InstructionParser._try_parse_int(ins.operands[1])
                    if imm == 0:
                        return 0
            if counter_slot and ins.mnemonic == "mov" \
                    and len(ins.operands) >= 2:
                base, _, _, off = \
                    InstructionParser.parse_memory_operand_full(
                        ins.operands[0])
                if (base, off) == counter_slot:
                    imm = InstructionParser._try_parse_int(ins.operands[1])
                    if imm == 0:
                        return 0
        return None


# smoke test
def _check():
    asm = """
    1200:       31 db                   xor    ebx,ebx
    1202:       48 8d 04 98             lea    rax,[rax+rbx*4]
    1206:       c7 00 2a 00 00 00       mov    DWORD PTR [rax],0x2a
    120c:       ff c3                   inc    ebx
    120e:       83 fb 64                cmp    ebx,0x64
    1211:       72 ef                   jb     1202
    1213:       48 c7 45 f0 00 00 00    mov    QWORD PTR [rbp-0x10],0x0
    121a:       00
    121b:       eb 10                   jmp    122d
    121d:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
    1221:       48 8d 14 85 00 00 00    lea    rdx,[rax*4+0x0]
    1228:       00
    1229:       89 10                   mov    DWORD PTR [rax],edx
    122b:       48 83 45 f0 01          add    QWORD PTR [rbp-0x10],0x1
    1230:       48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
    1234:       48 3b 45 f8             cmp    rax,QWORD PTR [rbp-0x8]
    1238:       72 e3                   jb     121d
    """
    insns = InstructionParser.parse(asm)
    addr_to_idx = {i.address: k for k, i in enumerate(insns)}
    la = LoopBoundAnalyzer(insns, addr_to_idx)
    loops = la.analyze()
    reg_loop = [l for l in loops if l.counter_reg == "rbx"]
    mem_loop = [l for l in loops if l.counter_slot is not None]
    assert reg_loop and reg_loop[0].trips == 100, \
        f"expected reg trips=100, got {reg_loop}"
    assert mem_loop and mem_loop[0].counter_slot == ("rbp", -0x10), \
        f"expected mem counter slot, got {mem_loop}"
    assert mem_loop[0].trips is None, \
        "mem counter with mem bound must be unbounded"
    wb = la.write_bytes_bound(0x1206, "rbx")
    assert wb == 100, f"expected write bound 100, got {wb}"
    print(f"[OK] loop_bound_analyzer: reg trips={reg_loop[0].trips}, "
          f"mem slot={mem_loop[0].counter_slot}")


if __name__ == "__main__":
    _check()
