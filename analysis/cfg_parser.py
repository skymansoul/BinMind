"""
CFG解析器 — 伪代码/汇编 → 基本块 → CFG.

输入: 反编译的伪代码行列表 (addr, text) 或 objdump 输出.
输出: BasicBlock 列表 + CFG 边 (后继/前驱).

分支识别:
  - if/goto 语句 → 条件跳转 (true/false分支)
  - call + jmp → 函数调用 + 返回
  - ret → 终止块
  - jmp → 无条件跳转

CFG用于 path_sensitive_vrf 的DFS分支敏感传播.
"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class BasicBlock:
    """基本块: 连续指令序列, 端点为跳转或标签."""
    id: int
    start_addr: int
    end_addr: int
    insns: List[Tuple[int, str]] = field(default_factory=list)
    # CFG 边
    succ_true: Optional[int] = None    # 条件为真时的目标
    succ_false: Optional[int] = None   # 条件为假时的目标
    succ_direct: Optional[int] = None  # 无条件跳转目标
    preds: List[int] = field(default_factory=list)
    # 语义标记
    is_entry: bool = False
    is_exit: bool = False
    is_call: bool = False
    # 条件表达式 (if 条件)
    condition_text: str = ""

    @property
    def is_conditional(self) -> bool:
        return self.succ_true is not None or self.succ_false is not None

    def __repr__(self) -> str:
        return (f"BB#{self.id} [0x{self.start_addr:x}-0x{self.end_addr:x}]"
                f" insns={len(self.insns)} cond={self.is_conditional}")


@dataclass
class ControlFlowGraph:
    """函数级控制流图."""
    func_name: str = ""
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    entry_id: int = 0
    exit_ids: List[int] = field(default_factory=list)

    def get_block(self, addr: int) -> Optional[BasicBlock]:
        """通过地址查找包含 addr 的基本块."""
        for bb in self.blocks.values():
            if bb.start_addr <= addr <= bb.end_addr:
                return bb
        return None

    def successors(self, bb_id: int) -> List[int]:
        bb = self.blocks.get(bb_id)
        if not bb:
            return []
        succs = []
        if bb.succ_direct is not None:
            succs.append(bb.succ_direct)
        if bb.succ_true is not None:
            succs.append(bb.succ_true)
        if bb.succ_false is not None:
            succs.append(bb.succ_false)
        return succs


class CfgParser:
    """将伪代码指令列表解析为 CFG.

    输入格式: [(addr, text), ...]
      其中 text 为伪代码行, 如:
        "if (n < 256) {" → 条件分支开始
        "while (i < count) {" → 循环头
        "malloc(0x40)" → 函数调用
        "memcpy(dst, src, n)" → 函数调用
        "}" → 块结束

    算法: 单遍扫描, 识别控制流改变指令作为块边界.
    """

    # 条件分支模式
    _IF_PAT = re.compile(r'if\s*\((.+)\)\s*\{?')
    _WHILE_PAT = re.compile(r'while\s*\((.+)\)\s*\{?')
    _FOR_PAT = re.compile(r'for\s*\((.+)\)\s*\{?')
    # 跳转/返回
    _GOTO_PAT = re.compile(r'goto\s+(\w+)')
    _RET_PAT = re.compile(r'return\b')
    _LABEL_PAT = re.compile(r'^(\w+):\s*$')

    def __init__(self):
        self._next_bb_id = 0

    def parse(self, insns: List[Tuple[int, str]],
              func_name: str = "") -> ControlFlowGraph:
        """解析指令列表为 CFG."""
        self._next_bb_id = 0
        cfg = ControlFlowGraph(func_name=func_name)

        if not insns:
            return cfg

        # 第一步: 识别块边界地址
        leaders = self._find_leaders(insns)

        # 第二步: 构建基本块
        blocks, addr_to_bb = self._build_blocks(insns, leaders)

        # 第三步: 建立 CFG 边
        self._build_edges(blocks, addr_to_bb)

        cfg.blocks = blocks
        cfg.entry_id = 0
        cfg.exit_ids = [bb.id for bb in blocks.values() if bb.is_exit]
        return cfg

    def _find_leaders(self, insns: List[Tuple[int, str]]) -> Set[int]:
        """识别基本块入口地址."""
        leaders: Set[int] = set()
        leaders.add(insns[0][0])  # 第一条指令
        prev_was_branch = False

        for i, (addr, text) in enumerate(insns):
            tl = text.strip().lower()

            if tl == '}':
                # 块结束后的下一条指令是新块的开始
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1][0])

            if self._IF_PAT.match(tl) or self._WHILE_PAT.match(tl):
                # 条件分支: 条件体开始
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1][0])
                prev_was_branch = True

            if self._GOTO_PAT.match(tl):
                prev_was_branch = True
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1][0])

            if self._RET_PAT.match(tl):
                prev_was_branch = True
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1][0])

            if prev_was_branch:
                leaders.add(addr)
                prev_was_branch = False

        return leaders

    def _build_blocks(self, insns: List[Tuple[int, str]],
                      leaders: Set[int]) -> Tuple[Dict[int, BasicBlock],
                                                   Dict[int, int]]:
        """构建基本块, 返回 (blocks, addr_to_bb_id)."""
        blocks: Dict[int, BasicBlock] = {}
        addr_to_bb: Dict[int, int] = {}
        sorted_leaders = sorted(leaders)

        for i, leader_addr in enumerate(sorted_leaders):
            next_leader = (sorted_leaders[i + 1]
                           if i + 1 < len(sorted_leaders)
                           else insns[-1][0] + 1)

            bb_insns = [(a, t) for a, t in insns
                        if leader_addr <= a < next_leader]
            if not bb_insns:
                continue

            bb_id = self._next_bb_id
            self._next_bb_id += 1

            bb = BasicBlock(
                id=bb_id,
                start_addr=leader_addr,
                end_addr=bb_insns[-1][0],
                insns=bb_insns,
            )

            last_text = bb_insns[-1][1].strip().lower() if bb_insns else ""
            if self._IF_PAT.match(last_text):
                m = self._IF_PAT.match(last_text)
                bb.condition_text = m.group(1) if m else ""
            if self._RET_PAT.match(last_text):
                bb.is_exit = True

            blocks[bb_id] = bb
            for a, _ in bb_insns:
                addr_to_bb[a] = bb_id

        return blocks, addr_to_bb

    def _build_edges(self, blocks: Dict[int, BasicBlock],
                     addr_to_bb: Dict[int, int]):
        """建立块间边."""
        sorted_ids = sorted(blocks.keys())
        for i, bb_id in enumerate(sorted_ids):
            bb = blocks[bb_id]
            last_insn = (bb.insns[-1][1].strip().lower()
                         if bb.insns else "")

            # 条件分支 → true/false 边
            cond_match = (self._IF_PAT.match(last_insn) or
                          self._WHILE_PAT.match(last_insn))
            if cond_match:
                # 下一个块是 true 分支
                if i + 1 < len(sorted_ids):
                    bb.succ_true = sorted_ids[i + 1]
                    blocks[sorted_ids[i + 1]].preds.append(bb_id)

            # 无条件跳转
            goto_m = self._GOTO_PAT.match(last_insn)
            if goto_m:
                bb.succ_direct = None  # 跨块跳转暂不做符号解析

            # 直落边: 非无条件跳转时, 下一个块是后继
            if not self._RET_PAT.match(last_insn) and not goto_m:
                if i + 1 < len(sorted_ids) and bb.succ_true != sorted_ids[i + 1]:
                    next_bb = blocks[sorted_ids[i + 1]]
                    if bb_id not in next_bb.preds:
                        bb.succ_false = sorted_ids[i + 1]
                        next_bb.preds.append(bb_id)

            if i == 0:
                bb.is_entry = True
