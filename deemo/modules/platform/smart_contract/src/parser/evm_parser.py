# EVM bytecode parser — hex → instruction sequence → basic blocks → function selectors
# 不拆: 核心解析器 320 行，拆了 circular import 风险高

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple

from ..core.opcodes import OPCODES, PUSH_OPCODES


@dataclass
class EVMOp:
    """解码后的 EVM 操作 — pc, opcode, name, push_data。"""
    pc: int
    opcode: int
    name: str
    push_data: bytes = b''
    gas: int = 0

    @property
    def is_push(self) -> bool:
        return self.opcode in PUSH_OPCODES

    @property
    def is_jumpdest(self) -> bool:
        return self.opcode == 0x5b


class EVMBytecodeParser:
    """EVM 字节码解析器 — decode → basic blocks → CFG → selectors。"""

    # 终止指令: 执行停止或无条件转移
    _TERMINATORS = frozenset({
        'STOP', 'RETURN', 'REVERT', 'SELFDESTRUCT', 'INVALID', 'JUMP'
    })
    _COND_JUMPS = frozenset({'JUMPI'})

    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.ops: List[EVMOp] = []
        self.basic_blocks: Dict[int, List[EVMOp]] = {}
        self.block_edges: Dict[int, List[int]] = {}
        self.jumpdest_positions: Set[int] = set()
        self._parsed = False
        self._cfg_built = False

    # ---- Parsing ----

    def parse_hex(self, hex_str: str) -> List[EVMOp]:
        """解析hex字符串（带或不带0x前缀）为指令序列。"""
        if hex_str.startswith('0x') or hex_str.startswith('0X'):
            hex_str = hex_str[2:]
        raw = bytes.fromhex(hex_str)
        self.bytecode = raw
        return self._parse()

    def _parse(self) -> List[EVMOp]:
        """解码原始字节为EVM指令列表。"""
        if self._parsed:
            return self.ops
        pc = 0
        blen = len(self.bytecode)
        while pc < blen:
            opcode = self.bytecode[pc]
            if opcode in OPCODES:
                name, stack_in, stack_out, _family, gas = OPCODES[opcode]
            else:
                name, stack_in, stack_out, gas = "INVALID", 0, 0, 0

            push_data = b''
            if opcode in PUSH_OPCODES:
                push_len = opcode - 0x5f
                end = min(pc + 1 + push_len, blen)
                push_data = self.bytecode[pc + 1:end]
                pc = end
            else:
                pc += 1

            op = EVMOp(pc=pc, opcode=opcode, name=name, push_data=push_data, gas=gas)
            self.ops.append(op)
            if op.is_jumpdest:
                self.jumpdest_positions.add(op.pc)
        self._parsed = True
        return self.ops

    def parse(self) -> List[EVMOp]:
        """解析字节码; _parse的别名。"""
        if not self._parsed:
            return self._parse()
        return self.ops

    # ---- Basic blocks ----

    def build_basic_blocks(self) -> Dict[int, List[EVMOp]]:
        """按JUMPDEST边界将线性指令流切分为基本块。

        每块从JUMPDEST(或偏移0)开始，以分支/终止指令结束。
        """
        if self.basic_blocks:
            return self.basic_blocks
        if not self.ops:
            self._parse()

        blocks: Dict[int, List[EVMOp]] = {}
        current: List[EVMOp] = []
        start = 0

        for op in self.ops:
            if op.is_jumpdest and current:
                blocks[start] = current
                current = []
                start = op.pc
            current.append(op)
            if op.name in ('JUMP', 'JUMPI', 'RETURN', 'REVERT', 'STOP', 'INVALID', 'SELFDESTRUCT'):
                blocks[start] = current
                current = []
                start = op.pc + 1
        if current:
            blocks[start] = current

        self.basic_blocks = blocks
        return blocks

    def build_cfg_edges(self) -> Dict[int, List[EVMOp]]:
        """构建基本块间的后继边。

        确定fall-through边和静态跳转目标。
        使用position-to-block索引实现O(1)查找。
        """
        if self._cfg_built:
            return self.basic_blocks

        blocks = self.build_basic_blocks()
        if not blocks:
            return blocks

        # position -> block_start map
        pos_to_block: Dict[int, int] = {}
        for b_start, blk_ops in blocks.items():
            for instr in blk_ops:
                pos_to_block[instr.pc] = b_start

        block_starts = sorted(blocks.keys())

        for idx, b_start in enumerate(block_starts):
            blk_ops = blocks[b_start]
            last = blk_ops[-1] if blk_ops else None
            if last is None:
                continue
            successors: List[int] = []

            # Conditional jump: fall-through + static target
            if last.name in self._COND_JUMPS:
                if idx + 1 < len(block_starts):
                    successors.append(block_starts[idx + 1])
                target = self._resolve_jump_target(last, blk_ops)
                if target is not None and target in blocks:
                    successors.append(target)

            # Unconditional jump: static target only
            elif last.name == 'JUMP':
                target = self._resolve_jump_target(last, blk_ops)
                if target is not None and target in blocks:
                    successors.append(target)

            # Terminator: no successors
            elif last.name in self._TERMINATORS:
                pass

            # Fall-through to next block
            else:
                if idx + 1 < len(block_starts):
                    successors.append(block_starts[idx + 1])

            self.block_edges[b_start] = successors

        self._cfg_built = True
        return blocks

    def _resolve_jump_target(self, jump_op: EVMOp, block_ops: List[EVMOp]) -> Optional[int]:
        """尝试从前导PUSH静态解析JUMP/JUMPI的目标地址。

        标准Solidity模式: PUSH <target> ... JUMP/JUMPI。
        检查倒数第二条指令是否有PUSH且operand为已知jumpdest。
        """
        if len(block_ops) < 2:
            return None
        prev = block_ops[-2]
        if prev.is_push and prev.push_data:
            try:
                candidate = int.from_bytes(prev.push_data, 'big')
                if candidate in self.jumpdest_positions:
                    return candidate
            except (ValueError, OverflowError):
                return None
        return None

    def get_basic_blocks(self) -> List[Tuple[int, List[EVMOp]]]:
        """返回基本块为(start_pc, [ops])元组，兼容旧API。"""
        blocks = self.build_basic_blocks()
        return sorted(blocks.items())

    # ---- Function selectors ----

    def find_function_selectors(self) -> Dict[str, int]:
        """从Solidity dispatch模式提取4字节函数选择器。

        模式: PUSH4 <4-byte selector> EQ PUSH <target> JUMPI
        使用原始字节码正则匹配以提升速度。
        """
        selectors: Dict[str, int] = {}
        # Match: PUSH4 (0x63) + 4 bytes, followed by typical dispatch suffix
        pattern = re.compile(rb'\x63(.{4})\x14')  # PUSH4 + 4 bytes + EQ
        for match in pattern.finditer(self.bytecode):
            selector = match.group(1).hex()
            position = match.start()
            selectors[selector] = position
        return selectors

    def find_dispatch_offset(self) -> Optional[int]:
        """定位Solidity dispatch入口点。

        启发式规则: 首个PUSH4紧跟EQ，通常为函数选择器比较起点。
        """
        ops = self.ops if self.ops else self._parse()
        for i in range(len(ops) - 2):
            a = ops[i]
            b = ops[i + 1]
            c = ops[i + 2]
            if (a.name == 'PUSH4' and
                b.name == 'EQ' and
                c.name.startswith('PUSH')):
                return a.pc
        return None

    # ---- Utility methods ----

    def get_instructions(self) -> List[EVMOp]:
        """返回已解析的指令列表。"""
        if not self.ops:
            self._parse()
        return self.ops

    def has_instruction(self, mnemonic: str) -> bool:
        """检查字节码是否包含指定助记符。"""
        for op in self.ops:
            if op.name == mnemonic:
                return True
        return False

    def instruction_at(self, position: int) -> Optional[EVMOp]:
        """二分查找指定字节偏移处的指令，O(log n)。"""
        ops = self.get_instructions()
        lo, hi = 0, len(ops) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            p = ops[mid].pc
            if p == position:
                return ops[mid]
            elif p < position:
                lo = mid + 1
            else:
                hi = mid - 1
        return None

    def find_loop_headers(self) -> Set[int]:
        """通过回边检测识别循环头。

        回边a→b中b支配a，则b为循环头。
        """
        dom = self.compute_dominators()
        blocks = self.build_cfg_edges()
        headers: Set[int] = set()

        for b_start, blk_ops in blocks.items():
            for succ in self.block_edges.get(b_start, []):
                if b_start in dom.get(succ, set()):
                    headers.add(succ)
        return headers

    def compute_dominators(self) -> Dict[int, Set[int]]:
        """Cooper-Harvey-Kennedy迭代支配者算法。

        可归约流图上快速收敛，通常O(N)，最坏O(N²)。
        """
        blocks = self.build_cfg_edges()
        if not blocks:
            return {}

        block_starts = sorted(blocks.keys())
        entry = block_starts[0] if block_starts else None
        if entry is None:
            return {}

        all_set = set(block_starts)
        dom: Dict[int, Set[int]] = {b: all_set.copy() for b in block_starts}
        dom[entry] = {entry}

        changed = True
        while changed:
            changed = False
            for b in block_starts:
                if b == entry:
                    continue
                preds = [p for p, succs in self.block_edges.items() if b in succs]
                if not preds:
                    new_dom: Set[int] = set()
                else:
                    new_dom = dom[preds[0]].copy()
                    for p in preds[1:]:
                        new_dom &= dom[p]
                new_dom.add(b)
                if new_dom != dom[b]:
                    dom[b] = new_dom
                    changed = True
        return dom
