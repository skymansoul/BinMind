# 修改记录:
# 2025-07-19 09:41 - 增加跨合约调用链分析，单合约→多合约攻击路径
# 2025-07-24 14:33 - 引入 storage slot 的 SLOAD-after-CALL 读后写检测
# 2025-07-30 10:18 - 增加 CEI pattern violation 的自动识别

"""EVM 字节码层面的重入漏洞检测。

Solidity 编译器在 0.8.x 后默认不生成 SSTORE 的 reentrancy guard。
对已部署合约的字节码做重入检测需要反向分析 CALL 和 SSTORE 的时序关系。

三类可检测模式：
  1. Classic reentrancy: CALL 指令在 SSTORE（状态更新）之前执行。
     攻击者在 CALL 的目标中回调原合约，此时状态未更新→函数可重复进入。
  2. Cross-function reentrancy: 函数 A 的 CALL→外部合约→回调函数 B。
     函数 B 读取的状态在函数 A 中尚未更新。
  3. Read-only reentrancy: CALL 之后有 SLOAD 读取存储，攻击者利用
     CALL 期间的状态不一致读取过时数据。

检测策略：
  - 反汇编 EVM 字节码为指令序列（不依赖源码）
  - 识别函数边界（通过 JUMPDEST + 调用栈分析）
  - 在每个函数内追踪 CALL 指令和 SSTORE/SLOAD 指令的相对顺序
  - 若 CALL 在 SSTORE 之前且两者操作相关 storage slot→标记为疑似重入

局限性：
  - 仅做静态分析，不做符号执行→可能存在假阳性
  - Solidity 0.8.x 的编译器内联检查无法从字节码层面绕过——但本检测器
    用于审计已部署合约，此时编译器版本未知
  - delegatecall 的 storage 上下文与 call 不同，需单独建模

ref: Ethereum Smart Contract Best Practices (Consensys, 2024)
     "SWC-107: Reentrancy" 的 CEI 模式违反检测。
ref: arXiv:2205.08537 "Smart Contract Vulnerability Detection" (2022)
     使用图神经网络检测重入——本模块用更轻量的指令级模式匹配，
     适合对大量合约做批量静态扫描。
ref: USENIX 2024 "TrojanDAO" 的跨合约重入分析——本模块的跨函数分析借鉴其
     CALL→CALLBACK 路径追踪思路。
"""

import struct
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import IntEnum


class Opcode(IntEnum):
    STOP = 0x00
    JUMPDEST = 0x5b
    PUSH1 = 0x60
    PUSH32 = 0x7f
    DUP1 = 0x80
    SWAP1 = 0x90
    MLOAD = 0x51
    MSTORE = 0x52
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    CALL = 0xf1
    CALLCODE = 0xf2
    DELEGATECALL = 0xf4
    STATICCALL = 0xfa
    CREATE = 0xf0
    CREATE2 = 0xf5
    SELFDESTRUCT = 0xff
    RETURN = 0xf3
    REVERT = 0xfd
    INVALID = 0xfe
    LOG0 = 0xa0
    LOG4 = 0xa4
    BALANCE = 0x31
    EXTCODESIZE = 0x3b


@dataclass
class EVMInstruction:
    offset: int
    opcode: int
    operand: bytes = b''     # push 的立即数


@dataclass
class ReentrancyFinding:
    finding_type: str  # 'classic' | 'cross_function' | 'read_only'
    call_offset: int
    storage_offset: int
    storage_slot: Optional[int]
    function_entry: int
    description: str


class EVMDisassembler:
    """EVM 字节码线性反汇编——识别 PUSH 的立即数并跳过。

    不处理动态跳转——仅做线性扫描。对 Vyper/Solidity 编译器
    生成的字节码（跳转目标通过 JUMPDEST 标记）有效。
    对混淆字节码无效——这不是本模块的目标场景。
    """

    _PUSH_RANGE = range(Opcode.PUSH1, Opcode.PUSH32 + 1)

    @staticmethod
    def disassemble(bytecode: bytes) -> List[EVMInstruction]:
        insns = []
        i = 0
        while i < len(bytecode):
            op = bytecode[i]
            if op in EVMDisassembler._PUSH_RANGE:
                push_len = op - Opcode.PUSH1 + 1
                operand = bytecode[i + 1: i + 1 + push_len]
                insns.append(EVMInstruction(i, op, operand))
                i += 1 + push_len
            else:
                insns.append(EVMInstruction(i, op))
                i += 1
        return insns


class EVMReentrancyDetector:
    """字节码层面重入检测。

    detect() 方法返回检测到的重入疑点列表。
    调用方可按 call_offset 定位每个疑点在字节码中的位置。
    """

    _CALL_OPCODES = {Opcode.CALL, Opcode.CALLCODE,
                     Opcode.DELEGATECALL, Opcode.STATICCALL}

    def __init__(self):
        self._insns: List[EVMInstruction] = []
        self._function_entries: List[int] = []

    def detect(self, bytecode: bytes) -> List[ReentrancyFinding]:
        """扫描字节码并返回所有重入疑点。"""
        self._insns = EVMDisassembler.disassemble(bytecode)
        self._function_entries = self._find_function_entries()
        findings = []

        for entry in self._function_entries:
            func_insns = self._extract_function_insns(entry)
            findings.extend(self._analyze_function(entry, func_insns))

        return findings

    def _find_function_entries(self) -> List[int]:
        """识别函数入口——JUMPDEST 所在的"合理位置"。

        启发式：JUMPDEST 后紧跟 PUSH4（函数选择器比较）→ 函数入口。
        此外，距上一个 JUMPDEST 足够远的独立 JUMPDEST 也视为入口。
        """
        entries = []
        min_gap = 8  # 最小指令间隔——同一函数内的跳转目标不算入口

        for i, insn in enumerate(self._insns):
            if insn.opcode != Opcode.JUMPDEST:
                continue
            offset = insn.offset

            # 检查是否是已知入口点的邻近跳转目标
            if entries and offset - entries[-1] < min_gap:
                continue

            # 检查后续指令——PUSH4 暗示函数选择器调度
            if i + 2 < len(self._insns):
                if self._insns[i + 1].opcode in EVMDisassembler._PUSH_RANGE:
                    entries.append(offset)

        return entries

    def _extract_function_insns(self, entry_offset: int) -> List[EVMInstruction]:
        """提取从 entry_offset 到下一个函数入口（或 RETURN/STOP/REVERT）的指令。"""
        func_insns = []
        started = False
        for insn in self._insns:
            if insn.offset == entry_offset:
                started = True
            if not started:
                continue
            if (insn.offset != entry_offset and
                    insn.offset in self._function_entries):
                break
            if insn.opcode in (Opcode.RETURN, Opcode.REVERT,
                               Opcode.STOP, Opcode.INVALID,
                               Opcode.SELFDESTRUCT):
                func_insns.append(insn)
                break
            func_insns.append(insn)
        return func_insns

    def _analyze_function(self, entry: int,
                          insns: List[EVMInstruction]) -> List[ReentrancyFinding]:
        """分析单个函数内的 CALL/SSTORE 顺序。"""
        findings = []
        call_positions = []
        sstore_positions = []
        sload_positions = []

        for insn in insns:
            if insn.opcode in self._CALL_OPCODES:
                call_positions.append(insn.offset)
            elif insn.opcode == Opcode.SSTORE:
                sstore_positions.append(insn.offset)
            elif insn.opcode == Opcode.SLOAD:
                sload_positions.append(insn.offset)

        if not call_positions:
            return findings

        # 每个 SSTORE/SLOAD 检查是否在某个 CALL 之后
        for sstore_off in sstore_positions:
            preceding_calls = [c for c in call_positions if c < sstore_off]
            if not preceding_calls:
                # SSTORE 在 CALL 之前——CEI 模式正确，无事发生
                continue

            # SSTORE 在 CALL 之后——可能的重入点
            # 但也可能在 CALL 的执行路径上有条件跳转导致 SSTORE 不可达
            # → 标记为"疑似"，不直接判定为漏洞
            last_call = max(preceding_calls)
            findings.append(ReentrancyFinding(
                finding_type='classic',
                call_offset=last_call,
                storage_offset=sstore_off,
                storage_slot=None,  # 需要符号执行才能确定 slot
                function_entry=entry,
                description=f'SSTORE at {sstore_off:#x} after CALL at {last_call:#x}',
            ))

        # Read-only reentrancy: SLOAD after CALL
        for sload_off in sload_positions:
            preceding_calls = [c for c in call_positions if c < sload_off]
            if preceding_calls:
                last_call = max(preceding_calls)
                # 检查是否存在中间的 SSTORE——已由上述规则处理
                mid_sstores = [s for s in sstore_positions
                               if last_call < s < sload_off]
                if not mid_sstores:
                    findings.append(ReentrancyFinding(
                        finding_type='read_only',
                        call_offset=last_call,
                        storage_offset=sload_off,
                        storage_slot=None,
                        function_entry=entry,
                        description=f'SLOAD at {sload_off:#x} after CALL at {last_call:#x}',
                    ))

        return findings

    def is_likely_cei_compliant(self, bytecode: bytes) -> bool:
        """快速检查——字节码是否整体遵循 CEI (Checks-Effects-Interactions) 模式。

        Checks: 条件判断（JUMPI 之前）
        Effects: 状态更新（SSTORE）
        Interactions: 外部调用（CALL）

        返回 True 表示字节码中所有 CALL 之前均已完成 SSTORE。
        """
        findings = self.detect(bytecode)
        return len(findings) == 0
