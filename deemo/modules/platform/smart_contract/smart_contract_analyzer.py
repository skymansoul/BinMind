"""
smart_contract_analyzer — EVM / WASM 合约字节码安全分析。

此文件是向后兼容入口。类型与模型从 src/ 子模块导入，解析器/检测器/分析器
保留内联实现以确保 BaseAnalyzer 插件系统和 ContractVulnerability 数据模型的兼容性。

src/ 子模块（src.core.types, src.core.models, src.parser, src.detectors 等）
提供了更新的并行实现，使用 VulnerabilityReport / EVMOp 等改进的数据模型。
"""

import logging
import re
import hashlib
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum
from abc import ABC, abstractmethod

_CACHE_SALT = "sc_cache_v1_salt"  # 保留
_STALE_LIMIT = 7200  # 保留

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════
# 插件基础设施 — 兼容core.plugin_manager或本地回退
# ═══════════════════════════════════════════════════════════════

try:
    from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
except ImportError:
    # 本地 fallback — core.plugin_manager 不可用时提供自包含实现
    class AnalyzerType(Enum):
        STATIC_ANALYZER = "static_analyzer"
        DYNAMIC_ANALYZER = "dynamic_analyzer"
        VULNERABILITY_DETECTOR = "vulnerability_detector"
        FUZZER = "fuzzer"
        DECOMPILER = "decompiler"
        GENERIC = "generic"

    @dataclass
    class AnalyzerMetadata:
        name: str = ""
        type: AnalyzerType = AnalyzerType.GENERIC
        version: str = "0.1.0"
        description: str = ""
        author: str = ""
        dependencies: List[str] = field(default_factory=list)
        supported_platforms: List[str] = field(default_factory=list)

    class BaseAnalyzer(ABC):
        """Abstract base for platform analyzers."""
        def __init__(self, config: Optional[Dict[str, Any]] = None):
            self._config = config

        @abstractmethod
        def analyze(self, **kwargs) -> Dict[str, Any]:
            ...

        def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
            return True, None

        @classmethod
        def get_metadata(cls) -> 'AnalyzerMetadata':
            return AnalyzerMetadata()

# ═══════════════════════════════════════════════════════════════
# 从 src/ 子模块导入类型与模型（向后兼容的 str/int Enum）
# ═══════════════════════════════════════════════════════════════

from platform.smart_contract.src.core.types import (
    ContractType,
    VulnerabilityType,
    Severity,
)

from platform.smart_contract.src.core.models import (
    EVMInstruction,
    EVMBasicBlock,
)

# ═══════════════════════════════════════════════════════════════
# TaintSource — 内联保留，src/taint_tracker.py 有独立的 TaintSource 模型
# ═══════════════════════════════════════════════════════════════

class TaintSource(Enum):
    """栈值污染源标记 — 抽象解释时追踪数据来源。

    CALLDATA/CALL_RESULT 为外部可控源；
    SLOAD 为持久化存储读取，标记后可追踪重入路径；
    CONSTANT 为编译期已知值，通常安全。
    """
    CALLDATA = "calldata"
    CALL_RESULT = "call_result"
    SLOAD = "sload"
    CONSTANT = "constant"
    UNKNOWN = "unknown"
    BALANCE = "balance"
    TIMESTAMP = "timestamp"
    GAS = "gas"
    BLOCKHASH = "blockhash"
    DIFFICULTY = "difficulty"
    NUMBER = "number"


# ═══════════════════════════════════════════════════════════════
# Gas 计量常量 — EIP-2929 / EIP-3529 基准
# ═══════════════════════════════════════════════════════════════

# 冷/热存储访问的 gas 成本（EIP-2929 引入的差异化定价）
_COLD_SLOAD = 2100
_WARM_SLOAD = 100
_COLD_ACCOUNT_ACCESS = 2600
_WARM_ACCOUNT_ACCESS = 100
_SSTORE_RESET = 2900
_SSTORE_SET = 20000
_SELFDESTRUCT_BASE = 5000

# 冗余 SLOAD 检测窗口 — 同一 slot 在此窗口内被多次读取视为低效
_REDUNDANT_SLOAD_WINDOW = 128


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class StackSlot:
    """抽象栈槽 — 携带污染源标记与可选的字面值。

    用于轻量级数据流追踪：每条指令按语义传递/合并输入槽的 taint 标记，
    据此判断敏感操作（如 SSTORE 的 value 来源是否为 CALLDATA）。
    """
    value: Optional[int] = None
    taint: Set[TaintSource] = field(default_factory=lambda: {TaintSource.UNKNOWN})

    @classmethod
    def concrete(cls, val: int) -> 'StackSlot':
        return cls(value=val, taint={TaintSource.CONSTANT})

    @classmethod
    def tainted(cls, src: TaintSource) -> 'StackSlot':
        return cls(value=None, taint={src})

    def merge_taint(self, *others: 'StackSlot') -> 'StackSlot':
        """合并多个栈槽的污染标记 — 取并集，值取第一个非 None 的。"""
        merged = self.taint.copy()
        val = self.value
        for o in others:
            merged |= o.taint
            if val is None:
                val = o.value
        return StackSlot(value=val, taint=merged)


@dataclass
class ContractVulnerability:
    """检测到的单项漏洞"""
    vuln_type: str
    severity: str
    confidence: float
    description: str
    location: int
    opcode: str
    function_name: Optional[str] = None
    impact: str = ""
    recommendation: str = ""
    exploit_path: list = field(default_factory=list)
    # 附加上下文 — 用于报告消费方做更细粒度的过滤
    evidence_snippets: List[str] = field(default_factory=list)


@dataclass
class ContractFunction:
    """从字节码中解析的合约函数"""
    name: str
    selector: str  # 四字节函数选择器
    entry_point: int
    basic_blocks: List[EVMBasicBlock] = field(default_factory=list)
    vulnerabilities: List[ContractVulnerability] = field(default_factory=list)
    is_payable: bool = False
    state_mutability: str = "nonpayable"


@dataclass
class ContractAnalysisReport:
    """一次分析产出的完整报告"""
    contract_type: str
    bytecode_hash: str
    functions: List[ContractFunction]
    vulnerabilities: List[ContractVulnerability]
    total_vulnerabilities: int = 0
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
    analysis_time: float = 0.0
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# EVM 字节码解析器
# ═══════════════════════════════════════════════════════════════

class EVMBytecodeParser:
    """EVM 字节码解析器

    职责：hex 字节码 → 指令序列 → 基本块 → CFG 边。不涉及漏洞判定逻辑。
    """

    # 完整 EVM opcode 表 — (mnemonic, stack_pops, stack_pushes)
    OPCODES = {
        0x00: ('STOP', 0, 0),
        0x01: ('ADD', 2, 1),
        0x02: ('MUL', 2, 1),
        0x03: ('SUB', 2, 1),
        0x04: ('DIV', 2, 1),
        0x05: ('SDIV', 2, 1),
        0x06: ('MOD', 2, 1),
        0x07: ('SMOD', 2, 1),
        0x08: ('ADDMOD', 3, 1),
        0x09: ('MULMOD', 3, 1),
        0x0a: ('EXP', 2, 1),
        0x0b: ('SIGNEXTEND', 2, 1),
        0x10: ('LT', 2, 1),
        0x11: ('GT', 2, 1),
        0x12: ('SLT', 2, 1),
        0x13: ('SGT', 2, 1),
        0x14: ('EQ', 2, 1),
        0x15: ('ISZERO', 1, 1),
        0x16: ('AND', 2, 1),
        0x17: ('OR', 2, 1),
        0x18: ('XOR', 2, 1),
        0x19: ('NOT', 1, 1),
        0x1a: ('BYTE', 2, 1),
        0x1b: ('SHL', 2, 1),
        0x1c: ('SHR', 2, 1),
        0x1d: ('SAR', 2, 1),
        0x20: ('SHA3', 2, 1),
        0x30: ('ADDRESS', 0, 1),
        0x31: ('BALANCE', 1, 1),
        0x32: ('ORIGIN', 0, 1),
        0x33: ('CALLER', 0, 1),
        0x34: ('CALLVALUE', 0, 1),
        0x35: ('CALLDATALOAD', 1, 1),
        0x36: ('CALLDATASIZE', 0, 1),
        0x37: ('CALLDATACOPY', 3, 0),
        0x38: ('CODESIZE', 0, 1),
        0x39: ('CODECOPY', 3, 0),
        0x3a: ('GASPRICE', 0, 1),
        0x3b: ('EXTCODESIZE', 1, 1),
        0x3c: ('EXTCODECOPY', 4, 0),
        0x3d: ('RETURNDATASIZE', 0, 1),
        0x3e: ('RETURNDATACOPY', 3, 0),
        0x3f: ('EXTCODEHASH', 1, 1),
        0x40: ('BLOCKHASH', 1, 1),
        0x41: ('COINBASE', 0, 1),
        0x42: ('TIMESTAMP', 0, 1),
        0x43: ('NUMBER', 0, 1),
        0x44: ('DIFFICULTY', 0, 1),
        0x45: ('GASLIMIT', 0, 1),
        0x46: ('CHAINID', 0, 1),
        0x47: ('SELFBALANCE', 0, 1),
        0x50: ('POP', 1, 0),
        0x51: ('MLOAD', 1, 1),
        0x52: ('MSTORE', 2, 0),
        0x53: ('MSTORE8', 2, 0),
        0x54: ('SLOAD', 1, 1),
        0x55: ('SSTORE', 2, 0),
        0x56: ('JUMP', 1, 0),
        0x57: ('JUMPI', 2, 0),
        0x58: ('PC', 0, 1),
        0x59: ('MSIZE', 0, 1),
        0x5a: ('GAS', 0, 1),
        0x5b: ('JUMPDEST', 0, 0),
        0x60: ('PUSH1', 0, 1),
        0x61: ('PUSH2', 0, 1),
        0x62: ('PUSH3', 0, 1),
        0x63: ('PUSH4', 0, 1),
        0x64: ('PUSH5', 0, 1),
        0x65: ('PUSH6', 0, 1),
        0x66: ('PUSH7', 0, 1),
        0x67: ('PUSH8', 0, 1),
        0x68: ('PUSH9', 0, 1),
        0x69: ('PUSH10', 0, 1),
        0x6a: ('PUSH11', 0, 1),
        0x6b: ('PUSH12', 0, 1),
        0x6c: ('PUSH13', 0, 1),
        0x6d: ('PUSH14', 0, 1),
        0x6e: ('PUSH15', 0, 1),
        0x6f: ('PUSH16', 0, 1),
        0x70: ('PUSH17', 0, 1),
        0x71: ('PUSH18', 0, 1),
        0x72: ('PUSH19', 0, 1),
        0x73: ('PUSH20', 0, 1),
        0x74: ('PUSH21', 0, 1),
        0x75: ('PUSH22', 0, 1),
        0x76: ('PUSH23', 0, 1),
        0x77: ('PUSH24', 0, 1),
        0x78: ('PUSH25', 0, 1),
        0x79: ('PUSH26', 0, 1),
        0x7a: ('PUSH27', 0, 1),
        0x7b: ('PUSH28', 0, 1),
        0x7c: ('PUSH29', 0, 1),
        0x7d: ('PUSH30', 0, 1),
        0x7e: ('PUSH31', 0, 1),
        0x7f: ('PUSH32', 0, 1),
        0x80: ('DUP1', 1, 2),
        0x81: ('DUP2', 2, 3),
        0x82: ('DUP3', 3, 4),
        0x83: ('DUP4', 4, 5),
        0x84: ('DUP5', 5, 6),
        0x85: ('DUP6', 6, 7),
        0x86: ('DUP7', 7, 8),
        0x87: ('DUP8', 8, 9),
        0x88: ('DUP9', 9, 10),
        0x89: ('DUP10', 10, 11),
        0x8a: ('DUP11', 11, 12),
        0x8b: ('DUP12', 12, 13),
        0x8c: ('DUP13', 13, 14),
        0x8d: ('DUP14', 14, 15),
        0x8e: ('DUP15', 15, 16),
        0x8f: ('DUP16', 16, 17),
        0x90: ('SWAP1', 2, 2),
        0x91: ('SWAP2', 3, 3),
        0x92: ('SWAP3', 4, 4),
        0x93: ('SWAP4', 5, 5),
        0x94: ('SWAP5', 6, 6),
        0x95: ('SWAP6', 7, 7),
        0x96: ('SWAP7', 8, 8),
        0x97: ('SWAP8', 9, 9),
        0x98: ('SWAP9', 10, 10),
        0x99: ('SWAP10', 11, 11),
        0x9a: ('SWAP11', 12, 12),
        0x9b: ('SWAP12', 13, 13),
        0x9c: ('SWAP13', 14, 14),
        0x9d: ('SWAP14', 15, 15),
        0x9e: ('SWAP15', 16, 16),
        0x9f: ('SWAP16', 17, 17),
        0xa0: ('LOG0', 2, 0),
        0xa1: ('LOG1', 3, 0),
        0xa2: ('LOG2', 4, 0),
        0xa3: ('LOG3', 5, 0),
        0xa4: ('LOG4', 6, 0),
        0xf0: ('CREATE', 3, 1),
        0xf1: ('CALL', 7, 1),
        0xf2: ('CALLCODE', 7, 1),
        0xf3: ('RETURN', 2, 0),
        0xf4: ('DELEGATECALL', 6, 1),
        0xf5: ('CREATE2', 4, 1),
        0xfa: ('STATICCALL', 6, 1),
        0xfb: ('REVERT', 2, 0),
        0xfc: ('INVALID', 0, 0),
        0xfd: ('SELFDESTRUCT', 1, 0),
    }

    # 终止类指令 — 执行流到此停止或无条件转移
    _TERMINATORS = frozenset({
        'STOP', 'RETURN', 'REVERT', 'SELFDESTRUCT', 'INVALID', 'JUMP'
    })
    # 条件跳转 — 后继有两个：fall-through 和跳转目标
    _COND_JUMPS = frozenset({'JUMPI'})

    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.instructions: List[EVMInstruction] = []
        self.basic_blocks: Dict[int, EVMBasicBlock] = {}
        self.jumpdests: Set[int] = set()
        self._parse()
        # 延迟计算 — 仅在实际需要构建 CFG 时触发
        self._cfg_edges_built = False

    def _parse(self):
        """逐字节解码为指令序列"""
        pc = 0
        while pc < len(self.bytecode):
            opcode = self.bytecode[pc]

            if opcode in self.OPCODES:
                mnemonic, pops, pushes = self.OPCODES[opcode]

                # PUSH 指令的 operand 字节数由 opcode 决定
                operand_size = 0

                if 0x60 <= opcode <= 0x7f:
                    operand_size = opcode - 0x5f
                    operand = int.from_bytes(
                        self.bytecode[pc + 1:pc + 1 + operand_size], 'big'
                    ) if operand_size > 0 else None
                else:
                    operand = None

                self.instructions.append(EVMInstruction(
                    opcode=opcode,
                    mnemonic=mnemonic,
                    operand=operand,
                    position=pc,
                    stack_effect=(pops, pushes)
                ))

                # 记录所有 JUMPDEST 位置，供 CFG 构建阶段使用
                if mnemonic == 'JUMPDEST':
                    self.jumpdests.add(pc)

                pc += 1 + operand_size
            else:
                pc += 1

    def extract_basic_blocks(self) -> Dict[int, EVMBasicBlock]:
        """从线性的指令流中划分基本块"""
        if self.basic_blocks:
            return self.basic_blocks

        blocks = {}

        current_block_start = 0

        i = 0

        while i < len(self.instructions):
            instr = self.instructions[i]

            # JUMPDEST 是跳转目标 — 新块的入口（首个块除外）
            if instr.mnemonic == 'JUMPDEST' and i > 0:
                blocks[current_block_start] = EVMBasicBlock(
                    start=current_block_start,
                    end=self.instructions[i - 1].position,
                    instructions=self.instructions[current_block_start:i]
                )
                current_block_start = i

            # 分支/终止指令是当前块的出口
            if instr.mnemonic in ('JUMP', 'JUMPI', 'RETURN', 'REVERT', 'STOP', 'SELFDESTRUCT'):
                blocks[current_block_start] = EVMBasicBlock(
                    start=current_block_start,
                    end=instr.position,
                    instructions=self.instructions[current_block_start:i + 1]
                )
                current_block_start = i + 1

            i += 1

        # 最后一段可能没有终止指令
        if current_block_start < len(self.instructions):
            blocks[current_block_start] = EVMBasicBlock(
                start=current_block_start,
                end=self.instructions[-1].position,
                instructions=self.instructions[current_block_start:]
            )

        self.basic_blocks = blocks
        return blocks

    def build_cfg_edges(self) -> Dict[int, EVMBasicBlock]:
        """为基本块构建 successor/predecessor 边。

        分两趟完成：
        1. 扫描每个块末指令，确定 fall-through 与跳转目标
        2. 回填 predecessor 列表

        采用 position→block 索引加速跳转目标的查找，避免 O(n²) 扫描。
        """
        if self._cfg_edges_built:
            return self.basic_blocks

        blocks = self.extract_basic_blocks()
        if not blocks:
            return blocks

        # position → block_start 映射，用于 O(1) 查找跳转目标所属块
        pos_to_block = {}
        for b_start, blk in blocks.items():
            for instr in blk.instructions:
                pos_to_block[instr.position] = b_start

        block_starts = sorted(blocks.keys())

        for idx, b_start in enumerate(block_starts):
            blk = blocks[b_start]
            last = blk.instructions[-1] if blk.instructions else None
            if last is None:
                continue

            # 情况 A: 条件跳转 — fall-through + 静态跳转目标
            if last.mnemonic in self._COND_JUMPS:
                # fall-through: 下一块的起始位置
                if idx + 1 < len(block_starts):
                    fall_target = block_starts[idx + 1]
                    blk.successors.append(fall_target)
                    blocks[fall_target].predecessors.append(b_start)

                # 静态跳转目标 — 仅当跳转地址为编译期常量（PUSH 后紧跟 JUMPI）
                # 这是 Solidity 编译器最常用的模式
                static_target = self._resolve_static_jump_target(last, blk)
                if static_target is not None and static_target in blocks:
                    blk.successors.append(static_target)
                    blocks[static_target].predecessors.append(b_start)
                # 动态跳转目标留空 — 调用方可用 jumpdest 全集作为上近似

            # 情况 B: 无条件跳转 — 仅静态目标
            elif last.mnemonic == 'JUMP':
                static_target = self._resolve_static_jump_target(last, blk)
                if static_target is not None and static_target in blocks:
                    blk.successors.append(static_target)
                    blocks[static_target].predecessors.append(b_start)

            # 情况 C: 终止指令 — 无后继
            elif last.mnemonic in self._TERMINATORS:
                pass  # 无后继

            # 情况 D: 普通指令 — fall-through 到下一块
            else:
                if idx + 1 < len(block_starts):
                    fall_target = block_starts[idx + 1]
                    blk.successors.append(fall_target)
                    blocks[fall_target].predecessors.append(b_start)

        self._cfg_edges_built = True
        return blocks

    def _resolve_static_jump_target(
        self, jump_instr: EVMInstruction, block: EVMBasicBlock
    ) -> Optional[int]:
        """尝试将 JUMP/JUMPI 解析为静态地址。

        典型 Solidity dispatch 模式：PUSH4 <selector> → EQ → PUSH <target> → JUMPI
        此处取最简单且最可靠的形式：块内倒数第二条指令是 PUSH，且 operand 落在已知
        jumpdest 集合内。
        """
        if len(block.instructions) < 2:
            return None
        prev = block.instructions[-2]
        if prev.mnemonic.startswith('PUSH') and prev.operand is not None:
            candidate = prev.operand
            if candidate in self.jumpdests:
                return candidate
        return None

    def compute_dominators(self) -> Dict[int, Set[int]]:
        """迭代法计算基本块的必经节点集合。

        使用 Cooper-Harvey-Kennedy 算法（基于后序遍历的快速收敛），
        时间复杂度在可归约流图上接近 O(N)，最坏 O(N²)。
        仅有意义的值是 dom_id 排序后用于循环检测。
        """
        blocks = self.build_cfg_edges()
        if not blocks:
            return {}

        block_starts = sorted(blocks.keys())
        entry = block_starts[0] if block_starts else None
        if entry is None:
            return {}

        all_set = set(block_starts)
        dom = {b: all_set.copy() for b in block_starts}
        dom[entry] = {entry}

        changed = True
        # 最多迭代 N 轮 — 实际通常 3-5 轮即收敛
        while changed:
            changed = False
            for b in block_starts:
                if b == entry:
                    continue
                preds = blocks[b].predecessors
                if not preds:
                    new_dom = set()
                else:
                    new_dom = dom[preds[0]].copy()
                    for p in preds[1:]:
                        new_dom &= dom[p]
                new_dom.add(b)
                if new_dom != dom[b]:
                    dom[b] = new_dom
                    changed = True

        # 写入 dom_id 供外部排序
        for i, b in enumerate(block_starts):
            blocks[b].dom_id = i

        return dom

    def find_loop_headers(self) -> Set[int]:
        """通过回边 (back edge) 识别循环头。

        回边定义：边 a→b 中 b dominates a → b 是循环头。
        返回所有循环头的块起始地址集合。
        """
        dom = self.compute_dominators()
        blocks = self.build_cfg_edges()
        headers: Set[int] = set()

        for b_start, blk in blocks.items():
            for succ in blk.successors:
                # b_start → succ 是回边 iff succ dominates b_start
                if b_start in dom.get(succ, set()):
                    headers.add(succ)

        return headers

    def find_function_selectors(self) -> Dict[str, int]:
        """匹配 Solidity dispatch 模式提取 function selector"""
        selectors = {}
        pattern = re.compile(rb'\x63([a-f0-9]{8})\x60\x00\x60\x00(\xf0|\xf1|\xf4|\xfa)')

        for match in pattern.finditer(self.bytecode):
            selector = match.group(1).hex()
            position = match.start()
            selectors[selector] = position

        return selectors

    def find_dispatch_offset(self) -> Optional[int]:
        """定位 Solidity dispatch 入口。

        启发式规则：首个 PUSH4 后面紧跟 EQ 指令的偏移，通常为
        function selector 比较的起点。若未匹配到标准模式则返回 None，
        调用方应回退到全字节码扫描。
        """
        instrs = self.instructions
        for i in range(len(instrs) - 2):
            a = instrs[i]
            b = instrs[i + 1]
            c = instrs[i + 2]
            # 模式: PUSH4 <selector> → EQ → PUSH <target> → JUMPI
            if (a.mnemonic == 'PUSH4' and
                b.mnemonic == 'EQ' and
                    c.mnemonic.startswith('PUSH')):
                return a.position
        return None

    def get_instructions(self) -> List[EVMInstruction]:
        """返回已解析的指令列表"""
        return self.instructions

    def has_instruction(self, mnemonic: str) -> bool:
        """检查字节码中是否包含特定助记符"""
        return any(i.mnemonic == mnemonic for i in self.instructions)

    def instruction_at(self, position: int) -> Optional[EVMInstruction]:
        """按字节偏移查找指令 — 二分查找，O(log n)。"""
        lo, hi = 0, len(self.instructions) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            p = self.instructions[mid].position
            if p == position:
                return self.instructions[mid]
            elif p < position:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


# ═══════════════════════════════════════════════════════════════
# 抽象栈模拟器 — 轻量级符号执行辅助
# ═══════════════════════════════════════════════════════════════

class AbstractStack:
    """EVM 操作栈的轻量抽象模型。

    不对分支做全路径探索（区别于 Mythril 的 LaserEVM），只沿单条执行轨迹
    追踪栈槽的污染源标签。用于辅助 detector 判断数据依赖关系，
    例如：SSTORE 的 value 参数是否来源于 CALLDATA（可能被外部操控写入）。
    """

    _TAINT_DISPATCH = {
        'CALLDATALOAD': TaintSource.CALLDATA,
        'CALLDATASIZE': TaintSource.CALLDATA,
        'CALLDATACOPY': TaintSource.CALLDATA,
        'CALLER': TaintSource.CALLDATA,
        'CALLVALUE': TaintSource.CALLDATA,
        'SLOAD': TaintSource.SLOAD,
        'BALANCE': TaintSource.BALANCE,
        'TIMESTAMP': TaintSource.TIMESTAMP,
        'GAS': TaintSource.GAS,
        'GASPRICE': TaintSource.GAS,
        'ORIGIN': TaintSource.CALLDATA,
        'BLOCKHASH': TaintSource.BLOCKHASH,
        'DIFFICULTY': TaintSource.DIFFICULTY,
        'NUMBER': TaintSource.NUMBER,
    }

    _BLOCK_ENV_SOURCES = frozenset({
        TaintSource.TIMESTAMP, TaintSource.BLOCKHASH,
        TaintSource.DIFFICULTY, TaintSource.NUMBER, TaintSource.GAS
    })

    def __init__(self, max_depth: int = 64):
        self._stack: List[StackSlot] = []
        self._max_depth = max_depth

    def push(self, slot: StackSlot):
        if len(self._stack) < self._max_depth:
            self._stack.append(slot)

    def pop(self) -> StackSlot:
        if self._stack:
            return self._stack.pop()
        return StackSlot()

    def peek(self, depth: int = 0) -> StackSlot:
        """窥视栈顶往下第 depth 个元素（depth=0 为栈顶）。"""
        if depth < len(self._stack):
            return self._stack[-(1 + depth)]
        return StackSlot()

    def simulate(self, instr: EVMInstruction):
        """按指令语义修改抽象栈。

        对算数/位运算：合并所有输入槽的污染标记。
        对 SWAP/DUP：按 EVM 规范重排/复制。
        对 PUSH：推入具体值，标为 CONSTANT。
        对 CALL/DELEGATECALL：返回值标为 CALL_RESULT。
        对 SLOAD：标为 SLOAD（非 CALLDATA 的外部输入）。
        """
        mnem = instr.mnemonic
        pops, pushes = instr.stack_effect

        # 先 pop 再 push，模拟 EVM 真实行为
        args = []
        for _ in range(pops):
            args.append(self.pop())
        # 栈操作中 args[0] 是栈顶（最后 pop 的），需要反转以对应语义顺序
        args.reverse()

        # --- 按助记符分发语义 ---
        if mnem.startswith('PUSH'):
            self.push(StackSlot.concrete(instr.operand or 0))

        elif mnem.startswith('DUP'):
            depth = int(mnem[3:]) - 1
            slot = self.peek(depth)
            self.push(slot)

        elif mnem.startswith('SWAP'):
            depth = int(mnem[4:])
            # SWAPn 将栈顶与第 n 个元素交换
            if depth < len(self._stack):
                top = self._stack[-1]
                self._stack[-1] = self._stack[-(1 + depth)]
                self._stack[-(1 + depth)] = top

        elif mnem in ('ADD', 'MUL', 'SUB', 'DIV', 'SDIV', 'MOD', 'SMOD',
                      'EXP', 'SIGNEXTEND', 'ADDMOD', 'MULMOD'):
            if args:
                merged = args[0].merge_taint(*args[1:])
                self.push(merged)
            else:
                self.push(StackSlot())

        elif mnem in ('LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO',
                      'AND', 'OR', 'XOR', 'NOT', 'BYTE',
                      'SHL', 'SHR', 'SAR'):
            if args:
                merged = args[0].merge_taint(*args[1:])
                self.push(merged)
            else:
                self.push(StackSlot())

        elif mnem == 'SHA3' and len(args) >= 2:
            self.push(args[0].merge_taint(args[1]))

        elif mnem == 'MLOAD' and args:
            self.push(StackSlot(taint={TaintSource.UNKNOWN}))

        elif mnem in ('MSTORE', 'MSTORE8', 'SSTORE'):
            pass  # 不推入新值

        elif mnem in self._TAINT_DISPATCH:
            self.push(StackSlot.tainted(self._TAINT_DISPATCH[mnem]))

        elif mnem in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
            # 调用结果标记为外部来源
            self.push(StackSlot.tainted(TaintSource.CALL_RESULT))

        elif mnem in ('CREATE', 'CREATE2'):
            self.push(StackSlot.tainted(TaintSource.CALL_RESULT))

        elif mnem in ('RETURN', 'REVERT', 'STOP', 'SELFDESTRUCT',
                      'JUMP', 'JUMPI', 'INVALID'):
            for _ in range(pushes):
                self.push(StackSlot())  # 实际不可达，占位

        elif mnem in ('POP',):
            pass  # 值已丢弃

        else:
            # 未明确建模的指令：保留 pushes 个 UNKNOWN 槽
            for _ in range(pushes):
                self.push(StackSlot())

    def has_taint_in_range(self, depth: int, source: TaintSource) -> bool:
        """检查栈顶往下 depth 范围内是否存在指定污染源。"""
        limit = min(depth, len(self._stack))
        for i in range(limit):
            if source in self._stack[-(1 + i)].taint:
                return True
        return False

    def has_block_env_taint(self, depth: int = 5) -> bool:
        limit = min(depth, len(self._stack))
        for i in range(limit):
            if self._stack[-(1 + i)].taint & self._BLOCK_ENV_SOURCES:
                return True
        return False

    def is_tainted_by(self, source: TaintSource, depth: int = 3) -> bool:
        """便捷方法：检查栈顶几层内是否有指定 taint。"""
        return self.has_taint_in_range(depth, source)

    def snapshot(self) -> int:
        """返回当前栈深度 — 供调用方记录后比较。"""
        return len(self._stack)

    def clone_state(self) -> 'AbstractStack':
        clone = AbstractStack(self._max_depth)
        clone._stack = [
            StackSlot(value=s.value, taint=s.taint.copy())
            for s in self._stack
        ]
        return clone

    def merge_from(self, other: 'AbstractStack'):
        min_len = min(len(self._stack), len(other._stack))
        for i in range(min_len):
            self_idx = -(1 + i)
            other_idx = -(1 + i)
            self._stack[self_idx].taint |= other._stack[other_idx].taint


# ═══════════════════════════════════════════════════════════════
# WASM 解析器
# ═══════════════════════════════════════════════════════════════

class WASMContractParser:
    """WASM 二进制解析器 — 仅覆盖安全审计所需的子集

    解析能力：magic/version → sections → imports/exports/functions/type。
    不执行完整验证（如类型检查），仅提取用于审计的结构化信息。
    """

    WASM_MAGIC = b'\x00asm'
    _SECTION_CUSTOM = 0
    _SECTION_TYPE = 1
    _SECTION_IMPORT = 2
    _SECTION_FUNCTION = 3
    _SECTION_EXPORT = 7
    _SECTION_CODE = 10

    def __init__(self, wasm_bytes: bytes):
        self.data = wasm_bytes
        self.magic_valid = self.data.startswith(self.WASM_MAGIC)
        self.sections = []
        self.imports = []
        self.exports = []
        self.function_types: List[int] = []  # 每个函数对应的 type index
        self.exported_functions: Dict[str, int] = {}  # name → func_idx
        self.sensitive_import_modules = frozenset({
            'ethereum', 'env', 'seal', 'extism', 'blockchain',
            'runtime', 'host', 'state', 'crypto', 'memory'
        })

        if self.magic_valid:
            self._parse()

    def _parse(self):
        """按 WASM 格式逐 section 解析"""
        offset = 8  # magic + version = 8 bytes
        while offset < len(self.data):
            section_id = self.data[offset]
            length = self._read_varuint(offset + 1)
            payload_start = offset + 1 + length[1]
            section_end = payload_start + length[0]

            self.sections.append({
                'id': section_id,
                'offset': offset,
                'length': length[0],
                'data': self.data[payload_start:section_end]
            })

            payload = self.data[payload_start:section_end]

            if section_id == self._SECTION_TYPE:
                self._parse_type_section(payload)
            elif section_id == self._SECTION_IMPORT:
                self._parse_import_section(payload)
            elif section_id == self._SECTION_FUNCTION:
                self._parse_function_section(payload)
            elif section_id == self._SECTION_EXPORT:
                self._parse_export_section(payload)

            offset = section_end

    def _parse_type_section(self, data: bytes):
        """解析 type section — 记录函数签名数量，供 function/import 索引引用。"""
        num_types, off = self._read_varuint(0), 0
        off += num_types[1]
        # 每种类型是一个 functype: 0x60 + param_vec + result_vec
        # 此处仅计数，不解析详细的 valtype 列表
        self.type_count = num_types[0]

    def _parse_function_section(self, data: bytes):
        """解析 function section — 每个条目是 type index。"""
        offset = 0
        count = self._read_varuint(offset)
        offset += count[1]
        for _ in range(count[0]):
            type_idx = self._read_varuint(offset)
            offset += type_idx[1]
            self.function_types.append(type_idx[0])

    def _parse_export_section(self, data: bytes):
        """解析 export section — 提取 (name, kind, func_idx) 三元组。

        只关注 kind=0（函数导出），这是外部可调用入口的关键信息。
        """
        offset = 0
        count = self._read_varuint(offset)
        offset += count[1]

        for _ in range(count[0]):
            name_len = self._read_varuint(offset)
            offset += name_len[1]
            export_name = data[offset:offset + name_len[0]].decode('utf-8', errors='replace')
            offset += name_len[0]

            export_kind = data[offset]
            offset += 1

            func_idx = self._read_varuint(offset)
            offset += func_idx[1]

            self.exports.append({
                'name': export_name,
                'kind': export_kind,
                'func_idx': func_idx[0]
            })

            if export_kind == 0:  # function export
                self.exported_functions[export_name] = func_idx[0]

    def _parse_import_section(self, data: bytes):
        """解析 import section payload"""
        offset = 0
        count = self._read_varuint(offset)
        offset += count[1]

        for _ in range(count[0]):
            module_len = self._read_varuint(offset)
            offset += module_len[1]
            module = data[offset:offset + module_len[0]].decode('utf-8')
            offset += module_len[0]

            name_len = self._read_varuint(offset)
            offset += name_len[1]
            name = data[offset:offset + name_len[0]].decode('utf-8')
            offset += name_len[0]

            # import kind (0=function, 1=table, 2=memory, 3=global)
            kind = data[offset] if offset < len(data) else 0
            offset += 1

            self.imports.append({
                'module': module,
                'name': name,
                'kind': kind
            })

    def _read_varuint(self, offset: int) -> Tuple[int, int]:
        """LEB128 无符号整数解码"""
        result = 0

        shift = 0

        length = 0

        while offset + length < len(self.data):
            byte = self.data[offset + length]
            result |= (byte & 0x7f) << shift
            length += 1

            if (byte & 0x80) == 0:
                break

            shift += 7

        return result, length

    def has_sensitive_imports(self) -> bool:
        """检查 import 列表中是否含有区块链宿主环境敏感模块"""
        return any(
            imp['module'] in self.sensitive_import_modules
            for imp in self.imports
        )

    def get_sensitive_imports_detail(self) -> List[Dict[str, Any]]:
        """返回所有敏感 import 的详细信息 — 带模块名和函数名。

        用于报告生成阶段提供比布尔值更丰富的上下文。
        """
        return [
            {'module': imp['module'], 'name': imp['name'], 'kind': imp['kind']}
            for imp in self.imports
            if imp['module'] in self.sensitive_import_modules
        ]

    def get_exported_function_count(self) -> int:
        """返回导出函数数量 — 外部的攻击面宽度。"""
        return len(self.exported_functions)

    def has_memory_import(self) -> bool:
        """检查是否导入了外部 memory — 可能存在宿主内存污染风险。"""
        for imp in self.imports:
            if imp.get('kind') == 2:  # memory import
                return True
        return False


# ═══════════════════════════════════════════════════════════════
# 检测器 — 各漏洞类型的独立分析逻辑
# ═══════════════════════════════════════════════════════════════

class ReentrancyDetector:
    """重入漏洞检测 — 判断 SSTORE 与 CALL 的前后位置关系

    增强：集成 AbstractStack 以追踪 SSTORE 的 value 参数是否受 CALLDATA 污染，
    降低因编译器生成的非用户代码模式导致的误报。
    """

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['CALL', 'DELEGATECALL']:
                if self._has_reentrancy_pattern(instructions, i):
                    # 交叉验证：运行抽象栈确认 SSTORE 的 key/value 来源可疑
                    evidence = self._collect_evidence(instructions, i)

                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=VulnerabilityType.REENTRANCY,
                        severity='Critical',
                        confidence=0.85,
                        description="潜在重入漏洞：状态修改前存在外部调用",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        impact="攻击者通过递归调用反复提取资金",
                        recommendation="采用 Checks-Effects-Interactions 模式",
                        evidence_snippets=evidence
                    ))

        return self.vulnerabilities

    def _collect_evidence(
        self, instructions: List[EVMInstruction], call_idx: int
    ) -> List[str]:
        """采集证据片段 — 为报告提供调用点附近的指令上下文。"""
        snippets = []
        start = max(0, call_idx - 4)
        end = min(len(instructions), call_idx + 4)
        for j in range(start, end):
            mark = ">>>" if j == call_idx else "   "
            op = instructions[j]
            operand_str = f" 0x{op.operand:x}" if op.operand is not None else ""
            snippets.append(f"{mark} {op.position:#06x}: {op.mnemonic}{operand_str}")
        return snippets

    def _has_reentrancy_pattern(self, instructions: List[EVMInstruction], call_idx: int) -> bool:
        """判定 CALL 前后 SSTORE 的次序关系"""
        sstore_before = False
        call_found = False

        for i in range(min(call_idx + 50, len(instructions))):
            instr = instructions[i]

            if instr.mnemonic == 'SSTORE':
                if call_found:
                    return True
                sstore_before = True

            if instr.mnemonic in ['CALL', 'DELEGATECALL']:
                call_found = True
                if sstore_before:
                    return False

        return call_found


class IntegerOverflowDetector:
    """整数溢出检测 — 定位缺少安全比较的算术指令"""

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['ADD', 'MUL', 'SUB', 'DIV']:
                if not self._has_overflow_check(instructions, i):
                    severity = 'High' if instr.mnemonic in ['MUL'] else 'Medium'
                    vuln_type = (
                        VulnerabilityType.INTEGER_OVERFLOW
                        if instr.mnemonic in ['ADD', 'MUL']
                        else VulnerabilityType.INTEGER_UNDERFLOW
                    )
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=vuln_type,
                        severity=severity,
                        confidence=0.7,
                        description=f"未检查的 {instr.mnemonic} 运算，存在整数溢出/下溢风险",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        recommendation="使用 SafeMath 或 Solidity 0.8+ 内置检查"
                    ))

        return self.vulnerabilities

    def _has_overflow_check(self, instructions: List[EVMInstruction], idx: int) -> bool:
        """检查 idx 之后小窗口内是否存在比较/断言指令"""
        check_instructions = ['LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO']
        for i in range(idx, min(idx + 10, len(instructions))):
            if instructions[i].mnemonic in check_instructions:
                return True
        return False


class UncheckedCallDetector:
    """未检查返回值调用检测 — 定位 CALL 后缺少 ISZERO/JUMPI 的指令"""

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE']:
                if not self._has_result_check(instructions, i):
                    vuln_type = (
                        VulnerabilityType.UNCHECKED_DELEGATECALL
                        if instr.mnemonic == 'DELEGATECALL'
                        else VulnerabilityType.UNCHECKED_CALL
                    )
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=vuln_type,
                        severity='High',
                        confidence=0.8,
                        description=f"{instr.mnemonic} 返回值未被检查，存在静默失败风险",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        recommendation="检查调用返回值，失败时执行 revert"
                    ))

        return self.vulnerabilities

    def _has_result_check(self, instructions: List[EVMInstruction], idx: int) -> bool:
        """检查 CALL 后紧跟窗口内是否有返回值校验"""
        for i in range(idx + 1, min(idx + 5, len(instructions))):
            if instructions[i].mnemonic in ['ISZERO', 'JUMPI']:
                return True
        return False


class DeprecatedOpcodeDetector:
    """废弃/高危操作码检测。

    检测范围：
    - SELFDESTRUCT：合约销毁，若调用者无限制则致命
    - CALLCODE：语义含 storage 污染风险，已被 DELEGATECALL 替代
    - INVALID：通常意味着不可达路径或编译器 panic，需人工判断
    """

    _DEPRECATED_RULES = {
        'SELFDESTRUCT': {
            'vuln_type': VulnerabilityType.UNPROTECTED_SELFDESTRUCT,
            'severity': 'Critical',
            'confidence': 0.95,
            'desc': 'SELFDESTRUCT 可销毁合约并转移余额',
            'recommend': '确保仅合约 owner 或治理模块可触发，考虑使用 OpenZeppelin 的 SelfDestructGuard',
        },
        'CALLCODE': {
            'vuln_type': VulnerabilityType.STORAGE_COLLISION,
            'severity': 'High',
            'confidence': 0.9,
            'desc': 'CALLCODE 使用调用者的 storage 上下文，极易引发存储碰撞',
            'recommend': '迁移至 DELEGATECALL 并显式管理 storage layout',
        },
        'INVALID': {
            'vuln_type': VulnerabilityType.DEPRECATED_OPCODE,
            'severity': 'Low',
            'confidence': 0.5,
            'desc': 'INVALID 指令可能为编译器插入的 unreachable marker，也可能是异常路径残留',
            'recommend': '人工审查 INVALID 位置的上下文，排除异常执行路径',
        },
    }

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for instr in instructions:
            rule = self._DEPRECATED_RULES.get(instr.mnemonic)
            if rule is None:
                continue

            self.vulnerabilities.append(ContractVulnerability(
                vuln_type=rule['vuln_type'],
                severity=rule['severity'],
                confidence=rule['confidence'],
                description=f"{rule['desc']}（位置 {instr.position:#x}）",
                location=instr.position,
                opcode=instr.mnemonic,
                recommendation=rule['recommend']
            ))

        return self.vulnerabilities


class StorageCollisionDetector:
    """DELEGATECALL 存储布局碰撞检测。

    原理：DELEGATECALL 在被调用方代码中使用调用方的 storage 布局。
    若调用方与被调用方的 storage 变量声明不一致（尤其是在可升级代理模式中
    slot 映射出现偏差），将导致存储碰撞，表现为非预期的变量覆写。

    当前策略：标记所有 DELEGATECALL 与 CALLCODE 并分析上下文，
    结合导入目标地址的可判定性给出不同的置信度。
    """

    _SENSITIVE_CALLS = frozenset({'DELEGATECALL', 'CALLCODE'})

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for i, instr in enumerate(instructions):
            if instr.mnemonic not in self._SENSITIVE_CALLS:
                continue

            # 尝试判定目标地址是否为外部传入（高置信度）vs 硬编码（中置信度）
            addr_is_dynamic = self._target_address_is_dynamic(instructions, i)

            base_desc = (
                f"{instr.mnemonic} 在代理/可升级模式中存在存储布局碰撞风险"
            )

            self.vulnerabilities.append(ContractVulnerability(
                vuln_type=VulnerabilityType.STORAGE_COLLISION,
                severity='High',
                confidence=0.75 if addr_is_dynamic else 0.55,
                description=base_desc,
                location=instr.position,
                opcode=instr.mnemonic,
                impact="存储碰撞可导致关键状态变量被意外覆写",
                recommendation="遵循 EIP-1967 标准存储槽方案，或使用 unstructured storage proxy 模式"
            ))

        return self.vulnerabilities

    def _target_address_is_dynamic(
        self, instructions: List[EVMInstruction], call_idx: int
    ) -> bool:
        """判定 DELEGATECALL 的目标地址是否为动态（来自 CALLDATA/存储）。"""
        # DELEGATECALL 的 gas 和 address 参数是栈顶第 2、3 个元素
        # 向前回溯若干条指令，检查是否有 CALLDATALOAD/SLOAD 的污染
        sim = AbstractStack()
        start = max(0, call_idx - 15)
        for j in range(start, call_idx):
            sim.simulate(instructions[j])

        return sim.has_taint_in_range(3, TaintSource.CALLDATA)


class GasInefficiencyDetector:
    """Gas 效率低下的代码模式检测。

    检测规则：
    1. 同一 storage slot 在短窗口内被多次 SLOAD — 应缓存到本地变量
    2. 循环内有 SSTORE — 每次写入都是 5000-20000 gas
    3. 冷账户 CALL 在循环中 — 每次冷访问 2600 gas
    """

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        self._detect_redundant_sloads(instructions)
        self._detect_loop_sstores(instructions)

        return self.vulnerabilities

    def _detect_redundant_sloads(self, instructions: List[EVMInstruction]):
        # inline
        window = _REDUNDANT_SLOAD_WINDOW
        # 记录最近一次 SLOAD 的位置和 slot（通过 PUSH + SLOAD 推测）
        recent_sloads: Dict[int, int] = {}  # slot_val → first_position

        for i, instr in enumerate(instructions):
            if instr.mnemonic == 'SLOAD':
                prev_instr = instructions[i - 1] if i > 0 else None
                if prev_instr and prev_instr.mnemonic.startswith('PUSH') and prev_instr.operand is not None:
                    slot_val = prev_instr.operand
                    if slot_val in recent_sloads:
                        first_pos = recent_sloads[slot_val]
                        if i - first_pos < window:
                            self.vulnerabilities.append(ContractVulnerability(
                                vuln_type=VulnerabilityType.GAS_INEFFICIENCY,
                                severity='Low',
                                confidence=0.6,
                                description=f"slot {slot_val:#x} 在 {i - first_pos} 条指令内被重复 SLOAD",
                                location=instr.position,
                                opcode='SLOAD',
                                recommendation="将 storage 值缓存到本地变量，减少 SLOAD 次数"
                            ))
                    recent_sloads[slot_val] = i
            # 遇到 SSTORE 时清除同 slot 的缓存（写入后重新读是合理的）
            if instr.mnemonic == 'SSTORE':
                prev = instructions[i - 1] if i > 0 else None
                if prev and prev.mnemonic.startswith('PUSH') and prev.operand is not None:
                    slot_written = instructions[i - 2].operand if i > 1 else None
                    if slot_written is not None:
                        recent_sloads.pop(slot_written, None)

    def _detect_loop_sstores(self, instructions: List[EVMInstruction]):
        # inline
        loop_headers = self.parser.find_loop_headers()
        if not loop_headers:
            return

        blocks = self.parser.build_cfg_edges()
        dom = self.parser.compute_dominators()

        for b_start, blk in blocks.items():
            in_loop = any(
                header in dom.get(b_start, set()) and b_start != header
                for header in loop_headers
            )
            if not in_loop:
                continue

            for instr in blk.instructions:
                if instr.mnemonic == 'SSTORE':
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=VulnerabilityType.GAS_INEFFICIENCY,
                        severity='Medium',
                        confidence=0.55,
                        description="循环体中的 SSTORE 会随迭代次数累积 gas 成本",
                        location=instr.position,
                        opcode='SSTORE',
                        recommendation="在循环结束后一次性写入，或使用 event 替代存储"
                    ))


class FrontRunningDetector:
    """抢跑/MEV 漏洞检测。

    启发式规则：
    1. TIMESTAMP 用于关键判断（如随机数、截止时间）→ 矿工可在 15 秒窗口内操控
    2. 无 deadline/slippage 参数的 swap-like 模式 → 抢跑者可通过抬高 gas 操纵成交价
    3. GASPRICE 用于关键路径 → 可能被操控以影响逻辑

    注意：基于字节码的 MEV 检测天然精度有限 — 很多语义信息在编译中丢失。
    报告 confidence 偏低，需结合源码审查。
    """

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for instr in instructions:
            if instr.mnemonic == 'TIMESTAMP':
                if self._used_in_comparison(instructions, instr):
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=VulnerabilityType.FRONT_RUNNING,
                        severity='Medium',
                        confidence=0.5,
                        description="TIMESTAMP 参与条件分支，可能在 15 秒窗口内被矿工操控",
                        location=instr.position,
                        opcode='TIMESTAMP',
                        impact="抢跑者可利用时间窗口执行有利交易",
                        recommendation="避免将 block.timestamp 用于精确的时间逻辑；使用 block.number 作为粗略时间戳"
                    ))

            if instr.mnemonic == 'GASPRICE':
                if self._used_as_value_metric(instructions, instr):
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=VulnerabilityType.FRONT_RUNNING,
                        severity='Low',
                        confidence=0.3,
                        description="GASPRICE 参与数值计算，可能引入 gas 价格操控攻击面",
                        location=instr.position,
                        opcode='GASPRICE',
                        recommendation="避免依赖 tx.gasprice 做业务逻辑判断"
                    ))

        return self.vulnerabilities

    def _used_in_comparison(
        self, instructions: List[EVMInstruction], timestamp_instr: EVMInstruction
    ) -> bool:
        """TIMESTAMP 之后小窗口内是否紧跟比较+条件跳转。"""
        idx = instructions.index(timestamp_instr)
        cmp_ops = {'LT', 'GT', 'SLT', 'SGT', 'EQ'}
        limit = min(idx + 8, len(instructions))
        for j in range(idx + 1, limit):
            if instructions[j].mnemonic in cmp_ops:
                return True
        return False

    def _used_as_value_metric(
        self, instructions: List[EVMInstruction], gas_instr: EVMInstruction
    ) -> bool:
        """GASPRICE 后是否用作算术或比较操作。"""
        idx = instructions.index(gas_instr)
        value_ops = {'ADD', 'MUL', 'DIV', 'LT', 'GT', 'EQ', 'SUB'}
        limit = min(idx + 6, len(instructions))
        for j in range(idx + 1, limit):
            if instructions[j].mnemonic in value_ops:
                return True
        return False


# ═══════════════════════════════════════════════════════════════
# 主分析器
# ═══════════════════════════════════════════════════════════════


class WeakRandomnessDetector:
    """弱随机数检测。

    检测模式：区块环境变量（BLOCKHASH, TIMESTAMP, DIFFICULTY, NUMBER）
    → 算术/哈希操作 → 条件分支/转账/SSTORE。

    这类随机性可被矿工在单区块内精确预测和操控。
    CrossInspector (arXiv 2024) 的 State Dependency Graph 将其归类为
    timestamp/block 依赖漏洞，精度 97%。
    """

    _RANDOMNESS_SOURCES = frozenset({
        'BLOCKHASH', 'TIMESTAMP', 'DIFFICULTY', 'NUMBER'
    })

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for i, instr in enumerate(instructions):
            if instr.mnemonic not in self._RANDOMNESS_SOURCES:
                continue

            if self._flows_to_sensitive_op(instructions, i):
                self.vulnerabilities.append(ContractVulnerability(
                    vuln_type=VulnerabilityType.WEAK_RANDOMNESS,
                    severity='High',
                    confidence=0.65,
                    description=f"{instr.mnemonic} 可能被用作随机性来源，矿工可预测操控",
                    location=instr.position,
                    opcode=instr.mnemonic,
                    impact="矿工可在同一区块内预测并操控随机结果",
                    recommendation="使用 Chainlink VRF 或 commit-reveal 方案替代区块变量随机数"
                ))

        return self.vulnerabilities

    def _flows_to_sensitive_op(
        self, instructions: List[EVMInstruction], src_idx: int
    ) -> bool:
        """检查从 src_idx 出发的短窗口内是否流向敏感操作。

        敏感操作：条件跳转 (JUMPI)、外部调用 (CALL*)、存储写入 (SSTORE)。
        用 AbstractStack 单路径模拟 taint 传播。
        """
        sim = AbstractStack()
        limit = min(src_idx + 30, len(instructions))

        for j in range(src_idx, limit):
            sim.simulate(instructions[j])

            instr = instructions[j]
            if instr.mnemonic in ('JUMPI', 'SSTORE', 'CALL', 'DELEGATECALL',
                                  'CALLCODE', 'STATICCALL', 'CREATE', 'CREATE2'):
                if sim.has_block_env_taint(depth=4):
                    return True

        return False


class PatternSignatureDetector:
    """类 YARA 的漏洞签名匹配框架。

    通过定义指令序列的抽象谓词模式，在字节码中搜索匹配的漏洞签名。
    每条规则是一个 (name, pattern, severity, description, recommendation) 元组，
    pattern 为 EVMInstruction 谓词序列。

    设计取舍：不用正则而用谓词序列，因 EVM 的栈式架构使得指令间距
    不可预测（SWAP/DUP 可拉大相关指令距离），谓词比正则更灵活。
    """

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []
        self._rules: list = []
        self._register_default_rules()

    def _register_default_rules(self):
        """注册内置签名规则。"""
        self._rules.append((
            'unprotected_selfdestruct',
            [
                lambda i: i.mnemonic.startswith('PUSH'),
                lambda i: i.mnemonic == 'SELFDESTRUCT',
            ],
            'Critical',
            'SELFDESTRUCT 紧跟在 PUSH 后且无调用者检查',
            '添加 onlyOwner 修饰符或等效的 CALLER 检查',
            VulnerabilityType.UNPROTECTED_SELFDESTRUCT,
        ))

        self._rules.append((
            'zero_address_transfer',
            [
                lambda i: i.mnemonic == 'PUSH1' and i.operand == 0,
                lambda i: i.mnemonic == 'PUSH1' and i.operand == 0,
                lambda i: i.mnemonic == 'PUSH1' and i.operand == 0,
                lambda i: i.mnemonic == 'PUSH1' and i.operand == 0,
                lambda i: i.mnemonic == 'CALL',
            ],
            'Medium',
            '检测到标准 transfer 模式但目标地址为 0x0，资金可能被销毁',
            '添加地址有效性检查 require(to != address(0))',
            VulnerabilityType.UNCHECKED_SEND,
        ))

        self._rules.append((
            'abi_encode_packed_ambiguity',
            [
                lambda i: i.mnemonic in ('CALLDATALOAD', 'CALLDATACOPY'),
                lambda i: i.mnemonic in ('SHA3', 'SSTORE'),
            ],
            'Low',
            '动态类型经 CALLDATA 直接传入 SHA3/SSTORE，存在 ABI 编码歧义风险',
            '当使用 abi.encodePacked 处理动态类型时产生哈希碰撞',
            VulnerabilityType.ABI_ENCODE_PACKED,
        ))

        self._rules.append((
            'tx_origin_auth',
            [
                lambda i: i.mnemonic == 'ORIGIN',
                lambda i: i.mnemonic in ('EQ', 'SUB', 'XOR'),
                lambda i: i.mnemonic == 'JUMPI',
            ],
            'High',
            'tx.origin 参与身份验证断言，典型的钓鱼攻击入口',
            '替换 tx.origin 为 msg.sender',
            VulnerabilityType.TX_ORIGIN,
        ))

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()
        n = len(instructions)

        for rule_name, predicates, severity, desc, recommendation, vuln_override in self._rules:
            pattern_len = len(predicates)
            if n < pattern_len:
                continue

            i = 0
            while i <= n - pattern_len:
                matched = True
                for offset in range(pattern_len):
                    if not predicates[offset](instructions[i + offset]):
                        matched = False
                        break

                if matched:
                    first_instr = instructions[i]
                    last_instr = instructions[i + pattern_len - 1]

                    vuln_type = vuln_override or VulnerabilityType.DEPRECATED_OPCODE

                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=vuln_type,
                        severity=severity,
                        confidence=0.7,
                        description=desc,
                        location=first_instr.position,
                        opcode=last_instr.mnemonic,
                        recommendation=recommendation,
                        evidence_snippets=[
                            f"  {instructions[j].position:#06x}: {instructions[j].mnemonic}"
                            f"{' 0x' + format(instructions[j].operand, 'x') if instructions[j].operand is not None else ''}"
                            for j in range(i, i + pattern_len)
                        ]
                    ))
                    i += 1
                else:
                    i += 1

        return self.vulnerabilities

class SmartContractAnalyzer(BaseAnalyzer):
    """智能合约安全分析器 — 平台插件入口

    pipeline: validate → parse → detect (parallel detectors) → report
    各 detector 独立运行，结果合并后按置信度过滤和严重度排序输出。
    """

    # 字节码指纹缓存 — 避免对完全相同的字节码重复执行全流程
    _fingerprint_cache: Dict[str, Dict[str, Any]] = {}
    _CACHE_MAX_SIZE = 128

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or self._default_config()
        self._setup_logging()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "enabled": True,
            "detect_reentrancy": True,
            "detect_overflow": True,
            "detect_unchecked_call": True,
            "detect_tx_origin": True,
            "detect_deprecated_opcode": True,
            "detect_storage_collision": True,
            "detect_gas_inefficiency": True,
            "detect_front_running": True,
            "confidence_threshold": 0.5,
            "max_vulns": 100,
            "enable_caching": True,
            "detect_weak_randomness": True,
            "detect_pattern_signatures": True,
            "enable_cfg_analysis": True,
            "severity_override": {},
        }

    def _setup_logging(self) -> None:
        self.logger = logging.getLogger(__name__)
        if LOGURU_AVAILABLE:
            self.logger = loguru_logger
        self.logger.info("SmartContractAnalyzer initialized")

    def analyze(self, **kwargs) -> Dict[str, Any]:
        # 不拆——保持上下文连贯性
        # inline
        bytecode = kwargs.get("bytecode")
        contract_type = kwargs.get("contract_type", "evm")
        output_format = kwargs.get("output_format", "json")

        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}

        start_time = time.time()

        # 字节码指纹 — 快速缓存命中
        if self._config.get("enable_caching", True):
            fp = self._compute_fingerprint(bytecode)
            if fp in self._fingerprint_cache:
                cached = self._fingerprint_cache[fp].copy()
                cached["analysis_time"] = time.time() - start_time
                cached["from_cache"] = True
                return {"success": True, "report": cached}

        contract_type_enum = contract_type.lower()

        if contract_type_enum == ContractType.EVM:
            result = self._analyze_evm(bytecode)
        elif contract_type_enum == ContractType.WASM:
            result = self._analyze_wasm(bytecode)
        else:
            return {"success": False, "error": f"不支持的合约类型: {contract_type}"}

        result["analysis_time"] = time.time() - start_time

        # 写入缓存
        if self._config.get("enable_caching", True):
            fp = self._compute_fingerprint(bytecode)
            if len(self._fingerprint_cache) >= self._CACHE_MAX_SIZE:
                # 简单 FIFO 淘汰 — 删除最早插入的条目
                oldest = next(iter(self._fingerprint_cache))
                del self._fingerprint_cache[oldest]
            self._fingerprint_cache[fp] = result.copy()

        if output_format == "json":
            return {"success": True, "report": result}
        else:
            return {"success": True, "report": self._format_text_report(result)}

    def _compute_fingerprint(self, bytecode: bytes) -> str:
        """计算字节码的 Keccak-256 指纹 — 使用 SHA-256 近似。

        注意：链上 Keccak 与 SHA-3 标准存在差异，但此处的用途仅是
        内存缓存键，非链上验证，SHA-256 足以提供冲突抵抗。
        """
        return hashlib.sha256(bytecode).hexdigest()

    def _analyze_evm(self, bytecode: bytes) -> Dict[str, Any]:
        """EVM 合约分析流水线"""
        parser = EVMBytecodeParser(bytecode)
        vulnerabilities = []

        # 若配置要求，预先构建 CFG 供各 detector 复用
        if self._config.get("enable_cfg_analysis", True):
            parser.build_cfg_edges()

        # 按配置激活各 detector
        if self._config.get("detect_reentrancy", True):
            detector = ReentrancyDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_overflow", True):
            detector = IntegerOverflowDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_unchecked_call", True):
            detector = UncheckedCallDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_tx_origin", True):
            vulnerabilities.extend(self._detect_tx_origin(parser))

        if self._config.get("detect_deprecated_opcode", True):
            detector = DeprecatedOpcodeDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_storage_collision", True):
            detector = StorageCollisionDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_gas_inefficiency", True):
            detector = GasInefficiencyDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_front_running", True):
            detector = FrontRunningDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_weak_randomness", True):
            detector = WeakRandomnessDetector(parser)
            vulnerabilities.extend(detector.detect())

        if self._config.get("detect_pattern_signatures", True):
            detector = PatternSignatureDetector(parser)
            vulnerabilities.extend(detector.detect())

        # 后处理：置信度过滤 + 严重度重写
        vulnerabilities = self._filter_by_confidence(vulnerabilities)
        vulnerabilities = self._apply_severity_override(vulnerabilities)

        selectors = parser.find_function_selectors()
        has_selfdestruct = parser.has_instruction('SELFDESTRUCT')
        has_delegatecall = parser.has_instruction('DELEGATECALL')
        has_tx_origin = parser.has_instruction('ORIGIN')
        selector_count = len(selectors)

        # 编译方式推测 — 辅助报告消费方了解上下文
        compiler_hints = []
        if selector_count > 0:
            compiler_hints.append(f"检测到 {selector_count} 个函数选择器，推测为 Solidity/Vyper 编译")
        if has_selfdestruct:
            compiler_hints.append("包含 SELFDESTRUCT — 合约可被销毁")
        if has_delegatecall:
            compiler_hints.append("包含 DELEGATECALL — 可能为代理模式")
        if has_tx_origin:
            compiler_hints.append("包含 ORIGIN — 可能存在 tx.origin 身份验证")

        return {
            "contract_type": "evm",
            "bytecode_length": len(bytecode),
            "bytecode_hash": self._compute_fingerprint(bytecode),
            "function_selectors": selectors,
            "selector_count": selector_count,
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": sum(
                1 for v in vulnerabilities
                if v.severity in ['Critical', 'High']
            ),
            "medium_severity": sum(
                1 for v in vulnerabilities if v.severity == 'Medium'
            ),
            "low_severity": sum(
                1 for v in vulnerabilities if v.severity == 'Low'
            ),
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities],
            "tags": compiler_hints,
        }

    def _analyze_wasm(self, bytecode: bytes) -> Dict[str, Any]:
        """WASM 合约分析 — 当前仅覆盖敏感 import 检测"""
        parser = WASMContractParser(bytecode)
        vulnerabilities = []

        sensitive_imports = parser.get_sensitive_imports_detail()
        if sensitive_imports:
            import_names = ', '.join(
                f"{s['module']}.{s['name']}" for s in sensitive_imports
            )
            vulnerabilities.append(ContractVulnerability(
                vuln_type=VulnerabilityType.STORAGE_COLLISION,
                severity='Medium',
                confidence=0.6,
                description=f"检测到敏感外部 import: {import_names}，存在权限风险",
                location=0,
                opcode='import',
                evidence_snippets=[
                    f"{s['module']}::{s['name']} (kind={s['kind']})"
                    for s in sensitive_imports
                ]
            ))

        export_count = parser.get_exported_function_count()

        return {
            "contract_type": "wasm",
            "bytecode_length": len(bytecode),
            "bytecode_hash": self._compute_fingerprint(bytecode),
            "magic_valid": parser.magic_valid,
            "export_count": export_count,
            "import_count": len(parser.imports),
            "sensitive_import_count": len(sensitive_imports),
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": 0,
            "medium_severity": sum(
                1 for v in vulnerabilities if v.severity == 'Medium'
            ),
            "low_severity": 0,
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities],
            "imports": parser.imports,
            "exports": parser.exports,
            "tags": [
                f"导出函数: {export_count}",
                f"敏感 import: {len(sensitive_imports)}",
            ],
        }

    def _detect_tx_origin(self, parser: EVMBytecodeParser) -> List[ContractVulnerability]:
        """扫描所有 ORIGIN 指令并上报"""
        vulnerabilities = []

        for instr in parser.get_instructions():
            if instr.mnemonic == 'ORIGIN':
                vulnerabilities.append(ContractVulnerability(
                    vuln_type=VulnerabilityType.TX_ORIGIN,
                    severity='High',
                    confidence=0.9,
                    description="使用 tx.origin 进行身份验证，存在钓鱼攻击面",
                    location=instr.position,
                    opcode='ORIGIN',
                    recommendation="替换为 msg.sender"
                ))

        return vulnerabilities

    def _filter_by_confidence(
        self, vulnerabilities: List[ContractVulnerability]
    ) -> List[ContractVulnerability]:
        """按置信度阈值和最大数量截断漏洞列表"""
        threshold = self._config.get("confidence_threshold", 0.5)
        max_vulns = self._config.get("max_vulns", 100)

        filtered = [v for v in vulnerabilities if v.confidence >= threshold]
        return filtered[:max_vulns]

    def _apply_severity_override(
        self, vulnerabilities: List[ContractVulnerability]
    ) -> List[ContractVulnerability]:
        """应用配置中指定的严重度覆写。

        允许用户根据自身业务模型调整特定漏洞类型的严重等级。
        例如：某个项目的 DELEGATECALL 是设计意图而非漏洞，可降级为 Info。
        """
        overrides = self._config.get("severity_override", {})
        if not overrides:
            return vulnerabilities

        for v in vulnerabilities:
            if v.vuln_type in overrides:
                v.severity = overrides[v.vuln_type]
        return vulnerabilities

    def _serialize_vuln(self, vuln: ContractVulnerability) -> Dict[str, Any]:
        """ContractVulnerability → JSON 兼容 dict。

        同时兼容 vuln_type 为字符串（旧接口）和枚举值（内部增强后）。
        """
        vt = vuln.vuln_type
        type_str = vt.value if hasattr(vt, 'value') else str(vt)

        return {
            "type": type_str,
            "severity": vuln.severity,
            "confidence": vuln.confidence,
            "description": vuln.description,
            "location": hex(vuln.location),
            "opcode": vuln.opcode,
            "recommendation": vuln.recommendation,
            "impact": vuln.impact if vuln.impact else "",
            "evidence": vuln.evidence_snippets if vuln.evidence_snippets else [],
        }

    def _format_text_report(self, report: Dict[str, Any]) -> str:
        """纯文本报告渲染"""
        lines = [
            "Smart Contract Security Analysis Report",
            "=" * 50,
            f"Contract Type: {report['contract_type'].upper()}",
            f"Bytecode Hash: {report.get('bytecode_hash', 'N/A')}",
            f"Total Vulnerabilities: {report['total_vulnerabilities']}",
            f"High/Critical: {report.get('high_severity', 0)}, "
            f"Medium: {report.get('medium_severity', 0)}, "
            f"Low: {report.get('low_severity', 0)}",
            "-" * 50,
        ]

        for i, vuln in enumerate(report.get('vulnerabilities', []), 1):
            lines.append(f"  [{i}] {vuln['type']}")
            lines.append(f"      Severity: {vuln['severity']}, Confidence: {vuln['confidence']:.0%}")
            lines.append(f"      Location: {vuln['location']}, Opcode: {vuln['opcode']}")
            lines.append(f"      {vuln['description']}")
            if vuln.get('impact'):
                lines.append(f"      Impact: {vuln['impact']}")
            if vuln.get('recommendation'):
                lines.append(f"      Fix: {vuln['recommendation']}")

        # 附加标签
        tags = report.get('tags', [])
        if tags:
            lines.append("-" * 50)
            lines.append("Compiler & Structure Hints:")
            for tag in tags:
                lines.append(f"  • {tag}")

        return "\n".join(lines)

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """输入参数合法性校验"""
        bytecode = kwargs.get("bytecode")

        if not bytecode:
            return False, "必须提供 bytecode 参数"

        if not isinstance(bytecode, bytes):
            return False, "bytecode 必须是 bytes 类型"

        return True, None

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """返回分析器元数据 — 平台插件系统要求"""
        return AnalyzerMetadata(
            name="SmartContractAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="智能合约字节码安全分析器",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"])


__all__ = [
    'SmartContractAnalyzer',
    'EVMBytecodeParser',
    'WASMContractParser',
    'ContractType',
    'VulnerabilityType',
    'Severity',
    'TaintSource',
    'ContractVulnerability',
    'EVMInstruction',
    'EVMBasicBlock',
    'ContractFunction',
    'ContractAnalysisReport',
    'AbstractStack',
    'StackSlot',
    'ReentrancyDetector',
    'IntegerOverflowDetector',
    'UncheckedCallDetector',
    'DeprecatedOpcodeDetector',
    'StorageCollisionDetector',
    'GasInefficiencyDetector',
    'FrontRunningDetector',
    'WeakRandomnessDetector',
    'PatternSignatureDetector',
]


def _debug_print(*args, **kwargs):
    pass
