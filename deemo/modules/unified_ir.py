"""
二进制中间语言统一抽象层 (VEX/Pcode/LLVM IR) 模块

功能:
    1. 设计统一的中间表示 (IR), 将 radare2 ESIL / Ghidra Pcode / Binary Ninja LLIL
       等映射到同一套语义指令集
    2. 跨引擎分析算法 (污点追踪 / 漏洞模式匹配) 基于统一 IR 编写
    3. 降低引擎依赖

核心技术:
    - IR 指令 (IRInstruction) + 基本块 (IRBlock) + 函数 (IRFunction)
    - 操作数: 寄存器/内存/立即数/标签
    - 多种后端适配器: r2 ESIL / Ghidra Pcode / LLIL
"""

import logging
import os
import re
import json
from typing import Dict, Any, List, Optional, Tuple, Set, Iterator
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class IROpcode(Enum):
    """统一 IR 操作码"""
    NOP = "nop"
    MOV = "mov"
    LOAD = "load"        # 从内存读
    STORE = "store"      # 写内存
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    MOD = "mod"
    AND = "and"
    OR = "or"
    XOR = "xor"
    SHL = "shl"
    SHR = "shr"
    CMP_EQ = "cmp_eq"
    CMP_NE = "cmp_ne"
    CMP_LT = "cmp_lt"
    CMP_LE = "cmp_le"
    CMP_GT = "cmp_gt"
    CMP_GE = "cmp_ge"
    JMP = "jmp"
    JMP_COND = "jmp_cond"
    CALL = "call"
    RET = "ret"
    PUSH = "push"
    POP = "pop"
    PHI = "phi"
    SYSCALL = "syscall"
    INTRINSIC = "intrinsic"
    UNKNOWN = "unknown"


class OperandKind(Enum):
    REGISTER = "register"
    MEMORY = "memory"
    IMMEDIATE = "immediate"
    LABEL = "label"
    TEMP = "temp"


@dataclass
class IROperand:
    """统一 IR 操作数"""
    kind: OperandKind
    value: Any             # 寄存器名 / 内存表达式 / 立即数值 / 标签 / 临时变量 id
    size: int = 8          # 位数 (8/16/32/64)

    def to_dict(self) -> Dict[str, Any]:
        return {'kind': self.kind.value, 'value': self.value, 'size': self.size}


@dataclass
class IRInstruction:
    """统一 IR 指令"""
    opcode: IROpcode
    operands: List[IROperand] = field(default_factory=list)
    address: int = 0
    raw: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'opcode': self.opcode.value,
            'operands': [op.to_dict() for op in self.operands],
            'address': hex(self.address),
            'raw': self.raw[:120]
        }


@dataclass
class IRBlock:
    """基本块"""
    block_id: str
    start_addr: int
    end_addr: int
    instructions: List[IRInstruction] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)
    predecessors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'block_id': self.block_id,
            'start': hex(self.start_addr),
            'end': hex(self.end_addr),
            'instructions': [i.to_dict() for i in self.instructions],
            'successors': self.successors,
            'predecessors': self.predecessors
        }


@dataclass
class IRFunction:
    """函数级 IR"""
    name: str
    address: int
    blocks: Dict[str, IRBlock] = field(default_factory=dict)
    entry_block: Optional[str] = None
    arch: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': hex(self.address),
            'entry': self.entry_block,
            'arch': self.arch,
            'blocks': {bid: b.to_dict() for bid, b in self.blocks.items()}
        }


# ============= 后端适配器 =============

class IRBackend:
    """IR 后端基类"""
    NAME = "base"

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        raise NotImplementedError

    def supported(self) -> bool:
        return True


class R2ESILBackend(IRBackend):
    """radare2 ESIL 后端"""

    NAME = "r2_esil"

    ESIL_MAP = {
        "mov": IROpcode.MOV,
        "lea": IROpcode.MOV,
        "add": IROpcode.ADD,
        "sub": IROpcode.SUB,
        "mul": IROpcode.MUL,
        "div": IROpcode.DIV,
        "and": IROpcode.AND,
        "or": IROpcode.OR,
        "xor": IROpcode.XOR,
        "shl": IROpcode.SHL,
        "shr": IROpcode.SHR,
        "cmp": IROpcode.CMP_EQ,
        "test": IROpcode.CMP_EQ,
        "jmp": IROpcode.JMP,
        "cjmp": IROpcode.JMP_COND,
        "ujmp": IROpcode.JMP,
        "call": IROpcode.CALL,
        "ret": IROpcode.RET,
        "push": IROpcode.PUSH,
        "pop": IROpcode.POP,
        "syscall": IROpcode.SYSCALL,
    }

    def __init__(self, r2_path: str = "r2"):
        self.r2_path = r2_path

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        import subprocess
        try:
            cmd = [self.r2_path, '-q', '-c', f'pdf @ {func_name}; q', binary_path]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                               encoding='utf-8', errors='replace')
        except Exception as e:
            logger.warning(f"r2 提升失败: {e}")
            return IRFunction(name=func_name, address=0)
        ir_fn = IRFunction(name=func_name, address=0)
        current_block = IRBlock(block_id="entry", start_addr=0, end_addr=0)
        for line in r.stdout.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                continue
            m = re.match(r"0x([0-9a-f]+)\s+(\S+)(.*)", stripped)
            if not m:
                continue
            addr = int(m.group(1), 16)
            mnem = m.group(2).lower()
            ops_str = m.group(3).strip()
            opcode = self.ESIL_MAP.get(mnem, IROpcode.UNKNOWN)
            operands = self._parse_operands(ops_str)
            ir_ins = IRInstruction(
                opcode=opcode,
                operands=operands,
                address=addr,
                raw=stripped
            )
            current_block.instructions.append(ir_ins)
        if current_block.instructions:
            ir_fn.blocks["entry"] = current_block
            ir_fn.entry_block = "entry"
        return ir_fn

    def _parse_operands(self, ops_str: str) -> List[IROperand]:
        result: List[IROperand] = []
        if not ops_str:
            return result
        for op in re.split(r",\s*", ops_str):
            op = op.strip()
            if not op:
                continue
            if op.startswith("0x") or op.lstrip("-").isdigit():
                try:
                    val = int(op, 0) if op.startswith("0x") else int(op)
                    result.append(IROperand(OperandKind.IMMEDIATE, val, 32))
                except ValueError:
                    pass
            elif op.startswith("[") and op.endswith("]"):
                inner = op[1:-1]
                result.append(IROperand(OperandKind.MEMORY, inner, 64))
            else:
                result.append(IROperand(OperandKind.REGISTER, op, 64))
        return result


class GhidraPcodeBackend(IRBackend):
    """Ghidra Pcode 后端 (占位: 需 Ghidra 环境)"""

    NAME = "ghidra_pcode"

    def supported(self) -> bool:
        return False

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        logger.warning("Ghidra 后端未实现, 返回空 IR")
        return IRFunction(name=func_name, address=0)


class BinaryNinjaLLILBackend(IRBackend):
    """Binary Ninja LLIL 后端 (占位: 需 binaryninja 绑定)"""

    NAME = "binja_llil"

    def supported(self) -> bool:
        return False

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        logger.warning("Binary Ninja 后端未实现, 返回空 IR")
        return IRFunction(name=func_name, address=0)


class UnifiedIRLifter:
    """统一 IR 提升器"""

    def __init__(self, prefer: str = "r2"):
        self.backends: Dict[str, IRBackend] = {
            "r2": R2ESILBackend(),
            "ghidra": GhidraPcodeBackend(),
            "binja": BinaryNinjaLLILBackend()
        }
        self.prefer = prefer if self.backends[prefer].supported() else "r2"

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        backend = self.backends[self.prefer]
        return backend.lift(binary_path, func_name)


# ============= 跨引擎分析: 污点追踪 =============

class TaintState:
    """污点状态"""

    def __init__(self):
        self.tainted: Set[str] = set()
        self.propagations: List[Dict[str, Any]] = []

    def add(self, name: str, source: str = "input"):
        self.tainted.add(name)
        self.propagations.append({'op': 'add', 'var': name, 'source': source})

    def is_tainted(self, name: str) -> bool:
        return name in self.tainted

    def propagate(self, src: str, dst: str):
        if src in self.tainted and dst not in self.tainted:
            self.tainted.add(dst)
            self.propagations.append({'op': 'prop', 'src': src, 'dst': dst})


def taint_track(ir: IRFunction, source_ops: List[str],
                sink_ops: Optional[List[str]] = None) -> TaintState:
    """基于统一 IR 做污点追踪"""
    state = TaintState()
    sink_ops = sink_ops or ["call", "store", "syscall"]
    for op_name in source_ops:
        state.add(op_name, source="user_input")
    for bid, block in ir.blocks.items():
        for ins in block.instructions:
            if ins.opcode == IROpcode.LOAD and ins.operands:
                if ins.operands[0].value in state.tainted:
                    for op in ins.operands[1:]:
                        state.propagate(ins.operands[0].value, str(op.value))
            elif ins.opcode == IROpcode.MOV and len(ins.operands) >= 2:
                src = str(ins.operands[0].value)
                dst = str(ins.operands[1].value)
                state.propagate(src, dst)
            elif ins.opcode == IROpcode.ADD and len(ins.operands) >= 2:
                if any(str(o.value) in state.tainted for o in ins.operands[:2]):
                    for op in ins.operands[2:]:
                        state.add(str(op.value), source="arith")
            elif ins.opcode.value in sink_ops and ins.operands:
                for op in ins.operands:
                    if str(op.value) in state.tainted:
                        state.propagations.append({
                            'op': 'sink_reach',
                            'sink': ins.opcode.value,
                            'var': str(op.value),
                            'address': hex(ins.address)
                        })
    return state


# ============= 漏洞模式匹配 =============

PATTERN_BUFFER_OVERFLOW = {
    'name': 'buffer_overflow_pattern',
    'sequence': [
        (IROpcode.LOAD, 'src'),
        (IROpcode.CMP_EQ, None),  # 简单长度检查 (可选)
        (IROpcode.STORE, 'dst')    # 写入
    ]
}


def match_vuln_patterns(ir: IRFunction) -> List[Dict[str, Any]]:
    """简单漏洞模式匹配"""
    findings = []
    for bid, block in ir.blocks.items():
        ins_list = block.instructions
        for i in range(len(ins_list) - 2):
            a, b, c = ins_list[i], ins_list[i+1], ins_list[i+2]
            if (a.opcode == IROpcode.LOAD and
                c.opcode == IROpcode.STORE and
                b.opcode != IROpcode.CMP_EQ):
                findings.append({
                    'pattern': 'possible_overflow_no_bounds',
                    'block': bid,
                    'addresses': [hex(a.address), hex(b.address), hex(c.address)]
                })
    return findings


def lift_and_analyze(binary_path: str, func_name: str,
                     prefer: str = "r2") -> Dict[str, Any]:
    """便捷入口: 提升 IR 并做污点 + 模式分析"""
    lifter = UnifiedIRLifter(prefer=prefer)
    ir = lifter.lift(binary_path, func_name)
    taint = taint_track(ir, source_ops=["rdi", "rsi", "rdx", "rcx", "r8", "r9"])
    patterns = match_vuln_patterns(ir)
    return {
        'success': True,
        'ir': ir.to_dict(),
        'taint': {
            'tainted_count': len(taint.tainted),
            'propagations': taint.propagations[:50]
        },
        'patterns': patterns
    }
