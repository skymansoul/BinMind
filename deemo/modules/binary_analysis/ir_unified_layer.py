import logging
import json
import hashlib
from dataclasses import dataclass, field

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class IROpcode:
    """?? IR ???"""
    # ????
    MOV = "mov"
    LOAD = "load"
    STORE = "store"
    PUSH = "push"
    POP = "pop"
    LEA = "lea"

    # ????
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    MOD = "mod"
    NEG = "neg"

    # ???
    AND = "and"
    OR = "or"
    XOR = "xor"
    NOT = "not"
    SHL = "shl"
    SHR = "shr"
    SAR = "sar"
    ROL = "rol"
    ROR = "ror"

    # ???
    JMP = "jmp"
    JCC = "jcc"
    CALL = "call"
    RET = "ret"
    SYSCALL = "syscall"
    INT = "int"

    # ??
    CMP = "cmp"
    TEST = "test"

    # ??
    ENTER = "enter"
    LEAVE = "leave"

    NOP = "nop"
    UNKNOWN = "c"

class ConditionType:
    # ??????
    EQ = "eq"
    NE = "ne"
    LT = "lt"
    LE = "le"
    GT = "gt"
    GE = "ge"
    BELOW = "below"
    ABOVE = "above"
    OVERFLOW = "overflow"
    SIGN = "sign"
    PARITY = "parity"
    NONE = "c"

class IROperandType:
    # IR ?????
    REGISTER = "register"
    IMMEDIATE = "immediate"
    MEMORY = "memory"
    LABEL = "label"
    STACK_OFFSET = "stack_offset"

@dataclass
class IROperand:
    operand_type: Any = None
    value: Any = None
    size: int = 0
    base_reg: Any = None
    index_reg: Any = None
    scale: Any = None
    displacement: Any = None
    comment: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.operand_type.value,
            "value": self.value if not isinstance(self.value, bytes) else self.value.hex(),
            "size": self.size,
            "base_reg": self.base_reg,
            "index_reg": self.index_reg,
            "scale": self.scale,
            "displacement": self.displacement,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IROperand":
        return cls(
            operand_type=IROperandType(data["type"]),
            value=data.get("value"),
            size=data.get("size", 4),
            base_reg=data.get("base_reg"),
            index_reg=data.get("index_reg"),
            scale=data.get("scale", 1),
            displacement=data.get("displacement", 0),
        )

    @classmethod
    def reg(cls, name: str, size: int = 4) -> "IROperand":
        return cls(operand_type=IROperandType.REGISTER, value=name, size=size)

    @classmethod
    def imm(cls, value: int, size: int = 4) -> "IROperand":
        return cls(operand_type=IROperandType.IMMEDIATE, value=value, size=size)

    @classmethod
    def mem(cls, base: str, disp: int = 0, size: int = 4) -> "IROperand":
        return cls(
            operand_type=IROperandType.MEMORY,
            value=None, size=size,
            base_reg=base, displacement=disp,
        )


class IRInstruction:
    __slots__ = ('opcode', 'operands', 'address', 'condition', 'ir_id', 'metadata',)

    def __init__(self, opcode, operands=None, address=None, condition=ConditionType.NONE, ir_id="", metadata=None):
        self.opcode = opcode
        self.operands = operands
        self.address = address
        self.condition = condition
        self.ir_id = ir_id
        self.metadata = metadata

    def __post_init__(self):
        if not self.ir_id:
            addr_str = hex(self.address) if self.address else "0"
            op_str = self.opcode.value
            self.ir_id = hashlib.md5(
                f"{addr_str}:{op_str}:{len(self.operands)}".encode()
            ).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ir_id": self.ir_id,
            "opcode": self.opcode.value,
            "operands": [op.to_dict() for op in self.operands],
            "address": hex(self.address) if self.address else None,
            "condition": self.condition.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IRInstruction":
        return cls(
            opcode=IROpcode(data["opcode"]),
            operands=[IROperand.from_dict(op) for op in data.get("operands", [])],
            address=int(data["address"], 16) if data.get("address") else None,
            condition=ConditionType(data.get("condition", "none")),
            ir_id=data.get("ir_id", ""),
            metadata=data.get("metadata", {}),
        )

    def is_control_flow(self) -> bool:
        return self.opcode in {
            IROpcode.JMP, IROpcode.JCC, IROpcode.CALL,
            IROpcode.RET, IROpcode.SYSCALL,
        }

    def is_memory_access(self) -> bool:
        return self.opcode in {
            IROpcode.LOAD, IROpcode.STORE,
            IROpcode.PUSH, IROpcode.POP, IROpcode.LEA,
        }


class IRBasicBlock:
    __slots__ = ('block_id', 'address', 'instructions', 'predecessors', 'successors', 'is_entry', 'is_exit', 'metadata',)

    def __init__(self, block_id, address=None, instructions=None, predecessors=None, successors=None, is_entry=False, is_exit=False, metadata=None):
        self.block_id = block_id
        self.address = address
        self.instructions = instructions
        self.predecessors = predecessors
        self.successors = successors
        self.is_entry = is_entry
        self.is_exit = is_exit
        self.metadata = metadata

    def instruction_count(self) -> int:
        return len(self.instructions)

    def contains_call(self) -> bool:
        return any(i.opcode == IROpcode.CALL for i in self.instructions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_id": self.block_id,
            "address": hex(self.address) if self.address else None,
            "instructions": [i.to_dict() for i in self.instructions],
            "predecessors": self.predecessors,
            "successors": self.successors,
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IRBasicBlock":
        return cls(
            block_id=data["block_id"],
            address=int(data["address"], 16) if data.get("address") else None,
            instructions=[IRInstruction.from_dict(i)
                         for i in data.get("instructions", [])],
            predecessors=data.get("predecessors", []),
            successors=data.get("successors", []),
            is_entry=data.get("is_entry", False),
            is_exit=data.get("is_exit", False),
            metadata=data.get("metadata", {}),
        )


class IRFunction:
    __slots__ = ('name', 'address', 'basic_blocks', 'entry_block_id', 'arguments', 'return_type', 'metadata',)

    def __init__(self, name, address=None, basic_blocks=None, entry_block_id="", arguments=None, return_type="void", metadata=None):
        self.name = name
        self.address = address
        self.basic_blocks = basic_blocks
        self.entry_block_id = entry_block_id
        self.arguments = arguments
        self.return_type = return_type
        self.metadata = metadata

    def total_instructions(self) -> int:
        return sum(bb.instruction_count() for bb in self.basic_blocks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": hex(self.address) if self.address else None,
            "basic_blocks": [bb.to_dict() for bb in self.basic_blocks],
            "entry_block_id": self.entry_block_id,
            "arguments": self.arguments,
            "return_type": self.return_type,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IRFunction":
        return cls(
            name=data["name"],
            address=int(data["address"], 16) if data.get("address") else None,
            basic_blocks=[IRBasicBlock.from_dict(bb)
                         for bb in data.get("basic_blocks", [])],
            entry_block_id=data.get("entry_block_id", ""),
            arguments=data.get("arguments", []),
            return_type=data.get("return_type", "void"),
            metadata=data.get("metadata", {}),
        )


class IRStatistics:
    __slots__ = ('total_functions', 'total_blocks', 'total_instructions', 'opcode_distribution', 'control_flow_count', 'memory_access_count', 'call_count', 'avg_block_size', 'max_block_size',)

    def __init__(self, total_functions=0, total_blocks=0, total_instructions=0, opcode_distribution=None, control_flow_count=0, memory_access_count=0, call_count=0, avg_block_size=0.0, max_block_size=0):
        self.total_functions = total_functions
        self.total_blocks = total_blocks
        self.total_instructions = total_instructions
        self.opcode_distribution = opcode_distribution
        self.control_flow_count = control_flow_count
        self.memory_access_count = memory_access_count
        self.call_count = call_count
        self.avg_block_size = avg_block_size
        self.max_block_size = max_block_size


class IRUnifiedLayer(BaseAnalyzer):
    """
    ??????????

    ?????
    1. ????/????????? IR
    2. IR ??? JSON ?????
    3. ???????????????
    4. IR ?? Pass ??
    5. ???/??? IR ?????
    """

    ARCH_REGISTERS = {
        "x86": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"],
        "x86_64": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"],
        "arm": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"],
        "arm64": [f"x{i}" for i in range(31)] + ["sp", "lr", "fp"],
        "mips": ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
                 "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
                 "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                 "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"],
    }

    DISASM_OPCODE_MAP = {
        "mov": IROpcode.MOV, "movsx": IROpcode.MOV, "movzx": IROpcode.MOV,
        "lea": IROpcode.LEA,
        "add": IROpcode.ADD, "sub": IROpcode.SUB, "mul": IROpcode.MUL,
        "imul": IROpcode.MUL, "div": IROpcode.DIV, "idiv": IROpcode.DIV,
        "and": IROpcode.AND, "or": IROpcode.OR, "xor": IROpcode.XOR,
        "not": IROpcode.NOT, "neg": IROpcode.NEG,
        "shl": IROpcode.SHL, "shr": IROpcode.SHR, "sar": IROpcode.SAR,
        "rol": IROpcode.ROL, "ror": IROpcode.ROR,
        "push": IROpcode.PUSH, "pop": IROpcode.POP,
        "jmp": IROpcode.JMP, "j": IROpcode.JCC, "je": IROpcode.JCC,
        "jne": IROpcode.JCC, "jg": IROpcode.JCC, "jl": IROpcode.JCC,
        "call": IROpcode.CALL, "ret": IROpcode.RET,
        "cmp": IROpcode.CMP, "test": IROpcode.TEST,
        "nop": IROpcode.NOP, "syscall": IROpcode.SYSCALL,
        "int": IROpcode.INT, "enter": IROpcode.ENTER, "leave": IROpcode.LEAVE,
    }

    CONDITION_MAP = {
        "je": ConditionType.EQ, "jz": ConditionType.EQ,
        "jne": ConditionType.NE, "jnz": ConditionType.NE,
        "jg": ConditionType.GT, "jge": ConditionType.GE,
        "jl": ConditionType.LT, "jle": ConditionType.LE,
        "ja": ConditionType.ABOVE, "jae": ConditionType.GE,
        "jb": ConditionType.BELOW, "jbe": ConditionType.LE,
        "jo": ConditionType.OVERFLOW, "js": ConditionType.SIGN,
        "jp": ConditionType.PARITY,
    }

    def __init__(self):
        self._ir_functions: Dict[str, IRFunction] = {}
        self._current_arch: str = "x86_64"

    def _parse_operand(self, operand_text: str, arch: str) -> IROperand:
        text = operand_text.strip().strip(",")
        if "[" in text and "]" in text:
            return self._parse_memory_operand(text.strip("[]"))
        if text.startswith("0x") or text.startswith("0X"):
            try:
                return IROperand.imm(int(text, 16))
            except ValueError:
                pass
            return IROperand.imm(0)
        if text.lstrip("-").isdigit():
            return IROperand.imm(int(text))
        regs = self.ARCH_REGISTERS.get(arch, [])
        if text.lower() in [r.lower() for r in regs]:
            return IROperand.reg(text.lower())
        return IROperand(operand_type=IROperandType.LABEL, value=text, size=4)

    def _parse_memory_operand(self, inner: str) -> IROperand:
        base_reg = None
        index_reg = None
        scale = 1
        displacement = 0
        parts = inner.replace("+", " + ").replace("-", " - ").split()
        sign = 1
        for part in parts:
            part = part.strip()
            if part == "+":
                sign = 1
            elif part == "-":
                sign = -1
            elif "*" in part:
                sub = part.split("*")
                if len(sub) == 2:
                    index_reg = sub[0].strip()
                    try:
                        scale = int(sub[1].strip())
                    except ValueError:
                        pass
                    scale = 1
            elif part.isdigit() or (
                part.startswith("0x") and all(c in "0123456789abcdefABCDEFx" for c in part)
            ):
                try:
                    displacement += sign * int(part, 16 if "0x" in part else 10)
                except ValueError:
                    pass
            else:
                if base_reg is None:
                    base_reg = part
                else:
                    index_reg = part
        return IROperand(
            operand_type=IROperandType.MEMORY, value=None, size=4,
            base_reg=base_reg, index_reg=index_reg, scale=scale,
            displacement=displacement,
        )

    def lift_to_ir(
        self,
        disassembly_lines: List[str],
        arch: str = "x86_64",
        base_address: int = 0x0,
    ) -> IRFunction:
        """
        ??????????? IR ??
        """
        self._current_arch = arch
        instructions: List[IRInstruction] = []
        block_boundaries: Set[int] = set()
        current_address = base_address

        for line in disassembly_lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            parts = line.split()
            if not parts:
                continue

            inst_offset = 0
            try:
                addr_str = parts[0].rstrip(":")
                if all(c in "0123456789abcdefABCDEF" for c in addr_str):
                    current_address = int(addr_str, 16)
                    inst_offset = 1
            except ValueError:
                pass

            opcode_text = parts[inst_offset].lower() if inst_offset < len(parts) else ""
            operands_text = parts[inst_offset + 1:] if inst_offset + 1 < len(parts) else []

            ir_opcode = self.DISASM_OPCODE_MAP.get(opcode_text, IROpcode.UNKNOWN)
            if ir_opcode == IROpcode.UNKNOWN:
                for prefix, code in self.DISASM_OPCODE_MAP.items():
                    if opcode_text.startswith(prefix) and prefix in ("j", "call"):
                        ir_opcode = code
                        break

            condition = ConditionType.NONE
            if ir_opcode == IROpcode.JCC and opcode_text.startswith("j"):
                condition = self.CONDITION_MAP.get(opcode_text, ConditionType.NONE)

            operands = []
            combined_ops = " ".join(operands_text).split(",")
            for op_text in combined_ops:
                op_text = op_text.strip()
                if op_text:
                    operands.append(self._parse_operand(op_text, arch))

            inst = IRInstruction(
                opcode=ir_opcode, operands=operands,
                address=current_address, condition=condition,
                metadata={"arch": arch, "raw": line},
            )
            instructions.append(inst)

            if inst.is_control_flow():
                block_boundaries.add(len(instructions))

            current_address += 4

        basic_blocks = self._build_basic_blocks(instructions, block_boundaries)
        func = IRFunction(
            name="lifted_function", address=base_address,
            basic_blocks=basic_blocks,
        )
        if basic_blocks:
            func.entry_block_id = basic_blocks[0].block_id

        self._ir_functions[func.name] = func
        logger.info(
            f"IR ????: {func.name}, {len(basic_blocks)} BB, "
            f"{func.total_instructions()} ??"
        )
        return func

    def _build_basic_blocks(
        self, instructions: List[IRInstruction], boundaries: Set[int]
    ) -> List[IRBasicBlock]:
        if not instructions:
            return []

        for i, inst in enumerate(instructions):
            if inst.is_control_flow() and i + 1 < len(instructions):
                boundaries.add(i + 1)
            for op in inst.operands:
                if op.operand_type == IROperandType.LABEL:
                    boundaries.add(i)

        sorted_b = sorted(boundaries)
        sorted_b = [0] + [b for b in sorted_b if b > 0]
        if sorted_b[-1] < len(instructions):
            sorted_b.append(len(instructions))

        blocks = []
        for idx, start in enumerate(sorted_b[:-1]):
            end = sorted_b[idx + 1]
            block_insts = instructions[start:end]
            if not block_insts:
                continue

            block = IRBasicBlock(
                block_id=f"bb_{idx}",
                address=block_insts[0].address,
                instructions=block_insts,
                is_entry=(idx == 0),
            )

            last = block_insts[-1]
            if last.opcode in (IROpcode.JMP, IROpcode.RET):
                pass
            elif last.opcode == IROpcode.JCC:
                if idx + 1 < len(sorted_b) - 1:
                    block.successors.append(f"bb_{idx + 1}")
            elif not last.is_control_flow():
                if idx + 1 < len(sorted_b) - 1:
                    block.successors.append(f"bb_{idx + 1}")
            blocks.append(block)

        for i, block in enumerate(blocks):
            for succ_id in block.successors:
                for succ_block in blocks:
                    if succ_block.block_id == succ_id:
                        succ_block.predecessors.append(block.block_id)

        return blocks

    def ir_to_json(self, ir_func: IRFunction, indent: int = 2) -> str:
        return json.dumps(ir_func.to_dict(), indent=indent, ensure_ascii=False)

    def ir_from_json(self, json_str: str) -> IRFunction:
        data = json.loads(json_str)
        func = IRFunction.from_dict(data)
        self._ir_functions[func.name] = func
        return func

    def ir_basic_block_structure(self, ir_func: IRFunction) -> Dict[str, Any]:
        blocks_info = []
        back_edges = []

        for block in ir_func.basic_blocks:
            for succ in block.successors:
                for pred in ir_func.basic_blocks:
                    if pred.block_id == succ:
                        if (block.address is not None and pred.address is not None
                                and pred.address <= block.address):
                            back_edges.append({
                                "from": block.block_id, "to": succ,
                                "type": "potential_loop_backedge",
                            })
            blocks_info.append({
                "block_id": block.block_id,
                "address": hex(block.address) if block.address else None,
                "instruction_count": block.instruction_count(),
                "predecessors": block.predecessors,
                "successors": block.successors,
                "is_entry": block.is_entry,
                "contains_call": block.contains_call(),
                "last_instruction": (
                    block.instructions[-1].opcode.value if block.instructions else "empty"
                ),
            })

        entry_blocks = [b.block_id for b in ir_func.basic_blocks if b.is_entry]
        exit_blocks = [b.block_id for b in ir_func.basic_blocks
                       if b.is_exit or not b.successors]

        return {
            "function_name": ir_func.name,
            "total_blocks": len(ir_func.basic_blocks),
            "entry_blocks": entry_blocks,
            "exit_blocks": exit_blocks,
            "back_edges": back_edges,
            "back_edge_count": len(back_edges),
            "blocks": blocks_info,
            "cfg_complexity": self._estimate_cfg_complexity(ir_func),
        }

    def _estimate_cfg_complexity(self, ir_func: IRFunction) -> str:
        edges = sum(len(b.successors) for b in ir_func.basic_blocks)
        nodes = len(ir_func.basic_blocks)
        if nodes <= 1:
            return "trivial"
        ratio = edges / nodes if nodes else 0
        if ratio < 1.1:
            return "linear"
        if ratio < 1.5:
            return "simple"
        if ratio < 2.5:
            return "moderate"
        return "complex"

    def ir_optimization_passes(
        self, ir_func: IRFunction, passes: Optional[List[str]] = None
    ) -> IRFunction:
        all_passes = ["constant_folding", "dead_code_elimination", "peephole"]
        selected = passes or all_passes
        optimization_count = 0
        for block in ir_func.basic_blocks:
            if "constant_folding" in selected:
                optimization_count += self._constant_folding(block)
            if "dead_code_elimination" in selected:
                optimization_count += self._dead_code_elimination(block)
            if "peephole" in selected:
                optimization_count += self._peephole_optimize(block)
        logger.info(
            f"IR ????: {ir_func.name}, {optimization_count} ???, passes={selected}"
        )
        return ir_func

    def _constant_folding(self, block: IRBasicBlock) -> int:
        folded = 0
        foldable = {IROpcode.ADD, IROpcode.SUB, IROpcode.MUL,
                    IROpcode.AND, IROpcode.OR, IROpcode.XOR,
                    IROpcode.SHL, IROpcode.SHR}
        for inst in block.instructions:
            if inst.opcode not in foldable:
                continue
            imm_ops = [op for op in inst.operands
                      if op.operand_type == IROperandType.IMMEDIATE]
            if len(imm_ops) < 2:
                continue
            try:
                a, b = imm_ops[0].value, imm_ops[1].value
                result = {
                    IROpcode.ADD: a + b, IROpcode.SUB: a - b,
                    IROpcode.MUL: a * b, IROpcode.AND: a & b,
                    IROpcode.OR: a | b, IROpcode.XOR: a ^ b,
                    IROpcode.SHL: a << b, IROpcode.SHR: a >> b,
                }.get(inst.opcode)
                if result is not None:
                    inst.operands = [IROperand.imm(result)]
                    inst.opcode = IROpcode.MOV
                    inst.metadata["folded"] = True
                    folded += 1
            except Exception:
                logger.debug("suppressed", exc_info=True)
        return folded

    def _dead_code_elimination(self, block: IRBasicBlock) -> int:
        eliminated = 0
        used_regs: Set[str] = set()
        for inst in reversed(block.instructions):
            for op in inst.operands:
                if op.operand_type == IROperandType.REGISTER:
                    used_regs.add(op.value)
            if inst.opcode in (IROpcode.MOV, IROpcode.LEA, IROpcode.LOAD):
                dests = inst.operands[:1]
                for d in dests:
                    if (d.operand_type == IROperandType.REGISTER
                            and d.value not in used_regs):
                        inst.metadata["dead"] = True
                        eliminated += 1
            if inst.opcode == IROpcode.NOP:
                inst.metadata["dead"] = True
                eliminated += 1

        kept = [inst for inst in block.instructions if not inst.metadata.get("dead")]
        if eliminated > 0:
            block.instructions = kept
        return eliminated

    def _peephole_optimize(self, block: IRBasicBlock) -> int:
        optimized = 0
        i = 0
        while i < len(block.instructions) - 1:
            cur = block.instructions[i]
            nxt = block.instructions[i + 1]
            if (cur.opcode == IROpcode.PUSH and nxt.opcode == IROpcode.POP
                    and cur.operands == nxt.operands):
                nxt.opcode = IROpcode.NOP
                nxt.metadata["dead"] = True
                optimized += 1
            if (cur.opcode == IROpcode.MOV and nxt.opcode == IROpcode.MOV
                    and cur.operands[0:1] == nxt.operands[0:1]):
                cur.metadata["dead"] = True
                optimized += 1
            i += 1
        kept = [inst for inst in block.instructions if not inst.metadata.get("dead")]
        if len(kept) < len(block.instructions):
            block.instructions = kept
        return optimized

    def compare_ir(self, ir_a: IRFunction, ir_b: IRFunction) -> Dict[str, Any]:
        a_blocks = len(ir_a.basic_blocks)
        b_blocks = len(ir_b.basic_blocks)
        block_similarity = min(a_blocks, b_blocks) / max(a_blocks, b_blocks, 1)

        a_opcodes = self._opcode_distribution(ir_a)
        b_opcodes = self._opcode_distribution(ir_b)
        opcode_similarity = self._cosine_similarity(a_opcodes, b_opcodes)

        a_seq = [inst.opcode.value for bb in ir_a.basic_blocks
                for inst in bb.instructions]
        b_seq = [inst.opcode.value for bb in ir_b.basic_blocks
                for inst in bb.instructions]
        edit_dist = self._edit_distance(a_seq, b_seq)
        max_len = max(len(a_seq), len(b_seq), 1)
        seq_similarity = 1.0 - (edit_dist / max_len)

        overall = 0.3 * block_similarity + 0.35 * opcode_similarity + 0.35 * seq_similarity

        return {
            "function_a": ir_a.name, "function_b": ir_b.name,
            "a_instructions": len(a_seq), "b_instructions": len(b_seq),
            "block_similarity": round(block_similarity, 4),
            "opcode_similarity": round(opcode_similarity, 4),
            "sequence_similarity": round(seq_similarity, 4),
            "overall_similarity": round(overall, 4),
            "likely_equivalent": overall > 0.85,
        }

    def _opcode_distribution(self, ir_func: IRFunction) -> Dict[str, int]:
        dist: Dict[str, int] = {}
        for bb in ir_func.basic_blocks:
            for inst in bb.instructions:
                op = inst.opcode.value
                dist[op] = dist.get(op, 0) + 1
        return dist

    def _cosine_similarity(self, d1: Dict[str, int], d2: Dict[str, int]) -> float:
        all_keys = set(d1.keys()) | set(d2.keys())
        v1 = [d1.get(k, 0) for k in all_keys]
        v2 = [d2.get(k, 0) for k in all_keys]
        dot = sum(a * b for a, b in zip(v1, v2))
        mag1 = (sum(a * a for a in v1)) ** 0.5
        mag2 = (sum(b * b for b in v2)) ** 0.5
        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    def _edit_distance(self, seq_a: List[str], seq_b: List[str]) -> int:
        m, n = len(seq_a), len(seq_b)
        prev = list(range(n + 1))
        curr = [0] * (n + 1)
        for i in range(1, m + 1):
            curr[0] = i
            for j in range(1, n + 1):
                cost = 0 if seq_a[i - 1] == seq_b[j - 1] else 1
                curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            prev, curr = curr, prev
        return prev[n]

    def get_ir_statistics(self, ir_func: Optional[IRFunction] = None) -> IRStatistics:
        funcs = [ir_func] if ir_func else list(self._ir_functions.values())
        stats = IRStatistics(total_functions=len(funcs))
        for func in funcs:
            stats.total_blocks += len(func.basic_blocks)
            for bb in func.basic_blocks:
                stats.total_instructions += bb.instruction_count()
                for inst in bb.instructions:
                    op = inst.opcode.value
                    stats.opcode_distribution[op] = (
                        stats.opcode_distribution.get(op, 0) + 1
                    )
                    if inst.is_control_flow():
                        stats.control_flow_count += 1
                    if inst.is_memory_access():
                        stats.memory_access_count += 1
                    if inst.opcode == IROpcode.CALL:
                        stats.call_count += 1
        if stats.total_blocks > 0:
            stats.avg_block_size = stats.total_instructions / stats.total_blocks
            stats.max_block_size = max(
                bb.instruction_count()
                for func in funcs for bb in func.basic_blocks
            )
        return stats

    def analyze(self, **kwargs) -> Dict[str, Any]:
        action = kwargs.get("action", "lift")
        try:
            if action == "lift":
                lines = kwargs.get("disassembly_lines", [])
                if not lines:
                    return {"success": False, "error": "disassembly_lines ??????"}
                arch = kwargs.get("arch", "x86_64")
                base = kwargs.get("base_address", 0x0)
                ir_func = self.lift_to_ir(lines, arch, base)
                return {
                    "success": True, "function_name": ir_func.name,
                    "basic_blocks": len(ir_func.basic_blocks),
                    "total_instructions": ir_func.total_instructions(),
                    "ir": ir_func.to_dict(),
                }

            elif action == "to_json":
                ir_func = kwargs.get("ir_func")
                if ir_func is None:
                    return {"success": False, "error": "ir_func ??????"}
                return {"success": True, "json": self.ir_to_json(ir_func)}

            elif action == "from_json":
                json_str = kwargs.get("json_str", "")
                if not json_str:
                    return {"success": False, "error": "json_str ??????"}
                ir_func = self.ir_from_json(json_str)
                return {
                    "success": True, "function_name": ir_func.name,
                    "basic_blocks": len(ir_func.basic_blocks),
                }

            elif action == "structure":
                ir_func = kwargs.get("ir_func")
                if ir_func is None:
                    return {"success": False, "error": "ir_func ??????"}
                return {"success": True, "structure": self.ir_basic_block_structure(ir_func)}

            elif action == "optimize":
                ir_func = kwargs.get("ir_func")
                if ir_func is None:
                    return {"success": False, "error": "ir_func ??????"}
                passes = kwargs.get("passes")
                optimized = self.ir_optimization_passes(ir_func, passes)
                return {
                    "success": True, "function_name": optimized.name,
                    "total_instructions": optimized.total_instructions(),
                    "ir": optimized.to_dict(),
                }

            elif action == "compare":
                ir_a = kwargs.get("ir_func_a")
                ir_b = kwargs.get("ir_func_b")
                if ir_a is None or ir_b is None:
                    return {"success": False, "error": "ir_func_a ? ir_func_b ?????"}
                return {"success": True, "comparison": self.compare_ir(ir_a, ir_b)}

            elif action == "stats":
                ir_func = kwargs.get("ir_func")
                stats = self.get_ir_statistics(ir_func)
                return {
                    "success": True,
                    "statistics": {
                        "total_functions": stats.total_functions,
                        "total_blocks": stats.total_blocks,
                        "total_instructions": stats.total_instructions,
                        "control_flow_count": stats.control_flow_count,
                        "memory_access_count": stats.memory_access_count,
                        "call_count": stats.call_count,
                        "avg_block_size": round(stats.avg_block_size, 2),
                        "max_block_size": stats.max_block_size,
                        "opcode_distribution": stats.opcode_distribution,
                    },
                }

            else:
                return {"success": False, "error": f"????: {action}"}

        except Exception as e:
            logger.error(f"IR ???????: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="IRUnifiedLayer",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="????????????????????????IR?????Pass?????????",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64", "mips"],
        )


def unify_ir_layer(**kwargs) -> Dict[str, Any]:
    return IRUnifiedLayer().analyze(**kwargs)

__all__ = ["IRUnifiedLayer", "unify_ir_layer"]
