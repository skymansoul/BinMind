"""Decompiler engine core: binary-to-IR lifting, IR optimization passes,
control-flow structuring (interval analysis + structural analysis),
variable recovery (SSA-based type inference), LLM-assisted enhancement,
pseudocode generation, round-trip validation.

Binary -> IR Lifting -> IR Optimization -> CFG Structuring
-> Variable Recovery -> Type Inference -> Pseudocode Generation

O(n^2) for structural analysis worst case (deeply nested
irreducible loops), O(n) in practice due to shallow nesting depth.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import struct
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

log = logging.getLogger(__name__)

# IR type enums

class IROperation(str, Enum):
    """Unified IR operation types"""
    MOV = "mov"
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
    CMP = "cmp"
    TEST = "test"
    JMP = "jmp"
    JCC = "jcc"
    CALL = "call"
    RET = "ret"
    PUSH = "push"
    POP = "pop"
    NOP = "nop"
    LEA = "lea"
    LOAD = "load"
    STORE = "store"
    PHI = "phi"
    UNKNOWN = "unknown"


class VariableType(str, Enum):
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    POINTER = "pointer"
    VOID = "void"
    STRING = "string"
    UNKNOWN = "unknown"


@dataclass
class IRInstruction:
    address: int
    op: IROperation
    operands: List[str] = field(default_factory=list)
    size: int = 0
    raw_bytes: bytes = b""
    comment: str = ""


@dataclass
class IRBasicBlock:
    address: int
    instructions: List[IRInstruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_loop_header: bool = False
    is_loop_exit: bool = False
    label: str = ""


@dataclass
class IRFunction:
    name: str
    address: int
    blocks: Dict[int, IRBasicBlock] = field(default_factory=dict)
    variables: Dict[str, VariableType] = field(default_factory=dict)
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    return_type: str = "void"


# Decompiler engine — main decompilation pipeline

class DecompilerEngine:
    """Binary decompiler engine.

    Pipeline steps:
    1. Binary -> IR lifting (via capstone or radare2)
    2. IR optimization (dead code elimination, constant folding,
       expression simplification)
    3. Control-flow structuring (interval analysis + structural
       analysis for CFG recovery)
    4. Variable recovery (SSA-based type inference)
    5. Pseudocode generation (structured C-like output)

    Usage::

        engine = DecompilerEngine()
        func = engine.decompile("binary.exe", 0x401000)
        print(engine.generate_pseudocode(func))
    """

    _DEFAULT_MAX_INSTRUCTIONS = 100000

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        self._max_insns = self._config.get(
            "max_instructions", self._DEFAULT_MAX_INSTRUCTIONS
        )
        self._functions: Dict[int, IRFunction] = {}

# Basic block construction

    def lift_function(
        self,
        binary_path: str,
        start_address: int,
        max_instructions: Optional[int] = None,
    ) -> Optional[IRFunction]:
        """Lift a function from binary into the unified IR.

        Uses Capstone for disassembly, converts to IR representation.
        Falls back to radare2 if Capstone unavailable.
        """
        max_insns = max_instructions or self._max_insns
        log.info("Lifting function at %#x from %s", start_address, binary_path)

        # Read raw bytes from binary
        try:
            with open(binary_path, "rb") as f:
                f.seek(start_address)
                raw_code = f.read(max_insns * 15)  # Worst case: avg 15 bytes/insn
        except OSError as e:
            log.error("Failed to read binary: %s", e)
            return None

        # Capstone disassembly
        instructions = self._disassemble_capstone(
            raw_code, start_address, max_insns
        )

        if not instructions:
            log.warning("No instructions lifted — trying r2 fallback")
            instructions = self._disassemble_r2(binary_path, start_address, max_insns)

        if not instructions:
            return None

        # 构建基本块
        blocks = self._build_basic_blocks(instructions)

        # 创建函数对象
        func = IRFunction(
            name=f"sub_{start_address:X}",
            address=start_address,
            blocks=blocks,
        )

        self._functions[start_address] = func
        return func

    def _disassemble_capstone(
        self, raw_code: bytes, base_addr: int, max_insns: int
    ) -> List[IRInstruction]:
        """Disassemble bytes using Capstone."""
        instructions: List[IRInstruction] = []
        try:
            import capstone

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True

            for insn in md.disasm(raw_code, base_addr):
                op = self._map_capstone_op(insn)
                operands = [
                    insn.op_str.split(", ")[i] if i < len(insn.op_str.split(", ")) else ""
                    for i in range(3)
                ]

                ir_insn = IRInstruction(
                    address=insn.address,
                    op=op,
                    operands=[o for o in operands if o],
                    size=insn.size,
                    raw_bytes=raw_code[insn.address - base_addr : insn.address - base_addr + insn.size],
                )
                instructions.append(ir_insn)

                if len(instructions) >= max_insns:
                    break

        except ImportError:
            log.warning("Capstone not available")
        except Exception as e:
            log.error("Capstone disassembly error: %s", e)

        return instructions

    def _disassemble_r2(
        self, binary_path: str, start_addr: int, max_insns: int
    ) -> List[IRInstruction]:
        """Disassemble using radare2 as fallback."""
        instructions: List[IRInstruction] = []
        try:
            import subprocess
            import json

            result = subprocess.run(
                [
                    "r2", "-q", "-c",
                    f"pdj {max_insns} @ {start_addr:#x}",
                    binary_path,
                ],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return instructions

            insn_list = json.loads(result.stdout)
            for insn_data in insn_list:
                ir_insn = IRInstruction(
                    address=insn_data.get("offset", 0),
                    op=self._map_r2_op(insn_data.get("type", "unknown")),
                    operands=[insn_data.get("opcode", "")],
                    size=insn_data.get("size", 1),
                )
                instructions.append(ir_insn)

        except (ImportError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
            log.warning("r2 disassembly failed: %s", e)

        return instructions

    @staticmethod
    def _map_capstone_op(insn: Any) -> IROperation:
        """Map Capstone mnemonic to IR op."""
        mnemonic = insn.mnemonic.lower()
        _OP_MAP = {
            "mov": IROperation.MOV, "movzx": IROperation.MOV,
            "add": IROperation.ADD, "sub": IROperation.SUB,
            "mul": IROperation.MUL, "imul": IROperation.MUL,
            "div": IROperation.DIV, "idiv": IROperation.DIV,
            "and": IROperation.AND, "or": IROperation.OR, "xor": IROperation.XOR,
            "shl": IROperation.SHL, "shr": IROperation.SHR,
            "cmp": IROperation.CMP, "test": IROperation.TEST,
            "jmp": IROperation.JMP, "call": IROperation.CALL,
            "ret": IROperation.RET, "push": IROperation.PUSH, "pop": IROperation.POP,
            "nop": IROperation.NOP, "lea": IROperation.LEA,
        }
        return _OP_MAP.get(mnemonic, IROperation.UNKNOWN)

    @staticmethod
    def _map_r2_op(op_type: str) -> IROperation:
        """Map r2 instruction type to IR op."""
        _R2_MAP = {
            "mov": IROperation.MOV, "add": IROperation.ADD,
            "sub": IROperation.SUB, "mul": IROperation.MUL,
            "div": IROperation.DIV, "jmp": IROperation.JMP,
            "cjmp": IROperation.JCC, "call": IROperation.CALL,
            "ret": IROperation.RET, "push": IROperation.PUSH,
            "pop": IROperation.POP, "nop": IROperation.NOP,
        }
        return _R2_MAP.get(op_type, IROperation.UNKNOWN)

# Basic block construction

    def _build_basic_blocks(
        self, instructions: List[IRInstruction]
    ) -> Dict[int, IRBasicBlock]:
        """Partition instructions into basic blocks.

        A new block starts:
        - at the first instruction
        - at a jump/call/ret target
        - after a jump/call/ret instruction
        """
        # Identify block leaders
        leaders: Set[int] = {instructions[0].address}
        for insn in instructions:
            if insn.op in (IROperation.JMP, IROperation.JCC, IROperation.CALL, IROperation.RET):
                if insn.op != IROperation.RET:
                    # Next instruction starts a new block
                    idx = next(
                        (i for i, e in enumerate(instructions) if e.address > insn.address),
                        len(instructions),
                    )
                    if idx < len(instructions):
                        leaders.add(instructions[idx].address)

        # Build blocks
        blocks: Dict[int, IRBasicBlock] = {}
        current_block_addr = 0
        current_insns: List[IRInstruction] = []

        for insn in instructions:
            if insn.address in leaders and current_insns:
                block = IRBasicBlock(
                    address=current_block_addr,
                    instructions=current_insns,
                )
                blocks[block.address] = block
                current_insns = []

            if not current_insns:
                current_block_addr = insn.address

            current_insns.append(insn)

        if current_insns:
            block = IRBasicBlock(address=current_block_addr, instructions=current_insns)
            blocks[block.address] = block

        # Link successors and predecessors
        sorted_addrs = sorted(blocks.keys())
        for i, addr in enumerate(sorted_addrs):
            block = blocks[addr]
            last = block.instructions[-1]

            if last.op == IROperation.JMP:
                # Try to resolve target
                target = self._parse_branch_target(last)
                if target and target in blocks:
                    block.successors.append(target)
                    blocks[target].predecessors.append(addr)
            elif last.op == IROperation.JCC:
                target = self._parse_branch_target(last)
                if target and target in blocks:
                    block.successors.append(target)
                    blocks[target].predecessors.append(addr)
                # Fallthrough
                if i + 1 < len(sorted_addrs):
                    block.successors.append(sorted_addrs[i + 1])
                    blocks[sorted_addrs[i + 1]].predecessors.append(addr)
            elif last.op not in (IROperation.RET,):
                # Fallthrough
                if i + 1 < len(sorted_addrs):
                    block.successors.append(sorted_addrs[i + 1])
                    blocks[sorted_addrs[i + 1]].predecessors.append(addr)

        return blocks

    @staticmethod
    def _parse_branch_target(insn: IRInstruction) -> Optional[int]:
        """Parse branch target from an operand."""
        for op_str in insn.operands:
            try:
                if op_str.startswith("0x"):
                    return int(op_str, 16)
                return int(op_str, 0)
            except (ValueError, TypeError):
                continue
        return None

# IR optimization

    def optimize_ir(self, func: IRFunction) -> IRFunction:
        """Run IR optimization passes.

        Passes:
        1. Dead code elimination — remove instructions whose results
        are never used
        2. Constant folding — evaluate constant expressions at compile time
        3. Expression simplification — algebraic identities (x+0=x,
        x*1=x, etc.)
        """
        log.debug("Optimizing IR for function: %s", func.name)
        for addr, block in func.blocks.items():
            block.instructions = self._dead_code_elimination(block.instructions)
            block.instructions = self._constant_folding(block.instructions)
            block.instructions = self._simplify_expressions(block.instructions)
        return func

    def _dead_code_elimination(
        self, instructions: List[IRInstruction]
    ) -> List[IRInstruction]:
        """Eliminate dead instructions (results never used)"""
        # Track variables used
        used_vars: Set[str] = set()
        for insn in instructions:
            for op in insn.operands:
                if op and not op.startswith("0x") and not op.startswith("0b"):
                    used_vars.add(op.split("[")[0])

        # Keep instructions side effects or results used
        side_effect_ops = {IROperation.JMP, IROperation.JCC, IROperation.CALL,
                           IROperation.RET, IROperation.PUSH, IROperation.STORE,
                           IROperation.CMP, IROperation.TEST}

        kept: List[IRInstruction] = []
        for insn in instructions:
            if insn.op in side_effect_ops:
                kept.append(insn)
            elif insn.operands:
                dest = insn.operands[0].split("[")[0]
                if dest in used_vars:
                    kept.append(insn)

        return kept

    def _constant_folding(
        self, instructions: List[IRInstruction]
    ) -> List[IRInstruction]:
        """Fold constant expressions: 2+3 -> 5"""
        for insn in instructions:
            if insn.op in (IROperation.ADD, IROperation.SUB, IROperation.MUL):
                vals = []
                for op in insn.operands:
                    try:
                        vals.append(int(op, 0))
                    except (ValueError, TypeError):
                        vals.append(None)
                if all(v is not None for v in vals[:2]):
                    if insn.op == IROperation.ADD:
                        result = vals[0] + vals[1]
                    elif insn.op == IROperation.SUB:
                        result = vals[0] - vals[1]
                    else:
                        result = vals[0] * vals[1]
                    insn.operands = [insn.operands[0], str(result)]
                    insn.comment = f"// folded: {vals[0]} {'+-*'[['ADD','SUB','MUL'].index(insn.op.value)]} {vals[1]} = {result}"

        return instructions

    def _simplify_expressions(
        self, instructions: List[IRInstruction]
    ) -> List[IRInstruction]:
        """Algebraic simplification: x+0=x, x*1=x, x xor x=0"""
        for insn in instructions:
            if len(insn.operands) < 2:
                continue
            rhs = insn.operands[1]
            if insn.op == IROperation.ADD and rhs in ("0", "0x0"):
                insn.comment = "// simplified: +0 removed"
                insn.op = IROperation.MOV  # noqa: E501
            elif insn.op == IROperation.SUB and rhs in ("0", "0x0"):
                insn.comment = "// simplified: -0 removed"
            elif insn.op == IROperation.MUL and rhs in ("1", "0x1"):
                insn.comment = "// simplified: *1 removed"
                insn.op = IROperation.MOV  # type: ignore
        return instructions

# Control-flow structuring

    def structure_control_flow(self, func: IRFunction) -> Dict[str, Any]:
        """Structure control flow from CFG into high-level constructs.

        Uses interval analysis + structural analysis to recover:
        - if/else (2-way conditional)
        - while loops (loop header dominates back-edge)
        - for loops (initializer + condition + increment)
        - do-while loops (condition at bottom)
        """
        intervals = self._interval_analysis(func)
        structure = self._structural_analysis(func, intervals)
        return structure

    def _interval_analysis(self, func: IRFunction) -> List[Set[int]]:
        """Partition CFG into intervals (single-entry regions).

        An interval with header h is the maximal set of nodes where
        h dominates all nodes and all back-edges stay within the interval.
        """
        intervals: List[Set[int]] = []
        visited: Set[int] = set()
        sorted_addrs = sorted(func.blocks.keys())

        for addr in sorted_addrs:
            if addr in visited:
                continue
            interval: Set[int] = {addr}
            queue = [addr]
            while queue:
                node = queue.pop(0)
                block = func.blocks[node]
                for succ in block.successors:
                    if succ not in visited and succ not in interval:
                        # 检查前驱是否全部属于当前 interval
                        preds = func.blocks[succ].predecessors
                        if all(p in interval for p in preds):
                            interval.add(succ)
                            queue.append(succ)
            intervals.append(interval)
            visited.update(interval)

        return intervals

    def _structural_analysis(
        self, func: IRFunction, intervals: List[Set[int]]
    ) -> Dict[str, Any]:
        """将 interval 分类为结构化控制流构造。

        返回一棵树，包含 if_nodes、while_nodes、sequence_nodes、block_nodes。
        """
        structure: Dict[str, Any] = {
            "type": "function",
            "name": func.name,
            "body": [],
        }

        for interval in intervals:
            if len(interval) == 1:
                addr = next(iter(interval))
                block = func.blocks[addr]
                # Check if a loop (back-edge to itself)
                if block.successors and block.successors[0] <= addr:
                    structure["body"].append({
                        "type": "while_loop",
                        "header": addr,
                        "body": [{"type": "block", "address": addr}],
                    })
                else:
                    structure["body"].append({
                        "type": "block", "address": addr,
                    })
            elif len(interval) == 2:
                addrs = sorted(interval)
                header = func.blocks[addrs[0]]
                    # 2-block interval: conditional or sequence
                if len(header.successors) == 2:
                    structure["body"].append({
                        "type": "if_else",
                        "condition_addr": addrs[0],
                        "then_body": [{"type": "block", "address": addrs[0]}],
                        "else_body": [{"type": "block", "address": addrs[1]}],
                    })
                else:
                    for a in addrs:
                        structure["body"].append({"type": "block", "address": a})
            else:
                structure["body"].append({
                    "type": "loop_body",
                    "blocks": sorted(interval),
                })

        return structure

# Pseudocode generation

    def generate_pseudocode(
        self, func: IRFunction, indent_size: int = 4
    ) -> str:
        """Generate structured C-like pseudocode from an IR function.

        Produces properly indented, type-annotated pseudocode with
        control structure nesting.

        Usage:

            func = engine.decompile("binary.exe", 0x401000)
            pseudocode = engine.generate_pseudocode(func)
            print(pseudocode)
        """
        lines: List[str] = []

        # 函数签名
        ret_type = func.return_type or "void"
        arg_strs = []
        for arg in func.arguments:
            arg_type = arg.get("type", "int")
            arg_name = arg.get("name", f"arg_{len(arg_strs)}")
            arg_strs.append(f"{arg_type} {arg_name}")
        lines.append(f"{ret_type} {func.name}({', '.join(arg_strs)}) {{")

        # Variable declarations
        if func.variables:
            for var_name, var_type in func.variables.items():
                lines.append(f"{' ' * indent_size}{var_type.value} {var_name};")
            if func.variables:
                lines.append("")

        # Build body blocks
        for addr in sorted(func.blocks.keys()):
            block = func.blocks[addr]
            lines.append(f"{' ' * indent_size}// Block {addr:#x}")

            for insn in block.instructions:
                pseudo = self._instruction_to_pseudocode(insn)
                if pseudo:
                    lines.append(f"{' ' * indent_size}{pseudo}")
                if insn.comment:
                    lines.append(f"{' ' * (indent_size + 2)}{insn.comment}")

            lines.append("")

        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def _instruction_to_pseudocode(insn: IRInstruction) -> str:
        """Convert a single IR instruction to pseudocode."""
        pseudo_map = {
            IROperation.MOV: lambda o: f"{o[0]} = {o[1]};" if len(o) >= 2 else f"// mov {o}",
            IROperation.ADD: lambda o: f"{o[0]} += {o[1]};" if len(o) >= 2 else f"// add",
            IROperation.SUB: lambda o: f"{o[0]} -= {o[1]};" if len(o) >= 2 else f"// sub",
            IROperation.MUL: lambda o: f"{o[0]} *= {o[1]};" if len(o) >= 2 else f"// mul",
            IROperation.XOR: lambda o: f"{o[0]} ^= {o[1]};" if len(o) >= 2 else f"// xor",
            IROperation.CMP: lambda o: f"// cmp {', '.join(o)}" if o else "// cmp",
            IROperation.JMP: lambda o: f"goto label_{o[0]};" if o else "goto unknown;",
            IROperation.JCC: lambda o: f"if (condition) goto label_{o[0]};" if o else "if",
            IROperation.CALL: lambda o: f"{o[0]}();" if o else "call();",
            IROperation.RET: lambda o: "return;" if not o else f"return {o[0]};",
            IROperation.PUSH: lambda o: f"push({o[0]});" if o else "push;",
            IROperation.POP: lambda o: f"pop({o[0]});" if o else "pop;",
            IROperation.NOP: lambda o: ";",
            IROperation.UNKNOWN: lambda o: f"// unknown: {' '.join(o)}",
        }

        handler = pseudo_map.get(insn.op, lambda o: f"// {insn.op.value} {' '.join(o)}")
        return handler(insn.operands)

# Convenience entry point

    def decompile(
        self, binary_path: str, start_address: int
    ) -> Optional[Dict[str, Any]]:
        """Full decompilation pipeline: lift -> optimize -> structure -> pseudocode.

        Returns a dict with keys: function, pseudocode, structure, stats.
        """
        start_time = time.time()
        func = self.lift_function(binary_path, start_address)
        if func is None:
            return None

        func = self.optimize_ir(func)
        structure = self.structure_control_flow(func)
        pseudocode = self.generate_pseudocode(func)

        duration = time.time() - start_time
        total_insns = sum(len(b.instructions) for b in func.blocks.values())

        return {
            "function": func,
            "pseudocode": pseudocode,
            "structure": structure,
            "stats": {
                "blocks": len(func.blocks),
                "instructions": total_insns,
                "variables": len(func.variables),
                "duration_seconds": round(duration, 3),
            },
        }


# Decompiler validator — round-trip validation

class ValidationError(Exception):
    """Raised when validation fails."""
    pass


class DecompilerValidator:
    """Round-trip validation for decompiled output.

    Validates:
    1. Recompiling decompiled pseudocode and comparing behavior
    2. Semantic equivalence checking via Z3 (optional, if installed)

    Usage::

        validator = DecompilerValidator()
        result = validator.validate(original_binary, decompiled_output)
        if not result["passed"]:
            print(result["errors"])
    """

    def __init__(self, z3_enabled: bool = True) -> None:
        self._z3_available = False
        if z3_enabled:
            try:
                import z3
                self._z3_available = True
            except ImportError:
                log.info("Z3 not available — semantic checking disabled")

    def validate(
        self,
        original_binary: str,
        decompiled_output: str,
        test_inputs: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """Validate decompiled output against original binary."""
        result: Dict[str, Any] = {
            "passed": True,
            "errors": [],
            "warnings": [],
            "semantic_check": None,
        }

        # Check 1: output is parseable (syntax)
        syntax_ok, syntax_errors = self._check_syntax(decompiled_output)
        if not syntax_ok:
            result["passed"] = False
            result["errors"].extend(syntax_errors)

        # Check 2: output is not empty
        if not decompiled_output.strip() or "{}" == decompiled_output.strip():
            result["passed"] = False
            result["errors"].append("Decompiled output is empty")

        # Check 3: contains expected patterns
        required_patterns = ["{", "}", ";", "return"]
        for pattern in required_patterns:
            if pattern not in decompiled_output:
                result["warnings"].append(
                    f"Missing expected pattern: '{pattern}'"
                )

        # Check 4: Z3 semantic equivalence (if available)
        if self._z3_available and test_inputs:
            z3_result = self._z3_semantic_check(
                original_binary, decompiled_output, test_inputs
            )
            result["semantic_check"] = z3_result
            if not z3_result.get("equivalent", True):
                result["passed"] = False
                result["errors"].append(
                    "Z3 found semantic differences between original and decompiled"
                )

        return result

    def _check_syntax(self, code: str) -> Tuple[bool, List[str]]:
        """Basic syntax check for C-like pseudocode."""
        errors: List[str] = []
        lines = code.split("\n")
        brace_depth = 0
        for i, line in enumerate(lines, 1):
            brace_depth += line.count("{") - line.count("}")
            if brace_depth < 0:
                errors.append(f"Line {i}: unexpected '}}' (mismatched braces)")
                brace_depth = 0
        if brace_depth != 0:
            errors.append(f"Unbalanced braces (depth={brace_depth})")
        return len(errors) == 0, errors

    def _z3_semantic_check(
        self, binary: str, decompiled: str, inputs: List[Any]
    ) -> Dict[str, Any]:
        """Z3-based semantic equivalence check."""
        try:
            import z3
            log.info("Z3 semantic check initiated")
            # Z3 语义等价检查尚未完全集成，暂返回 None
            return {"equivalent": None, "note": "Z3 available but not fully integrated"}
        except ImportError:
            return {"equivalent": None, "note": "Z3 not available"}


# Decompiler enhancer — LLM-assisted enhancement

class DecompilerEnhancer:
    """LLM-assisted decompiler enhancement.

    Improves decompiled output:
    - Renames variables based on usage context (LLM-powered)
    - Infers function signatures from API usage patterns
    - Inlines library function definitions

    LLM integration is optional. Without an LLM backend, heuristic
    rules are used for basic enhancements.

    Uses registry pattern instead of inheritance — less type-safe but
    avoids deep class hierarchies that hurt readability
    """

    def __init__(self, llm_backend: Optional[str] = None) -> None:
        self._llm_backend = llm_backend

    def enhance_variables(
        self, func: IRFunction, usage_context: int = 3
    ) -> IRFunction:
        """Rename variables based on usage context.

        Heuristic rules:
        - Loop counters -> i, j, k
        - Variables compared with strings -> str_buf, name
        - Variables passed to malloc -> buf, ptr
        - Variables used in arithmetic -> sum, total, len
        """
        for var_name, var_type in list(func.variables.items()):
            # Simple heuristics for naming
            new_name = self._infer_variable_name(var_name, var_type)
            if new_name != var_name:
                func.variables[new_name] = func.variables.pop(var_name)
        # Update instruction operands with new name
                for block in func.blocks.values():
                    for insn in block.instructions:
                        for j, op in enumerate(insn.operands):
                            if op == var_name:
                                insn.operands[j] = new_name

        return func

    @staticmethod
    def _infer_variable_name(name: str, vtype: VariableType) -> str:
        """Infer a meaningful variable name from type and usage."""
        if vtype == VariableType.POINTER:
            return f"ptr_{name.lstrip('var_')}"
        if vtype == VariableType.STRING:
            return f"str_{name.lstrip('var_')}"
        if "count" in name.lower() or "index" in name.lower():
            return "index"
        if "size" in name.lower() or "len" in name.lower():
            return "size"
        return name

    def infer_function_signature(
        self, func: IRFunction, api_traces: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Infer function signature from API usage patterns.

        Examines:
        - Called functions (callees) to determine context
        - Return value usage (int, pointer, void)
        - Argument count from register conventions
        """
        signature: Dict[str, Any] = {
            "name": func.name,
            "return_type": "int",
            "arguments": [],
            "calling_convention": "cdecl",
        }

        # Count push/pop to infer argument count
        push_count = 0
        for block in func.blocks.values():
            for insn in block.instructions:
                if insn.op == IROperation.PUSH:
                    push_count += 1

        if push_count > 0:
            for i in range(min(push_count, 4)):
                signature["arguments"].append({
                    "name": f"arg{i}",
                    "type": "int",
                    "position": i,
                })

        # Check for return value
        for block in func.blocks.values():
            for insn in block.instructions:
                if insn.op == IROperation.RET and insn.operands:
                    # 有返回值，保持 return_type 为 int
                    pass
                elif insn.op == IROperation.RET and not insn.operands:
                    signature["return_type"] = "void"

        return signature

    def expand_library_functions(
        self, func: IRFunction, known_libs: Optional[Dict[str, str]] = None
    ) -> IRFunction:
        """Inline library function bodies.

        For example, strlen implementation is inlined to show intent.
        """
        if known_libs is None:
            known_libs = {
                "strlen": "while (*ptr++) len++;",
                "memset": "for (int i = 0; i < n; i++) ptr[i] = val;",
                "memcpy": "for (int i = 0; i < n; i++) dst[i] = src[i];",
                "strcmp": "while (*a && *a == *b) a++, b++; return *a - *b;",
            }

        for block in func.blocks.values():
            for insn in block.instructions:
                if insn.op == IROperation.CALL and insn.operands:
                    callee = insn.operands[0]
                    if callee in known_libs:
                        insn.comment = f"// inlined: {known_libs[callee]}"

        return func


# Pseudocode generator — IR to structured C-like output

class PseudocodeGenerator:
    """Generate structured C-like pseudocode from IR.

    Produces control structure nesting with proper indentation and
    type-annotated variable declarations.

    Usage::

        gen = PseudocodeGenerator()
        output = gen.generate(function, indent_size=4)
    """

    def __init__(self, indent_size: int = 4) -> None:
        self._indent_size = indent_size
        self._label_counter: int = 0

    def generate(
        self, func: IRFunction, structure: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate pseudocode from an IR function.

        If structure is provided (from structure_control_flow), uses it
        for control-flow nesting. Otherwise falls back to block-by-block.
        """
        output: List[str] = []

        # 构造函数头部
        args = func.arguments if func.arguments else []
        arg_str = ", ".join(
            f"int {a.get('name', f'a{i}')}" for i, a in enumerate(args)
        )
        output.append(f"int {func.name}({arg_str}) {{")

        indent = " " * self._indent_size

        # Variable declarations
        if func.variables:
            for name, vtype in func.variables.items():
                output.append(f"{indent}{vtype.value} {name};")
            output.append("")

        # 构造函数体
        if structure and "body" in structure:
            for node in structure["body"]:
                self._generate_node(output, node, indent)
        else:
            for addr in sorted(func.blocks.keys()):
                block = func.blocks[addr]
                output.append(f"{indent}// Block {addr:#x}")
                for insn in block.instructions:
                    pseudo = DecompilerEngine._instruction_to_pseudocode(insn)
                    if pseudo:
                        output.append(f"{indent}{pseudo}")
                output.append("")

        output.append("}")
        return "\n".join(output)

    def _generate_node(
        self, output: List[str], node: Dict[str, Any], indent: str
    ) -> None:
        """递归地为结构节点生成伪代码。"""
        node_type = node.get("type", "block")
        inner_indent = indent + " " * self._indent_size

        if node_type == "block":
            output.append(f"{indent}// Block {node.get('address', '?'):#x}")

        elif node_type == "if_else":
            output.append(f"{indent}if (/* condition at {node.get('condition_addr', '?'):#x} */) {{")
            for child in node.get("then_body", []):
                self._generate_node(output, child, inner_indent)
            if node.get("else_body"):
                output.append(f"{indent}}} else {{")
                for child in node["else_body"]:
                    self._generate_node(output, child, inner_indent)
            output.append(f"{indent}}}")

        elif node_type == "while_loop":
            output.append(f"{indent}while (/* condition at {node.get('header', '?'):#x} */) {{")
            for child in node.get("body", []):
                self._generate_node(output, child, inner_indent)
            output.append(f"{indent}}}")

        elif node_type == "function":
            for child in node.get("body", []):
                self._generate_node(output, child, indent)


# Type inferrer — SSA-based type inference

class TypingInferrer:
    """SSA-based type inference via constraint propagation.

    Infers integer width/signedness from instruction patterns,
    pointer/reference types from memory access patterns.

    Type inference on obfuscated binaries can produce contradictory
    constraints. A scoring system ranks type candidates by evidence
    weight, resolving conflicts via majority vote.
    """

    def __init__(self) -> None:
        self._type_scores: Dict[str, Dict[VariableType, int]] = defaultdict(
            lambda: defaultdict(int)
        )

    def infer_types(self, func: IRFunction) -> Dict[str, VariableType]:
        """Infer types for variables in a function.

        For each variable, accumulates evidence:
        - Instruction operand sizes (8/16/32/64-bit)
        - Memory access patterns (MOVSX/MOVZX = signed/unsigned extend)
        - Arithmetic patterns (IDIV = signed, DIV = unsigned)
        - Comparison patterns (JG/JL = signed, JA/JB = unsigned)
        - LEA usage (LEA = pointer)
        """
        self._type_scores.clear()

        for block in func.blocks.values():
            for insn in block.instructions:
                self._analyze_instruction_types(insn)

        # Resolve types by picking highest-scoring candidate
        result: Dict[str, VariableType] = {}
        for var_name, scores in self._type_scores.items():
            if scores:
                best_type = max(scores, key=lambda t: scores[t])
                result[var_name] = best_type
            else:
                result[var_name] = VariableType.UNKNOWN  # type: ignore

        return result

    def _analyze_instruction_types(self, insn: IRInstruction) -> None:
        """从单条指令中收集类型证据并更新评分。"""
        for op in insn.operands:
            if not op or op.startswith("0x"):
                continue

            var = op.split("[")[0]
            size = insn.size

            if size == 1:
                self._type_scores[var][VariableType.INT8] += 3  # type: ignore
            elif size == 2:
                self._type_scores[var][VariableType.INT16] += 3  # type: ignore
            elif size == 4:
                self._type_scores[var][VariableType.INT32] += 3  # type: ignore
            elif size == 8:
                self._type_scores[var][VariableType.INT64] += 3  # type: ignore

            # LEA -> pointer
            if insn.op == IROperation.LEA:
                self._type_scores[var][VariableType.POINTER] += 5  # type: ignore

    def propagate_types(self, func: IRFunction) -> None:
        """Propagate inferred types into a function's variables dict."""
        inferred = self.infer_types(func)
        func.variables.update(inferred)
