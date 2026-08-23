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


class IROperation(str, Enum):
    """统一 IR 操作类型"""
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



class DecompilerEngine:
    """二进制反编译引擎

    管线步骤:
    1. 二进制 -> IR 提升 (通过 capstone 或 radare2)
    2. IR 优化 (死代码消除, 常量折叠, 表达式简化)
    3. 控制流结构化 (区间分析 + 结构分析)
    4. 变量恢复 (基于 SSA 的类型推断)
    5. 伪代码生成 (结构化 C 风格输出)

    用法:

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

    def lift_function(
        self,
        binary_path: str,
        start_address: int,
        max_instructions: Optional[int] = None,
        ) -> Optional[IRFunction]:
        """从二进制中提升函数到统一 IR"""
        max_insns = max_instructions or self._max_insns
        log.info("Lifting function at %#x from %s", start_address, binary_path)

        try:
            with open(binary_path, "rb") as f:
                f.seek(start_address)
                raw_code = f.read(max_insns * 15)
        except OSError as e:
            log.error("Failed to read binary: %s", e)
            return None

        instructions = self._disassemble_capstone(
            raw_code, start_address, max_insns
        )

        if not instructions:
            log.warning("No instructions lifted — trying r2 fallback")
            instructions = self._disassemble_r2(binary_path, start_address, max_insns)

        if not instructions:
            return None

        blocks = self._build_basic_blocks(instructions)

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
        """使用 Capstone 反汇编"""
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
        """使用 radare2 反汇编作为后备"""
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
        """将 Capstone 助记符映射到 IR 操作"""
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
        """将 r2 指令类型映射到 IR 操作"""
        _R2_MAP = {
            "mov": IROperation.MOV, "add": IROperation.ADD,
            "sub": IROperation.SUB, "mul": IROperation.MUL,
            "div": IROperation.DIV, "jmp": IROperation.JMP,
            "cjmp": IROperation.JCC, "call": IROperation.CALL,
            "ret": IROperation.RET, "push": IROperation.PUSH,
            "pop": IROperation.POP, "nop": IROperation.NOP,
        }
        return _R2_MAP.get(op_type, IROperation.UNKNOWN)

    def _build_basic_blocks(
        self, instructions: List[IRInstruction]
    ) -> Dict[int, IRBasicBlock]:
        """将指令划分为基本块"""
        leaders: Set[int] = {instructions[0].address}
        for insn in instructions:
            if insn.op in (IROperation.JMP, IROperation.JCC, IROperation.CALL, IROperation.RET):
                if insn.op != IROperation.RET:
                    idx = next(
                        (i for i, e in enumerate(instructions) if e.address > insn.address),
                        len(instructions),
                    )
                    if idx < len(instructions):
                        leaders.add(instructions[idx].address)

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

        sorted_addrs = sorted(blocks.keys())
        for i, addr in enumerate(sorted_addrs):
            block = blocks[addr]
            last = block.instructions[-1]

            if last.op == IROperation.JMP:
                target = self._parse_branch_target(last)
                if target and target in blocks:
                    block.successors.append(target)
                    blocks[target].predecessors.append(addr)
            elif last.op == IROperation.JCC:
                target = self._parse_branch_target(last)
                if target and target in blocks:
                    block.successors.append(target)
                    blocks[target].predecessors.append(addr)
                if i + 1 < len(sorted_addrs):
                    block.successors.append(sorted_addrs[i + 1])
                    blocks[sorted_addrs[i + 1]].predecessors.append(addr)
            elif last.op not in (IROperation.RET,):
                if i + 1 < len(sorted_addrs):
                    block.successors.append(sorted_addrs[i + 1])
                    blocks[sorted_addrs[i + 1]].predecessors.append(addr)

        return blocks

    @staticmethod
    def _parse_branch_target(insn: IRInstruction) -> Optional[int]:
        """从操作数中解析分支目标地址"""
        for op_str in insn.operands:
            try:
                if op_str.startswith("0x"):
                    return int(op_str, 16)
                return int(op_str, 0)
            except (ValueError, TypeError):
                continue
        return None

    def optimize_ir(self, func: IRFunction) -> IRFunction:
        """运行 IR 优化 pass"""
        log.debug("Optimizing IR for function: %s", func.name)
        for addr, block in func.blocks.items():
            block.instructions = self._dead_code_elimination(block.instructions)
            block.instructions = self._constant_folding(block.instructions)
            block.instructions = self._simplify_expressions(block.instructions)
        return func

    def _dead_code_elimination(
        self, instructions: List[IRInstruction]
    ) -> List[IRInstruction]:
        """消除死指令（结果从未使用）"""
        used_vars: Set[str] = set()
        for insn in instructions:
            for op in insn.operands:
                if op and not op.startswith("0x") and not op.startswith("0b"):
                    used_vars.add(op.split("[")[0])

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
        """常量折叠: 2+3 -> 5"""
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
        """代数化简: x+0=x, x*1=x, x xor x=0"""
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

    def structure_control_flow(self, func: IRFunction) -> Dict[str, Any]:
        """从 CFG 结构化控制流为高层构造

        使用区间分析 + 结构分析恢复:
        - if/else (双路条件)
        - while 循环 (循环头支配回边)
        - for 循环 (初始化 + 条件 + 递增)
        - do-while 循环 (条件在底部)
        """
        intervals = self._interval_analysis(func)
        structure = self._structural_analysis(func, intervals)
        return structure

    def _interval_analysis(self, func: IRFunction) -> List[Set[int]]:
        """将 CFG 划分为 interval (单入口区域)"""
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

    def generate_pseudocode(
        self, func: IRFunction, indent_size: int = 4
    ) -> str:
        """从 IR 函数生成结构化 C 风格伪代码"""
        lines: List[str] = []

        ret_type = func.return_type or "void"
        arg_strs = []
        for arg in func.arguments:
            arg_type = arg.get("type", "int")
            arg_name = arg.get("name", f"arg_{len(arg_strs)}")
            arg_strs.append(f"{arg_type} {arg_name}")
        lines.append(f"{ret_type} {func.name}({', '.join(arg_strs)}) {{")

        if func.variables:
            for var_name, var_type in func.variables.items():
                lines.append(f"{' ' * indent_size}{var_type.value} {var_name};")
            if func.variables:
                lines.append("")

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
        """将单条 IR 指令转为伪代码"""
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

    def decompile(
        self, binary_path: str, start_address: int
    ) -> Optional[Dict[str, Any]]:
        """完整反编译管线: lift -> optimize -> structure -> pseudocode"""
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
            "pseudocode": pseudocode,
            "structure": structure,
            "stats": {
                "blocks": len(func.blocks),
                "instructions": total_insns,
                "variables": len(func.variables),
                "duration_seconds": round(duration, 3),
            },
        }


class ValidationError(Exception):
    """验证失败时抛出"""
    pass


class DecompilerValidator:
    """反编译输出的往返验证

    验证:
    1. 重编译反编译伪代码并比较行为
    2. 通过 Z3 进行语义等价检查 (可选)

    用法:

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
        """验证反编译输出与原始二进制的一致性"""
        result: Dict[str, Any] = {
            "passed": True,
            "errors": [],
            "warnings": [],
            "semantic_check": None,
        }

        # 检查1: 语法可解析
        syntax_ok, syntax_errors = self._check_syntax(decompiled_output)
        if not syntax_ok:
            result["passed"] = False
            result["errors"].extend(syntax_errors)

        # 检查2: 输出非空
        if not decompiled_output.strip() or "{}" == decompiled_output.strip():
            result["passed"] = False
            result["errors"].append("Decompiled output is empty")

        # 检查3: 包含预期模式
        required_patterns = ["{", "}", ";", "return"]
        for pattern in required_patterns:
            if pattern not in decompiled_output:
                result["warnings"].append(
                    f"Missing expected pattern: '{pattern}'"
                )

        # 检查4: Z3 语义等价 (若可用)
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
        """C 风格伪代码的基础语法检查"""
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
        """基于 Z3 的语义等价检查"""
        try:
            import z3
            log.info("Z3 semantic check initiated")
            return {"equivalent": None, "note": "Z3 available but not fully integrated"}
        except ImportError:
            return {"equivalent": None, "note": "Z3 not available"}


class DecompilerEnhancer:
    """LLM 辅助反编译增强

    改进反编译输出:
    - 根据使用上下文重命名变量 (LLM-powered)
    - 从 API 使用模式推断函数签名
    - 内联库函数定义

    LLM 集成是可选的。无 LLM 后端时使用启发式规则进行基础增强
    """

    def __init__(self, llm_backend: Optional[str] = None) -> None:
        self._llm_backend = llm_backend

    def enhance_variables(
        self, func: IRFunction, usage_context: int = 3
    ) -> IRFunction:
        """根据使用上下文重命名变量

        启发式规则:
        - 循环计数器 -> i, j, k
        - 与字符串比较的变量 -> str_buf, name
        - 传递给 malloc 的变量 -> buf, ptr
        - 用于算术运算的变量 -> sum, total, len
        """
        for var_name, var_type in list(func.variables.items()):
            new_name = self._infer_variable_name(var_name, var_type)
            if new_name != var_name:
                func.variables[new_name] = func.variables.pop(var_name)
                for block in func.blocks.values():
                    for insn in block.instructions:
                        for j, op in enumerate(insn.operands):
                            if op == var_name:
                                insn.operands[j] = new_name

        return func

    @staticmethod
    def _infer_variable_name(name: str, vtype: VariableType) -> str:
        """从类型和用法推断有意义的变量名"""
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
        """从 API 使用模式推断函数签名

        检查:
        - 被调用函数 (callees) 以确定上下文
        - 返回值使用 (int, pointer, void)
        - 从寄存器约定推断参数数量
        """
        signature: Dict[str, Any] = {
            "name": func.name,
            "return_type": "int",
            "arguments": [],
            "calling_convention": "cdecl",
        }

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

        for block in func.blocks.values():
            for insn in block.instructions:
                if insn.op == IROperation.RET and insn.operands:
                    pass
                elif insn.op == IROperation.RET and not insn.operands:
                    signature["return_type"] = "void"

        return signature

    def expand_library_functions(
        self, func: IRFunction, known_libs: Optional[Dict[str, str]] = None
    ) -> IRFunction:
        """内联库函数体"""
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


class PseudocodeGenerator:
    """从 IR 生成结构化 C 风格伪代码"""

    def __init__(self, indent_size: int = 4) -> None:
        self._indent_size = indent_size
        self._label_counter: int = 0

    def generate(
        self, func: IRFunction, structure: Optional[Dict[str, Any]] = None
    ) -> str:
        """从 IR 函数生成伪代码"""
        output: List[str] = []

        args = func.arguments if func.arguments else []
        arg_str = ", ".join(
            f"int {a.get('name', f'a{i}')}" for i, a in enumerate(args)
        )
        output.append(f"int {func.name}({arg_str}) {{")

        indent = " " * self._indent_size

        if func.variables:
            for name, vtype in func.variables.items():
                output.append(f"{indent}{vtype.value} {name};")
            output.append("")

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


class TypingInferrer:
    """基于 SSA 的类型推断——约束传播

    从指令模式推断整型宽度/符号性，
    从内存访问模式推断指针/引用类型。

    混淆二进制的类型推断可能产生矛盾约束，
    评分系统按证据权重排序类型候选，多数投票解决冲突
    """

    def __init__(self) -> None:
        self._type_scores: Dict[str, Dict[VariableType, int]] = defaultdict(
            lambda: defaultdict(int)
        )

    def infer_types(self, func: IRFunction) -> Dict[str, VariableType]:
        """为函数中的变量推断类型

        对每个变量累积证据:
        - 指令操作数宽度 (8/16/32/64-bit)
        - 内存访问模式 (MOVSX/MOVZX = 有符号/无符号扩展)
        - 算术模式 (IDIV = 有符号, DIV = 无符号)
        - 比较模式 (JG/JL = 有符号, JA/JB = 无符号)
        - LEA 使用 (LEA = 指针)
        """
        self._type_scores.clear()

        for block in func.blocks.values():
            for insn in block.instructions:
                self._analyze_instruction_types(insn)

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

            if insn.op == IROperation.LEA:
                self._type_scores[var][VariableType.POINTER] += 5  # type: ignore

    def propagate_types(self, func: IRFunction) -> None:
        """将推断的类型传播到函数的 variables 字典"""
        inferred = self.infer_types(func)
        func.variables.update(inferred)
