"""
binary中间语言统一抽象层 (VEX/Pcode/LLVM IR) module

功能:
    1. 设计统一的中间表示 (IR), 将 radare2 ESIL / Ghidra Pcode / Binary Ninja LLIL
       等映射到同一套语义指令集
    2. 跨engine分析算法 (污点追踪 / 漏洞modematch) based on统一 IR 编写
    3. 降低enginedependency

core technology:
    - IR 指令 (IRInstruction) + basic block (IRBlock) + 函数 (IRFunction)
    - 操作数: 寄存器/memory/立即数/label
    - 多种backend适配器: r2 ESIL / Ghidra Pcode / LLIL
"""

import logging
import os
import re
import json
from enum import Enum
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class IROpcode:  # 原 Enum
    """统一 IR 操作码"""
    NOP = "nop"
    MOV = "mov"
    LOAD = "load"        # 从memory读
    STORE = "store"      # 写memory
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

class IROperand:
    """统一 IR 操作数"""
    __slots__ = ('kind', 'value', 'size')

    def __init__(self, kind: OperandKind, value, size: int = 8):
        self.kind = kind
        self.value = value            # 寄存器名 / memory表达式 / 立即数value / label / 临时变量 id
        self.size = size              # 位数 (8/16/32/64)

    def to_dict(self) -> Dict[str, Any]:
        return {'kind': self.kind, 'value': self.value, 'size': self.size}

class IRInstruction:
    """统一 IR 指令"""
    __slots__ = ('opcode', 'operands', 'address', 'raw', 'metadata')

    def __init__(self, opcode: IROpcode, operands: List[IROperand] = None,
                 address: int = 0, raw: str = "",
                 metadata: Dict[str, Any] = None):
        self.opcode = opcode
        self.operands = operands if operands is not None else []
        self.address = address
        self.raw = raw
        self.metadata = metadata if metadata is not None else {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'opcode': self.opcode,
            'operands': [op.to_dict() for op in self.operands],
            'address': hex(self.address),
            'raw': self.raw[:120]
        }

class IRBlock:
    """basic block"""
    __slots__ = ('block_id', 'start_addr', 'end_addr', 'instructions',
                 'successors', 'predecessors')

    def __init__(self, block_id: str, start_addr: int, end_addr: int,
                 instructions: List[IRInstruction] = None,
                 successors: List[str] = None,
                 predecessors: List[str] = None):
        self.block_id = block_id
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.instructions = instructions if instructions is not None else []
        self.successors = successors if successors is not None else []
        self.predecessors = predecessors if predecessors is not None else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'block_id': self.block_id,
            'start': hex(self.start_addr),
            'end': hex(self.end_addr),
            'instructions': [i.to_dict() for i in self.instructions],
            'successors': self.successors,
            'predecessors': self.predecessors
        }

class IRFunction:
    """函数级 IR"""
    __slots__ = ('name', 'address', 'blocks', 'entry_block', 'arch', 'metadata')

    def __init__(self, name: str, address: int,
                 blocks: Dict[str, IRBlock] = None,
                 entry_block: Optional[str] = None,
                 arch: str = "",
                 metadata: Dict[str, Any] = None):
        self.name = name
        self.address = address
        self.blocks = blocks if blocks is not None else {}
        self.entry_block = entry_block
        self.arch = arch
        self.metadata = metadata if metadata is not None else {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': hex(self.address),
            'entry': self.entry_block,
            'arch': self.arch,
            'blocks': {bid: b.to_dict() for bid, b in self.blocks.items()}
        }

class IRBackend:
    """IR backend基类"""
    NAME = "base"

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        raise NotImplementedError

    def supported(self) -> bool:
        return True

class R2ESILBackend(IRBackend):
    """radare2 ESIL backend"""

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
            logger.warning(f"r2 提升failed: {e}")
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
    """Ghidra Pcode backend - 通过 headless modeexport p-code JSON"""

    NAME = "ghidra_pcode"

    def __init__(self, ghidra_headless: str = "analyzeHeadless"):
        self.ghidra_headless = ghidra_headless

    def supported(self) -> bool:
        import shutil
        if shutil.which(self.ghidra_headless):
            return True
        # 也check常见的 Ghidra installpath
        for path in [
            "/opt/ghidra/support/analyzeHeadless",
            "/opt/ghidra_11.0/support/analyzeHeadless",
            os.path.expanduser("~/ghidra/support/analyzeHeadless"),
        ]:
            if os.path.isfile(path):
                self.ghidra_headless = path
                return True
        return False

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        if not self.supported():
            logger.warning("Ghidra headless unavailable, downgraded to r2 backend")
            fallback = R2ESILBackend()
            return fallback.lift(binary_path, func_name)

        import subprocess
        import tempfile
        import re as _re

        ir_fn = IRFunction(name=func_name, address=0)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                project_name = "tmp_project"
                script = f'''
import ghidra.app.decompiler as decomp
import json
from enum import Enum

fm = currentProgram.getFunctionManager()
func = fm.getGlobalFunctions("{func_name}")[0] if fm.getGlobalFunctions("{func_name}") else None
if func:
    dec = decomp.DecompInterface()
    dec.openProgram(currentProgram)
    result = dec.decompileFunction(func, 30, monitor)
    if result and result.decompileCompleted():
        pcode = []
        for op in result.getHighFunction().getPcodeOps():
            pcode.append({{
                "address": str(op.getSeqnum().getTarget()),
                "mnemonic": op.getMnemonic(),
                "output": str(op.getOutput()) if op.getOutput() else None,
                "inputs": [str(i) for i in op.getInputs()]
            }})
        print("__GHIDRA_PCODE_START__")
        print(json.dumps(pcode, indent=2))
        print("__GHIDRA_PCODE_END__")
    dec.dispose()
'''
                script_file = os.path.join(tmpdir, "export_pcode.py")
                with open(script_file, 'w') as f:
                    f.write(script)

                cmd = [
                    self.ghidra_headless, tmpdir, project_name,
                    "-import", binary_path,
                    "-scriptPath", tmpdir,
                    "-postScript", "export_pcode.py",
                    "-deleteProject", "-noanalysis"
                ]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=300, encoding='utf-8', errors='replace')

                # 解析 p-code JSON 输出
                stdout = r.stdout
                match = _re.search(
                    r'__GHIDRA_PCODE_START__\s*(.*?)\s*__GHIDRA_PCODE_END__',
                    stdout, _re.DOTALL
                )
                if match:
                    pcode_ops = json.loads(match.group(1))
                    current_block = IRBlock(
                        block_id="entry", start_addr=0, end_addr=0
                    )
                    for op in pcode_ops:
                        addr_str = op.get("address", "0")
                        try:
                            addr = int(addr_str) if addr_str.isdigit() else int(addr_str, 16)
                        except (ValueError, TypeError):
                            addr = 0
                        ir_ins = IRInstruction(
                            opcode=self._map_pcode_mnemonic(op.get("mnemonic", "")),
                            operands=self._parse_pcode_operands(op),
                            address=addr,
                            raw=op.get("mnemonic", "")
                        )
                        current_block.instructions.append(ir_ins)
                    if current_block.instructions:
                        ir_fn.blocks["entry"] = current_block
                        ir_fn.entry_block = "entry"
                    ir_fn.arch = "ghidra_pcode"
                else:
                    logger.info("Ghidra p-code export未返回data, downgraded to r2")
                    fallback = R2ESILBackend()
                    return fallback.lift(binary_path, func_name)

        except Exception as e:
            logger.warning(f"Ghidra 提升failed ({e}), downgraded to r2 backend")
            fallback = R2ESILBackend()
            return fallback.lift(binary_path, func_name)

        return ir_fn

    def _map_pcode_mnemonic(self, mnemonic: str) -> IROpcode:
        mapping = {
            "COPY": IROpcode.MOV,
            "LOAD": IROpcode.LOAD,
            "STORE": IROpcode.STORE,
            "INT_ADD": IROpcode.ADD,
            "INT_SUB": IROpcode.SUB,
            "INT_MULT": IROpcode.MUL,
            "INT_DIV": IROpcode.DIV,
            "INT_REM": IROpcode.MOD,
            "INT_AND": IROpcode.AND,
            "INT_OR": IROpcode.OR,
            "INT_XOR": IROpcode.XOR,
            "INT_LEFT": IROpcode.SHL,
            "INT_RIGHT": IROpcode.SHR,
            "INT_EQUAL": IROpcode.CMP_EQ,
            "INT_NOTEQUAL": IROpcode.CMP_NE,
            "INT_LESS": IROpcode.CMP_LT,
            "INT_LESSEQUAL": IROpcode.CMP_LE,
            "INT_SLESS": IROpcode.CMP_LT,
            "BRANCH": IROpcode.JMP,
            "CBRANCH": IROpcode.JMP_COND,
            "CALL": IROpcode.CALL,
            "RETURN": IROpcode.RET,
            "PUSH": IROpcode.PUSH,
            "POP": IROpcode.POP,
        }
        return mapping.get(mnemonic.upper(), IROpcode.UNKNOWN)

    def _parse_pcode_operands(self, op: Dict[str, Any]) -> List[IROperand]:
        result: List[IROperand] = []
        output = op.get("output")
        if output:
            result.append(IROperand(OperandKind.REGISTER, output, 64))
        for inp in op.get("inputs", []):
            inp_str = str(inp)
            if inp_str.startswith("0x") or inp_str.lstrip("-").isdigit():
                try:
                    val = int(inp_str, 0) if inp_str.startswith("0x") else int(inp_str)
                    result.append(IROperand(OperandKind.IMMEDIATE, val, 32))
                except ValueError:
                    result.append(IROperand(OperandKind.REGISTER, inp_str, 64))
            elif inp_str.startswith("ram(") or inp_str.startswith("["):
                result.append(IROperand(OperandKind.MEMORY, inp_str, 64))
            else:
                result.append(IROperand(OperandKind.REGISTER, inp_str, 64))
        return result

class BinaryNinjaLLILBackend(IRBackend):
    """Binary Ninja LLIL backend - 通过 binaryninja Python API 提升"""

    NAME = "binja_llil"

    def supported(self) -> bool:
        try:
            import binaryninja
            return True
        except ImportError:
            return False

    def lift(self, binary_path: str, func_name: str) -> IRFunction:
        if not self.supported():
            logger.warning("Binary Ninja API unavailable, downgraded to r2 backend")
            fallback = R2ESILBackend()
            return fallback.lift(binary_path, func_name)

        try:
            import binaryninja as bn

            bv = bn.BinaryViewType.get_view_of_file(binary_path)
            if bv is None:
                bv = bn.BinaryViewType.get_view_of_file_with_options(
                    binary_path, update_analysis=False
                )
                if bv is None:
                    raise RuntimeError("无法打开binaryfile")
                bv.update_analysis_and_wait()

            ir_fn = IRFunction(name=func_name, address=0)
            funcs = bv.get_functions_by_name(func_name)
            if not funcs:
                logger.info(f"Binary Ninja 未found函数 {func_name}, downgraded to r2")
                fallback = R2ESILBackend()
                return fallback.lift(binary_path, func_name)

            func = funcs[0]
            ir_fn.address = func.start

            for bb in func.llil.basic_blocks if func.llil else []:
                block_id = f"bb_{bb.start:08x}"
                ir_block = IRBlock(
                    block_id=block_id,
                    start_addr=bb.start,
                    end_addr=bb.end
                )
                for ins in bb:
                    ir_ins = self._convert_llil(ins)
                    ir_block.instructions.append(ir_ins)
                # 解析后继
                for edge in bb.outgoing_edges:
                    if edge.target and edge.target.start:
                        ir_block.successors.append(f"bb_{edge.target.start:08x}")
                if ir_block.instructions:
                    ir_fn.blocks[block_id] = ir_block
                if ir_fn.entry_block is None:
                    ir_fn.entry_block = block_id

            ir_fn.arch = "binja_llil"
            bv.file.close() if hasattr(bv, 'file') else None
            return ir_fn

        except Exception as e:
            logger.warning(f"Binary Ninja 提升failed ({e}), downgraded to r2 backend")
            fallback = R2ESILBackend()
            return fallback.lift(binary_path, func_name)

    def _convert_llil(self, ins) -> IRInstruction:
        """将 LLIL 指令convert为统一 IR 指令"""
        llil_to_ir = {
            "LLIL_NOP": IROpcode.NOP,
            "LLIL_SET_REG": IROpcode.MOV,
            "LLIL_LOAD": IROpcode.LOAD,
            "LLIL_STORE": IROpcode.STORE,
            "LLIL_ADD": IROpcode.ADD,
            "LLIL_SUB": IROpcode.SUB,
            "LLIL_MUL": IROpcode.MUL,
            "LLIL_DIVU": IROpcode.DIV,
            "LLIL_DIVS": IROpcode.DIV,
            "LLIL_MODU": IROpcode.MOD,
            "LLIL_MODS": IROpcode.MOD,
            "LLIL_AND": IROpcode.AND,
            "LLIL_OR": IROpcode.OR,
            "LLIL_XOR": IROpcode.XOR,
            "LLIL_LSL": IROpcode.SHL,
            "LLIL_LSR": IROpcode.SHR,
            "LLIL_CMP_E": IROpcode.CMP_EQ,
            "LLIL_CMP_NE": IROpcode.CMP_NE,
            "LLIL_CMP_SLT": IROpcode.CMP_LT,
            "LLIL_CMP_SLE": IROpcode.CMP_LE,
            "LLIL_CMP_ULT": IROpcode.CMP_LT,
            "LLIL_CMP_ULE": IROpcode.CMP_LE,
            "LLIL_JUMP": IROpcode.JMP,
            "LLIL_IF": IROpcode.JMP_COND,
            "LLIL_CALL": IROpcode.CALL,
            "LLIL_RET": IROpcode.RET,
            "LLIL_PUSH": IROpcode.PUSH,
            "LLIL_POP": IROpcode.POP,
            "LLIL_SYSCALL": IROpcode.SYSCALL,
        }
        opcode = llil_to_ir.get(str(ins.operation), IROpcode.UNKNOWN)
        operands: List[IROperand] = []
        for tok in ins.tokens if hasattr(ins, 'tokens') else []:
            tok_str = str(tok)
            if tok_str.startswith("0x"):
                try:
                    val = int(tok_str, 16)
                    operands.append(IROperand(OperandKind.IMMEDIATE, val, 32))
                except ValueError:
                    operands.append(IROperand(OperandKind.REGISTER, tok_str, 64))
            else:
                operands.append(IROperand(OperandKind.REGISTER, tok_str, 64))
        return IRInstruction(
            opcode=opcode,
            operands=operands,
            address=ins.address,
            raw=str(ins)[:120]
        )

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

class TaintState:
    """污点status"""

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
    """based on统一 IR 做污点追踪"""
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
            elif ins.opcode in sink_ops and ins.operands:
                for op in ins.operands:
                    if str(op.value) in state.tainted:
                        state.propagations.append({
                            'op': 'sink_reach',
                            'sink': ins.opcode,
                            'var': str(op.value),
                            'address': hex(ins.address)
                        })
    return state

PATTERN_BUFFER_OVERFLOW = {
    'name': 'buffer_overflow_pattern',
    'sequence': [
        (IROpcode.LOAD, 'src'),
        (IROpcode.CMP_EQ, None),  # 简单lengthcheck (可选)
        (IROpcode.STORE, 'dst')    # 写入
    ]
}

def match_vuln_patterns(ir: IRFunction) -> List[Dict[str, Any]]:
    """简单漏洞modematch"""
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
    """convenience entry point: 提升 IR 并做污点 + mode分析"""
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

