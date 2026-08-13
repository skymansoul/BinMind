"""
smart_contract_analyzer — EVM / WASM 合约字节码安全分析。

此文件保留作为向后兼容入口。内部实现已拆分为 src/ 下各子模块。
所有分析逻辑通过 SmartContractAnalyzer (继承 BaseAnalyzer) 接入平台插件系统。
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class ContractType:
    """合约类型常量 — 向后兼容保留。新代码使用 src.core.types.ContractType。"""
    EVM = "evm"
    WASM = "wasm"
    SOLIDITY = "solidity"
    VYPER = "vyper"


class VulnerabilityType:
    """漏洞类型常量 — 向后兼容保留。新代码使用 src.core.types.VulnerabilityType。"""
    REENTRANCY = "reentrancy"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    UNCHECKED_CALL = "unchecked_call"
    UNCHECKED_SEND = "unchecked_send"
    UNCHECKED_DELEGATECALL = "unchecked_delegatecall"
    TX_ORIGIN = "tx_origin"
    ABI_ENCODE_PACKED = "abi_encode_packed"
    DEPRECATED_OPCODE = "deprecated_opcode"
    GAS_LIMIT = "gas_limit"
    STORAGE_COLLISION = "storage_collision"
    SIGNATURE_REPLAY = "signature_replay"
    FRONT_RUNNING = "front_running"
    REENTRANCY_GUARD_MISSING = "reentrancy_guard_missing"


@dataclass
class EVMInstruction:
    """单条 EVM 指令 — opcode、助记符、可选立即数、栈影响"""
    opcode: int
    mnemonic: str
    operand: Optional[int] = None
    position: int = 0
    stack_effect: tuple = (0, 0)  # (pops, pushes)


@dataclass
class EVMBasicBlock:
    """EVM 基本块 — 连续指令序列，首指令为入口，末指令为分支/终止"""
    start: int
    end: int
    instructions: List[EVMInstruction]
    predecessors: list = field(default_factory=list)
    successors: list = field(default_factory=list)
    stack_height: int = 0
    is_reachable: bool = True


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


class EVMBytecodeParser:
    """EVM 字节码解析器"""

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

    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.instructions: List[EVMInstruction] = []
        self.basic_blocks: Dict[int, EVMBasicBlock] = {}
        self.jumpdests: Set[int] = set()
        self._parse()

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

    def find_function_selectors(self) -> Dict[str, int]:
        """匹配 Solidity dispatch 模式提取 function selector"""
        selectors = {}
        pattern = re.compile(rb'\x63([a-f0-9]{8})\x60\x00\x60\x00(\xf0|\xf1|\xf4|\xfa)')

        for match in pattern.finditer(self.bytecode):
            selector = match.group(1).hex()
            position = match.start()
            selectors[selector] = position

        return selectors

    def get_instructions(self) -> List[EVMInstruction]:
        """返回已解析的指令列表"""
        return self.instructions

    def has_instruction(self, mnemonic: str) -> bool:
        """检查字节码中是否包含特定助记符"""
        return any(i.mnemonic == mnemonic for i in self.instructions)


class WASMContractParser:
    """WASM 二进制解析器 — 仅覆盖安全审计所需的子集"""
    WASM_MAGIC = b'\x00asm'

    def __init__(self, wasm_bytes: bytes):
        self.data = wasm_bytes
        self.magic_valid = self.data.startswith(self.WASM_MAGIC)
        self.sections = []
        self.imports = []

        if self.magic_valid:
            self._parse()

    def _parse(self):
        """按 WASM 格式逐 section 解析"""
        offset = 8  # magic + version = 8 bytes
        while offset < len(self.data):
            section_id = self.data[offset]
            length = self._read_varuint(offset + 1)
            section_end = offset + 1 + length[1] + length[0]

            self.sections.append({
                'id': section_id,
                'offset': offset,
                'length': length[0],
                'data': self.data[offset + 1 + length[1]:section_end]
            })

            # section id=2 → import section
            if section_id == 2:
                self._parse_import_section(self.data[offset + 1 + length[1]:section_end])

            offset = section_end

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

            self.imports.append({
                'module': module,
                'name': name
            })

    def has_sensitive_imports(self) -> bool:
        """检查 import 列表中是否含有区块链宿主环境敏感模块"""
        sensitive_imports = ['ethereum', 'env', 'seal', 'extism']
        return any(imp['module'] in sensitive_imports for imp in self.imports)


class ReentrancyDetector:
    """重入漏洞检测 — 判断 SSTORE 与 CALL 的前后位置关系"""

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []

    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()

        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['CALL', 'DELEGATECALL']:
                if self._has_reentrancy_pattern(instructions, i):
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=VulnerabilityType.REENTRANCY,
                        severity='Critical',
                        confidence=0.85,
                        description="潜在重入漏洞：状态修改前存在外部调用",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        impact="攻击者通过递归调用反复提取资金",
                        recommendation="采用 Checks-Effects-Interactions 模式"
                    ))

        return self.vulnerabilities

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


class SmartContractAnalyzer(BaseAnalyzer):
    """智能合约安全分析器 — 平台插件入口"""

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
            "confidence_threshold": 0.5,
            "max_vulns": 100
        }

    def _setup_logging(self) -> None:
        self.logger = logging.getLogger(__name__)
        if LOGURU_AVAILABLE:
            self.logger = loguru_logger
        self.logger.info("SmartContractAnalyzer initialized")

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """执行合约安全分析"""
        bytecode = kwargs.get("bytecode")
        contract_type = kwargs.get("contract_type", "evm")
        output_format = kwargs.get("output_format", "json")

        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}

        import time
        start_time = time.time()

        try:
            contract_type_enum = ContractType(contract_type.lower())

            if contract_type_enum == ContractType.EVM:
                result = self._analyze_evm(bytecode)
            elif contract_type_enum == ContractType.WASM:
                result = self._analyze_wasm(bytecode)
            else:
                return {"success": False, "error": f"不支持的合约类型: {contract_type}"}

            result["analysis_time"] = time.time() - start_time

            if output_format == "json":
                return {"success": True, "report": result}
            else:
                return {"success": True, "report": self._format_text_report(result)}

        except Exception as e:
            self.logger.error(f"合约分析失败: {e}")
            return {"success": False, "error": str(e)}

    def _analyze_evm(self, bytecode: bytes) -> Dict[str, Any]:
        """EVM 合约分析流水线"""
        parser = EVMBytecodeParser(bytecode)
        vulnerabilities = []

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

        vulnerabilities = self._filter_by_confidence(vulnerabilities)
        selectors = parser.find_function_selectors()

        return {
            "contract_type": "evm",
            "bytecode_length": len(bytecode),
            "function_selectors": selectors,
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": sum(1 for v in vulnerabilities if v.severity in ['Critical', 'High']),
            "medium_severity": sum(1 for v in vulnerabilities if v.severity == 'Medium'),
            "low_severity": sum(1 for v in vulnerabilities if v.severity == 'Low'),
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities]
        }

    def _analyze_wasm(self, bytecode: bytes) -> Dict[str, Any]:
        """WASM 合约分析 — 当前仅覆盖敏感 import 检测"""
        parser = WASMContractParser(bytecode)
        vulnerabilities = []

        if parser.has_sensitive_imports():
            vulnerabilities.append(ContractVulnerability(
                vuln_type=VulnerabilityType.STORAGE_COLLISION,
                severity='Medium',
                confidence=0.6,
                description="检测到敏感外部 import，存在权限风险",
                location=0,
                opcode='import'
            ))

        return {
            "contract_type": "wasm",
            "bytecode_length": len(bytecode),
            "import_count": len(parser.imports),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities],
            "imports": parser.imports
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

    def _filter_by_confidence(self, vulnerabilities: List[ContractVulnerability]) -> List[ContractVulnerability]:
        """按置信度阈值和最大数量截断漏洞列表"""
        threshold = self._config.get("confidence_threshold", 0.5)
        max_vulns = self._config.get("max_vulns", 100)

        filtered = [v for v in vulnerabilities if v.confidence >= threshold]
        return filtered[:max_vulns]

    def _serialize_vuln(self, vuln: ContractVulnerability) -> Dict[str, Any]:
        """ContractVulnerability → JSON 兼容 dict"""
        return {
            "type": vuln.vuln_type.value,
            "severity": vuln.severity,
            "confidence": vuln.confidence,
            "description": vuln.description,
            "location": hex(vuln.location),
            "opcode": vuln.opcode,
            "recommendation": vuln.recommendation
        }

    def _format_text_report(self, report: Dict[str, Any]) -> str:
        """纯文本报告渲染"""
        lines = [
            "Smart Contract Security Analysis Report",
            "=" * 50,
            f"Contract Type: {report['contract_type'].upper()}",
            f"Total Vulnerabilities: {report['total_vulnerabilities']}"
        ]

        for i, vuln in enumerate(report.get('vulnerabilities', []), 1):
            lines.append(f"  [{i}] {vuln['type']}")
            lines.append(f"      Severity: {vuln['severity']}, Confidence: {vuln['confidence']:.0%}")
            lines.append(f"      {vuln['description']}")

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
    'VulnerabilityType'
]
