"""
智能合约字节码安全分析模块

功能：
1. EVM 字节码解析与反编译
2. WASM 合约解析
3. 重入漏洞检测
4. 整数溢出检测
5. 未检查调用检测
6. 利用路径生成

支持的链：
- 以太坊/EVM兼容链
- WASM链（如Polkadot/Substrate）

安全考虑：
- 仅用于授权的智能合约安全研究
- 检测结果需人工验证
- 需考虑不同链的特性差异
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class ContractType(Enum):
    EVM = "evm"
    WASM = "wasm"
    SOLIDITY = "solidity"
    VYPER = "vyper"


class VulnerabilityType(Enum):
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
    opcode: int
    mnemonic: str
    operand: Optional[int] = None
    position: int = 0
    stack_effect: Tuple[int, int] = (0, 0)


@dataclass
class EVMBasicBlock:
    start: int
    end: int
    instructions: List[EVMInstruction]
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    stack_height: int = 0
    is_reachable: bool = True


@dataclass
class ContractVulnerability:
    vuln_type: VulnerabilityType
    severity: str
    confidence: float
    description: str
    location: int
    opcode: str
    function_name: Optional[str] = None
    impact: str = ""
    recommendation: str = ""
    exploit_path: List[str] = field(default_factory=list)


@dataclass
class ContractFunction:
    name: str
    selector: str
    entry_point: int
    basic_blocks: List[int] = field(default_factory=list)
    vulnerabilities: List[ContractVulnerability] = field(default_factory=list)
    is_payable: bool = False
    state_mutability: str = "nonpayable"


@dataclass
class ContractAnalysisReport:
    contract_type: ContractType
    bytecode_hash: str
    functions: List[ContractFunction]
    vulnerabilities: List[ContractVulnerability]
    total_vulnerabilities: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    analysis_time: float
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EVMBytecodeParser:
    """EVM 字节码解析器"""
    
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
        pc = 0,
        while pc < len(self.bytecode):
            opcode = self.bytecode[pc]
            
            if opcode in self.OPCODES:
                mnemonic, pops, pushes = self.OPCODES[opcode]
                operand_size = 0
                
                if 0x60 <= opcode <= 0x7f:
                    operand_size = opcode - 0x5f
                    operand = int.from_bytes()
                        self.bytecode[pc + 1:pc + 1 + operand_size],
                        'big'
                    ) if operand_size > 0 else None
                else:
                    operand = None
                
                self.instructions.append(EVMInstruction(
                    opcode=opcode,
                    mnemonic=mnemonic,
                    operand=operand,
                    position=pc,
                    stack_effect=(pops, pushes)
                

                
                if mnemonic == 'JUMPDEST':
                    self.jumpdests.add(pc)
                
                pc += 1 + operand_size
            else:
                pc += 1
    
    def extract_basic_blocks(self) -> Dict[int, EVMBasicBlock]:
        if self.basic_blocks:
            return self.basic_blocks
        
        blocks = {}
        current_block_start = 0
        i = 0
        
        while i < len(self.instructions):
            instr = self.instructions[i]
            
            if instr.mnemonic == 'JUMPDEST' and i > 0:
                blocks[current_block_start] = EVMBasicBlock()
                    start=current_block_start,
                    end=self.instructions[i-1].position,
                    instructions=self.instructions[current_block_start:i]
                
                current_block_start = i
            
            if instr.mnemonic in ('JUMP', 'JUMPI', 'RETURN', 'REVERT', 'STOP', 'SELFDESTRUCT'):
                blocks[current_block_start] = EVMBasicBlock()
                    start=current_block_start,
                    end=instr.position,
                    instructions=self.instructions[current_block_start:i+1]
                
                current_block_start = i + 1
            
            i += 1
        
        if current_block_start < len(self.instructions):
            blocks[current_block_start] = EVMBasicBlock()
                start=current_block_start,
                end=self.instructions[-1].position,
                instructions=self.instructions[current_block_start:]
            
        
        self.basic_blocks = blocks,
        return blocks
    
    def find_function_selectors(self) -> Dict[str, int]:
        selectors = {}
        pattern = re.compile(rb'\x63([a-f0-9]{8})\x60\x00\x60\x00(\xf0|\xf1|\xf4|\xfa)')
        
        for match in pattern.finditer(self.bytecode):
            selector = match.group(1).hex()
            position = match.start()
            selectors[selector] = position
        
        return selectors
    
    def get_instructions(self) -> List[EVMInstruction]:
        return self.instructions
    
    def has_instruction(self, mnemonic: str) -> bool:
        return any(i.mnemonic == mnemonic for i in self.instructions)


class WASMContractParser:
    WASM_MAGIC = b'\x00asm'
    
    def __init__(self, wasm_bytes: bytes):
        self.data = wasm_bytes
        self.magic_valid = self.data.startswith(self.WASM_MAGIC)
        self.sections = []
        self.imports = []
        
        if self.magic_valid:
            self._parse()
    
    def _parse(self):
        offset = 8,
        while offset < len(self.data):
            section_id = self.data[offset]
            length = self._read_varuint(offset + 1)
            section_end = offset + 1 + length[1] + length[0]
            
            self.sections.append({)
                'id': section_id,
                'offset': offset,
                'length': length[0],
                'data': self.data[offset + 1 + length[1]:section_end]
            }
            
            if section_id == 2:
                self._parse_import_section(self.data[offset + 1 + length[1]:section_end])
            
            offset = section_end
    
    def _read_varuint(self, offset: int) -> Tuple[int, int]:
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
            
            self.imports.append({)
                'module': module,
                'name': name
            }
    
    def has_sensitive_imports(self) -> bool:
        sensitive_imports = ['ethereum', 'env', 'seal', 'extism']
        return any(imp['module'] in sensitive_imports for imp in self.imports)


class ReentrancyDetector:
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
                        description=f"潜在重入漏洞：在状态修改前进行外部调用",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        impact="攻击者可递归调用函数，多次提取资金",
                        recommendation="使用 Checks-Effects-Interactions 模式"
                    

        
        return self.vulnerabilities
    
    def _has_reentrancy_pattern(self, instructions: List[EVMInstruction], call_idx: int) -> bool:
        sstore_before = False
        call_found = False
        
        for i in range(min(call_idx + 50, len(instructions))):
            instr = instructions[i]
            
            if instr.mnemonic == 'SSTORE':
                if call_found:
                    return True
                sstore_before = True
            
            if instr.mnemonic in ['CALL', 'DELEGATECALL']:
                call_found = True,
                if sstore_before:
                    return False
        
        return call_found


class IntegerOverflowDetector:
    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []
    
    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()
        
        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['ADD', 'MUL', 'SUB', 'DIV']:
                if not self._has_overflow_check(instructions, i):
                    severity = 'High' if instr.mnemonic in ['MUL'] else 'Medium'
                    vuln_type = VulnerabilityType.INTEGER_OVERFLOW if instr.mnemonic in ['ADD', 'MUL'] else VulnerabilityType.INTEGER_UNDERFLOW
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=vuln_type,
                        severity=severity,
                        confidence=0.7,
                        description=f"未检查的{instr.mnemonic}操作可能导致整数溢出/下溢",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        recommendation="使用 SafeMath 库或 Solidity 0.8+ 的内置检查"
                    

        
        return self.vulnerabilities
    
    def _has_overflow_check(self, instructions: List[EVMInstruction], idx: int) -> bool:
        check_instructions = ['LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO']
        for i in range(idx, min(idx + 10, len(instructions))):
            if instructions[i].mnemonic in check_instructions:
                return True
        return False


class UncheckedCallDetector:
    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.vulnerabilities: List[ContractVulnerability] = []
    
    def detect(self) -> List[ContractVulnerability]:
        instructions = self.parser.get_instructions()
        
        for i, instr in enumerate(instructions):
            if instr.mnemonic in ['CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE']:
                if not self._has_result_check(instructions, i):
                    vuln_type = VulnerabilityType.UNCHECKED_DELEGATECALL if instr.mnemonic == 'DELEGATECALL' else VulnerabilityType.UNCHECKED_CALL
                    self.vulnerabilities.append(ContractVulnerability(
                        vuln_type=vuln_type,
                        severity='High',
                        confidence=0.8,
                        description=f"{instr.mnemonic} 调用返回值未检查",
                        location=instr.position,
                        opcode=instr.mnemonic,
                        recommendation="检查调用返回值，失败时进行适当处理"
                    

        
        return self.vulnerabilities
    
    def _has_result_check(self, instructions: List[EVMInstruction], idx: int) -> bool:
        for i in range(idx + 1, min(idx + 5, len(instructions))):
            if instructions[i].mnemonic in ['ISZERO', 'JUMPI']:
                return True
        return False


class SmartContractAnalyzer(BaseAnalyzer, ABC):
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
        bytecode = kwargs.get("bytecode")
        contract_type = kwargs.get("contract_type", "evm")
        output_format = kwargs.get("output_format", "json")
        
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}
        
        import time
        start_time = time.time()
        
        try:
            contract_type_enum = ContractType(contract_type.lower(

            
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
            self.logger.error(f"Smart contract analysis failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _analyze_evm(self, bytecode: bytes) -> Dict[str, Any]:
        parser = EVMBytecodeParser(bytecode)
        vulnerabilities = []
        
        if self._config.get("detect_reentrancy", True):
            detector = ReentrancyDetector(parser)
            vulnerabilities.extend(detector.detect(

        
        if self._config.get("detect_overflow", True):
            detector = IntegerOverflowDetector(parser)
            vulnerabilities.extend(detector.detect(

        
        if self._config.get("detect_unchecked_call", True):
            detector = UncheckedCallDetector(parser)
            vulnerabilities.extend(detector.detect(

        
        if self._config.get("detect_tx_origin", True):
            vulnerabilities.extend(self._detect_tx_origin(parser

        
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
        parser = WASMContractParser(bytecode)
        vulnerabilities = []
        
        if parser.has_sensitive_imports():
            vulnerabilities.append(ContractVulnerability(
                vuln_type=VulnerabilityType.STORAGE_COLLISION,
                severity='Medium',
                confidence=0.6,
                description="检测到敏感外部导入",
                location=0,
                opcode='import'
            

        
        return {
            "contract_type": "wasm",
            "bytecode_length": len(bytecode),
            "import_count": len(parser.imports),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities],
            "imports": parser.imports
        }
    
    def _detect_tx_origin(self, parser: EVMBytecodeParser) -> List[ContractVulnerability]:
        vulnerabilities = []
        
        for instr in parser.get_instructions():
            if instr.mnemonic == 'ORIGIN':
                vulnerabilities.append(ContractVulnerability(
                    vuln_type=VulnerabilityType.TX_ORIGIN,
                    severity='High',
                    confidence=0.9,
                    description="使用 tx.origin 进行身份验证，可能被钓鱼攻击利用",
                    location=instr.position,
                    opcode='ORIGIN',
                    recommendation="使用 msg.sender 替代 tx.origin"
                

        
        return vulnerabilities
    
    def _filter_by_confidence(self, vulnerabilities: List[ContractVulnerability]) -> List[ContractVulnerability]:
        threshold = self._config.get("confidence_threshold", 0.5)
        max_vulns = self._config.get("max_vulns", 100)
        
        filtered = [v for v in vulnerabilities if v.confidence >= threshold]
        return filtered[:max_vulns]
    
    def _serialize_vuln(self, vuln: ContractVulnerability) -> Dict[str, Any]:
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
        bytecode = kwargs.get("bytecode")
        
        if not bytecode:
            return False, "必须提供 bytecode"
        
        if not isinstance(bytecode, bytes):
            return False, "bytecode 必须是 bytes 类型"
        
        return True, None
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
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
])))))))))))))))))))))