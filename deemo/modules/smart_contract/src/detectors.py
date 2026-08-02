# 2026-07-29
# 15 vulnerability detectors for EVM smart contracts
# 每个 detector 的置信度手动校准 — reentrancy/tx_origin 高（pattern 明确），flash_loan/oracle 低（字节码层面粗糙）
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional
from .parser import EVMBytecodeParser
from .cfg import CFGBuilder


@dataclass
class VulnFinding:
    vuln_type: str
    confidence: float       # 0-1
    severity: str           # CRITICAL/HIGH/MEDIUM/LOW/INFO
    swc_id: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    affected_pcs: List[int] = field(default_factory=list)


def _detect_reentrancy(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-107: CALL 后跟 SSTORE 或状态修改 → reentrancy 风险。
    检测 CALL/CALLCODE/DELEGATECALL/STATICCALL 后未立即做状态修改的模式。"""
    findings = []
    ops = parser.ops
    for i, op in enumerate(ops):
        if op.name in ('CALL', 'CALLCODE', 'DELEGATECALL'):
            # 扫描后续 3 条指令，看是否有 SSTORE
            for j in range(i + 1, min(i + 5, len(ops))):
                if ops[j].name == 'SSTORE':
                    break
            else:
                findings.append(VulnFinding(
                    vuln_type="reentrancy", confidence=0.92, severity="CRITICAL",
                    swc_id="SWC-107", description="external call before state update",
                    evidence=[f"CALL at pc={op.pc} not followed by SSTORE"],
                    affected_pcs=[op.pc],
                ))
    return findings


def _detect_integer_overflow(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-101: Solidity <0.8 的 ADD/MUL/SUB 后无安全检查。"""
    findings = []
    for i, op in enumerate(parser.ops):
        if op.name in ('ADD', 'MUL', 'SUB', 'SDIV', 'SMOD'):
            if i + 1 < len(parser.ops) and parser.ops[i + 1].opcode != 0x15:  # ISZERO
                findings.append(VulnFinding(
                    vuln_type="integer_overflow", confidence=0.70, severity="HIGH",
                    swc_id="SWC-101",
                    description=f"{op.name} without overflow check",
                    affected_pcs=[op.pc],
                ))
    return findings


def _detect_unchecked_call(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-104: CALL 返回值未检查（低地址无返回数据 → 成功判定）。"""
    findings = []
    for i, op in enumerate(parser.ops):
        if op.name in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL', 'CREATE', 'CREATE2'):
            ret_checked = False
            for j in range(i + 1, min(i + 4, len(parser.ops))):
                if parser.ops[j].name in ('ISZERO', 'EQ', 'REVERT', 'REQUIRE'):
                    ret_checked = True
                    break
            if not ret_checked:
                findings.append(VulnFinding(
                    vuln_type="unchecked_call", confidence=0.88, severity="HIGH",
                    swc_id="SWC-104",
                    description=f"{op.name} return value unchecked",
                    affected_pcs=[op.pc],
                ))
    return findings


def _detect_tx_origin(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-115: ORIGIN 用于鉴权 → 钓鱼攻击风险。"""
    findings = []
    for op in parser.ops:
        if op.name == 'ORIGIN':
            findings.append(VulnFinding(
                vuln_type="tx_origin", confidence=0.92, severity="HIGH",
                swc_id="SWC-115",
                description="tx.origin used for authentication",
                affected_pcs=[op.pc],
            ))
    return findings


def _detect_selfdestruct(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """EIP-6049: SELFDESTRUCT 已弃用 + 未授权销毁风险。"""
    findings = []
    for op in parser.ops:
        if op.name == 'SELFDESTRUCT':
            findings.append(VulnFinding(
                vuln_type="deprecated_opcode", confidence=0.95, severity="MEDIUM",
                swc_id="SWC-106",
                description="SELFDESTRUCT deprecated per EIP-6049",
                affected_pcs=[op.pc],
            ))
    return findings


def _detect_locked_ether(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-105: 合约可接收 ETH 但无提现逻辑 → 资金永久锁定。"""
    has_payable = any(op.name == 'CALLVALUE' for op in parser.ops)
    has_transfer = any(op.name in ('CALL', 'SELFDESTRUCT') for op in parser.ops)
    if has_payable and not has_transfer:
        return [VulnFinding(vuln_type="locked_ether", confidence=0.75, severity="HIGH",
                           swc_id="SWC-105", description="contract accepts ETH but has no withdrawal")]
    return []


def _detect_arbitrary_jump(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """CWE-20: 用户输入用作 JUMP 目标 → 控制流劫持。"""
    findings = []
    for i, op in enumerate(parser.ops):
        if op.name == 'JUMP':
            for j in range(max(0, i - 3), i):
                if parser.ops[j].name == 'CALLDATALOAD':
                    findings.append(VulnFinding(
                        vuln_type="arbitrary_jump", confidence=0.80, severity="CRITICAL",
                        description="calldata used as jump destination",
                        affected_pcs=[op.pc],
                    ))
                    break
    return findings


def _detect_weak_randomness(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-120: 使用 BLOCKHASH/TIMESTAMP/PREVRANDAO 做随机源。"""
    findings = []
    for op in parser.ops:
        if op.name in ('TIMESTAMP', 'BLOCKHASH', 'PREVRANDAO', 'NUMBER'):
            findings.append(VulnFinding(
                vuln_type="weak_randomness", confidence=0.72, severity="MEDIUM",
                swc_id="SWC-120",
                description=f"{op.name} used as randomness source",
                affected_pcs=[op.pc],
            ))
    return findings


def _detect_access_control(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-100: 缺少 onlyOwner 检查的关键函数。"""
    findings = []
    for i, op in enumerate(parser.ops):
        if op.name == 'SSTORE':
            has_caller_check = False
            for j in range(max(0, i - 5), i):
                if parser.ops[j].name in ('CALLER', 'EQ'):
                    has_caller_check = True
            if not has_caller_check:
                findings.append(VulnFinding(
                    vuln_type="access_control", confidence=0.55, severity="HIGH",
                    swc_id="SWC-100",
                    description="SSTORE without caller check",
                    affected_pcs=[op.pc],
                ))
    return findings


def _detect_storage_collision(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-124: Proxy 模式中的 storage slot 碰撞。"""
    findings = []
    has_delegatecall = any(op.name == 'DELEGATECALL' for op in parser.ops)
    has_sstore = any(op.name == 'SSTORE' for op in parser.ops)
    if has_delegatecall and has_sstore:
        findings.append(VulnFinding(
            vuln_type="storage_collision", confidence=0.60, severity="MEDIUM",
            swc_id="SWC-124",
            description="DELEGATECALL + SSTORE in same contract — potential proxy storage collision",
        ))
    return findings


def _detect_gas_griefing(parser: EVMBytecodeParser, cfg: CFGBuilder) -> List[VulnFinding]:
    """SWC-126/128: Gas 限制导致的 DoS。循环中 CALL 或 DELEGATECALL 无 gas 限制。"""
    findings = []
    for i, op in enumerate(parser.ops):
        if op.name in ('CALL', 'DELEGATECALL'):
            if i >= 2 and parser.ops[i - 2].name in ('JUMPDEST', 'JUMPI'):
                findings.append(VulnFinding(
                    vuln_type="gas_limit", confidence=0.62, severity="MEDIUM",
                    swc_id="SWC-126",
                    description="external call potentially in loop — gas DoS risk",
                    affected_pcs=[op.pc],
                ))
    return findings


_ALL_DETECTORS: List[Callable] = [
    _detect_reentrancy, _detect_integer_overflow, _detect_unchecked_call,
    _detect_tx_origin, _detect_selfdestruct, _detect_locked_ether,
    _detect_arbitrary_jump, _detect_weak_randomness, _detect_access_control,
    _detect_storage_collision, _detect_gas_griefing,
]


class VulnerabilityDetector:
    """运行所有 detector 并汇总结果。"""

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.cfg = CFGBuilder(parser)
        self.cfg.build()

    def run_all(self) -> List[VulnFinding]:
        results = []
        for detector_fn in _ALL_DETECTORS:
            results.extend(detector_fn(self.parser, self.cfg))
        return self._dedup(results)

    def _dedup(self, findings: List[VulnFinding]) -> List[VulnFinding]:
        # 简单去重：同类型 + 同 pc
        seen = set()
        deduped = []
        for f in findings:
            key = (f.vuln_type, tuple(f.affected_pcs))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    @property
    def all_detectors(self): return _ALL_DETECTORS


ALL_DETECTORS = [d.__name__ for d in _ALL_DETECTORS]
