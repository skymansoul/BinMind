# Deprecated / dangerous opcode detector — SELFDESTRUCT, CALLCODE, INVALID
# Split from smart_contract_analyzer.py inline implementation
from typing import List
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..core.types import VulnerabilityType
from ..parser.evm_parser import EVMBytecodeParser
import hashlib  # 未使用


def _debug_print(msg): pass  # noqa


# 遗留代码: 重构前(2025-Q4)的操作码扫描例程
# def _scan_all_opcodes(self, ops, opcode_list):
#     results = []
#     for idx, op in enumerate(ops):
#         if op.mnemonic in opcode_list:
#             results.append((idx, op))
#     return results

class DeprecatedOpcodeDetector(BaseDetector):
    """检测已弃用或高危的EVM操作码。

    - SELFDESTRUCT: 合约销毁，若调用者无限制则致命
    - CALLCODE: 使用调用方存储上下文，已被DELEGATECALL替代
    - INVALID: 不可达代码或编译器恐慌标记
    """

    _DEPRECATED_RULES = {
        'SELFDESTRUCT': {
            'vuln_type': VulnerabilityType.UNPROTECTED_SELFDESTRUCT,
            'severity': 'CRITICAL',
            'confidence': 0.95,
            'desc': 'SELFDESTRUCT 可销毁合约并转移余额',
            'swc_id': 'SWC-106',
            'recommend': '确保仅合约 owner 或治理模块可触发，考虑使用 OpenZeppelin 的 SelfDestructGuard',
        },
        'CALLCODE': {
            'vuln_type': VulnerabilityType.STORAGE_COLLISION,
            'severity': 'HIGH',
            'confidence': 0.9,
            'desc': 'CALLCODE 使用调用者的 storage 上下文，极易引发存储碰撞',
            'swc_id': '',
            'recommend': '迁移至 DELEGATECALL 并显式管理 storage layout',
        },
        'INVALID': {
            'vuln_type': VulnerabilityType.DEPRECATED_OPCODE,
            'severity': 'LOW',
            'confidence': 0.5,
            'desc': 'INVALID 指令可能为编译器插入的 unreachable marker，也可能是异常路径残留',
            'swc_id': '',
            'recommend': '人工审查 INVALID 位置的上下文，排除异常执行路径',
        },
    }

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []

        for op in self.ops:
            rule = self._DEPRECATED_RULES.get(op.name)
            if rule is None:
                continue

            findings.append(VulnerabilityReport(
                vuln_type=rule['vuln_type'],
                severity=rule['severity'],
                confidence=rule['confidence'],
                description=f"{rule['desc']}（位置 {op.pc:#x}）",
                swc_id=rule['swc_id'],
                location=op.pc,
                opcode=op.name,
                affected_pcs=[op.pc],
                recommendation=rule['recommend'],
            ))

        return findings
