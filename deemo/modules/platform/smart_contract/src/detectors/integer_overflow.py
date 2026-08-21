# SWC-101: 整数溢出/下溢 - 算术操作无安全检查

from typing import List
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..parser.evm_parser import EVMBytecodeParser


class IntegerOverflowDetector(BaseDetector):
    """SWC-101 溢出检测 - ADD/MUL/SUB 后无 ISZERO/EQ 即告警。"""

    _ARITH_OPS = frozenset({'ADD', 'MUL', 'SUB', 'SDIV', 'SMOD', 'DIV', 'MOD'})
    _CHECK_OPS = frozenset({'ISZERO', 'EQ', 'LT', 'GT', 'SLT', 'SGT'})

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []
        ops = self.ops

        for i, op in enumerate(ops):
            if op.name not in self._ARITH_OPS:
                continue

            # 后 5 条内无 guard → 告警
            guarded = False
            for j in range(i + 1, min(i + 6, len(ops))):
                if ops[j].name in self._CHECK_OPS:
                    guarded = True
                    break

            if not guarded:
                vuln_type = (
                    "integer_overflow"
                    if op.name in ('ADD', 'MUL')
                    else "integer_underflow"
                )

                findings.append(VulnerabilityReport(
                    vuln_type=vuln_type,
                    confidence=0.70,
                    severity="HIGH",
                    swc_id="SWC-101",
                    description=f"{op.name} without overflow check",
                    location=op.pc,
                    opcode=op.name,
                    affected_pcs=[op.pc],
                    recommendation="use SafeMath or Solidity 0.8+ built-in checked arithmetic",
                ))

        return findings
