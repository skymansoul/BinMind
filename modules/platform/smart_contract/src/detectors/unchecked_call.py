# SWC-104: CALL/DELEGATECALL 返回值未检查 - 静默失败

from typing import List
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..parser.evm_parser import EVMBytecodeParser


class UncheckedCallDetector(BaseDetector):
	"""SWC-104 未检查调用返回值 - EVM CALL 成功/失败用返回值表示。"""

	_CALL_OPS = frozenset({'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL', 'CREATE', 'CREATE2'})
	_CHECK_OPS = frozenset({'ISZERO', 'EQ', 'REVERT', 'JUMPI'})

	def __init__(self, parser: EVMBytecodeParser):
		super().__init__(parser)

	def detect(self) -> List[VulnerabilityReport]:
		findings: List[VulnerabilityReport] = []
		ops = self.ops

		for i, op in enumerate(ops):
			if op.name not in self._CALL_OPS:
				continue

			ret_checked = False
			for j in range(i + 1, min(i + 4, len(ops))):
				if ops[j].name in self._CHECK_OPS:
					ret_checked = True
					break

			if not ret_checked:
				vuln_type = "unchecked_delegatecall" if op.name == 'DELEGATECALL' else "unchecked_call"
				confidence = 0.88
				severity = "HIGH"

				findings.append(VulnerabilityReport(
					vuln_type=vuln_type,
					confidence=confidence,
					severity=severity,
					swc_id="SWC-104",
					description=f"{op.name} return value unchecked — silent failure risk",
					location=op.pc,
					opcode=op.name,
					affected_pcs=[op.pc],
					recommendation="check return value and revert on failure",
				))

		return findings
