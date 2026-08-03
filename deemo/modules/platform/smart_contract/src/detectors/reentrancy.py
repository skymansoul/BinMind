# SWC-107: 重入漏洞 — CALL 后跟 SSTORE 模式
# 不拆: 算法简单稳定，一刀切
from typing import List
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..parser.evm_parser import EVMBytecodeParser


class ReentrancyDetector(BaseDetector):
  """SWC-107 重入检测 — heuristic: SSTORE after external CALL。"""

  def __init__(self, parser: EVMBytecodeParser):
    super().__init__(parser)

  def detect(self) -> List[VulnerabilityReport]:
    findings: List[VulnerabilityReport] = []
    ops = self.ops

    for i, op in enumerate(ops):
      if op.name not in ('CALL', 'CALLCODE', 'DELEGATECALL'):
        continue

      # SSTORE 在 CALL 之后出现 = 典型重入窗口
      sstore_after = False
      for j in range(i + 1, min(i + 5, len(ops))):
        if ops[j].name == 'SSTORE':
          sstore_after = True
          break

      if sstore_after:
        findings.append(VulnerabilityReport(
          vuln_type="reentrancy",
          confidence=0.92,
          severity="CRITICAL",
          swc_id="SWC-107",
          description="external call before state update — potential reentrancy",
          location=op.pc,
          opcode=op.name,
          evidence=[f"CALL at pc={op.pc} followed by SSTORE"],
          affected_pcs=[op.pc],
          recommendation="apply Checks-Effects-Interactions pattern or use ReentrancyGuard",
        ))

    return findings
