# SWC-115: tx.origin 用于鉴权 → 钓鱼攻击面

from typing import List
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..parser.evm_parser import EVMBytecodeParser


class TxOriginDetector(BaseDetector):
  """SWC-115 tx.origin 鉴权检测 - ORIGIN + (EQ/SUB/XOR) + JUMPI 模式。"""

  def __init__(self, parser: EVMBytecodeParser):
    super().__init__(parser)

  def detect(self) -> List[VulnerabilityReport]:
    findings: List[VulnerabilityReport] = []
    ops = self.ops

    for i, op in enumerate(ops):
      if op.name != 'ORIGIN':
        continue

      # ORIGIN 后 4 条内出现比较 + JUMPI = 鉴权模式
      used_for_auth = False
      for j in range(i + 1, min(i + 4, len(ops))):
        if ops[j].name in ('EQ', 'SUB', 'XOR'):
          if j + 1 < len(ops) and ops[j + 1].name == 'JUMPI':
            used_for_auth = True
            break

      confidence = 0.92 if used_for_auth else 0.72

      findings.append(VulnerabilityReport(
        vuln_type="tx_origin",
        confidence=confidence,
        severity="HIGH",
        swc_id="SWC-115",
        description="tx.origin used for authentication — phishing attack surface",
        location=op.pc,
        opcode="ORIGIN",
        affected_pcs=[op.pc],
        recommendation="replace tx.origin with msg.sender",
      ))

    return findings

def _debug_print(*args, **kwargs):  # 调试残余，未删除
    """环境变量BINMIND_DEBUG置位时输出调试信息。"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
