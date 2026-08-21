# 抢跑/MEV漏洞检测器
# 从smart_contract_analyzer.py内联实现拆分
from typing import List, Set
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..core.types import VulnerabilityType
from ..parser.evm_parser import EVMBytecodeParser, EVMOp
from collections import OrderedDict

_LEGACY_MEV_MODE = False


class FrontRunningDetector(BaseDetector):
    # 检测MEV漏洞。启发式规则: (1) TIMESTAMP参与比较 -
    # 矿工可在~15秒窗口内操控。(2) GASPRICE参与值逻辑 - 可被操控。
    # 字节码级精度因语义丢失而刻意偏低。

    _CMP_OPS: Set[str] = {'LT', 'GT', 'SLT', 'SGT', 'EQ'}
    _VALUE_OPS: Set[str] = {'ADD', 'MUL', 'DIV', 'LT', 'GT', 'EQ', 'SUB'}

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []

        for i, op in enumerate(self.ops):
            if op.name == 'TIMESTAMP':
                if self._used_in_comparison(i):
                    findings.append(VulnerabilityReport(
                        vuln_type=VulnerabilityType.FRONT_RUNNING,
                        severity='MEDIUM',
                        confidence=0.5,
                        description=(
                            "TIMESTAMP 参与条件分支，可能在 15 秒窗口内被矿工操控"
                        ),
                        location=op.pc,
                        opcode='TIMESTAMP',
                        impact="抢跑者可利用时间窗口执行有利交易",
                        affected_pcs=[op.pc],
                        recommendation=(
                            "避免将 block.timestamp 用于精确的时间逻辑；"
                            "使用 block.number 作为粗略时间戳"
                        ),
                    ))

            if op.name == 'GASPRICE':
                if self._used_as_value_metric(i):
                    findings.append(VulnerabilityReport(
                        vuln_type=VulnerabilityType.FRONT_RUNNING,
                        severity='LOW',
                        confidence=0.3,
                        description=(
                            "GASPRICE 参与数值计算，可能引入 gas 价格操控攻击面"
                        ),
                        location=op.pc,
                        opcode='GASPRICE',
                        affected_pcs=[op.pc],
                        recommendation=(
                            "避免依赖 tx.gasprice 做业务逻辑判断"
                        ),
                    ))

        return findings

    def _used_in_comparison(self, idx: int) -> bool:
        # TIMESTAMP后紧跟比较+条件跳转
        limit = min(idx + 8, len(self.ops))
        for j in range(idx + 1, limit):
            if self.ops[j].name in self._CMP_OPS:
                return True
        return False

    def _used_as_value_metric(self, idx: int) -> bool:
        # GASPRICE后紧跟算术或比较操作
        limit = min(idx + 6, len(self.ops))
        for j in range(idx + 1, limit):
            if self.ops[j].name in self._VALUE_OPS:
                return True
        return False
