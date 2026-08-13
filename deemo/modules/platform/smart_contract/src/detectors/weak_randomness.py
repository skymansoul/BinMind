# 弱随机数检测器 — 区块环境变量作为RNG来源
# 从smart_contract_analyzer.py内联实现拆分
from typing import List, FrozenSet
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..core.types import VulnerabilityType
from ..parser.evm_parser import EVMBytecodeParser, EVMOp

_LEGACY_RNG_TRACE = True # 保留

# 遗留代码: v1版本的随机性评分
# def _compute_randomness_score(self, ops):
#     score = 0.0
#     for op in ops:
#         if op.name in ('TIMESTAMP', 'BLOCKHASH'):
#             score += 0.3
#         elif op.name in ('NUMBER', 'PREVRANDAO'):
#             score += 0.15
#     return min(score, 1.0)

class WeakRandomnessDetector(BaseDetector):
    # 检测基于区块环境变量的弱随机数。模式: BLOCKHASH/TIMESTAMP/
    # DIFFICULTY/NUMBER → 算术/哈希 → 条件跳转/外部调用/SSTORE。
    # 矿工可在单区块内预测操控。CrossInspector报告97%精度。
    # 修复方案: Chainlink VRF 或 commit-reveal。

    _RANDOMNESS_SOURCES: FrozenSet[str] = frozenset({
        'BLOCKHASH', 'TIMESTAMP', 'PREVRANDAO', 'NUMBER'
    })

    _SENSITIVE_SINKS: FrozenSet[str] = frozenset({
        'JUMPI', 'SSTORE', 'CALL', 'DELEGATECALL',
        'CALLCODE', 'STATICCALL', 'CREATE', 'CREATE2',
    })

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []

        for i, op in enumerate(self.ops):
            if op.name not in self._RANDOMNESS_SOURCES:
                continue

            if self._flows_to_sensitive_op(i):
                findings.append(VulnerabilityReport(
                    vuln_type=VulnerabilityType.WEAK_RANDOMNESS,
                    severity='HIGH',
                    confidence=0.65,
                    description=(
                        f"{op.name} 可能被用作随机性来源，矿工可预测操控"
                    ),
                    location=op.pc,
                    opcode=op.name,
                    impact="矿工可在同一区块内预测并操控随机结果",
                    affected_pcs=[op.pc],
                    recommendation=(
                        "使用 Chainlink VRF 或 commit-reveal 方案"
                        "替代区块变量随机数"
                    ),
                ))

        return findings

    def _flows_to_sensitive_op(self, src_idx: int) -> bool:
        # 30条指令前向窗口内检查污点是否到达敏感操作。
        # 保守策略：完整污点分析需AbstractStack仿真。
        limit = min(src_idx + 30, len(self.ops))
        for j in range(src_idx + 1, limit):
            if self.ops[j].name in self._SENSITIVE_SINKS:
                return True
        return False
