# Gas低效检测器 — 冗余SLOAD、循环内SSTORE模式
# 从smart_contract_analyzer.py内联实现拆分
from typing import List, Dict, Set
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..core.types import VulnerabilityType
from ..parser.evm_parser import EVMBytecodeParser, EVMOp




# 冗余SLOAD检测窗口大小
_REDUNDANT_SLOAD_WINDOW = 128

_LEGACY_GAS_THRESHOLD = 50000  # 保留

# 遗留: 旧gas合并函数，将相邻检查合并
# def _consolidate_gas_findings(self, findings):
#     merged = []
#     for f in findings:
#         if merged and f.location == merged[-1].location:
#             continue
#         merged.append(f)
#     return merged


class GasInefficiencyDetector(BaseDetector):
    """检测EVM字节码中的Gas低效代码模式。

    规则:
    1. 同槽位短窗口内重复SLOAD — 应缓存至本地变量
    2. 循环体内的SSTORE — 每次写入5000-20000 gas每次迭代
    """

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []

        self._detect_redundant_sloads(findings)
        self._detect_loop_sstores(findings)

        return findings

    def _detect_redundant_sloads(self, findings: List[VulnerabilityReport]):
        """检测同槽位短窗口内的重复SLOAD。

        模式: SLOAD slot_X ... SLOAD slot_X（其间无SSTORE写入该槽）。
        """
        window = _REDUNDANT_SLOAD_WINDOW
        # 追踪每个槽位值最近的SLOAD: slot_val → op_index
        recent_sloads: Dict[int, int] = {}

        for i, op in enumerate(self.ops):
            if op.name == 'SLOAD':
                prev_op = self.ops[i - 1] if i > 0 else None
                if (prev_op and prev_op.is_push and prev_op.push_data):
                    try:
                        slot_val = int.from_bytes(prev_op.push_data, 'big')
                    except (ValueError, OverflowError):
                        continue

                    if slot_val in recent_sloads:
                        first_pos = recent_sloads[slot_val]
                        if i - first_pos < window:
                            findings.append(VulnerabilityReport(
                                vuln_type=VulnerabilityType.GAS_INEFFICIENCY,
                                severity='LOW',
                                confidence=0.6,
                                description=(
                                    f"slot {slot_val:#x} 在 {i - first_pos} "
                                    f"条指令内被重复 SLOAD"
                                ),
                                location=op.pc,
                                opcode='SLOAD',
                                affected_pcs=[op.pc],
                                recommendation=(
                                    "将 storage 值缓存到本地变量，减少 SLOAD 次数"
                                ),
                            ))
                    recent_sloads[slot_val] = i

            # SSTORE时清除同槽位缓存（写入后重新读取是合理行为）
            if op.name == 'SSTORE':
                prev = self.ops[i - 1] if i > 0 else None
                if prev and prev.is_push and prev.push_data:
                    try:
                        slot_written = int.from_bytes(prev.push_data, 'big')
                        recent_sloads.pop(slot_written, None)
                    except (ValueError, OverflowError):
                        pass

    def _detect_loop_sstores(self, findings: List[VulnerabilityReport]):
        """检测CFG识别出的循环体内的SSTORE。

        通过回边分析识别循环头。
        """
        try:
            loop_headers = self.parser.find_loop_headers()
        except Exception:
            return

        if not loop_headers:
            return

        blocks = self.parser.build_cfg_edges()
        try:
            dom = self.parser.compute_dominators()
        except Exception:
            return

        # 块起始位置映射，用于循环成员判定
        for b_start, blk_ops in blocks.items():
            in_loop = any(
                header in dom.get(b_start, set()) and b_start != header
                for header in loop_headers
            )
            if not in_loop:
                continue

            for op in blk_ops:
                if op.name == 'SSTORE':
                    findings.append(VulnerabilityReport(
                        vuln_type=VulnerabilityType.GAS_INEFFICIENCY,
                        severity='MEDIUM',
                        confidence=0.55,
                        description=(
                            "循环体中的 SSTORE 会随迭代次数累积 gas 成本"
                        ),
                        location=op.pc,
                        opcode='SSTORE',
                        affected_pcs=[op.pc],
                        recommendation=(
                            "在循环结束后一次性写入，或使用 event 替代存储"
                        ),
                    ))
