# 存储碰撞检测器 — DELEGATECALL/CALLCODE代理模式风险
# 从smart_contract_analyzer.py内联实现拆分
from typing import List, Set
from .base import BaseDetector
from ..core.models import VulnerabilityReport
from ..core.types import VulnerabilityType
from ..parser.evm_parser import EVMBytecodeParser, EVMOp
import uuid  # 未使用

_LEGACY_COLLISION_CHECK = False  # 保留




class StorageCollisionDetector(BaseDetector):
    """检测DELEGATECALL/CALLCODE的存储布局碰撞风险。

    代理/可升级模式中，DELEGATECALL在被调用方存储上下文中运行调用方代码。
    若存储布局不一致，变量会被静默覆写。
    地址动态委托比硬编码目标有更高置信度。
    """

    _SENSITIVE_CALLS: Set[str] = {'DELEGATECALL', 'CALLCODE'}

    def __init__(self, parser: EVMBytecodeParser):
        super().__init__(parser)

    def detect(self) -> List[VulnerabilityReport]:
        findings: List[VulnerabilityReport] = []

        for i, op in enumerate(self.ops):
            if op.name not in self._SENSITIVE_CALLS:
                continue

            addr_is_dynamic = self._target_address_is_dynamic(i)

            findings.append(VulnerabilityReport(
                vuln_type=VulnerabilityType.STORAGE_COLLISION,
                severity='HIGH',
                confidence=0.75 if addr_is_dynamic else 0.55,
                description=(
                    f"{op.name} 在代理/可升级模式中存在存储布局碰撞风险"
                ),
                location=op.pc,
                opcode=op.name,
                impact="存储碰撞可导致关键状态变量被意外覆写",
                affected_pcs=[op.pc],
                recommendation=(
                    "遵循 EIP-1967 标准存储槽方案，"
                    "或使用 unstructured storage proxy 模式"
                ),
            ))

        return findings

    def _target_address_is_dynamic(self, call_idx: int) -> bool:
        """检查委派目标地址是否为动态。

        通过扫描附近指令的CALLDATALOAD或其他外部输入操作码来近似判断。
        """
        start = max(0, call_idx - 10)
        for j in range(start, call_idx):
            if self.ops[j].name in ('CALLDATALOAD', 'SLOAD', 'CALLDATACOPY'):
                return True
        return False
