# core — 共享模型/类型/opcode表，全模块依赖
# 不拆: 拆了只会增加循环 import

from .models import (
    EVMInstruction,
    EVMBasicBlock,
    FunctionSelector,
    VulnerabilityReport,
    ContractInfo,
)
from .types import (
    ContractType,
    VulnerabilityType,
    Severity,
)
from .opcodes import (
    OPCODES,
    OpcodeFamily,
    PUSH_OPCODES,
    DUP_OPCODES,
    SWAP_OPCODES,
    TAINT_SOURCES,
    TAINT_SINKS,
    DEPRECATED_OPCODES,
)

__all__ = [
    "EVMInstruction",
    "EVMBasicBlock",
    "FunctionSelector",
    "VulnerabilityReport",
    "ContractInfo",
    "ContractType",
    "VulnerabilityType",
    "Severity",
    "OPCODES",
    "OpcodeFamily",
    "PUSH_OPCODES",
    "DUP_OPCODES",
    "SWAP_OPCODES",
    "TAINT_SOURCES",
    "TAINT_SINKS",
    "DEPRECATED_OPCODES",
]
