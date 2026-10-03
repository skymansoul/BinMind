# 类型枚举 - ContractType与VulnerabilityType，二者均继承Python Enum并以字符串为值

from enum import Enum
from typing import Any


class ContractType(str, Enum):
    """合约类型枚举 - 对应 EVM/WASM 编译目标。

    继承 str 以便与字符串字面量直接比较：
        ContractType.EVM == "evm"  # True
    """
    SOLIDITY = "solidity"
    VYPER = "vyper"
    YUL = "yul"
    WASM = "wasm"
    EVM = "evm"
    UNKNOWN = "unknown"


class VulnerabilityType(str, Enum):
    """漏洞类型枚举 - 字节码静态分析可检测的各类弱点。

    继承 str 以便与字符串字面量直接比较：
        VulnerabilityType.REENTRANCY == "reentrancy"  # True
    """
    REENTRANCY = "reentrancy"
    INTEGER_OVERFLOW = "integer_overflow"
    INTEGER_UNDERFLOW = "integer_underflow"
    UNCHECKED_CALL = "unchecked_call"
    UNCHECKED_SEND = "unchecked_send"
    UNCHECKED_DELEGATECALL = "unchecked_delegatecall"
    TX_ORIGIN = "tx_origin"
    ABI_ENCODE_PACKED = "abi_encode_packed"
    DEPRECATED_OPCODE = "deprecated_opcode"
    GAS_LIMIT = "gas_limit"
    STORAGE_COLLISION = "storage_collision"
    SIGNATURE_REPLAY = "signature_replay"
    FRONT_RUNNING = "front_running"
    REENTRANCY_GUARD_MISSING = "reentrancy_guard_missing"
    GAS_INEFFICIENCY = "gas_inefficiency"
    UNPROTECTED_SELFDESTRUCT = "unprotected_selfdestruct"
    WEAK_RANDOMNESS = "weak_randomness"
    LOCKED_ETHER = "locked_ether"
    ARBITRARY_JUMP = "arbitrary_jump"
    ACCESS_CONTROL = "access_control"
    SHORT_ADDRESS = "short_address"
    DOS_UNBOUNDED_LOOP = "dos_unbounded_loop"
    FORCED_ETHER_RECEIVE = "forced_ether_receive"
    ABI_ENCODING_AMBIGUITY = "abi_encoding_ambiguity"


class Severity(int, Enum):
    """严重等级 - 数值间隔允许中间插入。

    继承 int 以便与整数字面量直接比较：
        Severity.CRITICAL > Severity.HIGH  # True
        Severity.HIGH == 70  # True
    """
    CRITICAL = 100
    HIGH = 70
    MEDIUM = 40
    LOW = 15
    INFO = 5
