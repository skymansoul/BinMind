# 2026-07-28
# EVM opcode table — 参考 Ethereum Yellow Paper + EIP 更新
# 按 family 分组方便 gas profiling；taint source/sink 为 taint_tracker 准备
from enum import IntEnum

class OpcodeFamily(IntEnum):
    STOP_ARITHMETIC = 0;  MATH = 1;  ENV = 2;  BLOCK = 3
    STACK = 4;  MEMORY = 5;  STORAGE = 6;  FLOW = 7
    CALL = 8;  LOG = 9;  CREATE = 10;  MISC = 11

OPCODES = {
    0x00: ("STOP", 0, 0, OpcodeFamily.STOP_ARITHMETIC, 0),
    0x01: ("ADD", 2, 1, OpcodeFamily.MATH, 3),
    0x02: ("MUL", 2, 1, OpcodeFamily.MATH, 5),
    0x03: ("SUB", 2, 1, OpcodeFamily.MATH, 3),
    0x04: ("DIV", 2, 1, OpcodeFamily.MATH, 5),
    0x05: ("SDIV", 2, 1, OpcodeFamily.MATH, 5),
    0x06: ("MOD", 2, 1, OpcodeFamily.MATH, 5),
    0x07: ("SMOD", 2, 1, OpcodeFamily.MATH, 5),
    0x08: ("ADDMOD", 3, 1, OpcodeFamily.MATH, 8),
    0x09: ("MULMOD", 3, 1, OpcodeFamily.MATH, 8),
    0x0a: ("EXP", 2, 1, OpcodeFamily.MATH, 10),
    0x0b: ("SIGNEXTEND", 2, 1, OpcodeFamily.MATH, 5),
    0x10: ("LT", 2, 1, OpcodeFamily.MATH, 3),
    0x11: ("GT", 2, 1, OpcodeFamily.MATH, 3),
    0x12: ("SLT", 2, 1, OpcodeFamily.MATH, 3),
    0x13: ("SGT", 2, 1, OpcodeFamily.MATH, 3),
    0x14: ("EQ", 2, 1, OpcodeFamily.MATH, 3),
    0x15: ("ISZERO", 1, 1, OpcodeFamily.MATH, 3),
    0x16: ("AND", 2, 1, OpcodeFamily.MATH, 3),
    0x17: ("OR", 2, 1, OpcodeFamily.MATH, 3),
    0x18: ("XOR", 2, 1, OpcodeFamily.MATH, 3),
    0x19: ("NOT", 1, 1, OpcodeFamily.MATH, 3),
    0x1a: ("BYTE", 2, 1, OpcodeFamily.MATH, 3),
    0x1b: ("SHL", 2, 1, OpcodeFamily.MATH, 3),
    0x1c: ("SHR", 2, 1, OpcodeFamily.MATH, 3),
    0x1d: ("SAR", 2, 1, OpcodeFamily.MATH, 3),
    0x20: ("KECCAK256", 2, 1, OpcodeFamily.MATH, 30),
    0x30: ("ADDRESS", 0, 1, OpcodeFamily.ENV, 2),
    0x31: ("BALANCE", 1, 1, OpcodeFamily.ENV, 100),
    0x32: ("ORIGIN", 0, 1, OpcodeFamily.ENV, 2),
    0x33: ("CALLER", 0, 1, OpcodeFamily.ENV, 2),
    0x34: ("CALLVALUE", 0, 1, OpcodeFamily.ENV, 2),
    0x35: ("CALLDATALOAD", 1, 1, OpcodeFamily.ENV, 3),
    0x36: ("CALLDATASIZE", 0, 1, OpcodeFamily.ENV, 2),
    0x37: ("CALLDATACOPY", 3, 0, OpcodeFamily.ENV, 3),
    0x38: ("CODESIZE", 0, 1, OpcodeFamily.ENV, 2),
    0x39: ("CODECOPY", 3, 0, OpcodeFamily.ENV, 3),
    0x3a: ("GASPRICE", 0, 1, OpcodeFamily.ENV, 2),
    0x3b: ("EXTCODESIZE", 1, 1, OpcodeFamily.ENV, 100),
    0x3c: ("EXTCODECOPY", 4, 0, OpcodeFamily.ENV, 100),
    0x3d: ("RETURNDATASIZE", 0, 1, OpcodeFamily.ENV, 2),
    0x3e: ("RETURNDATACOPY", 3, 0, OpcodeFamily.ENV, 3),
    0x3f: ("EXTCODEHASH", 1, 1, OpcodeFamily.ENV, 100),
    0x40: ("BLOCKHASH", 1, 1, OpcodeFamily.BLOCK, 20),
    0x41: ("COINBASE", 0, 1, OpcodeFamily.BLOCK, 2),
    0x42: ("TIMESTAMP", 0, 1, OpcodeFamily.BLOCK, 2),
    0x43: ("NUMBER", 0, 1, OpcodeFamily.BLOCK, 2),
    0x44: ("PREVRANDAO", 0, 1, OpcodeFamily.BLOCK, 2),
    0x45: ("GASLIMIT", 0, 1, OpcodeFamily.BLOCK, 2),
    0x46: ("CHAINID", 0, 1, OpcodeFamily.BLOCK, 2),
    0x47: ("SELFBALANCE", 0, 1, OpcodeFamily.BLOCK, 5),
    0x48: ("BASEFEE", 0, 1, OpcodeFamily.BLOCK, 2),
    0x49: ("BLOBHASH", 1, 1, OpcodeFamily.BLOCK, 3),
    0x4a: ("BLOBBASEFEE", 0, 1, OpcodeFamily.BLOCK, 2),
    0x50: ("POP", 1, 0, OpcodeFamily.STACK, 2),
    0x51: ("MLOAD", 1, 1, OpcodeFamily.MEMORY, 3),
    0x52: ("MSTORE", 2, 0, OpcodeFamily.MEMORY, 3),
    0x53: ("MSTORE8", 2, 0, OpcodeFamily.MEMORY, 3),
    0x54: ("SLOAD", 1, 1, OpcodeFamily.STORAGE, 100),
    0x55: ("SSTORE", 2, 0, OpcodeFamily.STORAGE, 100),
    0x56: ("JUMP", 1, 0, OpcodeFamily.FLOW, 8),
    0x57: ("JUMPI", 2, 0, OpcodeFamily.FLOW, 10),
    0x58: ("PC", 0, 1, OpcodeFamily.FLOW, 2),
    0x59: ("MSIZE", 0, 1, OpcodeFamily.MEMORY, 2),
    0x5a: ("GAS", 0, 1, OpcodeFamily.MISC, 2),
    0x5b: ("JUMPDEST", 0, 0, OpcodeFamily.FLOW, 1),
    0x5c: ("TLOAD", 1, 1, OpcodeFamily.STORAGE, 100),
    0x5d: ("TSTORE", 2, 0, OpcodeFamily.STORAGE, 100),
    0x5e: ("MCOPY", 3, 0, OpcodeFamily.MEMORY, 3),
    0x5f: ("PUSH0", 0, 1, OpcodeFamily.STACK, 2),
    0x60: ("PUSH1", 0, 1, OpcodeFamily.STACK, 3),
    # PUSH2-PUSH32: 0x61-0x7f
    0x80: ("DUP1", 1, 2, OpcodeFamily.STACK, 3),
    # DUP2-DUP16: 0x81-0x8f
    0x90: ("SWAP1", 2, 2, OpcodeFamily.STACK, 3),
    # SWAP2-SWAP16: 0x91-0x9f
    0xa0: ("LOG0", 2, 0, OpcodeFamily.LOG, 375),
    0xa1: ("LOG1", 3, 0, OpcodeFamily.LOG, 750),
    0xa2: ("LOG2", 4, 0, OpcodeFamily.LOG, 1125),
    0xa3: ("LOG3", 5, 0, OpcodeFamily.LOG, 1500),
    0xa4: ("LOG4", 6, 0, OpcodeFamily.LOG, 1875),
    0xf0: ("CREATE", 3, 1, OpcodeFamily.CREATE, 32000),
    0xf1: ("CALL", 7, 1, OpcodeFamily.CALL, 100),
    0xf2: ("CALLCODE", 7, 1, OpcodeFamily.CALL, 100),
    0xf3: ("RETURN", 2, 0, OpcodeFamily.MISC, 0),
    0xf4: ("DELEGATECALL", 6, 1, OpcodeFamily.CALL, 100),
    0xf5: ("CREATE2", 4, 1, OpcodeFamily.CREATE, 32000),
    0xfa: ("STATICCALL", 6, 1, OpcodeFamily.CALL, 100),
    0xfd: ("REVERT", 2, 0, OpcodeFamily.MISC, 0),
    0xfe: ("INVALID", 0, 0, OpcodeFamily.MISC, 0),
    0xff: ("SELFDESTRUCT", 1, 0, OpcodeFamily.MISC, 5000),
}
# 填充 PUSH2-PUSH32, DUP2-DUP16, SWAP2-SWAP16
for i in range(2, 33):
    OPCODES[0x5f + i] = (f"PUSH{i}", 0, 1, OpcodeFamily.STACK, 3)
for i in range(2, 17):
    OPCODES[0x7f + i] = (f"DUP{i}", i, i + 1, OpcodeFamily.STACK, 3)
    OPCODES[0x8f + i] = (f"SWAP{i}", i + 1, i + 1, OpcodeFamily.STACK, 3)

DEPRECATED_OPCODES = {0xff}  # SELFDESTRUCT — EIP-6049

TAINT_SOURCES = {0x34, 0x35, 0x37}  # CALLVALUE, CALLDATALOAD, CALLDATACOPY
TAINT_SINKS = {0xf1, 0xf2, 0xf4, 0x55}  # CALL, CALLCODE, DELEGATECALL, SSTORE

PUSH_OPCODES = set(range(0x60, 0x80))
DUP_OPCODES = set(range(0x80, 0x90))
SWAP_OPCODES = set(range(0x90, 0xa0))
