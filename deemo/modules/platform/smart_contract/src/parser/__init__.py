# parser — EVM and WASM bytecode parsers
# 不拆: 两层解析器通过 __init__ 统一出口

from .evm_parser import EVMBytecodeParser, EVMOp
from .wasm_parser import WASMContractParser

__all__ = [
    "EVMBytecodeParser",
    "EVMOp",
    "WASMContractParser",
]
