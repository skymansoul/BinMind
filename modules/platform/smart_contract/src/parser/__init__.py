# parser - EVM and WASM bytecode parsers

from .evm_parser import EVMBytecodeParser, EVMOp
from .wasm_parser import WASMContractParser

__all__ = [
    "EVMBytecodeParser",
    "EVMOp",
    "WASMContractParser",
]
