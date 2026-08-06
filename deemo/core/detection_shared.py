"""
Shared data structures for the detection engine: TaintPath, CFGBlock, TaintSource, TaintSink.

Common type definitions used by taint_tracker, cfg_path_filter, and asm_detector.
Housed in a standalone module to avoid circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TaintSource:
    """Taint source: program entry point for user/external input."""
    kind: str             # 'read' | 'recv' | 'fgets' | 'scanf' | 'gets' | 'argv' | 'env'
    var_name: str         # variable/register receiving input
    func_name: str        # enclosing function
    address: int = 0      # instruction address (assembly) or 0 (decompiled)
    lineno: int = 0


@dataclass
class TaintSink:
    """Taint sink: dangerous operation consuming tainted data."""
    kind: str             # 'strcpy' | 'sprintf' | 'printf' | 'system' | 'memcpy' | 'free'
    var_name: str         # tainted variable
    func_name: str
    address: int = 0
    lineno: int = 0


@dataclass
class TaintPath:
    """Taint propagation path from source to sink."""
    source: TaintSource
    sink: TaintSink
    hops: list[str]       # intermediate variable/register names in path
    confidence: float     # 0.0-1.0 path confidence
    verified: bool = False


@dataclass
class CFGBlock:
    """Basic block node in a control-flow graph."""
    start_addr: int
    end_addr: int
    instructions: list[str] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)  # 后继块地址


@dataclass
class AsmCall:
    """Assembly-level function call record."""
    address: int
    mnemonic: str       # call / jmp
    target: str          # 目标函数名或地址
    args: list[str]      # 调用前各寄存器的值（从反汇编推断）


# Dangerous sink functions whose arguments may carry user input
_SINK_FUNCTIONS = {
    'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'memcpy', 'memmove', 'system', 'popen',
    'printf', 'fprintf', 'dprintf', 'syslog',
    'err', 'errx', 'warn', 'warnx',
}

# Source functions whose return values or output buffers carry external input
_SOURCE_FUNCTIONS = {
    'read', 'recv', 'recvfrom', 'fgets', 'gets',
    'scanf', 'fscanf', 'getline', 'getenv',
}


def is_source(func_name: str) -> bool:
    return func_name in _SOURCE_FUNCTIONS


def is_sink(func_name: str) -> bool:
    return func_name in _SINK_FUNCTIONS
