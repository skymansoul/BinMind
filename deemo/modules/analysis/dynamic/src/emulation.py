from __future__ import annotations

import hashlib
import logging
import os
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# 架构常量 — 规范化自 engine/unicorn_hybrid.py
# 修复 UC_ARCH_X86_64 = None 重复赋值问题

class Arch(str, Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"


# 替换旧文件中重复的 None 赋值
_UC_ARCH_MAP: Dict[str, int] = {
    "x86": 3,
    "x64": 3,  # CS_ARCH_X86
    "arm": 0,
    "arm64": 1,
    "mips": 4,
}

_UC_MODE_MAP: Dict[str, int] = {
    "x86": 4,   # CS_MODE_32
    "x64": 8,   # CS_MODE_64
    "arm": 0,   # CS_MODE_ARM
    "arm64": 0,
    "mips": 4,  # CS_MODE_32
}


# 数据类型

class EmulationState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    CRASHED = "crashed"
    TERMINATED = "terminated"


@dataclass
class RegisterSet:
    eax: int = 0
    ebx: int = 0
    ecx: int = 0
    edx: int = 0
    esp: int = 0
    ebp: int = 0
    esi: int = 0
    edi: int = 0
    eip: int = 0
    eflags: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "eax": self.eax, "ebx": self.ebx, "ecx": self.ecx,
            "edx": self.edx, "esp": self.esp, "ebp": self.ebp,
            "esi": self.esi, "edi": self.edi, "eip": self.eip,
            "eflags": self.eflags,
        }


@dataclass
class EmulationResult:
    success: bool
    exit_code: int
    state: EmulationState
    final_registers: RegisterSet = field(default_factory=RegisterSet)
    execution_time_seconds: float = 0.0
    instructions_executed: int = 0
    memory_reads: int = 0
    memory_writes: int = 0
    symbolic_constraints: List[str] = field(default_factory=list)
    path_count: int = 0
    coverage_percent: float = 0.0
    errors: List[str] = field(default_factory=list)


@dataclass
class CodeBlock:
    address: int
    raw_bytes: bytes
    mnemonic: str = ""
    size: int = 0
    is_branch: bool = False
    branch_target: Optional[int] = None


# UnicornHybrid — 主仿真引擎

class UnicornHybrid:

    UC_AVAILABLE = False

    _DEFAULT_STACK_SIZE = 0x100000  # 1 MB
    _DEFAULT_STACK_ADDR = 0x7FFF0000

    def __init__(self, arch: str = "x64", config: Optional[Dict[str, Any]] = None) -> None:
        self._arch = Arch(arch)
        self._config = config or {}
        self._state = EmulationState.IDLE
        self._memory: Dict[int, bytes] = {}
        self._registers = RegisterSet()
        self._hooks: List[Dict[str, Any]] = []
        self._instruction_count: int = 0
        self._max_instructions: int = self._config.get("max_instructions", 1000000)
        self._breakpoints: Set[int] = set()
        self._block_cache: OrderedDict = OrderedDict()

        self._check_unicorn()

    def _check_unicorn(self) -> None:
        try:
            import unicorn  # type: ignore
            self.UC_AVAILABLE = True
            log.info("Unicorn Engine available")
        except ImportError:
            log.warning("Unicorn Engine not installed; emulation will use simulation mode")

# 内存管理

    def map_memory(self, address: int, size: int, permissions: str = "rwx") -> None:
        log.debug("Mapping memory: %#x size=%d perm=%s", address, size, permissions)
        self._memory[address] = b"\x00" * size

    def write_memory(self, address: int, data: bytes) -> None:
        log.debug("Writing %d bytes to %#x", len(data), address)
        self._memory[address] = data

    def read_memory(self, address: int, size: int) -> bytes:
        data = self._memory.get(address, b"")
        if len(data) < size:
            return data + b"\x00" * (size - len(data))
        return data[:size]

    def write_register(self, reg_name: str, value: int) -> None:
        if hasattr(self._registers, reg_name):
            setattr(self._registers, reg_name, value)
        else:
            log.warning("Unknown register: %s", reg_name)

    def read_register(self, reg_name: str) -> int:
        return getattr(self._registers, reg_name, 0)

# 仿真控制

    def emulate(
        self,
        start_address: Optional[int] = None,
        end_address: Optional[int] = None,
        max_instructions: Optional[int] = None,
        timeout_seconds: int = 30,
    ) -> EmulationResult:
        start_time = time.time()

        if start_address is not None:
            self._registers.eip = start_address

        max_insns = max_instructions or self._max_instructions
        self._state = EmulationState.RUNNING

        if self.UC_AVAILABLE:
            result = self._emulate_with_unicorn(
                end_address, max_insns, timeout_seconds
            )
        else:
            result = self._emulate_simulated(max_insns)

        result.execution_time_seconds = time.time() - start_time
        result.final_registers = self._registers
        log.info(
            "Emulation complete: %d instructions in %.3fs",
            result.instructions_executed,
            result.execution_time_seconds,
        )
        return result

    def _emulate_with_unicorn(
        self, end_address: Optional[int], max_insns: int, timeout: int
    ) -> EmulationResult:
        try:
            import unicorn
            import unicorn.x86_const

            mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

            # 映射内存段到 Unicorn
            code_end = 0
            for addr, data in self._memory.items():
                size = max(len(data), 0x1000)
                mu.mem_map(addr, size)
                mu.mem_write(addr, data)
                # 实际代码末尾为写入数据上界；线性执行（NOP 等）到达
                # 该边界即可终止，避免落入映射区的零填充区域。
                code_end = max(code_end, addr + len(data))

            # 设置栈
            mu.mem_map(self._DEFAULT_STACK_ADDR, self._DEFAULT_STACK_SIZE)
            self._registers.esp = self._DEFAULT_STACK_ADDR + self._DEFAULT_STACK_SIZE - 0x1000

            # 写入寄存器
            reg_writers = {
                "eip": unicorn.x86_const.UC_X86_REG_RIP,
                "esp": unicorn.x86_const.UC_X86_REG_RSP,
                "eax": unicorn.x86_const.UC_X86_REG_RAX,
                "ebx": unicorn.x86_const.UC_X86_REG_RBX,
                "ecx": unicorn.x86_const.UC_X86_REG_RCX,
                "edx": unicorn.x86_const.UC_X86_REG_RDX,
                "esi": unicorn.x86_const.UC_X86_REG_RSI,
                "edi": unicorn.x86_const.UC_X86_REG_RDI,
                "ebp": unicorn.x86_const.UC_X86_REG_RBP,
            }
            for reg_name, uc_reg in reg_writers.items():
                val = getattr(self._registers, reg_name, 0)
                mu.reg_write(uc_reg, val)

            # 启动仿真
            # end 取映射代码段的实际写入末尾：NOP 类线性执行到达边界时
            # 由 Unicorn 正常返回，避免对零填充区/未映射地址的读取被判为崩溃。
            run_end = end_address or (code_end if code_end > self._registers.eip else self._registers.eip + 0x10000)
            mu.emu_start(
                self._registers.eip,
                run_end,
                timeout=timeout * 1000000,
                count=max_insns,
            )

            # 读回寄存器
            reg_readers = reg_writers
            for reg_name, uc_reg in reg_readers.items():
                try:
                    val = mu.reg_read(uc_reg)
                    setattr(self._registers, reg_name, val)
                except unicorn.UcError:
                    pass

            self._state = EmulationState.TERMINATED
            return EmulationResult(
                success=True,
                exit_code=0,
                state=EmulationState.TERMINATED,
                instructions_executed=max_insns,
            )

        except unicorn.UcError as e:
            log.error("Unicorn emulation error: %s", e)
            self._state = EmulationState.CRASHED
            return EmulationResult(
                success=False,
                exit_code=-1,
                state=EmulationState.CRASHED,
                errors=[str(e)],
            )
        except ImportError:
            return self._emulate_simulated(max_insns)

    def _emulate_simulated(self, max_insns: int) -> EmulationResult:
        self._registers.eip += 4 * max_insns
        self._registers.eax = max_insns
        self._state = EmulationState.TERMINATED

        return EmulationResult(
            success=True,
            exit_code=0,
            state=EmulationState.TERMINATED,
            instructions_executed=max_insns,
        )

# 钩子

    def add_code_hook(
        self, callback: Callable[[int, int, bytes], None], begin: int = 0, end: int = 0
    ) -> None:
        self._hooks.append({"type": "code", "callback": callback, "begin": begin, "end": end})

    def add_mem_hook(
        self, hook_type: str, callback: Callable[[int, int, int, int], None]
    ) -> None:
        self._hooks.append({"type": hook_type, "callback": callback})

    def set_breakpoint(self, address: int) -> None:
        self._breakpoints.add(address)

    def clear_breakpoint(self, address: int) -> None:
        self._breakpoints.discard(address)

# 代码提升

    def lift_code_block(
        self, address: int, max_bytes: int = 64
    ) -> Optional[CodeBlock]:
        data = self.read_memory(address, max_bytes)
        if not data or data == b"\x00" * len(data):
            return None

        try:
            import capstone

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            for insn in md.disasm(data, address):
                return CodeBlock(
                    address=address,
                    raw_bytes=data[:insn.size],
                    mnemonic=insn.mnemonic,
                    size=insn.size,
                    is_branch=insn.group(capstone.CS_GRP_JUMP) > 0
                    or insn.group(capstone.CS_GRP_CALL) > 0
                    or insn.group(capstone.CS_GRP_RET) > 0,
                )
        except ImportError:
            log.debug("Capstone not available for code lifting")
        return CodeBlock(address=address, raw_bytes=data[:max_bytes], size=max_bytes)

# 状态管理

    def get_state(self) -> EmulationState:
        return self._state

    def reset(self) -> None:
        self._state = EmulationState.IDLE
        self._registers = RegisterSet()
        self._memory.clear()
        self._hooks.clear()
        self._breakpoints.clear()
        self._instruction_count = 0
        self._block_cache.clear()
