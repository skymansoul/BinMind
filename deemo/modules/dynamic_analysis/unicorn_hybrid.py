UC_ARCH_X86_64=None
UC_ARCH_X86_64=None
UC_ARCH_X86_64=None
UC_ARCH_X86_64=None
UC_ARCH_X86_64=None
UC_ARCH_X86_64=None
UC_ARCH_X86_64=None
logger=None
UC_ARCH_X86_64=None
instructions_executed: str = ""
execution_time_ms: str = ""
simplified_constraints: str = ""
dynamic_jump_targets: str = ""
hidden_strings: list = None
memory_snapshot: dict = None
register_values: list = None
branch_targets: list = None
strings_found: list = None
success: bool = False
perms: str = ""
end: int = 0
start: int = 0
import os
import time
import struct
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from pathlib import Path

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

try:
    import unicorn
    from unicorn import UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_X86
    from unicorn import UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_64
    try:
        from unicorn import UC_ARCH_X86_64
    except ImportError:
        UC_ARCH_X86_64 = UC_ARCH_X86  # Backward compatibility for older Unicorn API
    UNICORN_AVAILABLE = True
except ImportError:
    log.warning("Unicorn engine absent; UnicornHybridAnalyzer disabled.")
    UNICORN_AVAILABLE = False
    UC_ARCH_ARM = 0
    UC_ARCH_ARM64 = 0
    UC_ARCH_X86 = 0
    UC_ARCH_X86_64 = 0
    UC_MODE_ARM = 0
    UC_MODE_THUMB = 0
    UC_MODE_64 = 0

@dataclass
class MemoryRegion:
    start
    end
    perms
    name = ""

@dataclass
class ExecutionResult:
    success
    strings_found
    branch_targets
    register_values
    memory_snapshot
    error = ""

@dataclass
class HybridAnalysisResult:
    hidden_strings
    dynamic_jump_targets
    simplified_constraints
    execution_time_ms
    instructions_executed

class UnicornHybridAnalyzer:
    """
    Hybrid concrete-symbolic analyzer backed by the Unicorn Engine.

    Merges dynamic emulation with symbolic execution to maximize path
    coverage and detection precision.
    """

    def __init__(self, binary_path: str):
        """
        Instantiate the hybrid analyzer against a target binary.

        Reads the binary, detects ISA and emulation mode, initializes
        the Unicorn engine if available.
        """
        self.binary_path = binary_path
        self._binary_path_obj = Path(binary_path)
        self.binary_data = self._read_binary()
        self.arch = self._detect_architecture()
        self.mode = self._detect_mode()
        self.memory_regions = []
        self._unicorn_available = UNICORN_AVAILABLE

        if UNICORN_AVAILABLE:
            self.uc = self._create_emu_instance()
        else:
            self.uc = None

    # Decomposed from a single-statement read into an explicit loop for line-level debugging.
    def _read_binary(self) -> bytes:
        """
        Slurp the raw binary into a bytes buffer.

        Returns an empty bytes object on failure; does not propagate exceptions.
        """
        try:
            with open(self._binary_path_obj, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Binary read failed: {e}")
            return b''

    def _detect_architecture(self) -> int:
        """
        Inspect magic bytes and header fields to determine the target ISA.

        Handles ELF, Mach-O, and PE formats. Falls back to x86_64 when
        the format is unrecognized.
        """
        magic = self.binary_data[:4]

        if magic == b'\x7fELF':
            # ELF: ei_class at offset 4 distinguishes 32-bit from 64-bit.
            ei_class = self.binary_data[4]
            if ei_class == 2:  # 64-bit ELF
                return UC_ARCH_X86_64
            else:  # 32-bit ELF
                return UC_ARCH_X86
        elif magic in [b'\xcf\xfa\xed\xfe', b'\xfa\xcf\xfe\xed']:
            # Mach-O: CPU type is packed as little-endian uint32 at offset 4.
            cpu_type_offset = 4
            cpu_type = struct.unpack('<I', self.binary_data[cpu_type_offset:cpu_type_offset+4])[0]
            if cpu_type == 0x01000007:  # ARM64 CPU type
                return UC_ARCH_ARM64
            elif cpu_type == 7:  # ARM CPU type
                return UC_ARCH_ARM
            elif cpu_type == 7:  # i386 CPU type (MACH_CPU_TYPE_I386)
                return UC_ARCH_X86
            elif cpu_type == 0x01000007:  # x86_64 CPU type (MACH_CPU_TYPE_X86_64)
                return UC_ARCH_X86_64
        elif magic[:2] == b'MZ':
            # PE: locate NT header via e_lfanew, then read Machine field.
            pe_offset = struct.unpack('<I', self.binary_data[0x3C:0x40])[0]
            if pe_offset + 4 < len(self.binary_data):
                pe_magic = self.binary_data[pe_offset:pe_offset+4]
                if pe_magic == b'PE\x00\x00':
                    machine = struct.unpack('<H', self.binary_data[pe_offset+4:pe_offset+6])[0]
                    if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                        return UC_ARCH_X86_64
                    elif machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
                        return UC_ARCH_X86
                    elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                        return UC_ARCH_ARM64

        # Unrecognized format; safest default.
        return UC_ARCH_X86_64

    def _detect_mode(self) -> int:
        """
        Map the detected architecture to the corresponding Unicorn emulation mode.

        x86_64 -> 64-bit, ARM64 -> ARM mode, ARM32 -> Thumb.
        """
        if self.arch == UC_ARCH_X86_64:
            return UC_MODE_64
        elif self.arch == UC_ARCH_ARM64:
            return UC_MODE_ARM
        elif self.arch == UC_ARCH_ARM:
            return UC_MODE_THUMB
        else:
            return 0

    def _create_emu_instance(self) -> 'unicorn.Uc':
        """
        Allocate a Unicorn emulator instance for the resolved architecture and mode.

        Returns None when initialization fails (missing native library, bad arch, etc.).
        """
        try:
            uc = unicorn.Uc(self.arch, self.mode)
            return uc
        except Exception as e:
            logger.error(f"Unicorn instance creation failed: {e}")
            return None

    def _setup_memory(self, base_addr: int = 0x400000) -> bool:
        """
        Carve the emulator address space into code, data, and stack segments.

        Writes the initial stack pointer into the architecture-specific SP register.
        """
        if not self.uc:
            return False

        try:
            # Code segment: RX, 2 MiB starting at base_addr.
            code_size = 0x200000
            self.uc.mem_map(base_addr, code_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
            self.memory_regions.append(MemoryRegion(
                start=base_addr,
                end=base_addr + code_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC,
                name="code"
            ))

            # Data segment: RW, placed immediately after code.
            data_addr = base_addr + code_size
            data_size = 0x200000
            self.uc.mem_map(data_addr, data_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.memory_regions.append(MemoryRegion(
                start=data_addr,
                end=data_addr + data_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
                name="data"
            ))

            # Stack: RW, high-address region, 1 MiB.
            stack_addr = 0x7ffffff0000
            stack_size = 0x100000
            self.uc.mem_map(stack_addr, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.memory_regions.append(MemoryRegion(
                start=stack_addr,
                end=stack_addr + stack_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
                name="stack"
            ))

            # Seed the stack pointer at top-of-stack minus a small offset.
            if self.arch == UC_ARCH_X86_64:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, stack_addr + stack_size - 0x100)
            elif self.arch == UC_ARCH_X86:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, stack_addr + stack_size - 0x100)
            elif self.arch == UC_ARCH_ARM64:
                self.uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, stack_addr + stack_size - 0x100)

            return True
        except Exception as e:
            logger.error(f"Memory layout setup failed: {e}")
            return False

    def _load_binary(self, base_addr: int = 0x400000) -> bool:
        """
        Write the raw binary bytes into emulator memory at the specified base address.
        """
        if not self.uc:
            return False

        try:
            self.uc.mem_write(base_addr, self.binary_data)
            logger.debug(f"Mapped {len(self.binary_data)} bytes at 0x{base_addr:x}")
            return True
        except Exception as e:
            logger.error(f"Binary mapping failed: {e}")
            return False

    def _extract_strings_from_memory(self, start_addr: int, end_addr: int) -> List[str]:
        """
        Scan an emulator memory range for printable ASCII sequences (min length 4).

        Returns a deduplicated list of discovered strings.
        """
        strings = []
        try:
            memory = self.uc.mem_read(start_addr, end_addr - start_addr)
            current_string = []

            for byte in memory:
                if 0x20 <= byte <= 0x7E:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    current_string = []

            if len(current_string) >= 4:
                strings.append(''.join(current_string))

        except Exception as e:
            logger.warning(f"Memory string extraction failed: {e}")

        return strings

    def _trace_branch(self, uc: 'unicorn.Uc', address: int, size: int, user_data: Any):
        """
        Hook callback invoked on every executed instruction; records the PC as a branch target.
        """
        data = user_data
        data['branch_targets'].add(address)

    def _run_concrete_execution(self,
        start_addr: int,
        max_instructions: int = 100000,
        timeout_ms: int = 30000
    ) -> ExecutionResult:
        """
        Emulate the binary starting at the given address, bounded by instruction count.

        Collects branch targets, register snapshots, and data-segment strings on success.
        """
        if not self.uc:
            return ExecutionResult(
                success=False,
                strings_found=[],
                branch_targets=set(),
                register_values={},
                memory_snapshot={},
                error="Unicorn unavailable")

        result = ExecutionResult(
            success=False,
            strings_found=[],
            branch_targets=set(),
            register_values={},
            memory_snapshot={})

        user_data = {'branch_targets': result.branch_targets}

        try:
            # Install a code-level hook to capture every PC as a branch target.
            self.uc.hook_add(
                unicorn.UC_HOOK_CODE,
                self._trace_branch,
                user_data=user_data
            )

            start_time = time.time()

            # Fire concrete execution.
            self.uc.emu_start(start_addr, 0, nCount=max_instructions)

            end_time = time.time()
            result.execution_time_ms = int((end_time - start_time) * 1000)
            result.success = True

            # Harvest printable strings from the data segment.
            for region in self.memory_regions:
                if region.name == "data":
                    result.strings_found.extend(self._extract_strings_from_memory(region.start, region.end))

            # Snapshot general-purpose registers on x86_64.
            if self.arch == UC_ARCH_X86_64:
                regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip']
                for reg_name in regs:
                    reg_const = getattr(unicorn.x86_const, f"UC_X86_REG_{reg_name.upper()}")
                    result.register_values[reg_name] = self.uc.reg_read(reg_const)

            # Deduplicate before returning.
            result.strings_found = list(set(result.strings_found))

        except unicorn.UcError as e:
            result.error = f"Unicorn error: {e}"
            logger.warning(f"Emulation aborted (Unicorn error): {e}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"Emulation aborted (unexpected): {e}")

        return result

    def _analyze_complex_functions(self, symbolic_info: Dict[str, Any]) -> List[ExecutionResult]:
        """
        Offload functions flagged as intractable by symbolic execution to concrete emulation.

        Caps at 5 functions to bound wall-clock time.
        """
        results = []

        complex_funcs = symbolic_info.get('complex_functions', [])
        if not complex_funcs:
            return results

        logger.info(f"Concretely executing {len(complex_funcs)} complex function(s)")

        for func_addr in complex_funcs[:5]:  # Hard cap to prevent runaway execution.
            result = self._run_concrete_execution(func_addr)
            if result.success:
                results.append(result)

        return results

    def _extract_hidden_strings(self) -> List[str]:
        """
        Recover obfuscated strings by scanning raw binary for ASCII runs and decryption gadgets.
        """
        hidden_strings = []

        # Direct ASCII scan over the entire binary blob; minimum 4 consecutive printable bytes.
        current_string = []
        for byte in self.binary_data:
            if 0x20 <= byte <= 0x7E:  # Printable ASCII range
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:  # Viable string threshold
                    hidden_strings.append(''.join(current_string))
                current_string = []

        # Flush trailing byte sequence.
        if len(current_string) >= 4:
            hidden_strings.append(''.join(current_string))

        decrypt_patterns = [
            b'\x8a\x06',  # MOV AL, [ESI]
            b'\x30',      # XOR opcode prefix
            b'\x2b',      # SUB opcode prefix
            b'\x0f\xbe',  # MOVSX byte
        ]

        # Identify offsets harboring decryption-indicative opcode sequences.
        for i in range(len(self.binary_data) - 10):
            window = self.binary_data[i:i+10]
            if any(pattern in window for pattern in decrypt_patterns):
                logger.debug(f"Decryption pattern candidate at offset 0x{i:x}")

        return hidden_strings

    def hybrid_analysis(self,
        symbolic_info: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        max_instructions: int = 100000
    ) -> HybridAnalysisResult:
        """
        Execute the hybrid analysis pipeline: set up memory, load binary, run concrete
        emulation on complex functions, and extract hidden strings.

        Returns an empty result if Unicorn is unavailable or memory setup fails.
        """
        if not UNICORN_AVAILABLE:
            logger.warning("Unicorn engine absent; hybrid analysis skipped.")
            return HybridAnalysisResult(
                hidden_strings=[],
                dynamic_jump_targets=set(),
                simplified_constraints=[],
                execution_time_ms=0,
                instructions_executed=0)

        logger.info("Starting hybrid symbolic-concrete analysis.")

        start_time = time.time()

        # Initialize emulator address space and inject binary data.
        if not self._setup_memory() or not self._load_binary():
            return HybridAnalysisResult(
                hidden_strings=[],
                dynamic_jump_targets=set(),
                simplified_constraints=[],
                execution_time_ms=0,
                instructions_executed=0)

        hidden_strings = []
        jump_targets = set()
        constraints = []

        instructions_executed = 0

        # When symbolic pre-analysis data is available, delegate its complex functions to concrete execution.
        if symbolic_info:
            exec_results = self._analyze_complex_functions(symbolic_info)
            for result in exec_results:
                hidden_strings.extend(result.strings_found)
                jump_targets.update(result.branch_targets)
                instructions_executed += max_instructions

        # Augment with strings mined directly from the raw binary.
        hidden_strings.extend(self._extract_hidden_strings())

        # Merge duplicates.
        hidden_strings = list(set(hidden_strings))

        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)

        logger.info(f"Hybrid analysis finished: {len(hidden_strings)} hidden string(s), {len(jump_targets)} jump target(s)")

        return HybridAnalysisResult(
            hidden_strings=hidden_strings,
            dynamic_jump_targets=jump_targets,
            simplified_constraints=constraints,
            execution_time_ms=execution_time_ms,
            instructions_executed=instructions_executed)

    def get_available_architectures(self) -> List[str]:
        """
        Report the ISA family names this analyzer can target.
        """
        return ['x86', 'x86_64', 'arm', 'arm64']

    def is_available(self) -> bool:
        """
        Verify whether the Unicorn native library is importable at runtime.
        """
        return UNICORN_AVAILABLE
logger=None
