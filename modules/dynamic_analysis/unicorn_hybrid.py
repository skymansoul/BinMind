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
        UC_ARCH_X86_64 = UC_ARCH_X86  # 旧版 Unicorn API 兼容
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
    start: int = 0
    end: int = 0
    perms: int = 0
    name: str = ""

@dataclass
class ExecutionResult:
    success: bool = False
    strings_found: list = None
    branch_targets: set = None
    register_values: dict = None
    memory_snapshot: dict = None
    error: str = ""

@dataclass
class HybridAnalysisResult:
    hidden_strings: list = None
    dynamic_jump_targets: set = None
    simplified_constraints: list = None
    execution_time_ms: int = 0
    instructions_executed: int = 0

class UnicornHybridAnalyzer:
    # 基于 Unicorn 引擎的混合具体-符号分析器

    def __init__(self, binary_path: str):
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

    def _read_binary(self) -> bytes:
        try:
            with open(self._binary_path_obj, 'rb') as f:
                return f.read()
        except Exception as e:
            log.error(f"Binary read failed: {e}")
            return b''

    def _detect_architecture(self) -> int:
        magic = self.binary_data[:4]

        if magic == b'\x7fELF':
            ei_class = self.binary_data[4]
            if ei_class == 2:
                return UC_ARCH_X86_64
            else:
                return UC_ARCH_X86
        elif magic in [b'\xcf\xfa\xed\xfe', b'\xfa\xcf\xfe\xed']:
            # Mach-O CPU type 位于偏移 4, 小端 uint32
            cpu_type_offset = 4
            cpu_type = struct.unpack('<I', self.binary_data[cpu_type_offset:cpu_type_offset+4])[0]
            if cpu_type == 0x01000007:
                return UC_ARCH_X86_64
            elif cpu_type == 0x0100000C:
                return UC_ARCH_ARM64
            elif cpu_type == 7:
                return UC_ARCH_X86
            elif cpu_type == 12:
                return UC_ARCH_ARM
        elif magic[:2] == b'MZ':
            # PE 通过 e_lfanew 定位 NT 头再读 Machine 字段
            pe_offset = struct.unpack('<I', self.binary_data[0x3C:0x40])[0]
            if pe_offset + 4 < len(self.binary_data):
                pe_magic = self.binary_data[pe_offset:pe_offset+4]
                if pe_magic == b'PE\x00\x00':
                    machine = struct.unpack('<H', self.binary_data[pe_offset+4:pe_offset+6])[0]
                    if machine == 0x8664:
                        return UC_ARCH_X86_64
                    elif machine == 0x014C:
                        return UC_ARCH_X86
                    elif machine == 0xAA64:
                        return UC_ARCH_ARM64

        # 未识别格式回退默认值
        return UC_ARCH_X86_64

    def _detect_mode(self) -> int:
        if self.arch == UC_ARCH_X86_64:
            return UC_MODE_64
        elif self.arch == UC_ARCH_ARM64:
            return UC_MODE_ARM
        elif self.arch == UC_ARCH_ARM:
            return UC_MODE_THUMB
        else:
            return 0

    def _create_emu_instance(self) -> 'unicorn.Uc':
        try:
            uc = unicorn.Uc(self.arch, self.mode)
            return uc
        except Exception as e:
            log.error(f"Unicorn instance creation failed: {e}")
            return None

    def _setup_memory(self, base_addr: int = 0x400000) -> bool:
        if not self.uc:
            return False

        try:
            # 代码段 RX 2MiB
            code_size = 0x200000
            self.uc.mem_map(base_addr, code_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
            self.memory_regions.append(MemoryRegion(
                start=base_addr,
                end=base_addr + code_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC,
                name="code"
            ))

            # 数据段 RW 紧跟代码段
            data_addr = base_addr + code_size
            data_size = 0x200000
            self.uc.mem_map(data_addr, data_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.memory_regions.append(MemoryRegion(
                start=data_addr,
                end=data_addr + data_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
                name="data"
            ))

            # 栈 RW 高地址区 1MiB
            stack_addr = 0x7ffffff0000
            stack_size = 0x100000
            self.uc.mem_map(stack_addr, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.memory_regions.append(MemoryRegion(
                start=stack_addr,
                end=stack_addr + stack_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
                name="stack"
            ))

            # 栈顶减偏移设 SP
            if self.arch == UC_ARCH_X86_64:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, stack_addr + stack_size - 0x100)
            elif self.arch == UC_ARCH_X86:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, stack_addr + stack_size - 0x100)
            elif self.arch == UC_ARCH_ARM64:
                self.uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, stack_addr + stack_size - 0x100)

            return True
        except Exception as e:
            log.error(f"Memory layout setup failed: {e}")
            return False

    def _load_binary(self, base_addr: int = 0x400000) -> bool:
        if not self.uc:
            return False

        try:
            self.uc.mem_write(base_addr, self.binary_data)
            log.debug(f"Mapped {len(self.binary_data)} bytes at 0x{base_addr:x}")
            return True
        except Exception as e:
            log.error(f"Binary mapping failed: {e}")
            return False

    def _extract_strings_from_memory(self, start_addr: int, end_addr: int) -> List[str]:
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
            log.warning(f"Memory string extraction failed: {e}")

        return strings

    def _trace_branch(self, uc: 'unicorn.Uc', address: int, size: int, user_data: Any):
        data = user_data
        data['branch_targets'].add(address)

    def _run_concrete_execution(self,
        start_addr: int,
        max_instructions: int = 100000,
        timeout_ms: int = 30000
    ) -> ExecutionResult:
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
            # 安装代码级钩子捕获每条指令 PC 作为分支目标
            self.uc.hook_add(
                unicorn.UC_HOOK_CODE,
                self._trace_branch,
                user_data=user_data
            )

            start_time = time.time()

            # 启动具体执行
            self.uc.emu_start(start_addr, 0, nCount=max_instructions)

            end_time = time.time()
            result.execution_time_ms = int((end_time - start_time) * 1000)
            result.success = True

            # 从数据段提取可打印字符串
            for region in self.memory_regions:
                if region.name == "data":
                    result.strings_found.extend(self._extract_strings_from_memory(region.start, region.end))

            # x86_64 快照通用寄存器
            if self.arch == UC_ARCH_X86_64:
                regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip']
                for reg_name in regs:
                    reg_const = getattr(unicorn.x86_const, f"UC_X86_REG_{reg_name.upper()}")
                    result.register_values[reg_name] = self.uc.reg_read(reg_const)

            # 返回前去重
            result.strings_found = list(set(result.strings_found))

        except unicorn.UcError as e:
            result.error = f"Unicorn error: {e}"
            log.warning(f"Emulation aborted (Unicorn error): {e}")
        except Exception as e:
            result.error = str(e)
            log.error(f"Emulation aborted (unexpected): {e}")

        return result

    def _analyze_complex_functions(self, symbolic_info: Dict[str, Any]) -> List[ExecutionResult]:
        results = []

        complex_funcs = symbolic_info.get('complex_functions', [])
        if not complex_funcs:
            return results

        log.info(f"Concretely executing {len(complex_funcs)} complex function(s)")

        for func_addr in complex_funcs[:5]:  # 硬上限防止失控执行
            result = self._run_concrete_execution(func_addr)
            if result.success:
                results.append(result)

        return results

    def _extract_hidden_strings(self) -> List[str]:
        hidden_strings = []

        # 直接对整个二进制 blob 做 ASCII 扫描, 最短 4 个连续可打印字节
        current_string = []
        for byte in self.binary_data:
            if 0x20 <= byte <= 0x7E:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:
                    hidden_strings.append(''.join(current_string))
                current_string = []

        # 刷新尾部字节序列
        if len(current_string) >= 4:
            hidden_strings.append(''.join(current_string))

        decrypt_patterns = [
            b'\x8a\x06',
            b'\x30',
            b'\x2b',
            b'\x0f\xbe',
        ]

        # 标记含解密特征 opcode 序列的偏移
        for i in range(len(self.binary_data) - 10):
            window = self.binary_data[i:i+10]
            if any(pattern in window for pattern in decrypt_patterns):
                log.debug(f"Decryption pattern candidate at offset 0x{i:x}")

        return hidden_strings

    def hybrid_analysis(self,
        symbolic_info: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        max_instructions: int = 100000
    ) -> HybridAnalysisResult:
        if not UNICORN_AVAILABLE:
            log.warning("Unicorn engine absent; hybrid analysis skipped.")
            return HybridAnalysisResult(
                hidden_strings=[],
                dynamic_jump_targets=set(),
                simplified_constraints=[],
                execution_time_ms=0,
                instructions_executed=0)

        log.info("Starting hybrid symbolic-concrete analysis.")

        start_time = time.time()

        # 初始化模拟器地址空间并写入二进制数据
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

        # 有符号预分析数据时将其复杂函数委托具体执行
        if symbolic_info:
            exec_results = self._analyze_complex_functions(symbolic_info)
            for result in exec_results:
                hidden_strings.extend(result.strings_found)
                jump_targets.update(result.branch_targets)
                instructions_executed += max_instructions

        # 合并原始二进制直接提取的字符串
        hidden_strings.extend(self._extract_hidden_strings())

        # 去重
        hidden_strings = list(set(hidden_strings))

        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)

        log.info(f"Hybrid analysis finished: {len(hidden_strings)} hidden string(s), {len(jump_targets)} jump target(s)")

        return HybridAnalysisResult(
            hidden_strings=hidden_strings,
            dynamic_jump_targets=jump_targets,
            simplified_constraints=constraints,
            execution_time_ms=execution_time_ms,
            instructions_executed=instructions_executed)

    def get_available_architectures(self) -> List[str]:
        return ['x86', 'x86_64', 'arm', 'arm64']

    def is_available(self) -> bool:
        return UNICORN_AVAILABLE
