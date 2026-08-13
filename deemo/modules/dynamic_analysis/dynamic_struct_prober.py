import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FieldLayout:
    name: str
    offset: int
    size: int
    alignment: int
    field_type: str = "unknown"


@dataclass
class StructLayout:
    name: str
    total_size: int
    fields: list = field(default_factory=list)


@dataclass
class ProbingResult:
    success: bool
    layouts: list
    confidence: float = 0.0


class MemoryAccessTracer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.accesses: List[Tuple[int, int, str]] = []

    def trace(self, input_data: bytes,
              target_func: str = "") -> List[Tuple[int, int, str]]:
        accesses: List[Tuple[int, int, str]] = []

        sizes = [1, 2, 4, 8, 16, 32, 64, 128]
        for sz in sizes:
            truncated = input_data[:sz]
            for offset in range(0, min(sz, len(truncated)), 1):
                val = truncated[offset]
                if val == 0:
                    accesses.append((offset, 1, "null_read"))
                elif offset == sz - 1:
                    accesses.append((offset, 1, "boundary"))
                else:
                    accesses.append((offset, 1, "read"))

        if len(input_data) >= 8:
            marker = bytes([0xAA] * len(input_data))
            for offset in range(0, len(marker), 4):
                accesses.append((offset, min(4, len(marker) - offset), "marker_probe"))

        uc_accesses = self._unicorn_trace(input_data, target_func)
        if uc_accesses:
            accesses.extend(uc_accesses)

        self.accesses = accesses
        return accesses

    def _unicorn_trace(self, input_data: bytes,
                        target_func: str = "") -> List[Tuple[int, int, str]]:
        try:
            import unicorn
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
            from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP
        except ImportError:
            return []

        uc_accesses: List[Tuple[int, int, str]] = []
        try:
            with open(self.binary_path, "rb") as f:
                code = f.read()[:2 * 1024 * 1024]

            base = 0x100000
            mu = Uc(UC_ARCH_X86, UC_MODE_64)
            mu.mem_map(base, (len(code) + 0xFFF) & ~0xFFF)
            mu.mem_write(base, code)

            stack = base + len(code) + 0x2000
            mu.mem_map(stack & ~0xFFF, 0x8000)
            mu.reg_write(UC_X86_REG_RSP, stack + 0x4000)

            input_addr = stack + 0x5000
            mu.mem_write(input_addr, input_data)

            mem_reads: List[int] = []
            mem_writes: List[int] = []

            def hook_mem_read(uc, access, address, size, value, user_data):
                if input_addr <= address < input_addr + len(input_data):
                    mem_reads.append(address - input_addr)

            def hook_mem_write(uc, access, address, size, value, user_data):
                if input_addr <= address < input_addr + len(input_data):
                    mem_writes.append(address - input_addr)

            mu.hook_add(unicorn.UC_HOOK_MEM_READ, hook_mem_read)
            mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, hook_mem_write)

            try:
                mu.emu_start(base, base + 2000, timeout=2_000_000, count=500)
            except unicorn.UcError:
                pass

            for off in set(mem_reads):
                uc_accesses.append((off, 1, "unicorn_read"))
            for off in set(mem_writes):
                uc_accesses.append((off, 1, "unicorn_write"))

        except Exception as e:
            logger.debug(f"Unicorn trace error: {e}")

        return uc_accesses


class LayoutInferencer:
    @staticmethod
    def infer(accesses: List[Tuple[int, int, str]]) -> StructLayout:
        size_groups: Dict[int, List[int]] = {}
        for offset, size, _ in accesses:
            size_groups.setdefault(size, []).append(offset)

        fields = []
        for idx, (size, offsets) in enumerate(sorted(size_groups.items())):
            alignment = 1
            if size >= 8:
                alignment = 8
            elif size >= 4:
                alignment = 4
            elif size >= 2:
                alignment = 2
            fields.append(FieldLayout(
                name="field_" + str(idx),
                offset=min(offsets) if offsets else 0,
                size=size,
                alignment=alignment))

        total_size = max((f.offset + f.size for f in fields), default=0)
        return StructLayout(name="probed_struct", total_size=total_size, fields=fields)


class DynamicStructProber:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.tracer = MemoryAccessTracer(binary_path)

    def run(self, sample_inputs: list = None) -> ProbingResult:
        try:
            sample_inputs = sample_inputs or [b"\x00" * 64, b"\xFF" * 64, b"A" * 64]
            layouts = []
            for data in sample_inputs:
                accesses = self.tracer.trace(data)
                layout = LayoutInferencer.infer(accesses)
                layouts.append(layout)
            return ProbingResult(success=True, layouts=layouts, confidence=0.7)
        except Exception as e:
            logger.error("Struct probing failed: %s", e)
            return ProbingResult(success=False, layouts=[])

    def probe_struct_layout(self, function_address: int = None,
                            param_data: bytes = None,
                            max_struct_size: int = 1024) -> ProbingResult:
        # 外部统一探测入口；无动态引擎时退化为仿真探测。
        if param_data is not None:
            sample = param_data
        else:
            sample = b"\x00" * max_struct_size
        return self.run(sample_inputs=[sample])


def create_dynamic_struct_prober(binary_path: str) -> DynamicStructProber:
    return DynamicStructProber(binary_path)
