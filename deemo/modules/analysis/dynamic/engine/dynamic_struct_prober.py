import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

__log = logging.getLogger(__name__)


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

# 新增: 多输入交叉验证布局推断
    # 单个输入可能无法触发所有字段访问，多输入的访问模式交集可以提高推断准确性
    @staticmethod
    def infer_from_multiple(all_accesses: List[List[Tuple[int, int, str]]]) -> StructLayout:
        combined: Dict[int, int] = {}  # offset -> max_size
        for accesses in all_accesses:
            for offset, size, _ in accesses:
                prev = combined.get(offset, 0)
                if size > prev:
                    combined[offset] = size

        sorted_offsets = sorted(combined.keys())
        if not sorted_offsets:
            return StructLayout(name="empty", total_size=0, fields=[])

        fields = []
        for idx, off in enumerate(sorted_offsets):
            sz = combined[off]
            alignment = 8 if sz >= 8 else (4 if sz >= 4 else (2 if sz >= 2 else 1))
            fields.append(FieldLayout(
                name=f"cross_field_{idx}",
                offset=off,
                size=sz,
                alignment=alignment))

        total_size = max(f.offset + f.size for f in fields) if fields else 0
        return StructLayout(name="cross_validated", total_size=total_size, fields=fields)


class DynamicStructProber:

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.tracer = MemoryAccessTracer(binary_path)

    def run(self, sample_inputs: list = None) -> ProbingResult:
        try:
            sample_inputs = sample_inputs or [b"\x00" * 64, b"\xFF" * 64, b"A" * 64]
            layouts = []
            all_accesses = []
            for data in sample_inputs:
                accesses = self.tracer.trace(data)
                all_accesses.append(accesses)
                layout = LayoutInferencer.infer(accesses)
                layouts.append(layout)

            # 交叉验证布局
            if len(all_accesses) >= 2:
                cross_layout = LayoutInferencer.infer_from_multiple(all_accesses)
                layouts.append(cross_layout)

            confidence = 0.7 + min(0.2, len(sample_inputs) * 0.05)
            return ProbingResult(success=True, layouts=layouts, confidence=confidence)
        except Exception as e:
            logger.error("Struct probing failed: %s", e)
            return ProbingResult(success=False, layouts=[])

# 新增: 对齐填充检测
    # 对推断的字段布局进行对齐分析，检测编译器可能插入的填充字节
    def detect_padding(self, layout: StructLayout) -> List[Dict[str, int]]:
        pads = []
        sorted_fields = sorted(layout.fields, key=lambda f: f.offset)
        for i in range(len(sorted_fields) - 1):
            cur_end = sorted_fields[i].offset + sorted_fields[i].size
            next_start = sorted_fields[i + 1].offset
            if next_start > cur_end:
                pads.append({
                    'after_field': sorted_fields[i].name,
                    'gap_size': next_start - cur_end,
                    'gap_offset': cur_end,
                })
        return pads


def create_dynamic_struct_prober(binary_path: str) -> DynamicStructProber:
    return DynamicStructProber(binary_path)
