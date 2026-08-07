"""
MMIO 仿真 responder. Simulates memory-mapped IO device responses
for firmware 仿真 配置urable 寄存器 maps, 读取/写入 钩子s
timing simulation
"""

from collections import OrderedDict
from contextlib import contextmanager


class RegisterType:
    READ = "read"
    WRITE = "write"
    READ_WRITE = "rw"

class RegisterSpec:
    """Single MMIO 寄存器 definition"""
    __slots__ = ("name", "offset", "width", "reg_type", "reset_value", "description")

    def __init__(self, name="", offset=0, width=4, reg_type=RegisterType.READ_WRITE,
                 reset_value=0, description=""):
        self.name = name
        self.offset = offset
        self.width = width
        self.reg_type = reg_type
        self.reset_value = reset_value
        self.description = description

    def __repr__(self):
        return f"RegisterSpec({self.name}, offset=0x{self.offset:x}, width={self.width})"

class PeripheralSpec:
    """Peripheral device specification"""
    __slots__ = ("name", "base_addr", "size", "registers", "vendor_id", "device_id")

    def __init__(self, name="", base_addr=0, size=4096, registers=None,
                 vendor_id=0, device_id=0):
        self.name = name
        self.base_addr = base_addr
        self.size = size
        self.registers: dict[str, RegisterSpec] = OrderedDict()
        if registers:
            for r in registers:
                self.registers[r.name] = r
        self.vendor_id = vendor_id
        self.device_id = device_id


class MMIOResponder:
    """Stateful MMIO device 仿真器 钩子-based 读取/写入 handling"""

    def __init__(self, spec: PeripheralSpec = None):
        self._spec = spec or PeripheralSpec()
        self._state: bytearray = bytearray(self._spec.size)
        self._read_hooks: dict[int, callable] = {}
        self._write_hooks: dict[int, callable] = {}
        self._access_log: list[tuple[str, int, int, int]] = []
        self._latency_ns: int = 0
        self._tick_ns: int = 10  # base clock period
        # 寄存器宽度缓存 — 避免每次访问都遍历全量寄存器列表
        self._width_cache: dict[int, int] = {}

        self._init_registers()

    def _init_registers(self):
        for reg in self._spec.registers.values():
            self._write_raw(reg.offset, reg.reset_value, reg.width)
            self._width_cache[reg.offset] = reg.width

    def respond(self, addr: int, data: int, is_write: bool = False) -> int:
        """处理 an MMIO access. 返回 读取 value or 0 写入"""
        offset = addr - self._spec.base_addr
        if is_write:
            return self._handle_write(offset, data)
        return self._handle_read(offset)

    def _handle_read(self, offset: int) -> int:
        width = self._guess_width(offset)
        if offset in self._read_hooks:
            val = self._read_hooks[offset](offset)
            self._latency_ns += self._tick_ns * 2
        else:
            val = self._read_raw(offset, width)
            self._latency_ns += self._tick_ns
        self._access_log.append(("read", offset, val, width))
        return val

    def _handle_write(self, offset: int, data: int) -> int:
        width = self._guess_width(offset)
        if offset in self._write_hooks:
            self._write_hooks[offset](offset, data)
        else:
            reg = self._find_register(offset)
            if reg and reg.reg_type == RegisterType.READ:
                pass  # 读取- 寄存器, ignore 写入
            else:
                self._write_raw(offset, data, width)
        self._latency_ns += self._tick_ns
        self._access_log.append(("write", offset, data, width))
        return 0

    def _read_raw(self, offset: int, width: int) -> int:
        end = min(offset + width, len(self._state))
        return int.from_bytes(self._state[offset:end], 'little')

    def _write_raw(self, offset: int, value: int, width: int):
        end = min(offset + width, len(self._state))
        self._state[offset:end] = value.to_bytes(width, 'little')[:end - offset]

    def _guess_width(self, offset: int) -> int:
        if offset in self._width_cache:
            return self._width_cache[offset]
        reg = self._find_register(offset)
        return reg.width if reg else 4

    def _find_register(self, offset: int):
        for reg in self._spec.registers.values():
            if reg.offset == offset:
                return reg
        return None

    def on_read(self, offset: int):
        """Decorator: 寄存器 a 读取 钩子 for a specific MMIO offset"""
        def decorator(fn):
            self._read_hooks[offset] = fn
            return fn
        return decorator

    def on_write(self, offset: int):
        """Decorator: 寄存器 a 写入 钩子 for a specific MMIO offset"""
        def decorator(fn):
            self._write_hooks[offset] = fn
            return fn
        return decorator

# 新增: 批量读写
    # 外设配置通常涉及多个连续寄存器的读写，批量操作减少函数调用开销
    def read_block(self, offset: int, length: int) -> bytes:
        """批量读取MMIO区域 — 用于DMA传输和配置块导出
        对连续地址空间执行多次单字读取，聚合为字节序列"""
        end = min(offset + length, len(self._state))
        return bytes(self._state[offset:end])

    def write_block(self, offset: int, data: bytes):
        """批量写入MMIO区域 — 用于固件上传和外设配置块导入"""
        end = min(offset + len(data), len(self._state))
        self._state[offset:end] = data[:end - offset]

    @property
    def elapsed_ns(self) -> int:
        return self._latency_ns

    def reset(self):
        self._state = bytearray(self._spec.size)
        self._access_log.clear()
        self._latency_ns = 0
        self._init_registers()

    def snapshot_state(self, offset: int, length: int) -> bytes:
        end = min(offset + length, len(self._state))
        return bytes(self._state[offset:end])

    def read_register(self, name: str) -> int:
        reg = self._spec.registers.get(name)
        if not reg:
            raise KeyError(f"Unknown register: {name}")
        return self._read_raw(reg.offset, reg.width)

    def write_register(self, name: str, value: int):
        reg = self._spec.registers.get(name)
        if not reg:
            raise KeyError(f"Unknown register: {name}")
        if reg.reg_type == RegisterType.READ:
            raise PermissionError(f"Register {name} is read-only")
        self._handle_write(reg.offset, value)

# 新增: 访问统计分析
    # 外设寄存器访问频率与模式分析帮助识别固件的硬件交互热点
    def access_stats(self) -> dict:
        """返回MMIO访问统计：读/写计数、按偏移量分组的频率分布
        用于外设使用模式分析和固件逆向中的硬件交互热点识别"""
        reads = sum(1 for a in self._access_log if a[0] == 'read')
        writes = sum(1 for a in self._access_log if a[0] == 'write')
        by_offset: dict[int, dict] = {}
        for op_type, offset, val, width in self._access_log:
            if offset not in by_offset:
                by_offset[offset] = {'reads': 0, 'writes': 0, 'samples': []}
            by_offset[offset][f'{op_type}s'] += 1
            if len(by_offset[offset]['samples']) < 5:
                by_offset[offset]['samples'].append(hex(val))
        return {
            'total_accesses': len(self._access_log),
            'reads': reads,
            'writes': writes,
            'by_offset': {
                hex(k): v for k, v in sorted(by_offset.items(), key=lambda x: x[0])
            },
        }


def create_mmio_responder(registers=None, base=0x40000000, size=0x1000) -> MMIOResponder:
    regs = []
    if registers:
        for r in registers:
            regs.append(RegisterSpec(
                name=r.get("name", "UNK"),
                offset=r.get("offset", 0),
                width=r.get("width", 4),
                reg_type=r.get("type", RegisterType.READ_WRITE),
                reset_value=r.get("reset", 0),
                description=r.get("desc", "")))
    spec = PeripheralSpec(name="custom", base_addr=base, size=size, registers=regs)
    return MMIOResponder(spec)
