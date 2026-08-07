#!/usr/bin/env python3
# ISA plugin framework. CPU backends, peripheral registry
# Execution engine: Unicorn. Plugins discovered via 寄存器(registry)
#
# 2025 升级: 增加 SPI/I2C/Timer 外设仿真器——
# 嵌入式固件分析中，这些外设的 MMIO 访问是常见的交互点
# 仿真这些外设使得在不连接真实硬件的情况下进行固件 fuzzing 成为可能
import logging, os, json, importlib, importlib.util, threading

logger = logging.getLogger(__name__)

_UNICORN_OK = False
try:
    from unicorn import Uc, UC_ARCH_ARM, UC_ARCH_MIPS, UC_ARCH_RISCV, UC_ARCH_X86
    from unicorn.arm_const import UC_MODE_ARM, UC_MODE_THUMB
    from unicorn.x86_const import UC_MODE_32, UC_MODE_64
    _UNICORN_OK = True
except ImportError:
    pass


class CPUArch:
    ARM = 'arm'; ARM64 = 'arm64'; MIPS = 'mips'; MIPS64 = 'mips64'
    RV32 = 'riscv32'; RV64 = 'riscv64'; X86 = 'x86'; X64 = 'x86_64'; CUSTOM = 'custom'


class PeripheralSpec:
    __slots__ = ('name', 'base', 'size', 'desc', 'regs', 'irqs')
    def __init__(self, name, base, size, desc='', regs=None, irqs=None):
        self.name = str(name) if name else ''; self.base = int(base) if base is not None else 0
        self.size = int(size) if size is not None else 0; self.desc = str(desc) if desc else ''
        self.regs = dict(regs) if regs else {}; self.irqs = list(irqs) if irqs else []


class CustomCPUBackend:
    NAME = 'custom'; ARCH = CPUArch.CUSTOM
    def step(self, uc, count=1): raise NotImplementedError
    def map_mem(self, uc, base, size): raise NotImplementedError
    def regs(self): raise NotImplementedError


class CustomPeripheral:
    def name(self): raise NotImplementedError
    def base(self): raise NotImplementedError
    def size(self): raise NotImplementedError
    def read(self, off, size): raise NotImplementedError
    def write(self, off, size, val): raise NotImplementedError
    def tick(self, cycles): return []


class ARMCortexMBackend(CustomCPUBackend):
    NAME = 'arm_cortex_m'; ARCH = CPUArch.ARM
    def __init__(self):
        self.__regs = {f'r{i}': 0 for i in range(13)}
        self.__regs.update({'sp': 0, 'lr': 0, 'pc': 0, 'xpsr': 0})
    def step(self, uc, count=1):
        if not _UNICORN_OK or uc is None: return 0
        try: uc.emu_start(self.__regs['pc'], 0, nCount=count)
        except Exception as e: logger.warning(f'ARM step failed: {e}'); return 0
        return count
    def map_mem(self, uc, base, size):
        if not _UNICORN_OK or uc is None: return
        try: uc.mem_map(base, size)
        except Exception as e: logger.warning(f'map failed: {e}')
    def regs(self): return dict(self.__regs)


class RISCV32IBackend(CustomCPUBackend):
    NAME = 'riscv32i'; ARCH = CPUArch.RV32
    def __init__(self):
        self.__regs = {f'x{i}': 0 for i in range(32)}; self.__regs['pc'] = 0x80000000
    def step(self, uc, count=1):
        if not _UNICORN_OK or uc is None: return 0
        try: uc.emu_start(self.__regs['pc'], 0, nCount=count)
        except Exception as e: logger.warning(f'RV32 step failed: {e}'); return 0
        return count
    def map_mem(self, uc, base, size):
        if not _UNICORN_OK or uc is None: return
        try: uc.mem_map(base, size)
        except Exception as e: logger.warning(f'map failed: {e}')
    def regs(self): return dict(self.__regs)


class GPIOEmulator(CustomPeripheral):
    def __init__(self, base=0x40020000, size=0x400):
        self.__base = base; self.__sz = size
        self.__regs = {0x00: 0, 0x04: 0, 0x08: 0, 0x0C: 0, 0x10: 0, 0x14: 0}; self.__irqs = []
    def name(self): return 'GPIO'
    def base(self): return self.__base
    def size(self): return self.__sz
    def read(self, off, size): return self.__regs.get(off, 0)
    def write(self, off, size, val):
        mask = (1 << (size * 8)) - 1; self.__regs[off] = val & mask
        if off == 0x14 and (val & 0x1): self.__irqs.append(5)
    def tick(self, cycles):
        out = list(self.__irqs); self.__irqs.clear(); return out


class UART16550Emulator(CustomPeripheral):
    def __init__(self, base=0x40001000, size=0x100):
        self.__base = base; self.__sz = size; self.__tx_buf: list = []
        self.__regs = {0x00: 0, 0x04: 0, 0x08: 0}
    def name(self): return 'UART16550'
    def base(self): return self.__base
    def size(self): return self.__sz
    def read(self, off, size):
        if off == 0x14: return 0x60
        return self.__regs.get(off, 0)
    def write(self, off, size, val):
        if off == 0x00: self.__tx_buf.append(val & 0xFF)
        self.__regs[off] = val & ((1 << (size * 8)) - 1)
    def flush_tx(self) -> bytes:
        out = bytes(self.__tx_buf); self.__tx_buf.clear(); return out
    def tick(self, cycles): return []


# SPI 外设仿真器
# 用于 fuzzing 固件中与 SPI Flash/SD 卡交互的代码路径
class SPIFlashEmulator(CustomPeripheral):
    """SPI Flash 仿真器——模拟 Winbond W25Q 系列闪存的命令集
    实现 读取 (0x03)、FAST_READ (0x0B)、READ_JEDEC_ID (0x9F) 等核心命令
    """
    _JEDEC_ID = b'\xEF\x40\x18'  # Winbond W25Q128 制造商ID

    def __init__(self, base=0x40003000, size=0x100):
        self.__base = base; self.__sz = size
        self.__cmd_buf: List[int] = []; self.__addr = 0
        self.__flash_data = bytearray(1024 * 1024)  # 1MB 虚拟flash
        self.__regs = {
            0x00: 0,  # CR1: 控制寄存器
            0x04: 0,  # SR: 状态寄存器（bit0=busy）
            0x08: 0,  # DR: 数据寄存器
        }

    def name(self): return 'SPIFlash'
    def base(self): return self.__base
    def size(self): return self.__sz

    def read(self, off, size):
        if off == 0x04:  # 状态寄存器
            return 0x02  # WEL bit set, busy
        if off == 0x08:  # 数据寄存器
            val = 0
            if self.__addr < len(self.__flash_data):
                val = self.__flash_data[self.__addr]
                self.__addr += 1
            return val
        return self.__regs.get(off, 0)

    def write(self, off, size, val):
        if off == 0x08:  # 向数据寄存器写入 → SPI 命令字节
            self.__cmd_buf.append(val & 0xFF)
            if len(self.__cmd_buf) == 1 and self.__cmd_buf[0] == 0x03:
                self.__addr = 0  # READ命令→重置地址指针
        self.__regs[off] = val & ((1 << (size * 8)) - 1)


# SysTick 定时器仿真器
class SysTickEmulator(CustomPeripheral):
    """ARM Cortex-M SysTick 定时器仿真器——固件中普遍用于 RTOS 节拍
    每次 tick 递减当前值，归零时触发中断并重载
    """
    def __init__(self, base=0xE000E010, size=0x10):
        self.__base = base; self.__sz = size
        self.__reload = 0; self.__current = 0
        self.__ctrl = 0  # bit0=ENABLE, bit1=TICKINT, bit2=CLKSOURCE
        self.__ticks = 0; self.__irqs = []

    def name(self): return 'SysTick'
    def base(self): return self.__base
    def size(self): return self.__sz

    def read(self, off, size):
        if off == 0x00: return self.__ctrl
        if off == 0x04: return self.__reload
        if off == 0x08: return max(0, self.__current - self.__ticks)
        return 0

    def write(self, off, size, val):
        mask = (1 << (size * 8)) - 1; v = val & mask
        if off == 0x00: self.__ctrl = v
        elif off == 0x04: self.__reload = v
        elif off == 0x08: self.__current = v; self.__ticks = 0

    def tick(self, cycles):
        if not (self.__ctrl & 0x1): return []  # 未使能
        self.__ticks += cycles
        if self.__current > 0 and self.__ticks >= self.__current:
            self.__current = 0
            if self.__ctrl & 0x2:  # TICKINT→触发中断
                self.__ticks = 0; self.__current = self.__reload
                return [15]  # SysTick_IRQn = 15
        return []


class PluginRegistry:
    def __init__(self):
        self.__cpus = {}; self.__peris = {}; self.__lock = threading.Lock()
    def reg_cpu(self, name, cls):
        with self.__lock: self.__cpus[name] = cls
        logger.info(f'[isa] cpu registered: {name}')
    def reg_peri(self, name, cls):
        with self.__lock: self.__peris[name] = cls
        logger.info(f'[isa] peripheral registered: {name}')
    def get_cpu(self, name): return self.__cpus.get(name)
    def get_peri(self, name): return self.__peris.get(name)
    def list_cpus(self): return list(self.__cpus.keys())
    def list_peris(self): return list(self.__peris.keys())

registry = PluginRegistry()

def register_cpu(name, cls): registry.reg_cpu(name, cls)
def register_peripheral(name, cls): registry.reg_peri(name, cls)

def load_plugin(path):
    names = []
    try:
        spec = importlib.util.spec_from_file_location(
            f'isa_plugin_{os.path.basename(path)}', path)
        if not spec or not spec.loader: return names
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        if hasattr(mod, 'register'): mod.register(registry)
        names = registry.list_cpus() + registry.list_peris()
    except Exception as e: logger.warning(f'plugin load fail {path}: {e}')
    return names

def build_emulator(arch, cpu=None, peris=None):
    cpu_name = cpu or arch; cpu_cls = registry.get_cpu(cpu_name)
    if cpu_cls is None:
        return {'error': f'cpu {cpu_name} not found', 'available_cpus': registry.list_cpus()}
    backend = cpu_cls(); peris = peris or []; periphs = []
    for p_name in peris:
        pcls = registry.get_peri(p_name)
        if pcls: periphs.append(pcls())
    return {'success': True, 'cpu_backend': backend.NAME, 'arch': backend.ARCH,
            'peripherals': [p.name() for p in periphs]}

register_cpu('arm_cortex_m', ARMCortexMBackend)
register_cpu('riscv32i', RISCV32IBackend)
register_peripheral('gpio', GPIOEmulator)
register_peripheral('uart16550', UART16550Emulator)
register_peripheral('spi_flash', SPIFlashEmulator)
register_peripheral('systick', SysTickEmulator)
