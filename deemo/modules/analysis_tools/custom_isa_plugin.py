"""
ISA plugin framework. CPU backends, peripheral registry.
Execution engine: Unicorn. Plugins discovered via register(registry).
"""

import logging
import os
import json
import importlib
import importlib.util
import threading

logger = logging.getLogger(__name__)

# ---- Unicorn (optional) ----
_UNICORN_OK = False
try:
    from unicorn import Uc, UC_ARCH_ARM, UC_ARCH_MIPS, UC_ARCH_RISCV, UC_ARCH_X86
    from unicorn.arm_const import UC_MODE_ARM, UC_MODE_THUMB
    from unicorn.x86_const import UC_MODE_32, UC_MODE_64
    _UNICORN_OK = True
except ImportError:
    pass


# ---- CPU architecture string constants ----
class CPUArch:
    ARM    = 'arm'
    ARM64  = 'arm64'
    MIPS   = 'mips'
    MIPS64 = 'mips64'
    RV32   = 'riscv32'
    RV64   = 'riscv64'
    X86    = 'x86'
    X64    = 'x86_64'
    CUSTOM = 'custom'


# ---- Peripheral spec ----
class PeripheralSpec:
    __slots__ = ('name', 'base', 'size', 'desc', 'regs', 'irqs')

    def __init__(self, name, base, size, desc='', regs=None, irqs=None):
        self.name = str(name) if name else ''
        self.base = int(base) if base is not None else 0
        self.size = int(size) if size is not None else 0
        self.desc = str(desc) if desc else ''
        self.regs = dict(regs) if regs else {}
        self.irqs = list(irqs) if irqs else []


# ---- CPU backend base class ----
class CustomCPUBackend:
    NAME = 'custom'
    ARCH = CPUArch.CUSTOM

    def step(self, uc, count=1):
        raise NotImplementedError

    def map_mem(self, uc, base, size):
        raise NotImplementedError

    def regs(self):
        raise NotImplementedError


# ---- Peripheral base class ----
class CustomPeripheral:
    def name(self):
        raise NotImplementedError

    def base(self):
        raise NotImplementedError

    def size(self):
        raise NotImplementedError

    def read(self, off, size):
        raise NotImplementedError

    def write(self, off, size, val):
        raise NotImplementedError

    def tick(self, cycles):
        return []


# ---- ARM Cortex-M backend ----
class ARMCortexMBackend(CustomCPUBackend):
    NAME = 'arm_cortex_m'
    ARCH = CPUArch.ARM

    def __init__(self):
        self.__regs = {f'r{i}': 0 for i in range(13)}
        self.__regs.update({'sp': 0, 'lr': 0, 'pc': 0, 'xpsr': 0})

    def step(self, uc, count=1):
        if not _UNICORN_OK or uc is None:
            return 0
        try:
            uc.emu_start(self.__regs['pc'], 0, nCount=count)
        except Exception as e:
            logger.warning(f'ARM step failed: {e}')
            return 0
        return count

    def map_mem(self, uc, base, size):
        if not _UNICORN_OK or uc is None:
            return
        try:
            uc.mem_map(base, size)
        except Exception as e:
            logger.warning(f'map failed: {e}')

    def regs(self):
        return dict(self.__regs)


# ---- GPIO peripheral emulator ----
class GPIOEmulator(CustomPeripheral):
    def __init__(self, base=0x40020000, size=0x400):
        self.__base = base
        self.__sz = size
        self.__regs = {0x00: 0, 0x04: 0, 0x08: 0, 0x0C: 0, 0x10: 0, 0x14: 0}
        self.__irqs = []

    def name(self):
        return 'GPIO'

    def base(self):
        return self.__base

    def size(self):
        return self.__sz

    def read(self, off, size):
        return self.__regs.get(off, 0)

    def write(self, off, size, val):
        mask = (1 << (size * 8)) - 1
        self.__regs[off] = val & mask
        if off == 0x14 and (val & 0x1):
            self.__irqs.append(5)

    def tick(self, cycles):
        out = list(self.__irqs)
        self.__irqs.clear()
        return out


# ---- Plugin registry ----
class PluginRegistry:
    def __init__(self):
        self.__cpus = {}
        self.__peris = {}
        self.__lock = threading.Lock()

    def reg_cpu(self, name, cls):
        with self.__lock:
            self.__cpus[name] = cls
        logger.info(f'[isa] cpu registered: {name}')

    def reg_peri(self, name, cls):
        with self.__lock:
            self.__peris[name] = cls
        logger.info(f'[isa] peripheral registered: {name}')

    def get_cpu(self, name):
        return self.__cpus.get(name)

    def get_peri(self, name):
        return self.__peris.get(name)

    def list_cpus(self):
        return list(self.__cpus.keys())

    def list_peris(self):
        return list(self.__peris.keys())


registry = PluginRegistry()


def register_cpu(name, cls):
    registry.reg_cpu(name, cls)


def register_peripheral(name, cls):
    registry.reg_peri(name, cls)


def load_plugin(path):
    names = []
    try:
        spec = importlib.util.spec_from_file_location(
            f'isa_plugin_{os.path.basename(path)}', path)
        if not spec or not spec.loader:
            return names
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, 'register'):
            mod.register(registry)
        names = registry.list_cpus() + registry.list_peris()
    except Exception as e:
        logger.warning(f'plugin load fail {path}: {e}')
    return names


def build_emulator(arch, cpu=None, peris=None):
    cpu_name = cpu or arch
    cpu_cls = registry.get_cpu(cpu_name)
    if cpu_cls is None:
        return {
            'error': f'cpu {cpu_name} not found',
            'available_cpus': registry.list_cpus(),
        }
    backend = cpu_cls()
    peris = peris or []
    periphs = []
    for p_name in peris:
        pcls = registry.get_peri(p_name)
        if pcls:
            periphs.append(pcls())
    return {
        'success': True,
        'cpu_backend': backend.NAME,
        'arch': backend.ARCH,
        'peripherals': [p.name() for p in periphs],
    }


# ---- Default registration ----
register_cpu('arm_cortex_m', ARMCortexMBackend)
register_peripheral('gpio', GPIOEmulator)
