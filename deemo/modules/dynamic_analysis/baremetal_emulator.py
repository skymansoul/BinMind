# 基于 Unicorn Engine 的裸机固件模拟器
import logging, os, struct
_log = logging.getLogger(__name__)
UNICORN_AVAILABLE = False
try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    _log.warning("Unicorn not installed")

class Architecture:
    ARM_CORTEX_M="arm_cortex_m"; ARM_CORTEX_A="arm_cortex_a"; MIPS="mips"; PPC="ppc"; X86="x86"

class MemoryRegionType:
    FLASH="flash"; RAM="ram"; ROM="rom"; MMIO="mmio"; STACK="stack"; PERIPHERAL="peripheral"

class MemoryRegion:
    def __init__(self,addr=0,size=0,type=None,permissions="rw"):
        self.address=addr; self.size=size; self.type=type; self.permissions=permissions

class ExecutionState:
    RUNNING="running"; STOPPED="stopped"; HALTED="halted"; COMPLETED="completed"; ERROR="error"

class ExecutionTrace:
    def __init__(self,pc=0,disassembly=""): self.pc=pc; self.disassembly=disassembly; self.steps=[]

class PeripheralState:
    def __init__(self,name="",base_address=0): self.name=name; self.base_address=base_address; self.registers={}

class FirmwareAnalysisResult:
    def __init__(self,firmware_path=""): self.firmware_path=firmware_path; self.architecture=None; self.findings=[]; self.traces=[]; self.vulnerabilities=[]

class BareMetalEmulator:
    def __init__(self,firmware_path="",arch=None):
        self.firmware_path=firmware_path; self.architecture=arch; self.memory_regions={}
        self.entry_point=0; self.stats={}; self.exceptions=[]
        self.UNICORN_AVAILABLE=UNICORN_AVAILABLE
    def load_firmware(self,path):
        if not path or ".." in path: raise ValueError("Invalid path")
        self.firmware_path=path
    def run(self): pass
    def _load_static(self):
        if not os.path.isfile(self.firmware_path): return False
        self.stats["firmware_size"]=os.path.getsize(self.firmware_path); return True

DEFAULT_MEMORY_LAYOUT={
    Architecture.ARM_CORTEX_M:[
        {"type":"flash","address":0x08000000,"size":0x100000,"permissions":"rx"},
        {"type":"ram","address":0x20000000,"size":0x20000,"permissions":"rw"},
        {"type":"stack","address":0x20040000,"size":0x1000,"permissions":"rw"},
    ],
}
PERIPHERAL_MAP={
    "GPIO":{"base":0x40020000,"size":0x400},
    "UART":{"base":0x40004000,"size":0x400},
    "TIMER":{"base":0x40008000,"size":0x400},
    "NVIC":{"base":0xE000E100,"size":0x1000},
}
