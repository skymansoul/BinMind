"""
嵌入式模拟器增强模块

增强功能：
1. Cortex-M 深度模拟
2. ESP32 外设模拟
3. MCU 外设支持
"""

import struct
import logging
from enum import Enum
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """支持的架构"""
    CORTEX_M0 = "cortex_m0"
    CORTEX_M3 = "cortex_m3"
    CORTEX_M4 = "cortex_m4"
    CORTEX_M4F = "cortex_m4f"
    ESP32 = "esp32"
    ESP8266 = "esp8266"


@dataclass
class PeripheralDefinition:
    """外设定义"""
    name: str
    base_address: int
    size: int
    registers: Dict[str, int] = field(default_factory=dict)
    handlers: Dict[str, Callable] = field(default_factory=dict)


@dataclass
class InterruptHandler:
    """中断处理程序"""
    name: str
    vector_number: int
    handler_address: int
    enabled: bool = False
    priority: int = 0


class CortexMPeripherals:
    """Cortex-M 外设定义"""
    
    SCB_BASE = 0xE000ED00
    SCB_SIZE = 0x1000
    
    NVIC_BASE = 0xE000E100
    NVIC_SIZE = 0x300
    
    SYSTICK_BASE = 0xE000E010
    SYSTICK_SIZE = 0x20
    
    FLASH_BASE = 0x08000000
    FLASH_SIZE = 0x100000
    
    SRAM_BASE = 0x20000000
    SRAM_SIZE = 0x40000
    
    @classmethod
    def get_all_peripherals(cls) -> List[PeripheralDefinition]:
        """获取所有外设定义"""
        return [
            PeripheralDefinition()
                name="SCB",
                base_address=cls.SCB_BASE,
                size=cls.SCB_SIZE,
                registers={
                    "CPUID": 0xE000ED00,
                    "ICSR": 0xE000ED04,
                    "VTOR": 0xE000ED08,
                    "AIRCR": 0xE000ED0C,
                    "SCR": 0xE000ED10,
                    "CCR": 0xE000ED14,
                    "SHP": 0xE000ED18,
                    "SHCSR": 0xE000ED24,
                }
            ),
            PeripheralDefinition()
                name="SysTick",
                base_address=cls.SYSTICK_BASE,
                size=cls.SYSTICK_SIZE,
                registers={
                    "CTRL": 0x00,
                    "LOAD": 0x04,
                    "VAL": 0x08,
                    "CALIB": 0x0C,
                }
            ),
            PeripheralDefinition()
                name="NVIC",
                base_address=cls.NVIC_BASE,
                size=cls.NVIC_SIZE,
                registers={}
            ),
        ]


class ESP32Peripherals:
    """ESP32 外设定义"""
    
    GPIO_BASE = 0x3FF44000
    GPIO_SIZE = 0x1000
    
    RTC_BASE = 0x3FF48000
    RTC_SIZE = 0x2000
    
    TIMER_BASE = 0x3FF5F000
    TIMER_SIZE = 0x1000
    
    UART0_BASE = 0x3FF4E000
    UART0_SIZE = 0x1000
    
    SPI0_BASE = 0x3FF42000
    SPI0_SIZE = 0x1000
    
    I2C0_BASE = 0x3FF53000
    I2C0_SIZE = 0x1000
    
    WIFI_BASE = 0x3FFAE000
    WIFI_SIZE = 0x20000
    
    BT_BASE = 0x3FFB0000
    BT_SIZE = 0x10000
    
    @classmethod
    def get_all_peripherals(cls) -> List[PeripheralDefinition]:
        """获取所有外设定义"""
        return [
            PeripheralDefinition()
                name="GPIO",
                base_address=cls.GPIO_BASE,
                size=cls.GPIO_SIZE,
                registers={
                    "OUT": 0x00,
                    "OUT_W1TS": 0x08,
                    "OUT_W1TC": 0x0C,
                    "IN": 0x3C,
                    "_ENABLE": 0x20,
                    "INT_ENA": 0x30,
                    "INT_TYPE": 0x34,
                    "STATUS": 0x44,
                    "STATUS_W1TS": 0x48,
                }
            ),
            PeripheralDefinition()
                name="RTC",
                base_address=cls.RTC_BASE,
                size=cls.RTC_SIZE,
                registers={
                    "ANA_CONFIG": 0x0,
                    "CTL0": 0x40,
                    "CTL1": 0x44,
                    "TIME0": 0x80,
                    "TIME1": 0x84,
                    "ALARM0": 0x90,
                    "ALARM1": 0x94,
                }
            ),
            PeripheralDefinition()
                name="Timer0",
                base_address=cls.TIMER_BASE,
                size=cls.TIMER_SIZE,
                registers={
                    "T0CONFIG": 0x00,
                    "T0LO": 0x04,
                    "T0HI": 0x08,
                    "T0UPDATE": 0x18,
                    "T0ALARM": 0x1C,
                }
            ),
            PeripheralDefinition()
                name="UART0",
                base_address=cls.UART0_BASE,
                size=cls.UART0_SIZE,
                registers={
                    "FIFO": 0x00,
                    "INT_RAW": 0x04,
                    "INT_STATUS": 0x08,
                    "INT_ENA": 0x0C,
                    "INT_CLR": 0x10,
                    "CLOCK": 0x14,
                    "BAUD": 0x18,
                    "STATUS": 0x1C,
                    "CONF0": 0x20,
                    "CONF1": 0x24,
                }
            ),
            PeripheralDefinition()
                name="SPI0",
                base_address=cls.SPI0_BASE,
                size=cls.SPI0_SIZE,
                registers={
                    "CMD": 0x00,
                    "ADDR": 0x04,
                    "CTRL": 0x08,
                    "CTRL2": 0x0C,
                    "DATA": 0x20,
                    "STATUS": 0x28,
                }
            ),
            PeripheralDefinition()
                name="I2C0",
                base_address=cls.I2C0_BASE,
                size=cls.I2C0_SIZE,
                registers={
                    "SLAVE_ADDR": 0x00,
                    "RX_GAP": 0x04,
                    "STATUS": 0x08,
                    "FIFO_CONF": 0x18,
                    "FIFO_DATA": 0x1C,
                    "CMD0": 0x28,
                    "CMD1": 0x2C,
                    "DATA": 0x30,
                }
            ),
        ]


@dataclass
class FirmwareInfo:
    """固件信息"""
    architecture: Architecture
    entry_point: int
    flash_base: int
    sram_base: int
    sram_size: int
    flash_size: int
    interrupt_vectors: List[InterruptHandler] = field(default_factory=list)
    peripherals: List[PeripheralDefinition] = field(default_factory=list)


class BaremetalEmulator:
    """
    嵌入式模拟器
    
    支持 Cortex-M 和 ESP32 等 MCU 的模拟执行
    """
    
    def __init__(self, architecture: Architecture):
        """
        初始化模拟器
        
        Args:
            architecture: 目标架构
        """
        self.architecture = architecture
        self.memory: Dict[int, bytearray] = {}
        self.registers: Dict[str, int] = {}
        self.peripherals: Dict[int, PeripheralDefinition] = {}
        self.interrupts: Dict[int, InterruptHandler] = {}
        self._init_peripherals()
        self._init_registers()
    
    def _init_registers(self) -> None:
        """初始化寄存器"""
        if self.architecture in [Architecture.CORTEX_M0, Architecture.CORTEX_M3,
                                  Architecture.CORTEX_M4, Architecture.CORTEX_M4F]:
            self.registers = {
                'R0': 0, 'R1': 0, 'R2': 0, 'R3': 0,
                'R4': 0, 'R5': 0, 'R6': 0, 'R7': 0,
                'R8': 0, 'R9': 0, 'R10': 0, 'R11': 0,
                'R12': 0,
                'SP': 0x20000000 + 0x10000,
                'LR': 0xFFFFFFFF,
                'PC': 0x08000000,
                'xPSR': 0x01000000,
            }
        elif self.architecture in [Architecture.ESP32]:
            self.registers = {
                'A0': 0, 'A1': 0, 'A2': 0, 'A3': 0,
                'A4': 0, 'A5': 0, 'A6': 0, 'A7': 0,
                'A8': 0, 'A9': 0, 'A10': 0, 'A11': 0,
                'A12': 0, 'A13': 0, 'A14': 0, 'A15': 0,
                'PC': 0x40000000,
            }
    
    def _init_peripherals(self) -> None:
        """初始化外设"""
        if self.architecture in [Architecture.CORTEX_M0, Architecture.CORTEX_M3,
                                  Architecture.CORTEX_M4, Architecture.CORTEX_M4F]:
            for peri in CortexMPeripherals.get_all_peripherals():
                self.peripherals[peri.base_address] = peri
                self._allocate_memory(peri.base_address, peri.size)
        
        elif self.architecture == Architecture.ESP32:
            for peri in ESP32Peripherals.get_all_peripherals():
                self.peripherals[peri.base_address] = peri
                self._allocate_memory(peri.base_address, peri.size)
    
    def _allocate_memory(self, base: int, size: int) -> None:
        """分配内存"""
        self.memory[base] = bytearray(size)
    
    def load_firmware(self, data: bytes, base_address: int = 0x08000000) -> None:
        """
        加载固件
        
        Args:
            data: 固件数据
            base_address: 加载地址
        """
        if base_address not in self.memory:
            self._allocate_memory(base_address, len(data

        
        self.memory[base_address][:len(data)] = data
        self.registers['PC'] = base_address
        
        self._parse_interrupt_vectors()
        
        logger.info(f"固件已加载到 0x{base_address:08X}，大小 {len(data)} 字节")
    
    def _parse_interrupt_vectors(self) -> None:
        """解析中断向量表"""
        if self.architecture in [Architecture.CORTEX_M0, Architecture.CORTEX_M3,
                                  Architecture.CORTEX_M4, Architecture.CORTEX_M4F]:
            if 0x08000000 in self.memory:
                vector_table = self.memory[0x08000000]
                
                stack_pointer = struct.unpack('<I', vector_table[0:4])[0]
                self.registers['SP'] = stack_pointer
                
                reset_handler = struct.unpack('<I', vector_table[4:8])[0] & 0xFFFFFFFE
                self.registers['PC'] = reset_handler & 0xFFFFFFFE
                
                vector_names = [
                    "Reset", "NMI", "HardFault", "MemManage", "BusFault", "UsageFault",
                    "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "SVCall",
                    "Debug", "Reserved", "PendSV", "SysTick"
                ]
                
                for i, name in enumerate(vector_names[:16]):
                    if i * 4 + 4 < len(vector_table):
                        addr = struct.unpack('<I', vector_table[i * 4 + 4:i * 4 + 8])[0]
                        addr = addr & 0xFFFFFFFE if addr != 0xFFFFFFFF else 0
                        
                        self.interrupts[i] = InterruptHandler()
                            name=name,
                            vector_number=i,
                            handler_address=addr
                        
    
    def read_memory(self, address: int, size: int = 4) -> int:
        """
        读取内存
        
        Args:
            address: 地址
            size: 读取大小（字节）
            
        Returns:
            读取的值
        """
        for base, mem in self.memory.items():
            if base <= address < base + len(mem):
                offset = address - base,
                if offset + size <= len(mem):
                    return int.from_bytes(mem[offset:offset+size], 'little')
        
        return 0
    
    def write_memory(self, address: int, value: int, size: int = 4) -> bool:
        """
        写入内存
        
        Args:
            address: 地址
            value: 值
            size: 写入大小（字节）
            
        Returns:
            是否成功
        """
        for base, mem in self.memory.items():
            if base <= address < base + len(mem):
                offset = address - base,
                if offset + size <= len(mem):
                    mem[offset:offset+size] = value.to_bytes(size, 'little')
                    return True
        
        return False
    
    def read_register(self, name: str) -> int:
        """读取寄存器"""
        return self.registers.get(name, 0)
    
    def write_register(self, name: str, value: int) -> None:
        """写入寄存器"""
        self.registers[name] = value
    
    def step(self) -> bool:
        """
        单步执行
        
        Returns:
            是否继续执行
        """
        if self.architecture in [Architecture.CORTEX_M0, Architecture.CORTEX_M3,
                                  Architecture.CORTEX_M4, Architecture.CORTEX_M4F]:
            return self._step_thumb()
        elif self.architecture == Architecture.ESP32:
            return self._step_xtensa()
        
        return False
    
    def _step_thumb(self) -> bool:
        """Thumb 指令单步执行"""
        pc = self.registers['PC']
        
        if pc not in self.memory:
            logger.warning(f"PC 0x{pc:08X} 超出范围")
            return False
        
        opcode = self.read_memory(pc, 2)
        
        if opcode & 0xF800 == 0xE800:
            self._execute_thumb_32(opcode)
        else:
            self._execute_thumb_16(opcode)
        
        return True
    
    def _execute_thumb_16(self, opcode: int) -> None:
        """执行 16 位 Thumb 指令"""
        pass
    
    def _execute_thumb_32(self, opcode: int) -> None:
        """执行 32 位 Thumb 指令"""
        pass
    
    def _step_xtensa(self) -> bool:
        """Xtensa 指令单步执行"""
        pc = self.registers['PC']
        
        if pc not in self.memory:
            logger.warning(f"PC 0x{pc:08X} 超出范围")
            return False
        
        return True
    
    def set_interrupt(self, irq_number: int, pending: bool = True) -> None:
        """
        设置中断
        
        Args:
            irq_number: 中断号
            pending: 是否挂起
        """
        if irq_number in self.interrupts:
            self.interrupts[irq_number].enabled = pending
    
    def get_firmware_info(self) -> FirmwareInfo:
        """
        获取固件信息
        
        Returns:
            固件信息
        """
        if self.architecture in [Architecture.CORTEX_M0, Architecture.CORTEX_M3,
                                  Architecture.CORTEX_M4, Architecture.CORTEX_M4F]:
            return FirmwareInfo(
                architecture=self.architecture,
                entry_point=0x08000000,
                flash_base=0x08000000,
                sram_base=0x20000000,
                sram_size=0x40000,
                flash_size=0x100000,
                interrupt_vectors=list(self.interrupts.values()),
                peripherals=list(self.peripherals.values()

            

        else:
            return FirmwareInfo(
                architecture=self.architecture,
                entry_point=0x40000000,
                flash_base=0x3F000000,
                sram_base=0x3FFAE000,
                sram_size=0x50000,
                flash_size=0x400000,
                interrupt_vectors=list(self.interrupts.values()),
                peripherals=list(self.peripherals.values()

            



def analyze_firmware(binary_path: str, architecture: str = 'auto') -> Dict[str, Any]:
    """
    分析固件二进制
    
    Args:
        binary_path: 固件文件路径
        architecture: 目标架构
        
    Returns:
        分析结果
    """
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    arch = Architecture.CORTEX_M3
    
    if architecture != 'auto':
        try:
            arch = Architecture(architecture)
        except ValueError:
            logger.warning(f"未知架构: {architecture}，使用默认 Cortex-M3")
    
    emulator = BaremetalEmulator(arch)
    emulator.load_firmware(data)
    
    info = emulator.get_firmware_info()
    
    result = {
        'architecture': info.architecture.value,
        'entry_point': hex(info.entry_point),
        'flash_base': hex(info.flash_base),
        'sram_base': hex(info.sram_base),
        'sram_size': info.sram_size,
        'flash_size': info.flash_size,
        'interrupt_vectors': [
            {
                'name': v.name,
                'number': v.vector_number,
                'address': hex(v.handler_address)
            }
            for v in info.interrupt_vectors if v.handler_address != 0
        ],
        'peripherals': [
            {
                'name': p.name,
                'base': hex(p.base_address),
                'size': p.size,
                'registers': list(p.registers.keys(

            }
            for p in info.peripherals
        ]
    }
    
    return result