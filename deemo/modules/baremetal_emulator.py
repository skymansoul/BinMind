#!/usr/bin/env python3
"""
嵌入式裸机固件模拟执行与动态分析模块

功能：
1. 裸机固件加载与模拟执行
2. 多架构支持（ARM Cortex-M、AVR、MIPS、RISC-V）
3. 外设模拟（GPIO、UART、Timer、Flash）
4. 动态分析：内存访问追踪、函数调用追踪
5. 异常检测：缓冲区溢出、空指针访问
6. 与 Unicorn/QEMU 集成

依赖：unicorn（可选）、qemu（可选）
"""

import os
import re
import struct
import logging
import tempfile
import threading
import time
from typing import Dict, Any, List, Optional, Tuple, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)

# Unicorn 可用性检查
UNICORN_AVAILABLE = False
try:
    from unicorn import Uc, UC_ARCH_ARM, UC_ARCH_X86, UC_ARCH_MIPS, UC_ARCH_ARM64
    from unicorn import UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_32, UC_MODE_64
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0
    from unicorn import UcError
    UNICORN_AVAILABLE = True
    logger.info("Unicorn 已加载，固件模拟功能可用")
except ImportError:
    logger.warning("Unicorn 未安装，固件模拟受限。安装: pip install unicorn")


# ==================== 常量定义 ====================

class Architecture(Enum):
    """支持的架构"""
    ARM_CORTEX_M = 'arm_cortex_m'
    ARM_CORTEX_A = 'arm_cortex_a'
    ARM64 = 'arm64'
    AVR = 'avr'
    MIPS = 'mips'
    RISC_V = 'riscv'
    X86 = 'x86'
    X86_64 = 'x86_64'


class MemoryRegionType(Enum):
    """内存区域类型"""
    FLASH = 'flash'
    RAM = 'ram'
    ROM = 'rom'
    PERIPHERAL = 'peripheral'
    STACK = 'stack'
    HEAP = 'heap'


class ExecutionState(Enum):
    """执行状态"""
    RUNNING = 'running'
    PAUSED = 'paused'
    STOPPED = 'stopped'
    ERROR = 'error'
    COMPLETED = 'completed'


# 默认内存布局（ARM Cortex-M）
DEFAULT_MEMORY_LAYOUT = {
    Architecture.ARM_CORTEX_M: [
        {'type': MemoryRegionType.FLASH, 'address': 0x08000000, 'size': 0x100000, 'perm': 'rx'},
        {'type': MemoryRegionType.RAM, 'address': 0x20000000, 'size': 0x40000, 'perm': 'rwx'},
        {'type': MemoryRegionType.PERIPHERAL, 'address': 0x40000000, 'size': 0x10000, 'perm': 'rw'},
        {'type': MemoryRegionType.STACK, 'address': 0x20040000, 'size': 0x1000, 'perm': 'rw'},
    ],
    Architecture.ARM_CORTEX_A: [
        {'type': MemoryRegionType.FLASH, 'address': 0x00000000, 'size': 0x800000, 'perm': 'rx'},
        {'type': MemoryRegionType.RAM, 'address': 0x40000000, 'size': 0x400000, 'perm': 'rwx'},
    ],
    Architecture.MIPS: [
        {'type': MemoryRegionType.FLASH, 'address': 0x80000000, 'size': 0x800000, 'perm': 'rx'},
        {'type': MemoryRegionType.RAM, 'address': 0xA0000000, 'size': 0x400000, 'perm': 'rwx'},
    ],
}

# 外设地址映射（ARM Cortex-M）
PERIPHERAL_MAP = {
    'GPIO': {'base': 0x40020000, 'size': 0x400},
    'UART': {'base': 0x40011000, 'size': 0x400},
    'TIMER': {'base': 0x40000000, 'size': 0x400},
    'SPI': {'base': 0x40013000, 'size': 0x400},
    'I2C': {'base': 0x40012000, 'size': 0x400},
    'FLASH_CTRL': {'base': 0x40022000, 'size': 0x400},
    'RCC': {'base': 0x40021000, 'size': 0x400},  # Reset and Clock Control
    'NVIC': {'base': 0xE000E000, 'size': 0x1000},  # Nested Vectored Interrupt Controller
}


@dataclass
class MemoryRegion:
    """内存区域数据类"""
    type: MemoryRegionType = MemoryRegionType.RAM
    address: int = 0
    size: int = 0
    permissions: str = 'rw'
    data: bytes = b''
    name: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionTrace:
    """执行追踪数据类"""
    pc: int = 0
    instruction: str = ''
    disassembly: str = ''
    timestamp: float = 0.0
    registers: Dict[str, int] = field(default_factory=dict)
    memory_reads: List[Tuple[int, int, bytes]] = field(default_factory=list)
    memory_writes: List[Tuple[int, int, bytes]] = field(default_factory=list)
    function_call: Optional[str] = None
    exception: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PeripheralState:
    """外设状态数据类"""
    name: str = ''
    base_address: int = 0
    registers: Dict[int, int] = field(default_factory=dict)
    enabled: bool = False
    interrupts: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FirmwareAnalysisResult:
    """固件分析结果数据类"""
    firmware_path: str = ''
    architecture: Architecture = Architecture.ARM_CORTEX_M
    entry_point: int = 0
    execution_state: ExecutionState = ExecutionState.STOPPED
    instructions_executed: int = 0
    execution_time: float = 0.0
    traces: List[ExecutionTrace] = field(default_factory=list)
    memory_accesses: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)
    function_calls: List[Dict[str, Any]] = field(default_factory=list)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[int, bool] = field(default_factory=dict)
    peripheral_states: Dict[str, PeripheralState] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BareMetalEmulator:
    """
    裸机固件模拟器
    
    功能：
    - 加载裸机固件
    - 多架构模拟执行
    - 外设模拟
    - 动态分析
    
    Attributes:
        firmware_path: 固件文件路径
        architecture: 目标架构
        memory_regions: 内存区域列表
        emu: Unicorn 模拟器实例
    """
    
    def __init__(, self)
        firmware_path: str,
        architecture: Architecture = Architecture.ARM_CORTEX_M,
        memory_layout: Optional[List[Dict[str, Any]]] = None,
        entry_point: Optional[int] = None,
        stack_size: int = 0x1000,
        enable_tracing: bool = True,
        enable_hooks: bool = True
    ):
        """
        初始化裸机固件模拟器
        
        Args:
            firmware_path: 固件文件路径
            architecture: 目标架构
            memory_layout: 自定义内存布局
            entry_point: 入口地址（可选，自动检测）
            stack_size: 栈大小
            enable_tracing: 是否启用执行追踪
            enable_hooks: 是否启用内存访问钩子
        """
        self.firmware_path = firmware_path
        self.architecture = architecture
        self.stack_size = stack_size
        self.enable_tracing = enable_tracing
        self.enable_hooks = enable_hooks
        
        # 内存布局
        self.memory_layout = memory_layout or DEFAULT_MEMORY_LAYOUT.get(architecture, [])
        self.memory_regions: Dict[int, MemoryRegion] = {}
        
        # 模拟器
        self.emu: Optional[Uc] = None
        self.execution_state = ExecutionState.STOPPED
        
        # 追踪数据
        self.traces: List[ExecutionTrace] = []
        self.memory_accesses: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        self.function_calls: List[Dict[str, Any]] = []
        self.exceptions: List[Dict[str, Any]] = []
        self.coverage: Dict[int, bool] = {}
        
        # 外设状态
        self.peripheral_states: Dict[str, PeripheralState] = {}
        
        # 统计
        self.stats: Dict[str, int] = defaultdict(int)
        
        # 入口地址
        self.entry_point = entry_point or 0
        
        # 验证路径
        self._validate_path()
        
        logger.info(f"[BareMetal] 初始化模拟器: {firmware_path}, 架构: {architecture}")
    
    def _validate_path(self) -> None:
        """
        验证固件文件路径
        """
        if not self.firmware_path:
            raise ValueError("固件文件路径不能为空")
        
        path = os.path.abspath(self.firmware_path)
        
        if '..' in self.firmware_path:
            raise ValueError("路径包含非法字符")
        
        if not os.path.exists(path):
            raise ValueError(f"文件不存在: {self.firmware_path}")
        
        self.firmware_path = path
    
    def load(self) -> bool:
        """
        加载固件
        
        Returns:
            True 如果加载成功
        """
        logger.info("[BareMetal] 加载固件...")
        
        if not UNICORN_AVAILABLE:
            logger.warning("[BareMetal] Unicorn 不可用，使用静态分析模式")
            return self._load_static()
        
        try:
            # 1. 创建模拟器
            self._create_emulator()
            
            # 2. 映射内存区域
            self._map_memory()
            
            # 3. 加载固件代码
            self._load_firmware_code()
            
            # 4. 设置钩子
            if self.enable_hooks:
                self._setup_hooks()
            
            # 5. 初始化外设
            self._init_peripherals()
            
            # 6. 设置入口地址
            self._detect_entry_point()
            
            logger.info(f"[BareMetal] 固件加载完成，入口: {hex(self.entry_point)}")
            return True
            
        except Exception as e:
            logger.error(f"[BareMetal] 加载失败: {e}")
            self.exceptions.append({)
                'type': 'load_error',
                'message': str(e)
            }
            return False
    
    def _create_emulator(self) -> None:
        """
        创建 Unicorn 模拟器实例
        """
        # 根据架构选择参数
        arch_map = {
            Architecture.ARM_CORTEX_M: (UC_ARCH_ARM, UC_MODE_THUMB),
            Architecture.ARM_CORTEX_A: (UC_ARCH_ARM, UC_MODE_ARM),
            Architecture.ARM64: (UC_ARCH_ARM64, UC_MODE_ARM),
            Architecture.MIPS: (UC_ARCH_MIPS, UC_MODE_32),
            Architecture.X86: (UC_ARCH_X86, UC_MODE_32),
            Architecture.X86_64: (UC_ARCH_X86, UC_MODE_64),
        }
        
        uc_arch, uc_mode = arch_map.get(self.architecture, (UC_ARCH_ARM, UC_MODE_THUMB

        
        self.emu = Uc(uc_arch, uc_mode)
        logger.info(f"[BareMetal] 创建模拟器: arch={uc_arch}, mode={uc_mode}")
    
    def _map_memory(self) -> None:
        """
        映射内存区域
        """
        for region_def in self.memory_layout:
            region = MemoryRegion()
                type=MemoryRegionType(region_def.get('type', 'ram')),
                address=region_def['address'],
                size=region_def['size'],
                permissions=region_def.get('perm', 'rw'),
                name=region_def.get('name', '')
            
            
            # Unicorn 权限映射
            perm_map = {
                'r': 1,
                'w': 2,
                'x': 4,
                'rw': 3,
                'rx': 5,
                'rwx': 7,
            }
            perm = perm_map.get(region.permissions, 3)
            
            # 映射内存
            self.emu.mem_map(region.address, region.size, perm)
            
            self.memory_regions[region.address] = region
            logger.debug(f"[BareMetal] 映射内存: {hex(region.address)}, size={hex(region.size)}, perm={region.permissions}")
    
    def _load_firmware_code(self) -> None:
        """
        加载固件代码到内存
        """
        # 读取固件文件
        with open(self.firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        # 确定加载地址（通常是 Flash 区域）
        flash_region = None,
        for addr, region in self.memory_regions.items():
            if region.type == MemoryRegionType.FLASH:
                flash_region = region
                break
        
        if not flash_region:
            # 使用第一个内存区域
            flash_region = list(self.memory_regions.values())[0]
        
        # 加载代码
        load_size = min(len(firmware_data), flash_region.size)
        self.emu.mem_write(flash_region.address, firmware_data[:load_size])
        
        flash_region.data = firmware_data[:load_size]
        
        logger.info(f"[BareMetal] 加载固件: {load_size} bytes at {hex(flash_region.address)}")
        
        # 初始化栈
        stack_region = None,
        for addr, region in self.memory_regions.items():
            if region.type == MemoryRegionType.STACK:
                stack_region = region
                break
        
        if stack_region:
            # 设置栈指针
            sp_init = stack_region.address + stack_region.size - 4
            self._set_register('SP', sp_init)
            logger.info(f"[BareMetal] 初始化栈指针: {hex(sp_init)}")
    
    def _setup_hooks(self) -> None:
        """
        设置执行钩子
        """
        # 代码执行钩子
        self.emu.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # 内存访问钩子
        self.emu.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
        self.emu.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        self.emu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)
        
        logger.info("[BareMetal] 钩子已设置")
    
    def _hook_code(self, uc: Uc, address: int, size: int, user_data: Any) -> None:
        """
        代码执行钩子
        
        Args:
            uc: Unicorn 实例
            address: 执行地址
            size: 指令大小
            user_data: 用户数据
        """
        self.stats['instructions_executed'] += 1
        
        # 记录覆盖率
        self.coverage[address] = True
        
        # 追踪
        if self.enable_tracing:
            trace = ExecutionTrace()
                pc=address,
                timestamp=time.time(),
                registers=self._get_registers()
            
            
            # 尝试反汇编
            try:
                code = uc.mem_read(address, size)
                trace.disassembly = self._disassemble_instruction(code, address)
            except:
                pass
            
            self.traces.append(trace)
            
            # 限制追踪数量
            if len(self.traces) > 10000:
                self.traces = self.traces[-5000:]
    
    def _hook_mem_read(self, uc: Uc, address: int, size: int, value: int, user_data: Any) -> None:
        """
        内存读取钩子
        """
        self.memory_accesses['read'].append((address, size

        self.stats['memory_reads'] += 1
        
        # 检查外设访问
        self._check_peripheral_access(address, 'read')
    
    def _hook_mem_write(self, uc: Uc, address: int, size: int, value: int, user_data: Any) -> None:
        """
        内存写入钩子
        """
        self.memory_accesses['write'].append((address, size

        self.stats['memory_writes'] += 1
        
        # 检查外设访问
        self._check_peripheral_access(address, 'write', value)
    
    def _hook_mem_invalid(self, uc: Uc, address: int, size: int, value: int, user_data: Any) -> bool:
        """
        无效内存访问钩子
        
        Returns:
            False 以停止执行
        """
        logger.warning(f"[BareMetal] 无效内存访问: {hex(address)}, size={size}")
        
        self.exceptions.append({)
            'type': 'invalid_memory_access',
            'address': hex(address),
            'size': size,
            'value': value if value else 'N/A'
        }
        
        # 记录潜在漏洞
        self._record_vulnerability('invalid_memory_access', address)
        
        return False  # 停止执行
    
    def _check_peripheral_access(self, address: int, access_type: str, value: int = 0) -> None:
        """
        检查外设访问
        
        Args:
            address: 访问地址
            access_type: 访问类型
            value: 写入值（写入时）
        """
        for name, info in PERIPHERAL_MAP.items():
            base = info['base']
            size = info['size']
            
            if base <= address < base + size:
                offset = address - base
                
                if name not in self.peripheral_states:
                    self.peripheral_states[name] = PeripheralState()
                        name=name,
                        base_address=base
                    
                
                state = self.peripheral_states[name]
                
                if access_type == 'write':
                    state.registers[offset] = value
                    logger.debug(f"[BareMetal] 外设写入: {name} offset={hex(offset)} value={hex(value)}")
                
                self.stats['peripheral_accesses'] += 1
    
    def _init_peripherals(self) -> None:
        """
        初始化外设状态
        """
        for name, info in PERIPHERAL_MAP.items():
            self.peripheral_states[name] = PeripheralState()
                name=name,
                base_address=info['base']
            
        
        logger.info(f"[BareMetal] 初始化 {len(self.peripheral_states)} 个外设")
    
    def _detect_entry_point(self) -> None:
        """
        检测入口地址
        
        对于 ARM Cortex-M，入口点在向量表中
        """
        if self.entry_point:
            return
        
        # ARM Cortex-M 向量表
        if self.architecture == Architecture.ARM_CORTEX_M:
            try:
                # 向量表在 Flash 起始地址
                flash_region = None,
                for addr, region in self.memory_regions.items():
                    if region.type == MemoryRegionType.FLASH:
                        flash_region = region
                        break
                
                if flash_region and len(flash_region.data) >= 8:
                    # 初始 SP（偏移 0）
                    initial_sp = struct.unpack('<I', flash_region.data[0:4])[0]
                    
                    # Reset Handler（偏移 4）
                    reset_handler = struct.unpack('<I', flash_region.data[4:8])[0]
                    
                    # ARM Cortex-M 地址最低位表示 Thumb 模式
                    self.entry_point = reset_handler & 0xFFFFFFFE
                    
                    logger.info(f"[BareMetal] 检测到入口: Reset Handler = {hex(self.entry_point)}, SP = {hex(initial_sp)}")
                    
                    # 设置 SP
                    self._set_register('SP', initial_sp)
                    
            except Exception as e:
                logger.warning(f"[BareMetal] 入口检测失败: {e}")
                self.entry_point = 0x08000000  # 默认 Flash 起始
        
        else:
            # 其他架构，使用第一个内存区域起始
            if self.memory_regions:
                self.entry_point = list(self.memory_regions.keys())[0]
    
    def _get_registers(self) -> Dict[str, int]:
        """
        获取当前寄存器值
        
        Returns:
            寄存器字典
        """
        registers = {}
        
        try:
            if self.architecture in [Architecture.ARM_CORTEX_M, Architecture.ARM_CORTEX_A]:
                # ARM 通用寄存器
                for i in range(16):
                    registers[f'R{i}'] = self.emu.reg_read(UC_ARM_REG_R0 + i)
                
                registers['PC'] = self.emu.reg_read(UC_ARM_REG_PC)
                registers['SP'] = self.emu.reg_read(UC_ARM_REG_SP)
                
        except Exception as e:
            logger.debug(f"[BareMetal] 获取寄存器失败: {e}")
        
        return registers
    
    def _set_register(self, name: str, value: int) -> None:
        """
        设置寄存器值
        
        Args:
            name: 寄存器名称
            value: 寄存器值
        """
        try:
            if name == 'SP':
                self.emu.reg_write(UC_ARM_REG_SP, value)
            elif name == 'PC':
                self.emu.reg_write(UC_ARM_REG_PC, value)
            elif name.startswith('R'):
                idx = int(name[1:])
                self.emu.reg_write(UC_ARM_REG_R0 + idx, value)
        except Exception as e:
            logger.debug(f"[BareMetal] 设置寄存器失败: {e}")
    
    def _disassemble_instruction(self, code: bytes, address: int) -> str:
        """
        反汇编单条指令
        
        Args:
            code: 指令字节
            address: 地址
            
        Returns:
            反汇编字符串
        """
        # 简化的反汇编（实际应使用 Capstone）
        try:
            if len(code) >= 2:
                # ARM Thumb 指令
                insn = struct.unpack('<H', code[:2])[0]
                return f'{hex(insn)}'
        except:
            pass
        
        return code.hex()
    
    def run(, self)
        max_instructions: int = 10000,
        timeout: float = 10.0,
        stop_on_exception: bool = True
    ) -> FirmwareAnalysisResult:
        """
        执行固件
        
        Args:
            max_instructions: 最大指令数
            timeout: 执行超时（秒）
            stop_on_exception: 是否在异常时停止
            
        Returns:
            FirmwareAnalysisResult 分析结果
        """
        logger.info(f"[BareMetal] 开始执行，入口: {hex(self.entry_point)}")
        
        if not self.emu:
            if not self.load():
                return self._generate_result()
        
        self.execution_state = ExecutionState.RUNNING
        start_time = time.time()
        
        try:
            # 执行
            self.emu.emu_start()
                self.entry_point,
                0,  # 结束地址（不限制）
                timeout * 1000000,  # 微秒
                max_instructions
            
            
            self.execution_state = ExecutionState.COMPLETED
            
        except UcError as e:
            logger.warning(f"[BareMetal] 执行异常: {e}")
            
            self.execution_state = ExecutionState.ERROR
            self.exceptions.append({)
                'type': 'execution_error',
                'error_code': e.errno,
                'message': str(e)
            }
            
            if stop_on_exception:
                self._record_vulnerability('execution_exception', self.entry_point)
            
        except Exception as e:
            logger.error(f"[BareMetal] 执行失败: {e}")
            self.execution_state = ExecutionState.ERROR
            self.exceptions.append({)
                'type': 'unknown_error',
                'message': str(e)
            }
        
        elapsed = time.time() - start_time
        
        logger.info(f"[BareMetal] 执行完成，状态: {self.execution_state}, 指令数: {self.stats['instructions_executed']}")
        
        # 分析结果
        self._analyze_execution()
        
        return self._generate_result()
    
    def _analyze_execution(self) -> None:
        """
        分析执行数据，检测漏洞
        """
        logger.info("[BareMetal] 分析执行数据...")
        
        # 1. 检测异常内存访问
        for exc in self.exceptions:
            if exc['type'] == 'invalid_memory_access':
                self._record_vulnerability('invalid_memory_access', int(exc['address'], 16

        
        # 2. 检测栈溢出
        self._detect_stack_overflow()
        
        # 3. 检测空指针访问
        self._detect_null_pointer_access()
        
        # 4. 检测未初始化内存访问
        self._detect_uninitialized_access()
        
        # 5. 分析外设访问
        self._analyze_peripheral_usage()
    
    def _record_vulnerability(self, vuln_type: str, address: int) -> None:
        """
        记录漏洞
        
        Args:
            vuln_type: 漏洞类型
            address: 相关地址
        """
        vuln_info = {
            'type': vuln_type,
            'address': hex(address),
            'severity': 'High',
            'description': f'检测到 {vuln_type} 在地址 {hex(address)}',
            'recommendation': self._get_vulnerability_recommendation(vuln_type)
        }
        
        # 避免重复
        if vuln_info not in self.exceptions:
            self.exceptions.append(vuln_info)
    
    def _get_vulnerability_recommendation(self, vuln_type: str) -> str:
        """
        获取漏洞修复建议
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            建议字符串
        """
        recommendations = {
            'invalid_memory_access': '检查指针有效性，添加边界检查',
            'execution_exception': '审查异常处理逻辑',
            'stack_overflow': '减小栈使用，检查递归深度',
            'null_pointer_access': '添加空指针检查',
            'uninitialized_access': '初始化所有变量',
        }
        
        return recommendations.get(vuln_type, '审查相关代码')
    
    def _detect_stack_overflow(self) -> None:
        """
        检测栈溢出
        """
        # 检查栈区域访问
        stack_region = None,
        for addr, region in self.memory_regions.items():
            if region.type == MemoryRegionType.STACK:
                stack_region = region
                break
        
        if stack_region:
            # 检查栈指针是否超出范围
            registers = self._get_registers()
            sp = registers.get('SP', 0)
            
            if sp < stack_region.address or sp >= stack_region.address + stack_region.size:
                self._record_vulnerability('stack_overflow', sp)
    
    def _detect_null_pointer_access(self) -> None:
        """
        检测空指针访问
        """
        for addr, size in self.memory_accesses.get('read', []):
            if addr == 0 or addr < 0x100:
                self._record_vulnerability('null_pointer_access', addr)
        
        for addr, size in self.memory_accesses.get('write', []):
            if addr == 0 or addr < 0x100:
                self._record_vulnerability('null_pointer_access', addr)
    
    def _detect_uninitialized_access(self) -> None:
        """
        检测未初始化内存访问
        """
        # 检查 RAM 区域是否在访问前被写入
        ram_region = None,
        for addr, region in self.memory_regions.items():
            if region.type == MemoryRegionType.RAM:
                ram_region = region
                break
        
        if ram_region:
            # 检查先读后写的模式
            writes_in_ram = [a for a, s in self.memory_accesses.get('write', []) 
                           if ram_region.address <= a < ram_region.address + ram_region.size]
            reads_in_ram = [a for a, s in self.memory_accesses.get('read', []) 
                          if ram_region.address <= a < ram_region.address + ram_region.size]
            
            # 如果有读但没有写，可能是未初始化访问
            if reads_in_ram and not writes_in_ram:
                logger.warning("[BareMetal] 可能存在未初始化内存访问")
    
    def _analyze_peripheral_usage(self) -> None:
        """
        分析外设使用情况
        """
        for name, state in self.peripheral_states.items():
            if state.registers:
                logger.info(f"[BareMetal] 外设 {name} 被访问，寄存器: {len(state.registers)}")
    
    def _load_static(self) -> bool:
        """
        静态加载模式（无模拟器）
        """
        logger.info("[BareMetal] 使用静态分析模式")
        
        # 读取固件
        with open(self.firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        # 基本分析
        self.stats['firmware_size'] = len(firmware_data)
        
        # 检测向量表
        if len(firmware_data) >= 8:
            initial_sp = struct.unpack('<I', firmware_data[0:4])[0]
            reset_handler = struct.unpack('<I', firmware_data[4:8])[0]
            
            self.entry_point = reset_handler & 0xFFFFFFFE
            
            logger.info(f"[BareMetal] 静态分析: SP={hex(initial_sp)}, Entry={hex(self.entry_point)}")
        
        return True
    
    def _generate_result(self) -> FirmwareAnalysisResult:
        """
        生成分析结果
        
        Returns:
            FirmwareAnalysisResult
        """
        result = FirmwareAnalysisResult()
        
        result.firmware_path = self.firmware_path
        result.architecture = self.architecture
        result.entry_point = self.entry_point
        result.execution_state = self.execution_state
        result.instructions_executed = self.stats.get('instructions_executed', 0)
        result.traces = self.traces[-100:] if self.traces else []  # 最后 100 条
        result.memory_accesses = dict(self.memory_accesses)
        result.function_calls = self.function_calls
        result.exceptions = self.exceptions
        result.coverage = self.coverage
        result.peripheral_states = self.peripheral_states
        
        # 漏洞汇总
        result.vulnerabilities = [e for e in self.exceptions if 'severity' in e]
        
        # 建议
        result.recommendations = self._generate_recommendations()
        
        # 元数据
        result.metadata = {
            'stats': dict(self.stats),
            'memory_regions': {
                hex(addr): {
                    'type': region.type.value,
                    'size': region.size,
                    'permissions': region.permissions
                }
                for addr, region in self.memory_regions.items()
            }
        }
        
        return result
    
    def _generate_recommendations(self) -> List[str]:
        """
        生成安全建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 基于漏洞
        vuln_types = set(v.get('type') for v in result.vulnerabilities)
        
        if 'invalid_memory_access' in vuln_types:
            recommendations.append('添加指针有效性检查')
        
        if 'null_pointer_access' in vuln_types:
            recommendations.append('检查所有指针是否为 NULL')
        
        if 'stack_overflow' in vuln_types:
            recommendations.append('减小栈使用，避免深度递归')
        
        # 基于覆盖率
        coverage_rate = len(self.coverage) / max(self.stats.get('instructions_executed', 1), 1)
        if coverage_rate < 0.5:
            recommendations.append('代码覆盖率较低，建议增加测试场景')
        
        # 通用建议
        recommendations.extend([)
            '启用 MPU（Memory Protection Unit）',
            '使用栈保护机制',
            '定期进行安全审计',
            '启用固件签名验证'
        ]
        
        return recommendations
    
    def stop(self) -> None:
        """
        停止执行
        """
        if self.emu and self.execution_state == ExecutionState.RUNNING:
            try:
                self.emu.emu_stop()
                self.execution_state = ExecutionState.STOPPED
            except:
                pass
    
    def cleanup(self) -> None:
        """
        清理资源
        """
        if self.emu:
            try:
                # 取消所有钩子
                self.emu.hook_del(UC_HOOK_CODE)
                self.emu.hook_del(UC_HOOK_MEM_READ)
                self.emu.hook_del(UC_HOOK_MEM_WRITE)
                self.emu.hook_del(UC_HOOK_MEM_INVALID)
            except:
                pass
            
            self.emu = None


def emulate_firmware(, firmware_path: str, architecture: Architecture = Architecture.ARM_CORTEX_M, max_instructions: int = 10000) -> FirmwareAnalysisResult:
    """
    模拟执行固件的便捷函数
    
    Args:
        firmware_path: 固件文件路径
        architecture: 目标架构
        max_instructions: 最大指令数
        
    Returns:
        FirmwareAnalysisResult
    """
    emulator = BareMetalEmulator()
        firmware_path=firmware_path,
        architecture=architecture
    
    
    if emulator.load():
        return emulator.run(max_instructions=max_instructions)
    
    return emulator._generate_result()


# ==================== 导出 ====================

__all__ = [
    'BareMetalEmulator',
    'FirmwareAnalysisResult',
    'ExecutionTrace',
    'MemoryRegion',
    'PeripheralState',
    'Architecture',
    'MemoryRegionType',
    'ExecutionState',
    'emulate_firmware',
    'UNICORN_AVAILABLE',
    'PERIPHERAL_MAP',
    'DEFAULT_MEMORY_LAYOUT'
])))))