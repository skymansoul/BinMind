#!/usr/bin/env python3
"""
MMIO与端口I/O自动响应模型

允许用户定义外设寄存器行为（基于SysML或模板），或从硬件文档自动生成仿真存根。
实现完整固件模拟所需的外设交互。
"""

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from pathlib import Path

logger = logging.getLogger(__name__)


class RegisterAccessType(Enum):
    """寄存器访问类型枚举"""
    READ_ONLY = "read_only"
    WRITE_ONLY = "write_only"
    READ_WRITE = "read_write"
    WRITE_ONE_TO_CLEAR = "write_one_to_clear"
    WRITE_ONE_TO_SET = "write_one_to_set"


class RegisterFieldType(Enum):
    """寄存器字段类型枚举"""
    RESERVED = "reserved"
    GENERAL = "general"
    FLAG = "flag"
    COUNTER = "counter"
    ADDRESS = "address"
    DATA = "data"


class AccessResult(Enum):
    """访问结果枚举"""
    SUCCESS = "success"
    DENIED = "denied"
    OUT_OF_RANGE = "out_of_range"
    INVALID_ACCESS = "invalid_access"


@dataclass
class RegisterField:
    """寄存器字段定义"""
    name: str
    bit_start: int
    bit_end: int
    field_type: RegisterFieldType = RegisterFieldType.GENERAL
    description: str = ""
    default_value: int = 0
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    enum_values: Optional[Dict[int, str]] = None


@dataclass
class Register:
    """寄存器定义"""
    name: str
    address: int
    size: int = 4
    access_type: RegisterAccessType = RegisterAccessType.READ_WRITE
    description: str = ""
    reset_value: int = 0
    fields: List[RegisterField] = field(default_factory=list)
    callback: Optional[Callable[[int, int], Tuple[int, AccessResult]]] = None


@dataclass
class Peripheral:
    """外设定义"""
    name: str
    base_address: int
    size: int
    registers: List[Register] = field(default_factory=list)
    description: str = ""
    interrupt_lines: List[int] = field(default_factory=list)


@dataclass
class MMIOAccess:
    """MMIO访问记录"""
    timestamp: int
    address: int
    size: int
    is_write: bool
    value: int
    peripheral_name: str
    register_name: str
    result: AccessResult


@dataclass
class MMIOAnalysisResult:
    """MMIO分析结果"""
    success: bool
    peripherals: List[Peripheral]
    access_log: List[MMIOAccess]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class BaseMMIOResponder(ABC):
    """MMIO响应器基类"""
    
    @abstractmethod
    def read(self, address: int, size: int) -> Tuple[int, AccessResult]:
        """
        读取MMIO地址
        
        Args:
            address: MMIO地址
            size: 读取大小
        
        Returns:
            (读取的值, 访问结果)
        """
        pass
    
    @abstractmethod
    def write(self, address: int, size: int, value: int) -> AccessResult:
        """
        写入MMIO地址
        
        Args:
            address: MMIO地址
            size: 写入大小
            value: 写入的值
        
        Returns:
            访问结果
        """
        pass


class RegisterFile:
    """寄存器文件"""
    
    def __init__(self):
        """初始化寄存器文件"""
        self.registers: Dict[int, Register] = {}
        self.register_values: Dict[int, int] = {}
    
    def add_register(self, register: Register):
        """
        添加寄存器
        
        Args:
            register: 寄存器定义
        """
        self.registers[register.address] = register
        self.register_values[register.address] = register.reset_value
        logger.info(f"添加寄存器: {register.name} @ 0x{register.address:x}")
    
    def get_register(self, address: int) -> Optional[Register]:
        """
        获取寄存器
        
        Args:
            address: 寄存器地址
        
        Returns:
            寄存器定义（如果存在）
        """
        return self.registers.get(address)
    
    def read(self, address: int) -> Tuple[int, AccessResult]:
        """
        读取寄存器
        
        Args:
            address: 寄存器地址
        
        Returns:
            (值, 访问结果)
        """
        register = self.get_register(address)
        if not register:
            return 0, AccessResult.OUT_OF_RANGE
        
        if register.access_type == RegisterAccessType.WRITE_ONLY:
            return 0, AccessResult.DENIED
        
        value = self.register_values.get(address, register.reset_value)
        
        if register.callback:
            value, result = register.callback(address, value)
            return value, result
        
        return value, AccessResult.SUCCESS
    
    def write(self, address: int, value: int, size: int = 4) -> AccessResult:
        """
        写入寄存器
        
        Args:
            address: 寄存器地址
            value: 写入的值
            size: 写入大小（默认4字节）
        
        Returns:
            访问结果
        """
        register = self.get_register(address)
        if not register:
            return AccessResult.OUT_OF_RANGE
        
        if register.access_type == RegisterAccessType.READ_ONLY:
            return AccessResult.DENIED
        
        if register.callback:
            _, result = register.callback(address, value)
            if result != AccessResult.SUCCESS:
                return result
        
        # 处理特殊写入类型
        if register.access_type == RegisterAccessType.WRITE_ONE_TO_CLEAR:
            current_value = self.register_values.get(address, register.reset_value)
            self.register_values[address] = current_value & ~value
        elif register.access_type == RegisterAccessType.WRITE_ONE_TO_SET:
            current_value = self.register_values.get(address, register.reset_value)
            self.register_values[address] = current_value | value
        else:
            self.register_values[address] = value
        
        return AccessResult.SUCCESS


class PeripheralSimulator(BaseMMIOResponder):
    """外设模拟器"""
    
    def __init__(self, peripheral: Peripheral):
        """
        初始化外设模拟器
        
        Args:
            peripheral: 外设定义
        """
        self.peripheral = peripheral
        self.register_file = RegisterFile()
        
        for reg in peripheral.registers:
            self.register_file.add_register(reg)
        
        logger.info(f"初始化外设模拟器: {peripheral.name}")
    
    def read(self, address: int, size: int) -> Tuple[int, AccessResult]:
        """读取MMIO地址"""
        offset = address - self.peripheral.base_address
        
        if offset < 0 or offset >= self.peripheral.size:
            return 0, AccessResult.OUT_OF_RANGE
        
        return self.register_file.read(self.peripheral.base_address + (offset - offset % 4))
    
    def write(self, address: int, size: int, value: int) -> AccessResult:
        """写入MMIO地址"""
        offset = address - self.peripheral.base_address
        
        if offset < 0 or offset >= self.peripheral.size:
            return AccessResult.OUT_OF_RANGE
        
        return self.register_file.write(self.peripheral.base_address + (offset - offset % 4), value, size)


class MMIOResponder:
    """
    MMIO与端口I/O自动响应模型
    
    允许用户定义外设寄存器行为（基于SysML或模板），或从硬件文档自动生成仿真存根。
    实现完整固件模拟所需的外设交互。
    """
    
    def __init__(self):
        """初始化MMIO响应器"""
        self.peripherals: Dict[str, PeripheralSimulator] = {}
        self.access_log: List[MMIOAccess] = []
        self.next_timestamp = 0
    
    def add_peripheral(self, peripheral: Peripheral):
        """
        添加外设
        
        Args:
            peripheral: 外设定义
        """
        simulator = PeripheralSimulator(peripheral)
        self.peripherals[peripheral.name] = simulator
        logger.info(f"添加外设: {peripheral.name} @ 0x{peripheral.base_address:x}")
    
    def load_from_sysml(self, sysml_content: str):
        """
        从SysML内容加载外设定义
        
        Args:
            sysml_content: SysML格式的外设定义
        """
        peripherals = self._parse_sysml(sysml_content)
        for peripheral in peripherals:
            self.add_peripheral(peripheral)
    
    def load_from_template(self, template_path: str):
        """
        从模板文件加载外设定义
        
        Args:
            template_path: 模板文件路径
        """
        if not os.path.exists(template_path):
            logger.error(f"模板文件不存在: {template_path}")
            return
        
        with open(template_path, 'r') as f:
            content = f.read()
        
        if template_path.endswith('.yaml') or template_path.endswith('.yml'):
            self._load_yaml_template(content)
        elif template_path.endswith('.sysml'):
            self.load_from_sysml(content)
        else:
            logger.warning(f"未知模板格式: {template_path}")
    
    def _parse_sysml(self, content: str) -> List[Peripheral]:
        """解析SysML内容"""
        peripherals = []
        
        # 简化实现：解析SysML-like格式
        current_peripheral = None
        current_register = None
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('peripheral '):
                if current_peripheral:
                    peripherals.append(current_peripheral)
                
                name = line.split()[1]
                current_peripheral = Peripheral(name=name, base_address=0, size=0)
            
            elif line.startswith('base_address:') and current_peripheral:
                current_peripheral.base_address = int(line.split(':')[1].strip(), 0)
            
            elif line.startswith('size:') and current_peripheral:
                current_peripheral.size = int(line.split(':')[1].strip())
            
            elif line.startswith('register '):
                if current_peripheral:
                    parts = line.split()
                    name = parts[1]
                    address = int(parts[2], 0)
                    current_register = Register(name=name, address=address)
                    current_peripheral.registers.append(current_register)
            
            elif line.startswith('access:') and current_register:
                access_type = line.split(':')[1].strip()
                current_register.access_type = RegisterAccessType(access_type)
            
            elif line.startswith('reset:') and current_register:
                current_register.reset_value = int(line.split(':')[1].strip(), 0)
        
        if current_peripheral:
            peripherals.append(current_peripheral)
        
        return peripherals
    
    def _load_yaml_template(self, content: str):
        """加载YAML模板"""
        try:
            import yaml
            data = yaml.safe_load(content)
            
            for peripheral_data in data.get('peripherals', []):
                registers = []
                for reg_data in peripheral_data.get('registers', []):
                    fields = []
                    for field_data in reg_data.get('fields', []):
                        fields.append(RegisterField(
                            name=field_data['name'],
                            bit_start=field_data['bit_start'],
                            bit_end=field_data['bit_end'],
                            field_type=RegisterFieldType(field_data.get('type', 'general'))
                        ))
                    
                    registers.append(Register(
                        name=reg_data['name'],
                        address=reg_data['address'],
                        size=reg_data.get('size', 4),
                        access_type=RegisterAccessType(reg_data.get('access', 'read_write')),
                        reset_value=reg_data.get('reset', 0),
                        fields=fields
                    ))
                
                peripheral = Peripheral(
                    name=peripheral_data['name'],
                    base_address=peripheral_data['base_address'],
                    size=peripheral_data['size'],
                    registers=registers,
                    description=peripheral_data.get('description', '')
                )
                
                self.add_peripheral(peripheral)
            
        except Exception as e:
            logger.error(f"加载YAML模板失败: {e}")
    
    def read(self, address: int, size: int = 4) -> Tuple[int, AccessResult]:
        """
        读取MMIO地址
        
        Args:
            address: MMIO地址
            size: 读取大小
        
        Returns:
            (值, 访问结果)
        """
        peripheral_name = "unknown"
        register_name = "unknown"
        
        for name, simulator in self.peripherals.items():
            if (simulator.peripheral.base_address <= address < 
                simulator.peripheral.base_address + simulator.peripheral.size):
                peripheral_name = name
                reg = simulator.register_file.get_register(address)
                register_name = reg.name if reg else "unknown"
                value, result = simulator.read(address, size)
                
                self._log_access(address, size, False, value, peripheral_name, register_name, result)
                return value, result
        
        self._log_access(address, size, False, 0, "unknown", "unknown", AccessResult.OUT_OF_RANGE)
        return 0, AccessResult.OUT_OF_RANGE
    
    def write(self, address: int, size: int, value: int) -> AccessResult:
        """
        写入MMIO地址
        
        Args:
            address: MMIO地址
            size: 写入大小
            value: 写入的值
        
        Returns:
            访问结果
        """
        peripheral_name = "unknown"
        register_name = "unknown"
        
        for name, simulator in self.peripherals.items():
            if (simulator.peripheral.base_address <= address < 
                simulator.peripheral.base_address + simulator.peripheral.size):
                peripheral_name = name
                reg = simulator.register_file.get_register(address)
                register_name = reg.name if reg else "unknown"
                result = simulator.write(address, size, value)
                
                self._log_access(address, size, True, value, peripheral_name, register_name, result)
                return result
        
        self._log_access(address, size, True, value, "unknown", "unknown", AccessResult.OUT_OF_RANGE)
        return AccessResult.OUT_OF_RANGE
    
    def _log_access(self, address: int, size: int, is_write: bool, value: int,
                   peripheral_name: str, register_name: str, result: AccessResult):
        """记录MMIO访问"""
        self.access_log.append(MMIOAccess(
            timestamp=self.next_timestamp,
            address=address,
            size=size,
            is_write=is_write,
            value=value,
            peripheral_name=peripheral_name,
            register_name=register_name,
            result=result
        ))
        self.next_timestamp += 1
    
    def generate_stub_code(self, language: str = 'c') -> str:
        """
        生成仿真存根代码
        
        Args:
            language: 目标语言（c, python）
        
        Returns:
            存根代码字符串
        """
        if language == 'c':
            return self._generate_c_stub()
        elif language == 'python':
            return self._generate_python_stub()
        else:
            return f"不支持的语言: {language}"
    
    def _generate_c_stub(self) -> str:
        """生成C语言存根"""
        lines = []
        lines.append("/**")
        lines.append(" * 自动生成的MMIO外设仿真存根")
        lines.append(" */")
        lines.append("")
        lines.append("#include <stdint.h>")
        lines.append("")
        
        for name, simulator in self.peripherals.items():
            lines.append(f"// {name} 外设寄存器")
            for reg in simulator.peripheral.registers:
                lines.append(f"volatile uint32_t {reg.name} = 0x{reg.reset_value:x};")
            lines.append("")
        
        lines.append("uint32_t mmio_read(uint32_t address) {")
        lines.append("    switch(address) {")
        
        for name, simulator in self.peripherals.items():
            for reg in simulator.peripheral.registers:
                lines.append(f"        case 0x{reg.address:x}:")
                lines.append(f"            return {reg.name};")
        
        lines.append("        default:")
        lines.append("            return 0;")
        lines.append("    }")
        lines.append("}")
        lines.append("")
        
        lines.append("void mmio_write(uint32_t address, uint32_t value) {")
        lines.append("    switch(address) {")
        
        for name, simulator in self.peripherals.items():
            for reg in simulator.peripheral.registers:
                lines.append(f"        case 0x{reg.address:x}:")
                lines.append(f"            {reg.name} = value;")
                lines.append("            break;")
        
        lines.append("    }")
        lines.append("}")
        
        return "\n".join(lines)
    
    def _generate_python_stub(self) -> str:
        """生成Python存根"""
        lines = []
        lines.append("# 自动生成的MMIO外设仿真存根")
        lines.append("")
        lines.append("class MMIOPeripheral:")
        lines.append("    def __init__(self):")
        
        for name, simulator in self.peripherals.items():
            for reg in simulator.peripheral.registers:
                lines.append(f"        self.{reg.name} = 0x{reg.reset_value:x}")
        
        lines.append("")
        lines.append("    def read(self, address):")
        lines.append("        register_map = {")
        
        for name, simulator in self.peripherals.items():
            for reg in simulator.peripheral.registers:
                lines.append(f"            0x{reg.address:x}: self.{reg.name},")
        
        lines.append("        }")
        lines.append("        return register_map.get(address, 0)")
        lines.append("")
        lines.append("    def write(self, address, value):")
        lines.append("        register_map = {")
        
        for name, simulator in self.peripherals.items():
            for reg in simulator.peripheral.registers:
                lines.append(f"            0x{reg.address:x}: '{reg.name}',")
        
        lines.append("        }")
        lines.append("        reg_name = register_map.get(address)")
        lines.append("        if reg_name:")
        lines.append("            setattr(self, reg_name, value)")
        
        return "\n".join(lines)
    
    def generate_report(self) -> str:
        """生成分析报告"""
        report = []
        report.append("=" * 60)
        report.append("MMIO响应器分析报告")
        report.append("=" * 60)
        report.append(f"外设数量: {len(self.peripherals)}")
        report.append(f"访问记录数: {len(self.access_log)}")
        report.append("")
        
        for name, simulator in self.peripherals.items():
            p = simulator.peripheral
            report.append(f"外设: {name}")
            report.append(f"  基地址: 0x{p.base_address:x}")
            report.append(f"  大小: {p.size} bytes")
            report.append(f"  寄存器数量: {len(p.registers)}")
            report.append("  寄存器:")
            
            for reg in p.registers:
                report.append(f"    {reg.name} @ 0x{reg.address:x}")
                report.append(f"      访问类型: {reg.access_type.value}")
                report.append(f"      复位值: 0x{reg.reset_value:x}")
            
            report.append("")
        
        return "\n".join(report)
    
    def reset(self):
        """重置所有外设状态"""
        for simulator in self.peripherals.values():
            for reg in simulator.peripheral.registers:
                simulator.register_file.register_values[reg.address] = reg.reset_value
        
        self.access_log.clear()
        self.next_timestamp = 0
        logger.info("MMIO响应器已重置")
