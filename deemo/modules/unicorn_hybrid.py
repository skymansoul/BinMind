#!/usr/bin/env python3
"""
基于 Unicorn Engine 的动态符号执行混合分析模块

弥补纯静态符号执行在处理自修改代码、加密字符串、重度混淆时的不足，
引入 Unicorn Engine 进行动态模拟与符号执行混合分析。
"""

import os
import time
import struct
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

import logging

logger = logging.getLogger(__name__)

try:
    import unicorn
    from unicorn import UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_X86, UC_ARCH_X86_64
    from unicorn import UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_64
    UNICORN_AVAILABLE = True
except ImportError:
    logger.warning("unicorn 未安装，UnicornHybridAnalyzer 将不可用")
    UNICORN_AVAILABLE = False
    # 定义占位常量，避免未定义错误
    UC_ARCH_ARM = 0
    UC_ARCH_ARM64 = 0
    UC_ARCH_X86 = 0
    UC_ARCH_X86_64 = 0
    UC_MODE_ARM = 0
    UC_MODE_THUMB = 0
    UC_MODE_64 = 0


@dataclass
class MemoryRegion:
    """内存区域信息"""
    start: int
    end: int
    perms: int
    name: str = ""


@dataclass
class ExecutionResult:
    """单次执行结果"""
    success: bool
    strings_found: List[str]
    branch_targets: Set[int]
    register_values: Dict[str, int]
    memory_snapshot: Dict[int, bytes]
    error: str = ""


@dataclass
class HybridAnalysisResult:
    """混合分析结果"""
    hidden_strings: List[str]
    dynamic_jump_targets: Set[int]
    simplified_constraints: List[str]
    execution_time_ms: int
    instructions_executed: int


class UnicornHybridAnalyzer:
    """
    基于 Unicorn Engine 的混合符号执行分析器
    
    将动态模拟与符号执行相结合，提高路径覆盖和漏洞发现准确率。
    """

    def __init__(self, binary_path: str):
        """
        初始化混合分析器
        
        Args:
            binary_path: 二进制文件路径
        """
        self.binary_path = binary_path
        self._binary_path_obj = Path(binary_path)
        self.binary_data = self._read_binary()
        self.arch = self._detect_architecture()
        self.mode = self._detect_mode()
        self.memory_regions = []
        self._unicorn_available = UNICORN_AVAILABLE
        
        if UNICORN_AVAILABLE:
            self.uc = self._create_emu_instance()
        else:
            self.uc = None

    def _read_binary(self) -> bytes:
        """
        读取二进制文件
        
        Returns:
            二进制数据
        """
        try:
            with open(self._binary_path_obj, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"读取二进制文件失败: {e}")
            return b''

    def _detect_architecture(self) -> int:
        """
        检测二进制文件架构
        
        Returns:
            Unicorn 架构常量
        """
        magic = self.binary_data[:4]
        
        if magic == b'\x7fELF':
            # ELF 文件
            ei_class = self.binary_data[4]
            if ei_class == 2:  # 64-bit,
                return UC_ARCH_X86_64
            else:  # 32-bit,
                return UC_ARCH_X86
        elif magic in [b'\xcf\xfa\xed\xfe', b'\xfa\xcf\xfe\xed']:
            # Mach-O 文件
            cpu_type_offset = 4
            cpu_type = struct.unpack('<I', self.binary_data[cpu_type_offset:cpu_type_offset+4])[0]
            if cpu_type == 0x01000007:  # ARM64,
                return UC_ARCH_ARM64
            elif cpu_type == 7:  # ARM,
                return UC_ARCH_ARM
            elif cpu_type == 7:  # i386,
                return UC_ARCH_X86
            elif cpu_type == 0x01000007:  # x86_64,
                return UC_ARCH_X86_64
        elif magic[:2] == b'MZ':
            # PE 文件
            pe_offset = struct.unpack('<I', self.binary_data[0x3C:0x40])[0]
            if pe_offset + 4 < len(self.binary_data):
                pe_magic = self.binary_data[pe_offset:pe_offset+4]
                if pe_magic == b'PE\x00\x00':
                    machine = struct.unpack('<H', self.binary_data[pe_offset+4:pe_offset+6])[0]
                    if machine == 0x8664:  # x64,
                        return UC_ARCH_X86_64
                    elif machine == 0x014C:  # x86,
                        return UC_ARCH_X86
                    elif machine == 0xAA64:  # ARM64,
                        return UC_ARCH_ARM64
        
        # 默认返回 x86_64
        return UC_ARCH_X86_64

    def _detect_mode(self) -> int:
        """
        检测运行模式
        
        Returns:
            Unicorn 模式常量
        """
        if self.arch == UC_ARCH_X86_64:
            return UC_MODE_64
        elif self.arch == UC_ARCH_ARM64:
            return UC_MODE_ARM
        elif self.arch == UC_ARCH_ARM:
            return UC_MODE_THUMB
        else:
            return 0

    def _create_emu_instance(self) -> 'unicorn.Uc':
        """
        创建 Unicorn 模拟器实例
        
        Returns:
            Unicorn 实例
        """
        try:
            uc = unicorn.Uc(self.arch, self.mode)
            return uc
        except Exception as e:
            logger.error(f"创建 Unicorn 实例失败: {e}")
            return None

    def _setup_memory(self, base_addr: int = 0x400000) -> bool:
        """
        设置模拟器内存布局
        
        Args:
            base_addr: 基地址
            
        Returns:
            是否成功
        """
        if not self.uc:
            return False
            
        try:
            # 代码段
            code_size = 0x200000
            self.uc.mem_map(base_addr, code_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
            self.memory_regions.append(MemoryRegion(
                start=base_addr,
                end=base_addr + code_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC,
                name="code"
            

            
            # 数据段
            data_addr = base_addr + code_size
            data_size = 0x200000
            self.uc.mem_map(data_addr, data_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.memory_regions.append(MemoryRegion(
                start=data_addr,
                end=data_addr + data_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
                name="data"
            

            
            # 栈
            stack_addr = 0x7ffffff0000
            stack_size = 0x100000
            self.uc.mem_map(stack_addr, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.memory_regions.append(MemoryRegion(
                start=stack_addr,
                end=stack_addr + stack_size,
                perms=unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
                name="stack"
            

            
            # 设置栈指针
            if self.arch == UC_ARCH_X86_64:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, stack_addr + stack_size - 0x100)
            elif self.arch == UC_ARCH_X86:
                self.uc.reg_write(unicorn.x86_const.UC_X86_REG_ESP, stack_addr + stack_size - 0x100)
            elif self.arch == UC_ARCH_ARM64:
                self.uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_SP, stack_addr + stack_size - 0x100)
            
            return True
        except Exception as e:
            logger.error(f"设置内存失败: {e}")
            return False

    def _load_binary(self, base_addr: int = 0x400000) -> bool:
        """
        将二进制文件加载到模拟器内存
        
        Args:
            base_addr: 加载地址
            
        Returns:
            是否成功
        """
        if not self.uc:
            return False
            
        try:
            self.uc.mem_write(base_addr, self.binary_data)
            logger.debug(f"已加载 {len(self.binary_data)} 字节到 0x{base_addr:x}")
            return True
        except Exception as e:
            logger.error(f"加载二进制失败: {e}")
            return False

    def _extract_strings_from_memory(self, start_addr: int, end_addr: int) -> List[str]:
        """
        从内存区域提取字符串
        
        Args:
            start_addr: 起始地址
            end_addr: 结束地址
            
        Returns:
            提取的字符串列表
        """
        strings = []
        try:
            memory = self.uc.mem_read(start_addr, end_addr - start_addr)
            current_string = []
            
            for byte in memory:
                if 0x20 <= byte <= 0x7E:
                    current_string.append(chr(byte

                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string

                    current_string = []
            
            if len(current_string) >= 4:
                strings.append(''.join(current_string

                
        except Exception as e:
            logger.warning(f"从内存提取字符串失败: {e}")
        
        return strings

    def _trace_branch(self, uc: 'unicorn.Uc', address: int, size: int, user_data: Any):
        """
        分支指令回调，记录跳转目标
        
        Args:
            uc: Unicorn 实例
            address: 当前地址
            size: 指令大小
            user_data: 用户数据
        """
        data = user_data
        data['branch_targets'].add(address)

    def _run_concrete_execution(, self)
        start_addr: int, 
        max_instructions: int = 100000,
        timeout_ms: int = 30000
    ) -> ExecutionResult:
        """
        运行具体执行
        
        Args:
            start_addr: 起始地址
            max_instructions: 最大指令数
            timeout_ms: 超时时间（毫秒）
            
        Returns:
            执行结果
        """
        if not self.uc:
            return ExecutionResult(
                success=False,
                strings_found=[],
                branch_targets=set(),
                register_values={},
                memory_snapshot={},
                error="Unicorn 不可用")
            

        
        result = ExecutionResult()
            success=False,
            strings_found=[],
            branch_targets=set(),
            register_values={},
            memory_snapshot={}
        
        
        user_data = {'branch_targets': result.branch_targets}
        
        try:
            # 设置分支跟踪
            self.uc.hook_add()
                unicorn.UC_HOOK_CODE,
                self._trace_branch,
                user_data=user_data
            
            
            start_time = time.time()
            
            # 执行
            self.uc.emu_start(start_addr, 0, count=max_instructions)
            
            end_time = time.time()
            result.execution_time_ms = int((end_time - start_time) * 1000)
            result.success = True
            
            # 提取字符串
            for region in self.memory_regions:
                if region.name == "data":
                    result.strings_found.extend(self._extract_strings_from_memory(region.start, region.end

            
            # 获取寄存器值
            if self.arch == UC_ARCH_X86_64:
                regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip']
                for reg_name in regs:
                    reg_const = getattr(unicorn.x86_const, f"UC_X86_REG_{reg_name.upper()}")
                    result.register_values[reg_name] = self.uc.reg_read(reg_const)
            
            # 去重字符串
            result.strings_found = list(set(result.strings_found

            
        except unicorn.UcError as e:
            result.error = f"Unicorn 错误: {e}"
            logger.warning(f"执行失败: {e}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"执行失败: {e}")
        
        return result

    def _analyze_complex_functions(self, symbolic_info: Dict[str, Any]) -> List[ExecutionResult]:
        """
        分析复杂函数（符号执行中难以处理的）
        
        Args:
            symbolic_info: 符号执行信息
            
        Returns:
            执行结果列表
        """
        results = []
        
        complex_funcs = symbolic_info.get('complex_functions', [])
        if not complex_funcs:
            return results
            
        logger.info(f"分析 {len(complex_funcs)} 个复杂函数")
        
        for func_addr in complex_funcs[:5]:  # 限制分析数量
            result = self._run_concrete_execution(func_addr)
            if result.success:
                results.append(result)
        
        return results

    def _extract_hidden_strings(self) -> List[str]:
        """
        提取隐藏字符串（通过执行解密循环或直接从二进制数据提取）
        
        Returns:
            解密后的字符串列表
        """
        hidden_strings = []
        
        # 直接从二进制数据中提取可打印字符串
        current_string = []
        for byte in self.binary_data:
            if 0x20 <= byte <= 0x7E:  # 可打印ASCII字符
                current_string.append(chr(byte

            else:
                if len(current_string) >= 4:  # 至少4个字符才视为有效字符串
                    hidden_strings.append(''.join(current_string

                current_string = []
        
        # 检查最后的字符串
        if len(current_string) >= 4:
            hidden_strings.append(''.join(current_string

        
        # 查找潜在的解密循环模式（简化实现）
        decrypt_patterns = [
            b'\x8a\x06',  # mov al, byte ptr [esi]
            b'\x30',      # xor
            b'\x2b',      # sub
            b'\x0f\xbe',  # movsx
        ]
        
        # 如果发现解密模式，标记需要进一步分析
        for i in range(len(self.binary_data) - 10):
            window = self.binary_data[i:i+10]
            if any(pattern in window for pattern in decrypt_patterns):
                logger.debug(f"发现潜在解密模式在偏移 0x{i:x}")
        
        return hidden_strings

    def hybrid_analysis(, self)
        symbolic_info: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        max_instructions: int = 100000
    ) -> HybridAnalysisResult:
        """
        执行混合分析
        
        Args:
            symbolic_info: 符号执行信息（可选）
            timeout: 超时时间（秒）
            max_instructions: 最大指令数
            
        Returns:
            混合分析结果
        """
        if not UNICORN_AVAILABLE:
            logger.warning("unicorn 未安装，跳过混合分析")
            return HybridAnalysisResult(
                hidden_strings=[],
                dynamic_jump_targets=set(),
                simplified_constraints=[],
                execution_time_ms=0,
                instructions_executed=0)
            

        
        logger.info("开始混合符号执行分析")
        
        start_time = time.time()
        
        # 设置内存和加载二进制
        if not self._setup_memory() or not self._load_binary():
            return HybridAnalysisResult(
                hidden_strings=[],
                dynamic_jump_targets=set(),
                simplified_constraints=[],
                execution_time_ms=0,
                instructions_executed=0)
            

        
        hidden_strings = []
        jump_targets = set()
        constraints = []
        instructions_executed = 0
        
        # 如果有符号执行信息，分析其中标记为复杂的函数
        if symbolic_info:
            exec_results = self._analyze_complex_functions(symbolic_info)
            for result in exec_results:
                hidden_strings.extend(result.strings_found)
                jump_targets.update(result.branch_targets)
                instructions_executed += max_instructions
        
        # 提取隐藏字符串
        hidden_strings.extend(self._extract_hidden_strings(

        
        # 去重
        hidden_strings = list(set(hidden_strings

        
        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)
        
        logger.info(f"混合分析完成: {len(hidden_strings)} 个隐藏字符串, {len(jump_targets)} 个跳转目标")
        
        return HybridAnalysisResult(
            hidden_strings=hidden_strings,
            dynamic_jump_targets=jump_targets,
            simplified_constraints=constraints,
            execution_time_ms=execution_time_ms,
            instructions_executed=instructions_executed)
        


    def get_available_architectures(self) -> List[str]:
        """
        获取支持的架构列表
        
        Returns:
            架构名称列表
        """
        return ['x86', 'x86_64', 'arm', 'arm64']

    def is_available(self) -> bool:
        """
        检查分析器是否可用
        
        Returns:
            是否可用
        """
        return UNICORN_AVAILABLE))))))))))))))))))))))))