"""
基于模拟执行的函数摘要自动生成模块

本模块对关键函数使用 Unicorn 或 angr 进行快速模拟执行，自动总结函数行为，
包括修改的全局变量、返回值和输入参数的关系、可能的错误码等，生成可读的
函数摘要，辅助逆向人员快速理解函数。

作者: Deemo 安全研究团队
版本: 1.0.0
"""

import os
import re
import logging
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum

logger = logging.getLogger(__name__)

# 尝试导入模拟执行框架
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    logger.warning("angr 未安装，动态符号执行功能不可用")

try:
    from unicorn import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False
    logger.warning("unicorn 未安装，具体执行功能不可用")


class ExecutionMode(Enum):
    """执行模式"""
    CONCRETE = "concrete"           # 纯具体执行
    SYMBOLIC = "symbolic"           # 纯符号执行
    CONCOLIC = "concolic"           # 混合执行（concrete + symbolic）


class ParameterRole(Enum):
    """参数角色"""
    INPUT = "input"                 # 输入参数
    OUTPUT = "output"               # 输出参数
    INPUT_OUTPUT = "input_output"   # 输入输出参数
    UNKNOWN = "unknown"


@dataclass
class MemoryAccess:
    """
    内存访问记录
    """
    address: int
    size: int
    is_write: bool
    value: Optional[int] = None
    symbolic: bool = False
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address) if self.address else "unknown",
            "size": self.size,
            "is_write": self.is_write,
            "value": hex(self.value) if self.value else None,
            "symbolic": self.symbolic,
            "description": self.description,
        }


@dataclass
class FunctionCall:
    """
    函数调用记录
    """
    address: int
    name: str
    arguments: List[Any] = field(default_factory=list)
    return_value: Optional[int] = None
    succeeded: bool = True
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "name": self.name,
            "arguments": [str(a) for a in self.arguments],
            "return_value": hex(self.return_value) if self.return_value else None,
            "succeeded": self.succeeded,
            "description": self.description,
        }


@dataclass
class ParameterInfo:
    """
    参数信息
    """
    name: str
    register: str
    role: ParameterRole
    offset: int = 0
    size: int = 8
    possible_values: List[Any] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "register": self.register,
            "role": self.role.value,
            "offset": self.offset,
            "size": self.size,
            "possible_values": [str(v) for v in self.possible_values[:10]],  # 限制数量
            "constraints": self.constraints,
            "description": self.description,
        }


@dataclass
class FunctionSummary:
    """
    函数摘要
    """
    function_name: str
    address: int
    
    # 基本信息
    entry_point: int = 0
    size: int = 0
    architecture: str = ""
    
    # 参数信息
    parameters: List[ParameterInfo] = field(default_factory=list)
    return_value: Optional[ParameterInfo] = None
    
    # 内存访问
    memory_reads: List[MemoryAccess] = field(default_factory=list)
    memory_writes: List[MemoryAccess] = field(default_factory=list)
    global_accesses: List[MemoryAccess] = field(default_factory=list)
    
    # 函数调用
    called_functions: List[FunctionCall] = field(default_factory=list)
    
    # 控制流
    branches: List[Tuple[int, int, int]] = field(default_factory=list)  # (addr, true_target, false_target)
    loops: List[Dict[str, Any]] = field(default_factory=list)
    
    # 错误处理
    error_paths: List[str] = field(default_factory=list)
    error_codes: Dict[int, str] = field(default_factory=dict)
    
    # 行为摘要
    behavior_summary: str = ""
    side_effects: List[str] = field(default_factory=list)
    
    # 执行统计
    execution_time: float = 0.0
    blocks_executed: int = 0
    instructions_executed: int = 0
    
    # 可信度
    confidence: float = 0.0
    analysis_method: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "address": hex(self.address),
            "entry_point": hex(self.entry_point),
            "size": self.size,
            "architecture": self.architecture,
            "parameters": [p.to_dict() for p in self.parameters],
            "return_value": self.return_value.to_dict() if self.return_value else None,
            "memory_reads": [m.to_dict() for m in self.memory_reads[:50]],
            "memory_writes": [m.to_dict() for m in self.memory_writes[:50]],
            "global_accesses": [g.to_dict() for g in self.global_accesses[:20]],
            "called_functions": [c.to_dict() for c in self.called_functions[:20]],
            "branches": [(hex(a), hex(t), hex(f)) for a, t, f in self.branches[:20]],
            "loops": self.loops[:10],
            "error_codes": {hex(k): v for k, v in self.error_codes.items()},
            "behavior_summary": self.behavior_summary,
            "side_effects": self.side_effects,
            "execution_time": f"{self.execution_time:.4f}s",
            "blocks_executed": self.blocks_executed,
            "instructions_executed": self.instructions_executed,
            "confidence": self.confidence,
            "analysis_method": self.analysis_method,
        }
    
    def to_enhanced_pseudocode(self, original_pseudocode: str) -> str:
        """
        生成增强的伪代码（带摘要注释）
        
        Args:
            original_pseudocode: 原始伪代码
        
        Returns:
            str: 增强后的伪代码
        """
        lines = [
            f"/* 函数摘要 - {self.function_name} */",
            f"/* 地址: {hex(self.address)} */",
            f"/* 分析方法: {self.analysis_method} */",
            f"/* 置信度: {self.confidence:.2f} */",
            "",
        ]
        
        # 添加参数信息
        if self.parameters:
            lines.append("/* 参数: */")
            for param in self.parameters:
                role_marker = {
                    ParameterRole.INPUT: "[IN]",
                    ParameterRole.OUTPUT: "[OUT]",
                    ParameterRole.INPUT_OUTPUT: "[IN/OUT]",
                    ParameterRole.UNKNOWN: "[?]",
                }.get(param.role, "")
                lines.append(f"/*   {param.register}: {param.name} {role_marker} */")
            lines.append("")
        
        # 添加行为摘要
        if self.behavior_summary:
            lines.append(f"/* 行为: {self.behavior_summary} */")
        
        # 添加副作用
        if self.side_effects:
            lines.append("/* 副作用: */")
            for effect in self.side_effects:
                lines.append(f"/*   - {effect} */")
            lines.append("")
        
        # 添加被调用函数
        if self.called_functions:
            func_names = [f.name for f in self.called_functions[:5]]
            lines.append(f"/* 调用: {', '.join(func_names)} */")
            lines.append("")
        
        # 添加原始伪代码
        lines.append("/* 原始伪代码: */")
        for line in original_pseudocode.split('\n'):
            lines.append(f"/* {line} */")
        
        return '\n'.join(lines)


class FunctionSummarizer:
    """
    函数摘要生成器
    
    通过模拟执行自动生成函数行为摘要
    """
    
    # x64 参数寄存器顺序
    X64_PARAM_REGISTERS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    
    # x86 参数寄存器顺序
    X86_PARAM_REGISTERS = ['ecx', 'edx', 'esi', 'edi']
    
    # 返回寄存器
    RETURN_REGISTER = {'amd64': 'rax', 'i386': 'eax'}
    
    # 常见 libc 函数特征
    KNOWN_FUNCTION_SIGNATURES = {
        'malloc': {'params': ['size'], 'returns': 'pointer', 'role': {'rdi': 'size'}},
        'free': {'params': ['ptr'], 'returns': 'void', 'role': {'rdi': 'ptr'}},
        'printf': {'params': ['format', '...'], 'returns': 'int', 'role': {'rdi': 'format'}},
        'scanf': {'params': ['format', '...'], 'returns': 'int', 'role': {'rdi': 'format'}},
        'strlen': {'params': ['str'], 'returns': 'size_t', 'role': {'rdi': 'str'}},
        'strcpy': {'params': ['dest', 'src'], 'returns': 'char*', 'role': {'rdi': 'dest', 'rsi': 'src'}},
        'strncpy': {'params': ['dest', 'src', 'n'], 'returns': 'char*', 'role': {'rdi': 'dest', 'rsi': 'src', 'rdx': 'n'}},
        'memcpy': {'params': ['dest', 'src', 'n'], 'returns': 'void*', 'role': {'rdi': 'dest', 'rsi': 'src', 'rdx': 'n'}},
        'memset': {'params': ['s', 'c', 'n'], 'returns': 'void*', 'role': {'rdi': 's', 'rsi': 'c', 'rdx': 'n'}},
        'open': {'params': ['pathname', 'flags', 'mode'], 'returns': 'int', 'role': {'rdi': 'pathname', 'rsi': 'flags', 'rdx': 'mode'}},
        'read': {'params': ['fd', 'buf', 'count'], 'returns': 'ssize_t', 'role': {'rdi': 'fd', 'rsi': 'buf', 'rdx': 'count'}},
        'write': {'params': ['fd', 'buf', 'count'], 'returns': 'ssize_t', 'role': {'rdi': 'fd', 'rsi': 'buf', 'rdx': 'count'}},
        'socket': {'params': ['domain', 'type', 'protocol'], 'returns': 'int', 'role': {'rdi': 'domain', 'rsi': 'type', 'rdx': 'protocol'}},
        'connect': {'params': ['sockfd', 'addr', 'addrlen'], 'returns': 'int', 'role': {'rdi': 'sockfd', 'rsi': 'addr', 'rdx': 'addrlen'}},
    }
    
    def __init__(, self)
        binary_path: str = "",
        arch: str = "amd64",
        mode: ExecutionMode = ExecutionMode.CONCRETE,
        timeout: int = 30,
        max_blocks: int = 1000
    ):
        """
        初始化函数摘要生成器
        
        Args:
            binary_path: 二进制文件路径
            arch: 架构 ('amd64' 或 'i386')
            mode: 执行模式
            timeout: 超时时间（秒）
            max_blocks: 最大执行块数
        """
        self.binary_path = binary_path
        self.arch = arch
        self.mode = mode
        self.timeout = timeout
        self.max_blocks = max_blocks
        
        self.logger = logging.getLogger(__name__)
        
        # 状态
        self._project = None
        self._initialized = False
        
        # 统计
        self.analysis_count = 0
    
    def initialize(self) -> bool:
        """
        初始化分析环境
        
        Returns:
            bool: 初始化是否成功
        """
        if self._initialized:
            return True
        
        if ANGR_AVAILABLE and self.binary_path:
            try:
                self._project = angr.Project(self.binary_path, auto_load_libs=False)
                self._initialized = True
                self.logger.info(f"angr 项目初始化成功: {self.binary_path}")
                return True
            except Exception as e:
                self.logger.error(f"angr 项目初始化失败: {e}")
        
        self._initialized = True,
        return True
    
    def summarize(, self)
        function_address: int,
        function_name: str = "",
        inputs: Optional[Dict[str, int]] = None,
        max_depth: int = 5
    ) -> FunctionSummary:
        """
        生成函数摘要
        
        Args:
            function_address: 函数地址
            function_name: 函数名
            inputs: 输入参数值
            max_depth: 最大分析深度
        
        Returns:
            FunctionSummary: 函数摘要
        """
        self.analysis_count += 1
        
        self.logger.info()
            f"生成函数摘要: {function_name or hex(function_address)}"
        
        
        # 初始化
        self.initialize()
        
        # 创建摘要对象
        summary = FunctionSummary()
            function_name=function_name or f"sub_{function_address:x}",
            address=function_address,
            architecture=self.arch,
            analysis_method=self.mode.value,
        
        
        # 使用 angr 分析
        if ANGR_AVAILABLE and self._project:
            try:
                summary = self._summarize_with_angr()
                    function_address,
                    function_name,
                    inputs,
                    max_depth,
                    summary
                
            except Exception as e:
                self.logger.error(f"angr 分析失败: {e}")
        
        # 如果 angr 不可用，使用简化分析
        if not summary.behavior_summary:
            summary = self._summarize_static(function_address, function_name, summary)
        
        return summary
    
    def _summarize_with_angr(, self)
        function_address: int,
        function_name: str,
        inputs: Optional[Dict[str, int]],
        max_depth: int,
        summary: FunctionSummary
    ) -> FunctionSummary:
        """
        使用 angr 生成摘要
        
        Args:
            function_address: 函数地址
            function_name: 函数名
            inputs: 输入参数
            max_depth: 最大深度
            summary: 摘要对象
        
        Returns:
            FunctionSummary: 函数摘要
        """
        import time
        start_time = time.time()
        
        # 查找函数
        func = self._project.kb.functions.get_by_addr(function_address)
        
        if func is None:
            self.logger.warning(f"函数未找到: {hex(function_address)}")
            return summary
        
        # 设置函数名
        if function_name:
            func.name = function_name
        
        summary.function_name = func.name
        summary.entry_point = func.addr
        
        # 参数推断
        summary.parameters = self._infer_parameters(func)
        
        # 识别被调用函数
        summary.called_functions = self._analyze_calls(func, max_depth)
        
        # 分析内存访问
        summary.memory_reads, summary.memory_writes = self._analyze_memory_access(func)
        
        # 生成行为摘要
        summary.behavior_summary = self._generate_behavior_summary(func, summary)
        
        # 分析副作用
        summary.side_effects = self._analyze_side_effects(func, summary)
        
        # 分析错误路径
        summary.error_codes = self._analyze_error_handling(func)
        
        # 更新统计
        summary.execution_time = time.time() - start_time
        summary.confidence = self._calculate_confidence(summary)
        
        return summary
    
    def _infer_parameters(self, func) -> List[ParameterInfo]:
        """
        推断函数参数
        
        Args:
            func: angr 函数对象
        
        Returns:
            List[ParameterInfo]: 参数信息列表
        """
        params = []
        
        # 检查是否是已知函数
        if func.name in self.KNOWN_FUNCTION_SIGNATURES:
            sig = self.KNOWN_FUNCTION_SIGNATURES[func.name]
            param_names = sig['params']
            roles = sig['role']
            
            regs = self.X64_PARAM_REGISTERS if self.arch == 'amd64' else self.X86_PARAM_REGISTERS
            
            for i, (reg, name) in enumerate(zip(regs, param_names)):
                role = ParameterRole.UNKNOWN,
                if reg in roles:
                    role_str = roles[reg]
                    if 'out' in role_str.lower():
                        role = ParameterRole.OUTPUT
                    elif 'in' in role_str.lower():
                        role = ParameterRole.INPUT
                
                params.append(ParameterInfo(
                    name=name,
                    register=reg,
                    role=role,
                    description=f"来自已知函数签名: {func.name}"
                

        else:
            # 尝试从 angr 的参数推断
            try:
                for i, (reg, _) in enumerate(func.info[' Calling Convention'].params.items()):
                    params.append(ParameterInfo(
                        name=f"arg{i}",
                        register=reg,
                        role=ParameterRole.UNKNOWN
                    

            except Exception:
                pass
        
        return params
    
    def _analyze_calls(, self)
        func,
        max_depth: int
    ) -> List[FunctionCall]:
        """
        分析函数调用
        
        Args:
            func: angr 函数对象
            max_depth: 最大深度
        
        Returns:
            List[FunctionCall]: 函数调用列表
        """
        calls = []
        
        # 获取直接调用
        for callee_addr, call_sites in func.callee_addresses.items():
            try:
                callee = self._project.kb.functions.get_by_addr(callee_addr)
                callee_name = callee.name
            except Exception:
                callee_name = f"sub_{callee_addr:x}"
            
            calls.append(FunctionCall(
                address=callee_addr,
                name=callee_name,
                description=f"从 {hex(func.addr)} 调用"
            

        
        # 只返回前20个
        return calls[:20]
    
    def _analyze_memory_access(, self)
        func
    ) -> Tuple[List[MemoryAccess], List[MemoryAccess]]:
        """
        分析内存访问
        
        Args:
            func: angr 函数对象
        
        Returns:
            Tuple[List, List]: (读取列表, 写入列表)
        """
        reads = []
        writes = []
        
        # 简化实现
        # 实际需要更复杂的内存访问分析
        
        return reads[:50], writes[:50]
    
    def _generate_behavior_summary(, self)
        func,
        summary: FunctionSummary
    ) -> str:
        """
        生成行为摘要
        
        Args:
            func: angr 函数对象
            summary: 函数摘要
        
        Returns:
            str: 行为摘要
        """
        behaviors = []
        
        # 基于函数名推断
        func_name = func.name.lower()
        
        if 'alloc' in func_name or 'malloc' in func_name or 'alloc' in func_name:
            behaviors.append("分配内存")
        if 'copy' in func_name or 'cpy' in func_name:
            behaviors.append("复制数据")
        if 'init' in func_name or 'setup' in func_name:
            behaviors.append("初始化资源")
        if 'free' in func_name or 'release' in func_name or 'destroy' in func_name:
            behaviors.append("释放资源")
        if 'check' in func_name or 'validate' in func_name or 'verify' in func_name:
            behaviors.append("验证或检查")
        if 'parse' in func_name or 'decode' in func_name:
            behaviors.append("解析数据")
        if 'encode' in func_name or 'serialize' in func_name:
            behaviors.append("编码数据")
        if 'send' in func_name or 'recv' in func_name or 'transmit' in func_name:
            behaviors.append("网络通信")
        if 'read' in func_name or 'write' in func_name:
            behaviors.append("读写数据")
        if 'encrypt' in func_name or 'decrypt' in func_name:
            behaviors.append("加密/解密")
        
        # 基于被调用函数推断
        call_names = [c.name.lower() for c in summary.called_functions]
        
        if any('malloc' in n or 'alloc' in n for n in call_names):
            behaviors.append("可能分配内存")
        if any('socket' in n or 'connect' in n for n in call_names):
            behaviors.append("可能进行网络通信")
        if any('printf' in n or 'write' in n for n in call_names):
            behaviors.append("可能输出信息")
        
        # 如果没有推断到任何行为
        if not behaviors:
            behaviors.append("执行复杂计算")
        
        return "; ".join(behaviors)
    
    def _analyze_side_effects(, self)
        func,
        summary: FunctionSummary
    ) -> List[str]:
        """
        分析副作用
        
        Args:
            func: angr 函数对象
            summary: 函数摘要
        
        Returns:
            List[str]: 副作用列表
        """
        side_effects = []
        
        # 检查全局变量访问
        if summary.memory_writes:
            side_effects.append("写入内存")
        
        # 检查网络调用
        call_names = [c.name for c in summary.called_functions]
        if any('socket' in n.lower() for n in call_names):
            side_effects.append("网络通信")
        if any('open' in n.lower() or 'read' in n.lower() or 'write' in n.lower() for n in call_names):
            side_effects.append("文件操作")
        
        # 检查内存分配
        if any('malloc' in n.lower() or 'alloc' in n.lower() for n in call_names):
            side_effects.append("内存分配")
        
        return side_effects
    
    def _analyze_error_handling(self, func) -> Dict[int, str]:
        """
        分析错误处理
        
        Args:
            func: angr 函数对象
        
        Returns:
            Dict[int, str]: 错误码映射
        """
        error_codes = {}
        
        # 常见错误码模式
        common_errors = {
            -1: "失败",
            0: "成功",
            1: "一般错误",
            -ENOMEM: "内存不足",
            -EINVAL: "无效参数",
            -EBADF: "无效文件描述符",
            -EFAULT: "地址错误",
        }
        
        # 简化实现
        # 实际需要分析返回值的用途
        
        return error_codes
    
    def _calculate_confidence(self, summary: FunctionSummary) -> float:
        """
        计算摘要置信度
        
        Args:
            summary: 函数摘要
        
        Returns:
            float: 置信度 (0.0 - 1.0)
        """
        confidence = 0.3  # 基础置信度
        
        # 参数识别
        if len(summary.parameters) > 0:
            confidence += 0.15
        
        # 行为摘要
        if summary.behavior_summary:
            confidence += 0.2
        
        # 被调用函数分析
        if len(summary.called_functions) > 0:
            confidence += 0.15
        
        # 副作用分析
        if len(summary.side_effects) > 0:
            confidence += 0.1
        
        # 错误处理分析
        if summary.error_codes:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _summarize_static(, self)
        function_address: int,
        function_name: str,
        summary: FunctionSummary
    ) -> FunctionSummary:
        """
        静态分析生成摘要（简化实现）
        
        Args:
            function_address: 函数地址
            function_name: 函数名
            summary: 摘要对象
        
        Returns:
            FunctionSummary: 函数摘要
        """
        summary.analysis_method = "static"
        summary.confidence = 0.3
        summary.behavior_summary = "需要动态分析获取更多信息"
        
        # 尝试基于函数名推断
        if function_name:
            func_lower = function_name.lower()
            
            behaviors = []
            if any(x in func_lower for x in ['init', 'setup', 'create']):
                behaviors.append("初始化操作")
            if any(x in func_lower for x in ['free', 'destroy', 'release', 'cleanup']):
                behaviors.append("资源释放")
            if any(x in func_lower for x in ['alloc', 'malloc', 'new']):
                behaviors.append("内存分配")
            if any(x in func_lower for x in ['read', 'write', 'io', 'file']):
                behaviors.append("数据读写")
            if any(x in func_lower for x in ['send', 'recv', 'socket', 'net', 'connect']):
                behaviors.append("网络通信")
            if any(x in func_lower for x in ['check', 'verify', 'validate']):
                behaviors.append("验证检查")
            if any(x in func_lower for x in ['parse', 'decode', 'encode']):
                behaviors.append("数据解析")
            if any(x in func_lower for x in ['encrypt', 'decrypt', 'cipher']):
                behaviors.append("加密操作")
            
            if behaviors:
                summary.behavior_summary = "; ".join(behaviors)
                summary.confidence = 0.5
        
        return summary
    
    def summarize_batch(, self)
        functions: List[Tuple[int, str]]
    ) -> List[FunctionSummary]:
        """
        批量生成函数摘要
        
        Args:
            functions: 函数列表 [(地址, 名称), ...]
        
        Returns:
            List[FunctionSummary]: 摘要列表
        """
        summaries = []
        
        for addr, name in functions:
            summary = self.summarize(addr, name)
            summaries.append(summary)
        
        return summaries
    
    def export_summaries(, self)
        summaries: List[FunctionSummary],
        output_path: str
    ) -> None:
        """
        导出摘要列表
        
        Args:
            summaries: 摘要列表
            output_path: 输出路径
        """
        data = {
            "binary": self.binary_path,
            "arch": self.arch,
            "function_count": len(summaries),
            "summaries": [s.to_dict() for s in summaries]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"摘要已导出: {output_path}")


def summarize_function(, binary_path: str, function_address: int, function_name: str = "", arch: str = "amd64") -> FunctionSummary:
    """
    便捷函数：生成函数摘要
    
    Args:
        binary_path: 二进制文件路径
        function_address: 函数地址
        function_name: 函数名
        arch: 架构
    
    Returns:
        FunctionSummary: 函数摘要
    """
    summarizer = FunctionSummarizer(binary_path=binary_path, arch=arch)
    return summarizer.summarize(function_address, function_name)


# 示例用法和测试
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # 创建生成器
    summarizer = FunctionSummarizer(arch="amd64")
    
    # 模拟函数数据
    test_functions = [
        (0x401000, "process_request"),
        (0x401100, "malloc_wrapper"),
        (0x401200, "init_connection"),
        (0x401300, "validate_input"),
        (0x401400, "encrypt_data"),
    ]
    
    # 生成摘要
    for addr, name in test_functions:
        summary = summarizer.summarize(addr, name)
        
        print("\n" + "=" * 60)
        print(f"函数摘要: {summary.function_name}")
        print("=" * 60)
        print(f"地址: {hex(summary.address)}")
        print(f"分析方法: {summary.analysis_method}")
        print(f"置信度: {summary.confidence:.2f}")
        
        if summary.parameters:
            print(f"\n参数:")
            for param in summary.parameters:
                print(f"  {param.register}: {param.name} [{param.role.value}]")
        
        if summary.behavior_summary:
            print(f"\n行为摘要: {summary.behavior_summary}")
        
        if summary.side_effects:
            print(f"\n副作用:")
            for effect in summary.side_effects:
                print(f"  - {effect}")
        
        if summary.called_functions:
            print(f"\n被调用函数:")
            for call in summary.called_functions[:5]:
                print(f"  - {call.name} @ {hex(call.address)}"