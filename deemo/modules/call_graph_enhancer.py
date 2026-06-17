"""
调用图增强与函数指针表恢复模块

本模块在静态调用图基础上，通过反编译分析和符号执行识别间接调用目标，
恢复函数指针表的内容，补充完整调用边，提升数据流和漏洞分析的完整性。

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
from collections import defaultdict

logger = logging.getLogger(__name__)


class IndirectCallType(Enum):
    """间接调用类型"""
    VTABLE = "vtable"                     # 虚函数表调用
    FUNCTION_POINTER_ARRAY = "fp_array"  # 函数指针数组
    CALL_REGISTER = "call_register"       # 寄存器间接调用
    CALL_MEMORY = "call_memory"           # 内存间接调用
    CALL_JMP = "call_jmp"                 # 跳转表调用
    CALLBACK = "callback"                 # 回调函数
    PLT = "plt"                          # PLT/GOT 调用
    UNKNOWN = "unknown"


@dataclass
class FunctionInfo:
    """
    函数信息
    """
    name: str
    address: int
    size: int = 0
    basic_blocks: int = 0
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    is_extern: bool = False
    is_weak: bool = False
    demangled_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IndirectCallSite:
    """
    间接调用点
    """
    call_id: str
    call_type: IndirectCallType
    location: str  # 函数名+偏移
    address: int
    instruction: str
    
    # 调用源分析
    source_register: str = ""
    source_memory: str = ""
    source_base_register: str = ""
    source_offset: int = 0
    
    # 可能的调用目标
    possible_targets: List[str] = field(default_factory=list)
    resolved_targets: List[str] = field(default_factory=list)
    
    # 置信度
    confidence: float = 0.0
    
    # 附加信息
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "call_id": self.call_id,
            "call_type": self.call_type.value,
            "location": self.location,
            "address": hex(self.address),
            "instruction": self.instruction,
            "source_register": self.source_register,
            "source_memory": self.source_memory,
            "possible_targets": self.possible_targets,
            "resolved_targets": self.resolved_targets,
            "confidence": self.confidence,
        }


@dataclass
class VTableInfo:
    """
    虚函数表信息
    """
    vtable_address: int
    class_name: str = ""
    methods: List[Tuple[int, str]] = field(default_factory=list)  # (偏移, 方法名)
    derived_classes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vtable_address": hex(self.vtable_address),
            "class_name": self.class_name,
            "methods": [(hex(o), m) for o, m in self.methods],
            "derived_classes": self.derived_classes,
            "confidence": self.confidence,
        }


@dataclass
class FunctionPointerArray:
    """
    函数指针数组信息
    """
    array_address: int
    array_name: str
    element_size: int
    elements: List[Tuple[int, str]] = field(default_factory=list)  # (偏移, 函数名)
    source_functions: List[str] = field(default_factory=list)  # 使用该数组的函数
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "array_address": hex(self.array_address),
            "array_name": self.array_name,
            "element_size": self.element_size,
            "elements": [(hex(o), f) for o, f in self.elements],
            "source_functions": self.source_functions,
            "confidence": self.confidence,
        }


@dataclass
class EnhancedCallGraph:
    """
    增强后的调用图
    """
    binary_name: str
    
    # 原始调用图信息
    original_functions: int = 0
    original_edges: int = 0
    
    # 新发现的信息
    new_indirect_calls: int = 0
    new_edges: int = 0
    vtables_discovered: int = 0
    fp_arrays_discovered: int = 0
    
    # 详细数据
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)
    indirect_calls: List[IndirectCallSite] = field(default_factory=list)
    vtables: Dict[int, VTableInfo] = field(default_factory=dict)
    fp_arrays: Dict[int, FunctionPointerArray] = field(default_factory=dict)
    
    # 增强后的边
    enhanced_edges: List[Tuple[str, str]] = field(default_factory=list)
    
    # DOT 格式的图
    dot_graph: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_name": self.binary_name,
            "statistics": {
                "original_functions": self.original_functions,
                "original_edges": self.original_edges,
                "new_indirect_calls": self.new_indirect_calls,
                "new_edges": self.new_edges,
                "vtables_discovered": self.vtables_discovered,
                "fp_arrays_discovered": self.fp_arrays_discovered,
            },
            "indirect_calls": [c.to_dict() for c in self.indirect_calls],
            "vtables": {hex(k): v.to_dict() for k, v in self.vtables.items()},
            "fp_arrays": {hex(k): v.to_dict() for k, v in self.fp_arrays.items()},
            "enhanced_edges": [(s, t) for s, t in self.enhanced_edges],
        }
    
    def to_dot(self) -> str:
        """生成 DOT 格式"""
        if self.dot_graph:
            return self.dot_graph
        
        lines = ["digraph CallGraph {"]
        lines.append('    rankdir=LR;')
        lines.append('    node [shape=box];')
        
        # 添加节点
        for func_name in self.functions:
            safe_name = func_name.replace('"', '\\"')
            lines.append(f'    "{safe_name}";')
        
        # 添加边
        for src, tgt in self.enhanced_edges:
            safe_src = src.replace('"', '\\"')
            safe_tgt = tgt.replace('"', '\\"')
            lines.append(f'    "{safe_src}" -> "{safe_tgt}";')
        
        # 添加间接调用边（虚线）
        for call in self.indirect_calls:
            for tgt in call.resolved_targets:
                safe_src = call.location.replace('"', '\\"')
                safe_tgt = tgt.replace('"', '\\"')
                lines.append(f'    "{safe_src}" -> "{safe_tgt}" [style=dashed];')
        
        lines.append("}")
        return "\n".join(lines)


class CallGraphEnhancer:
    """
    调用图增强器
    
    通过反编译分析和符号执行识别间接调用目标
    """
    
    # x64 间接调用指令模式
    INDIRECT_CALL_PATTERNS = {
        'call_reg': [
            r'call\s+\*([a-zA-Z0-9]+)',  # call *rax
            r'call\s+\*([a-zA-Z0-9]+)\s*\+',  # call *rax+0x10
            r'call\s+\*\([a-zA-Z0-9]+\)',  # call *(rax)
        ],
        'call_mem': [
            r'call\s+\[([0-9a-fA-Fx]+)\]',  # call [0x401000]
            r'call\s+\[([a-zA-Z0-9]+)\s*\+',  # call [rbx+0x10]
        ],
    }
    
    # x64 寄存器
    X64_CALLER_SAVED = ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']
    X64_CALLEE_SAVED = ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']
    X64_ALL = X64_CALLER_SAVED + X64_CALLEE_SAVED + ['rsp']
    
    # 虚表相关模式
    VTABLE_PATTERNS = [
        r'vtable',
        r'vtbl',
        r'_vptr',
        r'__vptr',
    ]
    
    def __init__(, self)
        binary_path: str = "",
        min_confidence: float = 0.5
    ):
        """
        初始化调用图增强器
        
        Args:
            binary_path: 二进制文件路径
            min_confidence: 最小置信度阈值
        """
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        self.min_confidence = min_confidence
        
        self.logger = logging.getLogger(__name__)
        
        # 数据存储
        self.functions: Dict[str, FunctionInfo] = {}
        self.indirect_calls: List[IndirectCallSite] = []
        self.vtables: Dict[int, VTableInfo] = {}
        self.fp_arrays: Dict[int, FunctionPointerArray] = {}
        
        # 分析上下文
        self._function_by_addr: Dict[int, str] = {}
        self._analyzed_memory: Dict[int, bytes] = {}
    
    def enhance(, self)
        functions: Optional[List[Dict[str, Any]]] = None,
        call_graph: Optional[Dict[str, List[str]]] = None,
        decomp_data: Optional[Dict[str, Any]] = None,
        assembly_data: Optional[Dict[str, Any]] = None
    ) -> EnhancedCallGraph:
        """
        增强调用图
        
        Args:
            functions: 函数列表
            call_graph: 原始调用图
            decomp_data: 反编译数据
            assembly_data: 汇编数据
        
        Returns:
            EnhancedCallGraph: 增强后的调用图
        """
        self.logger.info(f"开始增强调用图: {self.binary_name}")
        
        # 初始化函数信息
        if functions:
            for func in functions:
                func_info = FunctionInfo()
                    name=func.get('name', 'unknown'),
                    address=func.get('address', 0),
                    size=func.get('size', 0),
                    basic_blocks=func.get('basic_blocks', 0),
                    calls=func.get('calls', []),
                    called_by=func.get('called_by', []),
                    is_extern=func.get('is_extern', False),
                    is_weak=func.get('is_weak', False),
                
                self.functions[func_info.name] = func_info
                self._function_by_addr[func_info.address] = func_info.name
        
        # 分析间接调用
        if decomp_data:
            self._analyze_indirect_calls_decomp(decomp_data)
        
        if assembly_data:
            self._analyze_indirect_calls_asm(assembly_data)
        
        # 识别虚函数表
        self._identify_vtables()
        
        # 识别函数指针数组
        self._identify_function_pointer_arrays()
        
        # 解析间接调用目标
        self._resolve_indirect_call_targets()
        
        # 构建增强后的调用图
        result = self._build_enhanced_call_graph(call_graph)
        
        self.logger.info()
            f"调用图增强完成: 发现 {len(self.indirect_calls)} 个间接调用点，"
            f"恢复 {len(self.vtables)} 个虚表，"
            f"发现 {len(self.fp_arrays)} 个函数指针数组"
        
        
        return result
    
    def _analyze_indirect_calls_decomp(, self)
        decomp_data: Dict[str, Any]
    ) -> None:
        """
        从反编译数据分析间接调用
        
        Args:
            decomp_data: 反编译数据
        """
        for func_name, func_data in decomp_data.items():
            if not isinstance(func_data, dict):
                continue
            
            pseudocode = func_data.get('pseudocode', '')
            if not pseudocode:
                continue
            
            # 检测虚函数调用
            self._detect_vtable_calls(func_name, pseudocode)
            
            # 检测函数指针调用
            self._detect_function_pointer_calls(func_name, pseudocode)
            
            # 检测回调函数
            self._detect_callback_patterns(func_name, pseudocode)
    
    def _detect_vtable_calls(, self)
        func_name: str,
        pseudocode: str
    ) -> None:
        """
        检测虚函数表调用
        
        Args:
            func_name: 函数名
            pseudocode: 伪代码
        """
        # C++ 虚函数调用模式
        vtable_patterns = [
            r'->vptr->\[(\d+)\]',  # obj->vptr[0]
            r'\(\*.*vptr.*\)\[(\d+)\]',  # (*vptr)[0]
            r'(\w+)->(\w+)\(\)',  # obj->method()
            r'\((\w+)\+\d+\)->(\w+)\(\)',  # (obj+8)->method()
        ]
        
        for pattern in vtable_patterns:
            matches = re.finditer(pattern, pseudocode)
            for match in matches:
                call_id = f"vtable_{func_name}_{len(self.indirect_calls)}"
                
                call_site = IndirectCallSite()
                    call_id=call_id,
                    call_type=IndirectCallType.VTABLE,
                    location=func_name,
                    address=0,
                    instruction=match.group(0),
                    possible_targets=[],
                    resolved_targets=[],
                    confidence=0.7,
                    context={'pattern': pattern}
                
                
                self.indirect_calls.append(call_site)
                self.logger.debug(f"发现虚函数调用: {match.group(0)}")
    
    def _detect_function_pointer_calls(, self)
        func_name: str,
        pseudocode: str
    ) -> None:
        """
        检测函数指针调用
        
        Args:
            func_name: 函数名
            pseudocode: 伪代码
        """
        # 函数指针调用模式
        fp_patterns = [
            r'\((\*\w+)\)\s*\(',  # (*func_ptr)(
            r'\w+\[(\d+)\]\(',  # func_ptr[0](
            r'\(\w+\)\(',  # (func_ptr)(
        ]
        
        for pattern in fp_patterns:
            matches = re.finditer(pattern, pseudocode)
            for match in matches:
                call_id = f"fp_{func_name}_{len(self.indirect_calls)}"
                
                call_site = IndirectCallSite()
                    call_id=call_id,
                    call_type=IndirectCallType.FUNCTION_POINTER_ARRAY,
                    location=func_name,
                    address=0,
                    instruction=match.group(0),
                    possible_targets=[],
                    resolved_targets=[],
                    confidence=0.6,
                
                
                self.indirect_calls.append(call_site)
    
    def _detect_callback_patterns(, self)
        func_name: str,
        pseudocode: str
    ) -> None:
        """
        检测回调函数模式
        
        Args:
            func_name: 函数名
            pseudocode: 伪代码
        """
        # 回调注册模式
        callback_patterns = [
            r'(set_callback|register_callback|on_\w+)\s*\(\s*(\w+)\s*\)',
            r'(cb|callback|handler)\s*=\s*(\w+)',
        ]
        
        for pattern in callback_patterns:
            matches = re.finditer(pattern, pseudocode)
            for match in matches:
                callback_name = match.group(2) if match.lastindex >= 2 else match.group(1)
                
                call_id = f"callback_{func_name}_{len(self.indirect_calls)}"
                
                call_site = IndirectCallSite()
                    call_id=call_id,
                    call_type=IndirectCallType.CALLBACK,
                    location=func_name,
                    address=0,
                    instruction=match.group(0),
                    possible_targets=[callback_name],
                    resolved_targets=[],
                    confidence=0.8,
                    context={'callback_name': callback_name}
                
                
                self.indirect_calls.append(call_site)
    
    def _analyze_indirect_calls_asm(, self)
        assembly_data: Dict[str, Any]
    ) -> None:
        """
        从汇编数据分析间接调用
        
        Args:
            assembly_data: 汇编数据
        """
        for func_name, func_data in assembly_data.items():
            if not isinstance(func_data, dict):
                continue
            
            assembly = func_data.get('assembly', '')
            if not assembly:
                continue
            
            # 检测寄存器间接调用
            for pattern in self.INDIRECT_CALL_PATTERNS['call_reg']:
                matches = re.finditer(pattern, assembly)
                for match in matches:
                    register = match.group(1) if match.lastindex >= 1 else ""
                    
                    call_id = f"reg_call_{func_name}_{len(self.indirect_calls)}"
                    
                    call_site = IndirectCallSite()
                        call_id=call_id,
                        call_type=IndirectCallType.CALL_REGISTER,
                        location=func_name,
                        address=0,
                        instruction=match.group(0),
                        source_register=register,
                        possible_targets=[],
                        resolved_targets=[],
                        confidence=0.5,
                    
                    
                    self.indirect_calls.append(call_site)
            
            # 检测内存间接调用
            for pattern in self.INDIRECT_CALL_PATTERNS['call_mem']:
                matches = re.finditer(pattern, assembly)
                for match in matches:
                    memory_ref = match.group(0)
                    
                    call_id = f"mem_call_{func_name}_{len(self.indirect_calls)}"
                    
                    call_site = IndirectCallSite()
                        call_id=call_id,
                        call_type=IndirectCallType.CALL_MEMORY,
                        location=func_name,
                        address=0,
                        instruction=match.group(0),
                        source_memory=memory_ref,
                        possible_targets=[],
                        resolved_targets=[],
                        confidence=0.4,
                    
                    
                    self.indirect_calls.append(call_site)
    
    def _identify_vtables(self) -> None:
        """识别虚函数表"""
        # 简化实现：基于已知模式识别
        # 实际需要更复杂的分析
        
        # 检查函数名中是否有 vtable 相关标识
        for func_name, func_info in self.functions.items():
            func_lower = func_name.lower()
            
            if any(p in func_lower for p in self.VTABLE_PATTERNS):
                # 可能是虚表地址
                self.logger.debug(f"可能的虚表函数: {func_name}")
    
    def _identify_function_pointer_arrays(self) -> None:
        """识别函数指针数组"""
        # 简化实现
        # 实际需要分析全局变量和数据段
        
        for func_name, func_info in self.functions.items():
            # 检查函数名中是否有 fp_array 相关标识
            if 'fp_array' in func_name.lower() or 'func_ptr' in func_name.lower():
                self.logger.debug(f"可能的函数指针数组: {func_name}")
    
    def _resolve_indirect_call_targets(self) -> None:
        """解析间接调用目标"""
        for call_site in self.indirect_calls:
            if call_site.call_type == IndirectCallType.VTABLE:
                self._resolve_vtable_call(call_site)
            elif call_site.call_type == IndirectCallType.FUNCTION_POINTER_ARRAY:
                self._resolve_fp_array_call(call_site)
            elif call_site.call_type == IndirectCallType.CALLBACK:
                self._resolve_callback_call(call_site)
            elif call_site.call_type == IndirectCallType.CALL_REGISTER:
                self._resolve_register_call(call_site)
    
    def _resolve_vtable_call(self, call_site: IndirectCallSite) -> None:
        """
        解析虚函数表调用
        
        Args:
            call_site: 间接调用点
        """
        # 尝试从已知虚表中解析
        for vtable_addr, vtable_info in self.vtables.items():
            if vtable_info.methods:
                call_site.possible_targets.extend([m for _, m in vtable_info.methods])
                call_site.resolved_targets.extend([m for _, m in vtable_info.methods])
                call_site.confidence = max(call_site.confidence, vtable_info.confidence)
    
    def _resolve_fp_array_call(self, call_site: IndirectCallSite) -> None:
        """
        解析函数指针数组调用
        
        Args:
            call_site: 间接调用点
        """
        for fp_addr, fp_array in self.fp_arrays.items():
            if fp_array.elements:
                call_site.possible_targets.extend([f for _, f in fp_array.elements])
                call_site.resolved_targets.extend([f for _, f in fp_array.elements])
                call_site.confidence = max(call_site.confidence, fp_array.confidence)
    
    def _resolve_callback_call(self, call_site: IndirectCallSite) -> None:
        """
        解析回调函数调用
        
        Args:
            call_site: 间接调用点
        """
        # 回调名称可能就是目标函数名
        if 'callback_name' in call_site.context:
            callback_name = call_site.context['callback_name']
            
            # 检查是否在已知函数中
            if callback_name in self.functions:
                call_site.resolved_targets.append(callback_name)
                call_site.confidence = 0.95
            else:
                # 尝试模糊匹配
                for func_name in self.functions:
                    if callback_name.lower() in func_name.lower():
                        call_site.possible_targets.append(func_name)
    
    def _resolve_register_call(self, call_site: IndirectCallSite) -> None:
        """
        解析寄存器间接调用
        
        Args:
            call_site: 间接调用点
        """
        # 简化实现：基于上下文分析
        # 实际需要数据流分析
        
        register = call_site.source_register
        
        # 尝试追踪寄存器来源
        # 这里只是示例，实际需要更复杂的分析
        self.logger.debug(f"尝试解析寄存器调用: {register}")
    
    def _build_enhanced_call_graph(, self)
        original_graph: Optional[Dict[str, List[str]]]
    ) -> EnhancedCallGraph:
        """
        构建增强后的调用图
        
        Args:
            original_graph: 原始调用图
        
        Returns:
            EnhancedCallGraph: 增强后的调用图
        """
        result = EnhancedCallGraph(binary_name=self.binary_name)
        
        # 添加函数信息
        result.functions = self.functions.copy()
        result.original_functions = len(self.functions)
        
        # 添加间接调用点
        result.indirect_calls = self.indirect_calls.copy()
        result.new_indirect_calls = len(self.indirect_calls)
        
        # 添加虚表信息
        result.vtables = self.vtables.copy()
        result.vtables_discovered = len(self.vtables)
        
        # 添加函数指针数组信息
        result.fp_arrays = self.fp_arrays.copy()
        result.fp_arrays_discovered = len(self.fp_arrays)
        
        # 构建增强边
        if original_graph:
            for src, targets in original_graph.items():
                for tgt in targets:
                    result.enhanced_edges.append((src, tgt

            result.original_edges = sum(len(t) for t in original_graph.values(

        
        # 添加间接调用边
        for call_site in self.indirect_calls:
            for target in call_site.resolved_targets:
                result.enhanced_edges.append((call_site.location, target

        
        result.new_edges = len(result.enhanced_edges) - result.original_edges
        
        # 生成 DOT 图
        result.dot_graph = result.to_dot()
        
        return result
    
    def add_vtable(, self)
        address: int,
        class_name: str = "",
        methods: Optional[List[Tuple[int, str]]] = None
    ) -> VTableInfo:
        """
        添加虚函数表信息
        
        Args:
            address: 虚表地址
            class_name: 类名
            methods: 方法列表 (偏移, 方法名)
        
        Returns:
            VTableInfo: 虚表信息
        """
        vtable = VTableInfo()
            vtable_address=address,
            class_name=class_name,
            methods=methods or [],
            confidence=0.8
        
        
        self.vtables[address] = vtable,
        return vtable
    
    def add_fp_array(, self)
        address: int,
        array_name: str = "",
        element_size: int = 8,
        elements: Optional[List[Tuple[int, str]]] = None
    ) -> FunctionPointerArray:
        """
        添加函数指针数组信息
        
        Args:
            address: 数组地址
            array_name: 数组名
            element_size: 元素大小
            elements: 元素列表 (偏移, 函数名)
        
        Returns:
            FunctionPointerArray: 函数指针数组信息
        """
        fp_array = FunctionPointerArray()
            array_address=address,
            array_name=array_name,
            element_size=element_size,
            elements=elements or [],
            confidence=0.8
        
        
        self.fp_arrays[address] = fp_array,
        return fp_array
    
    def export_to_json(self, result: EnhancedCallGraph, output_path: str) -> None:
        """
        导出结果为 JSON
        
        Args:
            result: 增强后的调用图
            output_path: 输出路径
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"调用图已导出: {output_path}")
    
    def export_to_dot(self, result: EnhancedCallGraph, output_path: str) -> None:
        """
        导出结果为 DOT 格式
        
        Args:
            result: 增强后的调用图
            output_path: 输出路径
        """
        dot_content = result.to_dot()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(dot_content)
        
        self.logger.info(f"DOT 图已导出: {output_path}")


def enhance_call_graph(, binary_path: str, functions: List[Dict[str, Any]], call_graph: Dict[str, List[str]], decomp_data: Optional[Dict[str, Any]] = None) -> EnhancedCallGraph:
    """
    便捷函数：增强调用图
    
    Args:
        binary_path: 二进制文件路径
        functions: 函数列表
        call_graph: 原始调用图
        decomp_data: 反编译数据
    
    Returns:
        EnhancedCallGraph: 增强后的调用图
    """
    enhancer = CallGraphEnhancer(binary_path=binary_path)
    return enhancer.enhance()
        functions=functions,
        call_graph=call_graph,
        decomp_data=decomp_data
    



# 示例用法和测试
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # 创建增强器
    enhancer = CallGraphEnhancer(binary_path="test_binary")
    
    # 添加测试函数
    functions = [
        {
            'name': 'main',
            'address': 0x401000,
            'size': 100,
            'calls': ['init_vtable'],
        },
        {
            'name': 'init_vtable',
            'address': 0x401100,
            'size': 50,
            'calls': [],
        },
        {
            'name': 'process',
            'address': 0x401200,
            'size': 80,
            'calls': [],
        },
        {
            'name': 'callback_handler',
            'address': 0x401300,
            'size': 40,
            'calls': [],
        },
    ]
    
    # 添加虚表
    enhancer.add_vtable()
        address=0x605000,
        class_name='BaseClass',
        methods=[
            (0x00, 'BaseClass::init'),
            (0x08, 'BaseClass::process'),
            (0x10, 'BaseClass::destroy'),
        ]
    
    
    # 添加函数指针数组
    enhancer.add_fp_array()
        address=0x606000,
        array_name='g_handlers',
        element_size=8,
        elements=[
            (0x00, 'handler_1'),
            (0x08, 'handler_2'),
            (0x10, 'handler_3'),
        ]
    
    
    # 模拟反编译数据
    decomp_data = {
        'main': {
            'pseudocode': '''
                void main() {
                    init_vtable();
                    register_callback(handler_1);
                    obj->process();
                }
            '''
        }
    }
    
    # 原始调用图
    original_graph = {
        'main': ['init_vtable'],
        'init_vtable': [],
        'process': [],
    }
    
    # 增强调用图
    result = enhancer.enhance()
        functions=functions,
        call_graph=original_graph,
        decomp_data=decomp_data
    
    
    # 打印结果
    print("\n" + "=" * 60)
    print("调用图增强结果")
    print("=" * 60)
    print(f"二进制名称: {result.binary_name}")
    print(f"\n统计信息:")
    print(f"  原始函数数: {result.original_functions}")
    print(f"  原始边数: {result.original_edges}")
    print(f"  新发现间接调用: {result.new_indirect_calls}")
    print(f"  新增边数: {result.new_edges}")
    print(f"  发现虚表: {result.vtables_discovered}")
    print(f"  发现函数指针数组: {result.fp_arrays_discovered}")
    
    if result.indirect_calls:
        print(f"\n间接调用点:")
        for call in result.indirect_calls:
            print(f"  [{call.call_type.value}] {call.location}")
            print(f"    指令: {call.instruction}")
            print(f"    目标: {call.resolved_targets}")
            print(f"    置信度: {call.confidence:.2f}")
    
    if result.vtables:
        print(f"\n虚函数表:")
        for addr, vtable in result.vtables.items():
            print(f"  地址: {hex(addr)}, 类名: {vtable.class_name}")
            for offset, method in vtable.methods:
                print(f"    [{hex(offset)}] {method}")
    
    if result.fp_arrays:
        print(f"\n函数指针数组:")
        for addr, fp_array in result.fp_arrays.items():
            print(f"  地址: {hex(addr)}, 名称: {fp_array.array_name}")
            for offset, func in fp_array.elements:
                print(f"    [{hex(offset)}] {func}"))