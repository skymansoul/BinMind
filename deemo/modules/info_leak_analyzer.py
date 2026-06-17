"""
自动化信息泄露发现与量化评估模块

本模块专门针对格式化字符串漏洞和内存信息泄露进行检测和量化评估，
自动评估二进制中存在的泄露原语，量化可泄露的字节数、泄露数据的类型，
并生成泄露利用片段，为后续ASLR/KASLR绕过提供精确支持。

作者: Deemo 安全研究团队
版本: 1.0.0
"""

import os
import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)


class LeakType(Enum):
    """信息泄露类型枚举"""
    FORMAT_STRING = "format_string"           # 格式化字符串漏洞
    STACK_OVERFLOW_READ = "stack_overflow_read"   # 栈越界读
    HEAP_OVERFLOW_READ = "heap_overflow_read"     # 堆越界读
    USE_AFTER_FREE_READ = "uaf_read"             # 释放后使用读
    INTEGER_OVERFLOW_READ = "int_overflow_read"   # 整数溢出导致越界读
    OFF_BY_ONE_READ = "off_by_one_read"          # 单字节越界读
    UNINITIALIZED_READ = "uninit_read"            # 未初始化变量读
    BUFFER_OVERFLOW_READ = "buffer_overflow_read"  # 缓冲区越界读


class LeakDataType(Enum):
    """可泄露的数据类型"""
    STACK_ADDRESS = "stack_address"             # 栈地址
    HEAP_ADDRESS = "heap_address"               # 堆地址
    LIBC_ADDRESS = "libc_address"               # libc 地址
    BINARY_BASE = "binary_base"                  # 二进制基址
    CANARY = "canary"                           # Stack Canary
    POINTER = "pointer"                          # 指针值
    OFFSET = "offset"                            # 偏移量
    RANDOM_BYTES = "random_bytes"                # 随机字节
    ENVIRONMENT = "environment"                  # 环境变量
    UNKNOWN = "unknown"                          # 未知类型


class Severity(Enum):
    """泄露严重程度"""
    CRITICAL = "critical"    # 可泄露关键地址
    HIGH = "high"           # 可泄露有用信息
    MEDIUM = "medium"       # 可泄露有限信息
    LOW = "low"             # 信息价值有限


@dataclass
class LeakPoint:
    """
    信息泄露点数据类
    
    表示一个潜在的或确认的信息泄露点
    """
    leak_id: str                                    # 唯一标识符
    leak_type: LeakType                             # 泄露类型
    location: str                                   # 泄露位置（函数名+偏移）
    instruction: str                                # 相关指令
    severity: Severity                              # 严重程度
    leakable_data_types: List[LeakDataType] = field(default_factory=list)  # 可泄露的数据类型
    leakable_bytes: int = 0                        # 估计可泄露的字节数
    parameter_index: int = -1                       # 如果是格式化字符串，参数索引
    stack_offset: int = 0                          # 栈偏移量
    confidence: float = 0.0                        # 置信度 0-1
    description: str = ""                          # 描述
    exploit_snippet: str = ""                      # 利用代码片段
    raw_data: Dict[str, Any] = field(default_factory=dict)  # 原始数据
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "leak_id": self.leak_id,
            "leak_type": self.leak_type.value,
            "location": self.location,
            "instruction": self.instruction,
            "severity": self.severity.value,
            "leakable_data_types": [dt.value for dt in self.leakable_data_types],
            "leakable_bytes": self.leakable_bytes,
            "parameter_index": self.parameter_index,
            "stack_offset": self.stack_offset,
            "confidence": self.confidence,
            "description": self.description,
            "exploit_snippet": self.exploit_snippet,
        }


@dataclass
class LeakCapabilityMatrix:
    """
    信息泄露能力矩阵
    
    汇总所有泄露点，提供可操作的利用规划数据
    """
    binary_name: str
    total_leak_points: int = 0
    format_string_leaks: int = 0
    memory_read_leaks: int = 0
    
    # 可泄露的关键信息
    can_leak_stack_address: bool = False
    can_leak_heap_address: bool = False
    can_leak_libc_address: bool = False
    can_leak_binary_base: bool = False
    can_leak_canary: bool = False
    
    # 量化指标
    max_leakable_bytes: int = 0
    avg_leakable_bytes: float = 0.0
    
    # 详细泄露点列表
    leak_points: List[LeakPoint] = field(default_factory=list)
    
    # 利用建议
    best_leak_point: Optional[LeakPoint] = None
    exploit_strategy: str = ""
    recommended_bad_chars: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "binary_name": self.binary_name,
            "summary": {
                "total_leak_points": self.total_leak_points,
                "format_string_leaks": self.format_string_leaks,
                "memory_read_leaks": self.memory_read_leaks,
                "can_leak_stack_address": self.can_leak_stack_address,
                "can_leak_heap_address": self.can_leak_heap_address,
                "can_leak_libc_address": self.can_leak_libc_address,
                "can_leak_binary_base": self.can_leak_binary_base,
                "can_leak_canary": self.can_leak_canary,
                "max_leakable_bytes": self.max_leakable_bytes,
                "avg_leakable_bytes": self.avg_leakable_bytes,
            },
            "best_leak_point": self.best_leak_point.to_dict() if self.best_leak_point else None,
            "exploit_strategy": self.exploit_strategy,
            "leak_points": [lp.to_dict() for lp in self.leak_points],
        }


class InfoLeakAnalyzer:
    """
    信息泄露分析器
    
    专门检测格式化字符串漏洞和内存信息泄露，量化泄露能力
    """
    
    # 格式化字符串相关函数模式
    FORMAT_FUNC_PATTERNS = [
        r'printf\s*\(')
        r'fprintf\s*\(\s*\w+\s*,')
        r'sprintf\s*\(')
        r'snprintf\s*\(')
        r'vprintf\s*\(')
        r'vfprintf\s*\(')
        r'vsprintf\s*\(')
        r'vsnprintf\s*\(')
        r'puts\s*\(')
        r'putchar\s*\(')
    ]
    
    # 危险格式化函数（第一个参数直接是用户输入）
    DANGEROUS_FORMAT_PATTERNS = [
        (r'printf\s*\(\s*(\w+)\s*\)', 1),   # printf(user_input)
        (r'puts\s*\(\s*(\w+)\s*\)', 1),     # puts(user_input)
    ]
    
    # 安全格式化函数模式
    SAFE_FORMAT_PATTERNS = [
        r'printf\s*\(\s*"[^"]*"\s*,',  # printf("format", ...
        r'fprintf\s*\(\s*\w+\s*,\s*"[^"]*"\s*,',  # fprintf(fp, "format", ...
    ]
    
    # 可能的泄露格式说明符
    LEAK_FORMAT_SPECIFIERS = [
        ('%p', 'pointer', 8, '泄露指针值（64位）或整数'),
        ('%s', 'string', 0, '泄露字符串（到null）'),
        ('%x', 'hex_int', 8, '泄露十六进制整数'),
        ('%d', 'decimal', 4, '泄露十进制整数'),
        ('%u', 'unsigned', 4, '泄露无符号整数'),
        ('%c', 'char', 1, '泄露单个字符'),
        ('%ld', 'long', 8, '泄露长整型'),
        ('%lx', 'long_hex', 8, '泄露长十六进制'),
        ('%hd', 'short', 2, '泄露短整型'),
        ('%hhd', 'char_int', 1, '泄露字符型整数'),
        ('%08x', 'padded_hex', 8, '泄露8位十六进制（前导零）'),
        ('%#x', 'alternate_hex', 8, '泄露带0x前缀的十六进制'),
        ('%lld', 'long_long', 16, '泄露长长整型'),
    ]
    
    def __init__(, self)
        binary_path: str = "",
        min_confidence: float = 0.5,
        max_depth: int = 10
    ):
        """
        初始化信息泄露分析器
        
        Args:
            binary_path: 二进制文件路径
            min_confidence: 最小置信度阈值
            max_depth: 最大分析深度
        """
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        self.min_confidence = min_confidence
        self.max_depth = max_depth
        
        self.logger = logging.getLogger(__name__)
        self.leak_points: List[LeakPoint] = []
        self.analysis_context: Dict[str, Any] = {}
        
        # 分析结果缓存
        self._function_cache: Dict[str, Set[str]] = {}
        self._imported_functions: Set[str] = set()
        self._format_string_funcs: Set[str] = set()
    
    def analyze(, self)
        binary_info: Optional[Dict[str, Any]] = None,
        decomp_data: Optional[Dict[str, Any]] = None,
        crash_data: Optional[Dict[str, Any]] = None,
        symbols: Optional[Dict[str, int]] = None
    ) -> LeakCapabilityMatrix:
        """
        执行信息泄露分析
        
        Args:
            binary_info: 二进制基本信息
            decomp_data: 反编译数据
            crash_data: 崩溃数据（可能包含泄露信息）
            symbols: 符号表信息
        
        Returns:
            LeakCapabilityMatrix: 泄露能力矩阵
        """
        self.logger.info(f"开始信息泄露分析: {self.binary_name}")
        
        # 初始化分析上下文
        if binary_info:
            self.analysis_context['binary_info'] = binary_info,
            if 'imports' in binary_info:
                self._imported_functions = set(binary_info['imports'])
        
        if symbols:
            self.analysis_context['symbols'] = symbols
        
        # 清除之前的分析结果
        self.leak_points = []
        leak_matrix = LeakCapabilityMatrix(binary_name=self.binary_name)
        
        # 1. 检测格式化字符串漏洞
        if decomp_data:
            self._analyze_format_string_vulnerabilities(decomp_data)
        
        # 2. 分析崩溃数据中的泄露信息
        if crash_data:
            self._analyze_crash_data_leaks(crash_data)
        
        # 3. 检测内存越界读
        if decomp_data:
            self._analyze_memory_read_vulnerabilities(decomp_data)
        
        # 4. 评估泄露能力
        leak_matrix = self._build_leak_capability_matrix()
        
        # 5. 生成利用策略
        self._generate_exploit_strategy(leak_matrix)
        
        self.logger.info()
            f"信息泄露分析完成: 发现 {len(self.leak_points)} 个泄露点"
        
        
        return leak_matrix
    
    def _analyze_format_string_vulnerabilities(, self)
        decomp_data: Dict[str, Any]
    ) -> None:
        """
        分析格式化字符串漏洞
        
        Args:
            decomp_data: 反编译数据
        """
        self.logger.debug("分析格式化字符串漏洞")
        
        # 遍历反编译的函数
        for func_name, func_data in decomp_data.items():
            if not isinstance(func_data, dict):
                continue
            
            pseudocode = func_data.get('pseudocode', '')
            if not pseudocode:
                continue
            
            # 检测危险模式
            for pattern, param_idx in self.DANGEROUS_FORMAT_PATTERNS:
                matches = re.finditer(pattern, pseudocode)
                for match in matches:
                    # 检查是否真的没有格式化字符串
                    full_match = match.group(0)
                    if '"' not in full_match:
                        self._register_format_string_leak()
                            func_name=func_name,
                            match_text=full_match,
                            param_index=param_idx,
                            match=match
                        
            
            # 扫描可能的泄露点
            self._scan_format_string_leak_points(func_name, pseudocode)
    
    def _register_format_string_leak(, self)
        func_name: str,
        match_text: str,
        param_index: int,
        match: re.Match
    ) -> None:
        """
        注册格式化字符串泄露点
        
        Args:
            func_name: 函数名
            match_text: 匹配的文本
            param_index: 参数索引
            match: 正则匹配对象
        """
        leak_id = f"fmt_{func_name}_{len(self.leak_points)}"
        
        # 提取变量名
        var_name = match.group(param_index) if match.lastindex and match.lastindex >= param_index else "unknown"
        
        # 评估泄露能力
        leakable_types = self._evaluate_format_string_leakage(var_name)
        max_bytes = self._estimate_leak_bytes(var_name, param_index)
        
        # 生成利用片段
        exploit = self._generate_format_string_exploit(var_name, param_index)
        
        # 确定严重程度
        severity = self._determine_leak_severity(leakable_types, max_bytes)
        
        leak_point = LeakPoint()
            leak_id=leak_id,
            leak_type=LeakType.FORMAT_STRING,
            location=func_name,
            instruction=match_text,
            severity=severity,
            leakable_data_types=leakable_types,
            leakable_bytes=max_bytes,
            parameter_index=param_index,
            confidence=0.95,  # 格式化字符串漏洞置信度高
            description=f"格式化字符串漏洞: 直接打印变量 '{var_name}'",
            exploit_snippet=exploit,
            raw_data={
                'variable': var_name,
                'function': func_name,
            }
        
        
        self.leak_points.append(leak_point)
        self.logger.info(f"发现格式化字符串漏洞: {func_name} - {var_name}")
    
    def _scan_format_string_leak_points(, self)
        func_name: str,
        pseudocode: str
    ) -> None:
        """
        扫描格式化字符串泄露点
        
        Args:
            func_name: 函数名
            pseudocode: 伪代码
        """
        # 查找所有使用格式说明符的地方
        for spec, dtype, default_bytes, desc in self.LEAK_FORMAT_SPECIFIERS:
            if spec in pseudocode:
                # 计算出现次数和位置
                count = pseudocode.count(spec)
                
                leak_id = f"fmt_spec_{func_name}_{spec.replace('%', '')}_{len(self.leak_points)}"
                
                # 寻找包含该说明符的函数调用上下文
                context_pattern = rf'.*{spec}.*'
                context_matches = re.findall(context_pattern, pseudocode)
                
                leak_point = LeakPoint()
                    leak_id=leak_id,
                    leak_type=LeakType.FORMAT_STRING,
                    location=func_name,
                    instruction=f"格式说明符 {spec} (出现 {count} 次)",
                    severity=Severity.MEDIUM,
                    leakable_data_types=[self._spec_to_data_type(spec)],
                    leakable_bytes=default_bytes * count,
                    confidence=0.6,
                    description=f"{spec}: {desc}",
                    exploit_snippet=self._generate_format_spec_exploit(spec),
                
                
                self.leak_points.append(leak_point)
    
    def _evaluate_format_string_leakage(, self)
        var_name: str
    ) -> List[LeakDataType]:
        """
        评估格式化字符串的泄露能力
        
        Args:
            var_name: 变量名
        
        Returns:
            List[LeakDataType]: 可泄露的数据类型列表
        """
        leakable_types = []
        
        # 变量名模式匹配
        var_lower = var_name.lower()
        
        if any(x in var_lower for x in ['buf', 'input', 'user', 'data', 'str']):
            # 用户输入相关 - 可能泄露栈/堆数据
            leakable_types.extend([)
                LeakDataType.STACK_ADDRESS,
                LeakDataType.HEAP_ADDRESS,
                LeakDataType.UNKNOWN,
            ]
        
        if any(x in var_lower for x in ['addr', 'ptr', 'p']):
            # 指针变量 - 可能泄露地址
            leakable_types.extend([)
                LeakDataType.POINTER,
                LeakDataType.STACK_ADDRESS,
                LeakDataType.HEAP_ADDRESS,
            ]
        
        if any(x in var_lower for x in ['canary', 'cookie']):
            # Canary 相关
            leakable_types.append(LeakDataType.CANARY)
        
        # 默认情况
        if not leakable_types:
            leakable_types = [
                LeakDataType.POINTER,
                LeakDataType.OFFSET,
                LeakDataType.UNKNOWN,
            ]
        
        return leakable_types
    
    def _estimate_leak_bytes(, self)
        var_name: str,
        param_index: int
    ) -> int:
        """
        估计可泄露的字节数
        
        Args:
            var_name: 变量名
            param_index: 参数索引
        
        Returns:
            int: 估计的字节数
        """
        # 变量名模式
        var_lower = var_name.lower()
        
        # 缓冲区相关
        if any(x in var_lower for x in ['buf', 'buffer', 'data', 'input']):
            return 1024  # 可能泄露大量数据
        
        # 指针相关
        if any(x in var_lower for x in ['ptr', 'addr', 'p']):
            return 8  # 指针大小
        
        # 普通变量
        if 'canary' in var_lower:
            return 8
        
        return 64  # 默认估计
    
    def _generate_format_string_exploit(, self)
        var_name: str,
        param_index: int
    ) -> str:
        """
        生成格式化字符串利用代码片段
        
        Args:
            var_name: 变量名
            param_index: 参数索引
        
        Returns:
            str: 利用代码片段
        """
        exploits = []
        
        # 泄露栈内容
        exploits.append(f"# 泄露栈内容:")
        exploits.append(f"printf(\"%p \" * 20);  // 泄露20个栈指针")
        exploits.append(f"printf(\"%x \" * 10);   // 泄露10个十六进制值")
        
        # 泄露 libc 地址
        exploits.append(f"\n# 泄露 libc 地址:")
        exploits.append(f"printf(\"%llx \");     // 泄露长长整型（64位地址）")
        
        # 泄露栈偏移
        exploits.append(f"\n# 定位参数位置:")
        exploits.append(f"printf(\"%p%p%p%p%p%p%p%p%p%n\");  // 确定栈参数偏移")
        
        # 完整利用模板
        exploits.append(f"\n# 完整利用模板:")
        exploits.append(f'python3 -c "print(\'%08x.\' * 20)"')
        
        return '\n'.join(exploits)
    
    def _generate_format_spec_exploit(spec: str) -> str:
        """
        生成格式说明符利用代码
        
        Args:
            spec: 格式说明符
        
        Returns:
            str: 利用代码片段
        """
        return f'printf("{spec}");  // 使用 {spec} 泄露数据'
    
    def _determine_leak_severity(, self)
        leak_types: List[LeakDataType],
        max_bytes: int
    ) -> Severity:
        """
        确定泄露严重程度
        
        Args:
            leak_types: 可泄露的数据类型
            max_bytes: 最大可泄露字节数
        
        Returns:
            Severity: 严重程度
        """
        critical_types = {
            LeakDataType.LIBC_ADDRESS,
            LeakDataType.BINARY_BASE,
            LeakDataType.CANARY,
        }
        
        high_types = {
            LeakDataType.STACK_ADDRESS,
            LeakDataType.HEAP_ADDRESS,
            LeakDataType.POINTER,
        }
        
        # 检查是否包含关键泄露类型
        if any(t in critical_types for t in leak_types):
            return Severity.CRITICAL
        
        if any(t in high_types for t in leak_types) and max_bytes > 64:
            return Severity.HIGH
        
        if max_bytes > 256:
            return Severity.HIGH
        
        if max_bytes > 16:
            return Severity.MEDIUM
        
        return Severity.LOW
    
    def _spec_to_data_type(self, spec: str) -> LeakDataType:
        """
        将格式说明符转换为数据类型
        
        Args:
            spec: 格式说明符
        
        Returns:
            LeakDataType: 数据类型
        """
        if 'p' in spec:
            return LeakDataType.POINTER
        if 's' in spec:
            return LeakDataType.UNKNOWN
        if 'x' in spec.lower():
            return LeakDataType.RANDOM_BYTES
        if 'd' in spec or 'u' in spec:
            return LeakDataType.OFFSET
        return LeakDataType.UNKNOWN
    
    def _analyze_crash_data_leaks(, self)
        crash_data: Dict[str, Any]
    ) -> None:
        """
        分析崩溃数据中的泄露信息
        
        Args:
            crash_data: 崩溃数据
        """
        self.logger.debug("分析崩溃数据泄露")
        
        # 从崩溃数据提取泄露信息
        if 'registers' in crash_data:
            registers = crash_data['registers']
            
            # 检查是否包含栈/堆地址
            for reg_name, reg_value in registers.items():
                if isinstance(reg_value, (int, str)):
                    value = int(reg_value) if isinstance(reg_value, str) else reg_value
                    
                    # 检测栈地址 (0x7fff...)
                    if 0x7fff00000000 <= value <= 0x7fffffffffff:
                        self._register_address_leak()
                            address=value,
                            address_type=LeakDataType.STACK_ADDRESS,
                            source=f"寄存器 {reg_name} (崩溃时)",
                            context=crash_data
                        
                    
                    # 检测堆地址
                    elif value > 0x10000000000:
                        self._register_address_leak()
                            address=value,
                            address_type=LeakDataType.HEAP_ADDRESS,
                            source=f"寄存器 {reg_name} (崩溃时)",
                            context=crash_data
                        
    
    def _register_address_leak(, self)
        address: int,
        address_type: LeakDataType,
        source: str,
        context: Dict[str, Any]
    ) -> None:
        """
        注册地址泄露点
        
        Args:
            address: 地址值
            address_type: 地址类型
            source: 来源
            context: 上下文
        """
        leak_id = f"addr_{address_type.value}_{len(self.leak_points)}"
        
        leak_point = LeakPoint()
            leak_id=leak_id,
            leak_type=LeakType.STACK_OVERFLOW_READ if address_type == LeakDataType.STACK_ADDRESS
                       else LeakType.HEAP_OVERFLOW_READ,
            location=context.get('function', 'unknown'),
            instruction=f"地址泄露 @ {hex(address)}",
            severity=Severity.HIGH,
            leakable_data_types=[address_type],
            leakable_bytes=8,
            confidence=0.8,
            description=f"从 {source} 泄露 {address_type.value}",
            exploit_snippet=f"# 地址已泄露: {hex(address)}\n# 可用于绕过 ASLR",
            raw_data={
                'address': hex(address),
                'type': address_type.value,
                'source': source,
            }
        
        
        self.leak_points.append(leak_point)
        self.logger.info(f"发现地址泄露: {address_type.value} @ {hex(address)}")
    
    def _analyze_memory_read_vulnerabilities(, self)
        decomp_data: Dict[str, Any]
    ) -> None:
        """
        分析内存越界读漏洞
        
        Args:
            decomp_data: 反编译数据
        """
        self.logger.debug("分析内存越界读漏洞")
        
        # 扫描可能导致越界读的函数调用
        dangerous_patterns = [
            (r'strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', 'strcpy'),
            (r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', 'memcpy'),
            (r'strncpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', 'strncpy'),
            (r'gets\s*\(\s*(\w+)\s*\)', 'gets'),
        ]
        
        for func_name, func_data in decomp_data.items():
            if not isinstance(func_data, dict):
                continue
            
            pseudocode = func_data.get('pseudocode', '')
            
            for pattern, func_call in dangerous_patterns:
                matches = re.finditer(pattern, pseudocode)
                for match in matches:
                    self._register_memory_read_leak()
                        func_name=func_name,
                        match=match.group(0),
                        func_call=func_call,
                        match_obj=match
                    
    
    def _register_memory_read_leak(, self)
        func_name: str,
        match: str,
        func_call: str,
        match_obj: re.Match
    ) -> None:
        """
        注册内存越界读泄露点
        
        Args:
            func_name: 函数名
            match: 匹配文本
            func_call: 函数调用名
            match_obj: 匹配对象
        """
        leak_id = f"mem_{func_name}_{func_call}_{len(self.leak_points)}"
        
        # 评估泄露能力
        leakable_types = [LeakDataType.UNKNOWN, LeakDataType.OFFSET]
        
        # 获取源变量名（可能泄露的数据）
        if match_obj.lastindex >= 2:
            src_var = match_obj.group(2)
            if any(x in src_var.lower() for x in ['buf', 'data', 'input']):
                leakable_types.append(LeakDataType.STACK_ADDRESS)
                leakable_types.append(LeakDataType.HEAP_ADDRESS)
        
        leak_point = LeakPoint()
            leak_id=leak_id,
            leak_type=LeakType.BUFFER_OVERFLOW_READ,
            location=func_name,
            instruction=match,
            severity=Severity.MEDIUM,
            leakable_data_types=leakable_types,
            leakable_bytes=256,
            confidence=0.5,
            description=f"危险的 {func_call} 调用可能导致越界读",
            exploit_snippet=f"# {func_call} 调用可能泄露邻接内存数据",
        
        
        self.leak_points.append(leak_point)
        self.logger.info(f"发现潜在内存越界读: {func_name} - {func_call}")
    
    def _build_leak_capability_matrix(self) -> LeakCapabilityMatrix:
        """
        构建泄露能力矩阵
        
        Returns:
            LeakCapabilityMatrix: 泄露能力矩阵
        """
        matrix = LeakCapabilityMatrix(binary_name=self.binary_name)
        
        matrix.total_leak_points = len(self.leak_points)
        matrix.leak_points = self.leak_points
        
        # 分类统计
        for leak in self.leak_points:
            if leak.leak_type == LeakType.FORMAT_STRING:
                matrix.format_string_leaks += 1
            else:
                matrix.memory_read_leaks += 1
            
            # 更新可泄露的关键信息
            for dtype in leak.leakable_data_types:
                if dtype == LeakDataType.STACK_ADDRESS:
                    matrix.can_leak_stack_address = True
                elif dtype == LeakDataType.HEAP_ADDRESS:
                    matrix.can_leak_heap_address = True
                elif dtype == LeakDataType.LIBC_ADDRESS:
                    matrix.can_leak_libc_address = True
                elif dtype == LeakDataType.BINARY_BASE:
                    matrix.can_leak_binary_base = True
                elif dtype == LeakDataType.CANARY:
                    matrix.can_leak_canary = True
            
            # 更新最大泄露字节数
            if leak.leakable_bytes > matrix.max_leakable_bytes:
                matrix.max_leakable_bytes = leak.leakable_bytes
        
        # 计算平均泄露字节数
        if self.leak_points:
            total_bytes = sum(lp.leakable_bytes for lp in self.leak_points)
            matrix.avg_leakable_bytes = total_bytes / len(self.leak_points)
        
        # 选择最佳泄露点
        matrix.best_leak_point = self._select_best_leak_point()
        
        return matrix
    
    def _select_best_leak_point(self) -> Optional[LeakPoint]:
        """
        选择最佳泄露点
        
        Returns:
            Optional[LeakPoint]: 最佳泄露点
        """
        if not self.leak_points:
            return None
        
        # 按评分排序
        def score_leak(leak: LeakPoint) -> Tuple[int, float, int]:
            severity_score = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
            }.get(leak.severity, 0)
            
            return (severity_score, leak.confidence, leak.leakable_bytes)
        
        sorted_leaks = sorted()
            self.leak_points,
            key=score_leak,
            reverse=True
        
        
        return sorted_leaks[0] if sorted_leaks else None
    
    def _generate_exploit_strategy(self, matrix: LeakCapabilityMatrix) -> None:
        """
        生成利用策略
        
        Args:
            matrix: 泄露能力矩阵
        """
        strategies = []
        self.recommended_bad_chars = []
        
        # 根据泄露能力生成策略
        if matrix.can_leak_libc_address:
            strategies.append()
                "1. 泄露 libc 地址 → 计算 system 地址 → 获取 shell"
            
            self.recommended_bad_chars = ['\x00', '\x0a']
        
        if matrix.can_leak_binary_base:
            strategies.append()
                "2. 泄露 binary 基址 → 定位 ROP gadgets → 构建 ROP 链"
            
        
        if matrix.can_leak_canary:
            strategies.append()
                "3. 泄露 canary → 绕过栈保护 → 触发栈溢出"
            
        
        if matrix.can_leak_stack_address:
            strategies.append()
                "4. 泄露栈地址 → Stack Pivot → 新栈执行 ROP"
            
        
        if matrix.format_string_leaks > 0:
            strategies.append()
                "5. 格式化字符串泄露 → 使用 %p 泄露指针 → 定位利用原语"
            
        
        if not strategies:
            strategies.append("未发现有效的信息泄露路径")
        
        matrix.exploit_strategy = "\n".join(strategies)
        self.logger.info(f"生成利用策略:\n{matrix.exploit_strategy}")
    
    def detect_format_string_in_binary(, self)
        binary_path: str
    ) -> List[Dict[str, Any]]:
        """
        在二进制文件中检测格式化字符串漏洞
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            List[Dict[str, Any]]: 检测到的漏洞列表
        """
        self.logger.info(f"检测二进制文件格式化字符串漏洞: {binary_path}")
        
        results = []
        
        # 这里可以集成静态分析工具
        # 简化实现：返回空列表，等待反编译数据
        self.logger.warning("需要反编译数据才能进行完整分析")
        
        return results
    
    def generate_leak_payload(, self)
        leak_point: LeakPoint,
        target_type: LeakDataType
    ) -> str:
        """
        生成泄露载荷
        
        Args:
            leak_point: 泄露点
            target_type: 目标数据类型
        
        Returns:
            str: 泄露载荷
        """
        if leak_point.leak_type == LeakType.FORMAT_STRING:
            # 生成格式化字符串载荷
            if target_type == LeakDataType.POINTER:
                return '%p ' * 10
            elif target_type == LeakDataType.STACK_ADDRESS:
                return '%x ' * 20
            elif target_type == LeakDataType.LIBC_ADDRESS:
                return '%llx '
            else:
                return '%s '
        
        # 其他类型的载荷
        return f'LEAK_REQUEST:{target_type.value}'


def analyze_info_leak(, binary_path: str, binary_info: Optional[Dict[str, Any]] = None, decomp_data: Optional[Dict[str, Any]] = None, crash_data: Optional[Dict[str, Any]] = None) -> LeakCapabilityMatrix:
    """
    便捷函数：分析二进制文件的信息泄露
    
    Args:
        binary_path: 二进制文件路径
        binary_info: 二进制信息
        decomp_data: 反编译数据
        crash_data: 崩溃数据
    
    Returns:
        LeakCapabilityMatrix: 泄露能力矩阵
    """
    analyzer = InfoLeakAnalyzer(binary_path=binary_path)
    return analyzer.analyze()
        binary_info=binary_info,
        decomp_data=decomp_data,
        crash_data=crash_data
    



# 示例用法和测试
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # 创建分析器
    analyzer = InfoLeakAnalyzer(binary_path="test_binary")
    
    # 模拟反编译数据
    mock_decomp_data = {
        'vulnerable_func': {
            'pseudocode': '''
                void vulnerable_func(char *user_input) {
                    printf(user_input);  // 格式化字符串漏洞
                    printf("%p %p %p");  // 泄露栈内容
                }
            ''',
            'address': 0x401000,
        },
        'mem_leak_func': {
            'pseudocode': '''
                void mem_leak_func(char *buf, char *input) {
                    strcpy(buf, input);  // 可能越界读
                }
            ''',
            'address': 0x401100,
        }
    }
    
    # 执行分析
    result = analyzer.analyze(decomp_data=mock_decomp_data)
    
    # 打印结果
    print("\n" + "=" * 60)
    print("信息泄露分析结果")
    print("=" * 60)
    print(f"二进制名称: {result.binary_name}")
    print(f"总泄露点数量: {result.total_leak_points}")
    print(f"格式化字符串漏洞: {result.format_string_leaks}")
    print(f"内存越界读: {result.memory_read_leaks}")
    print(f"\n可泄露关键信息:")
    print(f"  - 栈地址: {result.can_leak_stack_address}")
    print(f"  - 堆地址: {result.can_leak_heap_address}")
    print(f"  - libc地址: {result.can_leak_libc_address}")
    print(f"  - 二进制基址: {result.can_leak_binary_base}")
    print(f"  - Canary: {result.can_leak_canary}")
    print(f"\n最大可泄露字节数: {result.max_leakable_bytes}")
    print(f"\n利用策略:\n{result.exploit_strategy}")
    
    if result.best_leak_point:
        print(f"\n最佳泄露点:")
        print(f"  ID: {result.best_leak_point.leak_id}")
        print(f"  类型: {result.best_leak_point.leak_type.value}")
        print(f"  位置: {result.best_leak_point.location}")
        print(f"  严重程度: {result.best_leak_point.severity.value}""