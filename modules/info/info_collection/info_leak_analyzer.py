"""信息泄露分析器 — 格式化字符串漏洞、内存读取泄露、利用能力矩阵。"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)


class LeakType:
    FORMAT_STRING = "format_string"
    STACK_OVERFLOW_READ = "stack_overflow_read"
    HEAP_OVERFLOW_READ = "heap_overflow_read"
    USE_AFTER_FREE_READ = "uaf_read"
    INTEGER_OVERFLOW_READ = "int_overflow_read"
    OFF_BY_ONE_READ = "off_by_one_read"
    UNINITIALIZED_READ = "uninit_read"
    BUFFER_OVERFLOW_READ = "buffer_overflow_read"


class LeakDataType:
    STACK_ADDRESS = "stack_address"
    HEAP_ADDRESS = "heap_address"
    LIBC_ADDRESS = "libc_address"
    BINARY_BASE = "binary_base"
    CANARY = "canary"
    POINTER = "pointer"
    OFFSET = "offset"
    RANDOM_BYTES = "random_bytes"
    ENVIRONMENT = "environment"
    UNKNOWN = "unknown"


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class LeakPoint:
    """已确认或潜在的信息泄露点数据结构。"""
    leak_id: str = ""
    leak_type: str = LeakType.FORMAT_STRING
    location: str = ""
    instruction: str = ""
    severity: str = Severity.LOW
    leakable_data_types: List[str] = field(default_factory=list)
    leakable_bytes: int = 0
    parameter_index: int = -1
    stack_offset: int = 0
    confidence: float = 0.0
    description: str = ""
    exploit_snippet: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    # 证据链：原始输入 → 传递给危险函数的路径
    evidence_chain: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leak_id": self.leak_id,
            "leak_type": self.leak_type,
            "location": self.location,
            "instruction": self.instruction,
            "severity": self.severity,
            "leakable_data_types": self.leakable_data_types,
            "leakable_bytes": self.leakable_bytes,
            "parameter_index": self.parameter_index,
            "stack_offset": self.stack_offset,
            "confidence": self.confidence,
            "description": self.description,
            "exploit_snippet": self.exploit_snippet,
            "evidence_chain": self.evidence_chain,
        }


@dataclass
class LeakCapabilityMatrix:
    """泄露全景汇总 — 所有泄露点及利用规划数据。"""
    binary_name: str = ""
    total_leak_points: int = 0
    format_string_leaks: int = 0
    memory_read_leaks: int = 0
    can_leak_stack_address: bool = False
    can_leak_heap_address: bool = False
    can_leak_libc_address: bool = False
    can_leak_binary_base: bool = False
    can_leak_canary: bool = False
    max_leakable_bytes: int = 0
    avg_leakable_bytes: float = 0.0
    leak_points: List[LeakPoint] = field(default_factory=list)
    best_leak_point: Optional[LeakPoint] = None
    exploit_strategy: str = ""
    recommended_bad_chars: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
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
    """反编译代码中的信息泄露漏洞检测。

    核心关注：格式化字符串漏洞与内存读取越界。
    增强：数据流追踪（污点源→sink），对用户可控输入传递到
    printf 族函数的路径进行评分，降低纯静态模式匹配的误报率。
    """

    FORMAT_FUNC_PATTERNS = [
        r'printf\s*\(', r'fprintf\s*\(\s*\w+\s*,', r'sprintf\s*\(',
        r'snprintf\s*\(', r'vprintf\s*\(', r'vfprintf\s*\(',
        r'vsprintf\s*\(', r'vsnprintf\s*\(', r'puts\s*\(',
        r'putchar\s*\(',
    ]

    DANGEROUS_FORMAT_PATTERNS = [
        (r'printf\s*\(\s*(\w+)\s*\)', 1),
        (r'puts\s*\(\s*(\w+)\s*\)', 1),
    ]

    SAFE_FORMAT_PATTERNS = [
        r'printf\s*\(\s*"[^"]*"\s*,',
        r'fprintf\s*\(\s*\w+\s*,\s*"[^"]*"\s*,',
    ]

    LEAK_FORMAT_SPECIFIERS = [
        ('%p', 'pointer', 8, '泄露指针值（64 位）或整数'),
        ('%s', 'string', 0, '泄露字符串（至空终止符）'),
        ('%x', 'hex_int', 8, '泄露十六进制整数'),
        ('%d', 'decimal', 4, '泄露十进制整数'),
        ('%u', 'unsigned', 4, '泄露无符号整数'),
        ('%lx', 'long_hex', 8, '泄露长整型十六进制'),
        ('%llx', 'long_long_hex', 8, '泄露长长整型十六进制'),
        ('%p', 'pointer', 8, '泄露指针'),
    ]

    # 污点源模式 — 用户/网络可控的输入函数
    _TAINT_SOURCES = [
        r'(?:recv|read|fgets|scanf|gets|getenv|argv)\s*\(',
        r'(?:memcpy|strcpy|strncpy)\s*\(\s*\w+\s*,\s*(\w+)',
    ]
    _TAINT_SOURCE_RE = re.compile('|'.join(_TAINT_SOURCES))

    def __init__(self, binary_path: str = "",
                 min_confidence: float = 0.5,
                 max_depth: int = 10):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        self.min_confidence = min_confidence
        self.max_depth = max_depth
        self.leak_points: List[LeakPoint] = []
        self.analysis_context: Dict[str, Any] = {}
        self._function_cache: Dict[str, Set[str]] = {}
        self._imported_functions: Set[str] = set()
        self._format_string_funcs: Set[str] = set()
        self.recommended_bad_chars: List[str] = []
        # 缓存每个函数的污点变量集合
        self._tainted_vars: Dict[str, set] = {}

    def _collect_tainted_vars(self, pseudocode: str) -> set:
        """从伪代码中提取污点源赋值的变量名。

        策略：在赋值语句中匹配 var = recv(...) 等模式。
        不做过程间分析 — 仅限当前函数内第一层赋值。
        复杂度：O(n) 单次正则扫描。
        """
        tainted = set()
        assign_pat = re.compile(r'(\w+)\s*=\s*(?:' + '|'.join(
            ['recv', 'read', 'fgets', 'scanf', 'gets', 'getenv',
             'atoi', 'strtol', 'memcpy', 'strcpy', 'argv']) + r')\s*\(')
        for m in assign_pat.finditer(pseudocode):
            tainted.add(m.group(1))
        return tainted

    def _trace_taint_to_printf(self, pseudocode: str, varname: str) -> list:
        """从污点变量追踪到 printf 族调用的路径片段。

        在伪代码中定位变量名出现位置，若其后续行存在 printf
        调用且参数列表中包含该变量，则记录该路径。
        """
        chain = []
        lines = pseudocode.split('\n')
        var_refs = [i for i, ln in enumerate(lines) if varname in ln]
        printf_lines = {i for i, ln in enumerate(lines)
                        if any(fn in ln for fn in ('printf', 'fprintf', 'sprintf', 'puts'))}
        for vline in var_refs:
            for pline in printf_lines:
                if 0 < pline - vline <= 5 and varname in lines[pline]:
                    chain.append(f"{varname}@L{vline}→printf@L{pline}")
        return chain[:5]

    def analyze(self,
                binary_info: Optional[Dict[str, Any]] = None,
                decomp_data: Optional[Dict[str, Any]] = None,
                crash_data: Optional[Dict[str, Any]] = None,
                symbols: Optional[Dict[str, int]] = None) -> LeakCapabilityMatrix:
        """完整信息泄露分析流水线入口。"""
        logger.info(f"启动信息泄露分析: {self.binary_name}")

        if binary_info:
            self.analysis_context['binary_info'] = binary_info
            if 'imports' in binary_info:
                self._imported_functions = set(binary_info['imports'])

        if symbols:
            self.analysis_context['symbols'] = symbols

        self.leak_points = []
        leak_matrix = LeakCapabilityMatrix(binary_name=self.binary_name)

        if decomp_data:
            self._analyze_format_string_vulnerabilities(decomp_data)

        if crash_data:
            self._analyze_crash_data_leaks(crash_data)

        if decomp_data:
            self._analyze_memory_read_vulnerabilities(decomp_data)

        leak_matrix = self._build_leak_capability_matrix()
        self._generate_exploit_strategy(leak_matrix)

        logger.info(f"信息泄露分析完成: 发现 {len(self.leak_points)} 个泄露点")
        return leak_matrix

    def _analyze_format_string_vulnerabilities(self, decomp_data: Dict[str, Any]) -> None:
        logger.debug("分析格式化字符串漏洞")
        for func_name, func_data in decomp_data.items():
            if not isinstance(func_data, dict):
                continue
            pseudocode = func_data.get('pseudocode', '')
            if not pseudocode:
                continue

            # 预先收集污点变量
            tainted = self._collect_tainted_vars(pseudocode)
            self._tainted_vars[func_name] = tainted

            for pattern, param_idx in self.DANGEROUS_FORMAT_PATTERNS:
                for match in re.finditer(pattern, pseudocode):
                    full_match = match.group(0)
                    if '"' not in full_match:
                        self._register_format_string_leak(
                            func_name=func_name, match_text=full_match,
                            param_index=param_idx, match=match,
                            tainted_vars=tainted)

            self._scan_format_string_leak_points(func_name, pseudocode)

    def _register_format_string_leak(self, func_name: str, match_text: str,
                                     param_index: int, match: re.Match,
                                     tainted_vars: set = None) -> None:
        leak_id = f"fmt_{func_name}_{len(self.leak_points)}"
        var_name = match.group(param_index) if match.lastindex and match.lastindex >= param_index else "unknown"
        leakable_types = self._evaluate_format_string_leakage(var_name)
        max_bytes = self._estimate_leak_bytes(var_name, param_index)
        exploit = self._generate_format_string_exploit(var_name, param_index)

        # 置信度调整：若变量源自污点源则提升置信度
        confidence = 0.95
        evidence_chain = []
        if tainted_vars and var_name in tainted_vars:
            confidence = min(confidence * 1.05, 1.0)
            evidence_chain.append(f"污点源: {var_name} 来自用户可控输入")

        severity = self._determine_leak_severity(leakable_types, max_bytes)

        self.leak_points.append(LeakPoint(
            leak_id=leak_id, leak_type=LeakType.FORMAT_STRING,
            location=func_name, instruction=match_text, severity=severity,
            leakable_data_types=leakable_types, leakable_bytes=max_bytes,
            parameter_index=param_index, confidence=confidence,
            description=f"格式化字符串漏洞: 直接打印 '{var_name}'",
            exploit_snippet=exploit,
            evidence_chain=evidence_chain,
            raw_data={'variable': var_name, 'function': func_name}))

    def _scan_format_string_leak_points(self, func_name: str, pseudocode: str) -> None:
        for spec, dtype, default_bytes, desc in self.LEAK_FORMAT_SPECIFIERS:
            if spec in pseudocode:
                count = pseudocode.count(spec)
                leak_id = f"fmt_spec_{func_name}_{spec.replace('%','')}_{len(self.leak_points)}"
                self.leak_points.append(LeakPoint(
                    leak_id=leak_id, leak_type=LeakType.FORMAT_STRING,
                    location=func_name,
                    instruction=f"格式说明符 {spec}（出现 {count} 次）",
                    severity=Severity.MEDIUM,
                    leakable_data_types=[self._spec_to_data_type(spec)],
                    leakable_bytes=default_bytes * count, confidence=0.6,
                    description=f"{spec}: {desc}"))

    def _evaluate_format_string_leakage(self, var_name: str) -> List[str]:
        leakable_types: List[str] = []
        var_lower = var_name.lower()
        if any(x in var_lower for x in ['buf', 'input', 'user', 'data', 'str']):
            leakable_types.extend([LeakDataType.STACK_ADDRESS,
                                   LeakDataType.HEAP_ADDRESS, LeakDataType.UNKNOWN])
        if any(x in var_lower for x in ['addr', 'ptr', 'p']):
            leakable_types.extend([LeakDataType.POINTER, LeakDataType.STACK_ADDRESS,
                                   LeakDataType.HEAP_ADDRESS])
        if any(x in var_lower for x in ['canary', 'cookie']):
            leakable_types.append(LeakDataType.CANARY)
        if not leakable_types:
            leakable_types = [LeakDataType.POINTER, LeakDataType.OFFSET, LeakDataType.UNKNOWN]
        return leakable_types

    def _estimate_leak_bytes(self, var_name: str, param_index: int) -> int:
        var_lower = var_name.lower()
        if any(x in var_lower for x in ['buf', 'buffer', 'data', 'input']):
            return 1024
        if any(x in var_lower for x in ['ptr', 'addr', 'p']):
            return 8
        if 'canary' in var_lower:
            return 8
        return 64

    def _generate_format_string_exploit(self, var_name: str, param_index: int) -> str:
        lines = [
            "# 泄露栈内容:",
            'printf("%p " * 20);  // 泄露 20 个栈指针',
            'printf("%x " * 10);  // 泄露 10 个十六进制值',
            "",
            "# 定位参数偏移:",
            'printf("%p%p%p%p%p%p%p%p%p%n");  // 查找栈参数偏移',
        ]
        return "\n".join(lines)

    @staticmethod
    def _generate_format_spec_exploit(spec: str) -> str:
        return f'printf("{spec}");  // 使用 {spec} 泄露数据'

    @staticmethod
    def _determine_leak_severity(leak_types: List[str], max_bytes: int) -> str:
        critical = {LeakDataType.LIBC_ADDRESS, LeakDataType.BINARY_BASE, LeakDataType.CANARY}
        high = {LeakDataType.STACK_ADDRESS, LeakDataType.HEAP_ADDRESS, LeakDataType.POINTER}
        if any(t in critical for t in leak_types):
            return Severity.CRITICAL
        if any(t in high for t in leak_types) and max_bytes > 64:
            return Severity.HIGH
        if max_bytes > 256:
            return Severity.HIGH
        if max_bytes > 16:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _spec_to_data_type(spec: str) -> str:
        if 'p' in spec:
            return LeakDataType.POINTER
        if 's' in spec:
            return LeakDataType.UNKNOWN
        if 'x' in spec.lower():
            return LeakDataType.RANDOM_BYTES
        if 'd' in spec or 'u' in spec:
            return LeakDataType.OFFSET
        return LeakDataType.UNKNOWN

    def _analyze_crash_data_leaks(self, crash_data: Dict[str, Any]) -> None:
        logger.debug("分析崩溃数据中的地址泄露")
        if 'registers' not in crash_data:
            return
        for reg_name, reg_value in crash_data['registers'].items():
            if not isinstance(reg_value, (int, str)):
                continue
            value = int(reg_value) if isinstance(reg_value, str) else reg_value
            if 0x7fff00000000 <= value <= 0x7fffffffffff:
                self._register_address_leak(value, LeakDataType.STACK_ADDRESS,
                                           f"寄存器 {reg_name}（崩溃时）", crash_data)
            elif value > 0x10000000000:
                self._register_address_leak(value, LeakDataType.HEAP_ADDRESS,
                                           f"寄存器 {reg_name}（崩溃时）", crash_data)

    def _register_address_leak(self, address: int, address_type: str,
                               source: str, context: Dict[str, Any]) -> None:
        leak_id = f"addr_{address_type}_{len(self.leak_points)}"
        self.leak_points.append(LeakPoint(
            leak_id=leak_id,
            leak_type=LeakType.STACK_OVERFLOW_READ if address_type == LeakDataType.STACK_ADDRESS
                      else LeakType.HEAP_OVERFLOW_READ,
            location=context.get('function', 'unknown'),
            instruction=f"地址泄露 @ {hex(address)}",
            severity=Severity.HIGH, leakable_data_types=[address_type],
            leakable_bytes=8, confidence=0.8,
            description=f"从 {source} 泄露了 {address_type}",
            exploit_snippet=f"# 地址已泄露: {hex(address)}\n# 可用于 ASLR 绕过",
            raw_data={'address': hex(address), 'type': address_type, 'source': source}))

    def _analyze_memory_read_vulnerabilities(self, decomp_data: Dict[str, Any]) -> None:
        logger.debug("分析内存读取漏洞")
        dangerous = [
            (r'strcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', 'strcpy'),
            (r'memcpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', 'memcpy'),
            (r'strncpy\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)', 'strncpy'),
            (r'gets\s*\(\s*(\w+)\s*\)', 'gets'),
        ]
        for func_name, func_data in decomp_data.items():
            if not isinstance(func_data, dict):
                continue
            pseudocode = func_data.get('pseudocode', '')
            for pattern, func_call in dangerous:
                for match in re.finditer(pattern, pseudocode):
                    self._register_memory_read_leak(func_name, match.group(0),
                                                    func_call, match)

    def _register_memory_read_leak(self, func_name: str, match: str,
                                   func_call: str, match_obj: re.Match) -> None:
        leak_id = f"mem_{func_name}_{func_call}_{len(self.leak_points)}"
        leakable_types = [LeakDataType.UNKNOWN, LeakDataType.OFFSET]
        if match_obj.lastindex and match_obj.lastindex >= 2:
            src_var = match_obj.group(2)
            if any(x in src_var.lower() for x in ['buf', 'data', 'input']):
                leakable_types.append(LeakDataType.STACK_ADDRESS)
                leakable_types.append(LeakDataType.HEAP_ADDRESS)
        self.leak_points.append(LeakPoint(
            leak_id=leak_id, leak_type=LeakType.BUFFER_OVERFLOW_READ,
            location=func_name, instruction=match, severity=Severity.MEDIUM,
            leakable_data_types=leakable_types, leakable_bytes=256,
            confidence=0.5, description=f"危险调用 {func_call} 可能导致越界读取",
            exploit_snippet=f"# {func_call} 调用可能泄露相邻内存"))

    def _build_leak_capability_matrix(self) -> LeakCapabilityMatrix:
        matrix = LeakCapabilityMatrix(binary_name=self.binary_name)
        matrix.total_leak_points = len(self.leak_points)
        matrix.leak_points = self.leak_points

        for leak in self.leak_points:
            if leak.leak_type == LeakType.FORMAT_STRING:
                matrix.format_string_leaks += 1
            else:
                matrix.memory_read_leaks += 1

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

            if leak.leakable_bytes > matrix.max_leakable_bytes:
                matrix.max_leakable_bytes = leak.leakable_bytes

        if self.leak_points:
            total = sum(lp.leakable_bytes for lp in self.leak_points)
            matrix.avg_leakable_bytes = total / len(self.leak_points)

        matrix.best_leak_point = self._select_best_leak_point()
        return matrix

    def _select_best_leak_point(self) -> Optional[LeakPoint]:
        if not self.leak_points:
            return None

        def score_leak(leak: LeakPoint) -> Tuple[int, float, int]:
            sev_map = {Severity.CRITICAL: 4, Severity.HIGH: 3,
                       Severity.MEDIUM: 2, Severity.LOW: 1}
            return (sev_map.get(leak.severity, 0), leak.confidence, leak.leakable_bytes)

        sorted_leaks = sorted(self.leak_points, key=score_leak, reverse=True)
        return sorted_leaks[0] if sorted_leaks else None

    def _compute_exploit_chain_depth(self, matrix: LeakCapabilityMatrix) -> int:
        """可利用链深度：从信息泄露到代码执行的阶段数。

        阶段定义：
        1 — 仅泄露非关键数据（偏移量、随机字节等）
        2 — 泄露地址空间信息（栈/堆/基址）
        3 — 泄露基址 + 关键防护（canary/libc）
        4 — 基址 + canary + libc 三者齐备（ASLR+DEP+StackGuard 全部可绕过）
        """
        depth = 1
        addr_leaks = (matrix.can_leak_stack_address, matrix.can_leak_heap_address,
                      matrix.can_leak_binary_base)
        critical_leaks = (matrix.can_leak_libc_address, matrix.can_leak_canary)

        if any(addr_leaks):
            depth = 2
        if sum(addr_leaks) >= 2:
            depth = max(depth, 3)
        if any(addr_leaks) and any(critical_leaks):
            depth = max(depth, 3)
        if sum(addr_leaks) >= 2 and all(critical_leaks):
            depth = 4

        return depth

    def _generate_exploit_strategy(self, matrix: LeakCapabilityMatrix) -> None:
        strategies = []
        self.recommended_bad_chars = []

        chain_depth = self._compute_exploit_chain_depth(matrix)

        if matrix.can_leak_libc_address:
            strategies.append("1. 泄露 libc 地址 → 计算 system 地址 → 获取 shell")
            self.recommended_bad_chars = ['\x00', '\x0a']

        if matrix.can_leak_binary_base:
            strategies.append("2. 泄露 binary base → 定位 ROP gadgets → 构建 ROP 链")

        if matrix.can_leak_canary:
            strategies.append("3. 泄露 canary → 绕过栈保护 → 触发溢出")

        if matrix.can_leak_stack_address:
            strategies.append("4. 泄露栈地址 → 栈迁移 → 在新栈上执行 ROP")

        if matrix.format_string_leaks > 0:
            strategies.append("5. 格式化字符串泄露 → 使用 %p/%x 提取指针")

        if not strategies:
            strategies.append("未识别到有效的信息泄露路径")

        strategies.append(f"\n利用链深度评估: Lv.{chain_depth}/4")
        if chain_depth >= 4:
            strategies.append("→ 全链利用可行：ASLR/SMEP/StackGuard 均存在绕过路径")
        elif chain_depth >= 3:
            strategies.append("→ 中链利用：可绕过主要防护，需额外基址泄露完成全链")
        elif chain_depth >= 2:
            strategies.append("→ 浅链利用：地址信息已泄露，可辅助其他漏洞完成利用")

        matrix.exploit_strategy = "\n".join(strategies)
        # ROP gadget 可用性：若已泄露基址，附 gadget 搜索建议
        if matrix.can_leak_binary_base or matrix.can_leak_libc_address:
            strategies.append("")
            strategies.append("ROP Gadget 候选搜索建议:")
            strategies.append("  - pop rdi; ret   (x64 System V ABI 第一参数)")
            strategies.append("  - pop rsi; pop r15; ret   (第二参数)")
            strategies.append("  - mov qword [reg], reg; ret   (write-what-where)")
            strategies.append("  - xchg eax, esp; ret   (栈迁移 pivot)")
            strategies.append("  - syscall; ret   (直接系统调用)")
        logger.info(f"已生成利用策略 (链深度={chain_depth}):\n{matrix.exploit_strategy}")

    def detect_format_string_in_binary(self, binary_path: str) -> List[Dict[str, Any]]:
        """扫描二进制中的格式化字符串漏洞模式。需反编译数据。"""
        logger.info(f"扫描二进制中的格式化字符串漏洞: {binary_path}")
        return []  # 无伪代码时返回空 — 有意义的结果需要伪代码上下文


def analyze_info_leak(binary_path: str,
                      binary_info: Optional[Dict[str, Any]] = None,
                      decomp_data: Optional[Dict[str, Any]] = None,
                      crash_data: Optional[Dict[str, Any]] = None) -> LeakCapabilityMatrix:
    """便捷入口：对指定二进制执行完整信息泄露分析。"""
    analyzer = InfoLeakAnalyzer(binary_path=binary_path)
    return analyzer.analyze(binary_info=binary_info, decomp_data=decomp_data,
                            crash_data=crash_data)
