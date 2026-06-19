"""
GPU 内核二进制安全分析模块

功能：
1. CUDA PTX/OpenCL SPIR-V 二进制解析
2. SASS (NVIDIA GPU 汇编) 分析
3. 共享内存竞争检测
4. 全局内存越界访问检测
5. GPU 特有的漏洞模式识别

安全考虑：
- 仅用于授权的 GPU 安全研究
- 模拟执行结果可能与实际硬件行为不同
- 需考虑 GPU 架构差异

已知限制：
- 部分 GPU 架构支持有限
- 复杂的内存访问模式可能产生误报
- 符号执行在 GPU 上下文中有局限性
"""

import logging
import hashlib
import struct
import re
from abc import ABC
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class GPUArchitecture(Enum):
    """GPU 架构枚举"""
    CUDA_SM_70 = "sm_70"      # Volta
    CUDA_SM_75 = "sm_75"      # Turing
    CUDA_SM_80 = "sm_80"      # Ampere
    CUDA_SM_86 = "sm_86"      # RTX 30 series
    CUDA_SM_89 = "sm_89"      # Ada Lovelace
    OPENCL = "opencl"
    HIP = "hip"
    SPIRV = "spirv"


class VulnCategory(Enum):
    """GPU 漏洞类别"""
    SHARED_MEMORY_RACE = "shared_memory_race"
    GLOBAL_MEMORY_OOB = "global_memory_oob"
    CONSTANT_MEMORY_VIOLATION = "constant_memory_violation"
    TEXURE_MEMORY_MISUSE = "texture_memory_misuse"
    WARP_DIVERGENCE_BUG = "warp_divergence_bug"
    SYNC_BARRIER_MISUSE = "sync_barrier_misuse"
    ATOMIC_OPERATION_BUG = "atomic_operation_bug"
    REGISTER_SPILLING_RISK = "register_spilling_risk"


@dataclass
class MemoryAccess:
    """内存访问信息"""
    address_expr: str
    access_type: str  # "read", "write", "atomic"
    offset: int
    size: int
    is_bounds_checked: bool
    line_number: Optional[int] = None


@dataclass
class ThreadSynchronization:
    """线程同步点"""
    sync_type: str  # "__syncthreads", "barrier", etc.
    location: int
    thread_mask: Optional[int] = None


@dataclass
class GPUVulnerability:
    """GPU 漏洞"""
    vuln_category: VulnCategory
    severity: float  # 0.0 - 10.0
    confidence: float  # 0.0 - 1.0
    location: int
    description: str
    affected_threads: List[int] = field(default_factory=list)
    memory_access: Optional[MemoryAccess] = None
    sync_point: Optional[ThreadSynchronization] = None
    recommendation: str = ""


@dataclass
class KernelInfo:
    """GPU 内核信息"""
    name: str
    architecture: GPUArchitecture
    binary_path: str
    entry_point: int
    shared_memory_size: int
    local_memory_size: int
    registers_per_thread: int
    grid_dim: Optional[Tuple[int, int, int]] = None
    block_dim: Optional[Tuple[int, int, int]] = None
    functions: List[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    """分析报告"""
    kernel_info: KernelInfo
    vulnerabilities: List[GPUVulnerability]
    total_issues: int
    high_severity_count: int
    medium_severity_count: int
    low_severity_count: int
    analysis_time: float
    warnings: List[str] = field(default_factory=list)


class PTXParser:
    """PTX (Parallel Thread Execution) 汇编解析器"""
    
    # PTX 指令模式
    LD_GLOBAL = re.compile(r'\bld\.global\.[bcsui]\d*')
    ST_GLOBAL = re.compile(r'\bst\.global\.[bcsui]\d*')
    LD_SHARED = re.compile(r'\bld\.shared\.[bcsui]\d*')
    ST_SHARED = re.compile(r'\bst\.shared\.[bcsui]\d*')
    LD_CONST = re.compile(r'\bld\.const\.[bcsui]\d*')
    LD_LOCAL = re.compile(r'\bld\.local\.[bcsui]\d*')
    ST_LOCAL = re.compile(r'\bst\.local\.[bcsui]\d*')
    ATOMIC_GLOBAL = re.compile(r'\batom\.[\w\.]+')
    SYNC_THREADS = re.compile(r'\bsync\.threads?')
    BARRIER = re.compile(r'\bbar\.')
    VOTE = re.compile(r'\bvote\.[\w\.]+')
    SHFL = re.compile(r'\bshfl\.[\w\.]+')
    WARP_SPECIAL = re.compile(r'\b(?:ballot|match|any|all)\.')
    BRANCH = re.compile(r'\b(bra|br|call)\b')
    
    def __init__(self, ptx_content: str):
        self.content = ptx_content
        self.lines = ptx_content.split('\n')
        self.functions = []
        self.kernels = []
        self.constants = {}
        self.shared_memory_declarations = []
        self._parse()
    
    def _parse(self):
        """解析PTX文件结构"""
        current_func = None
        
        for line_num, line in enumerate(self.lines, 1):
            line = line.strip()
            
            if not line or line.startswith('//'):
                continue
            
            # 解析版本信息
            version_match = re.match(r'\.version\s+(\d+\.\d+)', line)
            if version_match:
                self.ptx_version = version_match.group(1)
                continue
            
            # 解析目标架构
            target_match = re.match(r'\.target\s+(\w+)', line)
            if target_match:
                self.target_arch = target_match.group(1)
                continue
            
            # 解析内核定义
            kernel_match = re.match(r'\.entry\s+(\w+)', line)
            if kernel_match:
                current_func = {
                    'name': kernel_match.group(1),
                    'type': 'kernel',
                    'start_line': line_num,
                    'end_line': line_num,
                    'params': [],
                    'memory_accesses': [],
                    'sync_points': [],
                    'shared_memory_size': 0
                }
                self.kernels.append(current_func)
                continue
            
            # 解析函数定义
            func_match = re.match(r'\.func\s+(?:\(\))?\s*(\w+)', line)
            if func_match:
                current_func = {
                    'name': func_match.group(1),
                    'type': 'function',
                    'start_line': line_num,
                    'end_line': line_num,
                    'params': [],
                    'memory_accesses': [],
                    'sync_points': []
                }
                self.functions.append(current_func)
                continue
            
            # 解析共享内存声明
            shared_match = re.match(r'\.shared\s+(\w+)\s+(\w+)\[(\d+)\]', line)
            if shared_match:
                decl = {
                    'type': shared_match.group(1),
                    'name': shared_match.group(2),
                    'size': int(shared_match.group(3)),
                    'line_number': line_num
                }
                self.shared_memory_declarations.append(decl)
                if current_func:
                    current_func['shared_memory_size'] += int(shared_match.group(3

                continue
            
            # 解析常量
            const_match = re.match(r'\.const\s+(\w+)\s+(\w+)\s*=\s*(.+)', line)
            if const_match:
                self.constants[const_match.group(2)] = {
                    'type': const_match.group(1),
                    'value': const_match.group(3),
                    'line_number': line_num
                }
                continue
            
            # 更新函数结束位置
            if current_func:
                current_func['end_line'] = line_num

    def parse_memory_accesses(self) -> List[MemoryAccess]:
        """解析所有内存访问指令"""
        accesses = []
        for line_num, line in enumerate(self.lines, 1):
            line = line.strip()

            # 解析全局内存加载
            match = self.LD_GLOBAL.search(line)
            if match:
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="read",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=self._has_bounds_check(line),
                    line_number=line_num
                


            # 解析全局内存存储
            match_st = self.ST_GLOBAL.search(line)
            if match_st:
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="write",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=self._has_bounds_check(line),
                    line_number=line_num
                


            # 解析共享内存访问
            elif self.LD_SHARED.search(line):
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="read",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=True,
                    line_number=line_num
                

            elif self.ST_SHARED.search(line):
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="write",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=True,
                    line_number=line_num
                

            
            # 解析常量内存访问
            elif self.LD_CONST.search(line):
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="read",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=True,
                    line_number=line_num
                

            
            # 解析局部内存访问
            elif self.LD_LOCAL.search(line):
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="read",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=True,
                    line_number=line_num
                

            elif self.ST_LOCAL.search(line):
                accesses.append(MemoryAccess(
                    address_expr=line,
                    access_type="write",
                    offset=0,
                    size=self._extract_size(line),
                    is_bounds_checked=True,
                    line_number=line_num
                


        return accesses

    def _extract_size(self, line: str) -> int:
        """提取访问大小"""
        size_match = re.search(r'\.f?(\d+)', line)
        if size_match:
            return int(size_match.group(1)) // 8
        return 4

    def _has_bounds_check(self, line: str) -> bool:
        """检查是否有边界检查"""
        return any(pattern in line.lower( for pattern in ['cmp', 'setp', 'min.', 'max.', 'and', 'slt', 'sgt']))

    def parse_sync_points(self) -> List[ThreadSynchronization]:
        """解析同步点"""
        syncs = []
        for line_num, line in enumerate(self.lines, 1):
            line = line.strip()
            if self.SYNC_THREADS.search(line):
                syncs.append(ThreadSynchronization(
                    sync_type="__syncthreads",
                    location=line_num
                

            elif self.BARRIER.search(line):
                syncs.append(ThreadSynchronization(
                    sync_type="barrier",
                    location=line_num
                

            elif self.VOTE.search(line):
                syncs.append(ThreadSynchronization(
                    sync_type="vote",
                    location=line_num
                

        return syncs
    
    def get_kernels(self) -> List[Dict[str, Any]]:
        """获取内核列表"""
        return self.kernels
    
    def get_constants(self) -> Dict[str, Any]:
        """获取常量列表"""
        return self.constants
    
    def get_shared_memory_declarations(self) -> List[Dict[str, Any]]:
        """获取共享内存声明"""
        return self.shared_memory_declarations
    
    def detect_shared_memory_conflicts(self) -> List[Dict[str, Any]]:
        """检测共享内存冲突"""
        conflicts = []
        for kernel in self.kernels:
            for i in range(len(self.lines) - 1):
                line1 = self.lines[i]
                line2 = self.lines[i + 1]
                if (self.ST_SHARED.search(line1) and self.LD_SHARED.search(line2)) or \
                   (self.LD_SHARED.search(line1) and self.ST_SHARED.search(line2)):
                    conflicts.append({)
                        'kernel': kernel.get('name', 'unknown'),
                        'line_start': i + 1,
                        'line_end': i + 2,
                        'type': 'potential_data_race',
                        'description': "Potential shared memory race condition"
                    }
        return conflicts
    
    def detect_out_of_bounds(self) -> List[Dict[str, Any]]:
        """检测潜在的越界访问"""
        issues = []
        for line_num, line in enumerate(self.lines, 1):
            if self.LD_GLOBAL.search(line) or self.ST_GLOBAL.search(line):
                if not self._has_bounds_check(line):
                    if any(pattern in line for pattern in ['tid', 'ctaid', 'blockIdx', 'threadIdx']):
                        issues.append({)
                            'line_number': line_num,
                            'type': 'potential_oob',
                            'instruction': line.strip(),
                            'description': "Potential out-of-bounds access without bounds checking"
                        }
        return issues
    
    def detect_warp_divergence(self) -> List[Dict[str, Any]]:
        """检测warp分歧问题"""
        issues = []
        for line_num, line in enumerate(self.lines, 1):
            if self.BRANCH.search(line):
                issues.append({)
                    'line_number': line_num,
                    'type': 'potential_warp_divergence',
                    'instruction': line.strip(),
                    'description': "Branch instruction may cause warp divergence"
                }
        return issues


class SASSAnalyzer:
    """NVIDIA SASS (Shader Assembly) 汇编分析器"""
    
    # SASS 操作码模式
    LOAD_INSTRUCTION = re.compile(r'LDS\.|LDL\.|STL\.|STS\.')
    ATOMIC_INSTRUCTION = re.compile(r'ATOM\.|RED\.|GRED\.')
    BAR_INSTRUCTION = re.compile(r'BAR\.|EXIT')
    
    def __init__(self, sass_binary: bytes):
        self.binary = sass_binary
    
    def analyze(self) -> List[GPUVulnerability]:
        """分析 SASS 二进制"""
        vulns = []
        
        # 简化的模式匹配
        # 实际实现需要更复杂的反汇编逻辑
        offset = 0,
        while offset < len(self.binary) - 8:
            instruction = self.binary[offset:offset + 8]
            
            # 检测 LDS/STS (shared memory) 操作
            if self._is_load_store(instruction):
                if not self._has_sync_barrier_before(offset):
                    vulns.append(GPUVulnerability(
                        vuln_category=VulnCategory.SHARED_MEMORY_RACE,
                        severity=7.5,
                        confidence=0.6,
                        location=offset,
                        description="Shared memory access without preceding barrier",
                        recommendation="Add __syncthreads() before shared memory access"
                    

            
            offset += 8
        
        return vulns
    
    def _is_load_store(self, instruction: bytes) -> bool:
        """检查是否为加载/存储指令"""
        # 简化实现
        return instruction[0] in (0xfe, 0xfd, 0xfc)
    
    def _has_sync_barrier_before(self, offset: int) -> bool:
        """检查是否在访问前有同步屏障"""
        # 简化实现
        return True


class CUBINParser:
    """CUDA 二进制 (CUBIN) 解析器"""
    
    MAGIC = b'\xca\xfe\xba\xbe'
    
    def __init__(self, cubin_data: bytes):
        self.data = cubin_data
        self.header = self._parse_header()
    
    def _parse_header(self) -> Optional[Dict[str, Any]]:
        """解析 CUBIN 头"""
        if len(self.data) < 16:
            return None
        
        if self.data[:4] != self.MAGIC:
            return None
        
        return {
            "magic": self.data[:4],
            "version": struct.unpack_from('<I', self.data, 4)[0],
            "kernel_count": struct.unpack_from('<I', self.data, 8)[0]
        }
    
    def extract_kernels(self) -> List[Dict[str, Any]]:
        """提取内核信息"""
        if not self.header:
            return []
        
        kernels = []
        # 简化的内核提取
        # 实际实现需要解析 ELF-like 结构
        return kernels


class DataRaceDetector:
    """数据竞争检测器"""
    
    def __init__(self):
        self.access_graph: Dict[str, List[MemoryAccess]] = {}
    
    def detect_races(, self, accesses: List[MemoryAccess], syncs: List[ThreadSynchronization]) -> List[GPUVulnerability]:
        """
        检测数据竞争
        
        Args:
            accesses: 内存访问列表
            syncs: 同步点列表
        
        Returns:
            发现的竞争条件
        """
        races = []
        
        # 构建访问图
        for access in accesses:
            if access.address_expr not in self.access_graph:
                self.access_graph[access.address_expr] = []
            self.access_graph[access.address_expr].append(access)
        
        # 检测同一地址的竞争性访问
        for addr, addr_accesses in self.access_graph.items():
            write_accesses = [a for a in addr_accesses if a.access_type == "write"]
            read_accesses = [a for a in addr_accesses if a.access_type == "read"]
            
            if write_accesses and read_accesses:
                # 检查是否有同步点分隔
                has_sync = self._check_sync_between(write_accesses, read_accesses, syncs)
                
                if not has_sync:
                    races.append(GPUVulnerability(
                        vuln_category=VulnCategory.SHARED_MEMORY_RACE,
                        severity=8.0,
                        confidence=0.75,
                        location=write_accesses[0].line_number or 0,
                        description=f"Potential data race on address {addr}",
                        affected_threads=[0, 1],  # 简化
                        memory_access=write_accesses[0],
                        recommendation="Add __syncthreads() to synchronize thread access"
                    

        
        return races
    
    def _check_sync_between(, self, accesses1: List[MemoryAccess], accesses2: List[MemoryAccess], syncs: List[ThreadSynchronization]) -> bool:
        """检查两次访问之间是否有同步点"""
        # 简化实现
        return False


class GPUKernelAnalyzer(BaseAnalyzer, ABC):
    """
    GPU 内核二进制安全分析器
    
    配置示例 (YAML):
        gpu_analyzer:
          enabled: true
          architectures:
            - sm_80
            - sm_86
          check_shared_memory: true
          check_global_memory: true
          check_atomics: true
          race_detection: true
    
    用法示例:
        analyzer = GPUKernelAnalyzer()
        result = analyzer.analyze()
            binary_path="/path/to/kernel.cubin",
            output_format="json"
        
    """
    
    def __init__(, self, config: Optional[Dict[str, Any]] = None, target_architecture: Optional[GPUArchitecture] = None):
        """
        初始化 GPU 内核分析器
        
        Args:
            config: 配置字典
            target_architecture: 目标 GPU 架构
        """
        self._config = config or self._default_config()
        self._target_arch = target_architecture or GPUArchitecture.CUDA_SM_80
        self._setup_logging()
        
        # 子组件
        self._race_detector = DataRaceDetector()
        
        # 分析结果缓存
        self._analysis_cache: Dict[str, AnalysisReport] = {}
    
    def _default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            "enabled": True,
            "architectures": ["sm_70", "sm_75", "sm_80", "sm_86", "sm_89"],
            "check_shared_memory": True,
            "check_global_memory": True,
            "check_constant_memory": True,
            "check_atomics": True,
            "race_detection": True,
            "max_vulns_per_kernel": 100,
            "confidence_threshold": 0.5
        }
    
    def _setup_logging(self) -> None:
        """配置日志"""
        self.logger = logging.getLogger(__name__)
        if LOGURU_AVAILABLE:
            self.logger = loguru_logger
        
        arch = self._target_arch.value if self._target_arch else "unknown"
        self.logger.info(f"GPUKernelAnalyzer initialized for {arch}")
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行 GPU 内核安全分析
        
        Args:
            **kwargs: 关键字参数
                - binary_path: GPU 二进制路径 (.cubin, .ptx)
                - source_code: 可选的 PTX/OpenCL 源代码
                - architecture: 目标架构
                - output_format: 输出格式 (json, text)
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path")
        source_code = kwargs.get("source_code")
        architecture = kwargs.get("architecture")
        output_format = kwargs.get("output_format", "json")
        
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}
        
        import time
        start_time = time.time()
        
        try:
            # 确定架构
            target_arch = self._resolve_architecture(architecture, binary_path)
            
            # 解析二进制
            kernel_info = self._parse_binary(binary_path, source_code, target_arch)
            
            # 执行分析
            vulnerabilities = self._analyze_kernel(kernel_info, source_code)
            
            # 过滤低置信度结果
            vulnerabilities = self._filter_by_confidence(vulnerabilities)
            
            # 生成报告
            analysis_time = time.time() - start_time
            report = AnalysisReport()
                kernel_info=kernel_info,
                vulnerabilities=vulnerabilities,
                total_issues=len(vulnerabilities),
                high_severity_count=sum(1 for v in vulnerabilities if v.severity >= 7.0),
                medium_severity_count=sum(1 for v in vulnerabilities if 4.0 <= v.severity < 7.0),
                low_severity_count=sum(1 for v in vulnerabilities if v.severity < 4.0),
                analysis_time=analysis_time
            
            
            if output_format == "json":
                return {
                    "success": True,
                    "report": self._serialize_report(report)
                }
            else:
                return {
                    "success": True,
                    "report": self._format_text_report(report)
                }
                
        except FileNotFoundError:
            self.logger.error(f"Binary file not found: {binary_path}")
            return {"success": False, "error": f"文件不存在: {binary_path}"}
        except Exception as e:
            self.logger.error(f"GPU kernel analysis failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _resolve_architecture(, self, architecture: Optional[str], binary_path: Optional[str]) -> GPUArchitecture:
        """解析目标架构"""
        if architecture:
            try:
                return GPUArchitecture[architecture.upper(.replace('-', '_')])
            except KeyError:
                self.logger.warning(f"Unknown architecture {architecture}, using default")
        
        # 从文件扩展名推断
        if binary_path:
            if binary_path.endswith('.cubin'):
                return GPUArchitecture.CUDA_SM_80  # 默认
            elif binary_path.endswith('.ptx'):
                return GPUArchitecture.CUDA_SM_70
            elif binary_path.endswith('.cl') or binary_path.endswith('.oclc'):
                return GPUArchitecture.OPENCL
            elif binary_path.endswith('.spv'):
                return GPUArchitecture.SPIRV
        
        return self._target_arch
    
    def _parse_binary(, self, binary_path: str, source_code: Optional[str], architecture: GPUArchitecture) -> KernelInfo:
        """解析 GPU 二进制"""
        kernel_info = KernelInfo()
            name="unknown_kernel",
            architecture=architecture,
            binary_path=binary_path,
            entry_point=0,
            shared_memory_size=0,
            local_memory_size=0,
            registers_per_thread=0,
            functions=[]
        
        
        # 读取文件
        if binary_path and source_code is None:
            try:
                with open(binary_path, "rb") as f:
                    data = f.read()
                
                if architecture == GPUArchitecture.CUDA_SM_80:
                    cubin = CUBINParser(data)
                    if cubin.header:
                        kernel_info.name = "parsed_kernel"
                else:
                    # 尝试作为 PTX 文本解析
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        if '.visible' in text or '.entry' in text:
                            kernel_info.name = self._extract_kernel_name(text)
                            kernel_info.functions = self._extract_functions(text)
                    except Exception as e:
                        self.logger.debug(f"Could not parse as text: {e}")
                        
            except Exception as e:
                self.logger.error(f"Failed to read binary: {e}")
        
        # 如果有源代码
        if source_code:
            kernel_info.name = self._extract_kernel_name(source_code)
            kernel_info.functions = self._extract_functions(source_code)
        
        return kernel_info
    
    def _extract_kernel_name(self, content: str) -> str:
        """提取内核名称"""
        # 匹配 .entry 或 __global__ 或 kernel 关键字
        patterns = [
            r'\.entry\s+(\w+)',
            r'__global__\s+void\s+(\w+)',
            r'__kernel\s+void\s+(\w+)',
            r'kernel\s+void\s+(\w+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1)
        
        return "unknown_kernel"
    
    def _extract_functions(self, content: str) -> List[str]:
        """提取函数列表"""
        functions = []
        
        # PTX 函数
        for match in re.finditer(r'\.func\s+(\w+)', content):
            functions.append(match.group(1

        
        # OpenCL/CUDA 函数
        for match in re.finditer(r'(?:void|int|float|double)\s+(\w+)\s*\(', content):
            if match.group(1) not in functions:
                functions.append(match.group(1

        
        return functions
    
    def _analyze_kernel(, self, kernel_info: KernelInfo, source_code: Optional[str]) -> List[GPUVulnerability]:
        """分析内核"""
        vulns: List[GPUVulnerability] = []
        
        # 1. 解析源代码（如有）
        if source_code:
            vulns.extend(self._analyze_source(source_code

        
        # 2. 分析二进制
        if kernel_info.binary_path:
            vulns.extend(self._analyze_binary(kernel_info.binary_path

        
        # 3. 通用 GPU 漏洞检测
        vulns.extend(self._check_common_gpu_issues(kernel_info

        
        return vulns
    
    def _analyze_source(self, source_code: str) -> List[GPUVulnerability]:
        """分析源代码"""
        vulns = []
        
        if self._config.get("check_shared_memory", True):
            vulns.extend(self._check_shared_memory_issues(source_code

        
        if self._config.get("check_global_memory", True):
            vulns.extend(self._check_global_memory_issues(source_code

        
        if self._config.get("race_detection", True):
            vulns.extend(self._check_data_races(source_code

        
        return vulns
    
    def _check_shared_memory_issues(self, source_code: str) -> List[GPUVulnerability]:
        """检查共享内存问题"""
        vulns = []
        
        # 检测共享内存bank冲突
        if 'shared' in source_code.lower():
            # 简化的检测
            vulns.append(GPUVulnerability(
                vuln_category=VulnCategory.SHARED_MEMORY_RACE,
                severity=5.5,
                confidence=0.5,
                location=0,
                description="Shared memory usage detected - verify proper synchronization",
                recommendation="Ensure __syncthreads() is called after all shared memory modifications"
            

        
        return vulns
    
    def _check_global_memory_issues(self, source_code: str) -> List[GPUVulnerability]:
        """检查全局内存问题"""
        vulns = []
        
        # 检测可能的越界访问
        if 'ld.global' in source_code or 'st.global' in source_code:
            # 检查是否有边界检查
            if not any(pattern in source_code for pattern in ['cmp', 'setp', 'min', 'max']):
                vulns.append(GPUVulnerability(
                    vuln_category=VulnCategory.GLOBAL_MEMORY_OOB,
                    severity=7.0,
                    confidence=0.6,
                    location=0,
                    description="Global memory access without obvious bounds checking",
                    recommendation="Add bounds validation before global memory access"
                

        
        return vulns
    
    def _check_data_races(self, source_code: str) -> List[GPUVulnerability]:
        """检查数据竞争"""
        vulns = []
        
        # 解析内存访问和同步点
        if 'ld.shared' in source_code or 'st.shared' in source_code:
            if 'sync' not in source_code.lower() and 'barrier' not in source_code.lower():
                vulns.append(GPUVulnerability(
                    vuln_category=VulnCategory.SHARED_MEMORY_RACE,
                    severity=8.0,
                    confidence=0.7,
                    location=0,
                    description="Shared memory access pattern may cause data race",
                    recommendation="Add synchronization primitives to ensure thread safety"
                

        
        return vulns
    
    def _analyze_binary(self, binary_path: str) -> List[GPUVulnerability]:
        """分析二进制"""
        vulns = []
        
        try:
            with open(binary_path, "rb") as f:
                data = f.read()
            
            # 尝试解析为 CUBIN
            if binary_path.endswith('.cubin'):
                cubin = CUBINParser(data)
                if cubin.header:
                    sass = SASSAnalyzer(data)
                    vulns.extend(sass.analyze(

            
            # 检查特定字节模式
            vulns.extend(self._scan_binary_patterns(data

            
        except Exception as e:
            self.logger.error(f"Binary analysis failed: {e}")
        
        return vulns
    
    def _scan_binary_patterns(self, data: bytes) -> List[GPUVulnerability]:
        """扫描二进制中的特定模式"""
        vulns = []
        
        # 检测可能的不安全模式
        # 例如：连续的无同步全局内存写入
        # 这是一个简化实现
        
        return vulns
    
    def _check_common_gpu_issues(self, kernel_info: KernelInfo) -> List[GPUVulnerability]:
        """检查通用 GPU 问题"""
        vulns = []
        
        # 检查寄存器溢出风险
        if kernel_info.registers_per_thread > 64:
            vulns.append(GPUVulnerability(
                vuln_category=VulnCategory.REGISTER_SPILLING_RISK,
                severity=4.0,
                confidence=0.6,
                location=0,
                description=f"High register usage ({kernel_info.registers_per_thread}) may cause register spilling",
                recommendation="Reduce register usage or use -maxrregcount compiler option"
            

        
        return vulns
    
    def _filter_by_confidence(, self, vulnerabilities: List[GPUVulnerability]) -> List[GPUVulnerability]:
        """按置信度过滤"""
        threshold = self._config.get("confidence_threshold", 0.5)
        max_vulns = self._config.get("max_vulns_per_kernel", 100)
        
        filtered = [v for v in vulnerabilities if v.confidence >= threshold]
        filtered.sort(key=lambda v: v.severity, reverse=True)
        
        return filtered[:max_vulns]
    
    def _serialize_report(self, report: AnalysisReport) -> Dict[str, Any]:
        """序列化报告为 JSON 格式"""
        return {
            "kernel_name": report.kernel_info.name,
            "architecture": report.kernel_info.architecture.value,
            "total_issues": report.total_issues,
            "high_severity": report.high_severity_count,
            "medium_severity": report.medium_severity_count,
            "low_severity": report.low_severity_count,
            "analysis_time_seconds": round(report.analysis_time, 3),
            "vulnerabilities": [
                {
                    "category": v.vuln_category.value,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "location": hex(v.location) if v.location else "unknown",
                    "description": v.description,
                    "recommendation": v.recommendation
                }
                for v in report.vulnerabilities
            ],
            "warnings": report.warnings
        }
    
    def _format_text_report(self, report: AnalysisReport) -> str:
        """格式化文本报告"""
        lines = [
            f"GPU Kernel Security Analysis Report",
            f"{'=' * 50}",
            f"Kernel: {report.kernel_info.name}",
            f"Architecture: {report.kernel_info.architecture.value}",
            f"Total Issues: {report.total_issues}",
            f"  High Severity: {report.high_severity_count}",
            f"  Medium Severity: {report.medium_severity_count}",
            f"  Low Severity: {report.low_severity_count}",
            f"Analysis Time: {report.analysis_time:.3f}s",
            f"",
            f"Vulnerabilities:"
        ]
        
        for i, v in enumerate(report.vulnerabilities, 1):
            lines.append(f"  [{i}] {v.vuln_category.value}")
            lines.append(f"      Severity: {v.severity}/10, Confidence: {v.confidence:.0%}")
            lines.append(f"      Location: {hex(v.location) if v.location else 'unknown'}")
            lines.append(f"      {v.description}")
            lines.append(f"      Recommendation: {v.recommendation}")
        
        return "\n".join(lines)
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        binary_path = kwargs.get("binary_path")
        source_code = kwargs.get("source_code")
        
        if not binary_path and not source_code:
            return False, "必须提供 binary_path 或 source_code"
        
        if binary_path:
            import os
            if not os.path.exists(binary_path):
                return False, f"文件不存在: {binary_path}"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        self._analysis_cache.clear()
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="GPUKernelAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="GPU 内核二进制安全分析器，支持 CUDA/OpenCL/ROCm 平台",
            author="BinaryAnalysisPlatform",
            dependencies=["loguru"],
            supported_platforms=["x86_64", "aarch64"],
            config_schema={
                "enabled": {"type": "bool", "default": True},
                "architectures": {
                    "type": "list",
                    "default": ["sm_70", "sm_75", "sm_80", "sm_86", "sm_89"]
                },
                "check_shared_memory": {"type": "bool", "default": True},
                "check_global_memory": {"type": "bool", "default": True},
                "race_detection": {"type": "bool", "default": True},
                "confidence_threshold": {"type": "float", "default": 0.5}
            }))))))))))))))))))))))))))))))))))))))))))))))))