#!/usr/bin/env python3
"""
侧信道 Gadget 静态检测模块（Spectre/Meltdown 类）

功能：
1. Spectre V1 (Bounds Check Bypass) 检测：条件分支 → 数组访问模式
2. Spectre V2 (Branch Target Injection) 检测：间接跳转/调用分析
3. Meltdown 检测：内核访问用户空间内存
4. Spectre V4 (Speculative Store Bypass) 检测
5. 利用静态污点分析辅助判断输入来源
6. 输出可疑 gadget 列表，包含位置、类型、风险评级

依赖：现有反编译和模式匹配，无额外库
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

# Capstone 可用性检查
CAPSTONE_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_32, CS_MODE_64, CsInsn
    CAPSTONE_AVAILABLE = True
except ImportError:
    logger.warning("Capstone 未安装，汇编分析受限。安装: pip install capstone")


# ==================== 常量定义 ====================

class SpectreType(Enum):
    """推测执行漏洞类型"""
    SPECTRE_V1 = 'Spectre V1 (Bounds Check Bypass)'
    SPECTRE_V2 = 'Spectre V2 (Branch Target Injection)'
    SPECTRE_V4 = 'Spectre V4 (Speculative Store Bypass)'
    MELTDOWN = 'Meltdown (Kernel Data Leakage)'
    SPECTRE_V1_1 = 'Spectre V1.1 (Bypass Bounds Check via Speculative Store)'
    SPECTRE_RSPO = 'Speculative RSB Overflow'


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = 'Critical'
    HIGH = 'High'
    MEDIUM = 'Medium'
    LOW = 'Low'
    INFO = 'Info'


# Spectre V1 模式：条件分支后访问数组
SPECTRE_V1_PATTERNS = {
    'x86': [
        # cmp + jcc + mov/load pattern
        {
            'pattern': 'cmp.*j[a-z]{1,2}.*mov|cmp.*j[a-z]{1,2}.*lea',
            'description': '条件比较后进行内存访问',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'test.*j[a-z]{1,2}.*mov|test.*j[a-z]{1,2}.*lea',
            'description': '测试后进行内存访问',
            'risk': RiskLevel.HIGH
        },
        # 数组边界检查绕过
        {
            'pattern': 'cmp\\s+\\[.*\\],.*j[a-z]{1,2}.*\\[.*\\+.*\\]',
            'description': '边界检查后索引访问',
            'risk': RiskLevel.CRITICAL
        },
    ],
    'arm': [
        {
            'pattern': 'cmp.*b[a-z]{1,2}.*ldr|cmp.*b[a-z]{1,2}.*str',
            'description': 'ARM 条件比较后内存访问',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'subs.*b[a-z]{1,2}.*ldr',
            'description': 'ARM 减法比较后加载',
            'risk': RiskLevel.HIGH
        },
    ]
}

# Spectre V2 模式：间接跳转/调用
SPECTRE_V2_PATTERNS = {
    'x86': [
        {
            'pattern': 'call\\s+r[a-z]{2}|jmp\\s+r[a-z]{2}',
            'description': '间接调用/跳转（寄存器目标）',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'call\\s+\\[.*\\]|jmp\\s+\\[.*\\]',
            'description': '间接调用/跳转（内存目标）',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'ret',
            'description': '返回指令（可能被 RSB 操控）',
            'risk': RiskLevel.MEDIUM
        },
    ],
    'arm': [
        {
            'pattern': 'blx\\s+r[a-z]{2}|bx\\s+r[a-z]{2}',
            'description': 'ARM 间接跳转',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'blr',
            'description': 'ARM64 间接调用',
            'risk': RiskLevel.HIGH
        },
    ]
}

# Meltdown 模式：内核访问用户空间
MELTDOWN_PATTERNS = {
    'x86': [
        {
            'pattern': 'mov\\s+\\[0xffff[0-9a-fA-F]+\\]',
            'description': '访问内核地址空间（x86_64 高位地址）',
            'risk': RiskLevel.CRITICAL
        },
        {
            'pattern': 'mov\\s+r[a-z]{2},\\s+\\[r[a-z]{2}\\]\\s*;\\s*test',
            'description': '加载后测试（可能触发异常）',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'kernel.*user|access_user|copy_from_user',
            'description': '内核到用户数据传输函数',
            'risk': RiskLevel.MEDIUM
        },
    ],
    'arm': [
        {
            'pattern': 'ldr.*0xffff',
            'description': 'ARM 访问高地址',
            'risk': RiskLevel.CRITICAL
        },
    ]
}

# Spectre V4 模式：推测存储绕过
SPECTRE_V4_PATTERNS = {
    'x86': [
        {
            'pattern': 'mov\\s+\\[.*\\],.*mov\\s+.*\\[.*\\]',
            'description': '存储后立即加载（可能绕过）',
            'risk': RiskLevel.MEDIUM
        },
        {
            'pattern': 'str.*ldr',
            'description': '存储-加载序列',
            'risk': RiskLevel.MEDIUM
        },
    ],
    'arm': [
        {
            'pattern': 'str.*ldr',
            'description': 'ARM 存储-加载序列',
            'risk': RiskLevel.MEDIUM
        },
    ]
}

# 缓存侧信道利用模式
CACHE_SIDE_CHANNEL_PATTERNS = [
    {
        'pattern': 'clflush|clf',
        'description': '缓存刷新指令（侧信道利用）',
        'risk': RiskLevel.HIGH
    },
    {
        'pattern': 'prefetch',
        'description': '预取指令（可能用于探测）',
        'risk': RiskLevel.MEDIUM
    },
    {
        'pattern': 'rdtsc|rdtscp',
        'description': '时间戳计数器（计时攻击）',
        'risk': RiskLevel.HIGH
    },
    {
        'pattern': 'mfence|lfence|sfence',
        'description': '内存屏障（推测执行边界）',
        'risk': RiskLevel.LOW
    },
]

# 安全缓解指令
MITIGATION_PATTERNS = [
    {
        'pattern': 'lfence',
        'description': '加载屏障（Spectre V1 缓解）',
        'mitigation': True
    },
    {
        'pattern': 'retpoline',
        'description': 'Retpoline（Spectre V2 缓解）',
        'mitigation': True
    },
    {
        'pattern': 'endbr64|endbr32',
        'description': '间接分支跟踪（Intel CET）',
        'mitigation': True
    },
    {
        'pattern': 'csdb|ssbb',
        'description': 'ARM 推测执行屏障',
        'mitigation': True
    },
]


@dataclass
class SpectreGadget:
    """推测执行 Gadget 数据类"""
    gadget_id: str = ''
    spectre_type: SpectreType = SpectreType.SPECTRE_V1
    risk_level: RiskLevel = RiskLevel.MEDIUM
    location: str = ''
    address: int = 0
    instruction_sequence: List[str] = field(default_factory=list)
    pattern_matched: str = ''
    description: str = ''
    input_dependency: bool = False
    user_input_source: Optional[str] = None
    exploitability: str = 'Unknown'
    mitigations_present: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpectreAnalysisResult:
    """Spectre 分析结果数据类"""
    binary_path: str = ''
    architecture: str = ''
    total_gadgets: int = 0
    critical_gadgets: int = 0
    high_gadgets: int = 0
    medium_gadgets: int = 0
    gadgets: List[SpectreGadget] = field(default_factory=list)
    mitigations_found: List[str] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.LOW
    recommendations: List[str] = field(default_factory=list)
    analysis_time: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)


class SpectreGadgetDetector:
    """
    Spectre/Meltdown Gadget 静态检测器
    
    功能：
    - 检测推测执行漏洞 gadget
    - 模式匹配汇编代码
    - 风险评估
    - 生成缓解建议
    
    Attributes:
        binary_path: 二进制文件路径
        architecture: 目标架构
        gadgets: 检测到的 gadget 列表
    """
    
    def __init__(, self)
        binary_path: str,
        architecture: str = 'x86',
        use_capstone: bool = True,
        detect_all_types: bool = True
    ):
        """
        初始化 Spectre Gadget 检测器
        
        Args:
            binary_path: 二进制文件路径
            architecture: 架构类型 ('x86', 'arm', 'arm64')
            use_capstone: 是否使用 Capstone 反汇编
            detect_all_types: 是否检测所有漏洞类型
        """
        self.binary_path = binary_path
        self.architecture = architecture.lower()
        self.use_capstone = use_capstone and CAPSTONE_AVAILABLE
        self.detect_all_types = detect_all_types
        
        self.gadgets: List[SpectreGadget] = []
        self.mitigations_found: List[str] = []
        self.disassembly: List[str] = []
        self.pseudocode: str = ''
        
        # 统计
        self.stats: Dict[str, int] = defaultdict(int)
        
        # 验证路径
        self._validate_path()
        
        logger.info(f"[Spectre] 初始化检测器: {binary_path}, 架构: {architecture}")
    
    def _validate_path(self) -> None:
        """
        验证二进制文件路径
        """
        if not self.binary_path:
            raise ValueError("二进制文件路径不能为空")
        
        path = os.path.abspath(self.binary_path)
        
        if '..' in self.binary_path:
            raise ValueError("路径包含非法字符")
        
        if not os.path.exists(path):
            raise ValueError(f"文件不存在: {self.binary_path}")
        
        self.binary_path = path
    
    def detect(self) -> SpectreAnalysisResult:
        """
        执行完整的 Spectre Gadget 检测
        
        Returns:
            SpectreAnalysisResult 分析结果
        """
        logger.info("[Spectre] 开始检测推测执行 Gadget...")
        
        try:
            # 1. 获取反汇编代码
            self._get_disassembly()
            
            # 2. 获取伪代码（可选）
            self._get_pseudocode()
            
            # 3. 检测各类型 Gadget
            self._detect_spectre_v1()
            self._detect_spectre_v2()
            self._detect_meltdown()
            self._detect_spectre_v4()
            
            # 4. 检测缓存侧信道模式
            self._detect_cache_side_channel()
            
            # 5. 检测缓解措施
            self._detect_mitigations()
            
            # 6. 分析输入依赖
            self._analyze_input_dependency()
            
            # 7. 生成报告
            result = self._generate_result()
            
            logger.info(f"[Spectre] 检测完成，发现 {len(self.gadgets)} 个潜在 Gadget")
            
            return result
            
        except Exception as e:
            logger.error(f"[Spectre] 检测失败: {e}")
            return SpectreAnalysisResult(
                binary_path=self.binary_path,
                metadata={'error': str(e)})
            

    
    def _get_disassembly(self) -> None:
        """
        获取二进制反汇编代码
        
        使用 Capstone 或 radare2
        """
        logger.info("[Spectre] 获取反汇编代码...")
        
        if self.use_capstone:
            self._disassemble_with_capstone()
        else:
            self._disassemble_with_radare2()
    
    def _disassemble_with_capstone(self) -> None:
        """
        使用 Capstone 反汇编
        """
        try:
            # 确定架构和模式
            if self.architecture in ['x86', 'x86_64', 'amd64']:
                arch = CS_ARCH_X86
                mode = CS_MODE_64 if '64' in self.architecture else CS_MODE_32
            elif self.architecture in ['arm', 'arm64', 'aarch64']:
                arch = CS_ARCH_ARM
                mode = CS_MODE_32  # ARM64 需要单独处理
            else:
                arch = CS_ARCH_X86
                mode = CS_MODE_64
            
            # 读取二进制
            with open(self.binary_path, 'rb') as f:
                code = f.read()
            
            # 创建反汇编器
            md = Cs(arch, mode)
            md.detail = True
            
            # 反汇编
            for insn in md.disasm(code, 0x1000):
                self.disassembly.append(f'{hex(insn.address)}: {insn.mnemonic} {insn.op_str}')
            
            logger.info(f"[Spectre] Capstone 反汇编完成，{len(self.disassembly)} 条指令")
            
        except Exception as e:
            logger.warning(f"[Spectre] Capstone 反汇编失败: {e}")
            self._disassemble_with_radare2()
    
    def _disassemble_with_radare2(self) -> None:
        """
        使用 radare2 反汇编
        """
        try:
            import subprocess
            from config import Config
            
            cmd = [
                'r2', '-q', '-e', 'io.color=false',
                '-c', 'pd $s', self.binary_path
            ]
            
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            
            
            if result.returncode == 0:
                self.disassembly = result.stdout.strip().split('\n')
                logger.info(f"[Spectre] radare2 反汇编完成，{len(self.disassembly)} 条指令")
            else:
                logger.warning(f"[Spectre] radare2 反汇编失败: {result.stderr}")
                
        except Exception as e:
            logger.warning(f"[Spectre] radare2 反汇编失败: {e}")
    
    def _get_pseudocode(self) -> None:
        """
        获取伪代码（用于辅助分析）
        """
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.binary_path, None, 'radare2')
            # 获取主函数伪代码
            self.pseudocode = decompiler.decompile_function('main') or ''
            
        except Exception as e:
            logger.debug(f"[Spectre] 获取伪代码失败: {e}")
            self.pseudocode = ''
    
    def _detect_spectre_v1(self) -> None:
        """
        检测 Spectre V1 (Bounds Check Bypass)
        
        模式：条件分支 → 数组/指针访问
        """
        logger.info("[Spectre] 检测 Spectre V1...")
        
        patterns = SPECTRE_V1_PATTERNS.get(self.architecture, SPECTRE_V1_PATTERNS['x86'])
        
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']
            
            matches = self._find_pattern_in_disassembly(pattern)
            
            for match in matches:
                gadget = SpectreGadget()
                    gadget_id=f'SV1_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_V1,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=desc,
                    recommendations=[
                        '添加 lfence 指令在边界检查后',
                        '使用数组索引掩码',
                        '验证索引范围'
                    ]
                
                
                self.gadgets.append(gadget)
                self.stats['spectre_v1'] += 1
    
    def _detect_spectre_v2(self) -> None:
        """
        检测 Spectre V2 (Branch Target Injection)
        
        模式：间接跳转/调用
        """
        logger.info("[Spectre] 检测 Spectre V2...")
        
        patterns = SPECTRE_V2_PATTERNS.get(self.architecture, SPECTRE_V2_PATTERNS['x86'])
        
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']
            
            matches = self._find_pattern_in_disassembly(pattern)
            
            for match in matches:
                gadget = SpectreGadget()
                    gadget_id=f'SV2_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_V2,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=desc,
                    recommendations=[
                        '使用 retpoline 替换间接调用',
                        '启用 IBRS/IBPB',
                        '使用 Intel CET (endbr64)'
                    ]
                
                
                self.gadgets.append(gadget)
                self.stats['spectre_v2'] += 1
    
    def _detect_meltdown(self) -> None:
        """
        检测 Meltdown
        
        模式：内核访问用户空间内存
        """
        logger.info("[Spectre] 检测 Meltdown...")
        
        patterns = MELTDOWN_PATTERNS.get(self.architecture, MELTDOWN_PATTERNS['x86'])
        
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']
            
            matches = self._find_pattern_in_disassembly(pattern)
            
            for match in matches:
                gadget = SpectreGadget()
                    gadget_id=f'MD_{len(self.gadgets)}',
                    spectre_type=SpectreType.MELTDOWN,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=desc,
                    recommendations=[
                        '启用 KPTI (Kernel Page Table Isolation)',
                        '避免直接访问用户空间内存',
                        '使用安全的数据传输函数'
                    ]
                
                
                self.gadgets.append(gadget)
                self.stats['meltdown'] += 1
    
    def _detect_spectre_v4(self) -> None:
        """
        检测 Spectre V4 (Speculative Store Bypass)
        
        模式：存储后立即加载同一地址
        """
        logger.info("[Spectre] 检测 Spectre V4...")
        
        patterns = SPECTRE_V4_PATTERNS.get(self.architecture, SPECTRE_V4_PATTERNS['x86'])
        
        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']
            
            matches = self._find_pattern_in_disassembly(pattern)
            
            for match in matches:
                gadget = SpectreGadget()
                    gadget_id=f'SV4_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_V4,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=desc,
                    recommendations=[
                        '添加 ssbb 指令（ARM）',
                        '使用 sfence 指令（x86）',
                        '避免存储-加载序列'
                    ]
                
                
                self.gadgets.append(gadget)
                self.stats['spectre_v4'] += 1
    
    def _detect_cache_side_channel(self) -> None:
        """
        检测缓存侧信道利用模式
        
        clflush, rdtsc, prefetch 等
        """
        logger.info("[Spectre] 检测缓存侧信道模式...")
        
        for pattern_info in CACHE_SIDE_CHANNEL_PATTERNS:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']
            
            matches = self._find_pattern_in_disassembly(pattern)
            
            for match in matches:
                gadget = SpectreGadget()
                    gadget_id=f'CSC_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_V1,  # 侧信道是 Spectre 的一部分
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=f'缓存侧信道利用: {desc}',
                    recommendations=[
                        '避免使用缓存刷新指令',
                        '使用常数时间算法',
                        '添加随机延迟'
                    ]
                
                
                self.gadgets.append(gadget)
                self.stats['cache_side_channel'] += 1
    
    def _detect_mitigations(self) -> None:
        """
        检测已存在的缓解措施
        """
        logger.info("[Spectre] 检测缓解措施...")
        
        for pattern_info in MITIGATION_PATTERNS:
            pattern = pattern_info['pattern']
            desc = pattern_info['description']
            
            matches = self._find_pattern_in_disassembly(pattern)
            
            if matches:
                self.mitigations_found.append(desc)
                logger.info(f"[Spectre] 发现缓解措施: {desc}")
    
    def _analyze_input_dependency(self) -> None:
        """
        分析 Gadget 的输入依赖性
        
        判断条件是否依赖用户可控输入
        """
        logger.info("[Spectre] 分析输入依赖性...")
        
        # 使用伪代码辅助分析
        user_input_patterns = [
            'input', 'read', 'recv', 'get', 'user', 'param', 'arg',
            'buffer', 'data', 'request', 'packet'
        ]
        
        for gadget in self.gadgets:
            # 检查伪代码中是否有用户输入相关变量
            if self.pseudocode:
                for pattern in user_input_patterns:
                    if pattern.lower() in self.pseudocode.lower():
                        # 检查 gadget 位置附近的代码
                        gadget.input_dependency = True
                        gadget.user_input_source = pattern
                        break
            
            # 基于指令序列判断
            for insn in gadget.instruction_sequence:
                if any(p in insn.lower() for p in user_input_patterns):
                    gadget.input_dependency = True
                    break
    
    def _find_pattern_in_disassembly(self, pattern: str) -> List[Dict[str, Any]]:
        """
        在反汇编代码中查找模式
        
        Args:
            pattern: 正则表达式模式
            
        Returns:
            匹配结果列表
        """
        matches = []
        
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            
            # 搜索多行模式（3条指令窗口）
            for i in range(len(self.disassembly) - 2):
                window = '\n'.join(self.disassembly[i:i+3])
                
                if regex.search(window):
                    # 提取地址
                    first_line = self.disassembly[i]
                    addr_match = re.match(r'([0x]?[0-9a-fA-F]+):', first_line)
                    address = int(addr_match.group(1), 16) if addr_match else i
                    
                    matches.append({)
                        'location': f'Line {i}',
                        'address': address,
                        'instructions': self.disassembly[i:i+3],
                        'context': window
                    }
            
        except re.error as e:
            logger.warning(f"[Spectre] 正则错误: {pattern} - {e}")
        
        return matches
    
    def _generate_result(self) -> SpectreAnalysisResult:
        """
        生成分析结果
        
        Returns:
            SpectreAnalysisResult
        """
        result = SpectreAnalysisResult()
        
        result.binary_path = self.binary_path
        result.architecture = self.architecture
        result.total_gadgets = len(self.gadgets)
        result.gadgets = self.gadgets
        result.mitigations_found = self.mitigations_found
        result.analysis_time = datetime.now().isoformat()
        
        # 统计风险等级
        result.critical_gadgets = len([g for g in self.gadgets if g.risk_level == RiskLevel.CRITICAL])
        result.high_gadgets = len([g for g in self.gadgets if g.risk_level == RiskLevel.HIGH])
        result.medium_gadgets = len([g for g in self.gadgets if g.risk_level == RiskLevel.MEDIUM])
        
        # 确定整体风险
        if result.critical_gadgets > 0:
            result.overall_risk = RiskLevel.CRITICAL
        elif result.high_gadgets > 0:
            result.overall_risk = RiskLevel.HIGH
        elif result.medium_gadgets > 0:
            result.overall_risk = RiskLevel.MEDIUM
        else:
            result.overall_risk = RiskLevel.LOW
        
        # 生成建议
        result.recommendations = self._generate_recommendations()
        
        # 元数据
        result.metadata = {
            'stats': dict(self.stats),
            'disassembly_lines': len(self.disassembly),
            'pseudocode_available': bool(self.pseudocode)
        }
        
        return result
    
    def _generate_recommendations(self) -> List[str]:
        """
        生成安全建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 基于检测到的漏洞类型
        if self.stats['spectre_v1'] > 0:
            recommendations.append('Spectre V1: 在边界检查后添加 lfence 指令')
            recommendations.append('Spectre V1: 使用数组索引掩码技术')
        
        if self.stats['spectre_v2'] > 0:
            recommendations.append('Spectre V2: 使用 retpoline 替换间接调用')
            recommendations.append('Spectre V2: 启用 IBRS 和 IBPB')
        
        if self.stats['meltdown'] > 0:
            recommendations.append('Meltdown: 启用 KPTI')
            recommendations.append('Meltdown: 验证所有用户空间访问')
        
        if self.stats['spectre_v4'] > 0:
            recommendations.append('Spectre V4: 添加存储屏障指令')
        
        if self.stats['cache_side_channel'] > 0:
            recommendations.append('侧信道: 使用常数时间算法')
            recommendations.append('侧信道: 避免缓存刷新和时间测量')
        
        # 通用建议
        recommendations.extend([)
            '更新编译器以启用自动缓解',
            '使用最新的微码更新',
            '在敏感代码中添加推测执行屏障',
            '审查加密库实现'
        ]
        
        return recommendations


def detect_spectre_gadgets(, binary_path: str, architecture: str = 'x86') -> SpectreAnalysisResult:
    """
    检测 Spectre Gadget 的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        architecture: 架构类型
        
    Returns:
        SpectreAnalysisResult
    """
    detector = SpectreGadgetDetector()
        binary_path=binary_path,
        architecture=architecture
    
    
    return detector.detect()


# ==================== 导出 ====================

__all__ = [
    'SpectreGadgetDetector',
    'SpectreGadget',
    'SpectreAnalysisResult',
    'SpectreType',
    'RiskLevel',
    'detect_spectre_gadgets',
    'CAPSTONE_AVAILABLE',
    'SPECTRE_V1_PATTERNS',
    'SPECTRE_V2_PATTERNS',
    'MELTDOWN_PATTERNS',
    'SPECTRE_V4_PATTERNS'
]