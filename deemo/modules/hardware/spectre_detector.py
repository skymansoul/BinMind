import os
import re
import logging
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)

CAPSTONE_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_32, CS_MODE_64, CsInsn
    CAPSTONE_AVAILABLE = True
except ImportError:
    logger.warning("Capstone 未安装，汇编分析受限。安装: pip install capstone")


class SpectreType(str, Enum):
    """Spectre/Meltdown 变体类型。str 基类保证与内部字符串常量兼容比较。"""
    SPECTRE_V1 = 'Spectre V1 (Bounds Check Bypass)'
    SPECTRE_V2 = 'Spectre V2 (Branch Target Injection)'
    SPECTRE_V4 = 'Spectre V4 (Speculative Store Bypass)'
    MELTDOWN = 'Meltdown (Kernel Data Leakage)'
    SPECTRE_V1_1 = 'Spectre V1.1 (Bypass Bounds Check via Speculative Store)'
    SPECTRE_RSPO = 'Speculative RSB Overflow'


class RiskLevel(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
SPECTRE_V1_PATTERNS = {
    'x86': [
        {
            'pattern': 'cmp.*j[a-z]{1,2}.*mov|cmp.*j[a-z]{1,2}.*lea',
            'description': '条件比较后进行内存访问',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'test.*j[a-z]{1,2}.*mov|test.*j[a-z]{1,2}.*lea',
            'description': 'test 后进行内存访问',
            'risk': RiskLevel.HIGH
        },
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
            'description': 'ARM 减法比较后load',
            'risk': RiskLevel.HIGH
        },
    ]
}

SPECTRE_V2_PATTERNS = {
    'x86': [
        {
            'pattern': 'call\\s+r[a-z]{2}|jmp\\s+r[a-z]{2}',
            'description': '间接调用/跳转（寄存器target）',
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

MELTDOWN_PATTERNS = {
    'x86': [
        {
            'pattern': 'mov\\s+\\[0xffff[0-9a-fA-F]+\\]',
            'description': '访问内核地址空间（x86_64 高位地址）',
            'risk': RiskLevel.CRITICAL
        },
        {
            'pattern': 'mov\\s+r[a-z]{2},\\s+\\[r[a-z]{2}\\]\\s*;\\s*test',
            'description': 'load 后 test（可能触发异常）',
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

SPECTRE_V4_PATTERNS = {
    'x86': [
        {
            'pattern': 'mov\\s+\\[.*\\],.*mov\\s+.*\\[.*\\]',
            'description': '存储后立即load（可能绕过）',
            'risk': RiskLevel.MEDIUM
        },
        {
            'pattern': 'str.*ldr',
            'description': '存储-load序列',
            'risk': RiskLevel.MEDIUM
        },
    ],
    'arm': [
        {
            'pattern': 'str.*ldr',
            'description': 'ARM 存储-load序列',
            'risk': RiskLevel.MEDIUM
        },
    ]
}

CACHE_SIDE_CHANNEL_PATTERNS = [
    {
        'pattern': 'clflush',
        'description': 'cache刷新指令（侧信道利用）',
        'risk': RiskLevel.HIGH
    },
    {
        'pattern': 'prefetch',
        'description': '预取指令（可能用于探测）',
        'risk': RiskLevel.MEDIUM
    },
    {
        'pattern': 'rdtsc',
        'description': '时间戳计数器（计时攻击）',
        'risk': RiskLevel.HIGH
    },
    {
        'pattern': 'mfence|lfence|sfence',
        'description': '内存屏障（推测执行边界）',
        'risk': RiskLevel.LOW
    },
]

MITIGATION_PATTERNS = [
    {
        'pattern': 'lfence',
        'description': 'load 屏障（Spectre V1 缓解）',
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
    gadget_id: str = ''
    spectre_type: str = SpectreType.SPECTRE_V1
    risk_level: str = RiskLevel.MEDIUM
    location: str = ''
    address: int = 0
    instruction_sequence: list = field(default_factory=list)
    pattern_matched: str = ''
    description: str = ''
    input_dependency: bool = False
    user_input_source: Any = None
    exploitability: str = 'Unknown'
    mitigations_present: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

@dataclass
class SpectreAnalysisResult:
    binary_path: str = ''
    architecture: str = ''
    total_gadgets: int = 0
    critical_gadgets: int = 0
    high_gadgets: int = 0
    medium_gadgets: int = 0
    gadgets: list = field(default_factory=list)
    mitigations_found: list = field(default_factory=list)
    overall_risk: str = RiskLevel.LOW
    recommendations: list = field(default_factory=list)
    analysis_time: str = ''
    metadata: dict = field(default_factory=dict)

class SpectreGadgetDetector:
    """Spectre/Meltdown 推测执行漏洞 Gadget 静态检测引擎"""

    def __init__(self,
        binary_path: str,
        architecture: str = 'x86',
        use_capstone: bool = True,
        detect_all_types: bool = True
    ):
        self.binary_path = binary_path
        self.architecture = architecture.lower()
        self.use_capstone = use_capstone and CAPSTONE_AVAILABLE
        self.detect_all_types = detect_all_types

        self.gadgets: List[SpectreGadget] = []
        self.mitigations_found: List[str] = []
        self.disassembly: List[str] = []
        self.pseudocode: str = ''

        self.stats: Dict[str, int] = defaultdict(int)

        self._validate_path()

        logger.info(f"[Spectre] 初始化检测器: {binary_path}, architecture: {architecture}")

    def _validate_path(self) -> None:
        if not self.binary_path:
            raise ValueError("二进制文件路径不能为空")

        path = os.path.abspath(self.binary_path)

        if '..' in self.binary_path:
            raise ValueError("路径包含非法字符")

        if not os.path.exists(path):
            raise ValueError(f"file not found: {self.binary_path}")

        self.binary_path = path

    def detect(self) -> SpectreAnalysisResult:
        """执行完整检测流程：反汇编 → 模式匹配 → 缓解措施识别 → 风险评估"""
        logger.info("[Spectre] 开始检测推测执行 Gadget...")

        try:
            self._get_disassembly()

            self._get_pseudocode()

            self._detect_spectre_v1()
            self._detect_spectre_v2()
            self._detect_meltdown()
            self._detect_spectre_v4()

            self._detect_cache_side_channel()

            self._detect_mitigations()

            self._analyze_input_dependency()

            result = self._generate_result()

            logger.info(f"[Spectre] 检测完成，发现 {len(self.gadgets)} 个潜在 Gadget")

            return result

        except Exception as e:
            logger.error(f"[Spectre] 检测失败: {e}")
            return SpectreAnalysisResult(
                binary_path=self.binary_path,
                metadata={'error': str(e)})

    def _get_disassembly(self) -> None:
        logger.info("[Spectre] 获取反汇编代码...")

        if self.use_capstone:
            self._disassemble_with_capstone()
        else:
            self._disassemble_with_radare2()

    def _disassemble_with_capstone(self) -> None:
        try:
            if self.architecture in ['x86', 'x86_64', 'amd64']:
                arch = CS_ARCH_X86
                mode = CS_MODE_64 if '64' in self.architecture else CS_MODE_32
            elif self.architecture in ['arm', 'arm64', 'aarch64']:
                arch = CS_ARCH_ARM
                mode = CS_MODE_32
            else:
                arch = CS_ARCH_X86
                mode = CS_MODE_64

            with open(self.binary_path, 'rb') as f:
                code = f.read()

            md = Cs(arch, mode)
            md.detail = True

            for insn in md.disasm(code, 0x1000):
                self.disassembly.append(f'{hex(insn.address)}: {insn.mnemonic} {insn.op_str}')

            logger.info(f"[Spectre] Capstone 反汇编完成，{len(self.disassembly)} 条指令")

        except Exception as e:
            logger.warning(f"[Spectre] Capstone 反汇编失败: {e}")
            self._disassemble_with_radare2()

    def _disassemble_with_radare2(self) -> None:
        try:
            import subprocess
            from core.config import Config

            cmd = [
                'r2', '-q', '-e', 'io.color=false',
                '-c', 'pd $s', self.binary_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )

            if result.returncode == 0:
                self.disassembly = result.stdout.strip().split('\n')
                logger.info(f"[Spectre] radare2 反汇编完成，{len(self.disassembly)} 条指令")
            else:
                logger.warning(f"[Spectre] radare2 反汇编失败: {result.stderr}")

        except Exception as e:
            logger.warning(f"[Spectre] radare2 反汇编失败: {e}")

    def _get_pseudocode(self) -> None:
        try:
            from deobfuscation.decomp_ai import DecompilerAI

            decompiler = DecompilerAI(self.binary_path, None, 'radare2')
            self.pseudocode = decompiler.decompile_function('main') or ''

        except Exception as e:
            logger.debug(f"[Spectre] 获取伪代码失败: {e}")
            self.pseudocode = ''

    def _detect_spectre_v1(self) -> None:
        logger.info("[Spectre] 检测 Spectre V1...")

        patterns = SPECTRE_V1_PATTERNS.get(self.architecture, SPECTRE_V1_PATTERNS['x86'])

        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']

            matches = self._find_pattern_in_disassembly(pattern)

            for match in matches:
                gadget = SpectreGadget(
                    gadget_id=f'SV1_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_V1,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=desc,
                    recommendations=[
                        '在边界检查后添加 lfence 指令',
                        '使用数组索引掩码',
                        '校验索引范围'
                    ]
                )

                self.gadgets.append(gadget)
                self.stats['spectre_v1'] += 1

    def _detect_spectre_v2(self) -> None:
        logger.info("[Spectre] 检测 Spectre V2...")

        patterns = SPECTRE_V2_PATTERNS.get(self.architecture, SPECTRE_V2_PATTERNS['x86'])

        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']

            matches = self._find_pattern_in_disassembly(pattern)

            for match in matches:
                gadget = SpectreGadget(
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
                )

                self.gadgets.append(gadget)
                self.stats['spectre_v2'] += 1

    def _detect_meltdown(self) -> None:
        logger.info("[Spectre] 检测 Meltdown...")

        patterns = MELTDOWN_PATTERNS.get(self.architecture, MELTDOWN_PATTERNS['x86'])

        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']

            matches = self._find_pattern_in_disassembly(pattern)

            for match in matches:
                gadget = SpectreGadget(
                    gadget_id=f'MD_{len(self.gadgets)}',
                    spectre_type=SpectreType.MELTDOWN,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=desc,
                    recommendations=[
                        '启用 KPTI (内核页表隔离)',
                        '避免直接访问用户空间内存',
                        '使用安全的数据传输函数'
                    ]
                )

                self.gadgets.append(gadget)
                self.stats['meltdown'] += 1

    def _detect_spectre_v4(self) -> None:
        logger.info("[Spectre] 检测 Spectre V4...")

        patterns = SPECTRE_V4_PATTERNS.get(self.architecture, SPECTRE_V4_PATTERNS['x86'])

        for pattern_info in patterns:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']

            matches = self._find_pattern_in_disassembly(pattern)

            for match in matches:
                gadget = SpectreGadget(
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
                        '避免存储-load序列'
                    ]
                )

                self.gadgets.append(gadget)
                self.stats['spectre_v4'] += 1

    def _detect_cache_side_channel(self) -> None:
        logger.info("[Spectre] 检测 cache 侧信道模式...")

        for pattern_info in CACHE_SIDE_CHANNEL_PATTERNS:
            pattern = pattern_info['pattern']
            risk = pattern_info['risk']
            desc = pattern_info['description']

            matches = self._find_pattern_in_disassembly(pattern)

            for match in matches:
                gadget = SpectreGadget(
                    gadget_id=f'CSC_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_V1,
                    risk_level=risk,
                    location=match['location'],
                    address=match['address'],
                    instruction_sequence=match['instructions'],
                    pattern_matched=pattern,
                    description=f'cache侧信道利用: {desc}',
                    recommendations=[
                        '避免使用cache刷新指令',
                        '使用常数时间算法',
                        '添加随机delay'
                    ]
                )

                self.gadgets.append(gadget)
                self.stats['cache_side_channel'] += 1

    def _detect_mitigations(self) -> None:
        logger.info("[Spectre] 检测缓解措施...")

        for pattern_info in MITIGATION_PATTERNS:
            pattern = pattern_info['pattern']
            desc = pattern_info['description']

            matches = self._find_pattern_in_disassembly(pattern)

            if matches:
                self.mitigations_found.append(desc)
                logger.info(f"[Spectre] 发现缓解措施: {desc}")

    def _analyze_input_dependency(self) -> None:
        logger.info("[Spectre] 分析输入依赖性...")

        user_input_patterns = [
            'input', 'read', 'recv', 'get', 'user', 'param', 'arg',
            'buffer', 'data', 'request', 'packet'
        ]

        for gadget in self.gadgets:
            if self.pseudocode:
                for pattern in user_input_patterns:
                    if pattern.lower() in self.pseudocode.lower():
                        gadget.input_dependency = True
                        gadget.user_input_source = pattern
                        break

            for insn in gadget.instruction_sequence:
                if any(p in insn.lower() for p in user_input_patterns):
                    gadget.input_dependency = True
                    break

    def _find_pattern_in_disassembly(self, pattern: str) -> List[Dict[str, Any]]:
        matches = []

        try:
            regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)

            for i in range(len(self.disassembly) - 2):
                window = '\n'.join(self.disassembly[i:i+3])

                if regex.search(window):
                    first_line = self.disassembly[i]
                    addr_match = re.match(r'([0x]?[0-9a-fA-F]+):', first_line)
                    address = int(addr_match.group(1), 16) if addr_match else i

                    matches.append({
                        'location': f'Line {i}',
                        'address': address,
                        'instructions': self.disassembly[i:i+3],
                        'context': window
                    })

        except re.error as e:
            logger.warning(f"[Spectre] 正则错误: {pattern} - {e}")

        return matches

    def _generate_result(self) -> SpectreAnalysisResult:
        result = SpectreAnalysisResult()

        result.binary_path = self.binary_path
        result.architecture = self.architecture
        result.total_gadgets = len(self.gadgets)
        result.gadgets = self.gadgets
        result.mitigations_found = self.mitigations_found
        result.analysis_time = datetime.now().isoformat()

        result.critical_gadgets = len([g for g in self.gadgets if g.risk_level == RiskLevel.CRITICAL])
        result.high_gadgets = len([g for g in self.gadgets if g.risk_level == RiskLevel.HIGH])
        result.medium_gadgets = len([g for g in self.gadgets if g.risk_level == RiskLevel.MEDIUM])

        if result.critical_gadgets > 0:
            result.overall_risk = RiskLevel.CRITICAL
        elif result.high_gadgets > 0:
            result.overall_risk = RiskLevel.HIGH
        elif result.medium_gadgets > 0:
            result.overall_risk = RiskLevel.MEDIUM
        else:
            result.overall_risk = RiskLevel.LOW

        result.recommendations = self._generate_recommendations()

        result.metadata = {
            'stats': dict(self.stats),
            'disassembly_lines': len(self.disassembly),
            'pseudocode_available': bool(self.pseudocode)
        }

        return result

    def _generate_recommendations(self) -> List[str]:
        recommendations = []

        if self.stats['spectre_v1'] > 0:
            recommendations.append('Spectre V1: 在边界检查后添加 lfence 指令')
            recommendations.append('Spectre V1: 使用数组索引掩码技术')

        if self.stats['spectre_v2'] > 0:
            recommendations.append('Spectre V2: 使用 retpoline 替换间接调用')
            recommendations.append('Spectre V2: 启用 IBRS 和 IBPB')

        if self.stats['meltdown'] > 0:
            recommendations.append('Meltdown: 启用 KPTI')
            recommendations.append('Meltdown: 校验所有用户空间访问')

        if self.stats['spectre_v4'] > 0:
            recommendations.append('Spectre V4: 添加存储屏障指令')

        if self.stats['cache_side_channel'] > 0:
            recommendations.append('侧信道: 使用常数时间算法')
            recommendations.append('侧信道: 避免 cache 刷新和时间测量')

        recommendations.extend([
            '更新编译器以启用自动缓解',
            '使用最新的微码更新',
            '在敏感代码中添加推测执行屏障',
            '审查加密库实现'
        ])

        return recommendations


def detect_spectre_gadgets(binary_path: str, architecture: str = 'x86') -> SpectreAnalysisResult:
    detector = SpectreGadgetDetector(
        binary_path=binary_path,
        architecture=architecture
    )

    return detector.detect()


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
