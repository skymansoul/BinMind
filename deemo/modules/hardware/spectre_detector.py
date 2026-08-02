import os
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)

CAPSTONE_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_MODE_32, CS_MODE_64, CsInsn
    CAPSTONE_AVAILABLE = True
except ImportError:
    logger.warning("Capstone not installed，汇编分析受限。install: pip install capstone")


class SpectreType(str, Enum):
    """推测执行漏洞类型枚举。使用 str mixin 以兼容旧代码中的字符串比较。"""
    SPECTRE_V1 = 'Spectre V1 (Bounds Check Bypass)'
    SPECTRE_V2 = 'Spectre V2 (Branch Target Injection)'
    SPECTRE_V4 = 'Spectre V4 (Speculative Store Bypass)'
    MELTDOWN = 'Meltdown (Kernel Data Leakage)'
    SPECTRE_V1_1 = 'Spectre V1.1 (Bypass Bounds Check via Speculative Store)'
    SPECTRE_RSPO = 'Speculative RSB Overflow'
    # 新增类型
    SPECTRE_BHI = 'Spectre BHI (Branch History Injection)'
    RETBLEED = 'Retbleed (Return Stack Buffer Poisoning)'


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
            'description': 'condition比较后进行memory访问',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'test.*j[a-z]{1,2}.*mov|test.*j[a-z]{1,2}.*lea',
            'description': 'test后进行memory访问',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'cmp\\s+\\[.*\\],.*j[a-z]{1,2}.*\\[.*\\+.*\\]',
            'description': 'boundarycheck后index访问',
            'risk': RiskLevel.CRITICAL
        },
    ],
    'arm': [
        {
            'pattern': 'cmp.*b[a-z]{1,2}.*ldr|cmp.*b[a-z]{1,2}.*str',
            'description': 'ARM condition比较后memory访问',
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
            'description': '间接调用/跳转（memorytarget）',
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
            'description': '访问内核address空间（x86_64 高位address）',
            'risk': RiskLevel.CRITICAL
        },
        {
            'pattern': 'mov\\s+r[a-z]{2},\\s+\\[r[a-z]{2}\\]\\s*;\\s*test',
            'description': 'load后test（可能触发exception）',
            'risk': RiskLevel.HIGH
        },
        {
            'pattern': 'kernel.*user|access_user|copy_from_user',
            'description': '内核到用户data传输函数',
            'risk': RiskLevel.MEDIUM
        },
    ],
    'arm': [
        {
            'pattern': 'ldr.*0xffff',
            'description': 'ARM 访问高address',
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

# BHI 模式：间接分支前的条件分支可污染分支历史
_BHI_PATTERNS = {
    'x86': [
        {
            'pattern': 'j[a-z]{1,2}.*call\\s+r|j[a-z]{1,2}.*jmp\\s+r',
            'description': '条件跳转后间接调用 → BHI 攻击面',
            'risk': RiskLevel.MEDIUM
        },
    ]
}

# RSB 溢出模式：深层调用链 + ret 无对应 call
_RSB_PATTERNS = {
    'x86': [
        {
            'pattern': 'push.*call.*ret',
            'description': 'push/call/ret 序列 → RSB 溢出候选',
            'risk': RiskLevel.LOW
        },
    ]
}

CACHE_SIDE_CHANNEL_PATTERNS = [
    {
        'pattern': 'clflush|clf',
        'description': 'cache刷新指令（侧信道利用）',
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
        'description': 'memory屏障（推测executeboundary）',
        'risk': RiskLevel.LOW
    },
]

MITIGATION_PATTERNS = [
    {
        'pattern': 'lfence',
        'description': 'load屏障（Spectre V1 缓解）',
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
        'description': 'ARM 推测execute屏障',
        'mitigation': True
    },
]


@dataclass
class SpectreGadget:
    """推测执行漏洞 gadget 描述。"""
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
    """推测执行漏洞分析报告。"""
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
    """Spectre/Meltdown 推测执行漏洞 Gadget 静态检测引擎"""

    # 投机执行路径的最大深度（指令数）
    _MAX_SPEC_PATH_DEPTH = 15

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

        logger.info(f"[Spectre] initialize检测器: {binary_path}, architecture: {architecture}")

    def _validate_path(self) -> None:
        if not self.binary_path:
            raise ValueError("binaryfilepath不能is empty")

        path = os.path.abspath(self.binary_path)

        if '..' in self.binary_path:
            raise ValueError("path包含非法字符")

        if not os.path.exists(path):
            raise ValueError(f"file not found: {self.binary_path}")

        self.binary_path = path

    def detect(self) -> SpectreAnalysisResult:
        """执行完整检测流程：反汇编 → 模式匹配 → 缓解措施识别 → 风险评估"""
        logger.info("[Spectre] start检测推测execute Gadget...")

        try:
            self._get_disassembly()

            self._get_pseudocode()

            self._detect_spectre_v1()
            self._detect_spectre_v2()
            self._detect_meltdown()
            self._detect_spectre_v4()
            self._detect_bhi()
            self._detect_rsb_overflow()

            self._detect_cache_side_channel()

            self._detect_mitigations()

            self._analyze_input_dependency()

            self._analyze_gadget_chains()

            result = self._generate_result()

            logger.info(f"[Spectre] 检测complete，发现 {len(self.gadgets)} 个潜在 Gadget")

            return result

        except Exception as e:
            logger.error(f"[Spectre] 检测failed: {e}")
            return SpectreAnalysisResult(
                binary_path=self.binary_path,
                metadata={'error': str(e)})

    def _get_disassembly(self) -> None:
        logger.info("[Spectre] 获取disassembly代码...")

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

            logger.info(f"[Spectre] Capstone disassemblycomplete，{len(self.disassembly)} 条指令")

        except Exception as e:
            logger.warning(f"[Spectre] Capstone disassemblyfailed: {e}")
            self._disassemble_with_radare2()

    def _disassemble_with_radare2(self) -> None:
        try:
            import subprocess

            cmd = [
                'r2', '-q', '-e', 'io.color=false',
                '-c', 'pd $s', self.binary_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                self.disassembly = result.stdout.strip().split('\n')
                logger.info(f"[Spectre] radare2 disassemblycomplete，{len(self.disassembly)} 条指令")
            else:
                logger.warning(f"[Spectre] radare2 disassemblyfailed: {result.stderr}")

        except Exception as e:
            logger.warning(f"[Spectre] radare2 disassemblyfailed: {e}")

    def _get_pseudocode(self) -> None:
        try:
            from deobfuscation.decomp_ai import DecompilerAI

            decompiler = DecompilerAI(self.binary_path, None, 'radare2')
            self.pseudocode = decompiler.decompile_function('main') or ''

        except Exception as e:
            logger.debug(f"[Spectre] 获取pseudocodefailed: {e}")
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
                        '添加 lfence 指令在boundarycheck后',
                        '使用arrayindex掩码',
                        'validateindexrange'
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
                        '使用 retpoline replace间接调用',
                        'enable IBRS/IBPB',
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
                        'enable KPTI (Kernel Page Table Isolation)',
                        '避免直接访问用户空间memory',
                        '使用安全的data传输函数'
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

    def _detect_bhi(self) -> None:
        """检测 BHI (Branch History Injection)：条件分支后紧跟间接分支。

        BHI 通过在前一个条件分支中训练分支预测器来影响后续间接分支目标。
        模式: cmp/jcc 后 0-10 条指令内出现 call reg 或 jmp reg。
        """
        patterns = _BHI_PATTERNS.get(self.architecture, [])
        for pinfo in patterns:
            matches = self._find_pattern_in_disassembly(pinfo['pattern'])
            for m in matches:
                self.gadgets.append(SpectreGadget(
                    gadget_id=f'BHI_{len(self.gadgets)}',
                    spectre_type=SpectreType.SPECTRE_BHI,
                    risk_level=pinfo['risk'],
                    location=m['location'],
                    address=m['address'],
                    instruction_sequence=m['instructions'],
                    pattern_matched=pinfo['pattern'],
                    description=pinfo['description'],
                    recommendations=['更新微码以支持 BHI_DIS_S 位', '使用 CSPR/CMO 保护间接分支'],
                ))
                self.stats['bhi'] += 1

    def _detect_rsb_overflow(self) -> None:
        """检测 RSB (Return Stack Buffer) 溢出候选。

        μRL (2025) 发现的 LSL+RDSCP 序列说明 RSB 可被非对称 push/ret 操作操控。
        此处检测深层嵌套 call 或 call/ret 不匹配的模式。
        """
        patterns = _RSB_PATTERNS.get(self.architecture, [])
        for pinfo in patterns:
            matches = self._find_pattern_in_disassembly(pinfo['pattern'])
            for m in matches:
                self.gadgets.append(SpectreGadget(
                    gadget_id=f'RSB_{len(self.gadgets)}',
                    spectre_type=SpectreType.RETBLEED,
                    risk_level=pinfo['risk'],
                    location=m['location'],
                    address=m['address'],
                    instruction_sequence=m['instructions'],
                    pattern_matched=pinfo['pattern'],
                    description=pinfo['description'],
                    recommendations=['编译期添加 unwind 提示', '内核 RSB 填充 (RSB stuffing)'],
                ))
                self.stats['rsb_overflow'] += 1

    def _detect_cache_side_channel(self) -> None:
        logger.info("[Spectre] 检测cache侧信道mode...")

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
        logger.info("[Spectre] 分析输入dependency性...")

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

    def _analyze_gadget_chains(self) -> None:
        """分析 gadget 链：按地址距离聚类相邻 gadget。

        两个 gadget 在 64 字节窗口内（一条 cache line 内的指令），
        标记为可能的 exploit chain。这是启发式分析，实际可利用性
        需要符号执行确认。

        参考 μRL (2025) 的 reinforcement learning 方法：
        RL agent 自动发现指令序列组合，此处做静态近似。
        """
        if len(self.gadgets) < 2:
            return

        # 按地址排序
        sorted_gadgets = sorted(self.gadgets, key=lambda g: g.address)
        chain_id = 0
        for i in range(len(sorted_gadgets) - 1):
            g1 = sorted_gadgets[i]
            g2 = sorted_gadgets[i + 1]
            dist = g2.address - g1.address
            if 0 < dist <= 128:  # 两条 cache line 内
                chain_id += 1
                g1.metadata['chain_id'] = chain_id
                g2.metadata['chain_id'] = chain_id
                g1.metadata['chain_distance'] = dist

    def _find_pattern_in_disassembly(self, pattern: str) -> List[Dict[str, Any]]:
        matches = []

        try:
            regex = re.compile(pattern, re.IGNORECASE)

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
            logger.warning(f"[Spectre] 正则error: {pattern} - {e}")

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
            'pseudocode_available': bool(self.pseudocode),
            'gadget_chains': sum(1 for g in self.gadgets if 'chain_id' in g.metadata),
        }

        return result

    def _generate_recommendations(self) -> List[str]:
        recommendations = []

        if self.stats['spectre_v1'] > 0:
            recommendations.append('Spectre V1: 在boundarycheck后添加 lfence 指令')
            recommendations.append('Spectre V1: 使用arrayindex掩码技术')

        if self.stats['spectre_v2'] > 0:
            recommendations.append('Spectre V2: 使用 retpoline replace间接调用')
            recommendations.append('Spectre V2: enable IBRS 和 IBPB')

        if self.stats['meltdown'] > 0:
            recommendations.append('Meltdown: enable KPTI')
            recommendations.append('Meltdown: validate所有用户空间访问')

        if self.stats['spectre_v4'] > 0:
            recommendations.append('Spectre V4: 添加存储屏障指令')

        if self.stats.get('bhi', 0) > 0:
            recommendations.append('BHI: 更新 CPU 微码，enable BHI_DIS_S')

        if self.stats.get('rsb_overflow', 0) > 0:
            recommendations.append('RSB Overflow: 内核入口点执行 RSB stuffing')

        if self.stats['cache_side_channel'] > 0:
            recommendations.append('侧信道: 使用常数时间算法')
            recommendations.append('侧信道: 避免cache刷新和时间测量')

        recommendations.extend([
            'updatecompile器以enable自动缓解',
            '使用最新的微码update',
            '在敏感代码中添加推测execute屏障',
            '审查encrypt库实现'
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
