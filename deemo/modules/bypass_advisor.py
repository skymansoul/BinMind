from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import logging

logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """保护机制类型枚举"""
    ASLR = "aslr"
    DEP = "dep"
    CFI = "cfi"
    SEH = "seh"
    PIE = "pie"
    RELRO = "relro"
    STACK_CANARY = "stack_canary"
    NX = "nx"
    SAFESEH = "safeseh"
    GS = "gs"
    SMEP = "smep"
    SMAP = "smap"
    PAC = "pac"
    RETGUARD = "retguard"
    ABI = "abi"


class BypassDifficulty(Enum):
    """绕过难度等级"""
    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    NEAR_IMPOSSIBLE = "near_impossible"


class BypassMethod(Enum):
    """绕过方法类型"""
    ROP_CHAIN = "rop_chain"
    JOP_CHAIN = "jop_chain"
    ROPLESS = "ropless"
    SHELLCODE_INJECTION = "shellcode_injection"
    RETURN_TO_LIBC = "return_to_libc"
    RETURN_TO_USER = "return_to_user"
    SIGNAL_HANDLER = "signal_handler"
    EXCEPTION_CHAIN = "exception_chain"
    INFO_LEAK = "info_leak"
    HEAP_OVERFLOW = "heap_overflow"
    FORCED_UNWIND = "forced_unwind"
    SROP = "srop"
    ORW = "orw"
    DIRECT_SYSCALL = "direct_syscall"
    GOT_OVERWRITE = "got_overwrite"
    PLT_HIJACK = "plt_hijack"
    TLS_POISONING = "tls_poisoning"
    VTABLE_HIJACK = "vtable_hijack"


@dataclass
class ProtectionInfo:
    """保护机制信息"""
    protection_type: ProtectionType
    is_enabled: bool = False
    version: Optional[str] = None
    implementation: Optional[str] = None


@dataclass
class BypassStrategy:
    """绕过策略"""
    protection: ProtectionType
    methods: List[BypassMethod] = field(default_factory=list)
    difficulty: BypassDifficulty = BypassDifficulty.MODERATE
    prerequisites: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class BypassAnalysisResult:
    """绕过分析结果"""
    target_os: str
    target_arch: str
    protections: List[ProtectionInfo] = field(default_factory=list)
    bypass_strategies: Dict[ProtectionType, BypassStrategy] = field(default_factory=dict)
    combined_strategy: List[Tuple[ProtectionType, BypassMethod]] = field(default_factory=list)
    overall_difficulty: BypassDifficulty = BypassDifficulty.MODERATE
    confidence: float = 0.0


class BypassAdvisor:
    """
    保护机制绕过策略顾问
    
    分析目标二进制的保护机制配置，提供针对性的绕过策略建议。
    支持主流保护机制：ASLR、DEP/NX、CFI、SEH、PIE、RELRO、Stack Canary等。
    """
    
    def __init__(self):
        """初始化绕过顾问"""
        self.strategy_database = self._build_strategy_database()
    
    def _build_strategy_database(self) -> Dict[ProtectionType, BypassStrategy]:
        """构建绕过策略数据库"""
        return {
            ProtectionType.ASLR: BypassStrategy(
                protection=ProtectionType.ASLR,
                methods=[BypassMethod.INFO_LEAK, BypassMethod.RETURN_TO_LIBC, BypassMethod.GOT_OVERWRITE],
                difficulty=BypassDifficulty.MODERATE,
                prerequisites=["信息泄露漏洞", "可预测的内存布局"],
                limitations=["随机化熵足够高时难以绕过"],
                recommended_tools=["ROPgadget", "pwntools", "one_gadget"],
                references=["https://en.wikipedia.org/wiki/Address_space_layout_randomization"]
            ),
            ProtectionType.DEP: BypassStrategy(
                protection=ProtectionType.DEP,
                methods=[BypassMethod.ROP_CHAIN, BypassMethod.JOP_CHAIN, BypassMethod.RETURN_TO_LIBC, BypassMethod.SROP],
                difficulty=BypassDifficulty.EASY,
                prerequisites=["存在代码执行漏洞", "有足够的ROP gadgets"],
                limitations=["CFI会限制ROP链的有效性"],
                recommended_tools=["ROPgadget", "ropper", "pwntools"],
                references=["https://en.wikipedia.org/wiki/Data_Execution_Prevention"]
            ),
            ProtectionType.CFI: BypassStrategy(
                protection=ProtectionType.CFI,
                methods=[BypassMethod.VTABLE_HIJACK, BypassMethod.TLS_POISONING, BypassMethod.ROPLESS],
                difficulty=BypassDifficulty.HARD,
                prerequisites=["找到CFI绕过漏洞", "存在类型混淆漏洞"],
                limitations=["现代CFI实现非常强大"],
                recommended_tools=["CFIExplorer", "angr", "Ghidra"],
                references=["https://clang.llvm.org/docs/ControlFlowIntegrity.html"]
            ),
            ProtectionType.STACK_CANARY: BypassStrategy(
                protection=ProtectionType.STACK_CANARY,
                methods=[BypassMethod.INFO_LEAK, BypassMethod.FORCED_UNWIND, BypassMethod.HEAP_OVERFLOW],
                difficulty=BypassDifficulty.MODERATE,
                prerequisites=["信息泄露或内存越界读"],
                limitations=["无法泄露时难以绕过"],
                recommended_tools=["pwntools", "radare2"],
                references=["https://en.wikipedia.org/wiki/Stack_canary"]
            ),
            ProtectionType.PIE: BypassStrategy(
                protection=ProtectionType.PIE,
                methods=[BypassMethod.INFO_LEAK, BypassMethod.GOT_OVERWRITE, BypassMethod.PLT_HIJACK],
                difficulty=BypassDifficulty.MODERATE,
                prerequisites=["信息泄露漏洞"],
                limitations=["全地址空间随机化"],
                recommended_tools=["pwntools", "ROPgadget"],
                references=["https://en.wikipedia.org/wiki/Position-independent_executable"]
            ),
            ProtectionType.NX: BypassStrategy(
                protection=ProtectionType.NX,
                methods=[BypassMethod.ROP_CHAIN, BypassMethod.RETURN_TO_LIBC, BypassMethod.SROP],
                difficulty=BypassDifficulty.EASY,
                prerequisites=["存在代码执行漏洞"],
                limitations=["与DEP类似"],
                recommended_tools=["ROPgadget", "ropper"],
                references=["https://en.wikipedia.org/wiki/NX_bit"]
            ),
            ProtectionType.SMEP: BypassStrategy(
                protection=ProtectionType.SMEP,
                methods=[BypassMethod.RETURN_TO_USER, BypassMethod.DIRECT_SYSCALL, BypassMethod.ORW],
                difficulty=BypassDifficulty.HARD,
                prerequisites=["内核漏洞或SMEP绕过原语"],
                limitations=["需要内核级漏洞"],
                recommended_tools=["pwntools", "kallsyms"],
                references=["https://en.wikipedia.org/wiki/Supervisor_Mode_Execution_Prevention"]
            ),
            ProtectionType.SMAP: BypassStrategy(
                protection=ProtectionType.SMAP,
                methods=[BypassMethod.RETURN_TO_USER, BypassMethod.DIRECT_SYSCALL],
                difficulty=BypassDifficulty.HARD,
                prerequisites=["内核漏洞"],
                limitations=["需要内核级漏洞"],
                recommended_tools=["pwntools", "kallsyms"],
                references=["https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention"]
            ),
            ProtectionType.PAC: BypassStrategy(
                protection=ProtectionType.PAC,
                methods=[BypassMethod.INFO_LEAK, BypassMethod.VTABLE_HIJACK],
                difficulty=BypassDifficulty.HARD,
                prerequisites=["密钥泄露或签名绕过"],
                limitations=["硬件级保护"],
                recommended_tools=["angr", "Ghidra"],
                references=["https://developer.apple.com/documentation/security/preventing_exploits_using_pointer_authentication"]
            ),
            ProtectionType.RELRO: BypassStrategy(
                protection=ProtectionType.RELRO,
                methods=[BypassMethod.GOT_OVERWRITE, BypassMethod.PLT_HIJACK],
                difficulty=BypassDifficulty.EASY,
                prerequisites=["Partial RELRO或延迟绑定"],
                limitations=["Full RELRO时难以绕过"],
                recommended_tools=["pwntools", "readelf"],
                references=["https://wiki.debian.org/Hardening"]
            ),
            ProtectionType.SEH: BypassStrategy(
                protection=ProtectionType.SEH,
                methods=[BypassMethod.EXCEPTION_CHAIN, BypassMethod.SIGNAL_HANDLER],
                difficulty=BypassDifficulty.MODERATE,
                prerequisites=["异常处理链可被控制"],
                limitations=["SafeSEH会增加难度"],
                recommended_tools=["pwntools", "mona.py"],
                references=["https://en.wikipedia.org/wiki/Structured_Exception_Handling"]
            ),
            ProtectionType.SAFESEH: BypassStrategy(
                protection=ProtectionType.SAFESEH,
                methods=[BypassMethod.SIGNAL_HANDLER, BypassMethod.FORCED_UNWIND],
                difficulty=BypassDifficulty.HARD,
                prerequisites=["找到未注册的异常处理程序"],
                limitations=["需要特定条件"],
                recommended_tools=["mona.py", "pwntools"],
                references=["https://docs.microsoft.com/en-us/windows/win32/debug/exception-handling"]
            ),
            ProtectionType.GS: BypassStrategy(
                protection=ProtectionType.GS,
                methods=[BypassMethod.INFO_LEAK, BypassMethod.FORCED_UNWIND],
                difficulty=BypassDifficulty.MODERATE,
                prerequisites=["信息泄露漏洞"],
                limitations=["无法泄露时难以绕过"],
                recommended_tools=["pwntools", "windbg"],
                references=["https://docs.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check"]
            ),
            ProtectionType.RETGUARD: BypassStrategy(
                protection=ProtectionType.RETGUARD,
                methods=[BypassMethod.INFO_LEAK, BypassMethod.VTABLE_HIJACK],
                difficulty=BypassDifficulty.HARD,
                prerequisites=["密钥泄露或特定漏洞"],
                limitations=["编译器级保护"],
                recommended_tools=["angr", "Ghidra"],
                references=["https://llvm.org/docs/RetGuard.html"]
            )
        }
    
    def analyze_protections(self, binary_data: bytes, target_os: str, target_arch: str) -> BypassAnalysisResult:
        """
        分析二进制文件的保护机制
        
        Args:
            binary_data: 二进制数据
            target_os: 目标操作系统
            target_arch: 目标架构
            
        Returns:
            绕过分析结果
        """
        logger.info(f"开始分析保护机制: OS={target_os}, Arch={target_arch}")
        
        protections = self._detect_protections(binary_data)
        strategies = self._generate_strategies(protections)
        combined_strategy = self._combine_strategies(strategies)
        overall_difficulty = self._calculate_overall_difficulty(strategies)
        
        result = BypassAnalysisResult(
            target_os=target_os,
            target_arch=target_arch,
            protections=protections,
            bypass_strategies=strategies,
            combined_strategy=combined_strategy,
            overall_difficulty=overall_difficulty,
            confidence=0.85
        )
        
        logger.info(f"保护机制分析完成: {len(protections)} 种保护机制")
        return result
    
    def _detect_protections(self, binary_data: bytes) -> List[ProtectionInfo]:
        """检测二进制文件中的保护机制"""
        protections = []
        
        if b".note.ABI-tag" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.ABI))
        
        if b"_GLOBAL_OFFSET_TABLE_" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.RELRO, is_enabled=True))
        
        if b"__stack_chk_fail" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.STACK_CANARY, is_enabled=True))
        
        if b"__RELRO" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.RELRO, is_enabled=True))
        
        if b"__PIE__" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.PIE, is_enabled=True))
        
        if b"__cfi" in binary_data.lower():
            protections.append(ProtectionInfo(protection_type=ProtectionType.CFI, is_enabled=True))
        
        if b"__safeseh" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.SAFESEH, is_enabled=True))
        
        if b"__GSHandlerCheck" in binary_data:
            protections.append(ProtectionInfo(protection_type=ProtectionType.GS, is_enabled=True))
        
        return protections
    
    def _generate_strategies(self, protections: List[ProtectionInfo]) -> Dict[ProtectionType, BypassStrategy]:
        """为检测到的保护机制生成绕过策略"""
        strategies = {}
        
        for prot in protections:
            if prot.is_enabled and prot.protection_type in self.strategy_database:
                strategies[prot.protection_type] = self.strategy_database[prot.protection_type]
        
        return strategies
    
    def _combine_strategies(self, strategies: Dict[ProtectionType, BypassStrategy]) -> List[Tuple[ProtectionType, BypassMethod]]:
        """组合多个保护机制的绕过策略"""
        combined = []
        
        for prot, strategy in strategies.items():
            if strategy.methods:
                combined.append((prot, strategy.methods[0]))
        
        return combined
    
    def _calculate_overall_difficulty(self, strategies: Dict[ProtectionType, BypassStrategy]) -> BypassDifficulty:
        """计算总体绕过难度"""
        if not strategies:
            return BypassDifficulty.TRIVIAL
        
        difficulties = [s.difficulty for s in strategies.values()]
        
        if BypassDifficulty.NEAR_IMPOSSIBLE in difficulties:
            return BypassDifficulty.NEAR_IMPOSSIBLE
        if BypassDifficulty.HARD in difficulties:
            return BypassDifficulty.HARD
        if BypassDifficulty.MODERATE in difficulties:
            return BypassDifficulty.MODERATE
        if BypassDifficulty.EASY in difficulties:
            return BypassDifficulty.EASY
        
        return BypassDifficulty.TRIVIAL
    
    def generate_report(self, result: BypassAnalysisResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 绕过分析结果
            
        Returns:
            报告字符串
        """
        report = ["=" * 60]
        report.append("保护机制绕过策略报告")
        report.append("=" * 60)
        report.append("")
        report.append(f"目标平台: {result.target_os} / {result.target_arch}")
        report.append(f"总体绕过难度: {result.overall_difficulty.value}")
        report.append(f"分析置信度: {result.confidence * 100:.1f}%")
        report.append("")
        report.append("检测到的保护机制:")
        report.append("-" * 40)
        
        for prot in result.protections:
            status = "已启用" if prot.is_enabled else "未启用"
            report.append(f"  - {prot.protection_type.value}: {status}")
        
        report.append("")
        report.append("推荐绕过策略:")
        report.append("-" * 40)
        
        for prot, strategy in result.bypass_strategies.items():
            report.append(f"{prot.value}:")
            report.append(f"  难度: {strategy.difficulty.value}")
            report.append(f"  推荐方法: {', '.join(m.value for m in strategy.methods[:3])}")
            if strategy.prerequisites:
                report.append(f"  前提条件: {', '.join(strategy.prerequisites)}")
            if strategy.recommended_tools:
                report.append(f"  推荐工具: {', '.join(strategy.recommended_tools)}")
        
        report.append("")
        report.append("综合绕过方案:")
        report.append("-" * 40)
        
        for i, (prot, method) in enumerate(result.combined_strategy, 1):
            report.append(f"{i}. {prot.value} -> {method.value}")
        
        return "\n".join(report)
    
    def save_result(self, result: BypassAnalysisResult, filename: str):
        """
        保存结果到文件
        
        Args:
            result: 绕过分析结果
            filename: 输出文件名
        """
        report = self.generate_report(result)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"结果已保存到 {filename}")