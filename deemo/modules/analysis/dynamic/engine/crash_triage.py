# 崩溃分类与可利用性评估 —— 微软.exploitable 方法论
# 设计思路：基于崩溃特征（寄存器状态、栈帧、异常码）打分判定可利用性
# 每条规则带 confidence，综合评估并给出缓解

import re
import hashlib
import logging
import os
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

_log = logging.getLogger(__name__)


# 枚举

class CrashType(Enum):
    ACCESS_VIOLATION = auto()
    NULL_DEREFERENCE = auto()
    SIGABRT = auto()
    ILLEGAL_INSTRUCTION = auto()
    SIGBUS = auto()
    FP_EXCEPTION = auto()
    INTEGER_DIVIDE_BY_ZERO = auto()
    STACK_OVERFLOW = auto()
    HEAP_CORRUPTION = auto()
    DOUBLE_FREE = auto()
    USE_AFTER_FREE = auto()
    ASSERTION_FAILURE = auto()
    PRIVILEGED_INSTRUCTION = auto()
    ASSERT_FAILURE = auto()
    UNKNOWN = auto()


class ExploitabilityRating(Enum):
    EXPLOITABLE = auto()
    PROBABLY_EXPLOITABLE = auto()
    PROBABLY_NOT_EXPLOITABLE = auto()
    NOT_EXPLOITABLE = auto()
    UNKNOWN = auto()


@dataclass
class ExploitabilityAssessment:
    rating: ExploitabilityRating = ExploitabilityRating.UNKNOWN
    confidence: float = 0.0
    ruling_reasons: List[str] = field(default_factory=list)
    is_controlled_branch: bool = False
    is_dep_bypass_possible: bool = False
    is_aslr_bypass_possible: bool = False
    mitigations: List[str] = field(default_factory=list)


@dataclass
class CrashInfo:
    crash_type: CrashType = CrashType.UNKNOWN
    fault_address: int = 0
    crash_address: int = 0
    exception_code: Any = 0
    faulting_instruction: str = ""
    registers: Dict[str, int] = field(default_factory=dict)
    call_stack: List[str] = field(default_factory=list)
    stack_trace: List[Dict[str, Any]] = field(default_factory=list)
    instruction_bytes: bytes = b""
    modules: List[str] = field(default_factory=list)
    thread_id: int = 0
    process_name: str = ""


# 崩溃类型映射

_SIGNAL_TO_CRASH_TYPE = {
    11: CrashType.ACCESS_VIOLATION,    # SIGSEGV
    4: CrashType.ILLEGAL_INSTRUCTION,  # SIGILL
    6: CrashType.SIGABRT,
    7: CrashType.SIGBUS,
    8: CrashType.FP_EXCEPTION,         # SIGFPE
}

_WINDOWS_EXCEPTION_TO_CRASH_TYPE = {
    'c0000005': CrashType.ACCESS_VIOLATION,
    'c00000fd': CrashType.STACK_OVERFLOW,
    'c0000094': CrashType.INTEGER_DIVIDE_BY_ZERO,
    'c0000096': CrashType.PRIVILEGED_INSTRUCTION,
    'c0000008': CrashType.NULL_DEREFERENCE,  # INVALID_HANDLE 兜底
}


class CrashClassifier:

    @classmethod
    def from_signal(cls, signal: int, fault_addr: int = 0) -> CrashType:
        if signal == 11:
            if fault_addr == 0:
                return CrashType.NULL_DEREFERENCE
            return CrashType.ACCESS_VIOLATION
        return _SIGNAL_TO_CRASH_TYPE.get(signal, CrashType.UNKNOWN)

    @classmethod
    def from_windows_exception(cls, code: str) -> CrashType:
        return _WINDOWS_EXCEPTION_TO_CRASH_TYPE.get(
            code.lower().replace('0x', ''), CrashType.UNKNOWN)

    @classmethod
    def from_crash_info(cls, crash_info: CrashInfo) -> CrashType:
        if crash_info.crash_type is not CrashType.UNKNOWN:
            return crash_info.crash_type
        if isinstance(crash_info.exception_code, str):
            mapped = cls.from_windows_exception(crash_info.exception_code)
            if mapped is not CrashType.UNKNOWN:
                return mapped
        return CrashType.UNKNOWN

    @staticmethod
    def _controlled_branch(registers: Dict[str, int]) -> bool:
        eip = registers.get("rip") or registers.get("eip")
        if eip is None:
            return False
        # 常见填充模式
        patterns = [0x41414141, 0x42424242, 0x43434343, 0x44444444,
                    0x90909090, 0xCCCCCCCC, 0xCDCDCDCD, 0xFEEEFEEE,
                    0xABABABAB, 0xDDDDDDDD, 0xFDFDFDFD]
        for p in patterns:
            if eip == p or (eip & 0xFFFFFFFF) == p:
                return True
            if eip == (p | (p << 32)):
                return True
        if 0x20202020 <= (eip & 0xFFFFFFFF) <= 0x7E7E7E7E:
            return True
        # 检查 EIP 是否不在任何加载模块范围内 (粗略)
        return False

    @staticmethod
    def _check_near_null(addr: int) -> bool:
        """地址是否在 NULL 页面范围内 (< 0x1000)"""
        return addr < 0x1000

    @staticmethod
    def _check_stack_pivot(registers: Dict[str, int]) -> bool:
        """检查 ESP/RSP 是否指向堆区域 (非栈)"""
        rsp = registers.get("rsp", None) or registers.get("esp", None)
        if rsp is None:
            return False
        # 启发式: 栈通常在 0x7ff* 范围 (Windows) 或 0x7fff* (Linux)
        # 如果 RSP < 0x100000 或 > 0x800000000000，可能是 pivot
        if rsp < 0x100000 and rsp > 0x1000:
            return True
        # 检查是否在其他 page 类型的地址
        if rsp > 0x100000000000:
            return False  # 可能是正常高地址
        return False

    @staticmethod
    def _exception_code_name(code: int) -> str:
        codes = {
            0xC0000005: "ACCESS_VIOLATION",
            0xC0000017: "NO_MEMORY",
            0xC000001D: "ILLEGAL_INSTRUCTION",
            0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
            0xC000008D: "FLOAT_DENORMAL_OPERAND",
            0xC000008E: "FLOAT_DIVIDE_BY_ZERO",
            0xC000008F: "FLOAT_INEXACT_RESULT",
            0xC0000090: "FLOAT_INVALID_OPERATION",
            0xC0000091: "FLOAT_OVERFLOW",
            0xC0000092: "FLOAT_STACK_CHECK",
            0xC0000093: "FLOAT_UNDERFLOW",
            0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
            0xC0000095: "INTEGER_OVERFLOW",
            0xC0000096: "PRIVILEGED_INSTRUCTION",
            0xC00000FD: "STACK_OVERFLOW",
            0x80000003: "BREAKPOINT",
            0x80000004: "SINGLE_STEP",
        }
        return codes.get(code, f"UNKNOWN(0x{code:08X})")


# 崩溃分析器

class CrashAnalyzer:

    _RATING_BY_TYPE = {
        CrashType.ASSERTION_FAILURE: ExploitabilityRating.NOT_EXPLOITABLE,
        CrashType.SIGABRT: ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE,
        CrashType.INTEGER_DIVIDE_BY_ZERO: ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE,
        CrashType.NULL_DEREFERENCE: ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE,
        CrashType.HEAP_CORRUPTION: ExploitabilityRating.EXPLOITABLE,
        CrashType.DOUBLE_FREE: ExploitabilityRating.EXPLOITABLE,
        CrashType.USE_AFTER_FREE: ExploitabilityRating.EXPLOITABLE,
        CrashType.PRIVILEGED_INSTRUCTION: ExploitabilityRating.PROBABLY_EXPLOITABLE,
    }

    def __init__(self, crash_info: Optional[CrashInfo] = None,
                 binary_path: Optional[str] = None):
        self.crash_info = crash_info
        self.binary_path = binary_path
        self._classifier = CrashClassifier()

    def assess_exploitability(self, crash_info: Optional[CrashInfo] = None) -> ExploitabilityAssessment:
        ci = crash_info or self.crash_info
        if ci is None:
            return ExploitabilityAssessment()

        crash_type = CrashClassifier.from_crash_info(ci)
        assessment = ExploitabilityAssessment()

        if crash_type is CrashType.ILLEGAL_INSTRUCTION:
            if 'ud2' in (ci.faulting_instruction or "").lower() \
                    or (ci.instruction_bytes and ci.instruction_bytes[0] == 0xCC):
                assessment.rating = ExploitabilityRating.NOT_EXPLOITABLE
                assessment.confidence = 0.10
                assessment.ruling_reasons.append("UD2/INT3 通常由断言或反调试触发")
                return assessment

        if crash_type is CrashType.ACCESS_VIOLATION:
            controlled = CrashClassifier._controlled_branch(ci.registers)
            assessment.is_controlled_branch = controlled
            if controlled:
                assessment.rating = ExploitabilityRating.EXPLOITABLE
                assessment.confidence = 0.85
                assessment.ruling_reasons.append("控制流寄存器被用户数据覆盖")
            else:
                assessment.rating = ExploitabilityRating.PROBABLY_EXPLOITABLE
                assessment.confidence = 0.55
                assessment.ruling_reasons.append("访问违规，需结合上下文判定")
            self._suggest_mitigations(assessment)
            return assessment

        if crash_type is CrashType.NULL_DEREFERENCE:
            assessment.rating = ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE
            assessment.confidence = 0.30
            assessment.ruling_reasons.append("NULL 指针解引用，可能仅致拒绝服务")
            return assessment

        base_rating = self._RATING_BY_TYPE.get(crash_type)
        if base_rating is not None:
            assessment.rating = base_rating
            assessment.confidence = {
                ExploitabilityRating.EXPLOITABLE: 0.75,
                ExploitabilityRating.PROBABLY_EXPLOITABLE: 0.55,
                ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE: 0.35,
                ExploitabilityRating.NOT_EXPLOITABLE: 0.20,
            }.get(base_rating, 0.5)
            assessment.ruling_reasons.append(f"崩溃类型 {crash_type.name} 的基准评估")
            self._suggest_mitigations(assessment)
            return assessment

        assessment.rating = ExploitabilityRating.UNKNOWN
        assessment.confidence = 0.0
        return assessment

    def _suggest_mitigations(self, assessment: ExploitabilityAssessment) -> None:
        assessment.mitigations = [
            "DEP (数据执行保护)",
            "ASLR (地址空间布局随机化)",
            "CFG/CET (控制流完整性)",
        ]
        if assessment.is_controlled_branch:
            assessment.is_dep_bypass_possible = True
            assessment.is_aslr_bypass_possible = True

    def generate_report(self) -> str:
        assessment = self.assess_exploitability()
        ci = self.crash_info
        if ci is None:
            return ""
        assessment = self.assess_exploitability(ci)
        lines = [
            "=" * 60,
            "  崩溃分析报告",
            "=" * 60,
            f"  进程名称:      {ci.process_name}",
            f"  崩溃类型:      {ci.crash_type.name}",
            f"  可利用性:      {assessment.rating.name}",
            f"  置信度:        {assessment.confidence:.0%}",
            "-" * 40,
            f"  判定理由:      {'; '.join(assessment.ruling_reasons)}",
            "-" * 40,
            "  建议缓解措施:",
        ]
        for m in assessment.mitigations:
            lines.append(f"    - {m}")

        lines.append("=" * 60)
        return "\n".join(lines)


class CrashReport:

    @staticmethod
    def generate(crash_info: CrashInfo, assessment: ExploitabilityAssessment) -> Dict[str, Any]:
        crash_type = CrashClassifier.from_crash_info(crash_info)
        return {
            'crash_type': crash_type.name.lower(),
            'exploitability': assessment.rating.name.lower(),
            'confidence': assessment.confidence,
            'ruling_reasons': list(assessment.ruling_reasons),
            'is_controlled_branch': assessment.is_controlled_branch,
            'mitigations': list(assessment.mitigations),
            'fault_address': crash_info.fault_address,
            'exception_code': str(crash_info.exception_code),
            'call_stack': list(crash_info.call_stack),
        }


# 崩溃解析器 —— 支持 WinDbg / GDB 输出与转储文件

class CrashParser:

# 解析 WinDbg!分析 -v 输出
    @staticmethod
    def parse_windbg_output(text: str) -> CrashInfo:
        ci = CrashInfo()
        # 异常码
        m = re.search(r'ExceptionCode:\s*([0-9A-Fa-f]+)', text)
        if m:
            ci.exception_code = m.group(1)
            ci.crash_type = CrashClassifier.from_windows_exception(m.group(1))
        m = re.search(r'FAULTING_IP:\s*\S+\+([0-9A-Fa-f]+)', text)
        if m:
            ci.fault_address = int(m.group(1), 16)
        reg_pattern = re.compile(
            r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|r8|r9|r10|r11|r12|r13|r14|r15|'
            r'eax|ebx|ecx|edx|esi|edi|ebp|esp|eip)=([0-9a-fA-F`]+)')
        for m in reg_pattern.finditer(text):
            ci.registers[m.group(1).lower()] = int(m.group(2).replace('`', ''), 16)
        m = re.search(r'PROCESS_NAME:\s*(\S+)', text)
        if m:
            ci.process_name = m.group(1)

        return ci

# 解析 GDB backtrace
    @staticmethod
    def parse_gdb_output(text: str) -> CrashInfo:
        ci = CrashInfo()
        ci.crash_type = CrashType.UNKNOWN

        # 信号
        m = re.search(r'Program received signal (\w+)', text)
        if m:
            sig_map = {"SIGSEGV": 11, "SIGILL": 4, "SIGFPE": 8, "SIGABRT": 6, "SIGBUS": 7}
            ci.crash_type = CrashClassifier.from_signal(sig_map.get(m.group(1), 0))
            ci.exception_code = m.group(1)
        reg_pattern = re.compile(r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|r\d{1,2})\s+0x([0-9a-fA-F]+)')
        for m in reg_pattern.finditer(text):
            ci.registers[m.group(1)] = int(m.group(2), 16)
        bt_pattern = re.compile(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)')
        for m in bt_pattern.finditer(text):
            ci.call_stack.append(m.group(3))
        return ci

# 解析崩溃转储文件
    @staticmethod
    def parse_crash_dump(path: str) -> CrashInfo:
        """
        读取 minidump (.dmp) 或 core 转存 文件
        此处提供框架 —— 完整解析需要 DbgEng 或 pyelftools
        """
        ci = CrashInfo()
        ext = os.path.splitext(path)[1].lower()
        if ext == ".dmp":
            # Windows minidump: 需要 DbgEng COM 接口或 minidump 解析库
            # 当前回退: 尝试用 cdb 命令行解析
            return CrashParser._parse_dmp_via_cdb(path) or ci
        if ext in ("", ".core"):
            return CrashParser._parse_core_via_gdb(path) or ci
        return ci

    @staticmethod
    def _parse_dmp_via_cdb(path: str) -> Optional[CrashInfo]:
        """用 cdb.exe 解析 Windows minidump"""
        try:
            import subprocess
            r = subprocess.run(
                ["cdb.exe", "-z", path, "-c", "!analyze -v; q"],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return CrashParser.parse_windbg_output(r.stdout)
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_core_via_gdb(path: str) -> Optional[CrashInfo]:
        """用 gdb 批处理解析 core dump"""
        try:
            import subprocess
            r = subprocess.run(
                ["gdb", "-batch", "-ex", "thread apply all bt full",
                 "-ex", "info registers", "-ex", "quit", path],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return CrashParser.parse_gdb_output(r.stdout)
        except Exception:
            pass
        return None


# Round 3: FrameShift式碰撞去重 —— 基于堆栈哈希的崩溃分组
# LibAFL的crash dedup策略：将调用栈的前N帧做页对齐哈希
# 编辑距离<阈值(0.3)的崩溃视为同类，仅对代表性崩溃做深入分析
# 这避免了单个bug产生数百个变体时分析资源的浪费

class CrashDeduplicator:

    @staticmethod
    def stack_hash(frames: List[int]) -> str:
        normalized = [f & 0xFFFFFFFFFFFFF000 for f in frames]
        return hashlib.sha256(
            b''.join(f.to_bytes(8, 'little') for f in normalized)).hexdigest()

    @staticmethod
    def similarity(a: List[int], b: List[int]) -> float:
        min_len = min(len(a), len(b))
        if min_len == 0:
            return 0.0
        matches = sum(1 for i in range(min_len)
                      if (a[i] & 0xFFFFFFFFFFFFF000) == (b[i] & 0xFFFFFFFFFFFFF000))
        return matches / max(len(a), len(b))

    @classmethod
    def cluster(cls, crashes: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        clusters: Dict[str, List[int]] = {}
        for i, crash in enumerate(crashes):
            frames = crash.get('stack', [])
            matched = False
            for cid, indices in clusters.items():
                rep_frames = crashes[indices[0]].get('stack', [])
                if cls.similarity(frames, rep_frames) >= 0.7:
                    indices.append(i)
                    matched = True
                    break
            if not matched:
                clusters[f"CLUSTER-{len(clusters):03d}"] = [i]
        return clusters


import os  # noqa: E402
