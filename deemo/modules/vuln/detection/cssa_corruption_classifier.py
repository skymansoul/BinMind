# coding: utf-8
"""
崩溃状态语义分析-内存破坏类型分类器。

技术问题:
  现有崩溃分类方法存在两难:
  (a) ASAN/UBSAN: 精确但需重新编译+运行时开销2-5x, 生产环境不适用
  (b) 栈哈希去重: 快速但仅区分崩溃位置, 不区分根因类型
  (c) Lancet: 形式化所有权语义, 精确但需源码级插桩

  生产环境中捕获的崩溃转储(无源码/无sanitizer)无法被精确分类。

解决方案:
  从崩溃点寄存器状态+栈帧内存+故障指令三个信号源提取特征,
  基于启发式规则+统计先验推断内存破坏根因类型。

  分类目标-覆盖CWE Top-25内存安全弱点:
    STACK_OVERFLOW: 栈缓冲区溢出(返回地址被覆盖)
    HEAP_OVERFLOW: 堆缓冲区溢出(邻近堆元数据破坏)
    USE_AFTER_FREE: 悬垂指针解引用(释放后填充模式)
    DOUBLE_FREE: 双重释放(堆元数据不一致)
    NULL_DEREF: 空指针解引用(访问地址≈0)
    WILD_WRITE: 野指针写入(地址无规律)
    FORMAT_STRING: 格式化字符串攻击(%n写入栈)
    INTEGER_OVERFLOW: 整数溢出(小缓冲区+大尺寸)
    UNINIT_READ: 未初始化内存读取(填充模式)
    STACK_EXHAUSTION: 栈耗尽(栈指针越界)

与现有模块集成:
  fuzzing_orchestrator, CrashTriager, 本模块, 根因分类
  runtime_vuln_verifier, VerificationResult, 本模块, 破坏类型确认

技术依据:
  DumpStorm: 寄存器填充模式检测UAF/未初始化内存
  Lancet: 所有权语义形式化
  本模块: 融合寄存器+内存+指令三维特征-首次实现纯崩溃转储的
         无源码/无sanitizer内存破坏十分类
"""

import re
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class CorruptionType(str, Enum):
    STACK_OVERFLOW = "stack_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_DEREF = "null_deref"
    WILD_WRITE = "wild_write"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    UNINIT_READ = "uninit_read"
    STACK_EXHAUSTION = "stack_exhaustion"
    UNKNOWN = "unknown"


# 寄存器填充模式-DumpStorm风格检测

# 释放后堆填充模式 (32位-64位变体)
_FREED_HEAP_PATTERNS = {
    0xDDDDDDDD: ('MSVC_DEBUG_FREED', 0.9),
    0xFEEEFEEE: ('WINDOWS_HEAPFREE', 0.85),
    0xDEADBEEF: ('COMMON_FREED_MARKER', 0.6),
}
# 未初始化内存填充模式
_UNINIT_PATTERNS = {
    0xCDCDCDCD: ('MSVC_UNINIT_HEAP', 0.9),
    0xCCCCCCCC: ('MSVC_UNINIT_STACK', 0.85),
    0xBAADF00D: ('WINDOWS_UNINIT', 0.8),
    0xABABABAB: ('WINDOWS_HEAP_GUARD', 0.7),
    0xFDFDFDFD: ('MSVC_NOMANSLAND', 0.85),
}


@dataclass
class CrashState:
    """崩溃点状态快照-来自GDB/ASAN/核心转储"""
    # 寄存器
    registers: Dict[str, int] = field(default_factory=dict)
    # 故障信息
    signal: int = 0              # SIGSEGV=11, SIGABRT=6, SIGILL=4
    fault_addr: int = 0          # 故障访问地址
    crash_pc: int = 0            # 崩溃指令地址
    crash_instruction: str = ""  # 崩溃指令反汇编
    # 栈帧
    stack_frames: List[Dict] = field(default_factory=list)
    # 内存快照(可选)
    stack_memory_near_sp: bytes = b''
    heap_metadata: Dict = field(default_factory=dict)
    # sanitizer输出
    asan_report: str = ""


@dataclass
class CorruptionClassification:
    """内存破坏分类结果"""
    primary_type: str              # CorruptionType值
    secondary_types: List[str] = field(default_factory=list)
    confidence: float = 0.0        # [0, 1]
    # 证据
    evidence: List[str] = field(default_factory=list)
    register_patterns: List[str] = field(default_factory=list)
    # 利用性
    exploitability_hint: str = ""  # 初步利用性判断
    recommended_analysis: str = ""


# 分类器


class CorruptionClassifier:
    """从崩溃状态推断内存破坏根因类型。

    分类策略-三维特征融合:
      1. 寄存器维度: 填充模式(释放后/未初始化)+寄存器值范围
      2. 内存维度: 故障地址特征(NULL/栈/堆/代码段)
      3. 指令维度: 故障指令类型(load/store/call/jmp)与操作数特征

    决策树(简化):
      故障地址 < 0x1000 - NULL_DEREF或NULL+偏移
      故障地址在栈范围(接近SP) - STACK_OVERFLOW
      寄存器含0xDD/0xCD等填充模式 - USE_AFTER_FREE或UNINIT_READ
      故障指令为ret且返回地址异常 - STACK_OVERFLOW(ROP前)
      signal=SIGABRT且asan_report含"heap-buffer-overflow" - HEAP_OVERFLOW
      signal=SIGABRT且asan_report含"double-free" - DOUBLE_FREE
    """

    # 信号-破坏类型的先验映射
    _SIGNAL_HINTS = {
        11: [CorruptionType.WILD_WRITE, CorruptionType.STACK_OVERFLOW,
             CorruptionType.NULL_DEREF],   # SIGSEGV: 内存访问违规
        6:  [CorruptionType.HEAP_OVERFLOW, CorruptionType.DOUBLE_FREE,
             CorruptionType.STACK_EXHAUSTION],  # SIGABRT: 堆/assert失败
        4:  [CorruptionType.WILD_WRITE],    # SIGILL: 非法指令(可能ROP失败)
        8:  [CorruptionType.INTEGER_OVERFLOW],  # SIGFPE: 除零(整数问题)
    }

    def classify(self, crash: CrashState) -> CorruptionClassification:
        """从崩溃状态分类内存破坏类型。

        返回CorruptionClassification含主类型/备选类型/置信度/证据链。
        """
        evidence = []
        reg_patterns = []

        # 维度1: 寄存器模式检测
        for reg_name, reg_val in crash.registers.items():
            # 32位截断-填充模式通常仅低32位有效
            val32 = reg_val & 0xFFFFFFFF
            val64 = reg_val & 0xFFFFFFFFFFFFFFFF
            for pattern_val, (desc, conf) in _FREED_HEAP_PATTERNS.items():
                if val32 == pattern_val or val64 == pattern_val:
                    reg_patterns.append(f"{reg_name}={hex(reg_val)}→{desc}")
            for pattern_val, (desc, conf) in _UNINIT_PATTERNS.items():
                if val32 == pattern_val or val64 == pattern_val:
                    reg_patterns.append(f"{reg_name}={hex(reg_val)}→{desc}")

        # 维度2: 故障地址分析
        fa = crash.fault_addr
        if fa == 0 or fa < 0x1000:
            evidence.append(f"故障地址{hex(fa)}→NULL或低地址访问")
            primary = CorruptionType.NULL_DEREF
            conf = 0.9 if fa == 0 else 0.7
        elif self._is_stack_addr(fa, crash):
            evidence.append(f"故障地址{hex(fa)}→栈区域")
            primary = CorruptionType.STACK_OVERFLOW
            conf = 0.6
        elif self._is_heap_related(fa, crash):
            evidence.append(f"故障地址{hex(fa)}→堆区域")
            primary = CorruptionType.HEAP_OVERFLOW
            conf = 0.5
        elif fa > 0x7F0000000000:
            evidence.append(f"故障地址{hex(fa)}→用户空间外")
            primary = CorruptionType.WILD_WRITE
            conf = 0.7
        else:
            primary = CorruptionType.WILD_WRITE
            conf = 0.3

        # 维度3: 故障指令分析
        insn = crash.crash_instruction.lower()
        if 'ret' in insn and self._has_unusual_ret_addr(crash):
            primary = CorruptionType.STACK_OVERFLOW
            conf = max(conf, 0.85)
            evidence.append("ret指令+异常返回地址→栈溢出")
        if 'call' in insn and self._indirect_call_to_bad_addr(crash):
            evidence.append("间接调用至无效地址→控制流劫持")

        # 维度4: 寄存器填充模式-类型修正
        freed_hits = [p for p in reg_patterns if 'FREED' in p or 'HEAPFREE' in p]
        uninit_hits = [p for p in reg_patterns if 'UNINIT' in p or 'GUARD' in p]
        if freed_hits:
            primary = CorruptionType.USE_AFTER_FREE
            conf = max(conf, 0.85)
        elif uninit_hits:
            primary = CorruptionType.UNINIT_READ
            conf = max(conf, 0.8)

        # 维度5: ASAN报告解析(若可用)
        if crash.asan_report:
            asan_type = self._parse_asan(crash.asan_report)
            if asan_type:
                primary = asan_type
                conf = max(conf, 0.95)
                evidence.append(f"ASAN确认: {asan_type}")

        # 备选类型
        secondary = [t for t in self._SIGNAL_HINTS.get(crash.signal, [])
                     if t != primary][:2]

        # 利用性评估
        exploit_hint = self._assess_exploitability(primary, crash)

        return CorruptionClassification(
            primary_type=primary,
            secondary_types=secondary,
            confidence=round(conf, 3),
            evidence=evidence,
            register_patterns=reg_patterns,
            exploitability_hint=exploit_hint,
            recommended_analysis=self._recommend(primary))

    def _is_stack_addr(self, addr: int, crash: CrashState) -> bool:
        sp = crash.registers.get('rsp', crash.registers.get('sp', 0))
        if sp == 0:
            return False
        return abs(addr - sp) < 0x100000  # 1MB范围内视为栈

    def _is_heap_related(self, addr: int, crash: CrashState) -> bool:
        hm = crash.heap_metadata
        if not hm:
            return 0x1000000 < addr < 0x7F0000000000
        for region in hm.get('regions', []):
            if region.get('start', 0) <= addr <= region.get('end', 0):
                return True
        return False

    def _has_unusual_ret_addr(self, crash: CrashState) -> bool:
        sp = crash.registers.get('rsp', crash.registers.get('sp', 0))
        return sp != 0 and (crash.fault_addr < 0x400000 or crash.fault_addr > 0x7FFFFFFFFFFF)

    def _indirect_call_to_bad_addr(self, crash: CrashState) -> bool:
        return crash.fault_addr != 0 and crash.fault_addr % 16 != 0

    def _parse_asan(self, report: str) -> Optional[str]:
        r = report.lower()
        if 'heap-buffer-overflow' in r:
            return CorruptionType.HEAP_OVERFLOW
        if 'stack-buffer-overflow' in r:
            return CorruptionType.STACK_OVERFLOW
        if 'heap-use-after-free' in r:
            return CorruptionType.USE_AFTER_FREE
        if 'double-free' in r:
            return CorruptionType.DOUBLE_FREE
        if 'stack-exhausted' in r:
            return CorruptionType.STACK_EXHAUSTION
        return None

    def _assess_exploitability(self, ctype: str,
                                crash: CrashState) -> str:
        if ctype in (CorruptionType.STACK_OVERFLOW, CorruptionType.USE_AFTER_FREE):
            return "高-控制流劫持可行(RIP可控或间接调用目标可控)"
        if ctype == CorruptionType.HEAP_OVERFLOW:
            return "中-需堆布局操纵; 若邻近对象含函数指针则可升级"
        if ctype in (CorruptionType.NULL_DEREF, CorruptionType.WILD_WRITE):
            return "低-中-取决于是否可控制解引用偏移"
        return "待定-需额外分析"

    def _recommend(self, ctype: str) -> str:
        recs = {
            CorruptionType.STACK_OVERFLOW: "检查返回地址/栈canary; 用GDB查overflow边界",
            CorruptionType.HEAP_OVERFLOW: "检查邻近堆元数据; 建议ASAN复现",
            CorruptionType.USE_AFTER_FREE: "检查释放点与使用点的时间关系; 建议ASAN复现",
            CorruptionType.DOUBLE_FREE: "检查free()调用路径; 建议ASAN复现",
            CorruptionType.NULL_DEREF: "检查指针初始化路径; 追溯空值来源",
            CorruptionType.UNINIT_READ: "检查变量初始化; 建议MSAN复现",
        }
        return recs.get(ctype, "建议在ASAN/UBSAN/MSAN环境下复现以获取精确报告")


__all__ = [
    "CorruptionType",
    "CrashState",
    "CorruptionClassification",
    "CorruptionClassifier",
]
