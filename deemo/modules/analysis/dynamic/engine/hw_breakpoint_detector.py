"""
Hardware breakpoint detection and anti-debug analysis engine.

Detects the presence of hardware breakpoints, Intel CET shadow stacks,
single-step debugging (Trap Flag manipulation), and timing-based
HWBP anomalies via RDTSC profiling.
"""

import os
import re
import struct
import time
import logging
import platform
from enum import Enum, auto
from typing import Optional, List, Dict, Any, Set, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
__log = logging.getLogger(__name__)

_CURRENT_PLATFORM = platform.system().lower()
_IS_WINDOWS = _CURRENT_PLATFORM == "windows"
_IS_LINUX = _CURRENT_PLATFORM == "linux"


# ---------------------------------------------------------------------------
# Intel CET shadow stack instruction opcodes
#
# rdsspq = F3 0F 1E /1 (ModRM.reg == 1): read shadow stack pointer
# incsspq = F3 0F AE /5 (ModRM.reg == 5): increment shadow stack pointer
# rstorssp = F3 0F 01 /5 (ModRM.reg == 5): restore shadow stack pointer
# saveprevssp = F3 0F 01 EA: save previous shadow stack pointer
# setssbsy = F3 0F 01 /1 (ModRM.reg == 1): mark shadow stack busy
# clrssbsy = F3 0F AE /6 (ModRM.reg == 6): clear shadow stack busy
# wrssq = NP 0F 38 F6 /r: write to shadow stack (64-bit store)
# wrussq = 66 0F 38 F5 /r: write to user shadow stack
#
# 检测逻辑：在二进制中搜索这些指令的操作码字节序列，
# 出现 > 0 条即表明二进制使用了 CET 影子栈功能。
# ---------------------------------------------------------------------------

# rdsspq: F3 0F 1E with ModRM.reg == 1 (C8-CF)
_CET_SS_RDSSPQ_RE = re.compile(b'\xF3\x0F\x1E[\xC8-\xCF]', re.DOTALL)
# incsspq: F3 0F AE with ModRM.reg == 5 (E8-EF)
_CET_SS_INCSSPQ_RE = re.compile(b'\xF3\x0F\xAE[\xE8-\xEF]', re.DOTALL)
# rstorssp: F3 0F 01 with ModRM.reg == 5 (E8-EF)
_CET_SS_RSTORSSP_RE = re.compile(b'\xF3\x0F\x01[\xE8-\xEF]', re.DOTALL)
# saveprevssp: F3 0F 01 EA
_CET_SS_SAVEPREVSSP_BYTES = bytes([0xF3, 0x0F, 0x01, 0xEA])
# setssbsy: F3 0F 01 with ModRM.reg == 1 (C8-CF)
_CET_SS_SETSSBSY_RE = re.compile(b'\xF3\x0F\x01[\xC8-\xCF]', re.DOTALL)
# wrssq: NP 0F 38 F6
_CET_SS_WRSSQ_BYTES = bytes([0x0F, 0x38, 0xF6])
# wrussq: 66 0F 38 F5
_CET_SS_WRUSSQ_BYTES = bytes([0x66, 0x0F, 0x38, 0xF5])

# ---------------------------------------------------------------------------
# Trap Flag (TF) manipulation patterns
#
# PUSHFQ (9C) + modify [rsp] + POPFQ (9D) 是经典的 TF 设置惯用法。
# 恶意代码和反调试器常通过这种方式偷偷启用单步执行。
# 额外的检测模式：
#   OR [rsp], 0x100   ; 设置 TF (bit 8)
#   AND [rsp], ~0x100 ; 清除 TF
# ---------------------------------------------------------------------------

# PUSHFQ (9C) ... POPFQ (9D) 序列的最大指令跨度
_TF_SEQUENCE_MAX_SPAN = 64                     # 字节

# 直接修改 RFLAGS 的 TF bit: OR [rsp], 0x100
_TF_OR_PATTERN_RE = re.compile(
    b'\x83\x0C\x24\x00\x01', re.DOTALL          # OR DWORD [RSP], 100h
)
_TF_AND_PATTERN_RE = re.compile(
    b'\x83\x24\x24\xFF\xFE', re.DOTALL          # AND DWORD [RSP], ~100h
)


class DetectionMethod(Enum):
    """Hardware breakpoint detection technique taxonomy."""
    REGISTER_SCAN = "register_scan"              # 直接读 DR0-DR7
    TIMING_ANOMALY = "timing_anomaly"            # RDTSC 时序分析
    CET_SS_DETECT = "cet_ss_detect"             # CET 影子栈指令扫描
    TRAP_FLAG_SCAN = "trap_flag_scan"           # TF 操作序列检测
    INT1_SCAN = "int1_scan"                      # INT1 中断向量检测
    EXCEPTION_ANALYSIS = "exception_analysis"    # 异常处理路径分析


@dataclass
class CETShadowStackEvidence:
    """Evidence of Intel CET shadow stack usage in a binary."""
    instruction_type: str
    address: int                                 # 文件偏移或虚拟地址
    opcode_hex: str                              # 匹配到的操作码（hex）
    instruction_count: int                       # 总出现次数
    context_bytes: Optional[bytes] = None        # 指令周围的字节（±16）

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instruction": self.instruction_type,
            "address": hex(self.address),
            "opcode": self.opcode_hex,
            "count": self.instruction_count,
        }


@dataclass
class TimingMeasurement:
    """RDTSC-based timing sample for a code block."""
    block_address: int
    sample_count: int
    min_cycles: int
    max_cycles: int
    mean_cycles: float
    median_cycles: float
    stddev_cycles: float
    anomaly_score: float                         # 偏离"正常"执行时间的程度
    suspected_hwbp: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_address": hex(self.block_address),
            "samples": self.sample_count,
            "min_cycles": self.min_cycles,
            "max_cycles": self.max_cycles,
            "mean_cycles": self.mean_cycles,
            "median_cycles": self.median_cycles,
            "stddev_cycles": self.stddev_cycles,
            "anomaly_score": round(self.anomaly_score, 4),
            "suspected_hwbp": self.suspected_hwbp,
        }


@dataclass
class TrapFlagDetection:
    """Evidence of Trap Flag manipulation (single-step debugging)."""
    address: int
    pattern_type: str                            # pushfq_modify / or_immediate / and_immediate
    instruction_sequence: List[str]
    risk_level: str                              # LOW / MEDIUM / HIGH
    context_offset: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "pattern_type": self.pattern_type,
            "instruction_sequence": self.instruction_sequence,
            "risk_level": self.risk_level,
            "context_offset": self.context_offset,
        }


@dataclass
class HWBPDetectionResult:
    """Aggregated result of all hardware breakpoint detection methods."""
    method: DetectionMethod
    detected: bool
    confidence: float
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method.value,
            "detected": self.detected,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "details": self.details,
        }


class HWBreakpointDetector:
    """Multi-method hardware breakpoint and anti-debug detection engine.

    Combines register scanning, timing profiling, CET shadow stack
    instruction detection, and Trap Flag manipulation analysis into
    a unified detection pipeline. Each method produces independent
    results that are aggregated by confidence-weighted voting.

    策略优先级：
    1. 直接寄存器扫描（最可靠，但需要 ptrace/内核级访问）
    2. 时序异常检测（无需特权，但受噪声影响）
    3. CET 指令扫描（静态分析，零运行时开销）
    4. TF 序列检测（反-反调试，检测调试器自身的行为）
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        target_pid: Optional[int] = None,
        timing_samples: int = 100,
        timing_anomaly_threshold: float = 3.0,    # sigma multiplier
    ):
        self._binary_path = binary_path
        self._target_pid = target_pid
        self._timing_samples = timing_samples
        self._timing_anomaly_threshold = timing_anomaly_threshold

        # 二进制数据缓存
        self._binary_bytes: Optional[bytes] = None
        self._binary_base: int = 0
        self._loaded_binary()

        # 检测结果集合
        self._detection_results: List[HWBPDetectionResult] = []
        self._timing_measurements: List[TimingMeasurement] = []
        self._cet_evidence: List[CETShadowStackEvidence] = []
        self._trap_flag_detections: List[TrapFlagDetection] = []

    def _loaded_binary(self) -> None:
        """Load the binary file into a memory buffer for static analysis."""
        if not self._binary_path or not os.path.exists(self._binary_path):
            return
        try:
            with open(self._binary_path, "rb") as fh:
                self._binary_bytes = fh.read()
            __log.info("Binary loaded for HWBP detection: %s (%d bytes).",
                        self._binary_path, len(self._binary_bytes))
        except (IOError, PermissionError) as exc:
            __log.warning("Failed to load binary for HWBP detection: %s", exc)

    # ------------------------------------------------------------------
    # Direct register scan
    # ------------------------------------------------------------------

    def detect_via_register_scan(self) -> HWBPDetectionResult:
        """Directly read DR0-DR7 to detect active hardware breakpoints.

        Linux: 通过 ptrace(PTRACE_PEEKUSER, offsetof(debugreg)) 读取。
        Windows: 通过 GetThreadContext 读取 CONTEXT 结构中的 Dr0-Dr7。

        限制：此方法需要 ptrace 附加权限或 PROCESS_QUERY_INFORMATION。
        如果没有权限，返回 detected=False 而非抛出异常。
        """
        evidence: List[Dict[str, Any]] = []
        detected = False
        details = ""

        if self._target_pid is None:
            details = "No target PID specified -- register scan skipped."
            return HWBPDetectionResult(
                method=DetectionMethod.REGISTER_SCAN,
                detected=False, confidence=0.0,
                details=details,
            )

        # Stub: 实际实现需 ptrace 或 GetThreadContext
        # 这里提供框架结构供平台特定代码填充
        dr_values = self._read_debug_registers()

        for slot in range(4):
            dr_key = f"dr{slot}"
            if dr_values.get(dr_key, 0) != 0:
                detected = True
                evidence.append({
                    "slot": slot,
                    "address": hex(dr_values[dr_key]),
                    "dr7": hex(dr_values.get("dr7", 0)),
                })

        confidence = 0.95 if detected else 0.0
        details = (
            f"Register scan: {len(evidence)} active HWBP(s) found."
            if detected else
            "No active hardware breakpoints detected via register scan."
        )

        result = HWBPDetectionResult(
            method=DetectionMethod.REGISTER_SCAN,
            detected=detected,
            confidence=confidence,
            evidence=evidence,
            details=details,
        )
        self._detection_results.append(result)
        return result

    def _read_debug_registers(self) -> Dict[str, int]:
        """Platform-specific debug register reading stub."""
        # 完整实现依赖 ptrace / GetThreadContext
        # 此处返回空字典表示"无法读取"
        return {}

    # ------------------------------------------------------------------
    # Intel CET shadow stack detection
    # ------------------------------------------------------------------

    def detect_cet_shadow_stack(self) -> HWBPDetectionResult:
        """Scan binary for Intel CET shadow stack instructions.

        检测 rdsspq、incsspq、rstorssp、saveprevssp、wrssq、wrussq
        等 CET 硬件影子栈操作指令。这些指令的出现表明：

        1. 二进制在 CET 感知的编译器中编译（GCC -fcf-protection=full）
        2. 二进制使用了影子栈保护（可能阻碍传统的栈溢出利用）
        3. 运行时环境（CPU + OS）可能启用了 CET 强制保护

        检测意义：
        - 攻击面评估：CET 影子栈使传统 ROP 无法工作（ret 指令会触发 #CP）
        - 兼容性：在非 CET 硬件上这些指令被视为 NOP（F3 前缀忽略），
          但从二进制分析角度仍需识别其存在
        """
        if not self._binary_bytes:
            return HWBPDetectionResult(
                method=DetectionMethod.CET_SS_DETECT,
                detected=False,
                confidence=0.0,
                details="No binary data loaded for CET scan.",
            )

        evidence_list: List[CETShadowStackEvidence] = []
        cet_patterns: List[Tuple[str, bytes, Any]] = [
            ("rdsspq", b'\xF3\x0F\x1E', _CET_SS_RDSSPQ_RE),
            ("incsspq", b'\xF3\x0F\xAE', _CET_SS_INCSSPQ_RE),
            ("rstorssp", b'\xF3\x0F\x01', _CET_SS_RSTORSSP_RE),
            ("saveprevssp", _CET_SS_SAVEPREVSSP_BYTES[:3],
             _CET_SS_SAVEPREVSSP_BYTES),
            ("setssbsy", b'\xF3\x0F\x01', _CET_SS_SETSSBSY_RE),
            ("wrssq", _CET_SS_WRSSQ_BYTES, None),
            ("wrussq", _CET_SS_WRUSSQ_BYTES, None),
        ]

        total_hits = 0
        for inst_name, prefix_bytes, pattern in cet_patterns:
            if isinstance(pattern, bytes):
                # 精确字节匹配
                count = 0
                offset = 0
                positions: List[int] = []
                while True:
                    pos = self._binary_bytes.find(pattern, offset)
                    if pos == -1:
                        break
                    count += 1
                    positions.append(pos)
                    offset = pos + 1
            else:
                # 正则匹配
                matches = list(pattern.finditer(self._binary_bytes))
                count = len(matches)
                positions = [m.start() for m in matches]

            if count > 0:
                total_hits += count
                first_pos = positions[0] if positions else 0
                evt = CETShadowStackEvidence(
                    instruction_type=inst_name,
                    address=first_pos,
                    opcode_hex=(
                        self._binary_bytes[first_pos:first_pos + 4].hex(" ")
                        if first_pos + 4 <= len(self._binary_bytes) else ""
                    ),
                    instruction_count=count,
                )
                evidence_list.append(evt)

        detected = total_hits > 0
        details = (
            f"CET shadow stack detected: {total_hits} instruction(s) "
            f"across {len(evidence_list)} variant(s)."
            if detected else
            "No CET shadow stack instructions found."
        )

        self._cet_evidence = evidence_list
        result = HWBPDetectionResult(
            method=DetectionMethod.CET_SS_DETECT,
            detected=detected,
            confidence=0.90 if detected else 0.0,
            evidence=[ev.to_dict() for ev in evidence_list],
            details=details,
        )
        self._detection_results.append(result)
        return result

    # ------------------------------------------------------------------
    # Timing-based hardware breakpoint detection
    # ------------------------------------------------------------------

    def detect_via_timing_analysis(self) -> HWBPDetectionResult:
        """Detect hardware breakpoints via RDTSC-based timing anomaly analysis.

        原理：x86 硬件断点触发时，处理器需要执行微码辅助流程
        （保存 DR6、调用 #DB 处理程序、单步恢复），这个开销在微秒级别。
        正常执行没有这个开销，因此多次采样中如果某些执行明显慢于
        基线，可能表明硬件断点被安装在相关地址上。

        检测流程：
        1. 为每个目标代码块采集 N 次 RDTSC 测量
        2. 计算均值、标准差
        3. 标记超出 threshold 个标准差的异常样本
        4. 异常样本比例超过 20% 的代码块标记为"suspected HWBP"

        限制：
        - 系统负载、缓存未命中、中断都可能产生类似的时序抖动
        - 需要多次采样来抵消噪声（采样数越多，置信度越高）
        - 不适用于确定性执行环境（无噪声时 HWBP 的延迟可能 < 1us 而漏检）
        """
        if not self._binary_bytes or self._target_pid is None:
            return HWBPDetectionResult(
                method=DetectionMethod.TIMING_ANOMALY,
                detected=False,
                confidence=0.0,
                details="Timing analysis requires binary data and target PID.",
            )

        # 对代码块进行采样——此处以 64 字节为最小分析单元
        block_size = 64
        block_count = len(self._binary_bytes) // block_size
        measurements: List[TimingMeasurement] = []
        suspected_count = 0

        for block_idx in range(min(block_count, 50)):   # 限制分析范围
            block_addr = self._binary_base + block_idx * block_size
            timing_samples = self._collect_rdtsc_samples(block_addr)

            if not timing_samples or len(timing_samples) < 10:
                continue

            samples = timing_samples[:self._timing_samples]
            sorted_samples = sorted(samples)
            sample_n = len(samples)

            min_cycles = min(samples)
            max_cycles = max(samples)
            mean_cycles = sum(samples) / sample_n
            median_idx = sample_n // 2
            median_cycles = (
                sorted_samples[median_idx]
                if sample_n % 2 == 1
                else (sorted_samples[median_idx - 1] +
                      sorted_samples[median_idx]) / 2
            )

            # 标准差
            variance = sum(
                (x - mean_cycles) ** 2 for x in samples
            ) / sample_n
            stddev_cycles = variance ** 0.5

            # 异常分数：异常值比例
            if stddev_cycles > 0:
                anomaly_count = sum(
                    1 for x in samples
                    if abs(x - mean_cycles) >
                    self._timing_anomaly_threshold * stddev_cycles
                )
                anomaly_score = anomaly_count / sample_n
            else:
                anomaly_score = 0.0

            suspected_hwbp = anomaly_score > 0.20   # 超过 20% 的样本异常

            if suspected_hwbp:
                suspected_count += 1

            m = TimingMeasurement(
                block_address=block_addr,
                sample_count=sample_n,
                min_cycles=min_cycles,
                max_cycles=max_cycles,
                mean_cycles=mean_cycles,
                median_cycles=median_cycles,
                stddev_cycles=stddev_cycles,
                anomaly_score=anomaly_score,
                suspected_hwbp=suspected_hwbp,
            )
            measurements.append(m)

        self._timing_measurements = measurements

        detected = suspected_count > 0
        details = (
            f"Timing anomaly: {suspected_count}/{len(measurements)} "
            f"blocks show HWBP-like timing patterns."
            if detected else
            f"Timing analysis complete: {len(measurements)} blocks "
            f"checked, no anomalies detected."
        )

        # 置信度 = 被标记块的比例，但有上限
        confidence = min(
            0.70,
            (suspected_count / max(len(measurements), 1)) * 2.0
        ) if detected else 0.0

        result = HWBPDetectionResult(
            method=DetectionMethod.TIMING_ANOMALY,
            detected=detected,
            confidence=confidence,
            evidence=[m.to_dict() for m in measurements if m.suspected_hwbp],
            details=details,
        )
        self._detection_results.append(result)
        return result

    def _collect_rdtsc_samples(self, block_address: int) -> List[int]:
        """Collect RDTSC samples for timing analysis (stub).

        完整实现需要内联汇编或通过性能计数器读取。
        此处返回合成数据用于框架验证。
        """
        # Stub: 返回空列表表示"无法采集"
        # 完整实现：int __rdtsc() 内联汇编，每个样本之间加 mfence/lfence
        return []

    # ------------------------------------------------------------------
    # Trap Flag single-step detection
    # ------------------------------------------------------------------

    def detect_step_debugging(self) -> HWBPDetectionResult:
        """Detect Trap Flag (TF) single-step debugging patterns.

        TF (bit 8 of RFLAGS/EFLAGS) 启用 x86 单步执行模式——
        每条指令执行后触发 INT1 (#DB 异常)。调试器通过 TF 实现
        "单步步入"功能。

        检测的恶意/反调试模式：
        1. PUSHFQ + OR [rsp], 0x100 + POPFQ 序列 —— 显式设置 TF
        2. PUSHFQ + BTR [rsp], 8 序列 —— 通过位测试设置 TF
        3. OR [rsp], imm32 模式（立即数包含 0x100）—— 更隐蔽的 TF 设置
        4. AND [rsp], ~0x100 序列 —— 清除 TF（调试器退出单步模式）

        风险评估：
        - HIGH: 显式的 PUSHFQ/OR/POPFQ 序列，几乎肯定是调试相关
        - MEDIUM: 间接的 TF 操作（通过 XOR/BTR 等）
        - LOW: 仅出现 PUSHFQ/POPFQ 但无明显 TF 修改
        """
        if not self._binary_bytes:
            return HWBPDetectionResult(
                method=DetectionMethod.TRAP_FLAG_SCAN,
                detected=False,
                confidence=0.0,
                details="No binary data loaded for Trap Flag scan.",
            )

        detections: List[TrapFlagDetection] = []
        binary_len = len(self._binary_bytes)

        # 检测 PUSHFQ (9C) ... POPFQ (9D) 序列
        pushfq_positions: List[int] = []
        for i in range(binary_len - 1):
            if self._binary_bytes[i] == 0x9C:
                pushfq_positions.append(i)

        for pfq_pos in pushfq_positions:
            search_end = min(pfq_pos + _TF_SEQUENCE_MAX_SPAN, binary_len)
            chunk = self._binary_bytes[pfq_pos:search_end]

            popfq_pos = chunk.find(b'\x9D')
            if popfq_pos == -1:
                continue

            # 检查序列中是否有 TF 修改操作
            between_chunk = chunk[1:popfq_pos]   # PUSHFQ 和 POPFQ 之间的字节

            # Pattern A: OR [rsp], 0x100 (83 0C 24 00 01)
            if _TF_OR_PATTERN_RE.search(between_chunk):
                detections.append(TrapFlagDetection(
                    address=pfq_pos,
                    pattern_type="pushfq_or_tf_popqf",
                    instruction_sequence=[
                        "pushfq",
                        "or dword [rsp], 0x100  ; set TF (bit 8)",
                        "popfq",
                    ],
                    risk_level="HIGH",
                    context_offset=pfq_pos,
                ))

            # Pattern B: BTR [rsp], 8 (可能用于设置/清除 TF)
            if b'\x0F\xBA' in between_chunk:
                btr_idx = between_chunk.find(b'\x0F\xBA')
                if btr_idx + 3 < len(between_chunk):
                    modrm = between_chunk[btr_idx + 2]
                    # ModRM 检查：target = [rsp] (mod=00, rm=100)
                    if (modrm & 0xC7) == 0x04:
                        detections.append(TrapFlagDetection(
                            address=pfq_pos + btr_idx,
                            pattern_type="pushfq_btr_popqf",
                            instruction_sequence=[
                                "pushfq",
                                "btr [rsp], 8        ; bit test TF",
                                "popfq",
                            ],
                            risk_level="HIGH",
                            context_offset=pfq_pos,
                        ))

            # Pattern C: 有 PUSHFQ/POPFQ 但无明显 TF 修改
            # （可能是保存/恢复整个 EFLAGS 的正常操作）
            if len(between_chunk) >= 1:
                # 仅当序列极短（<= 3 条指令）且没有其他操作时才标记
                # 跳过——这在正常的 save/restore 场景中很常见
                pass

        # 独立检测直接修改标志的模式（无 PUSHFQ 配对）
        for match in _TF_OR_PATTERN_RE.finditer(self._binary_bytes):
            pos = match.start()
            # 确认不是 PUSHFQ...POPFQ 模式的一部分（避免重复）
            already_captured = any(
                abs(d.address - pos) < _TF_SEQUENCE_MAX_SPAN
                and d.pattern_type == "pushfq_or_tf_popqf"
                for d in detections
            )
            if not already_captured:
                detections.append(TrapFlagDetection(
                    address=pos,
                    pattern_type="or_immediate_tf",
                    instruction_sequence=[
                        "or dword [rsp], 0x100  ; set TF",
                    ],
                    risk_level="MEDIUM",
                    context_offset=pos,
                ))

        for match in _TF_AND_PATTERN_RE.finditer(self._binary_bytes):
            pos = match.start()
            detections.append(TrapFlagDetection(
                address=pos,
                pattern_type="and_immediate_clear_tf",
                instruction_sequence=[
                    "and dword [rsp], ~0x100  ; clear TF",
                ],
                risk_level="LOW",
                context_offset=pos,
            ))

        detected = len(detections) > 0
        high_risk = sum(1 for d in detections if d.risk_level == "HIGH")
        details = (
            f"Trap Flag patterns detected: {len(detections)} total "
            f"({high_risk} HIGH risk)."
            if detected else
            "No Trap Flag manipulation patterns detected."
        )

        confidence = min(0.95, high_risk * 0.3 + 0.2) if detected else 0.0
        self._trap_flag_detections = detections

        result = HWBPDetectionResult(
            method=DetectionMethod.TRAP_FLAG_SCAN,
            detected=detected,
            confidence=confidence,
            evidence=[d.to_dict() for d in detections],
            details=details,
        )
        self._detection_results.append(result)
        return result

    # ------------------------------------------------------------------
    # Aggregated detection
    # ------------------------------------------------------------------

    def run_all_detections(self) -> List[HWBPDetectionResult]:
        """Execute all detection methods and return aggregated results.

        检测顺序按可靠性降序排列：寄存器扫描 > CET 指令 > TF 扫描 > 时序分析。

        聚合投票：任何方法返回 detected=True 即标记为整体检测到 HWBP。
        """
        self._detection_results.clear()

        # 各方法独立运行，互不阻塞
        self.detect_via_register_scan()       # 最可靠
        self.detect_cet_shadow_stack()        # 静态特征，高置信度
        self.detect_step_debugging()          # TF 扫描，中置信度
        self.detect_via_timing_analysis()     # 时序分析，低置信度（噪声大）

        return self._detection_results

    def is_hwbp_detected(self) -> bool:
        """Quick check: was any detection method positive?"""
        return any(r.detected for r in self._detection_results)

    def get_overall_confidence(self) -> float:
        """Aggregate confidence across all detection methods.

        加权投票：寄存器扫描（权重 0.5）、CET 检测（0.25）、
        TF 扫描（0.15）、时序分析（0.1）。
        """
        weights = {
            DetectionMethod.REGISTER_SCAN: 0.50,
            DetectionMethod.CET_SS_DETECT: 0.25,
            DetectionMethod.TRAP_FLAG_SCAN: 0.15,
            DetectionMethod.TIMING_ANOMALY: 0.10,
        }
        total = 0.0
        for r in self._detection_results:
            w = weights.get(r.method, 0.1)
            total += r.confidence * w
        return min(1.0, total)

    # ------------------------------------------------------------------
    # Results retrieval
    # ------------------------------------------------------------------

    def get_detection_results(self) -> List[HWBPDetectionResult]:
        """Retrieve all detection results."""
        return list(self._detection_results)

    def get_timing_measurements(self) -> List[TimingMeasurement]:
        """Retrieve timing measurements."""
        return list(self._timing_measurements)

    def get_cet_evidence(self) -> List[CETShadowStackEvidence]:
        """Retrieve CET shadow stack evidence."""
        return list(self._cet_evidence)

    def get_trap_flag_detections(self) -> List[TrapFlagDetection]:
        """Retrieve Trap Flag manipulation detections."""
        return list(self._trap_flag_detections)

    def get_detection_summary(self) -> Dict[str, Any]:
        """Generate a diagnostic summary of all detection results."""
        suspicious_blocks = [
            m for m in self._timing_measurements if m.suspected_hwbp
        ]
        high_risk_tf = [
            d for d in self._trap_flag_detections
            if d.risk_level == "HIGH"
        ]
        return {
            "hwbp_detected": self.is_hwbp_detected(),
            "overall_confidence": round(self.get_overall_confidence(), 4),
            "register_scan": any(
                r.detected and r.method == DetectionMethod.REGISTER_SCAN
                for r in self._detection_results
            ),
            "cet_shadow_stack_detected": any(
                r.detected and r.method == DetectionMethod.CET_SS_DETECT
                for r in self._detection_results
            ),
            "cet_instruction_count": len(self._cet_evidence),
            "timing_anomalies": len(suspicious_blocks),
            "trap_flag_detections": len(self._trap_flag_detections),
            "trap_flag_high_risk": len(high_risk_tf),
            "detection_methods_run": len(self._detection_results),
        }

    def clear(self) -> None:
        """Reset all detection state."""
        self._detection_results.clear()
        self._timing_measurements.clear()
        self._cet_evidence.clear()
        self._trap_flag_detections.clear()
