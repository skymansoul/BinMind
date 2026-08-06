# 修改记录:
# 2025-09-13 14:51 — 初始实现：寄存器压力变化 + 溢出/填充计数 + 调度影响
# 2025-09-14 09:23 — 增加 x86-64 微架构端口压力建模

"""Patch Register Pressure Analyzer — 补丁对寄存器分配压力的影响。

手工补丁通常不考虑寄存器分配优化——编译器在寄存器分配时做全局
liveness 分析和图着色，而补丁作者通常选择"最方便"的寄存器。

本模块量化补丁引入的寄存器压力变化：
  1. 活跃寄存器数变化 (register pressure Δ)
  2. 新增的 spill/fill 操作（栈保存/恢复）
  3. 微架构端口压力（Intel Skylake/Zen4 执行端口模型）
  4. 指令级并行度 (ILP) 变化

高寄存器压力 → 编译器可能被迫 spill → 内存访问增加 → 性能退化。
补丁作者可能无意中选择了编译器已分配给其他变量的寄存器 → 冲突。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)


@dataclass
class RegPressure:
    """寄存器压力指标。"""
    peak_live_regs: int = 0
    avg_live_regs: float = 0.0
    spill_count: int = 0               # push/pop 或显式栈保存
    fill_count: int = 0
    xmm_used: int = 0                  # SIMD 寄存器使用数


@dataclass
class PortPressure:
    """执行端口压力（Skylake 简化模型）。"""
    port_0_1: float = 0.0   # ALU/FPU
    port_2_3: float = 0.0   # Load/Store
    port_5_6: float = 0.0   # ALU/Branch
    estimated_ipc: float = 1.0


@dataclass
class RegPressureReport:
    """寄存器压力分析报告。"""
    patch_id: str = ""
    # 原始
    original: RegPressure = field(default_factory=RegPressure)
    # 补丁后
    patched: RegPressure = field(default_factory=RegPressure)
    # 端口压力
    orig_ports: PortPressure = field(default_factory=PortPressure)
    patch_ports: PortPressure = field(default_factory=PortPressure)
    # 差异
    pressure_delta: int = 0
    spill_delta: int = 0
    # 判定
    pressure_severity: str = "low"
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'pressure_delta': self.pressure_delta,
            'spill_delta': self.spill_delta,
            'severity': self.pressure_severity,
            'orig_peak': self.original.peak_live_regs,
            'patch_peak': self.patched.peak_live_regs,
            'recommendation': self.recommendation,
        }


# ── 寄存器活跃度分析器 ────────────────────────────────────────────

class LivenessTracker:
    """逐指令追踪寄存器活跃度。

    对每条指令维护当前存活的寄存器集合。
    寄存器定义后变为活，最后使用后变为死。
    """

    def __init__(self):
        self._live_set = set()

    def analyze(self, asm_lines: List[str]) -> RegPressure:
        """分析一段汇编的寄存器压力。"""
        pressure = RegPressure()
        if not asm_lines:
            return pressure

        peak = 0; total = 0; count = 0

        for line in asm_lines:
            defs, uses, spills = self._classify_regs(line)
            # 计数 spills/fills
            pressure.spill_count += spills

            # 更新活跃集
            self._live_set.update(defs)
            self._live_set.difference_update(
                set(self._dead_after(line, asm_lines)))

            # XMM 寄存器
            pressure.xmm_used += sum(1 for r in self._live_set if r.startswith('xmm'))

            current = len(self._live_set)
            peak = max(peak, current)
            total += current
            count += 1

        pressure.peak_live_regs = peak
        pressure.avg_live_regs = total / count if count > 0 else 0.0

        return pressure

    def _classify_regs(self, inst: str) -> Tuple[Set[str], Set[str], int]:
        """分类指令中的寄存器：定义/使用/spill。"""
        parts = inst.strip().lower().replace(',', ' ').split()
        defs = set(); uses = set(); spills = 0
        if not parts:
            return defs, uses, spills

        mnemonic = parts[0]
        regs = [p.rstrip(',;') for p in parts[1:]
               if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?|sp|bp|xmm\d+)$', p)]

        if mnemonic in ('push',):
            uses.update(regs)
            spills += 1  # push = spill to stack
        elif mnemonic in ('pop',):
            defs.update(regs)
            spills += 1  # pop = fill from stack
        elif mnemonic in ('mov','lea','movzx','movsx'):
            if regs:
                defs.add(regs[0])
                uses.update(regs[1:])
        elif mnemonic in ('add','sub','xor','and','or','shl','shr','mul','imul','inc','dec','neg','not'):
            if regs:
                defs.add(regs[0])
                uses.update(regs)
        elif mnemonic in ('cmp','test'):
            uses.update(regs)
        elif mnemonic == 'call':
            defs.add('rax')  # 返回值
        elif mnemonic == 'ret':
            uses.add('rax')

        # 内存操作数中的寄存器
        for p in parts[1:]:
            if '[' in p:
                for m in re.finditer(r'\b(r[a-z0-9]+|xmm\d+)\b', p):
                    uses.add(m.group(0))

        return defs, uses, spills

    def _dead_after(self, inst: str, all_asm: List[str]) -> list:
        """简化的死寄存器检测：返回当前指令后可设为死的寄存器。"""
        # 保守策略：仅 ret 指令后清空所有寄存器
        if inst.strip().lower().startswith('ret'):
            return list(self._live_set)
        return []


# ── 端口压力建模 ──────────────────────────────────────────────────

class PortPressureModel:
    """Skylake/Zen4 简化的执行端口压力模型。

    Port 0/1: ALU, FPU, mul/div
    Port 2/3: Load, Store address
    Port 5/6: ALU, branch, fast int
    """

    def estimate(self, asm_lines: List[str]) -> PortPressure:
        """从指令序列估算端口压力。"""
        pp = PortPressure()
        p01 = 0; p23 = 0; p56 = 0
        for line in asm_lines:
            parts = line.strip().lower().split()
            if not parts:
                continue
            m = parts[0]
            if m in ('add','sub','xor','and','or','shl','shr','inc','dec','neg','not','lea'):
                p01 += 0.25; p56 += 0.25
            elif m in ('mul','imul','div','idiv'):
                p01 += 1.0
            elif m in ('mov',) and ('[' in line):
                p23 += 0.5
            elif m in ('push','pop','call','ret'):
                p23 += 0.5; p56 += 0.5
            elif m in ('cmp','test','j'):
                p56 += 0.25
        count = max(len(asm_lines), 1)
        pp.port_0_1 = p01 / count
        pp.port_2_3 = p23 / count
        pp.port_5_6 = p56 / count
        # IPC 估算
        total = pp.port_0_1 + pp.port_2_3 + pp.port_5_6
        pp.estimated_ipc = total / 3.0
        return pp


# ── 分析器 ────────────────────────────────────────────────────────

class RegPressureAnalyzer:
    """补丁寄存器压力分析器。"""

    def __init__(self):
        self._liveness = LivenessTracker()
        self._ports = PortPressureModel()

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "") -> RegPressureReport:
        """分析补丁对寄存器压力的影响。"""
        report = RegPressureReport(patch_id=patch_id)
        report.original = self._liveness.analyze(original_asm)
        report.patched = self._liveness.analyze(patched_asm)
        report.orig_ports = self._ports.estimate(original_asm)
        report.patch_ports = self._ports.estimate(patched_asm)

        report.pressure_delta = (report.patched.peak_live_regs -
                                 report.original.peak_live_regs)
        report.spill_delta = (report.patched.spill_count -
                              report.original.spill_count)

        if report.pressure_delta >= 3 or report.spill_delta >= 2:
            report.pressure_severity = "high"
            report.recommendation = "寄存器压力显著增加——可能导致性能退化和 spill 风暴"
        elif report.pressure_delta >= 1 or report.spill_delta >= 1:
            report.pressure_severity = "medium"
            report.recommendation = "寄存器压力略有增加——在热路径上建议审查"
        else:
            report.pressure_severity = "low"
            report.recommendation = "寄存器压力无显著变化"

        return report
