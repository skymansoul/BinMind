# 修改记录:
# 2025-08-17 08:54 — 初始实现：指令计数 + 访存模式 + 分支预测影响
# 2025-08-18 14:18 — 增加微架构成本表（基于 Agner Fog 指令延迟数据）

"""Patch Performance Impact Predictor — 补丁性能回归预测。

现有性能回归检测操作在源码级（AST diff + bytecode injection profiling）。
本模块在二进制补丁级操作——不依赖源码或重编译。

预测模型基于三个维度的静态分析：
  1. 指令计数/延迟增量：补丁新增的 uop 数 × 每条指令的微架构延迟
  2. 访存模式变更：补丁是否改变了缓存行为（如新增随机访存）
  3. 分支预测影响：补丁是否引入了难以预测的条件分支

代价模型：
  每条 x86-64 指令分配一个"微架构成本"（Agner Fog 数据），
  按补丁的预期执行频率加权求和得到总分。

与 PerfScope [ICSE 2014] 的差异：
  PerfScope 操作在 commit/patch 文件层面，用 AST 映射到代价函数。
  本模块操作在汇编指令层面，用微架构延迟表直接计算代价。
  不需要 profile database 作为先验——纯静态分析。

与 Cheng et al. [2024 TD Commons] 的差异：
  那个方案是两阶段：静态 AST diff → 动态 profiling。
  本模块完全静态——不需要执行环境，适用于 closed-source binary。

限制：
  静态分析的精度受限于对执行频率的估计（无条件/循环内/冷路径）。
  对 I/O 密集代码的预测能力弱（I/O 延迟不是指令级可建模的）。
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class ImpactCategory(str, Enum):
    NEGLIGIBLE = "negligible"    # < 1% 预期影响
    MINOR = "minor"              # 1-3%
    MODERATE = "moderate"        # 3-10%
    SIGNIFICANT = "significant"  # 10-30%
    SEVERE = "severe"            # > 30%


@dataclass
class InstructionCost:
    """单条指令的微架构成本。"""
    mnemonic: str
    uops_fused: float = 1.0           # 融合后的微操作数
    latency_cycles: float = 1.0        # 延迟（周期）
    throughput_reciprocal: float = 1.0 # 吞吐量倒数（cycles/uop）
    port_pressure: float = 0.25        # 执行端口压力 (0..1 per port)
    # 特殊标记
    is_memory_access: bool = False
    is_branch: bool = False
    is_atomic: bool = False


@dataclass
class PerfDelta:
    """补丁的性能变化估计。"""
    # 指令计数
    instructions_before: int = 0
    instructions_after: int = 0
    instruction_delta: int = 0         # 正=增加
    instruction_delta_pct: float = 0.0

    # 微架构成本
    uops_before: float = 0.0
    uops_after: float = 0.0
    uops_delta_pct: float = 0.0

    # 访存
    mem_accesses_before: int = 0
    mem_accesses_after: int = 0
    cache_line_touches: int = 0        # 估计的 cache line 访问数

    # 分支
    branches_before: int = 0
    branches_after: int = 0
    unpredictable_branches: int = 0    # 难以预测的分支数


@dataclass
class PerfImpactReport:
    """性能影响预测报告。"""
    patch_id: str = ""
    delta: PerfDelta = field(default_factory=PerfDelta)
    estimated_overhead_pct: float = 0.0
    category: ImpactCategory = ImpactCategory.NEGLIGIBLE
    # 最昂贵的指令
    expensive_instructions: List[str] = field(default_factory=list)
    # 文本建议
    hotspots: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'overhead_pct': round(self.estimated_overhead_pct, 2),
            'category': self.category.value,
            'inst_delta': self.delta.instruction_delta,
            'inst_delta_pct': round(self.delta.instruction_delta_pct, 2),
            'uops_delta_pct': round(self.delta.uops_delta_pct, 2),
            'mem_delta': (self.delta.mem_accesses_after -
                         self.delta.mem_accesses_before),
            'branch_delta': (self.delta.branches_after -
                            self.delta.branches_before),
            'expensive': self.expensive_instructions[:5],
            'hotspots': self.hotspots[:3],
            'recommendation': self.recommendation,
        }


# ── 微架构成本表 (x86-64, based on Agner Fog + uops.info) ────────

# 每条助记符 → InstructionCost
# 对常见补丁指令做精确建模，其余用默认值
_MICROARCH_COST_TABLE: Dict[str, InstructionCost] = {
    # 数据传输
    'mov': InstructionCost('mov', 1.0, 1.0, 0.25, 0.20, is_memory_access=False),
    'movaps': InstructionCost('movaps', 1.0, 3.0, 0.50, 0.40, is_memory_access=True),
    'movdqa': InstructionCost('movdqa', 1.0, 3.0, 0.50, 0.40, is_memory_access=True),
    'lea': InstructionCost('lea', 1.0, 1.0, 0.25, 0.20),
    'push': InstructionCost('push', 1.0, 2.0, 0.50, 0.35, is_memory_access=True),
    'pop': InstructionCost('pop', 1.0, 2.0, 0.50, 0.35, is_memory_access=True),
    'xchg': InstructionCost('xchg', 2.0, 2.0, 1.00, 0.60, is_memory_access=True),

    # 算术
    'add': InstructionCost('add', 1.0, 1.0, 0.25, 0.20),
    'sub': InstructionCost('sub', 1.0, 1.0, 0.25, 0.20),
    'inc': InstructionCost('inc', 1.0, 1.0, 0.25, 0.20),
    'dec': InstructionCost('dec', 1.0, 1.0, 0.25, 0.20),
    'mul': InstructionCost('mul', 2.0, 3.0, 1.00, 0.60),
    'imul': InstructionCost('imul', 2.0, 3.0, 1.00, 0.60),
    'div': InstructionCost('div', 3.0, 26.0, 6.00, 0.90),
    'idiv': InstructionCost('idiv', 3.0, 26.0, 6.00, 0.90),

    # 逻辑
    'xor': InstructionCost('xor', 1.0, 1.0, 0.25, 0.20),
    'and': InstructionCost('and', 1.0, 1.0, 0.25, 0.20),
    'or': InstructionCost('or', 1.0, 1.0, 0.25, 0.20),
    'not': InstructionCost('not', 1.0, 1.0, 0.25, 0.20),
    'shl': InstructionCost('shl', 1.0, 1.0, 0.50, 0.30),
    'shr': InstructionCost('shr', 1.0, 1.0, 0.50, 0.30),

    # 分支
    'jmp': InstructionCost('jmp', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'je': InstructionCost('je', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'jne': InstructionCost('jne', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'jg': InstructionCost('jg', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'jl': InstructionCost('jl', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'ja': InstructionCost('ja', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'jb': InstructionCost('jb', 1.0, 0.0, 0.50, 0.30, is_branch=True),
    'call': InstructionCost('call', 2.0, 0.0, 1.00, 0.60, is_branch=True),
    'ret': InstructionCost('ret', 2.0, 0.0, 1.00, 0.60, is_branch=True),
    'cmp': InstructionCost('cmp', 1.0, 1.0, 0.25, 0.20),

    # 栈帧
    'enter': InstructionCost('enter', 3.0, 8.0, 3.00, 0.70),
    'leave': InstructionCost('leave', 2.0, 4.0, 1.00, 0.40),

    # 系统
    'syscall': InstructionCost('syscall', 1.0, 50.0, 50.0, 1.00),
    'int': InstructionCost('int', 1.0, 50.0, 50.0, 1.00),
    'cpuid': InstructionCost('cpuid', 1.0, 100.0, 100.0, 1.00),

    # 默认
    'default': InstructionCost('default', 1.0, 1.0, 0.50, 0.30),
}


class InstructionCostEstimator:
    """指令级微架构成本估算。"""

    def estimate(self, asm_lines: List[str]) -> Tuple[PerfDelta, List[str]]:
        """估算一组汇编指令的微架构成本。"""
        delta = PerfDelta()
        expensive = []

        delta.instructions_before = 0  # Will be set by caller for comparison
        delta.instructions_after = len([l for l in asm_lines if l.strip()])

        total_uops = 0.0
        total_latency = 0.0
        total_mem = 0
        total_branches = 0

        for line in asm_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(';'):
                continue

            mnemonic = self._extract_mnemonic(stripped)
            cost = self._lookup_cost(mnemonic)

            total_uops += cost.uops_fused
            total_latency += cost.latency_cycles
            if cost.is_memory_access:
                total_mem += 1
            if cost.is_branch:
                total_branches += 1

            # 标记昂贵指令
            if cost.latency_cycles > 10:
                expensive.append(
                    "[%s] latency=%.0f cycles: %s" % (
                        cost.mnemonic, cost.latency_cycles,
                        stripped[:50]))

        delta.uops_after = total_uops
        delta.mem_accesses_after = total_mem
        delta.branches_after = total_branches
        delta.unpredictable_branches = self._estimate_unpredictable_branches(
            asm_lines)

        return delta, expensive

    def _extract_mnemonic(self, line: str) -> str:
        parts = line.lower().replace(',', ' ').split()
        if not parts:
            return 'nop'
        mnemonic = parts[0]
        # 处理 lock 前缀 → 将下一个 token 视为助记符
        if mnemonic == 'lock' and len(parts) > 1:
            mnemonic = parts[1]
        return mnemonic

    def _lookup_cost(self, mnemonic: str) -> InstructionCost:
        """查找指令的微架构成本。"""
        if mnemonic in _MICROARCH_COST_TABLE:
            return _MICROARCH_COST_TABLE[mnemonic]
        # 前缀匹配：如 movzx → 归类为 mov
        for prefix in ['mov', 'cmov', 'j', 'set', 'fld', 'fst']:
            if mnemonic.startswith(prefix) and prefix in _MICROARCH_COST_TABLE:
                return InstructionCost(
                    mnemonic,
                    uops_fused=_MICROARCH_COST_TABLE[prefix].uops_fused,
                    latency_cycles=_MICROARCH_COST_TABLE[prefix].latency_cycles,
                    throughput_reciprocal=_MICROARCH_COST_TABLE[prefix].throughput_reciprocal,
                    port_pressure=_MICROARCH_COST_TABLE[prefix].port_pressure,
                    is_memory_access=('ptr' in mnemonic or '[' in mnemonic),
                    is_branch=mnemonic.startswith('j') or mnemonic.startswith('call'),
                )
        return _MICROARCH_COST_TABLE['default']

    @staticmethod
    def _estimate_unpredictable_branches(asm_lines: List[str]) -> int:
        """启发式估计难以预测的分支数。

        模式：
          - 间接跳转 (jmp rax, call [rdi]) → 几乎不可预测
          - 比较后紧跟条件跳转 + 比较值来自内存 → 中度不可预测
          - 循环计数器 → 高度可预测（不计入）
        """
        count = 0
        for line in asm_lines:
            stripped = line.lower().strip()
            # 间接跳转/调用
            if re.search(r'\b(jmp|call)\s+\*?\w+\b', stripped):
                if re.search(r'\[', stripped):
                    count += 1  # 内存间接跳转 → 不可预测
            # 数据依赖的分支
            if re.search(r'\b(j\w+)\b', stripped):
                # 检查比较源是否来自内存
                if re.search(r'cmp\s+.*\[', stripped):
                    count += 1
        return count


# ── 性能影响预测器 ────────────────────────────────────────────────

class PerfImpactPredictor:
    """补丁性能影响静态预测。

    用法:
        predictor = PerfImpactPredictor()
        report = predictor.predict(original_asm, patched_asm, patch_id='CVE-2024-0001')
        print(f'估计开销: {report.estimated_overhead_pct:.1f}%')
    """

    def __init__(self):
        self._estimator = InstructionCostEstimator()

    def predict(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "",
                context_hint: str = "hot_path"
                ) -> PerfImpactReport:
        """预测补丁的性能影响。

        context_hint: 'hot_path' | 'cold_path' | 'unknown'
          影响权重因子。冷路径（错误处理）即使指令多也影响小。
        """
        report = PerfImpactReport(patch_id=patch_id)

        # 原始代码成本
        orig_delta, _ = self._estimator.estimate(original_asm)
        # 补丁后成本
        patch_delta, expensive = self._estimator.estimate(patched_asm)

        # 计算增量
        orig_inst = len([l for l in original_asm if l.strip()])
        patch_inst = len([l for l in patched_asm if l.strip()])

        delta = PerfDelta()
        delta.instructions_before = orig_inst
        delta.instructions_after = patch_inst
        delta.instruction_delta = patch_inst - orig_inst
        if orig_inst > 0:
            delta.instruction_delta_pct = ((patch_inst - orig_inst) / orig_inst) * 100.0
        delta.uops_before = orig_delta.uops_after
        delta.uops_after = patch_delta.uops_after
        if delta.uops_before > 0:
            delta.uops_delta_pct = (
                (delta.uops_after - delta.uops_before) / delta.uops_before * 100.0)
        delta.mem_accesses_before = orig_delta.mem_accesses_after
        delta.mem_accesses_after = patch_delta.mem_accesses_after
        delta.branches_before = orig_delta.branches_after
        delta.branches_after = patch_delta.branches_after
        delta.unpredictable_branches = patch_delta.unpredictable_branches
        # 估计 cache line 触达
        delta.cache_line_touches = self._estimate_cache_lines(patched_asm)

        report.delta = delta
        report.expensive_instructions = expensive

        # 综合开销估算
        overhead = self._compute_overhead(delta, context_hint)

        report.estimated_overhead_pct = overhead

        # 分级
        if overhead < 1.0:
            report.category = ImpactCategory.NEGLIGIBLE
        elif overhead < 3.0:
            report.category = ImpactCategory.MINOR
        elif overhead < 10.0:
            report.category = ImpactCategory.MODERATE
        elif overhead < 30.0:
            report.category = ImpactCategory.SIGNIFICANT
        else:
            report.category = ImpactCategory.SEVERE

        # 热点分析
        report.hotspots = self._identify_hotspots(delta, expensive)

        # 建议
        report.recommendation = self._generate_recommendation(report)

        return report

    def _compute_overhead(self, delta: PerfDelta,
                          context_hint: str) -> float:
        """综合多维度计算性能开销百分比。"""
        # 上下文权重
        weight = {'hot_path': 1.0, 'unknown': 0.5, 'cold_path': 0.1}.get(
            context_hint, 0.5)

        # 三维加权
        inst_impact = abs(delta.instruction_delta_pct) * 0.35
        uops_impact = abs(delta.uops_delta_pct) * 0.40

        mem_impact = 0.0
        mem_delta = delta.mem_accesses_after - delta.mem_accesses_before
        if mem_delta > 0 and delta.instructions_before > 0:
            mem_impact = (mem_delta / max(delta.instructions_before, 1)) * 100.0
        mem_impact *= 0.15

        branch_penalty = 0.0
        if delta.unpredictable_branches > 0:
            # 每个不可预测分支 ≈ 15 cycle 的误预测惩罚
            branch_penalty = delta.unpredictable_branches * 0.10

        overhead = (inst_impact + uops_impact + mem_impact + branch_penalty) * weight
        return max(0.0, overhead)

    @staticmethod
    def _estimate_cache_lines(asm_lines: List[str]) -> int:
        """估计访存会触达多少 cache line。"""
        mem_offsets: Set[int] = set()
        for line in asm_lines:
            m = re.search(r'\[.*\+?(0x[0-9a-f]+|\d+)\]', line, re.I)
            if m:
                try:
                    val_str = m.group(1)
                    val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                    cache_line = val // 64
                    mem_offsets.add(cache_line)
                except ValueError:
                    pass
        return len(mem_offsets)

    def _identify_hotspots(self, delta: PerfDelta,
                           expensive: List[str]) -> List[str]:
        """识别性能热点。"""
        hotspots = []
        if delta.instruction_delta_pct > 20:
            hotspots.append("指令数增加 %.0f%% — 若在热路径上影响显著" % delta.instruction_delta_pct)
        if delta.unpredictable_branches > 2:
            hotspots.append("%d 个难以预测的分支 — 分支误预测代价约 15-20 cycles/次" % delta.unpredictable_branches)
        if delta.cache_line_touches > 8:
            hotspots.append("触达 %d 个 cache line — 可能导致 L1 驱逐" % delta.cache_line_touches)
        for exp_inst in expensive[:2]:
            hotspots.append("昂贵指令: %s" % exp_inst)
        return hotspots

    def _generate_recommendation(self, report: PerfImpactReport) -> str:
        """生成性能优化建议。"""
        cat = report.category
        if cat == ImpactCategory.NEGLIGIBLE:
            return "性能影响可忽略——无需优化"
        elif cat == ImpactCategory.MINOR:
            return ("轻微影响 (%.1f%%)——若补丁在冷路径上可接受，"
                    "热路径上建议做一次微基准测试" % report.estimated_overhead_pct)
        elif cat == ImpactCategory.MODERATE:
            return ("中等影响 (%.1f%%)——建议对补丁区域做 perf stat 验证，"
                    "关注 IPC 和分支误预测率" % report.estimated_overhead_pct)
        elif cat == ImpactCategory.SIGNIFICANT:
            return ("显著影响 (%.1f%%)——审查指令选择：用 xor/lea 替代 mov-imm，"
                    "用条件移动 (cmov) 替代不可预测分支" % report.estimated_overhead_pct)
        else:
            return ("严重性能退化 (%.1f%%)——补丁可能需要架构级重设计" % report.estimated_overhead_pct)
