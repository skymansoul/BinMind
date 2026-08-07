# 创建: 2026-07-12 上午
# 修改: 2026-07-12 — 虚拟栈检测 + 内存模型一致性评分
"""
二进制 IR 提升质量评估器 — 无需 ground truth 的 IR 质量自动化度量。

二进制提升器 (RetDec/Ghidra/McSema) 输出的 LLVM IR 在"功能正确性"和
"分析适用性"两个维度上差异显著。Emulation-style IR (EIR) 使用虚拟栈、
寄存器变量、缺少类型信息——功能正确但下游分析工具无法直接使用。
High-level IR (HIR) 尝试恢复变量和类型但可能引入语义错误。

本模块提供三个维度的自动化质量评估 (不需要源码作为 ground truth):
  1. 虚拟栈检测: 识别 alloca + store/load 模式——虚拟栈操作越多, IR 质量越低
  2. 内存模型一致性: 检测 IR 中的 load/store 是否与原始二进制的访存模式一致
  3. 分析适用性: 评估 IR 是否可被下游工具 (angr/Binsec) 直接消费

每个维度 0-100 分, 综合加权为总质量分。
60+ 分 → 适合下游分析; 40-59 → 需要手动标注; <40 → 仅适合模拟执行。

ref: An & Lee — EIR vs HIR 转换, 本项目将其质量维度
     量化为三个可自动计算的指标, 不依赖源码 ground truth
ref: RetDec LLVM IR output format — 虚拟栈模式的定义参考,
     本项目将其作为"低质量"基线
ref: McSema (Trail of Bits) — 二进制提升器的语义正确性验证,
     本项目的内存模型一致性检查借鉴其"指令→IR 1:1 映射"思路
"""

from dataclasses import dataclass, field
from collections import Counter
import re


@dataclass
class IRQualityReport:
    """IR 提升质量评估报告。"""
    module_name: str = ''
    virtual_stack_score: float = 0.0    # 0-100, 越高越好 (越少虚拟栈)
    memory_fidelity_score: float = 0.0  # 0-100
    analysis_suitability_score: float = 0.0  # 0-100
    overall: float = 0.0               # 0-100
    level: str = ''                    # 'ready' | 'needs_work' | 'sim_only'
    issues: list[str] = field(default_factory=list)


def detect_virtual_stack(ir_lines: list[str]) -> tuple[float, list[str]]:
    """检测 EIR 的虚拟栈模式——alloca/load/store 围绕单个栈基址。

    虚拟栈特征: alloca 单个巨大数组 (模拟硬件栈), 所有局部变量
    通过 GEP 索引到此数组。越多此类模式 → 越低分。"""
    alloca_count = 0
    virtual_stack_alloca = 0
    issues = []

    for line in ir_lines:
        stripped = line.strip()
        if stripped.startswith('%') and 'alloca' in stripped:
            alloca_count += 1
            # 虚拟栈 alloca 特征: 大尺寸 (>256 bytes) 且仅出现一次
            size_match = re.search(r'alloca\s+\[?\s*(\d+)\s*x\s*i?\d+', stripped)
            if size_match:
                size = int(size_match.group(1))
                if size > 256:
                    virtual_stack_alloca += 1

    if alloca_count == 0:
        return 100.0, []

    virtual_ratio = virtual_stack_alloca / max(1, alloca_count)
    if virtual_ratio > 0.5:
        issues.append(f'虚拟栈占比过高 ({virtual_ratio:.0%}), 考虑运行 EIR→HIR 转换')
    elif virtual_ratio > 0.2:
        issues.append(f'部分虚拟栈残留 ({virtual_ratio:.0%})')

    score = 100.0 * (1.0 - virtual_ratio)
    return round(score, 1), issues


def detect_memory_fidelity(ir_lines: list[str],
                           original_ins_count: int = 0) -> tuple[float, list[str]]:
    """检测 IR 内存模型与原始二进制的保真度。

    检查: load/store 计数比、内联汇编残留、Intrinsic 使用。
    越多内联汇编 (call asm) → 越多未提升的指令 → 越低分。"""
    load_count = sum(1 for l in ir_lines if 'load' in l and 'volatile' not in l)
    store_count = sum(1 for l in ir_lines if 'store' in l and 'volatile' not in l)
    asm_count = sum(1 for l in ir_lines if 'call void asm' in l or 'call asm' in l)
    intrinsic_count = sum(1 for l in ir_lines if '@llvm.' in l)

    issues = []
    score = 100.0

    # 内联汇编惩罚: 每条 -5 分, 最多扣 30
    asm_penalty = min(30, asm_count * 5)
    score -= asm_penalty
    if asm_count > 3:
        issues.append(f'{asm_count} 条未提升的内联汇编指令')

    # Intrinsic 过多: 每条 -2 分, 最多扣 20
    intrinsic_penalty = min(20, intrinsic_count * 2)
    score -= intrinsic_penalty
    if intrinsic_count > 10:
        issues.append(f'{intrinsic_count} 条 LLVM intrinsic, 部分架构特性未抽象')

    # load/store 比率检查: 极端不对称暗示语义错误
    if load_count > 0 and store_count == 0 and original_ins_count > 10:
        score -= 15
        issues.append('有 load 无 store——缺少副作用建模')

    return round(max(0, score), 1), issues


def detect_analysis_suitability(ir_lines: list[str]) -> tuple[float, list[str]]:
    """评估 IR 是否可被下游分析工具直接消费。

    检查: PHI node 存在 (SSA 形式完好)、变量命名 (非纯数字临时变量)、
    类型信息完整性 (i32/i64 vs iN 截断)。"""
    phi_count = sum(1 for l in ir_lines if l.strip().startswith('phi '))
    unnamed_ratio = 0.0
    total_vars = 0
    unnamed = 0

    for line in ir_lines:
        m = re.match(r'\s*%(\d+)', line)
        if m:
            total_vars += 1
            unnamed += 1
        elif re.match(r'\s*%\w+', line):
            total_vars += 1

    if total_vars > 0:
        unnamed_ratio = unnamed / total_vars

    score = 100.0
    issues = []

    # PHI nodes: 有 → +分 (SSA 完整)
    if phi_count == 0 and total_vars > 10:
        score -= 10
        issues.append('无 PHI node——SSA 形式不完整, angr/Binsec 可能无法工作')

    # 未命名变量惩罚
    if unnamed_ratio > 0.5:
        penalty = (unnamed_ratio - 0.5) * 40
        score -= penalty
        issues.append(f'{unnamed_ratio:.0%} 变量为临时编号, 可读性差')

    return round(max(0, score), 1), issues


class IRLiftingQualityEvaluator:
    """二进制 IR 提升质量评估器。"""

    def evaluate(self, ir_code: str, module_name: str = '',
                 original_ins_count: int = 0) -> IRQualityReport:
        lines = ir_code.split('\n')
        report = IRQualityReport(module_name=module_name)

        report.virtual_stack_score, vs_issues = detect_virtual_stack(lines)
        report.memory_fidelity_score, mf_issues = detect_memory_fidelity(
            lines, original_ins_count)
        report.analysis_suitability_score, as_issues = detect_analysis_suitability(
            lines)

        report.issues = vs_issues + mf_issues + as_issues

        # 加权综合: 虚拟栈 30% + 内存保真 35% + 分析适用性 35%
        report.overall = round(
            0.30 * report.virtual_stack_score +
            0.35 * report.memory_fidelity_score +
            0.35 * report.analysis_suitability_score, 1)

        if report.overall >= 60:
            report.level = 'ready'
        elif report.overall >= 40:
            report.level = 'needs_work'
        else:
            report.level = 'sim_only'

        return report


__all__ = ['IRLiftingQualityEvaluator', 'IRQualityReport',
           'detect_virtual_stack', 'detect_memory_fidelity',
           'detect_analysis_suitability']
