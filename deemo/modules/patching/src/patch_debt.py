# 修改记录:
# 2025-08-15 11:45 — 初始实现：四维技术债务量化 + 加权合成
# 2025-08-16 09:18 — 增加补偿策略生成器（针对每种债务类型的偿还计划）

"""Patch Debt Quantifier — 补丁技术债务的量化评估。

每个二进制补丁在修复漏洞的同时引入"技术债务"——
代码质量的累积衰减。本模块从四个维度量化：

  1. Gadget 密度增量 (gadget_density_delta):
     补丁引入的新 ROP/JOP gadget 数量 / 补丁字节数。
     度量：每次修补增加了多少可利用的代码片段。

  2. 代码熵增量 (entropy_delta):
     补丁区域与周围代码的字节熵差异。
     高熵差表示补丁与原有编译产物的统计特征不匹配 → 容易被识别为"修补痕迹"。

  3. 体积膨胀率 (bloat_ratio):
     补丁字节数 / 原漏洞函数字节数。
     >1.0 表示补丁比原函数更大（如添加了大量安全检查）。

  4. 编译器优化偏离度 (optimization_divergence):
     补丁代码与编译器优化输出的特征距离。
     补丁通常是手工/模板生成的汇编 → 缺少编译器的指令调度和对齐优化。

债务偿还模型：
  复合债务分 = Σ(w_i · dimension_i)
  偿债紧急度按指数增长：urgency(t) = 1 - exp(-k · debt_score · t)
  当 urgency > 0.7 时建议"重构"（寻找源码级修复替代二进制补丁）。

与 patch_quality_evaluator 的差异:
  quality_evaluator 评估补丁的功能正确性（是否修了该修的）。
  本模块评估补丁的长期维护成本（修了之后的副作用）。
  两者正交：一个补丁可以 quality=high 但 debt=high（如临时 hotfix）。
"""

import math
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum
from collections import Counter

_log = logging.getLogger(__name__)


class DebtSeverity(str, Enum):
    NEGLIGIBLE = "negligible"     # < 0.15，正常修补开销
    ACCEPTABLE = "acceptable"     # 0.15-0.35
    CONCERNING = "concerning"     # 0.35-0.55，建议规划偿还
    SEVERE = "severe"             # 0.55-0.75，短期需重构
    CRITICAL = "critical"         # > 0.75，立即重构


@dataclass
class DebtDimensions:
    """四维技术债务度量。"""
    # 维度 1: Gadget 密度
    gadget_count_before: int = 0
    gadget_count_after: int = 0
    gadget_density_delta: float = 0.0     # Δ gadgets per byte of patch

    # 维度 2: 字节熵
    entropy_before: float = 0.0            # 补丁区域的 Shannon 熵
    entropy_after: float = 0.0
    entropy_delta: float = 0.0            # |after - before|，越高越突兀

    # 维度 3: 体积膨胀
    original_function_bytes: int = 1
    patch_bytes: int = 0
    bloat_ratio: float = 0.0              # patch / original

    # 维度 4: 优化偏离度
    optimization_divergence: float = 0.0  # 0..1，1=完全不像编译器输出


@dataclass
class DebtReport:
    """补丁技术债务完整报告。"""
    patch_id: str = ""
    dimensions: DebtDimensions = field(default_factory=DebtDimensions)
    composite_score: float = 0.0           # 0..1 复合债务分
    severity: DebtSeverity = DebtSeverity.NEGLIGIBLE
    # 维度权重
    weights: Dict[str, float] = field(default_factory=lambda: {
        'gadget': 0.35, 'entropy': 0.20, 'bloat': 0.25, 'opt_div': 0.20,
    })
    # 偿还建议
    amortization_months: float = 0.0       # 建议的偿还周期（月）
    urgency_now: float = 0.0               # 当前紧急度
    remediation_plan: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'composite': round(self.composite_score, 4),
            'severity': self.severity.value,
            'gadget_delta': round(self.dimensions.gadget_density_delta, 4),
            'entropy_delta': round(self.dimensions.entropy_delta, 4),
            'bloat_ratio': round(self.dimensions.bloat_ratio, 4),
            'opt_divergence': round(self.dimensions.optimization_divergence, 4),
            'amortization_months': round(self.amortization_months, 1),
            'urgency': round(self.urgency_now, 4),
            'remediation': self.remediation_plan,
        }


# ── Gadget 扫描器 ─────────────────────────────────────────────────

class GadgetScanner:
    """在二进制字节流中扫描 ROP gadget。

    识别常见 gadget 模式：
      - ret-terminated (c3): pop reg; ret, mov reg, [mem]; ret
      - call-terminated (ff / e8): 间接/直接调用后尾
      - jmp-terminated (eb / e9): 无条件跳转尾
      - syscall/int-terminated: 系统调用尾
    """

    # gadget 终止字节
    _TERMINATORS = {
        0xC3: 'ret',
        0xC2: 'retn',
        0xCB: 'retf',
        0xCA: 'retfn',
        0xFF: 'indirect',  # ff /4 = jmp, ff /2 = call
        0xEB: 'jmp_short',
        0xE9: 'jmp',
        0x0F: 'sys',       # 0f 05 = syscall, 0f 34 = sysenter
    }

    def count_gadgets(self, code_bytes: bytes, min_len: int = 2,
                      max_len: int = 16) -> int:
        """在代码字节中统计可达 gadget 数。

        算法：从每个字节偏移向后扫描，检查是否在 max_len 内
        遇到终止字节。对 x86 的变长指令集，每个偏移都可能是一个
        合法 gadget 入口（术语：gadget abundance）。
        """
        if not code_bytes:
            return 0
        count = 0
        n = len(code_bytes)
        for start in range(n - min_len + 1):
            for end in range(start + min_len, min(start + max_len + 1, n)):
                if code_bytes[end - 1] in self._TERMINATORS:
                    # 检查终止字节不是更长指令的一部分
                    if self._is_valid_terminator(code_bytes, end - 1, start):
                        count += 1
                        break
        return count

    @staticmethod
    def _is_valid_terminator(data: bytes, pos: int, start: int) -> bool:
        """判断 pos 处的字节是否为独立的终止符。"""
        if pos >= len(data):
            return False
        b = data[pos]
        if b in (0xC3, 0xCB):  # ret / retf — 总是独立终止
            return True
        if b == 0xC2 and pos + 2 <= len(data):  # retn imm16
            return True
        if b == 0xEB:  # jmp short — 总是独立
            return True
        if b == 0xE9 and pos + 5 <= len(data):  # jmp near
            return True
        # 0F 05 / 0F 34 需要至少 2 字节
        if b == 0x0F and pos + 1 < len(data):
            next_b = data[pos + 1]
            if next_b in (0x05, 0x34):
                return True
        if b == 0xFF and pos + 1 < len(data):
            modrm = data[pos + 1]
            reg_field = (modrm >> 3) & 0x7
            if reg_field in (0x04, 0x05):  # jmp / call indirect
                return True
        return False


# ── 熵计算器 ──────────────────────────────────────────────────────

class EntropyCalculator:
    """字节级 Shannon 熵计算。"""

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """计算字节分布的 Shannon 熵（bit）。"""
        if not data:
            return 0.0
        freq = Counter(data)
        n = len(data)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def relative_entropy(data: bytes, reference_entropy: float) -> float:
        """相对熵差：|H(data) - H_ref| / max(H_ref, 1)。"""
        h = EntropyCalculator.shannon_entropy(data)
        ref = max(reference_entropy, 1.0)
        return abs(h - ref) / ref


# ── 优化偏离度检测器 ──────────────────────────────────────────────

class OptimizationDivergenceDetector:
    """检测补丁代码与编译器优化输出的偏离程度。

    编译器优化产物的特征：
      - 指令长度分布接近幂律（少数长指令 + 多数短指令）
      - NOP 间距规律（对齐到 16/32 字节边界）
      - 寄存器使用偏向（优先使用 r8-r15 减少 REX 前缀）
      - 基本块大小分布接近对数正态

    手工/模板补丁的特征：
      - 指令长度均匀（多为短指令序列）
      - NOP 缺失或位置随机
      - 寄存器使用模式不一致
    """

    def measure(self, code_bytes: bytes) -> float:
        """返回 0..1 的优化偏离度。"""
        if len(code_bytes) < 8:
            return 0.0

        divergence = 0.0
        # 特征 1: NOP 密度（编译器生成的对齐 NOP 占比约 2-5%）
        nop_count = code_bytes.count(0x90)
        nop_ratio = nop_count / len(code_bytes)
        # 编译器输出预期 0.02-0.05，偏离此区间加分
        if nop_ratio < 0.005:
            divergence += 0.25  # 无对齐 → 手工代码
        elif nop_ratio > 0.15:
            divergence += 0.20  # 过多 NOP → 可疑

        # 特征 2: REX 前缀密度（x86-64 编译器偏好用 r8-r15 需 REX）
        rex_count = sum(1 for b in code_bytes if 0x40 <= b <= 0x4F)
        rex_ratio = rex_count / max(len(code_bytes), 1)
        if rex_ratio < 0.03:
            divergence += 0.20  # REX 极少 → 可能只用低 8 寄存器

        # 特征 3: 指令长度方差（编译器输出有较大的方差）
        if len(code_bytes) >= 16:
            chunks = [code_bytes[i:i+4] for i in range(0, min(len(code_bytes), 64), 4)]
            chunk_entropies = [
                EntropyCalculator.shannon_entropy(c) for c in chunks if c
            ]
            if len(chunk_entropies) >= 3:
                mu = sum(chunk_entropies) / len(chunk_entropies)
                variance = sum((h - mu) ** 2 for h in chunk_entropies) / len(chunk_entropies)
                std = math.sqrt(variance)
                if std < 0.3:
                    divergence += 0.25  # 过于均匀 → 模板化代码

        # 特征 4: 字节值分布（编译器输出有特征性分布）
        byte_entropy = EntropyCalculator.shannon_entropy(code_bytes)
        if byte_entropy < 3.0:  # 编译器输出的代码熵通常 3.5-5.5
            divergence += 0.30

        return min(divergence, 1.0)


# ── 债务量化器 ────────────────────────────────────────────────────

class PatchDebtQuantifier:
    """补丁技术债务主量化器。

    用法:
        quant = PatchDebtQuantifier()
        report = quant.quantify(
            original_function_bytes, patched_function_bytes,
            surrounding_code_context, patch_id='CVE-2024-0001')
        print(f'债务分: {report.composite_score:.2f}, 等级: {report.severity.value}')
    """

    def __init__(self):
        self._gadget_scanner = GadgetScanner()
        self._entropy_calc = EntropyCalculator()
        self._opt_div_detector = OptimizationDivergenceDetector()
        # 默认权重
        self.weights = {
            'gadget': 0.35,
            'entropy': 0.20,
            'bloat': 0.25,
            'opt_div': 0.20,
        }

    def quantify(self, original_function_bytes: bytes,
                 patched_function_bytes: bytes,
                 surrounding_context: bytes = b"",
                 patch_id: str = "") -> DebtReport:
        """主入口：量化补丁的技术债务。"""

        dims = DebtDimensions()

        # 维度 1: Gadget 密度
        n_before = self._gadget_scanner.count_gadgets(original_function_bytes)
        n_after = self._gadget_scanner.count_gadgets(patched_function_bytes)
        dims.gadget_count_before = n_before
        dims.gadget_count_after = n_after
        patch_byte_count = abs(len(patched_function_bytes) - len(original_function_bytes))
        if patch_byte_count > 0 and n_after > n_before:
            dims.gadget_density_delta = (n_after - n_before) / patch_byte_count
        else:
            dims.gadget_density_delta = 0.0

        # 维度 2: 字节熵
        # 以 surrounding_context 的熵为参考
        ref_entropy = self._entropy_calc.shannon_entropy(
            surrounding_context) if surrounding_context else 4.5
        dims.entropy_before = self._entropy_calc.shannon_entropy(original_function_bytes)
        dims.entropy_after = self._entropy_calc.shannon_entropy(patched_function_bytes)
        dims.entropy_delta = self._entropy_calc.relative_entropy(
            patched_function_bytes, ref_entropy)

        # 维度 3: 体积膨胀
        dims.original_function_bytes = max(len(original_function_bytes), 1)
        dims.patch_bytes = len(patched_function_bytes)
        dims.bloat_ratio = len(patched_function_bytes) / max(len(original_function_bytes), 1)

        # 维度 4: 优化偏离度
        dims.optimization_divergence = self._opt_div_detector.measure(
            patched_function_bytes)

        # 合成
        report = DebtReport(patch_id=patch_id, dimensions=dims,
                           weights=dict(self.weights))
        report.composite_score = self._compute_composite(dims, self.weights)
        report.severity = self._classify(report.composite_score)

        # 偿还模型: amortization_months = 12 / (1 + debt_score * 10)
        # 债务越高，偿还越紧迫
        debt = report.composite_score
        if debt < 0.05:
            report.amortization_months = 24.0
        else:
            report.amortization_months = max(1.0, 12.0 / (1.0 + debt * 8.0))

        # 当前紧急度（假设补丁已存活 3 个月）
        k = 0.15  # 紧急度增长速率
        assumed_age_months = 3.0
        report.urgency_now = 1.0 - math.exp(-k * debt * assumed_age_months)

        # 偿还计划
        report.remediation_plan = self._generate_plan(dims)

        return report

    def _compute_composite(self, dims: DebtDimensions,
                           weights: Dict[str, float]) -> float:
        """加权合成债务分。每维度先归一化到 0..1。"""
        # Gadget: 归一化（假设 ≤ 0.5 gadgets/byte 为严重）
        g_norm = min(dims.gadget_density_delta / 0.5, 1.0)

        # Entropy: 已经 0..1
        e_norm = min(dims.entropy_delta, 1.0)

        # Bloat: log 归一化（1x=0, 2x=0.5, 4x=1.0）
        if dims.bloat_ratio <= 1.0:
            b_norm = 0.0
        else:
            b_norm = min(math.log2(dims.bloat_ratio) / 2.0, 1.0)

        # Opt divergence: 已经 0..1
        o_norm = dims.optimization_divergence

        composite = (
            weights['gadget'] * g_norm +
            weights['entropy'] * e_norm +
            weights['bloat'] * b_norm +
            weights['opt_div'] * o_norm
        )
        return min(composite, 1.0)

    def _classify(self, score: float) -> DebtSeverity:
        if score < 0.15:
            return DebtSeverity.NEGLIGIBLE
        elif score < 0.35:
            return DebtSeverity.ACCEPTABLE
        elif score < 0.55:
            return DebtSeverity.CONCERNING
        elif score < 0.75:
            return DebtSeverity.SEVERE
        return DebtSeverity.CRITICAL

    def _generate_plan(self, dims: DebtDimensions) -> List[str]:
        """根据债务维度生成针对性偿还建议。"""
        plan = []
        if dims.gadget_density_delta > 0.1:
            plan.append(
                "Gadget 密度过高：审查补丁中多余的立即数和内存引用，"
                "用 xor/lea 替代 mov-imm 序列")
        if dims.entropy_delta > 0.3:
            plan.append(
                "熵差异大：补丁字节模式与周围代码显著不同，"
                "考虑用编译器重新编译补丁区域以减少统计特征差异")
        if dims.bloat_ratio > 1.5:
            plan.append(
                "体积膨胀 %.1fx：评估是否可删除冗余的安全检查" % dims.bloat_ratio)
        if dims.optimization_divergence > 0.5:
            plan.append(
                "优化偏离度高：补丁可能未经过编译器优化 pipeline，"
                "建议将修复逻辑回移植到源码并重新编译")
        if not plan:
            plan.append("债务水平可接受，维持当前补丁")
        return plan
