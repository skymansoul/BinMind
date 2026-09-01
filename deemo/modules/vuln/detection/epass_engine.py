# coding: utf-8
"""
漏洞利用原语感知的沙箱策略合成-编排引擎。

管线流程:
  1. 输入: 漏洞分析管线产出(漏洞类型+利用策略+保护机制)
  2. 原语映射: ExploitPrimitiveMapper-策略-系统调用阻断集
  3. BPF合成: SeccompPolicySynthesizer-可加载seccomp-BPF字节码
  4. 效果评估: 阻断后的预期防护效果+程序功能影响评估
  5. 策略推荐: 按效果/影响比排序的多级策略建议

策略分级:
  STRICT: 阻断所有核心syscall(KILL)-最高安全, 可能影响程序功能
  BALANCED: 核心syscall-ERRNO, 高影响syscall-ERRNO-平衡安全与可用
  PERMISSIVE: 仅阻断非高影响核心syscall-最低功能影响

与现有沙箱模块集成:
  sandbox_policy_gen - 通用allowlist(程序基线)
  sandbox_escape_detector - 运行时逃逸检测
  epass_engine - 利用特定的blocklist(漏洞临时防护)
  三者组合: 基线allowlist + 逃逸检测 + 利用blocklist = 纵深防御

创新点:
  预防式+利用原语特定-不同于DeSFAM(反应式)和BeaCon(通用allowlist),
  EPASS策略仅在二进制分析发现具体利用技术后才激活,
  且仅阻断该利用技术所需的syscall-最小化功能影响。
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .epass_exploit_mapper import (
    ExploitPrimitive, SyscallBlocklist, ExploitPrimitiveMapper,
)
from .epass_policy_synthesizer import SeccompPolicy, SeccompPolicySynthesizer

_log = logging.getLogger(__name__)


# 策略分级


class PolicyLevel(str):
    STRICT = "STRICT"
    BALANCED = "BALANCED"
    PERMISSIVE = "PERMISSIVE"


@dataclass
class PolicyRecommendation:
    """单条策略建议-含seccomp策略+效果评估"""
    level: str                         # PolicyLevel值
    policy: Optional[SeccompPolicy] = None
    # 效果评估
    exploit_blocked: List[str] = field(default_factory=list)
    effectiveness_score: float = 0.0   # [0,1] 阻断效果
    functionality_impact: float = 0.0   # [0,1] 功能影响(越低越好)
    # 元数据
    blocked_syscall_count: int = 0
    high_impact_count: int = 0
    recommendation: str = ""


@dataclass
class EpassReport:
    """EPASS策略合成完整报告"""
    target_binary: str
    vulnerability_type: str
    # 多级策略
    recommendations: List[PolicyRecommendation] = field(default_factory=list)
    # 最佳推荐
    best_recommendation: Optional[PolicyRecommendation] = None
    # 元数据
    exploit_primitives_found: List[str] = field(default_factory=list)
    generated_at: str = ""


# EPASS引擎


class EpassEngine:
    """漏洞利用原语感知的沙箱策略合成引擎。

    与exploit_generation_pipeline集成:
      ExploitPlan.strategies - 传入strategies参数
      保护机制信息 - 用于效果评估(ASLR/NX已启用-某些原语天然受阻)
    """

    def __init__(self):
        self._mapper = ExploitPrimitiveMapper()
        self._synthesizer = SeccompPolicySynthesizer()

    def generate(self, strategies: List[str] = None,
                  primitives: List[str] = None,
                  vuln_type: str = "",
                  binary_name: str = "",
                  existing_protections: Dict[str, str] = None
                  ) -> EpassReport:
        """合成利用原语感知的seccomp策略。

        参数:
          strategies: 利用策略列表(['rop_chain','ret2libc',...])
          primitives: 利用原语列表(与strategies二选一)
          vuln_type: 漏洞类型
          binary_name: 目标程序名
          existing_protections: 已有保护{ASLR,NX,PIE,...}

        返回EpassReport。
        """
        prot = existing_protections or {}

        # 原语映射
        if strategies:
            blocklists = self._mapper.map_from_strategies(strategies)
        elif primitives:
            blocklists = self._mapper.map_from_primitives(primitives)
        else:
            return EpassReport(target_binary=binary_name,
                                vulnerability_type=vuln_type)

        if not blocklists:
            return EpassReport(target_binary=binary_name,
                                vulnerability_type=vuln_type)

        unified = self._mapper.get_unified_blocklist(blocklists)

        # 三级策略合成
        recommendations = []

        # STRICT-阻断所有核心syscall(KILL)
        strict_bl = SyscallBlocklist(
            target_primitive="strict",
            critical_syscalls=unified.critical_syscalls,
            auxiliary_syscalls=unified.auxiliary_syscalls,
            high_impact_syscalls=unified.high_impact_syscalls)
        strict_policy = self._synthesizer.synthesize(
            strict_bl, f"epass_{binary_name}_strict", use_errno=False)
        func_impact_strict = self._assess_functional_impact(
            unified, PolicyLevel.STRICT, prot)
        recommendations.append(PolicyRecommendation(
            level=PolicyLevel.STRICT, policy=strict_policy,
            exploit_blocked=[bl.target_primitive for bl in blocklists],
            effectiveness_score=unified.estimated_effectiveness,
            functionality_impact=func_impact_strict,
            blocked_syscall_count=len(strict_bl.critical_syscalls),
            high_impact_count=len(strict_bl.high_impact_syscalls),
            recommendation=f"最高安全-阻断{len(strict_bl.critical_syscalls)}个syscall, "
                           f"功能影响{func_impact_strict:.0%}"))

        # BALANCED-KILL+高影响ERRNO
        balanced_policy = self._synthesizer.synthesize(
            unified, f"epass_{binary_name}_balanced", use_errno=True)
        func_impact_bal = self._assess_functional_impact(
            unified, PolicyLevel.BALANCED, prot)
        recommendations.append(PolicyRecommendation(
            level=PolicyLevel.BALANCED, policy=balanced_policy,
            exploit_blocked=[bl.target_primitive for bl in blocklists],
            effectiveness_score=unified.estimated_effectiveness * 0.9,
            functionality_impact=func_impact_bal,
            blocked_syscall_count=len(unified.critical_syscalls),
            high_impact_count=len(unified.high_impact_syscalls),
            recommendation=f"平衡-高影响syscall返回EPERM而非KILL, "
                           f"功能影响{func_impact_bal:.0%}"))

        # PERMISSIVE-仅阻断非高影响核心syscall
        permissive_critical = [s for s in unified.critical_syscalls
                                if s not in unified.high_impact_syscalls]
        perm_bl = SyscallBlocklist(
            target_primitive="permissive",
            critical_syscalls=permissive_critical,
            auxiliary_syscalls=unified.auxiliary_syscalls,
            high_impact_syscalls=[])
        perm_policy = self._synthesizer.synthesize(
            perm_bl, f"epass_{binary_name}_permissive", use_errno=True)
        func_impact_perm = self._assess_functional_impact(
            perm_bl, PolicyLevel.PERMISSIVE, prot)
        recommendations.append(PolicyRecommendation(
            level=PolicyLevel.PERMISSIVE, policy=perm_policy,
            exploit_blocked=[bl.target_primitive for bl in blocklists],
            effectiveness_score=unified.estimated_effectiveness * 0.6,
            functionality_impact=func_impact_perm,
            blocked_syscall_count=len(permissive_critical),
            high_impact_count=0,
            recommendation=f"宽松-仅阻断{len(permissive_critical)}个低影响syscall, "
                           f"功能影响{func_impact_perm:.0%}"))

        # 最佳推荐-选取效果>0.5中功能影响最小的
        best = None
        best_score = -1.0
        for rec in recommendations:
            score = rec.effectiveness_score * (1.0 - rec.functionality_impact)
            if score > best_score:
                best_score = score
                best = rec

        primitives_found = [bl.target_primitive for bl in blocklists]

        return EpassReport(
            target_binary=binary_name,
            vulnerability_type=vuln_type,
            recommendations=recommendations,
            best_recommendation=best,
            exploit_primitives_found=primitives_found)

    def _assess_functional_impact(self, blocklist: SyscallBlocklist,
                                    level: str,
                                    prot: Dict[str, str]) -> float:
        """评估策略对程序功能的影响-基于syscall的重要性权重。

        高影响syscall每阻断一个-+15%功能影响
        核心syscall每阻断一个-+5%功能影响
        ERRNO模式-影响减半(程序可优雅处理错误)
        """
        impact = 0.0
        impact += len(blocklist.high_impact_syscalls) * 0.15
        impact += (len(blocklist.critical_syscalls) -
                   len(blocklist.high_impact_syscalls)) * 0.05
        if level != PolicyLevel.STRICT:
            impact *= 0.5  # ERRNO-影响减半
        return min(1.0, impact)


# 便捷入口


def generate_epass_policy(strategies: List[str],
                            binary_name: str = "",
                            vuln_type: str = "",
                            level: str = PolicyLevel.BALANCED
                            ) -> EpassReport:
    """EPASS策略生成便捷入口"""
    return EpassEngine().generate(
        strategies=strategies, vuln_type=vuln_type, binary_name=binary_name)


__all__ = [
    "PolicyLevel",
    "PolicyRecommendation",
    "EpassReport",
    "EpassEngine",
    "generate_epass_policy",
]
