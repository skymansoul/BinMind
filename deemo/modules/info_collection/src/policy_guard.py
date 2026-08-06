"""
策略绑定的意图边界守卫 (PBIS)。

在分类器输出和执行路由之间插入策略检查层, 确保采集动作不超出
授权边界。每条规则建模为 (条件, 动作) 对, 按优先级顺序评估,
首个匹配的规则决定处置结果。

条件维度: category + target_cidrs + target_domain_pattern + method_forbidden
动作维度: ALLOW / DENY / REDACT / CAP_DEPTH

与网络防火墙 ACL 的关键差异: 传统 ACL 基于 IP/端口做二值决策,
本模块基于采集意图语义做细粒度控制 —— 例如 "允许 FILE_ANALYSIS
但仅限 PE 格式" 或 "允许 INTEL_CORRELATION 但屏蔽境外 OSINT 源"。

规则的优先级排序 + 首匹配语义 (first-match semantics) 参考了
IETF RFC 中防火墙策略语言的经典设计 (参见 PF / iptables 的规则链模型)。
CAP_DEPTH 和 REDACT 两种非二值动作是本模块对安全采集场景的适配。
"""

# File: policy_guard.py  |  2026-08-01 create PBIS; 2026-08-04 audit: replace Policy-as-Prompt

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple

from .intent_route import IntentCategory, IntentResult, CollectorSpec


class PolicyAction(Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"       # 脱敏 target 后放行
    CAP_DEPTH = "cap_depth"  # 强制限制采集深度


@dataclass
class PolicyRule:
    """单条策略规则。条件全部满足时触发对应动作。"""
    name: str
    action: PolicyAction
    # 匹配条件 (None = 不限制)
    categories: Optional[Set[IntentCategory]] = None
    target_cidrs: Optional[List[str]] = None     # 目标 IP 范围
    target_domain_pattern: Optional[str] = None  # 域名正则
    method_forbidden: Optional[Set[str]] = None  # 禁止的采集方式
    depth_max: Optional[str] = None              # 强制最大深度
    priority: int = 100     # 越小越优先

    def matches(self, result: IntentResult) -> bool:
        """检查 IntentResult 是否匹配此规则的条件。"""
        if self.categories is not None and result.category not in self.categories:
            return False
        if self.target_cidrs is not None and result.params.target:
            if not self._ip_in_cidrs(result.params.target):
                return False
        if self.target_domain_pattern is not None and result.params.target:
            if not re.search(self.target_domain_pattern, result.params.target, re.IGNORECASE):
                return False
        if self.method_forbidden is not None:
            if result.params.method in self.method_forbidden:
                return False
        return True

    def _ip_in_cidrs(self, target: str) -> bool:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        for cidr in (self.target_cidrs or []):
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False


@dataclass
class PolicyVerdict:
    """策略检查结果。"""
    allowed: bool
    action: PolicyAction
    matched_rule: str        # 触发的规则名
    modified_result: Optional[IntentResult] = None  # REDACT/CAP_DEPTH 时的修改版本
    deny_reason: str = ""


# ---------------------------------------------------------------------------
# 预置策略模板
# ---------------------------------------------------------------------------

_PRESET_RULES: List[PolicyRule] = [
    PolicyRule(
        name="deny_external_dynamic",
        action=PolicyAction.DENY,
        categories={IntentCategory.DYNAMIC_INTERACTION},
        target_cidrs=None,  # 仅示例: 实际应配置为内部 IP 范围
        priority=10,
    ),
    PolicyRule(
        name="cap_intel_depth",
        action=PolicyAction.CAP_DEPTH,
        categories={IntentCategory.INTEL_CORRELATION},
        depth_max="standard",
        priority=20,
    ),
    PolicyRule(
        name="redact_external_targets",
        action=PolicyAction.REDACT,
        target_cidrs=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        priority=30,
    ),
    PolicyRule(
        name="allow_all",
        action=PolicyAction.ALLOW,
        priority=1000,
    ),
]


class PolicyGuard:
    """
    策略守卫引擎。

    规则按 priority 升序评估, 首个匹配的规则决定结果。
    未匹配任何规则时默认 ALLOW (白名单模式) 或 DENY (黑名单模式)。
    """

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        default_action: PolicyAction = PolicyAction.ALLOW,
    ):
        self._rules = sorted(rules or _PRESET_RULES, key=lambda r: r.priority)
        self._default = default_action

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def remove_rule(self, name: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.name != name]
        return len(self._rules) < before

    def check(self, result: IntentResult) -> PolicyVerdict:
        """
        检查意图分类结果是否符合策略。

        返回 PolicyVerdict, 其中 allowed=False 时应阻断路由。
        """
        for rule in self._rules:
            if rule.matches(result):
                return self._apply_rule(rule, result)

        # 无规则匹配 → 默认动作
        if self._default == PolicyAction.ALLOW:
            return PolicyVerdict(
                allowed=True, action=PolicyAction.ALLOW,
                matched_rule="default_allow",
            )
        else:
            return PolicyVerdict(
                allowed=False, action=PolicyAction.DENY,
                matched_rule="default_deny",
                deny_reason="未匹配任何允许规则",
            )

    def check_collector(
        self, result: IntentResult, spec: CollectorSpec,
    ) -> PolicyVerdict:
        """
        检查特定采集器规格是否在策略范围内。
        比 check() 更细粒度: 针对单个采集器的授权检查。
        """
        base = self.check(result)
        if not base.allowed:
            return base
        # 额外检查: 采集器级别的约束
        for rule in self._rules:
            if rule.matches(result):
                if rule.action == PolicyAction.DENY:
                    return PolicyVerdict(
                        allowed=False, action=PolicyAction.DENY,
                        matched_rule=rule.name,
                        deny_reason=f"采集器 {spec.action_id} 被策略 '{rule.name}' 禁止",
                    )
        return base

    def _apply_rule(self, rule: PolicyRule, result: IntentResult) -> PolicyVerdict:
        if rule.action == PolicyAction.DENY:
            return PolicyVerdict(
                allowed=False, action=PolicyAction.DENY,
                matched_rule=rule.name,
                deny_reason=f"被策略 '{rule.name}' 拒绝",
            )
        elif rule.action == PolicyAction.REDACT:
            modified = IntentResult(
                category=result.category,
                confidence=result.confidence,
                params=result.params,
                matched_categories=result.matched_categories,
                ambiguous=result.ambiguous,
                used_llm=result.used_llm,
            )
            # 将 target 替换为脱敏版本
            if result.params.target:
                modified.params.target = self._redact_target(result.params.target)
            return PolicyVerdict(
                allowed=True, action=PolicyAction.REDACT,
                matched_rule=rule.name, modified_result=modified,
            )
        elif rule.action == PolicyAction.CAP_DEPTH:
            modified = IntentResult(
                category=result.category,
                confidence=result.confidence,
                params=result.params,
                matched_categories=result.matched_categories,
                ambiguous=result.ambiguous,
                used_llm=result.used_llm,
            )
            depth_order = {"shallow": 1, "standard": 2, "deep": 3}
            if rule.depth_max:
                current_depth = result.params.depth or "standard"
                if depth_order.get(current_depth, 2) > depth_order.get(rule.depth_max, 2):
                    modified.params.depth = rule.depth_max
            return PolicyVerdict(
                allowed=True, action=PolicyAction.CAP_DEPTH,
                matched_rule=rule.name, modified_result=modified,
            )
        else:  # ALLOW
            return PolicyVerdict(
                allowed=True, action=PolicyAction.ALLOW,
                matched_rule=rule.name,
            )

    @staticmethod
    def _redact_target(target: str) -> str:
        """脱敏: 保留前缀, 其余替换为哈希片段。"""
        if not target:
            return target
        import hashlib
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
            parts = target.split(".")
            return f"{parts[0]}.{parts[1]}.x.x"
        h = hashlib.sha256(target.encode()).hexdigest()[:8]
        if len(target) > 12:
            return target[:4] + ".." + h
        return "redacted:" + h


__all__ = [
    "PolicyAction",
    "PolicyRule",
    "PolicyVerdict",
    "PolicyGuard",
]
