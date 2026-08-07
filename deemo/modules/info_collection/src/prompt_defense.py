"""
对抗性提示注入防御 (APID) —— 面向安全工具路由的注入检测。

与通用提示注入检测器的关键差异: 通用检测器判定 "是否被注入",
本模块判定 "注入是否改变了路由决策"。
一个提示可能包含看似恶意的指令片段, 但若分类器的路由输出
在语义扰动前后保持一致, 则不触发拦截 —— 这大幅降低了误报率。

技术路线:
1. 语义扰动: 对输入做字符级 (NFKC 规范化)、词级 (分隔标记移除)、
   语序级 (句子逆序) 的受控扰动
2. 路由稳定性: 比较原始输入与扰动输入的分类器输出一致性
3. 结构信号: 检测分隔符滥用、角色切换提示、隐藏指令模式、
   零宽字符、编码混淆等已知注入特征
4. 综合评分: 加权融合为 injection_risk ∈ [0,1]

扰动方法的选择依据: 注入载荷依赖精确的措辞和分隔符来覆盖原有指令,
而自然语言请求具有语义冗余 —— 小扰动不应改变意图类别。
这种 "稳定性即安全性" 的非对称性构成了检测的理论基础。
"""

# File: prompt_defense.py  |  2026-07-29 create APID; 2026-08-04 audit: remove BAGEL/NofT

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PerturbationResult:
    """单次扰动后的分类器输出差异。"""
    perturbation_type: str  # "char" | "word" | "order" | "boundary"
    original_output: str
    perturbed_output: str
    category_changed: bool
    confidence_delta: float
    target_changed: bool


@dataclass
class InjectionReport:
    """注入检测报告。"""
    risk_score: float               # [0, 1], 综合注入风险
    routing_stability: float        # [0, 1], 路由稳定性 (1=完全稳定)
    structural_anomalies: List[str]  # 检测到的结构性异常
    perturbation_results: List[PerturbationResult]
    blocked: bool                    # 是否建议拦截
    reason: str = ""


# 结构性异常检测模式
# 这些模式提示可能的注入尝试, 但单个模式不足以判定 —
# 需与路由稳定性联合评估。

_STRUCTURAL_ANOMALIES = [
    # 分隔符滥用: 用 --- 或 === 分割注入指令
    (r"(?:^|\n)[-=]{3,}\s*\n", "分隔符注入"),
    # 角色切换: "ignore previous" / "forget earlier" / "you are now"
    (r"(?i)(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|earlier|above|prior)\s+(?:instructions?|prompts?|directions?)", "角色切换_指令覆盖"),
    (r"(?i)(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+(?:a|an))", "角色切换_身份重定义"),
    # 隐藏指令: "do NOT classify" / "always return" / "output exactly"
    (r"(?i)(?:do\s+not\s+classify|always\s+(?:return|output|respond)|output\s+exactly|return\s+only)", "隐藏指令_路由操纵"),
    # 嵌套分隔: 试图将恶意指令嵌入 JSON/XML 结构
    (r'\{[^}]*"(?:category|method|target)"[^}]*\}', "结构化注入_JSON"),
    # 重复模式: 多次重复同一指令以覆盖上下文
    (r"(?i)(.{20,}?)\1{2,}", "重复指令注入"),
    # 零宽字符: 利用不可见字符隐藏指令
    (r"[​‌‍‎‏‪-‮﻿]", "零宽字符"),
    # 编码混淆: base64 / hex 编码的隐藏载荷
    (r"(?i)(?:from:base64|decode\s*\(|0x[0-9a-f]{16,})", "编码混淆"),
]


def _detect_structural_anomalies(text: str) -> List[str]:
    """检测文本中的结构性注入异常。"""
    found: List[str] = []
    for pattern, label in _STRUCTURAL_ANOMALIES:
        if re.search(pattern, text):
            found.append(label)
    return found


def _perturb_chars(text: str) -> str:
    """字符级扰动: Unicode 规范化 + 同形字符还原。"""
    normalized = unicodedata.normalize("NFKC", text)
    # 去除零宽字符
    cleaned = re.sub(r"[​‌‍‎‏‪-‮﻿]", "", normalized)
    return cleaned


def _perturb_words(text: str) -> str:
    """词级扰动: 移除可能的注入分隔标记。"""
    cleaned = re.sub(r"(?i)(?:system|assistant|user|human)\s*:", "", text)
    cleaned = re.sub(r"\[/?INST\]", "", cleaned)
    cleaned = re.sub(r"<\|.*?\|>", "", cleaned)
    return cleaned


def _perturb_order(text: str) -> str:
    """语序扰动: 逆序句子以测试分类器对语序的敏感性。"""
    sentences = re.split(r"(?<=[.!?。！？\n])\s*", text)
    if len(sentences) <= 1:
        return text
    mid = len(sentences) // 2
    reordered = sentences[mid:] + sentences[:mid]
    return " ".join(reordered)


def _perturb_boundary(text: str) -> str:
    """边界扰动: 截断潜在的注入载荷。"""
    lines = text.split("\n")
    filtered: List[str] = []
    for line in lines:
        if len(line.strip()) > 300:
            filtered.append(line[:300] + "...")
        else:
            filtered.append(line)
    return "\n".join(filtered)


class PromptInjectionDefender:
    """
    提示注入防御器。

    不直接判定 "是否恶意", 而是度量 "路由决策在扰动下的稳定性"。
    一个良性请求在经过字符/词语/语序扰动后, 分类器应输出相似结果。
    注入请求则相反 — 微小的扰动 (如移除外层注入包装) 可能导致
    分类器输出剧烈变化。

    这种 "稳定性即安全性" 的假设源自:
    - 自然语言请求的语义冗余: 小扰动不应改变意图类别
    - 注入载荷的脆弱性: 注入依赖精确的指令措辞, 扰动后失效
    """

    def __init__(self, stability_threshold: float = 0.55):
        self._threshold = stability_threshold

    def assess(
        self,
        text: str,
        classify_fn,  # callable: str → IntentResult
    ) -> InjectionReport:
        """
        评估请求文本的注入风险。

        classify_fn: 接收文本, 返回 IntentResult 的可调用对象。
        通过依赖注入而非直接导入, 避免循环依赖, 也便于测试。
        """
        structural = _detect_structural_anomalies(text)

        perturbations: List[Tuple[str, str]] = [
            ("char", _perturb_chars(text)),
            ("word", _perturb_words(text)),
            ("order", _perturb_order(text)),
            ("boundary", _perturb_boundary(text)),
        ]

        original_result = classify_fn(text)
        original_cat = original_result.category.value
        original_target = original_result.params.target
        original_conf = original_result.confidence

        pert_results: List[PerturbationResult] = []
        cat_changes = 0
        target_changes = 0

        for ptype, ptext in perturbations:
            if ptext == text:
                # 扰动无变化 → 跳过 (输入太短或无扰动空间)
                pert_results.append(PerturbationResult(
                    perturbation_type=ptype,
                    original_output=original_cat,
                    perturbed_output=original_cat,
                    category_changed=False,
                    confidence_delta=0.0,
                    target_changed=False,
                ))
                continue

            pert_result = classify_fn(ptext)
            pert_cat = pert_result.category.value
            pert_target = pert_result.params.target
            cat_changed = (pert_cat != original_cat)
            target_changed = (pert_target != original_target)
            conf_delta = abs(pert_result.confidence - original_conf)

            if cat_changed:
                cat_changes += 1
            if target_changed:
                target_changes += 1

            pert_results.append(PerturbationResult(
                perturbation_type=ptype,
                original_output=original_cat,
                perturbed_output=pert_cat,
                category_changed=cat_changed,
                confidence_delta=conf_delta,
                target_changed=target_changed,
            ))

        # 路由稳定性评分
        effective_perturbations = max(1, len([p for p in pert_results if p.perturbed_output != p.original_output or p.confidence_delta > 0.01]))
        cat_stability = 1.0 - (cat_changes / effective_perturbations)
        target_stability = 1.0 - (target_changes / effective_perturbations)
        routing_stability = 0.6 * cat_stability + 0.4 * target_stability

        # 结构性异常权重: 每种异常降低稳定性评分
        structural_penalty = min(0.5, len(structural) * 0.12)
        adjusted_stability = max(0.0, routing_stability - structural_penalty)

        risk_score = 1.0 - adjusted_stability
        blocked = risk_score > self._threshold

        reason_parts: List[str] = []
        if cat_changes > 0:
            reason_parts.append(f"类别变更 {cat_changes}/{effective_perturbations}")
        if target_changes > 0:
            reason_parts.append(f"目标变更 {target_changes}/{effective_perturbations}")
        if structural:
            reason_parts.append(f"结构异常: {', '.join(structural)}")
        reason = "; ".join(reason_parts) if reason_parts else "无异常"

        return InjectionReport(
            risk_score=round(risk_score, 4),
            routing_stability=round(routing_stability, 4),
            structural_anomalies=structural,
            perturbation_results=pert_results,
            blocked=blocked,
            reason=reason,
        )

    def quick_scan(self, text: str) -> float:
        """
        快速结构扫描, 不执行分类器调用。
        返回基于结构异常的初步风险评分, 用于低成本的预筛选。
        """
        anomalies = _detect_structural_anomalies(text)
        if not anomalies:
            return 0.0
        base_score = min(0.6, len(anomalies) * 0.15)
        # 高严重性异常加权
        high_severity = {"角色切换_指令覆盖", "角色切换_身份重定义", "隐藏指令_路由操纵"}
        for a in anomalies:
            if a in high_severity:
                base_score += 0.15
        return min(0.95, base_score)


__all__ = [
    "PerturbationResult",
    "InjectionReport",
    "PromptInjectionDefender",
]
