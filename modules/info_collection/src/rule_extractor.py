"""
神经符号规则提取器 (NSRE)。

MoCQ 用 LLM 自动提取漏洞检测规则,
QRS 用多智能体验证和修剪规则。
本模块将同一思想应用于意图分类的规则集维护:
从 LLM 分类器的行为中反向提取关键词→类别的映射规则,
与现有规则集对比, 识别过时、缺失、冲突的规则。

流程:
1. 收集 LLM 分类器的历史输出, 关联原始请求文本
2. 对每个类别, 提取 LLM 高频使用的判别性关键词
3. 与现有 _CATEGORY_KEYWORDS 对比, 生成差异报告
4. 对候选规则做冲突检测, 避免同一关键词对应多类别
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .intent_route import IntentCategory


@dataclass
class KeywordRule:
    """单个关键词规则的记录。"""
    keyword: str
    category: IntentCategory
    llm_frequency: int        # LLM 分类为该类别时此关键词的出现次数
    rule_frequency: int       # 规则分类为该类别时此关键词的出现次数
    discriminative_score: float  # 该关键词对类别的判别力 [0, 1]
    status: str = ""  # "existing" | "missing" | "stale" | "conflicting"


@dataclass
class RuleExtractionReport:
    """规则提取报告。"""
    extracted_rules: List[KeywordRule]
    missing_rules: List[KeywordRule]     # LLM 使用但规则中不存在的
    stale_rules: List[KeywordRule]       # 规则中存在但 LLM 不再使用的
    conflicting_rules: List[KeywordRule]  # LLM 和规则将同一关键词分到不同类别
    suggested_additions: List[Tuple[str, IntentCategory]]
    suggested_removals: List[str]
    extraction_confidence: float  # 提取结果的总体置信度


class RuleExtractor:
    """
    神经符号规则提取器。

    不直接调用 LLM API, 而是分析 LLM 分类器的历史行为日志。
    这种 "行为逆向" 方法避免了提示注入攻击对规则提取过程的影响,
    也比直接询问 LLM "哪些关键词对应哪些类别" 更可靠 ——
    LLM 的自我报告解释 (self-reported explanations) 常与
    实际分类行为不一致。
    """

    def __init__(self, min_frequency: int = 3, min_discriminative: float = 0.3):
        self._min_freq = min_frequency
        self._min_disc = min_discriminative
        self._history: List[Tuple[str, IntentCategory, float]] = []
        # (request_text, llm_category, llm_confidence)

    def feed(self, text: str, llm_category: IntentCategory, llm_confidence: float) -> None:
        """提交一条 LLM 分类记录。"""
        self._history.append((text, llm_category, llm_confidence))
        if len(self._history) > 500:
            self._history = self._history[-500:]

    def extract(
        self,
        existing_keywords: Optional[Dict[IntentCategory, Tuple[str, ...]]] = None,
    ) -> RuleExtractionReport:
        """
        从积累的历史记录中提取关键词规则,
        与现有规则集对比, 生成差异报告。
        """
        if len(self._history) < 20:
            return RuleExtractionReport(
                extracted_rules=[], missing_rules=[], stale_rules=[],
                conflicting_rules=[], suggested_additions=[],
                suggested_removals=[], extraction_confidence=0.0,
            )

        # 对每个类别, 收集 LLM 分类为该类别的请求中的关键词
        cat_texts: Dict[IntentCategory, List[str]] = defaultdict(list)
        for text, cat, conf in self._history:
            if conf > 0.5:
                cat_texts[cat].append(text.lower())

        # 提取每个类别的判别性关键词
        all_keywords: Set[str] = set()
        cat_keyword_freq: Dict[IntentCategory, Counter] = {}

        for cat, texts in cat_texts.items():
            freq: Counter = Counter()
            for t in texts:
                tokens = self._tokenize(t)
                freq.update(tokens)
            cat_keyword_freq[cat] = freq
            all_keywords.update(freq.keys())

        # 计算每个 (关键词, 类别) 的判别力
        total_cat = {cat: sum(freq.values()) for cat, freq in cat_keyword_freq.items()}
        extracted: List[KeywordRule] = []

        for cat, freq in cat_keyword_freq.items():
            cat_total = max(1, total_cat.get(cat, 0))
            for kw, count in freq.most_common(100):
                if count < self._min_freq:
                    continue
                # TF-IDF 风格的判别力: 该词在目标类别中的比例 vs 全局比例
                global_count = sum(
                    cat_keyword_freq.get(c, Counter()).get(kw, 0)
                    for c in IntentCategory
                )
                cat_ratio = count / cat_total
                global_ratio = global_count / max(1, sum(total_cat.values()))
                discriminative = cat_ratio / max(0.001, global_ratio)
                discriminative_norm = min(1.0, discriminative / 10.0)

                if discriminative_norm < self._min_disc:
                    continue

                extracted.append(KeywordRule(
                    keyword=kw, category=cat,
                    llm_frequency=count, rule_frequency=0,
                    discriminative_score=round(discriminative_norm, 4),
                ))

        # 与现有规则集对比
        missing: List[KeywordRule] = []
        stale: List[KeywordRule] = []
        conflicting: List[KeywordRule] = []
        additions: List[Tuple[str, IntentCategory]] = []
        removals: List[str] = []

        if existing_keywords:
            existing_set: Dict[str, IntentCategory] = {}
            for cat, kws in existing_keywords.items():
                for kw in kws:
                    existing_set[kw.lower()] = cat

            extracted_kw_set: Dict[str, IntentCategory] = {}
            for rule in extracted:
                extracted_kw_set[rule.keyword] = rule.category

            for rule in extracted:
                if rule.keyword not in existing_set:
                    rule.status = "missing"
                    missing.append(rule)
                    if rule.discriminative_score > 0.5:
                        additions.append((rule.keyword, rule.category))
                elif existing_set[rule.keyword] != rule.category:
                    rule.status = "conflicting"
                    conflicting.append(rule)
                else:
                    rule.status = "existing"

            for kw, cat in existing_set.items():
                if kw not in extracted_kw_set:
                    stale.append(KeywordRule(
                        keyword=kw, category=cat,
                        llm_frequency=0, rule_frequency=0,
                        discriminative_score=0.0, status="stale",
                    ))
                    removals.append(kw)

        confidence = min(0.95, len(self._history) / 200.0)
        return RuleExtractionReport(
            extracted_rules=extracted,
            missing_rules=missing,
            stale_rules=stale,
            conflicting_rules=conflicting,
            suggested_additions=additions,
            suggested_removals=removals,
            extraction_confidence=round(confidence, 4),
        )

    def _tokenize(self, text: str) -> List[str]:
        """
        中文+英文混合分词。
        中文按单字和双字组合提取, 英文按单词边界分割。
        仅保留长度 ≥ 2 的 token, 避免单字噪声。
        """
        tokens: List[str] = []
        # 英文词
        eng_words = re.findall(r"[a-z0-9_]{2,}", text)
        tokens.extend(eng_words)
        # 中文双字
        chinese = re.findall(r"[一-鿿]+", text)
        for seg in chinese:
            tokens.append(seg)
            for i in range(len(seg) - 1):
                tokens.append(seg[i:i + 2])
        return tokens

    def suggest_rule_update(
        self,
        existing_keywords: Dict[IntentCategory, Tuple[str, ...]],
    ) -> Dict[IntentCategory, List[str]]:
        """
        生成合并了 LLM 提取规则的建议规则集。
        保留现有规则, 添加高置信度的新关键词, 移除过时关键词。
        """
        report = self.extract(existing_keywords)
        updated: Dict[IntentCategory, List[str]] = {
            cat: list(kws) for cat, kws in existing_keywords.items()
        }
        for kw, cat in report.suggested_additions:
            if cat not in updated:
                updated[cat] = []
            if kw not in updated[cat]:
                updated[cat].append(kw)
        for kw in report.suggested_removals:
            for cat in updated:
                if kw in updated[cat]:
                    updated[cat].remove(kw)
        return updated

    def reset(self) -> None:
        self._history.clear()


__all__ = [
    "KeywordRule",
    "RuleExtractionReport",
    "RuleExtractor",
]
