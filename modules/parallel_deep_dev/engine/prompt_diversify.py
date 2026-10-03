"""
创建: 2025-04-17
修改:
  2025-08-01 - 约束库提取到 divergent_constraints.py
对抗性提示多样化注入器 — 在 worker 调度前主动注入差异化约束，预防语义收敛。

问题：Algorithmic Groupthink 证实多 agent 系统存在"多样性坍塌"——
不同 prompt 的 agent 仍产出高度相似的输出，共享中间结果使多样性降低 5.9%，
而隔离可提升 10.3%。本系统的 semantic_dedup 是事后检测，发现收敛时
代码已生成完毕，修复成本高。

方案：在 worker 调度前，计算所有 prompt 对的 token 级 Jaccard 相似度。
对相似度超过阈值的 prompt 对，从约束库中选择互斥的差异化指令注入。
约束库包含 24 对经过验证的发散思维模式，覆盖架构范式、优化目标、
错误处理策略等维度。

约束选择策略：相似度越高的 prompt 对，注入的约束差异越大（核心理念差异，
而非表面措辞差异）。同一 worker 不会被重复分配同一约束。

与现有工作的差异：
  - Algorithmic Groupthink: 观测性研究，未提供自动化缓解系统
  - ToxiPrompt: 关注对抗性毒性生成，非代码生成场景
  - semantic_dedup: 事后检测（已构建），本模块是其事前预防的闭环搭档
  - 基于 token 重叠度的约束强度自适应选择在文献中未见
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# 发散思维约束库委托给 engine/divergent_constraints.py
from .divergent_constraints import DIVERGENT_PAIRS

# 默认相似度阈值
_DEFAULT_SIMILARITY_THRESHOLD: float = 0.45
# 强约束阈值——高于此值分配差异最大的约束对
_HIGH_SIMILARITY_THRESHOLD: float = 0.65


@dataclass
class DiversifyResult:
    """单个模块的多样化注入结果。"""
    module_key: str
    original_prompt_hash: str
    injected_constraint: str | None
    constrained_module: str | None   # 与哪个模块的 prompt 过于相似
    similarity_score: float


@dataclass
class PromptDiversifier:
    """对抗性提示多样化注入器。

    在 worker 调度前调用 diversify()，返回注入差异化约束后的 prompt 字典。
    若某模块的 prompt 与其他模块过于相似，自动分配互斥约束。

    similarity_threshold: 触发注入的最低 token 重叠度
    """

    similarity_threshold: float = _DEFAULT_SIMILARITY_THRESHOLD
    _used_pairs: set[int] = field(default_factory=set)
    _assignments: dict[str, int] = field(default_factory=dict)

    def diversify(
        self,
        prompts: dict[str, str],
    ) -> tuple[dict[str, str], list[DiversifyResult]]:
        """对 prompt 字典执行多样化注入。

        返回 (diversified_prompts, results)。
        diversified_prompts 包含注入了约束的增强版 prompt。
        未被检测为相似的模块保持原始 prompt 不变。
        """
        if len(prompts) < 2:
            return dict(prompts), []

        keys = list(prompts.keys())
        # 计算所有 prompt 对的 token 级 Jaccard 相似度
        similarities: list[tuple[str, str, float]] = []
        tokenized = {k: _tokenize(prompts[k]) for k in keys}

        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                sim = _jaccard_similarity(tokenized[keys[i]], tokenized[keys[j]])
                if sim >= self.similarity_threshold:
                    similarities.append((keys[i], keys[j], sim))

        if not similarities:
            return dict(prompts), []

        # 按相似度降序排列——最相似的 prompt 对优先分配约束
        similarities.sort(key=lambda x: x[2], reverse=True)

        results: list[DiversifyResult] = []
        diversified = dict(prompts)
        assigned_modules: set[str] = set()

        for ka, kb, sim in similarities:
            if ka in assigned_modules and kb in assigned_modules:
                continue

            # 选择与相似度匹配的约束对
            pair_idx = self._select_pair(sim, ka, kb)
            if pair_idx is None:
                continue

            constraint_a, constraint_b = DIVERGENT_PAIRS[pair_idx]
            self._used_pairs.add(pair_idx)

            # 注入约束——追加到 prompt 末尾
            if ka not in assigned_modules:
                diversified[ka] = _inject_constraint(prompts[ka], constraint_a)
                assigned_modules.add(ka)
                results.append(DiversifyResult(
                    module_key=ka,
                    original_prompt_hash=_hash_prompt(prompts[ka]),
                    injected_constraint=constraint_a[:80] + "...",
                    constrained_module=kb,
                    similarity_score=round(sim, 3),
                ))

            if kb not in assigned_modules:
                diversified[kb] = _inject_constraint(prompts[kb], constraint_b)
                assigned_modules.add(kb)
                results.append(DiversifyResult(
                    module_key=kb,
                    original_prompt_hash=_hash_prompt(prompts[kb]),
                    injected_constraint=constraint_b[:80] + "...",
                    constrained_module=ka,
                    similarity_score=round(sim, 3),
                ))

            self._assignments[ka] = pair_idx
            self._assignments[kb] = pair_idx

        return diversified, results

    def _select_pair(
        self,
        similarity: float,
        module_a: str,
        module_b: str,
    ) -> int | None:
        """根据相似度选择合适的约束对索引。

        高相似度（>0.65）：选择尚未使用的约束对中差异最大的。
        中等相似度：选择任意未使用的约束对。
        返回 None 表示无可用约束对。"""
        available = [
            i for i in range(len(DIVERGENT_PAIRS))
            if i not in self._used_pairs
        ]
        if not available:
            return None

        if similarity >= _HIGH_SIMILARITY_THRESHOLD:
            # 选择索引最大的未使用对（靠后的对差异通常更大）
            return max(available)
        # 中等相似度：简单轮转
        idx = (hash(module_a + module_b) % len(available))
        return available[idx]

    def stats(self) -> dict:
        return {
            "total_pairs": len(DIVERGENT_PAIRS),
            "used_pairs": len(self._used_pairs),
            "available_pairs": len(DIVERGENT_PAIRS) - len(self._used_pairs),
            "assignments": dict(self._assignments),
        }


# 相似度计算

def _tokenize(text: str) -> set[str]:
    """将文本分词。中英文混合：中文按字符级 bigram，英文按单词。"""
    # 提取中文字符
    chinese = re.findall(r'[一-鿿]+', text)
    tokens: set[str] = set()
    for segment in chinese:
        for i in range(len(segment) - 1):
            tokens.add(segment[i:i + 2])

    # 英文单词（>=3 字符）
    english = re.findall(r'[a-zA-Z_]\w{2,}', text.lower())
    tokens.update(english)

    # 关键词提取（含下划线的复合词）
    compounds = re.findall(r'\b\w+_\w+\b', text)
    tokens.update(t.lower() for t in compounds)

    return tokens


def _jaccard_similarity(a: set[str], b: set[str]) -> float:
    """Jaccard 相似度 = |A∩B| / |A∪B|。"""
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 0.0


def _hash_prompt(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _inject_constraint(prompt: str, constraint: str) -> str:
    """将差异化约束注入到 prompt 末尾。使用明确的标记分隔。"""
    injection = (
        f"\n\n---\n### 多样性约束（本模块专属设计指令）\n"
        f"{constraint}\n"
        f"注意：此约束旨在确保不同模块采用差异化的设计方案，"
        f"避免各模块产出功能等价但表面不同的代码。"
    )
    return prompt + injection


# 便捷集成入口

def diversify_module_prompts(
    diversifier: PromptDiversifier,
    module_defs: dict[str, dict],
    prompt_builder,
) -> tuple[dict[str, str], list[DiversifyResult]]:
    """从模块定义构建 prompt 并执行多样化注入。

    prompt_builder 签名为 (module_key, module_def) -> str。
    返回 (diversified_prompts, results)。"""
    original_prompts: dict[str, str] = {}
    for key, defn in module_defs.items():
        original_prompts[key] = prompt_builder(key, defn)

    return diversifier.diversify(original_prompts)
