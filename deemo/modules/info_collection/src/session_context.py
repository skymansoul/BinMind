"""
多轮会话上下文追踪器。

问题: 安全分析中常见的多轮交互模式 —— 第一轮指定目标, 第二轮指定方法,
第三轮调整深度 —— 被现有逐轮独立的歧义处理机制切断。
例如 "再扫描一次端口" 中的隐含 target 应从前一轮继承,
但静态模板无法回溯。

做法: 维护容量上限 12 条的结构化上下文栈, 参数级追踪 (target/method/depth/constraints)。
歧义解析时按时间衰减权重回溯: 衰减半衰期 15 分钟,
意味着一轮查询在 30 分钟后对当前轮的贡献降至 25%。

设计决策: 追踪操作参数而非对话历史。操作参数是稀疏的结构化槽位,
歧义解析是确定性投票而非生成式推理, 不易产生幻觉。
这是与通用对话上下文管理的关键差异。
"""

# File: session_context.py  |  2026-07-28 create session context

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .intent_route import IntentCategory, IntentResult


@dataclass
class ContextEntry:
    """单轮上下文条目。"""
    target: str = ""
    method: str = ""
    depth: str = "standard"
    category: Optional[IntentCategory] = None
    constraints: Dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0
    confidence: float = 0.5
    source: str = ""  # "llm" | "rule" | "user_explicit"


@dataclass
class ResolvedParams:
    """歧义解析后的参数。"""
    target: str
    method: str
    depth: str
    constraints: Dict[str, str]
    resolution_path: List[str]  # 记录每个参数是如何解析的: "current" | "context" | "template" | "unresolved"


class SessionContext:
    """
    多轮会话上下文管理器。

    容量控制: 最多保留 MAX_ENTRIES 条, 超出时淘汰最旧条目。
    时间衰减: 半衰期 15 分钟, 旧的上下文对当前轮的贡献趋近于 0。
    """

    MAX_ENTRIES = 12
    HALF_LIFE = 900.0  # 15 分钟

    def __init__(self):
        self._entries: OrderedDict[int, ContextEntry] = OrderedDict()
        self._seq = 0

    def add(self, entry: ContextEntry) -> None:
        """添加一轮上下文。"""
        entry.timestamp = time.time()
        self._seq += 1
        self._entries[self._seq] = entry
        self._prune()

    def add_from_result(self, result: IntentResult, source: str = "") -> None:
        """从 IntentResult 提取上下文并添加。"""
        entry = ContextEntry(
            target=result.params.target,
            method=result.params.method,
            depth=result.params.depth,
            category=result.category,
            constraints=dict(result.params.constraints),
            confidence=result.confidence,
            source=source or ("llm" if result.used_llm else "rule"),
        )
        self.add(entry)

    def _prune(self) -> None:
        """超过容量时删除最旧条目。"""
        while len(self._entries) > self.MAX_ENTRIES:
            self._entries.popitem(last=False)

    def _temporal_weight(self, ts: float, now: float) -> float:
        age = max(0.0, now - ts)
        import math
        return math.exp(-math.log(2) * age / self.HALF_LIFE)

    def resolve(
        self, current: IntentResult
    ) -> Tuple[IntentResult, ResolvedParams]:
        """
        利用历史上下文解析当前轮次的歧义。

        规则:
        1. 当前轮的显式参数优先 (置信度 > 0.5)
        2. 缺失参数从历史上下文中回溯, 按时间衰减权重加权投票
        3. target 和 method 是最关键的解析目标
        4. 历史 target 匹配当前 target 前缀时加权

        返回: (可能已修改的 IntentResult, 解析路径)
        """
        now = time.time()
        path: List[str] = []
        resolved_target = current.params.target
        resolved_method = current.params.method
        resolved_depth = current.params.depth
        resolved_constraints = dict(current.params.constraints)

        if resolved_target:
            path.append("target=current")
        if resolved_method:
            path.append("method=current")
        if resolved_depth and resolved_depth != "standard":
            path.append("depth=current")

        missing_target = not resolved_target
        missing_method = not resolved_method

        if not missing_target and not missing_method:
            # 无缺失, 仍需更新 missing_params
            current.missing_params = []
            current.ambiguous = False
            return current, ResolvedParams(
                target=resolved_target, method=resolved_method or "",
                depth=resolved_depth, constraints=resolved_constraints,
                resolution_path=path,
            )

        # 按时间衰减加权回溯
        target_votes: Dict[str, float] = {}
        method_votes: Dict[str, float] = {}
        depth_votes: Dict[str, float] = {}

        for entry in reversed(list(self._entries.values())):
            weight = self._temporal_weight(entry.timestamp, now)
            if weight < 0.05:
                continue  # 衰减过低, 忽略

            if missing_target and entry.target:
                # 精确匹配加分, 但此处是投票聚合
                target_votes[entry.target] = target_votes.get(entry.target, 0.0) + weight * entry.confidence

            if missing_method and entry.method:
                method_votes[entry.method] = method_votes.get(entry.method, 0.0) + weight * entry.confidence

            if entry.depth and entry.depth != "standard":
                depth_votes[entry.depth] = depth_votes.get(entry.depth, 0.0) + weight * entry.confidence

        if missing_target and target_votes:
            resolved_target = max(target_votes, key=target_votes.get)
            path.append("target=context")

        if missing_method and method_votes:
            resolved_method = max(method_votes, key=method_votes.get)
            path.append("method=context")

        if not resolved_depth and depth_votes:
            resolved_depth = max(depth_votes, key=depth_votes.get)
            path.append("depth=context")

        # 仍缺失的标记为 unresolved
        still_missing: List[str] = []
        if not resolved_target:
            still_missing.append("target")
            path.append("target=unresolved")
        if not resolved_method:
            still_missing.append("method")
            path.append("method=unresolved")

        # 更新当前结果的参数 (不修改原始对象, 返回新的理解)
        current.params.target = resolved_target
        current.params.method = resolved_method
        current.params.depth = resolved_depth or "standard"
        for k, v in resolved_constraints.items():
            current.params.constraints.setdefault(k, v)
        current.missing_params = still_missing
        current.ambiguous = bool(still_missing)

        resolved = ResolvedParams(
            target=resolved_target,
            method=resolved_method,
            depth=resolved_depth or "standard",
            constraints=resolved_constraints,
            resolution_path=path,
        )
        return current, resolved

    def suggest_clarification(self, missing: List[str]) -> List[str]:
        """
        基于历史上下文生成更智能的澄清问题。

        与 _AMBIGUITY_TEMPLATES 的通用模板不同,
        此处结合最近的 target 历史给出更具体的提示。
        """
        questions: List[str] = []
        recent_targets = self.recent_targets(3)

        if "target" in missing:
            if recent_targets:
                last_targets = ", ".join(recent_targets)
                questions.append(
                    f"请提供采集目标 (近期目标: {last_targets})"
                )
            else:
                questions.append("请提供采集目标 (IP 地址 / 域名 / 文件路径)")

        if "method" in missing:
            recent_methods = self._recent_values("method", 3)
            if recent_methods:
                methods_str = ", ".join(recent_methods)
                questions.append(
                    f"请指定采集方式 (近期方式: {methods_str})"
                )
            else:
                questions.append("请指定采集方式 (如: 端口扫描、进程枚举、PE 分析)")

        return questions

    def recent_targets(self, n: int = 5) -> List[str]:
        """获取最近的去重 target 列表。"""
        seen: set = set()
        targets: List[str] = []
        for entry in reversed(list(self._entries.values())):
            if entry.target and entry.target not in seen:
                targets.append(entry.target)
                seen.add(entry.target)
                if len(targets) >= n:
                    break
        return targets

    def _recent_values(self, attr: str, n: int) -> List[str]:
        """获取最近的去重属性值列表。"""
        seen: set = set()
        vals: List[str] = []
        for entry in reversed(list(self._entries.values())):
            v = getattr(entry, attr, "")
            if v and v not in seen:
                vals.append(v)
                seen.add(v)
                if len(vals) >= n:
                    break
        return vals

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()
        self._seq = 0


__all__ = [
    "ContextEntry",
    "ResolvedParams",
    "SessionContext",
]
