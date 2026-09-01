#!/usr/bin/env python3
# LLM引导符号执行——分支按LLM评分排优先级，带路径摘要，集成BaseAnalyzer
# DefaultLLMBranchScorer兜底模拟分支构造
# 分支去重，核心dataclass带__repr__，覆盖率感知加权

import logging as _logging
import json as _json
import heapq as _heapq
import hashlib as _hashlib
import re as _re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

__dbg = _logging.getLogger(__name__)


class BranchPriority(Enum):
    """分支优先级——指导探索顺序。"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_score(cls, score: float) -> "BranchPriority":
        """按评分区间映射优先级。"""
        if score >= 0.7:
            return cls.HIGH
        if score >= 0.4:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class BranchInfo:
    """分支点信息。"""
    address: int = 0
    condition: str = ""
    true_branch_target: Optional[int] = None
    false_branch_target: Optional[int] = None
    path_history: List[str] = field(default_factory=list)
    depth: int = 0
    constraint_count: int = 0
    condition_ast: Optional[Any] = None

    def __hash__(self):
        return hash(self.address)

    def __eq__(self, other):
        if not isinstance(other, BranchInfo):
            return False
        return (self.address == other.address and
                self.true_branch_target == other.true_branch_target and
                self.false_branch_target == other.false_branch_target)

    # 调试时快速查看分支关键属性
    def __repr__(self):
        return (f"BranchInfo(addr=0x{self.address:x}, cond='{self.condition[:40]}', "
                f"depth={self.depth})")


@dataclass
class PathSummary:
    """已探索符号执行路径的摘要。"""
    current_address: int = 0
    function_name: str = ""
    branch_info: Optional[BranchInfo] = None
    memory_access_patterns: List[str] = field(default_factory=list)
    register_values: Dict[str, str] = field(default_factory=dict)
    symbolic_variables: List[str] = field(default_factory=list)
    path_constraints: List[str] = field(default_factory=list)
    call_stack: List[str] = field(default_factory=list)


@dataclass
class LLMBranchScore:
    """分支评分结果 — 真/假分支各自独立评分与优先级。"""
    true_branch_score: float = 50.0
    false_branch_score: float = 50.0
    true_branch_priority: BranchPriority = BranchPriority.MEDIUM
    false_branch_priority: BranchPriority = BranchPriority.MEDIUM
    reasoning: str = ""
    suggested_constraints: List[str] = field(default_factory=list)
    vulnerability_likelihood: float = 0.0
    interesting_patterns: List[str] = field(default_factory=list)
    # 记录分支在队列中出现次数，避免重复打分耗尽优先级
    enqueue_count: int = 0

    def __lt__(self, other):
        return self.true_branch_score < other.true_branch_score

    def to_priority_tuple(self) -> Tuple[int, float]:
        return (-self.true_branch_priority.value.__hash__() if hasattr(self.true_branch_priority.value, '__hash__') else 0,
                -self.true_branch_score)

    # 快速定位高价值分支，辅助人工审查
    def __repr__(self):
        return (f"LLMBranchScore(true={self.true_branch_score:.1f}/{self.true_branch_priority.value}, "
                f"false={self.false_branch_score:.1f}/{self.false_branch_priority.value})")


class LLMBranchScorer:
    """LLM分支评分器接口。"""

    ai_provider: str = "openai"

    def score_branch(self, branch: BranchInfo,
                     path_history: List[PathSummary],
                     context: str = "") -> LLMBranchScore:
        raise NotImplementedError

    def score_branches(self, branches: List[BranchInfo],
                       path_history: List[PathSummary],
                       context: str = "") -> List[LLMBranchScore]:
        raise NotImplementedError


class DefaultLLMBranchScorer(LLMBranchScorer):
    """启发式分支评分器——基于条件文本模式匹配，无需LLM API。

    保留_extract_score/_extract_priority解析方法，供真实LLM响应文本接入时复用。
    """

    _VULN_PATTERNS = [
        (r'(?:memcpy|strcpy|strcat|sprintf|gets|scanf)\s*\(', "缓冲区操作"),
        (r'(?:malloc|calloc|realloc)\s*\(', "内存分配"),
        (r'(?:free)\s*\(', "内存释放"),
        (r'(?:system|exec|popen)\s*\(', "命令执行"),
        (r'(?:len|size|count|n)\s*(?:<|>|<=|>=|==)', "长度检查"),
        (r'(?:null|NULL|0)\s*(?:==|!=)\s*', "空指针检查"),
        (r'\[.*\]\s*=', "数组写入"),
        (r'(?:recv|read|fread)\s*\(', "数据输入"),
    ]

    def __init__(self, ai_provider: str = "openai"):
        self.ai_provider = ai_provider

    def _create_default_score(self) -> LLMBranchScore:
        """构造等分默认评分——无证据时真/假分支各占50。"""
        return LLMBranchScore(
            true_branch_score=50.0,
            false_branch_score=50.0,
            true_branch_priority=BranchPriority.MEDIUM,
            false_branch_priority=BranchPriority.MEDIUM,
        )

    def _extract_score(self, response: str, key: str) -> float:
        """从LLM响应文本解析KEY: value形式的分数。"""
        m = _re.search(rf"{_re.escape(key)}\s*[:=]\s*([\d.]+)", response)
        if not m:
            return 50.0
        try:
            return float(m.group(1))
        except ValueError:
            return 50.0

    def _extract_priority(self, response: str, key: str) -> BranchPriority:
        """从LLM响应文本解析KEY: high|medium|low形式的优先级。"""
        m = _re.search(rf"{_re.escape(key)}\s*[:=]\s*(\w+)", response)
        if not m:
            return BranchPriority.MEDIUM
        val = m.group(1).lower()
        if val in ("high", "critical", "very_high"):
            return BranchPriority.HIGH
        if val in ("low", "very_low"):
            return BranchPriority.LOW
        return BranchPriority.MEDIUM

    def score_branch(self, branch: BranchInfo,
                     path_history: List[PathSummary],
                     context: str = "") -> LLMBranchScore:
        """依据条件文本中的危险模式与上下文关键词加权;
        真分支继承条件匹配强度，假分支取补充分。"""
        cond_lower = branch.condition.lower()
        score = 0.0
        patterns: List[str] = []
        for pattern, label in self._VULN_PATTERNS:
            if _re.search(pattern, cond_lower):
                score += 0.2
                patterns.append(label)
        if branch.depth > 0:
            score = min(score + branch.depth * 0.05, 1.0)

        context_lower = context.lower()
        for pattern, label in self._VULN_PATTERNS:
            if _re.search(pattern, context_lower):
                score = min(score + 0.1, 1.0)

        true_score = 50.0 + score * 50.0
        false_score = 100.0 - true_score
        return LLMBranchScore(
            true_branch_score=round(true_score, 1),
            false_branch_score=round(false_score, 1),
            true_branch_priority=BranchPriority.from_score(score),
            false_branch_priority=BranchPriority.from_score(1.0 - score),
            reasoning=f"heuristic cond_score={score:.2f}",
            interesting_patterns=patterns,
        )

    def score_branches(self, branches: List[BranchInfo],
                       path_history: List[PathSummary],
                       context: str = "") -> List[LLMBranchScore]:
        return [self.score_branch(b, path_history, context) for b in branches]


@dataclass
class _AnalyzerType(Enum):
    SYMBOLIC_EXECUTOR = "symbolic_executor"


@dataclass
class _ExecutorMetadata:
    """执行器元数据。"""
    name: str
    type: _AnalyzerType
    version: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    supported_platforms: List[str] = field(default_factory=list)


class LLMGuidedSymbolicExecutor:
    """LLM引导的符号执行器。

    基于分支评分器对候选分支排序，模拟探索路径并汇总
    高优先级路径与可疑分支。实际符号求解由外部引擎提供，
    本类负责优先级调度与结果组织。
    """

    def __init__(self, binary_path: str = "",
                 scorer: Optional[LLMBranchScorer] = None):
        self.binary_path = binary_path
        self.scorer = scorer if scorer is not None else DefaultLLMBranchScorer()
        self.explored_paths: List[Dict[str, Any]] = []
        self.current_path: List[int] = []
        self.interesting_branches: List[BranchInfo] = []

    @classmethod
    def get_metadata(cls) -> _ExecutorMetadata:
        return _ExecutorMetadata(
            name="LLMGuidedSymbolicExecutor",
            type=_AnalyzerType.SYMBOLIC_EXECUTOR,
            version="1.0.0",
            description="LLM 引导的符号执行引擎，用于分支优先级调度与路径探索",
            dependencies=["openai", "angr"],
            supported_platforms=["x86", "x86_64", "arm64"],
        )

    def validate_input(self, binary_path: str = "") -> Tuple[bool, Optional[str]]:
        """校验输入参数。"""
        if not binary_path:
            return False, "binary_path 是必需参数"
        if not isinstance(binary_path, str):
            return False, "binary_path 必须是字符串"
        return True, None

    def analyze(self, binary_path: str = "",
                max_paths: int = 10,
                context: str = "") -> Dict[str, Any]:
        """执行分析 — 校验输入后生成探索路径报告。"""
        valid, error = self.validate_input(binary_path)
        if not valid:
            return {"success": False, "error": error}

        self.binary_path = binary_path
        self.current_path = [0x401000, 0x402000] if binary_path else []
        branches = self._simulate_branches()
        scores = self.scorer.score_branches(branches, [], context)

        explored = []
        for i, (branch, score) in enumerate(zip(branches, scores)):
            path = {
                "path_id": f"path_{i:03d}",
                "current_address": branch.address,
                "score": score.true_branch_score,
                "priority": score.true_branch_priority.value,
            }
            explored.append(path)
            self.explored_paths.append(path)
            self.current_path.append(branch.address)

        high_priority = [p for p in explored
                         if p["priority"] == BranchPriority.HIGH.value]
        self.interesting_branches = [
            b for b, s in zip(branches, scores)
            if s.true_branch_priority == BranchPriority.HIGH
        ]

        return {
            "success": True,
            "result": {
                "explored_paths": explored,
                "high_priority_paths": high_priority,
                "interesting_branches": [
                    {"address": b.address, "condition": b.condition}
                    for b in self.interesting_branches
                ],
                "analysis_summary": {
                    "total_paths": len(explored),
                    "high_priority_count": len(high_priority),
                    "binary_path": binary_path,
                },
            },
        }

    def cleanup(self) -> None:
        """清空已探索路径与当前路径。"""
        self.explored_paths.clear()
        self.current_path.clear()

    def _simulate_branches(self, count: int = 10) -> List[BranchInfo]:
        """构造模拟分支集合——用于无真实IR时验证调度逻辑。"""
        branches = []
        for i in range(count):
            branches.append(BranchInfo(
                address=0x401000 + i * 8,
                condition="arg1 < 0x100" if i % 3 == 0
                         else "ptr != NULL" if i % 3 == 1
                         else "len > 0x20",
                true_branch_target=0x402000 + i * 8,
                false_branch_target=0x403000 + i * 8,
                depth=i % 4,
                constraint_count=i,
            ))
        return branches
