# 已优化.
#!/usr/bin/env python3
# LLM-guided symbolic execution — branch prioritization with LLM scoring,
# path summaries, and integration with BaseAnalyzer interface.
# added simulated branch 构造 and DefaultLLMBranchScorer.
# branch dedup, __repr__ on core dataclasses, coverage-aware boost.

import logging as _logging
import json as _json
import heapq as _heapq
import hashlib as _hashlib
import re as _re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable

__dbg = _logging.getLogger(__name__)


# Data classes

@dataclass
class BranchPriority:
    """Priority ranking for a branch during symbolic execution."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class BranchInfo:
    """Information about a branch point."""
    address: int = 0
    branch_type: str = ""  # conditional, unconditional, indirect, call, ret
    condition: str = ""    # symbolic expression of the condition
    true_target: int = 0
    false_target: int = 0
    is_loop_header: bool = False
    is_loop_exit: bool = False
    call_depth: int = 0
    basic_block_id: int = 0
    parent_path_id: str = ""
    depth_from_entry: int = 0

    def __hash__(self):
        return hash((self.address, self.true_target, self.false_target))

    def __eq__(self, other):
        if not isinstance(other, BranchInfo):
            return False
        return (self.address == other.address and
                self.true_target == other.true_target and
                self.false_target == other.false_target)

    # 调试时快速看出分支关键属性，不用每次手动查字段
    def __repr__(self):
        return (f"BranchInfo(addr=0x{self.address:x}, type={self.branch_type}, "
                f"cond='{self.condition[:40]}', depth={self.depth_from_entry}, "
                f"loop_hdr={self.is_loop_header})")


@dataclass
class PathSummary:
    """Summary of an explored symbolic execution path."""
    path_id: str = ""
    entry_address: int = 0
    branch_sequence: List[BranchInfo] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    path_condition: str = ""
    visited_addresses: List[int] = field(default_factory=list)
    path_length: int = 0
    terminated_normally: bool = False
    terminated_with_error: bool = False
    error_type: str = ""
    symbolic_outputs: Dict[str, str] = field(default_factory=dict)
    vulnerability_found: bool = False
    vulnerability_type: str = ""
    vulnerability_address: int = 0
    interestingness_score: float = 0.0

    def get_branch_count(self) -> int:
        return len(self.branch_sequence)

    def get_unique_addresses(self) -> int:
        return len(set(self.visited_addresses))

    # 日志/报告里一眼看出路径摘要，不用拼字符串
    def __repr__(self):
        vuln_tag = f" VULN:{self.vulnerability_type}" if self.vulnerability_found else ""
        return (f"PathSummary(id={self.path_id}, len={self.path_length}, "
                f"branches={len(self.branch_sequence)}, "
                f"score={self.interestingness_score:.3f}{vuln_tag})")


@dataclass
class LLMBranchScore:
    """LLM-assigned score for a branch, guiding exploration priority."""
    branch: BranchInfo
    priority: int = BranchPriority.MEDIUM
    score: float = 0.5
    reasoning: str = ""
    suggested_constraints: List[str] = field(default_factory=list)
    vulnerability_likelihood: float = 0.0
    interesting_patterns: List[str] = field(default_factory=list)
    # 2026-07-30: 记录分支在队列中出现的次数，避免重复打分耗尽优先级
    enqueue_count: int = 0

    def __lt__(self, other):
        return self.score < other.score

    def to_priority_tuple(self) -> Tuple[int, float]:
        return (-self.priority, -self.score)

    # 快速定位高价值分支，辅助人工审查
    def __repr__(self):
        return (f"LLMBranchScore(addr=0x{self.branch.address:x}, "
                f"score={self.score:.3f}, pri={self.priority}, "
                f"vuln_lik={self.vulnerability_likelihood:.2f}, "
                f"patterns={self.interesting_patterns})")


# LLM Client interface (mockable)

class LLMBranchScorerBase:
    """Abstract base for LLM-based branch scoring."""

    def score_branch(self, branch: BranchInfo,
                     path_history: List[PathSummary],
                     context: str = "") -> LLMBranchScore:
        raise NotImplementedError

    def score_branches(self, branches: List[BranchInfo],
                       path_history: List[PathSummary],
                       context: str = "") -> List[LLMBranchScore]:
        raise NotImplementedError


# Default Scorer (heuristic + regex-based, no API required)

class DefaultLLMBranchScorer(LLMBranchScorerBase):
    """Heuristic branch scorer using pattern matching on conditions and context."""

    __slots__ = ('m_vuln_patterns', 'm_interesting_functions')

    def __init__(self):
        self.m_vuln_patterns = [
            (r'(?:memcpy|strcpy|strcat|sprintf|gets|scanf)\s*\(', "Buffer operation", 0.7),
            (r'(?:malloc|calloc|realloc)\s*\(', "Memory allocation", 0.3),
            (r'(?:free)\s*\(', "Memory deallocation", 0.5),
            (r'(?:system|exec|popen)\s*\(', "Command execution", 0.9),
            (r'(?:len|size|count|n)\s*(?:<|>|<=|>=|==)', "Length check", 0.4),
            (r'(?:null|NULL|0)\s*(?:==|!=)\s*', "Null check", 0.2),
            (r'\[.*\]\s*=', "Array write", 0.5),
            (r'(?:strcmp|strncmp|memcmp)\s*\(', "String comparison", 0.3),
            (r'(?:recv|read|fread)\s*\(', "Data input", 0.6),
            (r'(?:send|write|fwrite)\s*\(', "Data output", 0.3),
        ]
        self.m_interesting_functions: Set[str] = {
            "memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
            "gets", "scanf", "fscanf", "sscanf",
            "malloc", "calloc", "realloc", "free",
            "system", "execve", "execvp", "popen",
            "recv", "recvfrom", "read", "fread",
            "send", "sendto", "write", "fwrite",
        }

    def score_branch(self, branch: BranchInfo,
                     path_history: List[PathSummary],
                     context: str = "") -> LLMBranchScore:
        score_obj = LLMBranchScore(branch=branch)

        # Base score: prefer branches at deeper depth (more interesting paths)
        depth_factor = min(branch.depth_from_entry / 20.0, 1.0) * 0.2

        # Condition-based scoring
        cond_lower = branch.condition.lower()
        cond_score = 0.0
        pi = 0
        while pi < len(self.m_vuln_patterns):
            pattern, label, weight = self.m_vuln_patterns[pi]
            if _re.search(pattern, cond_lower):
                cond_score += weight * 0.3
                score_obj.interesting_patterns.append(label)
            pi += 1

        # Loop header/相关性
        if branch.is_loop_header:
            cond_score += 0.15
            score_obj.interesting_patterns.append("Loop header")
        if branch.is_loop_exit:
            cond_score += 0.1

        # Indirect branches are interesting
        if branch.branch_type == "indirect":
            cond_score += 0.2
            score_obj.interesting_patterns.append("Indirect branch")

        # Context-based scoring
        context_lower = context.lower()
        cxi = 0
        while cxi < len(self.m_vuln_patterns):
            pattern, label, weight = self.m_vuln_patterns[cxi]
            if _re.search(pattern, context_lower):
                cond_score += weight * 0.15
            cxi += 1

        # Normalize
        total_score = min(depth_factor + cond_score, 1.0)
        score_obj.score = max(0.05, total_score)
        score_obj.vulnerability_likelihood = cond_score

        # Assign priority
        if score_obj.score >= 0.8:
            score_obj.priority = BranchPriority.CRITICAL
        elif score_obj.score >= 0.6:
            score_obj.priority = BranchPriority.HIGH
        elif score_obj.score >= 0.3:
            score_obj.priority = BranchPriority.MEDIUM
        else:
            score_obj.priority = BranchPriority.LOW

        score_obj.reasoning = f"Heuristic score: depth={depth_factor:.2f} cond={cond_score:.2f}"
        return score_obj

    def score_branches(self, branches: List[BranchInfo],
                       path_history: List[PathSummary],
                       context: str = "") -> List[LLMBranchScore]:
        scores: List[LLMBranchScore] = []
        bi = 0
        while bi < len(branches):
            scores.append(self.score_branch(branches[bi], path_history, context))
            bi += 1
        return scores


# BaseAnalyzer interface (matching project convention)

class BaseAnalyzer:
    """Abstract analyzer interface for integration with the framework."""

    def analyze(self, **kwargs) -> Any:
        raise NotImplementedError

    def get_name(self) -> str:
        raise NotImplementedError

    def get_version(self) -> str:
        return "1.0.0"


# Simulated branch 构造

def _simulate_branches(function_address=0x400000, count=10) -> List[BranchInfo]:
    """Generate simulated branch information for testing/demonstration."""
    import random as _r
    branches: List[BranchInfo] = []
    branch_types = ["conditional", "conditional", "conditional", "unconditional", "indirect", "call", "ret"]
    i = 0
    while i < count:
        addr = function_address + i * 8 + _r.randint(0, 4)
        branch = BranchInfo(
            address=addr,
            branch_type=_r.choice(branch_types),
            condition=_r.choice([
                "arg1 < 10",
                "arg1 == 0",
                "len > 0x100",
                "ptr != NULL",
                "idx < count",
                "arg1 & 0xFF == 0x41",
                "(arg1 + arg2) > 0x1000",
            ]),
            true_target=addr + 0x10 + _r.randint(0, 0x100),
            false_target=addr + 0x20 + _r.randint(0, 0x100),
            is_loop_header=_r.random() < 0.2,
            is_loop_exit=_r.random() < 0.15,
            call_depth=_r.randint(0, 3),
            basic_block_id=i,
            parent_path_id=f"path_{i // 3}",
            depth_from_entry=i + _r.randint(0, 3),
        )
        branches.append(branch)
        i += 1
    return branches


# LLM-Guided Symbolic Executor

class LLMGuidedSymbolicExecutor(BaseAnalyzer):
    """Symbolic execution engine guided by LLM branch scoring.

    Integrates with the project's BaseAnalyzer interface for drop-in use
    in analysis pipelines.
    """

    __slots__ = ('m_scorer', 'm_paths', 'm_branch_queue', 'm_max_paths',
                 'm_max_depth', 'm_timeout_seconds', 'm_stats',
                 'm_active_paths', 'm_covered_addresses', 'm_vulnerabilities',
                 'm_seen_branches')  # 2026-07-30: 去重已处理的分支，防止死循环填满队列

    def __init__(self, scorer: Optional[LLMBranchScorerBase] = None,
                 max_paths: int = 100, max_depth: int = 50,
                 timeout_seconds: int = 300):
        self.m_scorer = scorer if scorer is not None else DefaultLLMBranchScorer()
        self.m_max_paths = max_paths
        self.m_max_depth = max_depth
        self.m_timeout_seconds = timeout_seconds
        self.m_paths: List[PathSummary] = []
        self.m_branch_queue: List[Tuple[int, float, int, BranchInfo]] = []
        self.m_active_paths: Dict[str, PathSummary] = {}
        self.m_covered_addresses: Set[int] = set()
        self.m_vulnerabilities: List[Dict[str, Any]] = []
        self.m_stats: Dict[str, Any] = {}
        # 2026-07-30: 分支指纹集合，同一 (addr, true_target, false_target) 只入队一次
        self.m_seen_branches: Set[Tuple[int, int, int]] = set()

    def get_name(self) -> str:
        return "LLMGuidedSymbolicExecutor"

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Entry point matching BaseAnalyzer interface."""
        binary_path = kwargs.get("binary_path", "")
        function_addr = kwargs.get("function_address", 0)
        initial_state = kwargs.get("initial_state")
        context = kwargs.get("context", "")

        self.reset()

        # 构造 or receive initial branches
        branches = kwargs.get("branches")
        if branches is None:
            branches = _simulate_branches(function_addr, count=15)

        return self.execute(branches, context=context)

    def _branch_fingerprint(self, branch: BranchInfo) -> Tuple[int, int, int]:
        """生成分支去重指纹：地址 + 两个目标地址构成唯一标识。
        仅用于内部去重，不影响 BranchInfo.__hash__ 的语义。"""
        return (branch.address, branch.true_target, branch.false_target)

    # 2026-07-30: 覆盖率感知加分 — 目标地址从未见过时提高优先级
    def _coverage_boost(self, branch: BranchInfo) -> float:
        """Return a small priority boost (0.0–0.1) for branches whose targets
        include uncovered addresses, incentivizing path diversity."""
        boost = 0.0
        if branch.true_target not in self.m_covered_addresses:
            boost += 0.05
        if branch.false_target and branch.false_target not in self.m_covered_addresses:
            boost += 0.05
        return boost

    def execute(self, initial_branches: List[BranchInfo],
                context: str = "") -> Dict[str, Any]:
        """Run LLM-guided symbolic execution starting from initial branches."""
        import time as _time
        start_time = _time.time()

        # Score and 队列 initial branches — 只入队未见过的新分支
        scores = self.m_scorer.score_branches(initial_branches, [], context)
        bi = 0
        while bi < len(scores):
            s = scores[bi]
            fp = self._branch_fingerprint(s.branch)
            if fp not in self.m_seen_branches:
                self.m_seen_branches.add(fp)
                priority_tuple = s.to_priority_tuple()
                # 2026-07-30: 覆盖率加分融入优先级元组，引导探索未覆盖区域
                _boost = self._coverage_boost(s.branch)
                _heapq.heappush(self.m_branch_queue,
                                (priority_tuple[0], priority_tuple[1] + _boost, bi, s.branch))
            bi += 1

        path_counter = 0

        while len(self.m_branch_queue) > 0 and path_counter < self.m_max_paths:
            # Check timeout
            if _time.time() - start_time > self.m_timeout_seconds:
                __dbg.warning("Symbolic execution timeout after %.1fs", _time.time() - start_time)
                break

            # Pop highest priority branch
            priority, score, idx, branch = _heapq.heappop(self.m_branch_queue)

            # Create path from this branch
            path = self._explore_branch(branch, context)

            if path:
                self.m_paths.append(path)
                self.m_active_paths[path.path_id] = path
                for addr in path.visited_addresses:
                    self.m_covered_addresses.add(addr)

                if path.vulnerability_found:
                    self.m_vulnerabilities.append({
                        "path_id": path.path_id,
                        "type": path.vulnerability_type,
                        "address": path.vulnerability_address,
                    })

                # 构造 follow-up branches for this path
                if path.path_length < self.m_max_depth:
                    new_branches = self._generate_next_branches(path, context)
                    if new_branches:
                        new_scores = self.m_scorer.score_branches(new_branches, self.m_paths, context)
                        nsi = 0
                        while nsi < len(new_scores):
                            ns = new_scores[nsi]
                            ns_fp = self._branch_fingerprint(ns.branch)
                            # 2026-07-30: 去重检查 — 已经入队的分支不再重复添加
                            if ns_fp not in self.m_seen_branches:
                                self.m_seen_branches.add(ns_fp)
                                # 已处理路径数为零时覆盖率集仍小，加分效果更明显
                                _boost = self._coverage_boost(ns.branch)
                                ns.enqueue_count += 1
                                pt = ns.to_priority_tuple()
                                _heapq.heappush(self.m_branch_queue,
                                                (pt[0], pt[1] + _boost, path_counter + nsi, ns.branch))
                            nsi += 1

            path_counter += 1

        # Compile stats
        self.m_stats = {
            "total_paths": len(self.m_paths),
            "covered_addresses": len(self.m_covered_addresses),
            "vulnerabilities_found": len(self.m_vulnerabilities),
            "max_depth_reached": max((p.path_length for p in self.m_paths), default=0),
            "elapsed_seconds": _time.time() - start_time,
            "branch_queue_remaining": len(self.m_branch_queue),
            # 2026-07-30: 去重统计，帮助判断分支空间的覆盖效率
            "unique_branches_enqueued": len(self.m_seen_branches),
        }

        return self._build_report()

    def _explore_branch(self, branch: BranchInfo, context: str) -> Optional[PathSummary]:
        """Simulate exploring a branch — returns a path summary."""
        import random as _r

        path = PathSummary(
            path_id=f"path_{_hashlib.sha256(str(branch.address).encode()).hexdigest()[:8]}",
            entry_address=branch.address,
            branch_sequence=[branch],
            path_length=1,
        )

        # Simulate path 探索
        visited = [branch.address, branch.true_target]
        if branch.false_target:
            visited.append(branch.false_target)

        path.visited_addresses = visited

        # Simulate constraint building
        if branch.condition:
            path.constraints.append(f"({branch.condition}) == true")
            path.path_condition = f"({branch.condition}) == true"

        # Simulate vulnerability 检测
        if _r.random() < 0.05:
            path.vulnerability_found = True
            path.vulnerability_type = _r.choice([
                "buffer_overflow", "use_after_free", "null_dereference",
                "integer_overflow", "format_string",
            ])
            path.vulnerability_address = branch.address
            path.interestingness_score = 0.9
        else:
            path.interestingness_score = _r.uniform(0.1, 0.7)

        path.terminated_normally = True
        path.path_length = 1

        return path

    def _generate_next_branches(self, path: PathSummary, context: str) -> List[BranchInfo]:
        """Generate follow-up branch points from a path."""
        import random as _r

        if not path.visited_addresses:
            return []

        next_branches: List[BranchInfo] = []
        last_addr = path.visited_addresses[-1]
        count = _r.randint(1, 3)

        i = 0
        while i < count:
            new_branch = BranchInfo(
                address=last_addr + i * 0x10 + _r.randint(0, 0x20),
                branch_type=_r.choice(["conditional", "unconditional", "indirect", "call"]),
                condition=_r.choice([
                    "arg1 < 10", "arg1 == 0", "len > 0x100",
                    "ptr != NULL", "idx < count",
                ]),
                true_target=last_addr + 0x40 + _r.randint(0, 0x100),
                false_target=last_addr + 0x60 + _r.randint(0, 0x100),
                call_depth=path.branch_sequence[0].call_depth + 1 if path.branch_sequence else 0,
                depth_from_entry=path.path_length + 1,
                parent_path_id=path.path_id,
            )
            next_branches.append(new_branch)
            i += 1

        return next_branches

    def _build_report(self) -> Dict[str, Any]:
        """Build a comprehensive execution report."""
        report = {
            "stats": dict(self.m_stats),
            "vulnerabilities": list(self.m_vulnerabilities),
            "top_paths": [],
            "coverage_summary": {
                "total_addresses": len(self.m_covered_addresses),
                "addresses": sorted(list(self.m_covered_addresses))[:100],
            },
            "branch_priorities": {
                "CRITICAL": sum(1 for _p, _s, _i, b in self.m_branch_queue),
            },
        }

        # Top paths by interestingness
        sorted_paths = sorted(self.m_paths, key=lambda p: p.interestingness_score, reverse=True)
        pi = 0
        while pi < min(10, len(sorted_paths)):
            p = sorted_paths[pi]
            report["top_paths"].append({
                "path_id": p.path_id,
                "score": p.interestingness_score,
                "length": p.path_length,
                "vuln": p.vulnerability_type if p.vulnerability_found else None,
            })
            pi += 1

        return report

    def get_paths(self) -> List[PathSummary]:
        return list(self.m_paths)

    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        return list(self.m_vulnerabilities)

    def reset(self):
        self.m_paths.clear()
        self.m_branch_queue.clear()
        self.m_active_paths.clear()
        self.m_covered_addresses.clear()
        self.m_vulnerabilities.clear()
        self.m_stats.clear()
        self.m_seen_branches.clear()  # 2026-07-30: 重置去重集合


def _debug_print(*args, **kwargs):  # 调试残余--未删除
    """Print debug info if env var is set. Not currently called."""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)


# End of llm_guided_symbex.py
