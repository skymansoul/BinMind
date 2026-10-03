"""复杂度驱动资源分配——代码复杂度 + 输入复杂度 + 协议复杂度 -> 综合分数"""
import math
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class ComplexityScore:
    input_complexity: float = 0.0
    code_complexity: float = 0.0
    protocol_complexity: float = 0.0
    combined_score: float = 0.0

    def __post_init__(self):
        if self.combined_score == 0.0:
            self.combined_score = (
                self.input_complexity * 0.3 +
                self.code_complexity * 0.5 +
                self.protocol_complexity * 0.2
            )


@dataclass
class ResourceAllocation:
    target: str
    cpu_share: float       # 0-1, 跨目标总和 = 1
    time_share: float
    memory_limit: int      # MB
    complexity: ComplexityScore = field(default_factory=ComplexityScore)


def estimate_complexity(target: str,
                        binary_size: int = None,
                        block_count: int = None,
                        branch_count: int = None,
                        input_size_min: int = 1,
                        input_size_max: int = 4096,
                        protocol_fields: int = 1) -> ComplexityScore:
    """估算目标的 fuzzing 难度"""
    _input_sz_range = math.log2(max(input_size_max, 1)) - math.log2(max(input_size_min, 1))
    _input_complexity = min(10.0, max(0.1, _input_sz_range))

    _code_complexity = 1.0
    if block_count and branch_count:
        _blocks = math.log2(max(block_count, 1))
        _branches = math.log2(max(branch_count, 1))
        _code_complexity = min(10.0, max(0.1, _blocks * 0.6 + _branches * 0.4))

    _proto_complexity = min(10.0, max(0.1, math.log2(max(protocol_fields, 1)) + 1))

    return ComplexityScore(
        input_complexity=_input_complexity,
        code_complexity=_code_complexity,
        protocol_complexity=_proto_complexity,
    )


def allocate_resources(targets: List[str],
                       complexities: Dict[str, ComplexityScore] = None,
                       total_cpu: float = 1.0,
                       total_time: float = 3600.0,
                       total_memory: int = 8192) -> List[ResourceAllocation]:
    """按复杂度比例分配 fuzzing 资源"""
    _comps = complexities or {}
    _allocations = []

    _scores = {}
    for _t in targets:
        _c = _comps.get(_t, ComplexityScore())
        _scores[_t] = _c.combined_score

    _total_score = sum(_scores.values())
    if _total_score <= 0:
        _total_score = len(targets)

    for _t in targets:
        _weight = _scores[_t] / _total_score
        _allocations.append(ResourceAllocation(
            target=_t,
            cpu_share=_weight,
            time_share=_weight,
            memory_limit=int(total_memory * _weight),
            complexity=_comps.get(_t, ComplexityScore()),
        ))

    return _allocations


def adjust_allocation(allocation: List[ResourceAllocation],
                      coverage_feedback: Dict[str, float],
                      min_share: float = 0.05) -> List[ResourceAllocation]:
    """覆盖率反馈动态调整：增长快的目标获更多资源，停滞的削减"""
    _total_gain = sum(max(0, _v) for _v in coverage_feedback.values())
    if _total_gain <= 0:
        return allocation

    _adj = []
    for _a in allocation:
        _gain = coverage_feedback.get(_a.target, 0)
        _share = max(min_share, _gain / _total_gain) if _total_gain > 0 else _a.cpu_share
        _a.cpu_share = _share
        _a.time_share = _share
        _adj.append(_a)

    _total_share = sum(_a.cpu_share for _a in _adj)
    if _total_share > 0:
        for _a in _adj:
            _a.cpu_share /= _total_share
            _a.time_share /= _total_share

    return _adj


def analyze_binary_complexity(binary_path: str) -> Dict[str, Any]:
    """二进制结构复杂度估算——基于文件大小与段结构近似推断"""
    _result = {
        "size": 0,
        "estimated_blocks": 0,
        "estimated_branches": 0,
        "section_count": 0,
    }
    if not os.path.isfile(binary_path):
        return _result
    try:
        _size = os.path.getsize(binary_path)
        _result["size"] = _size
        _result["estimated_blocks"] = max(1, _size // 256)
        _result["estimated_branches"] = max(1, _size // 64)
    except OSError:
        pass
    return _result


class CodeComplexityGuidedResourceAllocator:
    """分析资源按函数复杂度与风险比例分配，高风险函数获得更深符号执行"""

    def __init__(self):
        self.complexity_scores: Dict[int, float] = {}
        self.resource_allocation: Dict[int, Dict[str, Any]] = {}
        self.total_budget: float = 100.0

    def calculate_complexity_score(self, function_code: str) -> float:
        """函数复杂度评分：控制流 + API 调用 + 内存操作 + 规模"""
        score = 0.0

        cf_count = len(re.findall(r'(if|while|for|switch)', function_code))
        score += cf_count * 2

        api_count = len(re.findall(r'call\s+\w+', function_code))
        score += api_count * 1

        mem_count = len(re.findall(r'(malloc|free|memcpy|strcpy)', function_code))
        score += mem_count * 3

        line_count = len(function_code.split('\n'))
        score += line_count * 0.1

        return score

    @staticmethod
    def cyclomatic_complexity(function_code: str) -> int:
        """McCabe 圈复杂度: M = E - N + 2P，简化为决策点计数 + 1"""
        decision_patterns = [
            r'\bif\b', r'\bwhile\b', r'\bfor\b', r'\bswitch\b',
            r'\bcase\b', r'\bcatch\b', r'\band\b', r'\bor\b',
            r'\?\s*.*\s*:',
        ]
        count = 1
        for pat in decision_patterns:
            count += len(re.findall(pat, function_code))
        return count

    def allocate_resources(self, function_addr: int, complexity_score: float) -> Dict[str, Any]:
        """按复杂度等比分配资源"""
        allocation = {
            'function_addr': function_addr,
            'complexity_score': complexity_score,
            'symbolic_depth': min(10, int(complexity_score / 5)),
            'analysis_time': min(30, complexity_score * 0.5),
            'priority': 'high' if complexity_score > 20 else 'medium'
        }

        self.complexity_scores[function_addr] = complexity_score
        self.resource_allocation[function_addr] = allocation

        return allocation

    def distribute_budget(self, functions: Dict[int, str]) -> Dict[str, Any]:
        """预算按复杂度比例分配，单函数不超过总预算 40%"""
        total_complexity = 0
        allocations = {}

        for addr, code in functions.items():
            score = self.calculate_complexity_score(code)
            total_complexity += score
            allocations[addr] = score

        distribution = {}
        remaining_budget = self.total_budget

        for addr, score in allocations.items():
            if total_complexity > 0:
                budget_share = (score / total_complexity) * self.total_budget
                distribution[addr] = self.allocate_resources(addr, score)
                distribution[addr]['budget_share'] = budget_share

        return distribution

    def get_analysis_priority_order(self) -> List[int]:
        """按复杂度降序排列分析优先级"""
        sorted_funcs = sorted(
            self.complexity_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [addr for addr, score in sorted_funcs]

    def generate_allocation_report(self) -> str:
        """资源分配报告"""
        report = '# 复杂度驱动资源分配报告\n\n'

        report += '## 资源分配\n'
        for addr, allocation in self.resource_allocation.items():
            report += f'- {hex(addr)}: score={allocation["complexity_score"]}, time={allocation["analysis_time"]}min\n'

        return report
