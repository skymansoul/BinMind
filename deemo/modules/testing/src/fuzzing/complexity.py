# 2026-07-31
# Complexity-driven resource allocation — 智能分配 fuzzing 资源
# 估算：代码复杂度 + 输入复杂度 + 协议复杂度 → 综合分数
# 分配：按分数比例分配 CPU/时间/内存，高复杂度目标获得更多资源。
import math
import os
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class ComplexityScore:
    input_complexity: float = 0.0   # 输入尺寸、嵌套深度、边界数量
    code_complexity: float = 0.0    # 基本块数、分支数、函数数
    protocol_complexity: float = 0.0  # 消息类型数、字段数、状态机状态
    combined_score: float = 0.0     # 加权组合

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
    cpu_share: float       # 0-1, sum across all targets = 1
    time_share: float      # 0-1
    memory_limit: int      # MB
    complexity: ComplexityScore = field(default_factory=ComplexityScore)


# ================================================
def estimate_complexity(target: str,
                        binary_size: int = None,
                        block_count: int = None,
                        branch_count: int = None,
                        input_size_min: int = 1,
                        input_size_max: int = 4096,
                        protocol_fields: int = 1) -> ComplexityScore:
    """分析目标估算 fuzzing 难度。

    - 输入复杂度：输入尺寸范围、嵌套深度
    - 代码复杂度：基本块数、分支数
    - 协议复杂度：字段数
    """
    # Input complexity
    _input_sz_range = math.log2(max(input_size_max, 1)) - math.log2(max(input_size_min, 1))
    _input_complexity = min(10.0, max(0.1, _input_sz_range))

    # Code complexity
    _code_complexity = 1.0
    if block_count and branch_count:
        _blocks = math.log2(max(block_count, 1))
        _branches = math.log2(max(branch_count, 1))
        _code_complexity = min(10.0, max(0.1, _blocks * 0.6 + _branches * 0.4))

    # Protocol complexity
    _proto_complexity = min(10.0, max(0.1, math.log2(max(protocol_fields, 1)) + 1))

    return ComplexityScore(
        input_complexity=_input_complexity,
        code_complexity=_code_complexity,
        protocol_complexity=_proto_complexity,
    )


# ================================================
def allocate_resources(targets: List[str],
                       complexities: Dict[str, ComplexityScore] = None,
                       total_cpu: float = 1.0,
                       total_time: float = 3600.0,
                       total_memory: int = 8192) -> List[ResourceAllocation]:
    """按复杂度比例分配 fuzzing 资源。

    targets: 目标列表
    complexities: 每个目标的复杂度评分（可选，未提供的使用默认值）
    """
    _comps = complexities or {}
    _allocations = []

    # 计算加权分数
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


# ================================================
def adjust_allocation(allocation: List[ResourceAllocation],
                      coverage_feedback: Dict[str, float],
                      min_share: float = 0.05) -> List[ResourceAllocation]:
    """基于覆盖率反馈动态调整资源分配。
    覆盖率增长快的目标获得更多资源；停滞的目标降低。
    coverage_feedback: {target: coverage_delta_since_last_check}
    """
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

    # 归一化
    _total_share = sum(_a.cpu_share for _a in _adj)
    if _total_share > 0:
        for _a in _adj:
            _a.cpu_share /= _total_share
            _a.time_share /= _total_share

    return _adj


# ================================================
def analyze_binary_complexity(binary_path: str) -> Dict[str, Any]:
    """分析二进制文件的结构复杂度（用于估算代码复杂度的输入）。
    通过大小和段结构近似估算。
    """
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
        # 粗略估算：每 32 字节 ≈ 1 条指令，每 8 条指令 ≈ 1 branch
        _result["estimated_blocks"] = max(1, _size // 256)
        _result["estimated_branches"] = max(1, _size // 64)
    except OSError:
        pass
    return _result
