"""
差分测试数据模型原语。

从 differential_tester.py 中提取——这些dataclass和枚举构成自包含的数据契约。
与引擎（动词）分离后，其他模块可直接导入模型而无需引入subprocess/threading
及1500行的引擎类。字段变更即意味着所有消费者的传输格式变更。
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class TestMode(str, Enum):
    CROSS_VERSION = "cross_version"
    CROSS_IMPLEMENTATION = "cross_impl"

class DifferenceType(str, Enum):
    OUTPUT_MISMATCH = "output_mismatch"
    CRASH = "crash"
    HANG = "hang"
    MEMORY_CORRUPTION = "memory_corruption"
    BEHAVIOR_CHANGE = "behavior_change"
    PERFORMANCE_CHANGE = "performance_change"
    NONE = "none"


@dataclass
class TestCase:
    test_id: str
    input_data: bytes
    input_type: str = "random"
    coverage: float = 0.0
    mutation_info: str = ""
    generated_at: float = 0.0
    # 能量调度: 被选中次数与收益
    energy: float = 1.0
    times_chosen: int = 0
    new_paths_found: int = 0
    # 栈哈希，用于崩溃去重
    stack_hash: str = ""


@dataclass
class ExecutionResult:
    binary_path: str
    test_case: TestCase
    exit_code: int
    stdout: bytes
    stderr: bytes
    execution_time: float
    memory_usage: int = 0
    crashed: bool = False
    hung: bool = False
    error_message: str = ""
    # 崩溃上下文扩展
    signal_number: int = 0
    fault_address: int = 0
    crash_stack_frames: List[str] = field(default_factory=list)


@dataclass
class Difference:
    test_case: TestCase
    difference_type: str
    description: str
    severity: str = "unknown"
    binary_a_result: Optional[ExecutionResult] = None
    binary_b_result: Optional[ExecutionResult] = None
    likely_vulnerability: bool = False
    evidence: dict = field(default_factory=dict)
    # 去重分组键
    dedup_group: str = ""


@dataclass
class DifferentialTestResult:
    success: bool
    test_mode: str
    total_tests: int = 0
    total_differences: int = 0
    unique_inputs: int = 0
    execution_time: float = 0.0
    differences: list = field(default_factory=list)
    potential_vulnerabilities: list = field(default_factory=list)
    summary: str = ""
    coverage_stats: dict = field(default_factory=dict)
    # 崩溃去重统计
    unique_crash_groups: int = 0
    # 性能统计
    avg_exec_time_ms: float = 0.0
    exec_time_stddev: float = 0.0
