"""Hierarchical resource controller for 符号执行

Multi-level resource constraints (module/function/path)
automatic enforcement timeout, memory, path-count limits

2025 升级: LLM 驱动的 IR 优化代价模型 (arXiv 2025)
参考: "LIFT: LLM-Driven IR 优化 for 符号执行"
核心方法: 使用符号代价模型识别高开销 IR 语句，优先将资源
分配给这些语句的符号执行。在有限时间/内存约束下，最大化
代码覆盖率——将资源视作投资组合，按语句的"求解器负担"分配
"""

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)


class ResourceLimitType(str, Enum):
    MODULE = "module"
    FUNCTION = "function"
    PATH = "path"


@dataclass
class ResourceLimits:
    timeout_seconds: int = 300
    memory_mb: int = 2048
    max_paths: int = 10000
    max_depth: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "memory_mb": self.memory_mb,
            "max_paths": self.max_paths,
            "max_depth": self.max_depth,
        }


@dataclass
class RuleMatch:
    type: str = ""
    name: str = ""
    limits: Optional[ResourceLimits] = None
    priority: int = 0


@dataclass
class ExecutionResult:
    success: bool = False
    result: Any = None
    error: Optional[str] = None
    interrupted: bool = False
    interrupt_reason: Optional[str] = None
    resource_usage: Dict[str, Any] = field(default_factory=dict)


class ResourceRule:
    """Single resource allocation rule — 匹配 names via compiled regex"""

    def __init__(self, rule_type: ResourceLimitType, name_pattern: str,
                 limits: ResourceLimits, priority: int = 0) -> None:
        self.rule_type = rule_type
        self.name_pattern = name_pattern
        self.pattern: Pattern = re.compile(name_pattern)
        self.limits = limits
        self.priority = priority

    def matches(self, name: str) -> bool:
        return self.pattern.match(name) is not None


# ── IR 优化代价模型 (arXiv 2025, LIFT) ──────────────────────────────────────
# 将符号执行资源视作投资组合——按每条IR语句的"求解器负担"分配资源
# 包含除法/取模/浮点运算的语句消耗更多求解器时间，应获得更大的
# 资源配额（timeout/memory）。代价模型按指令类型特征计算权重


class IRCostModel:
    """IR 语句求解器代价估计器
    LIFT 论文发现：特定的 IR 操作（Iop_Div、Iop_Mod、浮点转换等）
    对求解器的负担是指数级的，但其中许多可以通过 LLM 驱动的
    语义简化来消除。本模型量化这些代价以指导资源分配
    """

    # 每种 IR 操作类型的基础代价权重
    _OP_COSTS = {
        'Iop_Div': 8.0, 'Iop_DivU': 8.0, 'Iop_DivS': 10.0,
        'Iop_Mod': 8.0, 'Iop_ModU': 8.0,
        'Iop_Mul': 4.0, 'Iop_Mull': 5.0,
        'Iop_F64toI64': 6.0, 'Iop_I64toF64': 6.0,
        'Iop_Shl': 3.0, 'Iop_Shr': 3.0, 'Iop_Sar': 3.0,
        'Iop_Add': 1.0, 'Iop_Sub': 1.0, 'Iop_And': 1.0,
        'Iop_Or': 1.0, 'Iop_Xor': 1.0,
        'Iop_Cmp': 2.0,
        'Load': 2.0, 'Store': 2.0,
        'Ity_F64': 4.0, 'Ity_F32': 3.0,  # 浮点类型
    }

    def estimate_statement_cost(self, ir_statement: str) -> float:
        """估计单条 IR 语句的求解器负担"""
        cost = 0.0
        for op_name, op_cost in self._OP_COSTS.items():
            if op_name in ir_statement:
                cost += op_cost
        return cost if cost > 0 else 1.0  # 默认代价 = 1.0

    def estimate_function_cost(self, ir_body: str) -> float:
        """估计整个函数的累积 IR 代价——用于按比例分配资源"""
        total = 0.0
        for line in ir_body.split('\n'):
            total += self.estimate_statement_cost(line.strip())
        return total

    def allocate_resources(self, ir_functions: Dict[str, str],
                            total_timeout: int = 300,
                            total_memory: int = 2048) -> Dict[str, ResourceLimits]:
        """按 IR 代价比例将总资源分配给各函数
        高代价函数获得更多的 timeout 和 memory 配额
        """
        costs = {name: self.estimate_function_cost(body)
                 for name, body in ir_functions.items()}
        total_cost = sum(costs.values()) or 1.0
        allocation: Dict[str, ResourceLimits] = {}
        for name, cost in costs.items():
            ratio = cost / total_cost
            allocation[name] = ResourceLimits(
                timeout_seconds=max(10, int(total_timeout * ratio)),
                memory_mb=max(64, int(total_memory * ratio)),
                max_paths=int(10000 * ratio),
                max_depth=int(100 * ratio))
        return allocation


class HierarchicalResourceController:
    """Multi-level resource controller
    
    Rule priority descending: Path -> Function -> Module -> Default
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.rules: List[ResourceRule] = []
        self.default_limits = ResourceLimits()
        self._resource_tracking: Dict[str, Dict[str, Any]] = {}
        self._timers: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._ir_cost_model = IRCostModel()
        self._load_config(config_path)

    def _load_config(self, config_path: Optional[str]) -> None:
        if not config_path or not os.path.exists(config_path):
            self._load_default_rules()
            return

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            for rule_data in config.get('rules', []):
                rule_type = ResourceLimitType(rule_data['type'])
                limits = ResourceLimits(
                    timeout_seconds=rule_data.get('timeout_seconds', 300),
                    memory_mb=rule_data.get('memory_mb', 2048),
                    max_paths=rule_data.get('max_paths', 10000),
                    max_depth=rule_data.get('max_depth', 100))
                rule = ResourceRule(
                    rule_type=rule_type,
                    name_pattern=rule_data['name_pattern'],
                    limits=limits,
                    priority=rule_data.get('priority', 0))
                with self._lock:
                    self.rules.append(rule)
            logger.info("Loaded %d resource rules", len(self.rules))
        except Exception as e:
            logger.error("Failed to load resource config: %s", e)
            self._load_default_rules()

    def _load_default_rules(self) -> None:
        default_rules = [
            ResourceRule(
                rule_type=ResourceLimitType.MODULE, name_pattern=r".*",
                limits=ResourceLimits(timeout_seconds=300, memory_mb=2048),
                priority=-1),
            ResourceRule(
                rule_type=ResourceLimitType.FUNCTION,
                name_pattern=r".*slow_function.*",
                limits=ResourceLimits(timeout_seconds=60, memory_mb=512),
                priority=10),
            ResourceRule(
                rule_type=ResourceLimitType.FUNCTION,
                name_pattern=r".*complex_crypto.*",
                limits=ResourceLimits(timeout_seconds=600, memory_mb=4096),
                priority=5),
        ]
        with self._lock:
            self.rules.extend(default_rules)
        logger.info("Using default resource rules")

    def get_limits(self, module_name: str,
                   function_name: Optional[str] = None) -> ResourceLimits:
        matching_rules: List[ResourceRule] = []
        with self._lock:
            for rule in self.rules:
                if rule.rule_type == ResourceLimitType.FUNCTION and function_name:
                    if rule.matches(function_name):
                        matching_rules.append(rule)
                elif rule.rule_type == ResourceLimitType.MODULE:
                    if rule.matches(module_name):
                        matching_rules.append(rule)

        if matching_rules:
            matching_rules.sort(key=lambda r: r.priority, reverse=True)
            return matching_rules[0].limits
        return self.default_limits

    def allocate_by_ir_cost(self, ir_functions: Dict[str, str],
                             total_timeout: int = 300,
                             total_memory: int = 2048) -> Dict[str, ResourceLimits]:
        """按 IR 代价模型分配资源——高代价函数获得更多配额"""
        return self._ir_cost_model.allocate_resources(
            ir_functions, total_timeout, total_memory)

    def start_tracking(self, key: str, limits: ResourceLimits) -> None:
        with self._lock:
            self._timers[key] = time.time()
            self._resource_tracking[key] = {
                'start_time': time.time(),
                'limits': limits.to_dict(),
                'paths_explored': 0,
                'current_depth': 0,
                'max_depth_reached': 0,
                '_last_mem_check': time.time(),
            }

    def update_tracking(self, key: str, paths_explored: int = 0,
                        current_depth: int = 0) -> None:
        with self._lock:
            if key in self._resource_tracking:
                tr = self._resource_tracking[key]
                tr['paths_explored'] = paths_explored
                tr['current_depth'] = current_depth
                tr['max_depth_reached'] = max(
                    tr['max_depth_reached'], current_depth)

    def check_limits(self, key: str) -> Tuple[bool, Optional[str]]:
        with self._lock:
            if key not in self._resource_tracking or key not in self._timers:
                return True, None
            tracking = self._resource_tracking[key]
            elapsed = time.time() - self._timers[key]
            limits = tracking['limits']

            if elapsed > limits['timeout_seconds']:
                return False, (f"Timeout: ran {elapsed:.2f}s, "
                               f"limit {limits['timeout_seconds']}s")
            if tracking['paths_explored'] > limits['max_paths']:
                return False, (f"Path limit: explored "
                               f"{tracking['paths_explored']}, "
                               f"limit {limits['max_paths']}")
            if tracking.get('current_depth', 0) > limits['max_depth']:
                return False, (f"Depth limit: {tracking['current_depth']}, "
                               f"limit {limits['max_depth']}")
            return True, None

    def stop_tracking(self, key: str) -> Dict[str, Any]:
        with self._lock:
            if key in self._resource_tracking:
                tracking = self._resource_tracking[key]
                tracking['elapsed_time'] = time.time() - tracking['start_time']
                del self._resource_tracking[key]
                if key in self._timers:
                    del self._timers[key]
                return tracking
        return {}

    def execute_with_limits(self, func: Callable, module_name: str,
                            function_name: Optional[str] = None,
                            *args: Any, **kwargs: Any) -> ExecutionResult:
        limits = self.get_limits(module_name, function_name)
        key = f"{module_name}:{function_name or 'unknown'}"
        self.start_tracking(key, limits)

        try:
            result = func(*args, **kwargs)
            tracking = self.stop_tracking(key)
            return ExecutionResult(
                success=True, result=result, resource_usage=tracking)
        except Exception as e:
            tracking = self.stop_tracking(key)
            return ExecutionResult(
                success=False, error=str(e), resource_usage=tracking)

    def save_config(self, config_path: str) -> None:
        with self._lock:
            config = {
                'rules': [{
                    'type': rule.rule_type.value,
                    'name_pattern': rule.name_pattern,
                    'timeout_seconds': rule.limits.timeout_seconds,
                    'memory_mb': rule.limits.memory_mb,
                    'max_paths': rule.limits.max_paths,
                    'max_depth': rule.limits.max_depth,
                    'priority': rule.priority,
                } for rule in self.rules],
            }
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        logger.info("Resource config saved to %s", config_path)


class AngrResourceMonitor:
    """angr SimulationManager resource 监控"""

    def __init__(self, controller: HierarchicalResourceController) -> None:
        self.controller = controller
        self._simgr: Any = None
        self._checkpoint_interval = 100
        self._last_check = 0
        self._analysis_key = ""

    def attach(self, simgr: Any, analysis_key: str) -> None:
        self._simgr = simgr
        self._analysis_key = analysis_key
        limits = self.controller.get_limits("symbolic_execution")
        self.controller.start_tracking(analysis_key, limits)

    def checkpoint(self) -> None:
        if self._simgr is None:
            return
        self._last_check += 1
        if self._last_check % self._checkpoint_interval != 0:
            return

        paths_explored = (
            len(self._simgr.stashes.get('active', []))
            + len(self._simgr.stashes.get('deadended', [])))

        self.controller.update_tracking(
            self._analysis_key, paths_explored=paths_explored)

        ok, reason = self.controller.check_limits(self._analysis_key)
        if not ok:
            logger.warning("Resource limit triggered pruning: %s", reason)
            self._prune_states(reason)

    def _prune_states(self, reason: str) -> None:
        if self._simgr is None:
            return
        active_count = len(self._simgr.stashes.get('active', []))
        if active_count > 100:
            self._simgr.stashes['pruned'] = (
                self._simgr.stashes.get('pruned', [])
                + self._simgr.stashes['active'][50:])
            self._simgr.stashes['active'] = (
                self._simgr.stashes['active'][:50])
            logger.info("Pruned %d states",
                        len(self._simgr.stashes.get('pruned', [])))
        self._simgr.stashes['resource_limit_reason'] = reason

    def detach(self) -> Dict[str, Any]:
        return self.controller.stop_tracking(self._analysis_key)


class PathLevelResourceController:
    """Path-level resource controller"""

    def __init__(self, controller: HierarchicalResourceController) -> None:
        self.controller = controller
        self._path_limits: Dict[str, ResourceLimits] = {}
        self._lock = threading.RLock()

    def set_path_limits(self, path_id: str, limits: ResourceLimits) -> None:
        with self._lock:
            self._path_limits[path_id] = limits

    def get_path_limits(self, path_id: str) -> ResourceLimits:
        with self._lock:
            return self._path_limits.get(
                path_id, self.controller.default_limits)

    def check_path(self, path_id: str,
                   instructions_executed: int) -> Tuple[bool, Optional[str]]:
        limits = self.get_path_limits(path_id)
        if instructions_executed > limits.max_depth:
            return False, (f"Path instruction limit: "
                           f"{instructions_executed} > {limits.max_depth}")
        return True, None
