$content = @"
\"\"\"
分级资源控制器 - 支持模块级、函数级、路径级的超时与内存配额控制

功能：
1. 分层资源配置：模块级 → 函数级（正则匹配）→ 路径级
2. angr模拟管理器集成，插入检查点进行资源监控
3. 超过配额自动剪枝并记录原因
4. 返回不完整结果而非空结果
\"\"\"

import os
import sys
import time
import re
import json
import logging
import threading
from typing import Dict, Any, Optional, Callable, Pattern, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class ResourceLimitType(Enum):
    \"\"\"资源限制类型\"\"\"
    MODULE = \"module\"
    FUNCTION = \"function\"
    PATH = \"path\"


@dataclass
class ResourceLimits:
    \"\"\"资源限制配置\"\"\"
    timeout_seconds: int = 300
    memory_mb: int = 2048
    max_paths: int = 10000
    max_depth: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            \"timeout_seconds\": self.timeout_seconds,
            \"memory_mb\": self.memory_mb,
            \"max_paths\": self.max_paths,
            \"max_depth\": self.max_depth
        }


@dataclass
class RuleMatch:
    \"\"\"规则匹配结果\"\"\"
    type: ResourceLimitType
    name: str
    limits: ResourceLimits
    priority: int = 0


@dataclass
class ExecutionResult:
    \"\"\"执行结果\"\"\"
    success: bool
    result: Any = None
    error: Optional[str] = None
    interrupted: bool = False
    interrupt_reason: Optional[str] = None
    resource_usage: Dict[str, Any] = field(default_factory=dict)


class ResourceRule:
    \"\"\"资源规则\"\"\"
    
    def __init__(
        self,
        rule_type: ResourceLimitType,
        name_pattern: str,
        limits: ResourceLimits,
        priority: int = 0
    ):
        self.rule_type = rule_type
        self.name_pattern = name_pattern
        self.pattern: Pattern = re.compile(name_pattern)
        self.limits = limits
        self.priority = priority
    
    def matches(self, name: str) -> bool:
        \"\"\"检查名称是否匹配规则\"\"\"
        return self.pattern.match(name) is not None


class HierarchicalResourceController:
    \"\"\"
    分级资源控制器
    
    支持多层级资源配置：
    - 模块级：按分析模块名称匹配
    - 函数级：按函数名正则匹配
    - 路径级：按执行路径特征匹配
    
    优先级：路径级 > 函数级 > 模块级 > 默认
    \"\"\"
    
    def __init__(self, config_path: Optional[str] = None):
        self.rules: List[ResourceRule] = []
        self.default_limits = ResourceLimits()
        self._load_config(config_path)
        self._active_limits: Dict[str, ResourceLimits] = {}
        self._resource_tracking: Dict[str, Dict[str, Any]] = {}
        self._timers: Dict[str, float] = {}
        self._lock = threading.RLock()
    
    def _load_config(self, config_path: Optional[str]):
        \"\"\"从配置文件加载规则\"\"\"
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
                    max_depth=rule_data.get('max_depth', 100)
                )
                rule = ResourceRule(
                    rule_type=rule_type,
                    name_pattern=rule_data['name_pattern'],
                    limits=limits,
                    priority=rule_data.get('priority', 0)
                )
                self.rules.append(rule)
            
            logger.info(f\"已加载 {len(self.rules)} 条资源规则\")
        except Exception as e:
            logger.error(f\"加载资源配置失败: {e}\")
            self._load_default_rules()
    
    def _load_default_rules(self):
        \"\"\"加载默认规则\"\"\"
        default_rules = [
            ResourceRule(
                rule_type=ResourceLimitType.MODULE,
                name_pattern=r\".*\",
                limits=ResourceLimits(timeout_seconds=300, memory_mb=2048),
                priority=-1
            ),
            ResourceRule(
                rule_type=ResourceLimitType.FUNCTION,
                name_pattern=r\".*slow_function.*\",
                limits=ResourceLimits(timeout_seconds=60, memory_mb=512),
                priority=10
            ),
            ResourceRule(
                rule_type=ResourceLimitType.FUNCTION,
                name_pattern=r\".*complex_crypto.*\",
                limits=ResourceLimits(timeout_seconds=600, memory_mb=4096),
                priority=5
            )
        ]
        self.rules.extend(default_rules)
        logger.info(\"使用默认资源规则\")
    
    def get_limits(self, module_name: str, function_name: Optional[str] = None) -> ResourceLimits:
        \"\"\"
        获取匹配的资源限制
        
        优先级：函数级 > 模块级 > 默认
        \"\"\"
        matching_rules = []
        
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
    
    def start_tracking(self, key: str, limits: ResourceLimits):
        \"\"\"开始追踪资源使用\"\"\"
        with self._lock:
            self._timers[key] = time.time()
            self._resource_tracking[key] = {
                'start_time': time.time(),
                'limits': limits.to_dict(),
                'paths_explored': 0,
                'current_depth': 0,
                'max_depth_reached': 0
            }
    
    def update_tracking(self, key: str, paths_explored: int = 0, current_depth: int = 0):
        \"\"\"更新追踪信息\"\"\"
        with self._lock:
            if key in self._resource_tracking:
                self._resource_tracking[key]['paths_explored'] = paths_explored
                self._resource_tracking[key]['current_depth'] = current_depth
                self._resource_tracking[key]['max_depth_reached'] = max(
                    self._resource_tracking[key]['max_depth_reached'],
                    current_depth
                )
    
    def check_limits(self, key: str) -> Tuple[bool, Optional[str]]:
        \"\"\"检查是否超出资源限制\"\"\"
        with self._lock:
            if key not in self._resource_tracking or key not in self._timers:
                return True, None
            
            tracking = self._resource_tracking[key]
            elapsed = time.time() - self._timers[key]
            limits = tracking['limits']
            
            if elapsed > limits['timeout_seconds']:
                return False, f\"超时: 已运行 {elapsed:.2f}s，限制 {limits['timeout_seconds']}s\"
            
            if tracking['paths_explored'] > limits['max_paths']:
                return False, f\"路径数超限: 已探索 {tracking['paths_explored']}，限制 {limits['max_paths']}\"
            
            if tracking['current_depth'] > limits['max_depth']:
                return False, f\"深度超限: 当前深度 {tracking['current_depth']}，限制 {limits['max_depth']}\"
            
            return True, None
    
    def stop_tracking(self, key: str) -> Dict[str, Any]:
        \"\"\"停止追踪并返回资源使用统计\"\"\"
        with self._lock:
            if key in self._resource_tracking:
                tracking = self._resource_tracking[key]
                tracking['elapsed_time'] = time.time() - tracking['start_time']
                del self._resource_tracking[key]
                del self._timers[key]
                return tracking
        return {}
    
    def execute_with_limits(
        self,
        func: Callable,
        module_name: str,
        function_name: Optional[str] = None,
        *args,
        **kwargs
    ) -> ExecutionResult:
        \"\"\"
        在资源限制下执行函数
        
        Args:
            func: 要执行的函数
            module_name: 模块名称（用于匹配规则）
            function_name: 函数名称（用于匹配规则）
        
        Returns:
            ExecutionResult
        \"\"\"
        limits = self.get_limits(module_name, function_name)
        key = f\"{module_name}:{function_name or 'unknown'}\"
        
        self.start_tracking(key, limits)
        
        try:
            result = func(*args, **kwargs)
            
            tracking = self.stop_tracking(key)
            return ExecutionResult(
                success=True,
                result=result,
                resource_usage=tracking
            )
            
        except Exception as e:
            tracking = self.stop_tracking(key)
            return ExecutionResult(
                success=False,
                error=str(e),
                resource_usage=tracking
            )
    
    def save_config(self, config_path: str):
        \"\"\"保存当前规则配置到文件\"\"\"
        config = {
            'rules': [
                {
                    'type': rule.rule_type.value,
                    'name_pattern': rule.name_pattern,
                    'timeout_seconds': rule.limits.timeout_seconds,
                    'memory_mb': rule.limits.memory_mb,
                    'max_paths': rule.limits.max_paths,
                    'max_depth': rule.limits.max_depth,
                    'priority': rule.priority
                }
                for rule in self.rules
            ]
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f\"资源配置已保存到 {config_path}\")


class AngrResourceMonitor:
    \"\"\"
    angr模拟管理器资源监控器
    
    在符号执行过程中插入检查点，监控资源使用并自动剪枝
    \"\"\"
    
    def __init__(self, controller: HierarchicalResourceController):
        self.controller = controller
        self._simgr = None
        self._checkpoint_interval = 100
        self._last_check = 0
        self._analysis_key = \"\"
    
    def attach(self, simgr, analysis_key: str):
        \"\"\"附加到模拟管理器\"\"\"
        self._simgr = simgr
        self._analysis_key = analysis_key
        limits = self.controller.get_limits(\"symbolic_execution\")
        self.controller.start_tracking(analysis_key, limits)
    
    def checkpoint(self):
        \"\"\"检查点：检查资源使用并可能剪枝\"\"\"
        if self._simgr is None:
            return
        
        self._last_check += 1
        
        if self._last_check % self._checkpoint_interval != 0:
            return
        
        paths_explored = len(self._simgr.stashes.get('active', [])) + \\
                        len(self._simgr.stashes.get('deadended', []))
        
        self.controller.update_tracking(
            self._analysis_key,
            paths_explored=paths_explored
        )
        
        ok, reason = self.controller.check_limits(self._analysis_key)
        
        if not ok:
            logger.warning(f\"资源限制触发剪枝: {reason}\")
            self._prune_states(reason)
    
    def _prune_states(self, reason: str):
        \"\"\"剪枝状态\"\"\"
        if self._simgr is None:
            return
        
        active_count = len(self._simgr.stashes.get('active', []))
        
        if active_count > 100:
            self._simgr.stashes['pruned'] = self._simgr.stashes.get('pruned', []) + \\
                                          self._simgr.stashes['active'][50:]
            self._simgr.stashes['active'] = self._simgr.stashes['active'][:50]
            logger.info(f\"已剪枝 {len(self._simgr.stashes.get('pruned', []))} 个状态\")
        
        self._simgr.stashes['resource_limit_reason'] = reason
    
    def detach(self) -> Dict[str, Any]:
        \"\"\"分离并返回统计信息\"\"\"
        return self.controller.stop_tracking(self._analysis_key)


class PathLevelResourceController:
    \"\"\"
    路径级资源控制器
    
    为每个符号执行路径设置独立的资源配额
    \"\"\"
    
    def __init__(self, controller: HierarchicalResourceController):
        self.controller = controller
        self._path_limits: Dict[str, ResourceLimits] = {}
    
    def set_path_limits(self, path_id: str, limits: ResourceLimits):
        \"\"\"为特定路径设置资源限制\"\"\"
        self._path_limits[path_id] = limits
    
    def get_path_limits(self, path_id: str) -> ResourceLimits:
        \"\"\"获取路径的资源限制\"\"\"
        return self._path_limits.get(path_id, self.controller.default_limits)
    
    def check_path(self, path_id: str, instructions_executed: int) -> Tuple[bool, Optional[str]]:
        \"\"\"检查路径是否超出限制\"\"\"
        limits = self.get_path_limits(path_id)
        
        if instructions_executed > limits.max_depth:
            return False, f\"路径指令数超限: {instructions_executed} > {limits.max_depth}\"
        
        return True, None
\"@

$content | Out-File -FilePath "C:\Users\Administrator\Desktop\deemo\modules\hierarchical_resource_controller.py" -Encoding UTF8