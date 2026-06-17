import os

content = '''# -*- coding: utf-8 -*-
"""Hierarchical Resource Controller"""
import os
import time
import re
import json
import threading
from dataclasses import dataclass
from enum import Enum

class ResourceLimitType(Enum):
    MODULE = "module"
    FUNCTION = "function"
    PATH = "path"

@dataclass
class ResourceLimits:
    timeout_seconds: int = 300
    memory_mb: int = 2048
    max_paths: int = 10000
    max_depth: int = 100

class ResourceRule:
    def __init__(self, rule_type, name_pattern, limits, priority=0):
        self.rule_type = rule_type
        self.name_pattern = name_pattern
        self.pattern = re.compile(name_pattern)
        self.limits = limits
        self.priority = priority

    def matches(self, name):
        return self.pattern.match(name) is not None

class HierarchicalResourceController:
    def __init__(self, config_path=None):
        self.rules = []
        self.default_limits = ResourceLimits()
        self._resource_tracking = {}
        self._timers = {}
        self._lock = threading.RLock()
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
        else:
            self._load_default_rules()

    def _load_config(self, config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            for rule_data in config.get("rules", []):
                rule_type = ResourceLimitType(rule_data["type"])
                limits = ResourceLimits(
                    timeout_seconds=rule_data.get("timeout_seconds", 300),
                    memory_mb=rule_data.get("memory_mb", 2048),
                    max_paths=rule_data.get("max_paths", 10000),
                    max_depth=rule_data.get("max_depth", 100)
                )
                rule = ResourceRule(rule_type=rule_type, name_pattern=rule_data["name_pattern"], limits=limits, priority=rule_data.get("priority", 0))
                self.rules.append(rule)
        except Exception:
            self._load_default_rules()

    def _load_default_rules(self):
        self.rules.extend([
            ResourceRule(ResourceLimitType.MODULE, r".*", ResourceLimits(timeout_seconds=300, memory_mb=2048), priority=-1),
            ResourceRule(ResourceLimitType.FUNCTION, r".*slow.*", ResourceLimits(timeout_seconds=60, memory_mb=512), priority=10)
        ])

    def get_limits(self, module_name, function_name=None):
        matching_rules = []
        for rule in self.rules:
            if rule.rule_type == ResourceLimitType.FUNCTION and function_name and rule.matches(function_name):
                matching_rules.append(rule)
            elif rule.rule_type == ResourceLimitType.MODULE and rule.matches(module_name):
                matching_rules.append(rule)
        if matching_rules:
            matching_rules.sort(key=lambda r: r.priority, reverse=True)
            return matching_rules[0].limits
        return self.default_limits

    def execute_with_limits(self, func, module_name, function_name=None, *args, **kwargs):
        limits = self.get_limits(module_name, function_name)
        try:
            return func(*args, **kwargs)
        except Exception:
            return None

class AngrResourceMonitor:
    def __init__(self, controller):
        self.controller = controller
        self._simgr = None

    def attach(self, simgr, analysis_key):
        self._simgr = simgr

    def checkpoint(self):
        pass

    def detach(self):
        pass

class PathLevelResourceController:
    def __init__(self, controller):
        self.controller = controller
        self._path_limits = {}

    def check_path(self, path_id, instructions_executed):
        return True, None
'''

with open("C:/Users/Administrator/Desktop/deemo/modules/hierarchical_resource_controller.py", "w", encoding="utf-8") as f:
    f.write(content)

print("File created successfully")
