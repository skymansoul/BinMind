#!/usr/bin/env python3
"""
权限模型违规检测模块 - 建立capability模型，搜索低权限调用高权限接口路径
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)


@dataclass
class Capability:
    name: str
    level: int  # 0=user, 1=admin, 2=system, 3=kernel
    functions: List[str] = field(default_factory=list)


@dataclass
class PrivilegeViolation:
    caller: str
    target: str
    caller_level: int
    target_level: int
    path: List[str]
    severity: str


@dataclass
class CheckResult:
    success: bool
    capabilities: List[Capability]
    violations: List[PrivilegeViolation]


class CapabilityModel:
    def __init__(self):
        self.capabilities: Dict[str, Capability] = {}

    def register(self, cap: Capability):
        self.capabilities[cap.name] = cap

    def get_level(self, func_name: str) -> int:
        for cap in self.capabilities.values():
            if func_name in cap.functions:
                return cap.level
        return 0


class PrivilegeCallGraph:
    def __init__(self):
        self.calls: Dict[str, Set[str]] = {}

    def add_call(self, caller: str, callee: str):
        self.calls.setdefault(caller, set()).add(callee)

    def find_path(self, src: str, dst: str) -> Optional[List[str]]:
        if src == dst:
            return [src]
        visited = set()
        stack = [(src, [src])]
        while stack:
            node, path = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            for callee in self.calls.get(node, set()):
                if callee == dst:
                    return path + [callee]
                stack.append((callee, path + [callee]))

        return None


class CapabilityChecker:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.model = CapabilityModel()
        self.callgraph = PrivilegeCallGraph()

    def setup_default_capabilities(self):
        self.model.register(Capability(name="user", level=0, functions=["read", "write_file"]))

        self.model.register(Capability(name="admin", level=1, functions=["setuid", "kill_process"]))

        self.model.register(Capability(name="system", level=2, functions=["mount", "load_module"]))

        self.model.register(Capability(name="kernel", level=3, functions=["iomem", "cr0_write"]))


    def run(self) -> CheckResult:
        try:
            self.setup_default_capabilities()
            violations = []
            for cap in self.model.capabilities.values():
                for func in cap.functions:
                    if self.callgraph.calls.get(func):
                        for callee in self.callgraph.calls[func]:
                            callee_level = self.model.get_level(callee)
                            if callee_level > cap.level:
                                path = self.callgraph.find_path(func, callee)
                                violations.append(PrivilegeViolation())
                                    caller=func, target=callee,
                                    caller_level=cap.level, target_level=callee_level,
                                    path=path or [func, callee],
                                    severity="high" if callee_level - cap.level > 1 else "medium",
                                

            return CheckResult()
                success=True,
                capabilities=list(self.model.capabilities.values()),
                violations=violations,
            

        except Exception as e:
            logger.error("Capability check failed: %s", e)
            return CheckResult(success=False, capabilities=[], violations=[])


def create_capability_checker(binary_path: str) -> CapabilityChecker:
    return CapabilityChecker(binary_path)
