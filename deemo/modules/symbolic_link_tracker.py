"""
自动化符号链接跟踪模块

功能：
1. 追踪符号链接
2. 检测TOCTOU竞争点
3. 路径遍历分析

核心组件：
- LinkTracker: 链接追踪器
- TOCTOUDetector: TOCTOU检测器
- PathAnalyzer: 路径分析器
"""

import os
import time
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class LinkType(Enum):
    SYMBOLIC = "symbolic"
    HARD = "hard"
    MOUNT = "mount"


@dataclass
class LinkInfo:
    path: str
    target: str
    link_type: LinkType
    exists: bool
    timestamp: float


@dataclass
class TOCTOUVulnerability:
    path: str
    operation_sequence: List[str]
    risk_level: str
    description: str


class LinkTracker:

    def __init__(self):
        self._links: Dict[str, LinkInfo] = {}

    def track_link(self, path: str) -> Optional[LinkInfo]:
        try:
            if os.path.islink(path):
                target = os.readlink(path)
                link_info = LinkInfo(
                    path=path,
                    target=target,
                    link_type=LinkType.SYMBOLIC,
                    exists=os.path.exists(path),
                    timestamp=time.time()
                )
                self._links[path] = link_info
                return link_info
        except Exception as e:
            logger.error(f"Failed to track link {path}: {e}")
        
        return None

    def get_link_info(self, path: str) -> Optional[LinkInfo]:
        return self._links.get(path)

    def resolve_path(self, path: str) -> str:
        while os.path.islink(path):
            target = os.readlink(path)
            if not os.path.isabs(target):
                target = os.path.join(os.path.dirname(path), target)
            path = target
        return path


class TOCTOUDetector:

    def __init__(self):
        self._tracker = LinkTracker()
        self._operations: List[Dict[str, Any]] = []

    def record_operation(self, operation: str, path: str):
        self._operations.append({
            "operation": operation,
            "path": path,
            "timestamp": time.time(),
            "link_info": self._tracker.track_link(path)
        })

    def detect_vulnerabilities(self) -> List[TOCTOUVulnerability]:
        vulnerabilities = []
        
        for i in range(len(self._operations) - 1):
            op1 = self._operations[i]
            op2 = self._operations[i + 1]
            
            if op1["path"] == op2["path"]:
                link1 = op1.get("link_info")
                link2 = op2.get("link_info")
                
                if link1 and link2 and link1.target != link2.target:
                    vulnerabilities.append(TOCTOUVulnerability(
                        path=op1["path"],
                        operation_sequence=[op1["operation"], op2["operation"]],
                        risk_level="high",
                        description="Symbolic link changed between operations"
                    ))
        
        return vulnerabilities

    def get_operations(self) -> List[Dict[str, Any]]:
        return self._operations


class PathAnalyzer:

    def analyze_path_traversal(self, path: str) -> Dict[str, Any]:
        parts = path.split(os.sep)
        traversal_steps = []
        current_path = ""
        
        for part in parts:
            if part == "..":
                traversal_steps.append({"type": "parent", "part": part})
                current_path = os.path.dirname(current_path)
            elif part == ".":
                traversal_steps.append({"type": "current", "part": part})
            else:
                traversal_steps.append({"type": "component", "part": part})
                current_path = os.path.join(current_path, part)
        
        return {
            "original_path": path,
            "components": parts,
            "traversal_steps": traversal_steps,
            "resolved_path": current_path,
            "has_traversal": any(step["type"] == "parent" for step in traversal_steps)
        }


def detect_toctou_race(operations: List[Dict[str, str]]) -> List[TOCTOUVulnerability]:
    detector = TOCTOUDetector()
    
    for op in operations:
        detector.record_operation(op["operation"], op["path"])
    
    return detector.detect_vulnerabilities()