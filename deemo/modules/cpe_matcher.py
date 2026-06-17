"""
自定义路径表达式(CPE)匹配引擎模块

功能：
1. 解析和匹配CPE路径表达式
2. 支持通配符和正则表达式
3. 多路径匹配

核心组件：
- CPEMatcher: CPE匹配器
- PathPattern: 路径模式
- MatchResult: 匹配结果
"""

import os
import re
import fnmatch
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MatchType(Enum):
    EXACT = "exact"
    WILDCARD = "wildcard"
    REGEX = "regex"


@dataclass
class PathPattern:
    pattern: str
    match_type: MatchType
    description: Optional[str] = None


@dataclass
class MatchResult:
    matched: bool
    pattern: PathPattern
    matched_path: Optional[str] = None
    captures: Dict[str, str] = field(default_factory=dict)


class CPEMatcher:

    def __init__(self):
        self._patterns: List[PathPattern] = []

    def add_pattern(self, pattern: str, match_type: MatchType = MatchType.WILDCARD,
                    description: Optional[str] = None):
        self._patterns.append(PathPattern(
            pattern=pattern,
            match_type=match_type,
            description=description
        ))

    def match(self, path: str) -> List[MatchResult]:
        results = []
        
        for pattern in self._patterns:
            matched, captures = self._match_single_pattern(path, pattern)
            if matched:
                results.append(MatchResult(
                    matched=True,
                    pattern=pattern,
                    matched_path=path,
                    captures=captures
                ))
        
        return results

    def _match_single_pattern(self, path: str, pattern: PathPattern) -> Tuple[bool, Dict[str, str]]:
        if pattern.match_type == MatchType.EXACT:
            return path == pattern.pattern, {}
        
        elif pattern.match_type == MatchType.WILDCARD:
            return fnmatch.fnmatch(path, pattern.pattern), {}
        
        elif pattern.match_type == MatchType.REGEX:
            match = re.match(pattern.pattern, path)
            if match:
                return True, match.groupdict()
            return False, {}
        
        return False, {}

    def match_any(self, path: str) -> bool:
        return len(self.match(path)) > 0

    def match_all(self, paths: List[str]) -> Dict[str, List[MatchResult]]:
        results = {}
        for path in paths:
            matches = self.match(path)
            if matches:
                results[path] = matches
        return results

    def get_patterns(self) -> List[PathPattern]:
        return self._patterns


def create_cpe_matcher(patterns: List[Dict[str, Any]]) -> CPEMatcher:
    matcher = CPEMatcher()
    
    for pattern in patterns:
        match_type = MatchType[pattern.get("type", "wildcard").upper()]
        matcher.add_pattern(pattern["pattern"], match_type, pattern.get("description"))
    
    return matcher


def match_paths(matcher: CPEMatcher, paths: List[str]) -> Dict[str, bool]:
    results = {}
    for path in paths:
        results[path] = matcher.match_any(path)
    return results