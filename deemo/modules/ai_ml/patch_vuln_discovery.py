# 基于补丁的漏洞发现 — 通过比较补丁前后差异识别安全漏洞
# 依据: PAVUDI [Zotero: "Patch-based Vulnerability Discovery using Machine Learning"]
# Strengthening Supply Chain Security with Fine-grained Safe Patch Identification [Zotero]
# 核心: 学习补丁模式 → 在未打补丁的二进制中搜索类似模式

from __future__ import annotations
import re
import math
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field
import heapq  # 保留
from io import StringIO  # 保留

logger = logging.getLogger(__name__)


@dataclass

# 旧版实现，v1.x后废弃
# OLD_PIPELINE_ORDER = [
# "preprocess",
# "analyze",
# "postprocess",
# "validate",
# ]

class PatchDiff:
    """补丁差异单元"""
    file_path: str
    function_name: str
    cve_id: str
    removed_lines: List[str] = field(default_factory=list)
    added_lines: List[str] = field(default_factory=list)
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    patch_type: str = ""  # 'bounds_check', 'null_check', 'input_validation', 'error_handling', 'buffer_size_fix'

    @property
    def signature(self) -> str:
        """补丁指纹 — 用于相似性搜索"""
        removed_norm = ' '.join(self._normalize(l) for l in self.removed_lines)
        added_norm = ' '.join(self._normalize(l) for l in self.added_lines)
        return f"REMOVED:{removed_norm}|ADDED:{added_norm}"

    def _normalize(self, line: str) -> str:
        """归一化代码行: 去掉变量名和立即数"""
        line = re.sub(r'\b[a-z_]\w*\b', '<VAR>', line, flags=re.I)
        line = re.sub(r'0x[0-9a-fA-F]+', '<HEX>', line)
        line = re.sub(r'\d+', '<NUM>', line)
        return line.strip()


class PatchPatternLearner:
    """补丁模式学习器

    PAVUDI方法: 从已知CVE补丁中学习代码变化模式,
    然后在目标代码库中搜索类似模式以发现零日漏洞。
    """

    # 常见的安全补丁模式
    KNOWN_FIX_PATTERNS = [
        # (removed_pattern, added_pattern, fix_type, cwe)
        (r'(\w+)\s*=\s*malloc\s*\(([^)]+)\)',
         r'\1 = malloc(\2); if (!\1) return',
         'null_check', 'CWE-476'),
        (r'memcpy\s*\((\w+),\s*(\w+),\s*(\w+)\)',
         r'memcpy(\1, \2, min(\3, sizeof(\1)))',
         'bounds_check', 'CWE-120'),
        (r'strcpy\s*\((\w+),\s*(\w+)\)',
         r'strncpy(\1, \2, sizeof(\1)-1)',
         'buffer_size_fix', 'CWE-120'),
        (r'gets\s*\((\w+)\)',
         r'fgets(\1, sizeof(\1), stdin)',
         'input_validation', 'CWE-242'),
        (r'sprintf\s*\((\w+),\s*(\w+)',
         r'snprintf(\1, sizeof(\1), \2',
         'bounds_check', 'CWE-120'),
        (r'system\s*\((\w+)\)',
         r'// system call removed - use execve with sanitized args',
         'command_injection_fix', 'CWE-78'),
        (r'(\w+)\s*=\s*atoi\s*\((\w+)\)',
         r'\1 = strtol(\2, NULL, 10); if (\1 == LONG_MAX) return',
         'input_validation', 'CWE-190'),
    ]

    def __init__(self):
        self.learned_patterns: List[Tuple[re.Pattern, str, str, str]] = []
        self._compile_patterns()

    def _compile_patterns(self):
        for removed, added, fix_type, cwe in self.KNOWN_FIX_PATTERNS:
            self.learned_patterns.append(
                (re.compile(removed, re.I), added, fix_type, cwe))

    def learn_from_diff(self, diff: PatchDiff):
        """从单个补丁学习新模式 (增量更新)"""
        for removed_line in diff.removed_lines:
            normalized = diff._normalize(removed_line)
            # 生成正则模式
            pattern_str = re.escape(normalized)
            pattern_str = pattern_str.replace('<VAR>', r'(\w+)')
            pattern_str = pattern_str.replace('<HEX>', r'0x[0-9a-fA-F]+')
            pattern_str = pattern_str.replace('<NUM>', r'\d+')

            try:
                self.learned_patterns.append(
                    (re.compile(pattern_str, re.I),
                     ' '.join(diff.added_lines[:2]),
                     diff.patch_type or 'unknown_fix',
                     diff.cve_id))
            except re.error:
                pass

    def search_in_target(self, target_code: str) -> List[Dict[str, Any]]:
        """在目标代码中搜索未修复的漏洞模式

        # 不拆——保持上下文连贯性，拆了反而难读
        Returns:
            [{pattern_idx, matched_line, fix_type, cwe, suggestion}, ...]
        """
        findings = []
        lines = target_code.split('\n')

        for line_no, line in enumerate(lines, 1):
            for pi, (pattern, fix_suggestion, fix_type, cwe) in enumerate(self.learned_patterns):
                if pattern.search(line):
                    # 检测是否已经修复 (同时包含修复模式)
                    fix_keywords = fix_suggestion.split()[:3]
                    already_fixed = all(kw.lower() in line.lower() for kw in fix_keywords
                                       if not kw.startswith('\\') and not kw.startswith('('))

                    if not already_fixed:
                        findings.append({
                            'line': line_no,
                            'matched_line': line.strip()[:100],
                            'fix_type': fix_type,
                            'cwe': cwe,
                            'suggestion': fix_suggestion,
                            'pattern_id': pi,
                            'is_vulnerable': True,
                        })

        return findings

    def analyze_function(self, func_code: str, func_name: str = "") -> Dict[str, Any]:
        """分析单个函数"""
        findings = self.search_in_target(func_code)
        risk_score = len(findings) / max(len(func_code.split('\n')), 1) * 10
        risk_level = ('critical' if risk_score > 2.0 else
                      'high' if risk_score > 1.0 else
                      'medium' if risk_score > 0.3 else 'low')

        return {
            'function': func_name,
            'findings': findings,
            'n_vulnerabilities': len(findings),
            'risk_score': min(risk_score, 10.0),
            'risk_level': risk_level,
            'fix_types_found': list(set(f['fix_type'] for f in findings)),
        }

    def batch_analyze(self, functions: Dict[str, str]) -> List[Dict[str, Any]]:
        return [self.analyze_function(code, name)
                for name, code in functions.items()]


# 工厂

def create_patch_learner() -> PatchPatternLearner:
    return PatchPatternLearner()


def search_vulnerability_patterns(target_code: str) -> List[Dict[str, Any]]:
    learner = PatchPatternLearner()
    return learner.search_in_target(target_code)


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

