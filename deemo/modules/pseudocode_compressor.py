"""
上下文感知伪代码压缩模块

功能：
1. 对超长伪代码使用 AST 感知裁剪
2. 保留关键路径
3. 减少 AI token 消耗
4. 支持多种压缩策略

核心组件：
- PseudocodeCompressor: 伪代码压缩器
- ASTAnalyzer: AST分析器
- CompressionStrategy: 压缩策略
"""

import os
import re
import ast
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CompressionStrategy(Enum):
    LINE_LIMIT = "line_limit"
    TOKEN_LIMIT = "token_limit"
    AST_PATTERN = "ast_pattern"
    SEMANTIC = "semantic"


class CompressionLevel(Enum):
    NONE = 0
    LIGHT = 1
    MEDIUM = 2
    AGGRESSIVE = 3
    EXTREME = 4


@dataclass
class CompressionConfig:
    strategy: CompressionStrategy = CompressionStrategy.TOKEN_LIMIT
    level: CompressionLevel = CompressionLevel.MEDIUM
    max_lines: int = 500
    max_tokens: int = 4096
    preserve_comments: bool = False
    preserve_functions: bool = True
    preserve_control_flow: bool = True


@dataclass
class CompressionResult:
    compressed_code: str
    original_lines: int
    compressed_lines: int
    original_tokens: int
    compressed_tokens: int
    compression_ratio: float
    preserved_elements: List[str]
    removed_elements: List[str]


class ASTAnalyzer:

    def __init__(self):
        self._function_defs = []
        self._control_flow = []
        self._variable_usages = {}
        self._complexity_scores = {}

    def analyze(self, code: str) -> Dict[str, Any]:
        try:
            tree = ast.parse(code)
            self._analyze_tree(tree)
            return {
                "functions": self._function_defs,
                "control_flow": self._control_flow,
                "variable_usages": self._variable_usages,
                "complexity": self._complexity_scores
            }
        except SyntaxError as e:
            logger.warning(f"Failed to parse code: {e}")
            return {}

    def _analyze_tree(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._analyze_function(node)
            elif isinstance(node, (ast.If, ast.While, ast.For, ast.Try)):
                self._control_flow.append({)
                    "type": type(node).__name__,
                    "lineno": node.lineno
                }

    def _analyze_function(self, node: ast.FunctionDef) -> None:
        complexity = self._calculate_complexity(node)
        self._function_defs.append({)
            "name": node.name,
            "lineno": node.lineno,
            "complexity": complexity
        }
        self._complexity_scores[node.name] = complexity

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        score = 1,
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                score += 1
            elif isinstance(child, ast.And):
                score += len(child.values) - 1,
        return score


class PseudocodeCompressor:

    def __init__(self, config: Optional[CompressionConfig] = None):
        self._config = config or CompressionConfig()
        self._analyzer = ASTAnalyzer()

    def compress(self, pseudocode: str) -> CompressionResult:
        original_lines = pseudocode.count('\n') + 1
        original_tokens = len(pseudocode.split(


        preserved = []
        removed = []

        if self._config.level == CompressionLevel.NONE:
            return CompressionResult(
                compressed_code=pseudocode,
                original_lines=original_lines,
                compressed_lines=original_lines,
                original_tokens=original_tokens,
                compressed_tokens=original_tokens,
                compression_ratio=1.0,
                preserved_elements=[],
                removed_elements=[])
            


        compressed = pseudocode

        if self._config.strategy == CompressionStrategy.LINE_LIMIT:
            compressed, removed_lines = self._apply_line_limit(pseudocode)
            removed.extend(removed_lines)

        elif self._config.strategy == CompressionStrategy.TOKEN_LIMIT:
            compressed, removed_tokens = self._apply_token_limit(compressed)
            removed.extend(removed_tokens)

        elif self._config.strategy == CompressionStrategy.AST_PATTERN:
            compressed, removed_elements = self._apply_ast_compression(compressed)
            removed.extend(removed_elements)

        elif self._config.strategy == CompressionStrategy.SEMANTIC:
            compressed, removed_semantic = self._apply_semantic_compression(compressed)
            removed.extend(removed_semantic)

        if not self._config.preserve_comments:
            compressed = self._remove_comments(compressed)

        compressed_lines = compressed.count('\n') + 1
        compressed_tokens = len(compressed.split(

        ratio = compressed_tokens / original_tokens if original_tokens > 0 else 1.0

        return CompressionResult(
            compressed_code=compressed,
            original_lines=original_lines,
            compressed_lines=compressed_lines,
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            compression_ratio=ratio,
            preserved_elements=preserved,
            removed_elements=removed)
        


    def _apply_line_limit(self, code: str) -> Tuple[str, List[str]]:
        lines = code.split('\n')
        removed = []

        if len(lines) <= self._config.max_lines:
            return code, removed

        preserved_lines = []
        function_stack = []
        important_sections = set()

        for i, line in enumerate(lines):
            if 'def ' in line or 'function ' in line:
                function_stack.append(i)
            elif function_stack and (line.strip() == '}' or line.strip() == 'end'):
                function_stack.pop()

            if self._is_important_line(line, i, function_stack):
                important_sections.add(i)

        for i, line in enumerate(lines):
            if i in important_sections or i < self._config.max_lines:
                preserved_lines.append(line)
            else:
                removed.append(f"Line {i+1}: {line[:50]}...")

        return '\n'.join(preserved_lines[:self._config.max_lines]), removed

    def _is_important_line(self, line: str, index: int, function_stack: List[int]) -> bool:
        line_lower = line.lower()
        important_patterns = [
            'if ', 'while ', 'for ', 'switch ', 'case ',
            'return ', 'throw ', 'break', 'continue',
            'malloc', 'free', 'calloc', 'realloc',
            'memcpy', 'strcpy', 'sprintf', 'printf',
            'vulnerability', 'exploit', 'buffer', 'overflow'
        ]
        return any(pattern in line_lower for pattern in important_patterns)

    def _apply_token_limit(self, code: str) -> Tuple[str, List[str]]:
        tokens = code.split()
        removed = []

        if len(tokens) <= self._config.max_tokens:
            return code, removed

        important_tokens = []
        normal_tokens = []

        for token in tokens:
            if self._is_important_token(token):
                important_tokens.append(token)
            else:
                normal_tokens.append(token)

        all_tokens = important_tokens + normal_tokens
        compressed_tokens = all_tokens[:self._config.max_tokens]

        if len(all_tokens) > self._config.max_tokens:
            removed.append(f"Removed {len(all_tokens) - self._config.max_tokens} tokens")

        return ' '.join(compressed_tokens), removed

    def _is_important_token(self, token: str) -> bool:
        important_keywords = {
            'if', 'else', 'while', 'for', 'return', 'break', 'continue',
            'malloc', 'free', 'memcpy', 'strcpy', 'strcmp', 'sprintf',
            'vulnerable', 'exploit', 'buffer', 'overflow', 'stack', 'heap'
        }
        return token.lower( in important_keywords)

    def _apply_ast_compression(self, code: str) -> Tuple[str, List[str]]:
        analysis = self._analyzer.analyze(code)
        removed = []

        if not analysis:
            return code, removed

        functions = analysis.get("functions", [])
        functions.sort(key=lambda x: x["complexity"], reverse=True)

        if self._config.level >= CompressionLevel.AGGRESSIVE:
            simple_funcs = [f for f in functions if f["complexity"] <= 2]
            removed.extend([f"Function: {f['name']}" for f in simple_funcs])

        return code, removed

    def _apply_semantic_compression(self, code: str) -> Tuple[str, List[str]]:
        lines = code.split('\n')
        compressed_lines = []
        removed = []
        seen_patterns = set()

        for line in lines:
            normalized = self._normalize_line(line)
            if normalized not in seen_patterns or self._is_unique_line(line):
                compressed_lines.append(line)
                seen_patterns.add(normalized)
            else:
                removed.append(f"Duplicate pattern: {line[:30]}...")

        return '\n'.join(compressed_lines), removed

    def _normalize_line(self, line: str) -> str:
        return re.sub(r'\b\d+\b', '#', line.strip(


    def _is_unique_line(self, line: str) -> bool:
        unique_patterns = ['return', 'malloc', 'free', 'calloc', 'realloc']
        return any(pattern in line.lower( for pattern in unique_patterns))

    def _remove_comments(self, code: str) -> str:
        lines = code.split('\n')
        filtered = []
        for line in lines:
            if '//' in line:
                line = line[:line.index('//')]
            if '# ' in line:
                line = line[:line.index('# ')]
            if line.strip():
                filtered.append(line)
        return '\n'.join(filtered)

    def set_config(self, config: CompressionConfig) -> None:
        self._config = config

    def get_config(self) -> CompressionConfig:
        return self._config


_global_compressor: Optional[PseudocodeCompressor] = None


def get_pseudocode_compressor() -> PseudocodeCompressor:
    global _global_compressor
    if _global_compressor is None:
        _global_compressor = PseudocodeCompressor()
    return _global_compressor


def compress_pseudocode(pseudocode: str, **kwargs) -> CompressionResult:
    compressor = get_pseudocode_compressor()
    
    if kwargs:
        config = CompressionConfig()
        if 'strategy' in kwargs:
            config.strategy = CompressionStrategy[kwargs['strategy'].upper()]
        if 'level' in kwargs:
            config.level = CompressionLevel[kwargs['level'].upper()]
        if 'max_tokens' in kwargs:
            config.max_tokens = kwargs['max_tokens']
        if 'max_lines' in kwargs:
            config.max_lines = kwargs['max_lines']
        compressor.set_config(config)
    
    return compressor.compress(pseudocode)))))))