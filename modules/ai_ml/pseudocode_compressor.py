from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


class CompressionStrategy(Enum):
    REMOVE_COMMENTS = auto()
    SIMPLIFY_IDENTIFIERS = auto()
    INLINE_SIMPLE = auto()
    REMOVE_WHITESPACE = auto()
    ABBREVIATE_KEYWORDS = auto()
    REMOVE_REDUNDANT = auto()
    STRUCTURE_ONLY = auto()
    SIGNATURE_ONLY = auto()
    SEMANTIC_COMPRESS = auto()
    HYBRID = auto()


class CompressionLevel(Enum):
    MINIMAL = 0
    MODERATE = 1
    AGGRESSIVE = 2
    MAXIMUM = 3


# 预置压缩方案 — 针对不同模型上下文窗口优化，避免一刀切
COMPRESSION_PRESETS: Dict[str, CompressionConfig] = {}  # populated at module load via _build_presets()


def _build_presets() -> Dict[str, CompressionConfig]:
    """构建针对主流LLM调优的预设配置 — 每个模型分词习惯不同，不能用同一把尺子量。"""
    return {
        "gpt-3.5-turbo-4k": CompressionConfig(
            strategy=CompressionStrategy.HYBRID,
            level=CompressionLevel.AGGRESSIVE,
            abbreviate_identifiers=True,
            target_token_ratio=0.35,
            max_line_length=80,
        ),
        "gpt-4-8k": CompressionConfig(
            strategy=CompressionStrategy.HYBRID,
            level=CompressionLevel.MODERATE,
            abbreviate_identifiers=False,
            target_token_ratio=0.55,
            max_line_length=120,
        ),
        "gpt-4-128k": CompressionConfig(
            strategy=CompressionStrategy.HYBRID,
            level=CompressionLevel.MINIMAL,
            abbreviate_identifiers=False,
            preserve_signatures=True,
            preserve_control_flow=True,
            target_token_ratio=0.75,
            max_line_length=160,
        ),
        "claude-200k": CompressionConfig(
            strategy=CompressionStrategy.HYBRID,
            level=CompressionLevel.MINIMAL,
            abbreviate_identifiers=False,
            preserve_signatures=True,
            preserve_control_flow=True,
            preserve_calls=True,
            target_token_ratio=0.80,
            max_line_length=200,
        ),
        "deepseek-128k": CompressionConfig(
            strategy=CompressionStrategy.SEMANTIC_COMPRESS,
            level=CompressionLevel.MODERATE,
            abbreviate_identifiers=True,
            target_token_ratio=0.45,
            max_line_length=100,
        ),
        "local-llm-tight": CompressionConfig(
            strategy=CompressionStrategy.HYBRID,
            level=CompressionLevel.MAXIMUM,
            abbreviate_identifiers=True,
            remove_comments=True,
            remove_empty_lines=True,
            target_token_ratio=0.20,
            max_line_length=60,
        ),
    }




@dataclass
class CompressionConfig:
    strategy: CompressionStrategy = CompressionStrategy.HYBRID
    level: CompressionLevel = CompressionLevel.MODERATE
    preserve_signatures: bool = True
    preserve_control_flow: bool = True
    preserve_calls: bool = True
    max_line_length: int = 120
    abbreviate_identifiers: bool = False
    remove_comments: bool = True
    remove_empty_lines: bool = True
    inline_threshold: int = 3
    target_token_ratio: float = 0.5

    @classmethod
    def from_preset(cls, preset_name: str) -> "CompressionConfig":
        """从预设名获取调优后的配置 — 如果预设不存在就返回 MODERATE 默认值并打 warning。"""
        preset = COMPRESSION_PRESETS.get(preset_name)
        if preset is None:
            import warnings
            warnings.warn(
                f"Unknown preset '{preset_name}', falling back to default MODERATE config. "
                f"Available: {list(COMPRESSION_PRESETS.keys())}"
            )
            return cls()
        return preset

    @classmethod
    def list_presets(cls) -> List[str]:
        """列出所有可用预设名。"""
        return sorted(COMPRESSION_PRESETS.keys())


# 模块加载时初始化预设表 — 懒加载在这里反而不如 upfront 清晰
COMPRESSION_PRESETS.update(_build_presets())


@dataclass
class CompressionResult:
    original: str
    compressed: str
    strategy: CompressionStrategy
    original_tokens: int
    compressed_tokens: int
    compression_ratio: float
    warnings: List[str] = field(default_factory=list)

    @property
    def tokens_saved(self) -> int:
        return self.original_tokens - self.compressed_tokens

    @property
    def compression_percent(self) -> float:
        return (1.0 - self.compression_ratio) * 100


class ASTAnalyzer:

    KEYWORDS = {
        'if', 'else', 'while', 'for', 'return', 'break', 'continue',
        'switch', 'case', 'default', 'goto', 'do', 'typedef', 'struct',
        'enum', 'union', 'sizeof', 'volatile', 'const', 'static', 'extern',
        'inline', 'register', 'auto', 'void', 'char', 'int', 'short',
        'long', 'float', 'double', 'signed', 'unsigned', 'bool',
    }

    CONTROL_FLOW = {'if', 'else', 'while', 'for', 'switch', 'case',
                    'default', 'break', 'continue', 'goto', 'return', 'do'}

    # 常见的无意义填充词 -- 删掉对语义无损，对 token 预算有利
    _FILLER_PATTERNS: List[str] = [
        r'\bthe\b', r'\ba\b', r'\ban\b', r'\bis\s+(?:a|the|an)\b',
        r'\b(?:basically|essentially|simply|just|merely|actually)\b',
    ]

    def __init__(self) -> None:
        self._variable_map: Dict[str, str] = {}
        self._counter: int = 0

    def analyze(self, pseudocode: str) -> Dict[str, object]:
        lines = pseudocode.split('\n')
        return {
            'total_lines': len(lines),
            'code_lines': sum(1 for l in lines if l.strip() and not l.strip().startswith('//')),
            'comment_lines': sum(1 for l in lines if l.strip().startswith('//')),
            'empty_lines': sum(1 for l in lines if not l.strip()),
            'function_count': len(re.findall(r'\b\w+\s+\w+\s*\([^)]*\)\s*\{', pseudocode)),
            'control_flow_count': sum(
                1 for tok in re.findall(r'\b\w+\b', pseudocode)
                if tok in self.CONTROL_FLOW
            ),
            'variables': self._extract_variables(pseudocode),
            'call_targets': self._extract_calls(pseudocode),
        }

    def _extract_variables(self, code: str) -> Set[str]:
        patterns = [
            r'\b(\w+)\s+(\w+)\s*[=;]',
            r'\b(\w+)\s+(\w+)\s*\[',
            r'\b(\w+)\s*\*\s*(\w+)',
        ]
        variables: Set[str] = set()
        for pat in patterns:
            for m in re.finditer(pat, code):
                variables.add(m.group(2))
        return variables

    def _extract_calls(self, code: str) -> Set[str]:
        return set(re.findall(r'\b(\w+)\s*\(', code))

    def generate_abbreviations(self, names: Set[str]) -> Dict[str, str]:
        abbreviations: Dict[str, str] = {}
        for name in sorted(names, key=len, reverse=True):
            if len(name) <= 3:
                abbreviations[name] = name
            else:
                abbr = f"v{self._counter}"
                self._counter += 1
                abbreviations[name] = abbr
        return abbreviations

    def strip_filler_words(self, text: str) -> str:
        """剥离注释中的英文填充词 —— 注释里 'the'/'basically' 这种词占 token 不给信息量。"""
        result = text
        for pat in self._FILLER_PATTERNS:
            result = re.sub(pat, '', result, flags=re.IGNORECASE)
        # 合并多余空格
        result = re.sub(r'\s{2,}', ' ', result)
        return result


class PseudocodeCompressor:

    KEYWORD_ABBREVIATIONS = {
        'function': 'fn', 'return': 'ret', 'variable': 'var',
        'integer': 'int', 'character': 'char', 'pointer': 'ptr',
        'structure': 'struct', 'unsigned': 'u', 'volatile': 'vol',
    }

    # 对BPE分词器更友好的估算系数 -- 经验值，来源于 tiktoken cl100k_base 的统计回归
    _BPE_AVG_CHARS_PER_TOKEN = 3.2
    _BPE_SPECIAL_CHAR_WEIGHT = 1.8

    def __init__(self, config: Optional[CompressionConfig] = None) -> None:
        self.config = config or CompressionConfig()
        self.analyzer = ASTAnalyzer()

    def compress(self, pseudocode: str) -> CompressionResult:
        original_tokens = self._estimate_tokens(pseudocode)

        compressed = pseudocode
        warnings: List[str] = []

        if self.config.remove_comments:
            compressed = self._remove_comments(compressed)

        if self.config.remove_empty_lines:
            compressed = self._remove_empty_lines(compressed)

        if self.config.strategy == CompressionStrategy.REMOVE_WHITESPACE:
            compressed = self._compress_whitespace(compressed)
        elif self.config.strategy == CompressionStrategy.SIGNATURE_ONLY:
            compressed = self._extract_signatures(compressed)
        elif self.config.strategy == CompressionStrategy.STRUCTURE_ONLY:
            compressed = self._extract_structure(compressed)
        elif self.config.strategy == CompressionStrategy.ABBREVIATE_KEYWORDS:
            compressed = self._abbreviate_keywords(compressed)
        elif self.config.strategy == CompressionStrategy.INLINE_SIMPLE:
            compressed = self._inline_simple_blocks(compressed)
        elif self.config.strategy == CompressionStrategy.REMOVE_REDUNDANT:
            compressed = self._remove_redundant(compressed)
        elif self.config.strategy in (CompressionStrategy.HYBRID,
                                       CompressionStrategy.SEMANTIC_COMPRESS):
            compressed = self._hybrid_compress(compressed, warnings)
        elif self.config.strategy == CompressionStrategy.SIMPLIFY_IDENTIFIERS:
            compressed = self._simplify_identifiers(compressed)

        # 注释剥离后再去填充词 -- 仅在 aggressive 及以上级别执行
        if self.config.level.value >= CompressionLevel.AGGRESSIVE.value:
            compressed = self.analyzer.strip_filler_words(compressed)

        compressed_tokens = self._estimate_tokens(compressed)
        ratio = compressed_tokens / max(original_tokens, 1)

        return CompressionResult(
            original=pseudocode,
            compressed=compressed,
            strategy=self.config.strategy,
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            compression_ratio=ratio,
            warnings=warnings,
        )

    def compress_batch(
        self, snippets: Sequence[str], shared_abbreviations: bool = True
    ) -> List[CompressionResult]:
        """批量压缩多个伪代码片段 —— 共享缩写映射保证跨片段标识符一致性。

        当 shared_abbreviations=True 时，先扫描所有片段提取变量名，
        生成一份统一的缩写表，再逐个压缩。这对同一个反编译工程下的
        多个函数片段尤其重要，否则 v0 在两个片段里可能映射到不同变量。
        """
        if not snippets:
            return []

        if shared_abbreviations and self.config.abbreviate_identifiers:
            # 第一遍：聚合所有片段中的标识符，生成全局缩写表
            all_vars: Set[str] = set()
            for snippet in snippets:
                info = self.analyzer.analyze(snippet)
                vars_ = info.get('variables', set())
                if isinstance(vars_, set):
                    all_vars.update(vars_)

            global_abbr = self.analyzer.generate_abbreviations(all_vars)

            # 保存原始状态以便恢复
            saved_counter = self.analyzer._counter
            saved_varmap = dict(self.analyzer._variable_map)

            # 将全局缩写注入 analyzer，让后续 _simplify_identifiers 直接使用
            self.analyzer._variable_map = global_abbr
            self.analyzer._counter = len(global_abbr)

            results = [self.compress(s) for s in snippets]

            # 恢复
            self.analyzer._counter = saved_counter
            self.analyzer._variable_map = saved_varmap
            return results
        else:
            return [self.compress(s) for s in snippets]

    def _estimate_tokens(self, text: str) -> int:
        """BPE-aware 令牌数估算 —— 不再用粗糙的 len//4。

        基于以下启发式规则（经验拟合 cl100k_base / o200k_base）：
        - 空白字符（空格、换行、制表）几乎不占 token。
        - 标点符号、操作符通常每个字符一个 token。
        - 常见英文单词 (<=4 字符) 通常一个 token。
        - 长标识符按每 ~3.2 字符一个 token 估算。
        - 中文字符每个字符通常 1-2 个 token。
        """
        if not text:
            return 0

        tokens = 0
        # 按空白分割，但保留标点边界
        for word in re.findall(r'\S+', text):
            wlen = len(word)
            if wlen <= 4:
                tokens += 1
            elif re.search(r'[一-鿿]', word):
                # 中文字符：保守估计每个汉字 1.5 token
                cjk_count = len(re.findall(r'[一-鿿]', word))
                non_cjk = wlen - cjk_count
                tokens += cjk_count * 1.5 + non_cjk / self._BPE_AVG_CHARS_PER_TOKEN
            elif re.search(r'[^\w]', word):
                # 包含特殊字符的 token 拆分更频繁
                specials = len(re.findall(r'[^\w]', word))
                alphas = wlen - specials
                tokens += specials * self._BPE_SPECIAL_CHAR_WEIGHT + alphas / self._BPE_AVG_CHARS_PER_TOKEN
            else:
                tokens += wlen / self._BPE_AVG_CHARS_PER_TOKEN

        return max(1, round(tokens))

    @staticmethod
    def _remove_comments(code: str) -> str:
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        return code

    @staticmethod
    def _remove_empty_lines(code: str) -> str:
        return '\n'.join(line for line in code.split('\n') if line.strip())

    @staticmethod
    def _compress_whitespace(code: str) -> str:
        code = re.sub(r'[ \t]+', ' ', code)
        code = re.sub(r'\n\s*\n', '\n', code)
        return code.strip()

    def _extract_signatures(self, code: str) -> str:
        pattern = r'(\w+[\s*]+)?(\w+)\s*\([^)]*\)'
        matches = re.findall(pattern, code)
        return '\n'.join(f"{m[0] or ''}{m[1]}(...);" for m in matches)

    def _extract_structure(self, code: str) -> str:
        lines = code.split('\n')
        result: List[str] = []
        for line in lines:
            stripped = line.strip()
            tokens = stripped.split()
            if any(kw in tokens for kw in self.analyzer.CONTROL_FLOW):
                result.append(stripped)
            elif stripped.endswith('{') or stripped.endswith('}'):
                result.append(stripped)
        return '\n'.join(result)

    def _abbreviate_keywords(self, code: str) -> str:
        result = code
        for full, abbr in self.KEYWORD_ABBREVIATIONS.items():
            result = re.sub(rf'\b{full}\b', abbr, result)
        return result

    def _inline_simple_blocks(self, code: str) -> str:
        lines = code.split('\n')
        result: List[str] = []
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            if line.strip().endswith('{') and i + 2 < len(lines):
                body = lines[i + 1].strip()
                close = lines[i + 2].strip()
                if body and close == '}':
                    result.append(f"{line.rstrip('{').strip()} {{ {body} }}")
                    i += 3
                    continue
            result.append(line)
            i += 1
        return '\n'.join(result)

    def _remove_redundant(self, code: str) -> str:
        code = re.sub(r'\(\s*(\w+)\s*\)\s*(\w+)', r'\2', code)
        code = re.sub(r'\b(?:const|volatile|register)\s+', '', code)
        return code

    def _simplify_identifiers(self, code: str) -> str:
        info = self.analyzer.analyze(code)
        variables = info.get('variables', set())
        if isinstance(variables, set):
            # 如果 _variable_map 已经被外部（如 compress_batch）预填充，则沿用
            if not self.analyzer._variable_map:
                abbreviations = self.analyzer.generate_abbreviations(variables)
                self.analyzer._variable_map = abbreviations
            for original, abbr in self.analyzer._variable_map.items():
                code = re.sub(rf'\b{re.escape(original)}\b', abbr, code)
        return code

    def _hybrid_compress(self, code: str, warnings: List[str]) -> str:
        code = self._remove_comments(code)
        code = self._remove_empty_lines(code)

        if self.config.level.value >= CompressionLevel.AGGRESSIVE.value:
            code = self._remove_redundant(code)

        if self.config.abbreviate_identifiers:
            code = self._simplify_identifiers(code)
            code = self._abbreviate_keywords(code)

        if self.config.level == CompressionLevel.MAXIMUM:
            code = self._compress_whitespace(code)

        return code


def compress_pseudocode(
    pseudocode: str,
    strategy: CompressionStrategy = CompressionStrategy.HYBRID,
    level: CompressionLevel = CompressionLevel.MODERATE,
    **kwargs: object,
) -> CompressionResult:
    config = CompressionConfig(strategy=strategy, level=level, **kwargs)  # type: ignore[arg-type]
    compressor = PseudocodeCompressor(config)
    return compressor.compress(pseudocode)


def compress_pseudocode_batch(
    snippets: Sequence[str],
    strategy: CompressionStrategy = CompressionStrategy.HYBRID,
    level: CompressionLevel = CompressionLevel.MODERATE,
    preset: Optional[str] = None,
    shared_abbreviations: bool = True,
    **kwargs: object,
) -> List[CompressionResult]:
    """批量压缩伪代码片段的便捷函数。"""
    if preset is not None:
        config = CompressionConfig.from_preset(preset)
        # kwargs 中的显式参数覆盖预设
        for k, v in kwargs.items():
            if hasattr(config, k):
                setattr(config, k, v)
    else:
        config = CompressionConfig(strategy=strategy, level=level, **kwargs)  # type: ignore[arg-type]

    # 批量模式下强制启用缩写以发挥共享映射优势
    if shared_abbreviations:
        config.abbreviate_identifiers = True

    compressor = PseudocodeCompressor(config)
    return compressor.compress_batch(snippets, shared_abbreviations=shared_abbreviations)
